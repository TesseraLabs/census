//! CLI command implementations.

use crate::apply::{self, ApplyInputs};
use crate::backup::{Backup, BackupTargets};
use crate::catalog::{
    self, CatalogError, LiveCatalog, OsTarget, ResolveCtx, ResolvedPermission, Risk,
    SourcedPrimitive,
};
use crate::doctor::{self, DoctorReport};
use crate::inspect::LiveInspector;
use crate::l10n::{self, LiveL10n, L10nSource};
use crate::lockout::LockoutContext;
use crate::model::{CompileInputs, ResolvedAccount};
use crate::mutate::ShadowUtilsProvisioner;
use crate::rolestore::{self, Limits};
use crate::sessions::LiveSessionSource;
use crate::state::SystemState;
use crate::status;
use crate::trust::{self, TrustMode, TrustOptions};
use crate::{declaration::Declaration, model, plan, state::RegistryState};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Default catalog roots in precedence order (lowest first): the packaged
/// vendor catalog under `/usr/share`, then the site overlay under `/etc`.
pub fn default_catalog_roots() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/usr/share/census/permissions"),
        PathBuf::from("/etc/census/permissions.d"),
    ]
}

/// Determine the OS target: an explicit `--os-target family-distro-version`
/// override (parsed below) or autodetection from `/etc/os-release`. The
/// override is split on `-` into at most three parts (`linux-debian-12`); a
/// two-part form omits the version. Both paths validate every field as a safe
/// path component (`OsTarget::new`/`detect`).
fn detect_os_target(override_spec: Option<&str>) -> Result<OsTarget, CatalogError> {
    match override_spec {
        Some(spec) => {
            let mut parts = spec.splitn(3, '-');
            let family = parts.next().unwrap_or_default().to_owned();
            let distro = parts.next().unwrap_or_default().to_owned();
            let version = parts.next().map(|s| s.to_owned());
            OsTarget::new(family, distro, version)
        }
        None => OsTarget::detect(),
    }
}

/// Render a plan as human-readable lines. Group actions print first (creates,
/// which precede account creation at apply time), then account actions, then
/// group deletes (which follow account deletion at apply time).
pub fn render_plan(p: &plan::Plan) -> String {
    if p.is_empty() {
        return "in sync — no changes\n".to_owned();
    }
    let mut out = String::new();
    // Group creates (applied before accounts).
    for ga in &p.group_actions {
        if let plan::GroupAction::Create { name, gid } = ga {
            match gid {
                Some(g) => out.push_str(&format!("CREATE GROUP {name} (gid {g})\n")),
                None => out.push_str(&format!("CREATE GROUP {name} (gid auto)\n")),
            }
        }
    }
    for action in &p.actions {
        match action {
            plan::Action::Create(a) => {
                out.push_str(&format!("CREATE {} (uid {}, shell {})\n", a.name, a.uid, a.shell));
            }
            plan::Action::Update { account, changes } => {
                out.push_str(&format!("UPDATE {}: {}\n", account.name, changes.join(", ")));
            }
            plan::Action::Delete { name } => {
                out.push_str(&format!("DELETE {} (destructive)\n", name));
            }
        }
    }
    // Group deletes (applied after account deletes).
    for ga in &p.group_actions {
        if let plan::GroupAction::Delete { name } = ga {
            out.push_str(&format!("DELETE GROUP {name} (destructive)\n"));
        }
    }
    out
}

/// Run `census plan`: parse declaration, resolve against role-store (expanding
/// permissions against the catalog), diff vs managed registry, print the plan.
/// Returns a non-zero exit on any error.
pub fn run_plan(
    declaration: &Path,
    managed: &Path,
    catalog_roots: Vec<PathBuf>,
    os_target: Option<&str>,
) -> ExitCode {
    let text = match std::fs::read_to_string(declaration) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read declaration {}: {e}", declaration.display());
            return ExitCode::FAILURE;
        }
    };
    let decl = match Declaration::parse(&text) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let catalog = LiveCatalog::new(catalog_roots);
    let os = match detect_os_target(os_target) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let ctx = ResolveCtx { catalog_version: None };
    let targets = match model::resolve(
        &decl,
        &CompileInputs { catalog: &catalog, os: &os, ctx: &ctx },
    ) {
        Ok((t, warnings)) => {
            for w in &warnings {
                eprintln!("census: warning: {w}");
            }
            t
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let state = match RegistryState::load(managed) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut p = plan::diff(&targets, &state);
    // Group plan: union of role groups ∪ [[group]], diffed against the managed
    // group registry + live system (read-only via getent group). A GID-pin
    // conflict (or managed-group GID drift) surfaces here, before any apply.
    let required = match crate::declaration::required_groups(&decl, &targets) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let inspector = LiveInspector::new();
    match plan::diff_groups_via_inspector(&required, &state.managed_groups(), &inspector) {
        Ok(group_actions) => p.group_actions = group_actions,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    }
    print!("{}", render_plan(&p));
    ExitCode::SUCCESS
}

/// Options for `census apply` (CLI-derived).
pub struct ApplyOpts<'a> {
    /// Declaration TOML path.
    pub declaration: &'a Path,
    /// Managed registry path.
    pub managed: &'a Path,
    /// `--trust-fs`: trust filesystem integrity (standalone mode).
    pub trust_fs: bool,
    /// `--i-understand-no-rescue`: proceed even with no rescue path.
    pub risk_acknowledged: bool,
    /// Root directory for rollback snapshots.
    pub rollback_root: PathBuf,
    /// Pinned trust-anchor path (managed mode). Production default
    /// `/etc/census/trust.pub`; injectable for tests.
    pub trust_anchor_path: PathBuf,
    /// Directory holding the persisted anti-rollback version floor. Production
    /// default `/var/lib/census`; injectable for tests.
    pub persist_dir: PathBuf,
    /// Path to Tessera's live-session registry (§12). Production default
    /// `/run/tessera/sessions.json`; injectable for tests. A delete over an
    /// account with a live session is deferred (not executed).
    pub sessions_file: PathBuf,
    /// Catalog roots in precedence order (lowest first) for permission
    /// expansion. `--catalog-dir` accumulates onto [`default_catalog_roots`].
    pub catalog_roots: Vec<PathBuf>,
    /// `--os-target family-distro-version` override. `None` autodetects from
    /// `/etc/os-release`.
    pub os_target: Option<String>,
}

/// Run `census apply`: verify trust → resolve → diff → lockout gate → snapshot
/// → apply phases over shadow-utils → write the managed registry atomically and
/// last. Returns a non-zero exit on any error (fail-closed).
pub fn run_apply(opts: ApplyOpts<'_>) -> ExitCode {
    let text = match std::fs::read_to_string(opts.declaration) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "error: cannot read declaration {}: {e}",
                opts.declaration.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let decl = match Declaration::parse(&text) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let state = match RegistryState::load(opts.managed) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Real provisioner over the auth-DB backup. The managed snapshot lets the
    // provisioner detect a UID change on update. Touched sudoers fragments are
    // registered into this backup by the orchestrator (via the provisioner)
    // before the snapshot, so a later-phase failure rolls them back too (R2).
    let mut backup = Backup::new(BackupTargets::auth_db_default(), opts.rollback_root.clone());
    let managed_now = state.managed_accounts();
    let inspector = LiveInspector::new();
    let session_source = LiveSessionSource::new(opts.sessions_file.clone());

    // Build the permission catalog + OS target for permission expansion. A
    // failure to determine the OS target fails closed before any mutation
    // (resolve cannot proceed without one).
    let catalog = LiveCatalog::new(opts.catalog_roots.clone());
    let os = match detect_os_target(opts.os_target.as_deref()) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let ctx = ResolveCtx { catalog_version: None };

    let inputs = ApplyInputs {
        declaration: &decl,
        declaration_bytes: text.as_bytes(),
        state: &state,
        inspector: &inspector,
        trust: TrustOptions {
            trust_fs: opts.trust_fs,
            trust_anchor_path: opts.trust_anchor_path.clone(),
            persist_dir: opts.persist_dir.clone(),
        },
        lockout: LockoutContext {
            // Rescue presence is determined out of band; absent that signal we
            // require explicit risk acknowledgement (handled by the gate).
            rescue_present: false,
            risk_acknowledged: opts.risk_acknowledged,
        },
        sudoers_dir: PathBuf::from(crate::sudoers::SUDOERS_DIR),
        session_source: &session_source,
        sessions_file: opts.sessions_file.clone(),
        compile: crate::model::CompileInputs { catalog: &catalog, os: &os, ctx: &ctx },
    };

    // Scope the provisioner so its mutable borrow of `backup` ends before we
    // inspect the retained snapshot path on the failure arm.
    let result = {
        let mut provisioner = ShadowUtilsProvisioner::new(managed_now, &mut backup);
        apply::run(inputs, &mut provisioner)
    };

    match result {
        Ok(report) => {
            for line in &report.log {
                eprintln!("census: {line}");
            }
            // Success: write the registry atomically and LAST, then drop snapshot.
            // Skip the registry rewrite on an empty (idempotent no-op) plan so a
            // byte-identical rewrite does not bump mtime (spec R8: zero mutations).
            if report.registry_written {
                if let Err(e) = apply::write_registry(
                    opts.managed,
                    &report.managed,
                    &report.managed_group_records,
                ) {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            }
            // Anti-rollback: persist the applied version AFTER a successful apply,
            // only in managed mode. Standalone (`--trust-fs`) never moves the floor.
            if let TrustMode::Managed { version } = report.trust_mode {
                if let Err(e) = trust::persist_version(&opts.persist_dir, version) {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            }
            backup.commit_success();
            // A deferred delete (live session present, §12) is a PARTIAL apply:
            // the applied part and the registry update (with the deferred account
            // retained) are committed above, but the destructive step did not
            // complete. Signal that with a distinct non-zero exit so CI/monitoring
            // sees the unfinished destructive work and a later run can complete it.
            if !report.deferred_deletes.is_empty() {
                let names: Vec<&str> = report
                    .deferred_deletes
                    .iter()
                    .map(|d| d.name.as_str())
                    .collect();
                eprintln!(
                    "census: deferred {} delete(s): {}",
                    report.deferred_deletes.len(),
                    names.join(", ")
                );
                println!(
                    "applied: {} mutation(s), {} deferred",
                    report.mutations,
                    report.deferred_deletes.len()
                );
            } else {
                println!("applied: {} mutation(s)", report.mutations);
            }
            apply_exit_code(report.deferred_deletes.len())
        }
        Err(e) => {
            eprintln!("error: {e}");
            // On a phase failure the orchestrator restored from the snapshot but
            // kept the snapshot dir for forensics; surface its path so the
            // operator can recover or inspect it.
            if let Some(path) = backup.keep_on_failure() {
                eprintln!("rollback snapshot retained at: {}", path.display());
            }
            ExitCode::FAILURE
        }
    }
}

/// Render a doctor report as human-readable lines (one per finding).
pub fn render_report(report: &DoctorReport) -> String {
    if report.findings.is_empty() {
        return "doctor: no findings — invariants hold\n".to_owned();
    }
    let mut out = String::new();
    for f in &report.findings {
        out.push_str(&format!(
            "{} [{}] {}: {}\n",
            f.severity.tag(),
            f.check,
            f.target,
            f.message
        ));
    }
    out
}

/// Resolve the declaration at `path` into target accounts for the optional
/// drift check. Returns `None` (and logs to stderr) on any read/parse/resolve
/// error — a doctor/status run continues without drift rather than aborting.
/// Permission expansion uses the default catalog roots and autodetected OS
/// target (these read-only commands report drift, not enforce trust).
fn resolve_targets(path: &Path) -> Option<Vec<ResolvedAccount>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("warning: cannot read declaration {}: {e}", path.display());
            return None;
        }
    };
    let decl = match Declaration::parse(&text) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("warning: declaration invalid: {e}");
            return None;
        }
    };
    let catalog = LiveCatalog::new(default_catalog_roots());
    let os = match detect_os_target(None) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("warning: cannot determine OS target: {e}");
            return None;
        }
    };
    let ctx = ResolveCtx { catalog_version: None };
    match model::resolve(&decl, &CompileInputs { catalog: &catalog, os: &os, ctx: &ctx }) {
        Ok((t, warnings)) => {
            for w in &warnings {
                eprintln!("census: warning: {w}");
            }
            Some(t)
        }
        Err(e) => {
            eprintln!("warning: cannot resolve declaration: {e}");
            None
        }
    }
}

/// Run `census doctor`: read-only diagnostics over the live system + registry,
/// optionally checking declaration drift. Exits NON-ZERO if any Error-severity
/// finding is present, else 0. Never mutates anything.
pub fn run_doctor(declaration: Option<&Path>, managed: &Path) -> ExitCode {
    let state = match RegistryState::load(managed) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let targets = declaration.and_then(resolve_targets);
    let inspector = LiveInspector::new();
    let report = doctor::run_doctor(&state, &inspector, targets.as_deref());
    print!("{}", render_report(&report));
    doctor_exit_code(&report)
}

/// Map the count of deferred deletes to the apply exit code. Zero deferrals →
/// `SUCCESS` (0). One or more → exit 3, a "partial apply — retry" signal that is
/// distinguishable from a phase failure (`FAILURE` == 1). Extracted as a pure
/// function so the exit-code policy is unit-testable.
fn apply_exit_code(deferred: usize) -> ExitCode {
    if deferred == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    }
}

/// Map a doctor report to its process exit code: non-zero iff it has errors.
/// Extracted as a pure function so the exit-code policy is unit-testable
/// without a live system.
fn doctor_exit_code(report: &DoctorReport) -> ExitCode {
    if report.has_errors() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Run `census status`: read-only summary of managed accounts, the persisted
/// declaration version, and optional drift. ALWAYS exits 0.
pub fn run_status(declaration: Option<&Path>, managed: &Path, persist_dir: &Path) -> ExitCode {
    let state = match RegistryState::load(managed) {
        Ok(s) => s,
        Err(e) => {
            // status never fails the exit code; surface the error and print an
            // empty summary by falling back to an absent registry.
            eprintln!("warning: {e}");
            print!("{}", status::render_status(&RegistryState::default_empty(), None, None));
            return ExitCode::SUCCESS;
        }
    };
    let persisted = match trust::last_applied_version(persist_dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("warning: cannot read persisted version: {e}");
            None
        }
    };
    let drift = declaration
        .and_then(resolve_targets)
        .map(|targets| plan::diff(&targets, &state));
    print!("{}", status::render_status(&state, persisted, drift.as_ref()));
    ExitCode::SUCCESS
}

// ============================================================================
// compile / show (read-only)
//
// `compile` and `show` expand ONE role from the declaration's role-store
// composition into concrete Unix primitives, retaining provenance per primitive
// (which permission/bundle → which catalog layer → catalog version). Both are
// strictly read-only: they never touch the registry, the live system, or trust
// state. `model::resolve` drops provenance (it only needs the flat union for the
// plan), so these commands re-walk the composition per-permission via
// `catalog::resolve_with_params`, which preserves `SourcedPrimitive`.
// ============================================================================

/// The display label for a risk class. Advisory only — never gates anything.
fn risk_label(risk: Option<Risk>) -> &'static str {
    match risk {
        Some(Risk::Contained) => "contained",
        Some(Risk::EscalationCapable) => "escalation-capable",
        // A leaf permission whose catalog record set no `risk` is shown as
        // unknown rather than silently assumed contained (honest labelling).
        None => "unknown",
    }
}

/// One expanded permission of a role, with its provenance retained.
#[derive(Debug, Clone)]
pub struct CompiledPermission {
    /// The fully-resolved permission (primitives carry per-primitive layer/via).
    pub resolved: ResolvedPermission,
}

/// A role expanded into concrete primitives with provenance, plus the raw
/// escape-hatch primitives the role declared directly (kept separate so compile
/// can show that they came from the role slice, not the catalog).
#[derive(Debug, Clone)]
pub struct CompiledRole {
    /// The role id.
    pub role: String,
    /// Each declared permission, expanded with provenance, in declaration order.
    pub permissions: Vec<CompiledPermission>,
    /// Raw `payload.groups` declared directly on the role (escape hatch).
    pub raw_groups: Vec<String>,
    /// Raw `payload.sudo_role`, if any (escape hatch).
    pub raw_sudo_role: Option<String>,
    /// Raw `payload.limits` (escape hatch); default when unset.
    pub raw_limits: Limits,
}

impl CompiledRole {
    /// The flat union of every group across all permissions plus the raw groups,
    /// each tagged with its source layer and the permission that pulled it in.
    /// Raw groups come first (they seed the role) with a synthetic `role` layer.
    fn flat_groups(&self) -> Vec<FlatPrimitive> {
        let mut out: Vec<FlatPrimitive> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for g in &self.raw_groups {
            if !seen.iter().any(|s| s == g) {
                seen.push(g.clone());
                out.push(FlatPrimitive::raw(g.clone()));
            }
        }
        for perm in &self.permissions {
            for p in &perm.resolved.groups {
                if !seen.iter().any(|s| s == &p.value) {
                    seen.push(p.value.clone());
                    out.push(FlatPrimitive::from_sourced(&perm.resolved.id, p));
                }
            }
        }
        out
    }

    /// The flat union of every sudo command across all permissions, deduped by
    /// value, each tagged with provenance.
    fn flat_sudo(&self) -> Vec<FlatPrimitive> {
        let mut out: Vec<FlatPrimitive> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for perm in &self.permissions {
            for p in &perm.resolved.sudo {
                if !seen.iter().any(|s| s == &p.value) {
                    seen.push(p.value.clone());
                    out.push(FlatPrimitive::from_sourced(&perm.resolved.id, p));
                }
            }
        }
        out
    }

    /// The effective limits for the role: raw limits win wholesale when present
    /// (mirrors `model::resolve`), else the first expanded limit per field.
    fn effective_limits(&self) -> Limits {
        if self.raw_limits != Limits::default() {
            return self.raw_limits.clone();
        }
        let mut limits = Limits::default();
        for perm in &self.permissions {
            if let Some(l) = &perm.resolved.limits {
                if limits.nofile.is_none() {
                    limits.nofile = l.nofile;
                }
                if limits.nproc.is_none() {
                    limits.nproc = l.nproc;
                }
            }
        }
        limits
    }
}

/// A primitive flattened for the compile view: the value plus where it came
/// from. `permission`/`layer` are `None` for a raw escape-hatch primitive (it
/// came from the role slice, not a catalog permission).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatPrimitive {
    /// The primitive value (group name or sudo command).
    pub value: String,
    /// The permission id that contributed it; `None` for a raw primitive.
    pub permission: Option<String>,
    /// The catalog layer it came from; `None` for a raw primitive.
    pub layer: Option<String>,
    /// For a bundle member, the member id that declared it (from `via`).
    pub via: Option<String>,
}

impl FlatPrimitive {
    fn raw(value: String) -> Self {
        FlatPrimitive {
            value,
            permission: None,
            layer: None,
            via: None,
        }
    }

    fn from_sourced(permission: &str, p: &SourcedPrimitive) -> Self {
        FlatPrimitive {
            value: p.value.clone(),
            // The permission the role referenced. When the primitive arrived via
            // a bundle member, `via` names the member; the referenced permission
            // is still the bundle the role named.
            permission: Some(permission.to_owned()),
            layer: Some(p.layer.clone()),
            via: p.via.clone(),
        }
    }

    /// The provenance suffix for the human view, e.g.
    /// ` [perm net-admin via firewall-diag @ linux-debian-12]` or ` [raw]`.
    fn provenance(&self) -> String {
        match (&self.permission, &self.layer) {
            (Some(perm), Some(layer)) => match &self.via {
                Some(via) if via != perm => format!(" [perm {perm} via {via} @ {layer}]"),
                _ => format!(" [perm {perm} @ {layer}]"),
            },
            _ => " [raw]".to_owned(),
        }
    }
}

/// Compile one role from the declaration's role-store composition, retaining
/// provenance. Reusable by `run_compile`, `run_show`, and lint. Fails closed if
/// the role slice is missing/malformed or any permission cannot be expanded.
///
/// Returns the compiled role plus the resolve warnings (raw-primitive lint,
/// unknown-OS-version, unused-param) the model layer would also surface.
pub fn compile_role(
    role: &str,
    decl: &Declaration,
    inputs: &CompileInputs<'_>,
) -> Result<(CompiledRole, Vec<model::ResolveWarning>), model::ResolveError> {
    let comp = rolestore::read_composition(&decl.role_store, role)?;
    let mut warnings: Vec<model::ResolveWarning> = Vec::new();

    // Mirror the model layer's raw-primitive lint exactly (only when the role
    // ALSO declares permissions — raw-only is the legacy path, not flagged).
    if !comp.permissions.is_empty() {
        if !comp.groups.is_empty() {
            warnings.push(model::ResolveWarning::RawPrimitiveAlongsidePermissions {
                role: role.to_owned(),
                primitive: "groups",
            });
        }
        if comp.sudo_role.is_some() {
            warnings.push(model::ResolveWarning::RawPrimitiveAlongsidePermissions {
                role: role.to_owned(),
                primitive: "sudo_role",
            });
        }
        if comp.limits != Limits::default() {
            warnings.push(model::ResolveWarning::RawPrimitiveAlongsidePermissions {
                role: role.to_owned(),
                primitive: "limits",
            });
        }
    }

    let mut permissions = Vec::with_capacity(comp.permissions.len());
    for perm in &comp.permissions {
        let (resolved, catalog_warnings) = catalog::resolve_with_params(
            &perm.id,
            &perm.params,
            inputs.os,
            inputs.catalog,
            inputs.ctx,
        )
        .map_err(|source| model::ResolveError::Catalog {
            role: role.to_owned(),
            source,
        })?;
        for w in catalog_warnings {
            warnings.push(model::ResolveWarning::Catalog(w));
        }
        permissions.push(CompiledPermission { resolved });
    }

    Ok((
        CompiledRole {
            role: role.to_owned(),
            permissions,
            raw_groups: comp.groups,
            raw_sudo_role: comp.sudo_role,
            raw_limits: comp.limits,
        },
        warnings,
    ))
}

/// Render the compiled role as a human-readable flat slice with provenance.
/// Pure (string in, string out) so the output shape is unit-testable.
pub fn render_compile_human(compiled: &CompiledRole) -> String {
    let mut out = String::new();
    out.push_str(&format!("role {}\n", compiled.role));

    let groups = compiled.flat_groups();
    out.push_str("groups:\n");
    if groups.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for g in &groups {
            out.push_str(&format!("  {}{}\n", g.value, g.provenance()));
        }
    }

    let sudo = compiled.flat_sudo();
    out.push_str("sudo:\n");
    if sudo.is_empty() {
        // A raw sudo_role is the legacy indirection; surface it so the operator
        // sees the role is not empty of sudo, it just uses the escape hatch.
        match &compiled.raw_sudo_role {
            Some(r) => out.push_str(&format!("  (sudo_role {r}) [raw]\n")),
            None => out.push_str("  (none)\n"),
        }
    } else {
        for s in &sudo {
            out.push_str(&format!("  {}{}\n", s.value, s.provenance()));
        }
    }

    let limits = compiled.effective_limits();
    out.push_str("limits:\n");
    if limits == Limits::default() {
        out.push_str("  (none)\n");
    } else {
        if let Some(n) = limits.nofile {
            out.push_str(&format!("  nofile = {n}\n"));
        }
        if let Some(n) = limits.nproc {
            out.push_str(&format!("  nproc = {n}\n"));
        }
    }
    out
}

/// Render the compiled role as a machine-readable JSON object. Hand-rolled (no
/// serde_json dependency) over the small, fixed shape; values are escaped. Pure
/// so the shape is unit-testable.
pub fn render_compile_json(compiled: &CompiledRole) -> String {
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!("\"role\":{},", json_str(&compiled.role)));

    out.push_str("\"groups\":[");
    out.push_str(&flat_primitives_json(&compiled.flat_groups()));
    out.push_str("],");

    out.push_str("\"sudo\":[");
    out.push_str(&flat_primitives_json(&compiled.flat_sudo()));
    out.push_str("],");

    let limits = compiled.effective_limits();
    out.push_str("\"limits\":{");
    out.push_str(&format!(
        "\"nofile\":{},\"nproc\":{}",
        limits.nofile.map(|n| n.to_string()).unwrap_or_else(|| "null".to_owned()),
        limits.nproc.map(|n| n.to_string()).unwrap_or_else(|| "null".to_owned()),
    ));
    out.push('}');
    out.push('}');
    out.push('\n');
    out
}

/// Render a list of flat primitives as JSON objects.
fn flat_primitives_json(prims: &[FlatPrimitive]) -> String {
    prims
        .iter()
        .map(|p| {
            format!(
                "{{\"value\":{},\"permission\":{},\"layer\":{},\"via\":{}}}",
                json_str(&p.value),
                p.permission.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
                p.layer.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
                p.via.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Escape a string as a JSON string literal (minimal: the structural chars and
/// control chars that would break the document). Catalog/role values are
/// already constrained, but escaping keeps the output well-formed regardless.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // U+2028 (line separator) and U+2029 (paragraph separator) are valid
            // JSON but are line terminators in ECMAScript: left literal, they
            // break any consumer that embeds this output in a JS/JSONP string.
            // Escape them so `compile --json` is safe to splice into JS.
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Run `census compile <role>`: expand one role into its flat compiled slice
/// with provenance, print it (human or JSON), optionally lint. Read-only; never
/// mutates. With `--lint`, exits non-zero if any lint ERROR is present.
pub fn run_compile(
    role: &str,
    declaration: &Path,
    catalog_roots: Vec<PathBuf>,
    os_target: Option<&str>,
    lint: bool,
    json: bool,
) -> ExitCode {
    let text = match std::fs::read_to_string(declaration) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("census: cannot read declaration {}: {e}", declaration.display());
            return ExitCode::FAILURE;
        }
    };
    let decl = match Declaration::parse(&text) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let catalog = LiveCatalog::new(catalog_roots.clone());
    let os = match detect_os_target(os_target) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let ctx = ResolveCtx { catalog_version: None };
    let inputs = CompileInputs { catalog: &catalog, os: &os, ctx: &ctx };

    let (compiled, warnings) = match compile_role(role, &decl, &inputs) {
        Ok(r) => r,
        Err(e) => {
            // A resolve error (unknown permission, cycle, namespace collision,
            // lowered bundle risk, …) is a hard lint ERROR — fail closed.
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };

    if json {
        print!("{}", render_compile_json(&compiled));
    } else {
        print!("{}", render_compile_human(&compiled));
    }

    if lint {
        let l10n = LiveL10n::new(catalog_roots);
        let findings = lint_role(&compiled, &warnings, &decl, &os, &catalog, &l10n);
        for f in &findings {
            eprintln!("census: {} [{}] {}", f.severity.tag(), f.code, f.message);
        }
        if findings.iter().any(|f| f.severity == LintSeverity::Error) {
            return ExitCode::FAILURE;
        }
    } else {
        // Without --lint, still surface the resolve warnings (they are advisory
        // signals, not errors) so a plain compile is informative.
        for w in &warnings {
            eprintln!("census: warning: {w}");
        }
    }
    ExitCode::SUCCESS
}

/// Run `census show <role> --lang <l>`: render a tree role → permission/bundle →
/// expanded primitives, with localized texts and (advisory) risk classes.
/// Read-only.
pub fn run_show(
    role: &str,
    declaration: &Path,
    catalog_roots: Vec<PathBuf>,
    os_target: Option<&str>,
    lang: Option<&str>,
) -> ExitCode {
    let text = match std::fs::read_to_string(declaration) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("census: cannot read declaration {}: {e}", declaration.display());
            return ExitCode::FAILURE;
        }
    };
    let decl = match Declaration::parse(&text) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let catalog = LiveCatalog::new(catalog_roots.clone());
    let os = match detect_os_target(os_target) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let ctx = ResolveCtx { catalog_version: None };
    let inputs = CompileInputs { catalog: &catalog, os: &os, ctx: &ctx };

    let (compiled, _warnings) = match compile_role(role, &decl, &inputs) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Language selection: explicit --lang beats LC_MESSAGES beats LANG beats en.
    // The real environment is read HERE (the pure picker stays testable).
    let lc_messages = std::env::var("LC_MESSAGES").ok();
    let env_lang = std::env::var("LANG").ok();
    let chosen = l10n::lang_from_env(lang, lc_messages.as_deref(), env_lang.as_deref());

    // l10n tree lives under the SAME roots as the catalog (`<root>/l10n/...`).
    let l10n = LiveL10n::new(catalog_roots);
    print!("{}", render_show_tree(&compiled, &chosen, &l10n));
    ExitCode::SUCCESS
}

/// Render the show tree: role → each permission (localized title + risk class +
/// optional summary/risk_note) → its expanded primitives. Pure over the l10n
/// source so it is unit-testable with a fake source.
pub fn render_show_tree(compiled: &CompiledRole, lang: &str, l10n: &dyn L10nSource) -> String {
    let mut out = String::new();
    out.push_str(&format!("role {}\n", compiled.role));

    if compiled.permissions.is_empty() {
        out.push_str("  (no permissions; raw escape-hatch only)\n");
    }

    for perm in &compiled.permissions {
        let r = &perm.resolved;
        let text = l10n::resolve_text(l10n, lang, &r.id);
        // Title line: id, localized title, advisory risk class. When the title
        // fell back to the id itself, mark it untranslated so the tree is honest.
        let untranslated = if text.locale_used.is_none() { " (untranslated)" } else { "" };
        out.push_str(&format!(
            "  permission {} — {}{} [{}]\n",
            r.id,
            text.title,
            untranslated,
            risk_label(r.risk)
        ));
        if let Some(summary) = &text.summary {
            out.push_str(&format!("    summary: {summary}\n"));
        }
        if let Some(note) = &text.risk_note {
            out.push_str(&format!("    risk: {note}\n"));
        }
        for g in &r.groups {
            out.push_str(&format!("    group {}{}\n", g.value, via_suffix(&r.id, &g.via)));
        }
        for s in &r.sudo {
            out.push_str(&format!("    sudo {}{}\n", s.value, via_suffix(&r.id, &s.via)));
        }
        if let Some(l) = &r.limits {
            if let Some(n) = l.nofile {
                out.push_str(&format!("    limit nofile = {n}\n"));
            }
            if let Some(n) = l.nproc {
                out.push_str(&format!("    limit nproc = {n}\n"));
            }
        }
    }

    if !compiled.raw_groups.is_empty() {
        out.push_str("  raw groups (escape hatch):\n");
        for g in &compiled.raw_groups {
            out.push_str(&format!("    {g}\n"));
        }
    }
    if let Some(r) = &compiled.raw_sudo_role {
        out.push_str(&format!("  raw sudo_role (escape hatch): {r}\n"));
    }
    out
}

/// Provenance suffix for a tree primitive: ` (via <member>)` when the primitive
/// arrived through a bundle member distinct from the named permission.
fn via_suffix(permission: &str, via: &Option<String>) -> String {
    match via {
        Some(m) if m != permission => format!(" (via {m})"),
        _ => String::new(),
    }
}

// ============================================================================
// Lint (compile --lint; reusable so doctor can call it later)
// ============================================================================

/// Lint severity. ERRORs make `compile --lint` exit non-zero (for CI); WARNINGs
/// are advisory and do not gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintSeverity {
    /// A blocking problem (catalog could not resolve, …).
    Error,
    /// An advisory signal (raw primitive used, missing translation, …).
    Warning,
}

impl LintSeverity {
    /// Short tag for output.
    pub fn tag(self) -> &'static str {
        match self {
            LintSeverity::Error => "ERROR",
            LintSeverity::Warning => "WARNING",
        }
    }
}

/// One lint finding: a stable code, a severity, and a human message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintFinding {
    /// A stable short code for the rule (e.g. `raw-primitive`, `unknown-os-version`).
    pub code: &'static str,
    /// ERROR (gates) vs WARNING (advisory).
    pub severity: LintSeverity,
    /// Human-readable detail.
    pub message: String,
}

/// Lint a successfully-compiled role plus its resolve warnings.
///
/// Resolve-time ERRORs (unknown permission, cycle, namespace collision, lowered
/// bundle risk, invalid sudo/param) are surfaced by `compile_role` returning
/// `Err` — they never reach a `CompiledRole`, so `run_compile` reports them as a
/// fatal error before lint runs. This function lints what a *successful* compile
/// can still flag: the warning-class signals (raw primitives, unknown OS
/// version, unused params) and the l10n completeness of the role's permission set
/// (missing / orphan translations).
///
/// The locale set linted is: the requested `--lang` (when given) plus a default
/// set (`en`, `ru`, `zh`) and any locale materially present in the l10n tree
/// (`available_locales`). This covers the vendor-declared starter set without a
/// separate locale-manifest input (which the catalog format does not carry yet).
///
/// Returns findings in a stable order (warnings from resolve, then l10n).
pub fn lint_role(
    compiled: &CompiledRole,
    warnings: &[model::ResolveWarning],
    _decl: &Declaration,
    _os: &OsTarget,
    _catalog: &LiveCatalog,
    l10n: &dyn L10nSource,
) -> Vec<LintFinding> {
    let mut out: Vec<LintFinding> = Vec::new();

    // Resolve-class warnings → lint warnings (never errors).
    for w in warnings {
        let (code, message): (&'static str, String) = match w {
            model::ResolveWarning::RawPrimitiveAlongsidePermissions { .. } => {
                ("raw-primitive", w.to_string())
            }
            model::ResolveWarning::Catalog(catalog::Warning::UnknownOsVersion { .. }) => {
                ("unknown-os-version", w.to_string())
            }
            model::ResolveWarning::Catalog(catalog::Warning::UnusedParam { .. }) => {
                ("unused-param", w.to_string())
            }
        };
        out.push(LintFinding {
            code,
            severity: LintSeverity::Warning,
            message,
        });
    }

    // l10n completeness over the role's permission ids. Missing translation and
    // orphan translation are warnings (a missing/broken text must never break
    // apply — spec). We lint over the role's own permission ids (the ids this
    // role actually references) so the signal is scoped to what was compiled.
    let ids: Vec<String> = compiled.permissions.iter().map(|p| p.resolved.id.clone()).collect();
    let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();

    let mut locales: Vec<String> = vec!["en".to_owned(), "ru".to_owned(), "zh".to_owned()];
    for l in l10n.available_locales() {
        if !locales.iter().any(|x| x == &l) {
            locales.push(l);
        }
    }
    let locale_refs: Vec<&str> = locales.iter().map(String::as_str).collect();

    for m in l10n::missing_translations(l10n, &locale_refs, &id_refs) {
        out.push(LintFinding {
            code: "missing-translation",
            severity: LintSeverity::Warning,
            message: format!("permission {} has no title in locale {}", m.id, m.locale),
        });
    }
    for o in l10n::orphan_translations(l10n, &locale_refs, &id_refs) {
        out.push(LintFinding {
            code: "orphan-translation",
            severity: LintSeverity::Warning,
            message: format!(
                "translation key {} in locale {} matches no referenced permission",
                o.id, o.locale
            ),
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::ExitCode;

    #[test]
    fn json_str_escapes_structural_and_control_chars() {
        assert_eq!(json_str("a\"b\\c"), r#""a\"b\\c""#);
        assert_eq!(json_str("a\nb\tc\r"), r#""a\nb\tc\r""#);
        // U+0000..U+001F other than the named ones use the \uXXXX form.
        assert_eq!(json_str("\u{0001}"), "\"\\u0001\"");
    }

    #[test]
    fn json_str_escapes_js_line_terminators() {
        // U+2028 / U+2029 are valid JSON but ECMAScript line terminators; they
        // must be escaped so the output is safe to embed in a JS/JSONP string.
        assert_eq!(json_str("a\u{2028}b"), "\"a\\u2028b\"");
        assert_eq!(json_str("a\u{2029}b"), "\"a\\u2029b\"");
    }

    /// Write a role-store slice + a declaration whose single role-account, once
    /// resolved, exactly matches the managed record below (→ empty plan). The
    /// role declares NO supplementary groups so the group plan is empty
    /// independent of the host's `getent` (these tests exercise account/registry
    /// behavior, not group provisioning).
    fn fixtures(dir: &Path) -> (PathBuf, PathBuf) {
        let store = dir.join("roles");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(
            store.join("oper.toml"),
            "role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"Operator\"\nlevel = 5\n[payload]\ngroups = []\n",
        )
        .unwrap();
        let decl = dir.join("declaration.toml");
        std::fs::write(
            &decl,
            format!(
                "version = 5\nrole_store = \"{}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"oper\"\nuid = 9010\n",
                store.display()
            ),
        )
        .unwrap();
        (decl, dir.join("managed.toml"))
    }

    #[test]
    fn empty_plan_apply_does_not_rewrite_registry() {
        let tmp = tempfile::tempdir().unwrap();
        let (decl, managed) = fixtures(tmp.path());

        // Managed registry already matches the resolved target → empty plan.
        std::fs::write(
            &managed,
            "[[account]]\nname = \"oper\"\nuid = 9010\nshell = \"/bin/bash\"\ngroups = []\nfrom_version = 5\n",
        )
        .unwrap();
        let before = std::fs::read(&managed).unwrap();
        let mtime_before = std::fs::metadata(&managed).unwrap().modified().unwrap();

        let code = run_apply(ApplyOpts {
            declaration: &decl,
            managed: &managed,
            trust_fs: true,
            risk_acknowledged: false,
            rollback_root: tmp.path().join("rollback"),
            trust_anchor_path: tmp.path().join("trust.pub"),
            persist_dir: tmp.path().to_path_buf(),
            sessions_file: tmp.path().join("sessions.json"),
            catalog_roots: vec![tmp.path().join("permissions")],
            os_target: Some("linux-debian-12".to_owned()),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));

        // Byte-identical AND mtime untouched: spec R8, zero on-disk mutation.
        let after = std::fs::read(&managed).unwrap();
        assert_eq!(before, after, "empty-plan apply must not rewrite managed.toml");
        let mtime_after = std::fs::metadata(&managed).unwrap().modified().unwrap();
        assert_eq!(mtime_before, mtime_after, "empty-plan apply must not bump mtime");

        // And no rollback snapshot was created (empty plan never snapshots).
        assert!(
            !tmp.path().join("rollback").exists(),
            "empty plan must not create a rollback snapshot"
        );

        // Standalone (`--trust-fs`) must NOT move the anti-rollback floor.
        assert_eq!(
            trust::last_applied_version(tmp.path()).unwrap(),
            None,
            "standalone apply must not persist a version floor"
        );
    }

    /// Build a managed (signed) declaration + pinned trust-anchor whose single
    /// role-account already matches the managed registry → empty plan. Returns
    /// (decl path, managed path, anchor path).
    fn signed_fixtures(dir: &Path, sk: &ed25519_dalek::SigningKey, version: u32) -> (PathBuf, PathBuf, PathBuf) {
        use ed25519_dalek::Signer;
        let store = dir.join("roles");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(
            store.join("oper.toml"),
            "role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"Operator\"\nlevel = 5\n[payload]\ngroups = []\n",
        )
        .unwrap();
        let head = format!("version = {version}\nrole_store = \"{}\"\n", store.display());
        let tail = "[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"oper\"\nuid = 9010\n";
        let payload = format!("{head}{tail}");
        let sig_hex = hex::encode(sk.sign(payload.as_bytes()).to_bytes());
        let decl = dir.join("declaration.toml");
        std::fs::write(&decl, format!("{head}signature = \"{sig_hex}\"\n{tail}")).unwrap();
        let anchor = dir.join("trust.pub");
        std::fs::write(&anchor, hex::encode(sk.verifying_key().to_bytes())).unwrap();
        (decl, dir.join("managed.toml"), anchor)
    }

    #[test]
    fn managed_empty_plan_apply_persists_version_floor() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
        let (decl, managed, anchor) = signed_fixtures(tmp.path(), &sk, 5);
        // Managed registry already matches → empty plan (no real mutations).
        std::fs::write(
            &managed,
            "[[account]]\nname = \"oper\"\nuid = 9010\nshell = \"/bin/bash\"\ngroups = []\nfrom_version = 5\n",
        )
        .unwrap();

        let code = run_apply(ApplyOpts {
            declaration: &decl,
            managed: &managed,
            trust_fs: false, // managed mode: signature + anti-rollback
            risk_acknowledged: false,
            rollback_root: tmp.path().join("rollback"),
            trust_anchor_path: anchor,
            persist_dir: tmp.path().to_path_buf(),
            sessions_file: tmp.path().join("sessions.json"),
            catalog_roots: vec![tmp.path().join("permissions")],
            os_target: Some("linux-debian-12".to_owned()),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));

        // Managed success persists the applied version floor.
        assert_eq!(trust::last_applied_version(tmp.path()).unwrap(), Some(5));
    }

    #[test]
    fn managed_replay_lower_version_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
        let (decl, managed, anchor) = signed_fixtures(tmp.path(), &sk, 5);
        std::fs::write(
            &managed,
            "[[account]]\nname = \"oper\"\nuid = 9010\nshell = \"/bin/bash\"\ngroups = [\"wheel\"]\nfrom_version = 5\n",
        )
        .unwrap();
        // Floor already at 9 → the version-5 declaration is a replay.
        trust::persist_version(tmp.path(), 9).unwrap();

        let code = run_apply(ApplyOpts {
            declaration: &decl,
            managed: &managed,
            trust_fs: false,
            risk_acknowledged: false,
            rollback_root: tmp.path().join("rollback"),
            trust_anchor_path: anchor,
            persist_dir: tmp.path().to_path_buf(),
            sessions_file: tmp.path().join("sessions.json"),
            catalog_roots: vec![tmp.path().join("permissions")],
            os_target: Some("linux-debian-12".to_owned()),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
        // Floor untouched by a refused apply.
        assert_eq!(trust::last_applied_version(tmp.path()).unwrap(), Some(9));
    }

    #[test]
    fn managed_unsigned_declaration_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let (decl, managed) = fixtures(tmp.path()); // unsigned declaration
        std::fs::write(
            &managed,
            "[[account]]\nname = \"oper\"\nuid = 9010\nshell = \"/bin/bash\"\ngroups = [\"wheel\"]\nfrom_version = 5\n",
        )
        .unwrap();
        let code = run_apply(ApplyOpts {
            declaration: &decl,
            managed: &managed,
            trust_fs: false, // managed mode but no signature → fail-closed
            risk_acknowledged: false,
            rollback_root: tmp.path().join("rollback"),
            trust_anchor_path: tmp.path().join("trust.pub"),
            persist_dir: tmp.path().to_path_buf(),
            sessions_file: tmp.path().join("sessions.json"),
            catalog_roots: vec![tmp.path().join("permissions")],
            os_target: Some("linux-debian-12".to_owned()),
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
        assert_eq!(
            trust::last_applied_version(tmp.path()).unwrap(),
            None,
            "refused apply must not persist a floor"
        );
    }

    // ---- doctor / status CLI-level (tasks 4.4) ----

    use crate::doctor::{DoctorReport, Finding, Severity};

    fn finding(sev: Severity) -> Finding {
        Finding { severity: sev, check: "x", target: "t".into(), message: "m".into() }
    }

    #[test]
    fn apply_exit_code_maps_deferrals() {
        // No deferrals → success (0); any deferral → exit 3 (partial — retry),
        // distinct from a phase failure (FAILURE == 1).
        assert_eq!(
            format!("{:?}", apply_exit_code(0)),
            format!("{:?}", ExitCode::SUCCESS)
        );
        assert_eq!(
            format!("{:?}", apply_exit_code(2)),
            format!("{:?}", ExitCode::from(3))
        );
    }

    #[test]
    fn doctor_exit_non_zero_when_errors() {
        let report = DoctorReport { findings: vec![finding(Severity::Error)] };
        assert_eq!(
            format!("{:?}", doctor_exit_code(&report)),
            format!("{:?}", ExitCode::FAILURE)
        );
    }

    #[test]
    fn doctor_exit_zero_when_clean() {
        let report = DoctorReport::default();
        assert_eq!(
            format!("{:?}", doctor_exit_code(&report)),
            format!("{:?}", ExitCode::SUCCESS)
        );
    }

    #[test]
    fn doctor_exit_zero_when_only_warnings() {
        let report = DoctorReport { findings: vec![finding(Severity::Warn)] };
        assert_eq!(
            format!("{:?}", doctor_exit_code(&report)),
            format!("{:?}", ExitCode::SUCCESS)
        );
    }

    #[test]
    fn render_report_clean_and_tagged() {
        assert!(render_report(&DoctorReport::default()).contains("no findings"));
        let report = DoctorReport {
            findings: vec![finding(Severity::Error), finding(Severity::Warn)],
        };
        let text = render_report(&report);
        assert!(text.contains("ERROR ["));
        assert!(text.contains("WARN ["));
    }

    #[test]
    fn status_always_exits_zero() {
        let tmp = tempfile::tempdir().unwrap();
        // No declaration, no managed file, no persisted version → still 0.
        let code = run_status(None, &tmp.path().join("absent.toml"), tmp.path());
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn status_with_declaration_exits_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let (decl, managed) = fixtures(tmp.path());
        std::fs::write(
            &managed,
            "[[account]]\nname = \"oper\"\nuid = 9010\nshell = \"/bin/bash\"\ngroups = [\"wheel\"]\nfrom_version = 5\n",
        )
        .unwrap();
        let code = run_status(Some(&decl), &managed, tmp.path());
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    // ---- compile / show / lint (slice 5) ----

    use crate::l10n::{Description, FakeL10n};

    /// Build a `CompiledRole` directly (no filesystem) for pure-render tests.
    fn sourced(value: &str, layer: &str, via: Option<&str>) -> SourcedPrimitive {
        SourcedPrimitive {
            value: value.to_owned(),
            layer: layer.to_owned(),
            via: via.map(str::to_owned),
        }
    }

    fn compiled_perm(id: &str, risk: Option<Risk>, groups: Vec<SourcedPrimitive>, sudo: Vec<SourcedPrimitive>) -> CompiledPermission {
        CompiledPermission {
            resolved: ResolvedPermission {
                id: id.to_owned(),
                risk,
                groups,
                sudo,
                limits: None,
                limits_layer: None,
                category_members: Vec::new(),
                resolved_catalog_version: None,
            },
        }
    }

    #[test]
    fn render_compile_human_shows_primitives_and_provenance() {
        let compiled = CompiledRole {
            role: "oper".to_owned(),
            permissions: vec![compiled_perm(
                "net-admin",
                Some(Risk::EscalationCapable),
                vec![sourced("netdev", "linux-debian-12", None)],
                vec![sourced("/usr/sbin/ip", "linux-debian", None)],
            )],
            raw_groups: vec!["wheel".to_owned()],
            raw_sudo_role: None,
            raw_limits: Limits::default(),
        };
        let text = render_compile_human(&compiled);
        // Group from the raw escape hatch is tagged [raw]; the permission group
        // carries the source layer; sudo carries its (different) layer.
        assert!(text.contains("wheel [raw]"), "{text}");
        assert!(text.contains("netdev [perm net-admin @ linux-debian-12]"), "{text}");
        assert!(text.contains("/usr/sbin/ip [perm net-admin @ linux-debian]"), "{text}");
    }

    #[test]
    fn render_compile_human_shows_bundle_via_provenance() {
        // A primitive pulled in through a bundle member shows `via`.
        let compiled = CompiledRole {
            role: "oper".to_owned(),
            permissions: vec![compiled_perm(
                "network-config",
                Some(Risk::EscalationCapable),
                vec![],
                vec![sourced("/usr/sbin/ip", "linux", Some("network-admin"))],
            )],
            raw_groups: vec![],
            raw_sudo_role: None,
            raw_limits: Limits::default(),
        };
        let text = render_compile_human(&compiled);
        assert!(
            text.contains("/usr/sbin/ip [perm network-config via network-admin @ linux]"),
            "{text}"
        );
    }

    #[test]
    fn render_compile_json_is_well_formed_shape() {
        let compiled = CompiledRole {
            role: "oper".to_owned(),
            permissions: vec![compiled_perm(
                "net-admin",
                None,
                vec![sourced("netdev", "linux", None)],
                vec![],
            )],
            raw_groups: vec![],
            raw_sudo_role: None,
            raw_limits: Limits { nofile: Some(1024), nproc: None },
        };
        let json = render_compile_json(&compiled);
        assert!(json.contains("\"role\":\"oper\""), "{json}");
        assert!(json.contains("\"value\":\"netdev\""), "{json}");
        assert!(json.contains("\"permission\":\"net-admin\""), "{json}");
        assert!(json.contains("\"layer\":\"linux\""), "{json}");
        assert!(json.contains("\"via\":null"), "{json}");
        assert!(json.contains("\"nofile\":1024"), "{json}");
        assert!(json.contains("\"nproc\":null"), "{json}");
    }

    /// Write a role-store slice + declaration referencing it, plus a catalog
    /// layer dir. Returns the declaration path and the catalog root.
    fn compile_fixture(dir: &Path, payload: &str, catalog_files: &[(&str, &str, &str)]) -> (PathBuf, PathBuf) {
        let store = dir.join("roles");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(
            store.join("oper.toml"),
            format!("role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"Operator\"\nlevel = 5\n{payload}"),
        )
        .unwrap();
        let decl = dir.join("declaration.toml");
        std::fs::write(
            &decl,
            format!(
                "version = 1\nrole_store = \"{}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"oper\"\nuid = 9010\n",
                store.display()
            ),
        )
        .unwrap();
        let catalog_root = dir.join("permissions");
        for (layer, file, body) in catalog_files {
            let layer_dir = catalog_root.join(layer);
            std::fs::create_dir_all(&layer_dir).unwrap();
            std::fs::write(layer_dir.join(format!("{file}.toml")), body).unwrap();
        }
        (decl, catalog_root)
    }

    #[test]
    fn compile_role_expands_with_provenance_over_tempdir() {
        let tmp = tempfile::tempdir().unwrap();
        let (decl_path, catalog_root) = compile_fixture(
            tmp.path(),
            "[payload]\npermissions = [\"net-admin\"]\n",
            &[(
                "linux",
                "net-admin",
                "id = \"net-admin\"\nrisk = \"escalation-capable\"\ngroups = [\"netdev\"]\nsudo = [\"/usr/sbin/ip\"]\n",
            )],
        );
        let decl = Declaration::parse(&std::fs::read_to_string(&decl_path).unwrap()).unwrap();
        let catalog = LiveCatalog::new(vec![catalog_root]);
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let ctx = ResolveCtx::default();
        let inputs = CompileInputs { catalog: &catalog, os: &os, ctx: &ctx };
        let (compiled, warnings) = compile_role("oper", &decl, &inputs).unwrap();
        assert_eq!(compiled.permissions.len(), 1);
        let groups = compiled.flat_groups();
        assert_eq!(groups[0].value, "netdev");
        assert_eq!(groups[0].permission.as_deref(), Some("net-admin"));
        assert_eq!(groups[0].layer.as_deref(), Some("linux"));
        assert!(warnings.is_empty(), "pure-permission role must not warn: {warnings:?}");
    }

    #[test]
    fn run_compile_clean_exits_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let (decl, catalog_root) = compile_fixture(
            tmp.path(),
            "[payload]\npermissions = [\"net-admin\"]\n",
            &[("linux", "net-admin", "id = \"net-admin\"\nrisk = \"contained\"\ngroups = [\"netdev\"]\n")],
        );
        let code = run_compile("oper", &decl, vec![catalog_root], Some("linux-debian-12"), false, false);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn run_compile_lint_clean_exits_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let (decl, catalog_root) = compile_fixture(
            tmp.path(),
            "[payload]\npermissions = [\"net-admin\"]\n",
            &[("linux", "net-admin", "id = \"net-admin\"\nrisk = \"contained\"\ngroups = [\"netdev\"]\n")],
        );
        // Pin the OS target so no UnknownOsVersion warning surfaces (still a
        // warning, not an error — but keep the test about the clean path).
        let code = run_compile("oper", &decl, vec![catalog_root], Some("linux-debian"), true, false);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn run_compile_lint_unknown_permission_exits_nonzero() {
        let tmp = tempfile::tempdir().unwrap();
        // Role references a permission no catalog layer defines → resolve ERROR.
        let (decl, catalog_root) = compile_fixture(
            tmp.path(),
            "[payload]\npermissions = [\"does-not-exist\"]\n",
            &[("linux", "net-admin", "id = \"net-admin\"\ngroups = [\"netdev\"]\n")],
        );
        let code = run_compile("oper", &decl, vec![catalog_root], Some("linux-debian"), true, false);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
    }

    #[test]
    fn run_compile_lint_cycle_exits_nonzero() {
        let tmp = tempfile::tempdir().unwrap();
        // a includes b, b includes a → cycle → resolve ERROR.
        let (decl, catalog_root) = compile_fixture(
            tmp.path(),
            "[payload]\npermissions = [\"a\"]\n",
            &[
                ("linux", "a", "id = \"a\"\nincludes = [\"b\"]\n"),
                ("linux", "b", "id = \"b\"\nincludes = [\"a\"]\n"),
            ],
        );
        let code = run_compile("oper", &decl, vec![catalog_root], Some("linux-debian"), true, false);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
    }

    #[test]
    fn lint_role_flags_raw_primitive_as_warning_not_error() {
        // A raw group alongside permissions is a WARNING; with only warnings,
        // compile --lint still exits 0.
        let tmp = tempfile::tempdir().unwrap();
        let (decl, catalog_root) = compile_fixture(
            tmp.path(),
            "[payload]\ngroups = [\"wheel\"]\npermissions = [\"net-admin\"]\n",
            &[("linux", "net-admin", "id = \"net-admin\"\nrisk = \"contained\"\ngroups = [\"netdev\"]\n")],
        );
        let code = run_compile("oper", &decl, vec![catalog_root], Some("linux-debian"), true, false);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn lint_role_emits_raw_and_missing_translation_warnings() {
        // Build a compiled role directly and lint it against a fake l10n source
        // that has no translation for the permission → missing-translation
        // warnings; the raw-primitive warning is carried in `warnings`.
        let compiled = CompiledRole {
            role: "oper".to_owned(),
            permissions: vec![compiled_perm("net-admin", Some(Risk::Contained), vec![], vec![])],
            raw_groups: vec!["wheel".to_owned()],
            raw_sudo_role: None,
            raw_limits: Limits::default(),
        };
        let warnings = vec![model::ResolveWarning::RawPrimitiveAlongsidePermissions {
            role: "oper".to_owned(),
            primitive: "groups",
        }];
        let decl = Declaration::parse(
            "version = 1\nrole_store = \"/r\"\n[defaults]\nuid_range = [9000,9999]\nshell = \"/bin/bash\"\nhome_base = \"/h\"\n",
        )
        .unwrap();
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let catalog = LiveCatalog::new(vec![]);
        // en has a title (so no missing for en), ru/zh do not.
        let l10n = FakeL10n::new().with("en", "net-admin", Description { title: Some("Network".to_owned()), summary: None, risk_note: None });
        let findings = lint_role(&compiled, &warnings, &decl, &os, &catalog, &l10n);
        assert!(findings.iter().any(|f| f.code == "raw-primitive" && f.severity == LintSeverity::Warning));
        assert!(
            findings.iter().any(|f| f.code == "missing-translation" && f.message.contains("ru")),
            "expected ru missing-translation: {findings:?}"
        );
        // No ERROR-severity finding from a successful compile → would not gate.
        assert!(!findings.iter().any(|f| f.severity == LintSeverity::Error));
    }

    #[test]
    fn render_show_tree_localizes_and_shows_risk() {
        let compiled = CompiledRole {
            role: "oper".to_owned(),
            permissions: vec![compiled_perm(
                "net-admin",
                Some(Risk::EscalationCapable),
                vec![sourced("netdev", "linux", None)],
                vec![sourced("/usr/sbin/ip", "linux", None)],
            )],
            raw_groups: vec![],
            raw_sudo_role: None,
            raw_limits: Limits::default(),
        };
        let l10n = FakeL10n::new().with(
            "ru",
            "net-admin",
            Description {
                title: Some("Управление сетью".to_owned()),
                summary: Some("Настройка интерфейсов".to_owned()),
                risk_note: Some("Фактически root".to_owned()),
            },
        );
        let text = render_show_tree(&compiled, "ru", &l10n);
        assert!(text.contains("permission net-admin — Управление сетью [escalation-capable]"), "{text}");
        assert!(text.contains("summary: Настройка интерфейсов"), "{text}");
        assert!(text.contains("group netdev"), "{text}");
        assert!(text.contains("sudo /usr/sbin/ip"), "{text}");
    }

    #[test]
    fn render_show_tree_falls_back_to_id_when_untranslated() {
        let compiled = CompiledRole {
            role: "oper".to_owned(),
            permissions: vec![compiled_perm("net-admin", Some(Risk::Contained), vec![], vec![])],
            raw_groups: vec![],
            raw_sudo_role: None,
            raw_limits: Limits::default(),
        };
        let l10n = FakeL10n::new();
        let text = render_show_tree(&compiled, "ru", &l10n);
        // Title falls back to the id, marked untranslated; risk class still shown.
        assert!(text.contains("permission net-admin — net-admin (untranslated) [contained]"), "{text}");
    }

    #[test]
    fn run_show_over_tempdir_with_l10n_renders_localized() {
        let tmp = tempfile::tempdir().unwrap();
        let (decl, catalog_root) = compile_fixture(
            tmp.path(),
            "[payload]\npermissions = [\"net-admin\"]\n",
            &[("linux", "net-admin", "id = \"net-admin\"\nrisk = \"escalation-capable\"\ngroups = [\"netdev\"]\n")],
        );
        // l10n tree under the SAME root: <root>/l10n/ru/network.toml.
        let l10n_dir = catalog_root.join("l10n").join("ru");
        std::fs::create_dir_all(&l10n_dir).unwrap();
        std::fs::write(l10n_dir.join("network.toml"), "[net-admin]\ntitle = \"Управление сетью\"\n").unwrap();

        // Drive the public entry point; it reads the real env for LANG, but
        // explicit --lang ru wins regardless of the host env.
        let code = run_show("oper", &decl, vec![catalog_root], Some("linux-debian"), Some("ru"));
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }
}
