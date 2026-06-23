//! CLI command implementations.

use crate::apply::{self, ApplyInputs};
use crate::backup::{Backup, BackupTargets};
use crate::catalog::{
    self, CatalogError, CatalogSource, LiveCatalog, OsTarget, ResolveCtx, ResolvedPermission,
    Risk, SourcedPrimitive,
};
use crate::coverage::{
    self, CoverageCtx, CoverageReport, LiveSurface, ResolvedRole, SurfaceClass, SurfaceScanner,
};
use crate::doctor::{self, DoctorReport};
use crate::fileaccess::AclBackend;
use crate::framework::{self, LoadedFrameworks};
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

    // Production file-access backend: the open ACL backend, snapshotting into a
    // `file-access` subdir of the rollback root so its ACL dumps do not collide
    // with the auth-DB full-file backup. A SEPARATE seam from the provisioner —
    // it materializes/revokes/snapshots/restores file grants while the
    // provisioner drives shadow-utils.
    let mut file_access = AclBackend::production(opts.rollback_root.join("file-access"));

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
        file_access: &mut file_access,
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
    let mut report = doctor::run_doctor(&state, &inspector, targets.as_deref());

    // Append framework cross-reference integrity findings (all advisory Warn —
    // the layer can never widen/break a grant, so it never fails doctor's exit
    // code). Best-effort: any failure to determine the OS target, read the
    // catalog, or load the framework tree just skips these findings with a
    // warning to stderr — a broken/absent advisory layer must not fail doctor.
    // An absent frameworks/ tree loads as empty → zero findings (no special-case).
    match detect_os_target(None) {
        Ok(os) => {
            let catalog = LiveCatalog::new(default_catalog_roots());
            match catalog.all_definitions(&os) {
                Ok(defs) => {
                    let known: std::collections::BTreeSet<String> =
                        defs.into_iter().map(|(_, def)| def.id).collect();
                    match framework::load_frameworks(&framework::default_framework_roots(), &os) {
                        Ok(loaded) => {
                            for w in &loaded.warnings {
                                report.findings.push(doctor::framework_load_warning(w));
                            }
                            report.findings.extend(doctor::framework_findings(
                                &framework::lint_loaded(&loaded, &known),
                            ));
                        }
                        Err(framework::FrameworkError::IdCollision { id }) => {
                            let lint = framework::FrameworkLint {
                                code: "id-collision",
                                severity: framework::FrameworkLintSeverity::Error,
                                message: format!(
                                    "framework id {id} declared in two roots (determinism)"
                                ),
                            };
                            report
                                .findings
                                .extend(doctor::framework_findings(&[lint]));
                        }
                        Err(e) => {
                            eprintln!("warning: framework check skipped (load failed): {e}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("warning: framework check skipped (catalog unreadable): {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("warning: cannot determine OS target for framework check: {e}");
        }
    }

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

    /// The flat union of every file grant across all permissions, keyed by path
    /// (access widens to the max, `recursive` ORs, shape recomputed) — the same
    /// rule `model::resolve` applies. Each carries the permission that pulled it in
    /// (first-seen). File grants only ever come from permissions (no raw escape
    /// hatch), so there is no raw seed here.
    fn flat_file_grants(&self) -> Vec<FlatFileGrant> {
        let mut out: Vec<FlatFileGrant> = Vec::new();
        for perm in &self.permissions {
            for g in &perm.resolved.file_grants {
                if let Some(existing) = out.iter_mut().find(|e| e.grant.path == g.path) {
                    // Widen in place, mirroring the resolver's by-path union so the
                    // compiled view shows one grant per path at its strongest.
                    existing.grant = catalog::union_resolved_file_grants(vec![
                        existing.grant.clone(),
                        g.clone(),
                    ])
                    .into_iter()
                    .next()
                    .expect("union of two grants on one path yields one");
                } else {
                    out.push(FlatFileGrant {
                        grant: g.clone(),
                        permission: perm.resolved.id.clone(),
                    });
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

/// A file grant flattened for the compile/show view: the resolved grant plus the
/// permission that contributed it. The render derives the access/recursive/shape
/// display and the enforcing backend from the grant itself.
#[derive(Debug, Clone)]
pub struct FlatFileGrant {
    /// The resolved file grant (path, access, recursive, shape, provenance).
    pub grant: catalog::ResolvedFileGrant,
    /// The permission id that pulled this grant in.
    pub permission: String,
}

/// The access token (`ro`/`rw`) for display.
fn access_token(access: catalog::Access) -> &'static str {
    match access {
        catalog::Access::Ro => "ro",
        catalog::Access::Rw => "rw",
    }
}

/// Describe which backend + guarantee resolves a grant of this shape in the open
/// build. A directory grant is enforced rewrite-proof by the open `AclBackend`; a
/// File or Pattern grant has no open backend and would REQUIRE a capability-gated
/// one — stated honestly so the view never implies the open build can enforce it.
/// Mirrors the routing in [`crate::fileaccess`] (Dir→AclBackend) and the
/// capability-gating contract (File/Pattern → capable backend required).
fn backend_for_shape(shape: catalog::Shape) -> &'static str {
    match shape {
        catalog::Shape::Dir => "AclBackend (dir, rewrite-proof)",
        catalog::Shape::File => "requires per-file-capable backend",
        catalog::Shape::Pattern => "requires pattern-capable backend",
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

    let files = compiled.flat_file_grants();
    out.push_str("files:\n");
    if files.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for f in &files {
            // `<path> <ro|rw>[ recursive] via <backend> [perm <id>]`
            let recursive = if f.grant.recursive { " recursive" } else { "" };
            out.push_str(&format!(
                "  {} {}{} via {} [perm {}]\n",
                f.grant.path,
                access_token(f.grant.access),
                recursive,
                backend_for_shape(f.grant.shape),
                f.permission,
            ));
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

    out.push_str("\"file_grants\":[");
    out.push_str(&flat_file_grants_json(&compiled.flat_file_grants()));
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

/// Render a list of flat file grants as JSON objects: path, access (`ro`/`rw`),
/// recursive, shape, the enforcing backend description, and the contributing
/// permission. Reuses `json_str` for escaping.
fn flat_file_grants_json(grants: &[FlatFileGrant]) -> String {
    grants
        .iter()
        .map(|f| {
            let shape = match f.grant.shape {
                catalog::Shape::Dir => "dir",
                catalog::Shape::File => "file",
                catalog::Shape::Pattern => "pattern",
            };
            format!(
                "{{\"path\":{},\"access\":{},\"recursive\":{},\"shape\":{},\"backend\":{},\"permission\":{}}}",
                json_str(&f.grant.path),
                json_str(access_token(f.grant.access)),
                f.grant.recursive,
                json_str(shape),
                json_str(backend_for_shape(f.grant.shape)),
                json_str(&f.permission),
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
        let mut findings = lint_role(&compiled, &warnings, &decl, &os, &catalog, &l10n);
        // Group-grant escalation lint: bindings that attach an escalation-capable
        // grant to a group every member inherits. Resolved from the declaration's
        // `[[role_group]]` blocks. A resolve failure here is advisory-only (the
        // group lint is a best-effort overlay on the per-role compile, which is
        // what `--lint` gates on); surface it as a warning and skip.
        match model::resolve_groups(&decl, &inputs) {
            Ok((groups, _warnings)) => findings.extend(group_grant_risk_findings(&groups)),
            Err(e) => eprintln!("census: warning: group lint skipped: {e}"),
        }
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

/// Options for `census show <role>` (CLI-derived).
pub struct ShowOpts<'a> {
    pub role: &'a str,
    pub declaration: &'a Path,
    pub catalog_roots: Vec<PathBuf>,
    pub os_target: Option<&'a str>,
    pub lang: Option<&'a str>,
    pub framework: Option<&'a str>,
    pub framework_roots: Vec<PathBuf>,
    pub format: Option<&'a str>,
}

/// Run `census show <role> --lang <l>`: render a tree role → permission/bundle →
/// expanded primitives, with localized texts and (advisory) risk classes.
/// Read-only.
pub fn run_show(opts: ShowOpts<'_>) -> ExitCode {
    let ShowOpts { role, declaration, catalog_roots, os_target, lang, framework, framework_roots, format } = opts;
    let json = format == Some("json");
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

    // --- framework cross-reference view (--framework given) ---
    //
    // When `--framework` is present we load the framework tree and render the
    // compiled role's permissions against the selected framework(s) — controls +
    // mapping provenance — in either human or JSON form. This is a wholly
    // separate, read-only report from the plain show tree.
    if let Some(fw_spec) = framework {
        let loaded = match framework::load_frameworks(&framework_roots, &os) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("census: {e}");
                return ExitCode::FAILURE;
            }
        };
        for w in &loaded.warnings {
            eprintln!("census: warning: {w}");
        }
        let selection = FrameworkSelection::resolve(fw_spec, &loaded);
        if json {
            print!("{}", render_show_framework_json(&compiled, &selection, &loaded));
        } else {
            print!("{}", render_show_framework_human(&compiled, &selection, &loaded));
        }
        return ExitCode::SUCCESS;
    }

    // --- JSON without --framework ---
    //
    // `--format json` may be requested without a framework. Per the slice
    // contract there is no framework stamp to emit (none was requested), so we
    // render a minimal JSON of the role and its permission ids — valid JSON, no
    // `frameworks` array. The stamped, framework-bearing JSON is only produced
    // when `--framework` is also given (handled above).
    if json {
        print!("{}", render_show_permissions_json(&compiled));
        return ExitCode::SUCCESS;
    }

    // --- default: the plain localized show tree (current behavior) ---
    //
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

/// Which framework(s) a `census show --framework <spec>` invocation displays.
///
/// `<spec>` is either a single framework id or `all`. We resolve it eagerly to a
/// sorted list of ids drawn from the loaded set so the render functions are pure
/// over a concrete id list: `all` expands to every loaded framework id (already
/// sorted, since `frameworks` is a `BTreeMap`), and a single id is kept as-is
/// (even if not loaded — the render then shows it with no controls, which is the
/// honest "framework not installed" signal rather than a silent empty report).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkSelection {
    /// The framework ids to display, sorted.
    pub ids: Vec<String>,
}

impl FrameworkSelection {
    /// Resolve a `--framework` spec against the loaded set. `all` → every loaded
    /// id; any other value → that single id verbatim.
    pub fn resolve(spec: &str, loaded: &LoadedFrameworks) -> FrameworkSelection {
        if spec == "all" {
            FrameworkSelection {
                ids: loaded.frameworks.keys().cloned().collect(),
            }
        } else {
            FrameworkSelection {
                ids: vec![spec.to_owned()],
            }
        }
    }
}

/// The mapping provenance contributions for one (framework, permission): each
/// physical mapping file that mentioned the permission, with its layer and path.
/// Drawn from `loaded.mappings` (the pre-union, per-file record) so the report
/// can point a reviewer at the exact source of every control mapping.
fn provenance_for<'a>(
    loaded: &'a LoadedFrameworks,
    fw: &str,
    perm: &str,
) -> Vec<&'a framework::MappingProvenance> {
    loaded
        .mappings
        .iter()
        .filter(|m| m.framework_id == fw && m.permission_id == perm)
        .map(|m| &m.provenance)
        .collect()
}

/// Render the framework cross-reference for a compiled role (human form). For
/// each selected framework, every permission of the role is listed with the
/// control ids it satisfies and the mapping provenance; a permission with no
/// mapping in that framework is printed with an explicit `(no mapping)` marker
/// (never omitted). Pure (no filesystem) so it is unit-testable.
pub fn render_show_framework_human(
    compiled: &CompiledRole,
    selected: &FrameworkSelection,
    loaded: &LoadedFrameworks,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("role {}\n", compiled.role));
    if selected.ids.is_empty() {
        out.push_str("  (no frameworks installed)\n");
        return out;
    }
    for fw in &selected.ids {
        // Version stamp from the manifest when the framework is loaded; an
        // unknown id is labelled so the report is honest about a missing install.
        match loaded.frameworks.get(fw) {
            Some(m) => out.push_str(&format!("framework {} ({})\n", fw, m.version)),
            None => out.push_str(&format!("framework {} (not installed)\n", fw)),
        }
        if compiled.permissions.is_empty() {
            out.push_str("  (no permissions; raw escape-hatch only)\n");
        }
        for perm in &compiled.permissions {
            let perm_id = &perm.resolved.id;
            let polar = loaded.controls_for(perm_id, fw);
            if polar.is_empty() {
                out.push_str(&format!("  permission {perm_id} (no mapping)\n"));
                continue;
            }
            out.push_str(&format!("  permission {perm_id}:\n"));
            if !polar.satisfies.is_empty() {
                out.push_str(&format!("    ✓ satisfies: {}\n", polar.satisfies.join(", ")));
            }
            if !polar.risk.is_empty() {
                out.push_str(&format!("    ⚠ risk: {}\n", polar.risk.join(", ")));
            }
            if !polar.related.is_empty() {
                out.push_str(&format!("    · related: {}\n", polar.related.join(", ")));
            }
            for prov in provenance_for(loaded, fw, perm_id) {
                let layer = prov.layer.as_deref().unwrap_or("-");
                out.push_str(&format!("    via {} [{}] {}\n", fw, layer, prov.path.display()));
            }
        }
    }
    out
}

/// Render the framework cross-reference as JSON (hand-rolled, no serde_json).
/// Each selected framework carries a version STAMP (`id` + `version`) and a
/// `permissions` array; an unmapped permission is marked `"mapped":false` with an
/// empty `controls` array (never omitted). Pure so the shape is unit-testable.
pub fn render_show_framework_json(
    compiled: &CompiledRole,
    selected: &FrameworkSelection,
    loaded: &LoadedFrameworks,
) -> String {
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!("\"role\":{},", json_str(&compiled.role)));
    out.push_str("\"frameworks\":[");
    let fws: Vec<String> = selected
        .ids
        .iter()
        .map(|fw| {
            // Version stamp: the manifest version when loaded, else null (an id
            // the caller named that is not installed).
            let version = loaded
                .frameworks
                .get(fw)
                .map(|m| json_str(&m.version))
                .unwrap_or_else(|| "null".to_owned());
            let perms: Vec<String> = compiled
                .permissions
                .iter()
                .map(|perm| {
                    let perm_id = &perm.resolved.id;
                    let polar = loaded.controls_for(perm_id, fw);
                    let mapped = !polar.is_empty();
                    let satisfies_json: Vec<String> = polar.satisfies.iter().map(|c| json_str(c)).collect();
                    let risk_json: Vec<String> = polar.risk.iter().map(|c| json_str(c)).collect();
                    let related_json: Vec<String> = polar.related.iter().map(|c| json_str(c)).collect();
                    let prov_json: Vec<String> = provenance_for(loaded, fw, perm_id)
                        .iter()
                        .map(|p| {
                            format!(
                                "{{\"layer\":{},\"path\":{}}}",
                                p.layer.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
                                json_str(&p.path.display().to_string()),
                            )
                        })
                        .collect();
                    format!(
                        "{{\"permission\":{},\"satisfies\":[{}],\"risk\":[{}],\"related\":[{}],\"mapped\":{},\"provenance\":[{}]}}",
                        json_str(perm_id),
                        satisfies_json.join(","),
                        risk_json.join(","),
                        related_json.join(","),
                        mapped,
                        prov_json.join(","),
                    )
                })
                .collect();
            format!(
                "{{\"id\":{},\"version\":{},\"permissions\":[{}]}}",
                json_str(fw),
                version,
                perms.join(","),
            )
        })
        .collect();
    out.push_str(&fws.join(","));
    out.push_str("]}");
    out.push('\n');
    out
}

/// Render a compiled role's permission ids as a minimal JSON object (no framework
/// block). Used by `census show --format json` WITHOUT `--framework`: no
/// framework was requested, so there is no version stamp and no `frameworks`
/// array — just the role and its permission ids. Pure / unit-testable.
pub fn render_show_permissions_json(compiled: &CompiledRole) -> String {
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!("\"role\":{},", json_str(&compiled.role)));
    out.push_str("\"permissions\":[");
    let perms: Vec<String> = compiled
        .permissions
        .iter()
        .map(|p| json_str(&p.resolved.id))
        .collect();
    out.push_str(&perms.join(","));
    out.push_str("]}");
    out.push('\n');
    out
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
        for g in &r.file_grants {
            let recursive = if g.recursive { " recursive" } else { "" };
            let via = g.sources.iter().find_map(|src| src.via.as_deref());
            out.push_str(&format!(
                "    file {} {}{} via {}{}\n",
                g.path,
                access_token(g.access),
                recursive,
                backend_for_shape(g.shape),
                match via {
                    Some(m) if m != r.id => format!(" (via {m})"),
                    _ => String::new(),
                },
            ));
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

// ============================================================================
// framework subcommand (read-only compliance cross-reference)
//
// `census framework {list,show,coverage}` surface the loaded framework tree:
// list installed frameworks, show one framework's controls + coverage stats, and
// the coverage gap-oracle (owned controls with no mapping). All strictly
// read-only metadata — they never touch compile/plan/apply. Each run_* loads the
// frameworks (resolving os-layered ones against the detected OS target) and
// delegates the output to a pure render helper.
// ============================================================================

/// Load the framework tree for a `framework` subcommand: resolve the OS target
/// (for os-layered frameworks) and call `load_frameworks`. Emits forward-compat
/// warnings to stderr. Returns the loaded set or an exit-failing error already
/// printed to stderr.
fn load_frameworks_for_cli(
    framework_roots: &[PathBuf],
    os_target: Option<String>,
) -> Result<LoadedFrameworks, ExitCode> {
    let os = match detect_os_target(os_target.as_deref()) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("census: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    match framework::load_frameworks(framework_roots, &os) {
        Ok(loaded) => {
            for w in &loaded.warnings {
                eprintln!("census: warning: {w}");
            }
            Ok(loaded)
        }
        Err(e) => {
            eprintln!("census: {e}");
            Err(ExitCode::FAILURE)
        }
    }
}

/// Run `census framework list`: enumerate installed frameworks with their version
/// and advertised `provides`. Always exits 0 (a query). Read-only.
pub fn run_framework_list(
    framework_roots: Vec<PathBuf>,
    os_target: Option<String>,
    json: bool,
) -> ExitCode {
    let loaded = match load_frameworks_for_cli(&framework_roots, os_target) {
        Ok(l) => l,
        Err(code) => return code,
    };
    if json {
        print!("{}", render_framework_list_json(&loaded));
    } else {
        print!("{}", render_framework_list_human(&loaded));
    }
    ExitCode::SUCCESS
}

/// Render the framework list (human form): one line per installed framework with
/// its id, version, title and `provides` tags. An empty tree reports
/// "no frameworks installed". Pure / unit-testable.
pub fn render_framework_list_human(loaded: &LoadedFrameworks) -> String {
    let mut out = String::new();
    if loaded.frameworks.is_empty() {
        out.push_str("no frameworks installed\n");
        return out;
    }
    out.push_str("frameworks:\n");
    for (id, m) in &loaded.frameworks {
        let provides = if m.provides.is_empty() {
            "-".to_owned()
        } else {
            m.provides.join(", ")
        };
        out.push_str(&format!(
            "  {} {} — {} [provides: {}]\n",
            id, m.version, m.title, provides
        ));
    }
    out
}

/// Render the framework list as JSON (hand-rolled). Each entry carries id,
/// version, title and the `provides` array. An empty tree yields an empty array.
/// Pure / unit-testable.
pub fn render_framework_list_json(loaded: &LoadedFrameworks) -> String {
    let mut out = String::new();
    out.push_str("{\"frameworks\":[");
    let items: Vec<String> = loaded
        .frameworks
        .iter()
        .map(|(id, m)| {
            let provides: Vec<String> = m.provides.iter().map(|p| json_str(p)).collect();
            format!(
                "{{\"id\":{},\"version\":{},\"title\":{},\"provides\":[{}]}}",
                json_str(id),
                json_str(&m.version),
                json_str(&m.title),
                provides.join(","),
            )
        })
        .collect();
    out.push_str(&items.join(","));
    out.push_str("]}");
    out.push('\n');
    out
}

/// Run `census framework lint`: load the framework cross-reference layer and
/// report integrity findings (orphaned mappings, provides/files desync, unknown
/// control dimension, id collision). The known-permission set is built from the
/// catalog so an orphaned mapping (a permission id absent from the catalog) is
/// detected. Read-only. Exit FAILURE iff any finding is an ERROR (only the
/// determinism-breaking id collision), else SUCCESS — warnings never gate.
pub fn run_framework_lint(
    framework_roots: Vec<PathBuf>,
    catalog_roots: Vec<PathBuf>,
    os_target: Option<String>,
    json: bool,
) -> ExitCode {
    let os = match detect_os_target(os_target.as_deref()) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Build the set of known catalog permission ids a mapping is validated
    // against. A catalog read failure is a hard error (we cannot tell orphaned
    // from valid without it).
    let catalog = LiveCatalog::new(catalog_roots);
    let known: std::collections::BTreeSet<String> = match catalog.all_definitions(&os) {
        Ok(defs) => defs.into_iter().map(|(_, def)| def.id).collect(),
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Load the framework tree directly (not via load_frameworks_for_cli) so the
    // determinism IdCollision error can be turned into a reported Error finding
    // rather than a bare process failure.
    let findings = match framework::load_frameworks(&framework_roots, &os) {
        Ok(loaded) => {
            for w in &loaded.warnings {
                eprintln!("census: warning: {w}");
            }
            framework::lint_loaded(&loaded, &known)
        }
        Err(framework::FrameworkError::IdCollision { id }) => {
            // The one determinism Error the lint surface REPORTS (not aborts on):
            // a duplicate framework id across roots makes the loaded set depend on
            // read order. Surface it as an Error finding and render normally.
            vec![framework::FrameworkLint {
                code: "id-collision",
                severity: framework::FrameworkLintSeverity::Error,
                message: format!("framework id {id} declared in two roots (determinism)"),
            }]
        }
        Err(e) => {
            // A malformed/unreadable framework file is a hard error, not a lint
            // finding — fail closed.
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };

    if json {
        print!("{}", render_framework_lint_json(&findings));
    } else {
        print!("{}", render_framework_lint_human(&findings));
    }

    if findings
        .iter()
        .any(|f| f.severity == framework::FrameworkLintSeverity::Error)
    {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Render framework lint findings (human form): one line per finding as
/// `{TAG} [{code}] {message}` (TAG is `ERROR`/`WARNING`), or a single
/// "no findings" line when empty. Pure / unit-testable.
pub fn render_framework_lint_human(findings: &[framework::FrameworkLint]) -> String {
    if findings.is_empty() {
        return "framework lint: no findings\n".to_owned();
    }
    let mut out = String::new();
    for f in findings {
        let tag = match f.severity {
            framework::FrameworkLintSeverity::Warning => "WARNING",
            framework::FrameworkLintSeverity::Error => "ERROR",
        };
        out.push_str(&format!("{} [{}] {}\n", tag, f.code, f.message));
    }
    out
}

/// Render framework lint findings as JSON (hand-rolled, no serde_json):
/// `{"findings":[{"code":..,"severity":"warning"|"error","message":..}, ...]}`.
/// Pure / unit-testable.
pub fn render_framework_lint_json(findings: &[framework::FrameworkLint]) -> String {
    let mut out = String::new();
    out.push_str("{\"findings\":[");
    let items: Vec<String> = findings
        .iter()
        .map(|f| {
            let severity = match f.severity {
                framework::FrameworkLintSeverity::Warning => "warning",
                framework::FrameworkLintSeverity::Error => "error",
            };
            format!(
                "{{\"code\":{},\"severity\":{},\"message\":{}}}",
                json_str(f.code),
                json_str(severity),
                json_str(&f.message),
            )
        })
        .collect();
    out.push_str(&items.join(","));
    out.push_str("]}");
    out.push('\n');
    out
}

/// The set of control ids covered by at least one **satisfies** mapping in
/// framework `fw`: the controls any mapping addresses (satisfies-polarity).
/// Empty when the framework has no satisfies mappings (or is absent).
fn covered_controls(loaded: &LoadedFrameworks, fw: &str) -> Vec<String> {
    loaded.satisfied_controls(fw)
}

/// Run `census framework show <fw>`: list the framework's controls (id, title,
/// owned, domain) plus coverage statistics (owned total / covered / uncovered).
/// A framework id that is not installed is an error (FAILURE). Read-only.
pub fn run_framework_show(
    fw: &str,
    framework_roots: Vec<PathBuf>,
    os_target: Option<String>,
    json: bool,
) -> ExitCode {
    let loaded = match load_frameworks_for_cli(&framework_roots, os_target) {
        Ok(l) => l,
        Err(code) => return code,
    };
    if !loaded.frameworks.contains_key(fw) {
        eprintln!("census: framework {fw} not installed");
        return ExitCode::FAILURE;
    }
    if json {
        print!("{}", render_framework_show_json(fw, &loaded));
    } else {
        print!("{}", render_framework_show_human(fw, &loaded));
    }
    ExitCode::SUCCESS
}

/// Coverage statistics for one framework: how many *owned* controls there are and
/// how many of them are covered by a mapping (vs left as a gap).
struct OwnedCoverageStats {
    owned_total: usize,
    owned_covered: usize,
    owned_uncovered: usize,
}

/// Compute owned-control coverage stats for framework `fw`: of the controls
/// flagged `owned = true`, how many appear in at least one mapping (covered) and
/// how many do not (the gap). Out-of-domain (`owned = false`) controls are not
/// counted here — they are surfaced separately by the coverage report.
fn owned_coverage_stats(loaded: &LoadedFrameworks, fw: &str) -> OwnedCoverageStats {
    let covered = covered_controls(loaded, fw);
    let defs = loaded.controls.get(fw);
    let owned_ids: Vec<&String> = defs
        .map(|d| d.iter().filter(|(_, c)| c.owned).map(|(id, _)| id).collect())
        .unwrap_or_default();
    let owned_total = owned_ids.len();
    let owned_covered = owned_ids
        .iter()
        .filter(|id| covered.iter().any(|c| &c == *id))
        .count();
    OwnedCoverageStats {
        owned_total,
        owned_covered,
        owned_uncovered: owned_total - owned_covered,
    }
}

/// Render `framework show` (human form): the version stamp, every control
/// definition (id, owned flag, optional domain, title), and the owned-coverage
/// statistics line. Pure / unit-testable.
pub fn render_framework_show_human(fw: &str, loaded: &LoadedFrameworks) -> String {
    let mut out = String::new();
    // Caller guarantees the framework is loaded; fall back gracefully regardless.
    let version = loaded
        .frameworks
        .get(fw)
        .map(|m| m.version.as_str())
        .unwrap_or("?");
    out.push_str(&format!("framework {fw} ({version})\n"));
    let covered = covered_controls(loaded, fw);
    out.push_str("controls:\n");
    match loaded.controls.get(fw) {
        Some(defs) if !defs.is_empty() => {
            for (id, def) in defs {
                let owned = if def.owned { "owned" } else { "inherited" };
                let domain = def.domain.as_deref().map(|d| format!(" {{{d}}}")).unwrap_or_default();
                let cov = if covered.iter().any(|c| c == id) { "covered" } else { "uncovered" };
                out.push_str(&format!("  {id} [{owned}] [{cov}]{domain} — {}\n", def.title));
            }
        }
        _ => out.push_str("  (no control definitions)\n"),
    }
    let stats = owned_coverage_stats(loaded, fw);
    out.push_str(&format!(
        "coverage: {}/{} owned controls covered ({} uncovered)\n",
        stats.owned_covered, stats.owned_total, stats.owned_uncovered,
    ));
    out
}

/// Render `framework show` as JSON (hand-rolled). Includes the id+version stamp,
/// a `controls` array (id/title/owned/domain/covered) and a `coverage` object
/// with owned totals. Pure / unit-testable.
pub fn render_framework_show_json(fw: &str, loaded: &LoadedFrameworks) -> String {
    let version = loaded
        .frameworks
        .get(fw)
        .map(|m| json_str(&m.version))
        .unwrap_or_else(|| "null".to_owned());
    let covered = covered_controls(loaded, fw);
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!("\"id\":{},\"version\":{},", json_str(fw), version));
    out.push_str("\"controls\":[");
    let controls: Vec<String> = loaded
        .controls
        .get(fw)
        .map(|defs| {
            defs.iter()
                .map(|(id, def)| {
                    format!(
                        "{{\"id\":{},\"title\":{},\"owned\":{},\"domain\":{},\"covered\":{}}}",
                        json_str(id),
                        json_str(&def.title),
                        def.owned,
                        def.domain.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
                        covered.iter().any(|c| c == id),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    out.push_str(&controls.join(","));
    out.push_str("],");
    let stats = owned_coverage_stats(loaded, fw);
    out.push_str(&format!(
        "\"coverage\":{{\"owned_total\":{},\"owned_covered\":{},\"owned_uncovered\":{}}}}}",
        stats.owned_total, stats.owned_covered, stats.owned_uncovered,
    ));
    out.push('\n');
    out
}

/// The computed coverage gap for a framework: which owned controls are covered by
/// a mapping, which owned controls are a gap (uncovered), and which controls are
/// out-of-domain (`owned = false`, surfaced separately and never counted as a
/// gap). All vectors are sorted (BTreeMap-derived) for deterministic output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkCoverage {
    /// Owned controls that appear in at least one mapping.
    pub covered: Vec<String>,
    /// Owned controls with no mapping — the gap a reviewer must close.
    pub gap: Vec<String>,
    /// Controls flagged `owned = false`: inherited / out of the org's scope.
    /// Listed for visibility, never counted in the gap.
    pub out_of_domain: Vec<String>,
}

/// Compute the coverage gap for framework `fw`.
///
///   * `covered` = owned controls present in some mapping (`reverse[fw]` keys).
///   * `gap`     = owned controls MINUS covered.
///   * `out_of_domain` = controls with `owned = false` (surfaced separately).
///
/// Coverage is judged only over controls that have a `controls.toml` definition
/// (the org's declared scope). A control referenced by a mapping but never
/// defined contributes nothing here (it cannot be "owned"); it simply is not in
/// the owned/gap/out-of-domain partition. Pure / unit-testable.
pub fn compute_framework_coverage(loaded: &LoadedFrameworks, fw: &str) -> FrameworkCoverage {
    let covered_set = covered_controls(loaded, fw);
    let mut covered = Vec::new();
    let mut gap = Vec::new();
    let mut out_of_domain = Vec::new();
    if let Some(defs) = loaded.controls.get(fw) {
        // BTreeMap iteration is sorted → deterministic output.
        for (id, def) in defs {
            if !def.owned {
                out_of_domain.push(id.clone());
            } else if covered_set.iter().any(|c| c == id) {
                covered.push(id.clone());
            } else {
                gap.push(id.clone());
            }
        }
    }
    FrameworkCoverage { covered, gap, out_of_domain }
}

/// Run `census framework coverage <fw>`: the gap oracle. Reports the framework's
/// owned controls that no mapping covers (plus the covered and out-of-domain
/// sets). A framework id that is not installed is an error (FAILURE). Read-only.
pub fn run_framework_coverage(
    fw: &str,
    framework_roots: Vec<PathBuf>,
    os_target: Option<String>,
    json: bool,
) -> ExitCode {
    let loaded = match load_frameworks_for_cli(&framework_roots, os_target) {
        Ok(l) => l,
        Err(code) => return code,
    };
    if !loaded.frameworks.contains_key(fw) {
        eprintln!("census: framework {fw} not installed");
        return ExitCode::FAILURE;
    }
    let coverage = compute_framework_coverage(&loaded, fw);
    if json {
        print!("{}", render_framework_coverage_json(fw, &loaded, &coverage));
    } else {
        print!("{}", render_framework_coverage_human(fw, &loaded, &coverage));
    }
    ExitCode::SUCCESS
}

/// Render `framework coverage` (human form): the version stamp, the gap list
/// (owned-uncovered controls — the actionable output), the covered list, and the
/// out-of-domain list. Pure / unit-testable.
pub fn render_framework_coverage_human(
    fw: &str,
    loaded: &LoadedFrameworks,
    coverage: &FrameworkCoverage,
) -> String {
    let version = loaded
        .frameworks
        .get(fw)
        .map(|m| m.version.as_str())
        .unwrap_or("?");
    let mut out = String::new();
    out.push_str(&format!("framework {fw} ({version})\n"));
    out.push_str(&format!(
        "gap: {} owned control(s) with no mapping\n",
        coverage.gap.len()
    ));
    if coverage.gap.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for id in &coverage.gap {
            out.push_str(&format!("  {id}\n"));
        }
    }
    out.push_str(&format!("covered: {}\n", coverage.covered.len()));
    for id in &coverage.covered {
        out.push_str(&format!("  {id}\n"));
    }
    out.push_str(&format!("out-of-domain (not counted): {}\n", coverage.out_of_domain.len()));
    for id in &coverage.out_of_domain {
        out.push_str(&format!("  {id}\n"));
    }
    out
}

/// Render `framework coverage` as JSON (hand-rolled). Includes the id+version
/// stamp plus `covered`, `gap`/`uncovered`, and `out_of_domain` arrays. Pure /
/// unit-testable.
pub fn render_framework_coverage_json(
    fw: &str,
    loaded: &LoadedFrameworks,
    coverage: &FrameworkCoverage,
) -> String {
    let version = loaded
        .frameworks
        .get(fw)
        .map(|m| json_str(&m.version))
        .unwrap_or_else(|| "null".to_owned());
    let arr = |v: &[String]| -> String {
        v.iter().map(|s| json_str(s)).collect::<Vec<_>>().join(",")
    };
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!("\"id\":{},\"version\":{},", json_str(fw), version));
    out.push_str(&format!("\"covered\":[{}],", arr(&coverage.covered)));
    // `gap` and `uncovered` are the same set (the actionable owned-uncovered
    // controls); both keys are emitted so either consumer name works.
    out.push_str(&format!("\"gap\":[{}],", arr(&coverage.gap)));
    out.push_str(&format!("\"uncovered\":[{}],", arr(&coverage.gap)));
    out.push_str(&format!("\"out_of_domain\":[{}]", arr(&coverage.out_of_domain)));
    out.push('}');
    out.push('\n');
    out
}

/// The controls under risk in a framework: each control with at least one `risk`
/// link, and the permission ids that threaten it. NOT filtered by `owned` — a
/// threat to an out-of-domain control is still significant (Census does not cover
/// it, but the capability can still undermine it). Sorted by control id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkRisk {
    /// `(control-id, [threatening permission ids])` pairs, sorted by control id.
    pub controls: Vec<(String, Vec<String>)>,
}

/// Compute the risk view for framework `fw`: every control with a `risk`-polarity
/// link and the permissions that threaten it, regardless of `owned`. Pure /
/// unit-testable.
pub fn compute_framework_risk(loaded: &LoadedFrameworks, fw: &str) -> FrameworkRisk {
    FrameworkRisk { controls: loaded.risk_controls(fw) }
}

/// Run `census framework risk <fw>`: list controls under threat (≥1 risk link)
/// and the permissions that undermine them. A framework id not installed is an
/// error (FAILURE). Read-only.
pub fn run_framework_risk(
    fw: &str,
    framework_roots: Vec<PathBuf>,
    os_target: Option<String>,
    json: bool,
) -> ExitCode {
    let loaded = match load_frameworks_for_cli(&framework_roots, os_target) {
        Ok(l) => l,
        Err(code) => return code,
    };
    if !loaded.frameworks.contains_key(fw) {
        eprintln!("census: framework {fw} not installed");
        return ExitCode::FAILURE;
    }
    let risk = compute_framework_risk(&loaded, fw);
    if json {
        print!("{}", render_framework_risk_json(fw, &loaded, &risk));
    } else {
        print!("{}", render_framework_risk_human(fw, &loaded, &risk));
    }
    ExitCode::SUCCESS
}

/// Render `framework risk` (human form): the version stamp, then each control
/// under threat with its title (when defined), an out-of-domain marker when the
/// control is `owned = false`, and the threatening permissions. Pure.
pub fn render_framework_risk_human(
    fw: &str,
    loaded: &LoadedFrameworks,
    risk: &FrameworkRisk,
) -> String {
    let version = loaded.frameworks.get(fw).map(|m| m.version.as_str()).unwrap_or("?");
    let defs = loaded.controls.get(fw);
    let mut out = String::new();
    out.push_str(&format!("framework {fw} ({version})\n"));
    out.push_str(&format!("controls under risk: {}\n", risk.controls.len()));
    if risk.controls.is_empty() {
        out.push_str("  (none)\n");
        return out;
    }
    for (ctrl, perms) in &risk.controls {
        let def = defs.and_then(|d| d.get(ctrl));
        let domain = match def {
            Some(d) if !d.owned => " [out-of-domain]",
            _ => "",
        };
        let title = def.map(|d| format!(" — {}", d.title)).unwrap_or_default();
        out.push_str(&format!("  ⚠ {ctrl}{domain}{title}\n"));
        out.push_str(&format!("    threatened by: {}\n", perms.join(", ")));
    }
    out
}

/// Render `framework risk` as JSON (hand-rolled). Carries the id+version stamp and
/// a `controls` array of `{id, owned, threatened_by:[perm...]}`. `owned` is null
/// when the control has no controls.toml definition. Pure.
pub fn render_framework_risk_json(
    fw: &str,
    loaded: &LoadedFrameworks,
    risk: &FrameworkRisk,
) -> String {
    let version = loaded.frameworks.get(fw).map(|m| json_str(&m.version)).unwrap_or_else(|| "null".to_owned());
    let defs = loaded.controls.get(fw);
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!("\"id\":{},\"version\":{},", json_str(fw), version));
    out.push_str("\"controls\":[");
    let items: Vec<String> = risk
        .controls
        .iter()
        .map(|(ctrl, perms)| {
            let owned = defs
                .and_then(|d| d.get(ctrl))
                .map(|d| d.owned.to_string())
                .unwrap_or_else(|| "null".to_owned());
            let by: Vec<String> = perms.iter().map(|p| json_str(p)).collect();
            format!(
                "{{\"id\":{},\"owned\":{},\"threatened_by\":[{}]}}",
                json_str(ctrl),
                owned,
                by.join(","),
            )
        })
        .collect();
    out.push_str(&items.join(","));
    out.push_str("]}");
    out.push('\n');
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
// catalog coverage (read-only audit)
//
// Enumerates the device's live privileged surface (`LiveSurface`) and reports
// what the installed catalog does NOT cover. Strictly read-only: it never runs
// the enumerated binaries, never reads config content, and never mutates. The
// pure coverage core (`coverage::coverage`) does the matching; this CLI layer
// only builds inputs, renders the report, and decides the `--min-coverage` exit.
// ============================================================================

/// Options for `census catalog coverage` (CLI-derived).
pub struct CoverageOpts {
    /// Emit machine-readable JSON instead of the human view.
    pub json: bool,
    /// `--os-target family-distro-version` override; autodetects when `None`.
    pub os_target: Option<String>,
    /// Catalog roots in precedence order (lowest first).
    pub catalog_roots: Vec<PathBuf>,
    /// Optional role-store dir whose roles are resolved into concrete instances
    /// (so parametrized permissions contribute named units/paths).
    pub roles: Option<PathBuf>,
    /// Optional declaration whose `[[role_group]]` bindings are resolved so a
    /// `group` object with a bound grant is counted covered. `None` means no
    /// binding-covered groups are folded in (membership coverage only).
    pub declaration: Option<PathBuf>,
    /// `--strict`: a parametrized record without a role instance does NOT cover.
    pub strict: bool,
    /// Surface classes to scan; empty means all classes.
    pub classes: Vec<SurfaceClass>,
    /// `--min-coverage <pct>`: non-zero exit when overall coverage is below this.
    pub min_coverage: Option<f64>,
    /// `--include-low-priority`: include low-priority objects in the human report
    /// (currently a presentation toggle; the metric is unaffected).
    pub include_low_priority: bool,
    /// `--cache`: accepted for forward-compat; caching is not yet implemented, so
    /// the flag is a no-op (a fresh scan runs every time).
    pub cache: bool,
}

/// Parse a `--class a,b,c` value into surface classes. An unknown token is an
/// error (fail closed rather than silently scanning fewer classes than asked).
pub fn parse_classes(spec: &str) -> Result<Vec<SurfaceClass>, String> {
    let mut out: Vec<SurfaceClass> = Vec::new();
    for tok in spec.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        let class = match tok {
            "sudo_bin" => SurfaceClass::SudoBin,
            "config" => SurfaceClass::Config,
            "unit" => SurfaceClass::Unit,
            "group" => SurfaceClass::Group,
            "capfile" => SurfaceClass::CapFile,
            "setuid" => SurfaceClass::Setuid,
            other => return Err(format!("unknown surface class '{other}'")),
        };
        if !out.contains(&class) {
            out.push(class);
        }
    }
    Ok(out)
}

/// The full set of surface classes, used when `--class` is not given.
fn all_classes() -> Vec<SurfaceClass> {
    vec![
        SurfaceClass::SudoBin,
        SurfaceClass::Config,
        SurfaceClass::Unit,
        SurfaceClass::Group,
        SurfaceClass::CapFile,
        SurfaceClass::Setuid,
    ]
}

/// Resolve every role slice under `roles_dir` into a `ResolvedRole` (concrete
/// expanded sudo + groups). Each role's permissions are expanded with their
/// declared params via `resolve_with_params`, so a parametrized record
/// (`service-restart units=[…]`) contributes concrete commands. A role that fails
/// to resolve is surfaced as a warning and skipped — a coverage audit should still
/// run over the roles that DO resolve rather than abort on one bad slice.
///
/// `catalog_roots` MUST be the same roots the main coverage pass uses (including
/// any `--catalog-dir` site overrides). A role may reference a permission defined
/// only in a site catalog; resolving roles against the bare defaults would fail
/// to expand it and under-contribute coverage.
fn resolve_roles(
    roles_dir: &Path,
    catalog_roots: &[PathBuf],
    os: &OsTarget,
    ctx: &ResolveCtx,
) -> Vec<ResolvedRole> {
    let catalog = LiveCatalog::new(catalog_roots.to_vec());
    let mut out: Vec<ResolvedRole> = Vec::new();
    let entries = match std::fs::read_dir(roles_dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("census: warning: cannot read roles dir {}: {e}", roles_dir.display());
            return out;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let role = match path.file_stem().and_then(|s| s.to_str()) {
            Some(r) => r,
            None => continue,
        };
        let comp = match rolestore::read_composition(roles_dir, role) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("census: warning: role {role}: {e}");
                continue;
            }
        };
        // A raw sudo_role names a sudoers alias, not a concrete binary, so it
        // contributes no command token and is intentionally not folded in; raw
        // groups DO gate-keep, so they seed the role's covered groups.
        let mut sudo: Vec<String> = Vec::new();
        let mut groups: Vec<String> = comp.groups.clone();
        let mut file_grants: Vec<catalog::ResolvedFileGrant> = Vec::new();
        for perm in &comp.permissions {
            match catalog::resolve_with_params(&perm.id, &perm.params, os, &catalog, ctx) {
                Ok((resolved, _warnings)) => {
                    for p in &resolved.sudo {
                        sudo.push(p.value.clone());
                    }
                    for p in &resolved.groups {
                        groups.push(p.value.clone());
                    }
                    // A parametrized config-edit grant only becomes a concrete path
                    // once a role supplies its parameter; fold the role-instance's
                    // resolved grants in so a config object under such a grant is
                    // counted covered (with the backend note) in the audit.
                    file_grants.extend(resolved.file_grants);
                }
                Err(e) => {
                    eprintln!("census: warning: role {role} permission {}: {e}", perm.id);
                }
            }
        }
        out.push(ResolvedRole::with_file_grants(sudo, groups, file_grants));
    }
    out
}

/// Map overall coverage and an optional `--min-coverage` threshold to an exit
/// code. Without a threshold the audit is read-only and always succeeds (0). With
/// a threshold, coverage below it exits 4 (a distinct CI-gate failure, separate
/// from a scan/catalog error which exits `FAILURE`==1). Pure so the policy is
/// unit-testable.
fn coverage_exit_code(overall_pct: f64, min: Option<f64>) -> ExitCode {
    match min {
        Some(threshold) if overall_pct < threshold => ExitCode::from(4),
        _ => ExitCode::SUCCESS,
    }
}

/// Render a coverage report as a human-readable audit. Pure (report in, string
/// out) so the output shape is unit-testable from a hand-built report.
pub fn render_coverage_human(report: &CoverageReport, include_low_priority: bool) -> String {
    // `include_low_priority` is applied upstream in `coverage_scoped` (it changes
    // which config objects are in the report at all); here it only annotates the
    // header so the reader knows which denominator they are looking at.
    let mut out = String::new();
    out.push_str(&format!(
        "coverage for {} (catalog {}){}\n",
        if report.os_target.is_empty() { "unknown" } else { &report.os_target },
        report.catalog_version.as_deref().unwrap_or("unknown"),
        if include_low_priority { " [incl. low-priority config]" } else { "" },
    ));

    // Per-class summary.
    out.push_str("by class:\n");
    for c in &report.by_class {
        out.push_str(&format!(
            "  {:<9} {}/{} ({:.1}%)\n",
            c.class.as_str(),
            c.covered,
            c.total,
            c.pct(),
        ));
    }
    out.push_str(&format!("overall: {:.1}%\n", report.overall_pct));

    // Covered objects that carry a HOW note (config via file grants): surface the
    // backend/guarantee so the operator can see which grant enforces each config.
    let noted: Vec<_> = report
        .objects
        .iter()
        .filter(|o| o.covered && o.coverage_note.is_some())
        .collect();
    if !noted.is_empty() {
        out.push_str("covered via file grants:\n");
        for o in &noted {
            out.push_str(&format!(
                "  [{}] {} — {}\n",
                o.object.class.as_str(),
                o.object.key,
                o.coverage_note.as_deref().unwrap_or(""),
            ));
        }
    }

    // Uncovered objects (honest gaps) grouped by class, with a suggestion.
    let gaps: Vec<_> = report
        .objects
        .iter()
        .filter(|o| {
            !o.covered && o.intentional_exclusion.is_none() && o.backend_limited.is_none()
        })
        .collect();
    out.push_str("uncovered:\n");
    if gaps.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for o in &gaps {
            let suggestion = o
                .suggested_permission
                .as_deref()
                .map(|s| format!(" → suggested: {s}"))
                .unwrap_or_default();
            out.push_str(&format!(
                "  [{}] {}{}\n",
                o.object.class.as_str(),
                o.object.key,
                suggestion,
            ));
        }
    }

    // Intentionally-uncovered, each with its reason (does not penalise the metric).
    let intentional: Vec<_> = report
        .objects
        .iter()
        .filter(|o| o.intentional_exclusion.is_some())
        .collect();
    if !intentional.is_empty() {
        out.push_str("intentionally uncovered:\n");
        for o in &intentional {
            out.push_str(&format!(
                "  [{}] {} — {}\n",
                o.object.class.as_str(),
                o.object.key,
                o.intentional_exclusion.as_deref().unwrap_or(""),
            ));
        }
    }

    // Backend-limited: objects the free dir-only backend cannot enforce without an
    // over-broad grant (a single file in a non-grantable parent). Reported in their
    // own section so they are visible but clearly NOT counted as gaps — distinct
    // from "intentionally uncovered" (out of scope) and from a real gap (fixable
    // with a grant). A per-file-capable backend would cover these.
    let backend_limited: Vec<_> = report
        .objects
        .iter()
        .filter(|o| o.backend_limited.is_some())
        .collect();
    if !backend_limited.is_empty() {
        out.push_str("backend-limited (requires per-file backend):\n");
        for o in &backend_limited {
            out.push_str(&format!(
                "  [{}] {} — {}\n",
                o.object.class.as_str(),
                o.object.key,
                o.backend_limited.as_deref().unwrap_or(""),
            ));
        }
    }

    // Anomalies (orphan setuid / orphan capfile) — investigate, separate from gaps.
    if !report.anomalies.is_empty() {
        out.push_str("anomalies (investigate):\n");
        for a in &report.anomalies {
            out.push_str(&format!("  [{}] {} ({})\n", a.class.as_str(), a.key, a.detail));
        }
    }

    out
}

/// Provenance as a stable lowercase token for JSON output.
fn provenance_json(p: &coverage::Provenance) -> String {
    match p {
        coverage::Provenance::Vendor => json_str("vendor"),
        coverage::Provenance::Addon(pkg) => json_str(&format!("addon:{pkg}")),
        coverage::Provenance::Orphan => json_str("orphan"),
    }
}

/// Render a coverage report as machine-readable JSON: an `objects` array of
/// per-object verdicts plus a `summary` object. Hand-rolled over the `json_str`
/// escaper (no serde_json dep), matching the `compile --json` style. Pure.
pub fn render_coverage_json(report: &CoverageReport) -> String {
    let mut out = String::new();
    out.push('{');

    out.push_str("\"objects\":[");
    let objs: Vec<String> = report
        .objects
        .iter()
        .map(|o| {
            format!(
                "{{\"class\":{},\"key\":{},\"covered\":{},\"provenance\":{},\"suggested_permission\":{},\"intentional_exclusion\":{},\"backend_limited\":{},\"coverage_note\":{}}}",
                json_str(o.object.class.as_str()),
                json_str(&o.object.key),
                o.covered,
                provenance_json(&o.object.provenance),
                o.suggested_permission.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
                o.intentional_exclusion.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
                o.backend_limited.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
                o.coverage_note.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
            )
        })
        .collect();
    out.push_str(&objs.join(","));
    out.push_str("],");

    // Anomalies array (orphan setuid/capfile) for the machine consumer.
    out.push_str("\"anomalies\":[");
    let anoms: Vec<String> = report
        .anomalies
        .iter()
        .map(|a| {
            format!(
                "{{\"class\":{},\"key\":{},\"provenance\":{}}}",
                json_str(a.class.as_str()),
                json_str(&a.key),
                provenance_json(&a.provenance),
            )
        })
        .collect();
    out.push_str(&anoms.join(","));
    out.push_str("],");

    // Summary: per-class counts, overall, catalog version, os target.
    out.push_str("\"summary\":{\"by_class\":[");
    let by: Vec<String> = report
        .by_class
        .iter()
        .map(|c| {
            format!(
                "{{\"class\":{},\"covered\":{},\"total\":{},\"pct\":{:.1}}}",
                json_str(c.class.as_str()),
                c.covered,
                c.total,
                c.pct(),
            )
        })
        .collect();
    out.push_str(&by.join(","));
    let warnings: Vec<String> = report.catalog_warnings.iter().map(|w| json_str(w)).collect();
    out.push_str(&format!(
        "],\"overall_pct\":{:.1},\"catalog_version\":{},\"os_target\":{},\"catalog_warnings\":[{}]}}",
        report.overall_pct,
        report.catalog_version.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
        json_str(&report.os_target),
        warnings.join(","),
    ));

    out.push('}');
    out.push('\n');
    out
}

/// Run `census catalog coverage`: enumerate the live privileged surface, compute
/// coverage against the installed catalog (+ optional roles), print the report
/// (human or JSON), and exit per `--min-coverage`. Read-only — never mutates.
pub fn run_coverage(opts: CoverageOpts) -> ExitCode {
    let os = match detect_os_target(opts.os_target.as_deref()) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let catalog = LiveCatalog::new(opts.catalog_roots.clone());

    // Catalog version is echoed into the report for the audit trail. We do not have
    // a separate version source here, so it is left unset unless the catalog
    // carries one through resolve (the report records what resolve saw).
    let ctx = ResolveCtx { catalog_version: None };

    let roles = match &opts.roles {
        Some(dir) => resolve_roles(dir, &opts.catalog_roots, &os, &ctx),
        None => Vec::new(),
    };

    // With a declaration, resolve its `[[role_group]]` bindings and collect the
    // names of groups that carry a grant (non-empty sudo and/or file). A `group`
    // surface object for such a group is covered by the binding even when no
    // membership primitive names it. Without a declaration this stays empty
    // (membership coverage only — the original behavior).
    let bound_grant_groups = match &opts.declaration {
        Some(decl_path) => {
            let decl = match read_declaration(decl_path) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("census: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let inputs = CompileInputs { catalog: &catalog, os: &os, ctx: &ctx };
            match model::resolve_groups(&decl, &inputs) {
                Ok((groups, _warnings)) => groups
                    .into_iter()
                    .filter(|g| !g.sudo_commands.is_empty() || !g.file_grants.is_empty())
                    .map(|g| g.name)
                    .collect(),
                Err(e) => {
                    eprintln!("census: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        None => Vec::new(),
    };

    let classes = if opts.classes.is_empty() {
        all_classes()
    } else {
        opts.classes.clone()
    };

    let surface = match LiveSurface::system().scan(&classes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };

    let cov_ctx = CoverageCtx {
        strict: opts.strict,
        catalog_version: ctx.catalog_version.clone(),
        bound_grant_groups,
    };
    let report = match coverage::coverage_scoped(
        &surface,
        &catalog,
        &os,
        &roles,
        &cov_ctx,
        opts.include_low_priority,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };

    // A catalog id that failed to resolve was skipped rather than aborting the
    // audit; surface each as a stderr warning so the gap is visible while the
    // report (on stdout) still covers everything that DID resolve.
    for w in &report.catalog_warnings {
        eprintln!("census: warning: {w}");
    }

    if opts.json {
        print!("{}", render_coverage_json(&report));
    } else {
        print!("{}", render_coverage_human(&report, opts.include_low_priority));
    }

    coverage_exit_code(report.overall_pct, opts.min_coverage)
}

// ============================================================================
// catalog which-grants (reverse lookup; read-only query)
//
// Given a path or command, report which catalog permissions grant access to it
// and how. The inverse of coverage: coverage asks "what surface is uncovered?",
// which-grants asks "what grants THIS object?". Read-only — it resolves the
// catalog, never runs the binary or reads file content, and always exits 0 unless
// the catalog/OS itself cannot be read (even "no grants" is a successful query).
// ============================================================================

/// Options for `census catalog which-grants <arg>`.
pub struct WhichGrantsOpts {
    /// The absolute path or command to look up.
    pub arg: String,
    /// Emit machine-readable JSON instead of the human view.
    pub json: bool,
    /// `--os-target family-distro-version` override; autodetects when `None`.
    pub os_target: Option<String>,
    /// Catalog roots in precedence order (lowest first).
    pub catalog_roots: Vec<PathBuf>,
    /// Optional declaration whose `[[role_group]]` bindings are resolved so group
    /// grants (`via %group sudoers` / `via g:group ACL`) appear in the lookup.
    /// `None` reports account grants only (the original behavior).
    pub declaration: Option<PathBuf>,
}

/// Build the reverse-lookup sources by resolving every catalog permission.
///
/// Each distinct id in `all_definitions` is resolved once; the concrete sudo
/// command strings and file grants become a [`coverage::GrantSource`]. A templated
/// sudo command (one still carrying a `{placeholder}` because no role instance
/// filled it) is SKIPPED — a reverse lookup is over concrete grants the catalog
/// would actually emit, and a literal `{unit}` is not a real command. Likewise a
/// templated file-grant path is skipped. An id that fails to resolve is skipped
/// with a stderr warning (mirroring the coverage audit's warn-and-skip), so one
/// bad record does not sink the whole query.
fn build_grant_sources(
    catalog: &dyn catalog::CatalogSource,
    os: &OsTarget,
    ctx: &ResolveCtx,
) -> Result<Vec<coverage::GrantSource>, CatalogError> {
    let all = catalog.all_definitions(os)?;
    let mut seen: Vec<String> = Vec::new();
    let mut out: Vec<coverage::GrantSource> = Vec::new();
    for (_layer, def) in &all {
        if seen.iter().any(|s| s == &def.id) {
            continue;
        }
        seen.push(def.id.clone());

        match catalog::resolve(&def.id, os, catalog, ctx) {
            Ok((resolved, _warnings)) => {
                // Keep only concrete (non-templated) sudo commands and file grants:
                // an unfilled `{placeholder}` is not a real grant to look up.
                let sudo: Vec<String> = resolved
                    .sudo
                    .iter()
                    .map(|p| p.value.clone())
                    .filter(|c| !has_unfilled_placeholder(c))
                    .collect();
                let file_grants: Vec<catalog::ResolvedFileGrant> = resolved
                    .file_grants
                    .iter()
                    .filter(|g| !has_unfilled_placeholder(&g.path))
                    .cloned()
                    .collect();
                if sudo.is_empty() && file_grants.is_empty() {
                    continue;
                }
                out.push(coverage::GrantSource {
                    id: resolved.id.clone(),
                    target: coverage::GrantTarget::Account(resolved.id),
                    risk: resolved.risk,
                    sudo,
                    file_grants,
                });
            }
            Err(e) => {
                eprintln!("census: warning: catalog permission {} unresolved: {e}", def.id);
            }
        }
    }
    Ok(out)
}

/// Read and parse a declaration TOML, returning a human-readable error string on
/// an I/O or parse failure. Shared by the optional-declaration paths of coverage
/// and which-grants so both report a malformed declaration the same way.
fn read_declaration(path: &Path) -> Result<Declaration, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read declaration {}: {e}", path.display()))?;
    Declaration::parse(&text).map_err(|e| e.to_string())
}

/// Build reverse-lookup sources from a declaration's `[[role_group]]` bindings.
///
/// Each resolved group with non-empty sudo and/or file grants becomes a
/// [`coverage::GrantSource`] tagged `target = Group(name)`, so a sudo command or
/// path reached through the group's `%group` sudoers / `g:group` ACL is reported
/// as a group match. The matching core (sudo prefix / file under-dir) is reused
/// unchanged — only the source set is widened. Group sources carry no per-source
/// risk class (`ResolvedGroup` is an aggregate of several roles' grants, not one
/// catalog permission); file matches still surface their own backend, and the
/// group-escalation surface is flagged by the lint, not the reverse lookup.
///
/// Returns an empty vec when the declaration has no group bindings. A resolve
/// failure is propagated (the caller already warns-and-continues on a soft error
/// elsewhere; here a malformed declaration is a hard read error, consistent with
/// the other declaration-driven commands).
fn build_group_grant_sources(
    decl: &Declaration,
    inputs: &CompileInputs<'_>,
) -> Result<Vec<coverage::GrantSource>, model::ResolveError> {
    let (groups, _warnings) = model::resolve_groups(decl, inputs)?;
    let mut out: Vec<coverage::GrantSource> = Vec::new();
    for g in groups {
        if g.sudo_commands.is_empty() && g.file_grants.is_empty() {
            continue;
        }
        out.push(coverage::GrantSource {
            id: g.name.clone(),
            target: coverage::GrantTarget::Group(g.name),
            risk: None,
            sudo: g.sudo_commands,
            file_grants: g.file_grants,
        });
    }
    Ok(out)
}

/// Whether a string still carries a `{placeholder}` (a templated value that no
/// role instance filled). Such a value is not a concrete grant, so the reverse
/// lookup skips it.
fn has_unfilled_placeholder(s: &str) -> bool {
    if let Some(open) = s.find('{') {
        s[open + 1..].contains('}')
    } else {
        false
    }
}

/// Render reverse-lookup matches as a human-readable report. Pure (matches in,
/// string out) so the output shape is unit-testable.
pub fn render_which_grants_human(arg: &str, matches: &[coverage::GrantMatch]) -> String {
    if matches.is_empty() {
        return format!("no permission grants access to {arg}\n");
    }
    let mut out = format!("{arg} granted by:\n");
    for m in matches {
        match m.kind {
            coverage::GrantKind::Sudo => {
                // Group target → `%group` sudoers (every member inherits); account
                // target → the per-account `sudo` mechanism (unchanged).
                let mechanism = match m.target.group() {
                    Some(g) => format!("via %group sudoers ({g})"),
                    None => "via sudo".to_owned(),
                };
                out.push_str(&format!(
                    "  {} — {}: {} [{}]\n",
                    m.permission,
                    mechanism,
                    m.detail,
                    risk_label(m.risk),
                ));
            }
            coverage::GrantKind::File => {
                let access = m.access.map(access_token).unwrap_or("");
                let recursive = if m.recursive == Some(true) { ", recursive" } else { "" };
                let backend = m.backend.as_deref().unwrap_or("");
                // Group target → `g:group` ACL; account target → the per-account
                // file mechanism (unchanged).
                let mechanism = match m.target.group() {
                    Some(g) => format!("via g:group ACL ({g})"),
                    None => "via file".to_owned(),
                };
                out.push_str(&format!(
                    "  {} — {} ({}): {}{} ({}) [{}]\n",
                    m.permission,
                    mechanism,
                    access,
                    m.detail,
                    recursive,
                    backend,
                    risk_label(m.risk),
                ));
            }
        }
    }
    out
}

/// Render reverse-lookup matches as machine-readable JSON: an array of match
/// objects. Hand-rolled over `json_str`, matching the coverage `--json` style.
/// Pure.
pub fn render_which_grants_json(matches: &[coverage::GrantMatch]) -> String {
    let mut out = String::new();
    out.push('[');
    let items: Vec<String> = matches
        .iter()
        .map(|m| {
            // `target` is `account` or `group`; `group` carries the inheriting
            // group name for a group match (null for an account match).
            let (target_kind, group) = match &m.target {
                coverage::GrantTarget::Account(_) => ("account", "null".to_owned()),
                coverage::GrantTarget::Group(g) => ("group", json_str(g)),
            };
            format!(
                "{{\"permission\":{},\"target\":{},\"group\":{},\"kind\":{},\"detail\":{},\"access\":{},\"recursive\":{},\"backend\":{},\"risk\":{}}}",
                json_str(&m.permission),
                json_str(target_kind),
                group,
                json_str(m.kind.as_str()),
                json_str(&m.detail),
                m.access.map(|a| json_str(access_token(a))).unwrap_or_else(|| "null".to_owned()),
                m.recursive.map(|r| r.to_string()).unwrap_or_else(|| "null".to_owned()),
                m.backend.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
                json_str(risk_label(m.risk)),
            )
        })
        .collect();
    out.push_str(&items.join(","));
    out.push(']');
    out.push('\n');
    out
}

/// Run `census catalog which-grants <arg>`: resolve the catalog, find every
/// permission that grants access to `arg`, print the matches (human or JSON), and
/// exit 0. Read-only — never mutates, never runs the arg. Only a catalog/OS read
/// error exits non-zero; "no grants" is a successful query (exit 0).
pub fn run_which_grants(opts: WhichGrantsOpts) -> ExitCode {
    let os = match detect_os_target(opts.os_target.as_deref()) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let catalog = LiveCatalog::new(opts.catalog_roots.clone());
    let ctx = ResolveCtx { catalog_version: None };

    let mut sources = match build_grant_sources(&catalog, &os, &ctx) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };

    // With a declaration, also fold in group grants from its `[[role_group]]`
    // bindings so a command/path reached through a `%group` sudoers fragment or a
    // `g:group` ACL is reported (with the inheriting group). Without one, only
    // account grants are looked up (the original behavior).
    if let Some(decl_path) = &opts.declaration {
        match read_declaration(decl_path) {
            Ok(decl) => {
                let inputs = CompileInputs { catalog: &catalog, os: &os, ctx: &ctx };
                match build_group_grant_sources(&decl, &inputs) {
                    Ok(group_sources) => sources.extend(group_sources),
                    Err(e) => {
                        eprintln!("census: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            Err(e) => {
                eprintln!("census: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    let matches = coverage::which_grants(&opts.arg, &sources);

    if opts.json {
        print!("{}", render_which_grants_json(&matches));
    } else {
        print!("{}", render_which_grants_human(&opts.arg, &matches));
    }

    // A query always succeeds — even "no grants" is a valid answer (exit 0).
    ExitCode::SUCCESS
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

/// Root-equivalent file paths: write access to any of these is effectively a path
/// to root (a writable sudoers fragment grants arbitrary sudo; a writable PAM/ssh
/// config subverts authentication; a writable PATH bin is run as whoever invokes
/// it). An `rw` grant on one of these (or under a recursive one) is flagged
/// escalation-capable. Curated and documented so the rule is reviewable, not a
/// magic list buried in code.
const ROOT_EQUIVALENT_RW_PREFIXES: &[&str] = &[
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/sudo.conf",
    "/etc/ssh",
    "/etc/pam.d",
    "/etc/polkit-1",
    "/etc/security",
    "/etc/sysctl.d",
    "/etc/sysctl.conf",
    "/etc/modprobe.d",
    "/etc/apparmor.d",
    "/etc/selinux",
    "/etc/systemd",
    // PATH binary directories: a writable executable here runs with the caller's
    // privilege the next time it is invoked (often root via cron/sudo).
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
];

/// Secret file/dir paths: even READ access leaks credentials/keys (password
/// hashes, TLS private keys). An `ro` (or `rw`) grant on one of these — or under
/// a recursive grant that contains it — is flagged. Every entry here is either an
/// exact file (`/etc/shadow`, `/etc/krb5.keytab`) or a real directory
/// (`/etc/ssl/private`), so the component-boundary matcher [`path_boundary_overlaps`]
/// classifies it correctly. SSH host keys live as a FILENAME family
/// (`/etc/ssh/ssh_host_*`), not a directory, so they are matched separately by
/// [`path_is_secret`] (a basename prefix), NOT listed here — a component-boundary
/// test would miss a grant directly on `/etc/ssh/ssh_host_rsa_key`.
const SECRET_PATH_PREFIXES: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/ssl/private",
    "/etc/pki/tls/private",
    "/etc/krb5.keytab",
];

/// The directory holding the SSH host private/public keys, and the filename
/// prefix that marks one. The host keys are a filename family (`ssh_host_rsa_key`,
/// `ssh_host_ed25519_key`, …) under a shared, non-secret directory (`/etc/ssh`
/// also holds the public `sshd_config`), so they cannot be a component-boundary
/// prefix in [`SECRET_PATH_PREFIXES`]; [`path_is_secret`] matches them by basename.
const SSH_HOST_KEY_DIR: &str = "/etc/ssh";
const SSH_HOST_KEY_PREFIX: &str = "ssh_host_";

/// Whether `candidate` is at or under `base` on a `/`-component boundary, OR
/// `base` is at or under `candidate` on a boundary. The second direction matters
/// for a recursive grant: a recursive grant on `/etc` (or `/`) CONTAINS a
/// sensitive `/etc/shadow`, so the grant must be flagged even though its declared
/// path is the broader one. A plain prefix test would miss the parent-grant case
/// or wrongly match a textual neighbour.
fn path_boundary_overlaps(base: &str, candidate: &str) -> bool {
    fn at_or_under(parent: &str, child: &str) -> bool {
        if parent == child {
            return true;
        }
        let parent = parent.strip_suffix('/').unwrap_or(parent);
        child
            .strip_prefix(parent)
            .is_some_and(|rest| rest.starts_with('/'))
    }
    at_or_under(base, candidate) || at_or_under(candidate, base)
}

/// Whether a grant on `path` touches a secret. The single classifier for both the
/// account ([`file_grant_risk_findings`]) and group ([`group_grant_risk_findings`])
/// lints, so the rule cannot drift between the two. A path is secret when:
///
/// - it overlaps a curated secret file/dir on a `/`-component boundary
///   (`/etc/shadow`, `/etc/ssl/private`, …) — including a recursive grant on a
///   parent that CONTAINS one; or
/// - it is, or lies under, an SSH host private key — a basename family
///   (`ssh_host_*`) directly in `/etc/ssh`. The component-boundary matcher cannot
///   express this (the key shares its directory with the non-secret
///   `sshd_config`), so it is checked explicitly: a recursive grant on `/etc/ssh`
///   already matches via the boundary rule, and a grant directly on
///   `/etc/ssh/ssh_host_rsa_key` matches here by basename prefix.
fn path_is_secret(path: &str) -> bool {
    if SECRET_PATH_PREFIXES
        .iter()
        .any(|p| path_boundary_overlaps(p, path))
    {
        return true;
    }
    // SSH host key: a file named `ssh_host_*` whose parent directory is `/etc/ssh`
    // (or a path at/under such a key). `parent_dir`/`basename` over the candidate
    // catch the exact-file case; the recursive-parent case (`/etc/ssh`) is already
    // covered by the boundary rule against a host-key path below.
    if let Some((parent, name)) = path.rsplit_once('/') {
        if parent == SSH_HOST_KEY_DIR && name.starts_with(SSH_HOST_KEY_PREFIX) {
            return true;
        }
    }
    false
}

/// Risk-lint a role's resolved file grants for escalation-capable / secret-leaking
/// access. Returns WARNING findings (advisory — they inform but do not gate
/// `compile --lint`, mirroring how the catalog's own `risk` labelling is advisory,
/// not enforcement). A grant is flagged when:
///
/// - it is `rw` and overlaps a root-equivalent path (writable sudoers/ssh/PATH);
/// - it touches (ro or rw) a secret path (shadow, private keys).
///
/// Overlap uses a path-component boundary in BOTH directions so a recursive grant
/// on a parent of a secret (e.g. recursive `/etc` containing `/etc/shadow`) is
/// caught, not just an exact match.
fn file_grant_risk_findings(compiled: &CompiledRole) -> Vec<LintFinding> {
    let mut out: Vec<LintFinding> = Vec::new();
    for f in compiled.flat_file_grants() {
        let path = &f.grant.path;

        if f.grant.access == catalog::Access::Rw
            && ROOT_EQUIVALENT_RW_PREFIXES
                .iter()
                .any(|p| path_boundary_overlaps(p, path))
        {
            out.push(LintFinding {
                code: "rw-root-equivalent",
                severity: LintSeverity::Warning,
                message: format!(
                    "rw file grant on root-equivalent path {path} (perm {}) is escalation-capable",
                    f.permission
                ),
            });
        }

        if path_is_secret(path) {
            out.push(LintFinding {
                code: "secret-path-access",
                severity: LintSeverity::Warning,
                message: format!(
                    "{} file grant on secret path {path} (perm {}) leaks credentials/keys",
                    access_token(f.grant.access),
                    f.permission
                ),
            });
        }
    }
    out
}

/// Whether a `%group` sudo command references a root-equivalent path: any argument
/// token (everything after the leading binary) overlaps a root-equivalent prefix.
/// This is the generic, reviewable escalation signal for a sudo grant — letting a
/// member run e.g. `vi /etc/sudoers` or `tee /etc/ssh/sshd_config` as root is a
/// path to root. We deliberately do NOT flag on the binary's own directory
/// (almost every sudo command runs a `/usr/bin` or `/usr/sbin` binary — that is
/// normal, not escalation); the root-equivalent PATH-dir prefixes describe WRITE
/// access to files there, the `g:group` file-grant lint's concern, not which
/// binary sudo runs. The match does not distinguish read/write/execute of the
/// argument (a `cat /etc/sudoers` is flagged too) — for an advisory WARNING this
/// conservatism is intended, so the wording says "references", not "edits".
fn sudo_command_edits_root_equivalent(command: &str) -> bool {
    command
        .split_whitespace()
        .skip(1) // skip the leading binary token
        .filter(|tok| tok.starts_with('/'))
        .any(|tok| {
            ROOT_EQUIVALENT_RW_PREFIXES
                .iter()
                .any(|p| path_boundary_overlaps(p, tok))
        })
}

/// Risk-lint the resolved group bindings for escalation-capable grants that
/// EVERY group member inherits (including effectively-nested LDAP members). A
/// group grant widens the blast radius beyond a single account, so the same
/// root-equivalent / secret-path risk classification used for `u:account` file
/// grants ([`ROOT_EQUIVALENT_RW_PREFIXES`] / [`SECRET_PATH_PREFIXES`], matched by
/// [`path_boundary_overlaps`]) is applied to `g:group` grants, and a root-
/// equivalent `%group` sudo command is flagged too. Findings are advisory
/// WARNINGs (like the account-side file-grant lint), each naming the group and
/// the inheritance so the reviewer sees the expanded surface.
///
/// Pure (groups in, findings out) so it is unit-tested from hand-built
/// `ResolvedGroup`s.
fn group_grant_risk_findings(groups: &[model::ResolvedGroup]) -> Vec<LintFinding> {
    let mut out: Vec<LintFinding> = Vec::new();
    for g in groups {
        let group = &g.name;

        // `%group` sudo that edits a root-equivalent path: every member can use
        // it to reach root, so it is an escalation surface for the whole group.
        for cmd in &g.sudo_commands {
            if sudo_command_edits_root_equivalent(cmd) {
                out.push(LintFinding {
                    code: "group-sudo-escalation",
                    severity: LintSeverity::Warning,
                    message: format!(
                        "%{group} sudo grant `{cmd}` references a root-equivalent path (escalation-capable); \
                         ALL members of group {group} (incl. effectively-nested LDAP) inherit it"
                    ),
                });
            }
        }

        // `g:group` file grants, classified exactly like a `u:account` grant.
        for grant in &g.file_grants {
            let path = &grant.path;
            if grant.access == catalog::Access::Rw
                && ROOT_EQUIVALENT_RW_PREFIXES
                    .iter()
                    .any(|p| path_boundary_overlaps(p, path))
            {
                out.push(LintFinding {
                    code: "group-rw-root-equivalent",
                    severity: LintSeverity::Warning,
                    message: format!(
                        "g:{group} rw file grant on root-equivalent path {path} is escalation-capable; \
                         ALL members of group {group} (incl. effectively-nested LDAP) inherit it"
                    ),
                });
            }
            if path_is_secret(path) {
                out.push(LintFinding {
                    code: "group-secret-path-access",
                    severity: LintSeverity::Warning,
                    message: format!(
                        "g:{group} {} file grant on secret path {path} leaks credentials/keys; \
                         ALL members of group {group} (incl. effectively-nested LDAP) inherit it",
                        access_token(grant.access)
                    ),
                });
            }
        }
    }
    out
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
            model::ResolveWarning::GroupsPrimitiveOnGroupTarget { .. } => {
                ("groups-on-group-target", w.to_string())
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

    // File-grant risk lint: rw on root-equivalent paths / access to secret paths.
    // Advisory warnings (like the catalog's own risk labelling), placed after the
    // resolve warnings and before l10n so the output order is stable.
    out.extend(file_grant_risk_findings(compiled));

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
                file_grants: Vec::new(),
                limits: None,
                limits_layer: None,
                category_members: Vec::new(),
                resolved_catalog_version: None,
            },
        }
    }

    /// A compiled permission carrying one resolved file grant.
    fn compiled_perm_with_file(
        id: &str,
        path: &str,
        access: crate::catalog::Access,
        recursive: bool,
        via: Option<&str>,
    ) -> CompiledPermission {
        let grant = crate::catalog::FileGrant {
            path: path.to_owned(),
            access,
            recursive,
        };
        CompiledPermission {
            resolved: ResolvedPermission {
                id: id.to_owned(),
                risk: None,
                groups: vec![],
                sudo: vec![],
                file_grants: vec![crate::catalog::ResolvedFileGrant {
                    path: path.to_owned(),
                    access,
                    recursive,
                    shape: grant.shape(),
                    sources: vec![crate::catalog::SourcedFileGrant {
                        layer: "linux".to_owned(),
                        via: via.map(str::to_owned),
                    }],
                }],
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

    // ---- file-grant rendering (slice 5) ----

    #[test]
    fn render_compile_human_shows_file_grants_dir_and_file() {
        use crate::catalog::Access;
        let compiled = CompiledRole {
            role: "oper".to_owned(),
            permissions: vec![
                // A rewrite-proof dir grant (open AclBackend) ...
                compiled_perm_with_file("ssh-edit", "/etc/ssh", Access::Rw, true, None),
                // ... and a per-file grant that needs a capable backend.
                compiled_perm_with_file("hosts-edit", "/etc/hosts", Access::Ro, false, None),
            ],
            raw_groups: vec![],
            raw_sudo_role: None,
            raw_limits: Limits::default(),
        };
        let text = render_compile_human(&compiled);
        assert!(
            text.contains("/etc/ssh rw recursive via AclBackend (dir, rewrite-proof) [perm ssh-edit]"),
            "{text}"
        );
        assert!(
            text.contains("/etc/hosts ro via requires per-file-capable backend [perm hosts-edit]"),
            "{text}"
        );
    }

    #[test]
    fn render_compile_json_emits_file_grants_array_escaped() {
        use crate::catalog::Access;
        let compiled = CompiledRole {
            role: "oper".to_owned(),
            // A path with a quote exercises the json_str escaper in the new array.
            permissions: vec![compiled_perm_with_file(
                "ssh-edit",
                "/etc/s\"sh",
                Access::Rw,
                true,
                None,
            )],
            raw_groups: vec![],
            raw_sudo_role: None,
            raw_limits: Limits::default(),
        };
        let json = render_compile_json(&compiled);
        assert!(json.contains("\"file_grants\":["), "{json}");
        assert!(json.contains(r#""path":"/etc/s\"sh""#), "{json}");
        assert!(json.contains("\"access\":\"rw\""), "{json}");
        assert!(json.contains("\"recursive\":true"), "{json}");
        assert!(json.contains("\"shape\":\"dir\""), "{json}");
        assert!(json.contains("\"backend\":\"AclBackend (dir, rewrite-proof)\""), "{json}");
        assert!(json.contains("\"permission\":\"ssh-edit\""), "{json}");
    }

    #[test]
    fn render_show_tree_shows_file_grant_with_backend() {
        use crate::catalog::Access;
        let compiled = CompiledRole {
            role: "oper".to_owned(),
            permissions: vec![compiled_perm_with_file("ssh-edit", "/etc/ssh", Access::Rw, true, None)],
            raw_groups: vec![],
            raw_sudo_role: None,
            raw_limits: Limits::default(),
        };
        let l10n = FakeL10n::new();
        let text = render_show_tree(&compiled, "en", &l10n);
        assert!(
            text.contains("file /etc/ssh rw recursive via AclBackend (dir, rewrite-proof)"),
            "{text}"
        );
    }

    // ---- risk lint (slice 5) ----

    #[test]
    fn risk_lint_flags_rw_on_root_equivalent() {
        use crate::catalog::Access;
        // rw on /etc/ssh is escalation-capable.
        let compiled = CompiledRole {
            role: "oper".to_owned(),
            permissions: vec![compiled_perm_with_file("ssh-edit", "/etc/ssh", Access::Rw, true, None)],
            raw_groups: vec![],
            raw_sudo_role: None,
            raw_limits: Limits::default(),
        };
        let findings = file_grant_risk_findings(&compiled);
        let f = findings
            .iter()
            .find(|f| f.code == "rw-root-equivalent")
            .expect("rw-root-equivalent finding");
        assert_eq!(f.severity, LintSeverity::Warning);
        assert!(f.message.contains("/etc/ssh"));
    }

    #[test]
    fn risk_lint_flags_secret_path_read() {
        use crate::catalog::Access;
        // A recursive grant on /etc that CONTAINS /etc/shadow is flagged even
        // though its declared path is the broader directory (boundary both ways).
        let compiled = CompiledRole {
            role: "oper".to_owned(),
            permissions: vec![compiled_perm_with_file("etc-read", "/etc", Access::Ro, true, None)],
            raw_groups: vec![],
            raw_sudo_role: None,
            raw_limits: Limits::default(),
        };
        let findings = file_grant_risk_findings(&compiled);
        assert!(
            findings.iter().any(|f| f.code == "secret-path-access"),
            "recursive /etc grant must flag the contained secret: {findings:?}"
        );
    }

    #[test]
    fn risk_lint_flags_ssh_host_key_read() {
        use crate::catalog::Access;
        // A direct (non-recursive) ro grant on an SSH host PRIVATE key must flag:
        // the key is a `ssh_host_*` file in /etc/ssh, which the component-boundary
        // matcher alone misses (it shares its dir with the public sshd_config), so
        // the basename rule in `path_is_secret` must catch it.
        let compiled = CompiledRole {
            role: "oper".to_owned(),
            permissions: vec![compiled_perm_with_file(
                "host-key-read",
                "/etc/ssh/ssh_host_rsa_key",
                Access::Ro,
                false,
                None,
            )],
            raw_groups: vec![],
            raw_sudo_role: None,
            raw_limits: Limits::default(),
        };
        let findings = file_grant_risk_findings(&compiled);
        let f = findings
            .iter()
            .find(|f| f.code == "secret-path-access")
            .expect("ro grant on an ssh host key must flag secret-path-access");
        assert_eq!(f.severity, LintSeverity::Warning);
        assert!(f.message.contains("/etc/ssh/ssh_host_rsa_key"));
        // A NON-secret file in the same directory (the public config) must NOT flag.
        let public = CompiledRole {
            role: "oper".to_owned(),
            permissions: vec![compiled_perm_with_file(
                "sshd-config-read",
                "/etc/ssh/sshd_config",
                Access::Ro,
                false,
                None,
            )],
            raw_groups: vec![],
            raw_sudo_role: None,
            raw_limits: Limits::default(),
        };
        assert!(
            !file_grant_risk_findings(&public)
                .iter()
                .any(|f| f.code == "secret-path-access"),
            "the public sshd_config in /etc/ssh must not be flagged secret"
        );
    }

    #[test]
    fn risk_lint_clean_grant_no_finding() {
        use crate::catalog::Access;
        // rw on an app config dir that is neither root-equivalent nor a secret.
        let compiled = CompiledRole {
            role: "oper".to_owned(),
            permissions: vec![compiled_perm_with_file("app-edit", "/etc/myapp", Access::Rw, true, None)],
            raw_groups: vec![],
            raw_sudo_role: None,
            raw_limits: Limits::default(),
        };
        assert!(file_grant_risk_findings(&compiled).is_empty());
    }

    // ---- group-grant escalation lint (slice 6) ----

    /// A resolved group carrying the given sudo commands and file grants (the
    /// fields the group lint inspects). Other fields are defaults.
    fn resolved_group(
        name: &str,
        sudo: &[&str],
        file_grants: Vec<catalog::ResolvedFileGrant>,
    ) -> model::ResolvedGroup {
        model::ResolvedGroup {
            name: name.to_owned(),
            gid: None,
            provenance: model::Provenance::Created,
            members: Vec::new(),
            sudo_commands: sudo.iter().map(|s| s.to_string()).collect(),
            file_grants,
            limits: Limits::default(),
            bound_roles: Vec::new(),
        }
    }

    fn rfg(path: &str, access: catalog::Access, recursive: bool) -> catalog::ResolvedFileGrant {
        catalog::ResolvedFileGrant {
            path: path.to_owned(),
            access,
            recursive,
            shape: if recursive { catalog::Shape::Dir } else { catalog::Shape::File },
            sources: Vec::new(),
        }
    }

    #[test]
    fn group_lint_flags_rw_root_equivalent_file_grant() {
        use crate::catalog::Access;
        let groups = vec![resolved_group("netops", &[], vec![rfg("/etc/ssh", Access::Rw, true)])];
        let findings = group_grant_risk_findings(&groups);
        let f = findings
            .iter()
            .find(|f| f.code == "group-rw-root-equivalent")
            .expect("group root-equivalent file finding");
        assert_eq!(f.severity, LintSeverity::Warning);
        // The note names the group and the inheritance (all members).
        assert!(f.message.contains("netops"));
        assert!(f.message.to_lowercase().contains("members"));
    }

    #[test]
    fn group_lint_flags_root_equivalent_sudo() {
        // A `%group` sudo command that edits a root-equivalent path (here a
        // sudoers fragment) is escalation surface inherited by every member.
        let groups = vec![resolved_group("netops", &["/usr/bin/tee /etc/sudoers.d/x"], vec![])];
        let findings = group_grant_risk_findings(&groups);
        let f = findings
            .iter()
            .find(|f| f.code == "group-sudo-escalation")
            .expect("group sudo escalation finding");
        assert_eq!(f.severity, LintSeverity::Warning);
        assert!(f.message.contains("netops"));
    }

    #[test]
    fn group_lint_flags_secret_path_grant() {
        use crate::catalog::Access;
        // A recursive grant on /etc that contains /etc/shadow is flagged (boundary
        // both ways), exactly as for an account grant.
        let groups = vec![resolved_group("auditors", &[], vec![rfg("/etc", Access::Ro, true)])];
        let findings = group_grant_risk_findings(&groups);
        let f = findings
            .iter()
            .find(|f| f.code == "group-secret-path-access")
            .expect("group secret-path finding");
        assert_eq!(f.severity, LintSeverity::Warning);
        assert!(f.message.contains("auditors"));
    }

    #[test]
    fn group_lint_flags_ssh_host_key_grant() {
        use crate::catalog::Access;
        // A direct ro grant on an SSH host private key bound to a group must flag
        // (same basename rule as the account lint — every member would read the key).
        let groups = vec![resolved_group(
            "keyops",
            &[],
            vec![rfg("/etc/ssh/ssh_host_ed25519_key", Access::Ro, false)],
        )];
        let findings = group_grant_risk_findings(&groups);
        let f = findings
            .iter()
            .find(|f| f.code == "group-secret-path-access")
            .expect("group grant on an ssh host key must flag secret-path-access");
        assert_eq!(f.severity, LintSeverity::Warning);
        assert!(f.message.contains("keyops"));
        assert!(f.message.contains("/etc/ssh/ssh_host_ed25519_key"));
    }

    #[test]
    fn group_lint_clean_group_has_no_finding() {
        use crate::catalog::Access;
        // A group with a benign app-dir grant and a non-root-equivalent sudo
        // command produces no escalation finding.
        let groups = vec![resolved_group(
            "appops",
            &["/usr/bin/systemctl restart atm-app"],
            vec![rfg("/etc/myapp", Access::Rw, true)],
        )];
        assert!(group_grant_risk_findings(&groups).is_empty());
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

    // ---- catalog coverage (render + exit-code helpers; slice 3) ----

    use crate::coverage::{
        ClassCoverage, CoverageReport, ObjectCoverage, Provenance, SurfaceClass, SurfaceObject,
    };

    /// A surface object for hand-built coverage reports.
    fn cov_obj(class: SurfaceClass, key: &str, prov: Provenance) -> SurfaceObject {
        SurfaceObject {
            class,
            key: key.to_owned(),
            provenance: prov,
            detail: String::new(),
        }
    }

    /// A hand-built coverage report exercising every render branch: a covered and
    /// an uncovered sudo_bin (the latter with a suggestion), an intentionally
    /// uncovered group, and an orphan-setuid anomaly.
    fn sample_report() -> CoverageReport {
        CoverageReport {
            by_class: vec![ClassCoverage {
                class: SurfaceClass::SudoBin,
                covered: 1,
                total: 2,
            }],
            objects: vec![
                ObjectCoverage {
                    object: cov_obj(SurfaceClass::SudoBin, "/usr/sbin/ip", Provenance::Vendor),
                    covered: true,
                    suggested_permission: None,
                    intentional_exclusion: None,
                    backend_limited: None,
                    coverage_note: None,
                },
                ObjectCoverage {
                    object: cov_obj(
                        SurfaceClass::SudoBin,
                        "/usr/sbin/cryptsetup",
                        Provenance::Vendor,
                    ),
                    covered: false,
                    suggested_permission: Some("luks-admin".to_owned()),
                    intentional_exclusion: None,
                    backend_limited: None,
                    coverage_note: None,
                },
                ObjectCoverage {
                    object: cov_obj(SurfaceClass::Group, "astra-admin", Provenance::Vendor),
                    covered: false,
                    suggested_permission: None,
                    intentional_exclusion: Some("admin-by-design".to_owned()),
                    backend_limited: None,
                    coverage_note: None,
                },
                // A config object covered by a file grant carries the backend note.
                ObjectCoverage {
                    object: cov_obj(
                        SurfaceClass::Config,
                        "/etc/ssh/sshd_config",
                        Provenance::Vendor,
                    ),
                    covered: true,
                    suggested_permission: None,
                    intentional_exclusion: None,
                    backend_limited: None,
                    coverage_note: Some("rw via AclBackend (dir)".to_owned()),
                },
                // A backend-limited config: a single file in /etc the dir-only
                // backend can't cover without an over-broad grant.
                ObjectCoverage {
                    object: cov_obj(
                        SurfaceClass::Config,
                        "/etc/login.defs",
                        Provenance::Vendor,
                    ),
                    covered: false,
                    suggested_permission: None,
                    intentional_exclusion: None,
                    backend_limited: Some(
                        "single file in non-grantable parent; requires per-file-capable backend"
                            .to_owned(),
                    ),
                    coverage_note: None,
                },
            ],
            setuid_inventory: vec![],
            anomalies: vec![cov_obj(
                SurfaceClass::Setuid,
                "/opt/x/flasher",
                Provenance::Orphan,
            )],
            overall_pct: 50.0,
            catalog_version: Some("2026.06".to_owned()),
            os_target: "linux-debian-12".to_owned(),
            catalog_warnings: vec![],
        }
    }

    #[test]
    fn resolve_roles_honours_catalog_dir_override() {
        // A role references a permission defined ONLY in a site catalog passed via
        // the same roots the coverage pass uses. resolve_roles must resolve it
        // against those roots (not the bare defaults) so the role contributes its
        // sudo binary to coverage.
        let tmp = tempfile::tempdir().unwrap();
        let site_root = tmp.path().join("site-permissions");
        let layer_dir = site_root.join("linux");
        std::fs::create_dir_all(&layer_dir).unwrap();
        std::fs::write(
            layer_dir.join("site-net.toml"),
            "id = \"site-net\"\nsudo = [\"/usr/sbin/site-tool\"]\n",
        )
        .unwrap();

        let roles_dir = tmp.path().join("roles");
        std::fs::create_dir_all(&roles_dir).unwrap();
        std::fs::write(
            roles_dir.join("oper.toml"),
            "role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"Operator\"\nlevel = 5\n[payload]\npermissions = [\"site-net\"]\n",
        )
        .unwrap();

        let os = OsTarget::new("linux", "debian", None).unwrap();
        let ctx = ResolveCtx::default();

        // With the site root passed through, the role resolves and contributes.
        let roles = resolve_roles(&roles_dir, &[site_root.clone()], &os, &ctx);
        assert_eq!(roles.len(), 1);
        assert!(
            roles[0].sudo.iter().any(|c| c == "/usr/sbin/site-tool"),
            "role must resolve its site-catalog permission: {:?}",
            roles[0].sudo
        );

        // Without the site root, the same permission is unknown: the role
        // resolves to nothing (warns-and-skips), proving the override mattered.
        let empty_root = tmp.path().join("empty-permissions");
        std::fs::create_dir_all(&empty_root).unwrap();
        let roles_no_override = resolve_roles(&roles_dir, &[empty_root], &os, &ctx);
        assert_eq!(roles_no_override.len(), 1);
        assert!(
            roles_no_override[0].sudo.is_empty(),
            "without the site root the permission cannot resolve"
        );
    }

    #[test]
    fn coverage_exit_code_gates_on_min_coverage() {
        // No threshold → always success even at 0%.
        assert_eq!(
            format!("{:?}", coverage_exit_code(0.0, None)),
            format!("{:?}", ExitCode::SUCCESS)
        );
        // Below threshold → exit 4 (CI-gate, distinct from FAILURE==1).
        assert_eq!(
            format!("{:?}", coverage_exit_code(81.0, Some(85.0))),
            format!("{:?}", ExitCode::from(4))
        );
        // At or above threshold → success.
        assert_eq!(
            format!("{:?}", coverage_exit_code(85.0, Some(85.0))),
            format!("{:?}", ExitCode::SUCCESS)
        );
        assert_eq!(
            format!("{:?}", coverage_exit_code(90.0, Some(85.0))),
            format!("{:?}", ExitCode::SUCCESS)
        );
    }

    #[test]
    fn render_coverage_human_shows_all_sections() {
        let text = render_coverage_human(&sample_report(), false);
        assert!(text.contains("linux-debian-12"), "{text}");
        assert!(text.contains("sudo_bin  1/2"), "{text}");
        assert!(text.contains("overall: 50.0%"), "{text}");
        // Uncovered gap with its suggestion.
        assert!(
            text.contains("/usr/sbin/cryptsetup") && text.contains("luks-admin"),
            "{text}"
        );
        // Intentionally-uncovered with its reason.
        assert!(
            text.contains("astra-admin") && text.contains("admin-by-design"),
            "{text}"
        );
        // A config object covered by a file grant lists its backend note.
        assert!(
            text.contains("covered via file grants")
                && text.contains("/etc/ssh/sshd_config")
                && text.contains("rw via AclBackend (dir)"),
            "{text}"
        );
        // Backend-limited section present, with the bare /etc file and its reason.
        assert!(
            text.contains("backend-limited (requires per-file backend)")
                && text.contains("/etc/login.defs")
                && text.contains("requires per-file-capable backend"),
            "{text}"
        );
        // A backend-limited object must NOT appear in the uncovered gap section.
        assert!(
            !text.contains("[config] /etc/login.defs →"),
            "backend-limited must not be a gap with a suggestion arrow: {text}"
        );
        // Anomaly section present.
        assert!(text.contains("anomalies") && text.contains("/opt/x/flasher"), "{text}");
        // The covered binary is NOT listed in the uncovered section (it appears
        // only in the class summary, never as a gap row with a suggestion arrow).
        assert!(
            !text.contains("[sudo_bin] /usr/sbin/ip"),
            "covered binary must not be rendered as a gap: {text}"
        );
    }

    #[test]
    fn render_coverage_json_has_objects_and_summary() {
        let json = render_coverage_json(&sample_report());
        assert!(json.contains("\"objects\":["), "{json}");
        assert!(json.contains("\"key\":\"/usr/sbin/ip\""), "{json}");
        assert!(json.contains("\"covered\":true"), "{json}");
        assert!(json.contains("\"suggested_permission\":\"luks-admin\""), "{json}");
        assert!(json.contains("\"intentional_exclusion\":\"admin-by-design\""), "{json}");
        assert!(json.contains("\"provenance\":\"vendor\""), "{json}");
        assert!(json.contains("\"overall_pct\":50.0"), "{json}");
        assert!(json.contains("\"catalog_version\":\"2026.06\""), "{json}");
        assert!(json.contains("\"os_target\":\"linux-debian-12\""), "{json}");
        assert!(json.contains("\"anomalies\":["), "{json}");
        // The config object's coverage note is emitted; non-config objects carry null.
        assert!(json.contains("\"coverage_note\":\"rw via AclBackend (dir)\""), "{json}");
        assert!(json.contains("\"coverage_note\":null"), "{json}");
        // The backend-limited config carries its reason; others carry null.
        assert!(
            json.contains("\"backend_limited\":\"single file in non-grantable parent; requires per-file-capable backend\""),
            "{json}"
        );
        assert!(json.contains("\"backend_limited\":null"), "{json}");
    }

    #[test]
    fn render_coverage_json_escapes_special_chars() {
        // A key with a quote and a newline must not break the JSON document — the
        // shared json_str escaper handles it.
        let mut report = sample_report();
        report.objects[0].object.key = "/usr/sbin/x\"y\nz".to_owned();
        let json = render_coverage_json(&report);
        assert!(json.contains(r#""key":"/usr/sbin/x\"y\nz""#), "{json}");
        // Document remains single-line apart from the trailing newline the renderer
        // appends (no raw newline leaked into the body).
        assert_eq!(json.matches('\n').count(), 1, "{json}");
    }

    #[test]
    fn parse_classes_parses_and_rejects_unknown() {
        let got = parse_classes("sudo_bin, group ,setuid").unwrap();
        assert_eq!(
            got,
            vec![
                SurfaceClass::SudoBin,
                SurfaceClass::Group,
                SurfaceClass::Setuid
            ]
        );
        // Duplicates collapse.
        assert_eq!(parse_classes("unit,unit").unwrap(), vec![SurfaceClass::Unit]);
        // Unknown token is a hard error (fail closed).
        assert!(parse_classes("sudo_bin,bogus").is_err());
    }

    // ---- catalog which-grants (reverse lookup) ----

    fn sudo_match(perm: &str, detail: &str) -> coverage::GrantMatch {
        coverage::GrantMatch {
            permission: perm.to_owned(),
            target: coverage::GrantTarget::Account(perm.to_owned()),
            kind: coverage::GrantKind::Sudo,
            detail: detail.to_owned(),
            access: None,
            recursive: None,
            backend: None,
            risk: Some(Risk::EscalationCapable),
        }
    }

    fn file_match(perm: &str, path: &str) -> coverage::GrantMatch {
        coverage::GrantMatch {
            permission: perm.to_owned(),
            target: coverage::GrantTarget::Account(perm.to_owned()),
            kind: coverage::GrantKind::File,
            detail: path.to_owned(),
            access: Some(crate::catalog::Access::Rw),
            recursive: Some(true),
            backend: Some("AclBackend".to_owned()),
            risk: Some(Risk::Contained),
        }
    }

    /// A group-target sudo match — reached through `%group` sudoers; `group` is
    /// the inheriting group.
    fn group_sudo_match(group: &str, detail: &str) -> coverage::GrantMatch {
        coverage::GrantMatch {
            permission: group.to_owned(),
            target: coverage::GrantTarget::Group(group.to_owned()),
            kind: coverage::GrantKind::Sudo,
            detail: detail.to_owned(),
            access: None,
            recursive: None,
            backend: None,
            risk: None,
        }
    }

    /// A group-target file match — reached through a `g:group` ACL.
    fn group_file_match(group: &str, path: &str) -> coverage::GrantMatch {
        coverage::GrantMatch {
            permission: group.to_owned(),
            target: coverage::GrantTarget::Group(group.to_owned()),
            kind: coverage::GrantKind::File,
            detail: path.to_owned(),
            access: Some(crate::catalog::Access::Rw),
            recursive: Some(true),
            backend: Some("AclBackend".to_owned()),
            risk: None,
        }
    }

    #[test]
    fn render_which_grants_human_groups_matches() {
        let matches = vec![
            sudo_match("network-admin", "/usr/sbin/ip link set"),
            file_match("ssh-edit", "/etc/ssh"),
        ];
        let text = render_which_grants_human("/usr/sbin/ip", &matches);
        assert!(text.contains("/usr/sbin/ip granted by:"), "{text}");
        assert!(
            text.contains("network-admin — via sudo: /usr/sbin/ip link set [escalation-capable]"),
            "{text}"
        );
        assert!(
            text.contains("ssh-edit — via file (rw): /etc/ssh, recursive (AclBackend) [contained]"),
            "{text}"
        );
    }

    #[test]
    fn render_which_grants_human_group_matches() {
        // Group matches render the group mechanism (%group sudoers / g:group ACL)
        // and name the inheriting group; account output is unchanged (covered by
        // render_which_grants_human_groups_matches above).
        let matches = vec![
            group_sudo_match("netops", "/usr/sbin/ip link set"),
            group_file_match("netops", "/etc/net"),
        ];
        let text = render_which_grants_human("/usr/sbin/ip", &matches);
        assert!(
            text.contains("netops — via %group sudoers (netops): /usr/sbin/ip link set"),
            "{text}"
        );
        assert!(
            text.contains("netops — via g:group ACL (netops) (rw): /etc/net, recursive (AclBackend)"),
            "{text}"
        );
    }

    #[test]
    fn render_which_grants_json_distinguishes_group_target() {
        let matches = vec![
            sudo_match("network-admin", "/usr/sbin/ip link set"),
            group_sudo_match("netops", "/usr/sbin/ip route"),
        ];
        let json = render_which_grants_json(&matches);
        // Account match carries target=account, group=null.
        assert!(json.contains("\"target\":\"account\""), "{json}");
        // Group match carries target=group and the group name.
        assert!(json.contains("\"target\":\"group\""), "{json}");
        assert!(json.contains("\"group\":\"netops\""), "{json}");
        assert!(json.contains("\"group\":null"), "{json}");
    }

    #[test]
    fn render_which_grants_human_no_match_message() {
        let text = render_which_grants_human("/usr/bin/nope", &[]);
        assert_eq!(text, "no permission grants access to /usr/bin/nope\n");
    }

    #[test]
    fn render_which_grants_json_shape() {
        let matches = vec![
            sudo_match("network-admin", "/usr/sbin/ip link set"),
            file_match("ssh-edit", "/etc/ssh"),
        ];
        let json = render_which_grants_json(&matches);
        assert!(json.starts_with('['), "{json}");
        assert!(json.contains("\"permission\":\"network-admin\""), "{json}");
        assert!(json.contains("\"kind\":\"sudo\""), "{json}");
        assert!(json.contains("\"detail\":\"/usr/sbin/ip link set\""), "{json}");
        // A sudo match carries null access/recursive/backend.
        assert!(json.contains("\"access\":null"), "{json}");
        assert!(json.contains("\"recursive\":null"), "{json}");
        // A file match carries concrete access/recursive/backend.
        assert!(json.contains("\"kind\":\"file\""), "{json}");
        assert!(json.contains("\"access\":\"rw\""), "{json}");
        assert!(json.contains("\"recursive\":true"), "{json}");
        assert!(json.contains("\"backend\":\"AclBackend\""), "{json}");
        assert!(json.contains("\"risk\":\"contained\""), "{json}");
    }

    #[test]
    fn render_which_grants_json_empty_is_empty_array() {
        assert_eq!(render_which_grants_json(&[]), "[]\n");
    }

    #[test]
    fn build_grant_sources_skips_templated_and_unresolvable() {
        // One concrete sudo perm, one templated (skipped because its {unit} is
        // unfilled with no role instance). build_grant_sources keeps only concrete.
        let tmp = tempfile::tempdir().unwrap();
        let (_decl, catalog_root) = compile_fixture(
            tmp.path(),
            "[payload]\npermissions = []\n",
            &[
                ("linux", "network-admin", "id = \"network-admin\"\nsudo = [\"/usr/sbin/ip\"]\n"),
                (
                    "linux",
                    "service-restart",
                    "id = \"service-restart\"\nsudo = [\"/usr/bin/systemctl restart {unit}\"]\n",
                ),
            ],
        );
        let catalog = LiveCatalog::new(vec![catalog_root]);
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let ctx = ResolveCtx::default();
        let sources = build_grant_sources(&catalog, &os, &ctx).unwrap();
        // network-admin contributes a concrete command; service-restart's only
        // command is templated and dropped, so it contributes nothing and is omitted.
        assert!(sources.iter().any(|s| s.id == "network-admin"
            && s.sudo.iter().any(|c| c == "/usr/sbin/ip")));
        assert!(
            !sources.iter().any(|s| s.id == "service-restart"),
            "a perm whose only grant is templated must be omitted: {sources:?}"
        );
    }

    #[test]
    fn build_group_grant_sources_emits_group_targets() {
        // A declaration binding a role to a group yields a Group-target source
        // carrying the group's sudo + file grants; a group with no grants is
        // omitted.
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("roles");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(
            store.join("netops.toml"),
            "role = \"netops\"\nversion = 1\nos = \"linux\"\nname = \"netops\"\nlevel = 5\n[payload]\npermissions = [\"net-admin\"]\n",
        )
        .unwrap();
        let catalog_root = tmp.path().join("permissions");
        std::fs::create_dir_all(catalog_root.join("linux")).unwrap();
        std::fs::write(
            catalog_root.join("linux").join("net-admin.toml"),
            "id = \"net-admin\"\nsudo = [\"/usr/sbin/ip\"]\n\n[[file]]\npath = \"/etc/net\"\naccess = \"rw\"\nrecursive = true\n",
        )
        .unwrap();
        let decl_text = format!(
            "version = 1\nrole_store = \"{}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n\
             [[group]]\nname = \"netops\"\ngid = 8020\n\
             [[group]]\nname = \"empty-grp\"\ngid = 8021\n\
             [[role_group]]\nrole = \"netops\"\ngroup = \"netops\"\n",
            store.display()
        );
        let decl = Declaration::parse(&decl_text).unwrap();
        let catalog = LiveCatalog::new(vec![catalog_root]);
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let ctx = ResolveCtx::default();
        let inputs = CompileInputs { catalog: &catalog, os: &os, ctx: &ctx };

        let sources = build_group_grant_sources(&decl, &inputs).unwrap();
        // The bound group is a Group-target source with the role's grants.
        let g = sources
            .iter()
            .find(|s| s.id == "netops")
            .expect("group source for bound group");
        assert_eq!(g.target, coverage::GrantTarget::Group("netops".to_owned()));
        assert!(g.sudo.iter().any(|c| c == "/usr/sbin/ip"));
        assert!(g.file_grants.iter().any(|fg| fg.path == "/etc/net"));
        // The grantless group is omitted.
        assert!(
            !sources.iter().any(|s| s.id == "empty-grp"),
            "a group with no grants must be omitted: {sources:?}"
        );
    }

    #[test]
    fn run_which_grants_finds_match_and_exits_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let (_decl, catalog_root) = compile_fixture(
            tmp.path(),
            "[payload]\npermissions = []\n",
            &[(
                "linux",
                "network-admin",
                "id = \"network-admin\"\nsudo = [\"/usr/sbin/ip link\"]\n",
            )],
        );
        let code = run_which_grants(WhichGrantsOpts {
            arg: "/usr/sbin/ip".to_owned(),
            json: false,
            os_target: Some("linux-debian".to_owned()),
            catalog_roots: vec![catalog_root],
            declaration: None,
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn run_which_grants_no_match_still_exits_zero() {
        // Even when nothing grants the arg, the query succeeds (exit 0).
        let tmp = tempfile::tempdir().unwrap();
        let (_decl, catalog_root) = compile_fixture(
            tmp.path(),
            "[payload]\npermissions = []\n",
            &[(
                "linux",
                "network-admin",
                "id = \"network-admin\"\nsudo = [\"/usr/sbin/ip\"]\n",
            )],
        );
        let code = run_which_grants(WhichGrantsOpts {
            arg: "/usr/bin/nonexistent".to_owned(),
            json: true,
            os_target: Some("linux-debian".to_owned()),
            catalog_roots: vec![catalog_root],
            declaration: None,
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
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
        let code = run_show(ShowOpts {
            role: "oper",
            declaration: &decl,
            catalog_roots: vec![catalog_root],
            os_target: Some("linux-debian"),
            lang: Some("ru"),
            framework: None,
            framework_roots: vec![],
            format: None,
        });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    // ---- framework cross-reference (slices 3 & 4) ----

    /// Build an artificial framework tree under `<dir>/frameworks/` and load it.
    /// Mirrors the helper style in `framework.rs` tests: a `framework.toml`
    /// manifest, `mappings/*.toml`, and an optional `controls.toml`. Returns the
    /// loaded set over a flat OS target (enough for flat frameworks).
    fn load_fw_tree(
        dir: &Path,
        manifests: &[(&str, &str)],
        mappings: &[(&str, &str)],
        controls: &[(&str, &str)],
    ) -> LoadedFrameworks {
        let root = dir.join("frameworks");
        for (relpath, body) in manifests.iter().chain(mappings).chain(controls) {
            let path = root.join(relpath);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, body).unwrap();
        }
        let os = OsTarget::new("linux", "debian", None).unwrap();
        framework::load_frameworks(&[root], &os).unwrap()
    }

    /// A `pci-dss` flat framework: maps `net-admin → 1.1, 1.2` and `log-read →
    /// 10.1`; `legacy` (not mapped by any role permission here) exists too. The
    /// `controls.toml` flags `1.1`/`1.2`/`10.1`/`9.9` owned and `2.1` inherited;
    /// `9.9` is owned-but-uncovered (the gap).
    fn pci_dss_tree(dir: &Path) -> LoadedFrameworks {
        load_fw_tree(
            dir,
            &[(
                "pci-dss/framework.toml",
                "id = \"pci-dss\"\nversion = \"4.0\"\ntitle = \"PCI DSS\"\ndimension = \"flat\"\nprovides = [\"crossref\", \"controls\"]\n",
            )],
            &[
                ("pci-dss/mappings/a.toml", "[net-admin]\nsatisfies = [\"1.1\", \"1.2\"]\n"),
                ("pci-dss/mappings/b.toml", "[log-read]\nsatisfies = [\"10.1\"]\n"),
            ],
            &[(
                "pci-dss/controls.toml",
                "[\"1.1\"]\ntitle = \"Firewall\"\nowned = true\ndomain = \"Network\"\n\
                 [\"1.2\"]\ntitle = \"Default deny\"\nowned = true\n\
                 [\"2.1\"]\ntitle = \"No vendor defaults\"\nowned = false\n\
                 [\"10.1\"]\ntitle = \"Audit logging\"\nowned = true\n\
                 [\"9.9\"]\ntitle = \"Uncovered owned\"\nowned = true\n",
            )],
        )
    }

    fn show_role() -> CompiledRole {
        CompiledRole {
            role: "oper".to_owned(),
            permissions: vec![
                compiled_perm("net-admin", None, vec![], vec![]),
                // unmapped: present in the role but absent from the framework.
                compiled_perm("disk-admin", None, vec![], vec![]),
            ],
            raw_groups: vec![],
            raw_sudo_role: None,
            raw_limits: Limits::default(),
        }
    }

    // --- SLICE 3 ---

    #[test]
    fn show_framework_human_shows_controls_provenance_and_no_mapping() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = pci_dss_tree(tmp.path());
        let sel = FrameworkSelection::resolve("pci-dss", &loaded);
        let out = render_show_framework_human(&show_role(), &sel, &loaded);
        // Mapped permission shows its controls and provenance file path.
        assert!(out.contains("permission net-admin:"), "{out}");
        assert!(out.contains("✓ satisfies: 1.1, 1.2"), "{out}");
        assert!(out.contains("via pci-dss"), "{out}");
        assert!(out.contains("a.toml"), "{out}");
        // Unmapped permission carries the explicit marker, never omitted.
        assert!(out.contains("permission disk-admin (no mapping)"), "{out}");
        // Version stamp present in the human header too.
        assert!(out.contains("framework pci-dss (4.0)"), "{out}");
    }

    #[test]
    fn show_framework_all_iterates_every_framework() {
        let tmp = tempfile::tempdir().unwrap();
        // Two frameworks in the tree.
        let loaded = load_fw_tree(
            tmp.path(),
            &[
                ("pci-dss/framework.toml", "id = \"pci-dss\"\nversion = \"4.0\"\ntitle = \"PCI\"\ndimension = \"flat\"\n"),
                ("soc2/framework.toml", "id = \"soc2\"\nversion = \"2\"\ntitle = \"SOC 2\"\ndimension = \"flat\"\n"),
            ],
            &[
                ("pci-dss/mappings/a.toml", "[net-admin]\nsatisfies = [\"1.1\"]\n"),
                ("soc2/mappings/a.toml", "[net-admin]\nsatisfies = [\"CC6.1\"]\n"),
            ],
            &[],
        );
        let sel = FrameworkSelection::resolve("all", &loaded);
        assert_eq!(sel.ids, vec!["pci-dss".to_owned(), "soc2".to_owned()]);
        let out = render_show_framework_human(&show_role(), &sel, &loaded);
        assert!(out.contains("framework pci-dss"), "{out}");
        assert!(out.contains("framework soc2"), "{out}");
        assert!(out.contains("1.1"), "{out}");
        assert!(out.contains("CC6.1"), "{out}");
    }

    #[test]
    fn show_framework_json_has_version_stamp_and_mapped_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = pci_dss_tree(tmp.path());
        let sel = FrameworkSelection::resolve("pci-dss", &loaded);
        let out = render_show_framework_json(&show_role(), &sel, &loaded);
        // Version stamp (id + version) MUST be present.
        assert!(out.contains("\"id\":\"pci-dss\""), "{out}");
        assert!(out.contains("\"version\":\"4.0\""), "{out}");
        // Mapped + unmapped permissions both present, with the mapped flag.
        assert!(out.contains("\"permission\":\"net-admin\""), "{out}");
        assert!(out.contains("\"satisfies\":[\"1.1\",\"1.2\"]"), "{out}");
        assert!(out.contains("\"mapped\":true"), "{out}");
        assert!(out.contains("\"permission\":\"disk-admin\""), "{out}");
        assert!(out.contains("\"mapped\":false"), "{out}");
        // Well-formed: balanced braces, single trailing newline.
        assert!(out.ends_with("}\n"), "{out}");
    }

    #[test]
    fn show_permissions_json_without_framework_has_no_frameworks_array() {
        let out = render_show_permissions_json(&show_role());
        assert!(out.contains("\"role\":\"oper\""), "{out}");
        assert!(out.contains("\"permissions\":[\"net-admin\",\"disk-admin\"]"), "{out}");
        // No framework stamp when no framework was requested.
        assert!(!out.contains("frameworks"), "{out}");
    }

    // --- SLICE 4 ---

    #[test]
    fn framework_list_human_and_json_show_version_and_provides() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = pci_dss_tree(tmp.path());
        let human = render_framework_list_human(&loaded);
        assert!(human.contains("pci-dss 4.0"), "{human}");
        assert!(human.contains("provides: crossref, controls"), "{human}");
        let json = render_framework_list_json(&loaded);
        assert!(json.contains("\"id\":\"pci-dss\""), "{json}");
        assert!(json.contains("\"version\":\"4.0\""), "{json}");
        assert!(json.contains("\"provides\":[\"crossref\",\"controls\"]"), "{json}");
    }

    #[test]
    fn framework_list_empty_reports_none() {
        let tmp = tempfile::tempdir().unwrap();
        // An empty tree (no frameworks dir created) → empty load.
        let loaded = load_fw_tree(tmp.path(), &[], &[], &[]);
        assert_eq!(render_framework_list_human(&loaded), "no frameworks installed\n");
        assert_eq!(render_framework_list_json(&loaded), "{\"frameworks\":[]}\n");
    }

    #[test]
    fn framework_coverage_computes_owned_covered_gap_and_out_of_domain() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = pci_dss_tree(tmp.path());
        let cov = compute_framework_coverage(&loaded, "pci-dss");
        // Owned + covered: 1.1, 1.2, 10.1 (all owned and referenced by a mapping).
        assert_eq!(cov.covered, vec!["1.1", "1.2", "10.1"]);
        // Owned but never mapped → the gap.
        assert_eq!(cov.gap, vec!["9.9"]);
        // owned = false → out-of-domain, NOT counted in the gap.
        assert_eq!(cov.out_of_domain, vec!["2.1"]);
        assert!(!cov.gap.contains(&"2.1".to_owned()));
    }

    #[test]
    fn framework_coverage_json_has_stamp_and_arrays() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = pci_dss_tree(tmp.path());
        let cov = compute_framework_coverage(&loaded, "pci-dss");
        let json = render_framework_coverage_json("pci-dss", &loaded, &cov);
        assert!(json.contains("\"id\":\"pci-dss\""), "{json}");
        assert!(json.contains("\"version\":\"4.0\""), "{json}");
        assert!(json.contains("\"gap\":[\"9.9\"]"), "{json}");
        assert!(json.contains("\"uncovered\":[\"9.9\"]"), "{json}");
        assert!(json.contains("\"out_of_domain\":[\"2.1\"]"), "{json}");
        assert!(json.contains("\"covered\":[\"1.1\",\"1.2\",\"10.1\"]"), "{json}");
        assert!(json.ends_with("}\n"), "{json}");
    }

    #[test]
    fn framework_show_human_lists_controls_and_owned_stats() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = pci_dss_tree(tmp.path());
        let out = render_framework_show_human("pci-dss", &loaded);
        assert!(out.contains("framework pci-dss (4.0)"), "{out}");
        // Owned/covered annotations per control.
        assert!(out.contains("1.1 [owned] [covered]"), "{out}");
        assert!(out.contains("2.1 [inherited]"), "{out}");
        assert!(out.contains("9.9 [owned] [uncovered]"), "{out}");
        // Owned coverage: 4 owned (1.1,1.2,10.1,9.9), 3 covered, 1 uncovered.
        assert!(out.contains("3/4 owned controls covered (1 uncovered)"), "{out}");
    }

    #[test]
    fn run_framework_list_over_tempdir_tree() {
        let tmp = tempfile::tempdir().unwrap();
        // Materialize a tree and drive the public entry point against it.
        let _ = pci_dss_tree(tmp.path());
        let root = tmp.path().join("frameworks");
        let code = run_framework_list(vec![root], Some("linux-debian".to_owned()), false);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn run_framework_coverage_missing_framework_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let _ = pci_dss_tree(tmp.path());
        let root = tmp.path().join("frameworks");
        let code = run_framework_coverage("nope", vec![root], Some("linux-debian".to_owned()), true);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
    }

    #[test]
    fn framework_lint_human_empty_is_no_findings() {
        assert_eq!(
            render_framework_lint_human(&[]),
            "framework lint: no findings\n"
        );
    }

    #[test]
    fn framework_lint_human_and_json_render_warning() {
        let findings = vec![framework::FrameworkLint {
            code: "orphaned-mapping",
            severity: framework::FrameworkLintSeverity::Warning,
            message: "x".into(),
        }];
        let human = render_framework_lint_human(&findings);
        assert!(human.contains("WARNING [orphaned-mapping]"), "{human}");
        let json = render_framework_lint_json(&findings);
        assert!(json.contains("\"severity\":\"warning\""), "{json}");
        assert!(json.contains("\"code\":\"orphaned-mapping\""), "{json}");
    }

    #[test]
    fn framework_lint_id_collision_renders_error() {
        let findings = vec![framework::FrameworkLint {
            code: "id-collision",
            severity: framework::FrameworkLintSeverity::Error,
            message: "collision".into(),
        }];
        let human = render_framework_lint_human(&findings);
        assert!(human.contains("ERROR [id-collision]"), "{human}");
        let json = render_framework_lint_json(&findings);
        assert!(json.contains("\"severity\":\"error\""), "{json}");
    }

    #[test]
    fn run_framework_lint_over_tempdir_tree_succeeds_with_warnings() {
        let tmp = tempfile::tempdir().unwrap();
        // Materialize the pci-dss tree: its mapped perms (net-admin, log-read) are
        // absent from an empty catalog → orphaned-mapping WARNINGS, no errors.
        let _ = pci_dss_tree(tmp.path());
        let fw_root = tmp.path().join("frameworks");
        // A fresh empty catalog root (no permission dirs).
        let cat_root = tmp.path().join("empty-catalog");
        std::fs::create_dir_all(&cat_root).unwrap();
        let code = run_framework_lint(
            vec![fw_root],
            vec![cat_root],
            Some("linux-debian".to_owned()),
            false,
        );
        // Warnings do not gate: exit SUCCESS.
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[test]
    fn show_framework_human_prints_polarity() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = load_fw_tree(
            tmp.path(),
            &[(
                "pci-dss/framework.toml",
                "id = \"pci-dss\"\nversion = \"4.0\"\ntitle = \"PCI\"\ndimension = \"flat\"\n",
            )],
            &[(
                "pci-dss/mappings/a.toml",
                "[net-admin]\nsatisfies = [\"1.1\"]\n[log-admin]\nrisk = [\"10.5.1\"]\n[audit]\nrelated = [\"10.2.1\"]\n",
            )],
            &[],
        );
        let role = CompiledRole {
            role: "oper".to_owned(),
            permissions: vec![
                compiled_perm("net-admin", None, vec![], vec![]),
                compiled_perm("log-admin", None, vec![], vec![]),
                compiled_perm("audit", None, vec![], vec![]),
                compiled_perm("ghost", None, vec![], vec![]),
            ],
            raw_groups: vec![],
            raw_sudo_role: None,
            raw_limits: Limits::default(),
        };
        let sel = FrameworkSelection::resolve("pci-dss", &loaded);
        let out = render_show_framework_human(&role, &sel, &loaded);
        assert!(out.contains("✓ satisfies:"), "{out}");
        assert!(out.contains("⚠ risk:"), "{out}");
        assert!(out.contains("· related:"), "{out}");
        assert!(out.contains("permission ghost (no mapping)"), "{out}");
    }

    #[test]
    fn show_framework_json_carries_each_polarity() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = load_fw_tree(
            tmp.path(),
            &[(
                "pci-dss/framework.toml",
                "id = \"pci-dss\"\nversion = \"4.0\"\ntitle = \"PCI\"\ndimension = \"flat\"\n",
            )],
            &[(
                "pci-dss/mappings/a.toml",
                "[net-admin]\nsatisfies = [\"1.1\"]\n[log-admin]\nrisk = [\"10.5.1\"]\n[audit]\nrelated = [\"10.2.1\"]\n",
            )],
            &[],
        );
        let role = CompiledRole {
            role: "oper".to_owned(),
            permissions: vec![
                compiled_perm("net-admin", None, vec![], vec![]),
                compiled_perm("log-admin", None, vec![], vec![]),
                compiled_perm("audit", None, vec![], vec![]),
            ],
            raw_groups: vec![],
            raw_sudo_role: None,
            raw_limits: Limits::default(),
        };
        let sel = FrameworkSelection::resolve("pci-dss", &loaded);
        let out = render_show_framework_json(&role, &sel, &loaded);
        assert!(out.contains("\"satisfies\":["), "{out}");
        assert!(out.contains("\"risk\":["), "{out}");
        assert!(out.contains("\"related\":["), "{out}");
        assert!(out.contains("\"id\":\"pci-dss\""), "{out}");
        assert!(out.contains("\"version\":"), "{out}");
    }

    #[test]
    fn framework_risk_lists_controls_and_threats() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = load_fw_tree(
            tmp.path(),
            &[(
                "pci-dss/framework.toml",
                "id = \"pci-dss\"\nversion = \"4.0\"\ntitle = \"PCI\"\ndimension = \"flat\"\nprovides = [\"crossref\", \"controls\"]\n",
            )],
            &[("pci-dss/mappings/a.toml", "[log-admin]\nrisk = [\"10.5.1\"]\n")],
            &[("pci-dss/controls.toml", "[\"10.5.1\"]\ntitle = \"Log integrity\"\nowned = false\n")],
        );
        let risk = compute_framework_risk(&loaded, "pci-dss");
        assert!(risk
            .controls
            .contains(&("10.5.1".to_owned(), vec!["log-admin".to_owned()])));
        let human = render_framework_risk_human("pci-dss", &loaded, &risk);
        assert!(human.contains("⚠ 10.5.1"), "{human}");
        assert!(human.contains("[out-of-domain]"), "{human}");
        assert!(human.contains("threatened by: log-admin"), "{human}");
        let json = render_framework_risk_json("pci-dss", &loaded, &risk);
        assert!(json.contains("\"id\":\"10.5.1\""), "{json}");
        assert!(json.contains("\"owned\":false"), "{json}");
        assert!(json.contains("\"threatened_by\":[\"log-admin\"]"), "{json}");
    }

    #[test]
    fn framework_coverage_ignores_risk_and_related() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = load_fw_tree(
            tmp.path(),
            &[(
                "pci-dss/framework.toml",
                "id = \"pci-dss\"\nversion = \"4.0\"\ntitle = \"PCI\"\ndimension = \"flat\"\nprovides = [\"crossref\", \"controls\"]\n",
            )],
            &[("pci-dss/mappings/a.toml", "[log-admin]\nrisk = [\"7.2.2\"]\n")],
            &[("pci-dss/controls.toml", "[\"7.2.2\"]\ntitle = \"Least privilege\"\nowned = true\n")],
        );
        let cov = compute_framework_coverage(&loaded, "pci-dss");
        assert!(!cov.covered.contains(&"7.2.2".to_owned()));
        assert!(cov.gap.contains(&"7.2.2".to_owned()));
    }

    #[test]
    fn run_framework_risk_missing_framework_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let _ = pci_dss_tree(tmp.path());
        let root = tmp.path().join("frameworks");
        let code = run_framework_risk("nope", vec![root], Some("linux-debian".to_owned()), true);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
    }
}
