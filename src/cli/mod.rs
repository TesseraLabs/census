//! CLI command implementations.
//!
//! This module is the binary's entry point: `src/main.rs` parses the clap tree
//! (`crate::cli_def`) and dispatches to the `run_*` handlers re-exported here.
//! The implementation is split into cohesive submodules:
//!
//! * [`render`] — shared leaf formatting helpers (JSON escaper, tokens).
//! * [`lint`] — the risk-lint engine for `compile --lint`.
//! * [`compile`] — `compile`/`show` role expansion with provenance.
//! * [`framework`] — `framework {list,show,coverage,risk,lint}` cross-reference.
//! * [`coverage`] — `catalog {coverage,which-grants}` audit + reverse lookup.
//!
//! The plan / apply / doctor / status orchestration handlers — which drive trust,
//! the registry, and the live system — live directly in this module, alongside
//! the shared input helpers (`detect_os_target`, `default_catalog_roots`,
//! `read_declaration`, `resolve_targets`) and the pure exit-code mappers.

mod compile;
mod coverage;
mod framework;
mod lint;
mod render;

#[cfg(test)]
mod tests;

// --- Public re-exports: the surface external callers (main.rs, tests) name -----
//
// `census::cli::run_apply`, `census::cli::ShowOpts`, etc. must keep resolving to
// the same paths after the split, so every handler / option type / public render
// helper the binary and the integration tests reach for is re-exported here.
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub use compile::{
    compile_role, render_compile_human, render_compile_json, render_show_framework_human,
    render_show_framework_json, render_show_permissions_json, render_show_tree, run_compile,
    run_show, CompiledPermission, CompiledRole, FlatFileGrant, FlatPrimitive, FrameworkSelection,
    ShowOpts,
};
pub use coverage::{
    parse_classes, render_coverage_human, render_coverage_json, render_which_grants_human,
    render_which_grants_json, run_coverage, run_which_grants, CoverageOpts, WhichGrantsOpts,
};
pub use framework::{
    compute_framework_coverage, compute_framework_risk, render_framework_coverage_human,
    render_framework_coverage_json, render_framework_lint_human, render_framework_lint_json,
    render_framework_list_human, render_framework_list_json, render_framework_risk_human,
    render_framework_risk_json, render_framework_show_human, render_framework_show_json,
    run_framework_coverage, run_framework_lint, run_framework_list, run_framework_risk,
    run_framework_show, FrameworkCoverage, FrameworkRisk,
};
pub use lint::{lint_role, LintFinding, LintSeverity};

use crate::apply::{self, ApplyInputs};
use crate::backup::{Backup, BackupTargets};
use crate::catalog::{CatalogError, CatalogSource, LiveCatalog, OsTarget, ResolveCtx};
use crate::declaration::Declaration;
use crate::doctor::{self, DoctorReport};
use crate::fileaccess::AclBackend;
use crate::inspect::LiveInspector;
use crate::lockout::LockoutContext;
use crate::model::{CompileInputs, ResolvedAccount};
use crate::mutate::ShadowUtilsProvisioner;
use crate::sessions::LiveSessionSource;
use crate::state::{RegistryState, SystemState};
use crate::trust::{self, TrustMode, TrustOptions};
use crate::{framework as fw, model, plan, status};

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
pub(crate) fn detect_os_target(override_spec: Option<&str>) -> Result<OsTarget, CatalogError> {
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

/// Read and parse a declaration TOML, returning a human-readable error string on
/// an I/O or parse failure. Shared by the optional-declaration paths of coverage
/// and which-grants so both report a malformed declaration the same way.
pub(crate) fn read_declaration(path: &Path) -> Result<Declaration, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read declaration {}: {e}", path.display()))?;
    Declaration::parse(&text).map_err(|e| e.to_string())
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
                out.push_str(&format!(
                    "CREATE {} (uid {}, shell {})\n",
                    a.name, a.uid, a.shell
                ));
            }
            plan::Action::Update { account, changes } => {
                out.push_str(&format!(
                    "UPDATE {}: {}\n",
                    account.name,
                    changes.join(", ")
                ));
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
            eprintln!(
                "census: cannot read declaration {}: {e}",
                declaration.display()
            );
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
    let catalog = LiveCatalog::new(catalog_roots);
    let os = match detect_os_target(os_target) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let ctx = ResolveCtx {
        catalog_version: None,
    };
    let targets = match model::resolve(
        &decl,
        &CompileInputs {
            catalog: &catalog,
            os: &os,
            ctx: &ctx,
        },
    ) {
        Ok((t, warnings)) => {
            for w in &warnings {
                eprintln!("census: warning: {w}");
            }
            t
        }
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let state = match RegistryState::load(managed) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("census: {e}");
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
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let inspector = LiveInspector::new();
    match plan::diff_groups_via_inspector(&required, &state.managed_groups(), &inspector) {
        Ok(group_actions) => p.group_actions = group_actions,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    }
    print!("{}", render_plan(&p));
    ExitCode::SUCCESS
}

/// Options for `census apply` (CLI-derived).
#[derive(Debug)]
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
                "census: cannot read declaration {}: {e}",
                opts.declaration.display()
            );
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
    let state = match RegistryState::load(opts.managed) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("census: {e}");
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
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let ctx = ResolveCtx {
        catalog_version: None,
    };

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
        compile: crate::model::CompileInputs {
            catalog: &catalog,
            os: &os,
            ctx: &ctx,
        },
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
                    eprintln!("census: {e}");
                    return ExitCode::FAILURE;
                }
            }
            // Anti-rollback: persist the applied version AFTER a successful apply,
            // only in managed mode. Standalone (`--trust-fs`) never moves the floor.
            if let TrustMode::Managed { version } = report.trust_mode {
                if let Err(e) = trust::persist_version(&opts.persist_dir, version) {
                    eprintln!("census: {e}");
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
            eprintln!("census: {e}");
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
    let ctx = ResolveCtx {
        catalog_version: None,
    };
    match model::resolve(
        &decl,
        &CompileInputs {
            catalog: &catalog,
            os: &os,
            ctx: &ctx,
        },
    ) {
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
            eprintln!("census: {e}");
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
                    match fw::load_frameworks(&fw::default_framework_roots(), &os) {
                        Ok(loaded) => {
                            for w in &loaded.warnings {
                                report.findings.push(doctor::framework_load_warning(w));
                            }
                            report
                                .findings
                                .extend(doctor::framework_findings(&fw::lint_loaded(
                                    &loaded, &known,
                                )));
                        }
                        Err(fw::FrameworkError::IdCollision { id }) => {
                            let lint = fw::FrameworkLint {
                                code: "id-collision",
                                severity: fw::FrameworkLintSeverity::Error,
                                message: format!(
                                    "framework id {id} declared in two roots (determinism)"
                                ),
                            };
                            report.findings.extend(doctor::framework_findings(&[lint]));
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
pub(crate) fn apply_exit_code(deferred: usize) -> ExitCode {
    if deferred == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    }
}

/// Map a doctor report to its process exit code: non-zero iff it has errors.
/// Extracted as a pure function so the exit-code policy is unit-testable
/// without a live system.
pub(crate) fn doctor_exit_code(report: &DoctorReport) -> ExitCode {
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
            print!(
                "{}",
                status::render_status(&RegistryState::default_empty(), None, None)
            );
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
    print!(
        "{}",
        status::render_status(&state, persisted, drift.as_ref())
    );
    ExitCode::SUCCESS
}
