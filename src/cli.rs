//! CLI command implementations.

use crate::apply::{self, ApplyInputs};
use crate::backup::{Backup, BackupTargets};
use crate::doctor::{self, DoctorReport};
use crate::inspect::LiveInspector;
use crate::lockout::LockoutContext;
use crate::model::ResolvedAccount;
use crate::mutate::ShadowUtilsProvisioner;
use crate::state::SystemState;
use crate::status;
use crate::trust::{self, TrustMode, TrustOptions};
use crate::{declaration::Declaration, model, plan, state::RegistryState};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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

/// Run `census plan`: parse declaration, resolve against role-store, diff vs
/// managed registry, print the plan. Returns a non-zero exit on any error.
pub fn run_plan(declaration: &Path, managed: &Path) -> ExitCode {
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
    let targets = match model::resolve(&decl) {
        Ok(t) => t,
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
            println!("applied: {} mutation(s)", report.mutations);
            ExitCode::SUCCESS
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
    match model::resolve(&decl) {
        Ok(t) => Some(t),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::ExitCode;

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
}
