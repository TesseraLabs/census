//! CLI command implementations.

use crate::apply::{self, ApplyInputs};
use crate::backup::{Backup, BackupTargets};
use crate::lockout::LockoutContext;
use crate::mutate::ShadowUtilsProvisioner;
use crate::state::SystemState;
use crate::trust::TrustOptions;
use crate::{declaration::Declaration, model, plan, state::RegistryState};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Render a plan as human-readable lines.
pub fn render_plan(p: &plan::Plan) -> String {
    if p.is_empty() {
        return "in sync — no changes\n".to_owned();
    }
    let mut out = String::new();
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
    let p = plan::diff(&targets, &state);
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
    // provisioner detect a UID change on update.
    // INTEGRATION (task 7): before snapshot(), call backup.add_file() for each touched /etc/sudoers.d/census-<role> when sudoers writing lands, else a sudoers write won't roll back (spec R2).
    let mut backup = Backup::new(BackupTargets::auth_db_default(), opts.rollback_root.clone());
    let managed_now = state.managed_accounts();

    let inputs = ApplyInputs {
        declaration: &decl,
        state: &state,
        trust: TrustOptions { trust_fs: opts.trust_fs },
        lockout: LockoutContext {
            // Rescue presence is determined out of band; absent that signal we
            // require explicit risk acknowledgement (handled by the gate).
            rescue_present: false,
            risk_acknowledged: opts.risk_acknowledged,
        },
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
                if let Err(e) = apply::write_registry(opts.managed, &report.managed) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::ExitCode;

    /// Write a role-store slice + a declaration whose single role-account, once
    /// resolved, exactly matches the managed record below (→ empty plan).
    fn fixtures(dir: &Path) -> (PathBuf, PathBuf) {
        let store = dir.join("roles");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(
            store.join("oper.toml"),
            "role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"Operator\"\nlevel = 5\n[payload]\ngroups = [\"wheel\"]\n",
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
            "[[account]]\nname = \"oper\"\nuid = 9010\nshell = \"/bin/bash\"\ngroups = [\"wheel\"]\nfrom_version = 5\n",
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
    }
}
