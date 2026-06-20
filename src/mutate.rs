//! Account mutation via shadow-utils (spec R1).
//!
//! Census does NOT edit `/etc/passwd`/`/etc/shadow`/`/etc/group`/`/etc/gshadow`
//! directly; it drives `useradd`/`usermod`/`gpasswd`/`userdel` (+ `chfn`,
//! `passwd -l`) with **argv arrays** (never a shell string, no injection
//! surface — PwnKit lesson). Success/failure is the process exit code, not
//! stdout.
//!
//! This module separates two concerns so the logic is unit-testable without
//! root:
//!   * pure **argv builders** (`build_create_argv`, `build_update_argv`,
//!     `build_delete_argv`) returning `Vec<Vec<String>>` — one inner vec per
//!     command to run, in order;
//!   * the [`Provisioner`] trait + [`ShadowUtilsProvisioner`] that actually
//!     executes them.
//!
//! The orchestrator ([`crate::apply`]) depends on the trait, so it can be driven
//! by a fake in tests.

use crate::model::ResolvedAccount;
use crate::state::ManagedAccount;
use std::process::Command;

/// GECOS marker prefix written via `chfn`. Astra's `useradd -c` rejects `:`/`=`,
/// so the marker is deliberately a single token containing neither character.
pub const GECOS_MARKER_PREFIX: &str = "census-role-";

/// Build the GECOS marker string for a role. Contains no `:` or `=` (Astra
/// `useradd -c` / `chfn` constraint; spec requirement "Маркер managed").
pub fn gecos_marker(role: &str) -> String {
    format!("{GECOS_MARKER_PREFIX}{role}")
}

/// Errors raised while building or executing mutations.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// A managed account's UID would change — rejected (UID is fleet-stable §10).
    #[error("refusing to change UID of managed account {name:?}: {from} -> {to} (UID is stable; not overwritten)")]
    UidChange {
        /// Account name.
        name: String,
        /// Current recorded UID.
        from: u32,
        /// Requested UID.
        to: u32,
    },
    /// An update was requested for an account with no managed record. This is a
    /// plan/state inconsistency (the diff produced an Update for an account the
    /// registry does not track), distinct from a UID change.
    #[error("no managed record for account {name}")]
    MissingManagedRecord {
        /// Account name.
        name: String,
    },
    /// A shadow-utils command exited non-zero.
    #[error("command {cmd:?} failed with status {status}: {stderr}")]
    CommandFailed {
        /// argv of the failed command.
        cmd: Vec<String>,
        /// Exit status string.
        status: String,
        /// Captured stderr (trimmed).
        stderr: String,
    },
    /// A shadow-utils command could not be spawned.
    #[error("cannot run command {cmd:?}: {reason}")]
    Spawn {
        /// argv of the command.
        cmd: Vec<String>,
        /// OS error.
        reason: String,
    },
    /// Backup/restore propagated through the provisioner.
    #[error("snapshot/restore failed: {0}")]
    Backup(String),
    /// A sudoers file write/validation failed.
    #[error("sudoers materialization failed: {0}")]
    Sudoers(String),
}

/// Build the ordered argv list to **create** a role account.
///
/// `useradd -u <uid> -m -d <home> -s <shell>` (NO `-c`: Astra GECOS quirk),
/// then group membership, then the GECOS marker via `chfn`, then `passwd -l`
/// to lock the password (reachability invariant §8). authorized_keys is NEVER
/// created here.
pub fn build_create_argv(acct: &ResolvedAccount) -> Vec<Vec<String>> {
    let mut cmds = Vec::new();

    let mut useradd = vec![
        "useradd".to_owned(),
        "-u".to_owned(),
        acct.uid.to_string(),
        "-m".to_owned(),
        "-d".to_owned(),
        acct.home.display().to_string(),
        "-s".to_owned(),
        acct.shell.clone(),
    ];
    if !acct.groups.is_empty() {
        useradd.push("-G".to_owned());
        useradd.push(acct.groups.join(","));
    }
    useradd.push(acct.name.clone());
    cmds.push(useradd);

    // GECOS marker via chfn (safe charset, no ':' or '=').
    cmds.push(vec![
        "chfn".to_owned(),
        "-f".to_owned(),
        gecos_marker(&acct.name),
        acct.name.clone(),
    ]);

    // Lock the password (shadow field becomes '!...'): role accounts are
    // unreachable by password by construction (§8).
    cmds.push(vec!["passwd".to_owned(), "-l".to_owned(), acct.name.clone()]);

    cmds
}

/// Build the ordered argv list to **update** an existing managed account to the
/// target. Rejects a UID change (returns `Err`) rather than overwriting.
///
/// `current` is the managed record (authoritative for the recorded UID). Shell
/// drift → `usermod -s`; group drift → `usermod -G <set>` (set semantics over
/// the role's managed groups).
pub fn build_update_argv(
    acct: &ResolvedAccount,
    current: &ManagedAccount,
) -> Result<Vec<Vec<String>>, ProvisionError> {
    if acct.uid != current.uid {
        return Err(ProvisionError::UidChange {
            name: acct.name.clone(),
            from: current.uid,
            to: acct.uid,
        });
    }

    let mut cmds = Vec::new();

    if acct.shell != current.shell {
        cmds.push(vec![
            "usermod".to_owned(),
            "-s".to_owned(),
            acct.shell.clone(),
            acct.name.clone(),
        ]);
    }

    let mut tg = acct.groups.clone();
    let mut cg = current.groups.clone();
    tg.sort();
    cg.sort();
    if tg != cg {
        // `usermod -G <full set>` replaces the supplementary group list
        // absolutely (any group not listed is removed). This is intentional, not
        // a bug: Census OWNS the complete supplementary group set of a managed
        // role-account. Role accounts are not human accounts — they have no
        // legitimate out-of-band group memberships an operator might have added,
        // so reconciling toward the declared set with absolute semantics is
        // exactly the desired behavior (the role's declaration is authoritative).
        cmds.push(vec![
            "usermod".to_owned(),
            "-G".to_owned(),
            acct.groups.join(","),
            acct.name.clone(),
        ]);
    }

    Ok(cmds)
}

/// Build the argv to **delete** a managed account: `userdel -r <name>` (removes
/// the home tree). Gating against lockout / live sessions happens upstream.
pub fn build_delete_argv(name: &str) -> Vec<Vec<String>> {
    vec![vec![
        "userdel".to_owned(),
        "-r".to_owned(),
        name.to_owned(),
    ]]
}

/// Backup/restore hook used by the orchestrator for atomicity (spec R2).
///
/// The orchestrator wraps mutation in `snapshot()` … (phases) … and on any
/// phase error calls `restore()`. Implementations back up the auth DB + touched
/// sudoers files.
pub trait Provisioner {
    /// Create a new role account (and lock its password, set marker, groups).
    fn create(&mut self, acct: &ResolvedAccount) -> Result<(), ProvisionError>;
    /// Reconcile an existing managed account toward `acct`. `changes` are the
    /// human-readable diffs (for logging); the authoritative current record is
    /// carried by the implementation if needed.
    fn update(&mut self, acct: &ResolvedAccount, changes: &[String])
        -> Result<(), ProvisionError>;
    /// Delete a managed account by name.
    fn delete(&mut self, name: &str) -> Result<(), ProvisionError>;
    /// Snapshot auth DB + touched sudoers files before mutation.
    fn snapshot(&mut self) -> Result<(), ProvisionError>;
    /// Restore from the snapshot taken by [`Provisioner::snapshot`].
    fn restore(&mut self) -> Result<(), ProvisionError>;
}

/// Real provisioner: runs shadow-utils via `std::process::Command` (argv array)
/// and delegates atomicity to an injected [`crate::backup::Backup`].
///
/// Update needs the *current* managed record to detect a UID change; it is
/// looked up from the supplied managed map by name.
pub struct ShadowUtilsProvisioner<'a> {
    managed: std::collections::BTreeMap<String, ManagedAccount>,
    backup: &'a mut crate::backup::Backup,
}

impl<'a> ShadowUtilsProvisioner<'a> {
    /// Build a real provisioner over the current managed snapshot and a backup.
    pub fn new(
        managed: std::collections::BTreeMap<String, ManagedAccount>,
        backup: &'a mut crate::backup::Backup,
    ) -> Self {
        ShadowUtilsProvisioner { managed, backup }
    }

    /// Run one argv command, mapping non-zero exit / spawn failure to errors.
    fn run(cmd: &[String]) -> Result<(), ProvisionError> {
        let (program, args) = cmd.split_first().ok_or_else(|| ProvisionError::Spawn {
            cmd: cmd.to_vec(),
            reason: "empty argv".to_owned(),
        })?;
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|e| ProvisionError::Spawn {
                cmd: cmd.to_vec(),
                reason: e.to_string(),
            })?;
        if output.status.success() {
            Ok(())
        } else {
            Err(ProvisionError::CommandFailed {
                cmd: cmd.to_vec(),
                status: output.status.to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            })
        }
    }

    fn run_all(cmds: &[Vec<String>]) -> Result<(), ProvisionError> {
        for cmd in cmds {
            Self::run(cmd)?;
        }
        Ok(())
    }
}

impl Provisioner for ShadowUtilsProvisioner<'_> {
    fn create(&mut self, acct: &ResolvedAccount) -> Result<(), ProvisionError> {
        Self::run_all(&build_create_argv(acct))
    }

    fn update(
        &mut self,
        acct: &ResolvedAccount,
        _changes: &[String],
    ) -> Result<(), ProvisionError> {
        let current = self
            .managed
            .get(&acct.name)
            .ok_or_else(|| ProvisionError::MissingManagedRecord {
                name: acct.name.clone(),
            })?;
        let cmds = build_update_argv(acct, current)?;
        Self::run_all(&cmds)
    }

    fn delete(&mut self, name: &str) -> Result<(), ProvisionError> {
        Self::run_all(&build_delete_argv(name))
    }

    fn snapshot(&mut self) -> Result<(), ProvisionError> {
        self.backup
            .snapshot()
            .map_err(|e| ProvisionError::Backup(e.to_string()))
    }

    fn restore(&mut self) -> Result<(), ProvisionError> {
        self.backup
            .restore()
            .map_err(|e| ProvisionError::Backup(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rolestore::Limits;
    use std::path::PathBuf;

    fn acct(name: &str, uid: u32, shell: &str, groups: &[&str]) -> ResolvedAccount {
        ResolvedAccount {
            name: name.to_owned(),
            uid,
            shell: shell.to_owned(),
            home: PathBuf::from(format!("/var/lib/census/home/{name}")),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            sudo_role: None,
            limits: Limits::default(),
            locked_password: true,
        }
    }

    fn managed(name: &str, uid: u32, shell: &str, groups: &[&str]) -> ManagedAccount {
        ManagedAccount {
            name: name.to_owned(),
            uid,
            shell: shell.to_owned(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            from_version: 1,
        }
    }

    #[test]
    fn create_argv_uses_explicit_uid_home_shell_and_locks_password() {
        let cmds = build_create_argv(&acct("oper", 9010, "/bin/bash", &["wheel", "docker"]));
        // useradd with explicit -u, -m, -d, -s; NO -c.
        let useradd = &cmds[0];
        assert_eq!(useradd[0], "useradd");
        assert!(useradd.contains(&"-u".to_owned()));
        assert!(useradd.contains(&"9010".to_owned()));
        assert!(useradd.contains(&"-m".to_owned()));
        assert!(useradd.contains(&"-d".to_owned()));
        assert!(useradd.contains(&"-s".to_owned()));
        assert!(useradd.contains(&"/bin/bash".to_owned()));
        assert!(!useradd.contains(&"-c".to_owned()), "must NOT pass -c (Astra GECOS quirk)");
        assert!(useradd.contains(&"-G".to_owned()));
        assert!(useradd.contains(&"wheel,docker".to_owned()));
        // last command locks the password.
        let last = cmds.last().unwrap();
        assert_eq!(last, &vec!["passwd".to_owned(), "-l".to_owned(), "oper".to_owned()]);
    }

    #[test]
    fn create_never_emits_authorized_keys() {
        let cmds = build_create_argv(&acct("oper", 9010, "/bin/bash", &[]));
        for c in &cmds {
            for tok in c {
                assert!(
                    !tok.contains("authorized_keys"),
                    "create must never touch authorized_keys, got {tok:?}"
                );
            }
        }
    }

    #[test]
    fn create_without_groups_omits_g_flag() {
        let cmds = build_create_argv(&acct("serv", 9020, "/bin/bash", &[]));
        assert!(!cmds[0].contains(&"-G".to_owned()));
    }

    #[test]
    fn gecos_marker_has_no_forbidden_chars() {
        for role in ["oper", "a-b-c", "serv9"] {
            let m = gecos_marker(role);
            assert!(!m.contains(':'), "marker {m:?} must not contain ':'");
            assert!(!m.contains('='), "marker {m:?} must not contain '='");
            assert!(m.starts_with(GECOS_MARKER_PREFIX));
        }
    }

    #[test]
    fn create_sets_gecos_marker_via_chfn() {
        let cmds = build_create_argv(&acct("oper", 9010, "/bin/bash", &[]));
        let chfn = cmds.iter().find(|c| c[0] == "chfn").expect("chfn marker call");
        assert!(chfn.contains(&gecos_marker("oper")));
        // and the marker token itself carries no ':' or '='.
        let marker = &chfn[2];
        assert!(!marker.contains(':') && !marker.contains('='));
    }

    #[test]
    fn update_uid_change_is_rejected() {
        let target = acct("oper", 9999, "/bin/bash", &[]);
        let current = managed("oper", 9010, "/bin/bash", &[]);
        let err = build_update_argv(&target, &current).unwrap_err();
        assert!(matches!(err, ProvisionError::UidChange { from: 9010, to: 9999, .. }));
    }

    #[test]
    fn update_shell_emits_usermod_s() {
        let target = acct("oper", 9010, "/bin/zsh", &["wheel"]);
        let current = managed("oper", 9010, "/bin/bash", &["wheel"]);
        let cmds = build_update_argv(&target, &current).unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0], vec!["usermod", "-s", "/bin/zsh", "oper"]);
    }

    #[test]
    fn update_groups_emits_usermod_g_set() {
        let target = acct("oper", 9010, "/bin/bash", &["wheel", "docker"]);
        let current = managed("oper", 9010, "/bin/bash", &["wheel"]);
        let cmds = build_update_argv(&target, &current).unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0][0], "usermod");
        assert!(cmds[0].contains(&"-G".to_owned()));
        assert!(cmds[0].contains(&"wheel,docker".to_owned()));
    }

    #[test]
    fn update_in_sync_emits_nothing() {
        let target = acct("oper", 9010, "/bin/bash", &["wheel", "docker"]);
        let current = managed("oper", 9010, "/bin/bash", &["docker", "wheel"]);
        let cmds = build_update_argv(&target, &current).unwrap();
        assert!(cmds.is_empty(), "no drift → no commands");
    }

    #[test]
    fn delete_uses_userdel_r() {
        let cmds = build_delete_argv("oper");
        assert_eq!(cmds, vec![vec!["userdel", "-r", "oper"]]);
    }

    #[test]
    fn update_without_managed_record_errors_missing_record_not_uid_change() {
        // An Update for an account the registry does not track is a plan/state
        // inconsistency. It must surface as MissingManagedRecord — NOT a faked
        // UidChange { from: 0 } — and must fail before any command runs.
        let tmp = tempfile::tempdir().unwrap();
        let mut backup = crate::backup::Backup::new(
            crate::backup::BackupTargets { files: vec![] },
            tmp.path().join("rollback"),
        );
        // Empty managed map → lookup for "oper" fails.
        let mut provisioner =
            ShadowUtilsProvisioner::new(std::collections::BTreeMap::new(), &mut backup);
        let target = acct("oper", 9010, "/bin/bash", &["wheel"]);
        let err = provisioner.update(&target, &[]).unwrap_err();
        assert!(
            matches!(err, ProvisionError::MissingManagedRecord { ref name } if name == "oper"),
            "expected MissingManagedRecord, got {err:?}"
        );
    }
}
