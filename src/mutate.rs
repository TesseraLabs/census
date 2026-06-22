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

use crate::model::{ResolvedAccount, ResolvedGroup};
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

impl From<crate::sudoers::SudoersError> for ProvisionError {
    fn from(e: crate::sudoers::SudoersError) -> Self {
        ProvisionError::Sudoers(e.to_string())
    }
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

/// Build the argv to **create** a group: `groupadd [-g <gid>] <name>`. The
/// `-g` flag pins the GID when the declaration requested one (else the OS
/// assigns it). argv array — no shell, no injection surface.
pub fn build_create_group_argv(name: &str, gid: Option<u32>) -> Vec<Vec<String>> {
    let mut cmd = vec!["groupadd".to_owned()];
    if let Some(g) = gid {
        cmd.push("-g".to_owned());
        cmd.push(g.to_string());
    }
    cmd.push(name.to_owned());
    vec![cmd]
}

/// Build the argv to **delete** a group: `groupdel <name>`. The OS refuses if
/// the group is the primary group of any account — Census only deletes groups
/// it created (registry-owned) and only after its accounts are removed.
pub fn build_delete_group_argv(name: &str) -> Vec<Vec<String>> {
    vec![vec!["groupdel".to_owned(), name.to_owned()]]
}

/// Build the argv to **add** a member to a group: `gpasswd -a <member> <group>`.
/// `gpasswd -a` adds one user to the supplementary member list without touching
/// the rest of it — the surgical add Census needs so it only ever manages its
/// own members and never disturbs the group's pre-existing/foreign membership.
/// argv array — no shell, no injection surface.
pub fn build_gpasswd_add_argv(group: &str, member: &str) -> Vec<Vec<String>> {
    vec![vec![
        "gpasswd".to_owned(),
        "-a".to_owned(),
        member.to_owned(),
        group.to_owned(),
    ]]
}

/// Build the argv to **remove** a member from a group: `gpasswd -d <member>
/// <group>`. `gpasswd -d` removes one user from the supplementary member list,
/// leaving every other member intact — the surgical removal that lets a release
/// strip only Census-added members without evicting the group's baseline ones.
pub fn build_gpasswd_del_argv(group: &str, member: &str) -> Vec<Vec<String>> {
    vec![vec![
        "gpasswd".to_owned(),
        "-d".to_owned(),
        member.to_owned(),
        group.to_owned(),
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
    /// Create a group via `groupadd` (pinning the GID when `gid` is `Some`).
    /// Runs in the group-create phase, BEFORE account creation, so membership
    /// (`useradd -G`) finds the group.
    fn create_group(&mut self, name: &str, gid: Option<u32>) -> Result<(), ProvisionError>;
    /// Delete a Census-owned group via `groupdel`. Runs in the group-delete
    /// phase, AFTER account deletion, so the group has no members.
    fn delete_group(&mut self, name: &str) -> Result<(), ProvisionError>;
    /// Materialize (or clear) the sudoers fragment for an account: if the
    /// account carries a sudo right ([`crate::sudoers::build_sudoers_content`]
    /// yields `Some`), write & validate `census-<role>`; otherwise ensure the
    /// fragment does not exist (a role that dropped sudo must lose its file).
    fn apply_sudoers(&mut self, acct: &ResolvedAccount) -> Result<(), ProvisionError>;
    /// Remove the `census-<name>` sudoers fragment for a deleted role
    /// (idempotent: absent fragment is success).
    fn remove_sudoers(&mut self, name: &str) -> Result<(), ProvisionError>;
    /// Materialize (or clear) the `%group` sudoers fragment for a group: if the
    /// group's bound roles grant sudo commands
    /// ([`crate::sudoers::build_group_sudoers_content`] yields `Some`), write &
    /// validate `census-grp-<group>`; otherwise ensure the fragment does not
    /// exist (a group that dropped its last sudo grant must lose its file).
    fn apply_group_sudoers(&mut self, group: &ResolvedGroup) -> Result<(), ProvisionError>;
    /// Remove the `census-grp-<group>` sudoers fragment Census owns for a group
    /// (idempotent: absent fragment is success). Named distinctly from
    /// [`crate::sudoers::remove_group_sudoers`] so the trait method and the free
    /// function do not collide at call sites.
    fn remove_group_sudoers_for(&mut self, group: &str) -> Result<(), ProvisionError>;
    /// Add `member` to `group` via `gpasswd -a` (surgical: only this member is
    /// touched, the group's other members are left intact).
    fn add_group_member(&mut self, group: &str, member: &str) -> Result<(), ProvisionError>;
    /// Remove `member` from `group` via `gpasswd -d` (surgical: only this member
    /// is removed; the group's pre-existing/foreign members stay).
    fn remove_group_member(&mut self, group: &str, member: &str)
        -> Result<(), ProvisionError>;
    /// Register a sudoers fragment path in the pre-mutation backup set, so a
    /// later-phase failure rolls the fragment back too (spec R2). Called by the
    /// orchestrator for every touched fragment BEFORE [`Provisioner::snapshot`].
    fn track_sudoers_backup(&mut self, path: std::path::PathBuf);
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
    /// Directory the role sudoers fragments live in. Defaults to
    /// [`crate::sudoers::SUDOERS_DIR`]; injectable for tests/containers.
    sudoers_dir: std::path::PathBuf,
}

impl<'a> ShadowUtilsProvisioner<'a> {
    /// Build a real provisioner over the current managed snapshot and a backup,
    /// writing sudoers fragments under the production `/etc/sudoers.d`.
    pub fn new(
        managed: std::collections::BTreeMap<String, ManagedAccount>,
        backup: &'a mut crate::backup::Backup,
    ) -> Self {
        Self::with_sudoers_dir(
            managed,
            backup,
            std::path::PathBuf::from(crate::sudoers::SUDOERS_DIR),
        )
    }

    /// Build a real provisioner with an explicit sudoers directory (tests /
    /// containers inject a writable temp dir).
    pub fn with_sudoers_dir(
        managed: std::collections::BTreeMap<String, ManagedAccount>,
        backup: &'a mut crate::backup::Backup,
        sudoers_dir: std::path::PathBuf,
    ) -> Self {
        ShadowUtilsProvisioner {
            managed,
            backup,
            sudoers_dir,
        }
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

    fn create_group(&mut self, name: &str, gid: Option<u32>) -> Result<(), ProvisionError> {
        Self::run_all(&build_create_group_argv(name, gid))
    }

    fn delete_group(&mut self, name: &str) -> Result<(), ProvisionError> {
        Self::run_all(&build_delete_group_argv(name))
    }

    fn apply_sudoers(&mut self, acct: &ResolvedAccount) -> Result<(), ProvisionError> {
        match crate::sudoers::build_sudoers_content(acct) {
            Some(content) => {
                crate::sudoers::write_sudoers(&self.sudoers_dir, &acct.name, &content)?;
            }
            None => {
                // No sudo right → the fragment must not exist (drop-to-none).
                crate::sudoers::remove_sudoers(&self.sudoers_dir, &acct.name)?;
            }
        }
        Ok(())
    }

    fn remove_sudoers(&mut self, name: &str) -> Result<(), ProvisionError> {
        crate::sudoers::remove_sudoers(&self.sudoers_dir, name)?;
        Ok(())
    }

    fn apply_group_sudoers(&mut self, group: &ResolvedGroup) -> Result<(), ProvisionError> {
        match crate::sudoers::build_group_sudoers_content(group) {
            Some(content) => {
                crate::sudoers::write_group_sudoers(&self.sudoers_dir, &group.name, &content)?;
            }
            None => {
                // No group sudo grant → the %group fragment must not exist.
                crate::sudoers::remove_group_sudoers(&self.sudoers_dir, &group.name)?;
            }
        }
        Ok(())
    }

    fn remove_group_sudoers_for(&mut self, group: &str) -> Result<(), ProvisionError> {
        crate::sudoers::remove_group_sudoers(&self.sudoers_dir, group)?;
        Ok(())
    }

    fn add_group_member(&mut self, group: &str, member: &str) -> Result<(), ProvisionError> {
        Self::run_all(&build_gpasswd_add_argv(group, member))
    }

    fn remove_group_member(&mut self, group: &str, member: &str) -> Result<(), ProvisionError> {
        Self::run_all(&build_gpasswd_del_argv(group, member))
    }

    fn track_sudoers_backup(&mut self, path: std::path::PathBuf) {
        self.backup.add_file(path);
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
            sudo_commands: Vec::new(),
            limits: Limits::default(),
            file_grants: Vec::new(),
            locked_password: true,
            provenance: crate::model::Provenance::Created,
        }
    }

    fn managed(name: &str, uid: u32, shell: &str, groups: &[&str]) -> ManagedAccount {
        ManagedAccount {
            name: name.to_owned(),
            uid,
            shell: shell.to_owned(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            sudo_role: None,
            sudo_commands: Vec::new(),
            file_grants: Vec::new(),
            provenance: crate::model::Provenance::Created,
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
    fn create_group_pins_gid_when_present() {
        let cmds = build_create_group_argv("atm-operators", Some(8010));
        assert_eq!(cmds, vec![vec!["groupadd", "-g", "8010", "atm-operators"]]);
    }

    #[test]
    fn create_group_omits_g_when_unpinned() {
        let cmds = build_create_group_argv("tellers", None);
        assert_eq!(cmds, vec![vec!["groupadd", "tellers"]]);
        assert!(!cmds[0].contains(&"-g".to_owned()));
    }

    #[test]
    fn delete_group_uses_groupdel() {
        let cmds = build_delete_group_argv("atm-operators");
        assert_eq!(cmds, vec![vec!["groupdel", "atm-operators"]]);
    }

    #[test]
    fn gpasswd_add_uses_dash_a_member_then_group() {
        // `gpasswd -a <member> <group>` — member precedes group (gpasswd order).
        let cmds = build_gpasswd_add_argv("wheel", "netops");
        assert_eq!(cmds, vec![vec!["gpasswd", "-a", "netops", "wheel"]]);
    }

    #[test]
    fn gpasswd_del_uses_dash_d_member_then_group() {
        let cmds = build_gpasswd_del_argv("wheel", "netops");
        assert_eq!(cmds, vec![vec!["gpasswd", "-d", "netops", "wheel"]]);
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
