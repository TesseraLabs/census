//! Current Census-managed state.
//!
//! This slice reads ONLY the managed registry (`/var/lib/census/managed.toml`)
//! — what Census previously recorded as managed. It does NOT read live
//! `/etc/passwd` (live drift is a later slice). The registry is authoritative
//! for "what Census manages" (spec §4).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A single file-access grant as last recorded by Census for an account.
///
/// Persisted so granting or revoking a permission that changes the file-grant
/// set is visible to the plan diff — the same privilege-revocation correctness
/// `sudo_commands` gets. The registry is the authority for *what to revoke*: a
/// grant that drops out of the resolved set but is still recorded here is the
/// backend's signal to remove its ACL entry (otherwise a revoked grant would
/// leak as a stale ACL). Only the enforcement-relevant fields are stored
/// (`path`/`access`/`recursive`); provenance and the derived shape are
/// recomputable from these at resolve time and need not be persisted.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ManagedFileGrant {
    /// Absolute path the grant targets.
    pub path: String,
    /// The set of access bits the grant carried (read/write/execute/traverse).
    pub access: crate::catalog::Access,
    /// Whether the grant applied recursively (directory grant).
    pub recursive: bool,
}

impl ManagedFileGrant {
    /// Project a resolved grant down to the persisted record (dropping provenance
    /// and the derived shape, which are recomputed at resolve time).
    pub fn from_resolved(g: &crate::catalog::ResolvedFileGrant) -> Self {
        ManagedFileGrant {
            path: g.path.clone(),
            access: g.access,
            recursive: g.recursive,
        }
    }
}

/// Snapshot of an adopted group's state at the moment Census adopted it — so a
/// later release can return it to "how it was" (its GID and pre-existing
/// members) without deleting the group itself.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct GroupBaseline {
    /// GID the group had at adopt time, or `None` when Census could not read it
    /// back at adopt. `None` is "GID unknown", kept distinct from a real GID `0`
    /// (root group): a later drift check skips an unknown baseline GID rather
    /// than spuriously flagging the live GID against `0`. `#[serde(default)]` so
    /// a baseline written before the field was optional reads cleanly as `None`.
    #[serde(default)]
    pub gid: Option<u32>,
    /// Members the group had at adopt time (pre-existing, foreign — preserved on
    /// release). `#[serde(default)]` so a baseline written with no members reads
    /// as empty.
    #[serde(default)]
    pub members: Vec<String>,
}

/// A single managed account as last recorded by Census.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ManagedAccount {
    /// Unix login name.
    pub name: String,
    /// Recorded UID.
    pub uid: u32,
    /// Recorded shell.
    pub shell: String,
    /// Recorded groups.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Recorded sudo role grant, if any. `None` means the account has no
    /// Census-owned sudoers fragment. Persisted so a sudo-only grant/revocation
    /// is visible to the plan diff (otherwise a revoked fragment leaks).
    #[serde(default)]
    pub sudo_role: Option<String>,
    /// Recorded concrete sudo commands (permission-expanded), each paired with
    /// the account it runs as. Persisted so that granting, revoking, or
    /// *re-targeting* (root → service account) a permission which changes the
    /// sudo command set is visible to the plan diff — the same
    /// privilege-revocation correctness that `sudo_role` gets, but for the
    /// concrete-command path (otherwise a stale NOPASSWD rule, or a stale
    /// run-spec, would leak after a permission changes). Each entry serializes as
    /// a bare string for a root command (`"/usr/sbin/ip"`) and as a `{ command,
    /// runas }` table only when narrowed, so a registry written before `runas`
    /// existed — and every all-root account — keeps its on-disk form unchanged.
    /// `#[serde(default)]` so a registry written before this field existed still
    /// reads (empty set).
    #[serde(default)]
    pub sudo_commands: Vec<crate::model::SudoCommand>,
    /// Recorded file-access grants (permission-expanded). Persisted so granting
    /// or revoking a permission that changes the file-grant set is visible to
    /// the plan diff and so the backend knows which ACL entries to revoke when a
    /// grant disappears (the registry is the authority for revocation).
    /// `#[serde(default)]` so a registry written before this field existed still
    /// reads (empty set).
    #[serde(default)]
    pub file_grants: Vec<ManagedFileGrant>,
    /// Provenance: `Created` — Census made the account (teardown is a full
    /// `userdel`); `Adopted` — the account was external and Census only bound
    /// grants to it (teardown strips the grants, the user is NEVER deleted).
    /// `#[serde(default)]` so a registry written before this field existed reads
    /// as `Created`. (No account-baseline is stored: an adopted user has no
    /// attributes to restore — Census only removes its own grants — so
    /// `provenance = Adopted` is enough.)
    #[serde(default)]
    pub provenance: crate::model::Provenance,
    /// Declaration `version` this account was created/updated from.
    pub from_version: u32,
}

/// A single managed group as last recorded by Census. A group is recorded here
/// whether Census created it (`groupadd`) or adopted a pre-existing one; the
/// `provenance` field distinguishes the two and drives the teardown contract
/// (full `groupdel` for `Created`, release-to-baseline for `Adopted`). The
/// registry stores what Census actually applied — its own grants and its own
/// added members — not the recomputable bindings.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ManagedGroup {
    /// Group name.
    pub name: String,
    /// Recorded GID (the GID the group had when Census created it — pinned or
    /// OS-assigned), or `None` when Census could not read it back at apply time.
    /// `None` is "GID unknown", kept distinct from a real GID `0` (root group):
    /// drift checks skip an unknown GID rather than spuriously flagging it against
    /// `0`. `#[serde(default)]` so a registry that omits the field (or was written
    /// before it was optional) reads cleanly as `None`.
    #[serde(default)]
    pub gid: Option<u32>,
    /// Provenance: `Created` (Census made the group; teardown is `groupdel`) or
    /// `Adopted` (pre-existing; teardown releases to baseline, never deletes).
    /// `#[serde(default)]` so a registry written before this field existed reads
    /// as `Created`.
    #[serde(default)]
    pub provenance: crate::model::Provenance,
    /// Members Census itself added to this group (for surgical removal on
    /// release / membership change: drop ONLY our own, never the foreign /
    /// baseline members). `#[serde(default)]` so an old registry reads as empty.
    #[serde(default)]
    pub members_added: Vec<String>,
    /// Concrete sudo commands bound to the group (for diff / revocation — same
    /// authority the account record carries), each paired with the account it
    /// runs as. Serializes a root command as a bare string and a narrowed one as
    /// a `{ command, runas }` table, keeping an all-root group's on-disk form
    /// unchanged. `#[serde(default)]` so an old registry reads as empty.
    #[serde(default)]
    pub sudo_commands: Vec<crate::model::SudoCommand>,
    /// File-access grants on the group (`g:group` ACL) — for diff and the
    /// authority of revocation. `#[serde(default)]` so an old registry reads as
    /// empty.
    #[serde(default)]
    pub file_grants: Vec<ManagedFileGrant>,
    /// Baseline snapshot captured at adopt (`None` for `Created`). Restored on
    /// release. `#[serde(default)]` so an old registry reads as `None`.
    #[serde(default)]
    pub adopt_baseline: Option<GroupBaseline>,
    /// Declaration `version` this group was created from.
    pub from_version: u32,
}

/// Read-only view of the current managed state.
pub trait SystemState {
    /// Managed accounts keyed by name.
    fn managed_accounts(&self) -> BTreeMap<String, ManagedAccount>;
    /// Managed groups keyed by name. Default empty so existing fakes / callers
    /// that predate group-provisioning keep compiling with no group state.
    fn managed_groups(&self) -> BTreeMap<String, ManagedGroup> {
        BTreeMap::new()
    }
}

/// Registry-backed state read from `managed.toml`. Absent file = empty state.
#[derive(Debug)]
pub struct RegistryState {
    accounts: BTreeMap<String, ManagedAccount>,
    groups: BTreeMap<String, ManagedGroup>,
}

/// On-disk shape of the managed registry (`managed.toml`): the `[[account]]`
/// and `[[group]]` arrays. Strict (`deny_unknown_fields`) — Census owns this
/// file and an unknown key is a typo or a smuggled field. `pub` so the
/// interface-contract test can generate its golden schema.
#[derive(Debug, serde::Deserialize, Default)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct RegistryFile {
    #[serde(default, rename = "account")]
    accounts: Vec<ManagedAccount>,
    #[serde(default, rename = "group")]
    groups: Vec<ManagedGroup>,
}

/// Errors reading the managed registry.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StateError {
    /// Registry file exists but cannot be read.
    #[error("cannot read managed registry {path}: {source}")]
    Io {
        /// The registry path consulted.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Registry TOML is malformed.
    #[error("managed registry {path} is invalid: {source}")]
    TomlParse {
        /// The registry path consulted.
        path: PathBuf,
        /// The underlying TOML deserialization error.
        #[source]
        source: toml::de::Error,
    },
}

impl RegistryState {
    /// An empty registry (no managed accounts). Useful as a read-only fallback
    /// when the on-disk registry cannot be loaded and the caller must not fail.
    pub fn default_empty() -> Self {
        RegistryState {
            accounts: BTreeMap::new(),
            groups: BTreeMap::new(),
        }
    }

    /// Load the registry. A missing file yields an empty (no-managed) state.
    pub fn load(path: &Path) -> Result<Self, StateError> {
        if !path.exists() {
            return Ok(RegistryState::default_empty());
        }
        let text = std::fs::read_to_string(path).map_err(|source| StateError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let file: RegistryFile = toml::from_str(&text).map_err(|source| StateError::TomlParse {
            path: path.to_path_buf(),
            source,
        })?;
        let accounts = file
            .accounts
            .into_iter()
            .map(|a| (a.name.clone(), a))
            .collect();
        let groups = file
            .groups
            .into_iter()
            .map(|g| (g.name.clone(), g))
            .collect();
        Ok(RegistryState { accounts, groups })
    }
}

impl SystemState for RegistryState {
    fn managed_accounts(&self) -> BTreeMap<String, ManagedAccount> {
        self.accounts.clone()
    }

    fn managed_groups(&self) -> BTreeMap<String, ManagedGroup> {
        self.groups.clone()
    }
}

/// In-memory state for tests.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct FakeState {
    /// The managed accounts this fake reports.
    pub accounts: BTreeMap<String, ManagedAccount>,
    /// The managed groups this fake reports.
    pub groups: BTreeMap<String, ManagedGroup>,
}

#[cfg(test)]
impl SystemState for FakeState {
    fn managed_accounts(&self) -> BTreeMap<String, ManagedAccount> {
        self.accounts.clone()
    }

    fn managed_groups(&self) -> BTreeMap<String, ManagedGroup> {
        self.groups.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn missing_registry_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let st = RegistryState::load(&tmp.path().join("absent.toml")).unwrap();
        assert!(st.managed_accounts().is_empty());
    }

    #[test]
    fn reads_recorded_accounts() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(
            br#"
[[account]]
name = "oper"
uid = 9010
shell = "/bin/bash"
groups = ["wheel"]
from_version = 3
"#,
        )
        .unwrap();
        let st = RegistryState::load(&path).unwrap();
        let accts = st.managed_accounts();
        assert_eq!(accts.len(), 1);
        let oper = &accts["oper"];
        assert_eq!(oper.uid, 9010);
        assert_eq!(oper.groups, vec!["wheel"]);
        assert_eq!(oper.from_version, 3);
    }

    #[test]
    fn reads_recorded_sudo_commands() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        std::fs::write(
            &path,
            r#"
[[account]]
name = "oper"
uid = 9010
shell = "/bin/bash"
groups = ["wheel"]
sudo_commands = ["/usr/sbin/ip", "/usr/bin/nmcli"]
from_version = 3
"#,
        )
        .unwrap();
        let st = RegistryState::load(&path).unwrap();
        let oper = &st.managed_accounts()["oper"];
        assert_eq!(
            oper.sudo_commands,
            vec![
                crate::model::SudoCommand::root("/usr/sbin/ip"),
                crate::model::SudoCommand::root("/usr/bin/nmcli"),
            ]
        );
    }

    #[test]
    fn root_sudo_command_serializes_as_a_bare_string_keeping_registry_back_compat() {
        // A root command (runas: None) must serialize as a bare TOML string, so a
        // registry of all-root accounts keeps its historical `sudo_commands =
        // ["..."]` shape — the on-disk format does not change until a command is
        // actually narrowed.
        let acct = ManagedAccount {
            name: "oper".to_owned(),
            uid: 9010,
            shell: "/bin/bash".to_owned(),
            groups: vec![],
            sudo_role: None,
            sudo_commands: vec![crate::model::SudoCommand::root("/usr/sbin/ip")],
            file_grants: vec![],
            provenance: crate::model::Provenance::Created,
            from_version: 1,
        };
        let toml = toml::to_string(&acct).unwrap();
        assert!(
            toml.contains(r#"sudo_commands = ["/usr/sbin/ip"]"#),
            "root command must serialize as a bare string array: {toml}"
        );
    }

    #[test]
    fn narrowed_sudo_command_round_trips_through_the_table_form() {
        // A narrowed command (runas: Some) serializes as a `{ command, runas }`
        // table and reads back identically — the run-as account survives the
        // registry round-trip so the diff can detect a stale run-spec.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        std::fs::write(
            &path,
            r#"
[[account]]
name = "oper"
uid = 9010
shell = "/bin/bash"
from_version = 3

[[account.sudo_commands]]
command = "/opt/QToolplus"
runas = "bfs_solutions"
"#,
        )
        .unwrap();
        let st = RegistryState::load(&path).unwrap();
        assert_eq!(
            st.managed_accounts()["oper"].sudo_commands,
            vec![crate::model::SudoCommand::as_user(
                "/opt/QToolplus",
                "bfs_solutions"
            )]
        );
    }

    #[test]
    fn old_registry_without_sudo_commands_reads_as_empty() {
        // Back-compat: a registry written before sudo_commands existed must still
        // load (serde default = empty), not be rejected.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        std::fs::write(
            &path,
            "[[account]]\nname = \"oper\"\nuid = 9010\nshell = \"/bin/bash\"\ngroups = [\"wheel\"]\nfrom_version = 3\n",
        )
        .unwrap();
        let st = RegistryState::load(&path).unwrap();
        assert!(st.managed_accounts()["oper"].sudo_commands.is_empty());
    }

    #[test]
    fn reads_recorded_file_grants() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        std::fs::write(
            &path,
            r#"
[[account]]
name = "oper"
uid = 9010
shell = "/bin/bash"
from_version = 3

[[account.file_grants]]
path = "/etc/ssh"
access = "rw"
recursive = true
"#,
        )
        .unwrap();
        let st = RegistryState::load(&path).unwrap();
        let oper = &st.managed_accounts()["oper"];
        assert_eq!(oper.file_grants.len(), 1);
        assert_eq!(oper.file_grants[0].path, "/etc/ssh");
        assert_eq!(oper.file_grants[0].access, crate::catalog::Access::RW);
        assert!(oper.file_grants[0].recursive);
    }

    #[test]
    fn old_registry_without_file_grants_reads_as_empty() {
        // Back-compat: a registry written before file_grants existed must still
        // load (serde default = empty), not be rejected.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        std::fs::write(
            &path,
            "[[account]]\nname = \"oper\"\nuid = 9010\nshell = \"/bin/bash\"\nfrom_version = 3\n",
        )
        .unwrap();
        let st = RegistryState::load(&path).unwrap();
        assert!(st.managed_accounts()["oper"].file_grants.is_empty());
    }

    #[test]
    fn file_grants_round_trip_through_serialize() {
        // A managed account with grants serializes and reloads identically.
        let acct = ManagedAccount {
            name: "oper".to_owned(),
            uid: 9010,
            shell: "/bin/bash".to_owned(),
            groups: vec![],
            sudo_role: None,
            sudo_commands: vec![],
            file_grants: vec![ManagedFileGrant {
                path: "/etc/ssh".to_owned(),
                access: crate::catalog::Access::RO,
                recursive: true,
            }],
            provenance: crate::model::Provenance::Created,
            from_version: 5,
        };
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        crate::apply::write_registry(&path, std::slice::from_ref(&acct), &[]).unwrap();
        let reloaded = RegistryState::load(&path).unwrap();
        assert_eq!(reloaded.managed_accounts()["oper"], acct);
    }

    #[test]
    fn unknown_field_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        std::fs::write(
            &path,
            r#"
[[account]]
name = "oper"
uid = 9010
shell = "/bin/bash"
groups = ["wheel"]
from_version = 3
bogus = "nope"
"#,
        )
        .unwrap();
        assert!(matches!(
            RegistryState::load(&path).unwrap_err(),
            StateError::TomlParse { .. }
        ));
    }

    #[test]
    fn malformed_registry_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        std::fs::write(&path, "= = bad").unwrap();
        assert!(matches!(
            RegistryState::load(&path).unwrap_err(),
            StateError::TomlParse { .. }
        ));
    }

    #[test]
    fn reads_recorded_groups() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        std::fs::write(
            &path,
            r#"
[[account]]
name = "oper"
uid = 9010
shell = "/bin/bash"
groups = ["atm-operators"]
from_version = 3

[[group]]
name = "atm-operators"
gid = 8010
from_version = 3
"#,
        )
        .unwrap();
        let st = RegistryState::load(&path).unwrap();
        let groups = st.managed_groups();
        assert_eq!(groups.len(), 1);
        let g = &groups["atm-operators"];
        assert_eq!(g.gid, Some(8010));
        assert_eq!(g.from_version, 3);
        // accounts still load alongside.
        assert_eq!(st.managed_accounts().len(), 1);
    }

    #[test]
    fn group_unknown_field_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        std::fs::write(
            &path,
            r#"
[[group]]
name = "g"
gid = 8010
from_version = 3
bogus = "nope"
"#,
        )
        .unwrap();
        assert!(matches!(
            RegistryState::load(&path).unwrap_err(),
            StateError::TomlParse { .. }
        ));
    }

    #[test]
    fn adopted_group_with_grants_round_trips() {
        // An adopted group carrying provenance, Census-added members, group sudo
        // commands, group file grants and an adopt baseline must serialize and
        // reload byte-for-byte identically (the diff/release authority must
        // survive a registry round-trip).
        use crate::model::Provenance;
        let group = ManagedGroup {
            name: "wheel".to_owned(),
            gid: Some(10),
            provenance: Provenance::Adopted,
            members_added: vec!["netops".to_owned()],
            sudo_commands: vec![crate::model::SudoCommand::root("/usr/sbin/ip")],
            file_grants: vec![ManagedFileGrant {
                path: "/etc/net".to_owned(),
                access: crate::catalog::Access::RW,
                recursive: true,
            }],
            adopt_baseline: Some(GroupBaseline {
                gid: Some(10),
                members: vec!["root".to_owned(), "admin".to_owned()],
            }),
            from_version: 7,
        };
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        crate::apply::write_registry(&path, &[], std::slice::from_ref(&group)).unwrap();
        let reloaded = RegistryState::load(&path).unwrap();
        assert_eq!(reloaded.managed_groups()["wheel"], group);
    }

    #[test]
    fn old_registry_group_without_new_fields_reads_as_created() {
        // Back-compat: a group written before provenance/members_added/
        // sudo_commands/file_grants/adopt_baseline existed must still load —
        // provenance defaults to Created, the collections empty, baseline None.
        use crate::model::Provenance;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        std::fs::write(
            &path,
            "[[group]]\nname = \"atm-operators\"\ngid = 8010\nfrom_version = 3\n",
        )
        .unwrap();
        let st = RegistryState::load(&path).unwrap();
        let g = &st.managed_groups()["atm-operators"];
        assert_eq!(g.provenance, Provenance::Created);
        assert!(g.members_added.is_empty());
        assert!(g.sudo_commands.is_empty());
        assert!(g.file_grants.is_empty());
        assert_eq!(g.adopt_baseline, None);
    }

    #[test]
    fn group_without_gid_reads_as_none() {
        // The GID is now optional (`Option<u32>`, serde default): a registry that
        // omits `gid` must read cleanly as `None` ("GID unknown"), not be rejected
        // and not be coerced to a `0` sentinel.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        std::fs::write(
            &path,
            "[[group]]\nname = \"atm-operators\"\nfrom_version = 3\n",
        )
        .unwrap();
        let st = RegistryState::load(&path).unwrap();
        assert_eq!(st.managed_groups()["atm-operators"].gid, None);
    }

    #[test]
    fn adopted_account_round_trips() {
        // An account carrying Adopted provenance survives a registry round-trip
        // (the release-vs-delete trigger is read back from the stored provenance).
        use crate::model::Provenance;
        let acct = ManagedAccount {
            name: "alice".to_owned(),
            uid: 1001,
            shell: "/bin/bash".to_owned(),
            groups: vec![],
            sudo_role: None,
            sudo_commands: vec![],
            file_grants: vec![],
            provenance: Provenance::Adopted,
            from_version: 4,
        };
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        crate::apply::write_registry(&path, std::slice::from_ref(&acct), &[]).unwrap();
        let reloaded = RegistryState::load(&path).unwrap();
        assert_eq!(reloaded.managed_accounts()["alice"], acct);
    }

    #[test]
    fn old_registry_account_without_provenance_reads_as_created() {
        // Back-compat: an account written before provenance existed reads as
        // Created (the conservative default — Census treats it as its own).
        use crate::model::Provenance;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        std::fs::write(
            &path,
            "[[account]]\nname = \"oper\"\nuid = 9010\nshell = \"/bin/bash\"\nfrom_version = 3\n",
        )
        .unwrap();
        let st = RegistryState::load(&path).unwrap();
        assert_eq!(
            st.managed_accounts()["oper"].provenance,
            Provenance::Created
        );
    }

    #[test]
    fn group_baseline_rejects_unknown_field() {
        // deny_unknown_fields on the baseline: a stray field is rejected, not
        // silently dropped.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        std::fs::write(
            &path,
            r#"
[[group]]
name = "wheel"
gid = 10
from_version = 3

[group.adopt_baseline]
gid = 10
members = ["root"]
bogus = "nope"
"#,
        )
        .unwrap();
        assert!(matches!(
            RegistryState::load(&path).unwrap_err(),
            StateError::TomlParse { .. }
        ));
    }

    #[test]
    fn absent_group_section_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        std::fs::write(
            &path,
            "[[account]]\nname = \"oper\"\nuid = 9010\nshell = \"/bin/bash\"\nfrom_version = 3\n",
        )
        .unwrap();
        let st = RegistryState::load(&path).unwrap();
        assert!(st.managed_groups().is_empty());
    }
}
