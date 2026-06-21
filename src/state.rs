//! Current Census-managed state.
//!
//! This slice reads ONLY the managed registry (`/var/lib/census/managed.toml`)
//! — what Census previously recorded as managed. It does NOT read live
//! `/etc/passwd` (live drift is a later slice). The registry is authoritative
//! for "what Census manages" (spec §4).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A single managed account as last recorded by Census.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
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
    /// Recorded concrete sudo commands (permission-expanded). Persisted so that
    /// granting or revoking a permission which changes the sudo command set is
    /// visible to the plan diff — the same privilege-revocation correctness that
    /// `sudo_role` gets, but for the concrete-command path (otherwise a stale
    /// NOPASSWD rule would leak after a permission is dropped). `#[serde(default)]`
    /// so a registry written before this field existed still reads (empty set).
    #[serde(default)]
    pub sudo_commands: Vec<String>,
    /// Declaration `version` this account was created/updated from.
    pub from_version: u32,
}

/// A single managed group as last recorded by Census. Only groups Census
/// itself created (`groupadd`) are recorded here; pre-existing/foreign groups
/// are never adopted, so the registry is authoritative for "what Census owns".
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedGroup {
    /// Group name.
    pub name: String,
    /// Recorded GID (the GID the group had when Census created it — pinned or
    /// OS-assigned). Doctor flags a live GID that diverges from this.
    pub gid: u32,
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

#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    #[serde(default, rename = "account")]
    accounts: Vec<ManagedAccount>,
    #[serde(default, rename = "group")]
    groups: Vec<ManagedGroup>,
}

/// Errors reading the managed registry.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// Registry file exists but cannot be read.
    #[error("cannot read managed registry {path}: {reason}")]
    Io { path: PathBuf, reason: String },
    /// Registry TOML is malformed.
    #[error("managed registry {path} is invalid: {reason}")]
    TomlParse { path: PathBuf, reason: String },
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
        let text = std::fs::read_to_string(path).map_err(|e| StateError::Io {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        let file: RegistryFile = toml::from_str(&text).map_err(|e| StateError::TomlParse {
            path: path.to_path_buf(),
            reason: e.to_string(),
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
#[derive(Default)]
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
    use super::*;
    use std::io::Write;

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
        assert_eq!(oper.sudo_commands, vec!["/usr/sbin/ip", "/usr/bin/nmcli"]);
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
        assert_eq!(g.gid, 8010);
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
