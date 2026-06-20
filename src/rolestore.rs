//! Reads the Linux *composition* subset of a Tessera role-store slice.
//!
//! Census needs only `payload.groups`, `payload.sudo_role`, `payload.limits`.
//! Parsing is TOLERANT (no `deny_unknown_fields`): full role-schema validation
//! is Tessera's responsibility (spec §17). Census ignores fields it does not
//! consume (`mac_mask`, `selinux`, `session`, `name`, `level`, ...).

use std::path::{Path, PathBuf};

/// systemd/rlimit composition subset Census consumes.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct Limits {
    /// `RLIMIT_NOFILE`.
    #[serde(default)]
    pub nofile: Option<u64>,
    /// `RLIMIT_NPROC`.
    #[serde(default)]
    pub nproc: Option<u64>,
}

/// The composition Census extracts from a role slice (Linux subset).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleComposition {
    /// Supplementary groups for the role account.
    pub groups: Vec<String>,
    /// Sudo role name, if the role carries one.
    pub sudo_role: Option<String>,
    /// Resource limits.
    pub limits: Limits,
}

// --- private tolerant mirror of the role-slice subset we read ---

#[derive(serde::Deserialize)]
struct SlicePayload {
    #[serde(default)]
    groups: Option<Vec<String>>,
    #[serde(default)]
    sudo_role: Option<String>,
    #[serde(default)]
    limits: Option<Limits>,
}

#[derive(serde::Deserialize)]
struct Slice {
    #[serde(default)]
    payload: Option<SlicePayload>,
}

/// Errors reading a role-store slice.
#[derive(Debug, thiserror::Error)]
pub enum RoleStoreError {
    /// Slice file is missing.
    #[error("role slice {0} not found")]
    NotFound(PathBuf),
    /// Slice file could not be read.
    #[error("cannot read role slice {path}: {reason}")]
    Io { path: PathBuf, reason: String },
    /// Slice TOML is malformed.
    #[error("role slice {path} TOML is invalid: {reason}")]
    TomlParse { path: PathBuf, reason: String },
}

/// Read `<role_store>/<role>.toml` and extract the Linux composition subset.
pub fn read_composition(
    role_store: &Path,
    role: &str,
) -> Result<RoleComposition, RoleStoreError> {
    let path = role_store.join(format!("{role}.toml"));
    if !path.exists() {
        return Err(RoleStoreError::NotFound(path));
    }
    let text = std::fs::read_to_string(&path).map_err(|e| RoleStoreError::Io {
        path: path.clone(),
        reason: e.to_string(),
    })?;
    let slice: Slice = toml::from_str(&text).map_err(|e| RoleStoreError::TomlParse {
        path: path.clone(),
        reason: e.to_string(),
    })?;
    let payload = slice.payload.unwrap_or(SlicePayload {
        groups: None,
        sudo_role: None,
        limits: None,
    });
    Ok(RoleComposition {
        groups: payload.groups.unwrap_or_default(),
        sudo_role: payload.sudo_role,
        limits: payload.limits.unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_slice(dir: &Path, role: &str, body: &str) {
        let mut f = std::fs::File::create(dir.join(format!("{role}.toml"))).unwrap();
        f.write_all(body.as_bytes()).unwrap();
    }

    #[test]
    fn reads_groups_sudo_limits() {
        let tmp = tempfile::tempdir().unwrap();
        write_slice(
            tmp.path(),
            "oper",
            r#"
role = "oper"
version = 3
os = "linux"
name = "Operator"
level = 5
[payload]
groups = ["wheel", "docker"]
sudo_role = "ops"
[payload.limits]
nofile = 1024
nproc = 512
"#,
        );
        let c = read_composition(tmp.path(), "oper").unwrap();
        assert_eq!(c.groups, vec!["wheel", "docker"]);
        assert_eq!(c.sudo_role.as_deref(), Some("ops"));
        assert_eq!(c.limits.nofile, Some(1024));
        assert_eq!(c.limits.nproc, Some(512));
    }

    #[test]
    fn ignores_unknown_and_astra_fields() {
        // mac_mask / selinux / session / unknown keys must NOT cause errors.
        let tmp = tempfile::tempdir().unwrap();
        write_slice(
            tmp.path(),
            "serv",
            r#"
role = "serv"
version = 1
os = "linux"
name = "Service"
level = 0
future_field = "ignored"
[payload]
groups = ["svc"]
[session]
max_ttl_seconds = 3600
"#,
        );
        let c = read_composition(tmp.path(), "serv").unwrap();
        assert_eq!(c.groups, vec!["svc"]);
        assert_eq!(c.sudo_role, None);
        assert_eq!(c.limits, Limits::default());
    }

    #[test]
    fn empty_payload_yields_empty_composition() {
        let tmp = tempfile::tempdir().unwrap();
        write_slice(
            tmp.path(),
            "min",
            "role = \"min\"\nversion = 1\nos = \"linux\"\nname = \"m\"\nlevel = 0\n",
        );
        let c = read_composition(tmp.path(), "min").unwrap();
        assert_eq!(c, RoleComposition::default());
    }

    #[test]
    fn missing_slice_is_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let err = read_composition(tmp.path(), "ghost").unwrap_err();
        assert!(matches!(err, RoleStoreError::NotFound(_)));
    }

    #[test]
    fn malformed_toml_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        write_slice(tmp.path(), "bad", "this is = = not toml");
        let err = read_composition(tmp.path(), "bad").unwrap_err();
        assert!(matches!(err, RoleStoreError::TomlParse { .. }));
    }
}
