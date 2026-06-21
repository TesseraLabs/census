//! Reads the Linux *composition* subset of a Tessera role-store slice.
//!
//! Census needs only `payload.groups`, `payload.sudo_role`, `payload.limits`.
//! Parsing is TOLERANT (no `deny_unknown_fields`): full role-schema validation
//! is Tessera's responsibility (spec §17). Census ignores fields it does not
//! consume (`mac_mask`, `selinux`, `session`, `name`, `level`, ...).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A permission reference as written in a role slice's `payload.permissions`.
///
/// Two surface forms, per spec ("id-строка или таблица `{id, <параметры>}`"):
/// a bare id string (`"network-admin"`), or a table with an `id` key plus
/// arbitrary parameters (`{ id = "service-restart", units = ["nginx"] }`).
///
/// Slice 3 expands only the *id* — the captured `params` are parsed (so a
/// parametrized slice is accepted, not rejected) but inert: parameter
/// substitution (templating the catalog record against `params`) is a separate
/// follow-up. Capturing the params now keeps the role-slice schema stable so
/// that follow-up needs no re-parse change.
#[derive(Debug, Clone, PartialEq)]
pub struct PermissionRef {
    /// The permission id to resolve against the catalog.
    pub id: String,
    /// Parameters from the table form (`units`, `path`, …). Empty for the bare
    /// string form. Inert this slice (templating is a follow-up); retained so
    /// the parsed shape is complete.
    pub params: BTreeMap<String, toml::Value>,
}

impl<'de> serde::Deserialize<'de> for PermissionRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Accept either a bare string (id only) or a table carrying `id` plus
        // free-form parameters. The role slice stays TOLERANT (Tessera owns the
        // schema), so the table form does NOT use deny_unknown_fields — extra
        // keys are captured as params rather than rejected.
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Bare(String),
            Table(BTreeMap<String, toml::Value>),
        }

        match Raw::deserialize(deserializer)? {
            Raw::Bare(id) => Ok(PermissionRef {
                id,
                params: BTreeMap::new(),
            }),
            Raw::Table(mut map) => {
                // The table form must carry an `id` string; the remaining keys
                // are parameters (inert this slice).
                let id = match map.remove("id") {
                    Some(toml::Value::String(s)) => s,
                    Some(_) => {
                        return Err(serde::de::Error::custom(
                            "permission table `id` must be a string",
                        ));
                    }
                    None => {
                        return Err(serde::de::Error::custom(
                            "permission table is missing `id`",
                        ));
                    }
                };
                Ok(PermissionRef { id, params: map })
            }
        }
    }
}

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
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RoleComposition {
    /// Supplementary groups for the role account (raw escape-hatch primitive).
    pub groups: Vec<String>,
    /// Sudo role name, if the role carries one (raw escape-hatch primitive).
    pub sudo_role: Option<String>,
    /// Resource limits (raw escape-hatch primitive).
    pub limits: Limits,
    /// Permission references to expand against the catalog. Each is a bare id or
    /// a `{id, ...params}` table. The raw `groups`/`sudo_role`/`limits` above are
    /// unioned with the expansion of these (spec: escape hatch coexists with
    /// permissions).
    pub permissions: Vec<PermissionRef>,
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
    #[serde(default)]
    permissions: Option<Vec<PermissionRef>>,
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
        permissions: None,
    });
    Ok(RoleComposition {
        groups: payload.groups.unwrap_or_default(),
        sudo_role: payload.sudo_role,
        limits: payload.limits.unwrap_or_default(),
        permissions: payload.permissions.unwrap_or_default(),
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
    fn reads_permissions_as_bare_id_strings() {
        let tmp = tempfile::tempdir().unwrap();
        write_slice(
            tmp.path(),
            "neteng",
            r#"
role = "neteng"
version = 1
os = "linux"
name = "Network Engineer"
level = 3
[payload]
permissions = ["network-admin", "log-read"]
"#,
        );
        let c = read_composition(tmp.path(), "neteng").unwrap();
        assert_eq!(c.permissions.len(), 2);
        assert_eq!(c.permissions[0].id, "network-admin");
        assert!(c.permissions[0].params.is_empty());
        assert_eq!(c.permissions[1].id, "log-read");
    }

    #[test]
    fn reads_permissions_table_form_with_params() {
        // The table form is accepted (not rejected) and its params captured —
        // they are inert this slice (templating is a follow-up).
        let tmp = tempfile::tempdir().unwrap();
        write_slice(
            tmp.path(),
            "svcadmin",
            r#"
role = "svcadmin"
version = 1
os = "linux"
name = "Service Admin"
level = 4
[payload]
permissions = [
  "network-admin",
  { id = "service-restart", units = ["nginx", "redis"] },
]
"#,
        );
        let c = read_composition(tmp.path(), "svcadmin").unwrap();
        assert_eq!(c.permissions.len(), 2);
        assert_eq!(c.permissions[0].id, "network-admin");
        assert_eq!(c.permissions[1].id, "service-restart");
        // Params captured but inert.
        let units = c.permissions[1].params.get("units").expect("units captured");
        assert!(units.is_array(), "units param retained as a toml value");
    }

    #[test]
    fn permissions_coexist_with_raw_fields() {
        // permissions AND raw groups/sudo_role/limits in the same payload — both
        // are read; the union/lint is the resolver's job, not the reader's.
        let tmp = tempfile::tempdir().unwrap();
        write_slice(
            tmp.path(),
            "mixed",
            r#"
role = "mixed"
version = 1
os = "linux"
name = "Mixed"
level = 2
[payload]
groups = ["wheel"]
sudo_role = "ops"
permissions = ["network-admin"]
[payload.limits]
nofile = 2048
"#,
        );
        let c = read_composition(tmp.path(), "mixed").unwrap();
        assert_eq!(c.groups, vec!["wheel"]);
        assert_eq!(c.sudo_role.as_deref(), Some("ops"));
        assert_eq!(c.limits.nofile, Some(2048));
        assert_eq!(c.permissions.len(), 1);
        assert_eq!(c.permissions[0].id, "network-admin");
    }

    #[test]
    fn permission_table_without_id_is_rejected() {
        // A table form that forgot `id` is a malformed permission ref.
        let tmp = tempfile::tempdir().unwrap();
        write_slice(
            tmp.path(),
            "bad",
            r#"
role = "bad"
version = 1
os = "linux"
name = "B"
level = 0
[payload]
permissions = [{ units = ["nginx"] }]
"#,
        );
        let err = read_composition(tmp.path(), "bad").unwrap_err();
        assert!(matches!(err, RoleStoreError::TomlParse { .. }));
    }

    #[test]
    fn absent_permissions_yields_empty_list() {
        let tmp = tempfile::tempdir().unwrap();
        write_slice(
            tmp.path(),
            "noperm",
            "role = \"noperm\"\nversion = 1\nos = \"linux\"\nname = \"n\"\nlevel = 0\n[payload]\ngroups = [\"wheel\"]\n",
        );
        let c = read_composition(tmp.path(), "noperm").unwrap();
        assert!(c.permissions.is_empty());
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
