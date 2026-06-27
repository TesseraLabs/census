//! Reads the Linux *composition* subset of a Tessera role-store slice.
//!
//! Census needs only `payload.groups`, `payload.sudo_role`, `payload.limits`,
//! `payload.permissions`, `payload.files`, and `payload.sudo`.
//! Parsing is TOLERANT (no `deny_unknown_fields`): full role-schema validation
//! is Tessera's responsibility (spec §17). Census ignores fields it does not
//! consume (`mac_mask`, `selinux`, `session`, `name`, `level`, ...). The one
//! exception is the inner `[[payload.files]]` grant, which reuses the strict
//! catalog [`FileGrant`] type: a role file grant is materialized as root via
//! setfacl, so an unknown key there must fail closed, not be silently ignored.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::catalog::{FileGrant, ParamValue};

/// A permission reference as written in a role slice's `payload.permissions`.
///
/// Two surface forms, per spec ("id-строка или таблица `{id, <параметры>}`"):
/// a bare id string (`"network-admin"`), or a table with an `id` key plus
/// arbitrary parameters (`{ id = "service-restart", units = ["nginx"] }`).
///
/// The `id` selects the catalog record; the `params` parameterize how that
/// record expands. A catalog permission may carry `{placeholder}` templates
/// (e.g. a `service-restart` whose sudo command names a unit, or a config-path
/// grant) that are meaningless without per-role values. The role supplies those
/// values here, and they are substituted into the matching placeholders at
/// resolve time (see `catalog::resolve_with_params`). Capturing them in the
/// parsed shape is what lets one catalog record serve many roles with different
/// units or paths.
#[derive(Debug, Clone, PartialEq)]
pub struct PermissionRef {
    /// The permission id to resolve against the catalog.
    pub id: String,
    /// Parameters from the table form (`units`, `path`, …). Empty for the bare
    /// string form. These fill the catalog record's `{placeholder}` templates
    /// during resolution, so a single record can be specialized per role.
    ///
    /// Values are held in the census-owned [`ParamValue`] domain, converted from
    /// the parsed TOML once at this slice-parse boundary so the resolve API never
    /// exposes `toml::Value`.
    pub params: BTreeMap<String, ParamValue>,
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
                        return Err(serde::de::Error::custom("permission table is missing `id`"));
                    }
                };
                // Convert the captured TOML params into the census-owned domain
                // here, at the parse boundary, so `toml::Value` never reaches the
                // resolve API.
                let params = map
                    .into_iter()
                    .map(|(k, v)| (k, ParamValue::from_toml(v)))
                    .collect();
                Ok(PermissionRef { id, params })
            }
        }
    }
}

/// Hand-written schema for [`PermissionRef`]: the type has a custom
/// `Deserialize` (a bare id string OR a `{ id = "...", <params> }` table) and
/// holds a param map schemars cannot reflect, so the schema is written by hand
/// to mirror the two accepted forms. The table arm stays tolerant
/// (`additionalProperties: true`) — extra keys are captured as params, matching
/// the tolerant role-store contract (§4.2). Behind the `schema` feature — schema
/// generation is a CI/contract concern, not part of the default public API.
#[cfg(feature = "schema")]
impl schemars::JsonSchema for PermissionRef {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "PermissionRef".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        // Arm 1: a bare id string. Arm 2: a table with a required `id` string
        // plus free-form params (tolerant: additionalProperties left unset → the
        // table accepts the extra keys that become params, matching §4.2).
        schemars::json_schema!({
            "oneOf": [
                { "type": "string" },
                {
                    "type": "object",
                    "required": ["id"],
                    "properties": {
                        "id": { "type": "string" },
                    },
                },
            ],
        })
    }
}

/// systemd/rlimit composition subset Census consumes.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
    /// Inline file-access grants (raw escape-hatch primitive), reusing the same
    /// shape as a catalog `[[file]]` grant. The strict catalog [`FileGrant`] type
    /// is reused deliberately: a role file grant is materialized as root via
    /// setfacl, so an unknown key must fail closed. Like the other raw primitives,
    /// these are unioned with the permission expansion by the resolver.
    pub files: Vec<FileGrant>,
    /// Inline sudo commands (raw escape-hatch primitive), the sudo parallel to
    /// `files`: a list of literal absolute command paths granted directly on the
    /// role, bypassing the catalog risk-label. Values are LITERAL-only — no
    /// `{placeholder}` and no argument list — because parametrization with
    /// confinement is the prerogative of a catalog id and its `[params.X]`
    /// constraints. Each value is validated and unioned into the account's
    /// sudo commands by the resolver alongside the permission expansion; an
    /// invalid value fails resolution closed (it would otherwise reach a NOPASSWD
    /// sudoers rule emitted as root).
    pub sudo: Vec<String>,
    /// Permission references to expand against the catalog. Each is a bare id or
    /// a `{id, ...params}` table. The raw `groups`/`sudo_role`/`limits`/`files`
    /// above are unioned with the expansion of these (spec: escape hatch coexists
    /// with permissions).
    pub permissions: Vec<PermissionRef>,
}

// --- tolerant mirror of the role-slice subset we read ---
//
// These two types are the SHAPE Census actually deserializes from a role slice:
// the consumed fields live UNDER a `[payload]` table, and the top level holds
// the role-wide keys Tessera owns (`role`, `version`, `os`, `name`, `level`, …)
// which Census ignores. They are the schema root for the role-store contract
// (NOT `RoleComposition`, which is the post-parse assembled view): a golden
// generated from `Slice` shows `groups`/`sudo_role`/`limits`/`permissions`
// nested under `payload`, matching the on-disk format and the taplo binding.
// Tolerant on purpose (no `deny_unknown_fields`) — Tessera owns the role schema
// and Census must ignore the adapter fields it does not consume (§4.2).

/// The `[payload]` subset Census reads from a role slice. Tolerant at the
/// payload level: unknown keys are ignored (Census reads only the Linux/payload
/// subset of a format Tessera owns). The one strict spot is the inner
/// `[[payload.files]]` grant, which reuses the catalog [`FileGrant`]
/// (`deny_unknown_fields`) — a role file grant materializes as root, so a typo'd
/// key there must fail closed. `pub` so the interface-contract test can
/// schematize it.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SlicePayload {
    #[serde(default)]
    groups: Option<Vec<String>>,
    #[serde(default)]
    sudo_role: Option<String>,
    #[serde(default)]
    limits: Option<Limits>,
    #[serde(default)]
    files: Option<Vec<FileGrant>>,
    #[serde(default)]
    sudo: Option<Vec<String>>,
    #[serde(default)]
    permissions: Option<Vec<PermissionRef>>,
}

/// The on-disk role slice as Census reads it: the role-wide top level (whose
/// keys Census ignores) plus the optional `[payload]` table it consumes.
/// Tolerant (no `deny_unknown_fields`) so foreign adapter fields are skipped.
/// This is the schema root for `contract/role-store.schema.json`. `pub` so the
/// interface-contract test can schematize it.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Slice {
    #[serde(default)]
    payload: Option<SlicePayload>,
}

/// Errors reading a role-store slice.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RoleStoreError {
    /// Slice file is missing.
    #[error("role slice {0} not found")]
    NotFound(PathBuf),
    /// Slice file could not be read.
    #[error("cannot read role slice {path}: {source}")]
    Io {
        /// The slice path consulted.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Slice TOML is malformed.
    #[error("role slice {path} TOML is invalid: {source}")]
    TomlParse {
        /// The slice path consulted.
        path: PathBuf,
        /// The underlying TOML deserialization error.
        #[source]
        source: toml::de::Error,
    },
}

/// Read `<role_store>/<role>.toml` and extract the Linux composition subset.
pub fn read_composition(role_store: &Path, role: &str) -> Result<RoleComposition, RoleStoreError> {
    let path = role_store.join(format!("{role}.toml"));
    if !path.exists() {
        return Err(RoleStoreError::NotFound(path));
    }
    let text = crate::fsutil::read_capped(&path, crate::fsutil::MAX_INPUT_FILE_BYTES).map_err(
        |source| RoleStoreError::Io {
            path: path.clone(),
            source,
        },
    )?;
    let slice: Slice = toml::from_str(&text).map_err(|source| RoleStoreError::TomlParse {
        path: path.clone(),
        source,
    })?;
    let payload = slice.payload.unwrap_or(SlicePayload {
        groups: None,
        sudo_role: None,
        limits: None,
        files: None,
        sudo: None,
        permissions: None,
    });
    Ok(RoleComposition {
        groups: payload.groups.unwrap_or_default(),
        sudo_role: payload.sudo_role,
        limits: payload.limits.unwrap_or_default(),
        files: payload.files.unwrap_or_default(),
        sudo: payload.sudo.unwrap_or_default(),
        permissions: payload.permissions.unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

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
        let units = c.permissions[1]
            .params
            .get("units")
            .expect("units captured");
        assert!(
            matches!(units, ParamValue::Array(_)),
            "units param retained as a list param value"
        );
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
    fn reads_single_inline_file_grant() {
        use crate::catalog::Access;
        let tmp = tempfile::tempdir().unwrap();
        write_slice(
            tmp.path(),
            "cal",
            r#"
role = "cal"
version = 1
os = "linux"
name = "Calibration"
level = 2
[payload]
[[payload.files]]
path = "/etc/X11/xorg.conf.d/99-calibration.conf"
access = "rw"
"#,
        );
        let c = read_composition(tmp.path(), "cal").unwrap();
        assert_eq!(c.files.len(), 1);
        assert_eq!(c.files[0].path, "/etc/X11/xorg.conf.d/99-calibration.conf");
        assert_eq!(c.files[0].access, Access::RW);
        // `recursive` defaults to false when omitted.
        assert!(!c.files[0].recursive);
    }

    #[test]
    fn reads_multiple_inline_file_grants() {
        use crate::catalog::Access;
        let tmp = tempfile::tempdir().unwrap();
        write_slice(
            tmp.path(),
            "multi",
            r#"
role = "multi"
version = 1
os = "linux"
name = "Multi"
level = 2
[payload]
[[payload.files]]
path = "/etc/app/conf.d"
access = "rw"
recursive = true
[[payload.files]]
path = "/var/log/app/current.log"
access = "ro"
"#,
        );
        let c = read_composition(tmp.path(), "multi").unwrap();
        assert_eq!(c.files.len(), 2);
        assert_eq!(c.files[0].path, "/etc/app/conf.d");
        assert!(c.files[0].recursive);
        assert_eq!(c.files[1].access, Access::RO);
    }

    #[test]
    fn inline_file_grants_coexist_with_permissions_and_raw_fields() {
        let tmp = tempfile::tempdir().unwrap();
        write_slice(
            tmp.path(),
            "coexist",
            r#"
role = "coexist"
version = 1
os = "linux"
name = "Coexist"
level = 3
[payload]
groups = ["wheel"]
sudo_role = "ops"
permissions = ["log-read"]
[[payload.files]]
path = "/etc/app"
access = "rw"
recursive = true
[payload.limits]
nofile = 1024
"#,
        );
        let c = read_composition(tmp.path(), "coexist").unwrap();
        assert_eq!(c.groups, vec!["wheel"]);
        assert_eq!(c.sudo_role.as_deref(), Some("ops"));
        assert_eq!(c.limits.nofile, Some(1024));
        assert_eq!(c.permissions.len(), 1);
        assert_eq!(c.files.len(), 1);
        assert_eq!(c.files[0].path, "/etc/app");
    }

    #[test]
    fn inline_file_grant_with_unknown_key_is_rejected() {
        // FileGrant is strict (deny_unknown_fields): a typo'd key must fail closed
        // because the grant materializes as root via setfacl.
        let tmp = tempfile::tempdir().unwrap();
        write_slice(
            tmp.path(),
            "typo",
            r#"
role = "typo"
version = 1
os = "linux"
name = "Typo"
level = 0
[payload]
[[payload.files]]
path = "/etc/app"
access = "rw"
recursiv = true
"#,
        );
        let err = read_composition(tmp.path(), "typo").unwrap_err();
        assert!(matches!(err, RoleStoreError::TomlParse { .. }));
    }

    #[test]
    fn reads_inline_sudo_commands() {
        // payload.sudo is parsed as a raw list of literal command paths; the
        // reader does not validate them (that is the resolver's fail-closed job).
        let tmp = tempfile::tempdir().unwrap();
        write_slice(
            tmp.path(),
            "reload",
            r#"
role = "reload"
version = 1
os = "linux"
name = "Reload"
level = 2
[payload]
sudo = ["/usr/sbin/myapp-reload", "/usr/bin/systemctl"]
"#,
        );
        let c = read_composition(tmp.path(), "reload").unwrap();
        assert_eq!(c.sudo, vec!["/usr/sbin/myapp-reload", "/usr/bin/systemctl"]);
    }

    #[test]
    fn inline_sudo_coexists_with_permissions_and_raw_fields() {
        let tmp = tempfile::tempdir().unwrap();
        write_slice(
            tmp.path(),
            "sudomix",
            r#"
role = "sudomix"
version = 1
os = "linux"
name = "Sudo Mix"
level = 3
[payload]
groups = ["wheel"]
permissions = ["log-read"]
sudo = ["/usr/sbin/myapp-reload"]
"#,
        );
        let c = read_composition(tmp.path(), "sudomix").unwrap();
        assert_eq!(c.groups, vec!["wheel"]);
        assert_eq!(c.permissions.len(), 1);
        assert_eq!(c.sudo, vec!["/usr/sbin/myapp-reload"]);
    }

    #[test]
    fn absent_inline_sudo_yields_empty_list() {
        let tmp = tempfile::tempdir().unwrap();
        write_slice(
            tmp.path(),
            "nosudo",
            "role = \"nosudo\"\nversion = 1\nos = \"linux\"\nname = \"n\"\nlevel = 0\n[payload]\ngroups = [\"wheel\"]\n",
        );
        let c = read_composition(tmp.path(), "nosudo").unwrap();
        assert!(c.sudo.is_empty());
    }

    #[test]
    fn absent_files_yields_empty_list() {
        let tmp = tempfile::tempdir().unwrap();
        write_slice(
            tmp.path(),
            "nofiles",
            "role = \"nofiles\"\nversion = 1\nos = \"linux\"\nname = \"n\"\nlevel = 0\n[payload]\ngroups = [\"wheel\"]\n",
        );
        let c = read_composition(tmp.path(), "nofiles").unwrap();
        assert!(c.files.is_empty());
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
