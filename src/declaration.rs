//! Declaration model + strict TOML parse + validation.
//!
//! The declaration references a role-store (for role composition) and adds the
//! account layer (uid/shell/home). Composition (groups/sudo/limits) is NOT
//! duplicated here — see `rolestore.rs`. Strict parsing: `deny_unknown_fields`.

use std::path::PathBuf;

/// Defaults applied to role accounts that omit a field.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// Inclusive [min, max] UID band for role accounts. Must be within the
    /// OS `UID_MAX` (validated against login.defs in a later slice).
    pub uid_range: [u32; 2],
    /// Default login shell when a role account omits `shell`.
    pub shell: String,
    /// Base directory for role-account homes.
    pub home_base: PathBuf,
}

/// A declared group: an optional GID pin for stability across the fleet
/// (audit/NFS). `gid = None` lets the OS assign the GID at creation time.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSpec {
    /// POSIX group name (the key used to reference / create the group).
    pub name: String,
    /// Optional pinned GID. When present, `groupadd -g <gid>`; on conflict
    /// (GID already belongs to a different group) apply refuses, never renumbers.
    #[serde(default)]
    pub gid: Option<u32>,
}

/// One role account: the projection of a role into a Unix account.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleAccount {
    /// Role id; key into the role-store (`<role_store>/<role>.toml`).
    pub role: String,
    /// Explicit, fleet-stable UID (spec §10).
    pub uid: u32,
    /// Login shell; falls back to `Defaults::shell` if absent.
    #[serde(default)]
    pub shell: Option<String>,
    /// Home directory; falls back to `<home_base>/<role>` if absent.
    #[serde(default)]
    pub home: Option<PathBuf>,
}

/// A parsed, schema-valid declaration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    /// Monotonic version; anti-rollback uses it (verification is a later slice).
    pub version: u32,
    /// Path to the role-store directory (source of role composition).
    pub role_store: PathBuf,
    /// Defaults block.
    pub defaults: Defaults,
    /// Role accounts (TOML `[[role_account]]`).
    #[serde(default, rename = "role_account")]
    pub role_accounts: Vec<RoleAccount>,
    /// Declared groups with optional GID pins (TOML `[[group]]`). The required
    /// set unions these names with every role's `payload.groups`.
    #[serde(default, rename = "group")]
    pub groups: Vec<GroupSpec>,
    /// Detached Ed25519 signature over the declaration bytes minus this line
    /// (hex of 64 bytes). Present in managed mode; absent under `--trust-fs`.
    /// The field exists so the strict (`deny_unknown_fields`) parser accepts a
    /// `signature = "..."` line — verification operates on RAW bytes via
    /// `trust::signed_payload`, not on this parsed value.
    #[serde(default)]
    pub signature: Option<String>,
}

/// Errors from parsing or validating a declaration.
#[derive(Debug, thiserror::Error)]
pub enum DeclarationError {
    /// TOML parse / type / unknown-field error.
    #[error("declaration TOML is invalid: {0}")]
    TomlParse(String),
    /// `version` must be >= 1.
    #[error("declaration version must be >= 1, got {0}")]
    VersionZero(u32),
    /// `uid_range` must be [min, max] with min <= max.
    #[error("uid_range must be [min, max] with min <= max, got [{0}, {1}]")]
    UidRangeInverted(u32, u32),
    /// A role account UID falls outside `defaults.uid_range`.
    #[error("role {role:?} uid {uid} is outside uid_range [{min}, {max}]")]
    UidOutOfRange { role: String, uid: u32, min: u32, max: u32 },
    /// Two role accounts share a UID.
    #[error("uid {uid} is used by both {first:?} and {second:?}")]
    UidCollision { uid: u32, first: String, second: String },
    /// Two role accounts share a role id.
    #[error("role {0:?} is declared more than once")]
    DuplicateRole(String),
    /// A role id is not a valid Tessera RoleId (must match `^[a-z][a-z0-9-]{0,15}$`).
    #[error(
        "role {value:?} is not a valid role id: must be 1-16 chars, start with a-z, \
         and contain only a-z, 0-9, or '-'"
    )]
    RoleIdInvalid { value: String },
    /// A declared `[[group]]` name is not a valid POSIX group name.
    #[error(
        "group {value:?} is not a valid group name: must be 1-32 chars, start with a \
         lowercase letter or '_', and contain only a-z, 0-9, '_', or '-'"
    )]
    GroupNameInvalid { value: String },
    /// Two `[[group]]` blocks declare the same name.
    #[error("group {0:?} is declared more than once")]
    DuplicateGroup(String),
    /// A group name in the required set is not a valid POSIX group name. Unlike
    /// [`Self::GroupNameInvalid`] (a declared `[[group]]` caught at parse), this
    /// covers names that flow in from a role-store's `payload.groups` and would
    /// otherwise reach `groupadd <name>` unvalidated. Apply fails closed.
    #[error(
        "required group {value:?} is not a valid group name: must be 1-32 chars, start with \
         a lowercase letter or '_', and contain only a-z, 0-9, '_', or '-'"
    )]
    InvalidGroupName { value: String },
}

/// True if `name` is a valid POSIX group name as Census accepts it:
/// 1-32 chars, first char a lowercase letter or `_`, rest `a-z`/`0-9`/`_`/`-`.
/// Deliberately stricter than the full POSIX-portable set (rejects upper-case
/// and leading digits) so created group names stay predictable across the fleet.
fn is_valid_group_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first == b'_') {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// True if `id` matches Tessera's RoleId rule: `^[a-z][a-z0-9-]{0,15}$`.
/// First char is `a-z`; remaining chars are `a-z`/`0-9`/`-`; total length 1..=16.
fn is_valid_role_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > 16 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl Declaration {
    /// Parse and validate a declaration from TOML text.
    pub fn parse(text: &str) -> Result<Self, DeclarationError> {
        let decl: Declaration =
            toml::from_str(text).map_err(|e| DeclarationError::TomlParse(e.to_string()))?;
        decl.validate()?;
        Ok(decl)
    }

    fn validate(&self) -> Result<(), DeclarationError> {
        if self.version < 1 {
            return Err(DeclarationError::VersionZero(self.version));
        }
        let [min, max] = self.defaults.uid_range;
        if min > max {
            return Err(DeclarationError::UidRangeInverted(min, max));
        }
        let mut seen_uid: Vec<(u32, String)> = Vec::new();
        let mut seen_role: Vec<String> = Vec::new();
        for acct in &self.role_accounts {
            if !is_valid_role_id(&acct.role) {
                return Err(DeclarationError::RoleIdInvalid {
                    value: acct.role.clone(),
                });
            }
            if seen_role.contains(&acct.role) {
                return Err(DeclarationError::DuplicateRole(acct.role.clone()));
            }
            seen_role.push(acct.role.clone());
            if acct.uid < min || acct.uid > max {
                return Err(DeclarationError::UidOutOfRange {
                    role: acct.role.clone(),
                    uid: acct.uid,
                    min,
                    max,
                });
            }
            if let Some((_, first)) = seen_uid.iter().find(|(u, _)| *u == acct.uid) {
                return Err(DeclarationError::UidCollision {
                    uid: acct.uid,
                    first: first.clone(),
                    second: acct.role.clone(),
                });
            }
            seen_uid.push((acct.uid, acct.role.clone()));
        }
        let mut seen_group: Vec<String> = Vec::new();
        for g in &self.groups {
            if !is_valid_group_name(&g.name) {
                return Err(DeclarationError::GroupNameInvalid {
                    value: g.name.clone(),
                });
            }
            if seen_group.contains(&g.name) {
                return Err(DeclarationError::DuplicateGroup(g.name.clone()));
            }
            seen_group.push(g.name.clone());
        }
        Ok(())
    }

    /// Effective shell for an account (its own, else the default).
    pub fn shell_for<'a>(&'a self, acct: &'a RoleAccount) -> &'a str {
        acct.shell.as_deref().unwrap_or(&self.defaults.shell)
    }

    /// Effective home for an account (its own, else `<home_base>/<role>`).
    pub fn home_for(&self, acct: &RoleAccount) -> PathBuf {
        acct.home
            .clone()
            .unwrap_or_else(|| self.defaults.home_base.join(&acct.role))
    }
}

/// Compute the **required group set**: the union of every resolved account's
/// supplementary groups (`payload.groups`, via [`crate::model::ResolvedAccount`])
/// with the names declared in `[[group]]`. The value is the pinned GID taken
/// from the matching `[[group]]` block (else `None`). A group named only by a
/// role (not in `[[group]]`) is required with no pin.
///
/// Returned as a `BTreeMap` so iteration order is deterministic (stable plan /
/// apply output). A name appearing both in a role and in `[[group]]` takes the
/// declared pin.
///
/// Every name in the resulting set is validated against [`is_valid_group_name`],
/// not only the `[[group]]`-declared ones. Declared names are already checked at
/// parse, but role-derived names (from `payload.groups`) are not — they would
/// otherwise reach `groupadd <name>` unvalidated. An invalid name (from either
/// source) fails closed with [`DeclarationError::InvalidGroupName`] so apply
/// never passes a malformed role-store group name to the OS.
pub fn required_groups(
    decl: &Declaration,
    resolved: &[crate::model::ResolvedAccount],
) -> Result<std::collections::BTreeMap<String, Option<u32>>, DeclarationError> {
    let mut out: std::collections::BTreeMap<String, Option<u32>> =
        std::collections::BTreeMap::new();
    // Role composition first (no pin from this source).
    for acct in resolved {
        for g in &acct.groups {
            out.entry(g.clone()).or_insert(None);
        }
    }
    // Declared groups override/insert the pin (authoritative for GID).
    for g in &decl.groups {
        out.insert(g.name.clone(), g.gid);
    }
    // Defense-in-depth: validate EVERY required name symmetrically (role-derived
    // and declared). Fail closed on the first invalid one.
    for name in out.keys() {
        if !is_valid_group_name(name) {
            return Err(DeclarationError::InvalidGroupName {
                value: name.clone(),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
version = 12
role_store = "/var/lib/tessera/roles"

[defaults]
uid_range = [9000, 9999]
shell = "/bin/bash"
home_base = "/var/lib/census/home"

[[role_account]]
role = "oper"
uid = 9010
shell = "/bin/bash"
home = "/var/lib/census/home/oper"

[[role_account]]
role = "serv"
uid = 9020
"#;

    #[test]
    fn parses_sample() {
        let d = Declaration::parse(SAMPLE).unwrap();
        assert_eq!(d.version, 12);
        assert_eq!(d.role_store, PathBuf::from("/var/lib/tessera/roles"));
        assert_eq!(d.defaults.uid_range, [9000, 9999]);
        assert_eq!(d.role_accounts.len(), 2);
        assert_eq!(d.role_accounts[0].role, "oper");
        assert_eq!(d.role_accounts[0].uid, 9010);
    }

    #[test]
    fn defaults_fill_shell_and_home() {
        let d = Declaration::parse(SAMPLE).unwrap();
        let serv = &d.role_accounts[1];
        assert_eq!(d.shell_for(serv), "/bin/bash");
        assert_eq!(d.home_for(serv), PathBuf::from("/var/lib/census/home/serv"));
    }

    #[test]
    fn unknown_field_rejected() {
        let doc = format!("{SAMPLE}\nbogus = 1\n");
        let err = Declaration::parse(&doc).unwrap_err();
        assert!(matches!(err, DeclarationError::TomlParse(_)));
    }

    #[test]
    fn version_zero_rejected() {
        let doc = SAMPLE.replace("version = 12", "version = 0");
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::VersionZero(0)
        ));
    }

    #[test]
    fn uid_out_of_range_rejected() {
        let doc = SAMPLE.replace("uid = 9010", "uid = 100");
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::UidOutOfRange { uid: 100, .. }
        ));
    }

    #[test]
    fn uid_collision_rejected() {
        let doc = SAMPLE.replace("uid = 9020", "uid = 9010");
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::UidCollision { uid: 9010, .. }
        ));
    }

    #[test]
    fn duplicate_role_rejected() {
        let doc = SAMPLE.replace("role = \"serv\"", "role = \"oper\"");
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::DuplicateRole(_)
        ));
    }

    #[test]
    fn invalid_role_ids_rejected() {
        for bad in ["", "../foo", "Abc", "1abc"] {
            let doc = SAMPLE.replace("role = \"oper\"", &format!("role = {bad:?}"));
            assert!(
                matches!(
                    Declaration::parse(&doc).unwrap_err(),
                    DeclarationError::RoleIdInvalid { .. }
                ),
                "role id {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn valid_role_ids_pass() {
        for good in ["oper", "a-b-c"] {
            let doc = SAMPLE.replace("role = \"oper\"", &format!("role = {good:?}"));
            assert!(
                Declaration::parse(&doc).is_ok(),
                "role id {good:?} must pass"
            );
        }
    }

    #[test]
    fn signature_line_accepted_by_strict_parser() {
        // deny_unknown_fields must not reject a `signature = "..."` line. As a
        // top-level scalar key it must precede any `[table]` header.
        let doc = "version = 12\nrole_store = \"/r\"\nsignature = \"abcdef\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/h\"\n";
        let d = Declaration::parse(doc).unwrap();
        assert_eq!(d.signature.as_deref(), Some("abcdef"));
    }

    #[test]
    fn absent_signature_defaults_to_none() {
        let d = Declaration::parse(SAMPLE).unwrap();
        assert_eq!(d.signature, None);
    }

    #[test]
    fn inverted_uid_range_rejected() {
        let doc = SAMPLE.replace("uid_range = [9000, 9999]", "uid_range = [9999, 9000]");
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::UidRangeInverted(9999, 9000)
        ));
    }

    // ---- [[group]] parsing + required-set (task 1) ----

    fn resolved(name: &str, groups: &[&str]) -> crate::model::ResolvedAccount {
        crate::model::ResolvedAccount {
            name: name.to_owned(),
            uid: 9010,
            shell: "/bin/bash".to_owned(),
            home: PathBuf::from(format!("/var/lib/census/home/{name}")),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            sudo_role: None,
            sudo_commands: Vec::new(),
            limits: crate::rolestore::Limits::default(),
            locked_password: true,
        }
    }

    #[test]
    fn group_block_with_pin_parses() {
        let doc = format!(
            "{SAMPLE}\n[[group]]\nname = \"atm-operators\"\ngid = 8010\n[[group]]\nname = \"tellers\"\n"
        );
        let d = Declaration::parse(&doc).unwrap();
        assert_eq!(d.groups.len(), 2);
        assert_eq!(d.groups[0].name, "atm-operators");
        assert_eq!(d.groups[0].gid, Some(8010));
        assert_eq!(d.groups[1].name, "tellers");
        assert_eq!(d.groups[1].gid, None);
    }

    #[test]
    fn group_block_unknown_field_rejected() {
        let doc = format!("{SAMPLE}\n[[group]]\nname = \"g\"\nbogus = 1\n");
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::TomlParse(_)
        ));
    }

    #[test]
    fn invalid_group_names_rejected() {
        for bad in ["", " ", "Bad", "1g", "a b", "with:colon"] {
            let doc = format!("{SAMPLE}\n[[group]]\nname = {bad:?}\n");
            assert!(
                matches!(
                    Declaration::parse(&doc).unwrap_err(),
                    DeclarationError::GroupNameInvalid { .. }
                ),
                "group name {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn valid_group_names_pass() {
        for good in ["wheel", "atm-operators", "_sys", "g9"] {
            let doc = format!("{SAMPLE}\n[[group]]\nname = {good:?}\n");
            assert!(
                Declaration::parse(&doc).is_ok(),
                "group name {good:?} must pass"
            );
        }
    }

    #[test]
    fn duplicate_group_rejected() {
        let doc = format!("{SAMPLE}\n[[group]]\nname = \"g\"\n[[group]]\nname = \"g\"\n");
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::DuplicateGroup(_)
        ));
    }

    #[test]
    fn required_groups_unions_roles_and_blocks() {
        let doc = format!(
            "{SAMPLE}\n[[group]]\nname = \"atm-operators\"\ngid = 8010\n[[group]]\nname = \"wheel\"\n"
        );
        let d = Declaration::parse(&doc).unwrap();
        let res = vec![resolved("oper", &["wheel", "docker"]), resolved("serv", &["wheel"])];
        let req = required_groups(&d, &res).unwrap();
        // union of role groups {wheel, docker} ∪ declared {atm-operators, wheel}
        assert_eq!(req.len(), 3);
        assert!(req.contains_key("wheel"));
        assert!(req.contains_key("docker"));
        assert!(req.contains_key("atm-operators"));
        // pin from [[group]]
        assert_eq!(req["atm-operators"], Some(8010));
        // role-only group has no pin
        assert_eq!(req["docker"], None);
        // wheel appears in roles AND declared (no pin) → None
        assert_eq!(req["wheel"], None);
    }

    #[test]
    fn required_groups_declared_pin_wins_over_role_mention() {
        // A group named by a role AND pinned in [[group]] keeps the pin.
        let doc = format!("{SAMPLE}\n[[group]]\nname = \"wheel\"\ngid = 7000\n");
        let d = Declaration::parse(&doc).unwrap();
        let res = vec![resolved("oper", &["wheel"])];
        let req = required_groups(&d, &res).unwrap();
        assert_eq!(req["wheel"], Some(7000));
    }

    #[test]
    fn required_groups_rejects_invalid_role_derived_name() {
        // A name coming from a role's payload.groups (not a [[group]] block) that
        // is not a valid POSIX group name must fail the required-set computation
        // rather than reaching `groupadd`.
        let d = Declaration::parse(SAMPLE).unwrap();
        for bad in ["Bad Name", "", "1g", "with:colon"] {
            let res = vec![resolved("oper", &[bad])];
            let err = required_groups(&d, &res).unwrap_err();
            assert!(
                matches!(err, DeclarationError::InvalidGroupName { ref value } if value == bad),
                "role-derived group name {bad:?} must be rejected, got {err:?}"
            );
        }
    }
}
