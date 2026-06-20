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
    fn inverted_uid_range_rejected() {
        let doc = SAMPLE.replace("uid_range = [9000, 9999]", "uid_range = [9999, 9000]");
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::UidRangeInverted(9999, 9000)
        ));
    }
}
