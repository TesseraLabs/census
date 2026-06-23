//! Declaration model + strict TOML parse + validation.
//!
//! The declaration references a role-store (for role composition) and adds the
//! account layer (uid/shell/home). Composition (groups/sudo/limits) is NOT
//! duplicated here — see `rolestore.rs`. Strict parsing: `deny_unknown_fields`.

use std::path::PathBuf;

/// Defaults applied to role accounts that omit a field.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupSpec {
    /// POSIX group name (the key used to reference / create the group).
    pub name: String,
    /// Optional pinned GID. When present, `groupadd -g <gid>`; on conflict
    /// (GID already belongs to a different group) apply refuses, never renumbers.
    #[serde(default)]
    pub gid: Option<u32>,
    /// Adoption flag. When `true` the group is taken under management as an
    /// existing OS group (Adopted provenance): Census never creates or deletes
    /// it and never touches its pre-existing members — it only adds/removes its
    /// own grants and its own added members, releasing to baseline. A pinned
    /// `gid` is incompatible with adoption (Census does not renumber an existing
    /// group), so `adopt = true` together with `gid` is rejected.
    #[serde(default)]
    pub adopt: bool,
    /// Members Census manages on this group. For an Adopted group these MUST be
    /// Census-managed OS users — Census must not drag a third party into a group
    /// it did not create; for a Created group any valid user name is allowed.
    #[serde(default)]
    pub members: Vec<String>,
}

/// One role account: the projection of a role into a Unix account.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleAccount {
    /// Role id; key into the role-store (`<role_store>/<role>.toml`).
    pub role: String,
    /// Explicit, fleet-stable UID (spec §10). Present for a Created account
    /// (Census creates the Unix user at this UID). Absent for an Adopted account
    /// (which instead names an existing user via `user`): Census never assigns a
    /// UID to a user it did not create.
    #[serde(default)]
    pub uid: Option<u32>,
    /// Existing OS user name to adopt. Mutually exclusive with `uid`; requires
    /// `adopt = true`. When set, the account is Adopted: Census binds the role's
    /// grants to this pre-existing user without ever running `useradd`/`userdel`.
    #[serde(default)]
    pub user: Option<String>,
    /// Adoption flag. `true` marks the account Adopted and requires `user`
    /// (and forbids `uid`). `false` (default) is a Created account keyed by `uid`.
    #[serde(default)]
    pub adopt: bool,
    /// Login shell; falls back to `Defaults::shell` if absent.
    #[serde(default)]
    pub shell: Option<String>,
    /// Home directory; falls back to `<home_base>/<role>` if absent.
    #[serde(default)]
    pub home: Option<PathBuf>,
}

impl RoleAccount {
    /// True if this account is Adopted (bound to an existing user) rather than
    /// Created. Derived from the identity source (`user`), not the `adopt` flag,
    /// so it stays consistent with provenance even on an unvalidated struct.
    pub fn is_adopted(&self) -> bool {
        self.user.is_some()
    }
}

/// A grant binding: attach a role's resolved permissions to a Unix group, so
/// every member of the group inherits them (many-to-one — several roles may
/// bind to the same group). `group` MUST name a `[[group]]` declared in the
/// same declaration; `role` is a role-store role id.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleGroup {
    /// Role id whose grants are bound to the group.
    pub role: String,
    /// Target group name; MUST match a declared `[[group]]`.
    pub group: String,
}

/// A parsed, schema-valid declaration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, schemars::JsonSchema)]
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
    /// Role→group grant bindings (TOML `[[role_group]]`). Each binds a role's
    /// permissions to a declared group.
    #[serde(default, rename = "role_group")]
    pub role_groups: Vec<RoleGroup>,
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
    /// A `[[role_account]]` declares both `uid` and `user`. Created (uid) and
    /// Adopted (user) are mutually exclusive provenances.
    #[error("role {role:?} declares both uid and user (Created and Adopted are exclusive)")]
    AccountUidAndUser { role: String },
    /// A `[[role_account]]` has `adopt = true` (or names a `user`) but the other
    /// half of an Adopted account is missing: adoption requires `user` AND
    /// `adopt = true` AND no `uid`.
    #[error(
        "role {role:?} is an inconsistent adoption: adopt requires `user` set, `adopt = true`, \
         and no `uid`"
    )]
    AccountAdoptInconsistent { role: String },
    /// A `[[role_account]]` is neither a valid Created account (has `uid`) nor a
    /// valid Adopted account (has `user`): one identity source is required.
    #[error("role {role:?} has neither uid (Created) nor user (Adopted)")]
    AccountNoIdentity { role: String },
    /// An adopted `user` name is not a valid POSIX user name (same class as a
    /// group name: 1-32 chars, lowercase/`_` first, then a-z/0-9/`_`/`-`).
    #[error(
        "user {value:?} is not a valid user name: must be 1-32 chars, start with a lowercase \
         letter or '_', and contain only a-z, 0-9, '_', or '-'"
    )]
    UserNameInvalid { value: String },
    /// A `[[group]]` declares `adopt = true` together with a pinned `gid`.
    /// Census does not renumber an existing group, so the two are incompatible.
    #[error("group {group:?} declares adopt together with a pinned gid (adoption never renumbers)")]
    GroupAdoptWithGid { group: String },
    /// A `[[group]].members` entry is not a valid POSIX user name.
    #[error(
        "group {group:?} member {value:?} is not a valid user name: must be 1-32 chars, start \
         with a lowercase letter or '_', and contain only a-z, 0-9, '_', or '-'"
    )]
    GroupMemberNameInvalid { group: String, value: String },
    /// A member of an Adopted group is not a Census-managed role account.
    /// Invariant A forbids forcing a third-party user into a pre-existing group.
    #[error(
        "adopted group {group:?} member {value:?} is not a Census-managed role account \
         (invariant A: cannot add a third-party user to a pre-existing group)"
    )]
    AdoptedGroupMemberUnmanaged { group: String, value: String },
    /// A `[[role_group]].group` references a name that is not a declared
    /// `[[group]]`.
    #[error("role_group binds role {role:?} to undeclared group {group:?}")]
    RoleGroupUndeclaredGroup { role: String, group: String },
    /// Two `[[role_group]]` blocks declare the same `(role, group)` pair.
    #[error("role_group pair (role {role:?}, group {group:?}) is declared more than once")]
    DuplicateRoleGroup { role: String, group: String },
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

/// True if `name` is a valid POSIX user (login) name as Census accepts it.
/// Census applies the same character class to user names as to group names
/// (1-32 chars, lowercase letter or `_` first, then `a-z`/`0-9`/`_`/`-`), so
/// this delegates to [`is_valid_group_name`]; it exists as a named predicate so
/// call sites read by intent (a user name, not a group name).
fn is_valid_user_name(name: &str) -> bool {
    is_valid_group_name(name)
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
            // The role id and its uniqueness apply to BOTH provenances: a role
            // names exactly one account whether Created or Adopted.
            if !is_valid_role_id(&acct.role) {
                return Err(DeclarationError::RoleIdInvalid {
                    value: acct.role.clone(),
                });
            }
            if seen_role.contains(&acct.role) {
                return Err(DeclarationError::DuplicateRole(acct.role.clone()));
            }
            seen_role.push(acct.role.clone());

            // Provenance is determined by the (uid | user) identity source.
            // Reject contradictory or empty forms before any provenance-specific
            // checks, so the branches below operate on a well-formed account.
            match (acct.uid, &acct.user) {
                (Some(_), Some(_)) => {
                    return Err(DeclarationError::AccountUidAndUser {
                        role: acct.role.clone(),
                    });
                }
                (None, None) => {
                    return Err(DeclarationError::AccountNoIdentity {
                        role: acct.role.clone(),
                    });
                }
                (Some(uid), None) => {
                    // Created account. `adopt` must be off (adopt applies only to
                    // an existing `user`); the original UID checks all apply.
                    if acct.adopt {
                        return Err(DeclarationError::AccountAdoptInconsistent {
                            role: acct.role.clone(),
                        });
                    }
                    if uid < min || uid > max {
                        return Err(DeclarationError::UidOutOfRange {
                            role: acct.role.clone(),
                            uid,
                            min,
                            max,
                        });
                    }
                    if let Some((_, first)) = seen_uid.iter().find(|(u, _)| *u == uid) {
                        return Err(DeclarationError::UidCollision {
                            uid,
                            first: first.clone(),
                            second: acct.role.clone(),
                        });
                    }
                    seen_uid.push((uid, acct.role.clone()));
                }
                (None, Some(user)) => {
                    // Adopted account: a `user` requires `adopt = true`. UID-band
                    // and uid-collision checks do not apply (Census assigns no
                    // UID to a user it did not create).
                    if !acct.adopt {
                        return Err(DeclarationError::AccountAdoptInconsistent {
                            role: acct.role.clone(),
                        });
                    }
                    if !is_valid_user_name(user) {
                        return Err(DeclarationError::UserNameInvalid {
                            value: user.clone(),
                        });
                    }
                }
            }
        }

        // The set of Census-managed OS user names. Group membership names an OS
        // user, so this must hold exactly the OS logins Census manages — never
        // role ids in disguise. A Created account's OS login equals its role id
        // (spec "role = account"); an Adopted account's OS login is its `user`.
        // Mixing the two namespaces would let a member pass merely by matching
        // some unrelated role id even when no such managed OS user exists.
        let mut managed_users: Vec<&str> = Vec::with_capacity(self.role_accounts.len());
        for acct in &self.role_accounts {
            match &acct.user {
                Some(user) => managed_users.push(user.as_str()),
                None => managed_users.push(acct.role.as_str()),
            }
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

            // Adoption never renumbers an existing group: a pin is contradictory.
            if g.adopt && g.gid.is_some() {
                return Err(DeclarationError::GroupAdoptWithGid {
                    group: g.name.clone(),
                });
            }

            for member in &g.members {
                if !is_valid_user_name(member) {
                    return Err(DeclarationError::GroupMemberNameInvalid {
                        group: g.name.clone(),
                        value: member.clone(),
                    });
                }
                // A member forced into an ADOPTED (pre-existing) group must be a
                // Census-managed OS user: Census must not drag a third party
                // into a group it did not create. A Created group may carry any
                // valid user. Cross-referencing managed OS users is possible
                // here because role accounts are fully known on the Declaration;
                // deeper checking (that the member's grants actually
                // materialize) belongs to the resolve/apply slices.
                if g.adopt && !managed_users.contains(&member.as_str()) {
                    return Err(DeclarationError::AdoptedGroupMemberUnmanaged {
                        group: g.name.clone(),
                        value: member.clone(),
                    });
                }
            }
        }

        // role_group bindings: each must name a valid role id and reference a
        // declared group; the (role, group) pair must be unique. We deliberately
        // do NOT require `role` to have its own role account: a role bound to a
        // group need not have a personal account (many-to-one), and the role's
        // existence is checked at resolve time against the role-store in a later
        // slice — hence the asymmetry with the account-side checks above.
        let mut seen_pair: Vec<(String, String)> = Vec::new();
        for rg in &self.role_groups {
            if !is_valid_role_id(&rg.role) {
                return Err(DeclarationError::RoleIdInvalid {
                    value: rg.role.clone(),
                });
            }
            if !seen_group.contains(&rg.group) {
                return Err(DeclarationError::RoleGroupUndeclaredGroup {
                    role: rg.role.clone(),
                    group: rg.group.clone(),
                });
            }
            let pair = (rg.role.clone(), rg.group.clone());
            if seen_pair.contains(&pair) {
                return Err(DeclarationError::DuplicateRoleGroup {
                    role: rg.role.clone(),
                    group: rg.group.clone(),
                });
            }
            seen_pair.push(pair);
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
        assert_eq!(d.role_accounts[0].uid, Some(9010));
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
            file_grants: Vec::new(),
            locked_password: true,
            provenance: crate::model::Provenance::Created,
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

    // ---- group-grants slice 1: provenance + adoption + role_group ----

    #[test]
    fn adopted_role_account_parses() {
        let doc = format!(
            "{SAMPLE}\n[[role_account]]\nrole = \"infra-admin\"\nuser = \"alice\"\nadopt = true\n"
        );
        let d = Declaration::parse(&doc).unwrap();
        let adopted = d.role_accounts.iter().find(|a| a.role == "infra-admin").unwrap();
        assert_eq!(adopted.user.as_deref(), Some("alice"));
        assert_eq!(adopted.uid, None);
        assert!(adopted.is_adopted());
    }

    #[test]
    fn role_account_with_user_and_uid_rejected() {
        let doc = format!(
            "{SAMPLE}\n[[role_account]]\nrole = \"infra-admin\"\nuser = \"alice\"\nuid = 9030\nadopt = true\n"
        );
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::AccountUidAndUser { .. }
        ));
    }

    #[test]
    fn adopt_without_user_rejected() {
        // adopt = true on a uid-keyed (Created) account is contradictory.
        let doc = format!(
            "{SAMPLE}\n[[role_account]]\nrole = \"infra-admin\"\nuid = 9030\nadopt = true\n"
        );
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::AccountAdoptInconsistent { .. }
        ));
    }

    #[test]
    fn user_without_adopt_rejected() {
        let doc = format!(
            "{SAMPLE}\n[[role_account]]\nrole = \"infra-admin\"\nuser = \"alice\"\n"
        );
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::AccountAdoptInconsistent { .. }
        ));
    }

    #[test]
    fn role_account_without_identity_rejected() {
        // Neither uid nor user: no identity source.
        let doc = format!("{SAMPLE}\n[[role_account]]\nrole = \"infra-admin\"\n");
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::AccountNoIdentity { .. }
        ));
    }

    #[test]
    fn adopted_user_invalid_name_rejected() {
        let doc = format!(
            "{SAMPLE}\n[[role_account]]\nrole = \"infra-admin\"\nuser = \"Bad Name\"\nadopt = true\n"
        );
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::UserNameInvalid { .. }
        ));
    }

    #[test]
    fn group_adopt_with_gid_rejected() {
        let doc = format!("{SAMPLE}\n[[group]]\nname = \"wheel\"\nadopt = true\ngid = 8020\n");
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::GroupAdoptWithGid { .. }
        ));
    }

    #[test]
    fn group_adopt_without_gid_passes() {
        let doc = format!("{SAMPLE}\n[[group]]\nname = \"wheel\"\nadopt = true\n");
        let d = Declaration::parse(&doc).unwrap();
        let wheel = d.groups.iter().find(|g| g.name == "wheel").unwrap();
        assert!(wheel.adopt);
        assert_eq!(wheel.gid, None);
    }

    #[test]
    fn group_member_invalid_name_rejected() {
        let doc = format!("{SAMPLE}\n[[group]]\nname = \"ops\"\nmembers = [\"Bad Name\"]\n");
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::GroupMemberNameInvalid { .. }
        ));
    }

    #[test]
    fn created_group_allows_any_valid_member() {
        // A Created group (no adopt) may name any valid user, managed or not.
        let doc = format!("{SAMPLE}\n[[group]]\nname = \"ops\"\nmembers = [\"external-user\"]\n");
        assert!(Declaration::parse(&doc).is_ok());
    }

    #[test]
    fn adopted_group_unmanaged_member_rejected() {
        // A third-party user must not be forced into an adopted (pre-existing)
        // group: Census never drags an unmanaged user into a group it did not
        // create.
        let doc = format!(
            "{SAMPLE}\n[[group]]\nname = \"wheel\"\nadopt = true\nmembers = [\"external-user\"]\n"
        );
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::AdoptedGroupMemberUnmanaged { .. }
        ));
    }

    #[test]
    fn adopted_group_managed_member_passes() {
        // The sample declares Created accounts `oper` and `serv`; a Created
        // account's OS login equals its role id, so `oper` is a managed OS user
        // and is allowed in an adopted group.
        let doc = format!(
            "{SAMPLE}\n[[group]]\nname = \"wheel\"\nadopt = true\nmembers = [\"oper\"]\n"
        );
        assert!(Declaration::parse(&doc).is_ok());
    }

    #[test]
    fn adopted_group_member_matches_os_user_not_role_id() {
        // Namespace separation: an adopted group's member names an OS user, not a
        // role id. An adopted account contributes its `user` (OS login) to the
        // managed set, NOT its role id. So a member equal to an adopted account's
        // role id — when no managed OS user carries that name — must be rejected,
        // even though the role id exists. (A Created account named "alice" would
        // be a managed OS user "alice" and pass; that distinct case is checked
        // separately below.)
        let doc = format!(
            "{SAMPLE}\n\
             [[role_account]]\nrole = \"infra-admin\"\nuser = \"alice\"\nadopt = true\n\
             [[group]]\nname = \"wheel\"\nadopt = true\nmembers = [\"infra-admin\"]\n"
        );
        assert!(
            matches!(
                Declaration::parse(&doc).unwrap_err(),
                DeclarationError::AdoptedGroupMemberUnmanaged { .. }
            ),
            "member matching an adopted account's role id (not its OS user) must be rejected"
        );
    }

    #[test]
    fn adopted_group_member_created_os_user_named_like_role_passes() {
        // The over-permit counterpart: a Created account whose role id is "alice"
        // IS a managed OS user "alice", so an adopted group may carry it.
        let doc = format!(
            "{SAMPLE}\n\
             [[role_account]]\nrole = \"alice\"\nuid = 9030\n\
             [[group]]\nname = \"wheel\"\nadopt = true\nmembers = [\"alice\"]\n"
        );
        assert!(
            Declaration::parse(&doc).is_ok(),
            "a Created account's OS login (== role id) is a managed user and may be a member"
        );
    }

    #[test]
    fn adopted_group_adopted_user_member_passes() {
        // An adopted account's OS user name is also a managed identity.
        let doc = format!(
            "{SAMPLE}\n\
             [[role_account]]\nrole = \"infra-admin\"\nuser = \"alice\"\nadopt = true\n\
             [[group]]\nname = \"wheel\"\nadopt = true\nmembers = [\"alice\"]\n"
        );
        assert!(Declaration::parse(&doc).is_ok());
    }

    #[test]
    fn role_group_parses_and_binds() {
        let doc = format!(
            "{SAMPLE}\n[[group]]\nname = \"wheel\"\n[[role_group]]\nrole = \"oper\"\ngroup = \"wheel\"\n"
        );
        let d = Declaration::parse(&doc).unwrap();
        assert_eq!(d.role_groups.len(), 1);
        assert_eq!(d.role_groups[0].role, "oper");
        assert_eq!(d.role_groups[0].group, "wheel");
    }

    #[test]
    fn role_group_unknown_field_rejected() {
        let doc = format!(
            "{SAMPLE}\n[[group]]\nname = \"wheel\"\n[[role_group]]\nrole = \"oper\"\ngroup = \"wheel\"\nbogus = 1\n"
        );
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::TomlParse(_)
        ));
    }

    #[test]
    fn role_group_to_undeclared_group_rejected() {
        let doc = format!("{SAMPLE}\n[[role_group]]\nrole = \"oper\"\ngroup = \"ghost\"\n");
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::RoleGroupUndeclaredGroup { .. }
        ));
    }

    #[test]
    fn role_group_invalid_role_id_rejected() {
        let doc = format!(
            "{SAMPLE}\n[[group]]\nname = \"wheel\"\n[[role_group]]\nrole = \"Bad\"\ngroup = \"wheel\"\n"
        );
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::RoleIdInvalid { .. }
        ));
    }

    #[test]
    fn duplicate_role_group_pair_rejected() {
        let doc = format!(
            "{SAMPLE}\n[[group]]\nname = \"wheel\"\n\
             [[role_group]]\nrole = \"oper\"\ngroup = \"wheel\"\n\
             [[role_group]]\nrole = \"oper\"\ngroup = \"wheel\"\n"
        );
        assert!(matches!(
            Declaration::parse(&doc).unwrap_err(),
            DeclarationError::DuplicateRoleGroup { .. }
        ));
    }

    #[test]
    fn distinct_role_group_pairs_to_same_group_pass() {
        // many-to-one: two different roles may bind to one group.
        let doc = format!(
            "{SAMPLE}\n[[group]]\nname = \"wheel\"\n\
             [[role_group]]\nrole = \"oper\"\ngroup = \"wheel\"\n\
             [[role_group]]\nrole = \"serv\"\ngroup = \"wheel\"\n"
        );
        let d = Declaration::parse(&doc).unwrap();
        assert_eq!(d.role_groups.len(), 2);
    }
}
