//! sudoers.d materialization for role accounts (spec R6).
//!
//! If a role carries a sudo role, Census owns a single file
//! `/etc/sudoers.d/census-<role>`. The **content builder** here is pure and
//! unit-tested; the actual write (temp file → `visudo -c -f <temp>` →
//! atomic rename) is an OS-execution concern done at apply time / integration
//! and is intentionally NOT unit-tested (it requires `visudo`).
//!
//! Census never edits foreign sudoers files — only `census-*`.

use crate::model::ResolvedAccount;

/// Filename (basename) Census owns for a role's sudoers fragment.
pub fn sudoers_filename(role: &str) -> String {
    format!("census-{role}")
}

/// Build the sudoers.d file content for an account, or `None` if the role
/// carries no sudo right (no file should exist).
///
/// Convention (design "Открытые вопросы" resolved minimally): the account is
/// granted sudo via membership semantics expressed as a per-user rule that
/// defers the command set to the role-store-configured alias named by
/// `sudo_role`. The rule references a `Cmnd_Alias` that the role-store/site
/// provisions; Census does not invent command lists.
pub fn build_sudoers_content(acct: &ResolvedAccount) -> Option<String> {
    let sudo_role = acct.sudo_role.as_ref()?;
    Some(format!(
        "# Managed by Census — role {role}. Do not edit by hand.\n\
         # Command set is the site-provisioned Cmnd_Alias {alias}.\n\
         {user} ALL=(ALL) {alias}\n",
        role = acct.name,
        user = acct.name,
        alias = sudo_role_alias(sudo_role),
    ))
}

/// Map a role-store `sudo_role` string into a sudoers `Cmnd_Alias` token.
/// Uppercased, non-alphanumeric → `_`, to satisfy sudoers alias syntax
/// (`[A-Z][A-Z0-9_]*`). Leading non-alpha is prefixed.
fn sudo_role_alias(sudo_role: &str) -> String {
    let mut out = String::with_capacity(sudo_role.len() + 8);
    out.push_str("CENSUS_");
    for ch in sudo_role.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rolestore::Limits;
    use std::path::PathBuf;

    fn acct(name: &str, sudo_role: Option<&str>) -> ResolvedAccount {
        ResolvedAccount {
            name: name.to_owned(),
            uid: 9010,
            shell: "/bin/bash".to_owned(),
            home: PathBuf::from(format!("/var/lib/census/home/{name}")),
            groups: vec![],
            sudo_role: sudo_role.map(|s| s.to_owned()),
            limits: Limits::default(),
            locked_password: true,
        }
    }

    #[test]
    fn no_sudo_role_yields_no_file() {
        assert!(build_sudoers_content(&acct("oper", None)).is_none());
    }

    #[test]
    fn sudo_role_yields_rule_referencing_alias() {
        let content = build_sudoers_content(&acct("oper", Some("ops"))).unwrap();
        assert!(content.contains("oper ALL=(ALL) CENSUS_OPS"));
        assert!(content.contains("Managed by Census"));
        // No stray ':' that would break a basic rule line shape.
        for line in content.lines().filter(|l| !l.starts_with('#')) {
            assert!(line.contains("ALL=(ALL)"));
        }
    }

    #[test]
    fn alias_token_is_valid_sudoers_syntax() {
        // alias must match [A-Z][A-Z0-9_]*
        let a = sudo_role_alias("ops-admin.2");
        assert_eq!(a, "CENSUS_OPS_ADMIN_2");
        assert!(a.chars().next().unwrap().is_ascii_uppercase());
        assert!(a.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'));
    }

    #[test]
    fn census_owns_only_prefixed_files() {
        assert_eq!(sudoers_filename("oper"), "census-oper");
        assert!(sudoers_filename("oper").starts_with("census-"));
    }
}
