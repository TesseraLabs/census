//! Resolves a declaration + role-store composition into `ResolvedAccount`s —
//! the fully-specified target Unix accounts Census wants to exist.

use crate::declaration::Declaration;
use crate::rolestore::{self, Limits, RoleStoreError};
use std::path::PathBuf;

/// A fully-resolved target account: declaration account-layer merged with the
/// role-store composition, plus Census invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAccount {
    /// Unix login name (equals the role id; spec "role = account").
    pub name: String,
    /// Stable UID.
    pub uid: u32,
    /// Login shell (real shell; reachability is gated elsewhere — spec §8).
    pub shell: String,
    /// Home directory.
    pub home: PathBuf,
    /// Supplementary groups (from role composition).
    pub groups: Vec<String>,
    /// Sudo role, if any.
    pub sudo_role: Option<String>,
    /// Resource limits.
    pub limits: Limits,
    /// Census invariant: role accounts always have a locked password (§8).
    pub locked_password: bool,
}

/// Resolve every role account in the declaration against the role-store.
/// Reads `<role_store>/<role>.toml` for each. Fails if any slice is missing
/// or malformed.
pub fn resolve(decl: &Declaration) -> Result<Vec<ResolvedAccount>, RoleStoreError> {
    let mut out = Vec::with_capacity(decl.role_accounts.len());
    for acct in &decl.role_accounts {
        let comp = rolestore::read_composition(&decl.role_store, &acct.role)?;
        out.push(ResolvedAccount {
            name: acct.role.clone(),
            uid: acct.uid,
            shell: decl.shell_for(acct).to_owned(),
            home: decl.home_for(acct),
            groups: comp.groups,
            sudo_role: comp.sudo_role,
            limits: comp.limits,
            locked_password: true,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixture() -> (tempfile::TempDir, Declaration) {
        let tmp = tempfile::tempdir().unwrap();
        let mut f = std::fs::File::create(tmp.path().join("oper.toml")).unwrap();
        f.write_all(
            br#"
role = "oper"
version = 1
os = "linux"
name = "Operator"
level = 5
[payload]
groups = ["wheel"]
sudo_role = "ops"
"#,
        )
        .unwrap();
        let store = tmp.path().display().to_string();
        let decl_text = format!(
            r#"
version = 4
role_store = "{store}"
[defaults]
uid_range = [9000, 9999]
shell = "/bin/bash"
home_base = "/var/lib/census/home"
[[role_account]]
role = "oper"
uid = 9010
"#
        );
        let decl = Declaration::parse(&decl_text).unwrap();
        (tmp, decl)
    }

    #[test]
    fn resolves_account_with_composition_and_invariants() {
        let (_tmp, decl) = fixture();
        let resolved = resolve(&decl).unwrap();
        assert_eq!(resolved.len(), 1);
        let a = &resolved[0];
        assert_eq!(a.name, "oper");
        assert_eq!(a.uid, 9010);
        assert_eq!(a.shell, "/bin/bash");
        assert_eq!(a.home, PathBuf::from("/var/lib/census/home/oper"));
        assert_eq!(a.groups, vec!["wheel"]);
        assert_eq!(a.sudo_role.as_deref(), Some("ops"));
        assert!(a.locked_password, "role accounts must be password-locked");
    }

    #[test]
    fn missing_slice_fails_resolution() {
        let (_tmp, mut decl) = fixture();
        decl.role_accounts[0].role = "ghost".to_owned();
        assert!(resolve(&decl).is_err());
    }
}
