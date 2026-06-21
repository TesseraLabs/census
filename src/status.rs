//! Read-only state summary for `census status` (spec §14).
//!
//! Prints what Census manages (accounts + the declaration version each was
//! created/updated from), the persisted declaration version floor, and — when a
//! declaration is supplied — a drift summary. Pure rendering; always exit 0.

use crate::plan::{Action, Plan};
use crate::state::SystemState;

/// Render the status summary. `persisted_version` is the anti-rollback floor
/// (`trust::last_applied_version`); `drift` is an optional plan computed against
/// the supplied declaration.
pub fn render_status(
    managed: &dyn SystemState,
    persisted_version: Option<u32>,
    drift: Option<&Plan>,
) -> String {
    let accounts = managed.managed_accounts();
    let mut out = String::new();

    out.push_str("managed accounts:\n");
    if accounts.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for (name, acct) in &accounts {
            out.push_str(&format!("  {name} (from_version {})\n", acct.from_version));
        }
    }

    match persisted_version {
        Some(v) => out.push_str(&format!("declaration version (persisted): {v}\n")),
        None => out.push_str("declaration version (persisted): none\n"),
    }

    if let Some(plan) = drift {
        if plan.is_empty() {
            out.push_str("drift: in sync\n");
        } else {
            let (mut creates, mut updates, mut deletes) = (0usize, 0usize, 0usize);
            for a in &plan.actions {
                match a {
                    Action::Create(_) => creates += 1,
                    Action::Update { .. } => updates += 1,
                    Action::Delete { .. } => deletes += 1,
                }
            }
            out.push_str(&format!(
                "drift: {creates} create(s), {updates} update(s), {deletes} delete(s)\n"
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::Action;
    use crate::rolestore::Limits;
    use crate::state::{FakeState, ManagedAccount};
    use crate::model::ResolvedAccount;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn state_of(accts: Vec<ManagedAccount>) -> FakeState {
        FakeState {
            accounts: accts.into_iter().map(|a| (a.name.clone(), a)).collect(),
        }
    }

    fn managed_acct(name: &str, from_version: u32) -> ManagedAccount {
        ManagedAccount {
            name: name.to_owned(),
            uid: 9010,
            shell: "/bin/bash".to_owned(),
            groups: vec![],
            sudo_role: None,
            from_version,
        }
    }

    fn target(name: &str) -> ResolvedAccount {
        ResolvedAccount {
            name: name.to_owned(),
            uid: 9010,
            shell: "/bin/bash".to_owned(),
            home: PathBuf::from("/h"),
            groups: vec![],
            sudo_role: None,
            limits: Limits::default(),
            locked_password: true,
        }
    }

    #[test]
    fn lists_managed_accounts_and_versions() {
        let st = state_of(vec![managed_acct("oper", 3), managed_acct("serv", 5)]);
        let out = render_status(&st, Some(7), None);
        assert!(out.contains("oper (from_version 3)"));
        assert!(out.contains("serv (from_version 5)"));
        assert!(out.contains("declaration version (persisted): 7"));
    }

    #[test]
    fn empty_managed_and_no_version() {
        let st = FakeState { accounts: BTreeMap::new() };
        let out = render_status(&st, None, None);
        assert!(out.contains("(none)"));
        assert!(out.contains("declaration version (persisted): none"));
    }

    #[test]
    fn drift_summary_counts_actions() {
        let st = state_of(vec![managed_acct("oper", 3)]);
        let plan = Plan {
            actions: vec![
                Action::Create(target("new")),
                Action::Update { account: target("oper"), changes: vec!["x".into()] },
                Action::Delete { name: "old".into() },
            ],
        };
        let out = render_status(&st, Some(3), Some(&plan));
        assert!(out.contains("drift: 1 create(s), 1 update(s), 1 delete(s)"));
    }

    #[test]
    fn in_sync_drift_reported() {
        let st = state_of(vec![managed_acct("oper", 3)]);
        let plan = Plan::default();
        let out = render_status(&st, Some(3), Some(&plan));
        assert!(out.contains("drift: in sync"));
    }
}
