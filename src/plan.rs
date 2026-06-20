//! Diff engine: resolved target accounts vs current managed state → a `Plan`.
//!
//! Pure logic. Ordering follows spec §5: creates/updates first (groups then
//! accounts is an apply-time concern, not modelled here), deletes are flagged
//! as destructive. No mutation happens here.

use crate::model::ResolvedAccount;
use crate::state::{ManagedAccount, SystemState};

/// A single planned change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Account does not exist in managed state — create it.
    Create(ResolvedAccount),
    /// Account exists but differs — reconcile it. `changes` are human-readable.
    Update {
        /// Target account.
        account: ResolvedAccount,
        /// What differs (field-level descriptions).
        changes: Vec<String>,
    },
    /// Account is managed but no longer declared — delete (destructive).
    Delete {
        /// Login name to remove.
        name: String,
    },
}

impl Action {
    /// Whether this action is destructive (delete).
    pub fn is_destructive(&self) -> bool {
        matches!(self, Action::Delete { .. })
    }
}

/// An ordered set of actions: creates, then updates, then deletes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    /// Ordered actions.
    pub actions: Vec<Action>,
}

impl Plan {
    /// True if nothing needs to change.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

/// Compare a resolved target account with its managed record; return the list
/// of human-readable field differences (empty == in sync).
fn diff_fields(target: &ResolvedAccount, current: &ManagedAccount) -> Vec<String> {
    let mut changes = Vec::new();
    if target.uid != current.uid {
        changes.push(format!("uid {} -> {}", current.uid, target.uid));
    }
    if target.shell != current.shell {
        changes.push(format!("shell {:?} -> {:?}", current.shell, target.shell));
    }
    let mut tg = target.groups.clone();
    let mut cg = current.groups.clone();
    tg.sort();
    cg.sort();
    if tg != cg {
        changes.push(format!("groups {:?} -> {:?}", current.groups, target.groups));
    }
    if target.sudo_role != current.sudo_role {
        changes.push(format!("sudo {:?} -> {:?}", current.sudo_role, target.sudo_role));
    }
    changes
}

/// Compute the plan. `targets` are the desired accounts (from `model::resolve`),
/// `state` is the current managed state.
pub fn diff(targets: &[ResolvedAccount], state: &dyn SystemState) -> Plan {
    let managed = state.managed_accounts();
    let mut actions = Vec::new();

    // Creates and updates, in declaration order (stable output).
    for target in targets {
        match managed.get(&target.name) {
            None => actions.push(Action::Create(target.clone())),
            Some(current) => {
                let changes = diff_fields(target, current);
                if !changes.is_empty() {
                    actions.push(Action::Update {
                        account: target.clone(),
                        changes,
                    });
                }
            }
        }
    }

    // Deletes: managed accounts no longer in targets (BTreeMap => sorted order).
    let declared: std::collections::BTreeSet<&str> =
        targets.iter().map(|t| t.name.as_str()).collect();
    for name in managed.keys() {
        if !declared.contains(name.as_str()) {
            actions.push(Action::Delete { name: name.clone() });
        }
    }

    Plan { actions }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rolestore::Limits;
    use crate::state::{FakeState, ManagedAccount};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn target(name: &str, uid: u32, shell: &str, groups: &[&str]) -> ResolvedAccount {
        ResolvedAccount {
            name: name.to_owned(),
            uid,
            shell: shell.to_owned(),
            home: PathBuf::from(format!("/var/lib/census/home/{name}")),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            sudo_role: None,
            limits: Limits::default(),
            locked_password: true,
        }
    }

    fn managed(name: &str, uid: u32, shell: &str, groups: &[&str], v: u32) -> ManagedAccount {
        ManagedAccount {
            name: name.to_owned(),
            uid,
            shell: shell.to_owned(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            sudo_role: None,
            from_version: v,
        }
    }

    /// Resolved target carrying a sudo_role (other fields match `target`).
    fn target_sudo(
        name: &str,
        uid: u32,
        shell: &str,
        groups: &[&str],
        sudo_role: Option<&str>,
    ) -> ResolvedAccount {
        let mut t = target(name, uid, shell, groups);
        t.sudo_role = sudo_role.map(|s| s.to_owned());
        t
    }

    /// Managed record carrying a sudo_role (other fields match `managed`).
    fn managed_sudo(
        name: &str,
        uid: u32,
        shell: &str,
        groups: &[&str],
        sudo_role: Option<&str>,
        v: u32,
    ) -> ManagedAccount {
        let mut m = managed(name, uid, shell, groups, v);
        m.sudo_role = sudo_role.map(|s| s.to_owned());
        m
    }

    fn state_of(accts: Vec<ManagedAccount>) -> FakeState {
        FakeState {
            accounts: accts.into_iter().map(|a| (a.name.clone(), a)).collect(),
        }
    }

    #[test]
    fn create_when_absent() {
        let targets = vec![target("oper", 9010, "/bin/bash", &["wheel"])];
        let st = FakeState { accounts: BTreeMap::new() };
        let plan = diff(&targets, &st);
        assert_eq!(plan.actions.len(), 1);
        assert!(matches!(plan.actions[0], Action::Create(_)));
    }

    #[test]
    fn idempotent_when_in_sync() {
        let targets = vec![target("oper", 9010, "/bin/bash", &["wheel"])];
        let st = state_of(vec![managed("oper", 9010, "/bin/bash", &["wheel"], 3)]);
        let plan = diff(&targets, &st);
        assert!(plan.is_empty(), "in-sync account must produce no actions");
    }

    #[test]
    fn update_on_group_drift() {
        let targets = vec![target("oper", 9010, "/bin/bash", &["wheel", "docker"])];
        let st = state_of(vec![managed("oper", 9010, "/bin/bash", &["wheel"], 3)]);
        let plan = diff(&targets, &st);
        match &plan.actions[0] {
            Action::Update { changes, .. } => {
                assert_eq!(changes.len(), 1);
                assert!(changes[0].contains("groups"));
            }
            other => panic!("expected Update, got {other:?}"),
        }
    }

    #[test]
    fn groups_diff_is_order_insensitive() {
        let targets = vec![target("oper", 9010, "/bin/bash", &["wheel", "docker"])];
        let st = state_of(vec![managed("oper", 9010, "/bin/bash", &["docker", "wheel"], 3)]);
        let plan = diff(&targets, &st);
        assert!(
            plan.is_empty(),
            "same group membership in different order must produce no actions"
        );
    }

    #[test]
    fn delete_when_vanished() {
        let targets: Vec<ResolvedAccount> = vec![];
        let st = state_of(vec![managed("oper", 9010, "/bin/bash", &[], 3)]);
        let plan = diff(&targets, &st);
        assert_eq!(plan.actions, vec![Action::Delete { name: "oper".into() }]);
        assert!(plan.actions[0].is_destructive());
    }

    #[test]
    fn sudo_revocation_yields_update_even_with_no_other_change() {
        // Managed account has sudo; target drops it. No other field differs.
        let targets = vec![target_sudo("oper", 9010, "/bin/bash", &["wheel"], None)];
        let st = state_of(vec![managed_sudo(
            "oper",
            9010,
            "/bin/bash",
            &["wheel"],
            Some("ops"),
            3,
        )]);
        let plan = diff(&targets, &st);
        assert_eq!(plan.actions.len(), 1, "sudo revocation must produce one action");
        match &plan.actions[0] {
            Action::Update { changes, .. } => {
                assert_eq!(changes.len(), 1, "only the sudo field should differ");
                assert!(changes[0].contains("sudo"), "change must mention sudo: {changes:?}");
            }
            other => panic!("expected Update, got {other:?}"),
        }
    }

    #[test]
    fn sudo_grant_yields_update_even_with_no_other_change() {
        // Reverse: managed has no sudo, target gains it.
        let targets = vec![target_sudo("oper", 9010, "/bin/bash", &["wheel"], Some("ops"))];
        let st = state_of(vec![managed_sudo(
            "oper",
            9010,
            "/bin/bash",
            &["wheel"],
            None,
            3,
        )]);
        let plan = diff(&targets, &st);
        assert_eq!(plan.actions.len(), 1);
        match &plan.actions[0] {
            Action::Update { changes, .. } => {
                assert_eq!(changes.len(), 1);
                assert!(changes[0].contains("sudo"), "change must mention sudo: {changes:?}");
            }
            other => panic!("expected Update, got {other:?}"),
        }
    }

    #[test]
    fn identical_sudo_role_is_idempotent() {
        let targets = vec![target_sudo("oper", 9010, "/bin/bash", &["wheel"], Some("ops"))];
        let st = state_of(vec![managed_sudo(
            "oper",
            9010,
            "/bin/bash",
            &["wheel"],
            Some("ops"),
            3,
        )]);
        let plan = diff(&targets, &st);
        assert!(plan.is_empty(), "identical sudo_role must produce no actions");
    }

    #[test]
    fn mixed_create_update_delete_ordering() {
        let targets = vec![
            target("oper", 9010, "/bin/bash", &["wheel", "docker"]), // update
            target("admin", 9030, "/bin/bash", &[]),                 // create
        ];
        let st = state_of(vec![
            managed("oper", 9010, "/bin/bash", &["wheel"], 3), // -> update
            managed("serv", 9020, "/bin/bash", &[], 3),        // -> delete
        ]);
        let plan = diff(&targets, &st);
        // order: targets first (oper update, admin create), then deletes (serv)
        assert!(matches!(plan.actions[0], Action::Update { .. }));
        assert!(matches!(plan.actions[1], Action::Create(_)));
        assert!(matches!(plan.actions[2], Action::Delete { .. }));
    }
}
