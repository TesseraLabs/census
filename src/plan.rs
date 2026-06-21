//! Diff engine: resolved target accounts vs current managed state → a `Plan`.
//!
//! Pure logic. Ordering follows spec §5: creates/updates first (groups then
//! accounts is an apply-time concern, not modelled here), deletes are flagged
//! as destructive. No mutation happens here.

use crate::inspect::GroupFacts;
use crate::model::ResolvedAccount;
use crate::state::{ManagedAccount, ManagedGroup, SystemState};
use std::collections::BTreeMap;

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

/// A single planned group change. Computed from the required set vs the managed
/// group registry + live facts (design Р3). Census only ever creates or deletes
/// groups it owns (in the registry); pre-existing/foreign groups are skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupAction {
    /// Group is required but not present in the system — create it (with the
    /// pinned GID if the declaration pinned one, else OS-assigned).
    Create {
        /// Group name to create.
        name: String,
        /// Pinned GID, if declared.
        gid: Option<u32>,
    },
    /// Group is in the registry (Census-owned) but no longer required and not
    /// declared — delete it (destructive). Sequenced after account deletes.
    Delete {
        /// Group name to remove.
        name: String,
    },
}

impl GroupAction {
    /// Whether this action is destructive (delete).
    pub fn is_destructive(&self) -> bool {
        matches!(self, GroupAction::Delete { .. })
    }
}

/// A planning error that must abort before any mutation (design §Безопасность).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GroupPlanError {
    /// A declaration pinned a GID that already belongs to a DIFFERENT existing
    /// group. Census refuses rather than renumbering (destructive for file
    /// owners). `existing_name` is the live group currently holding `gid`.
    #[error("group {group:?} pins gid {gid} but that gid already belongs to group {existing_name:?}; refusing to renumber")]
    GidPinConflict {
        /// The required group whose pin conflicts.
        group: String,
        /// The pinned GID.
        gid: u32,
        /// The live group that already owns the GID.
        existing_name: String,
    },
    /// A required group already exists with a GID that differs from its pin
    /// (Census would have to renumber an existing group in place — refused).
    #[error("group {group:?} exists with gid {live} but declaration pins gid {pinned}; refusing to renumber in place")]
    PinnedGidMismatch {
        /// The required group.
        group: String,
        /// The live GID.
        live: u32,
        /// The pinned GID.
        pinned: u32,
    },
    /// A managed (registry) group's live GID diverges from the recorded GID —
    /// surfaced as a planning error (not renumbered on the fly).
    #[error("managed group {group:?} has live gid {live} but registry recorded {recorded}; refusing to renumber")]
    ManagedGidDrift {
        /// The managed group.
        group: String,
        /// The live GID.
        live: u32,
        /// The registry-recorded GID.
        recorded: u32,
    },
}

/// An ordered set of actions: creates, then updates, then deletes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    /// Ordered account actions.
    pub actions: Vec<Action>,
    /// Ordered group actions (creates first, then deletes). Applied around the
    /// account phases: creates BEFORE account create, deletes AFTER account
    /// delete (design Р4).
    pub group_actions: Vec<GroupAction>,
}

impl Plan {
    /// True if nothing needs to change (no account AND no group actions).
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty() && self.group_actions.is_empty()
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

    Plan { actions, group_actions: Vec::new() }
}

/// Compute the group actions (design Р3). Pure logic over three inputs:
/// * `required` — the required group set (name → optional pinned GID) from
///   [`crate::declaration::required_groups`];
/// * `managed_groups` — the Census-owned groups recorded in the registry;
/// * `live` — live group facts by name (existence + GID), pre-collected by the
///   caller from a [`crate::inspect::SystemInspector`] for every name that
///   appears in `required` or `managed_groups`.
///
/// Rules (per design):
/// * required & not present in system → `Create` (with pinned GID if any);
/// * required & present but NOT in the registry (pre-existing/foreign) → SKIP
///   (no create, no adopt) — Census did not create it, so it never owns it;
/// * in registry & no longer required → `Delete` (orphan, Census-owned);
/// * required, pinned GID conflicts with a different live group, or differs
///   from an existing same-named group's GID, or a managed group's live GID
///   diverges from the registry → `Err` (abort before mutation; never renumber).
///
/// Creates are emitted in `required` (BTreeMap) order, then deletes in registry
/// order — deterministic, stable plan output.
pub fn diff_groups(
    required: &BTreeMap<String, Option<u32>>,
    managed_groups: &BTreeMap<String, ManagedGroup>,
    live: &BTreeMap<String, GroupFacts>,
    gid_owners: &BTreeMap<u32, String>,
) -> Result<Vec<GroupAction>, GroupPlanError> {
    // `gid_owners` maps a pinned GID to the live group that owns it (if any),
    // for pin-conflict detection against a DIFFERENT existing group. The caller
    // collects it (live group facts only cover required/managed names, which is
    // not enough to spot a foreign group already holding a pinned GID).
    let mut creates = Vec::new();
    for (name, pin) in required {
        match live.get(name) {
            // Already present in the system.
            Some(facts) => {
                if let Some(pinned) = pin {
                    if *pinned != facts.gid {
                        // Same-named group exists with a different GID than the
                        // pin → refuse (would require in-place renumber).
                        return Err(GroupPlanError::PinnedGidMismatch {
                            group: name.clone(),
                            live: facts.gid,
                            pinned: *pinned,
                        });
                    }
                }
                // Present (registry or foreign) and GID consistent → nothing to
                // create. Foreign groups are never adopted; membership is still
                // assigned by the account phase. Managed-group GID drift is
                // checked separately below.
            }
            // Not present → create (honoring the pin, with conflict check).
            None => {
                if let Some(pinned) = pin {
                    if let Some(owner) = gid_owners.get(pinned) {
                        if owner != name {
                            return Err(GroupPlanError::GidPinConflict {
                                group: name.clone(),
                                gid: *pinned,
                                existing_name: owner.clone(),
                            });
                        }
                    }
                }
                creates.push(GroupAction::Create {
                    name: name.clone(),
                    gid: *pin,
                });
            }
        }
    }

    // Managed-group GID drift: a registry group still present but whose live GID
    // no longer matches the recorded GID. Refuse (do not renumber on the fly).
    for (name, mg) in managed_groups {
        if let Some(facts) = live.get(name) {
            if facts.gid != mg.gid {
                return Err(GroupPlanError::ManagedGidDrift {
                    group: name.clone(),
                    live: facts.gid,
                    recorded: mg.gid,
                });
            }
        }
    }

    // Deletes: registry (Census-owned) groups no longer required (BTreeMap order).
    let mut deletes = Vec::new();
    for name in managed_groups.keys() {
        if !required.contains_key(name) {
            deletes.push(GroupAction::Delete { name: name.clone() });
        }
    }

    creates.extend(deletes);
    Ok(creates)
}

/// Collect live group facts for every name in `required` or `managed_groups`
/// from `inspector`, then run [`diff_groups`]. A thin orchestration helper so
/// CLI (`plan`) and apply share one collection path. Read-only.
pub fn diff_groups_via_inspector(
    required: &BTreeMap<String, Option<u32>>,
    managed_groups: &BTreeMap<String, ManagedGroup>,
    inspector: &dyn crate::inspect::SystemInspector,
) -> Result<Vec<GroupAction>, GroupPlanError> {
    let mut live: BTreeMap<String, GroupFacts> = BTreeMap::new();
    for name in required.keys().chain(managed_groups.keys()) {
        if live.contains_key(name) {
            continue;
        }
        if let Some(facts) = inspector.group(name) {
            live.insert(name.clone(), facts);
        }
    }
    // For each pinned GID, find the live group (if any) that already owns it,
    // so a conflict against a DIFFERENT existing group is caught.
    let mut gid_owners: BTreeMap<u32, String> = BTreeMap::new();
    for pin in required.values().flatten() {
        if let std::collections::btree_map::Entry::Vacant(e) = gid_owners.entry(*pin) {
            if let Some(owner) = inspector.group_name_by_gid(*pin) {
                e.insert(owner);
            }
        }
    }
    diff_groups(required, managed_groups, &live, &gid_owners)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rolestore::Limits;
    use crate::state::{FakeState, ManagedAccount};
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
            ..Default::default()
        }
    }

    #[test]
    fn create_when_absent() {
        let targets = vec![target("oper", 9010, "/bin/bash", &["wheel"])];
        let st = FakeState::default();
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

    // ---- group diff (task 3) ----

    use crate::inspect::GroupFacts;
    use crate::state::ManagedGroup;

    fn req(pairs: &[(&str, Option<u32>)]) -> BTreeMap<String, Option<u32>> {
        pairs.iter().map(|(n, g)| (n.to_string(), *g)).collect()
    }

    fn mgroup(name: &str, gid: u32) -> ManagedGroup {
        ManagedGroup { name: name.to_owned(), gid, from_version: 1 }
    }

    fn managed_groups(gs: &[ManagedGroup]) -> BTreeMap<String, ManagedGroup> {
        gs.iter().map(|g| (g.name.clone(), g.clone())).collect()
    }

    fn live_groups(pairs: &[(&str, u32)]) -> BTreeMap<String, GroupFacts> {
        pairs
            .iter()
            .map(|(n, gid)| (n.to_string(), GroupFacts { gid: *gid }))
            .collect()
    }

    fn owners(pairs: &[(u32, &str)]) -> BTreeMap<u32, String> {
        pairs.iter().map(|(g, n)| (*g, n.to_string())).collect()
    }

    fn no_owners() -> BTreeMap<u32, String> {
        BTreeMap::new()
    }

    #[test]
    fn group_create_when_missing() {
        // required atm-operators (pinned 8010), not in system, not in registry.
        let required = req(&[("atm-operators", Some(8010))]);
        let actions =
            diff_groups(&required, &BTreeMap::new(), &BTreeMap::new(), &no_owners()).unwrap();
        assert_eq!(
            actions,
            vec![GroupAction::Create {
                name: "atm-operators".into(),
                gid: Some(8010)
            }]
        );
    }

    #[test]
    fn group_create_without_pin() {
        let required = req(&[("tellers", None)]);
        let actions =
            diff_groups(&required, &BTreeMap::new(), &BTreeMap::new(), &no_owners()).unwrap();
        assert_eq!(actions, vec![GroupAction::Create { name: "tellers".into(), gid: None }]);
    }

    #[test]
    fn group_skip_foreign_existing() {
        // required wheel, already present in system but NOT in registry → SKIP.
        let required = req(&[("wheel", None)]);
        let live = live_groups(&[("wheel", 10)]);
        let actions = diff_groups(&required, &BTreeMap::new(), &live, &no_owners()).unwrap();
        assert!(actions.is_empty(), "foreign existing group must not be created or adopted");
    }

    #[test]
    fn group_delete_orphan_in_registry() {
        // Registry owns atm-operators; no longer required → Delete.
        let required = req(&[]);
        let registry = managed_groups(&[mgroup("atm-operators", 8010)]);
        let live = live_groups(&[("atm-operators", 8010)]);
        let actions = diff_groups(&required, &registry, &live, &no_owners()).unwrap();
        assert_eq!(actions, vec![GroupAction::Delete { name: "atm-operators".into() }]);
        assert!(actions[0].is_destructive());
    }

    #[test]
    fn group_in_registry_still_required_no_action() {
        let required = req(&[("atm-operators", Some(8010))]);
        let registry = managed_groups(&[mgroup("atm-operators", 8010)]);
        let live = live_groups(&[("atm-operators", 8010)]);
        let actions = diff_groups(&required, &registry, &live, &no_owners()).unwrap();
        assert!(actions.is_empty(), "still-required managed group needs no action");
    }

    #[test]
    fn group_pin_conflict_with_different_group_errors() {
        // Pin gid 8010 for atm-operators, but gid 8010 already belongs to a
        // DIFFERENT live group `other` (and atm-operators itself is absent).
        let required = req(&[("atm-operators", Some(8010))]);
        // atm-operators itself is absent; gid 8010 is owned by foreign `other`.
        let err = diff_groups(
            &required,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &owners(&[(8010, "other")]),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GroupPlanError::GidPinConflict { ref existing_name, gid: 8010, .. } if existing_name == "other"
        ));
    }

    #[test]
    fn group_pin_mismatch_with_same_name_errors() {
        // atm-operators exists live with gid 9999 but declaration pins 8010.
        let required = req(&[("atm-operators", Some(8010))]);
        let live = live_groups(&[("atm-operators", 9999)]);
        let err = diff_groups(&required, &BTreeMap::new(), &live, &no_owners()).unwrap_err();
        assert!(matches!(
            err,
            GroupPlanError::PinnedGidMismatch { live: 9999, pinned: 8010, .. }
        ));
    }

    #[test]
    fn managed_group_gid_drift_errors() {
        // Registry recorded gid 8010, but live shows 8099 → refuse.
        let required = req(&[("atm-operators", None)]);
        let registry = managed_groups(&[mgroup("atm-operators", 8010)]);
        let live = live_groups(&[("atm-operators", 8099)]);
        let err = diff_groups(&required, &registry, &live, &no_owners()).unwrap_err();
        assert!(matches!(
            err,
            GroupPlanError::ManagedGidDrift { live: 8099, recorded: 8010, .. }
        ));
    }

    #[test]
    fn group_create_and_delete_ordering() {
        // new group required; old managed group orphaned. Create precedes delete.
        let required = req(&[("new-grp", None)]);
        let registry = managed_groups(&[mgroup("old-grp", 8010)]);
        let live = live_groups(&[("old-grp", 8010)]);
        let actions = diff_groups(&required, &registry, &live, &no_owners()).unwrap();
        assert_eq!(actions.len(), 2);
        assert!(matches!(actions[0], GroupAction::Create { .. }));
        assert!(matches!(actions[1], GroupAction::Delete { .. }));
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
