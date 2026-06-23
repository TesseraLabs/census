//! Diff engine: resolved target accounts vs current managed state → a `Plan`.
//!
//! Pure logic. Ordering follows spec §5: creates/updates first (groups then
//! accounts is an apply-time concern, not modelled here), deletes are flagged
//! as destructive. No mutation happens here.

use std::collections::BTreeMap;

use crate::inspect::GroupFacts;
use crate::model::{Provenance, ResolvedAccount, ResolvedGroup};
use crate::state::{ManagedAccount, ManagedFileGrant, ManagedGroup, SystemState};

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

/// A single planned group change. Two diff paths feed this enum:
/// * the membership-driven path ([`diff_groups`]), which only ever `Create`s or `Delete`s groups
///   Census owns from the required set vs the registry + live facts (design Р3); and
/// * the declaration-driven path ([`diff_resolved_groups`]), which reconciles declared `[[group]]`
///   objects carrying grants/members and adds `Adopt`, `Release`, and `Update` for the
///   provenance-aware lifecycle.
///
/// Only `Delete` is destructive: it removes the underlying group. `Adopt`,
/// `Release`, and `Update` never destroy a group — `Release` strips Census's own
/// grants/members from an adopted group and returns it to baseline without a
/// `groupdel`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupAction {
    /// Group is required/declared (`Created` provenance) but not present in the
    /// system — create it (with the pinned GID if declared, else OS-assigned).
    Create {
        /// Group name to create.
        name: String,
        /// Pinned GID, if declared.
        gid: Option<u32>,
    },
    /// Group is declared with `Adopted` provenance and not yet in the registry —
    /// take the pre-existing group under management (snapshot its baseline, then
    /// layer Census's grants/members on top). Never creates the group. NOT
    /// destructive.
    Adopt {
        /// Group name to adopt.
        name: String,
    },
    /// Group is in the registry with `Adopted` provenance but no longer declared
    /// — release it: strip Census's own grants and Census-added members and
    /// return it to the recorded baseline. The underlying group is NEVER deleted.
    /// NOT destructive.
    Release {
        /// Group name to release.
        name: String,
    },
    /// Group is in the registry and still declared, but its grants or members
    /// differ from what Census recorded — reconcile it. `changes` are
    /// human-readable field-level descriptions. NOT destructive.
    Update {
        /// Group name to reconcile.
        name: String,
        /// What differs (field-level descriptions).
        changes: Vec<String>,
    },
    /// Group is in the registry with `Created` provenance but no longer
    /// required/declared — delete it (destructive). Sequenced after account
    /// deletes.
    Delete {
        /// Group name to remove.
        name: String,
    },
}

impl GroupAction {
    /// Whether this action is destructive. Only `Delete` removes the underlying
    /// group; `Adopt`/`Release`/`Update` leave the group intact.
    pub fn is_destructive(&self) -> bool {
        matches!(self, GroupAction::Delete { .. })
    }
}

/// A planning error that must abort before any mutation (design §Безопасность).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
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
    if !str_set_equal(&current.groups, &target.groups) {
        changes.push(format!(
            "groups {:?} -> {:?}",
            current.groups, target.groups
        ));
    }
    if target.sudo_role != current.sudo_role {
        changes.push(format!(
            "sudo {:?} -> {:?}",
            current.sudo_role, target.sudo_role
        ));
    }
    // Concrete sudo commands: compared set-equal (order-insensitive), mirroring
    // groups/sudo_role. Granting or revoking a permission that changes the
    // command set must produce an Update so the NOPASSWD fragment is rewritten —
    // otherwise a revoked command would leak as a stale rule.
    if !str_set_equal(&current.sudo_commands, &target.sudo_commands) {
        changes.push(format!(
            "sudo-commands {:?} -> {:?}",
            current.sudo_commands, target.sudo_commands
        ));
    }
    // File grants: compared set-equal (order-insensitive) by
    // (path, access, recursive), mirroring sudo_commands. Granting or revoking a
    // permission that changes the file-grant set must produce an Update so the
    // backend re-materializes / revokes the ACL — otherwise a revoked grant would
    // leak as a stale ACL entry.
    if !file_grants_set_equal(&current.file_grants, &target.file_grants) {
        let cur: Vec<_> = current
            .file_grants
            .iter()
            .map(grant_label_managed)
            .collect();
        let tgt: Vec<_> = target
            .file_grants
            .iter()
            .map(grant_label_resolved)
            .collect();
        changes.push(format!("file-grants {cur:?} -> {tgt:?}"));
    }
    changes
}

/// The set-equality key of a file grant: (path, access, recursive). Order- and
/// provenance-insensitive — provenance and the derived shape are not part of the
/// account's enforced state, only what is materialized is. The path is borrowed
/// (`&str`) so the key carries no allocation.
fn grant_key(path: &str, access: crate::catalog::Access, recursive: bool) -> (&str, bool, bool) {
    // access encoded as a bool (rw=true) so the tuple is cheaply Ord-comparable.
    (
        path,
        matches!(access, crate::catalog::Access::Rw),
        recursive,
    )
}

/// Whether a recorded managed file-grant set equals a resolved target set,
/// compared set-equal (order-insensitive) by (path, access, recursive). Shared
/// by the plan diff and `apply::build_managed_set`. Short-circuits on length, then
/// sorts borrowed keys (no path String is cloned).
pub fn file_grants_set_equal(
    managed: &[ManagedFileGrant],
    target: &[crate::catalog::ResolvedFileGrant],
) -> bool {
    if managed.len() != target.len() {
        return false;
    }
    let mut m: Vec<_> = managed
        .iter()
        .map(|g| grant_key(&g.path, g.access, g.recursive))
        .collect();
    let mut t: Vec<_> = target
        .iter()
        .map(|g| grant_key(&g.path, g.access, g.recursive))
        .collect();
    m.sort_unstable();
    t.sort_unstable();
    m == t
}

/// Whether two string lists are set-equal (order-insensitive). Shared by the
/// account diff (`groups`, `sudo_commands`) and the group diff
/// (`sudo_commands`, members) so both compare enforced sets the same way: order
/// is not part of the enforced state, membership is.
fn str_set_equal(a: &[String], b: &[String]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // Compare sorted borrowed `&str`: no String is cloned, only two pointer
    // vectors are sorted (the per-account/per-group diff loops run this often).
    let mut sa: Vec<&str> = a.iter().map(String::as_str).collect();
    let mut sb: Vec<&str> = b.iter().map(String::as_str).collect();
    sa.sort_unstable();
    sb.sort_unstable();
    sa == sb
}

/// A short human-readable label for a managed file grant (for change lines).
fn grant_label_managed(g: &ManagedFileGrant) -> String {
    format!(
        "{}={:?}{}",
        g.path,
        g.access,
        if g.recursive { " -R" } else { "" }
    )
}

/// A short human-readable label for a resolved file grant (for change lines).
fn grant_label_resolved(g: &crate::catalog::ResolvedFileGrant) -> String {
    format!(
        "{}={:?}{}",
        g.path,
        g.access,
        if g.recursive { " -R" } else { "" }
    )
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

    Plan {
        actions,
        group_actions: Vec::new(),
    }
}

/// Compute the group actions (design Р3). Pure logic over three inputs:
/// * `required` — the required group set (name → optional pinned GID) from
///   [`crate::declaration::required_groups`];
/// * `managed_groups` — the Census-owned groups recorded in the registry;
/// * `live` — live group facts by name (existence + GID), pre-collected by the caller from a
///   [`crate::inspect::SystemInspector`] for every name that appears in `required` or
///   `managed_groups`.
///
/// Rules (per design):
/// * required & not present in system → `Create` (with pinned GID if any);
/// * required & present but NOT in the registry (pre-existing/foreign) → SKIP (no create, no adopt)
///   — Census did not create it, so it never owns it;
/// * in registry & no longer required → `Delete` (orphan, Census-owned);
/// * required, pinned GID conflicts with a different live group, or differs from an existing
///   same-named group's GID, or a managed group's live GID diverges from the registry → `Err`
///   (abort before mutation; never renumber).
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
    // Only checked when a concrete GID was recorded — an unknown (`None`) GID has
    // nothing to diverge from, so it cannot be drift.
    for (name, mg) in managed_groups {
        if let (Some(facts), Some(recorded)) = (live.get(name), mg.gid) {
            if facts.gid != recorded {
                return Err(GroupPlanError::ManagedGidDrift {
                    group: name.clone(),
                    live: facts.gid,
                    recorded,
                });
            }
        }
    }

    // Deletes: registry (Census-owned) groups no longer required (BTreeMap order).
    // Only a `Created` group is groupdel'd here — this path is the authority for
    // group EXISTENCE. An `Adopted` group pre-existed Census, so its teardown is
    // a grant-release handled by the declaration-driven resolved path
    // (`GroupAction::Release`), never a `groupdel`: Census returns it to baseline
    // but leaves the underlying group (and its foreign members) alone.
    let mut deletes = Vec::new();
    for (name, mg) in managed_groups {
        if !required.contains_key(name) && mg.provenance == Provenance::Created {
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

/// Compute the declaration-driven group actions for groups carrying grants and
/// members (design "Adoption-baseline и release"). This is the second group diff
/// path, distinct from [`diff_groups`]: that one reconciles the membership-driven
/// required set (accounts joining groups like `netdev`); this one reconciles the
/// declared `[[group]]` objects that own grants/members and a provenance.
///
/// Rules:
/// * `target` not in `managed_groups`:
///   * `provenance == Created` → [`GroupAction::Create`] (with the pinned GID);
///   * `provenance == Adopted` → [`GroupAction::Adopt`] (take it under management, never create the
///     underlying group).
/// * `target` in `managed_groups`: compare what Census materializes — sudo commands and members
///   set-equal (order-insensitive), file grants by (path, access, recursive). Any difference →
///   [`GroupAction::Update`] with human-readable change lines (same shape as the account
///   `diff_fields`). All equal → no action.
/// * `managed` group with NO matching `target` (by name): the release-vs-delete trigger is the
///   SAVED provenance, never the declaration's shape — `Created` → [`GroupAction::Delete`] (full
///   `groupdel`); `Adopted` → [`GroupAction::Release`] (strip Census's grants/members, restore
///   baseline, never delete).
///
/// Ordering is deterministic: creates/adopts/updates in `targets` slice order,
/// then releases/deletes in `managed_groups` (BTreeMap) order — mirroring how
/// [`diff_groups`] sequences its deletes after its creates.
///
/// GID is deliberately NOT reconciled here. A group's GID is the responsibility
/// of the membership-driven [`diff_groups`] path, which compares the recorded
/// GID against live facts and fails closed with `GroupPlanError::ManagedGidDrift`
/// rather than renumbering. This declaration-driven path covers only the grants
/// Census materializes (sudo commands, file grants) and its added members — never
/// the GID (an adopted group carries `gid == None` regardless, since its GID is
/// observed at apply, never assigned).
pub fn diff_resolved_groups(
    targets: &[ResolvedGroup],
    managed_groups: &BTreeMap<String, ManagedGroup>,
) -> Vec<GroupAction> {
    let mut head = Vec::new();
    for target in targets {
        match managed_groups.get(&target.name) {
            None => match target.provenance {
                Provenance::Created => head.push(GroupAction::Create {
                    name: target.name.clone(),
                    gid: target.gid,
                }),
                Provenance::Adopted => head.push(GroupAction::Adopt {
                    name: target.name.clone(),
                }),
            },
            Some(current) => {
                let changes = diff_group_fields(target, current);
                if !changes.is_empty() {
                    head.push(GroupAction::Update {
                        name: target.name.clone(),
                        changes,
                    });
                }
            }
        }
    }

    // Releases/deletes: managed groups no longer declared (BTreeMap => sorted).
    // The trigger is the STORED provenance, not the declaration shape.
    let declared: std::collections::BTreeSet<&str> =
        targets.iter().map(|t| t.name.as_str()).collect();
    for (name, mg) in managed_groups {
        if declared.contains(name.as_str()) {
            continue;
        }
        match mg.provenance {
            Provenance::Created => head.push(GroupAction::Delete { name: name.clone() }),
            Provenance::Adopted => head.push(GroupAction::Release { name: name.clone() }),
        }
    }

    head
}

/// Compare a resolved target group with its managed record; return the list of
/// human-readable field differences (empty == in sync). Compares only what
/// Census materializes/owns: the group's sudo commands, file grants, and
/// Census-added members (`members_added`) — never the group's foreign/baseline
/// members. Mirrors the account `diff_fields` change-line shape.
fn diff_group_fields(target: &ResolvedGroup, current: &ManagedGroup) -> Vec<String> {
    let mut changes = Vec::new();
    if !str_set_equal(&current.sudo_commands, &target.sudo_commands) {
        changes.push(format!(
            "sudo-commands {:?} -> {:?}",
            current.sudo_commands, target.sudo_commands
        ));
    }
    if !file_grants_set_equal(&current.file_grants, &target.file_grants) {
        let cur: Vec<_> = current
            .file_grants
            .iter()
            .map(grant_label_managed)
            .collect();
        let tgt: Vec<_> = target
            .file_grants
            .iter()
            .map(grant_label_resolved)
            .collect();
        changes.push(format!("file-grants {cur:?} -> {tgt:?}"));
    }
    // Members compared against members_added — what Census itself added. The
    // group's pre-existing/foreign members are never part of the diff.
    if !str_set_equal(&current.members_added, &target.members) {
        changes.push(format!(
            "members {:?} -> {:?}",
            current.members_added, target.members
        ));
    }
    changes
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::rolestore::Limits;
    use crate::state::FakeState;

    fn target(name: &str, uid: u32, shell: &str, groups: &[&str]) -> ResolvedAccount {
        ResolvedAccount {
            name: name.to_owned(),
            uid,
            shell: shell.to_owned(),
            home: PathBuf::from(format!("/var/lib/census/home/{name}")),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            sudo_role: None,
            sudo_commands: Vec::new(),
            limits: Limits::default(),
            file_grants: Vec::new(),
            locked_password: true,
            provenance: crate::model::Provenance::Created,
        }
    }

    fn managed(name: &str, uid: u32, shell: &str, groups: &[&str], v: u32) -> ManagedAccount {
        ManagedAccount {
            name: name.to_owned(),
            uid,
            shell: shell.to_owned(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            sudo_role: None,
            sudo_commands: Vec::new(),
            file_grants: Vec::new(),
            provenance: crate::model::Provenance::Created,
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
        let st = state_of(vec![managed(
            "oper",
            9010,
            "/bin/bash",
            &["docker", "wheel"],
            3,
        )]);
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
        assert_eq!(
            plan.actions,
            vec![Action::Delete {
                name: "oper".into()
            }]
        );
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
        assert_eq!(
            plan.actions.len(),
            1,
            "sudo revocation must produce one action"
        );
        match &plan.actions[0] {
            Action::Update { changes, .. } => {
                assert_eq!(changes.len(), 1, "only the sudo field should differ");
                assert!(
                    changes[0].contains("sudo"),
                    "change must mention sudo: {changes:?}"
                );
            }
            other => panic!("expected Update, got {other:?}"),
        }
    }

    #[test]
    fn sudo_grant_yields_update_even_with_no_other_change() {
        // Reverse: managed has no sudo, target gains it.
        let targets = vec![target_sudo(
            "oper",
            9010,
            "/bin/bash",
            &["wheel"],
            Some("ops"),
        )];
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
                assert!(
                    changes[0].contains("sudo"),
                    "change must mention sudo: {changes:?}"
                );
            }
            other => panic!("expected Update, got {other:?}"),
        }
    }

    #[test]
    fn identical_sudo_role_is_idempotent() {
        let targets = vec![target_sudo(
            "oper",
            9010,
            "/bin/bash",
            &["wheel"],
            Some("ops"),
        )];
        let st = state_of(vec![managed_sudo(
            "oper",
            9010,
            "/bin/bash",
            &["wheel"],
            Some("ops"),
            3,
        )]);
        let plan = diff(&targets, &st);
        assert!(
            plan.is_empty(),
            "identical sudo_role must produce no actions"
        );
    }

    #[test]
    fn sudo_commands_change_yields_update() {
        // Same account otherwise; the permission set expanded a different sudo
        // command set → must be an Update with a change line mentioning it.
        let mut t = target("oper", 9010, "/bin/bash", &["wheel"]);
        t.sudo_commands = vec!["/usr/sbin/ip".into(), "/usr/bin/nmcli".into()];
        let mut m = managed("oper", 9010, "/bin/bash", &["wheel"], 3);
        m.sudo_commands = vec!["/usr/sbin/ip".into()];
        let plan = diff(&[t], &state_of(vec![m]));
        assert_eq!(plan.actions.len(), 1);
        match &plan.actions[0] {
            Action::Update { changes, .. } => {
                assert_eq!(changes.len(), 1, "only sudo-commands should differ");
                assert!(
                    changes[0].contains("sudo-commands"),
                    "change must mention sudo-commands: {changes:?}"
                );
            }
            other => panic!("expected Update, got {other:?}"),
        }
    }

    #[test]
    fn identical_sudo_commands_order_insensitive_is_idempotent() {
        // Same command set in a different order must NOT produce an action.
        let mut t = target("oper", 9010, "/bin/bash", &["wheel"]);
        t.sudo_commands = vec!["/usr/sbin/ip".into(), "/usr/bin/nmcli".into()];
        let mut m = managed("oper", 9010, "/bin/bash", &["wheel"], 3);
        m.sudo_commands = vec!["/usr/bin/nmcli".into(), "/usr/sbin/ip".into()];
        let plan = diff(&[t], &state_of(vec![m]));
        assert!(
            plan.is_empty(),
            "same command set in different order is in sync"
        );
    }

    // ---- file-grant diff ----

    use crate::catalog::{Access, ResolvedFileGrant, Shape, SourcedFileGrant};

    fn rgrant(path: &str, access: Access, recursive: bool) -> ResolvedFileGrant {
        ResolvedFileGrant {
            path: path.to_owned(),
            access,
            recursive,
            shape: if recursive { Shape::Dir } else { Shape::File },
            sources: vec![SourcedFileGrant {
                layer: "linux".to_owned(),
                via: None,
            }],
        }
    }

    fn mgrant(path: &str, access: Access, recursive: bool) -> ManagedFileGrant {
        ManagedFileGrant {
            path: path.to_owned(),
            access,
            recursive,
        }
    }

    #[test]
    fn file_grant_change_yields_update() {
        // Managed records a ro grant; the target widens it to rw → must Update
        // with a change line mentioning file-grants.
        let mut t = target("oper", 9010, "/bin/bash", &["wheel"]);
        t.file_grants = vec![rgrant("/etc/ssh", Access::Rw, true)];
        let mut m = managed("oper", 9010, "/bin/bash", &["wheel"], 3);
        m.file_grants = vec![mgrant("/etc/ssh", Access::Ro, true)];
        let plan = diff(&[t], &state_of(vec![m]));
        assert_eq!(plan.actions.len(), 1);
        match &plan.actions[0] {
            Action::Update { changes, .. } => {
                assert_eq!(changes.len(), 1, "only file-grants should differ");
                assert!(
                    changes[0].contains("file-grants"),
                    "change must mention file-grants: {changes:?}"
                );
            }
            other => panic!("expected Update, got {other:?}"),
        }
    }

    #[test]
    fn file_grant_removal_yields_update() {
        // Target drops a grant the registry still records → must Update so the
        // backend revokes it (no stale ACL leak).
        let t = target("oper", 9010, "/bin/bash", &["wheel"]); // no grants
        let mut m = managed("oper", 9010, "/bin/bash", &["wheel"], 3);
        m.file_grants = vec![mgrant("/etc/ssh", Access::Rw, true)];
        let plan = diff(&[t], &state_of(vec![m]));
        assert_eq!(plan.actions.len(), 1);
        match &plan.actions[0] {
            Action::Update { changes, .. } => {
                assert!(
                    changes[0].contains("file-grants"),
                    "removal must mention file-grants: {changes:?}"
                );
            }
            other => panic!("expected Update, got {other:?}"),
        }
    }

    #[test]
    fn identical_file_grants_order_insensitive_is_idempotent() {
        // Same grant set in a different order must NOT produce an action.
        let mut t = target("oper", 9010, "/bin/bash", &["wheel"]);
        t.file_grants = vec![
            rgrant("/etc/ssh", Access::Rw, true),
            rgrant("/etc/pam.d", Access::Ro, true),
        ];
        let mut m = managed("oper", 9010, "/bin/bash", &["wheel"], 3);
        m.file_grants = vec![
            mgrant("/etc/pam.d", Access::Ro, true),
            mgrant("/etc/ssh", Access::Rw, true),
        ];
        let plan = diff(&[t], &state_of(vec![m]));
        assert!(
            plan.is_empty(),
            "same grant set in different order is in sync"
        );
    }

    // ---- group diff ----

    fn req(pairs: &[(&str, Option<u32>)]) -> BTreeMap<String, Option<u32>> {
        pairs.iter().map(|(n, g)| (n.to_string(), *g)).collect()
    }

    fn mgroup(name: &str, gid: u32) -> ManagedGroup {
        ManagedGroup {
            name: name.to_owned(),
            gid: Some(gid),
            provenance: crate::model::Provenance::Created,
            members_added: Vec::new(),
            sudo_commands: Vec::new(),
            file_grants: Vec::new(),
            adopt_baseline: None,
            from_version: 1,
        }
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
        assert_eq!(
            actions,
            vec![GroupAction::Create {
                name: "tellers".into(),
                gid: None
            }]
        );
    }

    #[test]
    fn group_skip_foreign_existing() {
        // required wheel, already present in system but NOT in registry → SKIP.
        let required = req(&[("wheel", None)]);
        let live = live_groups(&[("wheel", 10)]);
        let actions = diff_groups(&required, &BTreeMap::new(), &live, &no_owners()).unwrap();
        assert!(
            actions.is_empty(),
            "foreign existing group must not be created or adopted"
        );
    }

    #[test]
    fn group_delete_orphan_in_registry() {
        // Registry owns atm-operators; no longer required → Delete.
        let required = req(&[]);
        let registry = managed_groups(&[mgroup("atm-operators", 8010)]);
        let live = live_groups(&[("atm-operators", 8010)]);
        let actions = diff_groups(&required, &registry, &live, &no_owners()).unwrap();
        assert_eq!(
            actions,
            vec![GroupAction::Delete {
                name: "atm-operators".into()
            }]
        );
        assert!(actions[0].is_destructive());
    }

    #[test]
    fn group_in_registry_still_required_no_action() {
        let required = req(&[("atm-operators", Some(8010))]);
        let registry = managed_groups(&[mgroup("atm-operators", 8010)]);
        let live = live_groups(&[("atm-operators", 8010)]);
        let actions = diff_groups(&required, &registry, &live, &no_owners()).unwrap();
        assert!(
            actions.is_empty(),
            "still-required managed group needs no action"
        );
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
            GroupPlanError::PinnedGidMismatch {
                live: 9999,
                pinned: 8010,
                ..
            }
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
            GroupPlanError::ManagedGidDrift {
                live: 8099,
                recorded: 8010,
                ..
            }
        ));
    }

    #[test]
    fn diff_groups_does_not_delete_adopted_orphan() {
        // The existence-authority path must NEVER groupdel an Adopted group: its
        // teardown is a grant-release on the resolved path, not a delete. Only a
        // Created orphan is deleted here.
        let required = req(&[]);
        let mut adopted = mgroup("wheel", 10);
        adopted.provenance = Provenance::Adopted;
        let registry = managed_groups(&[adopted, mgroup("z-created", 8099)]);
        let live = live_groups(&[("wheel", 10), ("z-created", 8099)]);
        let actions = diff_groups(&required, &registry, &live, &no_owners()).unwrap();
        // Only the Created orphan is deleted; the Adopted one is left untouched.
        assert_eq!(
            actions,
            vec![GroupAction::Delete {
                name: "z-created".into()
            }]
        );
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

    // ---- resolved-group diff (declaration-driven, provenance-aware) ----

    /// A resolved target group: provenance Created with the given pinned GID,
    /// empty grants/members. Mutated by the tests that need grants.
    fn rgroup(name: &str, gid: Option<u32>, provenance: crate::model::Provenance) -> ResolvedGroup {
        ResolvedGroup {
            name: name.to_owned(),
            gid,
            provenance,
            members: Vec::new(),
            sudo_commands: Vec::new(),
            file_grants: Vec::new(),
            limits: crate::rolestore::Limits::default(),
            bound_roles: Vec::new(),
        }
    }

    #[test]
    fn resolved_created_group_absent_yields_create() {
        let targets = vec![rgroup("atm-operators", Some(8010), Provenance::Created)];
        let actions = diff_resolved_groups(&targets, &BTreeMap::new());
        assert_eq!(
            actions,
            vec![GroupAction::Create {
                name: "atm-operators".into(),
                gid: Some(8010)
            }]
        );
    }

    #[test]
    fn resolved_adopted_group_absent_yields_adopt() {
        // An adopted group not yet in the registry → Adopt (not Create), gid is
        // observed at apply so the pin is irrelevant here.
        let targets = vec![rgroup("wheel", None, Provenance::Adopted)];
        let actions = diff_resolved_groups(&targets, &BTreeMap::new());
        assert_eq!(
            actions,
            vec![GroupAction::Adopt {
                name: "wheel".into()
            }]
        );
        assert!(!actions[0].is_destructive(), "adopt is never destructive");
    }

    #[test]
    fn managed_created_group_undeclared_yields_delete() {
        let registry = managed_groups(&[mgroup("atm-operators", 8010)]); // Created
        let actions = diff_resolved_groups(&[], &registry);
        assert_eq!(
            actions,
            vec![GroupAction::Delete {
                name: "atm-operators".into()
            }]
        );
        assert!(actions[0].is_destructive());
    }

    #[test]
    fn managed_adopted_group_undeclared_yields_release_not_delete() {
        // KEY invariant: the trigger is the SAVED provenance, not the declaration
        // shape. A managed Adopted group that vanished must Release, never Delete.
        let mut g = mgroup("wheel", 10);
        g.provenance = Provenance::Adopted;
        let registry = managed_groups(&[g]);
        let actions = diff_resolved_groups(&[], &registry);
        assert_eq!(
            actions,
            vec![GroupAction::Release {
                name: "wheel".into()
            }]
        );
        assert!(
            !actions[0].is_destructive(),
            "release must never be destructive"
        );
    }

    #[test]
    fn resolved_group_sudo_commands_drift_yields_update() {
        let mut t = rgroup("ops", Some(8020), Provenance::Created);
        t.sudo_commands = vec!["/usr/sbin/ip".into(), "/usr/bin/nmcli".into()];
        let mut m = mgroup("ops", 8020);
        m.sudo_commands = vec!["/usr/sbin/ip".into()];
        let registry = managed_groups(&[m]);
        let actions = diff_resolved_groups(&[t], &registry);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            GroupAction::Update { name, changes } => {
                assert_eq!(name, "ops");
                assert_eq!(
                    changes.len(),
                    1,
                    "only sudo-commands should differ: {changes:?}"
                );
                assert!(changes[0].contains("sudo-commands"), "{changes:?}");
            }
            other => panic!("expected Update, got {other:?}"),
        }
    }

    #[test]
    fn resolved_group_file_grants_drift_yields_update() {
        let mut t = rgroup("ops", Some(8020), Provenance::Created);
        t.file_grants = vec![rgrant("/etc/net", Access::Rw, true)];
        let mut m = mgroup("ops", 8020);
        m.file_grants = vec![mgrant("/etc/net", Access::Ro, true)];
        let registry = managed_groups(&[m]);
        let actions = diff_resolved_groups(&[t], &registry);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            GroupAction::Update { changes, .. } => {
                assert_eq!(
                    changes.len(),
                    1,
                    "only file-grants should differ: {changes:?}"
                );
                assert!(changes[0].contains("file-grants"), "{changes:?}");
            }
            other => panic!("expected Update, got {other:?}"),
        }
    }

    #[test]
    fn resolved_group_members_drift_against_members_added_yields_update() {
        // target.members differs from current.members_added (what Census added) →
        // Update. Foreign/baseline members are not part of this comparison.
        let mut t = rgroup("ops", Some(8020), Provenance::Created);
        t.members = vec!["netops".into(), "dbops".into()];
        let mut m = mgroup("ops", 8020);
        m.members_added = vec!["netops".into()];
        let registry = managed_groups(&[m]);
        let actions = diff_resolved_groups(&[t], &registry);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            GroupAction::Update { changes, .. } => {
                assert_eq!(changes.len(), 1, "only members should differ: {changes:?}");
                assert!(changes[0].contains("members"), "{changes:?}");
            }
            other => panic!("expected Update, got {other:?}"),
        }
    }

    #[test]
    fn resolved_group_fully_in_sync_yields_no_action() {
        // Every materialized field matches (order-insensitive) → no action.
        let mut t = rgroup("ops", Some(8020), Provenance::Created);
        t.sudo_commands = vec!["/usr/sbin/ip".into(), "/usr/bin/nmcli".into()];
        t.file_grants = vec![rgrant("/etc/net", Access::Rw, true)];
        t.members = vec!["dbops".into(), "netops".into()];
        let mut m = mgroup("ops", 8020);
        // Different ORDER on every set — must still be in sync.
        m.sudo_commands = vec!["/usr/bin/nmcli".into(), "/usr/sbin/ip".into()];
        m.file_grants = vec![mgrant("/etc/net", Access::Rw, true)];
        m.members_added = vec!["netops".into(), "dbops".into()];
        let registry = managed_groups(&[m]);
        let actions = diff_resolved_groups(&[t], &registry);
        assert!(
            actions.is_empty(),
            "fully-synced group must produce no action: {actions:?}"
        );
    }

    #[test]
    fn resolved_groups_ordering_is_deterministic() {
        // Targets in a fixed slice order: one update, one adopt, one create.
        // Managed-only groups (a Created and an Adopted) trail after, in BTreeMap
        // (sorted) order → Delete before Release because "z-created" > "a-...".
        let mut upd = rgroup("ops", Some(8020), Provenance::Created);
        upd.sudo_commands = vec!["/usr/sbin/ip".into()];
        let targets = vec![
            upd,                                                // -> Update (ops)
            rgroup("wheel", None, Provenance::Adopted),         // -> Adopt (wheel)
            rgroup("new-grp", Some(8030), Provenance::Created), // -> Create
        ];
        let mut adopted_orphan = mgroup("a-orphan", 11);
        adopted_orphan.provenance = Provenance::Adopted;
        let registry = managed_groups(&[
            mgroup("ops", 8020),      // declared → update target above
            adopted_orphan,           // undeclared Adopted → Release
            mgroup("z-orphan", 8099), // undeclared Created → Delete
        ]);
        let actions = diff_resolved_groups(&targets, &registry);
        // Head: targets order → Update(ops), Adopt(wheel), Create(new-grp).
        assert!(matches!(&actions[0], GroupAction::Update { name, .. } if name == "ops"));
        assert!(matches!(&actions[1], GroupAction::Adopt { name } if name == "wheel"));
        assert!(matches!(&actions[2], GroupAction::Create { name, .. } if name == "new-grp"));
        // Tail: managed-only in BTreeMap order → "a-orphan" (Release) then
        // "z-orphan" (Delete).
        assert_eq!(
            actions[3],
            GroupAction::Release {
                name: "a-orphan".into()
            }
        );
        assert_eq!(
            actions[4],
            GroupAction::Delete {
                name: "z-orphan".into()
            }
        );
        assert_eq!(actions.len(), 5);
        // Re-running on the same inputs is byte-identical (determinism).
        assert_eq!(diff_resolved_groups(&targets, &registry), actions);
    }
}
