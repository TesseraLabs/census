//! Read-only diagnostics for `census doctor` (spec §4, §7, §8).
//!
//! Doctor reconciles the managed *registry* against the *live* system (via
//! [`crate::inspect::SystemInspector`]) and reports invariant violations as
//! [`Finding`]s. It performs ZERO mutations — degradation is detected here and
//! repaired by `apply`.
//!
//! Severity:
//! - [`Severity::Error`] — a security invariant is broken (§8 unreachability, §4 registry
//!   integrity). `census doctor` exits non-zero.
//! - [`Severity::Warn`] — advisory (potential lockout §7, drift). Printed but does not fail the
//!   exit code.

use std::collections::BTreeSet;

use crate::inspect::SystemInspector;
use crate::model::ResolvedAccount;
use crate::plan;
use crate::state::SystemState;

/// Severity of a doctor finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Broken security invariant — fails the doctor exit code.
    Error,
    /// Advisory — printed but does not fail the exit code.
    Warn,
}

impl Severity {
    /// Short uppercase tag for rendering.
    pub fn tag(self) -> &'static str {
        match self {
            Severity::Error => "ERROR",
            Severity::Warn => "WARN",
        }
    }
}

/// A single diagnostic finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// How severe the finding is.
    pub severity: Severity,
    /// Stable check identifier (e.g. `"registry-integrity"`).
    pub check: &'static str,
    /// The account/object the finding concerns.
    pub target: String,
    /// Human-readable explanation.
    pub message: String,
}

/// The full set of findings from one doctor run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DoctorReport {
    /// All findings, in check order.
    pub findings: Vec<Finding>,
}

impl DoctorReport {
    /// True if any finding is an [`Severity::Error`] — caller exits non-zero.
    pub fn has_errors(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Error)
    }
}

/// Check identifiers (stable strings for output / tests / monitoring).
const CHECK_REGISTRY: &str = "registry-integrity";
const CHECK_GROUP_REGISTRY: &str = "group-registry-integrity";
const CHECK_UNREACHABLE: &str = "unreachability";
const CHECK_ANTILOCKOUT: &str = "anti-lockout";
/// Emitted when the shadow database cannot be read at all (a non-root run): we
/// cannot evaluate password-lock state, so the §8 unreachability and §7
/// anti-lockout checks degrade to this single advisory rather than firing a false
/// "password unlocked" Error or a false "no rescue" Warn for every account.
const CHECK_SHADOW_UNREADABLE: &str = "shadow-unreadable";
const CHECK_DRIFT: &str = "drift";
const CHECK_FILE_ACCESS_DRIFT: &str = "file-access-drift";
const CHECK_ADOPTED_GROUP_DRIFT: &str = "adopted-group-drift";
const CHECK_FRAMEWORK_INTEGRITY: &str = "framework-integrity";

/// Run all read-only doctor checks. `managed` is the registry-authoritative
/// state; `inspector` reads the live system; `targets` (if given) is the
/// resolved declaration used only for the drift check.
pub fn run_doctor(
    managed: &dyn SystemState,
    inspector: &dyn SystemInspector,
    targets: Option<&[ResolvedAccount]>,
) -> DoctorReport {
    let mut findings = Vec::new();
    let registry = managed.managed_accounts();
    let managed_names: BTreeSet<String> = registry.keys().cloned().collect();

    // Fetch each registry account's live facts ONCE and share them across the §4
    // and §8 loops. This avoids a second `getent passwd` per account and removes a
    // TOCTOU window where the account could change between the two checks.
    let account_facts: std::collections::BTreeMap<&String, Option<crate::inspect::AccountFacts>> =
        registry
            .keys()
            .map(|name| (name, inspector.account(name)))
            .collect();

    // Read the WHOLE shadow database once. `None` means it could not be read at
    // all (non-root) — a degraded read the §8 / §7 checks handle distinctly,
    // rather than spawning `getent shadow` per account and mistaking the failure
    // for "every account is unlocked / no rescue".
    let shadow_locks = inspector.shadow_locks();

    // --- §4 registry integrity (Error) ---
    for (name, record) in &registry {
        match account_facts.get(name).and_then(Option::as_ref) {
            None => findings.push(Finding {
                severity: Severity::Error,
                check: CHECK_REGISTRY,
                target: name.clone(),
                message: "registry entry has no live account (managed object vanished)".to_owned(),
            }),
            Some(facts) => {
                let mut diffs = Vec::new();
                if facts.uid != record.uid {
                    diffs.push(format!("uid {} != registry {}", facts.uid, record.uid));
                }
                if facts.shell != record.shell {
                    diffs.push(format!(
                        "shell {:?} != registry {:?}",
                        facts.shell, record.shell
                    ));
                }
                // Set-equal (order-insensitive). Compare sorted borrowed `&str`:
                // no group String is cloned, only two pointer vectors are sorted.
                let groups_differ = facts.groups.len() != record.groups.len() || {
                    let mut live_groups: Vec<&str> =
                        facts.groups.iter().map(String::as_str).collect();
                    let mut reg_groups: Vec<&str> =
                        record.groups.iter().map(String::as_str).collect();
                    live_groups.sort_unstable();
                    reg_groups.sort_unstable();
                    live_groups != reg_groups
                };
                if groups_differ {
                    diffs.push(format!(
                        "groups {:?} != registry {:?}",
                        facts.groups, record.groups
                    ));
                }
                if !diffs.is_empty() {
                    findings.push(Finding {
                        severity: Severity::Error,
                        check: CHECK_REGISTRY,
                        target: name.clone(),
                        message: format!(
                            "live account differs from registry: {}",
                            diffs.join("; ")
                        ),
                    });
                }
            }
        }
    }

    // Live census-marked account NOT in the registry → possible spoof. The
    // registry is authoritative (§4), not the GECOS marker.
    for marked in inspector.census_marked_accounts() {
        if !managed_names.contains(&marked) {
            findings.push(Finding {
                severity: Severity::Error,
                check: CHECK_REGISTRY,
                target: marked.clone(),
                message: "account carries a Census GECOS marker but is not in the registry \
                          (possible spoof; registry is authoritative)"
                    .to_owned(),
            });
        }
    }

    // --- §4 managed-group integrity (Error) ---
    // A Census-owned group recorded in the registry must still exist live, with
    // the recorded GID. A vanished managed group or a GID that drifted from the
    // record is a broken invariant (Census never renumbers on the fly).
    for (name, record) in &managed.managed_groups() {
        match inspector.group(name) {
            None => findings.push(Finding {
                severity: Severity::Error,
                check: CHECK_GROUP_REGISTRY,
                target: name.clone(),
                message: "registry group has no live group (managed group vanished)".to_owned(),
            }),
            Some(facts) => {
                // GID drift is a hard integrity Error only for a Created group:
                // Census assigned that GID, so a renumber out of band breaks the
                // invariant. An Adopted group's GID was observed, not assigned, so
                // its drift is advisory and handled below against the baseline as a
                // Warn — never double-reported here.
                // Compare only when the registry recorded a concrete GID. A `None`
                // (GID unknown at apply time) is not drift — there is nothing to
                // diverge from — so it is skipped rather than flagged.
                if let Some(recorded_gid) = record.gid {
                    if facts.gid != recorded_gid
                        && record.provenance == crate::model::Provenance::Created
                    {
                        findings.push(Finding {
                            severity: Severity::Error,
                            check: CHECK_GROUP_REGISTRY,
                            target: name.clone(),
                            message: format!(
                                "live gid {} != registry gid {recorded_gid} (managed group renumbered out of band)",
                                facts.gid
                            ),
                        });
                    }
                }
            }
        }
    }

    // --- adopted-group baseline drift (Warn) ---
    // For an Adopted group with a recorded baseline, advisory checks against the
    // live system: a GID that diverged from the adopt-time baseline, our own
    // `census-grp-<group>` sudoers fragment removed out of band while the registry
    // still records group sudo commands, or a Census-added member that is no
    // longer in the live group. All advisory (re-apply repairs) — never an Error:
    // a released/altered adopted object is drift, not a broken security invariant.
    for (name, record) in &managed.managed_groups() {
        if record.provenance != crate::model::Provenance::Adopted {
            continue;
        }
        let Some(baseline) = &record.adopt_baseline else {
            continue;
        };

        // GID drift vs the adopt-time baseline. Skip when the baseline GID is
        // unknown (`None`) — Census never recorded a GID to drift against, so
        // there is nothing to compare and a `None` must not be read as `0`.
        if let (Some(facts), Some(baseline_gid)) = (inspector.group(name), baseline.gid) {
            if facts.gid != baseline_gid {
                findings.push(Finding {
                    severity: Severity::Warn,
                    check: CHECK_ADOPTED_GROUP_DRIFT,
                    target: name.clone(),
                    message: format!(
                        "live gid {} != adopt baseline gid {baseline_gid} (adopted group renumbered out of band)",
                        facts.gid
                    ),
                });
            }
        }

        // Our sudoers fragment removed while the registry still records group sudo
        // commands. Best-effort: only a positive `Some(false)` is a finding.
        if !record.sudo_commands.is_empty()
            && inspector.group_sudoers_fragment_present(name) == Some(false)
        {
            findings.push(Finding {
                severity: Severity::Warn,
                check: CHECK_ADOPTED_GROUP_DRIFT,
                target: name.clone(),
                message: format!(
                    "census-grp-{name} sudoers fragment is gone but the registry records \
                     group sudo commands (drift; re-apply to repair)"
                ),
            });
        }

        // A member Census added to the adopted group is no longer in the live
        // group's member list. Best-effort: when the inspector reports no members
        // at all (default-impl / unreadable) we make no claim. We only flag a
        // member that is genuinely absent from a non-empty live list.
        let live_members = inspector.group_members(name);
        if !live_members.is_empty() {
            for added in &record.members_added {
                if !live_members.iter().any(|m| m == added) {
                    findings.push(Finding {
                        severity: Severity::Warn,
                        check: CHECK_ADOPTED_GROUP_DRIFT,
                        target: name.clone(),
                        message: format!(
                            "census-added member {added} is no longer in adopted group {name} \
                             (drift; re-apply to repair)"
                        ),
                    });
                }
            }
        }
    }

    // --- file-access drift (Warn) ---
    // For each managed file grant, check via the live system whether the account
    // still has its ACL entry on the path. A missing entry is drift (the grant was
    // recorded but the ACL is gone — manual edit, restore, rotation that dropped
    // it), repaired by a re-apply. Best-effort and READ-ONLY: the inspector shells
    // out to `getfacl` (argv-only, no mutation), and an indeterminate result
    // (`None` — no getfacl, path absent) is NOT a finding (we never claim drift we
    // could not verify). Like resource-map drift, this is a Warn, never an Error.
    for (name, record) in &registry {
        for grant in &record.file_grants {
            if inspector.file_access_present(&grant.path, name) == Some(false) {
                findings.push(Finding {
                    severity: Severity::Warn,
                    check: CHECK_FILE_ACCESS_DRIFT,
                    target: name.clone(),
                    message: format!(
                        "managed file grant on {} has no live ACL entry for the account \
                         (drift; re-apply to repair)",
                        grant.path
                    ),
                });
            }
        }
    }

    // The whole shadow database was unreadable (non-root). Emit ONE advisory and
    // skip every per-account password verdict below: a degraded read is "cannot
    // evaluate", not a fleet of false "shadow entry absent" Errors. The §7
    // anti-lockout check is likewise degraded (see below).
    let shadow_degraded = shadow_locks.is_none();
    if shadow_degraded && !registry.is_empty() {
        findings.push(Finding {
            severity: Severity::Warn,
            check: CHECK_SHADOW_UNREADABLE,
            target: "<system>".to_owned(),
            message: "shadow database is unreadable (run as root to evaluate password-lock \
                      state); cannot confirm §8 unreachability for managed accounts"
                .to_owned(),
        });
    }

    // --- §8 unreachability (Error) ---
    for (name, record) in &registry {
        match account_facts.get(name).and_then(Option::as_ref) {
            None => findings.push(Finding {
                severity: Severity::Error,
                check: CHECK_UNREACHABLE,
                target: name.clone(),
                message: "managed role account is missing (cannot verify unreachability)"
                    .to_owned(),
            }),
            Some(facts) => {
                let _ = record; // registry record not needed here; live facts authoritative
                                // Use the batched shadow read. When shadow is readable, an account
                                // present-and-unlocked is a §8 Error and an account ABSENT from the
                                // map genuinely has no shadow row (still an Error — we read shadow
                                // and the row is missing). When shadow is degraded we emitted the
                                // single advisory above and make no per-account password claim.
                if let Some(locks) = &shadow_locks {
                    match locks.get(name).copied() {
                        Some(true) => {}
                        Some(false) => findings.push(Finding {
                            severity: Severity::Error,
                            check: CHECK_UNREACHABLE,
                            target: name.clone(),
                            message:
                                "password is NOT locked (role account must be unreachable, §8)"
                                    .to_owned(),
                        }),
                        None => findings.push(Finding {
                            severity: Severity::Error,
                            check: CHECK_UNREACHABLE,
                            target: name.clone(),
                            message: "shadow entry is absent; cannot confirm password lock"
                                .to_owned(),
                        }),
                    }
                }
                // authorized_keys would be an alternative login path (§8). Use the
                // live home (passwd field 6); the registry does not record home.
                // Independent of shadow readability.
                if inspector.has_authorized_keys(name, &facts.home) {
                    findings.push(Finding {
                        severity: Severity::Error,
                        check: CHECK_UNREACHABLE,
                        target: name.clone(),
                        message: "~/.ssh/authorized_keys present (alternative login path, §8)"
                            .to_owned(),
                    });
                }
            }
        }
    }

    // --- §7 anti-lockout (Warn) ---
    if shadow_degraded {
        // We cannot evaluate which non-managed accounts can authenticate (their
        // password state is unknown), so a "no rescue" Warn would be a false
        // positive on every non-root run. Emit the distinct cannot-evaluate
        // advisory instead — but only when we did not already emit it above for an
        // empty registry's sake.
        if registry.is_empty() {
            findings.push(Finding {
                severity: Severity::Warn,
                check: CHECK_SHADOW_UNREADABLE,
                target: "<system>".to_owned(),
                message: "shadow database is unreadable (run as root to evaluate password-lock \
                          state); cannot evaluate the §7 anti-lockout rescue set"
                    .to_owned(),
            });
        }
    } else if inspector
        .login_capable_non_managed(&managed_names)
        .is_empty()
    {
        findings.push(Finding {
            severity: Severity::Warn,
            check: CHECK_ANTILOCKOUT,
            target: "<system>".to_owned(),
            message: "no login-capable account outside the managed set \
                      (potential lockout if the cert path fails, §7)"
                .to_owned(),
        });
    }

    // --- drift (Warn) ---
    if let Some(targets) = targets {
        let p = plan::diff(targets, managed);
        if !p.is_empty() {
            let (mut creates, mut updates, mut deletes) = (0usize, 0usize, 0usize);
            for a in &p.actions {
                match a {
                    plan::Action::Create(_) => creates += 1,
                    plan::Action::Update { .. } => updates += 1,
                    plan::Action::Delete { .. } => deletes += 1,
                }
            }
            findings.push(Finding {
                severity: Severity::Warn,
                check: CHECK_DRIFT,
                target: "<declaration>".to_owned(),
                message: format!(
                    "declaration drift: {creates} create(s), {updates} update(s), {deletes} delete(s)"
                ),
            });
        }
    }

    DoctorReport { findings }
}

/// Map framework cross-reference lint findings into doctor [`Finding`]s, ALWAYS as
/// [`Severity::Warn`]. The framework layer is advisory (it can never widen/break a
/// grant), so its integrity problems — orphaned mapping, provides/files desync,
/// unknown dimension, even an id collision — are surfaced as warnings that never
/// fail the doctor exit code. Gap coverage is intentionally NOT computed here (it
/// stays in `census framework coverage`).
pub fn framework_findings(lints: &[crate::framework::FrameworkLint]) -> Vec<Finding> {
    lints
        .iter()
        .map(|l| Finding {
            severity: Severity::Warn,
            check: CHECK_FRAMEWORK_INTEGRITY,
            target: "<framework>".to_owned(),
            message: format!("[{}] {}", l.code, l.message),
        })
        .collect()
}

/// Map a loader forward-compat warning string (unknown dimension / unknown provides
/// tag — the skips `load_frameworks` records) into a doctor Warn finding.
pub fn framework_load_warning(message: &str) -> Finding {
    Finding {
        severity: Severity::Warn,
        check: CHECK_FRAMEWORK_INTEGRITY,
        target: "<framework>".to_owned(),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::inspect::{AccountFacts, FakeInspector};
    use crate::rolestore::Limits;
    use crate::state::{FakeState, ManagedAccount};

    fn managed_acct(name: &str, uid: u32, shell: &str, groups: &[&str]) -> ManagedAccount {
        ManagedAccount {
            name: name.to_owned(),
            uid,
            shell: shell.to_owned(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            sudo_role: None,
            sudo_commands: Vec::new(),
            file_grants: Vec::new(),
            provenance: crate::model::Provenance::Created,
            from_version: 1,
        }
    }

    fn state_of(accts: Vec<ManagedAccount>) -> FakeState {
        FakeState {
            accounts: accts.into_iter().map(|a| (a.name.clone(), a)).collect(),
            ..Default::default()
        }
    }

    fn facts(uid: u32, shell: &str, groups: &[&str]) -> AccountFacts {
        AccountFacts {
            uid,
            shell: shell.to_owned(),
            home: PathBuf::from("/var/lib/census/home/oper"),
            groups: groups.iter().map(|g| g.to_string()).collect(),
        }
    }

    /// Inspector for a single fully-healthy managed account `oper`, plus a
    /// rescue account so anti-lockout does not fire.
    fn healthy_inspector() -> FakeInspector {
        let mut f = FakeInspector::default();
        f.accounts
            .insert("oper".into(), facts(9010, "/bin/bash", &["wheel"]));
        f.locked.insert("oper".into(), true);
        f.login_capable.insert("rescue".into());
        f
    }

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

    #[test]
    fn clean_system_has_no_findings() {
        let st = state_of(vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])]);
        let report = run_doctor(&st, &healthy_inspector(), None);
        assert!(
            report.findings.is_empty(),
            "clean system: {:?}",
            report.findings
        );
        assert!(!report.has_errors());
    }

    // ---- §4 registry integrity ----

    #[test]
    fn registry_entry_without_live_account_is_error() {
        let st = state_of(vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])]);
        let mut insp = FakeInspector::default();
        insp.login_capable.insert("rescue".into()); // suppress anti-lockout
        let report = run_doctor(&st, &insp, None);
        assert!(report.has_errors());
        assert!(report
            .findings
            .iter()
            .any(|f| f.check == CHECK_REGISTRY && f.message.contains("vanished")));
    }

    #[test]
    fn spoofed_gecos_marker_not_in_registry_is_error() {
        let st = state_of(vec![]); // empty registry
        let mut insp = FakeInspector::default();
        insp.marked.push("intruder".into());
        insp.login_capable.insert("rescue".into());
        let report = run_doctor(&st, &insp, None);
        assert!(report.has_errors());
        let f = report
            .findings
            .iter()
            .find(|f| f.check == CHECK_REGISTRY && f.target == "intruder")
            .expect("spoof finding");
        assert!(f.message.contains("spoof"));
    }

    #[test]
    fn marked_account_in_registry_is_not_flagged() {
        let st = state_of(vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])]);
        let mut insp = healthy_inspector();
        insp.marked.push("oper".into()); // marked AND in registry → fine
        let report = run_doctor(&st, &insp, None);
        assert!(!report.has_errors(), "{:?}", report.findings);
    }

    #[test]
    fn uid_mismatch_is_error() {
        let st = state_of(vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])]);
        let mut insp = healthy_inspector();
        insp.accounts
            .insert("oper".into(), facts(9999, "/bin/bash", &["wheel"]));
        let report = run_doctor(&st, &insp, None);
        assert!(report.has_errors());
        assert!(report
            .findings
            .iter()
            .any(|f| f.check == CHECK_REGISTRY && f.message.contains("uid")));
    }

    #[test]
    fn shell_and_group_drift_is_error() {
        let st = state_of(vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])]);
        let mut insp = healthy_inspector();
        insp.accounts
            .insert("oper".into(), facts(9010, "/bin/zsh", &["wheel", "docker"]));
        let report = run_doctor(&st, &insp, None);
        let f = report
            .findings
            .iter()
            .find(|f| f.check == CHECK_REGISTRY && f.target == "oper")
            .expect("drift finding");
        assert!(f.message.contains("shell"));
        assert!(f.message.contains("groups"));
    }

    #[test]
    fn group_order_does_not_trigger_registry_drift() {
        let st = state_of(vec![managed_acct(
            "oper",
            9010,
            "/bin/bash",
            &["wheel", "docker"],
        )]);
        let mut insp = healthy_inspector();
        insp.accounts.insert(
            "oper".into(),
            facts(9010, "/bin/bash", &["docker", "wheel"]),
        );
        let report = run_doctor(&st, &insp, None);
        assert!(
            !report.findings.iter().any(|f| f.check == CHECK_REGISTRY),
            "group order must not be a diff: {:?}",
            report.findings
        );
    }

    // ---- §4 managed-group integrity ----

    use crate::inspect::GroupFacts;
    use crate::state::ManagedGroup;

    fn state_with_group(accts: Vec<ManagedAccount>, groups: Vec<ManagedGroup>) -> FakeState {
        FakeState {
            accounts: accts.into_iter().map(|a| (a.name.clone(), a)).collect(),
            groups: groups.into_iter().map(|g| (g.name.clone(), g)).collect(),
        }
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

    #[test]
    fn managed_group_present_and_matching_is_clean() {
        let st = state_with_group(
            vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])],
            vec![mgroup("atm-operators", 8010)],
        );
        let mut insp = healthy_inspector();
        insp.groups
            .insert("atm-operators".into(), GroupFacts { gid: 8010 });
        let report = run_doctor(&st, &insp, None);
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.check == CHECK_GROUP_REGISTRY),
            "matching managed group must be clean: {:?}",
            report.findings
        );
    }

    #[test]
    fn managed_group_missing_from_system_is_error() {
        let st = state_with_group(
            vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])],
            vec![mgroup("atm-operators", 8010)],
        );
        // Inspector has NO atm-operators group → vanished.
        let insp = healthy_inspector();
        let report = run_doctor(&st, &insp, None);
        assert!(report.has_errors());
        let f = report
            .findings
            .iter()
            .find(|f| f.check == CHECK_GROUP_REGISTRY && f.target == "atm-operators")
            .expect("vanished group finding");
        assert!(f.message.contains("vanished"));
    }

    #[test]
    fn managed_group_gid_drift_is_error() {
        let st = state_with_group(
            vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])],
            vec![mgroup("atm-operators", 8010)],
        );
        let mut insp = healthy_inspector();
        insp.groups
            .insert("atm-operators".into(), GroupFacts { gid: 8099 });
        let report = run_doctor(&st, &insp, None);
        assert!(report.has_errors());
        let f = report
            .findings
            .iter()
            .find(|f| f.check == CHECK_GROUP_REGISTRY && f.target == "atm-operators")
            .expect("gid drift finding");
        assert!(f.message.contains("gid"));
    }

    // ---- adopted-group baseline drift (Warn) ----

    /// An adopted managed group with a recorded baseline and (optionally) our own
    /// grants/members. `record.gid` equals the baseline gid (observed at adopt).
    fn adopted_mgroup(
        name: &str,
        gid: u32,
        baseline_members: &[&str],
        members_added: &[&str],
        sudo_commands: &[&str],
    ) -> ManagedGroup {
        ManagedGroup {
            name: name.to_owned(),
            gid: Some(gid),
            provenance: crate::model::Provenance::Adopted,
            members_added: members_added.iter().map(|m| m.to_string()).collect(),
            sudo_commands: sudo_commands
                .iter()
                .map(|c| crate::model::SudoCommand::root(*c))
                .collect(),
            file_grants: Vec::new(),
            adopt_baseline: Some(crate::state::GroupBaseline {
                gid: Some(gid),
                members: baseline_members.iter().map(|m| m.to_string()).collect(),
            }),
            from_version: 1,
        }
    }

    #[test]
    fn adopted_group_in_sync_has_no_drift_finding() {
        let st = state_with_group(
            vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])],
            vec![adopted_mgroup(
                "wheel",
                10,
                &["root"],
                &["oper"],
                &["/usr/sbin/ip"],
            )],
        );
        let mut insp = healthy_inspector();
        insp.groups.insert("wheel".into(), GroupFacts { gid: 10 });
        insp.group_members
            .insert("wheel".into(), vec!["root".into(), "oper".into()]);
        insp.group_sudoers_fragments.insert("wheel".into(), true);
        let report = run_doctor(&st, &insp, None);
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.check == CHECK_ADOPTED_GROUP_DRIFT),
            "in-sync adopted group must have no drift finding: {:?}",
            report.findings
        );
        // And no false GID Error (the Created-only gid check must not fire here).
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.check == CHECK_GROUP_REGISTRY && f.target == "wheel"),
            "adopted group must not trip the Created gid Error: {:?}",
            report.findings
        );
    }

    #[test]
    fn adopted_group_gid_drift_is_warn_not_error() {
        let st = state_with_group(
            vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])],
            vec![adopted_mgroup("wheel", 10, &["root"], &[], &[])],
        );
        let mut insp = healthy_inspector();
        // Live gid diverged from the adopt baseline (10 → 12).
        insp.groups.insert("wheel".into(), GroupFacts { gid: 12 });
        insp.group_members
            .insert("wheel".into(), vec!["root".into()]);
        let report = run_doctor(&st, &insp, None);
        let f = report
            .findings
            .iter()
            .find(|f| f.check == CHECK_ADOPTED_GROUP_DRIFT && f.target == "wheel")
            .expect("adopted gid drift finding");
        assert_eq!(f.severity, Severity::Warn, "adopted gid drift is advisory");
        assert!(f.message.contains("gid"));
        // It must NOT also be reported as a Created-group integrity Error.
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.check == CHECK_GROUP_REGISTRY
                    && f.target == "wheel"
                    && f.severity == Severity::Error),
            "adopted gid drift must not double-report as a Created Error: {:?}",
            report.findings
        );
    }

    #[test]
    fn adopted_group_missing_fragment_is_warn() {
        let st = state_with_group(
            vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])],
            // Registry records group sudo commands, so a missing fragment is drift.
            vec![adopted_mgroup(
                "wheel",
                10,
                &["root"],
                &[],
                &["/usr/sbin/ip"],
            )],
        );
        let mut insp = healthy_inspector();
        insp.groups.insert("wheel".into(), GroupFacts { gid: 10 });
        insp.group_members
            .insert("wheel".into(), vec!["root".into()]);
        insp.group_sudoers_fragments.insert("wheel".into(), false); // removed out of band
        let report = run_doctor(&st, &insp, None);
        let f = report
            .findings
            .iter()
            .find(|f| f.check == CHECK_ADOPTED_GROUP_DRIFT && f.message.contains("fragment"))
            .expect("missing-fragment drift finding");
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.message.contains("census-grp-wheel"));
    }

    #[test]
    fn adopted_group_dropped_member_is_warn() {
        let st = state_with_group(
            vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])],
            // We added `oper`; baseline (foreign) member is `root`.
            vec![adopted_mgroup("wheel", 10, &["root"], &["oper"], &[])],
        );
        let mut insp = healthy_inspector();
        insp.groups.insert("wheel".into(), GroupFacts { gid: 10 });
        // Live group lists only the foreign member — our `oper` was dropped.
        insp.group_members
            .insert("wheel".into(), vec!["root".into()]);
        let report = run_doctor(&st, &insp, None);
        let f = report
            .findings
            .iter()
            .find(|f| f.check == CHECK_ADOPTED_GROUP_DRIFT && f.message.contains("oper"))
            .expect("dropped-member drift finding");
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.message.contains("no longer in"));
    }

    #[test]
    fn created_group_with_missing_fragment_yields_no_adopted_drift() {
        // The adopted-drift check is scoped to Adopted groups: a Created group
        // (no baseline) must never produce an adopted-drift finding even if its
        // fragment seam reports absent.
        let st = state_with_group(
            vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])],
            vec![mgroup("atm-operators", 8010)],
        );
        let mut insp = healthy_inspector();
        insp.groups
            .insert("atm-operators".into(), GroupFacts { gid: 8010 });
        insp.group_sudoers_fragments
            .insert("atm-operators".into(), false);
        let report = run_doctor(&st, &insp, None);
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.check == CHECK_ADOPTED_GROUP_DRIFT),
            "created group must not produce adopted-drift findings: {:?}",
            report.findings
        );
    }

    // ---- §8 unreachability ----

    #[test]
    fn unlocked_password_is_error() {
        let st = state_of(vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])]);
        let mut insp = healthy_inspector();
        insp.locked.insert("oper".into(), false);
        let report = run_doctor(&st, &insp, None);
        assert!(report.has_errors());
        assert!(report
            .findings
            .iter()
            .any(|f| f.check == CHECK_UNREACHABLE && f.message.contains("NOT locked")));
    }

    #[test]
    fn missing_shadow_entry_is_error() {
        let st = state_of(vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])]);
        let mut insp = healthy_inspector();
        insp.locked.remove("oper"); // no shadow info → None
        let report = run_doctor(&st, &insp, None);
        assert!(report.has_errors());
        assert!(report
            .findings
            .iter()
            .any(|f| f.check == CHECK_UNREACHABLE && f.message.contains("shadow")));
    }

    #[test]
    fn authorized_keys_present_is_error() {
        let st = state_of(vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])]);
        let mut insp = healthy_inspector();
        insp.authorized_keys.insert("oper".into());
        let report = run_doctor(&st, &insp, None);
        assert!(report.has_errors());
        assert!(report
            .findings
            .iter()
            .any(|f| f.check == CHECK_UNREACHABLE && f.message.contains("authorized_keys")));
    }

    #[test]
    fn locked_password_no_keys_is_clean_for_unreachability() {
        let st = state_of(vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])]);
        let report = run_doctor(&st, &healthy_inspector(), None);
        assert!(
            !report.findings.iter().any(|f| f.check == CHECK_UNREACHABLE),
            "{:?}",
            report.findings
        );
    }

    // ---- §7 anti-lockout ----

    #[test]
    fn no_rescue_account_warns_but_no_error() {
        let st = state_of(vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])]);
        let mut insp = healthy_inspector();
        insp.login_capable.clear(); // no rescue at all
        let report = run_doctor(&st, &insp, None);
        assert!(!report.has_errors(), "anti-lockout is a warning only");
        let f = report
            .findings
            .iter()
            .find(|f| f.check == CHECK_ANTILOCKOUT)
            .expect("anti-lockout warning");
        assert_eq!(f.severity, Severity::Warn);
    }

    #[test]
    fn unreadable_shadow_degrades_to_distinct_finding_not_false_warns() {
        // Model a non-root run: shadow is unreadable. The managed account `oper`
        // has a login shell and no authorized_keys. Doctor must NOT fire a false
        // §7 "no rescue" Warn nor a §8 "shadow absent" Error per account; instead
        // it emits the single distinct cannot-evaluate advisory.
        let st = state_of(vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])]);
        let mut insp = FakeInspector::default();
        insp.accounts
            .insert("oper".into(), facts(9010, "/bin/bash", &["wheel"]));
        insp.shadow_unreadable = true; // getent shadow fails (non-root)
                                       // A login-capable account exists but its lock state is unknowable.
        insp.login_capable.insert("rescue".into());

        let report = run_doctor(&st, &insp, None);

        // The distinct degraded finding is present, as a Warn (never an Error).
        let degraded = report
            .findings
            .iter()
            .find(|f| f.check == CHECK_SHADOW_UNREADABLE)
            .expect("degraded shadow-read advisory");
        assert_eq!(degraded.severity, Severity::Warn);

        // No false per-account §8 password Error (we could not evaluate it).
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.check == CHECK_UNREACHABLE && f.message.contains("password")),
            "degraded read must not produce a false password Error: {:?}",
            report.findings
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.check == CHECK_UNREACHABLE && f.message.contains("shadow")),
            "degraded read must not produce a per-account shadow-absent Error: {:?}",
            report.findings
        );

        // And the degraded read must NOT be a hard Error (doctor still exits 0 for
        // this advisory alone — a non-root informational run).
        assert!(
            !report.has_errors(),
            "degraded shadow read alone must not fail the exit code: {:?}",
            report.findings
        );
    }

    #[test]
    fn unreadable_shadow_still_flags_authorized_keys() {
        // authorized_keys detection does not depend on shadow, so a §8 keys Error
        // must still fire even when shadow is unreadable.
        let st = state_of(vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])]);
        let mut insp = FakeInspector::default();
        insp.accounts
            .insert("oper".into(), facts(9010, "/bin/bash", &["wheel"]));
        insp.shadow_unreadable = true;
        insp.authorized_keys.insert("oper".into());
        let report = run_doctor(&st, &insp, None);
        assert!(report
            .findings
            .iter()
            .any(|f| f.check == CHECK_UNREACHABLE && f.message.contains("authorized_keys")));
        assert!(
            report.has_errors(),
            "authorized_keys is a §8 Error regardless of shadow"
        );
    }

    #[test]
    fn rescue_present_no_antilockout_warning() {
        let st = state_of(vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])]);
        let report = run_doctor(&st, &healthy_inspector(), None);
        assert!(!report.findings.iter().any(|f| f.check == CHECK_ANTILOCKOUT));
    }

    // ---- drift ----

    #[test]
    fn drift_against_declaration_warns() {
        // Registry has oper@9010; declaration target wants groups [wheel,docker] → update drift.
        let st = state_of(vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])]);
        let targets = vec![target("oper", 9010, "/bin/bash", &["wheel", "docker"])];
        let report = run_doctor(&st, &healthy_inspector(), Some(&targets));
        let f = report
            .findings
            .iter()
            .find(|f| f.check == CHECK_DRIFT)
            .expect("drift warning");
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.message.contains("update(s)"));
        assert!(!report.has_errors(), "drift alone must not be an error");
    }

    #[test]
    fn no_drift_when_in_sync() {
        let st = state_of(vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])]);
        let targets = vec![target("oper", 9010, "/bin/bash", &["wheel"])];
        let report = run_doctor(&st, &healthy_inspector(), Some(&targets));
        assert!(!report.findings.iter().any(|f| f.check == CHECK_DRIFT));
    }

    // ---- file-access drift ----

    use crate::state::ManagedFileGrant;

    fn managed_acct_with_grant(name: &str, path: &str) -> ManagedAccount {
        ManagedAccount {
            file_grants: vec![ManagedFileGrant {
                path: path.to_owned(),
                access: crate::catalog::Access::Rw,
                recursive: true,
            }],
            ..managed_acct(name, 9010, "/bin/bash", &["wheel"])
        }
    }

    #[test]
    fn file_access_grant_present_no_finding() {
        let st = state_of(vec![managed_acct_with_grant("oper", "/etc/ssh")]);
        let mut insp = healthy_inspector();
        // ACL entry present on the path for the account.
        insp.file_acls
            .insert(("/etc/ssh".into(), "oper".into()), true);
        let report = run_doctor(&st, &insp, None);
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.check == CHECK_FILE_ACCESS_DRIFT),
            "present ACL must not drift: {:?}",
            report.findings
        );
    }

    #[test]
    fn file_access_grant_missing_is_warn() {
        let st = state_of(vec![managed_acct_with_grant("oper", "/etc/ssh")]);
        let mut insp = healthy_inspector();
        // Path readable but the account's ACL entry is gone → drift.
        insp.file_acls
            .insert(("/etc/ssh".into(), "oper".into()), false);
        let report = run_doctor(&st, &insp, None);
        let f = report
            .findings
            .iter()
            .find(|f| f.check == CHECK_FILE_ACCESS_DRIFT)
            .expect("file-access drift warning");
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.message.contains("/etc/ssh"));
        assert!(
            !report.has_errors(),
            "file-access drift is a warning, never an error"
        );
    }

    #[test]
    fn file_access_indeterminate_is_not_a_finding() {
        // No `file_acls` entry → inspector returns None (cannot verify). Best-effort
        // means we do NOT claim drift we could not confirm.
        let st = state_of(vec![managed_acct_with_grant("oper", "/etc/ssh")]);
        let report = run_doctor(&st, &healthy_inspector(), None);
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.check == CHECK_FILE_ACCESS_DRIFT),
            "indeterminate ACL must not be a finding: {:?}",
            report.findings
        );
    }

    #[test]
    fn has_errors_reflects_severity() {
        let mut r = DoctorReport::default();
        assert!(!r.has_errors());
        r.findings.push(Finding {
            severity: Severity::Warn,
            check: "x",
            target: "t".into(),
            message: "m".into(),
        });
        assert!(!r.has_errors(), "warnings alone are not errors");
        r.findings.push(Finding {
            severity: Severity::Error,
            check: "y",
            target: "t".into(),
            message: "m".into(),
        });
        assert!(r.has_errors());
    }

    #[test]
    fn empty_registry_with_rescue_is_clean() {
        let st = FakeState::default();
        let mut insp = FakeInspector::default();
        insp.login_capable.insert("root".into());
        let report = run_doctor(&st, &insp, None);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
    }

    #[test]
    fn framework_findings_map_both_severities_to_warn() {
        let lints = vec![
            crate::framework::FrameworkLint {
                code: "orphaned-mapping",
                severity: crate::framework::FrameworkLintSeverity::Warning,
                message: "orphan".into(),
            },
            crate::framework::FrameworkLint {
                code: "id-collision",
                severity: crate::framework::FrameworkLintSeverity::Error,
                message: "collision".into(),
            },
        ];
        let findings = framework_findings(&lints);
        assert_eq!(findings.len(), 2);
        for f in &findings {
            assert_eq!(f.severity, Severity::Warn);
            assert_eq!(f.check, "framework-integrity");
        }
        assert!(findings[0].message.contains("orphaned-mapping"));
        assert!(findings[1].message.contains("id-collision"));
    }

    #[test]
    fn framework_error_lint_does_not_flip_doctor_exit() {
        let lints = vec![crate::framework::FrameworkLint {
            code: "id-collision",
            severity: crate::framework::FrameworkLintSeverity::Error,
            message: "collision".into(),
        }];
        let mut report = DoctorReport::default();
        report.findings.extend(framework_findings(&lints));
        assert!(
            !report.has_errors(),
            "framework findings are Warn, never errors"
        );
    }

    #[test]
    fn framework_load_warning_is_warn_integrity() {
        let f = framework_load_warning("framework future skipped: unknown dimension");
        assert_eq!(f.severity, Severity::Warn);
        assert_eq!(f.check, "framework-integrity");
        assert!(f.message.contains("unknown dimension"));
    }
}
