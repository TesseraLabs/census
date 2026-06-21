//! Read-only diagnostics for `census doctor` (spec §4, §7, §8).
//!
//! Doctor reconciles the managed *registry* against the *live* system (via
//! [`crate::inspect::SystemInspector`]) and reports invariant violations as
//! [`Finding`]s. It performs ZERO mutations — degradation is detected here and
//! repaired by `apply`.
//!
//! Severity:
//! - [`Severity::Error`] — a security invariant is broken (§8 unreachability,
//!   §4 registry integrity). `census doctor` exits non-zero.
//! - [`Severity::Warn`] — advisory (potential lockout §7, drift). Printed but
//!   does not fail the exit code.

use crate::inspect::SystemInspector;
use crate::model::ResolvedAccount;
use crate::plan;
use crate::state::SystemState;
use std::collections::BTreeSet;

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
const CHECK_DRIFT: &str = "drift";

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

    // --- §4 registry integrity (Error) ---
    for (name, record) in &registry {
        match inspector.account(name) {
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
                let mut live_groups = facts.groups.clone();
                let mut reg_groups = record.groups.clone();
                live_groups.sort();
                reg_groups.sort();
                if live_groups != reg_groups {
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
                        message: format!("live account differs from registry: {}", diffs.join("; ")),
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
                if facts.gid != record.gid {
                    findings.push(Finding {
                        severity: Severity::Error,
                        check: CHECK_GROUP_REGISTRY,
                        target: name.clone(),
                        message: format!(
                            "live gid {} != registry gid {} (managed group renumbered out of band)",
                            facts.gid, record.gid
                        ),
                    });
                }
            }
        }
    }

    // --- §8 unreachability (Error) ---
    for (name, record) in &registry {
        match inspector.account(name) {
            None => findings.push(Finding {
                severity: Severity::Error,
                check: CHECK_UNREACHABLE,
                target: name.clone(),
                message: "managed role account is missing (cannot verify unreachability)".to_owned(),
            }),
            Some(facts) => {
                let _ = record; // registry record not needed here; live facts authoritative
                match inspector.password_locked(name) {
                    Some(true) => {}
                    Some(false) => findings.push(Finding {
                        severity: Severity::Error,
                        check: CHECK_UNREACHABLE,
                        target: name.clone(),
                        message: "password is NOT locked (role account must be unreachable, §8)"
                            .to_owned(),
                    }),
                    None => findings.push(Finding {
                        severity: Severity::Error,
                        check: CHECK_UNREACHABLE,
                        target: name.clone(),
                        message: "shadow entry is absent/unreadable; cannot confirm password lock"
                            .to_owned(),
                    }),
                }
                // authorized_keys would be an alternative login path (§8). Use the
                // live home (passwd field 6); the registry does not record home.
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
    if inspector.login_capable_non_managed(&managed_names).is_empty() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect::{AccountFacts, FakeInspector};
    use crate::rolestore::Limits;
    use crate::state::{FakeState, ManagedAccount};
    use std::path::PathBuf;

    fn managed_acct(name: &str, uid: u32, shell: &str, groups: &[&str]) -> ManagedAccount {
        ManagedAccount {
            name: name.to_owned(),
            uid,
            shell: shell.to_owned(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            sudo_role: None,
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
        f.accounts.insert("oper".into(), facts(9010, "/bin/bash", &["wheel"]));
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
            limits: Limits::default(),
            locked_password: true,
        }
    }

    #[test]
    fn clean_system_has_no_findings() {
        let st = state_of(vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])]);
        let report = run_doctor(&st, &healthy_inspector(), None);
        assert!(report.findings.is_empty(), "clean system: {:?}", report.findings);
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
        insp.accounts.insert("oper".into(), facts(9999, "/bin/bash", &["wheel"]));
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
        insp.accounts.insert("oper".into(), facts(9010, "/bin/zsh", &["wheel", "docker"]));
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
        let st = state_of(vec![managed_acct("oper", 9010, "/bin/bash", &["wheel", "docker"])]);
        let mut insp = healthy_inspector();
        insp.accounts.insert("oper".into(), facts(9010, "/bin/bash", &["docker", "wheel"]));
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
        ManagedGroup { name: name.to_owned(), gid, from_version: 1 }
    }

    #[test]
    fn managed_group_present_and_matching_is_clean() {
        let st = state_with_group(
            vec![managed_acct("oper", 9010, "/bin/bash", &["wheel"])],
            vec![mgroup("atm-operators", 8010)],
        );
        let mut insp = healthy_inspector();
        insp.groups.insert("atm-operators".into(), GroupFacts { gid: 8010 });
        let report = run_doctor(&st, &insp, None);
        assert!(
            !report.findings.iter().any(|f| f.check == CHECK_GROUP_REGISTRY),
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
        insp.groups.insert("atm-operators".into(), GroupFacts { gid: 8099 });
        let report = run_doctor(&st, &insp, None);
        assert!(report.has_errors());
        let f = report
            .findings
            .iter()
            .find(|f| f.check == CHECK_GROUP_REGISTRY && f.target == "atm-operators")
            .expect("gid drift finding");
        assert!(f.message.contains("gid"));
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
}
