//! Anti-lockout gate (spec R4 / requirement "Anti-lockout gate").
//!
//! `census apply` must refuse a plan that would leave the device with zero
//! working login paths. A "working path" after the plan is one of:
//!   * a **rescue/break-glass** channel defined OUTSIDE Census (an emergency
//!     account and/or sshd `UsePAM=no`). By design it is NOT in the managed
//!     registry, so Census never touches it — its presence is asserted to the
//!     gate, never inferred from managed state.
//!   * at least one role account that survives the plan (created or kept, not
//!     deleted) and is reachable via Tessera's cert path.
//!
//! If no rescue is configured AND the plan leaves no surviving role account,
//! apply must refuse — unless the operator passes the conscious-risk flag
//! (`--i-understand-no-rescue`), which is logged.
//!
//! Rescue *outside the managed registry* is structurally out of scope: this
//! module does not enumerate or validate it, it only takes a boolean assertion
//! that such a channel exists.

use crate::plan::{Action, Plan};

/// Inputs to the gate beyond the plan itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct LockoutContext {
    /// A rescue/break-glass channel exists outside Census (operator asserts it).
    pub rescue_present: bool,
    /// `--i-understand-no-rescue`: proceed even with no rescue and no surviving
    /// managed login path (conscious risk; logged by the caller).
    pub risk_acknowledged: bool,
}

/// Why the gate refused.
#[derive(Debug, thiserror::Error)]
pub enum LockoutError {
    /// The plan removes the last working login path and no rescue / risk-ack
    /// permits it.
    #[error(
        "anti-lockout: plan would leave zero working login paths (no rescue channel, \
         no surviving managed login account); refusing. Pass --i-understand-no-rescue \
         only if you have an out-of-band recovery path."
    )]
    WouldLockOut,
}

/// Count role accounts that remain reachable after the plan: any account that
/// is Created or Updated (kept) and is NOT Deleted. Since a single account name
/// cannot be both in this plan ordering, surviving == created or updated.
fn surviving_login_accounts(plan: &Plan) -> usize {
    plan.actions
        .iter()
        .filter(|a| matches!(a, Action::Create(_) | Action::Update { .. }))
        .count()
}

/// Gate the plan against lockout. Returns `Ok(())` if at least one working
/// login path remains (rescue present, OR a surviving managed login account),
/// OR the operator acknowledged the risk. Otherwise `Err(WouldLockOut)`.
///
/// Note: this gate is conservative. An empty plan (no-op) is always allowed —
/// it changes nothing and therefore cannot remove the last path.
pub fn gate(plan: &Plan, ctx: LockoutContext) -> Result<(), LockoutError> {
    if plan.is_empty() {
        return Ok(());
    }
    // A plan that touches no account cannot remove a login path. Group actions
    // (e.g. an orphan `groupdel`) do not affect login reachability, so a
    // group-only plan can never cause a lockout — pass regardless of rescue/ack.
    if plan.actions.is_empty() {
        return Ok(());
    }
    if ctx.rescue_present {
        return Ok(());
    }
    if surviving_login_accounts(plan) > 0 {
        return Ok(());
    }
    if ctx.risk_acknowledged {
        return Ok(());
    }
    Err(LockoutError::WouldLockOut)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ResolvedAccount;
    use crate::rolestore::Limits;
    use std::path::PathBuf;

    fn acct(name: &str) -> ResolvedAccount {
        ResolvedAccount {
            name: name.to_owned(),
            uid: 9010,
            shell: "/bin/bash".to_owned(),
            home: PathBuf::from("/var/lib/census/home/x"),
            groups: vec![],
            sudo_role: None,
            sudo_commands: Vec::new(),
            limits: Limits::default(),
            file_grants: Vec::new(),
            locked_password: true,
            provenance: crate::model::Provenance::Created,
        }
    }

    fn delete_only_plan() -> Plan {
        Plan {
            actions: vec![Action::Delete { name: "oper".into() }],
            ..Default::default()
        }
    }

    #[test]
    fn plan_removing_last_path_is_refused() {
        // Delete-only plan, no rescue, no risk-ack → refuse.
        let err = gate(&delete_only_plan(), LockoutContext::default()).unwrap_err();
        assert!(matches!(err, LockoutError::WouldLockOut));
    }

    #[test]
    fn rescue_outside_managed_allows_plan() {
        // Rescue is asserted present (out of managed scope) → plan allowed,
        // and the rescue channel is not represented in the plan at all.
        let ctx = LockoutContext { rescue_present: true, ..Default::default() };
        assert!(gate(&delete_only_plan(), ctx).is_ok());
    }

    #[test]
    fn surviving_managed_account_allows_plan() {
        let plan = Plan {
            actions: vec![
                Action::Create(acct("admin")),
                Action::Delete { name: "oper".into() },
            ],
            ..Default::default()
        };
        assert!(gate(&plan, LockoutContext::default()).is_ok());
    }

    #[test]
    fn risk_acknowledged_allows_lockout_plan() {
        let ctx = LockoutContext { risk_acknowledged: true, ..Default::default() };
        assert!(gate(&delete_only_plan(), ctx).is_ok());
    }

    #[test]
    fn empty_plan_is_noop_and_allowed() {
        assert!(gate(&Plan::default(), LockoutContext::default()).is_ok());
    }

    #[test]
    fn group_only_plan_is_allowed_without_rescue_or_ack() {
        // A plan with ONLY group actions (e.g. an orphan groupdel) and no
        // account actions touches no login path → must PASS even with no rescue
        // and no risk-ack.
        let plan = Plan {
            actions: vec![],
            group_actions: vec![crate::plan::GroupAction::Delete { name: "orphan".into() }],
        };
        assert!(gate(&plan, LockoutContext::default()).is_ok());
    }
}
