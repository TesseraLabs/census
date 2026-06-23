//! Anti-lockout gate (spec R4 / requirement "Anti-lockout gate").
//!
//! `census apply` must refuse a plan that would leave the device with zero
//! working login paths. A "working path" after the plan is one of:
//!   * a **rescue/break-glass** channel defined OUTSIDE Census (an emergency account and/or sshd
//!     `UsePAM=no`). By design it is NOT in the managed registry, so Census never touches it — its
//!     presence is asserted to the gate, never inferred from managed state.
//!   * at least one role account that survives the plan (created or kept, not deleted) and is
//!     reachable via Tessera's cert path.
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

/// Shells that disable interactive login. A managed account whose post-plan shell
/// is one of these (or empty) is NOT a surviving login path: an operator who set
/// the shell to a nologin/false stub cannot authenticate through it. The set
/// mirrors the live inspector's login-shell heuristic so the gate and the doctor
/// reachability check agree on what "login-capable" means.
const NON_LOGIN_SHELLS: &[&str] = &[
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
];

/// Whether `shell` keeps an account login-capable. An empty shell or any shell in
/// [`NON_LOGIN_SHELLS`] is not login-capable; anything else is. This is the same
/// signal sysadmins use to disable login, evaluated on the shell the plan would
/// leave in place (the resolved target for a Create/Update, the recorded shell for
/// an untouched managed account).
fn is_login_capable_shell(shell: &str) -> bool {
    !shell.is_empty() && !NON_LOGIN_SHELLS.contains(&shell)
}

/// Why the gate refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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

/// Count managed accounts that remain reachable AFTER the plan. A surviving
/// login account is one that, once the plan runs, still has a login-capable shell
/// (see [`is_login_capable_shell`]). Two sources contribute:
///
///   * a `Create`/`Update` action whose RESOLVED TARGET shell is login-capable — simply being
///     touched is not enough, because an `Update` that sets the shell to `nologin` removes a login
///     path rather than preserving one; and
///   * an `untouched_login_shell` — a managed account the plan does not change at all (no
///     Create/Update/Delete) and whose recorded shell is login-capable. These produce no `Action`,
///     yet they are real surviving logins, so the caller passes their shells in. Counting them
///     keeps the gate from refusing a plan that only deletes a redundant account while a working
///     one remains.
///
/// A single account name cannot appear in more than one plan action, and an
/// untouched account by definition has no action, so the two sources never double
/// count the same name.
fn surviving_login_accounts(plan: &Plan, untouched_login_shells: &[&str]) -> usize {
    let from_plan = plan
        .actions
        .iter()
        .filter(|a| match a {
            Action::Create(acct) => is_login_capable_shell(&acct.shell),
            Action::Update { account, .. } => is_login_capable_shell(&account.shell),
            Action::Delete { .. } => false,
        })
        .count();
    let from_untouched = untouched_login_shells
        .iter()
        .filter(|s| is_login_capable_shell(s))
        .count();
    from_plan + from_untouched
}

/// Gate the plan against lockout. Returns `Ok(())` if at least one working login
/// path remains (rescue present, OR a surviving managed login account), OR the
/// operator acknowledged the risk. Otherwise `Err(WouldLockOut)`.
///
/// `untouched_login_shells` carries the recorded shells of managed accounts the
/// plan leaves entirely unchanged — they survive as login paths even though they
/// produce no `Action`. The caller (apply) derives them from the managed registry
/// minus every name the plan touches.
///
/// Note: this gate is conservative. An empty plan (no-op) is always allowed — it
/// changes nothing and therefore cannot remove the last path.
pub fn gate(
    plan: &Plan,
    ctx: LockoutContext,
    untouched_login_shells: &[&str],
) -> Result<(), LockoutError> {
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
    if surviving_login_accounts(plan, untouched_login_shells) > 0 {
        return Ok(());
    }
    if ctx.risk_acknowledged {
        return Ok(());
    }
    Err(LockoutError::WouldLockOut)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::model::ResolvedAccount;
    use crate::rolestore::Limits;

    fn acct_with_shell(name: &str, shell: &str) -> ResolvedAccount {
        ResolvedAccount {
            name: name.to_owned(),
            uid: 9010,
            shell: shell.to_owned(),
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

    fn acct(name: &str) -> ResolvedAccount {
        acct_with_shell(name, "/bin/bash")
    }

    fn delete_only_plan() -> Plan {
        Plan {
            actions: vec![Action::Delete {
                name: "oper".into(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn plan_removing_last_path_is_refused() {
        // Delete-only plan, no rescue, no risk-ack, no untouched login → refuse.
        let err = gate(&delete_only_plan(), LockoutContext::default(), &[]).unwrap_err();
        assert!(matches!(err, LockoutError::WouldLockOut));
    }

    #[test]
    fn rescue_outside_managed_allows_plan() {
        // Rescue is asserted present (out of managed scope) → plan allowed,
        // and the rescue channel is not represented in the plan at all.
        let ctx = LockoutContext {
            rescue_present: true,
            ..Default::default()
        };
        assert!(gate(&delete_only_plan(), ctx, &[]).is_ok());
    }

    #[test]
    fn surviving_managed_account_allows_plan() {
        let plan = Plan {
            actions: vec![
                Action::Create(acct("admin")),
                Action::Delete {
                    name: "oper".into(),
                },
            ],
            ..Default::default()
        };
        assert!(gate(&plan, LockoutContext::default(), &[]).is_ok());
    }

    #[test]
    fn risk_acknowledged_allows_lockout_plan() {
        let ctx = LockoutContext {
            risk_acknowledged: true,
            ..Default::default()
        };
        assert!(gate(&delete_only_plan(), ctx, &[]).is_ok());
    }

    #[test]
    fn empty_plan_is_noop_and_allowed() {
        assert!(gate(&Plan::default(), LockoutContext::default(), &[]).is_ok());
    }

    #[test]
    fn group_only_plan_is_allowed_without_rescue_or_ack() {
        // A plan with ONLY group actions (e.g. an orphan groupdel) and no
        // account actions touches no login path → must PASS even with no rescue
        // and no risk-ack.
        let plan = Plan {
            actions: vec![],
            group_actions: vec![crate::plan::GroupAction::Delete {
                name: "orphan".into(),
            }],
        };
        assert!(gate(&plan, LockoutContext::default(), &[]).is_ok());
    }

    #[test]
    fn update_to_nologin_with_deletes_is_refused() {
        // [Update X->nologin, Delete Y, Delete Z]: the only touched account has
        // its shell set to a login-disabling stub, the rest are deleted, no
        // untouched login account and no rescue → the post-plan device has zero
        // login paths, so the gate must REFUSE (the discriminant-only gate wrongly
        // counted the Update as surviving).
        let plan = Plan {
            actions: vec![
                Action::Update {
                    account: acct_with_shell("x", "/usr/sbin/nologin"),
                    changes: vec!["shell".to_owned()],
                },
                Action::Delete { name: "y".into() },
                Action::Delete { name: "z".into() },
            ],
            ..Default::default()
        };
        let err = gate(&plan, LockoutContext::default(), &[]).unwrap_err();
        assert!(matches!(err, LockoutError::WouldLockOut));
    }

    #[test]
    fn update_keeping_login_shell_allows_plan() {
        // The dual of the above: an Update that keeps a real login shell IS a
        // surviving path, so the plan is allowed.
        let plan = Plan {
            actions: vec![Action::Update {
                account: acct_with_shell("x", "/bin/bash"),
                changes: vec!["groups".to_owned()],
            }],
            ..Default::default()
        };
        assert!(gate(&plan, LockoutContext::default(), &[]).is_ok());
    }

    #[test]
    fn delete_with_untouched_login_account_is_allowed() {
        // [Delete B] while an untouched in-sync managed account A still has a login
        // shell → A is a surviving login path even though it produces no Action, so
        // the gate must ALLOW the plan without rescue or risk-ack.
        let plan = Plan {
            actions: vec![Action::Delete { name: "b".into() }],
            ..Default::default()
        };
        assert!(gate(&plan, LockoutContext::default(), &["/bin/bash"]).is_ok());
    }

    #[test]
    fn delete_with_only_nologin_untouched_account_is_refused() {
        // The untouched account survives but cannot log in (nologin shell), so it
        // is NOT a surviving login path and the gate must still refuse.
        let plan = Plan {
            actions: vec![Action::Delete { name: "b".into() }],
            ..Default::default()
        };
        let err = gate(&plan, LockoutContext::default(), &["/usr/sbin/nologin"]).unwrap_err();
        assert!(matches!(err, LockoutError::WouldLockOut));
    }

    #[test]
    fn login_capable_shell_predicate() {
        assert!(is_login_capable_shell("/bin/bash"));
        assert!(is_login_capable_shell("/bin/sh"));
        assert!(!is_login_capable_shell("/usr/sbin/nologin"));
        assert!(!is_login_capable_shell("/sbin/nologin"));
        assert!(!is_login_capable_shell("/bin/false"));
        assert!(!is_login_capable_shell("/usr/bin/false"));
        assert!(!is_login_capable_shell(""));
    }
}
