//! Declaration trust gate (fail-closed).
//!
//! `census apply` mutates auth-critical OS state, so it must only proceed on a
//! *trusted* declaration. Two trust modes (spec R7 / requirement
//! "Доверие к декларации до мутаций"):
//!
//! - **managed**: valid signature + anti-rollback. The signature mechanism is a
//!   later change (`declaration-trust`); here it is a STUB that always returns
//!   "not trusted".
//! - **standalone**: explicit `--trust-fs` — the operator vouches for the
//!   integrity of the (root-only) filesystem holding the declaration. This is a
//!   conscious decision and is logged.
//!
//! Any other case → not trusted → caller MUST refuse before any mutation.

use crate::declaration::Declaration;

/// Options governing the trust decision (CLI-derived).
#[derive(Debug, Clone, Copy, Default)]
pub struct TrustOptions {
    /// `--trust-fs`: trust filesystem integrity (standalone mode).
    pub trust_fs: bool,
}

/// Outcome of a trust evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustDecision {
    /// Declaration is trusted; the carried `reason` is a human-readable log line.
    Trusted {
        /// Why trust was granted (logged before any mutation).
        reason: String,
    },
    /// Declaration is not trusted; `reason` explains why.
    NotTrusted {
        /// Why trust was denied.
        reason: String,
    },
}

impl TrustDecision {
    /// True if the declaration may be applied.
    pub fn is_trusted(&self) -> bool {
        matches!(self, TrustDecision::Trusted { .. })
    }

    /// The human-readable reason carried by either variant.
    pub fn reason(&self) -> &str {
        match self {
            TrustDecision::Trusted { reason } | TrustDecision::NotTrusted { reason } => reason,
        }
    }
}

/// Evaluate whether `decl` may be applied.
///
/// Order: `--trust-fs` wins (standalone). Otherwise fall through to the managed
/// signature path, which is currently a stub returning "not trusted". This is
/// infallible today (the `Result` reserves room for the real signature path,
/// which can fail to *parse* a signature, in the follow-up change).
pub fn verify_trust(
    decl: &Declaration,
    opts: TrustOptions,
) -> Result<TrustDecision, TrustError> {
    if opts.trust_fs {
        return Ok(TrustDecision::Trusted {
            reason: format!(
                "filesystem trust granted via --trust-fs (standalone), declaration version {}",
                decl.version
            ),
        });
    }
    // Managed signature path: not yet implemented (change `declaration-trust`).
    // Fail closed.
    Ok(verify_managed_signature_stub(decl))
}

/// STUB for the managed signature + anti-rollback path. Always "not trusted"
/// until the `declaration-trust` change lands the real mechanism.
fn verify_managed_signature_stub(_decl: &Declaration) -> TrustDecision {
    TrustDecision::NotTrusted {
        reason: "declaration is not signed and --trust-fs was not given (fail-closed)".to_owned(),
    }
}

/// Errors from trust evaluation. Reserved for the real signature path.
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    /// A signature was present but malformed (future signature path).
    #[error("declaration signature is malformed: {0}")]
    MalformedSignature(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decl() -> Declaration {
        Declaration::parse(
            r#"
version = 7
role_store = "/var/lib/tessera/roles"
[defaults]
uid_range = [9000, 9999]
shell = "/bin/bash"
home_base = "/var/lib/census/home"
"#,
        )
        .unwrap()
    }

    #[test]
    fn fail_closed_without_trust_fs() {
        let d = verify_trust(&decl(), TrustOptions::default()).unwrap();
        assert!(!d.is_trusted(), "no trust source → must be not trusted");
        match d {
            TrustDecision::NotTrusted { reason } => assert!(reason.contains("fail-closed")),
            other => panic!("expected NotTrusted, got {other:?}"),
        }
    }

    #[test]
    fn trust_fs_grants_trust_and_logs_reason() {
        let d = verify_trust(&decl(), TrustOptions { trust_fs: true }).unwrap();
        assert!(d.is_trusted());
        // The reason is the line the orchestrator logs.
        assert!(d.reason().contains("--trust-fs"));
        assert!(d.reason().contains("version 7"));
    }
}
