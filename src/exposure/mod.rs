//! Read-only exposure audit: a permission index of actual filesystem rights.
//!
//! Census provisions access forward (file-access grants, groups, sudoers). This
//! layer answers the reverse question — what a principal *actually* reaches on disk,
//! beyond the least-privilege intent — by reading the real discretionary access
//! state of the filesystem. It never mutates an OS object; it only reads.
//!
//! ## What this slice provides
//!
//! The foundation: a [`PermissionIndex`] built by one read-only walk of the scan
//! roots. Each [`InodeRecord`] carries the inode's path, owner uid/gid, mode, parsed
//! POSIX [`AclEntries`], and an [`ObjectClass`]. Both the walk ([`FsWalker`]) and the
//! ACL read ([`AclSource`]) sit behind injectable traits with in-memory fakes, so the
//! index is fully unit-testable without touching real system paths.
//!
//! ## Scope of this slice (what is still a placeholder)
//!
//! - [`ObjectClass`] currently has only [`ObjectClass::Generic`]; the cron / secret /
//!   setuid-binary classifier is a later slice. The field is laid in [`InodeRecord`]
//!   so the classifier drops in without a schema change.
//! - The access-check (effective `rwx` per principal, ancestor `x`-traversal),
//!   principal resolution, finding taxonomy, the `audit fs` / `audit expose` CLI, and
//!   the intended-baseline subtraction are all later slices and not present here.
//!
//! ## Advisory limits
//!
//! Group membership and principal resolution (later slices) read local
//! `/etc/passwd` and `/etc/group` only; NSS/LDAP sources are not consulted, so a
//! verdict is a local-database view. The eventual access verdict is DAC-only (mode +
//! owner + groups + POSIX ACL); MAC layers (SELinux, AppArmor, PARSEC) may restrict
//! actual access further, so the verdict is an upper bound.

mod access;
mod acl;
mod config;
mod expose;
mod fs_audit;
mod index;
mod mounts;
mod reach;
mod scope;
mod taxonomy;

#[doc(inline)]
pub use self::access::{
    effective, resolve_principal, AccessVia, Effective, Principal, ResolvedGroup,
};
#[doc(inline)]
pub use self::acl::{
    parse_getfacl_dump, AclEntries, AclEntry, AclPerms, AclSource, AclTag, BestEffortRunner,
    FakeAclSource, GetfaclReader, ScanRunner,
};
#[doc(inline)]
pub use self::config::{ExposureConfig, ExposureConfigError};
#[doc(inline)]
pub use self::expose::{
    expose, exposure_report, ExposureReport, IntendedBaseline, ManagedContext, DAC_ONLY_NOTE,
};
#[doc(inline)]
pub use self::fs_audit::{audit_fs, DEFAULT_BROAD_GROUPS};
#[doc(inline)]
pub use self::index::{
    FakeWalker, FsWalker, InodeRecord, InodeStat, LiveWalker, PermissionIndex, SkippedMount,
    WalkOutcome,
};
#[doc(inline)]
pub use self::mounts::{is_skip_fstype, MountTable};
#[doc(inline)]
pub use self::reach::Reachability;
#[doc(inline)]
pub use self::scope::{default_roots, is_pseudo_fs};
#[doc(inline)]
pub use self::taxonomy::{
    classify_object, classify_path_mode, derive_risk, derive_severity, finding_for, remediation,
    Classifier, Finding, NoManagedContext, RemediationClass, RemediationContext, Risk, Severity,
    DEFAULT_SECRET_GLOBS,
};

/// The security class of an indexed inode, used to derive a finding's risk and
/// severity.
///
/// Assigned by [`classify_object`](crate::exposure::classify_object) from a path-glob
/// table plus the setuid/setgid mode bits. The token (`as_str`) is the stable form
/// used in JSON output and filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ObjectClass {
    /// A cron job or spool entry (scheduled execution as another user).
    Cron,
    /// A systemd unit file (defines a privileged service).
    SystemdUnit,
    /// A binary on a system `PATH` directory (run by other users/services).
    PathBinary,
    /// The sudoers policy (`/etc/sudoers` and drop-ins).
    Sudoers,
    /// A security-relevant configuration file.
    Config,
    /// A secret-bearing object (key, credential, shadow).
    Secret,
    /// A setuid/setgid binary (runs with elevated identity).
    SetuidBinary,
    /// Anything not matched by a more specific class.
    #[default]
    Generic,
}

impl ObjectClass {
    /// The stable lowercase token for this class, used in JSON output and filters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cron => "cron",
            Self::SystemdUnit => "systemd-unit",
            Self::PathBinary => "path-binary",
            Self::Sudoers => "sudoers",
            Self::Config => "config",
            Self::Secret => "secret",
            Self::SetuidBinary => "setuid-binary",
            Self::Generic => "generic",
        }
    }
}

impl std::fmt::Display for ObjectClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors building the permission index.
///
/// The exposure layer is strictly read-only, so an error can never leave a partial
/// mutation — it only means part of the index could not be assembled. Only the walk
/// is fallible; the ACL read is best-effort and never errors (see [`AclSource`]).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExposureError {
    /// A scan root that exists could not be stat'd (an absent root is skipped, not an
    /// error).
    #[error("cannot walk scan root {root}: {reason}")]
    Walk {
        /// The root that could not be walked.
        root: String,
        /// Why the walk failed.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_class_token_and_default() {
        assert_eq!(ObjectClass::default(), ObjectClass::Generic);
        assert_eq!(ObjectClass::Generic.as_str(), "generic");
        assert_eq!(ObjectClass::Generic.to_string(), "generic");
    }
}
