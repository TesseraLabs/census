//! Finding taxonomy: classify an inode, derive its risk and severity, and decide
//! the remediation path.
//!
//! ## What a finding carries
//!
//! A [`Finding`] is the unit of exposure the audit reports: which principal (or
//! `None` in the global posture map), which path, the effective access and the
//! [`AccessVia`] reason it was granted, the inode's [`ObjectClass`], and three
//! derived judgements — [`Risk`] (escalation / leak / tamper), [`Severity`], and the
//! [`RemediationClass`] (`ambient` vs `in-model`) with a concrete remediation hint.
//!
//! ## Classification (deterministic priority)
//!
//! [`classify_object`] assigns an [`ObjectClass`] from a data table of path globs
//! plus the setuid/setgid mode bits. When several rules could match, a fixed
//! precedence applies, highest first:
//!
//! `setuid-binary > sudoers > cron > systemd-unit > secret > path-binary > config >
//! generic`
//!
//! Rationale for the order: a setuid/setgid bit elevates identity regardless of where
//! the file lives, so it dominates; sudoers, cron, and unit files are the highest-
//! value escalation surfaces and are placed above the broad `secret`/`path-binary`
//! globs so a sudoers drop-in is never mis-classed as a generic binary; `config` is
//! the catch-all for the security-relevant prefixes and sits just above `generic`.
//!
//! ## Risk / severity (data tables)
//!
//! [`derive_risk`] and [`derive_severity`] are pure lookups over `(access, class)`
//! and `(class, risk)`. A read of a non-secret object is deliberately NOT a finding
//! (everyone can read `/usr/bin`); only writes, and reads of secrets, are reported.
//!
//! ## Remediation (`ambient` vs `in-model`)
//!
//! [`remediation`] decides whether the access comes from an object Census *owns*
//! (a managed group, or a path under a Census file-access grant — `in-model`, fixable
//! by narrowing the declaration) or from a foreign object (`ambient`, fixable only by
//! a manual `chmod`/`setfacl`). The managed-context lookup is injected via
//! [`RemediationContext`] so the registry/catalog binding lands in a later slice; this
//! slice never reads the registry.

use crate::coverage::is_security_relevant_config;

use super::access::AccessVia;
use super::acl::AclPerms;
use super::index::InodeRecord;
use super::ObjectClass;

// --- object-class classification -------------------------------------------

/// Unix mode mask selecting the file-type bits.
const S_IFMT: u32 = 0o170_000;
/// The file-type value for a directory.
const S_IFDIR: u32 = 0o040_000;
/// The setuid + setgid bits. Either one elevates the identity a binary runs as.
const SETID_BITS: u32 = 0o6000;

/// The high-priority fixed glob table (above the configurable secret globs), in
/// descending priority: sudoers before cron before systemd-unit. `config`, the
/// configurable secret globs, the path-binary table, and the setuid bit are handled
/// around it (see [`Classifier::classify`]).
///
/// Glob syntax (see [`glob_match`]): `**` matches any run of path segments, `*`
/// matches within a single segment. Each pattern here MUST contain at most one `**`:
/// the matcher is general but backtracks across `**`, so multiple `**` in one pattern
/// would be exponential. The defaults below all hold to a single leading `**`.
const CLASS_GLOBS_HIGH: &[(&str, ObjectClass)] = &[
    // sudoers — the privilege policy itself.
    ("/etc/sudoers", ObjectClass::Sudoers),
    ("/etc/sudoers.d/**", ObjectClass::Sudoers),
    // cron — scheduled execution as another user.
    ("/var/spool/cron/**", ObjectClass::Cron),
    ("/etc/cron*/**", ObjectClass::Cron),
    ("/etc/crontab", ObjectClass::Cron),
    // systemd units — privileged service definitions.
    ("/etc/systemd/**", ObjectClass::SystemdUnit),
    ("/lib/systemd/system/**", ObjectClass::SystemdUnit),
];

/// The low-priority fixed glob table (below the configurable secret globs): binaries
/// on a system `PATH`.
const CLASS_GLOBS_LOW: &[(&str, ObjectClass)] = &[
    ("/usr/bin/**", ObjectClass::PathBinary),
    ("/bin/**", ObjectClass::PathBinary),
    ("/usr/local/bin/**", ObjectClass::PathBinary),
    ("/sbin/**", ObjectClass::PathBinary),
];

/// The default secret-classifying globs (keys, credentials, the shadow database).
///
/// The `exposure.toml` config overrides this list; absent a config these defaults
/// apply. Documented so the chosen set is reviewable.
pub const DEFAULT_SECRET_GLOBS: &[&str] = &[
    "/etc/shadow*",
    "**/*.key",
    "**/*.pem",
    "**/id_rsa*",
    // `.env` and its variants (`.env.local`, `.env.prod`, …).
    "**/.env*",
    "**/*credentials*",
];

/// The object-class classifier: the fixed glob tables plus a configurable set of
/// secret-classifying globs.
///
/// Built once per audit (from the `exposure.toml` config, or [`Classifier::default`]
/// when absent) and applied to every inode at index-build time, so the
/// [`InodeRecord::class`](super::InodeRecord) the engines read is config-driven. The
/// secret globs are the only configurable axis; the cron/sudoers/systemd-unit/
/// path-binary/config tables are fixed.
#[derive(Debug, Clone)]
pub struct Classifier {
    /// The secret-classifying globs (config-supplied, or the built-in defaults).
    secret_globs: Vec<String>,
}

impl Default for Classifier {
    fn default() -> Self {
        Self {
            secret_globs: DEFAULT_SECRET_GLOBS
                .iter()
                .map(|g| (*g).to_owned())
                .collect(),
        }
    }
}

impl Classifier {
    /// Construct with an explicit secret-glob list (from the config).
    #[must_use]
    pub const fn new(secret_globs: Vec<String>) -> Self {
        Self { secret_globs }
    }

    /// Classify an inode by its path and mode into an [`ObjectClass`].
    ///
    /// A setuid/setgid **regular file** is [`ObjectClass::SetuidBinary`] regardless of
    /// path (the id bit dominates); a setgid *directory* is the inheritance idiom and
    /// is excluded. Otherwise the precedence is: the high glob table (sudoers / cron /
    /// systemd-unit), then the configurable secret globs, then the path-binary table,
    /// then a security-relevant config prefix, else [`ObjectClass::Generic`].
    #[must_use]
    pub fn classify(&self, path: &str, mode: u32) -> ObjectClass {
        if (mode & S_IFMT) != S_IFDIR && (mode & SETID_BITS) != 0 {
            return ObjectClass::SetuidBinary;
        }
        for (glob, class) in CLASS_GLOBS_HIGH {
            if glob_match(glob, path) {
                return *class;
            }
        }
        for glob in &self.secret_globs {
            if glob_match(glob, path) {
                return ObjectClass::Secret;
            }
        }
        for (glob, class) in CLASS_GLOBS_LOW {
            if glob_match(glob, path) {
                return *class;
            }
        }
        if is_security_relevant_config(path) {
            return ObjectClass::Config;
        }
        ObjectClass::Generic
    }
}

/// Classify an indexed inode with the default (built-in) classifier. Convenience for
/// callers that do not carry a configured [`Classifier`].
#[must_use]
pub fn classify_object(record: &InodeRecord) -> ObjectClass {
    Classifier::default().classify(&record.path, record.mode)
}

/// Classify by path + mode with the default (built-in) classifier.
#[must_use]
pub fn classify_path_mode(path: &str, mode: u32) -> ObjectClass {
    Classifier::default().classify(path, mode)
}

/// Match a path against a glob with `**` (any run of segments) and `*` (within a
/// segment). Both pattern and path are split on `/` and matched segment by segment.
fn glob_match(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let seg: Vec<&str> = path.split('/').collect();
    match_segments(&pat, &seg)
}

/// Recursive segment matcher: `**` consumes zero or more whole segments, every other
/// pattern segment matches exactly one path segment via [`segment_match`].
fn match_segments(pat: &[&str], seg: &[&str]) -> bool {
    let Some((head, pat_rest)) = pat.split_first() else {
        // Pattern exhausted: match iff the path is exhausted too.
        return seg.is_empty();
    };
    if *head == "**" {
        // Try matching the remaining pattern against every suffix of the path
        // (including the full path and the empty tail), i.e. `**` = zero+ segments.
        let mut tail = seg;
        loop {
            if match_segments(pat_rest, tail) {
                return true;
            }
            match tail.split_first() {
                Some((_, next)) => tail = next,
                None => return false,
            }
        }
    }
    let Some((seg_head, seg_rest)) = seg.split_first() else {
        return false;
    };
    segment_match(head, seg_head) && match_segments(pat_rest, seg_rest)
}

/// Match a single path segment against a single pattern segment, where `*` is a
/// wildcard for any run of characters within the segment (it never spans `/`).
///
/// A pattern with no `*` is a plain equality. With `*`s the pattern is a sequence of
/// literal chunks: the first must be a prefix, the last a suffix, and any middle
/// chunks must occur in order. This is the standard glob-within-segment rule and is
/// sufficient for the classification table's patterns (`cron*`, `*.key`,
/// `*credentials*`, `id_rsa*`).
fn segment_match(pattern: &str, text: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == text;
    }
    let mut chunks = pattern.split('*');
    // The first chunk (before the first `*`) must be a literal prefix.
    let Some(first) = chunks.next() else {
        return true;
    };
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    // Walk the remaining chunks; the final one is the required suffix, the rest must
    // appear in order. `peekable` lets us treat the last chunk specially.
    let mut chunks = chunks.peekable();
    while let Some(chunk) = chunks.next() {
        if chunks.peek().is_none() {
            // Last chunk: the leftover must end with it (empty chunk ⇒ trailing `*`).
            return rest.ends_with(chunk);
        }
        if chunk.is_empty() {
            continue; // consecutive `*` — no constraint
        }
        match rest.find(chunk) {
            Some(pos) => {
                let end = pos + chunk.len();
                let (_, tail) = rest.split_at(end);
                rest = tail;
            }
            None => return false,
        }
    }
    // Only reached when the pattern ended with `*` and produced no trailing chunk.
    true
}

// --- risk / severity --------------------------------------------------------

/// The kind of harm an exposure enables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Risk {
    /// Write access that lets the principal gain higher privilege (run code as
    /// another user / root: cron, sudoers, units, path binaries, setuid, secrets).
    Escalation,
    /// Read access to a secret-bearing object (credential disclosure).
    Leak,
    /// Write access that lets the principal corrupt configuration or data without a
    /// direct privilege gain.
    Tamper,
}

impl Risk {
    /// The stable lowercase token (`escalation`, `leak`, `tamper`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Escalation => "escalation",
            Self::Leak => "leak",
            Self::Tamper => "tamper",
        }
    }
}

impl std::fmt::Display for Risk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How urgently a finding warrants attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Direct, high-impact exposure (escalation on a privileged class, secret leak).
    High,
    /// Meaningful but bounded (tamper of a security-relevant config).
    Medium,
    /// Low-impact (world-writable generic / scratch object).
    Low,
}

impl Severity {
    /// A numeric rank for ordering (`High` = 3 > `Medium` = 2 > `Low` = 1), so a
    /// dedup that keeps the most severe finding can compare without relying on the
    /// enum discriminant order.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
        }
    }

    /// The stable lowercase token (`high`, `medium`, `low`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Derive the [`Risk`] of an access to a classified object, or `None` when the access
/// is not a reportable finding.
///
/// Write access escalates on the privileged classes (cron / sudoers / systemd-unit /
/// path-binary / setuid-binary / secret) and tampers on config / generic. A read of a
/// secret is a leak. A read of any non-secret object is **not** a finding (read of a
/// world-readable binary or config is normal), so it returns `None`; an execute-only
/// access is likewise not a finding.
#[must_use]
pub const fn derive_risk(access: AclPerms, class: ObjectClass) -> Option<Risk> {
    if access.write {
        return Some(match class {
            ObjectClass::Cron
            | ObjectClass::Sudoers
            | ObjectClass::SystemdUnit
            | ObjectClass::PathBinary
            | ObjectClass::SetuidBinary
            | ObjectClass::Secret => Risk::Escalation,
            ObjectClass::Config | ObjectClass::Generic => Risk::Tamper,
        });
    }
    if access.read && matches!(class, ObjectClass::Secret) {
        return Some(Risk::Leak);
    }
    None
}

/// Derive the [`Severity`] from the object class and the risk.
///
/// Escalation and secret-leak are always High. Tamper is Medium on a config object
/// and Low otherwise (a world-writable generic / scratch object).
#[must_use]
pub const fn derive_severity(class: ObjectClass, risk: Risk) -> Severity {
    match risk {
        Risk::Escalation | Risk::Leak => Severity::High,
        Risk::Tamper => match class {
            ObjectClass::Config => Severity::Medium,
            _ => Severity::Low,
        },
    }
}

// --- remediation ------------------------------------------------------------

/// How a finding should be remediated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum RemediationClass {
    /// The access comes from a foreign object Census does not own (its mode / owner /
    /// ACL). Census cannot fix it by changing a declaration; the hint is a manual
    /// `chmod` / `setfacl`.
    Ambient,
    /// The access comes from an object Census owns (a managed group, or a path under a
    /// Census file-access grant). The hint is to narrow the declaration.
    InModel,
}

impl RemediationClass {
    /// The stable lowercase token (`ambient`, `in-model`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ambient => "ambient",
            Self::InModel => "in-model",
        }
    }
}

impl std::fmt::Display for RemediationClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The Census-managed context a remediation decision needs: whether a group is managed
/// by Census, and whether a path is covered by a Census file-access grant.
///
/// Injected (rather than reading the registry directly) so the real binding to
/// `managed.toml` / the permission catalog lands in a later slice while this slice
/// stays pure and testable with a fake.
pub trait RemediationContext {
    /// Whether `group` is a group Census manages (so widening it is an in-model fix).
    fn is_managed_group(&self, group: &str) -> bool;
    /// The Census file-access grant covering `path`, if any (returned as a
    /// human-facing grant descriptor for the hint). `None` when no grant covers it.
    fn covering_grant(&self, path: &str) -> Option<String>;
}

/// A context that owns nothing: every group is foreign and no path is granted, so
/// every finding is `ambient`. Used by the global posture map (no principal, no
/// managed binding).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoManagedContext;

impl RemediationContext for NoManagedContext {
    fn is_managed_group(&self, _group: &str) -> bool {
        false
    }
    fn covering_grant(&self, _path: &str) -> Option<String> {
        None
    }
}

/// Decide the [`RemediationClass`] and the concrete hint for an access.
///
/// In-model when the access is granted through a Census-managed group (the `via` is a
/// group/ACL-group entry for a managed group) or the path sits under a Census
/// file-access grant; the hint then points at narrowing that declaration. Otherwise
/// ambient, with a concrete manual command (`chmod` / `setfacl`) and NO promise that
/// Census will apply it.
#[must_use]
pub fn remediation(
    via: &AccessVia,
    path: &str,
    class: ObjectClass,
    access: AclPerms,
    ctx: &dyn RemediationContext,
) -> (RemediationClass, String) {
    // In-model: access via a Census-managed group.
    if let Some(group) = managed_group_of(via, ctx) {
        return (
            RemediationClass::InModel,
            format!(
                "narrow the Census declaration of group `{group}`: its membership grants \
                 access to `{path}` beyond what the role needs"
            ),
        );
    }
    // In-model: the path is under a Census file-access grant AND the access actually
    // flows through a Census-set ACL entry (`user:`/`group:`). Mere path-containment
    // is NOT enough: a world-writable file (`via=other_bits`) or a foreign group entry
    // that happens to sit under a granted directory is an AMBIENT source — narrowing
    // the grant would not remove that world/foreign access — so those stay ambient
    // with a manual chmod/setfacl hint. (A managed-group `via` was already classed
    // in-model above; this gate aligns the grant branch with that via-based rule.)
    if matches!(via, AccessVia::AclUser(_) | AccessVia::AclGroup(_)) {
        if let Some(grant) = ctx.covering_grant(path) {
            return (
                RemediationClass::InModel,
                format!(
                    "narrow the Census file-access grant `{grant}`: it covers `{path}`, which is \
                     wider than the role needs"
                ),
            );
        }
    }
    // Ambient: a foreign object — a concrete manual fix, no auto-fix promised.
    (
        RemediationClass::Ambient,
        ambient_hint(via, path, class, access),
    )
}

/// The managed group a `via` attributes the access to, if Census manages it.
fn managed_group_of(via: &AccessVia, ctx: &dyn RemediationContext) -> Option<String> {
    match via {
        AccessVia::Group(g) | AccessVia::AclGroup(g) if ctx.is_managed_group(g) => Some(g.clone()),
        _ => None,
    }
}

/// The concrete manual remediation command for an ambient finding (no auto-fix).
fn ambient_hint(via: &AccessVia, path: &str, class: ObjectClass, access: AclPerms) -> String {
    match via {
        AccessVia::OtherBits => {
            if access.write {
                format!("remove world write manually: `chmod o-w {path}`")
            } else if matches!(class, ObjectClass::Secret) {
                format!("remove world read of a secret manually: `chmod 640 {path}`")
            } else {
                format!("remove world read manually: `chmod o-rwx {path}`")
            }
        }
        AccessVia::AclUser(u) => {
            format!("remove the ACL entry manually: `setfacl -x u:{u} {path}`")
        }
        AccessVia::AclGroup(g) => {
            format!("remove the ACL entry manually: `setfacl -x g:{g} {path}`")
        }
        AccessVia::Group(_) => {
            if access.write {
                format!("remove group write manually: `chmod g-w {path}`")
            } else {
                format!("restrict group access manually on `{path}`")
            }
        }
        AccessVia::Owner => {
            format!("review ownership of `{path}` (the principal owns it)")
        }
    }
}

// --- finding ----------------------------------------------------------------

/// One exposure finding: a reachable access classified, scored, and given a
/// remediation path. Serializable for the JSON output (its shape is part of the locked
/// `exposure-report.schema.json` contract).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Finding {
    /// The principal the exposure is under, or `None` in the global posture map.
    pub principal: Option<String>,
    /// The exposed inode's absolute path.
    pub path: String,
    /// The principal's effective `read`/`write`/`execute` on the inode.
    pub access: AclPerms,
    /// The precedence class that granted the access. Serializes (and is schematized) as
    /// its single `via` token string (e.g. `acl_user:role-x`), matching the custom
    /// `Serialize`.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub via: AccessVia,
    /// The inode's object class.
    pub class: ObjectClass,
    /// The kind of harm enabled.
    pub risk: Risk,
    /// How urgent the finding is.
    pub severity: Severity,
    /// Whether the fix is ambient (manual) or in-model (narrow a declaration).
    pub remediation_class: RemediationClass,
    /// The concrete remediation hint.
    pub hint: String,
}

/// Build a [`Finding`] for one reachable access, or `None` when it is not a finding.
///
/// Returns `None` when the object is unreachable (an unreachable object is never an
/// exposure — see [`Reachability`](super::Reachability)) or when the access is not a
/// reportable risk (a read of a non-secret object). Otherwise classifies the object,
/// derives risk and severity, and decides the remediation path.
///
/// `principal` is the principal name for the per-principal mode, or `None` for the
/// global posture map.
#[must_use]
pub fn finding_for(
    record: &InodeRecord,
    access: AclPerms,
    via: &AccessVia,
    principal: Option<&str>,
    reachable: bool,
    ctx: &dyn RemediationContext,
) -> Option<Finding> {
    if !reachable {
        return None;
    }
    // Trust the class the index already computed (with the configured classifier); the
    // index is authoritative, so the engines never re-classify.
    let class = record.class;
    let risk = derive_risk(access, class)?;
    let severity = derive_severity(class, risk);
    let (remediation_class, hint) = remediation(via, &record.path, class, access, ctx);
    Some(Finding {
        principal: principal.map(str::to_owned),
        path: record.path.clone(),
        access,
        via: via.clone(),
        class,
        risk,
        severity,
        remediation_class,
        hint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn record(path: &str, mode: u32) -> InodeRecord {
        InodeRecord {
            path: path.to_owned(),
            uid: 0,
            gid: 0,
            mode,
            acl: None,
            // The index stores the classified class; mirror that so `finding_for`
            // (which trusts `record.class`) sees the right class in tests.
            class: classify_path_mode(path, mode),
        }
    }

    fn rwx(r: bool, w: bool, x: bool) -> AclPerms {
        AclPerms {
            read: r,
            write: w,
            execute: x,
        }
    }

    /// A fake remediation context: a set of managed groups and a list of
    /// `(grant-prefix, descriptor)` covering grants.
    #[derive(Default)]
    struct FakeContext {
        managed: BTreeSet<String>,
        grants: Vec<(String, String)>,
    }
    impl RemediationContext for FakeContext {
        fn is_managed_group(&self, group: &str) -> bool {
            self.managed.contains(group)
        }
        fn covering_grant(&self, path: &str) -> Option<String> {
            self.grants
                .iter()
                .find(|(prefix, _)| crate::catalog::path_at_or_under(prefix, path))
                .map(|(_, descriptor)| descriptor.clone())
        }
    }

    // --- classification ---

    #[test]
    fn classify_each_class_from_globs() {
        // A regular-file mode (S_IFREG) so the setuid rule does not fire.
        let reg = 0o100_644;
        assert_eq!(
            classify_path_mode("/etc/sudoers", reg),
            ObjectClass::Sudoers
        );
        assert_eq!(
            classify_path_mode("/etc/sudoers.d/zz", reg),
            ObjectClass::Sudoers
        );
        assert_eq!(
            classify_path_mode("/var/spool/cron/crontabs/root", reg),
            ObjectClass::Cron
        );
        assert_eq!(
            classify_path_mode("/etc/cron.d/job", reg),
            ObjectClass::Cron
        );
        assert_eq!(classify_path_mode("/etc/crontab", reg), ObjectClass::Cron);
        assert_eq!(
            classify_path_mode("/etc/systemd/system/x.service", reg),
            ObjectClass::SystemdUnit
        );
        assert_eq!(
            classify_path_mode("/lib/systemd/system/sshd.service", reg),
            ObjectClass::SystemdUnit
        );
        assert_eq!(classify_path_mode("/etc/shadow", reg), ObjectClass::Secret);
        assert_eq!(
            classify_path_mode("/home/u/.ssh/id_rsa", reg),
            ObjectClass::Secret
        );
        assert_eq!(
            classify_path_mode("/opt/app/server.pem", reg),
            ObjectClass::Secret
        );
        assert_eq!(
            classify_path_mode("/srv/app/.env", reg),
            ObjectClass::Secret
        );
        assert_eq!(
            classify_path_mode("/srv/app/aws_credentials.json", reg),
            ObjectClass::Secret
        );
        assert_eq!(
            classify_path_mode("/usr/bin/passwd", reg),
            ObjectClass::PathBinary
        );
        assert_eq!(
            classify_path_mode("/sbin/init", reg),
            ObjectClass::PathBinary
        );
        assert_eq!(
            classify_path_mode("/etc/ssh/sshd_config", reg),
            ObjectClass::Config
        );
        assert_eq!(
            classify_path_mode("/var/lib/app/data.db", reg),
            ObjectClass::Generic
        );
    }

    #[test]
    fn setuid_bit_dominates_path() {
        // A setuid regular file under /usr/bin is SetuidBinary, not PathBinary.
        assert_eq!(
            classify_path_mode("/usr/bin/sudo", 0o104_755),
            ObjectClass::SetuidBinary
        );
        // setgid regular file too.
        assert_eq!(
            classify_path_mode("/usr/bin/wall", 0o102_755),
            ObjectClass::SetuidBinary
        );
        // But a setgid DIRECTORY is the inheritance idiom, not a setuid binary.
        assert_eq!(
            classify_path_mode("/srv/shared", 0o042_775),
            ObjectClass::Generic
        );
    }

    #[test]
    fn classify_priority_sudoers_over_path_binary() {
        // A hypothetical sudoers drop-in path that also looks binary-ish: sudoers wins
        // because its row precedes the path-binary rows.
        assert_eq!(
            classify_path_mode("/etc/sudoers.d/90-cloud-init-users", 0o100_440),
            ObjectClass::Sudoers
        );
    }

    #[test]
    fn glob_segment_and_doublestar_semantics() {
        // `*` does not cross a segment boundary.
        assert!(glob_match("/etc/cron*/**", "/etc/cron.d/job"));
        assert!(
            !glob_match("/etc/cron*", "/etc/cron.d/job"),
            "* is one segment"
        );
        // `**` matches zero segments.
        assert!(glob_match("/a/**", "/a"));
        assert!(glob_match("/a/**", "/a/b/c"));
        // suffix / prefix / contains within a segment.
        assert!(glob_match("**/*.pem", "/x/y/server.pem"));
        assert!(glob_match("**/*credentials*", "/x/my_credentials_v2"));
        assert!(!glob_match("**/*.pem", "/x/server.pem.bak"));
    }

    // --- risk / severity ---

    #[test]
    fn risk_table() {
        let w = rwx(false, true, false);
        let r = rwx(true, false, false);
        assert_eq!(derive_risk(w, ObjectClass::Cron), Some(Risk::Escalation));
        assert_eq!(derive_risk(w, ObjectClass::Sudoers), Some(Risk::Escalation));
        assert_eq!(
            derive_risk(w, ObjectClass::SetuidBinary),
            Some(Risk::Escalation)
        );
        assert_eq!(derive_risk(w, ObjectClass::Secret), Some(Risk::Escalation));
        assert_eq!(derive_risk(w, ObjectClass::Config), Some(Risk::Tamper));
        assert_eq!(derive_risk(w, ObjectClass::Generic), Some(Risk::Tamper));
        assert_eq!(derive_risk(r, ObjectClass::Secret), Some(Risk::Leak));
        // read of a non-secret is NOT a finding.
        assert_eq!(derive_risk(r, ObjectClass::PathBinary), None);
        assert_eq!(derive_risk(r, ObjectClass::Config), None);
        // execute-only is not a finding.
        assert_eq!(
            derive_risk(rwx(false, false, true), ObjectClass::PathBinary),
            None
        );
    }

    #[test]
    fn severity_table() {
        assert_eq!(
            derive_severity(ObjectClass::Cron, Risk::Escalation),
            Severity::High
        );
        assert_eq!(
            derive_severity(ObjectClass::Secret, Risk::Leak),
            Severity::High
        );
        assert_eq!(
            derive_severity(ObjectClass::Config, Risk::Tamper),
            Severity::Medium
        );
        assert_eq!(
            derive_severity(ObjectClass::Generic, Risk::Tamper),
            Severity::Low
        );
    }

    // --- finding assembly + reachability gate ---

    #[test]
    fn cron_escalation_is_high_via_other_bits() {
        let rec = record("/var/spool/cron/crontabs/root", 0o100_666);
        let f = finding_for(
            &rec,
            rwx(true, true, false),
            &AccessVia::OtherBits,
            Some("svc"),
            true,
            &NoManagedContext,
        )
        .expect("write to cron is a finding");
        assert_eq!(f.class, ObjectClass::Cron);
        assert_eq!(f.risk, Risk::Escalation);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.principal.as_deref(), Some("svc"));
        assert_eq!(f.remediation_class, RemediationClass::Ambient);
    }

    #[test]
    fn secret_leak_is_high_via_other_bits() {
        let rec = record("/etc/shadow", 0o100_644);
        let f = finding_for(
            &rec,
            rwx(true, false, false),
            &AccessVia::OtherBits,
            None,
            true,
            &NoManagedContext,
        )
        .expect("world-readable secret is a finding");
        assert_eq!(f.class, ObjectClass::Secret);
        assert_eq!(f.risk, Risk::Leak);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.via, AccessVia::OtherBits);
        assert!(f.principal.is_none(), "global mode has no principal");
    }

    #[test]
    fn config_tamper_is_medium() {
        let rec = record("/etc/ssh/sshd_config", 0o100_666);
        let f = finding_for(
            &rec,
            rwx(true, true, false),
            &AccessVia::OtherBits,
            Some("svc"),
            true,
            &NoManagedContext,
        )
        .expect("config write is a finding");
        assert_eq!(f.class, ObjectClass::Config);
        assert_eq!(f.risk, Risk::Tamper);
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn generic_world_writable_is_low() {
        let rec = record("/var/lib/app/scratch", 0o100_666);
        let f = finding_for(
            &rec,
            rwx(true, true, false),
            &AccessVia::OtherBits,
            Some("svc"),
            true,
            &NoManagedContext,
        )
        .expect("generic write is a finding");
        assert_eq!(f.class, ObjectClass::Generic);
        assert_eq!(f.severity, Severity::Low);
    }

    #[test]
    fn unreachable_object_yields_no_finding() {
        let rec = record("/var/spool/cron/crontabs/root", 0o100_666);
        let f = finding_for(
            &rec,
            rwx(true, true, false),
            &AccessVia::OtherBits,
            Some("svc"),
            false, // unreachable
            &NoManagedContext,
        );
        assert!(f.is_none(), "an unreachable object is never a finding");
    }

    #[test]
    fn read_of_non_secret_yields_no_finding() {
        let rec = record("/usr/bin/ls", 0o100_755);
        let f = finding_for(
            &rec,
            rwx(true, false, true),
            &AccessVia::OtherBits,
            Some("svc"),
            true,
            &NoManagedContext,
        );
        assert!(
            f.is_none(),
            "reading a world-readable binary is not a finding"
        );
    }

    // --- remediation ---

    #[test]
    fn ambient_world_write_hint_is_chmod_no_autofix() {
        let (class, hint) = remediation(
            &AccessVia::OtherBits,
            "/var/spool/cron/crontabs/root",
            ObjectClass::Cron,
            rwx(false, true, false),
            &NoManagedContext,
        );
        assert_eq!(class, RemediationClass::Ambient);
        assert!(hint.contains("chmod o-w"), "hint: {hint}");
        assert!(
            hint.contains("manually"),
            "must not promise auto-fix: {hint}"
        );
    }

    #[test]
    fn ambient_secret_read_hint_is_chmod_640() {
        let (class, hint) = remediation(
            &AccessVia::OtherBits,
            "/etc/shadow",
            ObjectClass::Secret,
            rwx(true, false, false),
            &NoManagedContext,
        );
        assert_eq!(class, RemediationClass::Ambient);
        assert!(hint.contains("chmod 640"), "hint: {hint}");
    }

    #[test]
    fn ambient_acl_user_hint_is_setfacl() {
        let (class, hint) = remediation(
            &AccessVia::AclUser("role-x".to_owned()),
            "/etc/secret.key",
            ObjectClass::Secret,
            rwx(true, false, false),
            &NoManagedContext,
        );
        assert_eq!(class, RemediationClass::Ambient);
        assert!(hint.contains("setfacl -x u:role-x"), "hint: {hint}");
    }

    #[test]
    fn in_model_managed_group_hint_is_narrow_declaration() {
        let ctx = FakeContext {
            managed: std::iter::once("app".to_owned()).collect(),
            grants: Vec::new(),
        };
        let (class, hint) = remediation(
            &AccessVia::Group("app".to_owned()),
            "/srv/app/data",
            ObjectClass::Generic,
            rwx(false, true, false),
            &ctx,
        );
        assert_eq!(class, RemediationClass::InModel);
        assert!(hint.contains("group `app`"), "hint: {hint}");
        assert!(
            hint.contains("narrow"),
            "in-model hint must say narrow: {hint}"
        );
    }

    #[test]
    fn in_model_covering_grant_hint_points_at_grant() {
        let ctx = FakeContext {
            managed: BTreeSet::new(),
            grants: vec![(
                "/etc/ssh".to_owned(),
                "file-access rw on /etc/ssh".to_owned(),
            )],
        };
        let (class, hint) = remediation(
            &AccessVia::AclUser("role-x".to_owned()),
            "/etc/ssh/sshd_config",
            ObjectClass::Config,
            rwx(true, true, false),
            &ctx,
        );
        assert_eq!(class, RemediationClass::InModel);
        assert!(hint.contains("file-access grant"), "hint: {hint}");
    }

    #[test]
    fn unmanaged_group_via_is_ambient() {
        // A group `via` whose group is NOT managed stays ambient (chmod g-w).
        let (class, hint) = remediation(
            &AccessVia::Group("staff".to_owned()),
            "/srv/data",
            ObjectClass::Generic,
            rwx(false, true, false),
            &NoManagedContext,
        );
        assert_eq!(class, RemediationClass::Ambient);
        assert!(hint.contains("chmod g-w"), "hint: {hint}");
    }

    #[test]
    fn finding_serializes_to_json_tokens() {
        let rec = record("/etc/shadow", 0o100_644);
        let f = finding_for(
            &rec,
            rwx(true, false, false),
            &AccessVia::OtherBits,
            None,
            true,
            &NoManagedContext,
        )
        .expect("finding");
        let json = serde_json::to_value(&f).expect("serializes");
        assert_eq!(json["class"], "secret");
        assert_eq!(json["risk"], "leak");
        assert_eq!(json["severity"], "high");
        assert_eq!(json["remediation_class"], "ambient");
        assert_eq!(json["via"], "other_bits");
        assert_eq!(json["principal"], serde_json::Value::Null);
        assert_eq!(json["access"]["read"], true);
    }
}
