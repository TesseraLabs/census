//! The `audit expose` engine: per-principal exposure with intended-baseline
//! subtraction.
//!
//! ## What it produces
//!
//! [`expose`] runs the per-inode pipeline — effective access ([`effective`]) +
//! reachability ([`Reachability`]) + finding assembly ([`finding_for`]) — over the
//! whole index for one principal, yielding the raw set of reachable, risky accesses.
//! [`exposure_report`] wraps that with the killer filter: for a Census-managed
//! principal it subtracts the *intended baseline* (the account's home plus the paths
//! Census granted it) so only the EXCESS access beyond the least-privilege intent
//! remains; for a non-managed (arbitrary) uid there is no baseline and the raw
//! reachability is reported.
//!
//! ## Managed binding (the Срез-3 stub, now real)
//!
//! [`ManagedContext`] is the real [`RemediationContext`]: `is_managed_group` is backed
//! by the managed registry's group set and `covering_grant` by the principal's
//! recorded file-access grants, so a remaining finding is classed `in-model` (narrow
//! the declaration) when its access flows through a Census-owned group or grant, and
//! `ambient` otherwise. The registry is read through the injected [`SystemState`]
//! seam (production [`RegistryState`](crate::state::RegistryState), a fake in tests) —
//! the engine never hardcodes the `managed.toml` path.
//!
//! ## DAC-only verdict
//!
//! Every report carries [`DAC_ONLY_NOTE`]: the verdict is the discretionary-access
//! upper bound (mode + owner + POSIX ACL); MAC layers (`SELinux`, `AppArmor`, PARSEC)
//! may restrict actual access further.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::catalog::path_at_or_under;
use crate::state::SystemState;

use super::access::{effective, Principal};
use super::index::PermissionIndex;
use super::mac::{MacAccessKind, MacFinding, MacProvider};
use super::reach::Reachability;
use super::taxonomy::{finding_for, Finding, RemediationContext, Risk};

/// The DAC-only upper-bound caveat attached to every exposure report. The verdict
/// considers only discretionary access control; a MAC layer may restrict further.
pub const DAC_ONLY_NOTE: &str =
    "verdict is DAC-only (mode, owner, POSIX ACL) and is an upper bound: MAC layers \
     (SELinux, AppArmor, PARSEC) may restrict actual access further";

/// Run the exposure engine for `principal` over `index`, returning every reachable,
/// reportable access as a [`Finding`] (before any baseline subtraction).
///
/// For each indexed inode within `roots`, computes the principal's effective access,
/// checks reachability, and assembles a finding via [`finding_for`] (which drops
/// unreachable objects and non-risky accesses). `roots` gates the records considered,
/// a defense-in-depth bound so a stale or over-broad index cannot leak an out-of-scope
/// finding; an empty `roots` slice imposes no filter.
#[must_use]
pub fn expose(
    index: &PermissionIndex,
    principal: &Principal,
    roots: &[PathBuf],
    reachability: &Reachability,
    ctx: &dyn RemediationContext,
) -> Vec<Finding> {
    let roots: Vec<String> = roots
        .iter()
        .map(|r| r.to_string_lossy().into_owned())
        .collect();
    let mut findings: Vec<Finding> = Vec::new();
    for record in index.records() {
        if !within_roots(&record.path, &roots) {
            continue;
        }
        let eff = effective(record, principal);
        let reachable = reachability.is_reachable(&record.path);
        if let Some(finding) = finding_for(
            record,
            eff.access,
            &eff.via,
            Some(&principal.name),
            reachable,
            ctx,
        ) {
            findings.push(finding);
        }
    }
    findings
}

/// Whether `path` is within the scan roots (or `roots` is empty, meaning no filter).
fn within_roots(path: &str, roots: &[String]) -> bool {
    roots.is_empty() || roots.iter().any(|r| path_at_or_under(r, path))
}

/// Normalize and validate a baseline prefix (a home directory or a grant path),
/// returning the cleaned prefix or `None` if it is degenerate.
///
/// Trailing slashes are trimmed; the result must be a non-empty absolute path other
/// than the filesystem root. A degenerate prefix (`""`, `"/"`) is rejected because it
/// would make [`path_at_or_under`] match every path and silently subtract ALL excess
/// access — a total false negative reading as a clean audit.
fn valid_baseline_prefix(raw: &str) -> Option<String> {
    let trimmed = raw.trim_end_matches('/');
    (!trimmed.is_empty() && trimmed.starts_with('/')).then(|| trimmed.to_owned())
}

/// The path prefixes a managed principal's access is *supposed* to reach.
///
/// These are its home directory and the paths Census granted it. A finding whose path
/// lies under any of these is intended, not excess, and is subtracted.
#[derive(Debug, Clone, Default)]
pub struct IntendedBaseline {
    /// `(prefix, recursive)` pairs. A recursive prefix covers its whole subtree; a
    /// non-recursive one covers only the exact path (a single-file grant).
    prefixes: Vec<(String, bool)>,
}

impl IntendedBaseline {
    /// Whether `path` is covered by the baseline (at or under a recursive prefix, or
    /// equal to a non-recursive one).
    #[must_use]
    pub fn covers(&self, path: &str) -> bool {
        self.prefixes.iter().any(|(prefix, recursive)| {
            prefix == path || (*recursive && path_at_or_under(prefix, path))
        })
    }

    /// Drop every finding whose path the baseline covers, leaving only excess access.
    #[must_use]
    pub fn subtract(&self, findings: Vec<Finding>) -> Vec<Finding> {
        findings
            .into_iter()
            .filter(|f| !self.covers(&f.path))
            .collect()
    }

    /// Whether the baseline has no covered prefixes.
    #[allow(
        clippy::missing_const_for_fn,
        reason = "Vec::is_empty is not const-stable on the older musl cross toolchain used for the Astra target"
    )]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty()
    }
}

/// The real [`RemediationContext`] and intended-baseline source, built from the
/// managed registry for one principal.
///
/// Holds whether the principal is managed, its intended baseline (home + granted
/// paths), the grant prefixes (for `covering_grant`), and the registry's managed group
/// set (for `is_managed_group`).
#[derive(Debug, Clone, Default)]
pub struct ManagedContext {
    managed: bool,
    baseline: IntendedBaseline,
    /// `(grant_path, recursive)` the principal's role was granted, for in-model
    /// attribution of a remaining finding.
    grants: Vec<(String, bool)>,
    managed_groups: BTreeSet<String>,
}

impl ManagedContext {
    /// Build the context for `principal` from the managed registry `state`.
    ///
    /// The principal is managed when an account in the registry matches its name or
    /// uid. For a managed principal the baseline is its home (from the passwd-derived
    /// [`Principal::home`]) plus its recorded file-access grants; for a non-managed
    /// principal the baseline is empty (raw reachability). The managed group set comes
    /// from the registry regardless, so a finding's group attribution is judged
    /// against what Census actually manages.
    #[must_use]
    pub fn for_principal(state: &dyn SystemState, principal: &Principal) -> Self {
        let accounts = state.managed_accounts();
        // Bind precedence: an exact (name AND uid) match first, then a name-only
        // match, then a uid-only match. Matching on EITHER alone would let a uid
        // alias or an orphan-uid collision bind a foreign account's baseline (and be
        // non-deterministic when name and uid point at different accounts); the
        // ordering makes it deterministic and prefers the principal's own identity. A
        // partial match still binds (a uid drift is a legitimate same-account case)
        // but is logged.
        let account = accounts
            .values()
            .find(|a| a.name == principal.name && a.uid == principal.uid)
            .or_else(|| {
                accounts.values().find(|a| a.name == principal.name).inspect(|a| {
                    tracing::warn!(
                        principal = %principal.name,
                        uid = principal.uid,
                        registry_uid = a.uid,
                        "managed account matched by name only (uid differs); binding its baseline"
                    );
                })
            })
            .or_else(|| {
                accounts.values().find(|a| a.uid == principal.uid).inspect(|a| {
                    tracing::warn!(
                        principal = %principal.name,
                        uid = principal.uid,
                        registry_name = %a.name,
                        "managed account matched by uid only (name differs); binding its baseline"
                    );
                })
            });

        let managed = account.is_some();

        // Grant prefixes, with degenerate paths rejected (see `valid_baseline_prefix`):
        // an empty or `/` grant path would make `path_at_or_under` match every path
        // and silently subtract ALL excess access, reading as a clean audit.
        let mut grants: Vec<(String, bool)> = Vec::new();
        if let Some(account) = account {
            for grant in &account.file_grants {
                if let Some(prefix) = valid_baseline_prefix(&grant.path) {
                    grants.push((prefix, grant.recursive));
                } else {
                    tracing::warn!(
                        principal = %principal.name,
                        grant = %grant.path,
                        "managed grant path is empty or '/'; not used as a baseline prefix \
                         (it would hide all excess access)"
                    );
                }
            }
        }

        let mut prefixes = grants.clone();
        if managed {
            if let Some(home) = &principal.home {
                let home = home.to_string_lossy();
                // The home subtree is intended access — but only when it is a real
                // absolute path. A passwd entry with an empty home (`svc::…`) or a
                // daemon home of `/` must NOT become an all-covering baseline prefix.
                if let Some(prefix) = valid_baseline_prefix(&home) {
                    prefixes.push((prefix, true));
                } else {
                    tracing::warn!(
                        principal = %principal.name,
                        home = %home,
                        "principal home is empty or '/'; not used as a baseline prefix \
                         (it would hide all excess access)"
                    );
                }
            }
        }

        let managed_groups: BTreeSet<String> = state.managed_groups().into_keys().collect();

        Self {
            managed,
            baseline: IntendedBaseline { prefixes },
            grants,
            managed_groups,
        }
    }

    /// A principal-independent context for the global posture map (`audit fs`): no
    /// account binding and no baseline, but the registry's managed group set is
    /// populated so a broad-group-writable finding whose group Census manages is
    /// still classed `in-model`.
    #[must_use]
    pub fn global(state: &dyn SystemState) -> Self {
        Self {
            managed: false,
            baseline: IntendedBaseline::default(),
            grants: Vec::new(),
            managed_groups: state.managed_groups().into_keys().collect(),
        }
    }

    /// Whether the principal is Census-managed (and so subject to baseline
    /// subtraction).
    #[must_use]
    pub const fn is_managed(&self) -> bool {
        self.managed
    }

    /// The intended baseline (home + granted paths) for the principal.
    #[must_use]
    pub const fn baseline(&self) -> &IntendedBaseline {
        &self.baseline
    }
}

impl RemediationContext for ManagedContext {
    fn is_managed_group(&self, group: &str) -> bool {
        self.managed_groups.contains(group)
    }

    fn covering_grant(&self, path: &str) -> Option<String> {
        self.grants
            .iter()
            .find(|(prefix, recursive)| {
                prefix == path || (*recursive && path_at_or_under(prefix, path))
            })
            .map(|(prefix, _)| format!("file-access grant on {prefix}"))
    }
}

/// A per-principal exposure report for the JSON / text output.
///
/// Carries the (baseline-subtracted) findings plus the managed flag, the DAC-only
/// caveat, and the mounts the walk skipped. Its serialized shape is the locked
/// `exposure-report.schema.json` contract.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ExposureReport {
    /// The principal the report is for.
    pub principal: String,
    /// Whether the principal is Census-managed (baseline subtraction applied).
    pub managed: bool,
    /// The findings: excess access for a managed principal, raw reachability for a
    /// non-managed uid.
    pub findings: Vec<Finding>,
    /// The DAC-only upper-bound caveat ([`DAC_ONLY_NOTE`]).
    // Under the null provider this is the DAC-only note; when a real MAC provider is
    // active it is the formatted `DAC + <system>` note instead, hence `String` rather
    // than a `&'static str`. The doc line above is kept verbatim so the generated schema
    // `description` (which mirrors it) matches the locked golden until it is regenerated.
    pub dac_only_note: String,
    /// Mounts the walk did not descend (network/pseudo), so the reader knows coverage
    /// was trimmed.
    pub skipped_mounts: Vec<super::index::SkippedMount>,
}

/// Produce the full exposure report for `principal`.
///
/// Runs [`expose`], subtracts the intended baseline for a managed principal, then
/// refines the surviving findings against mandatory access control via `mac`.
///
/// `state` is the managed registry seam (injected, so tests use a fake). `mac` is the
/// MAC-provider seam ([`MacProvider`]): the open-build default is
/// [`NullMacProvider`](super::mac::NullMacProvider), under which the refinement is a
/// no-op — every finding is kept with no annotation and the report carries the
/// DAC-only caveat. With a real provider active the verdict becomes DAC ∧ MAC: a
/// finding the provider blocks in every assumable context is suppressed, one it
/// permits is annotated with the reachable contexts, and the note becomes
/// `DAC + <system>`.
#[must_use]
pub fn exposure_report(
    index: &PermissionIndex,
    principal: &Principal,
    roots: &[PathBuf],
    reachability: &Reachability,
    state: &dyn SystemState,
    mac: &dyn MacProvider,
) -> ExposureReport {
    let ctx = ManagedContext::for_principal(state, principal);
    let raw = expose(index, principal, roots, reachability, &ctx);
    let subtracted = if ctx.is_managed() {
        ctx.baseline().subtract(raw)
    } else {
        raw
    };
    let findings = refine_with_mac(subtracted, principal.uid, mac);
    let dac_only_note = if mac.is_active() {
        format!("DAC + {}", mac.system().as_str())
    } else {
        DAC_ONLY_NOTE.to_owned()
    };
    ExposureReport {
        principal: principal.name.clone(),
        managed: ctx.is_managed(),
        findings,
        dac_only_note,
        skipped_mounts: index.skipped_mounts().to_vec(),
    }
}

/// The [`MacAccessKind`] a finding's [`Risk`] must be checked against under mandatory
/// access control.
///
/// A write-exposure risk — escalation (write a privileged object) or tamper — is a
/// write check; a secret leak is a read check. The taxonomy never emits an
/// execute-only finding (a bare execute is not a reportable risk), so no risk maps to
/// [`MacAccessKind::Execute`]; that variant exists for a backend that models execute
/// permission but is unused by this mapping.
const fn mac_access_for_risk(risk: Risk) -> MacAccessKind {
    match risk {
        Risk::Escalation | Risk::Tamper => MacAccessKind::Write,
        Risk::Leak => MacAccessKind::Read,
    }
}

/// Refine DAC findings against mandatory access control, layered on top of the pure-DAC
/// findings (it never re-runs the DAC check).
///
/// With an inactive provider (the null default) the findings pass through unchanged —
/// none annotated, none suppressed.
///
/// With a real provider active, a finding is refined only when both its object is
/// labeled AND the principal has at least one assumable context. Otherwise it is kept
/// unannotated: an unlabeled object or an empty context set is *absence of MAC data*
/// (the uid may not be enrolled, or the backend may be in a partial state), not proof
/// the access is unreachable — suppressing on missing data would hide a real,
/// DAC-reachable hole. When both are present, the contexts are filtered to those the
/// label permits the finding's access kind: an empty result means the label denies the
/// access in every assumable context (provably unreachable) and the finding is
/// suppressed; a non-empty result annotates the finding with those contexts, sorted for
/// a deterministic report.
fn refine_with_mac(findings: Vec<Finding>, uid: u32, mac: &dyn MacProvider) -> Vec<Finding> {
    if !mac.is_active() {
        return findings;
    }
    let system = mac.system();
    // The principal's assumable contexts are constant across the whole report, so query
    // the backend once here rather than per finding (a real backend call is not free).
    let contexts = mac.principal_contexts(uid);
    findings
        .into_iter()
        .filter_map(|mut finding| {
            let Some(label) = mac.object_label(&finding.path) else {
                // Unlabeled object: no MAC data, keep the DAC finding as-is.
                return Some(finding);
            };
            if contexts.is_empty() {
                // No assumable context for the principal is missing data, not proof of
                // unreachability, so keep the DAC finding rather than suppress it.
                return Some(finding);
            }
            let kind = mac_access_for_risk(finding.risk);
            let mut reachable_in: Vec<String> = contexts
                .iter()
                .filter(|ctx| mac.permits(**ctx, label, kind))
                .map(|ctx| mac.render_context(*ctx))
                .collect();
            if reachable_in.is_empty() {
                // The principal has contexts but the label permits the access in none of
                // them — provably unreachable under MAC, so suppress the finding.
                return None;
            }
            // `principal_contexts` is an unordered set by contract; sort the rendered
            // contexts so the annotation is stable across runs and report diffs are real.
            reachable_in.sort_unstable();
            finding.mac = Some(MacFinding {
                system,
                object_label: Some(mac.render_label(label)),
                reachable_in,
            });
            Some(finding)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::exposure::index::{FakeWalker, InodeStat};
    use crate::exposure::{
        remediation, AccessVia, AclPerms, FakeAclSource, FakeMacProvider, MacContextId, MacLabelId,
        MacSystem, NullMacProvider, ObjectClass, RemediationClass,
    };
    use crate::model::Provenance;
    use crate::state::{FakeState, ManagedAccount, ManagedFileGrant, ManagedGroup};

    fn dir(path: &str, gid: u32, mode: u32) -> InodeStat {
        InodeStat {
            path: path.to_owned(),
            uid: 0,
            gid,
            mode: 0o040_000 | mode,
            is_dir: true,
        }
    }

    fn file(path: &str, gid: u32, mode: u32) -> InodeStat {
        InodeStat {
            path: path.to_owned(),
            uid: 0,
            gid,
            mode: 0o100_000 | mode,
            is_dir: false,
        }
    }

    /// Build an index + reachability for a tree of canned stats rooted at `/`.
    fn index_and_reach(
        stats: Vec<InodeStat>,
        principal: &Principal,
    ) -> (PermissionIndex, Vec<PathBuf>, Reachability) {
        let mut walker = FakeWalker::new();
        for s in stats {
            walker = walker.with(s);
        }
        let mut acl = FakeAclSource::new();
        let roots = vec![PathBuf::from("/")];
        let index = PermissionIndex::build(&walker, &mut acl, &roots).expect("build");
        let reach = Reachability::compute(&index, principal, &roots);
        (index, roots, reach)
    }

    fn managed_state_with_grant() -> FakeState {
        let mut accounts = BTreeMap::new();
        accounts.insert(
            "svc".to_owned(),
            ManagedAccount {
                name: "svc".to_owned(),
                uid: 5012,
                shell: "/bin/bash".to_owned(),
                groups: vec![],
                sudo_role: None,
                sudo_commands: vec![],
                file_grants: vec![ManagedFileGrant {
                    path: "/etc/ssh".to_owned(),
                    access: crate::catalog::Access::RW,
                    recursive: true,
                }],
                provenance: Provenance::Created,
                from_version: 1,
            },
        );
        FakeState {
            accounts,
            groups: BTreeMap::new(),
        }
    }

    /// The standard world-traversable directory chain plus three world-writable
    /// targets: one under the granted `/etc/ssh`, one ambient cron spool, one under
    /// the principal's home.
    fn exposed_tree() -> Vec<InodeStat> {
        vec![
            dir("/", 0, 0o755),
            dir("/etc", 0, 0o755),
            dir("/etc/ssh", 0, 0o755),
            file("/etc/ssh/sshd_config", 0, 0o666), // under grant → intended
            dir("/var", 0, 0o755),
            dir("/var/spool", 0, 0o755),
            dir("/var/spool/cron", 0, 0o755),
            dir("/var/spool/cron/crontabs", 0, 0o755),
            file("/var/spool/cron/crontabs/root", 0, 0o666), // ambient excess
            dir("/home", 0, 0o755),
            dir("/home/svc", 0, 0o755),
            file("/home/svc/.bashrc", 0, 0o666), // under home → intended
        ]
    }

    #[test]
    fn managed_principal_keeps_only_excess_beyond_baseline() {
        // svc is managed with a grant on /etc/ssh and home /home/svc. It writes to all
        // three world-writable targets; the report must keep ONLY /var/spool/cron
        // (the grant path and the home are subtracted as intended).
        let principal = Principal::new("svc", 5012, vec![]).with_home("/home/svc");
        let (index, roots, reach) = index_and_reach(exposed_tree(), &principal);
        let state = managed_state_with_grant();

        let report = exposure_report(&index, &principal, &roots, &reach, &state, &NullMacProvider);
        assert!(report.managed, "svc is in the registry");
        let paths: Vec<&str> = report.findings.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["/var/spool/cron/crontabs/root"],
            "only the excess cron access remains; grant + home subtracted"
        );
    }

    #[test]
    fn non_managed_uid_reports_raw_reachability() {
        // An arbitrary uid not in the registry: no baseline, so ALL reachable excess
        // (including what would be under a home/grant for a managed account) is kept.
        let principal = Principal::new("5099", 5099, vec![]).with_home("/home/svc");
        let (index, roots, reach) = index_and_reach(exposed_tree(), &principal);
        let state = FakeState::default(); // empty registry → not managed

        let report = exposure_report(&index, &principal, &roots, &reach, &state, &NullMacProvider);
        assert!(!report.managed, "uid 5099 is not in the registry");
        let mut paths: Vec<&str> = report.findings.iter().map(|f| f.path.as_str()).collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec![
                "/etc/ssh/sshd_config",
                "/home/svc/.bashrc",
                "/var/spool/cron/crontabs/root",
            ],
            "no subtraction → all reachable excess reported"
        );
    }

    #[test]
    fn dac_only_note_present_in_report() {
        let principal = Principal::new("5099", 5099, vec![]);
        let (index, roots, reach) = index_and_reach(exposed_tree(), &principal);
        let report = exposure_report(
            &index,
            &principal,
            &roots,
            &reach,
            &FakeState::default(),
            &NullMacProvider,
        );
        assert!(
            report.dac_only_note.contains("DAC-only"),
            "report carries the DAC-only upper-bound caveat"
        );
        assert!(report.dac_only_note.contains("MAC"));
    }

    #[test]
    fn managed_group_via_is_in_model_foreign_group_is_ambient() {
        // A registry whose managed groups include `app`. A finding granted through a
        // group named `app` is in-model (narrow the declaration); one through a
        // foreign group `staff` is ambient.
        let mut groups = BTreeMap::new();
        groups.insert(
            "app".to_owned(),
            ManagedGroup {
                name: "app".to_owned(),
                gid: Some(50),
                provenance: Provenance::Created,
                members_added: vec![],
                sudo_commands: vec![],
                file_grants: vec![],
                adopt_baseline: None,
                from_version: 1,
            },
        );
        let state = FakeState {
            accounts: BTreeMap::new(),
            groups,
        };
        let principal = Principal::new("svc", 5012, vec![]);
        let ctx = ManagedContext::for_principal(&state, &principal);

        assert!(ctx.is_managed_group("app"), "app is a managed group");
        assert!(!ctx.is_managed_group("staff"), "staff is foreign");

        // And the remediation classification reflects it.
        let (managed_class, managed_hint) = remediation(
            &AccessVia::Group("app".to_owned()),
            "/srv/app/data",
            ObjectClass::Generic,
            AclPerms {
                read: false,
                write: true,
                execute: false,
            },
            &ctx,
        );
        assert_eq!(managed_class, RemediationClass::InModel);
        assert!(managed_hint.contains("narrow"));

        let (foreign_class, _) = remediation(
            &AccessVia::Group("staff".to_owned()),
            "/srv/data",
            ObjectClass::Generic,
            AclPerms {
                read: false,
                write: true,
                execute: false,
            },
            &ctx,
        );
        assert_eq!(foreign_class, RemediationClass::Ambient);
    }

    #[test]
    fn covering_grant_matches_granted_subtree_only() {
        let state = managed_state_with_grant();
        let principal = Principal::new("svc", 5012, vec![]).with_home("/home/svc");
        let ctx = ManagedContext::for_principal(&state, &principal);
        assert!(ctx.is_managed());
        assert_eq!(
            ctx.covering_grant("/etc/ssh/sshd_config").as_deref(),
            Some("file-access grant on /etc/ssh")
        );
        assert!(ctx.covering_grant("/etc/passwd").is_none());
    }

    #[test]
    fn expose_engine_is_pure_without_subtraction() {
        // The raw engine reports every reachable excess; subtraction is a separate
        // layer (`exposure_report`), so `expose` alone keeps the granted/home paths.
        let principal = Principal::new("svc", 5012, vec![]).with_home("/home/svc");
        let (index, roots, reach) = index_and_reach(exposed_tree(), &principal);
        let ctx = ManagedContext::for_principal(&managed_state_with_grant(), &principal);
        let raw = expose(&index, &principal, &roots, &reach, &ctx);
        assert_eq!(raw.len(), 3, "raw engine does not subtract the baseline");
    }

    // --- regression: degenerate baseline prefixes (H1) ---

    fn run_with_home(home: &str) -> Vec<String> {
        // A managed principal whose passwd home is `home`, with a grant on /etc/ssh.
        let principal = Principal::new("svc", 5012, vec![]).with_home(home);
        let (index, roots, reach) = index_and_reach(exposed_tree(), &principal);
        let report = exposure_report(
            &index,
            &principal,
            &roots,
            &reach,
            &managed_state_with_grant(),
            &NullMacProvider,
        );
        assert!(report.managed);
        report.findings.into_iter().map(|f| f.path).collect()
    }

    #[test]
    fn empty_home_is_not_an_all_covering_baseline() {
        // A passwd entry with an empty home (`svc::…:/bin/bash`) must NOT subtract
        // every finding. The /etc/ssh grant still subtracts its subtree, but the home
        // and cron excess remain — the audit is NOT silently clean.
        let mut paths = run_with_home("");
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec!["/home/svc/.bashrc", "/var/spool/cron/crontabs/root"],
            "empty home must not hide all excess"
        );
    }

    #[test]
    fn root_home_is_not_an_all_covering_baseline() {
        // A daemon home of `/` must likewise not become an all-covering prefix.
        let mut paths = run_with_home("/");
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec!["/home/svc/.bashrc", "/var/spool/cron/crontabs/root"],
            "`/` home must not hide all excess"
        );
    }

    #[test]
    fn degenerate_grant_path_is_not_a_baseline() {
        // A managed account whose recorded grant path is `/` must not subtract
        // everything; with a valid home, only the home subtree is subtracted.
        let mut accounts = BTreeMap::new();
        accounts.insert(
            "svc".to_owned(),
            ManagedAccount {
                name: "svc".to_owned(),
                uid: 5012,
                shell: "/bin/bash".to_owned(),
                groups: vec![],
                sudo_role: None,
                sudo_commands: vec![],
                file_grants: vec![ManagedFileGrant {
                    path: "/".to_owned(), // degenerate
                    access: crate::catalog::Access::RW,
                    recursive: true,
                }],
                provenance: Provenance::Created,
                from_version: 1,
            },
        );
        let state = FakeState {
            accounts,
            groups: BTreeMap::new(),
        };
        let principal = Principal::new("svc", 5012, vec![]).with_home("/home/svc");
        let (index, roots, reach) = index_and_reach(exposed_tree(), &principal);
        let report = exposure_report(&index, &principal, &roots, &reach, &state, &NullMacProvider);
        let mut paths: Vec<&str> = report.findings.iter().map(|f| f.path.as_str()).collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec!["/etc/ssh/sshd_config", "/var/spool/cron/crontabs/root"],
            "the `/` grant must not subtract everything; only the home subtree is intended"
        );
    }

    // --- regression: bind precedence, uid collision (M1) ---

    #[test]
    fn name_match_wins_over_uid_collision() {
        // The principal is svc/5012. The registry holds the real `svc` account at a
        // DIFFERENT uid (a uid drift) and an unrelated `daemon` account that happens
        // to own uid 5012. Name precedence must bind `svc`, never the uid-colliding
        // `daemon`, so `daemon`'s foreign baseline is not subtracted.
        let mut accounts = BTreeMap::new();
        accounts.insert(
            "svc".to_owned(),
            ManagedAccount {
                name: "svc".to_owned(),
                uid: 9001, // uid drift vs the principal's 5012
                shell: "/bin/bash".to_owned(),
                groups: vec![],
                sudo_role: None,
                sudo_commands: vec![],
                file_grants: vec![ManagedFileGrant {
                    path: "/etc/svc-area".to_owned(),
                    access: crate::catalog::Access::RW,
                    recursive: true,
                }],
                provenance: Provenance::Created,
                from_version: 1,
            },
        );
        accounts.insert(
            "daemon".to_owned(),
            ManagedAccount {
                name: "daemon".to_owned(),
                uid: 5012, // collides with the principal's uid
                shell: "/usr/sbin/nologin".to_owned(),
                groups: vec![],
                sudo_role: None,
                sudo_commands: vec![],
                file_grants: vec![ManagedFileGrant {
                    path: "/etc/daemon-area".to_owned(),
                    access: crate::catalog::Access::RW,
                    recursive: true,
                }],
                provenance: Provenance::Created,
                from_version: 1,
            },
        );
        let state = FakeState {
            accounts,
            groups: BTreeMap::new(),
        };
        let principal = Principal::new("svc", 5012, vec![]);
        let ctx = ManagedContext::for_principal(&state, &principal);
        assert!(ctx.is_managed());
        assert_eq!(
            ctx.covering_grant("/etc/svc-area/x").as_deref(),
            Some("file-access grant on /etc/svc-area"),
            "binds the name-matched account svc"
        );
        assert!(
            ctx.covering_grant("/etc/daemon-area/x").is_none(),
            "must NOT bind the uid-colliding daemon's baseline"
        );
    }

    // --- regression: grant in-model only via a Census ACL entry (M2) ---

    #[test]
    fn world_writable_under_grant_is_ambient_not_in_model() {
        // A world-writable file UNDER a Census grant: the access comes from the other
        // bits, not the grant's ACL entry. Narrowing the grant would not remove world
        // write, so the source is ambient (chmod), not in-model.
        let ctx = ManagedContext::for_principal(
            &managed_state_with_grant(),
            &Principal::new("svc", 5012, vec![]).with_home("/home/svc"),
        );
        let (ambient_class, ambient_hint) = remediation(
            &AccessVia::OtherBits,
            "/etc/ssh/sshd_config", // under the /etc/ssh grant
            ObjectClass::Config,
            AclPerms {
                read: false,
                write: true,
                execute: false,
            },
            &ctx,
        );
        assert_eq!(
            ambient_class,
            RemediationClass::Ambient,
            "world-write under a grant is ambient, not in-model"
        );
        assert!(ambient_hint.contains("chmod o-w"), "hint: {ambient_hint}");

        // The dual: the SAME path reached through the grant's own ACL user entry IS
        // in-model (narrow the grant).
        let (acl_class, acl_hint) = remediation(
            &AccessVia::AclUser("svc".to_owned()),
            "/etc/ssh/sshd_config",
            ObjectClass::Config,
            AclPerms {
                read: true,
                write: true,
                execute: false,
            },
            &ctx,
        );
        assert_eq!(acl_class, RemediationClass::InModel);
        assert!(acl_hint.contains("file-access grant"), "hint: {acl_hint}");
    }

    // --- DAC ∧ MAC composite (Fake provider) ---

    /// A world-traversable chain to a world-readable secret (`/etc/shadow`, mode 0644):
    /// a non-owner principal reads it via the other bits → a secret-leak finding.
    fn secret_tree() -> Vec<InodeStat> {
        vec![
            dir("/", 0, 0o755),
            dir("/etc", 0, 0o755),
            file("/etc/shadow", 0, 0o644),
        ]
    }

    /// The three excess paths a non-managed uid reaches in [`exposed_tree`].
    const EXCESS_PATHS: [&str; 3] = [
        "/etc/ssh/sshd_config",
        "/home/svc/.bashrc",
        "/var/spool/cron/crontabs/root",
    ];

    #[test]
    fn null_provider_keeps_findings_unannotated_and_dac_note() {
        // Snapshot parity: under the null provider the report is exactly the pre-change
        // DAC output — same findings, every `mac` None, the DAC-only note, and no `mac`
        // key in the serialized finding.
        let principal = Principal::new("5099", 5099, vec![]);
        let (index, roots, reach) = index_and_reach(exposed_tree(), &principal);
        let report = exposure_report(
            &index,
            &principal,
            &roots,
            &reach,
            &FakeState::default(),
            &NullMacProvider,
        );
        let mut paths: Vec<&str> = report.findings.iter().map(|f| f.path.as_str()).collect();
        paths.sort_unstable();
        assert_eq!(paths, EXCESS_PATHS);
        assert!(
            report.findings.iter().all(|f| f.mac.is_none()),
            "null provider annotates nothing"
        );
        assert_eq!(
            report.dac_only_note, DAC_ONLY_NOTE,
            "note unchanged under the null provider"
        );
        let json = serde_json::to_string(&report.findings[0]).expect("serialize finding");
        assert!(
            !json.contains("\"mac\""),
            "the mac key is omitted when None: {json}"
        );
    }

    #[test]
    fn mac_suppresses_finding_blocked_in_every_context() {
        // Every excess path is labeled and the principal's one assumable context
        // permits nothing (default-deny) → all findings suppressed, and the note
        // reflects the active system.
        let principal = Principal::new("5099", 5099, vec![]);
        let (index, roots, reach) = index_and_reach(exposed_tree(), &principal);
        let label = MacLabelId::new(1);
        let ctx = MacContextId::new(1);
        let mut mac = FakeMacProvider::new(MacSystem::Parsec);
        for path in EXCESS_PATHS {
            mac.with_label(path, label, "secret_t");
        }
        mac.with_context(5099, ctx, "low_t");
        let report = exposure_report(
            &index,
            &principal,
            &roots,
            &reach,
            &FakeState::default(),
            &mac,
        );
        assert!(
            report.findings.is_empty(),
            "MAC blocks every finding in the only context → all suppressed"
        );
        assert_eq!(
            report.dac_only_note, "DAC + parsec",
            "an active provider changes the note"
        );
    }

    #[test]
    fn labeled_object_with_no_principal_contexts_is_kept_unannotated() {
        // An empty context set is absence of MAC data about the principal (uid not
        // enrolled, or partial backend state), not proof of unreachability. A labeled,
        // DAC-reachable finding must be KEPT (mac=None), never suppressed — suppressing
        // on missing data would hide the hole (fail-open false negative).
        let principal = Principal::new("5099", 5099, vec![]);
        let (index, roots, reach) = index_and_reach(exposed_tree(), &principal);
        let label = MacLabelId::new(1);
        let mut mac = FakeMacProvider::new(MacSystem::Parsec);
        for path in EXCESS_PATHS {
            mac.with_label(path, label, "secret_t");
        }
        // No `with_context` calls → `principal_contexts(5099)` is empty.
        let report = exposure_report(
            &index,
            &principal,
            &roots,
            &reach,
            &FakeState::default(),
            &mac,
        );
        let mut paths: Vec<&str> = report.findings.iter().map(|f| f.path.as_str()).collect();
        paths.sort_unstable();
        assert_eq!(
            paths, EXCESS_PATHS,
            "empty principal contexts must not suppress DAC-reachable findings"
        );
        assert!(
            report.findings.iter().all(|f| f.mac.is_none()),
            "no MAC data on the principal → no annotation"
        );
    }

    #[test]
    fn reachable_contexts_are_sorted_for_determinism() {
        // Two permitting contexts registered out of sorted order; the annotation must be
        // sorted by rendered string so report comparisons are stable across runs (the
        // context set is unordered by contract).
        let principal = Principal::new("5099", 5099, vec![]);
        let (index, roots, reach) = index_and_reach(exposed_tree(), &principal);
        let label = MacLabelId::new(9);
        let ctx_z = MacContextId::new(1);
        let ctx_a = MacContextId::new(2);
        let mut mac = FakeMacProvider::new(MacSystem::Selinux);
        mac.with_label("/var/spool/cron/crontabs/root", label, "cron_t")
            .with_context(5099, ctx_z, "z_ctx")
            .with_context(5099, ctx_a, "a_ctx")
            .set_permit(ctx_z, label, MacAccessKind::Write, true)
            .set_permit(ctx_a, label, MacAccessKind::Write, true);
        let report = exposure_report(
            &index,
            &principal,
            &roots,
            &reach,
            &FakeState::default(),
            &mac,
        );
        let cron = report
            .findings
            .iter()
            .find(|f| f.path == "/var/spool/cron/crontabs/root")
            .expect("cron finding kept");
        let ann = cron.mac.as_ref().expect("cron finding annotated");
        assert_eq!(
            ann.reachable_in,
            vec!["a_ctx".to_owned(), "z_ctx".to_owned()],
            "sorted regardless of context insertion order"
        );
    }

    #[test]
    fn mac_annotates_finding_reachable_in_some_context() {
        // Only the cron path is labeled; the write access is permitted in context Y but
        // not X → the finding survives annotated with just Y. The unlabeled paths remain
        // unannotated.
        let principal = Principal::new("5099", 5099, vec![]);
        let (index, roots, reach) = index_and_reach(exposed_tree(), &principal);
        let label = MacLabelId::new(7);
        let ctx_x = MacContextId::new(1);
        let ctx_y = MacContextId::new(2);
        let mut mac = FakeMacProvider::new(MacSystem::Selinux);
        mac.with_label("/var/spool/cron/crontabs/root", label, "cron_t")
            .with_context(5099, ctx_x, "x_t")
            .with_context(5099, ctx_y, "y_t")
            .set_permit(ctx_y, label, MacAccessKind::Write, true)
            .set_permit(ctx_x, label, MacAccessKind::Write, false);
        let report = exposure_report(
            &index,
            &principal,
            &roots,
            &reach,
            &FakeState::default(),
            &mac,
        );
        let cron = report
            .findings
            .iter()
            .find(|f| f.path == "/var/spool/cron/crontabs/root")
            .expect("cron finding kept");
        let ann = cron.mac.as_ref().expect("cron finding annotated");
        assert_eq!(ann.system, MacSystem::Selinux);
        assert_eq!(
            ann.object_label.as_deref(),
            Some("cron_t"),
            "the object's rendered label enriches the finding"
        );
        assert_eq!(
            ann.reachable_in,
            vec!["y_t".to_owned()],
            "only the permitting context is rendered"
        );
        let unlabeled = report
            .findings
            .iter()
            .find(|f| f.path == "/home/svc/.bashrc")
            .expect("unlabeled finding kept");
        assert!(
            unlabeled.mac.is_none(),
            "an unlabeled object carries no MAC annotation"
        );
    }

    #[test]
    fn active_provider_keeps_unlabeled_findings_without_annotation() {
        // A provider that labels nothing leaves every finding intact (no MAC data to
        // suppress with) and unannotated, but still stamps the active-system note.
        let principal = Principal::new("5099", 5099, vec![]);
        let (index, roots, reach) = index_and_reach(exposed_tree(), &principal);
        let mac = FakeMacProvider::new(MacSystem::Parsec);
        let report = exposure_report(
            &index,
            &principal,
            &roots,
            &reach,
            &FakeState::default(),
            &mac,
        );
        let mut paths: Vec<&str> = report.findings.iter().map(|f| f.path.as_str()).collect();
        paths.sort_unstable();
        assert_eq!(paths, EXCESS_PATHS);
        assert!(report.findings.iter().all(|f| f.mac.is_none()));
        assert_eq!(report.dac_only_note, "DAC + parsec");
    }

    #[test]
    fn risk_maps_to_mac_access_kind() {
        assert_eq!(mac_access_for_risk(Risk::Leak), MacAccessKind::Read);
        assert_eq!(mac_access_for_risk(Risk::Escalation), MacAccessKind::Write);
        assert_eq!(mac_access_for_risk(Risk::Tamper), MacAccessKind::Write);
    }

    #[test]
    fn leak_finding_is_checked_against_read_permission() {
        // A world-readable secret is a Leak: the composite must check READ. The provider
        // permits read (denies write) in the principal's context → the finding survives.
        let principal = Principal::new("5099", 5099, vec![]);
        let (index, roots, reach) = index_and_reach(secret_tree(), &principal);
        let label = MacLabelId::new(3);
        let ctx = MacContextId::new(1);
        let mut mac = FakeMacProvider::new(MacSystem::Parsec);
        mac.with_label("/etc/shadow", label, "shadow_t")
            .with_context(5099, ctx, "reader_t")
            .set_permit(ctx, label, MacAccessKind::Read, true)
            .set_permit(ctx, label, MacAccessKind::Write, false);
        let report = exposure_report(
            &index,
            &principal,
            &roots,
            &reach,
            &FakeState::default(),
            &mac,
        );
        let leak = report
            .findings
            .iter()
            .find(|f| f.path == "/etc/shadow")
            .expect("secret leak finding kept");
        assert_eq!(leak.risk, Risk::Leak);
        let ann = leak.mac.as_ref().expect("leak finding annotated");
        assert_eq!(ann.reachable_in, vec!["reader_t".to_owned()]);
    }

    #[test]
    fn leak_finding_suppressed_when_read_denied() {
        // The dual: denying READ suppresses the leak (write permission is irrelevant to
        // a read finding, confirming the risk→kind mapping selects Read).
        let principal = Principal::new("5099", 5099, vec![]);
        let (index, roots, reach) = index_and_reach(secret_tree(), &principal);
        let label = MacLabelId::new(3);
        let ctx = MacContextId::new(1);
        let mut mac = FakeMacProvider::new(MacSystem::Parsec);
        mac.with_label("/etc/shadow", label, "shadow_t")
            .with_context(5099, ctx, "reader_t")
            .set_permit(ctx, label, MacAccessKind::Read, false);
        let report = exposure_report(
            &index,
            &principal,
            &roots,
            &reach,
            &FakeState::default(),
            &mac,
        );
        assert!(
            report.findings.iter().all(|f| f.path != "/etc/shadow"),
            "a MAC read-block suppresses the secret leak"
        );
    }
}
