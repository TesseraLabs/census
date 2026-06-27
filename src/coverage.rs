//! Catalog coverage: enumerate the device's live privileged surface and report
//! what the installed permission catalog does NOT cover.
//!
//! `census catalog coverage` answers "did we forget anything?" — it is a
//! read-only audit, not part of the auth/apply path. The surface is a finite,
//! enumerable set of system objects across classes (setuid binaries, sudo-reachable
//! binaries, security-relevant `/etc` configs, systemd units, gate-keeping groups,
//! capability-bearing files). Coverage is computed against the *expanded*
//! primitives of the catalog (sudo commands, groups), not the raw records — a
//! binary is "covered" when some resolved permission would grant it.
//!
//! ## Two-layer design (why the seam)
//!
//! Mirroring `catalog.rs`'s `CatalogSource`/`LiveCatalog`/`FakeCatalog` split, the
//! live enumeration ([`LiveSurface`]) is kept thin and deliberately *untested by
//! unit tests*: it shells out (read-only, argv-only — never a shell string) to
//! `dpkg`/`systemctl`/`getcap` and walks real filesystems. All the coverage LOGIC
//! lives in the pure [`coverage`] core, which consumes an already-enumerated
//! `&[SurfaceObject]` plus a `CatalogSource`, so it is fully unit-tested with
//! [`FakeSurface`] + `FakeCatalog`. The real `LiveSurface` scan is exercised only
//! by the (separate) container test against a known image.
//!
//! ## Why setuid is not a grant object
//!
//! A setuid-root binary runs as root regardless of the caller — no group
//! membership or sudoers rule is needed to invoke it. So it is never something the
//! catalog "covers" by granting it; the relevant question is the reverse — is there
//! an *unexpected* setuid binary outside package ownership (a backdoor signal)?
//! Setuid objects are therefore reported as a separate inventory, and an
//! `orphan` (not package-owned) setuid file is an anomaly to investigate, not a
//! coverage gap that penalises the metric.

use crate::catalog::{
    self, Access, CatalogSource, OsTarget, ResolveCtx, ResolvedFileGrant, Risk, Shape,
};

/// A class of privileged surface object.
///
/// `Setuid` is intentionally *not* a grant class (see module docs): it is
/// inventory/anomaly only. The other five are grant classes whose coverage is
/// computed against expanded catalog primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceClass {
    /// A binary reachable via sudo (`/usr/sbin`, `/sbin`, admin `/usr/bin`).
    SudoBin,
    /// A security-relevant `/etc` config (conffile, drop-in).
    Config,
    /// A systemd unit (service/socket/timer/…).
    Unit,
    /// A gate-keeping group (`netdev`, `dialout`, `docker`, …).
    Group,
    /// A capability-bearing file (`getcap`).
    CapFile,
    /// A setuid/setgid binary — inventory/anomaly, not a grant object.
    Setuid,
}

impl SurfaceClass {
    /// Stable lowercase token used in CLI `--class` filters and JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            SurfaceClass::SudoBin => "sudo_bin",
            SurfaceClass::Config => "config",
            SurfaceClass::Unit => "unit",
            SurfaceClass::Group => "group",
            SurfaceClass::CapFile => "capfile",
            SurfaceClass::Setuid => "setuid",
        }
    }

    /// Whether this class participates in the coverage metric. `Setuid` does not
    /// (it is inventory/anomaly), so it carries weight 0 in `overall_pct`.
    fn is_grant_class(self) -> bool {
        !matches!(self, SurfaceClass::Setuid)
    }
}

/// Who put a surface object on the device.
///
/// This separates the OS's own surface (`Vendor`, covered by the vendor catalog)
/// from third-party software (`Addon`, a candidate add-on namespace) and from
/// objects no package owns (`Orphan` — either a site customization or, for a
/// setuid file, an anomaly worth investigating).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    /// Owned by a base OS package.
    Vendor,
    /// Owned by a recognizable add-on package (carries the package name).
    Addon(String),
    /// Not owned by any package (site config, or a setuid anomaly).
    Orphan,
}

/// One enumerated privileged-surface object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceObject {
    /// Which class of surface this is.
    pub class: SurfaceClass,
    /// Canonical key: binary path, config path, unit name, or group name.
    pub key: String,
    /// Who placed it on the device.
    pub provenance: Provenance,
    /// Free-form detail for the report (mode/owner/caps/idVendor).
    pub detail: String,
}

/// A surface-scan result: the enumerated objects plus any per-class degradations.
///
/// A *degradation* is distinct from an empty class. A class is legitimately empty
/// when its scan tool is simply absent (a non-systemd host has no units). It is
/// *degraded* when the tool is present but its run could not be trusted — a spawn
/// failure, a non-zero exit, non-UTF-8 output, or a wall-clock timeout. A degraded
/// grant class was NOT fully enumerated, so its objects are missing from the
/// coverage denominator and the metric for it reads higher than the truth. The
/// caller surfaces every degradation and fails the `--min-coverage` gate closed on
/// it, so a half-read scan can never be mistaken for a complete, passing audit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanOutcome {
    /// Every enumerated surface object across the requested classes.
    pub objects: Vec<SurfaceObject>,
    /// Per-class scan degradations (tool present but its output is untrustworthy).
    /// Empty on a clean scan.
    pub degraded: Vec<ScanDegraded>,
}

/// One class's scan degradation: the class whose live enumeration could not be
/// trusted, and a human reason naming the tool and how it failed. Kept separate
/// from a legitimately-empty class (tool simply absent) so a passing coverage gate
/// can never be misread as a complete audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanDegraded {
    /// The grant class whose live enumeration degraded.
    pub class: SurfaceClass,
    /// Why the class could not be trusted (tool + failure mode).
    pub reason: String,
}

/// A source of live surface objects, abstracted so the coverage core is pure and
/// unit tests supply an in-memory surface without touching the filesystem.
pub trait SurfaceScanner {
    /// Enumerate the privileged surface, restricted to the requested `classes`.
    ///
    /// Returns the enumerated objects together with any per-class degradations (a
    /// scan tool that was present but failed); see [`ScanOutcome`].
    fn scan(&self, classes: &[SurfaceClass]) -> Result<ScanOutcome, CoverageError>;
}

/// A resolved role instance the coverage core folds in so parametrized
/// permissions (e.g. `service-restart(units=[…])`) contribute concrete commands.
///
/// Kept deliberately small and string-keyed: it carries the already-resolved
/// expansion of a role's permission (the same `sudo`/`groups` strings the apply
/// path would emit), so the core can treat a role's concrete instance exactly
/// like a catalog primitive. The CLI slice builds these via
/// `catalog::resolve_with_params` over a `--roles <dir>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedRole {
    /// Expanded sudo command strings contributed by this role instance.
    pub sudo: Vec<String>,
    /// Expanded group names contributed by this role instance.
    pub groups: Vec<String>,
    /// Expanded file grants contributed by this role instance. A parametrized
    /// `[[file]]` grant (e.g. `app-config-edit path="/etc/{app}"`) only yields a
    /// concrete path once a role supplies the parameter, so a config object under
    /// such a grant is covered only when the role instance is folded in.
    pub file_grants: Vec<ResolvedFileGrant>,
}

impl ResolvedRole {
    /// Construct from already-expanded sudo + group strings (no file grants).
    pub fn new(sudo: Vec<String>, groups: Vec<String>) -> Self {
        ResolvedRole {
            sudo,
            groups,
            file_grants: Vec::new(),
        }
    }

    /// Construct from already-expanded sudo + group strings + file grants.
    pub fn with_file_grants(
        sudo: Vec<String>,
        groups: Vec<String>,
        file_grants: Vec<ResolvedFileGrant>,
    ) -> Self {
        ResolvedRole {
            sudo,
            groups,
            file_grants,
        }
    }
}

/// Context for a coverage computation.
#[derive(Debug, Clone, Default)]
pub struct CoverageCtx {
    /// When set, parametrized permissions that cannot resolve without a role
    /// instance (they fail with `MissingParam`) do NOT count as covering. Without
    /// strict, such a permission's static command prefix (up to the first
    /// `{placeholder}`) is treated as a covering prefix — honest "potentially
    /// covering" semantics for an operator without a role set.
    pub strict: bool,
    /// The catalog version this coverage was computed against, echoed into the
    /// report for the audit trail.
    pub catalog_version: Option<String>,
    /// Group names that a role-binding grants (a `[[role_group]]` whose resolved
    /// group carries non-empty sudo and/or file grants). A `group`-class surface
    /// object for such a group is covered by the binding even though no
    /// membership primitive expands its name — the role attached a grant to the
    /// group directly. Built by the CLI from `model::resolve_groups`; empty when
    /// no declaration/role-store is supplied (coverage then sees only
    /// membership-covered groups, exactly as before).
    pub bound_grant_groups: Vec<String>,
}

/// Per-object coverage verdict in the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectCoverage {
    /// The surface object this verdict is about.
    pub object: SurfaceObject,
    /// Whether the object is covered by the catalog (false for an honest gap).
    pub covered: bool,
    /// A best-effort suggested permission for an uncovered object (by domain).
    /// `None` when no suggestion applies (or the object is covered).
    pub suggested_permission: Option<String>,
    /// When set, the object is intentionally uncovered for this reason and does
    /// NOT penalise the metric (escalation mechanism, MAC/pdpl, app group, …).
    pub intentional_exclusion: Option<String>,
    /// When set, the object cannot be covered by any installed backend without an
    /// over-broad grant (a single file directly in a non-grantable parent like
    /// `/etc`, with only the dir-only `AclBackend` present). The free backend
    /// structurally can't constrain it — covering it would require granting the
    /// whole parent, which is an over-grant, not a real gap. So it is reported in
    /// a distinct bucket and, like `intentional_exclusion`, does NOT penalise the
    /// metric. Kept separate from `intentional_exclusion` so the report can tell
    /// "intentionally out of scope" apart from "backend can't enforce it yet".
    pub backend_limited: Option<String>,
    /// For a covered object, a short note on HOW it is covered when that is not
    /// obvious — currently the backend + guarantee that enforces a covering file
    /// grant (e.g. `rw via AclBackend (dir)`). `None` for objects covered by the
    /// sudo/group/unit mechanism (where the class itself implies the mechanism).
    pub coverage_note: Option<String>,
}

/// Coverage counts for a single grant class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassCoverage {
    /// The class these counts are for.
    pub class: SurfaceClass,
    /// Objects covered by the catalog.
    pub covered: usize,
    /// Objects counted toward the metric (covered + honest gaps; excludes
    /// intentionally-uncovered objects).
    pub total: usize,
}

impl ClassCoverage {
    /// Coverage percentage for this class.
    ///
    /// Zero-denominator convention: a class with `total == 0` (nothing to cover)
    /// returns `100.0`, NOT `NaN`. "No objects to cover" is fully covered by
    /// definition, and a sentinel of `100.0` keeps the metric well-ordered for the
    /// `--min-coverage` gate (a `NaN` would make every comparison false and let the
    /// gate silently pass). The same convention is applied in [`weighted_overall`].
    pub fn pct(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            (self.covered as f64) * 100.0 / (self.total as f64)
        }
    }
}

/// The full coverage report: per-class counts, per-object verdicts, the overall
/// percentage, and the anomalies (orphan setuid/cap) surfaced separately.
#[derive(Debug, Clone, PartialEq)]
pub struct CoverageReport {
    /// Per-class covered/total counts (grant classes only).
    pub by_class: Vec<ClassCoverage>,
    /// Per-object verdicts for every grant-class object scanned, in input order.
    pub objects: Vec<ObjectCoverage>,
    /// Setuid inventory: every setuid object (not a grant object).
    pub setuid_inventory: Vec<SurfaceObject>,
    /// Anomalies to investigate (orphan setuid / orphan capfile).
    pub anomalies: Vec<SurfaceObject>,
    /// Weighted overall coverage percentage across grant classes.
    pub overall_pct: f64,
    /// The catalog version coverage was computed against, if known.
    pub catalog_version: Option<String>,
    /// The OS target string coverage was computed for.
    pub os_target: String,
    /// Non-fatal warnings gathered while building the covered set: each is a
    /// catalog permission id that failed to resolve (cyclic/contradictory/etc.)
    /// and was skipped. A coverage audit is read-only — one bad record must not
    /// abort the whole report — so the offending ids are reported here instead
    /// of turning into a hard error. Empty when every id resolved.
    pub catalog_warnings: Vec<String>,
    /// Per-class scan degradations: grant classes whose live scan tool was present
    /// but failed (spawn error, non-zero exit, non-UTF-8 output, or timeout), so
    /// the class was not fully enumerated. Distinct from `catalog_warnings` (a
    /// catalog-side resolve failure). A non-empty list means the metric is computed
    /// over a shrunken denominator and may read higher than the truth; the CLI
    /// fails the `--min-coverage` gate closed whenever any entry is present. Filled
    /// by the CLI from the [`ScanOutcome`]; the pure core leaves it empty.
    pub scan_warnings: Vec<ScanDegraded>,
}

/// Errors computing coverage or enumerating the surface.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CoverageError {
    /// Resolving the catalog to build the covered set failed.
    #[error("catalog error while computing coverage: {0}")]
    Catalog(#[from] catalog::CatalogError),
    /// The live surface could not be enumerated (filesystem/command failure).
    /// Carries a human reason; the live scanner degrades gracefully where it can
    /// (e.g. missing `dpkg` ⇒ unknown provenance) and only errors when it cannot
    /// produce a meaningful surface at all.
    #[error("cannot enumerate privileged surface: {0}")]
    Scan(String),
}

/// An in-memory surface for tests: returns its objects filtered by class.
#[derive(Debug, Clone, Default)]
pub struct FakeSurface {
    objects: Vec<SurfaceObject>,
}

impl FakeSurface {
    /// Empty surface.
    pub fn new() -> Self {
        FakeSurface::default()
    }

    /// Add an object to the surface.
    pub fn with(mut self, object: SurfaceObject) -> Self {
        self.objects.push(object);
        self
    }
}

impl SurfaceScanner for FakeSurface {
    fn scan(&self, classes: &[SurfaceClass]) -> Result<ScanOutcome, CoverageError> {
        Ok(ScanOutcome {
            objects: self
                .objects
                .iter()
                .filter(|o| classes.contains(&o.class))
                .cloned()
                .collect(),
            degraded: Vec::new(),
        })
    }
}

// --- coverage core ----------------------------------------------------------

/// The set of expanded primitives the installed catalog (+ roles) grants,
/// against which surface objects are matched.
///
/// Built once per `coverage` call by resolving every catalog id and folding in
/// the resolved role instances. Keeping the covered set as concrete strings
/// (binary tokens, group names, unit names) is what makes the per-object match a
/// simple set/prefix test — and what makes a transitive escape NOT fabricate
/// coverage: only the binary actually granted lands here, never what it can reach.
struct CoveredSet {
    /// Canonical binary paths covered by some sudo command (argv-leading token of
    /// an expanded sudo string, symlink-resolved on the surface side). A
    /// `HashSet` because membership is the only query (`object_covered`) and a
    /// full-`/` scan tests thousands of objects against it — a linear `Vec` scan
    /// would be O(objects × covered).
    sudo_binaries: std::collections::HashSet<String>,
    /// Group names covered by some expanded `groups` primitive. `HashSet` for
    /// the same O(1)-membership reason as `sudo_binaries`.
    groups: std::collections::HashSet<String>,
    /// Concrete unit names covered by a `service-restart` instance (both `<u>`
    /// and `<u>.service` forms folded in). `HashSet` for O(1) membership.
    units: std::collections::HashSet<String>,
    /// Whether the catalog grants `service-admin` (covers ALL units).
    has_service_admin: bool,
    /// Whether the catalog grants `capability-admin` (covers all capfiles).
    has_capability_admin: bool,
    /// File grants the catalog (+ role instances) resolve to. A `Config`-class
    /// path is covered when it equals a grant path or lies under a recursive Dir
    /// grant (see [`config_grant_match`]). Stored as resolved grants so the match
    /// can distinguish ro/rw and name the enforcing backend in the report.
    file_grants: Vec<ResolvedFileGrant>,
}

/// Built-in set of security-relevant config path prefixes: the directories whose
/// contents gate authentication, privilege, network/firewall, kernel, audit, and
/// trust on a hardened Linux host. Used to NARROW the `config` denominator —
/// without this, the class would count every dpkg conffile (thousands of mostly
/// inert files like `/etc/hostname`), drowning the metric. A config object counts
/// toward the class only if it is at/under one of these prefixes OR is named by a
/// catalog file grant (see [`config_in_scope`]); everything else is low-priority
/// and excluded unless `--include-low-priority` is set.
///
/// The list is curated, not exhaustive: it is the privileged-config surface the
/// coverage audit cares about (sshd, PAM, sudo, sysctl, audit, TLS trust, polkit,
/// systemd, kernel modules, the limits/security stack). It is documented here so
/// the chosen denominator is honest and reviewable.
const SECURITY_RELEVANT_CONFIG_PREFIXES: &[&str] = &[
    "/etc/ssh",
    "/etc/pam.d",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/sysctl.conf",
    "/etc/sysctl.d",
    "/etc/audit",
    "/etc/ssl",
    "/etc/pki",
    "/etc/ca-certificates",
    "/etc/ca-certificates.conf",
    "/etc/polkit-1",
    "/etc/PolicyKit",
    "/etc/systemd",
    "/etc/security",
    "/etc/apparmor.d",
    "/etc/selinux",
    "/etc/modprobe.d",
    "/etc/modules-load.d",
    "/etc/login.defs",
    "/etc/securetty",
    "/etc/sudo.conf",
    "/etc/nsswitch.conf",
];

/// Parent directories too broad to ever grant wholesale: top-level system trees
/// and the shared trust dirs whose contents are a mix of unrelated, often
/// security-critical files owned by many packages. A single security-relevant
/// config sitting *directly* in one of these (e.g. `/etc/login.defs` in `/etc`,
/// `/etc/ssl/openssl.cnf` in `/etc/ssl`) cannot be covered by the free dir-ACL
/// backend without granting the entire parent — which would hand out write to
/// the whole tree, an over-grant far worse than the uncovered file. The free
/// backend (dir-only) structurally cannot constrain such an object to the single
/// file, so it is NOT a real coverage gap: it is *backend-limited* and reported
/// separately (see [`ObjectCoverage::backend_limited`]). A per-file-capable
/// backend (commercial) would cover it directly; the gate is therefore on the
/// installed backends' capability — with only the dir-only backend, parent ∈
/// this set ⇒ backend-limited.
///
/// The set is curated and documented so the "what we won't grant wholesale"
/// boundary is reviewable: the FHS top-level dirs an admin would never hand out
/// in full, plus the shared TLS trust dirs (`/etc/ssl`, `/etc/pki`,
/// `/etc/ca-certificates`) where a bare config file (e.g. `openssl.cnf`) sits
/// next to private-key material. A config under a *purpose-specific* subdir
/// (`/etc/ssh`, `/etc/sudoers.d`, `/etc/sysctl.d`) is NOT here — that subdir is
/// itself a grantable directory, so such an object stays a normal covered/gap.
const NON_GRANTABLE_PARENTS: &[&str] = &[
    "/",
    "/etc",
    "/usr",
    "/usr/local",
    "/var",
    "/boot",
    "/opt",
    "/run",
    "/etc/ssl",
    "/etc/pki",
    "/etc/ca-certificates",
];

/// Permission ids that act as class-wide "covers everything" grants. Detected by
/// id presence in the catalog (matches the spec wording "`service-admin`
/// present"): `service-admin` covers every unit, `capability-admin` every
/// capfile. Kept as named constants so the rule is explicit, not a magic string.
const SERVICE_ADMIN_ID: &str = "service-admin";
const CAPABILITY_ADMIN_ID: &str = "capability-admin";

/// The argv-leading token of a sudo command string: the binary, before any
/// argument. Splitting on the first whitespace gives the binary path; arguments
/// only narrow what the binary may do, they do not change "which binary is
/// reachable". An empty/whitespace string yields `None`.
fn sudo_binary_token(command: &str) -> Option<&str> {
    command.split_whitespace().next()
}

/// The static command prefix of a (possibly templated) sudo string: the binary
/// token up to the first `{placeholder}`. For `"/usr/bin/systemctl restart {unit}"`
/// this is `/usr/bin/systemctl` — the binary is reachable regardless of which
/// unit fills the placeholder. Returns `None` if the leading token itself is a
/// placeholder (no concrete binary prefix).
///
/// This is the non-strict "parametrized-without-instance potentially covers the
/// binary" rule: even with no role instance, granting `systemctl restart {unit}`
/// means the `systemctl` binary is on the device's covered surface.
fn static_binary_prefix(command: &str) -> Option<&str> {
    let token = sudo_binary_token(command)?;
    // A token containing a placeholder has no concrete binary prefix to offer
    // (e.g. `{tool}` as the leading word) — skip it.
    if token.contains('{') {
        return None;
    }
    Some(token)
}

/// Build the covered set by resolving every catalog id and folding in roles.
///
/// For each id in `all_definitions(os)`: resolve it; on success add every sudo
/// command's binary token and every group. `resolve` returns a permission's
/// templates verbatim — it never substitutes `{placeholder}`s and never reports
/// MissingParam (only `resolve_with_params`, driven by a concrete role instance,
/// does). So a parametrized record (e.g. `systemctl restart {unit}`) reaches
/// here as an `Ok` whose sudo strings still carry the literal `{unit}`. We
/// detect that ourselves via `has_placeholder` and apply the strict/non-strict
/// rule: in non-strict mode the template's static binary prefix is folded in as
/// "potentially covering"; in strict mode it contributes nothing (only a
/// concrete role instance can cover it).
///
/// A single id whose resolve fails (cyclic/contradictory/unknown include) must
/// NOT abort the audit: its error is collected as a warning string, the id is
/// skipped, and the covered set is built over the rest. The returned warnings
/// (the offending ids) ride out in `CoverageReport::catalog_warnings`. This
/// mirrors how role resolution already warns-and-skips a bad slice.
fn build_covered_set(
    catalog: &dyn CatalogSource,
    os: &OsTarget,
    roles: &[ResolvedRole],
    ctx: &CoverageCtx,
) -> Result<(CoveredSet, Vec<String>), CoverageError> {
    let mut sudo_binaries: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut groups: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut units: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut has_service_admin = false;
    let mut has_capability_admin = false;
    let mut file_grants: Vec<ResolvedFileGrant> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    let resolve_ctx = ResolveCtx {
        catalog_version: ctx.catalog_version.clone(),
    };

    let all = catalog.all_definitions(os)?;

    // Resolve each *distinct* id once (an id may appear on several layers as the
    // override chain; resolve merges them). Dedup ids first so we don't re-resolve.
    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (_layer, def) in &all {
        if !seen_ids.insert(def.id.clone()) {
            continue; // already resolved this id on an earlier layer
        }

        match catalog::resolve(&def.id, os, catalog, &resolve_ctx) {
            Ok((resolved, _warnings)) => {
                // Class-wide grants flip their flag ONLY on a successful resolve.
                // The mere presence of `service-admin`/`capability-admin` is not
                // enough: an id that exists but cannot resolve (cycle, contradiction,
                // unknown include) is recorded as a warning below and contributes
                // nothing — flipping the flag on bare presence would mark every
                // unit/capfile covered off a permission that never actually resolves,
                // a class-wide false "covered". So the flag rides the Ok arm, next to
                // the sudo/group/file primitives this same resolve produced.
                if def.id == SERVICE_ADMIN_ID {
                    has_service_admin = true;
                }
                if def.id == CAPABILITY_ADMIN_ID {
                    has_capability_admin = true;
                }
                for p in &resolved.sudo {
                    // A templated command (e.g. `/usr/bin/systemctl restart
                    // {unit}`) arrives here with the literal `{unit}` intact —
                    // `resolve` returns templates verbatim, so we detect the
                    // placeholder ourselves. Such a parametrized-without-instance
                    // command is "potentially covering" only in non-strict mode:
                    // its static binary prefix (up to the first `{`) means the
                    // binary is on the catalog's surface. Under strict, only a
                    // concrete role instance can cover it, so we contribute
                    // nothing for the template.
                    if has_placeholder(&p.value) {
                        if !ctx.strict {
                            if let Some(prefix) = static_binary_prefix(&p.value) {
                                sudo_binaries.insert(prefix.to_owned());
                            }
                        }
                    } else if let Some(bin) = sudo_binary_token(&p.value) {
                        sudo_binaries.insert(bin.to_owned());
                    }
                }
                for p in &resolved.groups {
                    groups.insert(p.value.clone());
                }
                // File grants the catalog declares statically (no `{param}`):
                // such a grant resolves to a concrete path even without a role
                // instance, so it covers a config object directly. A templated
                // grant path (e.g. `/etc/{app}`) is NOT concrete here — it is
                // folded in only via a role instance below, exactly like a
                // templated sudo command. (We do not honour strict/non-strict for
                // file grants: there is no static "binary prefix" analogue for a
                // path, and a partial prefix would over-claim coverage on a parent
                // directory the catalog never actually grants.)
                for g in &resolved.file_grants {
                    if !has_placeholder(&g.path) {
                        push_unique_grant(&mut file_grants, g.clone());
                    }
                }
            }
            Err(e) => {
                // One unresolvable id (cycle, contradiction, unknown include)
                // must not sink the whole audit. Record it and move on so the
                // covered set still reflects every id that DID resolve.
                warnings.push(format!("catalog permission {} unresolved: {e}", def.id));
            }
        }
    }

    // Fold in resolved role instances: concrete parametrized expansions
    // (`service-restart units=[atm-app]` → concrete `systemctl restart atm-app`
    // commands, `app-config-edit` paths, etc.). These contribute concrete binary
    // tokens, groups, and — for service-restart — named units.
    for role in roles {
        for cmd in &role.sudo {
            if let Some(bin) = sudo_binary_token(cmd) {
                sudo_binaries.insert(bin.to_owned());
            }
            // A service-restart-style command names a unit as its last argument;
            // record both `<u>` and `<u>.service` forms so a unit object matches
            // regardless of which form the surface scanner reports.
            if let Some(unit) = service_restart_unit(cmd) {
                fold_unit_forms(unit, &mut units);
            }
        }
        for g in &role.groups {
            groups.insert(g.clone());
        }
        // A role instance's file grants are already `{param}`-substituted to
        // concrete paths, so fold them in unconditionally — this is how a
        // parametrized config-edit grant (`/etc/{app}` → `/etc/nginx`) lands as a
        // covering grant.
        for g in &role.file_grants {
            push_unique_grant(&mut file_grants, g.clone());
        }
    }

    // Fold in groups that a `[[role_group]]` binding grants directly: the role
    // attached sudo/file grants to the group, so the group object is covered even
    // though no membership primitive names it. (Membership-covered groups are
    // already in `groups` from the loops above; this only ADDS binding-covered
    // ones, so existing coverage is untouched.)
    for g in &ctx.bound_grant_groups {
        groups.insert(g.clone());
    }

    Ok((
        CoveredSet {
            sudo_binaries,
            groups,
            units,
            has_service_admin,
            has_capability_admin,
            file_grants,
        },
        warnings,
    ))
}

/// Whether `s` carries a `{placeholder}` (a templated, parametrized command).
/// A templated sudo string is not concretely covering on its own — see
/// `build_covered_set` for the strict/non-strict handling.
fn has_placeholder(s: &str) -> bool {
    if let Some(open) = s.find('{') {
        s[open + 1..].contains('}')
    } else {
        false
    }
}

/// Extract the unit a `systemctl` service-restart command names: the last argv
/// token of a `systemctl`-family command, when it is not itself a subcommand
/// verb or an option. Returns `None` for non-systemctl commands or bare
/// `systemctl` (no unit). Best-effort — used only to fold a role instance's
/// named units into the covered set.
fn service_restart_unit(command: &str) -> Option<&str> {
    let mut tokens = command.split_whitespace();
    let bin = tokens.next()?;
    if !bin.ends_with("/systemctl") && bin != "systemctl" {
        return None;
    }
    // The unit is the last token; reject if it is an option or a verb-only call.
    let last = command.split_whitespace().last()?;
    if last == bin || last.starts_with('-') || is_systemctl_verb(last) {
        return None;
    }
    Some(last)
}

/// systemctl subcommand verbs that are never a unit name. Kept small and explicit
/// so a command like `systemctl daemon-reload` (a verb, no unit) does not get
/// mis-read as a unit named `daemon-reload`.
fn is_systemctl_verb(token: &str) -> bool {
    matches!(
        token,
        "start"
            | "stop"
            | "restart"
            | "status"
            | "is-active"
            | "reset-failed"
            | "enable"
            | "disable"
            | "daemon-reload"
    )
}

/// Record both `<unit>` and `<unit>.service` forms of a named unit. sudoers
/// matches argv exactly, so a role may name either form; recording both lets a
/// surface `Unit` object match whichever form the scanner reports.
fn fold_unit_forms(unit: &str, units: &mut std::collections::HashSet<String>) {
    let base = unit.strip_suffix(".service").unwrap_or(unit);
    units.insert(base.to_owned());
    units.insert(format!("{base}.service"));
}

/// Fold a covering file grant into the accumulator, keyed by path. A repeated
/// path unions the access bits (OR) and ORs `recursive` — the same union rule the
/// catalog/model use — so two grants on the same path do not let a narrower one
/// mask a wider, and the recorded access reflects every bit that would be
/// enforced.
fn push_unique_grant(acc: &mut Vec<ResolvedFileGrant>, grant: ResolvedFileGrant) {
    if let Some(existing) = acc.iter_mut().find(|g| g.path == grant.path) {
        existing.access |= grant.access;
        existing.recursive = existing.recursive || grant.recursive;
        // Recompute the shape against the now-effective recursive flag (a path
        // seen once as a file and once recursive is effectively a directory).
        existing.shape = if existing.recursive {
            Shape::Dir
        } else {
            existing.shape
        };
    } else {
        acc.push(grant);
    }
}

/// Compute coverage of `surface` against the installed catalog (+ roles).
///
/// Builds the covered set (every resolved catalog primitive + role instances),
/// then verdicts each surface object by class. Setuid objects are inventory; an
/// orphan setuid or orphan capfile is an anomaly. Intentionally-uncovered objects
/// (escalation mechanisms, MAC/pdpl, app/admin groups, noise groups) are flagged
/// with a reason and excluded from the metric denominator.
pub fn coverage(
    surface: &[SurfaceObject],
    catalog: &dyn CatalogSource,
    os: &OsTarget,
    roles: &[ResolvedRole],
    ctx: &CoverageCtx,
) -> Result<CoverageReport, CoverageError> {
    coverage_scoped(surface, catalog, os, roles, ctx, false)
}

/// Coverage with explicit `include_low_priority`: when `true`, config objects
/// that are neither security-relevant nor named by a grant are STILL counted in
/// the `config` denominator (the `--include-low-priority` view). When `false`
/// (the default and the meaningful metric), such low-priority conffiles are not
/// counted at all — they are dropped from both the per-object list and the
/// denominator so the `config` percentage reflects only the privileged-config
/// surface (see [`SECURITY_RELEVANT_CONFIG_PREFIXES`]).
pub fn coverage_scoped(
    surface: &[SurfaceObject],
    catalog: &dyn CatalogSource,
    os: &OsTarget,
    roles: &[ResolvedRole],
    ctx: &CoverageCtx,
    include_low_priority: bool,
) -> Result<CoverageReport, CoverageError> {
    let (covered, catalog_warnings) = build_covered_set(catalog, os, roles, ctx)?;

    let mut objects: Vec<ObjectCoverage> = Vec::new();
    let mut setuid_inventory: Vec<SurfaceObject> = Vec::new();
    let mut anomalies: Vec<SurfaceObject> = Vec::new();

    // Per-class running counts for the metric (grant classes only).
    let mut class_counts: Vec<(SurfaceClass, usize, usize)> = vec![
        (SurfaceClass::SudoBin, 0, 0),
        (SurfaceClass::Config, 0, 0),
        (SurfaceClass::Unit, 0, 0),
        (SurfaceClass::Group, 0, 0),
        (SurfaceClass::CapFile, 0, 0),
    ];

    for object in surface {
        // Setuid is inventory, never a grant object (see module docs). An orphan
        // setuid is additionally an anomaly to investigate.
        if object.class == SurfaceClass::Setuid {
            setuid_inventory.push(object.clone());
            if object.provenance == Provenance::Orphan {
                anomalies.push(object.clone());
            }
            continue;
        }

        // An orphan capfile is likewise an anomaly (an unexpected capability
        // outside package ownership is a backdoor signal), surfaced in addition
        // to its normal coverage verdict.
        if object.class == SurfaceClass::CapFile && object.provenance == Provenance::Orphan {
            anomalies.push(object.clone());
        }

        // Narrow the config denominator to the security-relevant surface. A
        // config object that is neither at/under a curated security-relevant
        // prefix nor named by a catalog file grant is low-priority noise (most
        // dpkg conffiles): by default it is dropped entirely — not counted, not
        // listed — so the `config` percentage measures only the privileged-config
        // surface. `--include-low-priority` keeps it (as an honest gap) so the
        // operator can still see the long tail.
        if object.class == SurfaceClass::Config
            && !include_low_priority
            && !config_in_scope(&object.key, &covered.file_grants)
        {
            continue;
        }

        // Intentionally-uncovered policy: these do not penalise the metric and
        // are reported with a reason rather than as a gap. This is checked BEFORE
        // the binding-covered set is consulted, so an admin-by-design group
        // (wheel/sudo/astra-admin…) bound by a role stays "intentionally excluded",
        // NOT "covered" — deliberate precedence: an excluded object never penalises
        // the metric, and a role binding does not turn an admin group into a
        // counted-covered grant object.
        if let Some(reason) = intentional_exclusion(object) {
            objects.push(ObjectCoverage {
                object: object.clone(),
                covered: false,
                suggested_permission: None,
                intentional_exclusion: Some(reason),
                backend_limited: None,
                coverage_note: None,
            });
            continue;
        }

        // Config coverage is grant-based and yields a backend/guarantee note;
        // every other class is covered by the sudo/group/unit mechanism (no note).
        // A config object whose strongest covering grant is `File`/`Pattern`-shaped
        // is *declared but unenforceable* in the open build: the dir-only
        // `AclBackend` can constrain a directory, not a single file or a glob. Such
        // a grant must NOT count as covered — that would inflate the numerator off a
        // guarantee the installed backend cannot make, the mirror image of how an
        // ungranted bare file in a non-grantable parent is correctly excluded. It is
        // routed to the backend-limited bucket below (leaving the metric).
        let mut unenforceable_grant: Option<&ResolvedFileGrant> = None;
        let (is_covered, coverage_note) = if object.class == SurfaceClass::Config {
            match config_grant_cover(&object.key, &covered.file_grants) {
                Some(grant) if grant_shape_enforceable(grant) => {
                    (true, Some(grant_coverage_note(grant)))
                }
                Some(grant) => {
                    // Covered only by a File/Pattern grant the open build cannot
                    // enforce; record it for the backend-limited bucket.
                    unenforceable_grant = Some(grant);
                    (false, None)
                }
                None => (false, None),
            }
        } else {
            (object_covered(object, &covered), None)
        };

        // Backend-limited reclassification (config objects only): either
        //   (a) a config object covered ONLY by a `File`/`Pattern`-shaped grant the
        //       installed dir-only backend cannot enforce (declared-but-unenforceable),
        //       or
        //   (b) an UNCOVERED single file directly in a non-grantable parent
        //       (e.g. `/etc/login.defs`) the dir-only `AclBackend` cannot cover
        //       without granting the whole parent — an over-grant, not a real gap.
        // Both are bucketed separately and excluded from the metric denominator,
        // each with its own reason so the report tells them apart. A per-file- or
        // pattern-capable backend (commercial) would cover case (a) directly.
        if object.class == SurfaceClass::Config {
            if let Some(grant) = unenforceable_grant {
                objects.push(ObjectCoverage {
                    object: object.clone(),
                    covered: false,
                    suggested_permission: None,
                    intentional_exclusion: None,
                    backend_limited: Some(format!(
                        "declared {} grant; requires {}",
                        shape_word(grant.shape),
                        grant_backend(grant),
                    )),
                    coverage_note: None,
                });
                continue;
            }
            if !is_covered && backend_limited_config(&object.key) {
                objects.push(ObjectCoverage {
                    object: object.clone(),
                    covered: false,
                    suggested_permission: None,
                    intentional_exclusion: None,
                    backend_limited: Some(
                        "single file in non-grantable parent; requires per-file-capable backend"
                            .to_owned(),
                    ),
                    coverage_note: None,
                });
                continue;
            }
        }

        // Tally toward the metric (covered + honest gaps; the intentional path
        // above already `continue`d out).
        for slot in class_counts.iter_mut() {
            if slot.0 == object.class {
                slot.2 += 1;
                if is_covered {
                    slot.1 += 1;
                }
            }
        }

        let suggested = if is_covered {
            None
        } else {
            suggest_permission_with_grants(object)
        };

        objects.push(ObjectCoverage {
            object: object.clone(),
            covered: is_covered,
            suggested_permission: suggested,
            intentional_exclusion: None,
            backend_limited: None,
            coverage_note,
        });
    }

    let by_class: Vec<ClassCoverage> = class_counts
        .iter()
        .filter(|(class, _, _)| class.is_grant_class())
        .map(|(class, covered, total)| ClassCoverage {
            class: *class,
            covered: *covered,
            total: *total,
        })
        .collect();

    let overall_pct = weighted_overall(&by_class);

    Ok(CoverageReport {
        by_class,
        objects,
        setuid_inventory,
        anomalies,
        overall_pct,
        catalog_version: ctx.catalog_version.clone(),
        os_target: os.layer_names().last().cloned().unwrap_or_default(),
        catalog_warnings,
        // The pure core does not run the live scan, so it knows of no scan
        // degradations; the CLI fills this from the `ScanOutcome` after scanning.
        scan_warnings: Vec::new(),
    })
}

/// Weighted overall coverage: the simple ratio of all covered grant objects to
/// all counted grant objects (each object weighs equally, so a class with more
/// objects contributes proportionally — "weighted" by object count, not a flat
/// average of per-class percentages, which would over-weight a tiny class).
///
/// Zero-denominator convention (same as [`ClassCoverage::pct`]): a surface with no
/// counted objects at all returns `100.0`, never `NaN` — an empty surface is fully
/// covered by definition, and a finite sentinel keeps the `--min-coverage` gate
/// comparison meaningful (a `NaN` would compare false against every threshold).
fn weighted_overall(by_class: &[ClassCoverage]) -> f64 {
    let covered: usize = by_class.iter().map(|c| c.covered).sum();
    let total: usize = by_class.iter().map(|c| c.total).sum();
    if total == 0 {
        100.0
    } else {
        (covered as f64) * 100.0 / (total as f64)
    }
}

/// Whether `object` is covered by the catalog's expanded primitives.
fn object_covered(object: &SurfaceObject, covered: &CoveredSet) -> bool {
    match object.class {
        // A binary is covered when its (symlink-resolved) path equals the binary
        // token of some sudo command. The surface side is responsible for having
        // resolved symlinks to the real path; here it is a plain equality on the
        // canonical key.
        SurfaceClass::SudoBin => covered.sudo_binaries.contains(&object.key),
        SurfaceClass::Group => covered.groups.contains(&object.key),
        SurfaceClass::Unit => {
            // service-admin covers every unit; otherwise the named unit must be in
            // a service-restart instance's units (either form).
            covered.has_service_admin || unit_covered(&object.key, &covered.units)
        }
        SurfaceClass::CapFile => covered.has_capability_admin,
        // Config coverage is grant-based and handled directly in `coverage_scoped`
        // (it needs the backend/guarantee note), so it never routes through here.
        SurfaceClass::Config => false,
        // Not a grant class; never reached for Setuid (filtered earlier).
        SurfaceClass::Setuid => false,
    }
}

/// Whether a config path is IN SCOPE for the `config` metric: either it is at/
/// under a curated security-relevant prefix, or it is named by a catalog file
/// grant (any grant whose path equals it or whose recursive directory contains
/// it). Out-of-scope config objects are low-priority and, by default, dropped
/// from the denominator entirely (see [`coverage_scoped`]).
fn config_in_scope(path: &str, grants: &[ResolvedFileGrant]) -> bool {
    if is_security_relevant_config(path) {
        return true;
    }
    // A path a grant actually targets is in scope even if it falls outside the
    // curated set — the catalog has explicitly taken an interest in it.
    grants.iter().any(|g| grant_covers_path(g, path).is_some())
}

/// Whether `path` is at or under one of the curated security-relevant prefixes.
/// The match is on a path-component boundary, NOT a naive substring: `/etc/ssh`
/// matches `/etc/ssh` and `/etc/ssh/sshd_config` but NOT `/etc/sshd_other`
/// (which merely shares a textual prefix). The bare `/etc/sudoers` file and the
/// `/etc/sudoers.d` directory are distinct entries so both are covered.
fn is_security_relevant_config(path: &str) -> bool {
    SECURITY_RELEVANT_CONFIG_PREFIXES
        .iter()
        .any(|prefix| catalog::path_at_or_under(prefix, path))
}

/// The strongest file grant covering a config `path`, or `None`. A path is covered
/// when it equals a grant path, or lies under a `recursive` Dir grant on a
/// component boundary. The caller decides the verdict from the returned grant: a
/// `Dir`-shaped grant is enforceable by the open `AclBackend` (truly covered),
/// while a `File`/`Pattern`-shaped grant is declared-but-unenforceable there (see
/// [`coverage_scoped`]).
fn config_grant_cover<'a>(
    path: &str,
    grants: &'a [ResolvedFileGrant],
) -> Option<&'a ResolvedFileGrant> {
    let mut best: Option<&'a ResolvedFileGrant> = None;
    for g in grants {
        if grant_covers_path(g, path).is_some() {
            best = Some(match best {
                None => g,
                Some(prev) => choose_stronger_cover(prev, g),
            });
        }
    }
    best
}

/// Pick the stronger of two covering grants for the config verdict.
///
/// Enforceability ranks first: a `Dir`-shaped grant (enforceable by the open
/// `AclBackend`) outranks a `File`/`Pattern`-shaped one, so a path covered by both
/// an enforceable directory grant and a paper-only file grant is reported as truly
/// covered, not demoted to backend-limited. Among grants of equal enforceability,
/// a write grant outranks a read-only one (a reviewer most needs the strongest
/// access reachable on the path); the first seen wins on a full tie, for stability.
fn choose_stronger_cover<'a>(
    prev: &'a ResolvedFileGrant,
    cand: &'a ResolvedFileGrant,
) -> &'a ResolvedFileGrant {
    let prev_enforceable = grant_shape_enforceable(prev);
    if prev_enforceable != grant_shape_enforceable(cand) {
        return if prev_enforceable { prev } else { cand };
    }
    if prev.access.contains(Access::WRITE) {
        prev
    } else {
        cand
    }
}

/// Whether a covering grant's shape can be enforced by the open build's dir-only
/// `AclBackend`. A `Dir` grant can; `File`/`Pattern` shapes need a per-file- or
/// pattern-capable (commercial) backend, so in the open build a config object
/// covered only by such a grant is declared-but-unenforceable, not truly covered.
fn grant_shape_enforceable(grant: &ResolvedFileGrant) -> bool {
    matches!(grant.shape, Shape::Dir)
}

/// The grant shape as a short word for a report reason (`File`, `Pattern`,
/// `directory`).
fn shape_word(shape: Shape) -> &'static str {
    match shape {
        Shape::Dir => "directory",
        Shape::File => "File",
        Shape::Pattern => "Pattern",
    }
}

/// Whether one grant covers `path`, returning the matching grant on success.
///
/// Match rule (the documented config-coverage semantics):
///
/// - an exact path equality always covers (any shape);
/// - a `recursive` directory grant covers any path strictly under it, matched on a `/`-component
///   boundary (so `/etc/ssh` recursive covers `/etc/ssh/sshd_config` but NOT `/etc/sshd_other`).
///
/// A non-recursive grant covers only its exact path — it makes no claim on
/// children. (Pattern grants are matched by exact path here; glob expansion is a
/// capable-backend concern, not something the open coverage audit simulates.)
fn grant_covers_path<'a>(
    grant: &'a ResolvedFileGrant,
    path: &str,
) -> Option<&'a ResolvedFileGrant> {
    if grant.path == path {
        return Some(grant);
    }
    if grant.recursive && catalog::path_at_or_under(&grant.path, path) {
        return Some(grant);
    }
    None
}

/// The coverage note for a covering grant: `<access> via <backend> (<shape>)`,
/// where `<access>` is the grant's canonical token (`ro`/`rw` or sorted perm
/// letters). A directory grant is enforced rewrite-proof by the open
/// `AclBackend`; a File or Pattern grant would need a capability-gated backend,
/// which the note states honestly so the report does not imply the open build
/// can enforce it.
fn grant_coverage_note(grant: &ResolvedFileGrant) -> String {
    let access = grant.access;
    match grant.shape {
        Shape::Dir => format!("{access} via AclBackend (dir)"),
        Shape::File => format!("{access} (requires per-file-capable backend)"),
        Shape::Pattern => format!("{access} (requires pattern-capable backend)"),
    }
}

/// Whether an uncovered config object is *backend-limited* rather than a genuine
/// gap: a single file sitting directly in a [`NON_GRANTABLE_PARENTS`] directory,
/// which the dir-only `AclBackend` cannot cover without granting the whole parent.
///
/// The check is purely on the object's parent directory equalling a non-grantable
/// parent — i.e. the file is at depth 1 under a too-broad tree (`/etc/login.defs`,
/// `/etc/ssl/openssl.cnf`). A file under a purpose-specific subdir
/// (`/etc/ssh/sshd_config` → parent `/etc/ssh`, a grantable directory) is NOT
/// backend-limited: that subdir can be granted, so the object is a normal covered/
/// gap. This gate assumes the dir-only backend (the open build); a per-file-capable
/// backend would cover these directly, so a future caller with such a backend
/// installed would simply not reclassify here.
fn backend_limited_config(path: &str) -> bool {
    let parent = parent_dir(path);
    NON_GRANTABLE_PARENTS.contains(&parent)
}

/// Whether a unit name is covered by the named-unit set, accepting both `<u>` and
/// `<u>.service` forms on either side.
fn unit_covered(unit: &str, covered_units: &std::collections::HashSet<String>) -> bool {
    let base = unit.strip_suffix(".service").unwrap_or(unit);
    let with_service = format!("{base}.service");
    covered_units.contains(unit)
        || covered_units.contains(base)
        || covered_units.contains(&with_service)
}

// --- intentionally-uncovered policy + suggestions ---------------------------

/// Built-in policy: objects that are intentionally not covered and must not
/// penalise the metric, each with a reason. Derived from the coverage research
/// (escalation mechanisms, MAC/pdpl binaries, app/admin groups, noise groups).
/// Returns the reason string, or `None` if the object is a normal coverage target.
fn intentional_exclusion(object: &SurfaceObject) -> Option<String> {
    match object.class {
        SurfaceClass::SudoBin | SurfaceClass::Setuid => {
            let name = basename(&object.key);
            // The escalation substrate itself is not an object of grant — it IS
            // the mechanism by which grants are exercised.
            if matches!(name, "su" | "sudo" | "pkexec" | "newgrp" | "sg") {
                return Some("escalation mechanism (not an object of grant)".to_owned());
            }
            // MAC / pdpl (Astra mandatory labels) are ceilinged by the commercial
            // ParsecBackend, never expanded by Census's open catalog.
            if name.starts_with("pdpl") || name.starts_with("parsec") {
                return Some("MAC/pdpl — commercial ParsecBackend layer".to_owned());
            }
            None
        }
        SurfaceClass::Group => {
            let g = object.key.as_str();
            // App/admin groups are admin-by-design or a customer site layer, not
            // the vendor base.
            if g == "astra-admin"
                || g == "astra-console"
                || g == "sudo"
                || g == "wheel"
                || g.starts_with("bfs_")
                || g.starts_with("ndc_")
            {
                return Some("admin-by-design / app site-layer group".to_owned());
            }
            // Noise groups: present on the system but not gate-keeping to any
            // grantable surface.
            if matches!(g, "messagebus" | "crontab" | "ssl-cert") {
                return Some("noise group (not gate-keeping to a grant)".to_owned());
            }
            None
        }
        _ => None,
    }
}

/// Best-effort suggested permission for an uncovered object, by domain heuristic.
/// Optional signal for the operator; `None` when nothing obvious applies.
fn suggest_permission(object: &SurfaceObject) -> Option<String> {
    match object.class {
        SurfaceClass::SudoBin => {
            let name = basename(&object.key);
            let id = match name {
                "cryptsetup" => "luks-admin",
                "setcap" | "getcap" => "capability-admin",
                "aa-enforce" | "aa-complain" | "apparmor_parser" | "aa-status" => "apparmor-admin",
                "update-ca-certificates" => "ca-trust-admin",
                "auditctl" | "augenrules" => "audit-config",
                "useradd" | "usermod" | "userdel" | "chpasswd" => "user-admin",
                "modprobe" | "rmmod" => "driver-config",
                "sysctl" => "kernel-tune",
                "parted" | "fdisk" | "lvm" => "disk-admin",
                "reboot" | "shutdown" | "poweroff" | "halt" => "power-control",
                "iptables" | "iptables-restore" | "nft" => "firewall-admin",
                _ => return None,
            };
            Some(id.to_owned())
        }
        SurfaceClass::Group => {
            let id = match object.key.as_str() {
                "netdev" => "network-admin",
                "dialout" => "device-serial",
                "plugdev" => "device-usb",
                "disk" => "disk-admin",
                "adm" | "systemd-journal" => "log-read",
                "docker" => "docker.admin",
                "lpadmin" => "print-admin",
                _ => return None,
            };
            Some(id.to_owned())
        }
        SurfaceClass::CapFile => Some("capability-admin".to_owned()),
        _ => None,
    }
}

/// Suggestion for an uncovered object, extending [`suggest_permission`] with a
/// config-specific hint: an in-scope config path with no covering grant suggests
/// declaring a file grant on its containing directory (the rewrite-proof open
/// unit). Other classes fall through to the existing domain heuristics.
fn suggest_permission_with_grants(object: &SurfaceObject) -> Option<String> {
    if object.class == SurfaceClass::Config {
        // Suggest a directory grant on the parent — the open `AclBackend` enforces
        // a directory rewrite-proof, so steering the author to the dir (not the
        // bare file) is the correct, enforceable remediation.
        let dir = parent_dir(&object.key);
        return Some(format!("file grant rw on {dir} (recursive)"));
    }
    suggest_permission(object)
}

/// The parent directory of a path (`/etc/ssh/sshd_config` → `/etc/ssh`). A path
/// with no `/` after the root, or the root itself, yields the path unchanged.
fn parent_dir(path: &str) -> &str {
    match path.rsplit_once('/') {
        // Keep the leading `/` for a top-level path (`/foo` → `/`).
        Some(("", _)) => "/",
        Some((parent, _)) => parent,
        None => path,
    }
}

/// The final path component of a binary path (`/usr/bin/su` → `su`).
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

// --- reverse lookup: which-grants -------------------------------------------
//
// The inverse of coverage: given a path or command, which catalog permissions
// grant access to it, and how. A read-only query (even "no grants" is success) —
// it never runs the binary or reads file content.

/// Who a grant lands on: a role account or a Unix group. The reverse lookup
/// echoes this into each match so the operator sees whether access is reached
/// through a per-account mechanism (`census-<role>` sudoers, `u:account` ACL) or
/// a group mechanism (`%group` sudoers, `g:group` ACL) — and, for the latter,
/// which group (every member inherits the grant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantTarget {
    /// The grant is carried by a role-account permission set (per-account
    /// mechanism). The string is informational (the catalog permission id is the
    /// authoritative key already on `GrantSource`); account sources use this so
    /// the account path renders exactly as before.
    Account(String),
    /// The grant is bound to the named Unix group: every member (including
    /// effectively-nested LDAP members) inherits it. Rendered via `%group`
    /// sudoers / `g:group` ACL.
    Group(String),
}

impl GrantTarget {
    /// The group name when this is a group target, else `None`. Lets the renderer
    /// and JSON pick the group-mechanism wording without matching the full enum.
    pub fn group(&self) -> Option<&str> {
        match self {
            GrantTarget::Group(g) => Some(g),
            GrantTarget::Account(_) => None,
        }
    }
}

/// A single grant origin's resolved grants, reduced to what the reverse lookup
/// needs: its id, the target it lands on (account or group), advisory risk, the
/// concrete sudo command strings it expands to, and its resolved file grants.
/// Built by the CLI from `catalog::resolve` over `all_definitions` (account
/// sources) and from `model::resolve_groups` (group sources), so the matching
/// core stays pure (no catalog/OS I/O) and is unit-tested directly from
/// hand-built sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSource {
    /// The permission id (account source) or group name (group source) that
    /// carries these grants — the audit key shown as the match's `permission`.
    pub id: String,
    /// Who the grant lands on. Account sources render via the per-account
    /// mechanism (unchanged); group sources render via `%group` / `g:group` and
    /// name the inheriting group.
    pub target: GrantTarget,
    /// Advisory risk class of the permission, echoed into each match.
    pub risk: Option<Risk>,
    /// Concrete sudo command strings the source expands to (templated
    /// commands with an unfilled `{placeholder}` are skipped by the CLI builder —
    /// a reverse lookup is over concrete grants, not templates).
    pub sudo: Vec<String>,
    /// Resolved file grants the source carries.
    pub file_grants: Vec<ResolvedFileGrant>,
}

/// What kind of grant matched the queried argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantKind {
    /// The arg is the binary of one of the permission's sudo commands.
    Sudo,
    /// The arg is covered by one of the permission's file grants.
    File,
}

impl GrantKind {
    /// Stable lowercase token for JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            GrantKind::Sudo => "sudo",
            GrantKind::File => "file",
        }
    }
}

/// One reverse-lookup match: a permission that grants access to the queried arg,
/// with the detail of HOW.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantMatch {
    /// The permission id (account source) or group name (group source) that
    /// grants access.
    pub permission: String,
    /// Who the grant lands on — an account-carried permission or a group every
    /// member inherits. Drives the rendered mechanism (`via sudo` / `via file`
    /// for accounts; `via %group sudoers` / `via g:group ACL` for groups).
    pub target: GrantTarget,
    /// Whether access is via sudo or via a file grant.
    pub kind: GrantKind,
    /// For a sudo match, the matching sudo command string; for a file match, the
    /// grant path. The concrete thing the operator should look at.
    pub detail: String,
    /// For a file match, the access (`ro`/`rw`); `None` for a sudo match.
    pub access: Option<Access>,
    /// For a file match, whether the grant is recursive; `None` for a sudo match.
    pub recursive: Option<bool>,
    /// The enforcing backend, when a file match names one (Dir → `AclBackend`);
    /// `None` for a sudo match (the mechanism is sudoers, implied by the kind).
    pub backend: Option<String>,
    /// Advisory risk class of the granting permission.
    pub risk: Option<Risk>,
}

/// Reverse lookup: which permissions in `sources` grant access to `arg`, and how.
///
/// Match rules (mirroring the forward coverage match exactly):
///
/// - **sudo/command**: a permission matches when the argv-leading binary token of one of its sudo
///   commands (the first whitespace-delimited token — args only narrow what the binary does, they
///   do not change which binary is reachable) equals `arg`. `arg` is itself reduced to its leading
///   token so passing a full command (`/usr/sbin/ip link`) matches the same as the bare binary.
/// - **file**: a permission matches when one of its file grants covers `arg` — exact path equality
///   (any shape) or `arg` strictly under a `recursive` Dir grant on a `/`-component boundary (the
///   same [`grant_covers_path`] rule coverage uses, so a recursive `/etc/ssh` grant matches
///   `/etc/ssh/sshd_config` but not `/etc/sshd_other`).
///
/// One permission can yield several matches (multiple matching sudo commands or
/// file grants). Results are in source order, sudo matches before file matches per
/// permission. An `arg` that matches nothing yields an empty vec — the caller
/// treats that as a successful "no grants" query, not an error.
pub fn which_grants(arg: &str, sources: &[GrantSource]) -> Vec<GrantMatch> {
    // Reduce the query to its leading binary token so a full command line and the
    // bare binary are treated identically (argv-boundary, like coverage).
    let arg_bin = sudo_binary_token(arg).unwrap_or(arg);

    let mut out: Vec<GrantMatch> = Vec::new();
    for src in sources {
        for cmd in &src.sudo {
            if let Some(bin) = sudo_binary_token(cmd) {
                if bin == arg_bin {
                    out.push(GrantMatch {
                        permission: src.id.clone(),
                        target: src.target.clone(),
                        kind: GrantKind::Sudo,
                        detail: cmd.clone(),
                        access: None,
                        recursive: None,
                        backend: None,
                        risk: src.risk,
                    });
                }
            }
        }
        for g in &src.file_grants {
            // File grants are matched on the literal path argument (not the
            // leading-token reduction — a path is not a command line).
            if grant_covers_path(g, arg).is_some() {
                out.push(GrantMatch {
                    permission: src.id.clone(),
                    target: src.target.clone(),
                    kind: GrantKind::File,
                    detail: g.path.clone(),
                    access: Some(g.access),
                    recursive: Some(g.recursive),
                    backend: Some(grant_backend(g)),
                    risk: src.risk,
                });
            }
        }
    }
    out
}

/// The backend that enforces a file grant, by shape. A directory grant is enforced
/// by the open `AclBackend`; File/Pattern shapes need a capability-gated backend,
/// stated honestly so the match does not imply the open build can enforce them.
fn grant_backend(grant: &ResolvedFileGrant) -> String {
    match grant.shape {
        Shape::Dir => "AclBackend".to_owned(),
        Shape::File => "per-file-capable backend".to_owned(),
        Shape::Pattern => "pattern-capable backend".to_owned(),
    }
}

// --- live surface scanner ---------------------------------------------------

/// Roots the live scanner walks/queries. Injectable so a (later) container test
/// can point at a fixture tree instead of the real `/`; unit tests never use this
/// (they go through `FakeSurface` + the pure core), so `LiveSurface` is
/// deliberately thin and unit-untested by design — its real enumeration is
/// exercised only by the container test.
#[derive(Debug, Clone)]
pub struct LiveSurface {
    /// Filesystem root to scan (real `/` in production; a fixture in tests).
    pub root: std::path::PathBuf,
    /// Directories holding sudo-reachable admin binaries (e.g. `/usr/sbin`,
    /// `/sbin`), relative to `root`.
    pub sudo_bin_dirs: Vec<std::path::PathBuf>,
}

impl LiveSurface {
    /// The production configuration: scan `/`, sudo binaries from the system
    /// admin directories.
    pub fn system() -> Self {
        LiveSurface {
            root: std::path::PathBuf::from("/"),
            sudo_bin_dirs: vec![
                std::path::PathBuf::from("/usr/sbin"),
                std::path::PathBuf::from("/sbin"),
            ],
        }
    }
}

/// Virtual / pseudo filesystem roots never walked for setuid files: they hold no
/// real on-disk binaries, and descending them is both pointless and (for `/proc`)
/// a way to wander into other processes. Kept absolute (under `root`) — the walker
/// skips a directory whose path equals one of these.
const VIRTUAL_DIRS: &[&str] = &["proc", "sys", "run", "dev"];

/// Standard on-disk binary directories `getcap` is scoped to (instead of `-r /`).
/// Capability-bearing files realistically live in these trees; scoping `getcap`
/// here keeps it on the root device and off NFS/FUSE/virtual mounts (`getcap` has
/// no `-xdev`), so a wedged mount cannot hang the audit. Only the ones that exist
/// under the scan root are passed (see [`LiveSurface::scan_capfiles`]).
const CAPFILE_SCAN_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/lib",
    "/usr/libexec",
];

impl SurfaceScanner for LiveSurface {
    fn scan(&self, classes: &[SurfaceClass]) -> Result<ScanOutcome, CoverageError> {
        // Read-only enumeration of the requested classes. Each class is gathered
        // independently; a class the caller did not request is skipped entirely so
        // an operator can scope an audit (`--class group` must not pay for a `/`
        // walk). Provenance is resolved in one bulk pass at the end so we shell out
        // to `dpkg` once, not per-object.
        let mut objects: Vec<SurfaceObject> = Vec::new();
        // Per-class scan degradations: a tool that was present but failed (see
        // `CaptureOutcome::Degraded`). Each propagates into the report so a
        // half-enumerated class is visible and fails the `--min-coverage` gate
        // closed instead of silently shrinking the denominator.
        let mut degraded: Vec<ScanDegraded> = Vec::new();

        if classes.contains(&SurfaceClass::SudoBin) {
            objects.extend(self.scan_sudo_bins()?);
        }
        if classes.contains(&SurfaceClass::Config) {
            let (objs, deg) = self.scan_configs();
            objects.extend(objs);
            degraded.extend(deg);
        }
        if classes.contains(&SurfaceClass::Unit) {
            let (objs, deg) = self.scan_units();
            objects.extend(objs);
            degraded.extend(deg);
        }
        if classes.contains(&SurfaceClass::Group) {
            objects.extend(self.scan_groups()?);
        }
        if classes.contains(&SurfaceClass::CapFile) {
            let (objs, deg) = self.scan_capfiles();
            objects.extend(objs);
            degraded.extend(deg);
        }
        if classes.contains(&SurfaceClass::Setuid) {
            objects.extend(self.scan_setuid()?);
        }

        // Bulk provenance: one `dpkg -S` over every path-keyed object marks
        // package-owned objects Vendor/Addon; the rest stay Orphan. Missing `dpkg`
        // ⇒ everything keeps its default Orphan (no crash) — see resolve_provenance.
        self.resolve_provenance(&mut objects);

        Ok(ScanOutcome { objects, degraded })
    }
}

impl LiveSurface {
    /// Enumerate sudo-reachable admin binaries from `sudo_bin_dirs`. A symlink is
    /// reported under its canonical (symlink-resolved) path so coverage matches the
    /// real binary the catalog grants, not an alias. A directory that does not
    /// exist is simply skipped (a minimal system may lack `/sbin`); a total failure
    /// to read ALL configured dirs is a hard `Scan` error (we cannot honestly claim
    /// "no admin binaries").
    fn scan_sudo_bins(&self) -> Result<Vec<SurfaceObject>, CoverageError> {
        let mut out: Vec<SurfaceObject> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut any_dir = false;
        for dir in &self.sudo_bin_dirs {
            let full = self.root.join(dir.strip_prefix("/").unwrap_or(dir));
            let entries = match std::fs::read_dir(&full) {
                Ok(e) => e,
                Err(e) => {
                    // A missing admin dir is fine; skip it. Logged at debug so a
                    // surprising skip is diagnosable without flooding a normal run.
                    tracing::debug!(path = %full.display(), reason = %e, "skipping unreadable sudo-bin dir");
                    continue;
                }
            };
            any_dir = true;
            for entry in entries.flatten() {
                let path = entry.path();
                // Resolve symlinks to the real binary; on failure (dangling link,
                // permission) fall back to the literal path rather than dropping it.
                //
                // FALSE-GAP CAVEAT: when canonicalization fails we key the object
                // on its literal (un-resolved) path. The catalog grants the real
                // binary's canonical path, so an object that could only be resolved
                // to an alias may read as an uncovered orphan even though the
                // underlying binary IS covered — an over-report in the safe (audit
                // flags more, not fewer) direction.
                let canonical = match std::fs::canonicalize(&path) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::debug!(
                            path = %path.display(),
                            reason = %e,
                            "canonicalize failed; keying object on literal path (may over-report)"
                        );
                        path.clone()
                    }
                };
                let key = canonical.to_string_lossy().into_owned();
                if !seen.insert(key.clone()) {
                    continue; // already recorded this canonical binary
                }
                let detail = mode_detail(&path);
                out.push(SurfaceObject {
                    class: SurfaceClass::SudoBin,
                    key,
                    provenance: Provenance::Orphan,
                    detail,
                });
            }
        }
        if !any_dir && !self.sudo_bin_dirs.is_empty() {
            return Err(CoverageError::Scan(format!(
                "no admin binary directory could be read under {}",
                self.root.display()
            )));
        }
        Ok(out)
    }

    /// Enumerate security-relevant `/etc` configs: package conffiles (via
    /// `dpkg-query`) plus any well-known drop-in directories that exist.
    ///
    /// Returns the objects plus an optional degradation. An ABSENT `dpkg-query` is
    /// non-fatal and not a degradation — config enumeration legitimately falls back
    /// to the on-disk drop-in dirs. But a `dpkg-query` that is PRESENT yet fails
    /// (non-zero exit, timeout, non-UTF-8) would silently drop the conffile half of
    /// the surface, so it is reported as a `Config` degradation; the drop-in dirs
    /// are still returned.
    fn scan_configs(&self) -> (Vec<SurfaceObject>, Option<ScanDegraded>) {
        let mut out: Vec<SurfaceObject> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut degraded: Option<ScanDegraded> = None;

        // Package conffiles: `dpkg-query -W -f='${Conffiles}\n'` lists, per package,
        // lines of `"<path> <md5>"`. We keep only paths under `/etc` (the security-
        // relevant surface) and ignore the checksum (we never read content).
        // dpkg-query must succeed cleanly: a truncated conffile listing parsed as
        // complete would under-report the config surface.
        match run_capture("dpkg-query", &["-W", "-f=${Conffiles}\n"], false) {
            CaptureOutcome::Ok(stdout) => {
                for path in parse_dpkg_conffiles(&stdout) {
                    if !seen.insert(path.clone()) {
                        continue;
                    }
                    out.push(SurfaceObject {
                        class: SurfaceClass::Config,
                        key: path,
                        provenance: Provenance::Orphan,
                        detail: "conffile".to_owned(),
                    });
                }
            }
            // No dpkg-query: legitimately fall back to the on-disk drop-in dirs.
            CaptureOutcome::Absent => {}
            // Present but failed: the conffile surface is incomplete — flag it.
            CaptureOutcome::Degraded(reason) => {
                degraded = Some(ScanDegraded {
                    class: SurfaceClass::Config,
                    reason,
                });
            }
        }

        // Drop-in directories: well-known fragment dirs whose mere presence implies
        // a security-relevant config surface (sudoers, sysctl, ssh). We record the
        // directory itself; enumerating every fragment would be noise and risks
        // reading content. Only dirs that actually exist are added.
        for d in CONFIG_DROPIN_DIRS {
            let full = self.root.join(d.strip_prefix('/').unwrap_or(d));
            if full.is_dir() {
                let key = d.to_string();
                if !seen.insert(key.clone()) {
                    continue;
                }
                out.push(SurfaceObject {
                    class: SurfaceClass::Config,
                    key,
                    provenance: Provenance::Orphan,
                    detail: "drop-in dir".to_owned(),
                });
            }
        }
        (out, degraded)
    }

    /// Enumerate systemd service units via `systemctl list-unit-files`.
    ///
    /// Returns the objects plus an optional degradation. An ABSENT `systemctl` (a
    /// non-systemd host, a container without it) ⇒ no units, no degradation: a
    /// unit-less host simply has nothing in this class. A PRESENT `systemctl` that
    /// fails (non-zero exit, timeout, non-UTF-8) would parse a partial listing as
    /// the whole and under-report the unit surface, so it is flagged degraded.
    fn scan_units(&self) -> (Vec<SurfaceObject>, Option<ScanDegraded>) {
        let stdout = match run_capture(
            "systemctl",
            &["list-unit-files", "--no-legend", "--type=service"],
            false,
        ) {
            CaptureOutcome::Ok(s) => s,
            CaptureOutcome::Absent => return (Vec::new(), None),
            CaptureOutcome::Degraded(reason) => {
                return (
                    Vec::new(),
                    Some(ScanDegraded {
                        class: SurfaceClass::Unit,
                        reason,
                    }),
                );
            }
        };
        let objs = parse_systemctl_units(&stdout)
            .into_iter()
            .map(|name| SurfaceObject {
                class: SurfaceClass::Unit,
                key: name,
                // Units are not path-keyed; provenance stays Orphan (the bulk dpkg
                // pass keys on filesystem paths, not unit names).
                provenance: Provenance::Orphan,
                detail: "service".to_owned(),
            })
            .collect();
        (objs, None)
    }

    /// Enumerate groups by reading `/etc/group` directly (not `getent`, to avoid a
    /// shell-out and to stay deterministic for the container test). A read failure
    /// is a hard error — a coverage run that cannot see the group surface would
    /// silently under-report gate-keeping groups.
    fn scan_groups(&self) -> Result<Vec<SurfaceObject>, CoverageError> {
        let path = self.root.join("etc/group");
        let text = crate::fsutil::read_capped(&path, crate::fsutil::MAX_INPUT_FILE_BYTES)
            .map_err(|e| CoverageError::Scan(format!("cannot read {}: {e}", path.display())))?;
        Ok(parse_etc_group(&text)
            .into_iter()
            .map(|name| SurfaceObject {
                class: SurfaceClass::Group,
                key: name,
                provenance: Provenance::Orphan,
                detail: "group".to_owned(),
            })
            .collect())
    }

    /// Enumerate capability-bearing files via `getcap -r` over the standard binary
    /// directories.
    ///
    /// `getcap` is scoped to [`CAPFILE_SCAN_DIRS`] (the on-disk binary trees that
    /// actually exist under `root`) rather than `getcap -r /`. `getcap` has no
    /// `-xdev`, so `-r /` would descend NFS/FUSE/virtual mounts and could hang the
    /// whole audit on a single wedged mount; capability-bearing files live in binary
    /// dirs, so scoping loses nothing real while staying on the root device. The
    /// wall-clock timeout in [`run_capture`] bounds it regardless.
    ///
    /// Returns the objects plus an optional degradation. An ABSENT `getcap` (the
    /// tool is optional on minimal systems) ⇒ no capfiles, no degradation. A PRESENT
    /// `getcap` that fails (non-zero exit, timeout, non-UTF-8) would under-report
    /// capability-bearing binaries, so it is flagged degraded.
    fn scan_capfiles(&self) -> (Vec<SurfaceObject>, Option<ScanDegraded>) {
        // Only the binary dirs that exist under `root` (a minimal system may lack
        // `/usr/local/sbin`, a fixture root may have just one). Keys are passed argv.
        let dirs: Vec<String> = CAPFILE_SCAN_DIRS
            .iter()
            .map(|d| self.root.join(d.strip_prefix('/').unwrap_or(d)))
            .filter(|p| p.is_dir())
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        if dirs.is_empty() {
            // No standard binary dir present: nothing to scan, not a degradation.
            return (Vec::new(), None);
        }
        let mut args: Vec<&str> = Vec::with_capacity(dirs.len() + 1);
        args.push("-r");
        args.extend(dirs.iter().map(String::as_str));

        let stdout = match run_capture("getcap", &args, false) {
            CaptureOutcome::Ok(s) => s,
            CaptureOutcome::Absent => return (Vec::new(), None),
            CaptureOutcome::Degraded(reason) => {
                return (
                    Vec::new(),
                    Some(ScanDegraded {
                        class: SurfaceClass::CapFile,
                        reason,
                    }),
                );
            }
        };
        let objs = parse_getcap(&stdout)
            .into_iter()
            .map(|(path, caps)| SurfaceObject {
                class: SurfaceClass::CapFile,
                key: path,
                provenance: Provenance::Orphan,
                detail: caps,
            })
            .collect();
        (objs, None)
    }

    /// Walk the filesystem from `root` collecting setuid/setgid binaries. Stays on
    /// the root device (`-xdev` semantics via `st_dev`) and skips virtual
    /// filesystems, so it never wanders into `/proc` or a network mount. An IO
    /// error on a single entry is skipped (a permission-denied subtree must not
    /// abort the whole audit); a failure to even open the root is fatal.
    fn scan_setuid(&self) -> Result<Vec<SurfaceObject>, CoverageError> {
        use std::os::unix::fs::MetadataExt;
        let root_meta = std::fs::metadata(&self.root)
            .map_err(|e| CoverageError::Scan(format!("cannot stat scan root: {e}")))?;
        let root_dev = root_meta.dev();

        let mut out: Vec<SurfaceObject> = Vec::new();
        // Iterative DFS with an explicit stack to bound recursion depth.
        let mut stack: Vec<std::path::PathBuf> = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            // Skip virtual filesystem roots (paths like `<root>/proc`).
            if is_virtual_dir(&self.root, &dir) {
                continue;
            }
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => continue, // unreadable subtree: skip, do not abort
            };
            for entry in entries.flatten() {
                let path = entry.path();
                // Use symlink-free metadata so a symlink is never followed off the
                // device or into a loop; we only care about real files/dirs.
                let meta = match std::fs::symlink_metadata(&path) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                // -xdev: never cross onto another device (network/virtual mounts).
                if meta.dev() != root_dev {
                    continue;
                }
                let ft = meta.file_type();
                if ft.is_dir() {
                    stack.push(path);
                } else if ft.is_file() && is_setuid_mode(meta.mode()) {
                    out.push(SurfaceObject {
                        class: SurfaceClass::Setuid,
                        key: path.to_string_lossy().into_owned(),
                        provenance: Provenance::Orphan,
                        detail: format!("mode {:04o}", meta.mode() & 0o7777),
                    });
                }
            }
        }
        Ok(out)
    }

    /// Mark package-owned path-keyed objects with their provenance in one bulk
    /// `dpkg -S` pass. Objects whose key is not an absolute filesystem path (units,
    /// groups) and any object `dpkg` does not know are left `Orphan`. If `dpkg` is
    /// absent the whole pass is a no-op — every object simply keeps `Orphan`, which
    /// for an audit reads as "ownership unknown", never a crash.
    fn resolve_provenance(&self, objects: &mut [SurfaceObject]) {
        // Only path-keyed classes can be looked up by `dpkg -S`.
        let paths: Vec<String> = objects
            .iter()
            .filter(|o| o.key.starts_with('/'))
            .map(|o| o.key.clone())
            .collect();
        if paths.is_empty() {
            return;
        }
        // Pass paths in fixed-size batches. A full `/` scan yields thousands of
        // paths; a single `dpkg -S p1 p2 …` argv would overrun ARG_MAX (E2BIG),
        // `run_capture` would return None, and EVERY object would silently fall
        // back to Orphan — flooding the anomaly list. Chunking bounds each argv;
        // a chunk that still fails degrades only its own paths to Orphan.
        let mut owners: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for chunk in paths.chunks(DPKG_SEARCH_CHUNK) {
            let mut args: Vec<&str> = vec!["-S"];
            args.extend(chunk.iter().map(String::as_str));
            // dpkg -S exits non-zero when SOME paths in the chunk are unowned yet
            // still prints the owned ones — accept that partial stdout. Provenance
            // is not a coverage grant class (a missing owner only leaves an object
            // `Orphan`, never inflates the metric), so a degraded `dpkg` chunk is
            // handled the same as an absent tool: its paths simply stay `Orphan`.
            let stdout = match run_capture("dpkg", &args, true) {
                CaptureOutcome::Ok(s) => s,
                CaptureOutcome::Absent | CaptureOutcome::Degraded(_) => continue,
            };
            merge_dpkg_owners(&mut owners, parse_dpkg_search(&stdout));
        }
        // O(1) owner lookup per object instead of a linear scan of the owner list
        // (a full-`/` scan has thousands of objects AND thousands of owners).
        for o in objects.iter_mut() {
            if let Some(pkg) = owners.get(&o.key) {
                o.provenance = classify_owner(pkg);
            }
        }
    }
}

/// How many paths to pass to one `dpkg -S` invocation. Chosen well under ARG_MAX
/// (typically ~2 MiB on Linux) even with long paths, so the argv never overruns
/// on a full-filesystem scan. Larger would be fewer process spawns but risks
/// E2BIG; 256 keeps each invocation safely bounded.
const DPKG_SEARCH_CHUNK: usize = 256;

/// Fold one chunk's parsed `dpkg -S` `(path, pkg)` pairs into the accumulating
/// owner map. The first owner seen for a path wins (a path repeated across
/// chunks — possible only if the caller batched a duplicate — keeps its initial
/// owner). A `HashMap` with `entry().or_insert` gives that first-wins semantics
/// in O(1) per pair rather than a linear membership scan. Pure so the chunk-merge
/// is unit-testable without shelling out.
fn merge_dpkg_owners(
    acc: &mut std::collections::HashMap<String, String>,
    chunk: Vec<(String, String)>,
) {
    for (path, pkg) in chunk {
        acc.entry(path).or_insert(pkg);
    }
}

/// Well-known security-relevant drop-in directories whose presence implies a
/// config surface. Recorded as directories (not per-fragment) to keep the report
/// signal-dense and avoid reading any file content.
const CONFIG_DROPIN_DIRS: &[&str] = &[
    "/etc/sudoers.d",
    "/etc/sysctl.d",
    "/etc/ssh/sshd_config.d",
    "/etc/pam.d",
    "/etc/security/limits.d",
];

/// Whether a path is (or is under) a virtual filesystem root relative to `root`.
/// Used by the setuid walker to skip `/proc /sys /run /dev` without crossing into
/// them.
fn is_virtual_dir(root: &std::path::Path, dir: &std::path::Path) -> bool {
    VIRTUAL_DIRS.iter().any(|v| dir == root.join(v))
}

/// Whether a Unix mode has the setuid or setgid bit set. Pure so it is unit-tested
/// with hand-built modes (the only setuid logic worth a test — the walk itself is
/// container-tested).
fn is_setuid_mode(mode: u32) -> bool {
    mode & 0o6000 != 0
}

/// Render a `mode NNNN` detail for a path, best-effort. An unstattable path yields
/// an empty detail rather than failing the whole enumeration.
fn mode_detail(path: &std::path::Path) -> String {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(m) => format!("mode {:04o}", m.mode() & 0o7777),
        Err(_) => String::new(),
    }
}

/// Outcome of running an external scan tool. Distinguishes the two cases the old
/// `Option` conflated, which is what lets the coverage gate fail closed:
///
///   * [`CaptureOutcome::Absent`] — the tool is not installed
///     (`io::ErrorKind::NotFound`). The class it would enumerate is legitimately
///     empty on this host (a non-systemd box has no units); NOT a degradation.
///   * [`CaptureOutcome::Degraded`] — the tool is present but its output cannot be
///     trusted: a spawn error other than NotFound, a non-zero exit, non-UTF-8
///     output, or a wall-clock timeout. The class was not fully enumerated, so the
///     caller marks it degraded and the metric/gate fail closed rather than
///     silently shrinking the denominator.
///   * [`CaptureOutcome::Ok`] — stdout captured cleanly (or accepted partial; see
///     `accept_partial`).
#[derive(Debug)]
enum CaptureOutcome {
    /// Captured stdout (clean success, or accepted partial output).
    Ok(String),
    /// The tool is not installed; the class is legitimately empty.
    Absent,
    /// The tool is present but its run failed; carries a human reason.
    Degraded(String),
}

/// Wall-clock budget for a single external scan command. Generous: the scan tools
/// (`getcap -r`, `systemctl`, `dpkg-query`) finish in well under a second on a
/// healthy host. The budget exists only to bound a pathological case — chiefly
/// `getcap` walking onto a wedged NFS/FUSE mount (it has no `-xdev`) — so a single
/// hung syscall cannot stall the whole read-only audit indefinitely. On expiry the
/// child is killed and the class is treated as DEGRADED.
const SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How often the watchdog polls the child for exit while waiting out the timeout.
/// Small enough to react promptly, large enough not to busy-spin.
const SCAN_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

/// Run an external command read-only with a wall-clock timeout, capturing stdout.
/// ARGV-only: the program and args go directly to `Command`, never via a shell, so
/// no argument can be read as a shell metacharacter.
///
/// `accept_partial` controls how a NON-ZERO exit with non-empty stdout is treated:
///
///   * `true` — accept the partial stdout. ONLY `dpkg -S` needs this: it exits non-zero when SOME
///     queried paths are unowned yet still prints the owned ones, and dropping that output would
///     flood every path to `Orphan`.
///   * `false` — require `status.success()`. For `systemctl` / `getcap` / `dpkg-query`, a non-zero
///     exit means the listing is incomplete or failed, and parsing truncated output as if it were
///     complete would under-report the surface, so it degrades.
///
/// See [`run_capture_inner`] for the timeout mechanics; this wrapper fixes the
/// budget to [`SCAN_TIMEOUT`].
fn run_capture(program: &str, args: &[&str], accept_partial: bool) -> CaptureOutcome {
    run_capture_inner(program, args, accept_partial, SCAN_TIMEOUT)
}

/// [`run_capture`] with an explicit timeout (so the timeout path is unit-testable
/// without waiting a minute).
///
/// stdout is drained on a dedicated thread so a child that fills the pipe buffer
/// cannot deadlock the watchdog, which polls `try_wait` until the child exits or
/// `timeout` elapses. On timeout the child is killed and the class is `Degraded`.
fn run_capture_inner(
    program: &str,
    args: &[&str],
    accept_partial: bool,
    timeout: std::time::Duration,
) -> CaptureOutcome {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Tool not installed: a legitimately empty class, not a degradation.
            tracing::debug!(program, "scan tool absent; class legitimately empty");
            return CaptureOutcome::Absent;
        }
        Err(e) => {
            tracing::debug!(program, reason = %e, "scan tool spawn failed; degrading");
            return CaptureOutcome::Degraded(format!("{program}: spawn failed: {e}"));
        }
    };

    // Drain stdout on a separate thread; without this a child that writes more than
    // the pipe buffer holds would block on write while we block on wait — a deadlock.
    let reader = child.stdout.take().map(|mut out| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            out.read_to_end(&mut buf).map(|_| buf)
        })
    });

    // Watchdog: poll for exit until the timeout, then kill.
    let start = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    if let Some(reader) = reader {
                        let _ = reader.join();
                    }
                    tracing::debug!(
                        program,
                        timeout_s = timeout.as_secs(),
                        "scan tool timed out; degrading"
                    );
                    return CaptureOutcome::Degraded(format!(
                        "{program}: timed out after {}s",
                        timeout.as_secs()
                    ));
                }
                std::thread::sleep(SCAN_POLL_INTERVAL);
            }
            Err(e) => {
                let _ = child.kill();
                // Reap the killed child so a transient `try_wait` error does not
                // leave a zombie, matching the timeout arm above.
                let _ = child.wait();
                if let Some(reader) = reader {
                    let _ = reader.join();
                }
                tracing::debug!(program, reason = %e, "scan tool wait failed; degrading");
                return CaptureOutcome::Degraded(format!("{program}: wait failed: {e}"));
            }
        }
    };

    let bytes = match reader {
        Some(handle) => match handle.join() {
            Ok(Ok(buf)) => buf,
            Ok(Err(e)) => {
                tracing::debug!(program, reason = %e, "scan tool stdout read failed; degrading");
                return CaptureOutcome::Degraded(format!("{program}: stdout read failed: {e}"));
            }
            Err(_) => {
                return CaptureOutcome::Degraded(format!("{program}: stdout reader panicked"));
            }
        },
        None => Vec::new(),
    };

    let stdout = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(program, reason = %e, "scan tool output not UTF-8; degrading");
            return CaptureOutcome::Degraded(format!("{program}: output not UTF-8: {e}"));
        }
    };
    if status.success() {
        return CaptureOutcome::Ok(stdout);
    }
    if accept_partial && !stdout.is_empty() {
        return CaptureOutcome::Ok(stdout);
    }
    tracing::debug!(program, status = ?status.code(), "scan tool non-zero exit; degrading");
    CaptureOutcome::Degraded(format!("{program}: non-zero exit {:?}", status.code()))
}

/// Classify a `dpkg -S` owner package name into a provenance. A recognizable
/// add-on (third-party, non-base) package carries its name as `Addon`; otherwise a
/// known owner is `Vendor`. The heuristic is deliberately conservative: only a
/// short list of add-on name prefixes is treated as `Addon` — everything else
/// owned is `Vendor` (the base OS surface). Tuned by the container test.
fn classify_owner(pkg: &str) -> Provenance {
    // A `dpkg -S` line may name several comma-separated packages for one path;
    // take the first as the nominal owner.
    let first = pkg.split(',').next().unwrap_or(pkg).trim();
    const ADDON_PREFIXES: &[&str] = &["docker", "containerd", "kubelet", "nvidia"];
    if ADDON_PREFIXES.iter().any(|p| first.starts_with(p)) {
        Provenance::Addon(first.to_owned())
    } else {
        Provenance::Vendor
    }
}

// --- pure parsers (unit-tested with in-memory inputs) -----------------------

/// Trailing marker words `dpkg` may append after the checksum in a `${Conffiles}`
/// record. Peeled off the END before the checksum so a path with a space is not
/// confused with these fixed-shape trailing fields.
const CONFFILE_MARKERS: &[&str] = &["obsolete", "newconffile", "remove-on-upgrade", "remove"];

/// Parse the `${Conffiles}` output of `dpkg-query -W -f='${Conffiles}\n'`. Each
/// non-empty line is `"<path> <md5>[ <marker>]"` (leading whitespace common); we
/// keep only `<path>` and only those under `/etc` (the security-relevant surface).
/// The checksum and any marker are ignored — we never read content.
/// Order-preserving, deduped.
///
/// The fixed-shape fields (`<md5>` and an optional trailing marker) are peeled off
/// the END, so a path that itself contains a space stays intact rather than being
/// truncated at its first space. A record with no checksum field (e.g. the trailing
/// half of a path split by an embedded newline) is skipped, and the `/etc/` prefix
/// gate drops any other stray fragment — neither fabricates a phantom conffile key.
fn parse_dpkg_conffiles(stdout: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Peel an optional trailing marker word, then the md5 checksum, leaving the
        // (possibly space-bearing) path.
        let mut rest = line;
        if let Some((head, last)) = rest.rsplit_once(char::is_whitespace) {
            if CONFFILE_MARKERS.contains(&last) {
                rest = head.trim_end();
            }
        }
        let path = match rest.rsplit_once(char::is_whitespace) {
            Some((path, _md5)) => path.trim_end(),
            None => continue, // no checksum field → not a conffile record
        };
        if !path.starts_with("/etc/") {
            continue;
        }
        let owned = path.to_owned();
        if !out.iter().any(|p| p == &owned) {
            out.push(owned);
        }
    }
    out
}

/// Parse `systemctl list-unit-files --no-legend --type=service`: each line is
/// `"<unit> <state> [preset]"`; we take the leading unit name. Blank lines and the
/// trailing `"N unit files listed."` summary (which `--no-legend` usually omits but
/// some versions still print) are skipped. Order-preserving, deduped.
fn parse_systemctl_units(stdout: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let name = match line.split_whitespace().next() {
            Some(n) => n,
            None => continue,
        };
        // A unit name always carries a `.service` (we asked for service type); a
        // bare summary word like `"123"` or a sentence does not — filter on that.
        if !name.ends_with(".service") {
            continue;
        }
        let owned = name.to_owned();
        if !out.iter().any(|n| n == &owned) {
            out.push(owned);
        }
    }
    out
}

/// Parse `/etc/group`: each non-comment line is `name:passwd:gid:members`; we take
/// the leading `name`. Blank and comment lines are skipped. Order-preserving,
/// deduped.
fn parse_etc_group(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name = match line.split(':').next() {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };
        let owned = name.to_owned();
        if !out.iter().any(|n| n == &owned) {
            out.push(owned);
        }
    }
    out
}

/// Parse `getcap -r <root>` output: each line is `"<path> <caps>"` (older getcap)
/// or `"<path> = <caps>"` (newer). Returns `(path, caps)` pairs. Order-preserving.
///
/// The capability set is a single whitespace-free token at the END of the line
/// (e.g. `cap_net_raw+ep`, or `cap_net_admin,cap_net_raw+ep` — comma-joined, no
/// inner space), so the path is everything before it. Splitting from the END (not
/// the first whitespace) keeps a path that itself contains spaces intact. A line
/// that does not begin with `/` (a banner, or the trailing half of a path with an
/// embedded newline that `lines()` split) or that has no capability token is
/// skipped rather than turned into a bogus object — a path is never fabricated
/// from a fragment we could not parse confidently.
fn parse_getcap(stdout: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // A getcap record always names an absolute path. Anything else is a banner
        // or a wrapped fragment — skip it, do not key an object on it.
        if !line.starts_with('/') {
            continue;
        }
        // Peel the trailing capability token; the remainder (minus the optional
        // ` =` separator of the newer format) is the path.
        let Some((head, caps)) = line.rsplit_once(char::is_whitespace) else {
            // No whitespace at all → no capability token; cannot parse confidently.
            continue;
        };
        let path = head.trim_end().trim_end_matches('=').trim_end();
        let caps = caps.trim();
        if path.is_empty() || !path.starts_with('/') {
            continue;
        }
        out.push((path.to_owned(), caps.to_owned()));
    }
    out
}

/// Parse `dpkg -S <paths>` output: each owned line is `"<pkg>[, <pkg>…]: <path>"`.
/// Lines like `"dpkg-query: no path found matching pattern <p>"` (printed to
/// stderr normally, but tolerated here) are skipped. Returns `(path, pkg)` pairs.
fn parse_dpkg_search(stdout: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Split on the LAST `": "` so a package name containing a colon (rare) does
        // not confuse the path split; `dpkg` uses `"<pkg>: <path>"`.
        let (pkg, path) = match line.rsplit_once(": ") {
            Some((p, path)) => (p.trim(), path.trim()),
            None => continue,
        };
        if path.is_empty() || !path.starts_with('/') {
            continue;
        }
        out.push((path.to_owned(), pkg.to_owned()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{FakeCatalog, ListOverride, ParamConstraint, PermissionDef};

    // --- builders -----------------------------------------------------------

    /// Build a `token`-kind constraint for every `{placeholder}` found across the
    /// given templates. Each catalog record must constrain every placeholder it
    /// uses; the coverage tests only exercise systemd-unit-shaped tokens, so a
    /// token constraint is the right default. A minimal `{name}` scan (the real
    /// placeholder grammar lives in `catalog`) suffices for these fixtures.
    fn token_params_for(templates: &[&str]) -> std::collections::BTreeMap<String, ParamConstraint> {
        let mut m = std::collections::BTreeMap::new();
        for t in templates {
            let mut rest = *t;
            while let Some(open) = rest.find('{') {
                let after = &rest[open + 1..];
                let Some(close) = after.find('}') else { break };
                let name = &after[..close];
                if !name.is_empty() {
                    m.insert(name.to_owned(), ParamConstraint::Token { max_len: None });
                }
                rest = &after[close + 1..];
            }
        }
        m
    }

    fn debian() -> OsTarget {
        OsTarget::new("linux", "debian", None).unwrap()
    }

    fn def(id: &str) -> PermissionDef {
        PermissionDef {
            id: id.to_owned(),
            risk: None,
            category: None,
            groups: ListOverride::default(),
            sudo: ListOverride::default(),
            runas: None,
            limits: None,
            replace: false,
            includes: Vec::new(),
            include_categories: Vec::new(),
            files: Vec::new(),
            params: std::collections::BTreeMap::new(),
        }
    }

    fn includes_def(id: &str, includes: &[&str]) -> PermissionDef {
        PermissionDef {
            includes: includes
                .iter()
                .map(|s| crate::catalog::Include::bare(*s))
                .collect(),
            ..def(id)
        }
    }

    fn sudo_def(id: &str, sudo: &[&str]) -> PermissionDef {
        PermissionDef {
            sudo: ListOverride::Replace(sudo.iter().map(|s| s.to_string()).collect()),
            params: token_params_for(sudo),
            ..def(id)
        }
    }

    fn group_def(id: &str, groups: &[&str]) -> PermissionDef {
        PermissionDef {
            groups: ListOverride::Replace(groups.iter().map(|s| s.to_string()).collect()),
            ..def(id)
        }
    }

    /// A catalog record carrying one `[[file]]` grant (path/access/recursive).
    fn file_def(id: &str, path: &str, access: Access, recursive: bool) -> PermissionDef {
        PermissionDef {
            files: vec![crate::catalog::FileGrant {
                path: path.to_owned(),
                access,
                recursive,
            }],
            params: token_params_for(&[path]),
            ..def(id)
        }
    }

    /// A resolved file grant for a role instance (already concrete/substituted).
    fn rfg(path: &str, access: Access, recursive: bool) -> ResolvedFileGrant {
        ResolvedFileGrant {
            path: path.to_owned(),
            access,
            recursive,
            shape: crate::catalog::FileGrant {
                path: path.to_owned(),
                access,
                recursive,
            }
            .shape(),
            sources: Vec::new(),
        }
    }

    fn obj(class: SurfaceClass, key: &str, prov: Provenance) -> SurfaceObject {
        SurfaceObject {
            class,
            key: key.to_owned(),
            provenance: prov,
            detail: String::new(),
        }
    }

    fn ctx() -> CoverageCtx {
        CoverageCtx {
            strict: false,
            catalog_version: Some("2026.06".to_owned()),
            bound_grant_groups: Vec::new(),
        }
    }

    fn find<'a>(report: &'a CoverageReport, key: &str) -> &'a ObjectCoverage {
        report
            .objects
            .iter()
            .find(|o| o.object.key == key)
            .unwrap_or_else(|| panic!("no object {key} in report"))
    }

    fn class_cov(report: &CoverageReport, class: SurfaceClass) -> &ClassCoverage {
        report.by_class.iter().find(|c| c.class == class).unwrap()
    }

    // --- FakeSurface scanner seam ------------------------------------------

    #[test]
    fn fake_surface_filters_by_class() {
        let s = FakeSurface::new()
            .with(obj(
                SurfaceClass::SudoBin,
                "/usr/sbin/ip",
                Provenance::Vendor,
            ))
            .with(obj(SurfaceClass::Group, "netdev", Provenance::Vendor));
        let only_bins = s.scan(&[SurfaceClass::SudoBin]).unwrap().objects;
        assert_eq!(only_bins.len(), 1);
        assert_eq!(only_bins[0].key, "/usr/sbin/ip");
    }

    // --- sudo_bin coverage -------------------------------------------------

    #[test]
    fn sudo_bin_covered_by_expanded_sudo_string() {
        // Catalog grants sudo /usr/sbin/ip; the binary /usr/sbin/ip is covered.
        let cat = FakeCatalog::new().with("linux", sudo_def("network-admin", &["/usr/sbin/ip"]));
        let surface = vec![obj(
            SurfaceClass::SudoBin,
            "/usr/sbin/ip",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(find(&r, "/usr/sbin/ip").covered);
        assert_eq!(class_cov(&r, SurfaceClass::SudoBin).covered, 1);
    }

    #[test]
    fn sudo_bin_covered_via_argv_boundary() {
        // A sudo string WITH arguments still covers the bare binary: the args only
        // narrow what it does, they do not change which binary is reachable.
        let cat = FakeCatalog::new().with(
            "linux",
            sudo_def("power-control", &["/sbin/shutdown -r now"]),
        );
        let surface = vec![obj(
            SurfaceClass::SudoBin,
            "/sbin/shutdown",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(find(&r, "/sbin/shutdown").covered);
    }

    #[test]
    fn literal_bound_bundle_member_sudo_is_covered() {
        // Coverage-regression guard: a bundle whose include LITERALLY binds a
        // parametrized leaf (e.g. `{ id = "svc-restart", units = "nginx" }`, no
        // role `{param}`) must contribute the rendered member command to the
        // covered set. coverage() resolves every id via `resolve()` WITHOUT params;
        // before eager literal-bound expansion the member's sudo was deferred and
        // silently missing, so the bound binary read as uncovered. With the fix the
        // concrete `/usr/sbin/svcctl` is on the catalog surface.
        let leaf = PermissionDef {
            sudo: ListOverride::Replace(vec!["/usr/sbin/svcctl restart {units}".to_owned()]),
            params: token_params_for(&["/usr/sbin/svcctl restart {units}"]),
            ..def("svc-restart")
        };
        let bundle = PermissionDef {
            includes: vec![crate::catalog::Include {
                id: "svc-restart".to_owned(),
                bindings: std::iter::once(("units".to_owned(), "nginx".to_owned())).collect(),
            }],
            ..def("nginx.operate")
        };
        let cat = FakeCatalog::new().with("linux", leaf).with("linux", bundle);
        let surface = vec![obj(
            SurfaceClass::SudoBin,
            "/usr/sbin/svcctl",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(
            find(&r, "/usr/sbin/svcctl").covered,
            "a literal-bound bundle member's sudo binary must be covered via resolve() without params"
        );
    }

    #[test]
    fn uncovered_sudo_bin_gets_suggestion() {
        // /usr/sbin/cryptsetup not granted by anything → uncovered + suggestion.
        let cat = FakeCatalog::new().with("linux", sudo_def("network-admin", &["/usr/sbin/ip"]));
        let surface = vec![obj(
            SurfaceClass::SudoBin,
            "/usr/sbin/cryptsetup",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        let c = find(&r, "/usr/sbin/cryptsetup");
        assert!(!c.covered);
        assert_eq!(c.suggested_permission.as_deref(), Some("luks-admin"));
    }

    // --- parametrized prefix / strict --------------------------------------

    #[test]
    fn parametrized_prefix_covers_binary_without_instance_non_strict() {
        // A templated record `systemctl restart {unit}` with NO role instance:
        // in non-strict mode the binary /usr/bin/systemctl is potentially covered.
        let cat = FakeCatalog::new().with(
            "linux",
            sudo_def("service-restart", &["/usr/bin/systemctl restart {unit}"]),
        );
        let surface = vec![obj(
            SurfaceClass::SudoBin,
            "/usr/bin/systemctl",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(find(&r, "/usr/bin/systemctl").covered);
    }

    #[test]
    fn parametrized_prefix_not_covered_under_strict() {
        let cat = FakeCatalog::new().with(
            "linux",
            sudo_def("service-restart", &["/usr/bin/systemctl restart {unit}"]),
        );
        let surface = vec![obj(
            SurfaceClass::SudoBin,
            "/usr/bin/systemctl",
            Provenance::Vendor,
        )];
        let strict = CoverageCtx {
            strict: true,
            catalog_version: None,
            bound_grant_groups: Vec::new(),
        };
        let r = coverage(&surface, &cat, &debian(), &[], &strict).unwrap();
        assert!(
            !find(&r, "/usr/bin/systemctl").covered,
            "strict must not count a parametrized record without an instance"
        );
    }

    #[test]
    fn role_instance_covers_named_unit() {
        // A role instance contributes a concrete `systemctl restart atm-app`
        // command; the unit atm-app (and atm-app.service) is then covered, even
        // under strict (a concrete instance, not a bare template).
        let cat = FakeCatalog::new().with(
            "linux",
            sudo_def("service-restart", &["/usr/bin/systemctl restart {unit}"]),
        );
        let role = ResolvedRole::new(
            vec!["/usr/bin/systemctl restart atm-app".to_owned()],
            vec![],
        );
        let surface = vec![
            obj(SurfaceClass::Unit, "atm-app.service", Provenance::Vendor),
            obj(SurfaceClass::Unit, "other.service", Provenance::Vendor),
        ];
        let strict = CoverageCtx {
            strict: true,
            catalog_version: None,
            bound_grant_groups: Vec::new(),
        };
        let r = coverage(&surface, &cat, &debian(), &[role], &strict).unwrap();
        assert!(find(&r, "atm-app.service").covered);
        assert!(!find(&r, "other.service").covered);
    }

    #[test]
    fn service_admin_covers_all_units() {
        // service-admin present → every unit covered, no per-unit instance needed.
        let cat =
            FakeCatalog::new().with("linux", sudo_def("service-admin", &["/usr/bin/systemctl"]));
        let surface = vec![
            obj(SurfaceClass::Unit, "atm-app.service", Provenance::Vendor),
            obj(SurfaceClass::Unit, "sshd.service", Provenance::Vendor),
        ];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(find(&r, "atm-app.service").covered);
        assert!(find(&r, "sshd.service").covered);
    }

    #[test]
    fn unresolvable_service_admin_does_not_flip_unit_class_to_covered() {
        // `service-admin` exists in the catalog but cannot resolve (it includes an
        // unknown id). The class-wide "covers every unit" flag must NOT be set off
        // bare id presence — a permission that never resolves grants nothing. So
        // every unit stays uncovered and the failure is recorded as a catalog
        // warning, instead of a class-wide false "covered".
        let cat =
            FakeCatalog::new().with("linux", includes_def("service-admin", &["does-not-exist"]));
        let surface = vec![
            obj(SurfaceClass::Unit, "atm-app.service", Provenance::Vendor),
            obj(SurfaceClass::Unit, "sshd.service", Provenance::Vendor),
        ];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(
            !find(&r, "atm-app.service").covered,
            "an unresolvable service-admin must not cover units"
        );
        assert!(!find(&r, "sshd.service").covered);
        assert_eq!(class_cov(&r, SurfaceClass::Unit).covered, 0);
        assert!(
            r.catalog_warnings
                .iter()
                .any(|w| w.contains("service-admin")),
            "the unresolvable id must be recorded as a warning: {:?}",
            r.catalog_warnings
        );
    }

    #[test]
    fn unresolvable_capability_admin_does_not_flip_capfile_class_to_covered() {
        // Same fail-closed rule for the capfile class-wide flag: a present-but-
        // unresolvable `capability-admin` must not mark every capfile covered.
        let cat = FakeCatalog::new().with(
            "linux",
            includes_def("capability-admin", &["does-not-exist"]),
        );
        let surface = vec![obj(
            SurfaceClass::CapFile,
            "/usr/bin/ping",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(!find(&r, "/usr/bin/ping").covered);
        assert!(r
            .catalog_warnings
            .iter()
            .any(|w| w.contains("capability-admin")));
    }

    // --- group / capfile ---------------------------------------------------

    #[test]
    fn group_covered_by_set_membership() {
        let cat = FakeCatalog::new().with("linux", group_def("network-admin", &["netdev"]));
        let surface = vec![
            obj(SurfaceClass::Group, "netdev", Provenance::Vendor),
            obj(SurfaceClass::Group, "video", Provenance::Vendor),
        ];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(find(&r, "netdev").covered);
        assert!(!find(&r, "video").covered);
        // netdev carries a domain suggestion; the covered one has none.
        assert_eq!(find(&r, "netdev").suggested_permission, None);
    }

    #[test]
    fn group_covered_by_role_binding_grant() {
        // A group with no membership-covering primitive is an honest gap by
        // default; once a `[[role_group]]` binding attaches a grant to it (folded
        // in via `bound_grant_groups`), the same group object is covered.
        let cat = FakeCatalog::new().with("linux", sudo_def("net", &["/usr/sbin/ip"]));
        let surface = vec![obj(
            SurfaceClass::Group,
            "atm-operators",
            Provenance::Vendor,
        )];

        // No binding → uncovered gap.
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(!find(&r, "atm-operators").covered);

        // With a binding-covered group folded in → covered.
        let bound = CoverageCtx {
            strict: false,
            catalog_version: None,
            bound_grant_groups: vec!["atm-operators".to_owned()],
        };
        let r2 = coverage(&surface, &cat, &debian(), &[], &bound).unwrap();
        assert!(find(&r2, "atm-operators").covered);
        assert_eq!(class_cov(&r2, SurfaceClass::Group).covered, 1);
    }

    #[test]
    fn capfile_covered_by_capability_admin_presence() {
        let with =
            FakeCatalog::new().with("linux", sudo_def("capability-admin", &["/usr/sbin/setcap"]));
        let surface = vec![obj(
            SurfaceClass::CapFile,
            "/usr/bin/ping",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &with, &debian(), &[], &ctx()).unwrap();
        assert!(find(&r, "/usr/bin/ping").covered);

        // Without capability-admin, the same capfile is uncovered.
        let without =
            FakeCatalog::new().with("linux", sudo_def("network-admin", &["/usr/sbin/ip"]));
        let r2 = coverage(&surface, &without, &debian(), &[], &ctx()).unwrap();
        assert!(!find(&r2, "/usr/bin/ping").covered);
    }

    // --- setuid inventory + anomalies --------------------------------------

    #[test]
    fn setuid_reported_as_inventory_not_grant() {
        let cat = FakeCatalog::new().with("linux", sudo_def("network-admin", &["/usr/sbin/ip"]));
        let surface = vec![obj(
            SurfaceClass::Setuid,
            "/usr/bin/mount",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        // It is in the inventory, NOT in the per-object coverage tally and not an
        // anomaly (it is package-owned).
        assert_eq!(r.setuid_inventory.len(), 1);
        assert_eq!(r.setuid_inventory[0].key, "/usr/bin/mount");
        assert!(r.anomalies.is_empty());
        assert!(r.objects.iter().all(|o| o.object.key != "/usr/bin/mount"));
    }

    #[test]
    fn orphan_setuid_is_anomaly() {
        let cat = FakeCatalog::new().with("linux", sudo_def("network-admin", &["/usr/sbin/ip"]));
        let surface = vec![obj(
            SurfaceClass::Setuid,
            "/opt/vendor/flasher",
            Provenance::Orphan,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert_eq!(r.anomalies.len(), 1);
        assert_eq!(r.anomalies[0].key, "/opt/vendor/flasher");
    }

    #[test]
    fn orphan_capfile_is_anomaly() {
        let cat = FakeCatalog::new().with("linux", sudo_def("network-admin", &["/usr/sbin/ip"]));
        let surface = vec![obj(
            SurfaceClass::CapFile,
            "/opt/x/weird",
            Provenance::Orphan,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert_eq!(r.anomalies.len(), 1);
        assert_eq!(r.anomalies[0].key, "/opt/x/weird");
    }

    // --- intentionally-uncovered -------------------------------------------

    #[test]
    fn escalation_mechanism_flagged_not_penalising() {
        let cat = FakeCatalog::new().with("linux", sudo_def("network-admin", &["/usr/sbin/ip"]));
        let surface = vec![
            obj(SurfaceClass::SudoBin, "/usr/bin/su", Provenance::Vendor),
            obj(SurfaceClass::SudoBin, "/usr/sbin/ip", Provenance::Vendor),
        ];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        let su = find(&r, "/usr/bin/su");
        assert!(su.intentional_exclusion.is_some());
        assert!(!su.covered);
        // The metric counts only ip (1/1 = 100%), su does not penalise it.
        assert_eq!(class_cov(&r, SurfaceClass::SudoBin).total, 1);
        assert_eq!(class_cov(&r, SurfaceClass::SudoBin).covered, 1);
        assert_eq!(r.overall_pct, 100.0);
    }

    #[test]
    fn pdpl_binary_flagged_commercial() {
        let cat = FakeCatalog::new().with("linux", sudo_def("network-admin", &["/usr/sbin/ip"]));
        let surface = vec![obj(
            SurfaceClass::SudoBin,
            "/usr/bin/pdpl-user",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        let p = find(&r, "/usr/bin/pdpl-user");
        assert!(p.intentional_exclusion.as_deref().unwrap().contains("pdpl"));
        // Not counted in the metric denominator.
        assert_eq!(class_cov(&r, SurfaceClass::SudoBin).total, 0);
    }

    #[test]
    fn astra_admin_group_flagged_site_layer() {
        let cat = FakeCatalog::new().with("linux", group_def("network-admin", &["netdev"]));
        let surface = vec![obj(SurfaceClass::Group, "astra-admin", Provenance::Vendor)];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        let g = find(&r, "astra-admin");
        assert!(g.intentional_exclusion.is_some());
        assert_eq!(class_cov(&r, SurfaceClass::Group).total, 0);
    }

    // --- overall_pct math + false positives --------------------------------

    #[test]
    fn overall_pct_weighted_by_object_count() {
        // 3 sudo bins (2 covered) + 1 group (1 covered) = 3/4 = 75%.
        let cat = FakeCatalog::new()
            .with("linux", sudo_def("a", &["/usr/sbin/ip", "/usr/bin/nmcli"]))
            .with("linux", group_def("g", &["netdev"]));
        let surface = vec![
            obj(SurfaceClass::SudoBin, "/usr/sbin/ip", Provenance::Vendor),
            obj(SurfaceClass::SudoBin, "/usr/bin/nmcli", Provenance::Vendor),
            obj(
                SurfaceClass::SudoBin,
                "/usr/sbin/cryptsetup",
                Provenance::Vendor,
            ),
            obj(SurfaceClass::Group, "netdev", Provenance::Vendor),
        ];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert_eq!(r.overall_pct, 75.0);
    }

    #[test]
    fn transitive_escape_does_not_fabricate_coverage() {
        // The catalog grants only /usr/bin/vi. /bin/sh is reachable via vi's
        // shell escape, but coverage must NOT mark /bin/sh covered — only the
        // granted binary is covered; the escape is a risk concern, not coverage.
        let cat = FakeCatalog::new().with("linux", sudo_def("edit", &["/usr/bin/vi"]));
        let surface = vec![
            obj(SurfaceClass::SudoBin, "/usr/bin/vi", Provenance::Vendor),
            obj(SurfaceClass::SudoBin, "/bin/sh", Provenance::Vendor),
        ];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(find(&r, "/usr/bin/vi").covered);
        assert!(!find(&r, "/bin/sh").covered);
    }

    #[test]
    fn binary_variants_do_not_auto_cover_each_other() {
        // Granting iptables does NOT cover iptables-restore — the production
        // firewall uses -restore explicitly; they must both be granted or both
        // uncovered.
        let cat = FakeCatalog::new().with("linux", sudo_def("fw", &["/usr/sbin/iptables"]));
        let surface = vec![
            obj(
                SurfaceClass::SudoBin,
                "/usr/sbin/iptables",
                Provenance::Vendor,
            ),
            obj(
                SurfaceClass::SudoBin,
                "/usr/sbin/iptables-restore",
                Provenance::Vendor,
            ),
        ];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(find(&r, "/usr/sbin/iptables").covered);
        assert!(!find(&r, "/usr/sbin/iptables-restore").covered);
    }

    #[test]
    fn sudo_bin_prefix_boundary_does_not_overcover() {
        // Granting sudo `/usr/sbin/ip` must NOT cover the distinct binary
        // `/usr/sbin/ipset`: they share a path PREFIX but are different
        // executables. Guards against a future refactor to a naive `starts_with`
        // reintroducing false coverage at the path-segment boundary.
        let cat = FakeCatalog::new().with("linux", sudo_def("network-admin", &["/usr/sbin/ip"]));
        let surface = vec![
            obj(SurfaceClass::SudoBin, "/usr/sbin/ip", Provenance::Vendor),
            obj(SurfaceClass::SudoBin, "/usr/sbin/ipset", Provenance::Vendor),
        ];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(find(&r, "/usr/sbin/ip").covered);
        assert!(
            !find(&r, "/usr/sbin/ipset").covered,
            "a path-prefix neighbour must not be over-covered"
        );
    }

    #[test]
    fn one_unresolvable_catalog_id_does_not_abort_audit() {
        // A catalog with one cyclic (unresolvable) permission alongside several
        // good ones: coverage must still produce a report over the good ids and
        // record the bad id as a warning — NOT return an Err. A read-only audit
        // ("did we forget anything?") must not be sunk by one malformed record.
        let cat = FakeCatalog::new()
            .with("linux", sudo_def("network-admin", &["/usr/sbin/ip"]))
            .with("linux", group_def("net-grp", &["netdev"]))
            // bad <-> loop: includes each other → resolve returns Cycle for both.
            .with("linux", includes_def("bad", &["loop"]))
            .with("linux", includes_def("loop", &["bad"]));
        let surface = vec![
            obj(SurfaceClass::SudoBin, "/usr/sbin/ip", Provenance::Vendor),
            obj(SurfaceClass::Group, "netdev", Provenance::Vendor),
        ];

        let r = coverage(&surface, &cat, &debian(), &[], &ctx())
            .expect("coverage must not abort on one bad catalog id");

        // The good ids still contributed coverage.
        assert!(find(&r, "/usr/sbin/ip").covered);
        assert!(find(&r, "netdev").covered);

        // The bad id(s) are surfaced as warnings, naming the offending id.
        assert!(
            !r.catalog_warnings.is_empty(),
            "the cyclic id must be recorded as a warning"
        );
        assert!(
            r.catalog_warnings
                .iter()
                .any(|w| w.contains("bad") || w.contains("loop")),
            "warning must name the unresolvable id: {:?}",
            r.catalog_warnings
        );
    }

    #[test]
    fn config_uncovered_without_any_grant() {
        // No file grant touches /etc/ssh; the config object is in scope
        // (security-relevant prefix) but honestly uncovered, with a suggestion to
        // declare a directory file grant.
        let cat = FakeCatalog::new().with("linux", sudo_def("net", &["/usr/sbin/ip"]));
        let surface = vec![obj(
            SurfaceClass::Config,
            "/etc/ssh/sshd_config",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        let c = find(&r, "/etc/ssh/sshd_config");
        assert!(!c.covered);
        assert_eq!(
            c.suggested_permission.as_deref(),
            Some("file grant rw on /etc/ssh (recursive)")
        );
    }

    // --- backend-limited config (single file in non-grantable parent) ------

    #[test]
    fn single_file_in_non_grantable_parent_is_backend_limited_not_a_gap() {
        // /etc/login.defs is security-relevant (in scope) and ungranted, but it
        // sits directly in /etc — a non-grantable parent. The dir-only AclBackend
        // can't cover it without granting all of /etc, so it is backend-limited,
        // NOT an uncovered gap, and it does not count toward the metric.
        let cat = FakeCatalog::new().with("linux", sudo_def("net", &["/usr/sbin/ip"]));
        let surface = vec![obj(
            SurfaceClass::Config,
            "/etc/login.defs",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        let c = find(&r, "/etc/login.defs");
        assert!(!c.covered);
        assert!(
            c.backend_limited.is_some(),
            "a single file in /etc must be backend-limited"
        );
        assert!(c.intentional_exclusion.is_none());
        // Excluded from the config denominator (not a gap, not counted).
        assert_eq!(class_cov(&r, SurfaceClass::Config).total, 0);
        assert_eq!(class_cov(&r, SurfaceClass::Config).covered, 0);
    }

    #[test]
    fn backend_limited_recognises_etc_ssl_bare_file() {
        // /etc/ssl/openssl.cnf sits directly in /etc/ssl (a shared trust dir, in
        // NON_GRANTABLE_PARENTS) — backend-limited, same as a bare /etc file.
        let cat = FakeCatalog::new().with("linux", sudo_def("net", &["/usr/sbin/ip"]));
        let surface = vec![obj(
            SurfaceClass::Config,
            "/etc/ssl/openssl.cnf",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        let c = find(&r, "/etc/ssl/openssl.cnf");
        assert!(c.backend_limited.is_some(), "{c:?}");
        assert_eq!(class_cov(&r, SurfaceClass::Config).total, 0);
    }

    #[test]
    fn file_under_grantable_subdir_stays_a_genuine_gap() {
        // /etc/ssh/sshd_config sits under /etc/ssh, a grantable directory: with no
        // grant it is a GENUINE uncovered gap (not backend-limited), and it counts.
        let cat = FakeCatalog::new().with("linux", sudo_def("net", &["/usr/sbin/ip"]));
        let surface = vec![obj(
            SurfaceClass::Config,
            "/etc/ssh/sshd_config",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        let c = find(&r, "/etc/ssh/sshd_config");
        assert!(!c.covered);
        assert!(
            c.backend_limited.is_none(),
            "a file under a grantable subdir is a real gap, not backend-limited"
        );
        assert_eq!(class_cov(&r, SurfaceClass::Config).total, 1);
    }

    #[test]
    fn exact_file_shape_grant_on_config_is_not_covered_in_open_build() {
        // A per-file (`File`-shape, non-recursive) grant resolved exactly onto a
        // config path does NOT count as covered in the open build: the dir-only
        // AclBackend cannot enforce a single-file grant, so declaring one must not
        // flip the object to covered (which would inflate the numerator off a
        // guarantee the installed backend cannot make). It is routed to the
        // backend-limited bucket — mirroring the ungranted single-file case — and
        // excluded from the metric denominator. A per-file-capable (commercial)
        // backend would cover it; the open build honestly cannot.
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("logindefs", "/etc/login.defs", Access::RW, false),
        );
        let surface = vec![obj(
            SurfaceClass::Config,
            "/etc/login.defs",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        let c = find(&r, "/etc/login.defs");
        assert!(
            !c.covered,
            "an unenforceable File-shape grant must not count as covered"
        );
        assert!(
            c.backend_limited.is_some(),
            "a declared-but-unenforceable File grant routes to backend-limited"
        );
        assert!(c.coverage_note.is_none());
        // Excluded from the denominator, exactly like the ungranted single-file case.
        assert_eq!(class_cov(&r, SurfaceClass::Config).total, 0);
        assert_eq!(class_cov(&r, SurfaceClass::Config).covered, 0);
    }

    #[test]
    fn enforceable_dir_grant_outranks_a_paper_file_grant_on_same_path() {
        // A path covered by BOTH an enforceable recursive Dir grant and a per-file
        // grant is reported as truly covered (via the Dir grant), not demoted to
        // backend-limited: enforceability ranks first in the covering-grant choice.
        let cat = FakeCatalog::new()
            .with("linux", file_def("ssh-dir", "/etc/ssh", Access::RW, true))
            .with(
                "linux",
                file_def("ssh-file", "/etc/ssh/sshd_config", Access::RW, false),
            );
        let surface = vec![obj(
            SurfaceClass::Config,
            "/etc/ssh/sshd_config",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        let c = find(&r, "/etc/ssh/sshd_config");
        assert!(
            c.covered,
            "an enforceable Dir grant must win over a paper File grant"
        );
        assert_eq!(c.coverage_note.as_deref(), Some("rw via AclBackend (dir)"));
        assert!(c.backend_limited.is_none());
        assert_eq!(class_cov(&r, SurfaceClass::Config).covered, 1);
    }

    #[test]
    fn backend_limited_excluded_from_denominator_alongside_real_gap() {
        // A mix: one backend-limited bare /etc file + one genuine gap under a
        // grantable subdir. Only the genuine gap counts (1/1 denominator → 0%
        // covered), the backend-limited one is excluded entirely.
        let cat = FakeCatalog::new().with("linux", sudo_def("net", &["/usr/sbin/ip"]));
        let surface = vec![
            obj(SurfaceClass::Config, "/etc/login.defs", Provenance::Vendor),
            obj(
                SurfaceClass::Config,
                "/etc/ssh/sshd_config",
                Provenance::Vendor,
            ),
        ];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(find(&r, "/etc/login.defs").backend_limited.is_some());
        let gap = find(&r, "/etc/ssh/sshd_config");
        assert!(!gap.covered && gap.backend_limited.is_none());
        assert_eq!(
            class_cov(&r, SurfaceClass::Config).total,
            1,
            "only the genuine gap counts; backend-limited excluded"
        );
    }

    // --- config coverage via file grants (slice 4) -------------------------

    #[test]
    fn config_under_recursive_dir_grant_is_covered_with_backend_note() {
        // Catalog gives a recursive rw Dir grant on /etc/ssh; the config object
        // /etc/ssh/sshd_config under it is covered, with an AclBackend (dir) note.
        let cat =
            FakeCatalog::new().with("linux", file_def("ssh-edit", "/etc/ssh", Access::RW, true));
        let surface = vec![obj(
            SurfaceClass::Config,
            "/etc/ssh/sshd_config",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        let c = find(&r, "/etc/ssh/sshd_config");
        assert!(c.covered);
        assert_eq!(c.coverage_note.as_deref(), Some("rw via AclBackend (dir)"));
        assert_eq!(class_cov(&r, SurfaceClass::Config).covered, 1);
        assert_eq!(class_cov(&r, SurfaceClass::Config).total, 1);
    }

    #[test]
    fn config_ro_vs_rw_distinguished_in_note() {
        // An ro recursive grant yields an `ro` note (not rw).
        let cat =
            FakeCatalog::new().with("linux", file_def("ssh-read", "/etc/ssh", Access::RO, true));
        let surface = vec![obj(
            SurfaceClass::Config,
            "/etc/ssh/sshd_config",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert_eq!(
            find(&r, "/etc/ssh/sshd_config").coverage_note.as_deref(),
            Some("ro via AclBackend (dir)")
        );
    }

    #[test]
    fn config_path_boundary_not_naive_prefix() {
        // /etc/security recursive must NOT cover /etc/securetty — they share a
        // textual prefix but not a path-component boundary. Both are security-
        // relevant (so both are in scope and counted), which makes the boundary
        // miss observable as an uncovered object, guarding against starts_with.
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("sec-edit", "/etc/security", Access::RW, true),
        );
        let surface = vec![
            obj(
                SurfaceClass::Config,
                "/etc/security/limits.conf",
                Provenance::Vendor,
            ),
            obj(SurfaceClass::Config, "/etc/securetty", Provenance::Vendor),
        ];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(find(&r, "/etc/security/limits.conf").covered);
        assert!(
            !find(&r, "/etc/securetty").covered,
            "a textual-prefix neighbour must not be over-covered"
        );
    }

    #[test]
    fn non_recursive_grant_covers_only_exact_path() {
        // A non-recursive File grant on /etc/sudoers MATCHES that exact path, NOT a
        // child of /etc/sudoers.d (which it makes no claim on). In the open build a
        // File-shape grant is declared-but-unenforceable (the dir-only AclBackend
        // can't constrain a single file), so the matched exact path is reported
        // backend-limited rather than covered — but it remains the only path the
        // grant matches.
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("sudoers-edit", "/etc/sudoers", Access::RW, false),
        );
        let surface = vec![
            obj(SurfaceClass::Config, "/etc/sudoers", Provenance::Vendor),
            obj(
                SurfaceClass::Config,
                "/etc/sudoers.d/census",
                Provenance::Vendor,
            ),
        ];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        let exact = find(&r, "/etc/sudoers");
        // Matched by the grant, but a File-shape grant is unenforceable in the open
        // build → backend-limited, not covered.
        assert!(!exact.covered);
        assert!(exact.backend_limited.is_some());
        // The child the non-recursive grant makes no claim on is not covered by it.
        assert!(!find(&r, "/etc/sudoers.d/census").covered);
    }

    #[test]
    fn config_covered_by_role_instance_grant() {
        // A parametrized config-edit grant is templated in the catalog (no concrete
        // path) and only a role instance supplies /etc/nginx. With the role folded
        // in, the config object under it is covered.
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("app-config-edit", "/etc/{app}", Access::RW, true),
        );
        let surface = vec![obj(
            SurfaceClass::Config,
            "/etc/nginx/nginx.conf",
            Provenance::Vendor,
        )];

        // Without the role instance: templated grant is not concrete → uncovered.
        // (/etc/nginx is not in the curated set, so it is only in scope BECAUSE a
        // grant — once concrete — names it; without the instance it is dropped.)
        let r0 = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(r0
            .objects
            .iter()
            .all(|o| o.object.key != "/etc/nginx/nginx.conf"));

        // With the role instance contributing a concrete /etc/nginx recursive grant.
        let role = ResolvedRole::with_file_grants(
            vec![],
            vec![],
            vec![rfg("/etc/nginx", Access::RW, true)],
        );
        let r = coverage(&surface, &cat, &debian(), &[role], &ctx()).unwrap();
        let c = find(&r, "/etc/nginx/nginx.conf");
        assert!(c.covered);
        assert_eq!(c.coverage_note.as_deref(), Some("rw via AclBackend (dir)"));
    }

    #[test]
    fn non_security_relevant_config_excluded_from_denominator() {
        // A low-priority conffile under a grantable subdir (/etc/app/app.conf) is
        // neither security-relevant nor grant-named: by default it is dropped from
        // the config class entirely (not counted, not listed), so the denominator
        // shrinks to the security-relevant object only. Its parent /etc/app is a
        // grantable subdir (NOT in NON_GRANTABLE_PARENTS), so under
        // --include-low-priority it is a genuine gap — distinct from the
        // backend-limited reclassification a bare /etc file would get.
        let cat =
            FakeCatalog::new().with("linux", file_def("ssh-edit", "/etc/ssh", Access::RW, true));
        let surface = vec![
            obj(
                SurfaceClass::Config,
                "/etc/ssh/sshd_config",
                Provenance::Vendor,
            ),
            obj(
                SurfaceClass::Config,
                "/etc/app/app.conf",
                Provenance::Vendor,
            ),
        ];

        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        // Only the security-relevant object is counted (1/1), the low-priority dropped.
        assert_eq!(class_cov(&r, SurfaceClass::Config).total, 1);
        assert!(r
            .objects
            .iter()
            .all(|o| o.object.key != "/etc/app/app.conf"));

        // With --include-low-priority, the low-priority file is counted (as an
        // uncovered gap), so the denominator grows and coverage drops.
        let r2 = coverage_scoped(&surface, &cat, &debian(), &[], &ctx(), true).unwrap();
        assert_eq!(class_cov(&r2, SurfaceClass::Config).total, 2);
        let low = find(&r2, "/etc/app/app.conf");
        assert!(!low.covered);
        assert!(low.backend_limited.is_none());
    }

    #[test]
    fn config_denominator_shrinks_vs_all_conffiles() {
        // A realistic mix: one security-relevant config + several inert conffiles.
        // The default config denominator counts only the security-relevant one,
        // demonstrating the narrowed, meaningful metric.
        let cat =
            FakeCatalog::new().with("linux", file_def("ssh-edit", "/etc/ssh", Access::RW, true));
        let surface = vec![
            obj(
                SurfaceClass::Config,
                "/etc/ssh/sshd_config",
                Provenance::Vendor,
            ),
            obj(SurfaceClass::Config, "/etc/hostname", Provenance::Vendor),
            obj(SurfaceClass::Config, "/etc/hosts", Provenance::Vendor),
            obj(SurfaceClass::Config, "/etc/motd", Provenance::Vendor),
        ];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert_eq!(
            class_cov(&r, SurfaceClass::Config).total,
            1,
            "denominator narrowed to the security-relevant config only"
        );
        assert_eq!(class_cov(&r, SurfaceClass::Config).pct(), 100.0);
    }

    #[test]
    fn empty_surface_is_full_coverage() {
        // Nothing to cover → 100% (no division by zero).
        let cat = FakeCatalog::new().with("linux", sudo_def("net", &["/usr/sbin/ip"]));
        let r = coverage(&[], &cat, &debian(), &[], &ctx()).unwrap();
        assert_eq!(r.overall_pct, 100.0);
        assert!(r.objects.is_empty());
    }

    // --- reverse lookup: which_grants ---------------------------------------

    fn grant_src(id: &str, sudo: &[&str], grants: Vec<ResolvedFileGrant>) -> GrantSource {
        GrantSource {
            id: id.to_owned(),
            target: GrantTarget::Account(id.to_owned()),
            risk: None,
            sudo: sudo.iter().map(|s| s.to_string()).collect(),
            file_grants: grants,
        }
    }

    /// A group-target source: the same grants, but reached through a `%group`
    /// sudoers fragment / `g:group` ACL (every member inherits).
    fn group_grant_src(group: &str, sudo: &[&str], grants: Vec<ResolvedFileGrant>) -> GrantSource {
        GrantSource {
            id: group.to_owned(),
            target: GrantTarget::Group(group.to_owned()),
            risk: None,
            sudo: sudo.iter().map(|s| s.to_string()).collect(),
            file_grants: grants,
        }
    }

    #[test]
    fn which_grants_finds_sudo_match_by_binary() {
        // One perm grants /usr/sbin/ip via sudo, one grants /etc/ssh rw via file.
        // which-grants /usr/sbin/ip finds only the sudo one.
        let sources = vec![
            grant_src("network-admin", &["/usr/sbin/ip link set"], vec![]),
            grant_src("ssh-edit", &[], vec![rfg("/etc/ssh", Access::RW, true)]),
        ];
        let matches = which_grants("/usr/sbin/ip", &sources);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].permission, "network-admin");
        assert_eq!(matches[0].kind, GrantKind::Sudo);
        assert_eq!(matches[0].detail, "/usr/sbin/ip link set");
        assert!(matches[0].access.is_none());
        assert!(matches[0].backend.is_none());
    }

    #[test]
    fn which_grants_finds_file_match_under_recursive_dir() {
        // /etc/ssh/sshd_config is under the recursive /etc/ssh rw grant → file match.
        let sources = vec![
            grant_src("network-admin", &["/usr/sbin/ip link set"], vec![]),
            grant_src("ssh-edit", &[], vec![rfg("/etc/ssh", Access::RW, true)]),
        ];
        let matches = which_grants("/etc/ssh/sshd_config", &sources);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].permission, "ssh-edit");
        assert_eq!(matches[0].kind, GrantKind::File);
        assert_eq!(matches[0].detail, "/etc/ssh");
        assert_eq!(matches[0].access, Some(Access::RW));
        assert_eq!(matches[0].recursive, Some(true));
        assert_eq!(matches[0].backend.as_deref(), Some("AclBackend"));
    }

    #[test]
    fn which_grants_non_matching_arg_is_empty() {
        let sources = vec![
            grant_src("network-admin", &["/usr/sbin/ip link set"], vec![]),
            grant_src("ssh-edit", &[], vec![rfg("/etc/ssh", Access::RW, true)]),
        ];
        assert!(which_grants("/usr/bin/nonexistent", &sources).is_empty());
        // A path neighbour of the recursive grant (textual prefix, not a
        // component-boundary child) does NOT match.
        assert!(which_grants("/etc/sshd_other", &sources).is_empty());
    }

    #[test]
    fn which_grants_full_command_arg_matches_bare_binary() {
        // Passing a full command line reduces to its leading binary token, so it
        // matches the same sudo grant as the bare binary.
        let sources = vec![grant_src("power", &["/sbin/shutdown -r now"], vec![])];
        let matches = which_grants("/sbin/shutdown -h", &sources);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].detail, "/sbin/shutdown -r now");
    }

    #[test]
    fn which_grants_non_recursive_file_matches_only_exact_path() {
        // A non-recursive File grant on /etc/sudoers matches that exact path, not a
        // child path. Its backend note states a per-file-capable backend.
        let sources = vec![grant_src(
            "sudoers-edit",
            &[],
            vec![rfg("/etc/sudoers", Access::RW, false)],
        )];
        let exact = which_grants("/etc/sudoers", &sources);
        assert_eq!(exact.len(), 1);
        assert_eq!(exact[0].kind, GrantKind::File);
        assert_eq!(
            exact[0].backend.as_deref(),
            Some("per-file-capable backend")
        );
        // A different path under it is not matched by the non-recursive grant.
        assert!(which_grants("/etc/sudoers.d/census", &sources).is_empty());
    }

    #[test]
    fn which_grants_finds_group_sudo_match() {
        // A group-bound sudo grant: which-grants on the command matches with
        // target=Group and the group name (every member inherits via %group).
        let sources = vec![group_grant_src(
            "netops",
            &["/usr/sbin/ip link set"],
            vec![],
        )];
        let matches = which_grants("/usr/sbin/ip", &sources);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].permission, "netops");
        assert_eq!(matches[0].kind, GrantKind::Sudo);
        assert_eq!(matches[0].target, GrantTarget::Group("netops".to_owned()));
        assert_eq!(matches[0].target.group(), Some("netops"));
    }

    #[test]
    fn which_grants_finds_group_file_match_under_recursive_dir() {
        // A path under a group's recursive `g:group` file grant matches with
        // target=Group.
        let sources = vec![group_grant_src(
            "netops",
            &[],
            vec![rfg("/etc/net", Access::RW, true)],
        )];
        let matches = which_grants("/etc/net/iface.conf", &sources);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].permission, "netops");
        assert_eq!(matches[0].kind, GrantKind::File);
        assert_eq!(matches[0].target, GrantTarget::Group("netops".to_owned()));
        assert_eq!(matches[0].access, Some(Access::RW));
        assert_eq!(matches[0].recursive, Some(true));
    }

    #[test]
    fn which_grants_account_and_group_sources_coexist() {
        // The same binary granted by both an account permission and a group: both
        // matches surface, each carrying its own target.
        let sources = vec![
            grant_src("network-admin", &["/usr/sbin/ip link"], vec![]),
            group_grant_src("netops", &["/usr/sbin/ip route"], vec![]),
        ];
        let matches = which_grants("/usr/sbin/ip", &sources);
        assert_eq!(matches.len(), 2);
        assert_eq!(
            matches[0].target,
            GrantTarget::Account("network-admin".to_owned())
        );
        assert!(matches[0].target.group().is_none());
        assert_eq!(matches[1].target, GrantTarget::Group("netops".to_owned()));
    }

    // --- live-scanner pure parsers (in-memory; no shell-out) ----------------

    #[test]
    fn parse_dpkg_conffiles_keeps_only_etc_paths() {
        // dpkg-query Conffiles: leading whitespace, `<path> <md5>`, sometimes an
        // `obsolete` marker. Only /etc paths are kept; the checksum is ignored.
        let stdout = "\
 /etc/ssh/sshd_config 1a2b3c
 /etc/hosts deadbeef obsolete
 /usr/share/foo/bar.conf 99
 /etc/sudoers cafef00d
";
        let got = parse_dpkg_conffiles(stdout);
        assert_eq!(
            got,
            vec![
                "/etc/ssh/sshd_config".to_owned(),
                "/etc/hosts".to_owned(),
                "/etc/sudoers".to_owned(),
            ]
        );
        // The non-/etc path was filtered out.
        assert!(!got.iter().any(|p| p.starts_with("/usr")));
    }

    #[test]
    fn parse_dpkg_conffiles_dedups() {
        let stdout = "/etc/a x\n/etc/a y\n/etc/b z\n";
        assert_eq!(
            parse_dpkg_conffiles(stdout),
            vec!["/etc/a".to_owned(), "/etc/b".to_owned()]
        );
    }

    #[test]
    fn parse_systemctl_units_takes_service_names_only() {
        let stdout = "\
ssh.service                 enabled enabled
cron.service                enabled enabled
something                   static
2 unit files listed.
";
        let got = parse_systemctl_units(stdout);
        assert_eq!(
            got,
            vec!["ssh.service".to_owned(), "cron.service".to_owned()]
        );
    }

    #[test]
    fn parse_etc_group_takes_names_skips_comments() {
        let text = "\
# a comment
root:x:0:
sudo:x:27:alice,bob

netdev:x:108:
";
        assert_eq!(
            parse_etc_group(text),
            vec!["root".to_owned(), "sudo".to_owned(), "netdev".to_owned()]
        );
    }

    #[test]
    fn parse_getcap_handles_both_formats() {
        // Old getcap: `path caps`; new getcap: `path = caps`.
        let stdout = "\
/usr/bin/ping cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
";
        let got = parse_getcap(stdout);
        assert_eq!(got.len(), 2);
        assert_eq!(
            got[0],
            ("/usr/bin/ping".to_owned(), "cap_net_raw+ep".to_owned())
        );
        assert_eq!(
            got[1],
            (
                "/usr/bin/mtr-packet".to_owned(),
                "cap_net_raw+ep".to_owned()
            )
        );
    }

    #[test]
    fn parse_getcap_path_with_space_keeps_full_path() {
        // A path containing a space must stay intact: the capability token is peeled
        // off the END, not the path truncated at its first space.
        let old_fmt = parse_getcap("/opt/my app/tool cap_net_raw+ep\n");
        assert_eq!(
            old_fmt,
            vec![("/opt/my app/tool".to_owned(), "cap_net_raw+ep".to_owned())]
        );
        let new_fmt = parse_getcap("/opt/my app/tool = cap_net_raw+ep\n");
        assert_eq!(
            new_fmt,
            vec![("/opt/my app/tool".to_owned(), "cap_net_raw+ep".to_owned())]
        );
    }

    #[test]
    fn parse_getcap_embedded_newline_no_phantom() {
        // A path with an embedded newline is split by `lines()` into a fragment with
        // no capability token (`/opt/weird`) and a non-absolute fragment
        // (`name cap_...`). Neither must fabricate an object.
        let got = parse_getcap("/opt/weird\nname cap_net_raw+ep\n");
        assert!(
            got.is_empty(),
            "an embedded-newline split must not fabricate a record: {got:?}"
        );
        // Comma-joined multi-cap token (single whitespace-free token) parses whole.
        let multi = parse_getcap("/usr/bin/foo cap_net_admin,cap_net_raw+ep\n");
        assert_eq!(
            multi,
            vec![(
                "/usr/bin/foo".to_owned(),
                "cap_net_admin,cap_net_raw+ep".to_owned()
            )]
        );
    }

    #[test]
    fn parse_dpkg_conffiles_path_with_space_keeps_full_path() {
        // A conffile path containing a space stays intact (md5/marker peeled off the
        // end); an embedded-newline fragment with no checksum is skipped.
        let stdout = "\
/etc/my app.conf 1a2b3c
/etc/x deadbeef obsolete
/etc/frag
";
        assert_eq!(
            parse_dpkg_conffiles(stdout),
            vec!["/etc/my app.conf".to_owned(), "/etc/x".to_owned()]
        );
    }

    #[test]
    fn parse_dpkg_search_embedded_newline_no_phantom() {
        // A path split by an embedded newline yields a trailing fragment with no
        // `": "` (or one not starting with `/`); it must not become a phantom key.
        let stdout = "\
openssh-server: /etc/ssh/sshd_config
frag-without-prefix
";
        let got = parse_dpkg_search(stdout);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "/etc/ssh/sshd_config");
    }

    #[test]
    fn parse_dpkg_search_maps_paths_to_packages() {
        let stdout = "\
openssh-server: /etc/ssh/sshd_config
coreutils, mawk: /usr/bin/[
dpkg-query: no path found matching pattern /opt/x
";
        let got = parse_dpkg_search(stdout);
        // Only the two real path lines map; the no-path diagnostic is skipped.
        assert_eq!(got.len(), 2);
        assert_eq!(
            got[0],
            (
                "/etc/ssh/sshd_config".to_owned(),
                "openssh-server".to_owned()
            )
        );
        assert_eq!(got[1].0, "/usr/bin/[");
    }

    #[test]
    fn merge_dpkg_owners_folds_chunks_first_owner_wins() {
        // Simulates the chunked `dpkg -S` pass: several parsed chunk outputs are
        // merged into one owner map. A path is keyed once (first owner wins); a
        // chunk that failed simply contributes nothing.
        let mut acc: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        merge_dpkg_owners(
            &mut acc,
            vec![
                (
                    "/etc/ssh/sshd_config".to_owned(),
                    "openssh-server".to_owned(),
                ),
                ("/usr/bin/[".to_owned(), "coreutils".to_owned()),
            ],
        );
        merge_dpkg_owners(
            &mut acc,
            vec![
                // duplicate path from a later chunk must not overwrite.
                ("/usr/bin/[".to_owned(), "other-pkg".to_owned()),
                ("/usr/sbin/ip".to_owned(), "iproute2".to_owned()),
            ],
        );
        // An empty chunk (a failed `dpkg` invocation) is a no-op.
        merge_dpkg_owners(&mut acc, vec![]);

        assert_eq!(acc.len(), 3);
        assert_eq!(
            acc.get("/etc/ssh/sshd_config").map(String::as_str),
            Some("openssh-server")
        );
        assert_eq!(
            acc.get("/usr/bin/[").map(String::as_str),
            Some("coreutils"),
            "first owner for a path wins across chunks"
        );
        assert_eq!(
            acc.get("/usr/sbin/ip").map(String::as_str),
            Some("iproute2")
        );
    }

    #[test]
    fn is_setuid_mode_detects_suid_and_sgid() {
        assert!(is_setuid_mode(0o4755)); // setuid
        assert!(is_setuid_mode(0o2755)); // setgid
        assert!(is_setuid_mode(0o6755)); // both
        assert!(!is_setuid_mode(0o0755)); // neither
        assert!(!is_setuid_mode(0o1755)); // sticky only, not suid/sgid
    }

    #[test]
    fn classify_owner_distinguishes_addon_from_vendor() {
        // A base-OS package is Vendor; a recognized add-on prefix is Addon(name).
        assert_eq!(classify_owner("coreutils"), Provenance::Vendor);
        assert_eq!(
            classify_owner("docker-ce"),
            Provenance::Addon("docker-ce".to_owned())
        );
        // First package of a comma list is the nominal owner.
        assert_eq!(classify_owner("coreutils, mawk"), Provenance::Vendor);
    }

    #[test]
    fn is_virtual_dir_skips_proc_sys_run_dev() {
        let root = std::path::Path::new("/");
        assert!(is_virtual_dir(root, std::path::Path::new("/proc")));
        assert!(is_virtual_dir(root, std::path::Path::new("/sys")));
        assert!(is_virtual_dir(root, std::path::Path::new("/run")));
        assert!(is_virtual_dir(root, std::path::Path::new("/dev")));
        assert!(!is_virtual_dir(root, std::path::Path::new("/usr")));
    }

    // --- run_capture: absent vs degraded vs ok, and the timeout watchdog -----

    #[test]
    fn run_capture_reports_absent_tool_distinct_from_degraded() {
        // An ABSENT tool (NotFound) is a legitimately-empty class, NOT a
        // degradation — this is what lets a missing optional tool stay non-fatal
        // while a present-but-failing one trips the gate.
        let out = run_capture("census-no-such-scan-tool-xyzzy", &[], false);
        assert!(
            matches!(out, CaptureOutcome::Absent),
            "a missing binary must be Absent, got {out:?}"
        );
    }

    #[test]
    fn run_capture_reports_nonzero_exit_as_degraded() {
        // A tool that is PRESENT but exits non-zero (without accept_partial) is a
        // degradation: parsing a failed/partial listing as complete would silently
        // under-report the surface, so the class must fail closed.
        let out = run_capture("false", &[], false);
        assert!(
            matches!(out, CaptureOutcome::Degraded(_)),
            "a non-zero exit must degrade, got {out:?}"
        );
    }

    #[test]
    fn run_capture_captures_clean_output() {
        // A clean exit yields Ok with stdout.
        let out = run_capture("true", &[], false);
        assert!(matches!(out, CaptureOutcome::Ok(_)), "got {out:?}");
    }

    #[test]
    fn run_capture_times_out_a_wedged_tool() {
        // A tool that never returns within the budget degrades (not Absent, not
        // Ok): the watchdog kills it and reports a timeout, so a hung `getcap` on a
        // wedged mount cannot stall the audit. Uses a short explicit budget so the
        // test does not wait the production minute.
        let out = run_capture_inner(
            "sleep",
            &["30"],
            false,
            std::time::Duration::from_millis(150),
        );
        assert!(
            matches!(out, CaptureOutcome::Degraded(ref r) if r.contains("timed out")),
            "a wedged tool must degrade with a timeout reason, got {out:?}"
        );
    }
}
