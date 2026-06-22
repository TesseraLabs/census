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

use crate::catalog::{self, CatalogSource, OsTarget, ResolveCtx};

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

/// A source of live surface objects, abstracted so the coverage core is pure and
/// unit tests supply an in-memory surface without touching the filesystem.
pub trait SurfaceScanner {
    /// Enumerate the privileged surface, restricted to the requested `classes`.
    fn scan(&self, classes: &[SurfaceClass]) -> Result<Vec<SurfaceObject>, CoverageError>;
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
}

impl ResolvedRole {
    /// Construct from already-expanded sudo + group strings.
    pub fn new(sudo: Vec<String>, groups: Vec<String>) -> Self {
        ResolvedRole { sudo, groups }
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
    /// Coverage percentage for this class (100.0 when there is nothing to cover).
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
}

/// Errors computing coverage or enumerating the surface.
#[derive(Debug, thiserror::Error)]
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
    fn scan(&self, classes: &[SurfaceClass]) -> Result<Vec<SurfaceObject>, CoverageError> {
        Ok(self
            .objects
            .iter()
            .filter(|o| classes.contains(&o.class))
            .cloned()
            .collect())
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
    /// an expanded sudo string, symlink-resolved on the surface side).
    sudo_binaries: Vec<String>,
    /// Group names covered by some expanded `groups` primitive.
    groups: Vec<String>,
    /// Concrete unit names covered by a `service-restart` instance (both `<u>`
    /// and `<u>.service` forms folded in).
    units: Vec<String>,
    /// Whether the catalog grants `service-admin` (covers ALL units).
    has_service_admin: bool,
    /// Whether the catalog grants `capability-admin` (covers all capfiles).
    has_capability_admin: bool,
}

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
    let mut sudo_binaries: Vec<String> = Vec::new();
    let mut groups: Vec<String> = Vec::new();
    let mut units: Vec<String> = Vec::new();
    let mut has_service_admin = false;
    let mut has_capability_admin = false;
    let mut warnings: Vec<String> = Vec::new();

    let resolve_ctx = ResolveCtx {
        catalog_version: ctx.catalog_version.clone(),
    };

    let all = catalog.all_definitions(os)?;
    for (_layer, def) in &all {
        // Class-wide grants are detected by id presence, matching the spec: the
        // mere existence of `service-admin`/`capability-admin` in the catalog
        // means every unit/capfile is covered.
        if def.id == SERVICE_ADMIN_ID {
            has_service_admin = true;
        }
        if def.id == CAPABILITY_ADMIN_ID {
            has_capability_admin = true;
        }
    }

    // Resolve each *distinct* id once (an id may appear on several layers as the
    // override chain; resolve merges them). Dedup ids first so we don't re-resolve.
    let mut seen_ids: Vec<String> = Vec::new();
    for (_layer, def) in &all {
        if seen_ids.iter().any(|s| s == &def.id) {
            continue;
        }
        seen_ids.push(def.id.clone());

        match catalog::resolve(&def.id, os, catalog, &resolve_ctx) {
            Ok((resolved, _warnings)) => {
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
                                push_unique(&mut sudo_binaries, prefix.to_owned());
                            }
                        }
                    } else if let Some(bin) = sudo_binary_token(&p.value) {
                        push_unique(&mut sudo_binaries, bin.to_owned());
                    }
                }
                for p in &resolved.groups {
                    push_unique(&mut groups, p.value.clone());
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
                push_unique(&mut sudo_binaries, bin.to_owned());
            }
            // A service-restart-style command names a unit as its last argument;
            // record both `<u>` and `<u>.service` forms so a unit object matches
            // regardless of which form the surface scanner reports.
            if let Some(unit) = service_restart_unit(cmd) {
                fold_unit_forms(unit, &mut units);
            }
        }
        for g in &role.groups {
            push_unique(&mut groups, g.clone());
        }
    }

    Ok((
        CoveredSet {
            sudo_binaries,
            groups,
            units,
            has_service_admin,
            has_capability_admin,
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
fn fold_unit_forms(unit: &str, units: &mut Vec<String>) {
    let base = unit.strip_suffix(".service").unwrap_or(unit);
    push_unique(units, base.to_owned());
    push_unique(units, format!("{base}.service"));
}

/// Push `value` only if not already present (order-preserving dedup).
fn push_unique(acc: &mut Vec<String>, value: String) {
    if !acc.iter().any(|v| v == &value) {
        acc.push(value);
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

        // Intentionally-uncovered policy: these do not penalise the metric and
        // are reported with a reason rather than as a gap.
        if let Some(reason) = intentional_exclusion(object) {
            objects.push(ObjectCoverage {
                object: object.clone(),
                covered: false,
                suggested_permission: None,
                intentional_exclusion: Some(reason),
            });
            continue;
        }

        let is_covered = object_covered(object, &covered);

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
            suggest_permission(object)
        };

        objects.push(ObjectCoverage {
            object: object.clone(),
            covered: is_covered,
            suggested_permission: suggested,
            intentional_exclusion: None,
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
    })
}

/// Weighted overall coverage: the simple ratio of all covered grant objects to
/// all counted grant objects (each object weighs equally, so a class with more
/// objects contributes proportionally — "weighted" by object count, not a flat
/// average of per-class percentages, which would over-weight a tiny class).
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
        SurfaceClass::SudoBin => covered.sudo_binaries.iter().any(|b| b == &object.key),
        SurfaceClass::Group => covered.groups.iter().any(|g| g == &object.key),
        SurfaceClass::Unit => {
            // service-admin covers every unit; otherwise the named unit must be in
            // a service-restart instance's units (either form).
            covered.has_service_admin || unit_covered(&object.key, &covered.units)
        }
        SurfaceClass::CapFile => covered.has_capability_admin,
        // Config coverage: our catalog models privilege via concrete sudo tools,
        // not a `config-edit` primitive, so a config path matches only when a sudo
        // command's binary path equals it. With no config-edit primitive in the
        // catalog, config-class objects are honestly reported uncovered unless such
        // a path match exists — config coverage is therefore expected to be low.
        SurfaceClass::Config => covered.sudo_binaries.iter().any(|b| b == &object.key),
        // Not a grant class; never reached for Setuid (filtered earlier).
        SurfaceClass::Setuid => false,
    }
}

/// Whether a unit name is covered by the named-unit set, accepting both `<u>` and
/// `<u>.service` forms on either side.
fn unit_covered(unit: &str, covered_units: &[String]) -> bool {
    let base = unit.strip_suffix(".service").unwrap_or(unit);
    let with_service = format!("{base}.service");
    covered_units
        .iter()
        .any(|u| u == unit || u == base || u == &with_service)
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

/// The final path component of a binary path (`/usr/bin/su` → `su`).
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
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

impl SurfaceScanner for LiveSurface {
    fn scan(&self, classes: &[SurfaceClass]) -> Result<Vec<SurfaceObject>, CoverageError> {
        // Read-only enumeration of the requested classes. Each class is gathered
        // independently; a class the caller did not request is skipped entirely so
        // an operator can scope an audit (`--class group` must not pay for a `/`
        // walk). Provenance is resolved in one bulk pass at the end so we shell out
        // to `dpkg` once, not per-object.
        let mut objects: Vec<SurfaceObject> = Vec::new();

        if classes.contains(&SurfaceClass::SudoBin) {
            objects.extend(self.scan_sudo_bins()?);
        }
        if classes.contains(&SurfaceClass::Config) {
            objects.extend(self.scan_configs());
        }
        if classes.contains(&SurfaceClass::Unit) {
            objects.extend(self.scan_units());
        }
        if classes.contains(&SurfaceClass::Group) {
            objects.extend(self.scan_groups()?);
        }
        if classes.contains(&SurfaceClass::CapFile) {
            objects.extend(self.scan_capfiles());
        }
        if classes.contains(&SurfaceClass::Setuid) {
            objects.extend(self.scan_setuid()?);
        }

        // Bulk provenance: one `dpkg -S` over every path-keyed object marks
        // package-owned objects Vendor/Addon; the rest stay Orphan. Missing `dpkg`
        // ⇒ everything keeps its default Orphan (no crash) — see resolve_provenance.
        self.resolve_provenance(&mut objects);

        Ok(objects)
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
        let mut seen: Vec<String> = Vec::new();
        let mut any_dir = false;
        for dir in &self.sudo_bin_dirs {
            let full = self.root.join(dir.strip_prefix("/").unwrap_or(dir));
            let entries = match std::fs::read_dir(&full) {
                Ok(e) => e,
                Err(_) => continue, // missing admin dir is fine; skip it
            };
            any_dir = true;
            for entry in entries.flatten() {
                let path = entry.path();
                // Resolve symlinks to the real binary; on failure (dangling link,
                // permission) fall back to the literal path rather than dropping it.
                let canonical = std::fs::canonicalize(&path).unwrap_or(path.clone());
                let key = canonical.to_string_lossy().into_owned();
                if seen.iter().any(|s| s == &key) {
                    continue;
                }
                seen.push(key.clone());
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
    /// `dpkg-query`) plus any well-known drop-in directories that exist. Missing
    /// `dpkg-query` is non-fatal — we still return the drop-in dirs we can see, so
    /// config enumeration degrades to "what is on disk" rather than erroring.
    fn scan_configs(&self) -> Vec<SurfaceObject> {
        let mut out: Vec<SurfaceObject> = Vec::new();
        let mut seen: Vec<String> = Vec::new();

        // Package conffiles: `dpkg-query -W -f='${Conffiles}\n'` lists, per package,
        // lines of `"<path> <md5>"`. We keep only paths under `/etc` (the security-
        // relevant surface) and ignore the checksum (we never read content).
        if let Some(stdout) = run_capture("dpkg-query", &["-W", "-f=${Conffiles}\n"]) {
            for path in parse_dpkg_conffiles(&stdout) {
                if seen.iter().any(|s| s == &path) {
                    continue;
                }
                seen.push(path.clone());
                out.push(SurfaceObject {
                    class: SurfaceClass::Config,
                    key: path,
                    provenance: Provenance::Orphan,
                    detail: "conffile".to_owned(),
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
                if seen.iter().any(|s| s == &key) {
                    continue;
                }
                seen.push(key.clone());
                out.push(SurfaceObject {
                    class: SurfaceClass::Config,
                    key,
                    provenance: Provenance::Orphan,
                    detail: "drop-in dir".to_owned(),
                });
            }
        }
        out
    }

    /// Enumerate systemd service units via `systemctl list-unit-files`. Missing
    /// `systemctl` (a non-systemd host, a container without it) ⇒ no units, no
    /// error: a unit-less host simply has nothing in this class.
    fn scan_units(&self) -> Vec<SurfaceObject> {
        let stdout = match run_capture(
            "systemctl",
            &["list-unit-files", "--no-legend", "--type=service"],
        ) {
            Some(s) => s,
            None => return Vec::new(),
        };
        parse_systemctl_units(&stdout)
            .into_iter()
            .map(|name| SurfaceObject {
                class: SurfaceClass::Unit,
                key: name,
                // Units are not path-keyed; provenance stays Orphan (the bulk dpkg
                // pass keys on filesystem paths, not unit names).
                provenance: Provenance::Orphan,
                detail: "service".to_owned(),
            })
            .collect()
    }

    /// Enumerate groups by reading `/etc/group` directly (not `getent`, to avoid a
    /// shell-out and to stay deterministic for the container test). A read failure
    /// is a hard error — a coverage run that cannot see the group surface would
    /// silently under-report gate-keeping groups.
    fn scan_groups(&self) -> Result<Vec<SurfaceObject>, CoverageError> {
        let path = self.root.join("etc/group");
        let text = std::fs::read_to_string(&path)
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

    /// Enumerate capability-bearing files via `getcap -r <root>`. Missing `getcap`
    /// ⇒ no capfiles, no error (the tool is optional on minimal systems).
    fn scan_capfiles(&self) -> Vec<SurfaceObject> {
        let root = self.root.to_string_lossy().into_owned();
        let stdout = match run_capture("getcap", &["-r", &root]) {
            Some(s) => s,
            None => return Vec::new(),
        };
        parse_getcap(&stdout)
            .into_iter()
            .map(|(path, caps)| SurfaceObject {
                class: SurfaceClass::CapFile,
                key: path,
                provenance: Provenance::Orphan,
                detail: caps,
            })
            .collect()
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
        let mut owners: Vec<(String, String)> = Vec::new();
        for chunk in paths.chunks(DPKG_SEARCH_CHUNK) {
            let mut args: Vec<&str> = vec!["-S"];
            args.extend(chunk.iter().map(String::as_str));
            let stdout = match run_capture("dpkg", &args) {
                Some(s) => s,
                None => continue, // this chunk failed ⇒ its paths stay Orphan
            };
            merge_dpkg_owners(&mut owners, parse_dpkg_search(&stdout));
        }
        for o in objects.iter_mut() {
            if let Some(pkg) = owners.iter().find(|(p, _)| p == &o.key).map(|(_, pkg)| pkg) {
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
/// owner). Pure so the chunk-merge is unit-testable without shelling out.
fn merge_dpkg_owners(acc: &mut Vec<(String, String)>, chunk: Vec<(String, String)>) {
    for (path, pkg) in chunk {
        if acc.iter().any(|(p, _)| p == &path) {
            continue;
        }
        acc.push((path, pkg));
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

/// Run an external command read-only, capturing stdout as a `String`. Returns
/// `None` if the binary is absent or exits non-zero (or its output is not UTF-8) —
/// every caller treats `None` as graceful degradation, never a panic. ARGV-only:
/// the program and args are passed directly to `Command`, never via a shell, so no
/// argument can be interpreted as a shell metacharacter.
fn run_capture(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program).args(args).output().ok()?;
    // `dpkg -S` exits non-zero when SOME paths are not owned even though it prints
    // the owned ones; accept stdout whenever it is non-empty, regardless of status.
    let stdout = String::from_utf8(output.stdout).ok()?;
    if stdout.is_empty() && !output.status.success() {
        return None;
    }
    Some(stdout)
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

/// Parse the `${Conffiles}` output of `dpkg-query -W -f='${Conffiles}\n'`. Each
/// non-empty line is `"<path> <md5>[ obsolete]"` (leading whitespace common);
/// we keep only `<path>` and only those under `/etc` (the security-relevant
/// surface). The checksum and any `obsolete` marker are ignored — we never read
/// content. Order-preserving, deduped.
fn parse_dpkg_conffiles(stdout: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // The path is the first whitespace-delimited token.
        let path = match line.split_whitespace().next() {
            Some(p) => p,
            None => continue,
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
fn parse_getcap(stdout: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Path is the first whitespace token; the rest (minus a leading `=`) is the
        // capability string.
        let mut parts = line.splitn(2, char::is_whitespace);
        let path = match parts.next() {
            Some(p) if !p.is_empty() => p.to_owned(),
            _ => continue,
        };
        let caps = parts
            .next()
            .map(|c| c.trim_start_matches('=').trim().to_owned())
            .unwrap_or_default();
        out.push((path, caps));
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
    use crate::catalog::{FakeCatalog, ListOverride, PermissionDef};

    // --- builders -----------------------------------------------------------

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
            limits: None,
            replace: false,
            includes: Vec::new(),
            include_categories: Vec::new(),
        }
    }

    fn includes_def(id: &str, includes: &[&str]) -> PermissionDef {
        PermissionDef {
            includes: includes.iter().map(|s| s.to_string()).collect(),
            ..def(id)
        }
    }

    fn sudo_def(id: &str, sudo: &[&str]) -> PermissionDef {
        PermissionDef {
            sudo: ListOverride::Replace(sudo.iter().map(|s| s.to_string()).collect()),
            ..def(id)
        }
    }

    fn group_def(id: &str, groups: &[&str]) -> PermissionDef {
        PermissionDef {
            groups: ListOverride::Replace(groups.iter().map(|s| s.to_string()).collect()),
            ..def(id)
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
            .with(obj(SurfaceClass::SudoBin, "/usr/sbin/ip", Provenance::Vendor))
            .with(obj(SurfaceClass::Group, "netdev", Provenance::Vendor));
        let only_bins = s.scan(&[SurfaceClass::SudoBin]).unwrap();
        assert_eq!(only_bins.len(), 1);
        assert_eq!(only_bins[0].key, "/usr/sbin/ip");
    }

    // --- sudo_bin coverage -------------------------------------------------

    #[test]
    fn sudo_bin_covered_by_expanded_sudo_string() {
        // Catalog grants sudo /usr/sbin/ip; the binary /usr/sbin/ip is covered.
        let cat = FakeCatalog::new().with("linux", sudo_def("network-admin", &["/usr/sbin/ip"]));
        let surface = vec![obj(SurfaceClass::SudoBin, "/usr/sbin/ip", Provenance::Vendor)];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(find(&r, "/usr/sbin/ip").covered);
        assert_eq!(class_cov(&r, SurfaceClass::SudoBin).covered, 1);
    }

    #[test]
    fn sudo_bin_covered_via_argv_boundary() {
        // A sudo string WITH arguments still covers the bare binary: the args only
        // narrow what it does, they do not change which binary is reachable.
        let cat =
            FakeCatalog::new().with("linux", sudo_def("power-control", &["/sbin/shutdown -r now"]));
        let surface = vec![obj(SurfaceClass::SudoBin, "/sbin/shutdown", Provenance::Vendor)];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(find(&r, "/sbin/shutdown").covered);
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
        let role = ResolvedRole::new(vec!["/usr/bin/systemctl restart atm-app".to_owned()], vec![]);
        let surface = vec![
            obj(SurfaceClass::Unit, "atm-app.service", Provenance::Vendor),
            obj(SurfaceClass::Unit, "other.service", Provenance::Vendor),
        ];
        let strict = CoverageCtx {
            strict: true,
            catalog_version: None,
        };
        let r = coverage(&surface, &cat, &debian(), &[role], &strict).unwrap();
        assert!(find(&r, "atm-app.service").covered);
        assert!(!find(&r, "other.service").covered);
    }

    #[test]
    fn service_admin_covers_all_units() {
        // service-admin present → every unit covered, no per-unit instance needed.
        let cat = FakeCatalog::new().with(
            "linux",
            sudo_def("service-admin", &["/usr/bin/systemctl"]),
        );
        let surface = vec![
            obj(SurfaceClass::Unit, "atm-app.service", Provenance::Vendor),
            obj(SurfaceClass::Unit, "sshd.service", Provenance::Vendor),
        ];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(find(&r, "atm-app.service").covered);
        assert!(find(&r, "sshd.service").covered);
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
    fn capfile_covered_by_capability_admin_presence() {
        let with = FakeCatalog::new().with(
            "linux",
            sudo_def("capability-admin", &["/usr/sbin/setcap"]),
        );
        let surface = vec![obj(SurfaceClass::CapFile, "/usr/bin/ping", Provenance::Vendor)];
        let r = coverage(&surface, &with, &debian(), &[], &ctx()).unwrap();
        assert!(find(&r, "/usr/bin/ping").covered);

        // Without capability-admin, the same capfile is uncovered.
        let without = FakeCatalog::new().with("linux", sudo_def("network-admin", &["/usr/sbin/ip"]));
        let r2 = coverage(&surface, &without, &debian(), &[], &ctx()).unwrap();
        assert!(!find(&r2, "/usr/bin/ping").covered);
    }

    // --- setuid inventory + anomalies --------------------------------------

    #[test]
    fn setuid_reported_as_inventory_not_grant() {
        let cat = FakeCatalog::new().with("linux", sudo_def("network-admin", &["/usr/sbin/ip"]));
        let surface = vec![obj(SurfaceClass::Setuid, "/usr/bin/mount", Provenance::Vendor)];
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
        assert!(p
            .intentional_exclusion
            .as_deref()
            .unwrap()
            .contains("pdpl"));
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
            obj(SurfaceClass::SudoBin, "/usr/sbin/cryptsetup", Provenance::Vendor),
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
            obj(SurfaceClass::SudoBin, "/usr/sbin/iptables", Provenance::Vendor),
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
            r.catalog_warnings.iter().any(|w| w.contains("bad") || w.contains("loop")),
            "warning must name the unresolvable id: {:?}",
            r.catalog_warnings
        );
    }

    #[test]
    fn config_uncovered_without_config_edit_primitive() {
        // The catalog has no config-edit primitive; a config object is honestly
        // uncovered unless a sudo binary path matches it (documented limitation).
        let cat = FakeCatalog::new().with("linux", sudo_def("net", &["/usr/sbin/ip"]));
        let surface = vec![obj(
            SurfaceClass::Config,
            "/etc/ssh/sshd_config",
            Provenance::Vendor,
        )];
        let r = coverage(&surface, &cat, &debian(), &[], &ctx()).unwrap();
        assert!(!find(&r, "/etc/ssh/sshd_config").covered);
    }

    #[test]
    fn empty_surface_is_full_coverage() {
        // Nothing to cover → 100% (no division by zero).
        let cat = FakeCatalog::new().with("linux", sudo_def("net", &["/usr/sbin/ip"]));
        let r = coverage(&[], &cat, &debian(), &[], &ctx()).unwrap();
        assert_eq!(r.overall_pct, 100.0);
        assert!(r.objects.is_empty());
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
        assert_eq!(got[0], ("/usr/bin/ping".to_owned(), "cap_net_raw+ep".to_owned()));
        assert_eq!(
            got[1],
            ("/usr/bin/mtr-packet".to_owned(), "cap_net_raw+ep".to_owned())
        );
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
            ("/etc/ssh/sshd_config".to_owned(), "openssh-server".to_owned())
        );
        assert_eq!(got[1].0, "/usr/bin/[");
    }

    #[test]
    fn merge_dpkg_owners_folds_chunks_first_owner_wins() {
        // Simulates the chunked `dpkg -S` pass: several parsed chunk outputs are
        // merged into one owner map. A path is keyed once (first owner wins); a
        // chunk that failed simply contributes nothing.
        let mut acc: Vec<(String, String)> = Vec::new();
        merge_dpkg_owners(
            &mut acc,
            vec![
                ("/etc/ssh/sshd_config".to_owned(), "openssh-server".to_owned()),
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
            acc.iter().find(|(p, _)| p == "/etc/ssh/sshd_config").map(|(_, k)| k.as_str()),
            Some("openssh-server")
        );
        assert_eq!(
            acc.iter().find(|(p, _)| p == "/usr/bin/[").map(|(_, k)| k.as_str()),
            Some("coreutils"),
            "first owner for a path wins across chunks"
        );
        assert_eq!(
            acc.iter().find(|(p, _)| p == "/usr/sbin/ip").map(|(_, k)| k.as_str()),
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
}
