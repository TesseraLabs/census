//! Framework cross-reference: a strictly **read-only** mapping from catalog
//! permission ids to compliance-framework control ids (PCI-DSS, SOC 2, ГОСТ …).
//!
//! A *framework* (e.g. `pci-dss`) ships a small tree under a framework root:
//! a `framework.toml` manifest, a `mappings/` tree (`permission-id → [control-id]`),
//! an optional structural `controls.toml` (`control-id → { owned, domain? }`), and
//! an l10n tree (`l10n/<locale>/controls.toml`) carrying the control *titles*.
//! Control titles live in l10n — never inline in `controls.toml` — so the
//! structural compliance file stays free of human-readable (and copyrighted) text
//! and a translator contributes wording without touching compliance structure,
//! exactly as permission text lives in the catalog's l10n tree. Census loads these
//! into two indices — forward (`permission → framework → PolarControls`) and a
//! polarity-keyed reverse (`polarity → framework → control → permissions`) — so a
//! reviewer can ask "which controls does this grant satisfy" and "which grants
//! does this control depend on". Each link carries a polarity (satisfies / risk /
//! related): whether the grant addresses, undermines, or merely touches the
//! control.
//!
//! ## Why this layer is fully decoupled from compile / plan / apply
//!
//! Cross-reference is *advisory metadata*, exactly like [`crate::l10n`]: it MUST
//! NOT influence primitive expansion, resolve, plan, or apply. It is therefore
//! never called from those paths, imports nothing from `compile`/`plan`/`apply`/
//! `model`, and the only catalog coupling is [`OsTarget`] (reused for the
//! os-layered layer chain — see below). A wrong, missing, or hostile framework
//! file can at worst produce a misleading *report*; it can never widen, narrow,
//! or break a grant. This is the security boundary: a community-contributed
//! framework mapping is reviewed as documentation, never as rights.
//!
//! ## Why absent → empty, and forward-compatibility is tolerated, not fatal
//!
//! No framework tree installed → empty indices, **never an error**: the mapping
//! is optional and its absence is the common case. For the same forward/back-compat
//! reason the catalog and l10n already adopt, *unknown* shapes are tolerated rather
//! than rejected, because a framework set can legitimately lead or lag the catalog
//! and the Census version reading it:
//!   * an unknown `dimension` value → the framework is **skipped with a warning** (a newer
//!     framework set may use a resolve dimension this Census predates);
//!   * an unknown `provides` tag → the framework is **skipped with a warning** (a newer set may
//!     advertise a capability this Census does not implement);
//!   * an unknown *permission-id* in a mapping file → kept verbatim as a forward reference (the
//!     catalog may add it later); it is just a map key, never an error.
//!
//! ## Why the *format* is still strict where it matters
//!
//! Tolerance is about *membership* (unknown dimensions/tags/ids), not *structure*.
//! Census owns the framework file format, so a malformed TOML, an unknown *field*
//! inside a known table (`deny_unknown_fields`), or an `owned` flag omitted from a
//! control definition is a hard error — these are typos that would silently drop a
//! reviewer's intent. A framework id declared in two roots is also a hard error:
//! two roots claiming the same id is ambiguous, and silently letting one win would
//! make the report depend on filesystem read order (non-deterministic). Hard errors
//! are [`FrameworkError`]; tolerated skips are [`LoadedFrameworks::warnings`].

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::catalog::OsTarget;

/// The resolve *dimension* of a framework: how its `mappings/` tree is laid out
/// and walked.
///
/// Stored on the manifest as a raw [`String`] and validated post-parse via
/// [`Dimension::parse`] rather than deserialized directly, because an *unknown*
/// dimension must be tolerated (skip-with-warning), not error the whole manifest
/// parse — serde would otherwise reject the entire file on an unrecognised enum
/// value, which is exactly the forward-compat behaviour this layer must avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum Dimension {
    /// `mappings/*.toml` read directly — the control mapping does not vary by OS.
    Flat,
    /// `mappings/<layer>/*.toml`, one subdir per OS-target layer
    /// (`linux`, `linux-debian`, `linux-debian-12`), merged bottom→top exactly
    /// like the catalog's leaf resolve. Used when a control's relevant grants
    /// differ per distro/version.
    OsLayered,
}

impl Dimension {
    /// Map a raw `dimension` string to a [`Dimension`], or `None` for an
    /// unrecognised value (which the loader treats as a tolerated skip, not an
    /// error). `"flat"` → [`Dimension::Flat`], `"os-layered"` →
    /// [`Dimension::OsLayered`].
    pub fn parse(s: &str) -> Option<Dimension> {
        match s {
            "flat" => Some(Dimension::Flat),
            "os-layered" => Some(Dimension::OsLayered),
            _ => None,
        }
    }
}

/// The known `provides` capability tags. A framework advertising a tag outside
/// this set is skipped with a warning (forward-compat: a newer set may advertise
/// a capability this Census does not implement). Kept as an explicit allow-list so
/// the tolerated-vs-rejected decision is a documented domain choice.
const KNOWN_PROVIDES: &[&str] = &["crossref", "controls"];

/// A framework manifest (`<root>/<fw>/framework.toml`), parsed strictly.
///
/// Strict (`deny_unknown_fields`) on the *known* fields: Census owns this format,
/// so an unrecognised field is a typo or a stale file, not something to silently
/// ignore. The one deliberate exception is `dimension`, kept as a raw [`String`]
/// (not a typed enum) so an unknown dimension *value* is tolerated post-parse —
/// see [`Dimension`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct FrameworkManifest {
    /// Framework id (e.g. `pci-dss`). Used as the key in every index; a collision
    /// across roots is a hard [`FrameworkError::IdCollision`].
    pub id: String,
    /// Framework version string (informational; surfaced in reports).
    pub version: String,
    /// Human-readable title (informational; surfaced in reports).
    pub title: String,
    /// Resolve dimension as a raw string, validated post-parse by
    /// [`Dimension::parse`]. Raw (not a typed enum) so an unknown value can be
    /// tolerated with a warning instead of failing the manifest parse.
    pub dimension: String,
    /// Advertised capability tags (see [`KNOWN_PROVIDES`]). An unknown tag causes
    /// the framework to be skipped with a warning. Absent defaults to empty.
    #[serde(default)]
    pub provides: Vec<String>,
}

/// Parse a `framework.toml` manifest, returning the raw [`toml::de::Error`].
///
/// The loader wraps the error into [`FrameworkError::TomlParse`] with the file
/// path, mirroring how [`crate::l10n::LiveL10n`]'s `parse_file` returns the raw
/// toml error and lets the caller attach path context.
pub fn parse_manifest(text: &str) -> Result<FrameworkManifest, toml::de::Error> {
    toml::from_str::<FrameworkManifest>(text)
}

/// One mapping-file entry: how a single permission relates to a set of control
/// ids, by **polarity**, parsed strictly.
///
/// A mapping file is a TOML table of `permission-id → { satisfies?, risk?,
/// related? }`. Each of the three lists is the set of control ids the permission
/// relates to under that polarity:
///   * `satisfies` — having this capability *addresses* the control;
///   * `risk` — the capability *undermines* the control (e.g. log rotation vs. log-integrity);
///   * `related` — neutrally touches the control's area, without satisfying it.
///
/// All three default to empty (a permission may carry any combination).
/// `deny_unknown_fields` so a typo'd key (`control = [...]`) is rejected rather
/// than silently dropping the reviewer's mapping.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingEntry {
    /// Control ids this permission satisfies (addresses), in author order.
    #[serde(default)]
    pub satisfies: Vec<String>,
    /// Control ids this permission undermines (a compliance risk), in author order.
    #[serde(default)]
    pub risk: Vec<String>,
    /// Control ids this permission neutrally relates to, in author order.
    #[serde(default)]
    pub related: Vec<String>,
}

/// The polarity of a permission↔control link: which of the three relations a
/// mapped control id falls under for a given permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Polarity {
    /// The capability addresses the control.
    Satisfies,
    /// The capability undermines the control (a compliance risk).
    Risk,
    /// The capability neutrally relates to the control.
    Related,
}

/// The control ids a permission relates to in one framework, partitioned by
/// polarity. The merged (union+dedup) result for a (permission, framework) pair.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolarControls {
    /// Controls this permission satisfies (addresses).
    pub satisfies: Vec<String>,
    /// Controls this permission undermines (risk).
    pub risk: Vec<String>,
    /// Controls this permission neutrally relates to.
    pub related: Vec<String>,
}

impl PolarControls {
    /// True when no polarity carries any control (the permission is unmapped in
    /// this framework).
    pub fn is_empty(&self) -> bool {
        self.satisfies.is_empty() && self.risk.is_empty() && self.related.is_empty()
    }
    /// The list for a given polarity.
    pub fn for_polarity(&self, p: Polarity) -> &[String] {
        match p {
            Polarity::Satisfies => &self.satisfies,
            Polarity::Risk => &self.risk,
            Polarity::Related => &self.related,
        }
    }
}

/// Merge one mapping file's `permission-id → MappingEntry` table into the
/// accumulator `into` (`permission-id → PolarControls`), **unioning** each
/// polarity (`satisfies`/`risk`/`related`) separately with dedup that preserves
/// first-seen order.
///
/// When the same permission id appears in several files (or, for os-layered
/// frameworks, several layers), each polarity's control list unions independently:
/// a control already recorded under that polarity is not added again, and new
/// controls append in the order first seen.
fn merge_mappings(
    into: &mut BTreeMap<String, PolarControls>,
    file_map: BTreeMap<String, MappingEntry>,
) {
    fn union_into(acc: &mut Vec<String>, incoming: Vec<String>) {
        for control in incoming {
            if !acc.iter().any(|c| c == &control) {
                acc.push(control);
            }
        }
    }
    for (perm, entry) in file_map {
        let acc = into.entry(perm).or_default();
        union_into(&mut acc.satisfies, entry.satisfies);
        union_into(&mut acc.risk, entry.risk);
        union_into(&mut acc.related, entry.related);
    }
}

/// A control definition from a framework's `controls.toml` — purely
/// **structural**, parsed strictly.
///
/// `controls.toml` is a TOML table of `control-id → { owned, domain? }`. It
/// carries **no human-readable text**: the control's title lives in the
/// framework's l10n tree (`<fw>/l10n/<locale>/controls.toml`, keyed by control
/// id), exactly as permission text lives in the catalog's l10n tree. Keeping the
/// structural compliance facts (which controls exist, who owns them, how they
/// group) separate from their wording means a community translator contributes a
/// title — or a new language — by touching only a language file, never the
/// compliance structure a reviewer signs off on; and the structural file stays
/// free of copyrighted source wording.
///
/// `owned` is **required** (no serde default): whether the *organisation* owns
/// this control (vs. it being inherited from a provider) is a material compliance
/// fact a reviewer must state explicitly, so an omitted `owned` is a parse error,
/// not a silent `false`. `deny_unknown_fields` guards against field typos —
/// including a stray `title`, which now belongs in the l10n tree, not here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ControlDef {
    /// Whether the organisation owns this control (required — see type docs).
    pub owned: bool,
    /// Optional grouping domain (e.g. "Access Control"). Absent → `None`.
    #[serde(default)]
    pub domain: Option<String>,
}

/// Parse a `controls.toml` file into a `control-id → ControlDef` map, returning
/// the raw [`toml::de::Error`] (the loader attaches the path). A `BTreeMap` so
/// iteration is deterministic (stable report output, reproducible tests).
pub fn parse_controls(text: &str) -> Result<BTreeMap<String, ControlDef>, toml::de::Error> {
    toml::from_str::<BTreeMap<String, ControlDef>>(text)
}

/// Resolve a control's display title for `locale`, with the same fallback chain
/// the permission catalog uses for its text: `locale → en → the bare id`.
///
/// The structural [`ControlDef`] carries no title — titles live in the framework's
/// l10n tree (`<fw_dir>/l10n/<locale>/controls.toml`, keyed by control id). This
/// reuses the catalog's l10n machinery verbatim: a [`crate::l10n::LiveL10n`]
/// rooted at the framework's own directory reads `<fw_dir>/l10n/<locale>/*.toml`
/// exactly as the catalog reads `<root>/l10n/<locale>/*.toml`, and
/// [`crate::l10n::resolve_text`] applies the `locale → en → id` fallback. An
/// unresolved id therefore degrades to the bare control-id string, so a report
/// always has a label even with no translation installed.
///
/// `fw` must be a loaded framework (its directory was captured in
/// [`LoadedFrameworks::framework_dirs`]); an unknown `fw` yields the bare `id`.
pub fn resolve_control_title(
    loaded: &LoadedFrameworks,
    fw: &str,
    id: &str,
    locale: &str,
) -> String {
    match loaded.framework_dirs.get(fw) {
        Some(dir) => {
            let l10n = crate::l10n::LiveL10n::new(vec![dir.clone()]);
            crate::l10n::resolve_text(&l10n, locale, id).title
        }
        // No directory recorded (framework not loaded) → the id is the only honest
        // label, matching the l10n fallback's last resort.
        None => id.to_owned(),
    }
}

/// Hard errors loading the framework cross-reference tree.
///
/// Reserved for failures a caller genuinely cannot proceed past: malformed/
/// unreadable files and the ambiguous framework-id collision. Tolerated forward-
/// compat skips (unknown dimension / unknown provides tag) are *not* errors — they
/// are recorded in [`LoadedFrameworks::warnings`]. Mirrors
/// [`crate::catalog::CatalogError`] in shape and doc style.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FrameworkError {
    /// A framework file or directory could not be read.
    #[error("cannot read framework path {path}: {reason}")]
    Io {
        /// The path that failed.
        path: PathBuf,
        /// Underlying reason.
        reason: String,
    },
    /// A framework file's TOML was malformed or violated the strict schema
    /// (unknown field, missing required `owned`, wrong types).
    #[error("framework file {path} TOML is invalid: {reason}")]
    TomlParse {
        /// The path that failed.
        path: PathBuf,
        /// Underlying reason.
        reason: String,
    },
    /// The same `framework.id` was declared in two roots (or two subdirs). Two
    /// roots claiming one id is ambiguous; letting one silently win would make the
    /// loaded report depend on filesystem read order, so it is rejected for
    /// determinism rather than treated as an override.
    #[error("framework id {id} declared in two roots")]
    IdCollision {
        /// The colliding framework id.
        id: String,
    },
}

/// Where a single mapping contribution came from: the framework, the OS layer
/// (`None` for a flat framework, `Some("linux-debian-12")` etc. for an os-layered
/// one), and the exact file. Per-contribution (one physical file), so a report can
/// point a reviewer at the precise source of every control mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingProvenance {
    /// The framework id this contribution belongs to.
    pub framework_id: String,
    /// The OS layer for an os-layered framework, or `None` for a flat one.
    pub layer: Option<String>,
    /// The exact mapping file this contribution was read from.
    pub path: PathBuf,
}

/// One *raw* mapping contribution: a single (framework, permission, file) tuple
/// carrying that file's controls and provenance, recorded **before** the cross-
/// file/cross-layer union.
///
/// Kept pre-union (one per physical file that mentions the permission) so that the
/// merged indices and the per-contribution provenance can both be exact: the
/// forward/reverse indices union+dedup across the relevant `LoadedMapping`s, while
/// each `LoadedMapping` preserves the precise file/layer it came from for audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedMapping {
    /// The framework this mapping belongs to.
    pub framework_id: String,
    /// The catalog permission id this mapping is keyed on.
    pub permission_id: String,
    /// The controls this file mapped the permission to, by polarity (this file
    /// only, not the cross-file union — see type docs).
    pub satisfies: Vec<String>,
    /// Risk-polarity controls from this file.
    pub risk: Vec<String>,
    /// Related-polarity controls from this file.
    pub related: Vec<String>,
    /// Where this contribution came from (framework / layer / file).
    pub provenance: MappingProvenance,
}

/// The fully-loaded framework cross-reference: manifests, both indices, control
/// definitions, raw provenance-bearing mappings, and forward-compat warnings.
///
/// Every map is a `BTreeMap` so iteration is deterministic (stable reports,
/// reproducible tests). An empty tree yields this struct with every map empty and
/// no warnings — never an error.
#[derive(Debug, Clone, Default)]
pub struct LoadedFrameworks {
    /// Loaded manifests, keyed by framework id.
    pub frameworks: BTreeMap<String, FrameworkManifest>,
    /// Forward index: `permission-id → framework-id → PolarControls` (merged,
    /// deduped union per polarity across files/layers).
    pub forward: BTreeMap<String, BTreeMap<String, PolarControls>>,
    /// Reverse index by polarity: `polarity → framework-id → control-id →
    /// [permission-id]`. The inverse of `forward`, split so coverage can ask for
    /// satisfies-controls and risk can ask for risk-controls independently.
    pub reverse: BTreeMap<Polarity, BTreeMap<String, BTreeMap<String, Vec<String>>>>,
    /// Control definitions per framework: `framework-id → control-id → ControlDef`.
    pub controls: BTreeMap<String, BTreeMap<String, ControlDef>>,
    /// The on-disk directory each loaded framework was read from
    /// (`framework-id → <root>/<fw>`). Retained so the report layer can resolve
    /// control titles from the framework's own l10n tree
    /// (`<dir>/l10n/<locale>/controls.toml`) via the catalog's l10n machinery —
    /// the structural [`ControlDef`] no longer carries a title.
    pub framework_dirs: BTreeMap<String, PathBuf>,
    /// Raw per-contribution mappings with provenance (pre-union; see
    /// [`LoadedMapping`]).
    pub mappings: Vec<LoadedMapping>,
    /// Human-readable forward-compat skips (unknown dimension / provides tag) and
    /// other non-fatal notes. Never the place for hard errors.
    pub warnings: Vec<String>,
}

impl LoadedFrameworks {
    /// The merged [`PolarControls`] for permission `perm` in framework `fw`.
    ///
    /// Borrows the stored value on a hit (no allocation) and yields an owned
    /// empty default on a miss, returned as a [`Cow`] so the common lookup-and-read
    /// path stays allocation-free. Callers read fields/methods straight through
    /// the `Cow`'s `Deref`.
    pub fn controls_for(&self, perm: &str, fw: &str) -> Cow<'_, PolarControls> {
        self.forward
            .get(perm)
            .and_then(|by_fw| by_fw.get(fw))
            .map_or_else(|| Cow::Owned(PolarControls::default()), Cow::Borrowed)
    }

    /// Controls in framework `fw` that have at least one **satisfies** link — the
    /// set coverage treats as "covered". Empty if the framework has no satisfies
    /// mappings (or is absent).
    pub fn satisfied_controls(&self, fw: &str) -> Vec<String> {
        self.reverse
            .get(&Polarity::Satisfies)
            .and_then(|by_fw| by_fw.get(fw))
            .map(|by_control| by_control.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Controls in framework `fw` that have at least one **risk** link, each with
    /// the permission ids that threaten it (deduped, sorted by control id).
    pub fn risk_controls(&self, fw: &str) -> Vec<(String, Vec<String>)> {
        self.reverse
            .get(&Polarity::Risk)
            .and_then(|by_fw| by_fw.get(fw))
            .map(|by_control| {
                by_control
                    .iter()
                    .map(|(ctrl, perms)| (ctrl.clone(), perms.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Severity of a framework cross-reference lint finding.
///
/// The framework layer is *advisory* metadata that can never widen, narrow, or
/// break a grant (see the module docs), so almost every integrity problem it can
/// detect is a [`FrameworkLintSeverity::Warning`] — a signal worth surfacing in a
/// report, not a reason to fail. The single [`FrameworkLintSeverity::Error`]
/// mirrors the loader's one hard failure, [`FrameworkError::IdCollision`]: a
/// duplicate framework id makes the loaded report depend on filesystem read order,
/// which is determinism-breaking rather than merely advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameworkLintSeverity {
    /// An advisory framework-layer integrity signal (the common case).
    Warning,
    /// A determinism-breaking problem (currently only an id collision).
    Error,
}

/// One framework cross-reference lint finding: a stable machine-readable [`code`],
/// a [`severity`], and a human-readable [`message`].
///
/// `code` is a stable identifier (never a free-form string) so downstream tooling
/// and tests can match on the *kind* of finding without parsing the message. The
/// defined codes are: `"orphaned-mapping"`, `"provides-desync"`,
/// `"mapping-unknown-control"`, `"satisfies-risk-conflict"`, `"id-collision"`,
/// `"control-missing-title"` (a control defined in `controls.toml` with no title
/// in any locale — see [`controls_missing_title`]), and (for the version-delta
/// comparator) `"controls-membership-delta"`.
///
/// [`code`]: FrameworkLint::code
/// [`severity`]: FrameworkLint::severity
/// [`message`]: FrameworkLint::message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkLint {
    /// Stable machine-readable finding code (see type docs).
    pub code: &'static str,
    /// How serious this finding is.
    pub severity: FrameworkLintSeverity,
    /// Human-readable description, naming the framework(s)/id(s) involved.
    pub message: String,
}

/// Lint an already-loaded framework cross-reference for integrity problems,
/// returning advisory findings (mostly [`FrameworkLintSeverity::Warning`]).
///
/// Operates purely on what [`load_frameworks`] already collected — it never
/// re-walks the filesystem and does no I/O. That is deliberate: this layer is
/// advisory metadata (see the module docs) and must stay off the report path's
/// hot loop, so linting is a pure function over the in-memory indices rather than
/// a second filesystem pass that could disagree with the loaded set.
///
/// `known_permission_ids` is the set of catalog permission ids a mapping is
/// validated against: a mapping keyed on an id outside this set is an orphaned
/// reference (the catalog may have dropped it, or it was a typo). The caller
/// supplies it because the framework layer imports nothing from the catalog beyond
/// [`OsTarget`].
///
/// Findings are appended in a fixed order so the output is deterministic regardless
/// of map contents: all orphaned-mapping findings first, then all provides-desync,
/// then all mapping-unknown-control. Within each group the source maps are
/// `BTreeMap`s, so the per-group order is sorted too.
pub fn lint_loaded(
    loaded: &LoadedFrameworks,
    known_permission_ids: &std::collections::BTreeSet<String>,
) -> Vec<FrameworkLint> {
    let mut findings = Vec::new();

    for (perm, by_fw) in &loaded.forward {
        if !known_permission_ids.contains(perm) {
            for fw in by_fw.keys() {
                findings.push(FrameworkLint {
                    code: "orphaned-mapping",
                    severity: FrameworkLintSeverity::Warning,
                    message: format!(
                        "framework mapping references permission-id {:?} absent from the catalog (orphaned mapping); framework {}",
                        perm, fw
                    ),
                });
            }
        }
    }

    for (id, manifest) in &loaded.frameworks {
        let has_controls = loaded.controls.get(id).is_some_and(|c| !c.is_empty());
        let advertises = manifest.provides.iter().any(|p| p == "controls");
        if advertises && !has_controls {
            findings.push(FrameworkLint {
                code: "provides-desync",
                severity: FrameworkLintSeverity::Warning,
                message: format!(
                    "framework {} advertises provides=\"controls\" but ships no controls.toml",
                    id
                ),
            });
        }
        if has_controls && !advertises {
            findings.push(FrameworkLint {
                code: "provides-desync",
                severity: FrameworkLintSeverity::Warning,
                message: format!(
                    "framework {} ships controls.toml but does not advertise provides=\"controls\"",
                    id
                ),
            });
        }
    }

    for id in loaded.frameworks.keys() {
        let Some(defined) = loaded
            .controls
            .get(id)
            .filter(|controls| !controls.is_empty())
        else {
            continue;
        };
        // Union of control ids referenced under ANY polarity for this framework.
        let mut referenced: std::collections::BTreeSet<&String> = std::collections::BTreeSet::new();
        for by_fw in loaded.reverse.values() {
            if let Some(by_control) = by_fw.get(id) {
                referenced.extend(by_control.keys());
            }
        }
        for ctrl in referenced {
            if !defined.contains_key(ctrl) {
                findings.push(FrameworkLint {
                    code: "mapping-unknown-control",
                    severity: FrameworkLintSeverity::Warning,
                    message: format!(
                        "framework {} mapping references control-id {:?} not defined in controls.toml",
                        id, ctrl
                    ),
                });
            }
        }
    }

    // A control-id in BOTH satisfies and risk of one permission is a contradiction
    // (the capability cannot both address and undermine the same control) → ERROR.
    for (perm, by_fw) in &loaded.forward {
        for (fw, polar) in by_fw {
            for ctrl in &polar.satisfies {
                if polar.risk.iter().any(|r| r == ctrl) {
                    findings.push(FrameworkLint {
                        code: "satisfies-risk-conflict",
                        severity: FrameworkLintSeverity::Error,
                        message: format!(
                            "framework {} permission {:?} maps control-id {:?} as both satisfies and risk (contradiction)",
                            fw, perm, ctrl
                        ),
                    });
                }
            }
        }
    }

    findings
}

/// Compares two versions of a framework's controls.toml control-id sets and reports
/// membership deltas. The current single-run load cannot diff two versions, so this
/// is a standalone comparator (a hook the spec asks for); it is intentionally NOT
/// wired into lint_loaded.
pub fn controls_membership_delta(
    old: &std::collections::BTreeMap<String, ControlDef>,
    new: &std::collections::BTreeMap<String, ControlDef>,
) -> Vec<FrameworkLint> {
    let mut findings = Vec::new();

    for id in old.keys() {
        if !new.contains_key(id) {
            findings.push(FrameworkLint {
                code: "controls-membership-delta",
                severity: FrameworkLintSeverity::Warning,
                message: format!(
                    "control {} removed in newer controls.toml (membership delta)",
                    id
                ),
            });
        }
    }

    for id in new.keys() {
        if !old.contains_key(id) {
            findings.push(FrameworkLint {
                code: "controls-membership-delta",
                severity: FrameworkLintSeverity::Warning,
                message: format!(
                    "control {} added in newer controls.toml (membership delta)",
                    id
                ),
            });
        }
    }

    findings
}

/// The structural control ids that resolve to NO title in **any** of `locales` —
/// the controls a report would render as the bare control id with nothing to flag
/// it.
///
/// This guards the exact drift the structural/l10n split risks: `controls.toml`
/// (which control ids exist) and the l10n tree (`l10n/<locale>/controls.toml`,
/// which carries the titles) are edited independently, so a control added to the
/// structural file but never given a title — or one whose id is typo'd between the
/// two — silently degrades to its bare id in every locale via the
/// `locale → en → id` fallback. The permission layer treats the same situation as
/// a first-class lint signal; this is the framework-layer mirror.
///
/// A title in **any** single locale clears the id: one resolvable title is enough
/// to give the report a real label, so the per-locale completeness gap (a control
/// translated in `en` but not `ru`) is deliberately not flagged here — that is a
/// translation-coverage concern, not the drift this detects. Reuses
/// [`crate::l10n::missing_translations`] over the control-id set (as the "catalog
/// ids") and keeps only the ids it reports as missing in *every* linted locale, so
/// the title-presence rule cannot drift from the permission lint's.
///
/// Pure over the supplied [`L10nSource`] and id/locale slices (no filesystem walk
/// of its own), so it is unit-tested with an in-memory source; the CLI lint wrapper
/// builds a [`crate::l10n::LiveL10n`] over the framework's own directory and passes
/// the live locale set in. Returned ids preserve the input `control_ids` order.
pub fn controls_missing_title(
    control_ids: &[&str],
    l10n: &dyn crate::l10n::L10nSource,
    locales: &[&str],
) -> Vec<String> {
    // `missing_translations` yields one `Missing` per (locale, id) that lacks a
    // title. An id is a drift signal only when it is missing in EVERY linted
    // locale, so count the locales each id is missing in and keep the ids whose
    // miss-count equals the number of locales linted.
    let missing = crate::l10n::missing_translations(l10n, locales, control_ids);
    control_ids
        .iter()
        .filter(|&&id| {
            let miss_count = missing.iter().filter(|m| m.id == id).count();
            miss_count == locales.len()
        })
        .map(|&id| id.to_owned())
        .collect()
}

/// The default framework roots in precedence order (lowest first): the vendor
/// tree under `/usr/share` and the local override tree under `/etc`, mirroring the
/// catalog/l10n `/etc`-over-`/usr/share` convention. Each root points *at* the
/// frameworks dir, so a framework `pci-dss` is `<root>/pci-dss/framework.toml`.
pub fn default_framework_roots() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/usr/share/census/frameworks"),
        PathBuf::from("/etc/census/frameworks.d"),
    ]
}

/// Read every `*.toml` file directly in `dir` (non-recursive), skipping symlinks,
/// and return `(path, text)` pairs sorted by path so merge order is deterministic.
///
/// A dir that does not exist contributes nothing (not an error). The symlink guard
/// mirrors the catalog/l10n one: this read happens as root, so a symlink planted in
/// a framework dir must not let an out-of-tree file be read (`is_symlink` uses
/// `symlink_metadata`, which does not follow the link).
fn read_toml_files(dir: &Path) -> Result<Vec<(PathBuf, String)>, FrameworkError> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| FrameworkError::Io {
        path: dir.to_owned(),
        reason: e.to_string(),
    })? {
        let entry = entry.map_err(|e| FrameworkError::Io {
            path: dir.to_owned(),
            reason: e.to_string(),
        })?;
        let path = entry.path();
        if path.is_symlink() {
            continue;
        }
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("toml") {
            paths.push(path);
        }
    }
    // Sort so the merge order within a dir is stable regardless of readdir order.
    paths.sort();

    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let text = std::fs::read_to_string(&path).map_err(|e| FrameworkError::Io {
            path: path.clone(),
            reason: e.to_string(),
        })?;
        out.push((path, text));
    }
    Ok(out)
}

/// Parse a single mapping file's text into a `permission-id → MappingEntry` map,
/// wrapping a toml error into [`FrameworkError::TomlParse`] tagged with `path`.
fn parse_mapping_file(
    path: &Path,
    text: &str,
) -> Result<BTreeMap<String, MappingEntry>, FrameworkError> {
    toml::from_str::<BTreeMap<String, MappingEntry>>(text).map_err(|e| FrameworkError::TomlParse {
        path: path.to_owned(),
        reason: e.to_string(),
    })
}

/// The set of mapping directories to read for a framework, each tagged with its
/// provenance `layer` (`None` for flat, `Some(layer)` for each os-layered layer
/// bottom→top). Centralises the one place the two dimensions diverge so the rest
/// of the loader is a single pass.
fn mapping_dirs(
    fw_dir: &Path,
    dimension: Dimension,
    os: &OsTarget,
) -> Vec<(Option<String>, PathBuf)> {
    let mappings_root = fw_dir.join("mappings");
    match dimension {
        // Flat: read mappings/*.toml directly; the OS target is ignored.
        Dimension::Flat => vec![(None, mappings_root)],
        // Os-layered: one subdir per OS layer, bottom→top. REUSE the catalog's
        // OsTarget::layer_names() so the chain-building lives in exactly one place
        // and never drifts from the catalog's leaf resolve. An absent layer subdir
        // simply contributes nothing (read_toml_files returns empty).
        Dimension::OsLayered => os
            .layer_names()
            .into_iter()
            .map(|layer| {
                let dir = mappings_root.join(&layer);
                (Some(layer), dir)
            })
            .collect(),
    }
}

/// Load the framework cross-reference from `roots` (precedence order, lowest
/// first), resolving os-layered frameworks against `os`.
///
/// Each `<root>/<fw>/` subdir is one framework: its `framework.toml` manifest, a
/// `mappings/` tree (flat or per-OS-layer per the manifest's `dimension`), and an
/// optional `controls.toml`. The loader:
///   * skips a framework whose dimension or `provides` tag is unknown, recording a warning
///     (forward-compat — never an error);
///   * rejects a duplicate `framework.id` across roots/subdirs as a hard
///     [`FrameworkError::IdCollision`] (determinism, not override);
///   * emits one [`LoadedMapping`] per (framework, permission, source-file) so per-contribution
///     provenance is exact, then builds the forward index by unioning+deduping the relevant
///     contributions and inverts it for the reverse index.
///
/// An absent root, or no frameworks at all, yields empty indices and no error.
///
/// Read-only: this function imports nothing from compile/plan/apply/model — only
/// [`OsTarget`] for the os-layered layer chain — and never mutates anything.
pub fn load_frameworks(
    roots: &[PathBuf],
    os: &OsTarget,
) -> Result<LoadedFrameworks, FrameworkError> {
    let mut out = LoadedFrameworks::default();

    for root in roots {
        if !root.is_dir() {
            // A root that is not installed contributes nothing (common case).
            continue;
        }
        // Iterate <root>/<fw>/ subdirs, sorted for a deterministic load order.
        let mut fw_dirs: Vec<PathBuf> = Vec::new();
        for entry in std::fs::read_dir(root).map_err(|e| FrameworkError::Io {
            path: root.clone(),
            reason: e.to_string(),
        })? {
            let entry = entry.map_err(|e| FrameworkError::Io {
                path: root.clone(),
                reason: e.to_string(),
            })?;
            let path = entry.path();
            // Symlink guard: this read happens as root; a planted symlink must not
            // let an out-of-tree directory be treated as a framework.
            if path.is_symlink() {
                continue;
            }
            if path.is_dir() {
                fw_dirs.push(path);
            }
        }
        fw_dirs.sort();

        for fw_dir in fw_dirs {
            load_one_framework(&fw_dir, os, &mut out)?;
        }
    }

    // Build the reverse index by inverting the (already merged+deduped) forward
    // index. Permission lists are deduped and BTreeMap iteration keeps order stable.
    out.reverse = invert_forward(&out.forward);

    Ok(out)
}

/// Load one `<root>/<fw>/` framework subdir into `out`, or skip it with a warning
/// for a tolerated forward-compat reason. A missing manifest is silently ignored
/// (the subdir is not a framework); a malformed one is a hard error.
fn load_one_framework(
    fw_dir: &Path,
    os: &OsTarget,
    out: &mut LoadedFrameworks,
) -> Result<(), FrameworkError> {
    let manifest_path = fw_dir.join("framework.toml");
    if manifest_path.is_symlink() || !manifest_path.is_file() {
        // No manifest → not a framework; ignore (the dir may be unrelated).
        return Ok(());
    }
    let manifest_text =
        std::fs::read_to_string(&manifest_path).map_err(|e| FrameworkError::Io {
            path: manifest_path.clone(),
            reason: e.to_string(),
        })?;
    let manifest = parse_manifest(&manifest_text).map_err(|e| FrameworkError::TomlParse {
        path: manifest_path.clone(),
        reason: e.to_string(),
    })?;

    // Tolerated forward-compat skips: unknown dimension, unknown provides tag. The
    // framework is not loaded into the indices, but a warning records why so the
    // signal is not silently lost.
    let Some(dimension) = Dimension::parse(&manifest.dimension) else {
        out.warnings.push(format!(
            "framework {} ({}) skipped: unknown dimension {:?}",
            manifest.id,
            manifest_path.display(),
            manifest.dimension
        ));
        return Ok(());
    };
    if let Some(unknown) = manifest
        .provides
        .iter()
        .find(|tag| !KNOWN_PROVIDES.contains(&tag.as_str()))
    {
        out.warnings.push(format!(
            "framework {} ({}) skipped: unknown provides tag {:?}",
            manifest.id,
            manifest_path.display(),
            unknown
        ));
        return Ok(());
    }

    // Framework-id collision across roots/subdirs is ambiguous → hard error
    // (determinism: a silent override would depend on read order).
    if out.frameworks.contains_key(&manifest.id) {
        return Err(FrameworkError::IdCollision {
            id: manifest.id.clone(),
        });
    }

    // --- mappings: one LoadedMapping per (permission, source-file), and a
    //     per-framework merged+deduped union folded into the forward index. ---
    let fw_id = manifest.id.clone();

    // Per-framework merge accumulator (`permission → PolarControls`).
    // `merge_mappings` works on this flat shape; it is folded into the nested
    // forward index (`permission → framework → PolarControls`) after every
    // file/layer is merged.
    let mut merged: BTreeMap<String, PolarControls> = BTreeMap::new();

    for (layer, dir) in mapping_dirs(fw_dir, dimension, os) {
        for (path, text) in read_toml_files(&dir)? {
            let file_map = parse_mapping_file(&path, &text)?;

            // Per-contribution provenance: record one LoadedMapping per permission
            // this file mentions, carrying *this file's* controls and layer/path.
            for (perm, entry) in &file_map {
                out.mappings.push(LoadedMapping {
                    framework_id: fw_id.clone(),
                    permission_id: perm.clone(),
                    satisfies: entry.satisfies.clone(),
                    risk: entry.risk.clone(),
                    related: entry.related.clone(),
                    provenance: MappingProvenance {
                        framework_id: fw_id.clone(),
                        layer: layer.clone(),
                        path: path.clone(),
                    },
                });
            }

            // Merge this file's controls into the per-framework accumulator,
            // unioning+deduping across all files and layers.
            merge_mappings(&mut merged, file_map);
        }
    }

    // Fold the per-framework merged union into the nested forward index keyed
    // `permission → framework → PolarControls`.
    for (perm, polar) in merged {
        out.forward
            .entry(perm)
            .or_default()
            .insert(fw_id.clone(), polar);
    }

    // --- controls.toml (optional): a missing file is fine; a malformed one is a
    //     hard error (Census owns the format). ---
    let controls_path = fw_dir.join("controls.toml");
    if !controls_path.is_symlink() && controls_path.is_file() {
        let controls_text =
            std::fs::read_to_string(&controls_path).map_err(|e| FrameworkError::Io {
                path: controls_path.clone(),
                reason: e.to_string(),
            })?;
        let defs = parse_controls(&controls_text).map_err(|e| FrameworkError::TomlParse {
            path: controls_path.clone(),
            reason: e.to_string(),
        })?;
        out.controls.insert(fw_id.clone(), defs);
    }

    // Record the framework's directory so the report layer can resolve control
    // titles from `<fw_dir>/l10n/<locale>/controls.toml` (the structural ControlDef
    // carries no title).
    out.framework_dirs.insert(fw_id.clone(), fw_dir.to_owned());
    out.frameworks.insert(fw_id, manifest);
    Ok(())
}

/// Build the polarity-keyed reverse index
/// (`polarity → framework → control → [permission]`) by inverting the forward
/// index (`permission → framework → PolarControls`). Permission lists are deduped
/// (first-seen order); `BTreeMap` iteration keeps the control and framework order
/// stable, so the inversion is deterministic.
fn invert_forward(
    forward: &BTreeMap<String, BTreeMap<String, PolarControls>>,
) -> BTreeMap<Polarity, BTreeMap<String, BTreeMap<String, Vec<String>>>> {
    let mut reverse: BTreeMap<Polarity, BTreeMap<String, BTreeMap<String, Vec<String>>>> =
        BTreeMap::new();
    for (perm, by_fw) in forward {
        for (fw, polar) in by_fw {
            for (polarity, controls) in [
                (Polarity::Satisfies, &polar.satisfies),
                (Polarity::Risk, &polar.risk),
                (Polarity::Related, &polar.related),
            ] {
                for control in controls {
                    let perms = reverse
                        .entry(polarity)
                        .or_default()
                        .entry(fw.clone())
                        .or_default()
                        .entry(control.clone())
                        .or_default();
                    if !perms.iter().any(|p| p == perm) {
                        perms.push(perm.clone());
                    }
                }
            }
        }
    }
    reverse
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    // --- helpers ---

    /// Write `body` to `<root>/<relpath>`, creating parent dirs. Mirrors l10n's
    /// `write_l10n` helper.
    fn write_file(root: &Path, relpath: &str, body: &str) {
        let path = root.join(relpath);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
    }

    /// A flat OS target (no version) — enough for flat-framework tests.
    fn flat_os() -> OsTarget {
        OsTarget::new("linux", "debian", None).unwrap()
    }

    fn ctl() -> ControlDef {
        ControlDef {
            owned: true,
            domain: None,
        }
    }

    // --- SLICE 1: formats & parsing ---

    #[test]
    fn valid_manifest_parses() {
        let m = parse_manifest(
            r#"
id = "pci-dss"
version = "4.0"
title = "PCI DSS"
dimension = "flat"
provides = ["crossref", "controls"]
"#,
        )
        .unwrap();
        assert_eq!(m.id, "pci-dss");
        assert_eq!(m.version, "4.0");
        assert_eq!(m.title, "PCI DSS");
        assert_eq!(m.dimension, "flat");
        assert_eq!(m.provides, vec!["crossref", "controls"]);
        assert_eq!(Dimension::parse(&m.dimension), Some(Dimension::Flat));
    }

    #[test]
    fn manifest_provides_defaults_empty() {
        let m = parse_manifest(
            r#"
id = "soc2"
version = "1"
title = "SOC 2"
dimension = "os-layered"
"#,
        )
        .unwrap();
        assert!(m.provides.is_empty());
        assert_eq!(Dimension::parse(&m.dimension), Some(Dimension::OsLayered));
    }

    #[test]
    fn manifest_unknown_field_rejected() {
        // deny_unknown_fields: an unrecognised manifest field is a typo / stale
        // file, not something to silently ignore.
        let err = parse_manifest(
            r#"
id = "x"
version = "1"
title = "X"
dimension = "flat"
bogus = "nope"
"#,
        );
        assert!(err.is_err(), "unknown manifest field must be rejected");
    }

    #[test]
    fn dimension_parse_maps_known_and_rejects_unknown() {
        assert_eq!(Dimension::parse("flat"), Some(Dimension::Flat));
        assert_eq!(Dimension::parse("os-layered"), Some(Dimension::OsLayered));
        assert_eq!(Dimension::parse("bogus"), None);
    }

    #[test]
    fn merge_mappings_unions_duplicate_perm_with_dedup() {
        // Two files mention the same permission with overlapping-but-different
        // controls: the union dedups and preserves first-seen order.
        let mut acc: BTreeMap<String, PolarControls> = BTreeMap::new();
        let mut file_a: BTreeMap<String, MappingEntry> = BTreeMap::new();
        file_a.insert(
            "network-admin".to_owned(),
            MappingEntry {
                satisfies: vec!["1.1".to_owned(), "1.2".to_owned()],
                risk: vec![],
                related: vec![],
            },
        );
        let mut file_b: BTreeMap<String, MappingEntry> = BTreeMap::new();
        file_b.insert(
            "network-admin".to_owned(),
            MappingEntry {
                satisfies: vec!["1.2".to_owned(), "2.1".to_owned()],
                risk: vec![],
                related: vec![],
            },
        );
        merge_mappings(&mut acc, file_a);
        merge_mappings(&mut acc, file_b);
        // 1.2 appears in both → deduped; first-seen order preserved.
        assert_eq!(acc["network-admin"].satisfies, vec!["1.1", "1.2", "2.1"]);
    }

    #[test]
    fn merge_mappings_unions_each_polarity_separately() {
        let mut acc: BTreeMap<String, PolarControls> = BTreeMap::new();
        let mut file_a: BTreeMap<String, MappingEntry> = BTreeMap::new();
        file_a.insert(
            "p".to_owned(),
            MappingEntry {
                satisfies: vec!["1.1".to_owned(), "1.2".to_owned()],
                risk: vec!["R.1".to_owned()],
                related: vec![],
            },
        );
        let mut file_b: BTreeMap<String, MappingEntry> = BTreeMap::new();
        file_b.insert(
            "p".to_owned(),
            MappingEntry {
                satisfies: vec!["1.2".to_owned(), "2.1".to_owned()],
                risk: vec!["R.1".to_owned(), "R.2".to_owned()],
                related: vec!["X".to_owned()],
            },
        );
        merge_mappings(&mut acc, file_a);
        merge_mappings(&mut acc, file_b);
        assert_eq!(acc["p"].satisfies, vec!["1.1", "1.2", "2.1"]);
        assert_eq!(acc["p"].risk, vec!["R.1", "R.2"]);
        assert_eq!(acc["p"].related, vec!["X"]);
    }

    #[test]
    fn mapping_entry_unknown_field_rejected() {
        // A typo'd field (`control` not `controls`) must be rejected.
        let err = toml::from_str::<BTreeMap<String, MappingEntry>>(
            "[network-admin]\ncontrol = [\"1.1\"]\n",
        );
        assert!(err.is_err(), "unknown mapping field must be rejected");
    }

    #[test]
    fn parse_controls_missing_owned_is_error() {
        // `owned` is required (no serde default): omitting it is a material
        // compliance fact left unstated → parse error.
        let err = parse_controls("[\"1.1\"]\ndomain = \"Network Security\"\n");
        assert!(err.is_err(), "missing `owned` must be a parse error");
    }

    #[test]
    fn parse_controls_valid_with_owned_and_optional_domain() {
        // `controls.toml` is structural only: owned + optional domain, no title.
        let defs = parse_controls(
            r#"
["1.1"]
owned = true
domain = "Network Security"

["1.2"]
owned = false
"#,
        )
        .unwrap();
        assert!(defs["1.1"].owned);
        assert_eq!(defs["1.1"].domain.as_deref(), Some("Network Security"));
        assert!(!defs["1.2"].owned);
        assert_eq!(defs["1.2"].domain, None);
    }

    #[test]
    fn parse_controls_title_is_rejected_as_unknown_field() {
        // A title in the structural file is the exact mistake the l10n split
        // forbids: titles belong in `l10n/<locale>/controls.toml`, not here.
        // `deny_unknown_fields` makes a stray `title` a hard parse error.
        let err = parse_controls("[\"1.1\"]\nowned = true\ntitle = \"Install a firewall\"\n");
        assert!(err.is_err(), "a `title` in controls.toml must be rejected");
    }

    #[test]
    fn parse_controls_unknown_field_rejected() {
        let err = parse_controls("[\"1.1\"]\nowned = true\nbogus = 1\n");
        assert!(err.is_err(), "unknown control field must be rejected");
    }

    // --- SLICE 2: loader & indices ---

    #[test]
    fn flat_framework_builds_indices_with_dedup_union() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(
            root,
            "pci-dss/framework.toml",
            r#"
id = "pci-dss"
version = "4.0"
title = "PCI DSS"
dimension = "flat"
provides = ["crossref", "controls"]
"#,
        );
        // a.toml and b.toml share network-admin with different controls → union.
        write_file(
            root,
            "pci-dss/mappings/a.toml",
            "[network-admin]\nsatisfies = [\"1.1\", \"1.2\"]\n",
        );
        write_file(
            root,
            "pci-dss/mappings/b.toml",
            "[network-admin]\nsatisfies = [\"1.2\", \"2.1\"]\n[log-read]\nsatisfies = [\"10.1\"]\n",
        );
        write_file(
            root,
            "pci-dss/controls.toml",
            r#"
["1.1"]
owned = true
["1.2"]
owned = true
["2.1"]
owned = false
["10.1"]
owned = true
"#,
        );

        let loaded = load_frameworks(&[root.to_path_buf()], &flat_os()).unwrap();

        // Manifest loaded.
        assert!(loaded.frameworks.contains_key("pci-dss"));
        // Forward index: dedup union of the duplicate permission.
        assert_eq!(
            loaded.forward["network-admin"]["pci-dss"].satisfies,
            vec!["1.1", "1.2", "2.1"]
        );
        assert_eq!(
            loaded.forward["log-read"]["pci-dss"].satisfies,
            vec!["10.1"]
        );
        // Convenience accessor agrees.
        assert_eq!(
            loaded.controls_for("network-admin", "pci-dss").satisfies,
            vec!["1.1", "1.2", "2.1"]
        );
        // Reverse index: control → permissions.
        assert_eq!(
            loaded.reverse[&Polarity::Satisfies]["pci-dss"]["1.1"],
            vec!["network-admin"]
        );
        assert_eq!(
            loaded.reverse[&Polarity::Satisfies]["pci-dss"]["1.2"],
            vec!["network-admin"]
        );
        assert_eq!(
            loaded.reverse[&Polarity::Satisfies]["pci-dss"]["10.1"],
            vec!["log-read"]
        );
        // Controls loaded with owned flags.
        assert!(loaded.controls["pci-dss"]["1.1"].owned);
        assert!(!loaded.controls["pci-dss"]["2.1"].owned);
        assert!(loaded.warnings.is_empty());
    }

    #[test]
    fn os_layered_framework_merges_layers_with_provenance() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(
            root,
            "gost/framework.toml",
            r#"
id = "gost"
version = "1"
title = "ГОСТ"
dimension = "os-layered"
provides = ["crossref"]
"#,
        );
        // Base linux layer and a version-specific layer both map network-admin.
        write_file(
            root,
            "gost/mappings/linux/net.toml",
            "[network-admin]\nsatisfies = [\"A.1\"]\n",
        );
        write_file(
            root,
            "gost/mappings/linux-debian-12/net.toml",
            "[network-admin]\nsatisfies = [\"A.2\"]\n",
        );

        let os = OsTarget::new("linux", "debian", Some("12".to_owned())).unwrap();
        let loaded = load_frameworks(&[root.to_path_buf()], &os).unwrap();

        // Grants from BOTH layers merged (union across the layer chain).
        assert_eq!(
            loaded.forward["network-admin"]["gost"].satisfies,
            vec!["A.1", "A.2"]
        );

        // Provenance per contribution: one LoadedMapping for the base layer file
        // (layer None? no — os-layered carries the layer name) and one for the
        // version layer.
        let base = loaded
            .mappings
            .iter()
            .find(|m| m.provenance.layer.as_deref() == Some("linux"))
            .expect("base-layer contribution present");
        assert_eq!(base.framework_id, "gost");
        assert_eq!(base.permission_id, "network-admin");
        assert_eq!(base.satisfies, vec!["A.1"]);
        assert!(base.provenance.path.ends_with("net.toml"));

        let ver = loaded
            .mappings
            .iter()
            .find(|m| m.provenance.layer.as_deref() == Some("linux-debian-12"))
            .expect("version-layer contribution present");
        assert_eq!(ver.satisfies, vec!["A.2"]);
        assert!(ver.provenance.path.ends_with("linux-debian-12/net.toml"));
    }

    #[test]
    fn provenance_flat_has_no_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(
            root,
            "pci-dss/framework.toml",
            "id = \"pci-dss\"\nversion = \"4\"\ntitle = \"PCI\"\ndimension = \"flat\"\n",
        );
        write_file(
            root,
            "pci-dss/mappings/net.toml",
            "[network-admin]\nsatisfies = [\"1.1\"]\n",
        );
        let loaded = load_frameworks(&[root.to_path_buf()], &flat_os()).unwrap();
        let m = loaded
            .mappings
            .iter()
            .find(|m| m.permission_id == "network-admin")
            .unwrap();
        assert_eq!(m.framework_id, "pci-dss");
        // Flat → layer is None.
        assert_eq!(m.provenance.layer, None);
        assert!(m.provenance.path.ends_with("net.toml"));
    }

    #[test]
    fn parses_three_polarities() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(
            root,
            "fw/framework.toml",
            "id = \"fw\"\nversion = \"1\"\ntitle = \"F\"\ndimension = \"flat\"\n",
        );
        write_file(
            root,
            "fw/mappings/m.toml",
            "[sudo-config]\nsatisfies = [\"7.2.2\"]\nrisk = [\"X\"]\nrelated = [\"Y\"]\n",
        );
        let loaded = load_frameworks(&[root.to_path_buf()], &flat_os()).unwrap();
        assert_eq!(loaded.forward["sudo-config"]["fw"].satisfies, vec!["7.2.2"]);
        assert_eq!(loaded.forward["sudo-config"]["fw"].risk, vec!["X"]);
        assert_eq!(loaded.forward["sudo-config"]["fw"].related, vec!["Y"]);
        assert_eq!(
            loaded.reverse[&Polarity::Satisfies]["fw"]["7.2.2"],
            vec!["sudo-config"]
        );
        assert_eq!(
            loaded.reverse[&Polarity::Risk]["fw"]["X"],
            vec!["sudo-config"]
        );
        assert_eq!(
            loaded.reverse[&Polarity::Related]["fw"]["Y"],
            vec!["sudo-config"]
        );
    }

    #[test]
    fn empty_tree_yields_empty_indices_no_error() {
        let tmp = tempfile::tempdir().unwrap();
        // A root path that does not exist contributes nothing, not an error.
        let nonexistent = tmp.path().join("does-not-exist");
        let loaded = load_frameworks(&[nonexistent], &flat_os()).unwrap();
        assert!(loaded.frameworks.is_empty());
        assert!(loaded.forward.is_empty());
        assert!(loaded.reverse.is_empty());
        assert!(loaded.controls.is_empty());
        assert!(loaded.mappings.is_empty());
        assert!(loaded.warnings.is_empty());
    }

    #[test]
    fn unknown_dimension_skips_framework_with_warning() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // Forward-compat: a framework using a dimension this Census predates.
        write_file(
            root,
            "future/framework.toml",
            "id = \"future\"\nversion = \"9\"\ntitle = \"Future\"\ndimension = \"hypergraph\"\n",
        );
        write_file(
            root,
            "future/mappings/x.toml",
            "[network-admin]\nsatisfies = [\"X\"]\n",
        );
        // A valid framework in the same root must still load.
        write_file(
            root,
            "pci-dss/framework.toml",
            "id = \"pci-dss\"\nversion = \"4\"\ntitle = \"PCI\"\ndimension = \"flat\"\n",
        );
        write_file(
            root,
            "pci-dss/mappings/x.toml",
            "[network-admin]\nsatisfies = [\"1.1\"]\n",
        );

        let loaded = load_frameworks(&[root.to_path_buf()], &flat_os()).unwrap();
        // future skipped (not in indices), warning recorded.
        assert!(!loaded.frameworks.contains_key("future"));
        assert_eq!(loaded.warnings.len(), 1);
        assert!(loaded.warnings[0].contains("future"));
        assert!(loaded.warnings[0].contains("dimension"));
        // pci-dss still loaded.
        assert!(loaded.frameworks.contains_key("pci-dss"));
        assert_eq!(
            loaded.forward["network-admin"]["pci-dss"].satisfies,
            vec!["1.1"]
        );
    }

    #[test]
    fn unknown_provides_tag_skips_framework_with_warning() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(
            root,
            "weird/framework.toml",
            r#"
id = "weird"
version = "1"
title = "Weird"
dimension = "flat"
provides = ["crossref", "teleport"]
"#,
        );
        write_file(
            root,
            "weird/mappings/x.toml",
            "[network-admin]\nsatisfies = [\"W\"]\n",
        );
        let loaded = load_frameworks(&[root.to_path_buf()], &flat_os()).unwrap();
        assert!(!loaded.frameworks.contains_key("weird"));
        assert_eq!(loaded.warnings.len(), 1);
        assert!(loaded.warnings[0].contains("provides"));
        assert!(loaded.warnings[0].contains("teleport"));
        // Skipped → no mappings entered the indices.
        assert!(loaded.forward.is_empty());
    }

    #[test]
    fn id_collision_across_roots_is_error() {
        let usr = tempfile::tempdir().unwrap();
        let etc = tempfile::tempdir().unwrap();
        // Both roots declare framework.id = "pci-dss" → ambiguous → hard error.
        write_file(
            usr.path(),
            "pci-dss/framework.toml",
            "id = \"pci-dss\"\nversion = \"4\"\ntitle = \"PCI\"\ndimension = \"flat\"\n",
        );
        write_file(
            etc.path(),
            "pci-dss/framework.toml",
            "id = \"pci-dss\"\nversion = \"4\"\ntitle = \"PCI override\"\ndimension = \"flat\"\n",
        );
        let err = load_frameworks(
            &[usr.path().to_path_buf(), etc.path().to_path_buf()],
            &flat_os(),
        )
        .unwrap_err();
        assert!(matches!(err, FrameworkError::IdCollision { id } if id == "pci-dss"));
    }

    #[test]
    fn malformed_manifest_is_hard_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(
            root,
            "broken/framework.toml",
            "this is = not valid toml [[[\n",
        );
        let err = load_frameworks(&[root.to_path_buf()], &flat_os()).unwrap_err();
        assert!(matches!(err, FrameworkError::TomlParse { .. }));
    }

    #[test]
    fn default_roots_are_usr_then_etc() {
        let roots = default_framework_roots();
        assert_eq!(
            roots,
            vec![
                PathBuf::from("/usr/share/census/frameworks"),
                PathBuf::from("/etc/census/frameworks.d"),
            ]
        );
    }

    #[test]
    fn os_layered_absent_layer_contributes_nothing() {
        // Only the base linux layer exists; the distro/version layers are absent.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(
            root,
            "gost/framework.toml",
            "id = \"gost\"\nversion = \"1\"\ntitle = \"G\"\ndimension = \"os-layered\"\n",
        );
        write_file(
            root,
            "gost/mappings/linux/net.toml",
            "[network-admin]\nsatisfies = [\"A.1\"]\n",
        );
        let os = OsTarget::new("linux", "debian", Some("12".to_owned())).unwrap();
        let loaded = load_frameworks(&[root.to_path_buf()], &os).unwrap();
        // Only the base layer contributed; no error from the missing subdirs.
        assert_eq!(
            loaded.forward["network-admin"]["gost"].satisfies,
            vec!["A.1"]
        );
        assert_eq!(loaded.mappings.len(), 1);
    }

    #[test]
    fn orphaned_mapping_flags_unknown_perm() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(
            root,
            "pci-dss/framework.toml",
            r#"
id = "pci-dss"
version = "4.0"
title = "PCI DSS"
dimension = "flat"
provides = ["crossref", "controls"]
"#,
        );
        write_file(
            root,
            "pci-dss/mappings/a.toml",
            "[ghost-perm]\nsatisfies = [\"1.1\"]\n",
        );
        write_file(root, "pci-dss/controls.toml", "[\"1.1\"]\nowned = true\n");

        let loaded = load_frameworks(&[root.to_path_buf()], &flat_os()).unwrap();
        let known_permission_ids = std::collections::BTreeSet::new();
        let findings = lint_loaded(&loaded, &known_permission_ids);
        let orphaned: Vec<_> = findings
            .iter()
            .filter(|finding| finding.code == "orphaned-mapping")
            .collect();
        assert_eq!(orphaned.len(), 1);
        assert!(orphaned[0].message.contains("ghost-perm"));

        let known_permission_ids = std::collections::BTreeSet::from(["ghost-perm".to_owned()]);
        let findings = lint_loaded(&loaded, &known_permission_ids);
        assert!(!findings
            .iter()
            .any(|finding| finding.code == "orphaned-mapping"));
    }

    #[test]
    fn provides_desync_both_directions() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(
            root,
            "fw-a/framework.toml",
            r#"
id = "fw-a"
version = "1"
title = "A"
dimension = "flat"
provides = ["controls"]
"#,
        );
        write_file(
            root,
            "fw-a/mappings/a.toml",
            "[perm-a]\nsatisfies = [\"1.1\"]\n",
        );
        write_file(
            root,
            "fw-b/framework.toml",
            r#"
id = "fw-b"
version = "1"
title = "B"
dimension = "flat"
provides = ["crossref"]
"#,
        );
        write_file(
            root,
            "fw-b/mappings/b.toml",
            "[perm-b]\nsatisfies = [\"1.1\"]\n",
        );
        write_file(root, "fw-b/controls.toml", "[\"1.1\"]\nowned = true\n");
        write_file(
            root,
            "fw-c/framework.toml",
            r#"
id = "fw-c"
version = "1"
title = "C"
dimension = "flat"
provides = ["controls"]
"#,
        );
        write_file(
            root,
            "fw-c/mappings/c.toml",
            "[perm-c]\nsatisfies = [\"1.1\"]\n",
        );
        write_file(root, "fw-c/controls.toml", "[\"1.1\"]\nowned = true\n");

        let loaded = load_frameworks(&[root.to_path_buf()], &flat_os()).unwrap();
        let known_permission_ids = std::collections::BTreeSet::from([
            "perm-a".to_owned(),
            "perm-b".to_owned(),
            "perm-c".to_owned(),
        ]);
        let findings = lint_loaded(&loaded, &known_permission_ids);
        let desync: Vec<_> = findings
            .iter()
            .filter(|finding| finding.code == "provides-desync")
            .collect();

        assert!(desync.iter().any(|finding| finding.message.contains("fw-a")
            && finding
                .message
                .contains("advertises provides=\"controls\" but ships no controls.toml")));
        assert!(desync.iter().any(|finding| finding.message.contains("fw-b")
            && finding
                .message
                .contains("ships controls.toml but does not advertise")));
        assert!(!desync
            .iter()
            .any(|finding| finding.message.contains("fw-c")));
    }

    #[test]
    fn mapping_unknown_control_flagged() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(
            root,
            "pci-dss/framework.toml",
            r#"
id = "pci-dss"
version = "4.0"
title = "PCI DSS"
dimension = "flat"
provides = ["crossref", "controls"]
"#,
        );
        write_file(
            root,
            "pci-dss/mappings/a.toml",
            "[network-admin]\nsatisfies = [\"9.9\", \"1.1\"]\n",
        );
        write_file(root, "pci-dss/controls.toml", "[\"1.1\"]\nowned = true\n");

        let loaded = load_frameworks(&[root.to_path_buf()], &flat_os()).unwrap();
        let known_permission_ids = std::collections::BTreeSet::from(["network-admin".to_owned()]);
        let findings = lint_loaded(&loaded, &known_permission_ids);
        let unknown: Vec<_> = findings
            .iter()
            .filter(|finding| finding.code == "mapping-unknown-control")
            .collect();

        assert_eq!(unknown.len(), 1);
        assert!(unknown[0].message.contains("9.9"));
        assert!(!unknown[0].message.contains("1.1"));
    }

    #[test]
    fn mapping_unknown_control_not_flagged_without_controls_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(
            root,
            "pci-dss/framework.toml",
            r#"
id = "pci-dss"
version = "4.0"
title = "PCI DSS"
dimension = "flat"
provides = ["controls"]
"#,
        );
        write_file(
            root,
            "pci-dss/mappings/a.toml",
            "[network-admin]\nsatisfies = [\"9.9\", \"1.1\"]\n",
        );

        let loaded = load_frameworks(&[root.to_path_buf()], &flat_os()).unwrap();
        let known_permission_ids = std::collections::BTreeSet::from(["network-admin".to_owned()]);
        let findings = lint_loaded(&loaded, &known_permission_ids);

        assert!(!findings
            .iter()
            .any(|finding| finding.code == "mapping-unknown-control"));
    }

    #[test]
    fn controls_membership_delta_reports_added_and_removed() {
        let old = BTreeMap::from([("1.1".to_owned(), ctl()), ("2.2".to_owned(), ctl())]);
        let new = BTreeMap::from([("2.2".to_owned(), ctl()), ("3.3".to_owned(), ctl())]);

        let findings = controls_membership_delta(&old, &new);

        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .all(|finding| finding.code == "controls-membership-delta"));
        assert!(findings[0].message.contains("1.1"));
        assert!(findings[0].message.contains("removed"));
        assert!(findings[1].message.contains("3.3"));
        assert!(findings[1].message.contains("added"));
    }

    #[test]
    fn consistent_framework_has_no_lints() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(
            root,
            "pci-dss/framework.toml",
            r#"
id = "pci-dss"
version = "4.0"
title = "PCI DSS"
dimension = "flat"
provides = ["crossref", "controls"]
"#,
        );
        write_file(
            root,
            "pci-dss/mappings/a.toml",
            "[network-admin]\nsatisfies = [\"1.1\"]\n",
        );
        write_file(root, "pci-dss/controls.toml", "[\"1.1\"]\nowned = true\n");

        let loaded = load_frameworks(&[root.to_path_buf()], &flat_os()).unwrap();
        let known_permission_ids = std::collections::BTreeSet::from(["network-admin".to_owned()]);

        assert!(lint_loaded(&loaded, &known_permission_ids).is_empty());
    }

    #[test]
    fn lint_satisfies_risk_conflict_is_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(
            root,
            "pci-dss/framework.toml",
            "id = \"pci-dss\"\nversion = \"4.0\"\ntitle = \"PCI\"\ndimension = \"flat\"\nprovides = [\"crossref\", \"controls\"]\n",
        );
        write_file(
            root,
            "pci-dss/mappings/a.toml",
            "[bad-perm]\nsatisfies = [\"C.1\"]\nrisk = [\"C.1\"]\n",
        );
        write_file(root, "pci-dss/controls.toml", "[\"C.1\"]\nowned = true\n");
        let loaded = load_frameworks(&[root.to_path_buf()], &flat_os()).unwrap();
        let known_permission_ids = std::collections::BTreeSet::from(["bad-perm".to_owned()]);
        let findings = lint_loaded(&loaded, &known_permission_ids);
        let conflict: Vec<_> = findings
            .iter()
            .filter(|f| f.code == "satisfies-risk-conflict")
            .collect();
        assert_eq!(conflict.len(), 1);
        assert_eq!(conflict[0].severity, FrameworkLintSeverity::Error);
    }

    #[test]
    fn lint_orphaned_covers_all_polarities() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_file(
            root,
            "pci-dss/framework.toml",
            "id = \"pci-dss\"\nversion = \"4.0\"\ntitle = \"PCI\"\ndimension = \"flat\"\n",
        );
        write_file(
            root,
            "pci-dss/mappings/a.toml",
            "[risk-only]\nrisk = [\"R.1\"]\n[related-only]\nrelated = [\"X\"]\n",
        );
        let loaded = load_frameworks(&[root.to_path_buf()], &flat_os()).unwrap();
        let known_permission_ids = std::collections::BTreeSet::new();
        let findings = lint_loaded(&loaded, &known_permission_ids);
        let orphaned: Vec<_> = findings
            .iter()
            .filter(|f| f.code == "orphaned-mapping")
            .collect();
        assert!(
            orphaned.iter().any(|f| f.message.contains("risk-only")),
            "{:?}",
            orphaned
        );
        assert!(
            orphaned.iter().any(|f| f.message.contains("related-only")),
            "{:?}",
            orphaned
        );
    }

    // --- SLICE: control-title l10n resolution ---

    /// Materialize a flat `pci-dss` framework whose `controls.toml` is structural
    /// (no title) and whose control titles live in the framework l10n tree under
    /// `l10n/{ru,en}/controls.toml`. Returns the loaded set over a flat OS target.
    fn fw_with_control_l10n(root: &Path) {
        write_file(
            root,
            "pci-dss/framework.toml",
            "id = \"pci-dss\"\nversion = \"4.0\"\ntitle = \"PCI DSS\"\ndimension = \"flat\"\nprovides = [\"crossref\", \"controls\"]\n",
        );
        write_file(
            root,
            "pci-dss/mappings/a.toml",
            "[network-admin]\nsatisfies = [\"7.2.2\"]\n",
        );
        // Structural only: owned, no title.
        write_file(
            root,
            "pci-dss/controls.toml",
            "[\"7.2.2\"]\nowned = true\n[\"7.2.4\"]\nowned = true\n",
        );
        // Titles live in the framework l10n tree, keyed by control id. ru has a
        // title for 7.2.2 only; en has 7.2.2; neither defines 7.2.4.
        write_file(
            root,
            "pci-dss/l10n/ru/controls.toml",
            "[\"7.2.2\"]\ntitle = \"Наименьшие привилегии\"\n",
        );
        write_file(
            root,
            "pci-dss/l10n/en/controls.toml",
            "[\"7.2.2\"]\ntitle = \"Least privilege\"\n",
        );
    }

    #[test]
    fn control_title_resolves_from_requested_locale() {
        let tmp = tempfile::tempdir().unwrap();
        fw_with_control_l10n(tmp.path());
        let loaded = load_frameworks(&[tmp.path().to_path_buf()], &flat_os()).unwrap();
        // ru is present → the Russian title wins.
        assert_eq!(
            resolve_control_title(&loaded, "pci-dss", "7.2.2", "ru"),
            "Наименьшие привилегии"
        );
    }

    #[test]
    fn control_title_falls_back_to_en_when_locale_missing() {
        let tmp = tempfile::tempdir().unwrap();
        fw_with_control_l10n(tmp.path());
        let loaded = load_frameworks(&[tmp.path().to_path_buf()], &flat_os()).unwrap();
        // zh has no l10n dir → fall back to en (mirrors the catalog's chain).
        assert_eq!(
            resolve_control_title(&loaded, "pci-dss", "7.2.2", "zh"),
            "Least privilege"
        );
    }

    #[test]
    fn control_title_falls_back_to_bare_id_when_untranslated() {
        let tmp = tempfile::tempdir().unwrap();
        fw_with_control_l10n(tmp.path());
        let loaded = load_frameworks(&[tmp.path().to_path_buf()], &flat_os()).unwrap();
        // 7.2.4 has no l10n entry in any locale → the bare control id is the label.
        assert_eq!(
            resolve_control_title(&loaded, "pci-dss", "7.2.4", "ru"),
            "7.2.4"
        );
        // An unknown framework also degrades to the bare id (no directory recorded).
        assert_eq!(
            resolve_control_title(&loaded, "no-such-fw", "7.2.2", "ru"),
            "7.2.2"
        );
    }

    // --- SLICE: control-missing-title integrity (structural vs l10n drift) ---

    #[test]
    fn controls_missing_title_flags_id_absent_from_every_locale() {
        // A control defined structurally but with no title in ANY linted locale —
        // exactly the drift the structural/l10n split risks: it would silently
        // render as the bare id in a report with nothing to flag it.
        let l10n = crate::l10n::FakeL10n::new()
            .with(
                "en",
                "7.2.2",
                crate::l10n::Description {
                    title: Some("Least privilege".to_owned()),
                    summary: None,
                    risk_note: None,
                },
            )
            .with(
                "ru",
                "7.2.2",
                crate::l10n::Description {
                    title: Some("Наименьшие привилегии".to_owned()),
                    summary: None,
                    risk_note: None,
                },
            );
        // 7.2.2 has a title (in both); 7.2.4 has none anywhere → only 7.2.4 flagged.
        let missing = controls_missing_title(&["7.2.2", "7.2.4"], &l10n, &["en", "ru"]);
        assert_eq!(missing, vec!["7.2.4".to_owned()]);
    }

    #[test]
    fn controls_missing_title_title_in_one_locale_clears_the_id() {
        // A title in ANY single locale is enough to resolve the report label, so
        // the id is NOT flagged even when other locales lack it (the per-locale
        // gap is a translation-completeness concern, not a drift concern).
        let l10n = crate::l10n::FakeL10n::new().with(
            "ru",
            "7.2.4",
            crate::l10n::Description {
                title: Some("Только по-русски".to_owned()),
                summary: None,
                risk_note: None,
            },
        );
        let missing = controls_missing_title(&["7.2.4"], &l10n, &["en", "ru"]);
        assert!(
            missing.is_empty(),
            "a title in any locale clears the id: {missing:?}"
        );
    }

    #[test]
    fn controls_missing_title_empty_when_all_translated() {
        let l10n = crate::l10n::FakeL10n::new()
            .with(
                "en",
                "a",
                crate::l10n::Description {
                    title: Some("A".to_owned()),
                    summary: None,
                    risk_note: None,
                },
            )
            .with(
                "en",
                "b",
                crate::l10n::Description {
                    title: Some("B".to_owned()),
                    summary: None,
                    risk_note: None,
                },
            );
        assert!(controls_missing_title(&["a", "b"], &l10n, &["en"]).is_empty());
    }

    #[test]
    fn controls_missing_title_over_live_tree_flags_undefined_control() {
        // End-to-end over a real framework l10n tree: 7.2.4 is in controls.toml
        // but has no title in en or ru → flagged; 7.2.2 is translated → not.
        let tmp = tempfile::tempdir().unwrap();
        fw_with_control_l10n(tmp.path());
        let loaded = load_frameworks(&[tmp.path().to_path_buf()], &flat_os()).unwrap();
        let dir = loaded.framework_dirs.get("pci-dss").unwrap();
        let l10n = crate::l10n::LiveL10n::new(vec![dir.clone()]);
        let ids: Vec<&str> = loaded.controls["pci-dss"]
            .keys()
            .map(String::as_str)
            .collect();
        let missing = controls_missing_title(&ids, &l10n, &["en", "ru"]);
        assert_eq!(missing, vec!["7.2.4".to_owned()]);
    }
}
