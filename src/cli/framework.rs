//! `census framework {list,show,coverage,risk,lint}` — read-only compliance
//! cross-reference.
//!
//! These surface the loaded framework tree: list installed frameworks, show one
//! framework's controls + coverage stats, the coverage gap-oracle (owned controls
//! with no mapping), the risk view (controls under threat), and lint integrity
//! findings. All strictly read-only metadata — they never touch
//! compile/plan/apply. Each `run_*` loads the frameworks (resolving os-layered
//! ones against the detected OS target) and delegates the output to a pure render
//! helper.

use std::path::PathBuf;
use std::process::ExitCode;

use crate::catalog::CatalogSource;
use crate::cli::detect_os_target;
use crate::cli::render::json_str;
use crate::framework::{self, resolve_control_title, LoadedFrameworks};
use crate::l10n::{self, L10nSource};
use crate::LiveCatalog;

/// Resolve the display locale for a framework report from an explicit `--lang`
/// plus the environment, mirroring `census show --lang`/`compile`'s selection:
/// explicit `--lang` → `LC_MESSAGES` → `LANG` → `en`. The real environment is
/// read here (the pure [`l10n::lang_from_env`] picker stays testable); control
/// titles then resolve through the framework l10n tree with the standard
/// `locale → en → id` fallback.
fn display_locale(lang: Option<&str>) -> String {
    let lc_messages = std::env::var("LC_MESSAGES").ok();
    let env_lang = std::env::var("LANG").ok();
    l10n::lang_from_env(lang, lc_messages.as_deref(), env_lang.as_deref())
}

/// Load the framework tree for a `framework` subcommand: resolve the OS target
/// (for os-layered frameworks) and call `load_frameworks`. Emits forward-compat
/// warnings to stderr. Returns the loaded set or an exit-failing error already
/// printed to stderr.
fn load_frameworks_for_cli(
    framework_roots: &[PathBuf],
    os_target: Option<String>,
) -> Result<LoadedFrameworks, ExitCode> {
    let os = match detect_os_target(os_target.as_deref()) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("census: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    match framework::load_frameworks(framework_roots, &os) {
        Ok(loaded) => {
            for w in &loaded.warnings {
                eprintln!("census: warning: {w}");
            }
            Ok(loaded)
        }
        Err(e) => {
            eprintln!("census: {e}");
            Err(ExitCode::FAILURE)
        }
    }
}

/// Run `census framework list`: enumerate installed frameworks with their version
/// and advertised `provides`. Always exits 0 (a query). Read-only.
pub fn run_framework_list(
    framework_roots: Vec<PathBuf>,
    os_target: Option<String>,
    json: bool,
) -> ExitCode {
    let loaded = match load_frameworks_for_cli(&framework_roots, os_target) {
        Ok(l) => l,
        Err(code) => return code,
    };
    if json {
        print!("{}", render_framework_list_json(&loaded));
    } else {
        print!("{}", render_framework_list_human(&loaded));
    }
    ExitCode::SUCCESS
}

/// Render the framework list (human form): one line per installed framework with
/// its id, version, title and `provides` tags. An empty tree reports
/// "no frameworks installed". Pure / unit-testable.
pub fn render_framework_list_human(loaded: &LoadedFrameworks) -> String {
    let mut out = String::new();
    if loaded.frameworks.is_empty() {
        out.push_str("no frameworks installed\n");
        return out;
    }
    out.push_str("frameworks:\n");
    for (id, m) in &loaded.frameworks {
        let provides = if m.provides.is_empty() {
            "-".to_owned()
        } else {
            m.provides.join(", ")
        };
        out.push_str(&format!(
            "  {} {} — {} [provides: {}]\n",
            id, m.version, m.title, provides
        ));
    }
    out
}

/// Render the framework list as JSON (hand-rolled). Each entry carries id,
/// version, title and the `provides` array. An empty tree yields an empty array.
/// Pure / unit-testable.
pub fn render_framework_list_json(loaded: &LoadedFrameworks) -> String {
    let mut out = String::new();
    out.push_str("{\"frameworks\":[");
    let items: Vec<String> = loaded
        .frameworks
        .iter()
        .map(|(id, m)| {
            let provides: Vec<String> = m.provides.iter().map(|p| json_str(p)).collect();
            format!(
                "{{\"id\":{},\"version\":{},\"title\":{},\"provides\":[{}]}}",
                json_str(id),
                json_str(&m.version),
                json_str(&m.title),
                provides.join(","),
            )
        })
        .collect();
    out.push_str(&items.join(","));
    out.push_str("]}");
    out.push('\n');
    out
}

/// Run `census framework lint`: load the framework cross-reference layer and
/// report integrity findings (orphaned mappings, provides/files desync, unknown
/// control dimension, id collision). The known-permission set is built from the
/// catalog so an orphaned mapping (a permission id absent from the catalog) is
/// detected. Read-only. Exit FAILURE iff any finding is an ERROR (only the
/// determinism-breaking id collision), else SUCCESS — warnings never gate.
pub fn run_framework_lint(
    framework_roots: Vec<PathBuf>,
    catalog_roots: Vec<PathBuf>,
    os_target: Option<String>,
    json: bool,
) -> ExitCode {
    let os = match detect_os_target(os_target.as_deref()) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Build the set of known catalog permission ids a mapping is validated
    // against. A catalog read failure is a hard error (we cannot tell orphaned
    // from valid without it).
    let catalog = LiveCatalog::new(catalog_roots);
    let known: std::collections::BTreeSet<String> = match catalog.all_definitions(&os) {
        Ok(defs) => defs.into_iter().map(|(_, def)| def.id).collect(),
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Load the framework tree directly (not via load_frameworks_for_cli) so the
    // determinism IdCollision error can be turned into a reported Error finding
    // rather than a bare process failure.
    let findings = match framework::load_frameworks(&framework_roots, &os) {
        Ok(loaded) => {
            for w in &loaded.warnings {
                eprintln!("census: warning: {w}");
            }
            let mut findings = framework::lint_loaded(&loaded, &known);
            // Control-title drift: a control present in a framework's structural
            // controls.toml but with no title in ANY locale would render as the
            // bare control id in reports with nothing to flag it. The structural
            // facts (controls.toml) and the titles (l10n/<locale>/controls.toml)
            // are edited independently, so this gap is exactly what the split
            // risks. This is an I/O step (it reads each framework's l10n tree), so
            // it lives here in the CLI wrapper rather than in the pure
            // `lint_loaded` — mirroring how the catalog/framework reads are done
            // here too. The permission layer flags the same drift; this is its
            // framework-layer mirror.
            findings.extend(control_missing_title_findings(&loaded));
            findings
        }
        Err(framework::FrameworkError::IdCollision { id }) => {
            // The one determinism Error the lint surface REPORTS (not aborts on):
            // a duplicate framework id across roots makes the loaded set depend on
            // read order. Surface it as an Error finding and render normally.
            vec![framework::FrameworkLint {
                code: "id-collision",
                severity: framework::FrameworkLintSeverity::Error,
                message: format!("framework id {id} declared in two roots (determinism)"),
            }]
        }
        Err(e) => {
            // A malformed/unreadable framework file is a hard error, not a lint
            // finding — fail closed.
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };

    if json {
        print!("{}", render_framework_lint_json(&findings));
    } else {
        print!("{}", render_framework_lint_human(&findings));
    }

    if findings
        .iter()
        .any(|f| f.severity == framework::FrameworkLintSeverity::Error)
    {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Build the `control-missing-title` findings: for every loaded framework, the
/// control ids defined in its structural `controls.toml` that resolve to NO title
/// in any locale. This is the I/O half of the framework lint — it walks each
/// framework's own l10n tree (`<fw_dir>/l10n/<locale>/controls.toml`), so it stays
/// in the CLI wrapper rather than the pure [`framework::lint_loaded`].
///
/// For each framework a [`crate::l10n::LiveL10n`] is rooted at the framework's own
/// directory (captured in [`framework::LoadedFrameworks::framework_dirs`]),
/// matching how [`framework::resolve_control_title`] resolves a single title. The
/// linted locale set is every locale materially present in that framework's tree
/// (`available_locales`) plus `en` (the fallback every starter set ships), so a
/// framework that ships only `ru` is still checked against `en`. The pure
/// [`framework::controls_missing_title`] then reports the ids with no title in any
/// of those locales. Findings are advisory WARNINGs — a missing title degrades
/// gracefully to the bare id and must never gate.
pub(crate) fn control_missing_title_findings(
    loaded: &framework::LoadedFrameworks,
) -> Vec<framework::FrameworkLint> {
    let mut out = Vec::new();
    // BTreeMap iteration is sorted → deterministic finding order across frameworks.
    for (fw, defs) in &loaded.controls {
        if defs.is_empty() {
            continue;
        }
        let Some(dir) = loaded.framework_dirs.get(fw) else {
            // No directory recorded means no l10n tree to read; nothing to check.
            continue;
        };
        let l10n = l10n::LiveL10n::new(vec![dir.clone()]);

        // Locales present in this framework's tree, plus `en` as the guaranteed
        // fallback (so a tree shipping only `ru` is still measured against `en`).
        let mut locales: Vec<String> = vec![l10n::DEFAULT_LOCALE.to_owned()];
        for loc in l10n.available_locales() {
            if !locales.iter().any(|l| l == &loc) {
                locales.push(loc);
            }
        }
        let locale_refs: Vec<&str> = locales.iter().map(String::as_str).collect();

        let ids: Vec<&str> = defs.keys().map(String::as_str).collect();
        for id in framework::controls_missing_title(&ids, &l10n, &locale_refs) {
            out.push(framework::FrameworkLint {
                code: "control-missing-title",
                severity: framework::FrameworkLintSeverity::Warning,
                message: format!(
                    "framework {fw} control {id:?} has no title in any locale (renders as the bare id); \
                     add it to {fw}/l10n/<locale>/controls.toml"
                ),
            });
        }
    }
    out
}

/// Render framework lint findings (human form): one line per finding as
/// `{TAG} [{code}] {message}` (TAG is `ERROR`/`WARNING`), or a single
/// "no findings" line when empty. Pure / unit-testable.
pub fn render_framework_lint_human(findings: &[framework::FrameworkLint]) -> String {
    if findings.is_empty() {
        return "framework lint: no findings\n".to_owned();
    }
    let mut out = String::new();
    for f in findings {
        let tag = match f.severity {
            framework::FrameworkLintSeverity::Warning => "WARNING",
            framework::FrameworkLintSeverity::Error => "ERROR",
        };
        out.push_str(&format!("{} [{}] {}\n", tag, f.code, f.message));
    }
    out
}

/// Render framework lint findings as JSON. Hand-rolled for exact-byte output
/// stability (golden-locked layout); not delegated to `serde_json`:
/// `{"findings":[{"code":..,"severity":"warning"|"error","message":..}, ...]}`.
/// Pure / unit-testable.
pub fn render_framework_lint_json(findings: &[framework::FrameworkLint]) -> String {
    let mut out = String::new();
    out.push_str("{\"findings\":[");
    let items: Vec<String> = findings
        .iter()
        .map(|f| {
            let severity = match f.severity {
                framework::FrameworkLintSeverity::Warning => "warning",
                framework::FrameworkLintSeverity::Error => "error",
            };
            format!(
                "{{\"code\":{},\"severity\":{},\"message\":{}}}",
                json_str(f.code),
                json_str(severity),
                json_str(&f.message),
            )
        })
        .collect();
    out.push_str(&items.join(","));
    out.push_str("]}");
    out.push('\n');
    out
}

/// The set of control ids covered by at least one **satisfies** mapping in
/// framework `fw`: the controls any mapping addresses (satisfies-polarity).
/// Empty when the framework has no satisfies mappings (or is absent).
fn covered_controls(loaded: &LoadedFrameworks, fw: &str) -> Vec<String> {
    loaded.satisfied_controls(fw)
}

/// Run `census framework show <fw>`: list the framework's controls (id, title,
/// owned, domain) plus coverage statistics (owned total / covered / uncovered).
/// A framework id that is not installed is an error (FAILURE). Read-only.
pub fn run_framework_show(
    fw: &str,
    framework_roots: Vec<PathBuf>,
    os_target: Option<String>,
    lang: Option<String>,
    json: bool,
) -> ExitCode {
    let loaded = match load_frameworks_for_cli(&framework_roots, os_target) {
        Ok(l) => l,
        Err(code) => return code,
    };
    if !loaded.frameworks.contains_key(fw) {
        eprintln!("census: framework {fw} not installed");
        return ExitCode::FAILURE;
    }
    let locale = display_locale(lang.as_deref());
    if json {
        print!("{}", render_framework_show_json(fw, &loaded, &locale));
    } else {
        print!("{}", render_framework_show_human(fw, &loaded, &locale));
    }
    ExitCode::SUCCESS
}

/// Coverage statistics for one framework: how many *owned* controls there are and
/// how many of them are covered by a mapping (vs left as a gap).
struct OwnedCoverageStats {
    owned_total: usize,
    owned_covered: usize,
    owned_uncovered: usize,
}

/// Compute owned-control coverage stats for framework `fw`: of the controls
/// flagged `owned = true`, how many appear in at least one mapping (covered) and
/// how many do not (the gap). Out-of-domain (`owned = false`) controls are not
/// counted here — they are surfaced separately by the coverage report.
fn owned_coverage_stats(loaded: &LoadedFrameworks, fw: &str) -> OwnedCoverageStats {
    let covered = covered_controls(loaded, fw);
    let defs = loaded.controls.get(fw);
    let owned_ids: Vec<&String> = defs
        .map(|d| {
            d.iter()
                .filter(|(_, c)| c.owned)
                .map(|(id, _)| id)
                .collect()
        })
        .unwrap_or_default();
    let owned_total = owned_ids.len();
    let owned_covered = owned_ids
        .iter()
        .filter(|id| covered.iter().any(|c| &c == *id))
        .count();
    OwnedCoverageStats {
        owned_total,
        owned_covered,
        owned_uncovered: owned_total - owned_covered,
    }
}

/// Render `framework show` (human form): the version stamp, every control
/// definition (id, owned flag, optional domain, title), and the owned-coverage
/// statistics line. Control titles are resolved from the framework l10n tree for
/// `locale` (fallback `locale → en → id`), since the structural [`ControlDef`]
/// carries no title. Pure / unit-testable.
///
/// [`ControlDef`]: framework::ControlDef
pub fn render_framework_show_human(fw: &str, loaded: &LoadedFrameworks, locale: &str) -> String {
    let mut out = String::new();
    // Caller guarantees the framework is loaded; fall back gracefully regardless.
    let version = loaded
        .frameworks
        .get(fw)
        .map(|m| m.version.as_str())
        .unwrap_or("?");
    out.push_str(&format!("framework {fw} ({version})\n"));
    let covered = covered_controls(loaded, fw);
    out.push_str("controls:\n");
    match loaded.controls.get(fw) {
        Some(defs) if !defs.is_empty() => {
            for (id, def) in defs {
                let owned = if def.owned { "owned" } else { "inherited" };
                let domain = def
                    .domain
                    .as_deref()
                    .map(|d| format!(" {{{d}}}"))
                    .unwrap_or_default();
                let cov = if covered.iter().any(|c| c == id) {
                    "covered"
                } else {
                    "uncovered"
                };
                let title = resolve_control_title(loaded, fw, id, locale);
                out.push_str(&format!("  {id} [{owned}] [{cov}]{domain} — {title}\n"));
            }
        }
        _ => out.push_str("  (no control definitions)\n"),
    }
    let stats = owned_coverage_stats(loaded, fw);
    out.push_str(&format!(
        "coverage: {}/{} owned controls covered ({} uncovered)\n",
        stats.owned_covered, stats.owned_total, stats.owned_uncovered,
    ));
    out
}

/// Render `framework show` as JSON (hand-rolled). Includes the id+version stamp,
/// a `controls` array (id/title/owned/domain/covered) and a `coverage` object
/// with owned totals. The `title` is resolved from the framework l10n tree for
/// `locale` (fallback `locale → en → id`). Pure / unit-testable.
pub fn render_framework_show_json(fw: &str, loaded: &LoadedFrameworks, locale: &str) -> String {
    let version = loaded
        .frameworks
        .get(fw)
        .map(|m| json_str(&m.version))
        .unwrap_or_else(|| "null".to_owned());
    let covered = covered_controls(loaded, fw);
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!("\"id\":{},\"version\":{},", json_str(fw), version));
    out.push_str("\"controls\":[");
    let controls: Vec<String> = loaded
        .controls
        .get(fw)
        .map(|defs| {
            defs.iter()
                .map(|(id, def)| {
                    let title = resolve_control_title(loaded, fw, id, locale);
                    format!(
                        "{{\"id\":{},\"title\":{},\"owned\":{},\"domain\":{},\"covered\":{}}}",
                        json_str(id),
                        json_str(&title),
                        def.owned,
                        def.domain
                            .as_deref()
                            .map(json_str)
                            .unwrap_or_else(|| "null".to_owned()),
                        covered.iter().any(|c| c == id),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    out.push_str(&controls.join(","));
    out.push_str("],");
    let stats = owned_coverage_stats(loaded, fw);
    out.push_str(&format!(
        "\"coverage\":{{\"owned_total\":{},\"owned_covered\":{},\"owned_uncovered\":{}}}}}",
        stats.owned_total, stats.owned_covered, stats.owned_uncovered,
    ));
    out.push('\n');
    out
}

/// The computed coverage gap for a framework: which owned controls are covered by
/// a mapping, which owned controls are a gap (uncovered), and which controls are
/// out-of-domain (`owned = false`, surfaced separately and never counted as a
/// gap). All vectors are sorted (BTreeMap-derived) for deterministic output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkCoverage {
    /// Owned controls that appear in at least one mapping.
    pub covered: Vec<String>,
    /// Owned controls with no mapping — the gap a reviewer must close.
    pub gap: Vec<String>,
    /// Controls flagged `owned = false`: inherited / out of the org's scope.
    /// Listed for visibility, never counted in the gap.
    pub out_of_domain: Vec<String>,
}

/// Compute the coverage gap for framework `fw`.
///
///   * `covered` = owned controls present in some mapping (`reverse[fw]` keys).
///   * `gap`     = owned controls MINUS covered.
///   * `out_of_domain` = controls with `owned = false` (surfaced separately).
///
/// Coverage is judged only over controls that have a `controls.toml` definition
/// (the org's declared scope). A control referenced by a mapping but never
/// defined contributes nothing here (it cannot be "owned"); it simply is not in
/// the owned/gap/out-of-domain partition. Pure / unit-testable.
pub fn compute_framework_coverage(loaded: &LoadedFrameworks, fw: &str) -> FrameworkCoverage {
    let covered_set = covered_controls(loaded, fw);
    let mut covered = Vec::new();
    let mut gap = Vec::new();
    let mut out_of_domain = Vec::new();
    if let Some(defs) = loaded.controls.get(fw) {
        // BTreeMap iteration is sorted → deterministic output.
        for (id, def) in defs {
            if !def.owned {
                out_of_domain.push(id.clone());
            } else if covered_set.iter().any(|c| c == id) {
                covered.push(id.clone());
            } else {
                gap.push(id.clone());
            }
        }
    }
    FrameworkCoverage {
        covered,
        gap,
        out_of_domain,
    }
}

/// Run `census framework coverage <fw>`: the gap oracle. Reports the framework's
/// owned controls that no mapping covers (plus the covered and out-of-domain
/// sets). A framework id that is not installed is an error (FAILURE). Read-only.
pub fn run_framework_coverage(
    fw: &str,
    framework_roots: Vec<PathBuf>,
    os_target: Option<String>,
    json: bool,
) -> ExitCode {
    let loaded = match load_frameworks_for_cli(&framework_roots, os_target) {
        Ok(l) => l,
        Err(code) => return code,
    };
    if !loaded.frameworks.contains_key(fw) {
        eprintln!("census: framework {fw} not installed");
        return ExitCode::FAILURE;
    }
    let coverage = compute_framework_coverage(&loaded, fw);
    if json {
        print!("{}", render_framework_coverage_json(fw, &loaded, &coverage));
    } else {
        print!(
            "{}",
            render_framework_coverage_human(fw, &loaded, &coverage)
        );
    }
    ExitCode::SUCCESS
}

/// Render `framework coverage` (human form): the version stamp, the gap list
/// (owned-uncovered controls — the actionable output), the covered list, and the
/// out-of-domain list. Pure / unit-testable.
pub fn render_framework_coverage_human(
    fw: &str,
    loaded: &LoadedFrameworks,
    coverage: &FrameworkCoverage,
) -> String {
    let version = loaded
        .frameworks
        .get(fw)
        .map(|m| m.version.as_str())
        .unwrap_or("?");
    let mut out = String::new();
    out.push_str(&format!("framework {fw} ({version})\n"));
    out.push_str(&format!(
        "gap: {} owned control(s) with no mapping\n",
        coverage.gap.len()
    ));
    if coverage.gap.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for id in &coverage.gap {
            out.push_str(&format!("  {id}\n"));
        }
    }
    out.push_str(&format!("covered: {}\n", coverage.covered.len()));
    for id in &coverage.covered {
        out.push_str(&format!("  {id}\n"));
    }
    out.push_str(&format!(
        "out-of-domain (not counted): {}\n",
        coverage.out_of_domain.len()
    ));
    for id in &coverage.out_of_domain {
        out.push_str(&format!("  {id}\n"));
    }
    out
}

/// Render `framework coverage` as JSON (hand-rolled). Includes the id+version
/// stamp plus `covered`, `gap`/`uncovered`, and `out_of_domain` arrays. Pure /
/// unit-testable.
pub fn render_framework_coverage_json(
    fw: &str,
    loaded: &LoadedFrameworks,
    coverage: &FrameworkCoverage,
) -> String {
    let version = loaded
        .frameworks
        .get(fw)
        .map(|m| json_str(&m.version))
        .unwrap_or_else(|| "null".to_owned());
    let arr =
        |v: &[String]| -> String { v.iter().map(|s| json_str(s)).collect::<Vec<_>>().join(",") };
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!("\"id\":{},\"version\":{},", json_str(fw), version));
    out.push_str(&format!("\"covered\":[{}],", arr(&coverage.covered)));
    // `gap` and `uncovered` are the same set (the actionable owned-uncovered
    // controls); both keys are emitted so either consumer name works.
    out.push_str(&format!("\"gap\":[{}],", arr(&coverage.gap)));
    out.push_str(&format!("\"uncovered\":[{}],", arr(&coverage.gap)));
    out.push_str(&format!(
        "\"out_of_domain\":[{}]",
        arr(&coverage.out_of_domain)
    ));
    out.push('}');
    out.push('\n');
    out
}

/// The controls under risk in a framework: each control with at least one `risk`
/// link, and the permission ids that threaten it. NOT filtered by `owned` — a
/// threat to an out-of-domain control is still significant (Census does not cover
/// it, but the capability can still undermine it). Sorted by control id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkRisk {
    /// `(control-id, [threatening permission ids])` pairs, sorted by control id.
    pub controls: Vec<(String, Vec<String>)>,
}

/// Compute the risk view for framework `fw`: every control with a `risk`-polarity
/// link and the permissions that threaten it, regardless of `owned`. Pure /
/// unit-testable.
pub fn compute_framework_risk(loaded: &LoadedFrameworks, fw: &str) -> FrameworkRisk {
    FrameworkRisk {
        controls: loaded.risk_controls(fw),
    }
}

/// Run `census framework risk <fw>`: list controls under threat (≥1 risk link)
/// and the permissions that undermine them. A framework id not installed is an
/// error (FAILURE). Read-only.
pub fn run_framework_risk(
    fw: &str,
    framework_roots: Vec<PathBuf>,
    os_target: Option<String>,
    lang: Option<String>,
    json: bool,
) -> ExitCode {
    let loaded = match load_frameworks_for_cli(&framework_roots, os_target) {
        Ok(l) => l,
        Err(code) => return code,
    };
    if !loaded.frameworks.contains_key(fw) {
        eprintln!("census: framework {fw} not installed");
        return ExitCode::FAILURE;
    }
    let risk = compute_framework_risk(&loaded, fw);
    let locale = display_locale(lang.as_deref());
    if json {
        print!("{}", render_framework_risk_json(fw, &loaded, &risk));
    } else {
        print!(
            "{}",
            render_framework_risk_human(fw, &loaded, &risk, &locale)
        );
    }
    ExitCode::SUCCESS
}

/// Render `framework risk` (human form): the version stamp, then each control
/// under threat with its title (resolved from the framework l10n tree for
/// `locale`, fallback `locale → en → id`), an out-of-domain marker when the
/// control is `owned = false`, and the threatening permissions. Pure.
pub fn render_framework_risk_human(
    fw: &str,
    loaded: &LoadedFrameworks,
    risk: &FrameworkRisk,
    locale: &str,
) -> String {
    let version = loaded
        .frameworks
        .get(fw)
        .map(|m| m.version.as_str())
        .unwrap_or("?");
    let defs = loaded.controls.get(fw);
    let mut out = String::new();
    out.push_str(&format!("framework {fw} ({version})\n"));
    out.push_str(&format!("controls under risk: {}\n", risk.controls.len()));
    if risk.controls.is_empty() {
        out.push_str("  (none)\n");
        return out;
    }
    for (ctrl, perms) in &risk.controls {
        let def = defs.and_then(|d| d.get(ctrl));
        let domain = match def {
            Some(d) if !d.owned => " [out-of-domain]",
            _ => "",
        };
        // Title from the framework l10n tree, but only for a defined control (an
        // undefined control has no declared scope to name — keep the bare id).
        let title = if def.is_some() {
            format!(" — {}", resolve_control_title(loaded, fw, ctrl, locale))
        } else {
            String::new()
        };
        out.push_str(&format!("  ⚠ {ctrl}{domain}{title}\n"));
        out.push_str(&format!("    threatened by: {}\n", perms.join(", ")));
    }
    out
}

/// Render `framework risk` as JSON (hand-rolled). Carries the id+version stamp and
/// a `controls` array of `{id, owned, threatened_by:[perm...]}`. `owned` is null
/// when the control has no controls.toml definition. Pure.
pub fn render_framework_risk_json(
    fw: &str,
    loaded: &LoadedFrameworks,
    risk: &FrameworkRisk,
) -> String {
    let version = loaded
        .frameworks
        .get(fw)
        .map(|m| json_str(&m.version))
        .unwrap_or_else(|| "null".to_owned());
    let defs = loaded.controls.get(fw);
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!("\"id\":{},\"version\":{},", json_str(fw), version));
    out.push_str("\"controls\":[");
    let items: Vec<String> = risk
        .controls
        .iter()
        .map(|(ctrl, perms)| {
            let owned = defs
                .and_then(|d| d.get(ctrl))
                .map(|d| d.owned.to_string())
                .unwrap_or_else(|| "null".to_owned());
            let by: Vec<String> = perms.iter().map(|p| json_str(p)).collect();
            format!(
                "{{\"id\":{},\"owned\":{},\"threatened_by\":[{}]}}",
                json_str(ctrl),
                owned,
                by.join(","),
            )
        })
        .collect();
    out.push_str(&items.join(","));
    out.push_str("]}");
    out.push('\n');
    out
}
