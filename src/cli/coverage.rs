//! `census catalog coverage` and `census catalog which-grants` — read-only audit
//! and reverse lookup over the device's privileged surface.
//!
//! `coverage` enumerates the device's live privileged surface (`LiveSurface`) and
//! reports what the installed catalog does NOT cover. `which-grants` is the
//! inverse: given a path or command, report which catalog permissions grant
//! access to it and how. Both are strictly read-only: they never run the
//! enumerated binaries, never read file content, and never mutate. The pure
//! coverage core (`crate::coverage`) does the matching; this CLI layer only builds
//! inputs, renders the report, and decides the `--min-coverage` exit.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::catalog::{self, CatalogError, OsTarget, ResolveCtx};
use crate::cli::read_declaration;
use crate::cli::render::{access_token, json_str, risk_label};
use crate::coverage::{
    self, CoverageCtx, CoverageReport, LiveSurface, ResolvedRole, SurfaceClass, SurfaceScanner,
};
use crate::declaration::Declaration;
use crate::model::{self, CompileInputs};
use crate::{rolestore, LiveCatalog};

/// Options for `census catalog coverage` (CLI-derived).
#[derive(Debug)]
pub struct CoverageOpts {
    /// Emit machine-readable JSON instead of the human view.
    pub json: bool,
    /// `--os-target family-distro-version` override; autodetects when `None`.
    pub os_target: Option<String>,
    /// Catalog roots in precedence order (lowest first).
    pub catalog_roots: Vec<PathBuf>,
    /// Optional role-store dir whose roles are resolved into concrete instances
    /// (so parametrized permissions contribute named units/paths).
    pub roles: Option<PathBuf>,
    /// Optional declaration whose `[[role_group]]` bindings are resolved so a
    /// `group` object with a bound grant is counted covered. `None` means no
    /// binding-covered groups are folded in (membership coverage only).
    pub declaration: Option<PathBuf>,
    /// `--strict`: a parametrized record without a role instance does NOT cover.
    pub strict: bool,
    /// Surface classes to scan; empty means all classes.
    pub classes: Vec<SurfaceClass>,
    /// `--min-coverage <pct>`: non-zero exit when overall coverage is below this.
    pub min_coverage: Option<f64>,
    /// `--include-low-priority`: include low-priority objects in the human report
    /// (currently a presentation toggle; the metric is unaffected).
    pub include_low_priority: bool,
    /// `--cache`: accepted for forward-compat; caching is not yet implemented, so
    /// the flag is a no-op (a fresh scan runs every time).
    pub cache: bool,
}

/// Parse a `--class a,b,c` value into surface classes. An unknown token is an
/// error (fail closed rather than silently scanning fewer classes than asked).
pub fn parse_classes(spec: &str) -> Result<Vec<SurfaceClass>, String> {
    let mut out: Vec<SurfaceClass> = Vec::new();
    for tok in spec.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        let class = match tok {
            "sudo_bin" => SurfaceClass::SudoBin,
            "config" => SurfaceClass::Config,
            "unit" => SurfaceClass::Unit,
            "group" => SurfaceClass::Group,
            "capfile" => SurfaceClass::CapFile,
            "setuid" => SurfaceClass::Setuid,
            other => return Err(format!("unknown surface class '{other}'")),
        };
        if !out.contains(&class) {
            out.push(class);
        }
    }
    // A non-empty spec that yields zero classes (e.g. `--class ""` or
    // `--class ","`) must not silently fall through to "all classes" in the
    // caller — that widens the audit, the opposite of the operator's intent.
    // An all-whitespace/empty spec is a usage error, fail closed.
    if out.is_empty() {
        return Err(format!("no surface classes in --class '{spec}'"));
    }
    Ok(out)
}

/// The full set of surface classes, used when `--class` is not given.
fn all_classes() -> Vec<SurfaceClass> {
    vec![
        SurfaceClass::SudoBin,
        SurfaceClass::Config,
        SurfaceClass::Unit,
        SurfaceClass::Group,
        SurfaceClass::CapFile,
        SurfaceClass::Setuid,
    ]
}

/// Resolve every role slice under `roles_dir` into a `ResolvedRole` (concrete
/// expanded sudo + groups). Each role's permissions are expanded with their
/// declared params via `resolve_with_params`, so a parametrized record
/// (`service-restart units=[…]`) contributes concrete commands. A role that fails
/// to resolve is surfaced as a warning and skipped — a coverage audit should still
/// run over the roles that DO resolve rather than abort on one bad slice.
///
/// `catalog_roots` MUST be the same roots the main coverage pass uses (including
/// any `--catalog-dir` site overrides). A role may reference a permission defined
/// only in a site catalog; resolving roles against the bare defaults would fail
/// to expand it and under-contribute coverage.
pub(crate) fn resolve_roles(
    roles_dir: &Path,
    catalog_roots: &[PathBuf],
    os: &OsTarget,
    ctx: &ResolveCtx,
) -> Vec<ResolvedRole> {
    let catalog = LiveCatalog::new(catalog_roots.to_vec());
    let mut out: Vec<ResolvedRole> = Vec::new();
    let entries = match std::fs::read_dir(roles_dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!(
                "census: warning: cannot read roles dir {}: {e}",
                roles_dir.display()
            );
            return out;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let role = match path.file_stem().and_then(|s| s.to_str()) {
            Some(r) => r,
            None => continue,
        };
        let comp = match rolestore::read_composition(roles_dir, role) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("census: warning: role {role}: {e}");
                continue;
            }
        };
        // A raw sudo_role names a sudoers alias, not a concrete binary, so it
        // contributes no command token and is intentionally not folded in; raw
        // groups DO gate-keep, so they seed the role's covered groups.
        let mut sudo: Vec<String> = Vec::new();
        let mut groups: Vec<String> = comp.groups.clone();
        let mut file_grants: Vec<catalog::ResolvedFileGrant> = Vec::new();
        for perm in &comp.permissions {
            match catalog::resolve_with_params(&perm.id, &perm.params, os, &catalog, ctx) {
                Ok((resolved, _warnings)) => {
                    for p in &resolved.sudo {
                        sudo.push(p.value.clone());
                    }
                    for p in &resolved.groups {
                        groups.push(p.value.clone());
                    }
                    // A parametrized config-edit grant only becomes a concrete path
                    // once a role supplies its parameter; fold the role-instance's
                    // resolved grants in so a config object under such a grant is
                    // counted covered (with the backend note) in the audit.
                    file_grants.extend(resolved.file_grants);
                }
                Err(e) => {
                    eprintln!("census: warning: role {role} permission {}: {e}", perm.id);
                }
            }
        }
        out.push(ResolvedRole::with_file_grants(sudo, groups, file_grants));
    }
    out
}

/// Map overall coverage and an optional `--min-coverage` threshold to an exit
/// code. Without a threshold the audit is read-only and always succeeds (0). With
/// a threshold, coverage below it exits 4 (a distinct CI-gate failure, separate
/// from a scan/catalog error which exits `FAILURE`==1). Pure so the policy is
/// unit-testable.
pub(crate) fn coverage_exit_code(overall_pct: f64, min: Option<f64>) -> ExitCode {
    match min {
        Some(threshold) if overall_pct < threshold => ExitCode::from(4),
        _ => ExitCode::SUCCESS,
    }
}

/// Render a coverage report as a human-readable audit. Pure (report in, string
/// out) so the output shape is unit-testable from a hand-built report.
pub fn render_coverage_human(report: &CoverageReport, include_low_priority: bool) -> String {
    // `include_low_priority` is applied upstream in `coverage_scoped` (it changes
    // which config objects are in the report at all); here it only annotates the
    // header so the reader knows which denominator they are looking at.
    let mut out = String::new();
    out.push_str(&format!(
        "coverage for {} (catalog {}){}\n",
        if report.os_target.is_empty() {
            "unknown"
        } else {
            &report.os_target
        },
        report.catalog_version.as_deref().unwrap_or("unknown"),
        if include_low_priority {
            " [incl. low-priority config]"
        } else {
            ""
        },
    ));

    // Per-class summary.
    out.push_str("by class:\n");
    for c in &report.by_class {
        out.push_str(&format!(
            "  {:<9} {}/{} ({:.1}%)\n",
            c.class.as_str(),
            c.covered,
            c.total,
            c.pct(),
        ));
    }
    out.push_str(&format!("overall: {:.1}%\n", report.overall_pct));

    // Covered objects that carry a HOW note (config via file grants): surface the
    // backend/guarantee so the operator can see which grant enforces each config.
    let noted: Vec<_> = report
        .objects
        .iter()
        .filter(|o| o.covered && o.coverage_note.is_some())
        .collect();
    if !noted.is_empty() {
        out.push_str("covered via file grants:\n");
        for o in &noted {
            out.push_str(&format!(
                "  [{}] {} — {}\n",
                o.object.class.as_str(),
                o.object.key,
                o.coverage_note.as_deref().unwrap_or(""),
            ));
        }
    }

    // Uncovered objects (honest gaps) grouped by class, with a suggestion.
    let gaps: Vec<_> = report
        .objects
        .iter()
        .filter(|o| !o.covered && o.intentional_exclusion.is_none() && o.backend_limited.is_none())
        .collect();
    out.push_str("uncovered:\n");
    if gaps.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for o in &gaps {
            let suggestion = o
                .suggested_permission
                .as_deref()
                .map(|s| format!(" → suggested: {s}"))
                .unwrap_or_default();
            out.push_str(&format!(
                "  [{}] {}{}\n",
                o.object.class.as_str(),
                o.object.key,
                suggestion,
            ));
        }
    }

    // Intentionally-uncovered, each with its reason (does not penalise the metric).
    let intentional: Vec<_> = report
        .objects
        .iter()
        .filter(|o| o.intentional_exclusion.is_some())
        .collect();
    if !intentional.is_empty() {
        out.push_str("intentionally uncovered:\n");
        for o in &intentional {
            out.push_str(&format!(
                "  [{}] {} — {}\n",
                o.object.class.as_str(),
                o.object.key,
                o.intentional_exclusion.as_deref().unwrap_or(""),
            ));
        }
    }

    // Backend-limited: objects the free dir-only backend cannot enforce without an
    // over-broad grant (a single file in a non-grantable parent). Reported in their
    // own section so they are visible but clearly NOT counted as gaps — distinct
    // from "intentionally uncovered" (out of scope) and from a real gap (fixable
    // with a grant). A per-file-capable backend would cover these.
    let backend_limited: Vec<_> = report
        .objects
        .iter()
        .filter(|o| o.backend_limited.is_some())
        .collect();
    if !backend_limited.is_empty() {
        out.push_str("backend-limited (requires per-file backend):\n");
        for o in &backend_limited {
            out.push_str(&format!(
                "  [{}] {} — {}\n",
                o.object.class.as_str(),
                o.object.key,
                o.backend_limited.as_deref().unwrap_or(""),
            ));
        }
    }

    // Anomalies (orphan setuid / orphan capfile) — investigate, separate from gaps.
    if !report.anomalies.is_empty() {
        out.push_str("anomalies (investigate):\n");
        for a in &report.anomalies {
            out.push_str(&format!(
                "  [{}] {} ({})\n",
                a.class.as_str(),
                a.key,
                a.detail
            ));
        }
    }

    out
}

/// Provenance as a stable lowercase token for JSON output.
fn provenance_json(p: &coverage::Provenance) -> String {
    match p {
        coverage::Provenance::Vendor => json_str("vendor"),
        coverage::Provenance::Addon(pkg) => json_str(&format!("addon:{pkg}")),
        coverage::Provenance::Orphan => json_str("orphan"),
    }
}

/// Render a coverage report as machine-readable JSON: an `objects` array of
/// per-object verdicts plus a `summary` object. Hand-rolled over the `json_str`
/// escaper for exact-byte output stability (golden-locked layout), matching the
/// `compile --json` style; not delegated to `serde_json`. Pure.
pub fn render_coverage_json(report: &CoverageReport) -> String {
    let mut out = String::new();
    out.push('{');

    out.push_str("\"objects\":[");
    let objs: Vec<String> = report
        .objects
        .iter()
        .map(|o| {
            format!(
                "{{\"class\":{},\"key\":{},\"covered\":{},\"provenance\":{},\"suggested_permission\":{},\"intentional_exclusion\":{},\"backend_limited\":{},\"coverage_note\":{}}}",
                json_str(o.object.class.as_str()),
                json_str(&o.object.key),
                o.covered,
                provenance_json(&o.object.provenance),
                o.suggested_permission.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
                o.intentional_exclusion.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
                o.backend_limited.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
                o.coverage_note.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
            )
        })
        .collect();
    out.push_str(&objs.join(","));
    out.push_str("],");

    // Anomalies array (orphan setuid/capfile) for the machine consumer.
    out.push_str("\"anomalies\":[");
    let anoms: Vec<String> = report
        .anomalies
        .iter()
        .map(|a| {
            format!(
                "{{\"class\":{},\"key\":{},\"provenance\":{}}}",
                json_str(a.class.as_str()),
                json_str(&a.key),
                provenance_json(&a.provenance),
            )
        })
        .collect();
    out.push_str(&anoms.join(","));
    out.push_str("],");

    // Summary: per-class counts, overall, catalog version, os target.
    out.push_str("\"summary\":{\"by_class\":[");
    let by: Vec<String> = report
        .by_class
        .iter()
        .map(|c| {
            format!(
                "{{\"class\":{},\"covered\":{},\"total\":{},\"pct\":{:.1}}}",
                json_str(c.class.as_str()),
                c.covered,
                c.total,
                c.pct(),
            )
        })
        .collect();
    out.push_str(&by.join(","));
    let warnings: Vec<String> = report
        .catalog_warnings
        .iter()
        .map(|w| json_str(w))
        .collect();
    out.push_str(&format!(
        "],\"overall_pct\":{:.1},\"catalog_version\":{},\"os_target\":{},\"catalog_warnings\":[{}]}}",
        report.overall_pct,
        report.catalog_version.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
        json_str(&report.os_target),
        warnings.join(","),
    ));

    out.push('}');
    out.push('\n');
    out
}

/// Run `census catalog coverage`: enumerate the live privileged surface, compute
/// coverage against the installed catalog (+ optional roles), print the report
/// (human or JSON), and exit per `--min-coverage`. Read-only — never mutates.
pub fn run_coverage(opts: CoverageOpts) -> ExitCode {
    let os = match crate::cli::detect_os_target(opts.os_target.as_deref()) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let catalog = LiveCatalog::new(opts.catalog_roots.clone());

    // Catalog version is echoed into the report for the audit trail. We do not have
    // a separate version source here, so it is left unset unless the catalog
    // carries one through resolve (the report records what resolve saw).
    let ctx = ResolveCtx {
        catalog_version: None,
    };

    let roles = match &opts.roles {
        Some(dir) => resolve_roles(dir, &opts.catalog_roots, &os, &ctx),
        None => Vec::new(),
    };

    // With a declaration, resolve its `[[role_group]]` bindings and collect the
    // names of groups that carry a grant (non-empty sudo and/or file). A `group`
    // surface object for such a group is covered by the binding even when no
    // membership primitive names it. Without a declaration this stays empty
    // (membership coverage only — the original behavior).
    let bound_grant_groups = match &opts.declaration {
        Some(decl_path) => {
            let decl = match read_declaration(decl_path) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("census: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let inputs = CompileInputs {
                catalog: &catalog,
                os: &os,
                ctx: &ctx,
            };
            match model::resolve_groups(&decl, &inputs) {
                Ok((groups, _warnings)) => groups
                    .into_iter()
                    .filter(|g| !g.sudo_commands.is_empty() || !g.file_grants.is_empty())
                    .map(|g| g.name)
                    .collect(),
                Err(e) => {
                    eprintln!("census: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        None => Vec::new(),
    };

    let classes = if opts.classes.is_empty() {
        all_classes()
    } else {
        opts.classes.clone()
    };

    let surface = match LiveSurface::system().scan(&classes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };

    let cov_ctx = CoverageCtx {
        strict: opts.strict,
        catalog_version: ctx.catalog_version.clone(),
        bound_grant_groups,
    };
    let report = match coverage::coverage_scoped(
        &surface,
        &catalog,
        &os,
        &roles,
        &cov_ctx,
        opts.include_low_priority,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };

    // A catalog id that failed to resolve was skipped rather than aborting the
    // audit; surface each as a stderr warning so the gap is visible while the
    // report (on stdout) still covers everything that DID resolve.
    for w in &report.catalog_warnings {
        eprintln!("census: warning: {w}");
    }

    if opts.json {
        print!("{}", render_coverage_json(&report));
    } else {
        print!(
            "{}",
            render_coverage_human(&report, opts.include_low_priority)
        );
    }

    coverage_exit_code(report.overall_pct, opts.min_coverage)
}

// ============================================================================
// catalog which-grants (reverse lookup; read-only query)
//
// Given a path or command, report which catalog permissions grant access to it
// and how. The inverse of coverage: coverage asks "what surface is uncovered?",
// which-grants asks "what grants THIS object?". Read-only — it resolves the
// catalog, never runs the binary or reads file content, and always exits 0 unless
// the catalog/OS itself cannot be read (even "no grants" is a successful query).
// ============================================================================

/// Options for `census catalog which-grants <arg>`.
#[derive(Debug)]
pub struct WhichGrantsOpts {
    /// The absolute path or command to look up.
    pub arg: String,
    /// Emit machine-readable JSON instead of the human view.
    pub json: bool,
    /// `--os-target family-distro-version` override; autodetects when `None`.
    pub os_target: Option<String>,
    /// Catalog roots in precedence order (lowest first).
    pub catalog_roots: Vec<PathBuf>,
    /// Optional declaration whose `[[role_group]]` bindings are resolved so group
    /// grants (`via %group sudoers` / `via g:group ACL`) appear in the lookup.
    /// `None` reports account grants only (the original behavior).
    pub declaration: Option<PathBuf>,
}

/// Build the reverse-lookup sources by resolving every catalog permission.
///
/// Each distinct id in `all_definitions` is resolved once; the concrete sudo
/// command strings and file grants become a [`coverage::GrantSource`]. A templated
/// sudo command (one still carrying a `{placeholder}` because no role instance
/// filled it) is SKIPPED — a reverse lookup is over concrete grants the catalog
/// would actually emit, and a literal `{unit}` is not a real command. Likewise a
/// templated file-grant path is skipped. An id that fails to resolve is skipped
/// with a stderr warning (mirroring the coverage audit's warn-and-skip), so one
/// bad record does not sink the whole query.
pub(crate) fn build_grant_sources(
    catalog: &dyn catalog::CatalogSource,
    os: &OsTarget,
    ctx: &ResolveCtx,
) -> Result<Vec<coverage::GrantSource>, CatalogError> {
    let all = catalog.all_definitions(os)?;
    let mut seen: Vec<String> = Vec::new();
    let mut out: Vec<coverage::GrantSource> = Vec::new();
    for (_layer, def) in &all {
        if seen.iter().any(|s| s == &def.id) {
            continue;
        }
        seen.push(def.id.clone());

        match catalog::resolve(&def.id, os, catalog, ctx) {
            Ok((resolved, _warnings)) => {
                // Keep only concrete (non-templated) sudo commands and file grants:
                // an unfilled `{placeholder}` is not a real grant to look up.
                let sudo: Vec<String> = resolved
                    .sudo
                    .iter()
                    .map(|p| p.value.clone())
                    .filter(|c| !has_unfilled_placeholder(c))
                    .collect();
                let file_grants: Vec<catalog::ResolvedFileGrant> = resolved
                    .file_grants
                    .iter()
                    .filter(|g| !has_unfilled_placeholder(&g.path))
                    .cloned()
                    .collect();
                if sudo.is_empty() && file_grants.is_empty() {
                    continue;
                }
                out.push(coverage::GrantSource {
                    id: resolved.id.clone(),
                    target: coverage::GrantTarget::Account(resolved.id),
                    risk: resolved.risk,
                    sudo,
                    file_grants,
                });
            }
            Err(e) => {
                eprintln!(
                    "census: warning: catalog permission {} unresolved: {e}",
                    def.id
                );
            }
        }
    }
    Ok(out)
}

/// Build reverse-lookup sources from a declaration's `[[role_group]]` bindings.
///
/// Each resolved group with non-empty sudo and/or file grants becomes a
/// [`coverage::GrantSource`] tagged `target = Group(name)`, so a sudo command or
/// path reached through the group's `%group` sudoers / `g:group` ACL is reported
/// as a group match. The matching core (sudo prefix / file under-dir) is reused
/// unchanged — only the source set is widened. Group sources carry no per-source
/// risk class (`ResolvedGroup` is an aggregate of several roles' grants, not one
/// catalog permission); file matches still surface their own backend, and the
/// group-escalation surface is flagged by the lint, not the reverse lookup.
///
/// Returns an empty vec when the declaration has no group bindings. A resolve
/// failure is propagated (the caller already warns-and-continues on a soft error
/// elsewhere; here a malformed declaration is a hard read error, consistent with
/// the other declaration-driven commands).
pub(crate) fn build_group_grant_sources(
    decl: &Declaration,
    inputs: &CompileInputs<'_, impl catalog::CatalogSource>,
) -> Result<Vec<coverage::GrantSource>, model::ResolveError> {
    let (groups, _warnings) = model::resolve_groups(decl, inputs)?;
    let mut out: Vec<coverage::GrantSource> = Vec::new();
    for g in groups {
        if g.sudo_commands.is_empty() && g.file_grants.is_empty() {
            continue;
        }
        out.push(coverage::GrantSource {
            id: g.name.clone(),
            target: coverage::GrantTarget::Group(g.name),
            risk: None,
            // The coverage reverse-lookup keys on the command text; the run-as
            // account does not change which command path is granted, so project
            // each `SudoCommand` down to its command string here.
            sudo: g.sudo_commands.into_iter().map(|c| c.command).collect(),
            file_grants: g.file_grants,
        });
    }
    Ok(out)
}

/// Whether a string still carries a `{placeholder}` (a templated value that no
/// role instance filled). Such a value is not a concrete grant, so the reverse
/// lookup skips it.
fn has_unfilled_placeholder(s: &str) -> bool {
    if let Some(open) = s.find('{') {
        s[open + 1..].contains('}')
    } else {
        false
    }
}

/// Render reverse-lookup matches as a human-readable report. Pure (matches in,
/// string out) so the output shape is unit-testable.
pub fn render_which_grants_human(arg: &str, matches: &[coverage::GrantMatch]) -> String {
    if matches.is_empty() {
        return format!("no permission grants access to {arg}\n");
    }
    let mut out = format!("{arg} granted by:\n");
    for m in matches {
        match m.kind {
            coverage::GrantKind::Sudo => {
                // Group target → `%group` sudoers (every member inherits); account
                // target → the per-account `sudo` mechanism (unchanged).
                let mechanism = match m.target.group() {
                    Some(g) => format!("via %group sudoers ({g})"),
                    None => "via sudo".to_owned(),
                };
                out.push_str(&format!(
                    "  {} — {}: {} [{}]\n",
                    m.permission,
                    mechanism,
                    m.detail,
                    risk_label(m.risk),
                ));
            }
            coverage::GrantKind::File => {
                let access = m.access.map(access_token).unwrap_or("");
                let recursive = if m.recursive == Some(true) {
                    ", recursive"
                } else {
                    ""
                };
                let backend = m.backend.as_deref().unwrap_or("");
                // Group target → `g:group` ACL; account target → the per-account
                // file mechanism (unchanged).
                let mechanism = match m.target.group() {
                    Some(g) => format!("via g:group ACL ({g})"),
                    None => "via file".to_owned(),
                };
                out.push_str(&format!(
                    "  {} — {} ({}): {}{} ({}) [{}]\n",
                    m.permission,
                    mechanism,
                    access,
                    m.detail,
                    recursive,
                    backend,
                    risk_label(m.risk),
                ));
            }
        }
    }
    out
}

/// Render reverse-lookup matches as machine-readable JSON: an array of match
/// objects. Hand-rolled over `json_str`, matching the coverage `--json` style.
/// Pure.
pub fn render_which_grants_json(matches: &[coverage::GrantMatch]) -> String {
    let mut out = String::new();
    out.push('[');
    let items: Vec<String> = matches
        .iter()
        .map(|m| {
            // `target` is `account` or `group`; `group` carries the inheriting
            // group name for a group match (null for an account match).
            let (target_kind, group) = match &m.target {
                coverage::GrantTarget::Account(_) => ("account", "null".to_owned()),
                coverage::GrantTarget::Group(g) => ("group", json_str(g)),
            };
            format!(
                "{{\"permission\":{},\"target\":{},\"group\":{},\"kind\":{},\"detail\":{},\"access\":{},\"recursive\":{},\"backend\":{},\"risk\":{}}}",
                json_str(&m.permission),
                json_str(target_kind),
                group,
                json_str(m.kind.as_str()),
                json_str(&m.detail),
                m.access.map(|a| json_str(access_token(a))).unwrap_or_else(|| "null".to_owned()),
                m.recursive.map(|r| r.to_string()).unwrap_or_else(|| "null".to_owned()),
                m.backend.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
                json_str(risk_label(m.risk)),
            )
        })
        .collect();
    out.push_str(&items.join(","));
    out.push(']');
    out.push('\n');
    out
}

/// Run `census catalog which-grants <arg>`: resolve the catalog, find every
/// permission that grants access to `arg`, print the matches (human or JSON), and
/// exit 0. Read-only — never mutates, never runs the arg. Only a catalog/OS read
/// error exits non-zero; "no grants" is a successful query (exit 0).
pub fn run_which_grants(opts: WhichGrantsOpts) -> ExitCode {
    let os = match crate::cli::detect_os_target(opts.os_target.as_deref()) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let catalog = LiveCatalog::new(opts.catalog_roots.clone());
    let ctx = ResolveCtx {
        catalog_version: None,
    };

    let mut sources = match build_grant_sources(&catalog, &os, &ctx) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };

    // With a declaration, also fold in group grants from its `[[role_group]]`
    // bindings so a command/path reached through a `%group` sudoers fragment or a
    // `g:group` ACL is reported (with the inheriting group). Without one, only
    // account grants are looked up (the original behavior).
    if let Some(decl_path) = &opts.declaration {
        match read_declaration(decl_path) {
            Ok(decl) => {
                let inputs = CompileInputs {
                    catalog: &catalog,
                    os: &os,
                    ctx: &ctx,
                };
                match build_group_grant_sources(&decl, &inputs) {
                    Ok(group_sources) => sources.extend(group_sources),
                    Err(e) => {
                        eprintln!("census: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            Err(e) => {
                eprintln!("census: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    let matches = coverage::which_grants(&opts.arg, &sources);

    if opts.json {
        print!("{}", render_which_grants_json(&matches));
    } else {
        print!("{}", render_which_grants_human(&opts.arg, &matches));
    }

    // A query always succeeds — even "no grants" is a valid answer (exit 0).
    ExitCode::SUCCESS
}
