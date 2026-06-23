//! `compile` and `show` (read-only role expansion with provenance).
//!
//! `compile` and `show` expand ONE role from the declaration's role-store
//! composition into concrete Unix primitives, retaining provenance per primitive
//! (which permission/bundle → which catalog layer → catalog version). Both are
//! strictly read-only: they never touch the registry, the live system, or trust
//! state. `model::resolve` drops provenance (it only needs the flat union for the
//! plan), so these commands re-walk the composition per-permission via
//! `catalog::resolve_with_params`, which preserves `SourcedPrimitive`.
//!
//! `show --framework` additionally renders the compiled role's permissions
//! against a compliance framework's controls (a separate read-only report).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::catalog::{self, ResolveCtx, ResolvedPermission, SourcedPrimitive};
use crate::cli::detect_os_target;
use crate::cli::lint::{lint_role, LintSeverity};
use crate::cli::render::{access_token, backend_for_shape, json_str, risk_label, via_suffix};
use crate::declaration::Declaration;
use crate::framework::{self, LoadedFrameworks};
use crate::l10n::{self, L10nSource, LiveL10n};
use crate::model::{self, CompileInputs};
use crate::rolestore::{self, Limits};
use crate::LiveCatalog;

/// One expanded permission of a role, with its provenance retained.
#[derive(Debug, Clone)]
pub struct CompiledPermission {
    /// The fully-resolved permission (primitives carry per-primitive layer/via).
    pub resolved: ResolvedPermission,
}

/// A role expanded into concrete primitives with provenance, plus the raw
/// escape-hatch primitives the role declared directly (kept separate so compile
/// can show that they came from the role slice, not the catalog).
#[derive(Debug, Clone)]
pub struct CompiledRole {
    /// The role id.
    pub role: String,
    /// Each declared permission, expanded with provenance, in declaration order.
    pub permissions: Vec<CompiledPermission>,
    /// Raw `payload.groups` declared directly on the role (escape hatch).
    pub raw_groups: Vec<String>,
    /// Raw `payload.sudo_role`, if any (escape hatch).
    pub raw_sudo_role: Option<String>,
    /// Raw `payload.limits` (escape hatch); default when unset.
    pub raw_limits: Limits,
}

impl CompiledRole {
    /// The flat union of every group across all permissions plus the raw groups,
    /// each tagged with its source layer and the permission that pulled it in.
    /// Raw groups come first (they seed the role) with a synthetic `role` layer.
    pub(crate) fn flat_groups(&self) -> Vec<FlatPrimitive> {
        let mut out: Vec<FlatPrimitive> = Vec::new();
        // Borrowed seen-set: O(1) membership, no per-element clone. Output order
        // stays first-seen (raw groups first), only owned values land in `out`.
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for g in &self.raw_groups {
            if seen.insert(g.as_str()) {
                out.push(FlatPrimitive::raw(g.clone()));
            }
        }
        for perm in &self.permissions {
            for p in &perm.resolved.groups {
                if seen.insert(p.value.as_str()) {
                    out.push(FlatPrimitive::from_sourced(&perm.resolved.id, p));
                }
            }
        }
        out
    }

    /// The flat union of every sudo command across all permissions, deduped by
    /// value, each tagged with provenance.
    fn flat_sudo(&self) -> Vec<FlatPrimitive> {
        let mut out: Vec<FlatPrimitive> = Vec::new();
        // Borrowed seen-set: O(1) membership, first-seen output order, no clones
        // for the dedup itself (only deduped values are cloned into `out`).
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for perm in &self.permissions {
            for p in &perm.resolved.sudo {
                if seen.insert(p.value.as_str()) {
                    out.push(FlatPrimitive::from_sourced(&perm.resolved.id, p));
                }
            }
        }
        out
    }

    /// The flat union of every file grant across all permissions, keyed by path
    /// (access widens to the max, `recursive` ORs, shape recomputed) — the same
    /// rule `model::resolve` applies. Each carries the permission that pulled it in
    /// (first-seen). File grants only ever come from permissions (no raw escape
    /// hatch), so there is no raw seed here.
    pub(crate) fn flat_file_grants(&self) -> Vec<FlatFileGrant> {
        let mut out: Vec<FlatFileGrant> = Vec::new();
        for perm in &self.permissions {
            for g in &perm.resolved.file_grants {
                if let Some(existing) = out.iter_mut().find(|e| e.grant.path == g.path) {
                    // Widen in place, mirroring the resolver's by-path union so the
                    // compiled view shows one grant per path at its strongest. Both
                    // inputs share a path, so the union collapses to a single grant;
                    // if it somehow yielded none we keep the existing grant unchanged.
                    if let Some(merged) =
                        catalog::union_resolved_file_grants(vec![existing.grant.clone(), g.clone()])
                            .into_iter()
                            .next()
                    {
                        existing.grant = merged;
                    }
                } else {
                    out.push(FlatFileGrant {
                        grant: g.clone(),
                        permission: perm.resolved.id.clone(),
                    });
                }
            }
        }
        out
    }

    /// The effective limits for the role: raw limits win wholesale when present
    /// (mirrors `model::resolve`), else the first expanded limit per field.
    fn effective_limits(&self) -> Limits {
        if self.raw_limits != Limits::default() {
            return self.raw_limits.clone();
        }
        let mut limits = Limits::default();
        for perm in &self.permissions {
            if let Some(l) = &perm.resolved.limits {
                if limits.nofile.is_none() {
                    limits.nofile = l.nofile;
                }
                if limits.nproc.is_none() {
                    limits.nproc = l.nproc;
                }
            }
        }
        limits
    }
}

/// A primitive flattened for the compile view: the value plus where it came
/// from. `permission`/`layer` are `None` for a raw escape-hatch primitive (it
/// came from the role slice, not a catalog permission).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatPrimitive {
    /// The primitive value (group name or sudo command).
    pub value: String,
    /// The permission id that contributed it; `None` for a raw primitive.
    pub permission: Option<String>,
    /// The catalog layer it came from; `None` for a raw primitive.
    pub layer: Option<String>,
    /// For a bundle member, the member id that declared it (from `via`).
    pub via: Option<String>,
}

impl FlatPrimitive {
    fn raw(value: String) -> Self {
        FlatPrimitive {
            value,
            permission: None,
            layer: None,
            via: None,
        }
    }

    fn from_sourced(permission: &str, p: &SourcedPrimitive) -> Self {
        FlatPrimitive {
            value: p.value.clone(),
            // The permission the role referenced. When the primitive arrived via
            // a bundle member, `via` names the member; the referenced permission
            // is still the bundle the role named.
            permission: Some(permission.to_owned()),
            layer: Some(p.layer.clone()),
            via: p.via.clone(),
        }
    }

    /// The provenance suffix for the human view, e.g.
    /// ` [perm net-admin via firewall-diag @ linux-debian-12]` or ` [raw]`.
    fn provenance(&self) -> String {
        match (&self.permission, &self.layer) {
            (Some(perm), Some(layer)) => match &self.via {
                Some(via) if via != perm => format!(" [perm {perm} via {via} @ {layer}]"),
                _ => format!(" [perm {perm} @ {layer}]"),
            },
            _ => " [raw]".to_owned(),
        }
    }
}

/// A file grant flattened for the compile/show view: the resolved grant plus the
/// permission that contributed it. The render derives the access/recursive/shape
/// display and the enforcing backend from the grant itself.
#[derive(Debug, Clone)]
pub struct FlatFileGrant {
    /// The resolved file grant (path, access, recursive, shape, provenance).
    pub grant: catalog::ResolvedFileGrant,
    /// The permission id that pulled this grant in.
    pub permission: String,
}

/// Compile one role from the declaration's role-store composition, retaining
/// provenance. Reusable by `run_compile`, `run_show`, and lint. Fails closed if
/// the role slice is missing/malformed or any permission cannot be expanded.
///
/// Returns the compiled role plus the resolve warnings (raw-primitive lint,
/// unknown-OS-version, unused-param) the model layer would also surface.
pub fn compile_role(
    role: &str,
    decl: &Declaration,
    inputs: &CompileInputs<'_, impl catalog::CatalogSource>,
) -> Result<(CompiledRole, Vec<model::ResolveWarning>), model::ResolveError> {
    let comp = rolestore::read_composition(&decl.role_store, role)?;
    let mut warnings: Vec<model::ResolveWarning> = Vec::new();

    // Mirror the model layer's raw-primitive lint exactly (only when the role
    // ALSO declares permissions — raw-only is the legacy path, not flagged).
    if !comp.permissions.is_empty() {
        if !comp.groups.is_empty() {
            warnings.push(model::ResolveWarning::RawPrimitiveAlongsidePermissions {
                role: role.to_owned(),
                primitive: "groups",
            });
        }
        if comp.sudo_role.is_some() {
            warnings.push(model::ResolveWarning::RawPrimitiveAlongsidePermissions {
                role: role.to_owned(),
                primitive: "sudo_role",
            });
        }
        if comp.limits != Limits::default() {
            warnings.push(model::ResolveWarning::RawPrimitiveAlongsidePermissions {
                role: role.to_owned(),
                primitive: "limits",
            });
        }
    }

    let mut permissions = Vec::with_capacity(comp.permissions.len());
    for perm in &comp.permissions {
        let (resolved, catalog_warnings) = catalog::resolve_with_params(
            &perm.id,
            &perm.params,
            inputs.os,
            inputs.catalog,
            inputs.ctx,
        )
        .map_err(|source| model::ResolveError::Catalog {
            role: role.to_owned(),
            source: Box::new(source),
        })?;
        for w in catalog_warnings {
            warnings.push(model::ResolveWarning::Catalog(w));
        }
        permissions.push(CompiledPermission { resolved });
    }

    Ok((
        CompiledRole {
            role: role.to_owned(),
            permissions,
            raw_groups: comp.groups,
            raw_sudo_role: comp.sudo_role,
            raw_limits: comp.limits,
        },
        warnings,
    ))
}

/// Render the compiled role as a human-readable flat slice with provenance.
/// Pure (string in, string out) so the output shape is unit-testable.
pub fn render_compile_human(compiled: &CompiledRole) -> String {
    let mut out = String::new();
    out.push_str(&format!("role {}\n", compiled.role));

    let groups = compiled.flat_groups();
    out.push_str("groups:\n");
    if groups.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for g in &groups {
            out.push_str(&format!("  {}{}\n", g.value, g.provenance()));
        }
    }

    let sudo = compiled.flat_sudo();
    out.push_str("sudo:\n");
    if sudo.is_empty() {
        // A raw sudo_role is the legacy indirection; surface it so the operator
        // sees the role is not empty of sudo, it just uses the escape hatch.
        match &compiled.raw_sudo_role {
            Some(r) => out.push_str(&format!("  (sudo_role {r}) [raw]\n")),
            None => out.push_str("  (none)\n"),
        }
    } else {
        for s in &sudo {
            out.push_str(&format!("  {}{}\n", s.value, s.provenance()));
        }
    }

    let files = compiled.flat_file_grants();
    out.push_str("files:\n");
    if files.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for f in &files {
            // `<path> <ro|rw>[ recursive] via <backend> [perm <id>]`
            let recursive = if f.grant.recursive { " recursive" } else { "" };
            out.push_str(&format!(
                "  {} {}{} via {} [perm {}]\n",
                f.grant.path,
                access_token(f.grant.access),
                recursive,
                backend_for_shape(f.grant.shape),
                f.permission,
            ));
        }
    }

    let limits = compiled.effective_limits();
    out.push_str("limits:\n");
    if limits == Limits::default() {
        out.push_str("  (none)\n");
    } else {
        if let Some(n) = limits.nofile {
            out.push_str(&format!("  nofile = {n}\n"));
        }
        if let Some(n) = limits.nproc {
            out.push_str(&format!("  nproc = {n}\n"));
        }
    }
    out
}

/// Render the compiled role as a machine-readable JSON object. Hand-rolled over
/// the small, fixed shape for exact-byte output control: the layout and escaping
/// (including U+2028/U+2029) are golden-locked by the contract tests, so the
/// renderer is deliberately not delegated to `serde_json` to avoid silent byte
/// drift on a dependency bump. Pure so the shape is unit-testable.
pub fn render_compile_json(compiled: &CompiledRole) -> String {
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!("\"role\":{},", json_str(&compiled.role)));

    out.push_str("\"groups\":[");
    out.push_str(&flat_primitives_json(&compiled.flat_groups()));
    out.push_str("],");

    out.push_str("\"sudo\":[");
    out.push_str(&flat_primitives_json(&compiled.flat_sudo()));
    out.push_str("],");

    out.push_str("\"file_grants\":[");
    out.push_str(&flat_file_grants_json(&compiled.flat_file_grants()));
    out.push_str("],");

    let limits = compiled.effective_limits();
    out.push_str("\"limits\":{");
    out.push_str(&format!(
        "\"nofile\":{},\"nproc\":{}",
        limits
            .nofile
            .map(|n| n.to_string())
            .unwrap_or_else(|| "null".to_owned()),
        limits
            .nproc
            .map(|n| n.to_string())
            .unwrap_or_else(|| "null".to_owned()),
    ));
    out.push('}');
    out.push('}');
    out.push('\n');
    out
}

/// Render a list of flat primitives as JSON objects.
fn flat_primitives_json(prims: &[FlatPrimitive]) -> String {
    prims
        .iter()
        .map(|p| {
            format!(
                "{{\"value\":{},\"permission\":{},\"layer\":{},\"via\":{}}}",
                json_str(&p.value),
                p.permission
                    .as_deref()
                    .map(json_str)
                    .unwrap_or_else(|| "null".to_owned()),
                p.layer
                    .as_deref()
                    .map(json_str)
                    .unwrap_or_else(|| "null".to_owned()),
                p.via
                    .as_deref()
                    .map(json_str)
                    .unwrap_or_else(|| "null".to_owned()),
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Render a list of flat file grants as JSON objects: path, access (`ro`/`rw`),
/// recursive, shape, the enforcing backend description, and the contributing
/// permission. Reuses `json_str` for escaping.
fn flat_file_grants_json(grants: &[FlatFileGrant]) -> String {
    grants
        .iter()
        .map(|f| {
            let shape = match f.grant.shape {
                catalog::Shape::Dir => "dir",
                catalog::Shape::File => "file",
                catalog::Shape::Pattern => "pattern",
            };
            format!(
                "{{\"path\":{},\"access\":{},\"recursive\":{},\"shape\":{},\"backend\":{},\"permission\":{}}}",
                json_str(&f.grant.path),
                json_str(access_token(f.grant.access)),
                f.grant.recursive,
                json_str(shape),
                json_str(backend_for_shape(f.grant.shape)),
                json_str(&f.permission),
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Run `census compile <role>`: expand one role into its flat compiled slice
/// with provenance, print it (human or JSON), optionally lint. Read-only; never
/// mutates. With `--lint`, exits non-zero if any lint ERROR is present.
pub fn run_compile(
    role: &str,
    declaration: &Path,
    catalog_roots: Vec<PathBuf>,
    os_target: Option<&str>,
    lint: bool,
    json: bool,
) -> ExitCode {
    let text = match std::fs::read_to_string(declaration) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "census: cannot read declaration {}: {e}",
                declaration.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let decl = match Declaration::parse(&text) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let catalog = LiveCatalog::new(catalog_roots.clone());
    let os = match detect_os_target(os_target) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let ctx = ResolveCtx {
        catalog_version: None,
    };
    let inputs = CompileInputs {
        catalog: &catalog,
        os: &os,
        ctx: &ctx,
    };

    let (compiled, warnings) = match compile_role(role, &decl, &inputs) {
        Ok(r) => r,
        Err(e) => {
            // A resolve error (unknown permission, cycle, namespace collision,
            // lowered bundle risk, …) is a hard lint ERROR — fail closed.
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };

    if json {
        print!("{}", render_compile_json(&compiled));
    } else {
        print!("{}", render_compile_human(&compiled));
    }

    if lint {
        let l10n = LiveL10n::new(catalog_roots);
        let mut findings = lint_role(&compiled, &warnings, &decl, &os, &catalog, &l10n);
        // Group-grant escalation lint: bindings that attach an escalation-capable
        // grant to a group every member inherits. Resolved from the declaration's
        // `[[role_group]]` blocks. A resolve failure here is advisory-only (the
        // group lint is a best-effort overlay on the per-role compile, which is
        // what `--lint` gates on); surface it as a warning and skip.
        match model::resolve_groups(&decl, &inputs) {
            Ok((groups, _warnings)) => {
                findings.extend(crate::cli::lint::group_grant_risk_findings(&groups))
            }
            Err(e) => eprintln!("census: warning: group lint skipped: {e}"),
        }
        for f in &findings {
            eprintln!("census: {} [{}] {}", f.severity.tag(), f.code, f.message);
        }
        if findings.iter().any(|f| f.severity == LintSeverity::Error) {
            return ExitCode::FAILURE;
        }
    } else {
        // Without --lint, still surface the resolve warnings (they are advisory
        // signals, not errors) so a plain compile is informative.
        for w in &warnings {
            eprintln!("census: warning: {w}");
        }
    }
    ExitCode::SUCCESS
}

/// Options for `census show <role>` (CLI-derived).
#[derive(Debug)]
pub struct ShowOpts<'a> {
    pub role: &'a str,
    pub declaration: &'a Path,
    pub catalog_roots: Vec<PathBuf>,
    pub os_target: Option<&'a str>,
    pub lang: Option<&'a str>,
    pub framework: Option<&'a str>,
    pub framework_roots: Vec<PathBuf>,
    pub format: Option<&'a str>,
}

/// Run `census show <role> --lang <l>`: render a tree role → permission/bundle →
/// expanded primitives, with localized texts and (advisory) risk classes.
/// Read-only.
pub fn run_show(opts: ShowOpts<'_>) -> ExitCode {
    let ShowOpts {
        role,
        declaration,
        catalog_roots,
        os_target,
        lang,
        framework,
        framework_roots,
        format,
    } = opts;
    let json = format == Some("json");
    let text = match std::fs::read_to_string(declaration) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "census: cannot read declaration {}: {e}",
                declaration.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let decl = match Declaration::parse(&text) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let catalog = LiveCatalog::new(catalog_roots.clone());
    let os = match detect_os_target(os_target) {
        Ok(os) => os,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let ctx = ResolveCtx {
        catalog_version: None,
    };
    let inputs = CompileInputs {
        catalog: &catalog,
        os: &os,
        ctx: &ctx,
    };

    let (compiled, _warnings) = match compile_role(role, &decl, &inputs) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };

    // --- framework cross-reference view (--framework given) ---
    //
    // When `--framework` is present we load the framework tree and render the
    // compiled role's permissions against the selected framework(s) — controls +
    // mapping provenance — in either human or JSON form. This is a wholly
    // separate, read-only report from the plain show tree.
    if let Some(fw_spec) = framework {
        let loaded = match framework::load_frameworks(&framework_roots, &os) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("census: {e}");
                return ExitCode::FAILURE;
            }
        };
        for w in &loaded.warnings {
            eprintln!("census: warning: {w}");
        }
        let selection = FrameworkSelection::resolve(fw_spec, &loaded);
        if json {
            print!(
                "{}",
                render_show_framework_json(&compiled, &selection, &loaded)
            );
        } else {
            print!(
                "{}",
                render_show_framework_human(&compiled, &selection, &loaded)
            );
        }
        return ExitCode::SUCCESS;
    }

    // --- JSON without --framework ---
    //
    // `--format json` may be requested without a framework. Per the slice
    // contract there is no framework stamp to emit (none was requested), so we
    // render a minimal JSON of the role and its permission ids — valid JSON, no
    // `frameworks` array. The stamped, framework-bearing JSON is only produced
    // when `--framework` is also given (handled above).
    if json {
        print!("{}", render_show_permissions_json(&compiled));
        return ExitCode::SUCCESS;
    }

    // --- default: the plain localized show tree (current behavior) ---
    //
    // Language selection: explicit --lang beats LC_MESSAGES beats LANG beats en.
    // The real environment is read HERE (the pure picker stays testable).
    let lc_messages = std::env::var("LC_MESSAGES").ok();
    let env_lang = std::env::var("LANG").ok();
    let chosen = l10n::lang_from_env(lang, lc_messages.as_deref(), env_lang.as_deref());

    // l10n tree lives under the SAME roots as the catalog (`<root>/l10n/...`).
    let l10n = LiveL10n::new(catalog_roots);
    print!("{}", render_show_tree(&compiled, &chosen, &l10n));
    ExitCode::SUCCESS
}

/// Which framework(s) a `census show --framework <spec>` invocation displays.
///
/// `<spec>` is either a single framework id or `all`. We resolve it eagerly to a
/// sorted list of ids drawn from the loaded set so the render functions are pure
/// over a concrete id list: `all` expands to every loaded framework id (already
/// sorted, since `frameworks` is a `BTreeMap`), and a single id is kept as-is
/// (even if not loaded — the render then shows it with no controls, which is the
/// honest "framework not installed" signal rather than a silent empty report).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkSelection {
    /// The framework ids to display, sorted.
    pub ids: Vec<String>,
}

impl FrameworkSelection {
    /// Resolve a `--framework` spec against the loaded set. `all` → every loaded
    /// id; any other value → that single id verbatim.
    pub fn resolve(spec: &str, loaded: &LoadedFrameworks) -> FrameworkSelection {
        if spec == "all" {
            FrameworkSelection {
                ids: loaded.frameworks.keys().cloned().collect(),
            }
        } else {
            FrameworkSelection {
                ids: vec![spec.to_owned()],
            }
        }
    }
}

/// The mapping provenance contributions for one (framework, permission): each
/// physical mapping file that mentioned the permission, with its layer and path.
/// Drawn from `loaded.mappings` (the pre-union, per-file record) so the report
/// can point a reviewer at the exact source of every control mapping.
fn provenance_for<'a>(
    loaded: &'a LoadedFrameworks,
    fw: &str,
    perm: &str,
) -> Vec<&'a framework::MappingProvenance> {
    loaded
        .mappings
        .iter()
        .filter(|m| m.framework_id == fw && m.permission_id == perm)
        .map(|m| &m.provenance)
        .collect()
}

/// Render the framework cross-reference for a compiled role (human form). For
/// each selected framework, every permission of the role is listed with the
/// control ids it satisfies and the mapping provenance; a permission with no
/// mapping in that framework is printed with an explicit `(no mapping)` marker
/// (never omitted). Pure (no filesystem) so it is unit-testable.
pub fn render_show_framework_human(
    compiled: &CompiledRole,
    selected: &FrameworkSelection,
    loaded: &LoadedFrameworks,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("role {}\n", compiled.role));
    if selected.ids.is_empty() {
        out.push_str("  (no frameworks installed)\n");
        return out;
    }
    for fw in &selected.ids {
        // Version stamp from the manifest when the framework is loaded; an
        // unknown id is labelled so the report is honest about a missing install.
        match loaded.frameworks.get(fw) {
            Some(m) => out.push_str(&format!("framework {} ({})\n", fw, m.version)),
            None => out.push_str(&format!("framework {} (not installed)\n", fw)),
        }
        if compiled.permissions.is_empty() {
            out.push_str("  (no permissions; raw escape-hatch only)\n");
        }
        for perm in &compiled.permissions {
            let perm_id = &perm.resolved.id;
            let polar = loaded.controls_for(perm_id, fw);
            if polar.is_empty() {
                out.push_str(&format!("  permission {perm_id} (no mapping)\n"));
                continue;
            }
            out.push_str(&format!("  permission {perm_id}:\n"));
            if !polar.satisfies.is_empty() {
                out.push_str(&format!(
                    "    ✓ satisfies: {}\n",
                    polar.satisfies.join(", ")
                ));
            }
            if !polar.risk.is_empty() {
                out.push_str(&format!("    ⚠ risk: {}\n", polar.risk.join(", ")));
            }
            if !polar.related.is_empty() {
                out.push_str(&format!("    · related: {}\n", polar.related.join(", ")));
            }
            for prov in provenance_for(loaded, fw, perm_id) {
                let layer = prov.layer.as_deref().unwrap_or("-");
                out.push_str(&format!(
                    "    via {} [{}] {}\n",
                    fw,
                    layer,
                    prov.path.display()
                ));
            }
        }
    }
    out
}

/// Render the framework cross-reference as JSON. Hand-rolled for exact-byte
/// output stability (the layout is golden-locked); not delegated to `serde_json`.
/// Each selected framework carries a version STAMP (`id` + `version`) and a
/// `permissions` array; an unmapped permission is marked `"mapped":false` with an
/// empty `controls` array (never omitted). Pure so the shape is unit-testable.
pub fn render_show_framework_json(
    compiled: &CompiledRole,
    selected: &FrameworkSelection,
    loaded: &LoadedFrameworks,
) -> String {
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!("\"role\":{},", json_str(&compiled.role)));
    out.push_str("\"frameworks\":[");
    let fws: Vec<String> = selected
        .ids
        .iter()
        .map(|fw| {
            // Version stamp: the manifest version when loaded, else null (an id
            // the caller named that is not installed).
            let version = loaded
                .frameworks
                .get(fw)
                .map(|m| json_str(&m.version))
                .unwrap_or_else(|| "null".to_owned());
            let perms: Vec<String> = compiled
                .permissions
                .iter()
                .map(|perm| {
                    let perm_id = &perm.resolved.id;
                    let polar = loaded.controls_for(perm_id, fw);
                    let mapped = !polar.is_empty();
                    let satisfies_json: Vec<String> = polar.satisfies.iter().map(|c| json_str(c)).collect();
                    let risk_json: Vec<String> = polar.risk.iter().map(|c| json_str(c)).collect();
                    let related_json: Vec<String> = polar.related.iter().map(|c| json_str(c)).collect();
                    let prov_json: Vec<String> = provenance_for(loaded, fw, perm_id)
                        .iter()
                        .map(|p| {
                            format!(
                                "{{\"layer\":{},\"path\":{}}}",
                                p.layer.as_deref().map(json_str).unwrap_or_else(|| "null".to_owned()),
                                json_str(&p.path.display().to_string()),
                            )
                        })
                        .collect();
                    format!(
                        "{{\"permission\":{},\"satisfies\":[{}],\"risk\":[{}],\"related\":[{}],\"mapped\":{},\"provenance\":[{}]}}",
                        json_str(perm_id),
                        satisfies_json.join(","),
                        risk_json.join(","),
                        related_json.join(","),
                        mapped,
                        prov_json.join(","),
                    )
                })
                .collect();
            format!(
                "{{\"id\":{},\"version\":{},\"permissions\":[{}]}}",
                json_str(fw),
                version,
                perms.join(","),
            )
        })
        .collect();
    out.push_str(&fws.join(","));
    out.push_str("]}");
    out.push('\n');
    out
}

/// Render a compiled role's permission ids as a minimal JSON object (no framework
/// block). Used by `census show --format json` WITHOUT `--framework`: no
/// framework was requested, so there is no version stamp and no `frameworks`
/// array — just the role and its permission ids. Pure / unit-testable.
pub fn render_show_permissions_json(compiled: &CompiledRole) -> String {
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!("\"role\":{},", json_str(&compiled.role)));
    out.push_str("\"permissions\":[");
    let perms: Vec<String> = compiled
        .permissions
        .iter()
        .map(|p| json_str(&p.resolved.id))
        .collect();
    out.push_str(&perms.join(","));
    out.push_str("]}");
    out.push('\n');
    out
}

/// Render the show tree: role → each permission (localized title + risk class +
/// optional summary/risk_note) → its expanded primitives. Pure over the l10n
/// source so it is unit-testable with a fake source.
pub fn render_show_tree(compiled: &CompiledRole, lang: &str, l10n: &dyn L10nSource) -> String {
    let mut out = String::new();
    out.push_str(&format!("role {}\n", compiled.role));

    if compiled.permissions.is_empty() {
        out.push_str("  (no permissions; raw escape-hatch only)\n");
    }

    for perm in &compiled.permissions {
        let r = &perm.resolved;
        let text = l10n::resolve_text(l10n, lang, &r.id);
        // Title line: id, localized title, advisory risk class. When the title
        // fell back to the id itself, mark it untranslated so the tree is honest.
        let untranslated = if text.locale_used.is_none() {
            " (untranslated)"
        } else {
            ""
        };
        out.push_str(&format!(
            "  permission {} — {}{} [{}]\n",
            r.id,
            text.title,
            untranslated,
            risk_label(r.risk)
        ));
        if let Some(summary) = &text.summary {
            out.push_str(&format!("    summary: {summary}\n"));
        }
        if let Some(note) = &text.risk_note {
            out.push_str(&format!("    risk: {note}\n"));
        }
        for g in &r.groups {
            out.push_str(&format!(
                "    group {}{}\n",
                g.value,
                via_suffix(&r.id, &g.via)
            ));
        }
        for s in &r.sudo {
            out.push_str(&format!(
                "    sudo {}{}\n",
                s.value,
                via_suffix(&r.id, &s.via)
            ));
        }
        for g in &r.file_grants {
            let recursive = if g.recursive { " recursive" } else { "" };
            let via = g.sources.iter().find_map(|src| src.via.as_deref());
            out.push_str(&format!(
                "    file {} {}{} via {}{}\n",
                g.path,
                access_token(g.access),
                recursive,
                backend_for_shape(g.shape),
                match via {
                    Some(m) if m != r.id => format!(" (via {m})"),
                    _ => String::new(),
                },
            ));
        }
        if let Some(l) = &r.limits {
            if let Some(n) = l.nofile {
                out.push_str(&format!("    limit nofile = {n}\n"));
            }
            if let Some(n) = l.nproc {
                out.push_str(&format!("    limit nproc = {n}\n"));
            }
        }
    }

    if !compiled.raw_groups.is_empty() {
        out.push_str("  raw groups (escape hatch):\n");
        for g in &compiled.raw_groups {
            out.push_str(&format!("    {g}\n"));
        }
    }
    if let Some(r) = &compiled.raw_sudo_role {
        out.push_str(&format!("  raw sudo_role (escape hatch): {r}\n"));
    }
    out
}
