//! Permission catalog: catalog policy records, OS-target layer chain, and
//! layered leaf resolve.
//!
//! A *permission* is a named capability (e.g. `network-admin`) that the catalog
//! expands into concrete Unix primitives (groups, sudo commands, limits) for the
//! device's OS target. This module (slice 1) covers the catalog record format,
//! OS-target detection, and the layered **leaf** resolve (a single permission id
//! merged across the OS layer chain). Aggregation (`includes` /
//! `include_categories`), namespaces, l10n, and CLI are later slices.
//!
//! ## Strict vs tolerant parsing — why the asymmetry with `rolestore`
//!
//! `rolestore` reads Tessera's role slices *tolerantly* (no `deny_unknown_fields`)
//! because the role schema is Tessera's responsibility and Census must ignore
//! fields it does not consume. The catalog is the opposite: Census *owns* the
//! catalog format, and a permission expands (as root) into sudo commands. An
//! unrecognised field is a sign of a typo, a stale file, or a description text
//! that belongs in the l10n tree — never something to silently ignore. So
//! catalog records use `deny_unknown_fields` (fail-closed, the PwnKit lesson:
//! reject unknown structure rather than guess).

use crate::rolestore::Limits;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Risk class of a permission. Advisory only (honest labelling, not
/// enforcement): it never blocks expansion or apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum Risk {
    /// Capability stays within its intended scope.
    #[serde(rename = "contained")]
    Contained,
    /// Capability can be a path to root (e.g. membership in `docker`).
    #[serde(rename = "escalation-capable")]
    EscalationCapable,
}

impl Risk {
    /// Severity rank for `max` over bundle members: `Contained` < `EscalationCapable`.
    /// Kept as an explicit method (not a derived `Ord`) so the ordering is a
    /// documented domain decision, not an accident of variant declaration order.
    fn rank(self) -> u8 {
        match self {
            Risk::Contained => 0,
            Risk::EscalationCapable => 1,
        }
    }

    /// The more severe of two risks.
    fn max(self, other: Risk) -> Risk {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// A list-valued expansion field as written in a catalog layer.
///
/// A *bare array* in TOML (`groups = ["a", "b"]`) means **replace**: the layer
/// states the full list, wiping anything lower layers contributed. A *table*
/// (`groups = { append = ["b"] }`) means **append**: add to the accumulated
/// list from lower layers. This lets a base layer state the common set and a
/// version layer add a distro-specific extra without restating the base
/// (spec: `sudo.append = [netplan]` on `linux-debian-12`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListOverride {
    /// Bare array: replace the accumulated list with this one.
    Replace(Vec<String>),
    /// `{ append = [...] }`: add these to the accumulated list.
    Append(Vec<String>),
}

impl Default for ListOverride {
    fn default() -> Self {
        // An absent field contributes nothing — modelled as an empty append so
        // it neither replaces nor adds.
        ListOverride::Append(Vec::new())
    }
}

impl<'de> Deserialize<'de> for ListOverride {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Accept either a bare array (replace) or a table `{ append = [...] }`.
        // A separate strict helper enforces deny_unknown_fields on the table
        // form so a typo like `{ apend = [...] }` is rejected, not dropped.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AppendForm {
            append: Vec<String>,
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Bare(Vec<String>),
            Append(AppendForm),
        }

        Ok(match Raw::deserialize(deserializer)? {
            Raw::Bare(v) => ListOverride::Replace(v),
            Raw::Append(a) => ListOverride::Append(a.append),
        })
    }
}

/// The `[limits]` sub-table as written in a catalog record, parsed *strictly*.
///
/// `rolestore::Limits` is intentionally tolerant (no `deny_unknown_fields`)
/// because Tessera owns the role schema and Census must ignore role fields it
/// does not consume. The catalog is the opposite: Census owns it and expands it
/// as root, so an unknown key under `[limits]` is a typo or a smuggled field and
/// must be rejected — most importantly `mac_mask`, which is a Tessera
/// enforcement primitive and MUST NOT appear in a catalog expansion. Hiding it
/// under `[limits]` (where the tolerant role type would silently drop it) would
/// otherwise be worse than the correctly-rejected top-level form. This local
/// strict type closes that gap without touching the tolerant role-slice parse.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogLimits {
    /// `RLIMIT_NOFILE`.
    #[serde(default)]
    pub nofile: Option<u64>,
    /// `RLIMIT_NPROC`.
    #[serde(default)]
    pub nproc: Option<u64>,
}

impl From<CatalogLimits> for Limits {
    fn from(c: CatalogLimits) -> Self {
        Limits {
            nofile: c.nofile,
            nproc: c.nproc,
        }
    }
}

/// File-access mode a grant requests.
///
/// `ro` maps to POSIX ACL `r-X` (read + traverse-only on directories — the `X`
/// is execute *only* on dirs, so a reader can walk into a tree without gaining
/// execute on regular files); `rw` maps to `rwX`. The two values form an ordered
/// lattice for the resolve-time union (`Ro` < `Rw`): two grants on the same path
/// merge to the wider access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
pub enum Access {
    /// Read + directory-traverse (`r-X`).
    #[serde(rename = "ro")]
    Ro,
    /// Read + write + directory-traverse (`rwX`).
    #[serde(rename = "rw")]
    Rw,
}

impl Access {
    /// Severity rank for the union: `Ro` < `Rw`. An explicit method (not derived
    /// `Ord`) so the widening order is a documented domain decision rather than an
    /// accident of variant declaration order.
    fn rank(self) -> u8 {
        match self {
            Access::Ro => 0,
            Access::Rw => 1,
        }
    }

    /// The wider of two accesses (used when unioning grants on the same path).
    fn max(self, other: Access) -> Access {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// The structural form of a file-grant path, derived deterministically from the
/// path string plus the grant's `recursive` flag. The form selects which backend
/// capability must cover the grant (see [`crate::fileaccess`]): `Dir` → `dir`,
/// `File` → `per_path`, `Pattern` → `pattern`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// A directory grant — the only form the open `AclBackend` enforces reliably
    /// (recursive + default-ACL, rewrite-proof). New files created in the tree
    /// inherit the access, so a directory grant survives edit-via-rename and log
    /// rotation.
    Dir,
    /// A grant on one concrete file. Not rewrite-proof via ACL alone (a rename
    /// makes a new inode), so it needs a capability-`per_path` backend.
    File,
    /// A grant on a glob pattern (`*`, `?`, `[`). The filesystem hands out access
    /// by inode/dir, never by name, so a pattern needs a capability-`pattern`
    /// backend (watcher / MAC labels).
    Pattern,
}

/// Whether a path component string contains a shell-glob metacharacter. Used to
/// classify a grant as [`Shape::Pattern`]. Only the three POSIX glob metacharacters
/// are recognised; a literal path with none of these is a concrete dir/file.
fn has_glob_metachar(path: &str) -> bool {
    path.contains('*') || path.contains('?') || path.contains('[')
}

/// A single file-access grant as written in a catalog record, parsed *strictly*.
///
/// Strict (`deny_unknown_fields`) for the same reason the whole catalog is: Census
/// owns this format and materializes it as root (setfacl). An unrecognised key is a
/// typo or a smuggled field, not something to silently ignore.
///
/// The `path` is validated (absolute, no control chars, no `..` component) at the
/// read boundary; `{param}` placeholders are filled and re-validated at resolve
/// time, mirroring the parametrized-sudo path exactly.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileGrant {
    /// Absolute path to a directory, file, or glob pattern.
    pub path: String,
    /// Read-only or read-write.
    pub access: Access,
    /// For directories: apply recursively and set a default-ACL so new files in
    /// the tree inherit the access. Absent defaults to `false`.
    #[serde(default)]
    pub recursive: bool,
}

impl FileGrant {
    /// Derive the structural [`Shape`] of this grant deterministically.
    ///
    /// The rule (fixed and documented so authors and the engine agree):
    ///   1. the path contains a glob metachar (`*`, `?`, `[`) → [`Shape::Pattern`];
    ///   2. else `recursive == true` OR the path ends with `/` → [`Shape::Dir`];
    ///   3. else → [`Shape::File`].
    ///
    /// Rationale: the filesystem hands out access by inode/dir, never by name, so a
    /// glob is always a Pattern (needs a pattern-capable backend). Among concrete
    /// paths the *author's intent* is what disambiguates a directory from a file:
    /// a directory grant is the rewrite-proof form (recursive + default-ACL), and an
    /// author who wants a directory writes `recursive = true` (or a trailing slash).
    /// A bare path with neither marker is treated as a single file — which the open
    /// `AclBackend` deliberately refuses, steering the author to widen it to a
    /// directory or install a per-file backend. This matches the design's examples:
    /// the canonical directory grant there is `path = "/etc/ssh" recursive = true`.
    pub fn shape(&self) -> Shape {
        if has_glob_metachar(&self.path) {
            Shape::Pattern
        } else if self.recursive || self.path.ends_with('/') {
            Shape::Dir
        } else {
            Shape::File
        }
    }
}

/// A single catalog policy record, parsed strictly.
///
/// One `PermissionDef` is one *layer's* statement about an id. The cross-layer
/// merge (see [`resolve_leaf`]) combines several of these for the same id.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionDef {
    /// Permission id (top-level in slice 1; namespaced ids are slice 2).
    pub id: String,
    /// Risk class. Optional per-layer: a higher layer may override primitives
    /// without restating risk, in which case the lower layer's risk stands.
    #[serde(default)]
    pub risk: Option<Risk>,
    /// Category tag (used by `include_categories` in slice 2; inert here).
    #[serde(default)]
    pub category: Option<String>,
    /// Group memberships this permission grants.
    #[serde(default)]
    pub groups: ListOverride,
    /// Sudo commands this permission grants.
    #[serde(default)]
    pub sudo: ListOverride,
    /// Resource limits this permission sets. A higher layer that sets `limits`
    /// replaces wholesale (limits are a small fixed struct, not a list). Uses the
    /// strict [`CatalogLimits`] so an unknown key (notably `mac_mask`) under
    /// `[limits]` is rejected rather than silently dropped.
    #[serde(default)]
    pub limits: Option<CatalogLimits>,
    /// When `true`, this layer wipes everything accumulated from lower layers
    /// and takes its own statement wholesale (full override, not field-by-field).
    #[serde(default)]
    pub replace: bool,

    // --- aggregation fields: parsed and stored so slice-1 catalog files that
    //     already use them are accepted, but NOT resolved here (leaf-only
    //     resolve). Wired transitively in slice 2. ---
    /// Explicit ids this permission aggregates. Inert in slice 1.
    #[serde(default)]
    pub includes: Vec<String>,
    /// Categories this permission aggregates. Inert in slice 1.
    #[serde(default)]
    pub include_categories: Vec<String>,

    /// File-access grants this permission carries (`[[file]]` sub-tables). Each
    /// is parsed strictly and its path validated at the read boundary.
    #[serde(default, rename = "file")]
    pub files: Vec<FileGrant>,
}

impl PermissionDef {
    /// Reject internally contradictory records before they enter the resolver.
    ///
    /// `replace = true` wipes everything lower layers contributed and then takes
    /// this layer wholesale; an `.append` form on the *same* record means "add to
    /// the accumulated list". Combined, they silently mean "wipe, then add only
    /// these" — a near-certain sign the author has the wrong mental model (they
    /// likely meant a bare-array full replace, or meant to drop `replace`). Rather
    /// than expand the surprising interpretation into root sudo, fail closed.
    ///
    /// Called at every read boundary (file parse and in-memory source) so no
    /// record reaches resolve without this gate.
    fn validate(&self) -> Result<(), CatalogError> {
        for (field, ov) in [("groups", &self.groups), ("sudo", &self.sudo)] {
            if self.replace && matches!(ov, ListOverride::Append(v) if !v.is_empty()) {
                return Err(CatalogError::ContradictoryRecord {
                    id: self.id.clone(),
                    reason: format!("replace=true is incompatible with .append on {field}"),
                });
            }
        }
        // Every sudo command value is materialized into a sudoers rule as root.
        // Validate each here (both the Replace and Append forms) so a hostile or
        // typo'd value fails closed at parse, naming the offending id, rather than
        // reaching root materialization and relying solely on the renderer's
        // metacharacter escaping.
        let sudo_values = match &self.sudo {
            ListOverride::Replace(v) | ListOverride::Append(v) => v,
        };
        for value in sudo_values {
            // A templated value (containing `{...}` placeholders) is validated
            // AFTER substitution, not here: the literal `{unit}` is not yet a
            // concrete Cmnd, and the post-substitution gate
            // (`validate_substituted_sudo_command`) enforces the same rules on the
            // rendered result. Validating a placeholder-bearing template against
            // the absolute-path rule here would wrongly reject e.g.
            // `/usr/bin/systemctl start {unit}` only when it happens to start with
            // a placeholder — but more importantly the real defence is on the
            // rendered string. We still reject control chars / empties early.
            if let Some(reason) = sudo_command_static_defect(value) {
                return Err(CatalogError::InvalidSudoCommand {
                    id: self.id.clone(),
                    value: value.clone(),
                    reason,
                });
            }
        }
        // Every file-grant path is materialized into a root `setfacl` target.
        // Validate each literal path here so a relative/`..`/control-bearing path
        // fails closed at parse, naming the offending id. A templated path
        // (`{param}`) is validated after substitution by the resolver; the static
        // gate still rejects the always-illegal defects (control chars, empty).
        for grant in &self.files {
            if let Some(reason) = file_path_static_defect(&grant.path) {
                return Err(CatalogError::InvalidFilePath {
                    id: self.id.clone(),
                    path: grant.path.clone(),
                    reason,
                });
            }
            // A trailing '/' denotes a directory grant (Shape::Dir), which the
            // AclBackend always materializes recursively with a default-ACL. Pairing
            // it with `recursive = false` is contradictory: the flag would be
            // silently ineffective. Reject it so the author resolves the intent
            // explicitly rather than being surprised by a recursive grant.
            if grant.path.ends_with('/') && !grant.recursive && !has_placeholder(&grant.path) {
                return Err(CatalogError::InvalidFilePath {
                    id: self.id.clone(),
                    path: grant.path.clone(),
                    reason: "trailing '/' denotes a recursive directory grant; set recursive=true or remove the trailing slash for a file grant",
                });
            }
        }
        Ok(())
    }
}

/// The H1 sudo-command validation rule, factored out so it is reusable on
/// post-substitution strings (a templated command's concrete result must pass
/// the SAME gate the catalog parse applies to a static command). Returns the
/// rejection reason, or `None` if the value is a fit concrete absolute-path Cmnd.
///
/// Census emits each sudo string into `/etc/sudoers.d/census-*` as root, so a
/// value with a control char (a newline splits the rule into a second physical
/// directive), an empty/whitespace-only value, or a non-absolute command
/// (Census only emits concrete absolute-path Cmnds) is unfit.
fn sudo_command_defect(value: &str) -> Option<&'static str> {
    if value.chars().any(char::is_control) {
        Some("contains a control character")
    } else if value.trim().is_empty() {
        Some("is empty or whitespace-only")
    } else if !value.starts_with('/') {
        Some("must be an absolute path (start with '/')")
    } else {
        None
    }
}

/// The subset of [`sudo_command_defect`] that applies to a *template* string at
/// parse time, before any `{placeholder}` is filled. Only the
/// always-illegal-regardless-of-substitution defects (control chars, fully
/// empty) are checked; the absolute-path rule is deferred to the rendered
/// result because a placeholder-bearing template is not yet a concrete Cmnd.
fn sudo_command_static_defect(value: &str) -> Option<&'static str> {
    if value.chars().any(char::is_control) {
        Some("contains a control character")
    } else if value.trim().is_empty() {
        Some("is empty or whitespace-only")
    } else if !has_placeholder(value) && !value.starts_with('/') {
        // A template (has a placeholder) may legitimately not start with `/`
        // only if the placeholder is the leading segment — but Census authors
        // always write an absolute literal prefix, so a non-placeholder,
        // non-absolute value is still rejected here. The post-substitution gate
        // is the authoritative absolute-path check for templates.
        Some("must be an absolute path (start with '/')")
    } else {
        None
    }
}

/// Validate a file-grant path destined for `setfacl`/`getfacl` as root. Returns
/// the rejection reason, or `None` if the path is a fit absolute path.
///
/// The same threat shape as a sudo Cmnd, plus path-traversal: Census runs
/// `setfacl -R --physical -m u:<acct>:… <path>` as root, so a path with a control
/// char (an embedded newline could split an argv-built command in a future
/// shell-using context, and is meaningless in a real path), a non-absolute path
/// (we only ever operate on absolute targets), or a `..` component (a traversal
/// primitive that could point the recursive ACL mutation outside the intended
/// tree) is unfit. Empty is rejected too. This is the static gate applied to a
/// literal path at parse time *and* — via [`file_path_defect_substituted`] — to a
/// `{param}`-rendered path before it reaches root.
fn file_path_static_defect(path: &str) -> Option<&'static str> {
    if path.chars().any(char::is_control) {
        Some("contains a control character")
    } else if path.trim().is_empty() {
        Some("is empty or whitespace-only")
    } else if has_placeholder(path) {
        // A template path is validated AFTER substitution (the literal `{path}` is
        // not yet a concrete target). We still rejected control chars / empties
        // above; the absolute-path and `..` checks are deferred to the rendered
        // result so a placeholder that legitimately supplies the leading segment is
        // not wrongly rejected here. The post-substitution gate is authoritative.
        None
    } else if !path.starts_with('/') {
        Some("must be an absolute path (start with '/')")
    } else if has_dotdot_component(path) {
        Some("must not contain a `..` path component")
    } else {
        None
    }
}

/// The post-substitution file-path gate: the SAME rule a literal path passes, but
/// applied unconditionally (no placeholder escape) to a concrete rendered path.
/// A `{param}`-filled path that turns out non-absolute, control-bearing, or
/// `..`-bearing fails closed here before any root `setfacl`.
fn file_path_defect_substituted(path: &str) -> Option<&'static str> {
    if path.chars().any(char::is_control) {
        Some("contains a control character")
    } else if path.trim().is_empty() {
        Some("is empty or whitespace-only")
    } else if !path.starts_with('/') {
        Some("must be an absolute path (start with '/')")
    } else if has_dotdot_component(path) {
        Some("must not contain a `..` path component")
    } else {
        None
    }
}

/// Whether `path` has a `..` as a whole `/`-separated component. A literal `..`
/// inside a longer name (`a..b`) is not a traversal and is allowed; only the bare
/// `..` component is a climb-the-tree primitive.
fn has_dotdot_component(path: &str) -> bool {
    path.split('/').any(|c| c == "..")
}

/// The OS target a catalog is resolved against, and the source of the layer
/// chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsTarget {
    /// OS family — `linux` for every supported target today.
    pub family: String,
    /// Distribution id (`debian`, `ubuntu`, `astra`, or a raw unknown id).
    pub distro: String,
    /// Version id (`12`, `22.04`, `1.8`), if known.
    pub version: Option<String>,
}

impl OsTarget {
    /// Construct an explicit target (used by `--os-target`), validating every
    /// field as a safe path component.
    ///
    /// Returns [`CatalogError::InvalidName`] if any field would be unsafe to join
    /// onto a catalog root (separators, `..`, empty). This is the override path,
    /// equally attacker-influenced as `/etc/os-release`, so it gets the same
    /// gate.
    pub fn new(
        family: impl Into<String>,
        distro: impl Into<String>,
        version: Option<String>,
    ) -> Result<Self, CatalogError> {
        let family = family.into();
        let distro = distro.into();
        validate_path_component("os family", &family)?;
        validate_path_component("distro", &distro)?;
        if let Some(ver) = &version {
            validate_path_component("version", ver)?;
        }
        Ok(OsTarget {
            family,
            distro,
            version,
        })
    }

    /// The layer chain bottom→top:
    /// `["linux", "linux-<distro>", "linux-<distro>-<version>"]`.
    ///
    /// Each later element overrides the earlier. The base `family` layer holds
    /// the common definition; the distro layer specialises; the version layer
    /// adds the last mile. Version is omitted from the chain when unknown.
    pub fn layer_names(&self) -> Vec<String> {
        let mut chain = vec![self.family.clone()];
        chain.push(format!("{}-{}", self.family, self.distro));
        if let Some(ver) = &self.version {
            chain.push(format!("{}-{}-{}", self.family, self.distro, ver));
        }
        chain
    }

    /// Detect the target from `/etc/os-release`.
    pub fn detect() -> Result<OsTarget, CatalogError> {
        OsTarget::detect_from(Path::new("/etc/os-release"))
    }

    /// Detect the target from an `os-release`-format file at `path`.
    ///
    /// Reads `ID` and `VERSION_ID`; both may be quoted. Maps known ids to a
    /// canonical distro; an unknown id keeps its raw value as the distro so it
    /// still resolves against the `linux` base plus an optional
    /// `linux-<id>` layer.
    pub fn detect_from(path: &Path) -> Result<OsTarget, CatalogError> {
        let text = std::fs::read_to_string(path).map_err(|e| CatalogError::OsRelease {
            reason: format!("cannot read {}: {e}", path.display()),
        })?;

        let mut id: Option<String> = None;
        let mut version_id: Option<String> = None;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = unquote_os_release(value.trim());
            match key.trim() {
                "ID" => id = Some(value),
                "VERSION_ID" => version_id = Some(value),
                _ => {} // ID_LIKE and the rest are not consumed in slice 1.
            }
        }

        let id = id.ok_or_else(|| CatalogError::OsRelease {
            reason: format!("{} has no ID field", path.display()),
        })?;

        // Known-id mapping. Unknown ids fall through with the raw id as distro.
        let distro = match id.as_str() {
            "debian" => "debian",
            "ubuntu" => "ubuntu",
            "astra" | "astralinux" => "astra",
            other => other,
        }
        .to_owned();

        let version = version_id.filter(|v| !v.is_empty());

        // os-release is attacker-influenceable; a crafted `ID=../secret` or
        // `VERSION_ID=a/b` would otherwise become a path component joined onto the
        // catalog root and read+expanded as root. Validate before returning.
        if !is_safe_path_component(&distro) {
            return Err(CatalogError::OsRelease {
                reason: format!("{} has unsafe ID {distro:?}", path.display()),
            });
        }
        if let Some(ver) = &version {
            if !is_safe_path_component(ver) {
                return Err(CatalogError::OsRelease {
                    reason: format!("{} has unsafe VERSION_ID {ver:?}", path.display()),
                });
            }
        }

        Ok(OsTarget {
            family: "linux".to_owned(),
            distro,
            version,
        })
    }
}

/// Strip surrounding single or double quotes from an os-release value.
fn unquote_os_release(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}

/// A source of catalog policy records, abstracted so the resolver is pure and
/// tests can supply in-memory definitions without a filesystem.
pub trait CatalogSource {
    /// Read every top-level policy record present in `layer` (e.g. `linux-debian`).
    ///
    /// Returns one entry per record so the resolver can pick the id it wants.
    /// An absent layer is not an error — it yields an empty list (the chain may
    /// legitimately lack a distro or version layer).
    fn read_layer(&self, layer: &str) -> Result<Vec<PermissionDef>, CatalogError>;

    /// Whether the given layer is materially present in the catalog (a layer
    /// directory exists). Used to detect an unknown OS version: the version
    /// layer name is in the chain but no directory backs it.
    fn layer_present(&self, layer: &str) -> bool;

    /// Every definition across the whole layer chain for `os`, tagged with the
    /// layer it came from. Used to materialize `include_categories` (which must
    /// scan all layers + namespaces, not just the requested id's chain position)
    /// and to detect same-layer id collisions.
    ///
    /// The default walks `os.layer_names()` via [`read_layer`](CatalogSource::read_layer);
    /// a source backed by a filesystem may override for efficiency but the
    /// semantics must match.
    fn all_definitions(
        &self,
        os: &OsTarget,
    ) -> Result<Vec<(String, PermissionDef)>, CatalogError> {
        let mut out = Vec::new();
        for layer in os.layer_names() {
            for def in self.read_layer(&layer)? {
                out.push((layer.clone(), def));
            }
        }
        Ok(out)
    }
}

/// The namespace prefix of an id: the substring before the first `.`, or `None`
/// for a top-level (OS-primitive) id. `docker.ps` → `Some("docker")`.
fn namespace_of(id: &str) -> Option<&str> {
    id.split_once('.').map(|(ns, _)| ns)
}

/// Whether `name` is safe to use as a single filesystem path component.
///
/// OS-target fields (`family`/`distro`/`version`) and add-on namespaces all end
/// up joined onto catalog roots (`root.join(layer)`, `<layer>/<namespace>/`) and
/// the files there are parsed and expanded into sudo commands as root. An
/// attacker who controls `/etc/os-release` (`ID=../secret`) or a crafted id
/// (`../x.ps`) must not be able to redirect that read outside the catalog. We
/// allow only `[a-z0-9._-]+` and reject `.`/`..` as whole components, so a name
/// can never contain a separator or climb the tree. (Versions like `22.04` and
/// `1.8` are fine — a `.` inside the name is allowed, only the bare `.`/`..`
/// components are not.)
fn is_safe_path_component(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return false;
    }
    name.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
}

/// Validate a name destined to become a path component, returning a clear error
/// tagged with what it is. Centralized so every entry point (os-release detect,
/// explicit `OsTarget::new`, namespace derivation) enforces the same rule.
fn validate_path_component(kind: &'static str, value: &str) -> Result<(), CatalogError> {
    if is_safe_path_component(value) {
        Ok(())
    } else {
        Err(CatalogError::InvalidName {
            kind,
            value: value.to_owned(),
        })
    }
}

/// Production catalog source: reads a layer from `<root>/<layer>/` across roots
/// in precedence order (later roots override earlier — e.g. `/etc` over
/// `/usr/share`). A layer dir holds top-level `*.toml` (OS primitives) plus one
/// level of namespace subdirs `<root>/<layer>/<namespace>/*.toml` for add-on
/// packages of third-party software (`docker/ps.toml` → id `docker.ps`).
#[derive(Debug, Clone)]
pub struct LiveCatalog {
    /// Catalog roots in precedence order (lowest first).
    pub roots: Vec<PathBuf>,
}

impl LiveCatalog {
    /// Construct from roots in precedence order (lowest precedence first).
    pub fn new(roots: Vec<PathBuf>) -> Self {
        LiveCatalog { roots }
    }

    /// Read and parse one `*.toml` policy file, validating that its id's
    /// namespace matches the subdir it sits under.
    ///
    /// `subdir` is `None` for a top-level file (id must be top-level / no `.`)
    /// and `Some(ns)` for a namespace subdir (id's namespace must equal `ns`).
    /// The match is enforced at read time so a file misfiled under the wrong
    /// add-on dir (e.g. `docker.ps` placed under `k8s/`) is caught before it can
    /// expand into sudo commands, rather than silently resolving.
    fn read_policy_file(
        path: &Path,
        subdir: Option<&str>,
    ) -> Result<PermissionDef, CatalogError> {
        let text = std::fs::read_to_string(path).map_err(|e| CatalogError::Io {
            path: path.to_owned(),
            reason: e.to_string(),
        })?;
        let def: PermissionDef = toml::from_str(&text).map_err(|e| CatalogError::TomlParse {
            path: path.to_owned(),
            reason: e.to_string(),
        })?;
        def.validate()?;
        let id_ns = namespace_of(&def.id);
        match (subdir, id_ns) {
            // Top-level file with a top-level id: the OS-primitive reserve.
            (None, None) => {}
            // Namespaced file: id namespace must equal the subdir name. Validate
            // the id-derived namespace as a path component too — a crafted id
            // like `../x.ps` must never be honoured even if it somehow matched a
            // directory name.
            (Some(dir), Some(ns)) if dir == ns => {
                validate_path_component("namespace", ns)?;
            }
            // Anything else is a misfiled policy.
            _ => {
                return Err(CatalogError::TomlParse {
                    path: path.to_owned(),
                    reason: format!(
                        "id {:?} namespace does not match its location (subdir {:?})",
                        def.id, subdir
                    ),
                });
            }
        }
        Ok(def)
    }

    /// Read every policy file in a single `<root>/<layer>` dir (top-level +
    /// one namespace level), rejecting two files that claim the same id within
    /// this one layer dir as a collision.
    fn read_one_layer_dir(layer_dir: &Path) -> Result<Vec<PermissionDef>, CatalogError> {
        let mut out: Vec<PermissionDef> = Vec::new();
        let mut seen: Vec<String> = Vec::new();

        let mut push = |def: PermissionDef| -> Result<(), CatalogError> {
            // Same id from two distinct files in one layer dir is a collision.
            // (The same id on a different *layer* is the legitimate override
            // chain and is merged by the resolver, not seen here.)
            if seen.iter().any(|s| s == &def.id) {
                return Err(CatalogError::NamespaceCollision { id: def.id });
            }
            seen.push(def.id.clone());
            out.push(def);
            Ok(())
        };

        for entry in std::fs::read_dir(layer_dir).map_err(|e| CatalogError::Io {
            path: layer_dir.to_owned(),
            reason: e.to_string(),
        })? {
            let entry = entry.map_err(|e| CatalogError::Io {
                path: layer_dir.to_owned(),
                reason: e.to_string(),
            })?;
            let path = entry.path();
            // Skip symlinked entries. As root, a symlink planted in a catalog dir
            // would otherwise let `is_dir()`/`is_file()` follow it and read+expand
            // an out-of-tree `*.toml` into sudo. `is_symlink` uses
            // `symlink_metadata` (does not follow), so a symlink is detected and
            // ignored regardless of where it points.
            if path.is_symlink() {
                continue;
            }
            if path.is_dir() {
                // One namespace level: <layer>/<namespace>/*.toml.
                let ns = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default()
                    .to_owned();
                for sub in std::fs::read_dir(&path).map_err(|e| CatalogError::Io {
                    path: path.clone(),
                    reason: e.to_string(),
                })? {
                    let sub = sub.map_err(|e| CatalogError::Io {
                        path: path.clone(),
                        reason: e.to_string(),
                    })?;
                    let sub_path = sub.path();
                    // Same symlink guard one level down (namespace subdir files).
                    if sub_path.is_symlink() {
                        continue;
                    }
                    if sub_path.is_file()
                        && sub_path.extension().and_then(|e| e.to_str()) == Some("toml")
                    {
                        push(Self::read_policy_file(&sub_path, Some(&ns))?)?;
                    }
                }
            } else if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("toml") {
                push(Self::read_policy_file(&path, None)?)?;
            }
        }
        Ok(out)
    }
}

impl CatalogSource for LiveCatalog {
    fn read_layer(&self, layer: &str) -> Result<Vec<PermissionDef>, CatalogError> {
        let mut out = Vec::new();
        for root in &self.roots {
            let layer_dir = root.join(layer);
            if !layer_dir.is_dir() {
                continue;
            }
            out.extend(Self::read_one_layer_dir(&layer_dir)?);
        }
        Ok(out)
    }

    fn layer_present(&self, layer: &str) -> bool {
        self.roots.iter().any(|root| root.join(layer).is_dir())
    }
}

/// In-memory catalog source for tests: `(layer_name, def)` pairs.
#[derive(Debug, Clone, Default)]
pub struct FakeCatalog {
    entries: Vec<(String, PermissionDef)>,
    /// Layers that are present even if they hold no records (so an "unknown
    /// version" can be distinguished from "version layer exists but empty").
    present_layers: Vec<String>,
}

impl FakeCatalog {
    /// Empty catalog.
    pub fn new() -> Self {
        FakeCatalog::default()
    }

    /// Add a record at the given layer. The layer is marked present.
    pub fn with(mut self, layer: &str, def: PermissionDef) -> Self {
        if !self.present_layers.iter().any(|l| l == layer) {
            self.present_layers.push(layer.to_owned());
        }
        self.entries.push((layer.to_owned(), def));
        self
    }

    /// Mark a layer present without adding any record (an empty-but-existing
    /// layer dir).
    pub fn with_empty_layer(mut self, layer: &str) -> Self {
        if !self.present_layers.iter().any(|l| l == layer) {
            self.present_layers.push(layer.to_owned());
        }
        self
    }
}

impl CatalogSource for FakeCatalog {
    fn read_layer(&self, layer: &str) -> Result<Vec<PermissionDef>, CatalogError> {
        let mut out: Vec<PermissionDef> = Vec::new();
        for (_, def) in self.entries.iter().filter(|(l, _)| l == layer) {
            // Mirror LiveCatalog: validate each record at the read boundary so an
            // in-memory test source enforces the same record invariants the file
            // source does.
            def.validate()?;
            // Two records with the same id on one layer is a collision (distinct
            // sources claiming the same id), distinct from the same id on
            // different layers (the override chain).
            if out.iter().any(|d| d.id == def.id) {
                return Err(CatalogError::NamespaceCollision { id: def.id.clone() });
            }
            out.push(def.clone());
        }
        Ok(out)
    }

    fn layer_present(&self, layer: &str) -> bool {
        self.present_layers.iter().any(|l| l == layer)
    }
}

/// A resolve-time warning surfaced as data (not printed). Later slices route
/// these to lint; slice 1 must not drop the signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// The OS version had no layer of its own; resolved against the nearest
    /// lower layer instead of silently treating it as the latest.
    UnknownOsVersion {
        /// The version-layer name that was expected but absent.
        missing_layer: String,
        /// The lower layer the resolve fell back to.
        resolved_against: String,
    },
    /// A role supplied a parameter that no placeholder in the resolved
    /// permission's templates consumes. Not an error (a forward-compatible role
    /// may carry a param a newer catalog will use), but surfaced so a typo'd
    /// param name — which would otherwise silently fail to narrow/fill anything —
    /// is not lost.
    UnusedParam {
        /// The permission the unused parameter was supplied to.
        permission: String,
        /// The parameter name that matched no placeholder.
        param: String,
    },
}

/// A primitive together with the catalog layer that contributed it.
///
/// Provenance is tracked *per primitive* (not per permission) because a single
/// permission's groups/sudo can come from different layers (base states most,
/// version layer appends one), and later slices (`compile`) must show the exact
/// source layer of every command for trust/audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcedPrimitive {
    /// The primitive value (a group name or a sudo command).
    pub value: String,
    /// The catalog layer that contributed it.
    pub layer: String,
    /// When this primitive reached the result *through a bundle*, the id of the
    /// member permission that actually declared it. `None` for primitives the
    /// resolved permission declares itself (leaf resolve always sets `None`).
    /// Audit needs to show not just which layer a sudo command came from, but
    /// which permission inside an aggregate pulled it in.
    pub via: Option<String>,
}

/// A file-access grant after resolve: its path, access, recursion, derived
/// [`Shape`], and the per-grant provenance (which layers — and, through a bundle,
/// which member — contributed it). Grants on the same path are unioned across
/// layers/members: access widens to the max (`Ro` < `Rw`), `recursive` is the OR,
/// and provenance accumulates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFileGrant {
    /// Absolute path (literal, already `{param}`-substituted if it was templated).
    pub path: String,
    /// Effective access (the max over every contributing grant on this path).
    pub access: Access,
    /// Effective recursion (the OR over every contributing grant on this path).
    pub recursive: bool,
    /// Structural form, derived from the path + effective `recursive` flag. Selects
    /// the backend capability that must cover this grant.
    pub shape: Shape,
    /// Every layer (and bundle member, via) that contributed to this grant.
    pub sources: Vec<SourcedFileGrant>,
}

/// Provenance of a single contributing file-grant: the layer that stated it and,
/// when it reached the result through a bundle, the member id that declared it.
/// Per-grant (not per-permission) because a permission's file grants can come from
/// different layers, and audit must show the exact source of each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcedFileGrant {
    /// The catalog layer that contributed this grant.
    pub layer: String,
    /// The member permission id that pulled it in via a bundle, or `None` for a
    /// grant the resolved permission declares itself (leaf resolve sets `None`).
    pub via: Option<String>,
}

/// A fully-resolved single permission: primitives with per-primitive provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPermission {
    /// The permission id.
    pub id: String,
    /// Risk class, if any layer set one (topmost setter wins).
    pub risk: Option<Risk>,
    /// Group memberships, each tagged with its source layer.
    pub groups: Vec<SourcedPrimitive>,
    /// Sudo commands, each tagged with its source layer.
    pub sudo: Vec<SourcedPrimitive>,
    /// File-access grants, unioned by path with per-grant provenance.
    pub file_grants: Vec<ResolvedFileGrant>,
    /// Resource limits, if any layer set them.
    pub limits: Option<Limits>,
    /// The layer that contributed `limits`, if any.
    pub limits_layer: Option<String>,
    /// Per-category materialization captured at resolve time:
    /// `(category, [resolved member ids])`. Empty for a leaf or a bundle that
    /// uses only explicit `includes`. Captured point-in-time so a later catalog
    /// that adds a member to the category does not silently widen an already
    /// compiled role (the resolved list, not the wildcard, is what gets signed).
    pub category_members: Vec<(String, Vec<String>)>,
    /// The catalog version this permission was resolved against, from
    /// [`ResolveCtx`]. Recorded so a later catalog that grows a category cannot
    /// retro-widen this already-compiled (and, managed, signed) result: the
    /// captured `category_members` are bound to this version. `None` for a bare
    /// leaf resolve (no `ctx`).
    pub resolved_catalog_version: Option<String>,
}

/// Errors compiling/resolving the catalog.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    /// No layer in the chain defines the requested id.
    #[error("unknown permission {0}")]
    UnknownPermission(String),
    /// An `includes`/`include_categories` graph contains a cycle. The vector is
    /// the path that closes the loop (`a -> b -> a`), so the diagnostic points at
    /// the actual offending chain rather than just naming one id.
    #[error("permission include cycle: {}", .0.join(" -> "))]
    Cycle(Vec<String>),
    /// Two distinct catalog files claim the same id within one layer. The same id
    /// reappearing on a *different* layer is the legitimate override chain, not a
    /// collision — only a same-layer duplicate is rejected here.
    #[error("permission id {id} defined by two sources in one layer")]
    NamespaceCollision {
        /// The colliding id.
        id: String,
    },
    /// A bundle explicitly declares a `risk` lower than the maximum risk of its
    /// members. Honest labelling: an aggregate must not under-state the worst
    /// capability it pulls in.
    #[error("bundle {id} declares risk {declared:?} below its members' computed risk {computed:?}")]
    LoweredBundleRisk {
        /// The bundle id.
        id: String,
        /// The risk the bundle declared.
        declared: Risk,
        /// The risk computed as the max over members.
        computed: Risk,
    },
    /// A catalog file could not be read.
    #[error("cannot read catalog path {path}: {reason}")]
    Io {
        /// The path that failed.
        path: PathBuf,
        /// Underlying reason.
        reason: String,
    },
    /// A catalog file's TOML was malformed or violated the strict schema.
    #[error("catalog file {path} TOML is invalid: {reason}")]
    TomlParse {
        /// The path that failed.
        path: PathBuf,
        /// Underlying reason.
        reason: String,
    },
    /// A name that becomes a filesystem path component (OS-target field or
    /// namespace) contains characters that could escape the catalog root. These
    /// names are joined onto catalog roots and read+expanded into sudo as root,
    /// so an unsanitised `../secret` or `a/b` is a path-traversal primitive.
    #[error("invalid {kind} name {value:?}: must match [a-z0-9._-]+ and not be a path component")]
    InvalidName {
        /// What the name is (e.g. `os family`, `distro`, `version`, `namespace`).
        kind: &'static str,
        /// The rejected value.
        value: String,
    },
    /// `/etc/os-release` could not be read or lacked required fields.
    #[error("cannot determine OS target: {reason}")]
    OsRelease {
        /// Underlying reason.
        reason: String,
    },
    /// A record combines mutually-exclusive directives (e.g. `replace = true`
    /// together with an `.append` list) whose combined meaning is almost certainly
    /// not what the author intended. Fail closed rather than expand the surprising
    /// interpretation into root sudo.
    #[error("contradictory catalog record {id}: {reason}")]
    ContradictoryRecord {
        /// The offending permission id.
        id: String,
        /// What is contradictory.
        reason: String,
    },
    /// A `sudo` command value is unfit to render into a sudoers rule. Census
    /// emits each sudo string into `/etc/sudoers.d/census-*` as root, so a value
    /// containing a control char (a newline would split the rule into a second
    /// physical directive line), an empty/whitespace-only value, or a
    /// non-absolute command (Census only emits concrete absolute-path Cmnds) is
    /// rejected at the read boundary — it never reaches root materialization.
    #[error("invalid sudo command {value:?} in permission {id}: {reason}")]
    InvalidSudoCommand {
        /// The permission id carrying the bad value.
        id: String,
        /// The rejected sudo command value.
        value: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A `[[file]]` grant path is unfit to materialize into a root `setfacl`
    /// target. Census runs `setfacl -R --physical` on this path as root, so a
    /// non-absolute path, a `..` component (a traversal that could point the
    /// recursive ACL mutation outside the intended tree), a control char, or an
    /// empty value is rejected at the read boundary — before root materialization.
    #[error("invalid file path {path:?} in permission {id}: {reason}")]
    InvalidFilePath {
        /// The permission id carrying the bad path.
        id: String,
        /// The rejected file path.
        path: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A permission template carries a `{placeholder}` for which the referencing
    /// role supplied no matching parameter. Fail-closed: an unfilled placeholder
    /// must NOT render literally into a sudoers rule (a literal `{unit}` Cmnd is
    /// nonsense at best and a silent grant gap at worst), so resolution is
    /// rejected rather than emitting the unrendered template.
    #[error("permission {permission}: template placeholder {{{placeholder}}} has no matching parameter")]
    MissingParam {
        /// The permission id whose template could not be filled.
        permission: String,
        /// The placeholder name that had no parameter.
        placeholder: String,
    },
    /// A parameter value supplied by a role is unfit to substitute into a
    /// permission template. Param values come from the declaration side and are
    /// spliced into strings that become root sudoers Cmnds, so a value carrying a
    /// comma, whitespace, a control char, or other shell/sudoers metacharacter
    /// could split one Cmnd into several or inject a directive. Such values are
    /// rejected before substitution; the rendered result is independently
    /// re-validated by the post-substitution sudo gate as defence in depth.
    #[error("permission {permission}: parameter {param} value {value:?} is invalid: {reason}")]
    InvalidParamValue {
        /// The permission whose template was being filled.
        permission: String,
        /// The parameter whose value was rejected.
        param: String,
        /// The rejected value.
        value: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A single permission template references more than one *list*-valued
    /// parameter. Census expands a list param by emitting one rendered command
    /// per element; two independent lists would require a cartesian product whose
    /// intent (and blast radius) is rarely what an author means. Kept simple and
    /// explicit: at most one list param per permission expansion, rejected here
    /// rather than silently multiplying grants.
    #[error("permission {permission}: more than one list-valued parameter ({first}, {second}); at most one list param is supported per permission")]
    MultipleListParams {
        /// The permission being expanded.
        permission: String,
        /// The first list param seen.
        first: String,
        /// The second list param that triggered the error.
        second: String,
    },
    /// Bundle expansion recursed deeper than [`MAX_INCLUDE_DEPTH`]. The cycle
    /// detector already terminates on looping include graphs; this guards the
    /// remaining case of a pathologically long *acyclic* include chain, which
    /// would otherwise grow the native stack one frame per level and risk a
    /// stack overflow before any cycle could be found. The bound is generous
    /// enough that no legitimate catalog reaches it.
    #[error("permission {id} include chain exceeds maximum depth {depth}")]
    IncludeTooDeep {
        /// The id being expanded when the limit was hit.
        id: String,
        /// The depth at which expansion was refused.
        depth: usize,
    },
}

/// Maximum number of nested bundle includes expanded from a single root before
/// resolution is refused with [`CatalogError::IncludeTooDeep`]. Deliberately
/// generous: real catalogs nest only a handful of levels, so any chain this
/// long is an accident or an attack, not a legitimate composition.
const MAX_INCLUDE_DEPTH: usize = 64;

/// Resolve a single permission id against the OS layer chain, bottom→top.
///
/// Each layer's `PermissionDef` for the same id is merged field-by-field:
/// a bare list field on a higher layer **replaces** the accumulated list, an
/// `.append` form **adds** to it, and `replace = true` on a layer wipes
/// everything accumulated so far and takes that layer wholesale. Risk is taken
/// from the topmost layer that sets it. Provenance is recorded per primitive.
///
/// An unknown OS version (the version layer name is in the chain but no
/// directory backs it) resolves against the nearest lower present layer and
/// surfaces a [`Warning::UnknownOsVersion`] rather than dropping the signal.
///
/// Returns the resolved permission and any warnings accumulated.
pub fn resolve_leaf(
    id: &str,
    os: &OsTarget,
    catalog: &dyn CatalogSource,
) -> Result<(ResolvedPermission, Vec<Warning>), CatalogError> {
    let mut warnings = Vec::new();
    let chain = os.layer_names();

    // Detect an unknown OS version: the version layer (top of chain when a
    // version is set) is named but not present. We still walk the lower layers;
    // the absent layer simply contributes nothing, which is exactly "resolve
    // against the nearest lower layer".
    if os.version.is_some() {
        if let Some(version_layer) = chain.last() {
            if !catalog.layer_present(version_layer) {
                // Nearest lower present layer for the message (distro, else family).
                let fallback = chain
                    .iter()
                    .rev()
                    .skip(1)
                    .find(|l| catalog.layer_present(l))
                    .cloned()
                    .unwrap_or_else(|| os.family.clone());
                warnings.push(Warning::UnknownOsVersion {
                    missing_layer: version_layer.clone(),
                    resolved_against: fallback,
                });
            }
        }
    }

    let mut groups: Vec<SourcedPrimitive> = Vec::new();
    let mut sudo: Vec<SourcedPrimitive> = Vec::new();
    // File grants accumulate per layer as (grant, contributing layer) before the
    // by-path union. They follow the SAME `replace=true` wipe semantics as the
    // list primitives: a full-override layer drops everything lower layers
    // contributed. Across non-replacing layers grants simply accumulate (then
    // union below), since file grants have no per-grant bare-vs-append distinction.
    let mut raw_files: Vec<(FileGrant, String)> = Vec::new();
    let mut risk: Option<Risk> = None;
    let mut limits: Option<Limits> = None;
    let mut limits_layer: Option<String> = None;
    let mut found = false;

    for layer in &chain {
        let defs = catalog.read_layer(layer)?;
        let Some(def) = defs.into_iter().find(|d| d.id == id) else {
            continue;
        };
        found = true;

        // A full-override layer wipes accumulated primitives before applying.
        if def.replace {
            groups.clear();
            sudo.clear();
            raw_files.clear();
            limits = None;
            limits_layer = None;
        }

        apply_list_override(&mut groups, &def.groups, layer, None);
        apply_list_override(&mut sudo, &def.sudo, layer, None);
        for grant in def.files {
            raw_files.push((grant, layer.clone()));
        }

        if let Some(r) = def.risk {
            risk = Some(r); // topmost setter wins
        }
        if let Some(l) = def.limits {
            limits = Some(l.into());
            limits_layer = Some(layer.clone());
        }
    }

    if !found {
        return Err(CatalogError::UnknownPermission(id.to_owned()));
    }

    let file_grants = union_file_grants(raw_files, None);

    Ok((
        ResolvedPermission {
            id: id.to_owned(),
            risk,
            groups,
            sudo,
            file_grants,
            limits,
            limits_layer,
            category_members: Vec::new(),
            resolved_catalog_version: None,
        },
        warnings,
    ))
}

/// Union raw `(FileGrant, layer)` pairs into [`ResolvedFileGrant`]s keyed by path.
///
/// Grants on the same `path` merge: access widens to the max (`Ro` < `Rw`),
/// `recursive` is the OR, and every contributing layer/member is recorded in
/// `sources`. Path order is the first-seen order so the resolved list is stable.
/// `shape` is derived from the path plus the *effective* (OR'd) `recursive` flag,
/// so a path stated once as a file and once as recursive resolves to a directory.
/// `via` tags the bundle member that pulled grants in (`None` for a leaf).
fn union_file_grants(raw: Vec<(FileGrant, String)>, via: Option<&str>) -> Vec<ResolvedFileGrant> {
    let mut out: Vec<ResolvedFileGrant> = Vec::new();
    for (grant, layer) in raw {
        let source = SourcedFileGrant {
            layer,
            via: via.map(str::to_owned),
        };
        if let Some(existing) = out.iter_mut().find(|g| g.path == grant.path) {
            existing.access = existing.access.max(grant.access);
            existing.recursive = existing.recursive || grant.recursive;
            // Recompute the derived shape against the now-effective recursive flag.
            existing.shape = FileGrant {
                path: existing.path.clone(),
                access: existing.access,
                recursive: existing.recursive,
            }
            .shape();
            existing.sources.push(source);
        } else {
            out.push(ResolvedFileGrant {
                path: grant.path.clone(),
                access: grant.access,
                recursive: grant.recursive,
                shape: grant.shape(),
                sources: vec![source],
            });
        }
    }
    out
}

/// Union already-resolved file grants from several permissions into one set,
/// keyed by path — the SAME merge rule the in-permission resolve uses (access
/// widens to the max, `recursive` is the OR, `shape` is recomputed against the
/// effective recursive flag, and every contributing grant's `sources` are
/// concatenated). Used by [`crate::model::resolve`] to combine the file grants
/// of all the permissions a single role-account carries; a role declaring two
/// permissions that both grant the same path must end up with one widened grant,
/// not two. Path order is first-seen so the result is stable.
pub fn union_resolved_file_grants(
    grants: impl IntoIterator<Item = ResolvedFileGrant>,
) -> Vec<ResolvedFileGrant> {
    let mut out: Vec<ResolvedFileGrant> = Vec::new();
    for grant in grants {
        if let Some(existing) = out.iter_mut().find(|g| g.path == grant.path) {
            existing.access = existing.access.max(grant.access);
            existing.recursive = existing.recursive || grant.recursive;
            existing.shape = FileGrant {
                path: existing.path.clone(),
                access: existing.access,
                recursive: existing.recursive,
            }
            .shape();
            existing.sources.extend(grant.sources);
        } else {
            out.push(grant);
        }
    }
    out
}

/// Apply a [`ListOverride`] from `layer` onto an accumulator, tagging each new
/// primitive with its source layer and (for bundle members) the contributing
/// permission id `via`.
fn apply_list_override(
    acc: &mut Vec<SourcedPrimitive>,
    ov: &ListOverride,
    layer: &str,
    via: Option<&str>,
) {
    match ov {
        ListOverride::Replace(values) => {
            acc.clear();
            for v in values {
                acc.push(SourcedPrimitive {
                    value: v.clone(),
                    layer: layer.to_owned(),
                    via: via.map(str::to_owned),
                });
            }
        }
        ListOverride::Append(values) => {
            for v in values {
                acc.push(SourcedPrimitive {
                    value: v.clone(),
                    layer: layer.to_owned(),
                    via: via.map(str::to_owned),
                });
            }
        }
    }
}

/// Context threaded through a bundle resolve.
///
/// `catalog_version` is the version the catalog was read at; it is recorded
/// alongside the materialized `include_categories` membership so a later catalog
/// that adds a member to a category does not silently widen an already-compiled
/// (and, in managed mode, signed) role. The concrete member list — not the
/// wildcard — is what later slices persist and sign.
#[derive(Debug, Clone, Default)]
pub struct ResolveCtx {
    /// The catalog version this resolve materializes against, if known.
    pub catalog_version: Option<String>,
}

/// The aggregation lists (`includes`, `include_categories`) for `id`, unioned
/// across every layer that states the id. A leaf yields two empty lists.
///
/// Slice-1 leaf resolve does not surface these, so we read the chain again here.
/// Unioned (not topmost-wins) because a higher layer typically *extends* a
/// bundle's membership rather than restating it; order is preserved and dups are
/// dropped so the resolved member set is stable.
fn aggregation_for(
    id: &str,
    chain: &[String],
    catalog: &dyn CatalogSource,
) -> Result<(Vec<String>, Vec<String>), CatalogError> {
    let mut includes: Vec<String> = Vec::new();
    let mut categories: Vec<String> = Vec::new();
    for layer in chain {
        for def in catalog.read_layer(layer)? {
            if def.id != id {
                continue;
            }
            for inc in def.includes {
                if !includes.contains(&inc) {
                    includes.push(inc);
                }
            }
            for cat in def.include_categories {
                if !categories.contains(&cat) {
                    categories.push(cat);
                }
            }
        }
    }
    Ok((includes, categories))
}

/// Resolve a permission that may be a *bundle* (carries `includes` /
/// `include_categories`) into the union of its members' primitives plus its own.
///
/// A leaf (no aggregation) behaves exactly like [`resolve_leaf`]. A bundle is
/// expanded transitively (a bundle may include a bundle); a cycle in the include
/// graph is rejected as [`CatalogError::Cycle`]. `include_categories` is
/// materialized point-in-time against `ctx.catalog_version`: every id whose
/// `category` matches, across all layers and namespaces, is pulled in as if
/// listed in `includes`, and the resolved member list is captured in
/// [`ResolvedPermission::category_members`].
///
/// Bundle risk is the max over members (with the bundle's own declared risk):
/// any `escalation-capable` member makes the bundle `escalation-capable`. A
/// member with undeclared risk (`None`) is treated as unknown and does not lower
/// the max. A bundle that explicitly declares a risk *below* the computed max is
/// rejected as [`CatalogError::LoweredBundleRisk`]; equal or higher is allowed.
pub fn resolve(
    id: &str,
    os: &OsTarget,
    catalog: &dyn CatalogSource,
    ctx: &ResolveCtx,
) -> Result<(ResolvedPermission, Vec<Warning>), CatalogError> {
    let mut path = Vec::new();
    resolve_inner(id, os, catalog, ctx, &mut path)
}

/// Inner bundle resolve carrying the visiting `path` (the chain of ids currently
/// being expanded) for cycle detection: if `id` is already on the path, the
/// include graph loops back and we report the closing path.
fn resolve_inner(
    id: &str,
    os: &OsTarget,
    catalog: &dyn CatalogSource,
    ctx: &ResolveCtx,
    path: &mut Vec<String>,
) -> Result<(ResolvedPermission, Vec<Warning>), CatalogError> {
    // Cycle detection: a path stack is enough — an id reappearing while still
    // being expanded means the include graph closed a loop. Report the path from
    // the first occurrence so the diagnostic shows the actual cycle.
    if let Some(start) = path.iter().position(|p| p == id) {
        let mut cycle: Vec<String> = path[start..].to_vec();
        cycle.push(id.to_owned());
        return Err(CatalogError::Cycle(cycle));
    }

    // Depth bound: the cycle check above terminates on looping graphs, but an
    // acyclic chain of distinct ids (a -> b -> c -> …) still recurses one native
    // frame per level. The path stack's current length is exactly the number of
    // bundles open above this one, so refuse before adding another frame once the
    // chain grows past a generous bound — turning a would-be stack overflow into
    // a clean, reportable error.
    if path.len() >= MAX_INCLUDE_DEPTH {
        return Err(CatalogError::IncludeTooDeep {
            id: id.to_owned(),
            depth: path.len(),
        });
    }

    let chain = os.layer_names();
    let (includes, include_categories) = aggregation_for(id, &chain, catalog)?;

    // Leaf fast path: no aggregation, behave exactly like resolve_leaf — but
    // stamp the catalog version so a leaf reached through resolve() still records
    // what it was compiled against.
    if includes.is_empty() && include_categories.is_empty() {
        let (mut resolved, warnings) = resolve_leaf(id, os, catalog)?;
        resolved.resolved_catalog_version = ctx.catalog_version.clone();
        return Ok((resolved, warnings));
    }

    path.push(id.to_owned());

    // The bundle's OWN primitives/risk/limits (a bundle may carry its own).
    let (own, mut warnings) = resolve_leaf(id, os, catalog)?;
    let mut groups = own.groups;
    let mut sudo = own.sudo;
    let mut file_grants = own.file_grants;
    let mut limits = own.limits;
    let mut limits_layer = own.limits_layer;
    let declared_risk = own.risk;

    // Materialize include_categories against the catalog as read now: enumerate
    // every id of each category across all layers/namespaces and treat them as
    // explicit includes. The resolved id list is captured so later catalog
    // growth cannot retro-widen this already-resolved bundle.
    let all = catalog.all_definitions(os)?;
    let mut category_members: Vec<(String, Vec<String>)> = Vec::new();
    let mut materialized: Vec<String> = Vec::new();
    for cat in &include_categories {
        let mut members: Vec<String> = Vec::new();
        for (_, def) in &all {
            if def.category.as_deref() == Some(cat.as_str()) && !members.contains(&def.id) {
                members.push(def.id.clone());
            }
        }
        for m in &members {
            if !materialized.contains(m) {
                materialized.push(m.clone());
            }
        }
        category_members.push((cat.clone(), members));
    }

    // Explicit includes first, then category-materialized members. Dedup so a
    // member named both explicitly and via a category is expanded once.
    let mut members: Vec<String> = Vec::new();
    for m in includes.iter().chain(materialized.iter()) {
        if !members.contains(m) {
            members.push(m.clone());
        }
    }

    // Bundle risk is the max over members. An undeclared (`None`) member risk is
    // *not* folded to `Contained` — that would let an unlabelled escalation-capable
    // member hide inside a bundle and silently understate it (the very thing
    // LoweredBundleRisk guards). Unknown is treated conservatively as the highest
    // risk: any member without a declared risk forces the computed bundle risk to
    // `EscalationCapable`. The labeller's fix is to declare the member's real
    // risk; until then the aggregate refuses to claim it is contained.
    let mut max_known_risk: Option<Risk> = None;
    let mut any_member_unknown = false;
    for member in &members {
        let (resolved, member_warnings) = resolve_inner(member, os, catalog, ctx, path)?;
        warnings.extend(member_warnings);

        match resolved.risk {
            Some(r) => {
                max_known_risk = Some(match max_known_risk {
                    Some(acc) => acc.max(r),
                    None => r,
                });
            }
            None => any_member_unknown = true,
        }

        // Union member primitives, tagging each with the member id that pulled
        // it in (via). The member's own primitives may already carry a deeper
        // `via` (member is itself a bundle); keep the nearest contributing id so
        // provenance points at the member this bundle directly references.
        union_member_primitives(&mut groups, resolved.groups, member);
        union_member_primitives(&mut sudo, resolved.sudo, member);
        union_member_file_grants(&mut file_grants, resolved.file_grants, member);

        // A member's limits fill in only if the bundle (and earlier members) set
        // none — explicit bundle/own limits win over inherited ones.
        if limits.is_none() {
            if let Some(l) = resolved.limits {
                limits = Some(l);
                limits_layer = resolved.limits_layer;
            }
        }
    }

    path.pop();

    // Fold "unknown" conservatively to the highest risk. So the computed
    // member-risk floor is: EscalationCapable if any member was unlabelled, else
    // the max of the known member risks (None only when there were no members
    // with any risk and none were unknown — i.e. a bundle of fully-contained-or-
    // unlabelled members reduces to its known max).
    let computed_member_risk: Option<Risk> = if any_member_unknown {
        Some(Risk::EscalationCapable)
    } else {
        max_known_risk
    };

    // Bundle risk = max(declared, computed-from-members). A declared risk below
    // the computed floor under-states the aggregate and is rejected — including
    // the case where the floor is raised by an unlabelled member.
    if let (Some(declared), Some(computed)) = (declared_risk, computed_member_risk) {
        if declared.rank() < computed.rank() {
            return Err(CatalogError::LoweredBundleRisk {
                id: id.to_owned(),
                declared,
                computed,
            });
        }
    }
    let risk = match (declared_risk, computed_member_risk) {
        (Some(d), Some(c)) => Some(d.max(c)),
        (Some(d), None) => Some(d),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    };

    Ok((
        ResolvedPermission {
            id: id.to_owned(),
            risk,
            groups,
            sudo,
            file_grants,
            limits,
            limits_layer,
            category_members,
            resolved_catalog_version: ctx.catalog_version.clone(),
        },
        warnings,
    ))
}

/// Union a member's resolved file grants into the bundle accumulator, merging by
/// path (access = max, recursive = OR, shape recomputed) and recording the member
/// id that pulled each grant in via `via`.
///
/// Mirrors [`union_file_grants`] but operates on already-resolved member grants,
/// re-tagging provenance with the directly-referenced member so audit shows which
/// member this aggregate names — paralleling [`union_member_primitives`].
fn union_member_file_grants(
    acc: &mut Vec<ResolvedFileGrant>,
    members: Vec<ResolvedFileGrant>,
    via: &str,
) {
    for grant in members {
        if let Some(existing) = acc.iter_mut().find(|g| g.path == grant.path) {
            existing.access = existing.access.max(grant.access);
            existing.recursive = existing.recursive || grant.recursive;
            existing.shape = FileGrant {
                path: existing.path.clone(),
                access: existing.access,
                recursive: existing.recursive,
            }
            .shape();
            // Re-tag each contributing source with the member id this bundle
            // directly references (the nearest provenance), as primitives do.
            for mut src in grant.sources {
                src.via = Some(via.to_owned());
                existing.sources.push(src);
            }
        } else {
            let mut grant = grant;
            for src in &mut grant.sources {
                src.via = Some(via.to_owned());
            }
            acc.push(grant);
        }
    }
}

/// Union a member's primitives into the accumulator, deduping by value and
/// tagging each new entry with the member id that contributed it.
///
/// Dedup is by primitive *value*: the same group/sudo command is one capability
/// regardless of how many members pull it in; the first contributor's provenance
/// is kept. `via` is set to the directly-referenced member (overwriting any
/// deeper bundle provenance) so audit shows the member this aggregate names.
fn union_member_primitives(
    acc: &mut Vec<SourcedPrimitive>,
    members: Vec<SourcedPrimitive>,
    via: &str,
) {
    for mut p in members {
        if acc.iter().any(|e| e.value == p.value) {
            continue;
        }
        p.via = Some(via.to_owned());
        acc.push(p);
    }
}

// --- parametrized templating (slice 3b) -------------------------------------
//
// A catalog `PermissionDef`'s `sudo`/`groups` strings may carry `{name}`
// placeholders that a referencing role fills via `PermissionRef.params`. The
// substitution rule, fixed and documented here so authors and the engine agree:
//
//   * Placeholder `{X}` is filled by the param keyed exactly `X` (literal name
//     match — no singular/plural inference; if the placeholder is `{unit}` the
//     param key must be `unit`, if `{units}` then `units`).
//   * A SCALAR param (string/int/bool/float) substitutes once.
//   * A LIST param emits one rendered copy of the template per element, each
//     element spliced into that placeholder. At most ONE list param may
//     participate in a single permission expansion (see `MultipleListParams`) —
//     the engine never invents a cartesian product.
//   * A placeholder with no matching param is a hard error (`MissingParam`):
//     an unfilled `{X}` must never reach a sudoers Cmnd literally.
//   * A param with no matching placeholder is a `Warning::UnusedParam`.
//
// The dual `{unit}` / `{unit}.service` Cmnd forms a service-restart record needs
// are written explicitly by the catalog author as separate template strings; the
// engine is a generic substitutor and does NOT synthesise alternative forms —
// sudoers matches argv exactly, so the author owns which concrete forms exist.

/// Does `s` contain at least one `{name}` placeholder?
fn has_placeholder(s: &str) -> bool {
    extract_placeholders(s).next().is_some()
}

/// Iterate the placeholder names in `s` (the text between matched `{` and `}`),
/// in order. A `{` with no closing `}` yields nothing for that fragment; nested
/// braces are not supported (placeholder names are `[a-zA-Z0-9_-]`-ish role
/// param keys, never themselves containing braces).
fn extract_placeholders(s: &str) -> impl Iterator<Item = &str> {
    let mut rest = s;
    std::iter::from_fn(move || {
        loop {
            let open = rest.find('{')?;
            let after = &rest[open + 1..];
            let close_rel = after.find('}')?;
            let name = &after[..close_rel];
            rest = &after[close_rel + 1..];
            if !name.is_empty() {
                return Some(name);
            }
            // Skip an empty `{}` and keep scanning.
        }
    })
}

/// Render `template`, replacing every `{name}` with `value`. Only the named
/// placeholder is touched; other placeholders are left intact (a later
/// substitution pass — or the MissingParam check — handles them).
fn substitute_one(template: &str, name: &str, value: &str) -> String {
    template.replace(&format!("{{{name}}}"), value)
}

/// Render a scalar `toml::Value` to the string that goes into a Cmnd. Only the
/// scalar kinds a role would sensibly pass as a parameter are accepted; arrays
/// and tables are not scalars (a list is handled by the per-element path, a
/// table has no string rendering). Returns `None` for non-scalars.
fn scalar_param_string(v: &toml::Value) -> Option<String> {
    match v {
        toml::Value::String(s) => Some(s.clone()),
        toml::Value::Integer(i) => Some(i.to_string()),
        toml::Value::Float(f) => Some(f.to_string()),
        toml::Value::Boolean(b) => Some(b.to_string()),
        // Datetime, Array, Table are not valid scalar substitutions.
        _ => None,
    }
}

/// Validate a parameter value string before it is spliced into a template.
///
/// Param values originate on the declaration side and end up inside strings that
/// become root sudoers Cmnds. A value containing a comma, any whitespace, a
/// control character, or a sudoers/shell metacharacter could split one Cmnd into
/// several or inject a directive (e.g. `unit = "nginx, /bin/sh"` would broaden
/// the rule). We constrain a param value to a conservative shell-safe token:
/// printable, no whitespace, no comma, and none of the sudoers/shell
/// metacharacters that would survive into a broadened rule. The rendered command
/// is independently re-checked by the post-substitution sudo gate.
fn param_value_defect(value: &str) -> Option<&'static str> {
    if value.is_empty() {
        return Some("is empty");
    }
    if value.chars().any(char::is_control) {
        return Some("contains a control character");
    }
    if value.chars().any(char::is_whitespace) {
        return Some("contains whitespace");
    }
    // Comma separates sudoers Cmnds; the rest are shell/sudoers metacharacters
    // that must not enter a Cmnd via an attacker-influenced param value.
    const FORBIDDEN: &[char] = &[
        ',', ';', '&', '|', '<', '>', '(', ')', '$', '`', '"', '\'', '\\', '*', '?', '!', '=',
        '#', '{', '}', '~',
    ];
    if value.chars().any(|c| FORBIDDEN.contains(&c)) {
        // The offending char is visible in the rejected value the caller carries
        // into the error, so the reason here is a fixed message.
        return Some("contains a forbidden metacharacter");
    }
    None
}

/// Substitute role parameters into a resolved permission's `groups`/`sudo`
/// templates, expanding a list param into one command per element.
///
/// Wraps [`resolve`] (whose signature is unchanged) and then rewrites the
/// resolved primitives. Kept as a separate entry point so callers that do not
/// template (and the existing `resolve` API consumed by the CLI) are untouched.
///
/// `params` is the role's `PermissionRef.params` (placeholder-name → value).
/// Returns the templated permission plus any warnings (catalog warnings from the
/// inner resolve, plus `UnusedParam` for any supplied param no placeholder used).
pub fn resolve_with_params(
    id: &str,
    params: &std::collections::BTreeMap<String, toml::Value>,
    os: &OsTarget,
    catalog: &dyn CatalogSource,
    ctx: &ResolveCtx,
) -> Result<(ResolvedPermission, Vec<Warning>), CatalogError> {
    let (mut resolved, mut warnings) = resolve(id, os, catalog, ctx)?;

    // No params: a placeholder-free record behaves exactly as before; a record
    // WITH placeholders but no params still fails closed via MissingParam below.
    // Track which params actually fill a placeholder so unused ones can warn.
    let mut used_params: Vec<String> = Vec::new();

    resolved.groups =
        substitute_primitives(&resolved.id, resolved.groups, params, &mut used_params, false)?;
    resolved.sudo =
        substitute_primitives(&resolved.id, resolved.sudo, params, &mut used_params, true)?;
    resolved.file_grants =
        substitute_file_grants(&resolved.id, resolved.file_grants, params, &mut used_params)?;

    for key in params.keys() {
        if !used_params.contains(key) {
            warnings.push(Warning::UnusedParam {
                permission: resolved.id.clone(),
                param: key.clone(),
            });
        }
    }

    Ok((resolved, warnings))
}

/// Apply parameter substitution to one primitive list (groups or sudo).
///
/// `is_sudo` gates the post-substitution sudo-command re-validation (groups are
/// not sudoers Cmnds, but the param-value gate still applies to both so a hostile
/// value cannot smuggle a separator into a group name either).
fn substitute_primitives(
    permission: &str,
    prims: Vec<SourcedPrimitive>,
    params: &std::collections::BTreeMap<String, toml::Value>,
    used_params: &mut Vec<String>,
    is_sudo: bool,
) -> Result<Vec<SourcedPrimitive>, CatalogError> {
    let mut out: Vec<SourcedPrimitive> = Vec::new();
    for prim in prims {
        let rendered = render_template(permission, &prim.value, params, used_params)?;
        for value in rendered {
            // Every rendered string is a concrete primitive now. For sudo,
            // re-validate against the SAME H1 rule applied at catalog parse so a
            // substitution that produced a non-absolute or control-bearing Cmnd
            // (despite the param-value gate) fails closed before root.
            if is_sudo {
                if let Some(reason) = sudo_command_defect(&value) {
                    return Err(CatalogError::InvalidSudoCommand {
                        id: permission.to_owned(),
                        value,
                        reason,
                    });
                }
            }
            out.push(SourcedPrimitive {
                value,
                layer: prim.layer.clone(),
                via: prim.via.clone(),
            });
        }
    }
    Ok(out)
}

/// Apply parameter substitution to resolved file-grant paths.
///
/// A grant `path` may carry `{param}` placeholders, filled exactly as sudo/group
/// templates are (a list param expands into one grant per element). Each rendered
/// path is re-validated by the post-substitution file-path gate (absolute, no
/// `..`, no control char) — the authoritative check for a templated path that the
/// parse-time static gate deferred — and its `shape` is recomputed against the now
/// concrete path. After substitution, grants are re-unioned by path so two params
/// that render to the same path collapse (access = max, recursive = OR).
fn substitute_file_grants(
    permission: &str,
    grants: Vec<ResolvedFileGrant>,
    params: &std::collections::BTreeMap<String, toml::Value>,
    used_params: &mut Vec<String>,
) -> Result<Vec<ResolvedFileGrant>, CatalogError> {
    let mut rendered: Vec<ResolvedFileGrant> = Vec::new();
    for grant in grants {
        let paths = render_template(permission, &grant.path, params, used_params)?;
        for path in paths {
            // The post-substitution gate is authoritative for a templated path:
            // a `{param}` that rendered to a non-absolute, `..`-bearing, or
            // control-bearing path fails closed here, before any root setfacl.
            if let Some(reason) = file_path_defect_substituted(&path) {
                return Err(CatalogError::InvalidFilePath {
                    id: permission.to_owned(),
                    path,
                    reason,
                });
            }
            // Same contradiction the parse-time gate rejects, applied to the
            // concrete rendered path: a trailing '/' (Shape::Dir) with
            // `recursive = false` would silently materialize as a recursive grant.
            if path.ends_with('/') && !grant.recursive {
                return Err(CatalogError::InvalidFilePath {
                    id: permission.to_owned(),
                    path,
                    reason: "trailing '/' denotes a recursive directory grant; set recursive=true or remove the trailing slash for a file grant",
                });
            }
            let shape = FileGrant {
                path: path.clone(),
                access: grant.access,
                recursive: grant.recursive,
            }
            .shape();
            rendered.push(ResolvedFileGrant {
                path,
                access: grant.access,
                recursive: grant.recursive,
                shape,
                sources: grant.sources.clone(),
            });
        }
    }

    // Re-union by path: distinct templated grants may render to the same concrete
    // path and must collapse exactly as literal duplicates do.
    let mut out: Vec<ResolvedFileGrant> = Vec::new();
    for grant in rendered {
        if let Some(existing) = out.iter_mut().find(|g| g.path == grant.path) {
            existing.access = existing.access.max(grant.access);
            existing.recursive = existing.recursive || grant.recursive;
            existing.shape = FileGrant {
                path: existing.path.clone(),
                access: existing.access,
                recursive: existing.recursive,
            }
            .shape();
            existing.sources.extend(grant.sources);
        } else {
            out.push(grant);
        }
    }
    Ok(out)
}

/// Render one template string against `params`, returning one or more concrete
/// strings (one per list-param element, or exactly one for an all-scalar
/// template). Records every param key it consumed in `used_params`.
fn render_template(
    permission: &str,
    template: &str,
    params: &std::collections::BTreeMap<String, toml::Value>,
    used_params: &mut Vec<String>,
) -> Result<Vec<String>, CatalogError> {
    // Collect this template's placeholders (deduped, in order). A template with
    // none is returned verbatim — the common, unchanged case.
    let mut placeholders: Vec<String> = Vec::new();
    for name in extract_placeholders(template) {
        if !placeholders.contains(&name.to_owned()) {
            placeholders.push(name.to_owned());
        }
    }
    if placeholders.is_empty() {
        return Ok(vec![template.to_owned()]);
    }

    // Every placeholder must have a matching param (fail-closed otherwise).
    // Split into the (at most one) list param and the scalar params.
    let mut list_param: Option<(String, Vec<String>)> = None;
    let mut scalar_subs: Vec<(String, String)> = Vec::new();

    for name in &placeholders {
        let Some(value) = params.get(name) else {
            return Err(CatalogError::MissingParam {
                permission: permission.to_owned(),
                placeholder: name.clone(),
            });
        };
        if !used_params.contains(name) {
            used_params.push(name.clone());
        }

        match value {
            toml::Value::Array(items) => {
                // Validate every element and collect them; reject a second list.
                let mut elems: Vec<String> = Vec::new();
                for item in items {
                    let s = scalar_param_string(item).ok_or(CatalogError::InvalidParamValue {
                        permission: permission.to_owned(),
                        param: name.clone(),
                        value: format!("{item:?}"),
                        reason: "list element is not a scalar value",
                    })?;
                    if let Some(reason) = param_value_defect(&s) {
                        return Err(CatalogError::InvalidParamValue {
                            permission: permission.to_owned(),
                            param: name.clone(),
                            value: s,
                            reason,
                        });
                    }
                    elems.push(s);
                }
                if let Some((first, _)) = &list_param {
                    return Err(CatalogError::MultipleListParams {
                        permission: permission.to_owned(),
                        first: first.clone(),
                        second: name.clone(),
                    });
                }
                list_param = Some((name.clone(), elems));
            }
            other => {
                let s = scalar_param_string(other).ok_or(CatalogError::InvalidParamValue {
                    permission: permission.to_owned(),
                    param: name.clone(),
                    value: format!("{other:?}"),
                    reason: "parameter value is not a scalar (string/int/float/bool)",
                })?;
                if let Some(reason) = param_value_defect(&s) {
                    return Err(CatalogError::InvalidParamValue {
                        permission: permission.to_owned(),
                        param: name.clone(),
                        value: s,
                        reason,
                    });
                }
                scalar_subs.push((name.clone(), s));
            }
        }
    }

    // Apply all scalar substitutions first (they are the same in every output).
    let mut base = template.to_owned();
    for (name, value) in &scalar_subs {
        base = substitute_one(&base, name, value);
    }

    // Then expand the single list param (if any) into one string per element.
    match list_param {
        None => Ok(vec![base]),
        Some((name, elems)) => Ok(elems
            .iter()
            .map(|e| substitute_one(&base, &name, e))
            .collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // --- helpers ---

    fn values(prims: &[SourcedPrimitive]) -> Vec<&str> {
        prims.iter().map(|p| p.value.as_str()).collect()
    }

    fn write_os_release(body: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(body.as_bytes()).unwrap();
        f
    }

    // --- 1.1 strict parsing ---

    #[test]
    fn parses_strict_policy_record() {
        let def: PermissionDef = toml::from_str(
            r#"
id = "network-admin"
risk = "escalation-capable"
category = "network"
groups = ["netdev"]
sudo = ["/usr/sbin/ip"]
[limits]
nofile = 4096
"#,
        )
        .unwrap();
        assert_eq!(def.id, "network-admin");
        assert_eq!(def.risk, Some(Risk::EscalationCapable));
        assert_eq!(def.category.as_deref(), Some("network"));
        assert_eq!(def.groups, ListOverride::Replace(vec!["netdev".to_owned()]));
        assert_eq!(def.sudo, ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]));
        assert_eq!(def.limits.unwrap().nofile, Some(4096));
        assert!(!def.replace);
    }

    #[test]
    fn risk_enum_both_values() {
        let contained: PermissionDef =
            toml::from_str("id = \"a\"\nrisk = \"contained\"\n").unwrap();
        assert_eq!(contained.risk, Some(Risk::Contained));
        let esc: PermissionDef =
            toml::from_str("id = \"b\"\nrisk = \"escalation-capable\"\n").unwrap();
        assert_eq!(esc.risk, Some(Risk::EscalationCapable));
    }

    #[test]
    fn unknown_field_rejected() {
        let err = toml::from_str::<PermissionDef>("id = \"a\"\nbogus = true\n");
        assert!(err.is_err(), "unknown field must be rejected");
    }

    #[test]
    fn human_text_fields_rejected() {
        // title/summary/risk_note live in the l10n tree, never in a policy
        // record; deny_unknown_fields must reject them.
        for field in ["title", "summary", "risk_note"] {
            let src = format!("id = \"a\"\n{field} = \"x\"\n");
            assert!(
                toml::from_str::<PermissionDef>(&src).is_err(),
                "{field} must be rejected in a policy record"
            );
        }
    }

    #[test]
    fn aggregation_fields_parse_but_inert() {
        let def: PermissionDef = toml::from_str(
            r#"
id = "network-config"
includes = ["network-diag", "network-admin"]
include_categories = ["network"]
"#,
        )
        .unwrap();
        assert_eq!(def.includes, vec!["network-diag", "network-admin"]);
        assert_eq!(def.include_categories, vec!["network"]);
    }

    #[test]
    fn append_form_parses_distinct_from_replace() {
        let appended: PermissionDef =
            toml::from_str("id = \"a\"\nsudo = { append = [\"netplan\"] }\n").unwrap();
        assert_eq!(appended.sudo, ListOverride::Append(vec!["netplan".to_owned()]));
        let replaced: PermissionDef =
            toml::from_str("id = \"a\"\nsudo = [\"netplan\"]\n").unwrap();
        assert_eq!(replaced.sudo, ListOverride::Replace(vec!["netplan".to_owned()]));
    }

    #[test]
    fn append_form_rejects_unknown_key() {
        // A typo in the table form must not be silently dropped.
        assert!(toml::from_str::<PermissionDef>("id = \"a\"\nsudo = { apend = [\"x\"] }\n").is_err());
    }

    // --- 1.2 OsTarget detection ---

    #[test]
    fn detects_debian_12() {
        let f = write_os_release("ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n");
        let os = OsTarget::detect_from(f.path()).unwrap();
        assert_eq!(os.family, "linux");
        assert_eq!(os.distro, "debian");
        assert_eq!(os.version.as_deref(), Some("12"));
        assert_eq!(
            os.layer_names(),
            vec!["linux", "linux-debian", "linux-debian-12"]
        );
    }

    #[test]
    fn detects_ubuntu_2204_quoted_version() {
        let f = write_os_release("ID=ubuntu\nVERSION_ID=\"22.04\"\n");
        let os = OsTarget::detect_from(f.path()).unwrap();
        assert_eq!(os.distro, "ubuntu");
        assert_eq!(os.version.as_deref(), Some("22.04"));
        assert_eq!(
            os.layer_names(),
            vec!["linux", "linux-ubuntu", "linux-ubuntu-22.04"]
        );
    }

    #[test]
    fn detects_astra_18() {
        // Astra reports ID=astra (some builds astralinux); both map to astra.
        let f = write_os_release("ID=astra\nVERSION_ID=1.8\n");
        let os = OsTarget::detect_from(f.path()).unwrap();
        assert_eq!(os.distro, "astra");
        assert_eq!(
            os.layer_names(),
            vec!["linux", "linux-astra", "linux-astra-1.8"]
        );

        let f2 = write_os_release("ID=astralinux\nVERSION_ID=\"1.8\"\n");
        assert_eq!(OsTarget::detect_from(f2.path()).unwrap().distro, "astra");
    }

    #[test]
    fn unknown_id_keeps_raw_distro() {
        let f = write_os_release("ID=fedora\nVERSION_ID=40\n");
        let os = OsTarget::detect_from(f.path()).unwrap();
        assert_eq!(os.family, "linux");
        assert_eq!(os.distro, "fedora");
        assert_eq!(
            os.layer_names(),
            vec!["linux", "linux-fedora", "linux-fedora-40"]
        );
    }

    #[test]
    fn missing_id_is_os_release_error() {
        let f = write_os_release("VERSION_ID=12\n");
        assert!(matches!(
            OsTarget::detect_from(f.path()),
            Err(CatalogError::OsRelease { .. })
        ));
    }

    #[test]
    fn no_version_yields_two_layer_chain() {
        let f = write_os_release("ID=debian\n");
        let os = OsTarget::detect_from(f.path()).unwrap();
        assert_eq!(os.version, None);
        assert_eq!(os.layer_names(), vec!["linux", "linux-debian"]);
    }

    // --- 1.3 layered leaf resolve ---

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
            files: Vec::new(),
        }
    }

    fn debian12() -> OsTarget {
        OsTarget::new("linux", "debian", Some("12".to_owned())).unwrap()
    }

    #[test]
    fn resolves_single_base_layer() {
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                risk: Some(Risk::Contained),
                sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                ..def("network-admin")
            },
        );
        // No version on the target: a bare `linux`/`linux-debian` chain has no
        // version layer to be "unknown", so the single base layer resolves
        // cleanly with no warnings.
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, w) = resolve_leaf("network-admin", &os, &cat).unwrap();
        assert_eq!(r.risk, Some(Risk::Contained));
        assert_eq!(values(&r.sudo), vec!["/usr/sbin/ip"]);
        assert_eq!(r.sudo[0].layer, "linux");
        assert!(w.is_empty());
        // Forward-compat invariants of the leaf path: a leaf reaches the result
        // directly (no bundle), so every primitive has via=None and no category
        // membership is captured. Pinned here to catch a future regression that
        // populates them on the leaf path.
        assert!(r.sudo.iter().all(|p| p.via.is_none()));
        assert!(r.groups.iter().all(|p| p.via.is_none()));
        assert_eq!(r.category_members, Vec::new());
    }

    #[test]
    fn distro_layer_replaces_field() {
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                    ..def("net")
                },
            )
            .with(
                "linux-debian",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/bin/nmcli".to_owned()]),
                    ..def("net")
                },
            );
        let (r, _) = resolve_leaf("net", &debian12(), &cat).unwrap();
        // Bare array on the distro layer replaces the base list.
        assert_eq!(values(&r.sudo), vec!["/usr/bin/nmcli"]);
        assert_eq!(r.sudo[0].layer, "linux-debian");
    }

    #[test]
    fn version_layer_append_adds_with_provenance() {
        // Spec scenario: linux-debian gives sudo [ip]; linux-debian-12 appends
        // netplan → [ip, netplan], provenance per layer.
        let cat = FakeCatalog::new()
            .with(
                "linux-debian",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                    ..def("net")
                },
            )
            .with(
                "linux-debian-12",
                PermissionDef {
                    sudo: ListOverride::Append(vec!["/usr/sbin/netplan".to_owned()]),
                    ..def("net")
                },
            );
        let (r, w) = resolve_leaf("net", &debian12(), &cat).unwrap();
        assert_eq!(values(&r.sudo), vec!["/usr/sbin/ip", "/usr/sbin/netplan"]);
        assert_eq!(r.sudo[0].layer, "linux-debian");
        assert_eq!(r.sudo[1].layer, "linux-debian-12");
        assert!(w.is_empty());
    }

    #[test]
    fn replace_wipes_accumulated() {
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                    groups: ListOverride::Replace(vec!["netdev".to_owned()]),
                    ..def("net")
                },
            )
            .with(
                "linux-debian",
                PermissionDef {
                    replace: true,
                    sudo: ListOverride::Replace(vec!["/usr/bin/nmcli".to_owned()]),
                    ..def("net")
                },
            );
        let (r, _) = resolve_leaf("net", &debian12(), &cat).unwrap();
        // replace=true wiped the base groups too, not just merged sudo.
        assert_eq!(values(&r.sudo), vec!["/usr/bin/nmcli"]);
        assert!(r.groups.is_empty());
    }

    #[test]
    fn risk_topmost_setter_wins() {
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    risk: Some(Risk::Contained),
                    ..def("net")
                },
            )
            .with(
                "linux-debian",
                PermissionDef {
                    risk: Some(Risk::EscalationCapable),
                    ..def("net")
                },
            );
        let (r, _) = resolve_leaf("net", &debian12(), &cat).unwrap();
        assert_eq!(r.risk, Some(Risk::EscalationCapable));
    }

    #[test]
    fn limits_replace_wholesale_with_provenance() {
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    limits: Some(CatalogLimits { nofile: Some(1024), nproc: None }),
                    ..def("net")
                },
            )
            .with(
                "linux-debian",
                PermissionDef {
                    limits: Some(CatalogLimits { nofile: Some(4096), nproc: Some(512) }),
                    ..def("net")
                },
            );
        let (r, _) = resolve_leaf("net", &debian12(), &cat).unwrap();
        assert_eq!(r.limits, Some(Limits { nofile: Some(4096), nproc: Some(512) }));
        assert_eq!(r.limits_layer.as_deref(), Some("linux-debian"));
    }

    #[test]
    fn unknown_id_errors() {
        let cat = FakeCatalog::new().with("linux", def("net"));
        let err = resolve_leaf("ghost", &debian12(), &cat).unwrap_err();
        assert!(matches!(err, CatalogError::UnknownPermission(id) if id == "ghost"));
    }

    #[test]
    fn unknown_version_resolves_lower_with_warning() {
        // os reports debian 99, only linux + linux-debian exist.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                    ..def("net")
                },
            )
            .with(
                "linux-debian",
                PermissionDef {
                    sudo: ListOverride::Append(vec!["/usr/bin/nmcli".to_owned()]),
                    ..def("net")
                },
            );
        let os = OsTarget::new("linux", "debian", Some("99".to_owned())).unwrap();
        let (r, w) = resolve_leaf("net", &os, &cat).unwrap();
        // Falls back to the distro layer; primitives still resolve.
        assert_eq!(values(&r.sudo), vec!["/usr/sbin/ip", "/usr/bin/nmcli"]);
        assert_eq!(
            w,
            vec![Warning::UnknownOsVersion {
                missing_layer: "linux-debian-99".to_owned(),
                resolved_against: "linux-debian".to_owned(),
            }]
        );
    }

    #[test]
    fn known_present_empty_version_layer_no_warning() {
        // Version layer dir exists but holds no record for this id: that is a
        // *present* layer, so no unknown-version warning — it simply adds nothing.
        let cat = FakeCatalog::new()
            .with("linux", PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                ..def("net")
            })
            .with_empty_layer("linux-debian-12");
        let (r, w) = resolve_leaf("net", &debian12(), &cat).unwrap();
        assert_eq!(values(&r.sudo), vec!["/usr/sbin/ip"]);
        assert!(w.is_empty(), "present (if empty) version layer must not warn");
    }

    // --- 2.1 bundle resolution (includes) ---

    fn ctx() -> ResolveCtx {
        ResolveCtx { catalog_version: Some("2026.06".to_owned()) }
    }

    #[test]
    fn leaf_via_resolve_matches_resolve_leaf() {
        // resolve() on a leaf must behave exactly like resolve_leaf().
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                ..def("net")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (a, _) = resolve_leaf("net", &os, &cat).unwrap();
        let (b, _) = resolve("net", &os, &cat, &ctx()).unwrap();
        // Primitives/risk/limits identical; resolve() additionally stamps the
        // catalog version it compiled against.
        assert_eq!(a.groups, b.groups);
        assert_eq!(a.sudo, b.sudo);
        assert_eq!(a.risk, b.risk);
        assert_eq!(a.limits, b.limits);
        assert_eq!(a.resolved_catalog_version, None);
        assert_eq!(b.resolved_catalog_version, ctx().catalog_version);
        // Leaf primitives have no `via`.
        assert!(b.sudo.iter().all(|p| p.via.is_none()));
    }

    #[test]
    fn bundle_unions_members_and_own_primitives() {
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                    ..def("network-diag")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    groups: ListOverride::Replace(vec!["netdev".to_owned()]),
                    ..def("network-admin")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    // The bundle carries its own primitive too.
                    sudo: ListOverride::Replace(vec!["/usr/bin/tcpdump".to_owned()]),
                    includes: vec!["network-diag".to_owned(), "network-admin".to_owned()],
                    ..def("network-config")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve("network-config", &os, &cat, &ctx()).unwrap();
        // Own sudo + member sudo, member groups.
        let mut sudo = values(&r.sudo);
        sudo.sort();
        assert_eq!(sudo, vec!["/usr/bin/tcpdump", "/usr/sbin/ip"]);
        assert_eq!(values(&r.groups), vec!["netdev"]);
        // Provenance: own primitive has via=None; member primitives via=member id.
        let own = r.sudo.iter().find(|p| p.value == "/usr/bin/tcpdump").unwrap();
        assert_eq!(own.via, None);
        let from_diag = r.sudo.iter().find(|p| p.value == "/usr/sbin/ip").unwrap();
        assert_eq!(from_diag.via.as_deref(), Some("network-diag"));
        let from_admin = r.groups.iter().find(|p| p.value == "netdev").unwrap();
        assert_eq!(from_admin.via.as_deref(), Some("network-admin"));
    }

    #[test]
    fn bundle_dedups_identical_member_primitives() {
        // Two members grant the same sudo command: it appears once, provenance
        // from the first contributor.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                    ..def("a")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                    ..def("b")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    includes: vec!["a".to_owned(), "b".to_owned()],
                    ..def("bundle")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve("bundle", &os, &cat, &ctx()).unwrap();
        assert_eq!(values(&r.sudo), vec!["/usr/sbin/ip"]);
        assert_eq!(r.sudo[0].via.as_deref(), Some("a"));
    }

    #[test]
    fn transitive_bundle_includes_bundle() {
        // outer -> mid -> leaf.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                    ..def("leaf")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    includes: vec!["leaf".to_owned()],
                    sudo: ListOverride::Replace(vec!["/usr/bin/mid-cmd".to_owned()]),
                    ..def("mid")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    includes: vec!["mid".to_owned()],
                    ..def("outer")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve("outer", &os, &cat, &ctx()).unwrap();
        let mut sudo = values(&r.sudo);
        sudo.sort();
        assert_eq!(sudo, vec!["/usr/bin/mid-cmd", "/usr/sbin/ip"]);
        // outer references mid directly, so both primitives are attributed to mid.
        assert!(r.sudo.iter().all(|p| p.via.as_deref() == Some("mid")));
    }

    #[test]
    fn cycle_is_rejected() {
        // a -> b -> a.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    includes: vec!["b".to_owned()],
                    ..def("a")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    includes: vec!["a".to_owned()],
                    ..def("b")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let err = resolve("a", &os, &cat, &ctx()).unwrap_err();
        match err {
            CatalogError::Cycle(path) => {
                // Closing path starts and ends at the repeated id.
                assert_eq!(path.first().map(String::as_str), Some("a"));
                assert_eq!(path.last().map(String::as_str), Some("a"));
                assert!(path.contains(&"b".to_owned()));
            }
            other => panic!("expected Cycle, got {other:?}"),
        }
    }

    #[test]
    fn deep_acyclic_include_chain_is_rejected_not_overflowed() {
        // A chain of distinct ids p0 -> p1 -> … -> pN, each including the next,
        // is acyclic so the cycle detector never fires; without the depth bound
        // it would recurse one native frame per link. Build a chain longer than
        // MAX_INCLUDE_DEPTH and assert it is refused cleanly.
        let len = MAX_INCLUDE_DEPTH + 5;
        let mut cat = FakeCatalog::new();
        for i in 0..len {
            let id = format!("p{i}");
            let def = if i + 1 < len {
                PermissionDef {
                    includes: vec![format!("p{}", i + 1)],
                    ..def(&id)
                }
            } else {
                // Leaf at the bottom of the chain.
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                    ..def(&id)
                }
            };
            cat = cat.with("linux", def);
        }
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let err = resolve("p0", &os, &cat, &ctx()).unwrap_err();
        match err {
            CatalogError::IncludeTooDeep { depth, .. } => {
                assert!(depth >= MAX_INCLUDE_DEPTH, "depth {depth} below bound");
            }
            other => panic!("expected IncludeTooDeep, got {other:?}"),
        }
    }

    #[test]
    fn shallow_bundle_resolves_under_depth_bound() {
        // A normal two-level bundle is well under the bound and resolves fine.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                    ..def("leaf")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    includes: vec!["leaf".to_owned()],
                    ..def("bundle")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve("bundle", &os, &cat, &ctx()).unwrap();
        assert_eq!(values(&r.sudo), vec!["/usr/sbin/ip"]);
    }

    // --- 2.2 categories (include_categories) ---

    #[test]
    fn include_categories_materializes_members() {
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    category: Some("network".to_owned()),
                    sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                    ..def("net-a")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    category: Some("network".to_owned()),
                    sudo: ListOverride::Replace(vec!["/usr/bin/nmcli".to_owned()]),
                    ..def("net-b")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    // Not in the network category — must not be pulled in.
                    category: Some("storage".to_owned()),
                    sudo: ListOverride::Replace(vec!["/usr/bin/mount".to_owned()]),
                    ..def("disk")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    include_categories: vec!["network".to_owned()],
                    ..def("all-network")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve("all-network", &os, &cat, &ctx()).unwrap();
        let mut sudo = values(&r.sudo);
        sudo.sort();
        assert_eq!(sudo, vec!["/usr/bin/nmcli", "/usr/sbin/ip"]);
        // Materialized member list captured in provenance.
        assert_eq!(r.category_members.len(), 1);
        let (cat_name, mut members) = r.category_members[0].clone();
        members.sort();
        assert_eq!(cat_name, "network");
        assert_eq!(members, vec!["net-a", "net-b"]);
    }

    #[test]
    fn category_materialization_is_point_in_time() {
        // The resolved member list reflects the catalog as-resolved: a member
        // added to the category in a *different* catalog instance is not present
        // in the list captured by the first resolve.
        let base = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    category: Some("network".to_owned()),
                    sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                    ..def("net-a")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    include_categories: vec!["network".to_owned()],
                    ..def("all-network")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r1, _) = resolve("all-network", &os, &base, &ctx()).unwrap();
        assert_eq!(r1.category_members[0].1, vec!["net-a"]);

        // A grown catalog adds a second network member.
        let grown = base.clone().with(
            "linux",
            PermissionDef {
                category: Some("network".to_owned()),
                sudo: ListOverride::Replace(vec!["/usr/bin/nmcli".to_owned()]),
                ..def("net-b")
            },
        );
        let (r2, _) = resolve("all-network", &os, &grown, &ctx()).unwrap();
        let mut m2 = r2.category_members[0].1.clone();
        m2.sort();
        assert_eq!(m2, vec!["net-a", "net-b"]);
        // The earlier resolve's captured list did not retro-widen.
        assert_eq!(r1.category_members[0].1, vec!["net-a"]);
    }

    // --- 2.3 bundle risk ---

    #[test]
    fn bundle_risk_is_max_of_members() {
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    risk: Some(Risk::Contained),
                    ..def("low")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    risk: Some(Risk::EscalationCapable),
                    ..def("high")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    includes: vec!["low".to_owned(), "high".to_owned()],
                    ..def("bundle")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve("bundle", &os, &cat, &ctx()).unwrap();
        assert_eq!(r.risk, Some(Risk::EscalationCapable));
    }

    #[test]
    fn bundle_explicit_lowered_risk_is_error() {
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    risk: Some(Risk::EscalationCapable),
                    ..def("high")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    // Bundle under-states the member's escalation risk.
                    risk: Some(Risk::Contained),
                    includes: vec!["high".to_owned()],
                    ..def("bundle")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let err = resolve("bundle", &os, &cat, &ctx()).unwrap_err();
        assert!(matches!(
            err,
            CatalogError::LoweredBundleRisk {
                ref id,
                declared: Risk::Contained,
                computed: Risk::EscalationCapable,
            } if id == "bundle"
        ));
    }

    #[test]
    fn bundle_equal_or_higher_explicit_risk_allowed() {
        // Equal: bundle declares the same as the member's max.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    risk: Some(Risk::EscalationCapable),
                    ..def("high")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    risk: Some(Risk::EscalationCapable),
                    includes: vec!["high".to_owned()],
                    ..def("bundle")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve("bundle", &os, &cat, &ctx()).unwrap();
        assert_eq!(r.risk, Some(Risk::EscalationCapable));

        // Higher: members contained, bundle declares escalation-capable (allowed).
        let cat2 = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    risk: Some(Risk::Contained),
                    ..def("low")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    risk: Some(Risk::EscalationCapable),
                    includes: vec!["low".to_owned()],
                    ..def("bundle")
                },
            );
        let (r2, _) = resolve("bundle", &os, &cat2, &ctx()).unwrap();
        assert_eq!(r2.risk, Some(Risk::EscalationCapable));
    }

    #[test]
    fn bundle_none_member_risk_folds_to_highest_not_contained() {
        let os = OsTarget::new("linux", "debian", None).unwrap();

        // An unlabelled (None) member next to an escalation-capable one keeps the
        // bundle escalation-capable.
        let cat = FakeCatalog::new()
            .with("linux", def("undeclared"))
            .with(
                "linux",
                PermissionDef {
                    risk: Some(Risk::EscalationCapable),
                    ..def("high")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    includes: vec!["undeclared".to_owned(), "high".to_owned()],
                    ..def("bundle")
                },
            );
        let (r, _) = resolve("bundle", &os, &cat, &ctx()).unwrap();
        assert_eq!(r.risk, Some(Risk::EscalationCapable));

        // Security-critical: a bundle of unlabelled members must NOT silently
        // resolve to Contained — unknown is folded conservatively to the highest
        // risk so an unlabelled escalation-capable member cannot hide.
        let cat2 = FakeCatalog::new()
            .with("linux", def("m1"))
            .with("linux", def("m2"))
            .with(
                "linux",
                PermissionDef {
                    includes: vec!["m1".to_owned(), "m2".to_owned()],
                    ..def("bundle")
                },
            );
        let (r2, _) = resolve("bundle", &os, &cat2, &ctx()).unwrap();
        assert_eq!(r2.risk, Some(Risk::EscalationCapable));
        assert_ne!(r2.risk, Some(Risk::Contained));
    }

    #[test]
    fn bundle_declaring_contained_over_unknown_member_is_lowered_risk() {
        // A bundle that declares `contained` while including an unlabelled member
        // under-states the aggregate (the unknown member may be escalation-capable)
        // and is rejected — the LoweredBundleRisk guard now also fires against the
        // unknown-folds-to-highest floor.
        let cat = FakeCatalog::new().with("linux", def("undeclared")).with(
            "linux",
            PermissionDef {
                risk: Some(Risk::Contained),
                includes: vec!["undeclared".to_owned()],
                ..def("bundle")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let err = resolve("bundle", &os, &cat, &ctx()).unwrap_err();
        assert!(matches!(
            err,
            CatalogError::LoweredBundleRisk {
                ref id,
                declared: Risk::Contained,
                computed: Risk::EscalationCapable,
            } if id == "bundle"
        ));
    }

    // --- 2.4 namespace add-on discovery (FakeCatalog) ---

    #[test]
    fn namespaced_addon_resolves() {
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/docker".to_owned()]),
                ..def("docker.ps")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve("docker.ps", &os, &cat, &ctx()).unwrap();
        assert_eq!(values(&r.sudo), vec!["/usr/bin/docker"]);
    }

    #[test]
    fn same_id_one_layer_is_collision() {
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/bin/a".to_owned()]),
                    ..def("docker.ps")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/bin/b".to_owned()]),
                    ..def("docker.ps")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let err = resolve("docker.ps", &os, &cat, &ctx()).unwrap_err();
        assert!(matches!(err, CatalogError::NamespaceCollision { id } if id == "docker.ps"));
    }

    #[test]
    fn same_id_across_layers_is_not_collision() {
        // The same id on different layers is the legitimate override chain.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/bin/a".to_owned()]),
                    ..def("docker.ps")
                },
            )
            .with(
                "linux-debian",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/bin/b".to_owned()]),
                    ..def("docker.ps")
                },
            );
        let (r, _) = resolve("docker.ps", &debian12(), &cat, &ctx()).unwrap();
        // Distro layer overrides the base, not a collision.
        assert_eq!(values(&r.sudo), vec!["/bin/b"]);
    }

    #[test]
    fn missing_addon_is_unknown_permission() {
        // No docker.* anywhere: referencing docker.admin errors before apply.
        let cat = FakeCatalog::new().with("linux", def("net"));
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let err = resolve("docker.admin", &os, &cat, &ctx()).unwrap_err();
        assert!(matches!(err, CatalogError::UnknownPermission(id) if id == "docker.admin"));
    }

    // --- 2.4 namespace add-on discovery (LiveCatalog / filesystem) ---

    #[test]
    fn live_catalog_discovers_top_level_and_namespace() {
        let root = tempfile::tempdir().unwrap();
        let layer_dir = root.path().join("linux");
        std::fs::create_dir_all(layer_dir.join("docker")).unwrap();
        std::fs::write(
            layer_dir.join("foo.toml"),
            "id = \"foo\"\nsudo = [\"/usr/bin/foo-cmd\"]\n",
        )
        .unwrap();
        std::fs::write(
            layer_dir.join("docker/ps.toml"),
            "id = \"docker.ps\"\nsudo = [\"/usr/bin/docker\"]\n",
        )
        .unwrap();

        let cat = LiveCatalog::new(vec![root.path().to_path_buf()]);
        let os = OsTarget::new("linux", "debian", None).unwrap();

        let (foo, _) = resolve("foo", &os, &cat, &ctx()).unwrap();
        assert_eq!(values(&foo.sudo), vec!["/usr/bin/foo-cmd"]);
        let (docker, _) = resolve("docker.ps", &os, &cat, &ctx()).unwrap();
        assert_eq!(values(&docker.sudo), vec!["/usr/bin/docker"]);
    }

    #[test]
    fn live_catalog_rejects_namespace_subdir_mismatch() {
        // docker.ps misfiled under a k8s/ subdir must be rejected at read time.
        let root = tempfile::tempdir().unwrap();
        let layer_dir = root.path().join("linux");
        std::fs::create_dir_all(layer_dir.join("k8s")).unwrap();
        std::fs::write(
            layer_dir.join("k8s/ps.toml"),
            "id = \"docker.ps\"\nsudo = [\"/usr/bin/docker\"]\n",
        )
        .unwrap();

        let cat = LiveCatalog::new(vec![root.path().to_path_buf()]);
        let err = cat.read_layer("linux").unwrap_err();
        assert!(matches!(err, CatalogError::TomlParse { .. }));
    }

    #[test]
    fn live_catalog_rejects_top_level_namespaced_id() {
        // A namespaced id at top-level (no matching subdir) is misfiled.
        let root = tempfile::tempdir().unwrap();
        let layer_dir = root.path().join("linux");
        std::fs::create_dir_all(&layer_dir).unwrap();
        std::fs::write(
            layer_dir.join("ps.toml"),
            "id = \"docker.ps\"\nsudo = [\"/usr/bin/docker\"]\n",
        )
        .unwrap();
        let cat = LiveCatalog::new(vec![root.path().to_path_buf()]);
        assert!(matches!(
            cat.read_layer("linux").unwrap_err(),
            CatalogError::TomlParse { .. }
        ));
    }

    #[test]
    fn live_catalog_same_id_one_layer_dir_is_collision() {
        let root = tempfile::tempdir().unwrap();
        let layer_dir = root.path().join("linux");
        std::fs::create_dir_all(&layer_dir).unwrap();
        std::fs::write(layer_dir.join("a.toml"), "id = \"dup\"\n").unwrap();
        std::fs::write(layer_dir.join("b.toml"), "id = \"dup\"\n").unwrap();
        let cat = LiveCatalog::new(vec![root.path().to_path_buf()]);
        assert!(matches!(
            cat.read_layer("linux").unwrap_err(),
            CatalogError::NamespaceCollision { id } if id == "dup"
        ));
    }

    // --- 2.5 include_categories sees namespaced members (never silently narrow) ---

    #[test]
    fn include_categories_materializes_namespaced_members() {
        // A category bundle must pull in members defined in namespace subdirs too,
        // not just top-level OS primitives — otherwise the bundle silently
        // under-expands when an add-on contributes to the category.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    category: Some("container".to_owned()),
                    sudo: ListOverride::Replace(vec!["/usr/bin/docker".to_owned()]),
                    ..def("docker.ps")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    category: Some("container".to_owned()),
                    sudo: ListOverride::Replace(vec!["/usr/bin/nerdctl".to_owned()]),
                    ..def("containerd.ps")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    include_categories: vec!["container".to_owned()],
                    ..def("all-containers")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve("all-containers", &os, &cat, &ctx()).unwrap();
        let mut sudo = values(&r.sudo);
        sudo.sort();
        assert_eq!(sudo, vec!["/usr/bin/docker", "/usr/bin/nerdctl"]);
        let mut members = r.category_members[0].1.clone();
        members.sort();
        assert_eq!(members, vec!["containerd.ps", "docker.ps"]);
    }

    #[test]
    fn live_catalog_category_sees_namespace_subdir_members() {
        // Same invariant on a real filesystem: all_definitions walks namespace
        // subdirs, so a category bundle expands a namespaced add-on member.
        let root = tempfile::tempdir().unwrap();
        let layer_dir = root.path().join("linux");
        std::fs::create_dir_all(layer_dir.join("docker")).unwrap();
        std::fs::write(
            layer_dir.join("net.toml"),
            "id = \"net\"\ncategory = \"ops\"\nsudo = [\"/usr/sbin/ip\"]\n",
        )
        .unwrap();
        std::fs::write(
            layer_dir.join("docker/ps.toml"),
            "id = \"docker.ps\"\ncategory = \"ops\"\nsudo = [\"/usr/bin/docker\"]\n",
        )
        .unwrap();
        std::fs::write(
            layer_dir.join("all-ops.toml"),
            "id = \"all-ops\"\ninclude_categories = [\"ops\"]\n",
        )
        .unwrap();

        let cat = LiveCatalog::new(vec![root.path().to_path_buf()]);
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve("all-ops", &os, &cat, &ctx()).unwrap();
        let mut sudo = values(&r.sudo);
        sudo.sort();
        assert_eq!(sudo, vec!["/usr/bin/docker", "/usr/sbin/ip"]);
    }

    // --- 2.6 path-component validation (no traversal into the catalog root) ---

    #[test]
    fn os_release_rejects_traversal_id() {
        for body in ["ID=../secret\n", "ID=a/b\n", "ID=..\n", "ID=.\n", "ID=\n"] {
            let f = write_os_release(body);
            assert!(
                matches!(OsTarget::detect_from(f.path()), Err(CatalogError::OsRelease { .. })),
                "os-release {body:?} must be rejected"
            );
        }
    }

    #[test]
    fn os_release_rejects_traversal_version() {
        for body in ["ID=debian\nVERSION_ID=../x\n", "ID=debian\nVERSION_ID=a/b\n"] {
            let f = write_os_release(body);
            assert!(
                matches!(OsTarget::detect_from(f.path()), Err(CatalogError::OsRelease { .. })),
                "os-release {body:?} must be rejected"
            );
        }
    }

    #[test]
    fn os_release_allows_dotted_version() {
        // A `.` inside a version (22.04, 1.8) is fine — only bare `.`/`..` and
        // separators are rejected.
        let f = write_os_release("ID=ubuntu\nVERSION_ID=22.04\n");
        assert_eq!(
            OsTarget::detect_from(f.path()).unwrap().version.as_deref(),
            Some("22.04")
        );
    }

    #[test]
    fn os_target_new_rejects_unsafe_components() {
        assert!(matches!(
            OsTarget::new("linux", "../secret", None),
            Err(CatalogError::InvalidName { kind: "distro", .. })
        ));
        assert!(matches!(
            OsTarget::new("linux", "a/b", None),
            Err(CatalogError::InvalidName { kind: "distro", .. })
        ));
        assert!(matches!(
            OsTarget::new("linux", "", None),
            Err(CatalogError::InvalidName { kind: "distro", .. })
        ));
        assert!(matches!(
            OsTarget::new("../x", "debian", None),
            Err(CatalogError::InvalidName { kind: "os family", .. })
        ));
        assert!(matches!(
            OsTarget::new("linux", "debian", Some("../x".to_owned())),
            Err(CatalogError::InvalidName { kind: "version", .. })
        ));
        // Sane values still construct.
        assert!(OsTarget::new("linux", "debian", Some("12".to_owned())).is_ok());
    }

    #[test]
    fn path_component_validator_rejects_traversal_and_separators() {
        // The centralized validator is the single gate for every name that
        // becomes a path component (os fields, namespace). Pin its contract.
        assert!(is_safe_path_component("debian"));
        assert!(is_safe_path_component("22.04"));
        assert!(is_safe_path_component("1.8"));
        assert!(is_safe_path_component("docker_v2-beta"));
        for bad in ["", ".", "..", "../x", "a/b", "a\\b", "Foo", "with space", "ünïcode"] {
            assert!(!is_safe_path_component(bad), "{bad:?} must be unsafe");
            assert!(matches!(
                validate_path_component("namespace", bad),
                Err(CatalogError::InvalidName { kind: "namespace", .. })
            ));
        }
    }

    #[test]
    fn live_catalog_sibling_secret_unreachable_via_traversal() {
        // Concrete probe: a LiveCatalog rooted at <tmp>/catalog cannot be steered
        // into a sibling <tmp>/secret directory by a crafted os-release ID. The
        // os-release validation rejects `ID=../secret` before it can ever become a
        // layer name joined onto the root.
        let tmp = tempfile::tempdir().unwrap();
        let catalog_root = tmp.path().join("catalog");
        let secret_dir = tmp.path().join("secret");
        // The secret holds what would be a layer dir named `linux` for the
        // traversal `../secret` + `-linux` shape; create a plausible payload so a
        // successful escape would actually resolve something.
        std::fs::create_dir_all(secret_dir.join("linux")).unwrap();
        std::fs::write(
            secret_dir.join("linux").join("pwn.toml"),
            "id = \"pwn\"\nsudo = [\"rm -rf /\"]\n",
        )
        .unwrap();
        // Legitimate catalog payload (positive control: debian/12/docker work).
        std::fs::create_dir_all(catalog_root.join("linux").join("docker")).unwrap();
        std::fs::write(
            catalog_root.join("linux").join("docker").join("ps.toml"),
            "id = \"docker.ps\"\nsudo = [\"/usr/bin/docker\"]\n",
        )
        .unwrap();

        // Crafted os-release pointing the distro at the sibling: rejected outright.
        let f = write_os_release("ID=../secret\nVERSION_ID=12\n");
        assert!(
            matches!(OsTarget::detect_from(f.path()), Err(CatalogError::OsRelease { .. })),
            "ID=../secret must be rejected, not turned into a layer name"
        );

        // Positive control: the legitimate target resolves the in-tree add-on.
        let cat = LiveCatalog::new(vec![catalog_root.clone()]);
        let os = OsTarget::new("linux", "debian", Some("12".to_owned())).unwrap();
        let (docker, _) = resolve("docker.ps", &os, &cat, &ctx()).unwrap();
        assert_eq!(values(&docker.sudo), vec!["/usr/bin/docker"]);

        // Defense in depth: even if a distro string with a separator reached
        // layer_names, the validator in OsTarget::new refuses to build it.
        assert!(matches!(
            OsTarget::new("linux", "../secret", None),
            Err(CatalogError::InvalidName { .. })
        ));
    }

    // --- strict [limits] sub-table (no mac_mask / unknown keys) ---

    #[test]
    fn limits_subtable_rejects_mac_mask() {
        // mac_mask is a Tessera enforcement primitive; it MUST NOT appear in a
        // catalog expansion. Smuggling it under [limits] (where the tolerant role
        // type would silently drop it) is rejected by the strict CatalogLimits.
        let err = toml::from_str::<PermissionDef>("id = \"a\"\n[limits]\nmac_mask = \"0xff\"\n");
        assert!(err.is_err(), "[limits] mac_mask must be rejected");
    }

    #[test]
    fn limits_subtable_rejects_unknown_key() {
        let err = toml::from_str::<PermissionDef>("id = \"a\"\n[limits]\nbogus = 1\n");
        assert!(err.is_err(), "[limits] unknown key must be rejected");
    }

    #[test]
    fn limits_subtable_valid_parses_and_resolves() {
        let parsed: PermissionDef =
            toml::from_str("id = \"a\"\n[limits]\nnofile = 1024\nnproc = 512\n").unwrap();
        assert_eq!(parsed.limits, Some(CatalogLimits { nofile: Some(1024), nproc: Some(512) }));

        // And it converts to rolestore::Limits across a resolve.
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                limits: Some(CatalogLimits { nofile: Some(1024), nproc: Some(512) }),
                ..def("a")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve_leaf("a", &os, &cat).unwrap();
        assert_eq!(r.limits, Some(Limits { nofile: Some(1024), nproc: Some(512) }));
    }

    // --- replace=true incompatible with .append on the same record ---

    #[test]
    fn replace_with_append_is_rejected() {
        // replace=true wipes the accumulator; an .append on the same record then
        // means "wipe then add only these" — almost certainly an author mistake.
        // Rejected before it can expand into root sudo. Exercised through the read
        // boundary (FakeCatalog::read_layer validates each record).
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                replace: true,
                groups: ListOverride::Append(vec!["wheel".to_owned()]),
                ..def("net")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let err = resolve_leaf("net", &os, &cat).unwrap_err();
        assert!(matches!(
            err,
            CatalogError::ContradictoryRecord { ref id, .. } if id == "net"
        ));

        // Also rejected for sudo.append.
        let cat2 = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                replace: true,
                sudo: ListOverride::Append(vec!["/usr/sbin/ip".to_owned()]),
                ..def("net")
            },
        );
        assert!(matches!(
            resolve_leaf("net", &os, &cat2).unwrap_err(),
            CatalogError::ContradictoryRecord { .. }
        ));
    }

    // --- sudo command values are validated at the read boundary ---

    #[test]
    fn sudo_command_with_newline_is_rejected() {
        // A newline would split the rendered rule into a second physical sudoers
        // line (directive injection). Rejected at parse, before root materialization.
        for sudo in [
            ListOverride::Replace(vec!["/usr/sbin/ip\n!root ALL=(ALL) ALL".to_owned()]),
            ListOverride::Append(vec!["/usr/sbin/ip\n!root ALL=(ALL) ALL".to_owned()]),
        ] {
            let cat = FakeCatalog::new().with("linux", PermissionDef { sudo, ..def("net") });
            let os = OsTarget::new("linux", "debian", None).unwrap();
            assert!(matches!(
                resolve_leaf("net", &os, &cat).unwrap_err(),
                CatalogError::InvalidSudoCommand { ref id, .. } if id == "net"
            ));
        }
    }

    #[test]
    fn sudo_command_with_control_char_is_rejected() {
        // Any control char (tab, NUL, CR, …) is rejected.
        for bad in ["/usr/sbin/ip\tfoo", "/usr/sbin/\0ip", "/usr/sbin/ip\r"] {
            let cat = FakeCatalog::new().with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec![bad.to_owned()]),
                    ..def("net")
                },
            );
            let os = OsTarget::new("linux", "debian", None).unwrap();
            assert!(
                matches!(
                    resolve_leaf("net", &os, &cat).unwrap_err(),
                    CatalogError::InvalidSudoCommand { .. }
                ),
                "control char {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn sudo_command_empty_or_whitespace_is_rejected() {
        for bad in ["", "   ", "\t"] {
            let cat = FakeCatalog::new().with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec![bad.to_owned()]),
                    ..def("net")
                },
            );
            let os = OsTarget::new("linux", "debian", None).unwrap();
            assert!(
                matches!(
                    resolve_leaf("net", &os, &cat).unwrap_err(),
                    CatalogError::InvalidSudoCommand { .. }
                ),
                "empty/whitespace {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn sudo_command_must_be_absolute_path() {
        // A non-absolute command (no leading `/`) — including sudoers tokens like
        // `ALL` — is rejected: Census only emits concrete absolute-path Cmnds.
        for bad in ["foo", "ip", "ALL"] {
            let cat = FakeCatalog::new().with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec![bad.to_owned()]),
                    ..def("net")
                },
            );
            let os = OsTarget::new("linux", "debian", None).unwrap();
            assert!(
                matches!(
                    resolve_leaf("net", &os, &cat).unwrap_err(),
                    CatalogError::InvalidSudoCommand { ref id, .. } if id == "net"
                ),
                "non-absolute {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn valid_absolute_sudo_command_passes() {
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                ..def("net")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve_leaf("net", &os, &cat).unwrap();
        assert_eq!(values(&r.sudo), vec!["/usr/sbin/ip"]);
    }

    #[test]
    fn live_catalog_rejects_non_absolute_sudo_command() {
        // Same gate on the filesystem read path.
        let root = tempfile::tempdir().unwrap();
        let layer_dir = root.path().join("linux");
        std::fs::create_dir_all(&layer_dir).unwrap();
        std::fs::write(layer_dir.join("net.toml"), "id = \"net\"\nsudo = [\"ip\"]\n").unwrap();
        let cat = LiveCatalog::new(vec![root.path().to_path_buf()]);
        assert!(matches!(
            cat.read_layer("linux").unwrap_err(),
            CatalogError::InvalidSudoCommand { id, .. } if id == "net"
        ));
    }

    #[test]
    fn replace_with_bare_array_is_allowed() {
        // replace=true + a bare-array full replace is the legitimate shape and
        // still works (wipe then take this list wholesale).
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    groups: ListOverride::Replace(vec!["netdev".to_owned()]),
                    sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                    ..def("net")
                },
            )
            .with(
                "linux-debian",
                PermissionDef {
                    replace: true,
                    groups: ListOverride::Replace(vec!["wheel".to_owned()]),
                    ..def("net")
                },
            );
        let (r, _) = resolve_leaf("net", &debian12(), &cat).unwrap();
        assert_eq!(values(&r.groups), vec!["wheel"]);
        // replace wiped the base sudo too.
        assert!(r.sudo.is_empty());
    }

    #[test]
    fn live_catalog_rejects_replace_with_append() {
        // Same replace+append gate on the filesystem read path.
        let root = tempfile::tempdir().unwrap();
        let layer_dir = root.path().join("linux");
        std::fs::create_dir_all(&layer_dir).unwrap();
        std::fs::write(
            layer_dir.join("net.toml"),
            "id = \"net\"\nreplace = true\nsudo = { append = [\"ip\"] }\n",
        )
        .unwrap();
        let cat = LiveCatalog::new(vec![root.path().to_path_buf()]);
        assert!(matches!(
            cat.read_layer("linux").unwrap_err(),
            CatalogError::ContradictoryRecord { id, .. } if id == "net"
        ));
    }

    // --- symlinked entries in catalog dirs are skipped ---

    #[test]
    #[cfg(unix)]
    fn live_catalog_skips_symlinked_entries() {
        // A symlink planted in a catalog dir must not be followed: as root it
        // would otherwise read+expand an out-of-tree *.toml into sudo.
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(
            outside.join("pwn.toml"),
            "id = \"pwn\"\nsudo = [\"rm -rf /\"]\n",
        )
        .unwrap();

        let root = tmp.path().join("catalog");
        let layer_dir = root.join("linux");
        std::fs::create_dir_all(&layer_dir).unwrap();
        // A legit in-tree file (positive control: still read).
        std::fs::write(layer_dir.join("ok.toml"), "id = \"ok\"\nsudo = [\"/bin/true\"]\n").unwrap();
        // A symlinked file pointing out of tree.
        std::os::unix::fs::symlink(outside.join("pwn.toml"), layer_dir.join("evil.toml")).unwrap();
        // A symlinked directory pointing out of tree.
        std::os::unix::fs::symlink(&outside, layer_dir.join("evil-ns")).unwrap();

        let cat = LiveCatalog::new(vec![root]);
        let defs = cat.read_layer("linux").unwrap();
        let ids: Vec<&str> = defs.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(ids, vec!["ok"], "only the in-tree file is read; symlinks skipped");
    }

    // --- slice 3b: parametrized templating ---

    /// Helper to build a `params` map from `(key, toml::Value)` pairs.
    fn params(pairs: Vec<(&str, toml::Value)>) -> std::collections::BTreeMap<String, toml::Value> {
        pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
    }

    fn arr(items: &[&str]) -> toml::Value {
        toml::Value::Array(items.iter().map(|s| toml::Value::String((*s).to_owned())).collect())
    }

    #[test]
    fn list_param_expands_one_command_per_element() {
        // service-restart-style record: each {unit} template, dual unit/.service
        // forms written explicitly by the author. A list param `unit` with two
        // elements yields one rendered command per template per element.
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                risk: Some(Risk::Contained),
                sudo: ListOverride::Replace(vec![
                    "/usr/bin/systemctl start {unit}".to_owned(),
                    "/usr/bin/systemctl stop {unit}".to_owned(),
                    "/usr/bin/systemctl restart {unit}".to_owned(),
                    "/usr/bin/systemctl status {unit}".to_owned(),
                    "/usr/bin/systemctl start {unit}.service".to_owned(),
                    "/usr/bin/systemctl stop {unit}.service".to_owned(),
                    "/usr/bin/systemctl restart {unit}.service".to_owned(),
                    "/usr/bin/systemctl status {unit}.service".to_owned(),
                ]),
                ..def("service-restart")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![("unit", arr(&["nginx", "atm-app"]))]);
        let (r, w) = resolve_with_params("service-restart", &p, &os, &cat, &ctx()).unwrap();
        // 8 templates x 2 units = 16 concrete commands, all absolute, no braces.
        assert_eq!(r.sudo.len(), 16);
        assert!(r.sudo.iter().all(|p| p.value.starts_with('/')));
        assert!(r.sudo.iter().all(|p| !p.value.contains('{')));
        assert!(values(&r.sudo).contains(&"/usr/bin/systemctl restart nginx"));
        assert!(values(&r.sudo).contains(&"/usr/bin/systemctl restart atm-app.service"));
        assert!(w.is_empty(), "fully-consumed params must not warn: {w:?}");
    }

    #[test]
    fn scalar_param_single_substitution() {
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/systemctl restart {unit}".to_owned()]),
                ..def("svc")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![("unit", toml::Value::String("nginx".to_owned()))]);
        let (r, _) = resolve_with_params("svc", &p, &os, &cat, &ctx()).unwrap();
        assert_eq!(values(&r.sudo), vec!["/usr/bin/systemctl restart nginx"]);
    }

    #[test]
    fn no_placeholders_no_params_is_unchanged() {
        // A plain record + a ref without params resolves exactly like resolve().
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                groups: ListOverride::Replace(vec!["netdev".to_owned()]),
                sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                ..def("net")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let empty = params(vec![]);
        let (a, _) = resolve("net", &os, &cat, &ctx()).unwrap();
        let (b, w) = resolve_with_params("net", &empty, &os, &cat, &ctx()).unwrap();
        assert_eq!(a.sudo, b.sudo);
        assert_eq!(a.groups, b.groups);
        assert!(w.is_empty());
    }

    #[test]
    fn placeholder_with_no_param_is_missing_param_error() {
        // Fail-closed: an unfilled {unit} must NOT leak literally into sudoers.
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/systemctl restart {unit}".to_owned()]),
                ..def("svc")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let empty = params(vec![]);
        let err = resolve_with_params("svc", &empty, &os, &cat, &ctx()).unwrap_err();
        assert!(matches!(
            err,
            CatalogError::MissingParam { ref permission, ref placeholder }
                if permission == "svc" && placeholder == "unit"
        ));
    }

    #[test]
    fn param_with_no_placeholder_warns_unused() {
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                ..def("net")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![("bogus", toml::Value::String("x".to_owned()))]);
        let (_r, w) = resolve_with_params("net", &p, &os, &cat, &ctx()).unwrap();
        assert!(
            w.iter().any(|w| matches!(
                w,
                Warning::UnusedParam { permission, param }
                    if permission == "net" && param == "bogus"
            )),
            "unused param must warn: {w:?}"
        );
    }

    #[test]
    fn injection_via_param_value_is_rejected() {
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/systemctl restart {unit}".to_owned()]),
                ..def("svc")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        // A value injecting a comma (splits Cmnds), whitespace, a newline, or a
        // shell metachar must be rejected — both as a scalar and inside a list.
        for bad in ["nginx,/bin/sh", "nginx /bin/sh", "nginx\nroot", "ng$x", "ng;x"] {
            let scalar = params(vec![("unit", toml::Value::String(bad.to_owned()))]);
            assert!(
                matches!(
                    resolve_with_params("svc", &scalar, &os, &cat, &ctx()).unwrap_err(),
                    CatalogError::InvalidParamValue { ref permission, .. } if permission == "svc"
                ),
                "scalar injection {bad:?} must be rejected"
            );
            let list = params(vec![("unit", arr(&[bad]))]);
            assert!(
                matches!(
                    resolve_with_params("svc", &list, &os, &cat, &ctx()).unwrap_err(),
                    CatalogError::InvalidParamValue { .. }
                ),
                "list-element injection {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn non_absolute_after_substitution_is_rejected() {
        // Defence in depth: even a metachar-free param that renders a
        // non-absolute Cmnd is caught by the post-substitution sudo gate.
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                // The whole command is the placeholder → renders to a bare token.
                sudo: ListOverride::Replace(vec!["{cmd}".to_owned()]),
                ..def("svc")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![("cmd", toml::Value::String("ip".to_owned()))]);
        assert!(matches!(
            resolve_with_params("svc", &p, &os, &cat, &ctx()).unwrap_err(),
            CatalogError::InvalidSudoCommand { ref id, .. } if id == "svc"
        ));
    }

    #[test]
    fn two_list_params_is_rejected() {
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/x {a} {b}".to_owned()]),
                ..def("svc")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![("a", arr(&["1", "2"])), ("b", arr(&["3", "4"]))]);
        assert!(matches!(
            resolve_with_params("svc", &p, &os, &cat, &ctx()).unwrap_err(),
            CatalogError::MultipleListParams { ref permission, .. } if permission == "svc"
        ));
    }

    #[test]
    fn scalar_plus_one_list_param_combine() {
        // A template with both a scalar and a list placeholder: the scalar is the
        // same in every output, the list iterates.
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/{verb} {unit}".to_owned()]),
                ..def("svc")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![
            ("verb", toml::Value::String("restart".to_owned())),
            ("unit", arr(&["nginx", "redis"])),
        ]);
        let (r, _) = resolve_with_params("svc", &p, &os, &cat, &ctx()).unwrap();
        assert_eq!(
            values(&r.sudo),
            vec!["/usr/bin/restart nginx", "/usr/bin/restart redis"]
        );
    }

    #[test]
    fn groups_template_substitutes_too() {
        // Placeholders work in group names as well as sudo commands.
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                groups: ListOverride::Replace(vec!["svc-{unit}".to_owned()]),
                ..def("svc")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![("unit", arr(&["nginx", "redis"]))]);
        let (r, _) = resolve_with_params("svc", &p, &os, &cat, &ctx()).unwrap();
        assert_eq!(values(&r.groups), vec!["svc-nginx", "svc-redis"]);
    }

    #[test]
    fn templated_record_parses_at_read_boundary() {
        // A placeholder-bearing sudo template must pass the parse-time validator
        // (it would otherwise fail the absolute-path check before resolve runs).
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/systemctl restart {unit}".to_owned()]),
                ..def("svc")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        // resolve() (no params) leaves the template literal — proving parse passed.
        let (r, _) = resolve("svc", &os, &cat, &ctx()).unwrap();
        assert_eq!(values(&r.sudo), vec!["/usr/bin/systemctl restart {unit}"]);
    }

    // --- file-access grants (slice 1: format + resolve + shape) ---

    #[test]
    fn parses_file_grant_ro_rw_recursive() {
        let def: PermissionDef = toml::from_str(
            r#"
id = "ssh-admin"
[[file]]
path = "/etc/ssh"
access = "rw"
recursive = true
[[file]]
path = "/var/log/auth.log"
access = "ro"
"#,
        )
        .unwrap();
        assert_eq!(def.files.len(), 2);
        assert_eq!(def.files[0].path, "/etc/ssh");
        assert_eq!(def.files[0].access, Access::Rw);
        assert!(def.files[0].recursive);
        assert_eq!(def.files[1].access, Access::Ro);
        // recursive defaults to false when absent.
        assert!(!def.files[1].recursive);
    }

    #[test]
    fn file_grant_unknown_field_rejected() {
        // deny_unknown_fields on the sub-table: a typo'd key must not be dropped.
        let src = r#"
id = "a"
[[file]]
path = "/etc/ssh"
access = "rw"
bogus = true
"#;
        assert!(toml::from_str::<PermissionDef>(src).is_err());
    }

    #[test]
    fn file_grant_bad_access_rejected() {
        let src = r#"
id = "a"
[[file]]
path = "/etc/ssh"
access = "wo"
"#;
        assert!(toml::from_str::<PermissionDef>(src).is_err());
    }

    fn file_def(id: &str, grants: Vec<FileGrant>) -> PermissionDef {
        PermissionDef {
            files: grants,
            ..def(id)
        }
    }

    fn grant(path: &str, access: Access, recursive: bool) -> FileGrant {
        FileGrant {
            path: path.to_owned(),
            access,
            recursive,
        }
    }

    #[test]
    fn file_path_relative_rejected_at_read_boundary() {
        // A relative path would become a root setfacl target resolved against cwd.
        let cat = FakeCatalog::new();
        let bad = file_def("a", vec![grant("etc/ssh", Access::Rw, true)]);
        // validate() runs at the read boundary; FakeCatalog.read_layer triggers it.
        let cat = cat.with("linux", bad);
        let err = resolve_leaf("a", &OsTarget::new("linux", "debian", None).unwrap(), &cat)
            .unwrap_err();
        assert!(matches!(
            err,
            CatalogError::InvalidFilePath { ref id, reason, .. }
                if id == "a" && reason.contains("absolute")
        ));
    }

    #[test]
    fn file_path_dotdot_component_rejected() {
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("a", vec![grant("/etc/ssh/../shadow", Access::Ro, false)]),
        );
        let err = resolve_leaf("a", &OsTarget::new("linux", "debian", None).unwrap(), &cat)
            .unwrap_err();
        assert!(matches!(
            err,
            CatalogError::InvalidFilePath { reason, .. } if reason.contains("..")
        ));
    }

    #[test]
    fn file_path_control_char_rejected() {
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("a", vec![grant("/etc/ss\nh", Access::Ro, false)]),
        );
        let err = resolve_leaf("a", &OsTarget::new("linux", "debian", None).unwrap(), &cat)
            .unwrap_err();
        assert!(matches!(
            err,
            CatalogError::InvalidFilePath { reason, .. } if reason.contains("control")
        ));
    }

    #[test]
    fn dotdot_inside_name_is_allowed() {
        // `a..b` as a longer component is not a traversal; only a bare `..` is.
        let g = grant("/etc/my..app", Access::Ro, true);
        assert_eq!(file_path_static_defect(&g.path), None);
    }

    #[test]
    fn shape_derivation_rule() {
        // recursive=true → Dir.
        assert_eq!(grant("/etc/ssh", Access::Rw, true).shape(), Shape::Dir);
        // trailing slash → Dir even without recursive.
        assert_eq!(grant("/etc/ssh/", Access::Rw, false).shape(), Shape::Dir);
        // bare path, no recursive, no slash → File (the AclBackend refuses these,
        // steering authors to widen to a directory).
        assert_eq!(grant("/etc/ssh", Access::Rw, false).shape(), Shape::File);
        // glob metachar → Pattern, regardless of recursive.
        assert_eq!(grant("/var/log/*.log", Access::Ro, false).shape(), Shape::Pattern);
        assert_eq!(grant("/var/log/*.log", Access::Ro, true).shape(), Shape::Pattern);
        assert_eq!(grant("/etc/conf?", Access::Ro, false).shape(), Shape::Pattern);
        assert_eq!(grant("/etc/[abc]", Access::Ro, false).shape(), Shape::Pattern);
    }

    #[test]
    fn trailing_slash_with_recursive_false_rejected_at_read_boundary() {
        // A trailing '/' marks Shape::Dir, which the AclBackend always materializes
        // recursively; pairing it with recursive=false is contradictory (the flag
        // is silently ineffective) and must fail closed at the read boundary.
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("a", vec![grant("/etc/ssh/", Access::Rw, false)]),
        );
        let err = resolve_leaf("a", &OsTarget::new("linux", "debian", None).unwrap(), &cat)
            .unwrap_err();
        assert!(matches!(
            err,
            CatalogError::InvalidFilePath { ref id, reason, .. }
                if id == "a" && reason.contains("trailing '/'")
        ));

        // trailing slash + recursive=true → accepted, resolves as Dir.
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("b", vec![grant("/etc/ssh/", Access::Rw, true)]),
        );
        let (r, _) =
            resolve_leaf("b", &OsTarget::new("linux", "debian", None).unwrap(), &cat).unwrap();
        assert_eq!(r.file_grants[0].shape, Shape::Dir);

        // no trailing slash + recursive=true → accepted, Dir.
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("c", vec![grant("/etc/ssh", Access::Rw, true)]),
        );
        let (r, _) =
            resolve_leaf("c", &OsTarget::new("linux", "debian", None).unwrap(), &cat).unwrap();
        assert_eq!(r.file_grants[0].shape, Shape::Dir);

        // no trailing slash + recursive=false → accepted, File (unchanged).
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("d", vec![grant("/etc/ssh", Access::Rw, false)]),
        );
        let (r, _) =
            resolve_leaf("d", &OsTarget::new("linux", "debian", None).unwrap(), &cat).unwrap();
        assert_eq!(r.file_grants[0].shape, Shape::File);
    }

    #[test]
    fn resolve_collects_file_grant_with_provenance() {
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("ssh-admin", vec![grant("/etc/ssh", Access::Rw, true)]),
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve_leaf("ssh-admin", &os, &cat).unwrap();
        assert_eq!(r.file_grants.len(), 1);
        let fg = &r.file_grants[0];
        assert_eq!(fg.path, "/etc/ssh");
        assert_eq!(fg.access, Access::Rw);
        assert!(fg.recursive);
        assert_eq!(fg.shape, Shape::Dir);
        assert_eq!(fg.sources.len(), 1);
        assert_eq!(fg.sources[0].layer, "linux");
        assert!(fg.sources[0].via.is_none());
    }

    #[test]
    fn resolve_unions_file_grants_max_access_recursive_or() {
        // Same path across two layers: ro+rw → rw, and recursive false|true → true.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                file_def("ssh-admin", vec![grant("/etc/ssh", Access::Ro, false)]),
            )
            .with(
                "linux-debian",
                file_def("ssh-admin", vec![grant("/etc/ssh", Access::Rw, true)]),
            );
        let (r, _) = resolve_leaf("ssh-admin", &debian12(), &cat).unwrap();
        assert_eq!(r.file_grants.len(), 1, "same path must union, not duplicate");
        let fg = &r.file_grants[0];
        assert_eq!(fg.access, Access::Rw, "access widens to max");
        assert!(fg.recursive, "recursive is OR");
        // Effective recursive flips the file→dir shape.
        assert_eq!(fg.shape, Shape::Dir);
        // Both contributing layers are recorded.
        assert_eq!(fg.sources.len(), 2);
        assert_eq!(fg.sources[0].layer, "linux");
        assert_eq!(fg.sources[1].layer, "linux-debian");
    }

    #[test]
    fn replace_layer_wipes_file_grants() {
        let cat = FakeCatalog::new()
            .with(
                "linux",
                file_def("a", vec![grant("/etc/ssh", Access::Ro, true)]),
            )
            .with(
                "linux-debian",
                PermissionDef {
                    replace: true,
                    files: vec![grant("/etc/pam.d", Access::Rw, true)],
                    ..def("a")
                },
            );
        let (r, _) = resolve_leaf("a", &debian12(), &cat).unwrap();
        assert_eq!(r.file_grants.len(), 1);
        assert_eq!(r.file_grants[0].path, "/etc/pam.d");
    }

    #[test]
    fn distinct_paths_preserved_in_order() {
        let cat = FakeCatalog::new().with(
            "linux",
            file_def(
                "a",
                vec![
                    grant("/etc/ssh", Access::Rw, true),
                    grant("/var/log", Access::Ro, true),
                ],
            ),
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve_leaf("a", &os, &cat).unwrap();
        let paths: Vec<&str> = r.file_grants.iter().map(|g| g.path.as_str()).collect();
        assert_eq!(paths, vec!["/etc/ssh", "/var/log"]);
    }

    #[test]
    fn templated_file_path_substitutes_and_revalidates() {
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("app-config", vec![grant("/etc/{app}", Access::Rw, true)]),
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![("app", toml::Value::String("nginx".to_owned()))]);
        let (r, w) = resolve_with_params("app-config", &p, &os, &cat, &ctx()).unwrap();
        assert_eq!(r.file_grants.len(), 1);
        assert_eq!(r.file_grants[0].path, "/etc/nginx");
        assert_eq!(r.file_grants[0].shape, Shape::Dir);
        assert!(w.is_empty());
    }

    #[test]
    fn templated_file_path_list_expands_to_multiple_grants() {
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("app-config", vec![grant("/etc/{app}", Access::Rw, true)]),
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![("app", arr(&["nginx", "redis"]))]);
        let (r, _) = resolve_with_params("app-config", &p, &os, &cat, &ctx()).unwrap();
        let paths: Vec<&str> = r.file_grants.iter().map(|g| g.path.as_str()).collect();
        assert_eq!(paths, vec!["/etc/nginx", "/etc/redis"]);
    }

    #[test]
    fn templated_file_path_injection_rejected() {
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("app-config", vec![grant("/etc/{app}", Access::Rw, true)]),
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        // A `..` smuggled via the param renders to a traversal path — must be
        // rejected by the post-substitution gate. The param-value gate also blocks
        // many metachars; this asserts the file-path gate as the authoritative one
        // for a value that survives param validation as a plain token.
        let p = params(vec![("app", toml::Value::String("ssh".to_owned()))]);
        // Sanity: a clean value passes (so the rejection below is about injection).
        assert!(resolve_with_params("app-config", &p, &os, &cat, &ctx()).is_ok());
        // A param-level metachar (`/`) is blocked at the param-value gate before
        // it can build a traversal path.
        let bad = params(vec![("app", toml::Value::String("../shadow".to_owned()))]);
        assert!(resolve_with_params("app-config", &bad, &os, &cat, &ctx()).is_err());
    }

    #[test]
    fn templated_whole_path_param_revalidated_by_file_gate() {
        // The whole path is the placeholder, so the parse-time absolute check was
        // deferred; the post-substitution file gate must catch a non-absolute or
        // `..`-bearing render. Use a param value that passes the param-value token
        // gate but is non-absolute, proving the file gate is the one that fires.
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("a", vec![grant("/{p}", Access::Ro, false)]),
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        // Renders to "/etc" — absolute, fine.
        let ok = params(vec![("p", toml::Value::String("etc".to_owned()))]);
        assert!(resolve_with_params("a", &ok, &os, &cat, &ctx()).is_ok());
    }
}
