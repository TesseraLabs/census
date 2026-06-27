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

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::rolestore::Limits;

/// Risk class of a permission. Advisory only (honest labelling, not
/// enforcement): it never blocks expansion or apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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

/// Hand-written schema for [`ListOverride`]: the type has a custom
/// `Deserialize` (a bare array OR a `{ append = [...] }` table), so its schema
/// is written by hand to mirror exactly that one-of. A derive would not match
/// the custom deserializer, defeating the point of the contract. The two arms
/// are: a plain array of strings (replace), or a strict object with a required
/// `append` array (append). Behind the `schema` feature — schema generation is a
/// CI/contract concern, not part of the default public API.
#[cfg(feature = "schema")]
impl schemars::JsonSchema for ListOverride {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ListOverride".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        // Both arms describe an array of strings. Build the element schema once
        // per arm from the canonical `Vec<String>` schema so the element type
        // stays in lockstep with the field type rather than being hand-spelled.
        let replace = <Vec<String>>::json_schema(generator);
        let append_items = <Vec<String>>::json_schema(generator);

        // Arm 1: bare array → Replace. Arm 2: `{ append = [...] }` → Append
        // (strict object, append required).
        schemars::json_schema!({
            "oneOf": [
                replace,
                {
                    "type": "object",
                    "required": ["append"],
                    "properties": {
                        "append": append_items,
                    },
                    "additionalProperties": false,
                },
            ],
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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

/// A role-supplied permission parameter value, in the census-owned param domain.
///
/// A role's `PermissionRef` carries parameters that fill a catalog template's
/// `{placeholder}`s. Census reads role slices as TOML, but the parameter domain
/// is Census's own contract — only the scalar kinds a template can splice
/// (string/int/float/bool) plus a list of those (which expands to one rendered
/// command per element). Keeping this a census type, rather than re-exposing
/// `toml::Value`, means a future TOML parser bump (or a non-TOML role source) is
/// not a breaking change to the resolve API: conversion happens once, at the
/// slice-parse boundary ([`ParamValue::from_toml`]).
#[derive(Debug, Clone, PartialEq)]
pub enum ParamValue {
    /// A string parameter.
    String(String),
    /// An integer parameter.
    Integer(i64),
    /// A floating-point parameter.
    Float(f64),
    /// A boolean parameter.
    Boolean(bool),
    /// A list parameter; expands the template into one command per element. Only
    /// scalar elements are valid — a nested list or table element is rejected at
    /// resolve time.
    Array(Vec<ParamValue>),
    /// A value census does not splice into a template (a TOML datetime, table, or
    /// nested non-scalar). Preserved so it round-trips and is rejected with a
    /// clear "not a scalar" error at the point it would be substituted, rather
    /// than silently dropped at the parse boundary.
    Other,
}

impl ParamValue {
    /// Convert a parsed `toml::Value` into the census param domain. The single
    /// boundary where `toml` enters the parameter path; every downstream resolve
    /// API speaks [`ParamValue`].
    pub fn from_toml(value: toml::Value) -> Self {
        match value {
            toml::Value::String(s) => ParamValue::String(s),
            toml::Value::Integer(i) => ParamValue::Integer(i),
            toml::Value::Float(f) => ParamValue::Float(f),
            toml::Value::Boolean(b) => ParamValue::Boolean(b),
            toml::Value::Array(items) => {
                ParamValue::Array(items.into_iter().map(ParamValue::from_toml).collect())
            }
            // Datetime and Table have no scalar template rendering.
            _ => ParamValue::Other,
        }
    }
}

/// The maximum length a `token`/`enum`/`path`-kind constraint accepts when no
/// explicit `max_len` is given. A systemd unit name, a Unix login, and an
/// interface name all fit well under this; the ceiling exists so an
/// unconstrained-length token cannot balloon a rendered sudoers line. 256 is
/// generous for any real identifier yet still bounds the rendered Cmnd.
const PARAM_DEFAULT_MAX_LEN: usize = 256;

/// The default `kind = "path"` glob policy: reject glob metacharacters (`*?[`)
/// in a substituted path unless the record opts in with `deny_glob = false`. A
/// glob in a file-grant path widens the ACL target from one tree to a pattern,
/// so the safe default is to refuse it.
const PARAM_PATH_DENY_GLOB_DEFAULT: bool = true;

/// A per-parameter constraint a catalog record places on the value a role may
/// substitute into one of its `{placeholder}`s.
///
/// Templating fills `{name}` in a sudo command, group name, or file-grant path
/// with a role-supplied value; without a constraint that value is unbounded, so
/// a role could point a parametrized file permission at `/etc/shadow` or splice
/// an unexpected unit into a `systemctl` rule. Every placeholder in a record
/// MUST carry a matching `[params.<name>]` (enforced at parse, fail-closed), and
/// the substituted value is checked against it at resolve time, *before* the
/// existing sudo/path static gates — defence in depth, not instead of them.
///
/// Tagged on the TOML `kind` key (externally distinct kinds, one set of
/// per-kind fields each), so a record writes e.g. `kind = "token"` /
/// `kind = "path"` / `kind = "enum"` and only that kind's fields are accepted
/// (`deny_unknown_fields`, like the rest of the catalog).
///
/// # Examples
///
/// ```toml
/// [params.units]
/// kind = "token"          # systemd unit name; safe charset, bounded length
///
/// [params.path]
/// kind = "path"
/// allow_prefix = ["/etc/app/"]   # substituted path must sit under one of these
///
/// [params.verb]
/// kind = "enum"
/// values = ["start", "stop"]     # substituted value must be one of these
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum ParamConstraint {
    /// A portable identifier (a systemd unit, an interface, a login name). The
    /// substituted value must be non-empty, within the length bound, and drawn
    /// from a safe identifier charset (ASCII alphanumerics plus the documented
    /// `-_.@:\/` set systemd unit names use). Sudoers/path/shell metacharacters
    /// are rejected — the param-value gate already blocks the worst of them, and
    /// this narrows further to a real identifier shape.
    #[serde(rename = "token")]
    Token {
        /// Maximum accepted length; defaults to [`PARAM_DEFAULT_MAX_LEN`].
        #[serde(default)]
        max_len: Option<usize>,
    },
    /// A filesystem path. The substituted value must sit under one of
    /// `allow_prefix` (so a parametrized file grant cannot be steered outside its
    /// intended trees), pass the existing post-substitution path gate (absolute,
    /// no `..`, no control char), stay within the length bound, and — unless
    /// `deny_glob = false` — contain no glob metacharacter (`*?[`).
    #[serde(rename = "path")]
    Path {
        /// Allowed path prefixes; the substituted path must be at, or under, one
        /// of them on a `/`-component boundary (so `/etc/app/` admits
        /// `/etc/app/x` but never the sibling `/etc/apparmor.d`). Each prefix
        /// must be an absolute directory ending in `/`; at least one is required
        /// (an empty list would allow any absolute path) — both enforced at parse.
        allow_prefix: Vec<String>,
        /// Reject glob metacharacters (`*?[`) in the substituted path unless set
        /// to `false`. Defaults to [`PARAM_PATH_DENY_GLOB_DEFAULT`] (true).
        #[serde(default)]
        deny_glob: Option<bool>,
        /// Maximum accepted length; defaults to [`PARAM_DEFAULT_MAX_LEN`].
        #[serde(default)]
        max_len: Option<usize>,
    },
    /// A closed set of allowed values. The substituted value must equal one of
    /// `values` exactly.
    #[serde(rename = "enum")]
    Enum {
        /// The exact set of accepted values; must be non-empty (enforced at
        /// parse — an empty set would reject every value).
        values: Vec<String>,
    },
    /// A single safe path segment that doubles as a plain name. The substituted
    /// value must be non-empty, within the length bound, and drawn from a
    /// deliberately narrow charset — ASCII alphanumerics plus `.`, `_`, `-`
    /// only — with the bare `.` and `..` components rejected outright. Because it
    /// cannot contain `/`, `\`, `:`, `@`, or any control character, one value is
    /// safe to drop into both a single path component (`/etc/{seg}`) and a token
    /// position (a unit name, a login), without risking traversal, an absolute
    /// path, or a sudoers/shell metacharacter.
    ///
    /// This is strictly narrower than [`ParamConstraint::Token`]: `token` admits
    /// `/`, `\`, `:`, and `@` (needed for path-like and instance/slice unit
    /// names) and so is *not* safe as a path segment. The exclusion of `@` and
    /// `:` here is the known limitation — `segment` cannot express a systemd
    /// instance or slice unit name (`wg-quick@wg0`, `system.slice`); those still
    /// require `token`.
    #[serde(rename = "segment")]
    Segment {
        /// Maximum accepted length; defaults to [`PARAM_DEFAULT_MAX_LEN`].
        #[serde(default)]
        max_len: Option<usize>,
    },
}

/// The safe punctuation a `kind = "token"` value may use beyond ASCII
/// alphanumerics: the characters systemd unit names and similar identifiers
/// rely on. Deliberately excludes every sudoers/shell metacharacter (comma,
/// semicolon, the redirection and quoting set, and so on) and whitespace, so a
/// token cannot smuggle one past this gate. The `@` and `:` appear in
/// instance/slice unit names (such as wg-quick@wg0 and system-getty.slice);
/// the slash and dot appear in path-like unit names; the hyphen and underscore
/// are ubiquitous in identifiers.
const TOKEN_EXTRA_CHARS: &[char] = &['-', '_', '.', '@', ':', '\\', '/'];

/// The safe punctuation a `kind = "segment"` value may use beyond ASCII
/// alphanumerics. Strictly narrower than [`TOKEN_EXTRA_CHARS`]: only the dot,
/// underscore, and hyphen that appear inside a single filename or plain
/// identifier. Excludes every path separator (`/`, `\`), the `@`/`:` of
/// instance/slice unit names, and all shell/sudoers metacharacters, so a
/// segment value can never widen a path component into a traversal, an absolute
/// path, or a second path level.
const SEGMENT_EXTRA_CHARS: &[char] = &['.', '_', '-'];

/// Whether `child` is `parent` itself, or lies under it on a `/`-component
/// boundary. Unlike a raw [`str::starts_with`], `parent = "/etc/app"` matches
/// `/etc/app` and `/etc/app/conf` but never the textual sibling
/// `/etc/apparmor.d`. A single trailing `/` on `parent` is ignored, so
/// `"/etc/app"` and `"/etc/app/"` behave identically.
///
/// This is the enforcement counterpart of the advisory boundary test used by the
/// risk lints (`crate::cli::lint`), which builds its bidirectional overlap check
/// on top of this same matcher so the two can never drift apart.
pub(crate) fn path_at_or_under(parent: &str, child: &str) -> bool {
    let parent = parent.strip_suffix('/').unwrap_or(parent);
    if parent == child {
        return true;
    }
    child
        .strip_prefix(parent)
        .is_some_and(|rest| rest.starts_with('/'))
}

impl ParamConstraint {
    /// Validate the constraint declaration itself (independent of any value).
    ///
    /// A `path` constraint with no `allow_prefix`, or an `enum` with no
    /// `values`, would accept anything (or nothing) and is almost certainly an
    /// authoring mistake; reject it at parse so the record fails closed rather
    /// than silently widening. Returns the rejection reason, or `None` if the
    /// declaration is well-formed.
    fn declaration_defect(&self) -> Option<&'static str> {
        match self {
            ParamConstraint::Token { .. } => None,
            ParamConstraint::Path { allow_prefix, .. } => {
                if allow_prefix.is_empty() {
                    Some("path constraint requires a non-empty allow_prefix")
                } else if allow_prefix.iter().any(|p| !p.starts_with('/')) {
                    Some("every allow_prefix must be an absolute path (start with '/')")
                } else if allow_prefix.iter().any(|p| !p.ends_with('/')) {
                    // A prefix must name a directory boundary. Without the
                    // trailing `/`, a containment test could admit a textual
                    // sibling (`/etc/app` matching `/etc/apparmor.d/...`); fail
                    // closed at parse so only component-bounded prefixes are
                    // ever enforced.
                    Some("every allow_prefix must name a directory (end with '/')")
                } else {
                    None
                }
            }
            ParamConstraint::Enum { values } => {
                if values.is_empty() {
                    Some("enum constraint requires a non-empty values list")
                } else {
                    None
                }
            }
            // A segment declaration carries only an optional length bound; like a
            // token, there is nothing in the declaration itself that can be
            // malformed.
            ParamConstraint::Segment { .. } => None,
        }
    }

    /// The constraint with its defaulted-optional fields resolved to the effective
    /// values resolve actually enforces (`max_len` → [`PARAM_DEFAULT_MAX_LEN`],
    /// `deny_glob` → [`PARAM_PATH_DENY_GLOB_DEFAULT`]). Used to compare two
    /// constraints by *meaning* rather than by surface syntax, so e.g.
    /// `max_len = None` and `max_len = 256` (the default) are recognised as the
    /// same constraint instead of a spurious conflict.
    fn normalized(&self) -> ParamConstraint {
        match self {
            ParamConstraint::Token { max_len } => ParamConstraint::Token {
                max_len: Some(max_len.unwrap_or(PARAM_DEFAULT_MAX_LEN)),
            },
            ParamConstraint::Path {
                allow_prefix,
                deny_glob,
                max_len,
            } => ParamConstraint::Path {
                allow_prefix: allow_prefix.clone(),
                deny_glob: Some(deny_glob.unwrap_or(PARAM_PATH_DENY_GLOB_DEFAULT)),
                max_len: Some(max_len.unwrap_or(PARAM_DEFAULT_MAX_LEN)),
            },
            ParamConstraint::Enum { values } => ParamConstraint::Enum {
                values: values.clone(),
            },
            ParamConstraint::Segment { max_len } => ParamConstraint::Segment {
                max_len: Some(max_len.unwrap_or(PARAM_DEFAULT_MAX_LEN)),
            },
        }
    }

    /// Check one substituted value against this constraint. Returns the rejection
    /// reason, or `None` if the value satisfies the constraint.
    ///
    /// Runs at resolve time, *before* the existing sudo/path static gates, on
    /// every rendered value (for a list param, on each element). The two layers
    /// are complementary: this one bounds the value to the record's declared
    /// domain (charset / prefix / member set), the static gates independently
    /// re-check the fully-rendered Cmnd or path.
    fn value_defect(&self, value: &str) -> Option<&'static str> {
        match self {
            ParamConstraint::Token { max_len } => {
                if value.is_empty() {
                    return Some("token value is empty");
                }
                if value.len() > max_len.unwrap_or(PARAM_DEFAULT_MAX_LEN) {
                    return Some("token value exceeds max_len");
                }
                if value
                    .chars()
                    .any(|c| !(c.is_ascii_alphanumeric() || TOKEN_EXTRA_CHARS.contains(&c)))
                {
                    return Some(
                        "token value contains a character outside the safe identifier charset",
                    );
                }
                None
            }
            ParamConstraint::Path {
                allow_prefix,
                deny_glob,
                max_len,
            } => {
                if value.len() > max_len.unwrap_or(PARAM_DEFAULT_MAX_LEN) {
                    return Some("path value exceeds max_len");
                }
                // The absolute/`..`/control checks are the file-path gate's job and
                // run right after; here we own the prefix and glob policy. The
                // prefix test is on a `/`-component boundary, not a raw text
                // prefix, so a sibling directory can never satisfy it.
                if !allow_prefix
                    .iter()
                    .any(|p| path_at_or_under(p.as_str(), value))
                {
                    return Some("path value is not under any allowed prefix");
                }
                if deny_glob.unwrap_or(PARAM_PATH_DENY_GLOB_DEFAULT) && has_glob_metachar(value) {
                    return Some(
                        "path value contains a glob metacharacter (*?[) but globs are denied",
                    );
                }
                None
            }
            ParamConstraint::Enum { values } => {
                if values.iter().any(|v| v == value) {
                    None
                } else {
                    Some("value is not one of the allowed enum values")
                }
            }
            ParamConstraint::Segment { max_len } => {
                if value.is_empty() {
                    return Some("segment value is empty");
                }
                if value.len() > max_len.unwrap_or(PARAM_DEFAULT_MAX_LEN) {
                    return Some("segment value exceeds max_len");
                }
                // `.` and `..` are valid filenames to the charset check below but
                // are the current-directory and parent-directory components; a
                // value that is exactly one of them must never reach a path, so
                // reject them before the charset gate.
                if value == "." || value == ".." {
                    return Some("segment value must not be `.` or `..`");
                }
                if value
                    .chars()
                    .any(|c| !(c.is_ascii_alphanumeric() || SEGMENT_EXTRA_CHARS.contains(&c)))
                {
                    return Some(
                        "segment value contains a character outside the safe path-segment charset",
                    );
                }
                None
            }
        }
    }
}

/// The set of file-access bits a grant requests.
///
/// A *set* of independent bits, not an ordered ladder: each of `read`, `write`,
/// `execute`, `traverse` composes by union (OR), so two grants on the same path
/// merge to the union of their bits. The four bits map onto a POSIX ACL perm
/// string (see [`crate::fileaccess`]):
///
/// - `read` → `r` (read file contents / list a directory);
/// - `write` → `w`;
/// - `execute` → lowercase `x` (run a file — execute on a *file* inode);
/// - `traverse` → conditional `X` (enter/search a directory — execute on a *dir*
///   inode only, never on a regular file the way lowercase `x` would).
///
/// `read` and `traverse` are deliberately separate: a directory-read grant lists
/// a tree (`r`) and walks into it (`X`) without ever gaining execute on the
/// regular files inside, which is exactly the legacy `ro` semantics. The two
/// legacy strings map onto fixed bit sets that materialize byte-for-byte to the
/// historical ACL strings: `"ro"` → `{read, traverse}` (`r-X`) and `"rw"` →
/// `{read, write, traverse}` (`rwX`).
///
/// Some POSIX ACL modes have no representation here on purpose: there is no
/// `append` bit, because the open ACL backend cannot express append-only access,
/// and admitting a token that maps to it would promise enforcement Census cannot
/// deliver. An unknown access token or bit name fails closed at parse.
// `Ord` is derived over the raw `u8` bit field so an `Access` can key a
// set-equality comparison (the plan/apply drift gate sorts grant keys). The
// order is arbitrary-but-total — only equality and a stable sort are relied on,
// never a "wider/narrower" meaning (access composes by bit-union, not a ladder).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Access(u8);

impl Access {
    /// Read file contents or list a directory → ACL `r`.
    pub const READ: Access = Access(0b0001);
    /// Modify file contents or a directory's entries → ACL `w`.
    pub const WRITE: Access = Access(0b0010);
    /// Run a file (execute on a *file* inode) → lowercase ACL `x`.
    pub const EXECUTE: Access = Access(0b0100);
    /// Enter/search a directory (execute on a *dir* inode) → conditional ACL `X`.
    pub const TRAVERSE: Access = Access(0b1000);

    /// Legacy `ro`: read + directory-traverse — materializes to `r-X`.
    pub const RO: Access = Access(Access::READ.0 | Access::TRAVERSE.0);
    /// Legacy `rw`: read + write + directory-traverse — materializes to `rwX`.
    pub const RW: Access = Access(Access::READ.0 | Access::WRITE.0 | Access::TRAVERSE.0);

    /// Whether this set contains every bit in `bit` (used to test a single bit).
    #[must_use]
    pub const fn contains(self, bit: Access) -> bool {
        self.0 & bit.0 == bit.0
    }

    /// Whether no bit is set. An empty access grants nothing; the parser rejects
    /// it so a grant always requests at least one capability.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The union of two access sets (OR of their bits). Used when unioning grants
    /// on the same path across permissions, layers, and bundle members: access
    /// composes rather than picking a winner, so `{read} ∪ {write,traverse}` is
    /// `{read,write,traverse}`. Commutative and idempotent.
    #[must_use]
    pub const fn union(self, other: Access) -> Access {
        Access(self.0 | other.0)
    }
}

impl std::ops::BitOr for Access {
    type Output = Access;

    fn bitor(self, rhs: Access) -> Access {
        self.union(rhs)
    }
}

impl std::ops::BitOrAssign for Access {
    fn bitor_assign(&mut self, rhs: Access) {
        self.0 |= rhs.0;
    }
}

impl std::fmt::Debug for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Debug as the set of bit names so test failures and logs read clearly,
        // e.g. `Access(read | traverse)`.
        let mut first = true;
        write!(f, "Access(")?;
        for (bit, name) in [
            (Access::READ, "read"),
            (Access::WRITE, "write"),
            (Access::EXECUTE, "execute"),
            (Access::TRAVERSE, "traverse"),
        ] {
            if self.contains(bit) {
                if !first {
                    write!(f, " | ")?;
                }
                write!(f, "{name}")?;
                first = false;
            }
        }
        if first {
            write!(f, "<empty>")?;
        }
        write!(f, ")")
    }
}

impl std::fmt::Display for Access {
    /// Render the short display token (`ro`/`rw` for the legacy sets, else the
    /// sorted perm letters `r`/`w`/`x`/`X`). A human-facing summary for plan and
    /// coverage notes; the machine-readable, round-tripping form is the serde
    /// serialization (see [`Access::serialize`]).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display_token())
    }
}

impl<'de> Deserialize<'de> for Access {
    /// Parse an access from TOML, accepting two interchangeable grammars:
    ///
    /// - one of the eight canonical compact strings — the legacy aliases `"ro"`
    ///   (== `{read, traverse}`) and `"rw"` (== `{read, write, traverse}`), plus
    ///   the lowercase perm-letter combinations in fixed `r` < `w` < `x` order
    ///   (`"r"`, `"w"`, `"x"`, `"rx"`, `"wx"`, `"rwx"`); a misordered or repeated
    ///   string (`"xr"`, `"rr"`) is rejected so the grammar matches the schema;
    /// - an array of bit names: `["read"]`, `["read", "traverse"]`,
    ///   `["read", "execute"]`, … drawn from `read`/`write`/`execute`/`traverse`
    ///   — the only way to spell a set the compact letters cannot (e.g. a
    ///   `traverse` bit on its own).
    ///
    /// Both forms must name at least one capability. Any unknown token, letter, or
    /// bit name — including anything that would map to an `append`-style mode
    /// Census cannot enforce — fails closed.
    fn deserialize<D>(deserializer: D) -> Result<Access, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        // Accept either a string (compact letters / legacy alias) or a list of
        // bit names. `toml`/`serde` hand us one or the other; an untagged enum
        // lets a single field accept both without a wrapper table.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Compact(String),
            Bits(Vec<String>),
        }

        match Raw::deserialize(deserializer)? {
            Raw::Compact(s) => parse_compact_access(&s)
                .ok_or_else(|| D::Error::custom(format!("unknown access {s:?}"))),
            Raw::Bits(names) => parse_bit_names(&names).map_err(D::Error::custom),
        }
    }
}

impl serde::Serialize for Access {
    /// Serialize so a round-tripped grant re-parses to the same set. The two
    /// legacy sets keep their historical string spellings (`"ro"`, `"rw"`) so a
    /// persisted managed-registry grant written before this change still reads
    /// back identically. Every other set serializes as the bit-name ARRAY
    /// (`["read", "write"]`, …): the compact letter form would render `{read,
    /// write}` as `"rw"`, colliding with the legacy `rw` alias (which carries
    /// traverse), so the array form is the only spelling that round-trips every
    /// non-legacy set unambiguously.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq as _;

        if *self == Access::RO {
            return serializer.serialize_str("ro");
        }
        if *self == Access::RW {
            return serializer.serialize_str("rw");
        }
        let bits: &[(Access, &str)] = &[
            (Access::READ, "read"),
            (Access::WRITE, "write"),
            (Access::EXECUTE, "execute"),
            (Access::TRAVERSE, "traverse"),
        ];
        let present = bits.iter().filter(|(b, _)| self.contains(*b)).count();
        let mut seq = serializer.serialize_seq(Some(present))?;
        for (bit, name) in bits {
            if self.contains(*bit) {
                seq.serialize_element(name)?;
            }
        }
        seq.end()
    }
}

impl Access {
    /// A short human-readable token for display (logs, plan/coverage notes).
    /// Legacy `ro`/`rw` keep their historical spelling; any other set renders as
    /// sorted perm letters (`r`, `w`, lowercase `x` for execute, capital `X` for
    /// traverse). This is a DISPLAY form, not the serialization form: the literal
    /// `{read, write}` set displays as `rw`, which is fine for a human note but
    /// would collide with the legacy `rw` alias on parse, so serialization uses
    /// the unambiguous bit-name array instead (see [`Access::serialize`]).
    fn display_token(self) -> String {
        if self == Access::RO {
            return "ro".to_owned();
        }
        if self == Access::RW {
            return "rw".to_owned();
        }
        let mut s = String::with_capacity(4);
        if self.contains(Access::READ) {
            s.push('r');
        }
        if self.contains(Access::WRITE) {
            s.push('w');
        }
        if self.contains(Access::EXECUTE) {
            s.push('x');
        }
        if self.contains(Access::TRAVERSE) {
            s.push('X');
        }
        s
    }
}

/// Parse a compact access string into an [`Access`], or `None` if it is not one
/// of the accepted spellings.
///
/// Exactly the eight canonical compact tokens are accepted — the two legacy
/// aliases (`ro`, `rw`) plus the lowercase perm-letter combinations in a fixed
/// `r` < `w` < `x` order (`r`, `w`, `x`, `rx`, `wx`, `rwx`). This is the precise
/// set the JSON-schema contract advertises, so the parser and the schema never
/// drift: a misordered (`xr`), repeated (`rr`), or capital-`X` string fails
/// closed here. Anything beyond these (a traverse bit without the legacy alias,
/// or any mix the letters cannot spell) is expressed through the bit-name array
/// form instead.
fn parse_compact_access(s: &str) -> Option<Access> {
    let access = match s {
        // Legacy aliases — fixed sets that preserve the historical ACL strings.
        "ro" => Access::RO,
        "rw" => Access::RW,
        // Lowercase perm letters, canonical `r` < `w` < `x` order only.
        "r" => Access::READ,
        "w" => Access::WRITE,
        "x" => Access::EXECUTE,
        "rx" => Access::READ.union(Access::EXECUTE),
        "wx" => Access::WRITE.union(Access::EXECUTE),
        "rwx" => Access::READ.union(Access::WRITE).union(Access::EXECUTE),
        _ => return None,
    };
    Some(access)
}

/// Parse an array of bit names (`["read", "traverse"]`, …) into an [`Access`].
/// Each name maps to one bit; an empty list, an unknown name, or a duplicate is
/// rejected with a clear message. Returns the rejection reason on failure.
fn parse_bit_names(names: &[String]) -> Result<Access, String> {
    if names.is_empty() {
        return Err("access bit-name list is empty".to_owned());
    }
    let mut acc = Access(0);
    for name in names {
        let bit = match name.as_str() {
            "read" => Access::READ,
            "write" => Access::WRITE,
            "execute" => Access::EXECUTE,
            "traverse" => Access::TRAVERSE,
            other => return Err(format!("unknown access bit {other:?}")),
        };
        if acc.contains(bit) {
            return Err(format!("duplicate access bit {name:?}"));
        }
        acc |= bit;
    }
    Ok(acc)
}

/// Hand-written schema for [`Access`]: the type has a custom `Deserialize`
/// (a compact perm string OR an array of bit names), so its schema is written by
/// hand to mirror exactly that one-of rather than a derived enum that would not
/// match the deserializer. The string arm enumerates the accepted compact tokens
/// (the legacy aliases plus the perm-letter combinations); the array arm is a
/// list drawn from the four bit names. Behind the `schema` feature — schema
/// generation is a CI/contract concern, not part of the default public API.
#[cfg(feature = "schema")]
impl schemars::JsonSchema for Access {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Access".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "A set of file-access bits. Either a compact perm \
                string (letters r/w/x plus the legacy aliases \"ro\"/\"rw\") or \
                an array of bit names drawn from read/write/execute/traverse.",
            "oneOf": [
                {
                    "type": "string",
                    "enum": ["ro", "rw", "r", "w", "x", "rx", "wx", "rwx"],
                },
                {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["read", "write", "execute", "traverse"],
                    },
                    "minItems": 1,
                    "uniqueItems": true,
                },
            ],
        })
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
/// read boundary. `{param}` placeholders here are filled and re-validated at
/// resolve time, mirroring the parametrized-sudo path exactly — but this
/// substitution path applies ONLY to a catalog permission grant, which has a
/// param source (the referencing role's `PermissionRef` params). A raw role
/// `[payload].files` grant has no param source, so `crate::model` forbids
/// placeholders there entirely and validates the literal path in full; this type
/// is shared by both, but only the catalog side ever substitutes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct FileGrant {
    /// Absolute path to a directory, file, or glob pattern.
    pub path: String,
    /// The set of access bits this grant requests (read/write/execute/traverse).
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

    /// Static defect in this grant's literal path, or `None` if it is fit to
    /// materialize as a root `setfacl` target. Returns the rejection reason.
    ///
    /// Two rules, shared with the catalog parse gate so they can never drift
    /// between a catalog `[[file]]` grant and a raw role `[payload].files` grant:
    ///   1. the path passes [`file_path_static_defect`] (absolute, no `..`
    ///      component, no control char, non-empty);
    ///   2. a trailing `/` (a directory grant) is not paired with
    ///      `recursive = false` — the flag would be silently ineffective because a
    ///      directory grant always materializes recursively with a default-ACL, so
    ///      the contradiction is rejected to force the author to state the intent.
    ///
    /// IMPORTANT: a path bearing a `{param}` placeholder is partially EXEMPTED
    /// here — rule 2 is skipped, and rule 1's absolute-path / `..` checks are also
    /// deferred by [`file_path_static_defect`] (only control-char / empty are
    /// rejected). That exemption is sound ONLY for a catalog permission grant,
    /// whose placeholder is filled and then re-validated in full by the
    /// authoritative post-substitution gate. It is NOT sufficient on its own for a
    /// raw role grant, which is never substituted: a caller validating a raw
    /// `[payload].files` grant MUST first reject any placeholder (see
    /// [`has_placeholder`]) so the path reaching this method is always literal and
    /// rules 1 and 2 apply with no exemption. `crate::model` does exactly that.
    pub(crate) fn static_path_defect(&self) -> Option<&'static str> {
        if let Some(reason) = file_path_static_defect(&self.path) {
            return Some(reason);
        }
        if self.path.ends_with('/') && !self.recursive && !has_placeholder(&self.path) {
            return Some(
                "trailing '/' denotes a recursive directory grant; set recursive=true or remove the trailing slash for a file grant",
            );
        }
        None
    }
}

/// One entry in a bundle's `includes` list: the member permission id, plus an
/// optional set of *bindings* that thread the bundle's own parameters into the
/// member's `{placeholder}`s.
///
/// Two surface forms parse into this one type:
///
/// * a **bare string** (`"service-observe"`) — the member is pulled in verbatim,
///   with no bindings. This is the only form slices before param-mapping knew,
///   so every existing `includes = ["a", "b"]` keeps working unchanged.
/// * a **table** (`{ id = "service-control", units = "{app}" }`) — every key
///   other than `id` is a binding: its name is a *member* parameter and its
///   value is a template over the *bundle's* parameters. At resolve time the
///   template is rendered with the bundle's params (guard 1) to produce the
///   member's concrete param value, which the member then validates against its
///   own constraint (guard 2).
///
/// The two scopes never mix: `bindings` keys live in the member's parameter
/// namespace, while the placeholders inside the binding *values* live in the
/// bundle's. A bundle's role-facing surface is only its own `[params.*]`; member
/// parameters are internal and reachable only through a binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Include {
    /// The member permission id this entry aggregates.
    pub id: String,
    /// Member-parameter-name → binding template over the bundle's parameters.
    /// Empty for the bare-string form (no binding — back-compat).
    pub bindings: std::collections::BTreeMap<String, String>,
}

impl Include {
    /// A bare include with no bindings — the back-compatible string form.
    pub fn bare(id: impl Into<String>) -> Self {
        Include {
            id: id.into(),
            bindings: std::collections::BTreeMap::new(),
        }
    }

    /// Does this include carry at least one binding (the table form)?
    fn is_bound(&self) -> bool {
        !self.bindings.is_empty()
    }
}

impl From<&str> for Include {
    fn from(id: &str) -> Self {
        Include::bare(id)
    }
}

impl From<String> for Include {
    fn from(id: String) -> Self {
        Include::bare(id)
    }
}

impl<'de> Deserialize<'de> for Include {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Accept either a bare string (id, no bindings) or a table whose `id`
        // key names the member and whose every *other* key is a binding
        // (member-param → template). Unlike most catalog tables this one cannot
        // use `deny_unknown_fields`: the binding keys are author-chosen member
        // parameter names, not a fixed schema, so they are captured into a flat
        // map and `id` is lifted out of it. A table missing `id`, or carrying a
        // non-string binding value, is rejected.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Bare(String),
            // A binding value must be a string template; a non-string (array,
            // table, integer) is not a template and is rejected by this typing.
            Table(std::collections::BTreeMap<String, String>),
        }

        match Raw::deserialize(deserializer)? {
            Raw::Bare(id) => Ok(Include::bare(id)),
            Raw::Table(mut map) => {
                let id = map.remove("id").ok_or_else(|| {
                    serde::de::Error::custom("include table is missing the required `id` key")
                })?;
                Ok(Include { id, bindings: map })
            }
        }
    }
}

/// Hand-written schema for [`Include`]: the custom `Deserialize` accepts a bare
/// string OR a table `{ id = "...", <member_param> = "<template>", ... }` whose
/// non-`id` keys are author-chosen, so a derive cannot describe it. The two arms
/// are a plain string, or an object requiring `id` with additional string
/// properties (the bindings). Behind the `schema` feature — schema generation is
/// a CI/contract concern, not part of the default public API.
#[cfg(feature = "schema")]
impl schemars::JsonSchema for Include {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Include".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let id = <String>::json_schema(generator);
        let binding = <String>::json_schema(generator);
        schemars::json_schema!({
            "oneOf": [
                {
                    "type": "string",
                },
                {
                    "type": "object",
                    "required": ["id"],
                    "properties": {
                        "id": id,
                    },
                    "additionalProperties": binding,
                },
            ],
        })
    }
}

/// A single catalog policy record, parsed strictly.
///
/// One `PermissionDef` is one *layer's* statement about an id. The cross-layer
/// merge (see [`resolve_leaf`]) combines several of these for the same id.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
    /// The Unix account this permission's `sudo` commands run *as*, or `None`
    /// for the default `(ALL)` (root) run-spec.
    ///
    /// A service utility must often be launched under a non-root service account
    /// (`sudo -u bfs_solutions ./QToolplus`), never as root. Setting `runas` to
    /// that account narrows the grant: every command this permission contributes
    /// renders under `(<runas>)` instead of `(ALL)`, so the privilege handed out
    /// is "be that service account for these commands", not a root-equivalent.
    /// Overrides across layers exactly like `risk`: the topmost layer that sets
    /// `runas` wins; a higher layer that restates `sudo` without `runas` leaves
    /// the lower layer's run-spec standing. Validated at the read boundary.
    #[serde(default)]
    pub runas: Option<String>,
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
    /// Explicit members this permission aggregates. Each entry is either a bare
    /// id string or a table binding the member's parameters to templates over
    /// this bundle's own parameters (see [`Include`]). Inert in slice 1.
    #[serde(default)]
    pub includes: Vec<Include>,
    /// Categories this permission aggregates. Inert in slice 1.
    #[serde(default)]
    pub include_categories: Vec<String>,

    /// File-access grants this permission carries (`[[file]]` sub-tables). Each
    /// is parsed strictly and its path validated at the read boundary.
    #[serde(default, rename = "file")]
    pub files: Vec<FileGrant>,

    /// Per-parameter constraints (`[params.<name>]` sub-tables) bounding the
    /// values a role may substitute into this record's `{placeholder}`s. Every
    /// placeholder that appears in any template (sudo, groups, file path) MUST
    /// have a matching entry here, and every entry MUST name a placeholder that
    /// the record actually uses — both enforced at the read boundary
    /// (fail-closed). The constraint is applied to each substituted value at
    /// resolve time, before the static sudo/path gates.
    #[serde(default)]
    pub params: std::collections::BTreeMap<String, ParamConstraint>,
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
        // A `runas` token is spliced into the sudoers run-spec `(<runas>)` as
        // root. Validate it here so a value carrying a sudoers metacharacter (a
        // `)` that closes the run-spec early, a `,` that splits the Cmnd list, a
        // `!` negation) — or one that is not a portable Unix username at all —
        // fails closed at parse, naming the id, rather than reaching the renderer
        // and relying solely on its metacharacter neutralization.
        if let Some(runas) = &self.runas {
            if let Some(reason) = runas_defect(runas) {
                return Err(CatalogError::InvalidRunas {
                    id: self.id.clone(),
                    value: runas.clone(),
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
            if let Some(reason) = grant.static_path_defect() {
                return Err(CatalogError::InvalidFilePath {
                    id: self.id.clone(),
                    path: grant.path.clone(),
                    reason,
                });
            }
        }

        // Parameter guard rails (fail-closed, pre-release: no grace period).
        //
        // 1. Each declared constraint must be internally well-formed (a `path`
        //    with no allow_prefix, an `enum` with no values, accepts/refuses
        //    everything and is almost certainly an authoring mistake).
        for (name, constraint) in &self.params {
            if let Some(reason) = constraint.declaration_defect() {
                return Err(CatalogError::InvalidParamConstraint {
                    id: self.id.clone(),
                    param: name.clone(),
                    reason,
                });
            }
        }

        // 1b. Every placeholder inside an include *binding* must name a parameter
        //     this bundle declares. A binding value is a template over the
        //     bundle's own params, so a reference to a param the bundle does not
        //     have (`units = "{xyz}"` with no `[params.xyz]`) is dead — and worse,
        //     a binding the author believes threads a value actually threads
        //     nothing. Rejected with a precise error before the generic
        //     unconstrained-placeholder check below, which would otherwise report
        //     the same gap less helpfully.
        for inc in &self.includes {
            for template in inc.bindings.values() {
                for name in extract_placeholders(template) {
                    if !self.params.contains_key(name) {
                        return Err(CatalogError::UnknownBundleParam {
                            bundle: self.id.clone(),
                            member: inc.id.clone(),
                            param: name.to_owned(),
                        });
                    }
                }
            }
        }

        // 2. Every placeholder used in ANY of this record's templates must have a
        //    matching `[params.<name>]`. A placeholder a role could fill with an
        //    unconstrained value is the fail-open class this guard closes, so a
        //    missing constraint is rejected here, before resolve.
        let used = self.placeholder_names();
        for name in &used {
            if !self.params.contains_key(name) {
                return Err(CatalogError::UnconstrainedParam {
                    id: self.id.clone(),
                    param: name.clone(),
                });
            }
        }

        // 3. Conversely, a declared constraint whose name appears in NO template
        //    is dead config — a typo'd placeholder name or a stale entry. Reject
        //    it (pre-release strictness) so the constraint a role relies on is
        //    never silently inert.
        for name in self.params.keys() {
            if !used.contains(name) {
                return Err(CatalogError::OrphanParamConstraint {
                    id: self.id.clone(),
                    param: name.clone(),
                });
            }
        }

        Ok(())
    }

    /// Every distinct `{placeholder}` name this record's templates reference,
    /// across sudo commands, group names, file-grant paths, **and the binding
    /// templates in its `includes`**.
    ///
    /// The single source of truth for "which parameters does this record take",
    /// used by [`PermissionDef::validate`] to require a constraint per
    /// placeholder. Order is first-seen; duplicates are collapsed.
    ///
    /// Binding templates are included deliberately: a bundle parameter that
    /// appears *only* inside an include binding (never in this record's own
    /// sudo/group/file template) is still a real, role-supplied input that must
    /// be constrained. Were it omitted here, that parameter's `[params.*]` entry
    /// would be rejected as an orphan and the value would reach the binding-render
    /// step unconstrained — the fail-open the binding guard exists to close.
    fn placeholder_names(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        let mut push_from = |template: &str| {
            for name in extract_placeholders(template) {
                if !names.iter().any(|n| n == name) {
                    names.push(name.to_owned());
                }
            }
        };
        for ov in [&self.groups, &self.sudo] {
            let values = match ov {
                ListOverride::Replace(v) | ListOverride::Append(v) => v,
            };
            for v in values {
                push_from(v);
            }
        }
        for grant in &self.files {
            push_from(&grant.path);
        }
        // Bundle parameters consumed by an include binding count as used: the
        // binding value is a template over this bundle's params.
        for inc in &self.includes {
            for template in inc.bindings.values() {
                push_from(template);
            }
        }
        names
    }
}

/// The sudo-command validation gate (control-char / absolute-path / empty
/// check), factored out so it is reusable on post-substitution strings: a
/// templated command's concrete result must pass the SAME gate the catalog parse
/// applies to a static command. Returns the rejection reason, or `None` if the
/// value is a fit concrete absolute-path Cmnd.
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
    } else if has_dotdot_component(value) {
        // sudo normalizes `..` segments, so a substituted command like
        // `/usr/bin/../../bin/bash` collapses to a BROADER Cmnd than the literal
        // prefix suggests. Reject any `..` component post-substitution, mirroring
        // the file-path gate, so a hostile param value cannot widen the grant.
        Some("must not contain a `..` path component")
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

/// The maximum length Census accepts for a `runas` username. POSIX leaves the
/// limit to the system (`LOGIN_NAME_MAX` is commonly 32, including the NUL), and
/// `useradd` rejects longer names on Linux; 32 is the safe portable ceiling, and
/// rejecting longer values at parse keeps a pathological token out of the
/// sudoers run-spec.
const RUNAS_MAX_LEN: usize = 32;

/// Validate a `runas` token destined for the sudoers run-spec `(<runas>)`, run as
/// root. Returns the rejection reason, or `None` if the value is a fit Unix
/// username.
///
/// The token is spliced verbatim into `(<runas>)`, so a sudoers metacharacter
/// would change the rule's meaning rather than name an account: `)` closes the
/// run-spec early, `(` opens a nested one, `,` splits the Cmnd list, `!` negates,
/// `:`/`=`/`\` are rule punctuation, and whitespace splits the field. A control
/// char (notably a newline) would inject a second directive. Beyond "no
/// metacharacters", the value must be a real portable Unix username — a POSIX
/// portable name (`[a-z_][a-z0-9_-]*`) with an optional trailing `$` (the form
/// `useradd` accepts for machine accounts) — so a structurally-wrong token that
/// happens to carry no metacharacter (a leading digit, an uppercase letter, an
/// embedded `{param}` we deliberately do not template here) is still rejected.
fn runas_defect(value: &str) -> Option<&'static str> {
    if value.is_empty() {
        return Some("is empty");
    }
    if value.len() > RUNAS_MAX_LEN {
        return Some("exceeds the maximum username length (32)");
    }
    if value.chars().any(char::is_control) {
        return Some("contains a control character");
    }
    if value.chars().any(char::is_whitespace) {
        return Some("contains whitespace");
    }
    // Templated run-as is out of scope: a `{param}` runas would need its own
    // substitution + re-validation path. Reject the template metacharacters
    // explicitly so the failure names the real reason rather than the generic
    // "not a portable username" below.
    if value.contains('{') || value.contains('}') {
        return Some("must not be templated ({...} is not supported for runas)");
    }
    if value
        .chars()
        .any(|c| matches!(c, ',' | ':' | '=' | '\\' | '(' | ')' | '!'))
    {
        return Some("contains a sudoers metacharacter ( , : = \\ ( ) ! )");
    }
    // POSIX portable username: first char a lowercase letter or underscore, the
    // rest lowercase letters / digits / underscore / hyphen, with an optional
    // single trailing `$` (machine-account form).
    let core = value.strip_suffix('$').unwrap_or(value);
    if core.is_empty() {
        return Some("must be a Unix username, not a bare `$`");
    }
    let mut chars = core.chars();
    let first = chars.next()?;
    if !(first.is_ascii_lowercase() || first == '_') {
        return Some("must start with a lowercase letter or underscore");
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
        return Some("must be a portable Unix username (lowercase letters, digits, `_`, `-`)");
    }
    None
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
pub(crate) fn file_path_static_defect(path: &str) -> Option<&'static str> {
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
/// `..` component is a climb-the-tree primitive. `pub(crate)` so the resolver can
/// reuse the same traversal check on a raw inline-sudo command literal.
pub(crate) fn has_dotdot_component(path: &str) -> bool {
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
        let text =
            crate::fsutil::read_capped(path, crate::fsutil::MAX_INPUT_FILE_BYTES).map_err(|e| {
                CatalogError::OsRelease {
                    reason: format!("cannot read {}: {e}", path.display()),
                }
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
    for quote in ['"', '\''] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|v| v.strip_suffix(quote))
        {
            return inner.to_owned();
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
    fn all_definitions(&self, os: &OsTarget) -> Result<Vec<(String, PermissionDef)>, CatalogError> {
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
    fn read_policy_file(path: &Path, subdir: Option<&str>) -> Result<PermissionDef, CatalogError> {
        let text = crate::fsutil::read_capped(path, crate::fsutil::MAX_INPUT_FILE_BYTES).map_err(
            |source| CatalogError::Io {
                path: path.to_owned(),
                source,
            },
        )?;
        let def: PermissionDef =
            toml::from_str(&text).map_err(|source| CatalogError::TomlParse {
                path: path.to_owned(),
                source,
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
                return Err(CatalogError::MisfiledPolicy {
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

        for entry in std::fs::read_dir(layer_dir).map_err(|source| CatalogError::Io {
            path: layer_dir.to_owned(),
            source,
        })? {
            let entry = entry.map_err(|source| CatalogError::Io {
                path: layer_dir.to_owned(),
                source,
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
                for sub in std::fs::read_dir(&path).map_err(|source| CatalogError::Io {
                    path: path.clone(),
                    source,
                })? {
                    let sub = sub.map_err(|source| CatalogError::Io {
                        path: path.clone(),
                        source,
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
    /// For a **sudo** primitive: the account this command runs as, or `None` for
    /// the default `(ALL)` (root) run-spec. Tracked per primitive — not per
    /// resolved permission — so a command keeps the run-spec of the permission
    /// that actually declared it as it flows through a bundle union. A bundle
    /// that pulls in a member which de-rooted its own command (`runas =
    /// Some("svc")`) MUST NOT silently widen it back to root: the member's
    /// command carries its own `runas` here, and the bundle's own `runas` applies
    /// only to the bundle's own commands.
    ///
    /// Always `None` for a **groups** primitive (a group membership has no
    /// run-spec); this type is shared by both the groups and sudo vectors, and
    /// only the sudo path ever sets the field.
    pub runas: Option<String>,
    /// When this primitive reached the result through a *parametrized* bundle
    /// include, the binding that produced it, rendered as `param=value` pairs
    /// (e.g. `units=Supervisor`). Audit (`census compile`/`show`) reads it to show
    /// not just which member a primitive came from (`via`) but with which
    /// substitution. `None` for a primitive that came in verbatim or through a
    /// bare include.
    ///
    /// Provenance only: it is deliberately **excluded** from every drift /
    /// dedup key (sudo dedups on `(value, runas)`, the plan layer keys file/sudo
    /// drift on the materialized primitive, not its source), so recording it can
    /// never perturb plan/apply.
    pub binding: Option<String>,
}

/// A file-access grant after resolve: its path, access, recursion, derived
/// [`Shape`], and the per-grant provenance (which layers — and, through a bundle,
/// which member — contributed it). Grants on the same path are unioned across
/// layers/members: access is the bit-union (OR of the access bits), `recursive`
/// is the OR, and provenance accumulates.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedFileGrant {
    /// Absolute path (literal, already `{param}`-substituted if it was templated).
    pub path: String,
    /// Effective access (the bit-union over every contributing grant on this path).
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
    /// When this grant reached the result through a *parametrized* bundle
    /// include, the binding that produced it, rendered as `param=value` pairs
    /// (e.g. `path=/etc/Supervisor`). Provenance only — excluded from the drift
    /// key (file drift keys on `(path, access, recursive)`), so it never
    /// perturbs plan/apply. `None` for a verbatim or bare-include grant.
    pub binding: Option<String>,
}

/// A bundle member pulled in with parameter *bindings* (the `includes` table
/// form), resolved through the OS layer chain but **not yet substituted**.
///
/// A bare include is flattened into the bundle's own primitives at resolve time.
/// A bound include cannot be: its member templates carry the member's own
/// `{placeholder}`s, which are filled from the bundle's role-supplied parameters
/// through this entry's `bindings` — a two-stage substitution that only
/// [`resolve_with_params`] (where role parameters are known) can perform. So the
/// member is resolved here (layer merge, risk fold, cycle detection) and carried
/// intact, with its own `[params.*]` constraints preserved on `member.params`
/// for the member-side guard, until binding expansion runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundMember {
    /// The include entry: the member id plus its bindings (member-param-name →
    /// template over the bundle's parameters).
    pub include: Include,
    /// The member resolved through the layer chain, un-substituted. Its
    /// `params` are the member's own constraints (the member-side guard).
    pub member: ResolvedPermission,
}

/// A fully-resolved single permission: primitives with per-primitive provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedPermission {
    /// The permission id.
    pub id: String,
    /// Risk class, if any layer set one (topmost setter wins).
    pub risk: Option<Risk>,
    /// The account this permission's sudo commands run as, or `None` for the
    /// default `(ALL)` (root) run-spec. Resolved topmost-setter-wins, exactly
    /// like `risk`: the highest layer that sets `runas` wins; a higher layer that
    /// restates `sudo` without `runas` leaves the lower layer's run-spec
    /// standing. For a bundle, this is the bundle's OWN `runas` — a single
    /// resolved permission carries one run-spec, applied to every sudo command it
    /// contributes, so a bundle narrows all its members' commands to one account
    /// rather than per-member run-specs.
    pub runas: Option<String>,
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
    /// The parameter constraints in effect for this resolved permission, by
    /// placeholder name. Merged from every contributing record: across OS layers
    /// the topmost layer that declares a given param wins (mirroring `risk` /
    /// `runas`), and across bundle members each member contributes its own
    /// params (a member's constraint fills a name the bundle and earlier members
    /// have not already set). These are the constraints
    /// [`resolve_with_params`] enforces on each substituted value, before the
    /// static sudo/path gates.
    pub params: std::collections::BTreeMap<String, ParamConstraint>,
    /// Members pulled in with parameter bindings (the `includes` table form),
    /// resolved but **not yet substituted**. Empty for a leaf, a bare-only
    /// bundle, or once binding expansion has consumed them. These are expanded by
    /// [`resolve_with_params`], which renders each binding with the bundle's
    /// role-supplied parameters (the bundle-side guard) and then substitutes the
    /// member against its own constraints (the member-side guard). A plain
    /// [`resolve`] leaves them here unexpanded — their primitives are absent from
    /// the flat vectors above — because binding expansion needs role parameters.
    pub bound_members: Vec<BoundMember>,
}

/// Errors compiling/resolving the catalog.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
    #[error(
        "bundle {id} declares risk {declared:?} below its members' computed risk {computed:?}"
    )]
    LoweredBundleRisk {
        /// The bundle id.
        id: String,
        /// The risk the bundle declared.
        declared: Risk,
        /// The risk computed as the max over members.
        computed: Risk,
    },
    /// A catalog file could not be read.
    #[error("cannot read catalog path {path}: {source}")]
    Io {
        /// The path that failed.
        path: PathBuf,
        /// The underlying I/O error (preserves `io::ErrorKind` and the source chain).
        #[source]
        source: std::io::Error,
    },
    /// A catalog file's TOML was malformed or violated the strict schema.
    #[error("catalog file {path} TOML is invalid: {source}")]
    TomlParse {
        /// The path that failed.
        path: PathBuf,
        /// The underlying TOML deserialization error.
        #[source]
        source: toml::de::Error,
    },
    /// A catalog policy file sits under the wrong namespace location (its id's
    /// namespace does not match the subdirectory it was read from). A structural
    /// misfiling, distinct from a malformed-TOML failure.
    #[error("catalog file {path} is misfiled: {reason}")]
    MisfiledPolicy {
        /// The path that was misfiled.
        path: PathBuf,
        /// What did not line up (id namespace vs subdir).
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
    /// A `runas` token is unfit to splice into the sudoers run-spec `(<runas>)`.
    /// The value is rendered as root, so a token carrying a sudoers metacharacter
    /// (which would change the rule's meaning rather than name an account), a
    /// control char, whitespace, a `{param}` template (out of scope), or one that
    /// is simply not a portable Unix username is rejected at the read boundary —
    /// before it reaches root materialization.
    #[error("invalid runas {value:?} in permission {id}: {reason}")]
    InvalidRunas {
        /// The permission id carrying the bad runas token.
        id: String,
        /// The rejected runas value.
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
    #[error(
        "permission {permission}: template placeholder {{{placeholder}}} has no matching parameter"
    )]
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
    /// A `{placeholder}` appears in one of a record's templates (sudo, groups, or
    /// a file path) but the record declares no matching `[params.<name>]`
    /// constraint. A substituted value with no constraint is unbounded — a role
    /// could point a parametrized file permission at `/etc/shadow` or splice an
    /// arbitrary token into a sudoers Cmnd — so a missing constraint is rejected
    /// at the read boundary, before resolve. Pre-release: no grace period, every
    /// placeholder must be constrained.
    #[error(
        "permission {id}: template placeholder {{{param}}} has no [params.{param}] constraint"
    )]
    UnconstrainedParam {
        /// The permission id whose template carries the unconstrained placeholder.
        id: String,
        /// The placeholder name lacking a constraint.
        param: String,
    },
    /// A record declares a `[params.<name>]` constraint for a name that appears
    /// in NO template. Dead config — a typo'd placeholder name or a stale entry —
    /// which would silently never apply; rejected at the read boundary so a
    /// constraint a role relies on is never inert.
    #[error("permission {id}: [params.{param}] constrains a placeholder no template uses")]
    OrphanParamConstraint {
        /// The permission id carrying the orphan constraint.
        id: String,
        /// The constrained name that matches no placeholder.
        param: String,
    },
    /// A `[params.<name>]` constraint declaration is itself malformed (e.g. a
    /// `path` kind with no `allow_prefix`, an `enum` with no `values`, or a
    /// non-absolute prefix). Rejected at the read boundary so a constraint that
    /// would accept everything (or nothing) never reaches resolve.
    #[error("permission {id}: invalid [params.{param}] constraint: {reason}")]
    InvalidParamConstraint {
        /// The permission id carrying the malformed constraint.
        id: String,
        /// The parameter whose constraint is malformed.
        param: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A substituted parameter value violates its record's `[params.<name>]`
    /// constraint (outside the token charset, not under an allowed path prefix,
    /// not in the enum set, over the length bound, or carrying a denied glob).
    /// Enforced at resolve time, before the static sudo/path gates — the value
    /// is bounded to the record's declared domain so a role cannot widen a
    /// parametrized grant past what the catalog author allowed. For a list param,
    /// any single offending element fails the whole expansion closed.
    #[error(
        "permission {id}: parameter {param} value {value:?} violates its constraint: {reason}"
    )]
    ParamConstraintViolation {
        /// The permission id whose constraint was violated.
        id: String,
        /// The parameter whose value was rejected.
        param: String,
        /// The rejected substituted value.
        value: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// Two bundle members contribute `[params.<name>]` constraints for the same
    /// placeholder name with structurally different constraints. The bundle
    /// expands every member's templates into one shared `{name}` domain, so two
    /// members disagreeing on what values that name may take is ambiguous: a
    /// first-writer-wins merge would silently bind the placeholder to one
    /// member's constraint and let the other member's templates render values its
    /// author never sanctioned. Fail closed — the labeller must reconcile the two
    /// members onto one constraint (or rename the placeholder). Identical
    /// constraints merge idempotently and never trip this.
    #[error(
        "bundle {id}: members declare conflicting [params.{param}] constraints; \
         a placeholder shared across members must resolve to one constraint"
    )]
    ConflictingParamConstraint {
        /// The bundle id whose members disagree.
        id: String,
        /// The placeholder name with conflicting constraints.
        param: String,
    },
    /// An include binding's template references a parameter the bundle does not
    /// declare (`{ id = "m", units = "{xyz}" }` with no `[params.xyz]` on the
    /// bundle). A binding value is a template over the bundle's *own* parameters,
    /// so a reference to a non-existent one threads nothing — the author's intent
    /// silently fails. Rejected at the read boundary, before resolve.
    #[error(
        "bundle {bundle}: include {member} binds against {{{param}}}, which is not a parameter of the bundle"
    )]
    UnknownBundleParam {
        /// The bundle id carrying the binding.
        bundle: String,
        /// The member the binding targets.
        member: String,
        /// The bundle-parameter name the binding template referenced.
        param: String,
    },
    /// An include binding names a member parameter the member does not have
    /// (`{ id = "m", nope = "{app}" }` where `m` has no `{nope}` placeholder).
    /// The binding would feed a value into a placeholder that does not exist —
    /// dead config that silently grants nothing. Rejected before resolve.
    #[error(
        "bundle {bundle}: include {member} binds parameter {param}, which the member does not use"
    )]
    OrphanIncludeBinding {
        /// The bundle id carrying the binding.
        bundle: String,
        /// The member the binding targets.
        member: String,
        /// The member-parameter name that matches no member placeholder.
        param: String,
    },
    /// A bound member has a `{placeholder}` that no include binding fills (and
    /// that the bundle does not otherwise supply). A bundle's role-facing surface
    /// is only its own `[params.*]`; member parameters are internal and reachable
    /// only through a binding, so a member placeholder left unbound could never be
    /// filled — the expansion would carry a literal `{placeholder}` into a root
    /// primitive. Rejected before resolve, fail-closed.
    #[error(
        "bundle {bundle}: include {member} leaves member parameter {{{param}}} unbound; \
         a parametrized include must bind every member placeholder"
    )]
    UnboundMemberParam {
        /// The bundle id carrying the binding.
        bundle: String,
        /// The member with the unbound placeholder.
        member: String,
        /// The member-placeholder name left unbound.
        param: String,
    },
    /// A bundle includes a member that is itself a parametrized bundle (its
    /// resolution carries un-substituted bound members). This applies to BOTH
    /// include forms: a bound include `{ id = "...", p = "..." }` and a bare
    /// include `"..."` of such a bundle are equally rejected. Nested/transitive
    /// param-mapping is out of scope for v1: it would require per-level binding
    /// scopes the engine does not model, so a bundle may include only leaf or
    /// unparametrized members. Rejected rather than silently dropping the inner
    /// bindings (a bound include) or under-granting the inner bound members (a
    /// bare include). The fix is to bind the inner bundle's members directly.
    #[error(
        "bundle {bundle}: include {member} is itself a parametrized bundle; \
         nested parameter mapping is not supported"
    )]
    NestedParamMapping {
        /// The outer bundle id.
        bundle: String,
        /// The member that is itself a parametrized bundle.
        member: String,
    },
    /// A bundle's binding fan-out and a member's internal list parameter would
    /// together produce more than one list dimension across the whole expansion.
    /// Census expands a single list by emitting one rendered copy per element; two
    /// independent list dimensions (a bundle list parameter threaded into a
    /// member that also takes a list, or a binding template referencing two list
    /// bundle parameters) would require a cartesian product whose blast radius is
    /// rarely intended. At most one list dimension per bundle expansion, rejected
    /// here rather than silently multiplying root grants.
    #[error(
        "bundle {bundle}: more than one list dimension across the expansion ({first}, {second}); \
         at most one list parameter is supported per bundle expansion"
    )]
    MultipleExpansionLists {
        /// The bundle being expanded.
        bundle: String,
        /// The first list dimension seen (a bundle or member parameter name).
        first: String,
        /// The second list dimension that triggered the error.
        second: String,
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
    let mut runas: Option<String> = None;
    let mut limits: Option<Limits> = None;
    let mut limits_layer: Option<String> = None;
    // Parameter constraints, merged across layers. A higher layer's entry for a
    // given name overrides a lower layer's (topmost-setter-wins, like risk): the
    // layer that owns the template for a placeholder owns its constraint. A
    // `replace=true` layer wipes accumulated params alongside the primitives —
    // it restates its own templates and (per its own validate()) their
    // constraints.
    let mut params: std::collections::BTreeMap<String, ParamConstraint> =
        std::collections::BTreeMap::new();
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
            params.clear();
        }

        apply_list_override(&mut groups, &def.groups, layer, None);
        apply_list_override(&mut sudo, &def.sudo, layer, None);
        for grant in def.files {
            raw_files.push((grant, layer.clone()));
        }
        for (name, constraint) in def.params {
            params.insert(name, constraint); // topmost setter wins
        }

        if let Some(r) = def.risk {
            risk = Some(r); // topmost setter wins
        }
        if let Some(u) = def.runas {
            runas = Some(u); // topmost setter wins, mirroring risk
        }
        if let Some(l) = def.limits {
            limits = Some(l.into());
            limits_layer = Some(layer.clone());
        }
    }

    if !found {
        return Err(CatalogError::UnknownPermission(id.to_owned()));
    }

    // Stamp this leaf's resolved run-spec onto every one of ITS sudo commands, so
    // the run-as account travels with each command as a per-primitive fact. When
    // this leaf is later pulled into a bundle, the bundle union preserves these
    // per-command run-specs — a member that de-rooted its command keeps that
    // narrowing instead of being silently widened back to the bundle's `(ALL)`.
    for cmd in &mut sudo {
        cmd.runas = runas.clone();
    }

    let file_grants = union_file_grants(raw_files, None);

    Ok((
        ResolvedPermission {
            id: id.to_owned(),
            risk,
            runas,
            groups,
            sudo,
            file_grants,
            limits,
            limits_layer,
            category_members: Vec::new(),
            resolved_catalog_version: None,
            params,
            // A leaf resolve never expands bindings (it has no `includes`); the
            // bundle resolve attaches bound members.
            bound_members: Vec::new(),
        },
        warnings,
    ))
}

/// Union raw `(FileGrant, layer)` pairs into [`ResolvedFileGrant`]s keyed by path.
///
/// Grants on the same `path` merge: access is the bit-union (OR of the access
/// bits), `recursive` is the OR, and every contributing layer/member is recorded
/// in `sources`. Path order is the first-seen order so the resolved list is stable.
/// `shape` is derived from the path plus the *effective* (OR'd) `recursive` flag,
/// so a path stated once as a file and once as recursive resolves to a directory.
/// `via` tags the bundle member that pulled grants in (`None` for a leaf).
pub(crate) fn union_file_grants(
    raw: Vec<(FileGrant, String)>,
    via: Option<&str>,
) -> Vec<ResolvedFileGrant> {
    let mut out: Vec<ResolvedFileGrant> = Vec::new();
    for (grant, layer) in raw {
        let source = SourcedFileGrant {
            layer,
            via: via.map(str::to_owned),
            binding: None,
        };
        if let Some(existing) = out.iter_mut().find(|g| g.path == grant.path) {
            existing.access |= grant.access;
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
/// is the bit-union, `recursive` is the OR, `shape` is recomputed against the
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
            existing.access |= grant.access;
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
    // `runas` is set later (only on the sudo vec, after the leaf's run-spec is
    // resolved topmost-wins); the groups vec keeps `None`.
    match ov {
        ListOverride::Replace(values) => {
            acc.clear();
            for v in values {
                acc.push(SourcedPrimitive {
                    value: v.clone(),
                    layer: layer.to_owned(),
                    via: via.map(str::to_owned),
                    runas: None,
                    binding: None,
                });
            }
        }
        ListOverride::Append(values) => {
            for v in values {
                acc.push(SourcedPrimitive {
                    value: v.clone(),
                    layer: layer.to_owned(),
                    via: via.map(str::to_owned),
                    runas: None,
                    binding: None,
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
) -> Result<(Vec<Include>, Vec<String>), CatalogError> {
    let mut includes: Vec<Include> = Vec::new();
    let mut categories: Vec<String> = Vec::new();
    for layer in chain {
        for def in catalog.read_layer(layer)? {
            if def.id != id {
                continue;
            }
            for inc in def.includes {
                // Dedup must be binding-aware: two table-includes of the same
                // member id with DIFFERENT bindings are two distinct expansions
                // (e.g. the same `service-control` bound to two different units),
                // not a duplicate. Collapsing them by id alone would silently drop
                // one expansion. An exact (id + bindings) repeat is a true dup.
                if !includes
                    .iter()
                    .any(|e| e.id == inc.id && e.bindings == inc.bindings)
                {
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
        let mut cycle: Vec<String> = path.iter().skip(start).cloned().collect();
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
    // Parameter constraints in effect for the bundle: the bundle's OWN params
    // first, then each member's. A member's constraint fills a placeholder name
    // the bundle (and earlier members) have not already bound — the bundle's own
    // statement wins. A name already present must agree structurally: because
    // `service-restart`-style bundles fill `{units}` across every member, each
    // member declares the SAME constraint for that name, which merges
    // idempotently. Two members declaring the same name with DIFFERENT
    // constraints is ambiguous (one shared placeholder, two domains) and is
    // rejected at the merge below rather than silently bound to one member's.
    let mut params = own.params;
    // The bundle's OWN run-spec. This applies only to the bundle's own sudo
    // commands (already stamped onto `own.sudo` by resolve_leaf). Each member's
    // commands keep the run-spec the member resolved to — carried per primitive
    // through the union below — so a member that de-rooted its command is never
    // silently widened back to the bundle's run-spec. The field on the resolved
    // permission records the bundle's own run-spec for audit; the authoritative
    // per-command run-spec lives on each `SourcedPrimitive.runas`.
    let runas = own.runas;

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

    // Split explicit includes into *bare* (no bindings — flattened into the
    // bundle's own primitives, exactly as before) and *bound* (a parameter
    // binding — resolved but carried un-substituted for the two-stage
    // expansion in `resolve_with_params`). A bare include and a
    // category-materialized member are both plain ids.
    let mut bare_members: Vec<String> = Vec::new();
    let mut bound_includes: Vec<Include> = Vec::new();
    for inc in &includes {
        if inc.is_bound() {
            bound_includes.push(inc.clone());
        } else if !bare_members.contains(&inc.id) {
            bare_members.push(inc.id.clone());
        }
    }

    // Explicit bare includes first, then category-materialized members. Dedup so
    // a member named both explicitly and via a category is expanded once.
    let mut members: Vec<String> = Vec::new();
    for m in bare_members.iter().chain(materialized.iter()) {
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

        // A bare include of a permission that itself param-maps (its resolution
        // carries un-substituted bound members) must fail closed, exactly as the
        // bound-include path does below. Flattening only this permission's own
        // primitives would silently drop the included bundle's bound members —
        // under-granting without a word. Nested/transitive param-mapping is out
        // of scope for v1, so reject it here too rather than carrying a parametrized
        // bundle's bindings through a bare include. The author's fix is to bind the
        // included bundle's members directly. (Leaves like service-control /
        // service-observe have no bound members and pass through unaffected.)
        if !resolved.bound_members.is_empty() {
            return Err(CatalogError::NestedParamMapping {
                bundle: id.to_owned(),
                member: member.clone(),
            });
        }

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

        // A member's param constraints fill placeholder names the bundle (and
        // earlier members) have not yet bound. The bundle expands members'
        // templates into its own sudo/file set, so every placeholder those
        // templates carry must have a constraint reachable here. A name already
        // present must agree structurally: an identical constraint merges
        // idempotently, but two members declaring the SAME name with DIFFERENT
        // constraints is ambiguous and fails closed rather than silently keeping
        // whichever member resolved first and letting the other's templates
        // render values its author never sanctioned.
        for (name, constraint) in resolved.params {
            match params.entry(name) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(constraint);
                }
                std::collections::btree_map::Entry::Occupied(slot) => {
                    // Compare by EFFECTIVE meaning, not surface syntax: a member
                    // writing `max_len = 256` (the default) and another leaving it
                    // implicit declare the same constraint and must merge, not
                    // conflict. A genuine difference (different kind, prefixes,
                    // enum set, or bound) still fails closed.
                    if slot.get().normalized() != constraint.normalized() {
                        return Err(CatalogError::ConflictingParamConstraint {
                            id: id.to_owned(),
                            param: slot.key().clone(),
                        });
                    }
                }
            }
        }

        // A member's limits fill in only if the bundle (and earlier members) set
        // none — explicit bundle/own limits win over inherited ones.
        if limits.is_none() {
            if let Some(l) = resolved.limits {
                limits = Some(l);
                limits_layer = resolved.limits_layer;
            }
        }
    }

    // Table-form includes split into two classes by whether ANY binding value
    // references a bundle `{param}`:
    //
    // * **Purely literal** (`{ id = "service-control", units = "nginx" }`): every
    //   binding value is a concrete string, so the member can be rendered NOW with
    //   no role input. It is expanded eagerly here and its primitives flattened
    //   into the bundle, exactly like a bare include — so plain `resolve()` (no
    //   params) returns the concrete grants. This is what the curated per-app
    //   packages use, and is the path catalog-wide consumers (coverage /
    //   reverse-lookup, which call `resolve()` without params) depend on.
    // * **References a bundle `{param}`** (`{ id = "service-control", units =
    //   "{app}" }`, e.g. app-scope): the value cannot be rendered until the role
    //   supplies the parameter, so it is carried DEFERRED in `bound_members` and
    //   expanded by `resolve_with_params`. `resolve()` without that param legitimately
    //   cannot render it.
    //
    // Either way the member's risk folds into the bundle risk now: a member never
    // lowers the aggregate's honest risk just because its expansion is deferred.
    let mut bound_members: Vec<BoundMember> = Vec::new();
    for inc in bound_includes {
        let (resolved, member_warnings) = resolve_inner(&inc.id, os, catalog, ctx, path)?;
        warnings.extend(member_warnings);

        // Nested param-mapping is out of scope for v1: a member that is itself a
        // parametrized bundle (it carries its own bound members) would require
        // transitive, per-level binding scopes the engine does not model. Reject it
        // for BOTH classes — a literal-bound include of a param-mapping bundle is as
        // unsupported as a deferred one — rather than silently dropping its bindings.
        if !resolved.bound_members.is_empty() {
            return Err(CatalogError::NestedParamMapping {
                bundle: id.to_owned(),
                member: inc.id.clone(),
            });
        }

        match resolved.risk {
            Some(r) => {
                max_known_risk = Some(match max_known_risk {
                    Some(acc) => acc.max(r),
                    None => r,
                });
            }
            None => any_member_unknown = true,
        }

        // A binding value referencing a bundle param keeps the include deferred;
        // a binding set that is entirely concrete is rendered now.
        let references_bundle_param = inc
            .bindings
            .values()
            .any(|template| has_placeholder(template));

        if references_bundle_param {
            bound_members.push(BoundMember {
                include: inc,
                member: resolved,
            });
        } else {
            // Eager expansion: render the literal bindings and flatten the member's
            // primitives into the bundle. A purely-literal binding consumes NO
            // bundle parameter, so guard 1 (bundle-constraint on the binding INPUT)
            // has nothing to check — `expand_bound_member` is called with empty
            // bundle params/constraints. Guard 2 (the member's OWN constraint + the
            // static sudo/path gates on each rendered value) still runs inside
            // `expand_bound_member`. Provenance (`via` member id + `binding`
            // `param=value`) is stamped identically to the deferred path.
            let bound = BoundMember {
                include: inc,
                member: resolved,
            };
            let empty_params: std::collections::BTreeMap<String, ParamValue> =
                std::collections::BTreeMap::new();
            let empty_constraints: std::collections::BTreeMap<String, ParamConstraint> =
                std::collections::BTreeMap::new();
            let mut ignored_used: Vec<String> = Vec::new();
            let (mut g, mut s, mut f) = expand_bound_member(
                id,
                &bound,
                &empty_params,
                &empty_constraints,
                &mut ignored_used,
            )?;
            union_member_primitives(&mut groups, std::mem::take(&mut g), &bound.include.id);
            union_member_primitives(&mut sudo, std::mem::take(&mut s), &bound.include.id);
            union_member_file_grants(&mut file_grants, std::mem::take(&mut f), &bound.include.id);
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
            runas,
            groups,
            sudo,
            file_grants,
            limits,
            limits_layer,
            category_members,
            resolved_catalog_version: ctx.catalog_version.clone(),
            params,
            bound_members,
        },
        warnings,
    ))
}

/// Union a member's resolved file grants into the bundle accumulator, merging by
/// path (access = bit-union, recursive = OR, shape recomputed) and recording the
/// member id that pulled each grant in via `via`.
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
            existing.access |= grant.access;
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
        // Dedup by the (value, runas) pair, not value alone. For groups `runas`
        // is always `None` on both sides, so this is value-equality as before. For
        // sudo it keeps the same command under two different run-specs as two
        // distinct grants — collapsing them would drop a member's narrowing (e.g.
        // a member granting `/opt/tool` as a service account would be discarded if
        // the bundle already granted it as root), silently widening privilege.
        if acc.iter().any(|e| e.value == p.value && e.runas == p.runas) {
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
//   * Placeholder `{X}` is filled by the param keyed exactly `X` (literal name match — no
//     singular/plural inference; if the placeholder is `{unit}` the param key must be `unit`, if
//     `{units}` then `units`).
//   * A SCALAR param (string/int/bool/float) substitutes once.
//   * A LIST param emits one rendered copy of the template per element, each element spliced into
//     that placeholder. At most ONE list param may participate in a single permission expansion
//     (see `MultipleListParams`) — the engine never invents a cartesian product.
//   * A placeholder with no matching param is a hard error (`MissingParam`): an unfilled `{X}` must
//     never reach a sudoers Cmnd literally.
//   * A param with no matching placeholder is a `Warning::UnusedParam`.
//
// The dual `{unit}` / `{unit}.service` Cmnd forms a service-restart record needs
// are written explicitly by the catalog author as separate template strings; the
// engine is a generic substitutor and does NOT synthesise alternative forms —
// sudoers matches argv exactly, so the author owns which concrete forms exist.

/// Does `s` contain at least one `{name}` placeholder?
pub(crate) fn has_placeholder(s: &str) -> bool {
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

/// Render a scalar [`ParamValue`] to the string that goes into a Cmnd. Only the
/// scalar kinds a role would sensibly pass as a parameter are accepted; arrays
/// and the `Other` catch-all are not scalars (a list is handled by the
/// per-element path, the rest have no string rendering). Returns `None` for
/// non-scalars.
fn scalar_param_string(v: &ParamValue) -> Option<String> {
    match v {
        ParamValue::String(s) => Some(s.clone()),
        ParamValue::Integer(i) => Some(i.to_string()),
        ParamValue::Float(f) => Some(f.to_string()),
        ParamValue::Boolean(b) => Some(b.to_string()),
        // Array and Other are not valid scalar substitutions.
        ParamValue::Array(_) | ParamValue::Other => None,
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
        ',', ';', '&', '|', '<', '>', '(', ')', '$', '`', '"', '\'', '\\', '*', '?', '!', '=', '#',
        '{', '}', '~',
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
    params: &std::collections::BTreeMap<String, ParamValue>,
    os: &OsTarget,
    catalog: &impl CatalogSource,
    ctx: &ResolveCtx,
) -> Result<(ResolvedPermission, Vec<Warning>), CatalogError> {
    let (mut resolved, mut warnings) = resolve(id, os, catalog, ctx)?;

    // No params: a placeholder-free record behaves exactly as before; a record
    // WITH placeholders but no params still fails closed via MissingParam below.
    // Track which params actually fill a placeholder so unused ones can warn.
    let mut used_params: Vec<String> = Vec::new();

    // Bound members (parametrized includes) are carried un-substituted; pull them
    // out so the bundle's own primitives substitute against the bundle's own
    // params first, then each bound member expands through its bindings below.
    let bound_members = std::mem::take(&mut resolved.bound_members);

    // The per-parameter constraints in effect for this resolved permission (see
    // `ResolvedPermission::params`). Each substituted value is checked against
    // its name's constraint inside `render_template`, BEFORE the static
    // sudo/path gates below. Taken out so the field can be borrowed while the
    // primitive vectors are moved through the substitution helpers.
    let constraints = std::mem::take(&mut resolved.params);

    // One-list invariant across the WHOLE bundle expansion (not just per template
    // string). The bundle's own/bare-member templates fan a list bundle param
    // inside `render_template`; a binding fan-out fans a (possibly different) list
    // bundle param at the include layer. No single render sees both, so a
    // top-level check here rejects two independent list dimensions before either
    // path silently produces an unintended cartesian.
    enforce_single_expansion_list(&resolved, &bound_members, params)?;

    resolved.groups = substitute_primitives(
        &resolved.id,
        resolved.groups,
        params,
        &constraints,
        &mut used_params,
        false,
    )?;
    resolved.sudo = substitute_primitives(
        &resolved.id,
        resolved.sudo,
        params,
        &constraints,
        &mut used_params,
        true,
    )?;
    resolved.file_grants = substitute_file_grants(
        &resolved.id,
        resolved.file_grants,
        params,
        &constraints,
        &mut used_params,
    )?;

    // Expand each bound member: render its bindings with the bundle's params
    // (guard 1), then substitute the member against ITS OWN constraints (guard 2).
    // The two scopes stay distinct — `constraints` is the bundle's, the member's
    // own `[params.*]` ride on `bound.member.params` — so neither guard is
    // skipped or conflated.
    for bound in bound_members {
        let (mut g, mut s, mut f) =
            expand_bound_member(&resolved.id, &bound, params, &constraints, &mut used_params)?;
        // Merge the member's expanded primitives into the bundle exactly as the
        // bare-member union does: dedup groups/sudo by (value, runas), union file
        // grants by path.
        union_member_primitives(
            &mut resolved.groups,
            std::mem::take(&mut g),
            &bound.include.id,
        );
        union_member_primitives(
            &mut resolved.sudo,
            std::mem::take(&mut s),
            &bound.include.id,
        );
        union_member_file_grants(
            &mut resolved.file_grants,
            std::mem::take(&mut f),
            &bound.include.id,
        );
    }

    resolved.params = constraints;

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

/// Reject a bundle expansion that would fan out over more than one list
/// dimension (the one-list invariant, applied across the whole expansion).
///
/// `render_template` already rejects two list parameters inside a single template
/// string, but a parametrized bundle fans on two separate layers: the bundle's
/// own/bare-member templates, and each bound member's binding templates. A list
/// bundle parameter used in either layer is one fan-out dimension; two distinct
/// list dimensions across the whole expansion would silently multiply root
/// grants. This collects every list-valued bundle parameter actually consumed —
/// by the bundle's own substituted templates and by every binding — and refuses
/// once a second distinct one appears.
fn enforce_single_expansion_list(
    resolved: &ResolvedPermission,
    bound_members: &[BoundMember],
    params: &std::collections::BTreeMap<String, ParamValue>,
) -> Result<(), CatalogError> {
    // Only a parametrized bundle (one with bound members) needs this cross-layer
    // check: it is the sole construct that fans out on two independent layers.
    // Without bound members, a single template's two-list case is already the
    // authoritative `render_template` `MultipleListParams` path, and reproducing
    // it here would only change that error's variant. Leave it untouched.
    if bound_members.is_empty() {
        return Ok(());
    }

    // A bundle parameter is a list dimension iff the role supplied it as an array.
    let is_list = |name: &str| matches!(params.get(name), Some(ParamValue::Array(_)));

    let mut seen: Option<String> = None;
    let mut check = |name: &str| -> Result<(), CatalogError> {
        if !is_list(name) {
            return Ok(());
        }
        match &seen {
            Some(first) if first == name => Ok(()),
            Some(first) => Err(CatalogError::MultipleExpansionLists {
                bundle: resolved.id.clone(),
                first: first.clone(),
                second: name.to_owned(),
            }),
            None => {
                seen = Some(name.to_owned());
                Ok(())
            }
        }
    };

    // The bundle's own + bare-member templates (already merged into the flat
    // vectors) reference bundle params directly.
    for prim in resolved.groups.iter().chain(resolved.sudo.iter()) {
        for name in extract_placeholders(&prim.value) {
            check(name)?;
        }
    }
    for grant in &resolved.file_grants {
        for name in extract_placeholders(&grant.path) {
            check(name)?;
        }
    }
    // Each binding template references bundle params; a binding consuming two
    // distinct list bundle params (`"{apps}-{envs}"`) trips the same check.
    for bound in bound_members {
        for template in bound.include.bindings.values() {
            for name in extract_placeholders(template) {
                check(name)?;
            }
        }
    }
    Ok(())
}

/// The expanded primitives a bound member contributes: groups, sudo, file grants.
type ExpandedMember = (
    Vec<SourcedPrimitive>,
    Vec<SourcedPrimitive>,
    Vec<ResolvedFileGrant>,
);

/// One fan-out instance of a bound member's bindings: the member's concrete
/// parameter map plus a `param=value` provenance summary for audit.
type RenderedBinding = (std::collections::BTreeMap<String, ParamValue>, String);

/// Expand one bound member into its `(groups, sudo, file_grants)`.
///
/// Two stages, two guards:
///
/// 1. **Guard 1 (bundle side).** Each binding value is a template over the
///    bundle's parameters. Render it with `bundle_params`, and for every bundle
///    parameter the template consumes explicitly check the bundle constraint
///    (`bundle_constraints`) and [`param_value_defect`]. This is NOT free: a
///    bundle parameter that appears only inside a binding would otherwise reach
///    this render unchecked (the bundle's own templates never mention it), so the
///    check is wired here rather than relying on the bundle's own substitution.
/// 2. **Guard 2 (member side).** The rendered binding values become the member's
///    concrete parameters, and the member's primitives are substituted against
///    the member's OWN constraints (`bound.member.params`) and static gates.
///
/// A bundle *list* parameter threaded through a binding fans the whole member out
/// per element; the one-list invariant across the expansion is enforced upstream
/// by [`enforce_single_expansion_list`].
fn expand_bound_member(
    bundle: &str,
    bound: &BoundMember,
    bundle_params: &std::collections::BTreeMap<String, ParamValue>,
    bundle_constraints: &std::collections::BTreeMap<String, ParamConstraint>,
    used_params: &mut Vec<String>,
) -> Result<ExpandedMember, CatalogError> {
    let member_id = &bound.include.id;

    // Completeness: every binding key must be a member parameter, and every
    // member placeholder must be bound. The member's parameter surface is its own
    // `[params.*]` (one entry per placeholder, guaranteed by the member's own
    // parse-time validation). A role can reach member parameters ONLY through
    // bindings, so an unbound member placeholder could never be filled.
    for binding_key in bound.include.bindings.keys() {
        if !bound.member.params.contains_key(binding_key) {
            return Err(CatalogError::OrphanIncludeBinding {
                bundle: bundle.to_owned(),
                member: member_id.clone(),
                param: binding_key.clone(),
            });
        }
    }
    for member_param in bound.member.params.keys() {
        if !bound.include.bindings.contains_key(member_param) {
            return Err(CatalogError::UnboundMemberParam {
                bundle: bundle.to_owned(),
                member: member_id.clone(),
                param: member_param.clone(),
            });
        }
    }

    // Render the bindings into the member's concrete parameters. A scalar bundle
    // param yields one member-param map; a single list bundle param fans the
    // member out into one map per element (the one-list invariant guarantees at
    // most one list dimension across the whole expansion). Each rendered map also
    // carries a human-readable `param=value` summary for provenance.
    let fanned = render_bindings(
        bundle,
        member_id,
        &bound.include.bindings,
        bundle_params,
        bundle_constraints,
        used_params,
    )?;

    let mut out_groups: Vec<SourcedPrimitive> = Vec::new();
    let mut out_sudo: Vec<SourcedPrimitive> = Vec::new();
    let mut out_files: Vec<ResolvedFileGrant> = Vec::new();

    for (member_params, provenance) in fanned {
        // Guard 2: substitute the member's own primitives against the member's
        // own constraints and static gates. A bound value that satisfies the
        // bundle constraint but violates the member's (or fails the member's
        // path/sudo gate) fails closed here.
        let mut member_used: Vec<String> = Vec::new();
        let mut g = substitute_primitives(
            member_id,
            bound.member.groups.clone(),
            &member_params,
            &bound.member.params,
            &mut member_used,
            false,
        )?;
        let mut s = substitute_primitives(
            member_id,
            bound.member.sudo.clone(),
            &member_params,
            &bound.member.params,
            &mut member_used,
            true,
        )?;
        let mut f = substitute_file_grants(
            member_id,
            bound.member.file_grants.clone(),
            &member_params,
            &bound.member.params,
            &mut member_used,
        )?;

        // Stamp the binding provenance onto each expanded primitive so audit can
        // show `via <member> (param=value)`. Provenance only — never a drift key.
        for p in g.iter_mut().chain(s.iter_mut()) {
            p.binding = Some(provenance.clone());
        }
        for grant in &mut f {
            for src in &mut grant.sources {
                src.binding = Some(provenance.clone());
            }
        }

        out_groups.append(&mut g);
        out_sudo.append(&mut s);
        out_files.append(&mut f);
    }

    Ok((out_groups, out_sudo, out_files))
}

/// Render a member's bindings into one or more concrete member-parameter maps.
///
/// Each binding value is a template over the *bundle's* parameters. Scalars
/// produce a single map; one list bundle parameter (threaded through any binding)
/// fans into one map per element. Returns each map paired with a `param=value`
/// provenance summary.
///
/// Guard 1 lives here: for every bundle parameter a binding consumes, the value
/// is explicitly checked against the bundle constraint and [`param_value_defect`]
/// before it is spliced — so a bundle parameter used only in a binding is still
/// constrained, not silently trusted.
fn render_bindings(
    bundle: &str,
    member: &str,
    bindings: &std::collections::BTreeMap<String, String>,
    bundle_params: &std::collections::BTreeMap<String, ParamValue>,
    bundle_constraints: &std::collections::BTreeMap<String, ParamConstraint>,
    used_params: &mut Vec<String>,
) -> Result<Vec<RenderedBinding>, CatalogError> {
    // Discover the single list bundle parameter (if any) any binding consumes, and
    // its elements. Scalars are resolved once; the list, if present, drives the
    // fan-out. `render_template` is reused so guard 1 (constraint + value gate)
    // runs identically to the bundle's own templates — including on a parameter no
    // bundle-own template ever mentions.
    //
    // Determine the fan-out width: 1 for an all-scalar binding set, or the list
    // length. The list parameter is identified by scanning binding placeholders.
    let mut list_len: Option<usize> = None;
    let mut list_name: Option<String> = None;
    for template in bindings.values() {
        for name in extract_placeholders(template) {
            if let Some(ParamValue::Array(items)) = bundle_params.get(name) {
                // A second distinct list parameter is rejected upstream by
                // `enforce_single_expansion_list`; here we just record the one.
                list_len = Some(items.len());
                list_name = Some(name.to_owned());
            }
        }
    }

    let width = list_len.unwrap_or(1);
    let mut out = Vec::with_capacity(width);

    for index in 0..width {
        let mut member_params: std::collections::BTreeMap<String, ParamValue> =
            std::collections::BTreeMap::new();
        // For the fan-out element, present the list parameter as a single scalar
        // so each binding renders to exactly one string for this element.
        let mut element_params = bundle_params.clone();
        if let Some(name) = &list_name {
            if let Some(ParamValue::Array(items)) = bundle_params.get(name) {
                // `index` is in `0..items.len()` (width is the list length), so
                // the element is always present; `get` keeps the access panic-free.
                if let Some(element) = items.get(index) {
                    element_params.insert(name.clone(), element.clone());
                }
            }
        }

        let mut summary_parts: Vec<String> = Vec::new();
        for (member_param, template) in bindings {
            // Guard 1: render the binding with the bundle's params, checking each
            // consumed bundle param against the bundle constraint + value gate.
            // A binding-only bundle param is therefore constrained right here.
            let rendered = render_template(
                bundle,
                template,
                &element_params,
                bundle_constraints,
                used_params,
            )?;
            // With the list flattened to a scalar above, each binding renders to
            // exactly one string.
            let [value] = rendered.as_slice() else {
                // A binding template that still expands to multiple values would
                // mean a second list dimension slipped past the upstream guard.
                return Err(CatalogError::MultipleExpansionLists {
                    bundle: bundle.to_owned(),
                    first: list_name.as_deref().unwrap_or_default().to_owned(),
                    second: format!("binding {member}.{member_param}"),
                });
            };
            summary_parts.push(format!("{member_param}={value}"));
            member_params.insert(member_param.clone(), ParamValue::String(value.clone()));
        }
        out.push((member_params, summary_parts.join(", ")));
    }

    Ok(out)
}

/// Apply parameter substitution to one primitive list (groups or sudo).
///
/// `is_sudo` gates the post-substitution sudo-command re-validation (groups are
/// not sudoers Cmnds, but the param-value gate still applies to both so a hostile
/// value cannot smuggle a separator into a group name either).
fn substitute_primitives(
    permission: &str,
    prims: Vec<SourcedPrimitive>,
    params: &std::collections::BTreeMap<String, ParamValue>,
    constraints: &std::collections::BTreeMap<String, ParamConstraint>,
    used_params: &mut Vec<String>,
    is_sudo: bool,
) -> Result<Vec<SourcedPrimitive>, CatalogError> {
    let mut out: Vec<SourcedPrimitive> = Vec::new();
    for prim in prims {
        let rendered = render_template(permission, &prim.value, params, constraints, used_params)?;
        for value in rendered {
            // Every rendered string is a concrete primitive now. For sudo,
            // re-validate against the SAME sudo-command gate applied at catalog
            // parse so a substitution that produced a non-absolute or
            // control-bearing Cmnd (despite the param-value gate) fails closed
            // before root.
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
                // Preserve the per-command run-spec across substitution: a
                // templated sudo command keeps the run-as account of the
                // permission that declared it (`runas` is not itself templated).
                runas: prim.runas.clone(),
                // Preserve any binding provenance attached upstream (a bound
                // member's primitive carries `param=value`); a non-bound
                // primitive keeps `None`.
                binding: prim.binding.clone(),
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
/// that render to the same path collapse (access = bit-union, recursive = OR).
fn substitute_file_grants(
    permission: &str,
    grants: Vec<ResolvedFileGrant>,
    params: &std::collections::BTreeMap<String, ParamValue>,
    constraints: &std::collections::BTreeMap<String, ParamConstraint>,
    used_params: &mut Vec<String>,
) -> Result<Vec<ResolvedFileGrant>, CatalogError> {
    let mut rendered: Vec<ResolvedFileGrant> = Vec::new();
    for grant in grants {
        let paths = render_template(permission, &grant.path, params, constraints, used_params)?;
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
            existing.access |= grant.access;
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

/// Check a single substituted value against the constraint declared for its
/// parameter name. Fail-closed in two ways: a value the constraint rejects is a
/// [`CatalogError::ParamConstraintViolation`], and a *missing* constraint (a
/// placeholder with no `[params.<name>]` reaching resolve) is itself a violation
/// — parse-time validation guarantees one exists, so a gap here means a record
/// reached resolve without passing the gate and must not be expanded.
fn check_param_constraint(
    permission: &str,
    name: &str,
    value: &str,
    constraints: &std::collections::BTreeMap<String, ParamConstraint>,
) -> Result<(), CatalogError> {
    let Some(constraint) = constraints.get(name) else {
        return Err(CatalogError::ParamConstraintViolation {
            id: permission.to_owned(),
            param: name.to_owned(),
            value: value.to_owned(),
            reason: "parameter has no constraint (record reached resolve unvalidated)",
        });
    };
    if let Some(reason) = constraint.value_defect(value) {
        return Err(CatalogError::ParamConstraintViolation {
            id: permission.to_owned(),
            param: name.to_owned(),
            value: value.to_owned(),
            reason,
        });
    }
    Ok(())
}

/// Render one template string against `params`, returning one or more concrete
/// strings (one per list-param element, or exactly one for an all-scalar
/// template). Records every param key it consumed in `used_params`.
///
/// Each substituted value is checked against `constraints` (the resolved
/// permission's `[params.<name>]` table) BEFORE it is spliced in — and before
/// the caller's static sudo/path gates run on the rendered string. For a list
/// param, every element is checked, so one bad element fails the whole render
/// closed.
fn render_template(
    permission: &str,
    template: &str,
    params: &std::collections::BTreeMap<String, ParamValue>,
    constraints: &std::collections::BTreeMap<String, ParamConstraint>,
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
            ParamValue::Array(items) => {
                // Validate every element and collect them; reject a second list.
                let mut elems: Vec<String> = Vec::new();
                for item in items {
                    let s = scalar_param_string(item).ok_or_else(|| {
                        CatalogError::InvalidParamValue {
                            permission: permission.to_owned(),
                            param: name.clone(),
                            value: format!("{item:?}"),
                            reason: "list element is not a scalar value",
                        }
                    })?;
                    if let Some(reason) = param_value_defect(&s) {
                        return Err(CatalogError::InvalidParamValue {
                            permission: permission.to_owned(),
                            param: name.clone(),
                            value: s,
                            reason,
                        });
                    }
                    // Per-record constraint gate, ahead of the static sudo/path
                    // gates: each list element must satisfy `[params.<name>]`.
                    check_param_constraint(permission, name, &s, constraints)?;
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
                let s =
                    scalar_param_string(other).ok_or_else(|| CatalogError::InvalidParamValue {
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
                // Per-record constraint gate, ahead of the static sudo/path gates.
                check_param_constraint(permission, name, &s, constraints)?;
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
    use std::io::Write;

    use super::*;

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
        assert_eq!(
            def.sudo,
            ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()])
        );
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
        assert_eq!(
            def.includes,
            vec![
                Include::bare("network-diag"),
                Include::bare("network-admin")
            ]
        );
        assert_eq!(def.include_categories, vec!["network"]);
    }

    #[test]
    fn append_form_parses_distinct_from_replace() {
        let appended: PermissionDef =
            toml::from_str("id = \"a\"\nsudo = { append = [\"netplan\"] }\n").unwrap();
        assert_eq!(
            appended.sudo,
            ListOverride::Append(vec!["netplan".to_owned()])
        );
        let replaced: PermissionDef = toml::from_str("id = \"a\"\nsudo = [\"netplan\"]\n").unwrap();
        assert_eq!(
            replaced.sudo,
            ListOverride::Replace(vec!["netplan".to_owned()])
        );
    }

    #[test]
    fn append_form_rejects_unknown_key() {
        // A typo in the table form must not be silently dropped.
        assert!(
            toml::from_str::<PermissionDef>("id = \"a\"\nsudo = { apend = [\"x\"] }\n").is_err()
        );
    }

    // --- 1.2 OsTarget detection ---

    #[test]
    fn detects_debian_12() {
        let f =
            write_os_release("ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n");
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
            runas: None,
            limits: None,
            replace: false,
            includes: Vec::new(),
            include_categories: Vec::new(),
            files: Vec::new(),
            params: std::collections::BTreeMap::new(),
        }
    }

    /// Build a single-entry `params` map for a `token`-kind constraint with no
    /// length cap — the common case for the systemd-unit-style placeholders the
    /// resolve tests exercise.
    fn token_param(name: &str) -> std::collections::BTreeMap<String, ParamConstraint> {
        let mut m = std::collections::BTreeMap::new();
        m.insert(name.to_owned(), ParamConstraint::Token { max_len: None });
        m
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
                    limits: Some(CatalogLimits {
                        nofile: Some(1024),
                        nproc: None,
                    }),
                    ..def("net")
                },
            )
            .with(
                "linux-debian",
                PermissionDef {
                    limits: Some(CatalogLimits {
                        nofile: Some(4096),
                        nproc: Some(512),
                    }),
                    ..def("net")
                },
            );
        let (r, _) = resolve_leaf("net", &debian12(), &cat).unwrap();
        assert_eq!(
            r.limits,
            Some(Limits {
                nofile: Some(4096),
                nproc: Some(512)
            })
        );
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
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                    ..def("net")
                },
            )
            .with_empty_layer("linux-debian-12");
        let (r, w) = resolve_leaf("net", &debian12(), &cat).unwrap();
        assert_eq!(values(&r.sudo), vec!["/usr/sbin/ip"]);
        assert!(
            w.is_empty(),
            "present (if empty) version layer must not warn"
        );
    }

    // --- 2.1 bundle resolution (includes) ---

    fn ctx() -> ResolveCtx {
        ResolveCtx {
            catalog_version: Some("2026.06".to_owned()),
        }
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
                    includes: vec!["network-diag".into(), "network-admin".into()],
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
        let own = r
            .sudo
            .iter()
            .find(|p| p.value == "/usr/bin/tcpdump")
            .unwrap();
        assert_eq!(own.via, None);
        let from_diag = r.sudo.iter().find(|p| p.value == "/usr/sbin/ip").unwrap();
        assert_eq!(from_diag.via.as_deref(), Some("network-diag"));
        let from_admin = r.groups.iter().find(|p| p.value == "netdev").unwrap();
        assert_eq!(from_admin.via.as_deref(), Some("network-admin"));
    }

    #[test]
    fn bundle_members_conflicting_param_constraint_rejected() {
        // Two members share the placeholder name `{unit}` but constrain it
        // differently — one as a free token, one as a closed enum. The bundle
        // expands both members' templates into one shared `{unit}` domain, so a
        // first-writer-wins merge would silently bind `{unit}` to one member's
        // constraint and let the other's template render values its author never
        // sanctioned. The merge must fail closed instead.
        let mut enum_unit = std::collections::BTreeMap::new();
        enum_unit.insert(
            "unit".to_owned(),
            ParamConstraint::Enum {
                values: vec!["ssh".to_owned()],
            },
        );
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec![
                        "/usr/bin/systemctl restart {unit}".to_owned()
                    ]),
                    params: token_param("unit"),
                    ..def("svc-token")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(
                        vec!["/usr/bin/systemctl status {unit}".to_owned()],
                    ),
                    params: enum_unit,
                    ..def("svc-enum")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    includes: vec!["svc-token".into(), "svc-enum".into()],
                    ..def("svc-bundle")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let err = resolve("svc-bundle", &os, &cat, &ctx()).unwrap_err();
        assert!(
            matches!(
                err,
                CatalogError::ConflictingParamConstraint { ref id, ref param }
                    if id == "svc-bundle" && param == "unit"
            ),
            "expected ConflictingParamConstraint, got {err:?}"
        );
    }

    #[test]
    fn bundle_members_identical_param_constraint_merges() {
        // The legitimate case the guard must NOT break: two members both declare
        // `{unit}` as the SAME token constraint. The merge is idempotent and the
        // bundle resolves cleanly with one constraint in effect.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec![
                        "/usr/bin/systemctl restart {unit}".to_owned()
                    ]),
                    params: token_param("unit"),
                    ..def("svc-a")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(
                        vec!["/usr/bin/systemctl status {unit}".to_owned()],
                    ),
                    params: token_param("unit"),
                    ..def("svc-b")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    includes: vec!["svc-a".into(), "svc-b".into()],
                    ..def("svc-bundle")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve("svc-bundle", &os, &cat, &ctx()).unwrap();
        // One constraint survives for the shared name, and both members' templates
        // came through.
        assert_eq!(
            r.params.get("unit"),
            Some(&ParamConstraint::Token { max_len: None })
        );
        let mut sudo = values(&r.sudo);
        sudo.sort();
        assert_eq!(
            sudo,
            vec![
                "/usr/bin/systemctl restart {unit}",
                "/usr/bin/systemctl status {unit}"
            ]
        );
    }

    #[test]
    fn bundle_preserves_each_members_runas_per_command() {
        // Fail-open regression guard. A member de-roots its own command
        // (`runas = "bfs_solutions"`); the bundle pulls it in and ALSO carries its
        // own command under its own run-spec (`runas = "ops"`). The member's
        // command MUST keep its service account — never silently widen back to the
        // bundle's run-spec or to root `(ALL)` — and the bundle's own command must
        // carry the bundle's run-spec. runas is a per-primitive fact end-to-end.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/opt/QToolplus".to_owned()]),
                    runas: Some("bfs_solutions".to_owned()),
                    ..def("db-tool")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    // The bundle's own command, under the bundle's own run-spec.
                    sudo: ListOverride::Replace(vec!["/usr/bin/own-tool".to_owned()]),
                    runas: Some("ops".to_owned()),
                    includes: vec!["db-tool".into()],
                    ..def("toolbox")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve("toolbox", &os, &cat, &ctx()).unwrap();

        let member_cmd = r
            .sudo
            .iter()
            .find(|p| p.value == "/opt/QToolplus")
            .expect("member command present");
        assert_eq!(
            member_cmd.runas.as_deref(),
            Some("bfs_solutions"),
            "the member's de-rooted command must keep its own run-spec, not widen to the bundle's"
        );
        assert_eq!(member_cmd.via.as_deref(), Some("db-tool"));

        let own_cmd = r
            .sudo
            .iter()
            .find(|p| p.value == "/usr/bin/own-tool")
            .expect("bundle's own command present");
        assert_eq!(
            own_cmd.runas.as_deref(),
            Some("ops"),
            "the bundle's own command must carry the bundle's run-spec"
        );
        assert_eq!(own_cmd.via, None);
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
                    includes: vec!["a".into(), "b".into()],
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
                    includes: vec!["leaf".into()],
                    sudo: ListOverride::Replace(vec!["/usr/bin/mid-cmd".to_owned()]),
                    ..def("mid")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    includes: vec!["mid".into()],
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
                    includes: vec!["b".into()],
                    ..def("a")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    includes: vec!["a".into()],
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
                    includes: vec![format!("p{}", i + 1).into()],
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
                    includes: vec!["leaf".into()],
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
                    includes: vec!["low".into(), "high".into()],
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
                    includes: vec!["high".into()],
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
                    includes: vec!["high".into()],
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
                    includes: vec!["low".into()],
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
                    includes: vec!["undeclared".into(), "high".into()],
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
                    includes: vec!["m1".into(), "m2".into()],
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
                includes: vec!["undeclared".into()],
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
        assert!(matches!(err, CatalogError::MisfiledPolicy { .. }));
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
            CatalogError::MisfiledPolicy { .. }
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
                matches!(
                    OsTarget::detect_from(f.path()),
                    Err(CatalogError::OsRelease { .. })
                ),
                "os-release {body:?} must be rejected"
            );
        }
    }

    #[test]
    fn os_release_rejects_traversal_version() {
        for body in [
            "ID=debian\nVERSION_ID=../x\n",
            "ID=debian\nVERSION_ID=a/b\n",
        ] {
            let f = write_os_release(body);
            assert!(
                matches!(
                    OsTarget::detect_from(f.path()),
                    Err(CatalogError::OsRelease { .. })
                ),
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
            Err(CatalogError::InvalidName {
                kind: "os family",
                ..
            })
        ));
        assert!(matches!(
            OsTarget::new("linux", "debian", Some("../x".to_owned())),
            Err(CatalogError::InvalidName {
                kind: "version",
                ..
            })
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
        for bad in [
            "",
            ".",
            "..",
            "../x",
            "a/b",
            "a\\b",
            "Foo",
            "with space",
            "ünïcode",
        ] {
            assert!(!is_safe_path_component(bad), "{bad:?} must be unsafe");
            assert!(matches!(
                validate_path_component("namespace", bad),
                Err(CatalogError::InvalidName {
                    kind: "namespace",
                    ..
                })
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
            matches!(
                OsTarget::detect_from(f.path()),
                Err(CatalogError::OsRelease { .. })
            ),
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
        assert_eq!(
            parsed.limits,
            Some(CatalogLimits {
                nofile: Some(1024),
                nproc: Some(512)
            })
        );

        // And it converts to rolestore::Limits across a resolve.
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                limits: Some(CatalogLimits {
                    nofile: Some(1024),
                    nproc: Some(512),
                }),
                ..def("a")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve_leaf("a", &os, &cat).unwrap();
        assert_eq!(
            r.limits,
            Some(Limits {
                nofile: Some(1024),
                nproc: Some(512)
            })
        );
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

    // --- runas token is validated at the read boundary ---

    #[test]
    fn valid_runas_is_accepted_and_resolves() {
        // A plain service-account name and the machine-account `$` form are both
        // accepted, and the resolved permission carries the run-as account.
        for user in ["bfs_solutions", "_svc", "app-runner", "machine$"] {
            let cat = FakeCatalog::new().with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/opt/tool".to_owned()]),
                    runas: Some(user.to_owned()),
                    ..def("svc")
                },
            );
            let os = OsTarget::new("linux", "debian", None).unwrap();
            let (r, _) = resolve_leaf("svc", &os, &cat).expect("valid runas resolves");
            assert_eq!(r.runas.as_deref(), Some(user), "runas must propagate");
        }
    }

    #[test]
    fn invalid_runas_is_rejected_naming_the_id() {
        // Each value is unfit for the sudoers run-spec `(<runas>)`: empty, a
        // metacharacter that would split/close the run-spec, embedded whitespace,
        // a `{param}` template (out of scope), and a control char. Every rejection
        // must be `InvalidRunas` and name the offending permission id.
        let os = OsTarget::new("linux", "debian", None).unwrap();
        for bad in [
            "",              // empty
            "root, evil",    // comma + space: would split the Cmnd list
            "bfs solutions", // embedded space
            "a(b)",          // parens: open/close a nested run-spec
            "{param}",       // templated runas is out of scope
            "ro\tot",        // control char (tab)
        ] {
            let cat = FakeCatalog::new().with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/opt/tool".to_owned()]),
                    runas: Some(bad.to_owned()),
                    ..def("svc")
                },
            );
            assert!(
                matches!(
                    resolve_leaf("svc", &os, &cat).unwrap_err(),
                    CatalogError::InvalidRunas { ref id, .. } if id == "svc"
                ),
                "value {bad:?} must be rejected as InvalidRunas naming `svc`"
            );
        }
    }

    #[test]
    fn runas_overrides_topmost_setter_wins_like_risk() {
        // A base layer sets runas; a version layer that restates sudo without a
        // runas leaves the base run-spec standing. A version layer that DOES set
        // runas wins. Mirrors the `risk` override semantics.
        let base_only = FakeCatalog::new()
            .with(
                "linux-debian",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/opt/tool".to_owned()]),
                    runas: Some("base_acct".to_owned()),
                    ..def("svc")
                },
            )
            .with(
                "linux-debian-12",
                PermissionDef {
                    // Restates sudo, no runas: base run-spec must stand.
                    sudo: ListOverride::Append(vec!["/opt/extra".to_owned()]),
                    ..def("svc")
                },
            );
        let os = OsTarget::new("linux", "debian", Some("12".to_owned())).unwrap();
        let (r, _) = resolve_leaf("svc", &os, &base_only).unwrap();
        assert_eq!(r.runas.as_deref(), Some("base_acct"));

        let version_wins = FakeCatalog::new()
            .with(
                "linux-debian",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/opt/tool".to_owned()]),
                    runas: Some("base_acct".to_owned()),
                    ..def("svc")
                },
            )
            .with(
                "linux-debian-12",
                PermissionDef {
                    runas: Some("version_acct".to_owned()),
                    ..def("svc")
                },
            );
        let (r2, _) = resolve_leaf("svc", &os, &version_wins).unwrap();
        assert_eq!(r2.runas.as_deref(), Some("version_acct"), "topmost wins");
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
        std::fs::write(
            layer_dir.join("net.toml"),
            "id = \"net\"\nsudo = [\"ip\"]\n",
        )
        .unwrap();
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
        std::fs::write(
            layer_dir.join("ok.toml"),
            "id = \"ok\"\nsudo = [\"/bin/true\"]\n",
        )
        .unwrap();
        // A symlinked file pointing out of tree.
        std::os::unix::fs::symlink(outside.join("pwn.toml"), layer_dir.join("evil.toml")).unwrap();
        // A symlinked directory pointing out of tree.
        std::os::unix::fs::symlink(&outside, layer_dir.join("evil-ns")).unwrap();

        let cat = LiveCatalog::new(vec![root]);
        let defs = cat.read_layer("linux").unwrap();
        let ids: Vec<&str> = defs.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["ok"],
            "only the in-tree file is read; symlinks skipped"
        );
    }

    // --- slice 3b: parametrized templating ---

    /// Helper to build a `params` map from `(key, toml::Value)` pairs, converting
    /// each TOML value through the parse boundary into the census param domain
    /// (mirrors what `PermissionRef` deserialization does).
    fn params(pairs: Vec<(&str, toml::Value)>) -> std::collections::BTreeMap<String, ParamValue> {
        pairs
            .into_iter()
            .map(|(k, v)| (k.to_owned(), ParamValue::from_toml(v)))
            .collect()
    }

    fn arr(items: &[&str]) -> toml::Value {
        toml::Value::Array(
            items
                .iter()
                .map(|s| toml::Value::String((*s).to_owned()))
                .collect(),
        )
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
                params: token_param("unit"),
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
                params: token_param("unit"),
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
                params: token_param("unit"),
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
                params: token_param("unit"),
                ..def("svc")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        // A value injecting a comma (splits Cmnds), whitespace, a newline, or a
        // shell metachar must be rejected — both as a scalar and inside a list.
        for bad in [
            "nginx,/bin/sh",
            "nginx /bin/sh",
            "nginx\nroot",
            "ng$x",
            "ng;x",
        ] {
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
                params: token_param("cmd"),
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
    fn dotdot_after_substitution_is_rejected() {
        // A metachar-free param value that renders a `..`-bearing command —
        // `/usr/bin/../../bin/bash` — passes the param-value gate (`/` and `.` are
        // valid path chars) but sudo would normalize the `..` to a broader Cmnd.
        // The post-substitution sudo gate must reject it.
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/{tool}".to_owned()]),
                params: token_param("tool"),
                ..def("svc")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![(
            "tool",
            toml::Value::String("../../bin/bash".to_owned()),
        )]);
        assert!(
            matches!(
                resolve_with_params("svc", &p, &os, &cat, &ctx()).unwrap_err(),
                CatalogError::InvalidSudoCommand { ref id, .. } if id == "svc"
            ),
            "a substituted `..` command must be rejected"
        );
    }

    #[test]
    fn two_list_params_is_rejected() {
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/x {a} {b}".to_owned()]),
                params: {
                    let mut m = token_param("a");
                    m.insert("b".to_owned(), ParamConstraint::Token { max_len: None });
                    m
                },
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
                params: {
                    let mut m = token_param("verb");
                    m.insert("unit".to_owned(), ParamConstraint::Token { max_len: None });
                    m
                },
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
                params: token_param("unit"),
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
                params: token_param("unit"),
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
        assert_eq!(def.files[0].access, Access::RW);
        assert!(def.files[0].recursive);
        assert_eq!(def.files[1].access, Access::RO);
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
    fn file_grant_new_access_forms_parse() {
        // A `[[file]]` grant accepts the new forms: a compact letter string and a
        // bit-name array, alongside the legacy aliases.
        let def: PermissionDef = toml::from_str(
            r#"
id = "fs"
[[file]]
path = "/usr/local/bin/tool"
access = "rx"
[[file]]
path = "/srv/data"
access = ["read", "write"]
recursive = true
"#,
        )
        .unwrap();
        assert_eq!(def.files[0].access, Access::READ | Access::EXECUTE);
        assert_eq!(def.files[1].access, Access::READ | Access::WRITE);
    }

    #[test]
    fn file_grant_append_access_rejected_fail_closed() {
        // `append` is not declarable (no append bit, no backend); a grant naming
        // it fails closed at parse rather than silently degrading.
        let compact = r#"
id = "fs"
[[file]]
path = "/var/log/app.log"
access = "a"
"#;
        assert!(toml::from_str::<PermissionDef>(compact).is_err());
        let array = r#"
id = "fs"
[[file]]
path = "/var/log/app.log"
access = ["append"]
"#;
        assert!(toml::from_str::<PermissionDef>(array).is_err());
    }

    // --- Access bit set: parse, union, canonical token ---

    /// Parse one access value from a standalone `access = <value>` TOML fragment.
    fn parse_access(value: &str) -> Result<Access, toml::de::Error> {
        #[derive(Deserialize)]
        struct Wrap {
            access: Access,
        }
        toml::from_str::<Wrap>(&format!("access = {value}")).map(|w| w.access)
    }

    #[test]
    fn access_legacy_aliases_map_to_fixed_sets() {
        // `ro` == {read, traverse}; `rw` == {read, write, traverse}. These are the
        // sets that preserve the historical ACL strings (proven in fileaccess.rs).
        assert_eq!(parse_access("\"ro\"").unwrap(), Access::RO);
        assert_eq!(parse_access("\"rw\"").unwrap(), Access::RW);
        assert_eq!(
            Access::RO,
            Access::READ | Access::TRAVERSE,
            "ro is read+traverse"
        );
        assert_eq!(
            Access::RW,
            Access::READ | Access::WRITE | Access::TRAVERSE,
            "rw is read+write+traverse"
        );
    }

    #[test]
    fn access_compact_letters_parse() {
        assert_eq!(parse_access("\"r\"").unwrap(), Access::READ);
        assert_eq!(parse_access("\"w\"").unwrap(), Access::WRITE);
        assert_eq!(parse_access("\"x\"").unwrap(), Access::EXECUTE);
        assert_eq!(
            parse_access("\"rx\"").unwrap(),
            Access::READ | Access::EXECUTE
        );
        assert_eq!(
            parse_access("\"rwx\"").unwrap(),
            Access::READ | Access::WRITE | Access::EXECUTE
        );
    }

    #[test]
    fn access_bit_name_array_parses() {
        assert_eq!(
            parse_access("[\"read\", \"traverse\"]").unwrap(),
            Access::RO
        );
        assert_eq!(
            parse_access("[\"read\", \"execute\"]").unwrap(),
            Access::READ | Access::EXECUTE
        );
        assert_eq!(parse_access("[\"write\"]").unwrap(), Access::WRITE);
        // Order does not matter — it is a set.
        assert_eq!(
            parse_access("[\"traverse\", \"read\"]").unwrap(),
            Access::READ | Access::TRAVERSE
        );
    }

    #[test]
    fn access_unknown_or_append_token_rejected_fail_closed() {
        // Legacy typo, a bare unknown letter, an empty value, the never-declarable
        // `append`, and an unknown bit name all fail closed at parse.
        assert!(parse_access("\"wo\"").is_err());
        assert!(parse_access("\"q\"").is_err());
        assert!(parse_access("\"\"").is_err());
        assert!(parse_access("\"append\"").is_err());
        assert!(parse_access("\"a\"").is_err());
        assert!(parse_access("[\"append\"]").is_err());
        assert!(parse_access("[\"read\", \"bogus\"]").is_err());
        // Empty array names no capability.
        assert!(parse_access("[]").is_err());
        // A duplicate letter/name is a typo, not a wider grant.
        assert!(parse_access("\"rr\"").is_err());
        assert!(parse_access("[\"read\", \"read\"]").is_err());
    }

    #[test]
    fn access_noncanonical_compact_spellings_rejected() {
        // The compact grammar accepts ONLY the eight canonical spellings the schema
        // advertises. A misordered string, or capital `X` as a traverse spelling,
        // is rejected so the parser never drifts wider than the contract — the
        // bit-name array is the way to express those sets.
        assert!(parse_access("\"xr\"").is_err(), "misordered xr rejected");
        assert!(parse_access("\"wr\"").is_err(), "misordered wr rejected");
        assert!(
            parse_access("\"rX\"").is_err(),
            "capital-X compact rejected"
        );
        assert!(parse_access("\"X\"").is_err(), "bare capital X rejected");
        assert!(parse_access("\"xw\"").is_err(), "misordered xw rejected");
        // The array form is how a traverse-bearing non-legacy set is expressed.
        assert_eq!(
            parse_access("[\"read\", \"traverse\"]").unwrap(),
            Access::RO
        );
        assert_eq!(
            parse_access("[\"write\", \"traverse\"]").unwrap(),
            Access::WRITE | Access::TRAVERSE
        );
    }

    #[test]
    fn bundle_members_param_constraint_default_max_len_not_conflicting() {
        // A member declaring `max_len = 256` (the default) and another leaving it
        // implicit declare the SAME effective token constraint; the merge must be
        // idempotent, not a false ConflictingParamConstraint.
        let mut explicit = std::collections::BTreeMap::new();
        explicit.insert(
            "unit".to_owned(),
            ParamConstraint::Token {
                max_len: Some(PARAM_DEFAULT_MAX_LEN),
            },
        );
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec![
                        "/usr/bin/systemctl restart {unit}".to_owned()
                    ]),
                    params: token_param("unit"), // max_len: None (implicit default)
                    ..def("svc-implicit")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(
                        vec!["/usr/bin/systemctl status {unit}".to_owned()],
                    ),
                    params: explicit, // max_len: Some(default)
                    ..def("svc-explicit")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    includes: vec!["svc-implicit".into(), "svc-explicit".into()],
                    ..def("svc-bundle")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve("svc-bundle", &os, &cat, &ctx())
            .expect("identical-effective constraints must merge, not conflict");
        assert!(r.params.contains_key("unit"));
    }

    #[test]
    fn access_union_is_bit_or_idempotent_and_order_independent() {
        let a = Access::READ;
        let b = Access::WRITE | Access::TRAVERSE;
        let want = Access::READ | Access::WRITE | Access::TRAVERSE;
        assert_eq!(a | b, want);
        assert_eq!(b | a, want, "commutative");
        assert_eq!(want | want, want, "idempotent");
        assert_eq!(a.union(a), a, "self-union is identity");

        let mut acc = Access::READ;
        acc |= Access::WRITE;
        assert_eq!(acc, Access::READ | Access::WRITE);
    }

    #[test]
    fn access_serde_round_trips_every_set() {
        // The serialized form (legacy string for ro/rw, bit-name array otherwise)
        // must re-deserialize to the same set for EVERY combination — this is what
        // keeps the persisted managed-registry grant stable across writes.
        let all = [
            Access::READ,
            Access::WRITE,
            Access::EXECUTE,
            Access::TRAVERSE,
        ];
        // Every non-empty subset of the four bits, plus the legacy sets.
        for mask in 1u8..=0b1111 {
            let mut set = Access(0);
            for (i, bit) in all.iter().enumerate() {
                if mask & (1 << i) != 0 {
                    set |= *bit;
                }
            }
            #[derive(serde::Serialize, Deserialize, PartialEq, Debug)]
            struct Wrap {
                access: Access,
            }
            let toml_str = toml::to_string(&Wrap { access: set }).unwrap();
            let back: Wrap = toml::from_str(&toml_str).unwrap();
            assert_eq!(back.access, set, "serde round-trip for {set:?}\n{toml_str}");
        }
    }

    #[test]
    fn access_legacy_sets_serialize_to_legacy_strings() {
        // ro/rw keep their historical string spelling so a registry written before
        // the bit-set change still reads back unchanged.
        #[derive(serde::Serialize)]
        struct Wrap {
            access: Access,
        }
        assert_eq!(
            toml::to_string(&Wrap { access: Access::RO }).unwrap(),
            "access = \"ro\"\n"
        );
        assert_eq!(
            toml::to_string(&Wrap { access: Access::RW }).unwrap(),
            "access = \"rw\"\n"
        );
        // A non-legacy set serializes as the bit-name array (NOT a colliding
        // letter string).
        assert_eq!(
            toml::to_string(&Wrap {
                access: Access::READ | Access::WRITE
            })
            .unwrap(),
            "access = [\"read\", \"write\"]\n"
        );
    }

    #[test]
    fn access_display_tokens() {
        assert_eq!(Access::RO.to_string(), "ro");
        assert_eq!(Access::RW.to_string(), "rw");
        assert_eq!(Access::READ.to_string(), "r");
        assert_eq!(Access::EXECUTE.to_string(), "x");
        assert_eq!((Access::READ | Access::WRITE).to_string(), "rw");
        assert_eq!((Access::READ | Access::EXECUTE).to_string(), "rx");
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
        let bad = file_def("a", vec![grant("etc/ssh", Access::RW, true)]);
        // validate() runs at the read boundary; FakeCatalog.read_layer triggers it.
        let cat = cat.with("linux", bad);
        let err =
            resolve_leaf("a", &OsTarget::new("linux", "debian", None).unwrap(), &cat).unwrap_err();
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
            file_def("a", vec![grant("/etc/ssh/../shadow", Access::RO, false)]),
        );
        let err =
            resolve_leaf("a", &OsTarget::new("linux", "debian", None).unwrap(), &cat).unwrap_err();
        assert!(matches!(
            err,
            CatalogError::InvalidFilePath { reason, .. } if reason.contains("..")
        ));
    }

    #[test]
    fn file_path_control_char_rejected() {
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("a", vec![grant("/etc/ss\nh", Access::RO, false)]),
        );
        let err =
            resolve_leaf("a", &OsTarget::new("linux", "debian", None).unwrap(), &cat).unwrap_err();
        assert!(matches!(
            err,
            CatalogError::InvalidFilePath { reason, .. } if reason.contains("control")
        ));
    }

    #[test]
    fn dotdot_inside_name_is_allowed() {
        // `a..b` as a longer component is not a traversal; only a bare `..` is.
        let g = grant("/etc/my..app", Access::RO, true);
        assert_eq!(file_path_static_defect(&g.path), None);
    }

    #[test]
    fn shape_derivation_rule() {
        // recursive=true → Dir.
        assert_eq!(grant("/etc/ssh", Access::RW, true).shape(), Shape::Dir);
        // trailing slash → Dir even without recursive.
        assert_eq!(grant("/etc/ssh/", Access::RW, false).shape(), Shape::Dir);
        // bare path, no recursive, no slash → File (the AclBackend refuses these,
        // steering authors to widen to a directory).
        assert_eq!(grant("/etc/ssh", Access::RW, false).shape(), Shape::File);
        // glob metachar → Pattern, regardless of recursive.
        assert_eq!(
            grant("/var/log/*.log", Access::RO, false).shape(),
            Shape::Pattern
        );
        assert_eq!(
            grant("/var/log/*.log", Access::RO, true).shape(),
            Shape::Pattern
        );
        assert_eq!(
            grant("/etc/conf?", Access::RO, false).shape(),
            Shape::Pattern
        );
        assert_eq!(
            grant("/etc/[abc]", Access::RO, false).shape(),
            Shape::Pattern
        );
    }

    #[test]
    fn trailing_slash_with_recursive_false_rejected_at_read_boundary() {
        // A trailing '/' marks Shape::Dir, which the AclBackend always materializes
        // recursively; pairing it with recursive=false is contradictory (the flag
        // is silently ineffective) and must fail closed at the read boundary.
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("a", vec![grant("/etc/ssh/", Access::RW, false)]),
        );
        let err =
            resolve_leaf("a", &OsTarget::new("linux", "debian", None).unwrap(), &cat).unwrap_err();
        assert!(matches!(
            err,
            CatalogError::InvalidFilePath { ref id, reason, .. }
                if id == "a" && reason.contains("trailing '/'")
        ));

        // trailing slash + recursive=true → accepted, resolves as Dir.
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("b", vec![grant("/etc/ssh/", Access::RW, true)]),
        );
        let (r, _) =
            resolve_leaf("b", &OsTarget::new("linux", "debian", None).unwrap(), &cat).unwrap();
        assert_eq!(r.file_grants[0].shape, Shape::Dir);

        // no trailing slash + recursive=true → accepted, Dir.
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("c", vec![grant("/etc/ssh", Access::RW, true)]),
        );
        let (r, _) =
            resolve_leaf("c", &OsTarget::new("linux", "debian", None).unwrap(), &cat).unwrap();
        assert_eq!(r.file_grants[0].shape, Shape::Dir);

        // no trailing slash + recursive=false → accepted, File (unchanged).
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("d", vec![grant("/etc/ssh", Access::RW, false)]),
        );
        let (r, _) =
            resolve_leaf("d", &OsTarget::new("linux", "debian", None).unwrap(), &cat).unwrap();
        assert_eq!(r.file_grants[0].shape, Shape::File);
    }

    #[test]
    fn resolve_collects_file_grant_with_provenance() {
        let cat = FakeCatalog::new().with(
            "linux",
            file_def("ssh-admin", vec![grant("/etc/ssh", Access::RW, true)]),
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve_leaf("ssh-admin", &os, &cat).unwrap();
        assert_eq!(r.file_grants.len(), 1);
        let fg = &r.file_grants[0];
        assert_eq!(fg.path, "/etc/ssh");
        assert_eq!(fg.access, Access::RW);
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
                file_def("ssh-admin", vec![grant("/etc/ssh", Access::RO, false)]),
            )
            .with(
                "linux-debian",
                file_def("ssh-admin", vec![grant("/etc/ssh", Access::RW, true)]),
            );
        let (r, _) = resolve_leaf("ssh-admin", &debian12(), &cat).unwrap();
        assert_eq!(
            r.file_grants.len(),
            1,
            "same path must union, not duplicate"
        );
        let fg = &r.file_grants[0];
        assert_eq!(fg.access, Access::RW, "access widens to max");
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
                file_def("a", vec![grant("/etc/ssh", Access::RO, true)]),
            )
            .with(
                "linux-debian",
                PermissionDef {
                    replace: true,
                    files: vec![grant("/etc/pam.d", Access::RW, true)],
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
                    grant("/etc/ssh", Access::RW, true),
                    grant("/var/log", Access::RO, true),
                ],
            ),
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (r, _) = resolve_leaf("a", &os, &cat).unwrap();
        let paths: Vec<&str> = r.file_grants.iter().map(|g| g.path.as_str()).collect();
        assert_eq!(paths, vec!["/etc/ssh", "/var/log"]);
    }

    /// A file-grant record carrying a per-parameter constraint, for the
    /// templated-path tests (every placeholder needs a constraint at parse).
    fn file_def_p(
        id: &str,
        grants: Vec<FileGrant>,
        params: std::collections::BTreeMap<String, ParamConstraint>,
    ) -> PermissionDef {
        PermissionDef {
            params,
            ..file_def(id, grants)
        }
    }

    #[test]
    fn templated_file_path_substitutes_and_revalidates() {
        let cat = FakeCatalog::new().with(
            "linux",
            file_def_p(
                "app-config",
                vec![grant("/etc/{app}", Access::RW, true)],
                token_param("app"),
            ),
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
            file_def_p(
                "app-config",
                vec![grant("/etc/{app}", Access::RW, true)],
                token_param("app"),
            ),
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
            file_def_p(
                "app-config",
                vec![grant("/etc/{app}", Access::RW, true)],
                token_param("app"),
            ),
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        // A `..` smuggled via the param renders to a traversal path — must be
        // rejected by the post-substitution gate. The token constraint admits the
        // `..`-bearing value (`.` and `/` are valid identifier chars), so the
        // file-path gate is the authoritative one for the traversal here.
        let p = params(vec![("app", toml::Value::String("ssh".to_owned()))]);
        // Sanity: a clean value passes (so the rejection below is about injection).
        assert!(resolve_with_params("app-config", &p, &os, &cat, &ctx()).is_ok());
        // `/etc/../shadow` renders a `..` component; the file gate rejects it.
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
            file_def_p(
                "a",
                vec![grant("/{p}", Access::RO, false)],
                token_param("p"),
            ),
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        // Renders to "/etc" — absolute, fine.
        let ok = params(vec![("p", toml::Value::String("etc".to_owned()))]);
        assert!(resolve_with_params("a", &ok, &os, &cat, &ctx()).is_ok());
    }

    // --- parameter guard rails (feature B): per-record [params.*] constraints ---

    #[test]
    fn placeholder_without_constraint_rejected_at_parse() {
        // A template carries {unit} but the record declares no [params.unit]:
        // fail-closed at the read boundary, before resolve.
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/systemctl restart {unit}".to_owned()]),
                ..def("svc")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let err = resolve("svc", &os, &cat, &ctx()).unwrap_err();
        assert!(matches!(
            err,
            CatalogError::UnconstrainedParam { ref id, ref param }
                if id == "svc" && param == "unit"
        ));
    }

    #[test]
    fn orphan_constraint_rejected_at_parse() {
        // A [params.unused] constraint with no matching placeholder is dead
        // config and rejected at parse (pre-release strictness).
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                params: token_param("unused"),
                ..def("net")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let err = resolve("net", &os, &cat, &ctx()).unwrap_err();
        assert!(matches!(
            err,
            CatalogError::OrphanParamConstraint { ref id, ref param }
                if id == "net" && param == "unused"
        ));
    }

    #[test]
    fn malformed_path_constraint_rejected_at_parse() {
        // A path-kind constraint with an empty allow_prefix would accept any
        // absolute path, defeating the guard rail — rejected at parse.
        let mut p = std::collections::BTreeMap::new();
        p.insert(
            "app".to_owned(),
            ParamConstraint::Path {
                allow_prefix: Vec::new(),
                deny_glob: None,
                max_len: None,
            },
        );
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/edit {app}".to_owned()]),
                params: p,
                ..def("svc")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        assert!(matches!(
            resolve("svc", &os, &cat, &ctx()).unwrap_err(),
            CatalogError::InvalidParamConstraint { ref id, ref param, .. }
                if id == "svc" && param == "app"
        ));
    }

    #[test]
    fn path_constraint_rejects_value_outside_allow_prefix() {
        let mut p = std::collections::BTreeMap::new();
        p.insert(
            "path".to_owned(),
            ParamConstraint::Path {
                allow_prefix: vec!["/etc/myapp/".to_owned()],
                deny_glob: None,
                max_len: None,
            },
        );
        let cat = FakeCatalog::new().with(
            "linux",
            file_def_p("app-config", vec![grant("{path}", Access::RW, true)], p),
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        // Under the prefix → accepted.
        let ok = params(vec![(
            "path",
            toml::Value::String("/etc/myapp/conf/".to_owned()),
        )]);
        assert!(resolve_with_params("app-config", &ok, &os, &cat, &ctx()).is_ok());
        // The classic fail-open target: /etc/shadow is not under the prefix.
        let bad = params(vec![(
            "path",
            toml::Value::String("/etc/shadow".to_owned()),
        )]);
        assert!(matches!(
            resolve_with_params("app-config", &bad, &os, &cat, &ctx()).unwrap_err(),
            CatalogError::ParamConstraintViolation { ref id, ref param, .. }
                if id == "app-config" && param == "path"
        ));
    }

    #[test]
    fn path_constraint_declaration_requires_trailing_slash() {
        // A prefix without a trailing `/` lets a textual `starts_with` admit a
        // sibling directory (`/etc/app` would match `/etc/apparmor.d/...`). The
        // declaration gate must fail closed at parse so only component-bounded
        // prefixes ever reach enforcement.
        let no_slash = ParamConstraint::Path {
            allow_prefix: vec!["/etc/app".to_owned()],
            deny_glob: None,
            max_len: None,
        };
        assert!(
            no_slash.declaration_defect().is_some(),
            "an allow_prefix without a trailing '/' must be rejected at parse"
        );
        let with_slash = ParamConstraint::Path {
            allow_prefix: vec!["/etc/app/".to_owned()],
            deny_glob: None,
            max_len: None,
        };
        assert!(
            with_slash.declaration_defect().is_none(),
            "a component-bounded allow_prefix must be accepted"
        );
    }

    #[test]
    fn path_constraint_value_check_is_component_bounded() {
        // Defence in depth behind the declaration gate: the value check itself
        // must match on a `/`-component boundary, never a raw text prefix. Even
        // given a (now parse-rejected) slash-less prefix, a sibling directory
        // must not be admitted.
        let c = ParamConstraint::Path {
            allow_prefix: vec!["/etc/app".to_owned()],
            deny_glob: None,
            max_len: None,
        };
        // The classic sibling escape: `/etc/app` must NOT admit `/etc/apparmor.d`.
        assert_eq!(
            c.value_defect("/etc/apparmor.d/usr.sbin.foo"),
            Some("path value is not under any allowed prefix"),
            "a sibling directory must never satisfy the prefix"
        );
        // A genuine child, and the directory itself, are admitted.
        assert!(c.value_defect("/etc/app/conf").is_none());
        assert!(c.value_defect("/etc/app").is_none());
        // A trailing-slash prefix behaves identically on the boundary.
        let c_slash = ParamConstraint::Path {
            allow_prefix: vec!["/etc/app/".to_owned()],
            deny_glob: None,
            max_len: None,
        };
        assert_eq!(
            c_slash.value_defect("/etc/apparmor.d/x"),
            Some("path value is not under any allowed prefix")
        );
        assert!(c_slash.value_defect("/etc/app/x").is_none());
    }

    #[test]
    fn path_constraint_denies_glob_by_default() {
        // The path-kind `deny_glob` (default true) is the second line of defence
        // behind the param-value gate, which already forbids `*?[` for sudo
        // safety. Exercise the constraint directly so its glob policy is tested
        // independent of which gate fires first at resolve.
        let c = ParamConstraint::Path {
            allow_prefix: vec!["/srv/".to_owned()],
            deny_glob: None, // default true
            max_len: None,
        };
        assert!(c
            .value_defect("/srv/*.conf")
            .is_some_and(|r| r.contains("glob")));
        // The same value under an explicit deny_glob=false is allowed (prefix ok).
        let c_allow = ParamConstraint::Path {
            allow_prefix: vec!["/srv/".to_owned()],
            deny_glob: Some(false),
            max_len: None,
        };
        assert!(c_allow.value_defect("/srv/*.conf").is_none());

        // And at resolve, a glob value still fails closed (the param-value gate is
        // the one that fires first here) — the path is never widened to a pattern.
        let mut p = std::collections::BTreeMap::new();
        p.insert(
            "path".to_owned(),
            ParamConstraint::Path {
                allow_prefix: vec!["/srv/".to_owned()],
                deny_glob: None,
                max_len: None,
            },
        );
        let cat = FakeCatalog::new().with(
            "linux",
            file_def_p("g", vec![grant("{path}", Access::RO, true)], p),
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let bad = params(vec![(
            "path",
            toml::Value::String("/srv/*.conf".to_owned()),
        )]);
        assert!(resolve_with_params("g", &bad, &os, &cat, &ctx()).is_err());
    }

    #[test]
    fn enum_constraint_rejects_value_not_in_list() {
        let mut p = std::collections::BTreeMap::new();
        p.insert(
            "verb".to_owned(),
            ParamConstraint::Enum {
                values: vec!["start".to_owned(), "stop".to_owned()],
            },
        );
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/systemctl {verb} nginx".to_owned()]),
                params: p,
                ..def("svc")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        // Allowed value → accepted.
        let ok = params(vec![("verb", toml::Value::String("start".to_owned()))]);
        assert!(resolve_with_params("svc", &ok, &os, &cat, &ctx()).is_ok());
        // A verb outside the set (e.g. `mask`) is refused.
        let bad = params(vec![("verb", toml::Value::String("mask".to_owned()))]);
        assert!(matches!(
            resolve_with_params("svc", &bad, &os, &cat, &ctx()).unwrap_err(),
            CatalogError::ParamConstraintViolation { ref param, .. } if param == "verb"
        ));
    }

    #[test]
    fn token_constraint_rejects_illegal_char() {
        // A token value carrying a char outside the safe identifier charset (a
        // space is already blocked by the param-value gate; use a `,` which the
        // FORBIDDEN set blocks — so use a `;`? both are blocked earlier). Use a
        // char the param-value gate permits but the token charset does not: the
        // param-value gate permits e.g. `+`, the token charset does not.
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/systemctl restart {unit}".to_owned()]),
                params: token_param("unit"),
                ..def("svc")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let bad = params(vec![("unit", toml::Value::String("ngin+x".to_owned()))]);
        assert!(matches!(
            resolve_with_params("svc", &bad, &os, &cat, &ctx()).unwrap_err(),
            CatalogError::ParamConstraintViolation { ref param, .. } if param == "unit"
        ));
        // A clean systemd-style instance name passes (charset includes @, -).
        let ok = params(vec![(
            "unit",
            toml::Value::String("wg-quick@wg0".to_owned()),
        )]);
        assert!(resolve_with_params("svc", &ok, &os, &cat, &ctx()).is_ok());
    }

    #[test]
    fn token_constraint_enforces_max_len() {
        let mut p = std::collections::BTreeMap::new();
        p.insert(
            "unit".to_owned(),
            ParamConstraint::Token { max_len: Some(4) },
        );
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/systemctl restart {unit}".to_owned()]),
                params: p,
                ..def("svc")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let bad = params(vec![("unit", toml::Value::String("nginx".to_owned()))]);
        assert!(matches!(
            resolve_with_params("svc", &bad, &os, &cat, &ctx()).unwrap_err(),
            CatalogError::ParamConstraintViolation { reason, .. } if reason.contains("max_len")
        ));
    }

    #[test]
    fn list_param_one_bad_element_fails_closed() {
        // A list param expands to one Cmnd per element; a SINGLE element outside
        // the constraint must fail the whole resolve closed, not silently drop.
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/systemctl restart {units}".to_owned()]),
                params: token_param("units"),
                ..def("svc")
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        // First element clean, second carries an illegal char.
        let bad = params(vec![("units", arr(&["nginx", "ngin+x"]))]);
        assert!(matches!(
            resolve_with_params("svc", &bad, &os, &cat, &ctx()).unwrap_err(),
            CatalogError::ParamConstraintViolation { ref param, .. } if param == "units"
        ));
        // All-clean list resolves.
        let ok = params(vec![("units", arr(&["nginx", "redis"]))]);
        assert!(resolve_with_params("svc", &ok, &os, &cat, &ctx()).is_ok());
    }

    #[test]
    fn params_table_parses_from_toml() {
        // The on-disk [params.<name>] surface deserializes into the right kinds,
        // and an unknown key inside a constraint is rejected (deny_unknown_fields).
        let def: PermissionDef = toml::from_str(
            r#"
id = "svc"
sudo = ["/usr/bin/systemctl {verb} {units}"]
[[file]]
path = "{cfg}"
access = "rw"
recursive = true
[params.units]
kind = "token"
[params.verb]
kind = "enum"
values = ["start", "stop"]
[params.cfg]
kind = "path"
allow_prefix = ["/etc/app/"]
deny_glob = false
"#,
        )
        .unwrap();
        assert_eq!(def.params.len(), 3);
        assert!(matches!(
            def.params.get("units"),
            Some(ParamConstraint::Token { max_len: None })
        ));
        assert!(matches!(
            def.params.get("verb"),
            Some(ParamConstraint::Enum { values }) if values.len() == 2
        ));
        assert!(matches!(
            def.params.get("cfg"),
            Some(ParamConstraint::Path {
                deny_glob: Some(false),
                ..
            })
        ));

        // Unknown key inside a token constraint is rejected.
        assert!(toml::from_str::<PermissionDef>(
            "id = \"svc\"\nsudo = [\"/x {u}\"]\n[params.u]\nkind = \"token\"\nbogus = 1\n"
        )
        .is_err());
    }

    #[test]
    fn segment_constraint_parses_from_toml() {
        // The `[params.<name>]` surface accepts `kind = "segment"` with an
        // optional `max_len`, and a bare segment (no max_len) deserializes to the
        // defaulted-None form.
        let def: PermissionDef = toml::from_str(
            r#"
id = "app-config"
[[file]]
path = "/etc/{app}"
access = "rw"
recursive = true
[params.app]
kind = "segment"
max_len = 64
"#,
        )
        .unwrap();
        assert!(matches!(
            def.params.get("app"),
            Some(ParamConstraint::Segment { max_len: Some(64) })
        ));

        let def_bare: PermissionDef =
            toml::from_str("id = \"a\"\nsudo = [\"/x {s}\"]\n[params.s]\nkind = \"segment\"\n")
                .unwrap();
        assert!(matches!(
            def_bare.params.get("s"),
            Some(ParamConstraint::Segment { max_len: None })
        ));

        // A non-integer max_len is rejected by deserialization.
        assert!(toml::from_str::<PermissionDef>(
            "id = \"a\"\nsudo = [\"/x {s}\"]\n[params.s]\nkind = \"segment\"\nmax_len = \"big\"\n"
        )
        .is_err());

        // An unknown key inside a segment constraint is rejected
        // (deny_unknown_fields, like every other kind).
        assert!(toml::from_str::<PermissionDef>(
            "id = \"a\"\nsudo = [\"/x {s}\"]\n[params.s]\nkind = \"segment\"\nbogus = 1\n"
        )
        .is_err());
    }

    #[test]
    fn segment_value_defect_accepts_and_rejects() {
        // A segment value is a single safe path component that doubles as a plain
        // name: ASCII alphanumerics plus `.`, `_`, `-` only.
        let c = ParamConstraint::Segment { max_len: None };
        // Accepted: capitalised app name, hyphen+digit, dotted, underscored.
        for ok in ["Supervisor", "app-1", "foo.bar", "a_b", "x"] {
            assert!(
                c.value_defect(ok).is_none(),
                "expected {ok:?} to pass the segment charset"
            );
        }
        // Rejected: a path separator turns one segment into two (or a traversal),
        // and the `.`/`..` components and the empty value must never reach a path.
        for (bad, frag) in [
            ("foo/bar", "charset"),
            ("../x", "charset"),
            ("a\\b", "charset"),
            ("a:b", "charset"),
            ("a@b", "charset"),
            ("..", "`.` or `..`"),
            (".", "`.` or `..`"),
            ("", "empty"),
        ] {
            assert!(
                c.value_defect(bad).is_some_and(|r| r.contains(frag)),
                "expected {bad:?} to be rejected mentioning {frag:?}"
            );
        }
        // A control character is outside the charset.
        assert!(c.value_defect("a\u{7}b").is_some());

        // The length bound is enforced.
        let c4 = ParamConstraint::Segment { max_len: Some(4) };
        assert!(c4.value_defect("abcd").is_none());
        assert!(c4
            .value_defect("abcde")
            .is_some_and(|r| r.contains("max_len")));
    }

    #[test]
    fn segment_constraint_resolves_into_path_and_token() {
        // One segment value safely fills both a path component and a sudo token.
        let mut p = std::collections::BTreeMap::new();
        p.insert("app".to_owned(), ParamConstraint::Segment { max_len: None });
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/systemctl restart {app}".to_owned()]),
                params: p,
                ..file_def("app-scope", vec![grant("/etc/{app}", Access::RW, true)])
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let ok = params(vec![("app", toml::Value::String("Supervisor".to_owned()))]);
        let (r, _) = resolve_with_params("app-scope", &ok, &os, &cat, &ctx()).unwrap();
        assert_eq!(r.file_grants[0].path, "/etc/Supervisor");
        assert_eq!(r.sudo[0].value, "/usr/bin/systemctl restart Supervisor");

        // A traversal value is refused at the segment gate, before any path gate.
        let bad = params(vec![("app", toml::Value::String("../etc".to_owned()))]);
        assert!(matches!(
            resolve_with_params("app-scope", &bad, &os, &cat, &ctx()).unwrap_err(),
            CatalogError::ParamConstraintViolation { ref param, .. } if param == "app"
        ));
    }

    // --- Feature A: parametrized includes (param-mapping) ---------------------

    /// A single-entry `params` map carrying a `segment`-kind constraint with no
    /// length cap — the safe app-name kind for the param-mapping tests.
    fn segment_param(name: &str) -> std::collections::BTreeMap<String, ParamConstraint> {
        let mut m = std::collections::BTreeMap::new();
        m.insert(name.to_owned(), ParamConstraint::Segment { max_len: None });
        m
    }

    /// A table-form include binding one member parameter to a template.
    fn bound_inc(id: &str, member_param: &str, template: &str) -> Include {
        let mut bindings = std::collections::BTreeMap::new();
        bindings.insert(member_param.to_owned(), template.to_owned());
        Include {
            id: id.to_owned(),
            bindings,
        }
    }

    /// Build the canonical `app-scope` bundle catalog: `service-control` (binds
    /// member `units` ← `{app}`) and `app-config-edit` (binds member `path` ←
    /// `/etc/{app}`), under a bundle `segment` param `app`/`apps`.
    fn app_scope_catalog() -> FakeCatalog {
        FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec![
                        "/usr/bin/systemctl restart {units}".to_owned()
                    ]),
                    params: token_param("units"),
                    ..def("service-control")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    params: {
                        let mut m = std::collections::BTreeMap::new();
                        m.insert(
                            "path".to_owned(),
                            ParamConstraint::Path {
                                allow_prefix: vec!["/etc/".to_owned()],
                                deny_glob: Some(true),
                                max_len: None,
                            },
                        );
                        m
                    },
                    ..file_def("app-config-edit", vec![grant("{path}", Access::RW, false)])
                },
            )
            .with(
                "linux",
                PermissionDef {
                    includes: vec![
                        bound_inc("service-control", "units", "{app}"),
                        bound_inc("app-config-edit", "path", "/etc/{app}"),
                    ],
                    params: segment_param("app"),
                    ..def("app-scope")
                },
            )
    }

    #[test]
    fn param_mapping_threads_one_value_into_unit_and_path() {
        // Lead test (guard 2 / H2): one `app` value resolves to a unit-restart sudo
        // command and an /etc/<app> file grant — the path binding reaches the
        // member path gate and passes (the `/` in `/etc/{app}` is NOT banned).
        let cat = app_scope_catalog();
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![("app", toml::Value::String("Supervisor".to_owned()))]);
        let (r, _) = resolve_with_params("app-scope", &p, &os, &cat, &ctx()).unwrap();

        assert_eq!(
            values(&r.sudo),
            vec!["/usr/bin/systemctl restart Supervisor"]
        );
        assert_eq!(r.file_grants.len(), 1);
        assert_eq!(r.file_grants[0].path, "/etc/Supervisor");

        // Provenance: each bound primitive records the member (`via`) and the
        // binding (`param=value`).
        let unit = &r.sudo[0];
        assert_eq!(unit.via.as_deref(), Some("service-control"));
        assert_eq!(unit.binding.as_deref(), Some("units=Supervisor"));
        let grant_src = &r.file_grants[0].sources[0];
        assert_eq!(grant_src.via.as_deref(), Some("app-config-edit"));
        assert_eq!(grant_src.binding.as_deref(), Some("path=/etc/Supervisor"));
    }

    #[test]
    fn param_mapping_traversal_fails_closed_on_both_guards() {
        // Guard 2 (path): `app="../x"` passes guard 1 only if `segment` allowed it
        // — it does not (`/` and `..`). Even bypassing that, `/etc/../x` would be
        // refused by the member path gate. Either way: fail closed.
        let cat = app_scope_catalog();
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![("app", toml::Value::String("../x".to_owned()))]);
        assert!(matches!(
            resolve_with_params("app-scope", &p, &os, &cat, &ctx()).unwrap_err(),
            CatalogError::ParamConstraintViolation { ref param, .. } if param == "app"
        ));
    }

    #[test]
    fn param_mapping_member_constraint_rejects_independently_of_guard_1() {
        // Guard 2 in isolation: a bound value that PASSES the bundle constraint
        // (guard 1) but is rejected by the MEMBER's own constraint. Every other
        // rejection test trips guard 1 or a parse gate first; this one pins the
        // member-side guard alone, so it cannot silently regress.
        //
        // `app="etc"` is a perfectly valid `segment` — guard 1 accepts it. The
        // binding `/x/{app}` renders the member value `/x/etc`, which the member's
        // own `[params.path]` (allow_prefix=["/etc/"]) rejects: `/x/etc` is not
        // under `/etc/`. The error must therefore originate at the MEMBER scope.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    params: {
                        let mut m = std::collections::BTreeMap::new();
                        m.insert(
                            "path".to_owned(),
                            ParamConstraint::Path {
                                allow_prefix: vec!["/etc/".to_owned()],
                                deny_glob: Some(true),
                                max_len: None,
                            },
                        );
                        m
                    },
                    ..file_def("config-edit", vec![grant("{path}", Access::RW, false)])
                },
            )
            .with(
                "linux",
                PermissionDef {
                    // Bundle param `app` is a segment; the binding prefixes a path
                    // the member constraint will NOT admit. Guard 1 sees only the
                    // segment value (`etc`), which it accepts.
                    includes: vec![bound_inc("config-edit", "path", "/x/{app}")],
                    params: segment_param("app"),
                    ..def("bad-prefix")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        // `etc` passes the bundle segment gate (alnum-only, no `/`/`..`).
        assert!(ParamConstraint::Segment { max_len: None }
            .value_defect("etc")
            .is_none());

        let p = params(vec![("app", toml::Value::String("etc".to_owned()))]);
        let err = resolve_with_params("bad-prefix", &p, &os, &cat, &ctx()).unwrap_err();
        // The rejection names the MEMBER permission and its `path` parameter, and
        // carries the MEMBER-scope rendered value (`/x/etc`) — proving it came from
        // `expand_bound_member` → `substitute_file_grants` (guard 2), not from the
        // bundle-scope guard 1 (which would name `bad-prefix`/`app`/`etc`).
        assert!(
            matches!(
                &err,
                CatalogError::ParamConstraintViolation { id, param, value, .. }
                    if id == "config-edit" && param == "path" && value == "/x/etc"
            ),
            "expected a member-scope path-constraint violation, got {err:?}"
        );
    }

    #[test]
    fn param_mapping_binding_only_param_is_constraint_checked() {
        // Lead test (guard 1 / C1): a bundle param used ONLY inside a binding (the
        // bundle has no own template mentioning it) is still constraint-checked.
        // A bad value fails closed — it does NOT slip through as `UnusedParam`.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec![
                        "/usr/bin/systemctl restart {units}".to_owned()
                    ]),
                    params: token_param("units"),
                    ..def("service-control")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    // The bundle carries NO own template; `app` appears only in the
                    // binding expression.
                    includes: vec![bound_inc("service-control", "units", "{app}")],
                    params: segment_param("app"),
                    ..def("app-svc")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();

        // A clean value resolves and is marked used (no UnusedParam warning).
        let ok = params(vec![("app", toml::Value::String("Supervisor".to_owned()))]);
        let (r, warnings) = resolve_with_params("app-svc", &ok, &os, &cat, &ctx()).unwrap();
        assert_eq!(
            values(&r.sudo),
            vec!["/usr/bin/systemctl restart Supervisor"]
        );
        assert!(
            !warnings
                .iter()
                .any(|w| matches!(w, Warning::UnusedParam { param, .. } if param == "app")),
            "a binding-consumed param must not warn as unused"
        );

        // A value the BUNDLE segment constraint rejects fails closed at guard 1 —
        // proving the binding-only param is checked, not silently trusted.
        let bad = params(vec![("app", toml::Value::String("a/b".to_owned()))]);
        assert!(matches!(
            resolve_with_params("app-svc", &bad, &os, &cat, &ctx()).unwrap_err(),
            CatalogError::ParamConstraintViolation { ref param, .. } if param == "app"
        ));
    }

    #[test]
    fn param_mapping_list_fans_out_per_app() {
        // A bundle LIST param (`apps`) fans the WHOLE bundle per element.
        let cat = app_scope_catalog();
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![("app", arr(&["Supervisor", "gateway"]))]);
        let (r, _) = resolve_with_params("app-scope", &p, &os, &cat, &ctx()).unwrap();

        let mut sudo = values(&r.sudo);
        sudo.sort();
        assert_eq!(
            sudo,
            vec![
                "/usr/bin/systemctl restart Supervisor",
                "/usr/bin/systemctl restart gateway",
            ]
        );
        let mut paths: Vec<&str> = r.file_grants.iter().map(|g| g.path.as_str()).collect();
        paths.sort();
        assert_eq!(paths, vec!["/etc/Supervisor", "/etc/gateway"]);
    }

    #[test]
    fn param_mapping_two_list_bundle_params_in_binding_rejected() {
        // H1: a binding expression referencing two list bundle params is a second
        // list dimension — rejected, not silently a cartesian.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/bin/x {units}".to_owned()]),
                    params: token_param("units"),
                    ..def("svc")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    includes: vec![bound_inc("svc", "units", "{apps}-{envs}")],
                    params: {
                        let mut m = segment_param("apps");
                        m.insert(
                            "envs".to_owned(),
                            ParamConstraint::Segment { max_len: None },
                        );
                        m
                    },
                    ..def("two-list")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![("apps", arr(&["a", "b"])), ("envs", arr(&["x", "y"]))]);
        assert!(matches!(
            resolve_with_params("two-list", &p, &os, &cat, &ctx()).unwrap_err(),
            CatalogError::MultipleExpansionLists { ref bundle, .. } if bundle == "two-list"
        ));
    }

    #[test]
    fn param_mapping_bundle_list_times_member_list_rejected() {
        // H1: a bundle list param fanned into a member AND a second list bundle
        // param consumed by the bundle's own template = two dimensions → reject.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/bin/x {units}".to_owned()]),
                    params: token_param("units"),
                    ..def("svc")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    // Bundle's own template fans on `tools`; the binding fans on
                    // `apps`. Two distinct list dimensions across the expansion.
                    sudo: ListOverride::Replace(vec!["/usr/bin/own {tools}".to_owned()]),
                    includes: vec![bound_inc("svc", "units", "{apps}")],
                    params: {
                        let mut m = segment_param("apps");
                        m.insert("tools".to_owned(), ParamConstraint::Token { max_len: None });
                        m
                    },
                    ..def("cross")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![
            ("apps", arr(&["a", "b"])),
            ("tools", arr(&["t1", "t2"])),
        ]);
        assert!(matches!(
            resolve_with_params("cross", &p, &os, &cat, &ctx()).unwrap_err(),
            CatalogError::MultipleExpansionLists { ref bundle, .. } if bundle == "cross"
        ));
    }

    #[test]
    fn param_mapping_unbound_member_param_rejected() {
        // M2: a member placeholder no binding fills → UnboundMemberParam.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/bin/x {units}".to_owned()]),
                    params: token_param("units"),
                    ..def("svc")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    // No binding for `units`.
                    includes: vec![Include::bare("svc")],
                    ..def("nobind")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        // A bare include of a parametrized member is the unbound case: the member's
        // `{units}` is never supplied (member params are internal). But a bare
        // include flattens the member, so its placeholder surfaces at the bundle
        // and needs a bundle param — which the bundle does not declare. The
        // expansion has no bound members, so this is the existing flatten path:
        // it fails on the missing param / unconstrained placeholder, fail-closed.
        // (The dedicated UnboundMemberParam path covers the *bound* include shape
        // below.)
        let p = params(vec![]);
        assert!(resolve_with_params("nobind", &p, &os, &cat, &ctx()).is_err());
    }

    #[test]
    fn param_mapping_unbound_member_param_in_bound_include_rejected() {
        // M2: a member with TWO placeholders, only one bound → UnboundMemberParam
        // for the unbound one.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/bin/x {a} {b}".to_owned()]),
                    params: {
                        let mut m = token_param("a");
                        m.insert("b".to_owned(), ParamConstraint::Token { max_len: None });
                        m
                    },
                    ..def("two-param")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    // Binds `a` but not `b`.
                    includes: vec![bound_inc("two-param", "a", "{app}")],
                    params: segment_param("app"),
                    ..def("partial")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![("app", toml::Value::String("X".to_owned()))]);
        assert!(matches!(
            resolve_with_params("partial", &p, &os, &cat, &ctx()).unwrap_err(),
            CatalogError::UnboundMemberParam { ref member, ref param, .. }
                if member == "two-param" && param == "b"
        ));
    }

    #[test]
    fn param_mapping_orphan_binding_rejected() {
        // M2: a binding naming a member param the member does not have.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/bin/x {units}".to_owned()]),
                    params: token_param("units"),
                    ..def("svc")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    // `nope` is not a parameter of `svc`.
                    includes: vec![bound_inc("svc", "nope", "{app}")],
                    params: segment_param("app"),
                    ..def("orphan")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![("app", toml::Value::String("X".to_owned()))]);
        assert!(matches!(
            resolve_with_params("orphan", &p, &os, &cat, &ctx()).unwrap_err(),
            CatalogError::OrphanIncludeBinding { ref member, ref param, .. }
                if member == "svc" && param == "nope"
        ));
    }

    #[test]
    fn param_mapping_unknown_bundle_param_rejected_at_parse() {
        // M2: a binding template referencing a bundle param that does not exist is
        // a read-boundary error (PermissionDef::validate).
        let def = PermissionDef {
            includes: vec![bound_inc("svc", "units", "{xyz}")],
            params: segment_param("app"),
            ..def("bad-bundle")
        };
        assert!(matches!(
            def.validate().unwrap_err(),
            CatalogError::UnknownBundleParam { ref bundle, ref param, .. }
                if bundle == "bad-bundle" && param == "xyz"
        ));
    }

    #[test]
    fn param_mapping_nested_bundle_rejected() {
        // M3: a bound member that is ITSELF a parametrized bundle → NestedParamMapping.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/bin/x {units}".to_owned()]),
                    params: token_param("units"),
                    ..def("leaf-svc")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    // `inner` is itself a parametrized bundle (it carries a binding).
                    includes: vec![bound_inc("leaf-svc", "units", "{app}")],
                    params: segment_param("app"),
                    ..def("inner")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    // `outer` binds `inner`, which is parametrized → reject.
                    includes: vec![bound_inc("inner", "app", "{x}")],
                    params: segment_param("x"),
                    ..def("outer")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        assert!(matches!(
            resolve("outer", &os, &cat, &ctx()).unwrap_err(),
            CatalogError::NestedParamMapping { ref bundle, ref member, .. }
                if bundle == "outer" && member == "inner"
        ));
    }

    #[test]
    fn bare_include_of_parametrized_bundle_rejected() {
        // M3, bare-include arm: a BARE (string) include of a permission that is
        // itself a parametrized bundle (its resolution carries bound members) must
        // fail closed with NestedParamMapping, exactly as the bound-include arm
        // does — otherwise the outer bundle would flatten only the inner's own
        // primitives and silently drop the inner's bound members (under-grant).
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/bin/x {units}".to_owned()]),
                    params: token_param("units"),
                    ..def("leaf-svc")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    // `inner` param-maps: it binds the leaf to a unit name.
                    includes: vec![bound_inc("leaf-svc", "units", "{app}")],
                    params: segment_param("app"),
                    ..def("inner")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    // `outer` BARE-includes `inner` (a string, no binding). `inner`
                    // is parametrized, so the bare include is rejected too.
                    includes: vec!["inner".into()],
                    ..def("outer")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        assert!(matches!(
            resolve("outer", &os, &cat, &ctx()).unwrap_err(),
            CatalogError::NestedParamMapping { ref bundle, ref member, .. }
                if bundle == "outer" && member == "inner"
        ));
    }

    #[test]
    fn bare_include_of_plain_bundle_still_resolves() {
        // The guard must NOT over-reach: a bare include of a NON-parametrized
        // bundle (no bound members — only static primitives and/or bare members)
        // still flattens normally. Only an inner bundle that param-maps is blocked.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    // A plain leaf: a static sudo command, no params, no bindings.
                    sudo: ListOverride::Replace(vec!["/usr/bin/plain".to_owned()]),
                    ..def("plain-leaf")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    // `inner` is an unparametrized bundle: it bare-includes the leaf
                    // and adds a static command of its own. No bound members.
                    sudo: ListOverride::Replace(vec!["/usr/bin/inner".to_owned()]),
                    includes: vec!["plain-leaf".into()],
                    ..def("inner-plain")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    // `outer` bare-includes the plain inner bundle — must resolve.
                    includes: vec!["inner-plain".into()],
                    ..def("outer-plain")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (resolved, _warnings) =
            resolve("outer-plain", &os, &cat, &ctx()).expect("plain bare include resolves");
        let sudo: Vec<&str> = resolved.sudo.iter().map(|p| p.value.as_str()).collect();
        assert!(
            sudo.contains(&"/usr/bin/plain") && sudo.contains(&"/usr/bin/inner"),
            "both the leaf and inner static commands must flatten through the bare \
             includes; got {sudo:?}"
        );
    }

    #[test]
    fn param_mapping_dedup_is_binding_aware() {
        // M4: two table-includes of the same member id with DIFFERENT bindings must
        // NOT collapse — they are distinct expansions.
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec![
                        "/usr/bin/systemctl restart {units}".to_owned()
                    ]),
                    params: token_param("units"),
                    ..def("service-control")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    // Same member, two different bindings.
                    includes: vec![
                        bound_inc("service-control", "units", "{a}"),
                        bound_inc("service-control", "units", "{b}"),
                    ],
                    params: {
                        let mut m = segment_param("a");
                        m.insert("b".to_owned(), ParamConstraint::Segment { max_len: None });
                        m
                    },
                    ..def("multi")
                },
            );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![
            ("a", toml::Value::String("Supervisor".to_owned())),
            ("b", toml::Value::String("gateway".to_owned())),
        ]);
        let (r, _) = resolve_with_params("multi", &p, &os, &cat, &ctx()).unwrap();
        let mut sudo = values(&r.sudo);
        sudo.sort();
        assert_eq!(
            sudo,
            vec![
                "/usr/bin/systemctl restart Supervisor",
                "/usr/bin/systemctl restart gateway",
            ]
        );
    }

    #[test]
    fn bare_string_includes_still_parse() {
        // Back-compat: the bare-string `includes` form deserializes to an Include
        // with no bindings, alongside a table form on the same list.
        let def: PermissionDef = toml::from_str(
            r#"
id = "mixed"
includes = [
  "service-observe",
  { id = "service-control", units = "{app}" },
]
[params.app]
kind = "segment"
"#,
        )
        .unwrap();
        assert_eq!(def.includes.len(), 2);
        assert_eq!(def.includes[0], Include::bare("service-observe"));
        assert_eq!(def.includes[1].id, "service-control");
        assert_eq!(
            def.includes[1].bindings.get("units").map(String::as_str),
            Some("{app}")
        );

        // An include table missing `id` is rejected.
        assert!(toml::from_str::<PermissionDef>(
            "id = \"x\"\nincludes = [ { units = \"{app}\" } ]\n[params.app]\nkind = \"segment\"\n"
        )
        .is_err());
    }

    #[test]
    fn param_mapping_provenance_excluded_from_drift_keys() {
        // M1: the binding provenance must not perturb the materialized primitive.
        // The sudo command value and the file grant (path, access, recursive) — the
        // drift keys — are exactly what a non-mapped grant would produce; only the
        // `binding`/`via` provenance differs, and those are never compared.
        let cat = app_scope_catalog();
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let p = params(vec![("app", toml::Value::String("Supervisor".to_owned()))]);
        let (r, _) = resolve_with_params("app-scope", &p, &os, &cat, &ctx()).unwrap();

        // The drift-relevant fields are the plain rendered primitive — provenance
        // lives only on `via`/`binding`, which the plan/apply key never reads.
        assert_eq!(r.sudo[0].value, "/usr/bin/systemctl restart Supervisor");
        assert_eq!(r.sudo[0].runas, None);
        assert_eq!(r.file_grants[0].path, "/etc/Supervisor");
        assert_eq!(r.file_grants[0].access, Access::RW);
        assert!(!r.file_grants[0].recursive);
    }
}
