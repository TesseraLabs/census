//! MAC-system-neutral provider SPI for refining a DAC verdict against mandatory
//! access control (Astra PARSEC now, `SELinux` later).
//!
//! ## Why an opaque, black-box SPI
//!
//! The exposure audit computes discretionary access (mode + owner + POSIX ACL) in
//! [`effective`](super::access::effective) and reports every verdict as an upper
//! bound — a DAC-writable object that the host's mandatory access control actually
//! forbids still surfaces as a finding. This module is the open-core seam that lets a
//! commercial backend fold in that mandatory layer **without teaching the open AGPL
//! core a single mandatory rule**. It mirrors the established
//! [`FileAccessBackend`](crate::fileaccess::FileAccessBackend) idiom: the open core
//! defines a trait plus a neutral default, and a commercial backend is injected by the
//! enterprise overlay.
//!
//! The core deliberately knows nothing about labels, lattices, or ordering:
//!
//! - [`MacLabelId`] and [`MacContextId`] are **opaque interned handles**. The core
//!   receives them from the backend and hands them straight back to
//!   [`MacProvider::permits`] / [`MacProvider::render_context`] /
//!   [`MacProvider::render_label`] — it never parses or compares their contents.
//! - [`MacProvider::principal_contexts`] returns an **unordered set**. The core
//!   assumes no lattice and no precedence between contexts. This is exactly what lets
//!   `SELinux` type-enforcement (no natural order) drop into the same trait as PARSEC's
//!   Biba/BLP lattice with no core change.
//! - The single mandatory decision lives entirely behind
//!   [`MacProvider::permits`], a black box the core treats as ground truth.
//!
//! ## Distinguishing "no MAC" from a real backend
//!
//! The open build's default is [`NullMacProvider`]: `object_label` yields `None`,
//! `permits` yields `true`, so the composite layer collapses to a no-op and
//! the audit's output is byte-for-byte what it is today. To let the note selection
//! (`DAC + <system>` vs the DAC-only note) and the `--mac` gating tell a real backend
//! apart from this neutral default, the trait carries [`MacProvider::is_active`]: it
//! defaults to `true` (a real backend is active) and [`NullMacProvider`] overrides it
//! to `false`. A single always-present `&dyn MacProvider` (Null as the default) is
//! cleaner than threading an `Option<&dyn MacProvider>` through every call site, and
//! `is_active` is the one explicit signal callers branch on. When `is_active` is
//! `false`, [`MacProvider::system`] is not meaningful and callers MUST NOT consult it.
//!
//! ## Read-only
//!
//! Like the rest of the exposure layer, this SPI is strictly read-only: it inspects
//! labels and evaluates permits, and never mutates any OS object or MAC state.

use std::collections::HashMap;

/// The mandatory access control system a [`MacProvider`] refines the verdict against.
///
/// The token ([`Self::as_str`]) is the stable form used in report notes (`DAC +
/// <system>`) and JSON output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum MacSystem {
    /// Astra Linux PARSEC (Biba integrity + BLP confidentiality lattice).
    Parsec,
    /// `SELinux` type-enforcement (unordered domains/types).
    Selinux,
}

impl MacSystem {
    /// The stable lowercase token for this system (`parsec`, `selinux`), used in
    /// report notes and JSON output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parsec => "parsec",
            Self::Selinux => "selinux",
        }
    }
}

impl std::fmt::Display for MacSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The mandatory-access refinement attached to a finding when a real provider is active.
///
/// Present only when the provider labels the object (a null provider or an unlabeled
/// object leaves the finding's annotation `None`). Its shape differs by audit mode:
///
/// - **expose** (per-principal): [`object_label`](Self::object_label) is the rendered
///   object label and [`reachable_in`](Self::reachable_in) is the **non-empty** set of
///   contexts in which the principal's access holds. A finding that MAC blocks in every
///   assumable context is suppressed rather than annotated, so in this mode an empty
///   `reachable_in` never occurs.
/// - **posture** (`audit fs`, principal-independent): there is no principal to evaluate
///   `permits` for, so [`reachable_in`](Self::reachable_in) is **empty** and the
///   annotation only carries the object's label.
///
/// Consequently `reachable_in` MAY be empty when this annotation is present — that is
/// the posture shape, not a "blocked" verdict.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct MacFinding {
    /// The MAC system whose rule refined (expose) or labeled (posture) the object.
    pub system: MacSystem,
    /// The rendered object label, when the provider labels the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_label: Option<String>,
    /// The rendered principal contexts in which the access holds. Non-empty in expose
    /// mode; empty in posture mode (no principal to evaluate).
    pub reachable_in: Vec<String>,
}

/// Which access a mandatory check is asked about.
///
/// The composite layer maps a DAC finding to the kind it must verify — a
/// write-exposure finding checks [`Self::Write`], a secret-read finding checks
/// [`Self::Read`]. The core carries the kind opaquely to [`MacProvider::permits`]; it
/// does not itself encode what "write" means under any mandatory rule (that is the
/// backend's, e.g. Biba integrity for write vs BLP confidentiality for read).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MacAccessKind {
    /// Read the object's contents.
    Read,
    /// Write / modify the object.
    Write,
    /// Execute the object.
    Execute,
}

impl MacAccessKind {
    /// The stable lowercase token for this kind (`read`, `write`, `execute`), for
    /// structured logging and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Execute => "execute",
        }
    }
}

impl std::fmt::Display for MacAccessKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An opaque handle to an object's mandatory label, interned by the backend.
///
/// The wrapped integer is an **interning index into the backend's own table**, not a
/// parse of the label — it is meaningless to the core and to any other backend. The
/// core never inspects it; it only carries the handle back to
/// [`MacProvider::permits`] and [`MacProvider::render_label`]. There is deliberately
/// no `FromStr`/`From<&str>` and no way to read a label's semantics out of the
/// handle: all label meaning stays behind the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacLabelId(u32);

impl MacLabelId {
    /// Mint a label handle from a backend interning index.
    ///
    /// The value is the backend's own table index; the core assigns no meaning to it.
    #[must_use]
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// The raw backend interning index (escape hatch for a backend keying its own
    /// interning table). This is NOT a rendered label — use
    /// [`MacProvider::render_label`] for a human-facing string.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// An opaque handle to a principal's mandatory context, interned by the backend.
///
/// Same contract as [`MacLabelId`]: the wrapped integer is a backend interning index,
/// not a parse of the context, and carries no order — the core must not compare two
/// [`MacContextId`]s for precedence (there is no lattice assumption). It is only ever
/// handed back to [`MacProvider::permits`] and [`MacProvider::render_context`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacContextId(u32);

impl MacContextId {
    /// Mint a context handle from a backend interning index.
    ///
    /// The value is the backend's own table index; the core assigns no meaning to it.
    #[must_use]
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// The raw backend interning index (escape hatch for a backend keying its own
    /// interning table). This is NOT a rendered context — use
    /// [`MacProvider::render_context`] for a human-facing string.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// The MAC-refinement SPI the exposure audit composes with, on top of the pure-DAC
/// [`effective`](super::access::effective).
///
/// ## Contract
///
/// - The core treats [`MacLabelId`]/[`MacContextId`] as **opaque**: it never parses a
///   label, never assumes a lattice or any ordering among contexts, and never encodes
///   a mandatory rule. All mandatory semantics (Biba/BLP/type-enforcement) live behind
///   [`permits`](Self::permits).
/// - [`principal_contexts`](Self::principal_contexts) returns an **unordered set** of
///   the contexts a principal may assume; the core filters it by
///   [`permits`](Self::permits) but attaches no precedence to the order.
/// - [`object_label`](Self::object_label) returning `None` means the object is
///   unlabeled / the backend has no MAC data for it; the core then leaves the DAC
///   verdict untouched (there is nothing to tighten with).
/// - [`render_context`](Self::render_context) / [`render_label`](Self::render_label)
///   are how the core prints handles it cannot itself interpret.
/// - [`is_active`](Self::is_active) distinguishes a real backend (`true`, the default)
///   from the neutral [`NullMacProvider`] (`false`). [`system`](Self::system) is only
///   meaningful when `is_active` is `true`.
///
/// Implementors are **read-only**: evaluating a provider never mutates any OS object
/// or MAC state.
pub trait MacProvider {
    /// The mandatory system this provider refines against. Only meaningful when
    /// [`is_active`](Self::is_active) returns `true`.
    fn system(&self) -> MacSystem;

    /// The object's mandatory label handle, or `None` when the object is unlabeled or
    /// the backend has no MAC data for the path. The core does not parse the handle.
    fn object_label(&self, path: &str) -> Option<MacLabelId>;

    /// The unordered set of mandatory contexts the principal `uid` may assume. Order
    /// carries no meaning; an empty set means the backend exposes no assumable context
    /// for the principal.
    fn principal_contexts(&self, uid: u32) -> Vec<MacContextId>;

    /// Whether `ctx` is permitted `access` to `label` under the backend's mandatory
    /// rule. This is the single black box carrying all mandatory semantics; the core
    /// treats its verdict as ground truth.
    fn permits(&self, ctx: MacContextId, label: MacLabelId, access: MacAccessKind) -> bool;

    /// A human-facing rendering of a context handle, for report output. The core
    /// prints this string without interpreting it.
    fn render_context(&self, ctx: MacContextId) -> String;

    /// A human-facing rendering of a label handle, for report output. The core prints
    /// this string without interpreting it.
    fn render_label(&self, label: MacLabelId) -> String;

    /// Whether a real MAC backend is active. `true` by default (a real backend);
    /// [`NullMacProvider`] overrides it to `false` so note selection and `--mac`
    /// gating can tell the neutral default apart from an injected backend.
    fn is_active(&self) -> bool {
        true
    }
}

/// The open-build default provider: MAC-neutral, so the audit's output is unchanged.
///
/// [`object_label`](MacProvider::object_label) yields `None` and
/// [`permits`](MacProvider::permits) yields `true`, so the composite over
/// [`effective`](super::access::effective) collapses to a no-op — identical findings
/// and note to a DAC-only build. [`is_active`](MacProvider::is_active) is `false`, the
/// signal that no real backend is linked.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullMacProvider;

impl MacProvider for NullMacProvider {
    // `is_active` is `false`, so this value is never consulted by note selection or
    // gating; it is a placeholder to satisfy the always-present-provider design and
    // is documented as not meaningful for the null provider.
    fn system(&self) -> MacSystem {
        MacSystem::Parsec
    }

    fn object_label(&self, _path: &str) -> Option<MacLabelId> {
        None
    }

    fn principal_contexts(&self, _uid: u32) -> Vec<MacContextId> {
        Vec::new()
    }

    fn permits(&self, _ctx: MacContextId, _label: MacLabelId, _access: MacAccessKind) -> bool {
        true
    }

    // The null provider never produces handles (object_label is None,
    // principal_contexts is empty), so these are unreachable in practice; they return
    // an empty string rather than panicking to keep the SPI total.
    fn render_context(&self, _ctx: MacContextId) -> String {
        String::new()
    }

    fn render_label(&self, _label: MacLabelId) -> String {
        String::new()
    }

    fn is_active(&self) -> bool {
        false
    }
}

/// A configurable in-memory [`MacProvider`] for unit tests — no `libpdp`/`libselinux`.
///
/// Configure it with object labels (by path), principal contexts (by uid), a
/// permit table keyed by `(context, label, access)`, and the renderings for each
/// handle, then exercise the composite (suppress / annotate) entirely
/// in memory. A `(context, label, access)` triple absent from the permit table is
/// treated as **denied** (`false`), modelling a default-deny mandatory system.
///
/// [`is_active`](MacProvider::is_active) is `true` (the default), so the Fake stands
/// in for a real, injected backend.
#[derive(Debug, Clone)]
pub struct FakeMacProvider {
    system: MacSystem,
    labels: HashMap<String, MacLabelId>,
    contexts: HashMap<u32, Vec<MacContextId>>,
    permits: HashMap<(MacContextId, MacLabelId, MacAccessKind), bool>,
    label_render: HashMap<MacLabelId, String>,
    context_render: HashMap<MacContextId, String>,
}

impl FakeMacProvider {
    /// An empty fake for the given system (no labels, contexts, or permits yet).
    #[must_use]
    pub fn new(system: MacSystem) -> Self {
        Self {
            system,
            labels: HashMap::new(),
            contexts: HashMap::new(),
            permits: HashMap::new(),
            label_render: HashMap::new(),
            context_render: HashMap::new(),
        }
    }

    /// Register that `path` carries `label`, rendered as `render`.
    pub fn with_label(
        &mut self,
        path: impl Into<String>,
        label: MacLabelId,
        render: impl Into<String>,
    ) -> &mut Self {
        self.labels.insert(path.into(), label);
        self.label_render.insert(label, render.into());
        self
    }

    /// Add `ctx` (rendered as `render`) to the assumable context set of `uid`.
    pub fn with_context(
        &mut self,
        uid: u32,
        ctx: MacContextId,
        render: impl Into<String>,
    ) -> &mut Self {
        self.contexts.entry(uid).or_default().push(ctx);
        self.context_render.insert(ctx, render.into());
        self
    }

    /// Set whether `ctx` is permitted `access` to `label`. Triples never set are
    /// denied by default.
    pub fn set_permit(
        &mut self,
        ctx: MacContextId,
        label: MacLabelId,
        access: MacAccessKind,
        allow: bool,
    ) -> &mut Self {
        self.permits.insert((ctx, label, access), allow);
        self
    }
}

impl MacProvider for FakeMacProvider {
    fn system(&self) -> MacSystem {
        self.system
    }

    fn object_label(&self, path: &str) -> Option<MacLabelId> {
        self.labels.get(path).copied()
    }

    fn principal_contexts(&self, uid: u32) -> Vec<MacContextId> {
        self.contexts.get(&uid).cloned().unwrap_or_default()
    }

    fn permits(&self, ctx: MacContextId, label: MacLabelId, access: MacAccessKind) -> bool {
        self.permits
            .get(&(ctx, label, access))
            .copied()
            .unwrap_or(false)
    }

    fn render_context(&self, ctx: MacContextId) -> String {
        self.context_render
            .get(&ctx)
            .cloned()
            .unwrap_or_else(|| format!("ctx#{}", ctx.as_u32()))
    }

    fn render_label(&self, label: MacLabelId) -> String {
        self.label_render
            .get(&label)
            .cloned()
            .unwrap_or_else(|| format!("label#{}", label.as_u32()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_system_token_and_display() {
        assert_eq!(MacSystem::Parsec.as_str(), "parsec");
        assert_eq!(MacSystem::Selinux.as_str(), "selinux");
        assert_eq!(MacSystem::Parsec.to_string(), "parsec");
        assert_eq!(MacSystem::Selinux.to_string(), "selinux");
    }

    #[test]
    fn mac_system_serde_roundtrips_as_kebab_token() {
        let json = serde_json::to_string(&MacSystem::Selinux).expect("serialize");
        assert_eq!(json, "\"selinux\"");
        let back: MacSystem = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, MacSystem::Selinux);
    }

    #[test]
    fn mac_access_kind_token_and_display() {
        assert_eq!(MacAccessKind::Read.as_str(), "read");
        assert_eq!(MacAccessKind::Write.as_str(), "write");
        assert_eq!(MacAccessKind::Execute.as_str(), "execute");
        assert_eq!(MacAccessKind::Write.to_string(), "write");
    }

    #[test]
    fn null_provider_is_neutral_and_inactive() {
        let null = NullMacProvider;
        assert!(!null.is_active(), "null provider signals no real backend");
        assert_eq!(
            null.object_label("/etc/shadow"),
            None,
            "null provider labels nothing"
        );
        assert!(
            null.principal_contexts(1000).is_empty(),
            "null provider exposes no contexts"
        );
        // permits is unconditionally true, so the composite layer keeps
        // every DAC finding — behaviour identical to a DAC-only build.
        let ctx = MacContextId::new(0);
        let label = MacLabelId::new(0);
        for access in [
            MacAccessKind::Read,
            MacAccessKind::Write,
            MacAccessKind::Execute,
        ] {
            assert!(null.permits(ctx, label, access), "null permits {access}");
        }
    }

    #[test]
    fn fake_provider_returns_configured_labels_and_contexts() {
        let mut fake = FakeMacProvider::new(MacSystem::Parsec);
        let secret = MacLabelId::new(7);
        let ctx_hi = MacContextId::new(1);
        fake.with_label("/etc/shadow", secret, "0:0:0:CCNR")
            .with_context(1000, ctx_hi, "svc_t");

        assert_eq!(fake.system(), MacSystem::Parsec);
        assert!(fake.is_active(), "the fake stands in for a real backend");
        assert_eq!(fake.object_label("/etc/shadow"), Some(secret));
        assert_eq!(fake.object_label("/etc/hosts"), None, "unlabeled path");
        assert_eq!(fake.principal_contexts(1000), vec![ctx_hi]);
        assert!(
            fake.principal_contexts(2000).is_empty(),
            "a uid with no configured contexts yields an empty set"
        );
        assert_eq!(fake.render_label(secret), "0:0:0:CCNR");
        assert_eq!(fake.render_context(ctx_hi), "svc_t");
    }

    #[test]
    fn fake_permit_table_defaults_to_deny() {
        let mut fake = FakeMacProvider::new(MacSystem::Selinux);
        let label = MacLabelId::new(3);
        let ctx = MacContextId::new(4);
        // Never set → denied (default-deny mandatory model).
        assert!(!fake.permits(ctx, label, MacAccessKind::Write));
        fake.set_permit(ctx, label, MacAccessKind::Write, true);
        assert!(fake.permits(ctx, label, MacAccessKind::Write));
        // A different access kind on the same pair is still denied.
        assert!(!fake.permits(ctx, label, MacAccessKind::Read));
    }

    #[test]
    fn core_runs_opaque_handles_through_permit_and_render_without_parsing() {
        // This exercises exactly what the composite layer does, inline, to
        // prove the core treats the handles as opaque: it takes whatever
        // `object_label`/`principal_contexts` return, feeds them straight to `permits`
        // and `render_context`, and never inspects or orders them. The two contexts
        // are deliberately non-lattice (no precedence): the principal is reachable in
        // exactly one of them, and the filter neither assumes nor needs an order.
        let mut fake = FakeMacProvider::new(MacSystem::Selinux);
        let label = MacLabelId::new(42);
        let ctx_low = MacContextId::new(10);
        let ctx_high = MacContextId::new(11);
        fake.with_label("/srv/secret", label, "secret_t")
            .with_context(1000, ctx_low, "low_t")
            .with_context(1000, ctx_high, "high_t")
            // Permitted only in the high context; blocked in the low one.
            .set_permit(ctx_high, label, MacAccessKind::Read, true)
            .set_permit(ctx_low, label, MacAccessKind::Read, false);

        let object = fake
            .object_label("/srv/secret")
            .expect("the object is labeled");
        let reachable: Vec<String> = fake
            .principal_contexts(1000)
            .into_iter()
            .filter(|ctx| fake.permits(*ctx, object, MacAccessKind::Read))
            .map(|ctx| fake.render_context(ctx))
            .collect();

        assert_eq!(
            reachable,
            vec!["high_t".to_owned()],
            "access holds only in the high context; the core selected it by permit \
             alone, without interpreting or ordering the opaque handles"
        );
    }

    #[test]
    fn opaque_ids_expose_only_the_interning_index_not_a_parse() {
        // The handles carry a backend interning index and nothing else — no way to
        // read a label's meaning out of them. `as_u32` is the raw index escape hatch,
        // distinct from the human rendering which only the provider can produce.
        let label = MacLabelId::new(99);
        let ctx = MacContextId::new(5);
        assert_eq!(label.as_u32(), 99);
        assert_eq!(ctx.as_u32(), 5);
        // Unrendered handles fall back to a synthetic token, never a parsed label.
        let fake = FakeMacProvider::new(MacSystem::Parsec);
        assert_eq!(fake.render_label(label), "label#99");
        assert_eq!(fake.render_context(ctx), "ctx#5");
    }

    #[test]
    fn null_provider_is_usable_as_a_trait_object_default() {
        // The design threads an always-present `&dyn MacProvider`; the null provider
        // is the default, and callers branch on `is_active`.
        let provider: &dyn MacProvider = &NullMacProvider;
        assert!(!provider.is_active());
        assert_eq!(provider.object_label("/anything"), None);
    }
}
