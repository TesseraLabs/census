//! Shared, leaf-level formatting helpers for the CLI renderers.
//!
//! These are the small pure functions every `render_*` helper across the CLI
//! submodules reuses: the JSON string escaper, the advisory risk label, the
//! access/shape/backend tokens, and the bundle-`via` provenance suffix. They
//! have no dependencies on other CLI items, so they live here and are shared as
//! `pub(crate)` to keep the rule (and the exact output bytes) in one place.

use crate::catalog::{self, Risk};

/// The display label for a risk class. Advisory only — never gates anything.
pub(crate) fn risk_label(risk: Option<Risk>) -> &'static str {
    match risk {
        Some(Risk::Contained) => "contained",
        Some(Risk::EscalationCapable) => "escalation-capable",
        // A leaf permission whose catalog record set no `risk` is shown as
        // unknown rather than silently assumed contained (honest labelling).
        None => "unknown",
    }
}

/// The access token (`ro`/`rw`) for display.
pub(crate) fn access_token(access: catalog::Access) -> &'static str {
    match access {
        catalog::Access::Ro => "ro",
        catalog::Access::Rw => "rw",
    }
}

/// Describe which backend + guarantee resolves a grant of this shape in the open
/// build. A directory grant is enforced rewrite-proof by the open `AclBackend`; a
/// File or Pattern grant has no open backend and would REQUIRE a capability-gated
/// one — stated honestly so the view never implies the open build can enforce it.
/// Mirrors the routing in [`crate::fileaccess`] (Dir→AclBackend) and the
/// capability-gating contract (File/Pattern → capable backend required).
pub(crate) fn backend_for_shape(shape: catalog::Shape) -> &'static str {
    match shape {
        catalog::Shape::Dir => "AclBackend (dir, rewrite-proof)",
        catalog::Shape::File => "requires per-file-capable backend",
        catalog::Shape::Pattern => "requires pattern-capable backend",
    }
}

/// Provenance suffix for a tree primitive: ` (via <member>)` when the primitive
/// arrived through a bundle member distinct from the named permission.
pub(crate) fn via_suffix(permission: &str, via: &Option<String>) -> String {
    match via {
        Some(m) if m != permission => format!(" (via {m})"),
        _ => String::new(),
    }
}

/// Escape a string as a JSON string literal (minimal: the structural chars and
/// control chars that would break the document). Catalog/role values are
/// already constrained, but escaping keeps the output well-formed regardless.
pub(crate) fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // U+2028 (line separator) and U+2029 (paragraph separator) are valid
            // JSON but are line terminators in ECMAScript: left literal, they
            // break any consumer that embeds this output in a JS/JSONP string.
            // Escape them so `compile --json` is safe to splice into JS.
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
