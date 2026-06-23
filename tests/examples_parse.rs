//! The shipped example + packaged TOML files must parse through the REAL
//! parsers, not just validate against the golden schemas.
//!
//! `taplo check` (configured in `taplo.toml`) validates these files against the
//! generated JSON schemas, but taplo is an external CLI that may not be present
//! in every CI/dev environment — and a schema is only an approximation of what
//! the Rust parser accepts (path validation, the `replace`/`append` invariant,
//! namespace/location matching, the role-slice `[payload]` nesting, …). These
//! tests run each shipped file through the exact parser the binary uses, so a
//! file that drifts out of the format fails `cargo test` even with no taplo.
//!
//! Covered:
//!   - `examples/declaration.toml`     → `Declaration::parse`
//!   - `examples/roles/*.toml`         → `rolestore::read_composition` (the
//!                                        real role-slice parser, `[payload]`)
//!   - `share/permissions/<layer>/**`  → `LiveCatalog::read_layer` (parse +
//!                                        `validate` + namespace/location check)

use std::path::{Path, PathBuf};

use census::catalog::{CatalogSource, LiveCatalog};
use census::declaration::Declaration;
use census::rolestore::read_composition;

/// The census crate root (`CARGO_MANIFEST_DIR`), so the tests find the shipped
/// files regardless of the working directory the runner uses.
fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

#[test]
fn example_declaration_parses_through_real_parser() {
    let path = repo("examples/declaration.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    Declaration::parse(&text).unwrap_or_else(|e| {
        panic!(
            "shipped {} no longer parses as a Declaration: {e}",
            path.display()
        )
    });
}

#[test]
fn example_role_slices_parse_through_real_parser() {
    let store = repo("examples/roles");
    let mut count = 0usize;
    for entry in std::fs::read_dir(&store)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", store.display()))
    {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let role = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("role slice has a file stem");
        // `read_composition` is the exact path the binary uses: it parses the
        // tolerant `Slice` shape and extracts the `[payload]` subset, including
        // the `PermissionRef` one-of (bare id string vs `{id, ...params}`).
        read_composition(&store, role).unwrap_or_else(|e| {
            panic!(
                "shipped role slice {} no longer parses: {e}",
                path.display()
            )
        });
        count += 1;
    }
    assert!(count > 0, "expected at least one example role slice under {}", store.display());
}

#[test]
fn packaged_catalog_layers_parse_through_real_parser() {
    let perms = repo("share/permissions");
    // The catalog parser keys off OS-target layer directories (`linux`,
    // `linux-debian-12`, …). `l10n` is a sibling localization tree, NOT a
    // permission layer, so it is deliberately excluded — feeding it to the
    // permission parser would (correctly) fail, since its files are not
    // PermissionDefs. `read_layer` runs the real per-file parse + `validate` +
    // namespace/location check for every `*.toml` in the layer.
    let catalog = LiveCatalog::new(vec![perms.clone()]);
    let mut layers = 0usize;
    let mut records = 0usize;
    for entry in std::fs::read_dir(&perms)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", perms.display()))
    {
        let path = entry.unwrap().path();
        if !path.is_dir() {
            continue;
        }
        let layer = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if layer == "l10n" {
            continue;
        }
        let defs = catalog.read_layer(layer).unwrap_or_else(|e| {
            panic!("packaged catalog layer {layer:?} no longer parses: {e}")
        });
        records += defs.len();
        layers += 1;
    }
    assert!(layers > 0, "expected at least one packaged catalog layer under {}", perms.display());
    assert!(records > 0, "expected at least one packaged permission record");
}
