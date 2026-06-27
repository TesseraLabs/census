//! Census core: declaration → role-store composition → plan → apply.
#![forbid(unsafe_code)]
// Census has zero unsafe code; the forbid above makes that a compile-time
// contract. The restriction-group lints below (unwrap_used, expect_used, panic,
// indexing_slicing) catch real production hazards but fire pervasively inside
// test modules where a panic on a broken fixture is the intended failure mode —
// exempt test code so production paths stay linted without test noise.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::float_cmp,
        reason = "test fixtures intentionally panic on malformed setup, and \
                  coverage-percentage assertions compare deterministic exact \
                  values; these hazards only matter on production paths"
    )
)]

// --- Public API surface (curated) ---------------------------------------
//
// Census is consumed two ways: as the `census` binary (`src/main.rs` drives the
// `cli` module) and as a library by the interface-contract / integration tests
// (which read the config + state types and the CLI definition). Only the modules
// those consumers need are `pub`; everything else is `pub(crate)` plumbing so it
// is not semver-locked.
//
// `cli` is the binary's entry point and threads many of the domain types through
// its public render/run functions, so the modules whose types appear in those
// signatures (`plan`, `doctor`, `l10n`, `model`, `fileaccess`, `coverage`,
// `framework`, `trust`) stay `pub` even though most callers reach them only
// through `cli`. The genuinely external config/state contract types are
// re-exported at the crate root below for discoverability.

/// Permission catalog: records, OS-target layering, parametrized resolve.
pub mod catalog;
/// Command/flag tree (`clap`) — the CLI contract the binary and the golden tests
/// read.
pub mod cli_def;
/// Coverage / surface-class analysis (used by the binary and `cli`).
pub mod coverage;
/// Declaration parsing and validation (the operator-authored input).
pub mod declaration;
/// Doctor (drift) report types surfaced by `cli`.
pub mod doctor;
/// File-access enforcement SPI + the open ACL backend.
pub mod fileaccess;
/// Compliance-framework manifests and control cross-reference.
pub mod framework;
/// Localization source trait surfaced by `cli`'s tree renderer.
pub mod l10n;
/// Resolve layer: declaration + role-store → target accounts/groups.
pub mod model;
/// Plan diff types surfaced by `cli`'s render functions.
pub mod plan;
/// Role-store slice reading (the Tessera composition subset Census consumes).
pub mod rolestore;
/// Managed-registry state types (`managed.toml`).
pub mod state;
/// Trust verification (signed declarations, anti-rollback) and its public consts.
pub mod trust;

/// CLI command implementations (the binary's entry point).
pub mod cli;

// --- Internal plumbing (not part of the public API) ----------------------
pub(crate) mod apply;
pub(crate) mod backup;
pub(crate) mod fsutil;
pub(crate) mod inspect;
pub(crate) mod lockout;
pub(crate) mod mutate;
pub(crate) mod sessions;
pub(crate) mod status;
pub(crate) mod sudoers;

// --- Curated root re-exports of the primary public types -----------------
// `#[doc(inline)]` so they render on the crate root rather than only deep in
// their modules (M-DOC-INLINE). These are the types external consumers most
// often name.
#[doc(inline)]
pub use crate::catalog::{LiveCatalog, OsTarget, PermissionDef};
#[doc(inline)]
pub use crate::cli_def::Cli;
#[doc(inline)]
pub use crate::declaration::Declaration;
#[doc(inline)]
pub use crate::rolestore::read_composition;
#[doc(inline)]
pub use crate::state::{ManagedAccount, ManagedGroup, RegistryFile, RegistryState};
