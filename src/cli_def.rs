//! Public clap CLI definitions.
//!
//! These structs are the machine-readable surface of the `census` binary. They
//! live in the library (not `src/main.rs`) so the interface-contract test can
//! introspect the `clap::Command` tree via [`clap::CommandFactory`] — a binary
//! crate's items are private to that crate and invisible to integration tests.
//! `main.rs` re-exports these and keeps the dispatch (`match`) logic; the
//! definitions here are behaviour-free (no `run_*` wiring), so the contract test
//! sees exactly what the binary parses.

use clap::{Parser, Subcommand};

/// Top-level CLI: `census <command>`.
#[derive(Debug, Parser)]
#[command(
    name = "census",
    version,
    about = "Declarative Unix access provisioner"
)]
pub struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// The top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show the create/update/delete plan without mutating anything.
    Plan {
        /// Path to the declaration TOML.
        #[arg(long, default_value = "/etc/census/declaration.toml")]
        declaration: std::path::PathBuf,
        /// Path to the managed registry (current Census-managed state).
        #[arg(long, default_value = "/var/lib/census/managed.toml")]
        managed: std::path::PathBuf,
        /// Extra catalog root for permission expansion (repeatable; appended to
        /// the defaults in precedence order — later wins).
        #[arg(long = "catalog-dir")]
        catalog_dir: Vec<std::path::PathBuf>,
        /// Override the OS target as `family-distro-version` (e.g.
        /// `linux-debian-12`); autodetected from /etc/os-release if absent.
        #[arg(long)]
        os_target: Option<String>,
    },
    /// Apply the plan: materialize accounts via shadow-utils (requires root).
    Apply {
        /// Path to the declaration TOML.
        #[arg(long, default_value = "/etc/census/declaration.toml")]
        declaration: std::path::PathBuf,
        /// Path to the managed registry (current Census-managed state).
        #[arg(long, default_value = "/var/lib/census/managed.toml")]
        managed: std::path::PathBuf,
        /// Trust the declaration based on filesystem integrity (standalone).
        #[arg(long)]
        trust_fs: bool,
        /// Proceed even if no rescue/break-glass login path is configured.
        #[arg(long)]
        i_understand_no_rescue: bool,
        /// Path to Tessera's live-session registry. A delete over an account with
        /// a live session is deferred (§12). Absent file → no live sessions.
        #[arg(long, default_value = "/run/tessera/sessions.json")]
        sessions_file: std::path::PathBuf,
        /// Extra catalog root for permission expansion (repeatable; appended to
        /// the defaults in precedence order — later wins).
        #[arg(long = "catalog-dir")]
        catalog_dir: Vec<std::path::PathBuf>,
        /// Override the OS target as `family-distro-version` (e.g.
        /// `linux-debian-12`); autodetected from /etc/os-release if absent.
        #[arg(long)]
        os_target: Option<String>,
    },
    /// Read-only diagnostics: verify the §4/§7/§8 invariants hold. Non-zero exit
    /// on any error-severity finding (for monitoring/CI).
    Doctor {
        /// Optional declaration TOML; enables the drift check when present.
        #[arg(long)]
        declaration: Option<std::path::PathBuf>,
        /// Path to the managed registry (current Census-managed state).
        #[arg(long, default_value = "/var/lib/census/managed.toml")]
        managed: std::path::PathBuf,
    },
    /// Read-only state summary: managed accounts, persisted version, drift.
    /// Always exits 0.
    Status {
        /// Optional declaration TOML; enables the drift summary when present.
        #[arg(long)]
        declaration: Option<std::path::PathBuf>,
        /// Path to the managed registry (current Census-managed state).
        #[arg(long, default_value = "/var/lib/census/managed.toml")]
        managed: std::path::PathBuf,
    },
    /// Read-only: expand a role into its flat compiled primitives with
    /// provenance. With --lint, exits non-zero on any lint ERROR (for CI).
    Compile {
        /// The role id to compile.
        role: String,
        /// Path to the declaration TOML.
        #[arg(long, default_value = "/etc/census/declaration.toml")]
        declaration: std::path::PathBuf,
        /// Extra catalog root for permission expansion (repeatable; appended to
        /// the defaults in precedence order — later wins).
        #[arg(long = "catalog-dir")]
        catalog_dir: Vec<std::path::PathBuf>,
        /// Override the OS target as `family-distro-version` (e.g.
        /// `linux-debian-12`); autodetected from /etc/os-release if absent.
        #[arg(long)]
        os_target: Option<String>,
        /// Run catalog/role lint; exit non-zero on any lint ERROR.
        #[arg(long)]
        lint: bool,
        /// Emit machine-readable JSON instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Read-only: render a role as a tree of permissions/bundles → primitives
    /// with localized descriptions and advisory risk classes.
    Show {
        /// The role id to show.
        role: String,
        /// Path to the declaration TOML.
        #[arg(long, default_value = "/etc/census/declaration.toml")]
        declaration: std::path::PathBuf,
        /// Extra catalog root for permission expansion (repeatable; appended to
        /// the defaults in precedence order — later wins).
        #[arg(long = "catalog-dir")]
        catalog_dir: Vec<std::path::PathBuf>,
        /// Override the OS target as `family-distro-version` (e.g.
        /// `linux-debian-12`); autodetected from /etc/os-release if absent.
        #[arg(long)]
        os_target: Option<String>,
        /// Display language (e.g. `ru`); falls back to LC_MESSAGES, LANG, en.
        #[arg(long)]
        lang: Option<String>,
        /// Cross-reference a compliance framework (`fw` id or `all`): print the
        /// control ids each permission satisfies plus mapping provenance.
        #[arg(long)]
        framework: Option<String>,
        /// Extra framework root (repeatable; appended to the default framework
        /// roots). For tests / site overlays.
        #[arg(long = "framework-dir")]
        framework_dir: Vec<std::path::PathBuf>,
        /// Output format: `human` (default) or `json`.
        #[arg(long)]
        format: Option<String>,
    },
    /// Catalog operations.
    Catalog {
        /// The catalog subcommand.
        #[command(subcommand)]
        sub: CatalogSub,
    },
    /// Framework cross-reference operations (read-only compliance metadata).
    Framework {
        /// The framework subcommand.
        #[command(subcommand)]
        sub: FrameworkSub,
    },
}

/// Framework cross-reference subcommands.
#[derive(Debug, Subcommand)]
pub enum FrameworkSub {
    /// List installed frameworks with their version and advertised capabilities.
    List {
        /// Extra framework root (repeatable; appended to the defaults).
        #[arg(long = "framework-dir")]
        framework_dir: Vec<std::path::PathBuf>,
        /// Override the OS target as `family-distro-version`; autodetected if
        /// absent (used to resolve os-layered frameworks).
        #[arg(long)]
        os_target: Option<String>,
        /// Output format: `human` (default) or `json`.
        #[arg(long)]
        format: Option<String>,
    },
    /// Show one framework's controls plus coverage statistics.
    Show {
        /// The framework id to show.
        fw: String,
        /// Extra framework root (repeatable; appended to the defaults).
        #[arg(long = "framework-dir")]
        framework_dir: Vec<std::path::PathBuf>,
        /// Override the OS target as `family-distro-version`; autodetected if
        /// absent (used to resolve os-layered frameworks).
        #[arg(long)]
        os_target: Option<String>,
        /// Display language for control titles (e.g. `ru`); falls back to
        /// LC_MESSAGES, LANG, then en, then the bare control id.
        #[arg(long)]
        lang: Option<String>,
        /// Output format: `human` (default) or `json`.
        #[arg(long)]
        format: Option<String>,
    },
    /// Gap oracle: report a framework's owned controls that no mapping covers.
    Coverage {
        /// The framework id to analyze.
        fw: String,
        /// Extra framework root (repeatable; appended to the defaults).
        #[arg(long = "framework-dir")]
        framework_dir: Vec<std::path::PathBuf>,
        /// Override the OS target as `family-distro-version`; autodetected if
        /// absent (used to resolve os-layered frameworks).
        #[arg(long)]
        os_target: Option<String>,
        /// Output format: `human` (default) or `json`.
        #[arg(long)]
        format: Option<String>,
    },
    /// Controls under risk: report controls a mapping undermines (risk links).
    Risk {
        /// The framework id to analyze.
        fw: String,
        /// Extra framework root (repeatable; appended to the defaults).
        #[arg(long = "framework-dir")]
        framework_dir: Vec<std::path::PathBuf>,
        /// Override the OS target as `family-distro-version`; autodetected if
        /// absent (used to resolve os-layered frameworks).
        #[arg(long)]
        os_target: Option<String>,
        /// Display language for control titles (e.g. `ru`); falls back to
        /// LC_MESSAGES, LANG, then en, then the bare control id.
        #[arg(long)]
        lang: Option<String>,
        /// Output format: `human` (default) or `json`.
        #[arg(long)]
        format: Option<String>,
    },
    /// Lint the framework cross-reference layer for integrity problems.
    Lint {
        /// Extra framework root (repeatable; appended to the defaults).
        #[arg(long = "framework-dir")]
        framework_dir: Vec<std::path::PathBuf>,
        /// Extra catalog root (repeatable; appended to the defaults) — used to
        /// detect orphaned mappings (permission-id absent from the catalog).
        #[arg(long = "catalog-dir")]
        catalog_dir: Vec<std::path::PathBuf>,
        /// Override the OS target as `family-distro-version`; autodetected if absent.
        #[arg(long)]
        os_target: Option<String>,
        /// Output format: `human` (default) or `json`.
        #[arg(long)]
        format: Option<String>,
    },
}

/// Catalog subcommands.
#[derive(Debug, Subcommand)]
pub enum CatalogSub {
    /// Read-only audit: enumerate the device's live privileged surface and report
    /// what the installed catalog does NOT cover. Never mutates or runs binaries.
    Coverage {
        /// Emit machine-readable JSON instead of the human view.
        #[arg(long)]
        json: bool,
        /// Override the OS target as `family-distro-version` (e.g.
        /// `linux-debian-12`); autodetected from /etc/os-release if absent.
        #[arg(long)]
        os_target: Option<String>,
        /// Extra catalog root for permission expansion (repeatable; appended to
        /// the defaults in precedence order — later wins).
        #[arg(long = "catalog-dir")]
        catalog_dir: Vec<std::path::PathBuf>,
        /// Role-store dir whose roles are resolved into concrete instances so
        /// parametrized permissions contribute named units/paths/groups.
        #[arg(long)]
        roles: Option<std::path::PathBuf>,
        /// Declaration whose `[[role_group]]` bindings are resolved so a `group`
        /// object with a bound grant counts as covered. Optional; without it
        /// coverage sees only membership-covered groups.
        #[arg(long)]
        declaration: Option<std::path::PathBuf>,
        /// A parametrized record with no role instance does NOT count as covering.
        #[arg(long)]
        strict: bool,
        /// Restrict to a comma-separated subset of classes
        /// (sudo_bin,config,unit,group,capfile,setuid). Default: all.
        #[arg(long)]
        class: Option<String>,
        /// Exit non-zero (CI-gate) when overall coverage is below this percent.
        #[arg(long)]
        min_coverage: Option<f64>,
        /// Include low-priority objects in the human report.
        #[arg(long)]
        include_low_priority: bool,
        /// Accept (no-op) — surface caching is not yet implemented.
        #[arg(long)]
        cache: bool,
    },
    /// Read-only reverse lookup: given an absolute path or command, report which
    /// catalog permissions grant access to it and how. Always exits 0 (a query).
    WhichGrants {
        /// The absolute path (file or binary) or command to look up.
        arg: String,
        /// Emit machine-readable JSON instead of the human view.
        #[arg(long)]
        json: bool,
        /// Override the OS target as `family-distro-version` (e.g.
        /// `linux-debian-12`); autodetected from /etc/os-release if absent.
        #[arg(long)]
        os_target: Option<String>,
        /// Extra catalog root for permission expansion (repeatable; appended to
        /// the defaults in precedence order — later wins).
        #[arg(long = "catalog-dir")]
        catalog_dir: Vec<std::path::PathBuf>,
        /// Declaration whose `[[role_group]]` bindings are resolved so group
        /// grants (`via %group sudoers` / `via g:group ACL`) appear in the
        /// lookup. Optional; without it only account grants are reported.
        #[arg(long)]
        declaration: Option<std::path::PathBuf>,
    },
}
