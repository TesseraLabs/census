use clap::{Parser, Subcommand};
use census::coverage::SurfaceClass;

#[derive(Parser)]
#[command(name = "census", version, about = "Declarative Unix access provisioner")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
    },
    /// Catalog operations.
    Catalog {
        #[command(subcommand)]
        sub: CatalogSub,
    },
}

#[derive(Subcommand)]
enum CatalogSub {
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
}

/// The default catalog roots plus any `--catalog-dir` overrides, in precedence
/// order (lowest first). Overrides are appended so a site dir given on the CLI
/// wins over the packaged defaults.
fn catalog_roots_with_overrides(
    overrides: Vec<std::path::PathBuf>,
) -> Vec<std::path::PathBuf> {
    let mut roots = census::cli::default_catalog_roots();
    roots.extend(overrides);
    roots
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Plan {
            declaration,
            managed,
            catalog_dir,
            os_target,
        } => census::cli::run_plan(
            &declaration,
            &managed,
            catalog_roots_with_overrides(catalog_dir),
            os_target.as_deref(),
        ),
        Command::Apply {
            declaration,
            managed,
            trust_fs,
            i_understand_no_rescue,
            sessions_file,
            catalog_dir,
            os_target,
        } => census::cli::run_apply(census::cli::ApplyOpts {
            declaration: &declaration,
            managed: &managed,
            trust_fs,
            risk_acknowledged: i_understand_no_rescue,
            rollback_root: std::path::PathBuf::from("/var/lib/census/rollback"),
            trust_anchor_path: std::path::PathBuf::from(census::trust::DEFAULT_TRUST_ANCHOR),
            persist_dir: std::path::PathBuf::from(census::trust::DEFAULT_PERSIST_DIR),
            sessions_file,
            catalog_roots: catalog_roots_with_overrides(catalog_dir),
            os_target,
        }),
        Command::Doctor { declaration, managed } => {
            census::cli::run_doctor(declaration.as_deref(), &managed)
        }
        Command::Status { declaration, managed } => census::cli::run_status(
            declaration.as_deref(),
            &managed,
            std::path::Path::new(census::trust::DEFAULT_PERSIST_DIR),
        ),
        Command::Compile {
            role,
            declaration,
            catalog_dir,
            os_target,
            lint,
            json,
        } => census::cli::run_compile(
            &role,
            &declaration,
            catalog_roots_with_overrides(catalog_dir),
            os_target.as_deref(),
            lint,
            json,
        ),
        Command::Show {
            role,
            declaration,
            catalog_dir,
            os_target,
            lang,
        } => census::cli::run_show(
            &role,
            &declaration,
            catalog_roots_with_overrides(catalog_dir),
            os_target.as_deref(),
            lang.as_deref(),
        ),
        Command::Catalog { sub } => match sub {
            CatalogSub::Coverage {
                json,
                os_target,
                catalog_dir,
                roles,
                strict,
                class,
                min_coverage,
                include_low_priority,
                cache,
            } => {
                // Parse the optional --class filter up front so an unknown class is
                // a clean error before any scanning runs.
                let classes = match class {
                    Some(spec) => match census::cli::parse_classes(&spec) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("census: {e}");
                            return std::process::ExitCode::FAILURE;
                        }
                    },
                    None => Vec::<SurfaceClass>::new(),
                };
                census::cli::run_coverage(census::cli::CoverageOpts {
                    json,
                    os_target,
                    catalog_roots: catalog_roots_with_overrides(catalog_dir),
                    roles,
                    strict,
                    classes,
                    min_coverage,
                    include_low_priority,
                    cache,
                })
            }
        },
    }
}
