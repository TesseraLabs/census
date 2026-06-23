#![forbid(unsafe_code)]

use std::io::IsTerminal;

use census::cli_def::{CatalogSub, Cli, Command, FrameworkSub};
use census::coverage::SurfaceClass;
use clap::Parser;

/// Install the process-wide `tracing` subscriber. Diagnostics go to STDERR so
/// they never contaminate the machine-readable STDOUT (`--json` output, the
/// plan/coverage renders) or the program's exit code. The filter reads
/// `CENSUS_LOG` first, then `RUST_LOG`, defaulting to `warn`; ANSI colour is
/// enabled only when stderr is a terminal. `try_init` is used so a second call
/// (e.g. from a test harness in the same process) is a no-op rather than a panic.
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("CENSUS_LOG")
        .or_else(|_| tracing_subscriber::EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_env_filter(filter)
        .try_init();
}

/// The default catalog roots plus any `--catalog-dir` overrides, in precedence
/// order (lowest first). Overrides are appended so a site dir given on the CLI
/// wins over the packaged defaults.
fn catalog_roots_with_overrides(overrides: Vec<std::path::PathBuf>) -> Vec<std::path::PathBuf> {
    let mut roots = census::cli::default_catalog_roots();
    roots.extend(overrides);
    roots
}

/// The default framework roots plus any `--framework-dir` overrides, in
/// precedence order (lowest first). Overrides are appended so a dir given on the
/// CLI (or a test tree) wins over the packaged defaults — paralleling
/// [`catalog_roots_with_overrides`].
fn framework_roots_with_overrides(overrides: Vec<std::path::PathBuf>) -> Vec<std::path::PathBuf> {
    let mut roots = census::framework::default_framework_roots();
    roots.extend(overrides);
    roots
}

fn main() -> std::process::ExitCode {
    init_tracing();
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
        Command::Doctor {
            declaration,
            managed,
        } => census::cli::run_doctor(declaration.as_deref(), &managed),
        Command::Status {
            declaration,
            managed,
        } => census::cli::run_status(
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
            framework,
            framework_dir,
            format,
        } => census::cli::run_show(census::cli::ShowOpts {
            role: &role,
            declaration: &declaration,
            catalog_roots: catalog_roots_with_overrides(catalog_dir),
            os_target: os_target.as_deref(),
            lang: lang.as_deref(),
            framework: framework.as_deref(),
            framework_roots: framework_roots_with_overrides(framework_dir),
            format: format.as_deref(),
        }),
        Command::Catalog { sub } => match sub {
            CatalogSub::Coverage {
                json,
                os_target,
                catalog_dir,
                roles,
                declaration,
                strict,
                class,
                min_coverage,
                include_low_priority,
                cache,
            } => {
                // Validate --min-coverage up front. The gate compares
                // `overall_pct < threshold`; a non-finite threshold (NaN/inf) or
                // one outside 0..=100 would make that comparison meaningless and
                // could let a CI coverage gate silently pass (`x < NaN` is always
                // false). Reject it before any scanning runs. This is a runtime
                // check rather than a clap value_parser so the CLI help golden
                // stays byte-stable.
                if let Some(m) = min_coverage {
                    if !m.is_finite() || !(0.0..=100.0).contains(&m) {
                        eprintln!(
                            "census: --min-coverage must be a finite percentage in 0..=100, got {m}"
                        );
                        return std::process::ExitCode::FAILURE;
                    }
                }
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
                    declaration,
                    strict,
                    classes,
                    min_coverage,
                    include_low_priority,
                    cache,
                })
            }
            CatalogSub::WhichGrants {
                arg,
                json,
                os_target,
                catalog_dir,
                declaration,
            } => census::cli::run_which_grants(census::cli::WhichGrantsOpts {
                arg,
                json,
                os_target,
                catalog_roots: catalog_roots_with_overrides(catalog_dir),
                declaration,
            }),
        },
        Command::Framework { sub } => match sub {
            FrameworkSub::List {
                framework_dir,
                os_target,
                format,
            } => census::cli::run_framework_list(
                framework_roots_with_overrides(framework_dir),
                os_target,
                format.as_deref() == Some("json"),
            ),
            FrameworkSub::Show {
                fw,
                framework_dir,
                os_target,
                format,
            } => census::cli::run_framework_show(
                &fw,
                framework_roots_with_overrides(framework_dir),
                os_target,
                format.as_deref() == Some("json"),
            ),
            FrameworkSub::Coverage {
                fw,
                framework_dir,
                os_target,
                format,
            } => census::cli::run_framework_coverage(
                &fw,
                framework_roots_with_overrides(framework_dir),
                os_target,
                format.as_deref() == Some("json"),
            ),
            FrameworkSub::Risk {
                fw,
                framework_dir,
                os_target,
                format,
            } => census::cli::run_framework_risk(
                &fw,
                framework_roots_with_overrides(framework_dir),
                os_target,
                format.as_deref() == Some("json"),
            ),
            FrameworkSub::Lint {
                framework_dir,
                catalog_dir,
                os_target,
                format,
            } => census::cli::run_framework_lint(
                framework_roots_with_overrides(framework_dir),
                catalog_roots_with_overrides(catalog_dir),
                os_target,
                format.as_deref() == Some("json"),
            ),
        },
    }
}
