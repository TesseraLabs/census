#![forbid(unsafe_code)]
// The restriction-group lints (unwrap_used, expect_used, panic, indexing_slicing)
// catch production hazards but fire inside the test module below, where a panic on
// a broken fixture is the intended failure mode — exempt test code, mirroring
// lib.rs's crate-root exemption.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "test fixtures intentionally panic on malformed setup; these \
                  hazards only matter on production paths"
    )
)]

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

/// The catalog roots for a subcommand, in precedence order (lowest first).
///
/// The packaged defaults come first; the `--additional-catalog-dir` roots are
/// appended so a site dir given on the CLI wins over the defaults (later wins on
/// a permission-id collision). `--no-default-catalog-dirs` drops the packaged
/// defaults, leaving only the additional roots.
///
/// # Errors
///
/// Returns an error when the resolved list is empty — `--no-default-catalog-dirs`
/// without any `--additional-catalog-dir`. Expanding the catalog against zero
/// roots is refused fail-closed rather than silently resolving nothing.
fn catalog_roots_with_overrides(
    additional: Vec<std::path::PathBuf>,
    no_default: bool,
) -> Result<Vec<std::path::PathBuf>, &'static str> {
    let mut roots = if no_default {
        Vec::new()
    } else {
        census::cli::default_catalog_roots()
    };
    roots.extend(additional);
    if roots.is_empty() {
        return Err(
            "no catalog roots configured (--no-default-catalog-dirs given without --additional-catalog-dir)",
        );
    }
    Ok(roots)
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
            additional_catalog_dir,
            no_default_catalog_dirs,
            os_target,
            diff,
        } => {
            let catalog_roots =
                match catalog_roots_with_overrides(additional_catalog_dir, no_default_catalog_dirs)
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("census: {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                };
            census::cli::run_plan(
                &declaration,
                &managed,
                catalog_roots,
                os_target.as_deref(),
                diff,
            )
        }
        Command::Apply {
            declaration,
            managed,
            trust_fs,
            i_understand_no_rescue,
            sessions_file,
            additional_catalog_dir,
            no_default_catalog_dirs,
            os_target,
        } => {
            let catalog_roots =
                match catalog_roots_with_overrides(additional_catalog_dir, no_default_catalog_dirs)
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("census: {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                };
            census::cli::run_apply(census::cli::ApplyOpts {
                declaration: &declaration,
                managed: &managed,
                trust_fs,
                risk_acknowledged: i_understand_no_rescue,
                rollback_root: std::path::PathBuf::from("/var/lib/census/rollback"),
                trust_anchor_path: std::path::PathBuf::from(census::trust::DEFAULT_TRUST_ANCHOR),
                persist_dir: std::path::PathBuf::from(census::trust::DEFAULT_PERSIST_DIR),
                sessions_file,
                catalog_roots,
                os_target,
            })
        }
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
            additional_catalog_dir,
            no_default_catalog_dirs,
            os_target,
            lint,
            json,
        } => {
            let catalog_roots =
                match catalog_roots_with_overrides(additional_catalog_dir, no_default_catalog_dirs)
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("census: {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                };
            census::cli::run_compile(
                &role,
                &declaration,
                catalog_roots,
                os_target.as_deref(),
                lint,
                json,
            )
        }
        Command::Show {
            role,
            declaration,
            additional_catalog_dir,
            no_default_catalog_dirs,
            os_target,
            lang,
            framework,
            framework_dir,
            format,
        } => {
            let catalog_roots =
                match catalog_roots_with_overrides(additional_catalog_dir, no_default_catalog_dirs)
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("census: {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                };
            census::cli::run_show(census::cli::ShowOpts {
                role: &role,
                declaration: &declaration,
                catalog_roots,
                os_target: os_target.as_deref(),
                lang: lang.as_deref(),
                framework: framework.as_deref(),
                framework_roots: framework_roots_with_overrides(framework_dir),
                format: format.as_deref(),
            })
        }
        Command::Catalog { sub } => match sub {
            CatalogSub::Coverage {
                json,
                os_target,
                additional_catalog_dir,
                no_default_catalog_dirs,
                roles,
                declaration,
                strict,
                class,
                min_coverage,
                include_low_priority,
                cache,
            } => {
                let catalog_roots = match catalog_roots_with_overrides(
                    additional_catalog_dir,
                    no_default_catalog_dirs,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("census: {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                };
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
                    catalog_roots,
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
                additional_catalog_dir,
                no_default_catalog_dirs,
                declaration,
            } => {
                let catalog_roots = match catalog_roots_with_overrides(
                    additional_catalog_dir,
                    no_default_catalog_dirs,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("census: {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                };
                census::cli::run_which_grants(census::cli::WhichGrantsOpts {
                    arg,
                    json,
                    os_target,
                    catalog_roots,
                    declaration,
                })
            }
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
                lang,
                format,
            } => census::cli::run_framework_show(
                &fw,
                framework_roots_with_overrides(framework_dir),
                os_target,
                lang,
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
                lang,
                format,
            } => census::cli::run_framework_risk(
                &fw,
                framework_roots_with_overrides(framework_dir),
                os_target,
                lang,
                format.as_deref() == Some("json"),
            ),
            FrameworkSub::Lint {
                framework_dir,
                additional_catalog_dir,
                no_default_catalog_dirs,
                os_target,
                format,
            } => {
                let catalog_roots = match catalog_roots_with_overrides(
                    additional_catalog_dir,
                    no_default_catalog_dirs,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("census: {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                };
                census::cli::run_framework_lint(
                    framework_roots_with_overrides(framework_dir),
                    catalog_roots,
                    os_target,
                    format.as_deref() == Some("json"),
                )
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::catalog_roots_with_overrides;
    use std::path::PathBuf;

    #[test]
    fn defaults_used_when_no_flags() {
        let roots = catalog_roots_with_overrides(Vec::new(), false)
            .expect("the packaged defaults are never empty");
        assert_eq!(roots, census::cli::default_catalog_roots());
    }

    #[test]
    fn additional_roots_appended_after_defaults() {
        let extra = PathBuf::from("/srv/site-permissions");
        let roots = catalog_roots_with_overrides(vec![extra.clone()], false)
            .expect("defaults plus an additional root are never empty");
        let mut expected = census::cli::default_catalog_roots();
        expected.push(extra);
        // The additional root must land last so it wins a permission-id collision.
        assert_eq!(roots, expected);
    }

    #[test]
    fn no_default_isolates_to_additional_roots() {
        let extra = PathBuf::from("/srv/site-permissions");
        let roots = catalog_roots_with_overrides(vec![extra.clone()], true)
            .expect("a single additional root is enough to resolve");
        assert_eq!(roots, vec![extra]);
    }

    #[test]
    fn no_default_without_additional_is_refused() {
        let err = catalog_roots_with_overrides(Vec::new(), true)
            .expect_err("zero roots must fail closed, never resolve into the void");
        assert!(
            err.contains("no catalog roots configured"),
            "the error must name the empty-roots failure: {err}"
        );
    }
}
