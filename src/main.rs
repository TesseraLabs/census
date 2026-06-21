use clap::{Parser, Subcommand};

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
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Plan { declaration, managed } => census::cli::run_plan(&declaration, &managed),
        Command::Apply {
            declaration,
            managed,
            trust_fs,
            i_understand_no_rescue,
            sessions_file,
        } => census::cli::run_apply(census::cli::ApplyOpts {
            declaration: &declaration,
            managed: &managed,
            trust_fs,
            risk_acknowledged: i_understand_no_rescue,
            rollback_root: std::path::PathBuf::from("/var/lib/census/rollback"),
            trust_anchor_path: std::path::PathBuf::from(census::trust::DEFAULT_TRUST_ANCHOR),
            persist_dir: std::path::PathBuf::from(census::trust::DEFAULT_PERSIST_DIR),
            sessions_file,
        }),
        Command::Doctor { declaration, managed } => {
            census::cli::run_doctor(declaration.as_deref(), &managed)
        }
        Command::Status { declaration, managed } => census::cli::run_status(
            declaration.as_deref(),
            &managed,
            std::path::Path::new(census::trust::DEFAULT_PERSIST_DIR),
        ),
    }
}
