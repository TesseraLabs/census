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
        } => census::cli::run_apply(census::cli::ApplyOpts {
            declaration: &declaration,
            managed: &managed,
            trust_fs,
            risk_acknowledged: i_understand_no_rescue,
            rollback_root: std::path::PathBuf::from("/var/lib/census/rollback"),
        }),
    }
}
