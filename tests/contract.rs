//! Interface-contract golden tests.
//!
//! The `census` CLI surface (command/flag tree) and its TOML formats are a
//! public contract: external scripts, CI pipelines, and deployed config files
//! depend on them. An accidental rename, a dropped field, a changed default, or
//! a tightened type silently breaks them. These tests freeze the surface as
//! committed golden artifacts under `census/contract/` and fail on any drift.
//!
//! Source of truth is the code: each test regenerates the artifact from the
//! live `clap::Command` / `schemars` schema and asserts byte-equality against
//! the committed golden. To intentionally change the surface, run
//! `UPDATE_CONTRACT=1 cargo test` to rewrite the goldens, review the diff, and
//! update the contract design spec (`specs/2026-06-23-census-interface-contract-design.md`).
//!
//! See that spec, §6, for the enforcement design.

use std::path::{Path, PathBuf};

use census::catalog::PermissionDef;
use census::cli_def::Cli;
use census::declaration::Declaration;
use census::framework::{ControlDef, FrameworkManifest};
use census::rolestore::Slice as RoleSlice;
use census::state::RegistryFile;

use clap::CommandFactory;
use schemars::schema_for;

/// Absolute path to a committed golden file under `census/contract/`.
fn contract_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("contract").join(name)
}

/// Compare `actual` to the committed golden `name`, or rewrite it when
/// `UPDATE_CONTRACT` is set. On mismatch, fail with a directive to regenerate.
fn assert_or_update(name: &str, actual: &str) {
    let path = contract_path(name);
    if std::env::var_os("UPDATE_CONTRACT").is_some() {
        std::fs::write(&path, actual)
            .unwrap_or_else(|e| panic!("cannot write golden {}: {e}", path.display()));
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read golden {} ({e}); generate it with `UPDATE_CONTRACT=1 cargo test`",
            path.display()
        )
    });
    assert_eq!(
        actual,
        expected,
        "\ncontract drift in {name}: the generated artifact no longer matches the committed golden.\n\
         If this change to the interface is intentional, run `UPDATE_CONTRACT=1 cargo test`,\n\
         review `git diff census/contract/`, and update the contract spec\n\
         (specs/2026-06-23-census-interface-contract-design.md), marking the change major/minor (§5).\n",
    );
}

/// Pretty-print a schemars schema to the exact JSON form committed as golden.
fn schema_json<T: schemars::JsonSchema>() -> String {
    serde_json::to_string_pretty(&schema_for!(T)).expect("schema serializes")
}

// --- TOML schema goldens (§6.1) ---

#[test]
fn declaration_schema_matches_golden() {
    assert_or_update("declaration.schema.json", &schema_json::<Declaration>());
}

#[test]
fn role_store_schema_matches_golden() {
    // `Slice` is the type Census actually deserializes from a role slice: the
    // consumed fields (groups/sudo_role/limits/permissions) live UNDER a
    // `[payload]` table, with role-wide keys at the top level. Schematizing the
    // real parsed type (not the assembled `RoleComposition` view) keeps the
    // golden — and the taplo binding on examples/roles/*.toml — describing the
    // on-disk format. Tolerant by contract (additionalProperties not false), so
    // foreign adapter fields are accepted — §4.2.
    assert_or_update("role-store.schema.json", &schema_json::<RoleSlice>());
}

#[test]
fn catalog_permission_schema_matches_golden() {
    assert_or_update(
        "catalog-permission.schema.json",
        &schema_json::<PermissionDef>(),
    );
}

#[test]
fn framework_schema_matches_golden() {
    // The framework format spans two files; the manifest is the root schema and
    // ControlDef is referenced as a definition within it via the wrapper below.
    assert_or_update("framework.schema.json", &framework_schema_json());
}

#[test]
fn managed_registry_schema_matches_golden() {
    assert_or_update(
        "managed-registry.schema.json",
        &schema_json::<RegistryFile>(),
    );
}

/// Combined schema for the framework format: the manifest plus the control
/// definition. `manifest.toml` and `controls.toml` are separate files, so a
/// single root struct does not exist; the golden wraps both under one document
/// so a change to either surfaces as drift.
fn framework_schema_json() -> String {
    let manifest = schema_for!(FrameworkManifest);
    let control = schema_for!(ControlDef);
    let combined = serde_json::json!({
        "manifest": manifest,
        "control": control,
    });
    serde_json::to_string_pretty(&combined).expect("framework schema serializes")
}

// --- CLI contract golden (§6.2) ---

/// A normalized argument: the structural facts that form the contract. Help and
/// about text are deliberately excluded — they are not contract (spec §1.2).
#[derive(serde::Serialize)]
struct ArgModel {
    id: String,
    long: Option<String>,
    takes_value: bool,
    required: bool,
    default: Option<String>,
    repeatable: bool,
    num_args: Option<String>,
}

/// A normalized command node: name, whether it has about text (presence only,
/// not the text), its arguments, and its subcommands — sorted deterministically.
#[derive(serde::Serialize)]
struct CommandModel {
    name: String,
    about_present: bool,
    subcommands: Vec<CommandModel>,
    args: Vec<ArgModel>,
}

/// Build the normalized model of a `clap::Command` tree. Recurses into
/// subcommands; sorts args by id and subcommands by name so the output is
/// deterministic regardless of declaration order.
fn model_command(cmd: &clap::Command) -> CommandModel {
    let mut args: Vec<ArgModel> = cmd
        .get_arguments()
        .filter(|a| a.get_id() != "help" && a.get_id() != "version")
        .map(model_arg)
        .collect();
    args.sort_by(|a, b| a.id.cmp(&b.id));

    let mut subcommands: Vec<CommandModel> =
        cmd.get_subcommands().map(model_command).collect();
    subcommands.sort_by(|a, b| a.name.cmp(&b.name));

    CommandModel {
        name: cmd.get_name().to_string(),
        about_present: cmd.get_about().is_some(),
        subcommands,
        args,
    }
}

/// Project a `clap::Arg` to the structural facts that form the contract.
fn model_arg(arg: &clap::Arg) -> ArgModel {
    let num_args = arg.get_num_args().map(|n| format!("{n}"));
    let default = {
        let defaults = arg.get_default_values();
        if defaults.is_empty() {
            None
        } else {
            Some(
                defaults
                    .iter()
                    .map(|v| v.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(","),
            )
        }
    };
    ArgModel {
        id: arg.get_id().to_string(),
        long: arg.get_long().map(|s| s.to_string()),
        takes_value: matches!(
            arg.get_action(),
            clap::ArgAction::Set | clap::ArgAction::Append
        ),
        required: arg.is_required_set(),
        default,
        repeatable: matches!(arg.get_action(), clap::ArgAction::Append),
        num_args,
    }
}

#[test]
fn cli_contract_matches_golden() {
    let cmd = Cli::command();
    let model = model_command(&cmd);
    let json = serde_json::to_string_pretty(&model).expect("cli model serializes");
    assert_or_update("cli.json", &json);
}

// --- Contract version (§7) ---

/// The committed contract version string. A major surface change (§5) bumps it.
const CONTRACT_VERSION: &str = "census-interface v0";

#[test]
fn contract_version_matches() {
    let path = contract_path("VERSION");
    let actual = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    assert_eq!(
        actual.trim_end_matches('\n'),
        CONTRACT_VERSION,
        "contract/VERSION must equal {CONTRACT_VERSION:?}"
    );
}
