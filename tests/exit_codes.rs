//! Behavioral tests for the contract exit codes (spec §3, enforced per §6.3).
//!
//! `clap` introspection (see `contract.rs`) freezes the command/flag tree but
//! cannot model process exit codes — those are a separate part of the contract.
//! These tests invoke the built binary and assert the codes external callers and
//! CI gates depend on:
//!   - `status` always exits 0 (a read-only summary, never a gate);
//!   - `catalog which-grants` always exits 0 (a query — "no grants" is success);
//!   - `catalog coverage --min-coverage` exits non-zero on a coverage shortfall.
//!
//! The `apply` exit-3 path (partial apply: deletes deferred due to a live
//! session, §3.2) is NOT exercised here: it requires root and real shadow-utils
//! mutation, infeasible in a unit/integration environment. The exit-code mapping
//! is unit-tested directly in `cli.rs` (`apply_exit_code_maps_deferrals`).

use std::io::Write;
use std::process::Command;

fn write(path: &std::path::Path, body: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
}

#[test]
fn status_always_exits_zero_even_without_managed() {
    let tmp = tempfile::tempdir().unwrap();
    let managed = tmp.path().join("managed.toml"); // absent on purpose

    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args(["status", "--managed"])
        .arg(&managed)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "status must always exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn which_grants_always_exits_zero_on_no_match() {
    let tmp = tempfile::tempdir().unwrap();
    // An empty catalog root: nothing grants the queried path, but a query that
    // finds no grants is still a successful query (exit 0).
    let catalog_root = tmp.path().join("permissions");
    std::fs::create_dir_all(catalog_root.join("linux")).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args(["catalog", "which-grants", "/usr/sbin/ip", "--catalog-dir"])
        .arg(&catalog_root)
        .args(["--os-target", "linux-debian-12"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "which-grants must always exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn coverage_min_coverage_gate_exits_nonzero_on_shortfall() {
    let tmp = tempfile::tempdir().unwrap();
    // An empty catalog cannot cover the device's privileged surface, so coverage
    // is below 100%. Gating at 100% must trip the CI gate (non-zero exit).
    let catalog_root = tmp.path().join("permissions");
    std::fs::create_dir_all(catalog_root.join("linux")).unwrap();
    write(
        &catalog_root.join("linux").join("placeholder.toml"),
        "id = \"placeholder\"\n",
    );

    // Scope the scan to a single cheap class (`group` reads /etc/group) so the
    // test does not walk the whole filesystem (setuid/capfile classes do): the
    // gate behaviour is the same for any class, and the empty catalog leaves it
    // uncovered regardless.
    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args(["catalog", "coverage", "--catalog-dir"])
        .arg(&catalog_root)
        .args([
            "--os-target",
            "linux-debian-12",
            "--class",
            "group",
            "--min-coverage",
            "100.0",
        ])
        .output()
        .unwrap();

    // The contract code for a coverage-gate shortfall is specifically 4
    // (`coverage_exit_code` in cli.rs), distinct from 1 (a phase failure) — so a
    // CI gate can tell "coverage too low" from "the command broke". Assert the
    // exact code, matching the precision of the `apply` exit-3 unit test.
    assert_eq!(
        out.status.code(),
        Some(4),
        "coverage --min-coverage 100 must exit with the gate code 4 on shortfall; \
         got {:?}; stdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
