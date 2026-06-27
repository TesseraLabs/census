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

// Integration tests are a separate crate, so the crate-root test exemption in
// lib.rs does not reach them. In a test a panic on a broken fixture is the
// intended failure mode, so the production-hazard restriction lints are allowed
// here, mirroring lib.rs's `cfg_attr(test, ...)`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a panic on a broken fixture is the intended failure mode in tests"
)]

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
        .args([
            "catalog",
            "which-grants",
            "/usr/sbin/ip",
            "--additional-catalog-dir",
        ])
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
        .args(["catalog", "coverage", "--additional-catalog-dir"])
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

#[test]
fn coverage_rejects_invalid_min_coverage() {
    // `--min-coverage` is a percentage parsed as `f64` by clap; a non-numeric
    // value is a usage error, not a coverage shortfall. clap rejects it before the
    // command runs and exits with its usage-error code (2) — distinct from the
    // gate code (4), so a misconfigured CI invocation cannot masquerade as a
    // genuine coverage shortfall.
    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args([
            "catalog",
            "coverage",
            "--os-target",
            "linux-debian-12",
            "--class",
            "group",
            "--min-coverage",
            "not-a-number",
        ])
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(2),
        "an invalid --min-coverage must be a clap usage error (exit 2), not the \
         coverage-gate code; got {:?}; stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn coverage_rejects_out_of_range_min_coverage() {
    // `NaN`, `inf`, a negative, and `>100` all PARSE as valid `f64`, so clap
    // accepts them — but the runtime guard rejects them: the gate compares
    // `overall_pct < threshold`, and a non-finite or out-of-range threshold would
    // make that comparison meaningless (`x < NaN` is always false, silently
    // passing a CI gate). Each must exit 1 (`ExitCode::FAILURE`) with the
    // `census: --min-coverage` diagnostic, distinct from the gate code (4) and the
    // clap usage code (2). The negative case uses `--min-coverage=-1` so clap reads
    // `-1` as the value, not as a flag.
    for value in ["NaN", "inf", "100.1"] {
        let out = Command::new(env!("CARGO_BIN_EXE_census"))
            .args([
                "catalog",
                "coverage",
                "--os-target",
                "linux-debian-12",
                "--class",
                "group",
                "--min-coverage",
                value,
            ])
            .output()
            .unwrap();
        assert_out_of_range_rejected(value, &out);
    }

    // Negative value: glued `--flag=value` form so clap does not treat `-1` as a
    // separate (unknown) flag.
    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args([
            "catalog",
            "coverage",
            "--os-target",
            "linux-debian-12",
            "--class",
            "group",
            "--min-coverage=-1",
        ])
        .output()
        .unwrap();
    assert_out_of_range_rejected("-1", &out);
}

#[test]
fn no_default_catalog_dirs_without_additional_fails_closed() {
    // `--no-default-catalog-dirs` drops the packaged roots; with no
    // `--additional-catalog-dir` that leaves zero roots. Expanding the catalog
    // against nothing would silently resolve every permission to empty, so the
    // command must refuse with a non-zero exit and a clear diagnostic rather than
    // open the catalog into the void.
    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args([
            "compile",
            "some-role",
            "--no-default-catalog-dirs",
            "--os-target",
            "linux-debian-12",
        ])
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "zero catalog roots must fail closed (non-zero exit); got {:?}; stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no catalog roots configured"),
        "must name the empty-roots failure; stderr: {stderr}"
    );
}

#[test]
fn old_catalog_dir_flag_is_rejected() {
    // `--catalog-dir` was renamed to `--additional-catalog-dir` with no alias
    // (private repo, no external consumers). The old spelling must now be an
    // unknown-argument usage error (clap exit 2), proving the rename took effect.
    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args(["compile", "some-role", "--catalog-dir", "/tmp/whatever"])
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(2),
        "the removed --catalog-dir flag must be a clap usage error (exit 2); \
         got {:?}; stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Assert the binary rejected an out-of-range `--min-coverage` value via the
/// runtime guard: exit code 1 and the `census: --min-coverage` diagnostic on
/// stderr.
fn assert_out_of_range_rejected(value: &str, out: &std::process::Output) {
    assert_eq!(
        out.status.code(),
        Some(1),
        "--min-coverage {value} must be rejected by the runtime guard (exit 1); \
         got {:?}; stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("census: --min-coverage"),
        "--min-coverage {value} must report the runtime guard diagnostic; \
         stderr: {stderr}"
    );
}
