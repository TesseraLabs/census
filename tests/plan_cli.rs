//! End-to-end test of `census plan` against on-disk fixtures.

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
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
}

#[test]
fn plan_reports_create_for_new_role() {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("roles");
    std::fs::create_dir(&store).unwrap();
    write(
        &store.join("oper.toml"),
        "role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"Operator\"\nlevel = 5\n[payload]\ngroups = [\"wheel\"]\n",
    );
    let decl = tmp.path().join("declaration.toml");
    write(
        &decl,
        &format!(
            "version = 1\nschema = 1\nrole_store = \"{}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"oper\"\nuid = 9010\n",
            store.display()
        ),
    );
    let managed = tmp.path().join("managed.toml"); // absent on purpose

    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args(["plan", "--declaration"])
        .arg(&decl)
        .arg("--managed")
        .arg(&managed)
        // Pin the OS target so the test does not depend on the host's
        // /etc/os-release (the role uses raw groups, so the catalog is unused;
        // we only need a valid target for the resolve path).
        .args(["--os-target", "linux-debian-12"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("CREATE oper"), "got: {stdout}");
}

#[test]
fn plan_diff_shows_runas_fragment_and_target_path_for_create() {
    // A role whose permission narrows a command to a service account. `plan
    // --diff` must name the target sudoers path and show the new fragment's rule
    // line with the run-as — the operator previews that the command runs as
    // `bfs_solutions`, not root, before any apply.
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("roles");
    std::fs::create_dir(&store).unwrap();
    write(
        &store.join("svc.toml"),
        "role = \"svc\"\nversion = 1\nos = \"linux\"\nname = \"Service\"\nlevel = 5\n[payload]\npermissions = [\"run-cdmtool\"]\n",
    );
    let catalog_root = tmp.path().join("permissions");
    std::fs::create_dir_all(catalog_root.join("linux")).unwrap();
    write(
        &catalog_root.join("linux").join("cdmtool.toml"),
        "id = \"run-cdmtool\"\nsudo = [\"/usr/bin/id\"]\nrunas = \"bfs_solutions\"\n",
    );
    let decl = tmp.path().join("declaration.toml");
    write(
        &decl,
        &format!(
            "version = 1\nschema = 1\nrole_store = \"{}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"svc\"\nuid = 9100\n",
            store.display()
        ),
    );
    let managed = tmp.path().join("managed.toml"); // absent → CREATE

    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args(["plan", "--diff", "--declaration"])
        .arg(&decl)
        .arg("--managed")
        .arg(&managed)
        .arg("--additional-catalog-dir")
        .arg(&catalog_root)
        .args(["--os-target", "linux-debian-12"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("+ CREATE svc  ->  /etc/sudoers.d/census-svc"),
        "must name the target sudoers path: {stdout}"
    );
    assert!(
        stdout.contains("+ svc ALL=(bfs_solutions) NOPASSWD: /usr/bin/id"),
        "must show the run-as in the new fragment: {stdout}"
    );
}

#[test]
fn plan_without_diff_keeps_terse_output() {
    // The default plan output must be unchanged by the --diff feature: no
    // fragment lines, just the CREATE summary.
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("roles");
    std::fs::create_dir(&store).unwrap();
    write(
        &store.join("oper.toml"),
        "role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"Operator\"\nlevel = 5\n[payload]\ngroups = [\"wheel\"]\n",
    );
    let decl = tmp.path().join("declaration.toml");
    write(
        &decl,
        &format!(
            "version = 1\nschema = 1\nrole_store = \"{}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"oper\"\nuid = 9010\n",
            store.display()
        ),
    );
    let managed = tmp.path().join("managed.toml");

    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args(["plan", "--declaration"])
        .arg(&decl)
        .arg("--managed")
        .arg(&managed)
        .args(["--os-target", "linux-debian-12"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("CREATE oper (uid 9010"), "got: {stdout}");
    assert!(
        !stdout.contains("->  /etc/sudoers.d"),
        "terse output must not show artifact paths: {stdout}"
    );
}

#[test]
fn plan_fails_on_missing_role_slice() {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("roles");
    std::fs::create_dir(&store).unwrap();
    let decl = tmp.path().join("declaration.toml");
    write(
        &decl,
        &format!(
            "version = 1\nschema = 1\nrole_store = \"{}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"ghost\"\nuid = 9010\n",
            store.display()
        ),
    );
    let managed = tmp.path().join("managed.toml");

    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args(["plan", "--declaration"])
        .arg(&decl)
        .arg("--managed")
        .arg(&managed)
        .args(["--os-target", "linux-debian-12"])
        .output()
        .unwrap();

    assert!(!out.status.success(), "expected failure for missing slice");
}
