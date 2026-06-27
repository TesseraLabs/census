//! End-to-end tests of `census compile` and `census show` against on-disk
//! fixtures (real `--additional-catalog-dir`, role-store, and l10n tree).

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

/// Lay down a role-store slice, a declaration, and a catalog layer with one
/// permission. Returns (declaration path, catalog root).
fn fixtures(
    tmp: &std::path::Path,
    payload: &str,
    perm_body: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let store = tmp.join("roles");
    std::fs::create_dir_all(&store).unwrap();
    write(
        &store.join("oper.toml"),
        &format!("role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"Operator\"\nlevel = 5\n{payload}"),
    );
    let decl = tmp.join("declaration.toml");
    write(
        &decl,
        &format!(
            "version = 1\nschema = 1\nrole_store = \"{}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"oper\"\nuid = 9010\n",
            store.display()
        ),
    );
    let catalog_root = tmp.join("permissions");
    write(&catalog_root.join("linux").join("net.toml"), perm_body);
    (decl, catalog_root)
}

#[test]
fn compile_prints_primitives_with_provenance() {
    let tmp = tempfile::tempdir().unwrap();
    let (decl, catalog_root) = fixtures(
        tmp.path(),
        "[payload]\npermissions = [\"net-admin\"]\n",
        "id = \"net-admin\"\nrisk = \"escalation-capable\"\ngroups = [\"netdev\"]\nsudo = [\"/usr/sbin/ip\"]\n",
    );

    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .arg("compile")
        .arg("oper")
        .arg("--declaration")
        .arg(&decl)
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
    assert!(stdout.contains("netdev"), "expected group: {stdout}");
    assert!(stdout.contains("/usr/sbin/ip"), "expected sudo: {stdout}");
    // Provenance: the source permission and layer are shown.
    assert!(
        stdout.contains("perm net-admin"),
        "expected provenance: {stdout}"
    );
}

#[test]
fn compile_json_emits_machine_shape() {
    let tmp = tempfile::tempdir().unwrap();
    let (decl, catalog_root) = fixtures(
        tmp.path(),
        "[payload]\npermissions = [\"net-admin\"]\n",
        "id = \"net-admin\"\nrisk = \"contained\"\ngroups = [\"netdev\"]\n",
    );

    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args(["compile", "oper", "--json", "--declaration"])
        .arg(&decl)
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
    assert!(stdout.contains("\"role\":\"oper\""), "{stdout}");
    assert!(stdout.contains("\"value\":\"netdev\""), "{stdout}");
}

#[test]
fn compile_renders_file_grants_human_and_json() {
    let tmp = tempfile::tempdir().unwrap();
    let (decl, catalog_root) = fixtures(
        tmp.path(),
        "[payload]\npermissions = [\"ssh-edit\"]\n",
        "id = \"ssh-edit\"\nrisk = \"escalation-capable\"\n[[file]]\npath = \"/etc/ssh\"\naccess = \"rw\"\nrecursive = true\n",
    );

    // Human view shows a files: section with the backend/guarantee.
    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args(["compile", "oper", "--declaration"])
        .arg(&decl)
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
        stdout.contains("/etc/ssh rw recursive via AclBackend (dir, rewrite-proof)"),
        "expected files section: {stdout}"
    );

    // JSON view emits a file_grants array.
    let out_json = Command::new(env!("CARGO_BIN_EXE_census"))
        .args(["compile", "oper", "--json", "--declaration"])
        .arg(&decl)
        .arg("--additional-catalog-dir")
        .arg(&catalog_root)
        .args(["--os-target", "linux-debian-12"])
        .output()
        .unwrap();
    assert!(out_json.status.success());
    let json = String::from_utf8(out_json.stdout).unwrap();
    assert!(json.contains("\"file_grants\":["), "{json}");
    assert!(json.contains("\"path\":\"/etc/ssh\""), "{json}");
    assert!(json.contains("\"shape\":\"dir\""), "{json}");
}

#[test]
fn compile_shows_runas_human_and_json() {
    // A permission that narrows its command to a service account. The human view
    // shows `(runas bfs_solutions)` next to the command; the JSON sudo entry
    // carries a `"runas"` field.
    let tmp = tempfile::tempdir().unwrap();
    let (decl, catalog_root) = fixtures(
        tmp.path(),
        "[payload]\npermissions = [\"run-cdmtool\"]\n",
        "id = \"run-cdmtool\"\nsudo = [\"/usr/bin/id\"]\nrunas = \"bfs_solutions\"\n",
    );

    // Human view.
    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args(["compile", "oper", "--declaration"])
        .arg(&decl)
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
        stdout.contains("/usr/bin/id (runas bfs_solutions) [perm run-cdmtool @ linux]"),
        "human view must show the run-as: {stdout}"
    );

    // JSON view.
    let out_json = Command::new(env!("CARGO_BIN_EXE_census"))
        .args(["compile", "oper", "--json", "--declaration"])
        .arg(&decl)
        .arg("--additional-catalog-dir")
        .arg(&catalog_root)
        .args(["--os-target", "linux-debian-12"])
        .output()
        .unwrap();
    assert!(out_json.status.success());
    let json = String::from_utf8(out_json.stdout).unwrap();
    assert!(
        json.contains("\"runas\":\"bfs_solutions\""),
        "JSON sudo entry must carry the run-as: {json}"
    );
}

#[test]
fn compile_omits_runas_for_root_command_json_null() {
    // A plain root command: human shows no `(runas …)`, JSON carries `"runas":null`.
    let tmp = tempfile::tempdir().unwrap();
    let (decl, catalog_root) = fixtures(
        tmp.path(),
        "[payload]\npermissions = [\"net-admin\"]\n",
        "id = \"net-admin\"\nsudo = [\"/usr/sbin/ip\"]\n",
    );

    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args(["compile", "oper", "--json", "--declaration"])
        .arg(&decl)
        .arg("--additional-catalog-dir")
        .arg(&catalog_root)
        .args(["--os-target", "linux-debian-12"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let json = String::from_utf8(out.stdout).unwrap();
    assert!(json.contains("\"value\":\"/usr/sbin/ip\""), "{json}");
    assert!(
        json.contains("\"runas\":null"),
        "root command must carry runas:null: {json}"
    );
}

#[test]
fn compile_lint_unknown_permission_exits_nonzero() {
    let tmp = tempfile::tempdir().unwrap();
    let (decl, catalog_root) = fixtures(
        tmp.path(),
        "[payload]\npermissions = [\"ghost\"]\n",
        "id = \"net-admin\"\ngroups = [\"netdev\"]\n",
    );

    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args(["compile", "oper", "--lint", "--declaration"])
        .arg(&decl)
        .arg("--additional-catalog-dir")
        .arg(&catalog_root)
        .args(["--os-target", "linux-debian"])
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "lint over an unknown permission must fail"
    );
}

#[test]
fn show_renders_localized_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let (decl, catalog_root) = fixtures(
        tmp.path(),
        "[payload]\npermissions = [\"net-admin\"]\n",
        "id = \"net-admin\"\nrisk = \"escalation-capable\"\ngroups = [\"netdev\"]\n",
    );
    // l10n tree under the same root.
    write(
        &catalog_root.join("l10n").join("ru").join("network.toml"),
        "[net-admin]\ntitle = \"Управление сетью\"\nsummary = \"Настройка интерфейсов\"\n",
    );

    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args(["show", "oper", "--lang", "ru", "--declaration"])
        .arg(&decl)
        .arg("--additional-catalog-dir")
        .arg(&catalog_root)
        .args(["--os-target", "linux-debian"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("Управление сетью"),
        "expected localized title: {stdout}"
    );
    assert!(
        stdout.contains("escalation-capable"),
        "expected risk class: {stdout}"
    );
}

#[test]
fn show_falls_back_to_id_when_translation_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let (decl, catalog_root) = fixtures(
        tmp.path(),
        "[payload]\npermissions = [\"net-admin\"]\n",
        "id = \"net-admin\"\nrisk = \"contained\"\ngroups = [\"netdev\"]\n",
    );
    // No l10n tree at all → title falls back to the id, marked untranslated.

    let out = Command::new(env!("CARGO_BIN_EXE_census"))
        .args(["show", "oper", "--lang", "ru", "--declaration"])
        .arg(&decl)
        .arg("--additional-catalog-dir")
        .arg(&catalog_root)
        .args(["--os-target", "linux-debian"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("net-admin"), "id fallback: {stdout}");
    assert!(
        stdout.contains("untranslated"),
        "untranslated marker: {stdout}"
    );
}
