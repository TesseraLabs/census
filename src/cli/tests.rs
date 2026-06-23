//\! Unit tests for the CLI handlers, renderers, and the risk-lint engine.
//\!
//\! The CLI implementation is split across sibling submodules ([`super::compile`],
//\! [`super::coverage`], [`super::framework`], [`super::lint`], [`super::render`]),
//\! so this module glob-imports each one (plus the orchestration handlers in
//\! [`super`]) to reach the `pub(crate)` helpers the tests exercise by name.

use super::compile::*;
use super::coverage::*;
use super::framework::*;
use super::lint::*;
use super::render::*;
use super::*;
use crate::catalog::{self, ResolvedPermission, Risk, SourcedPrimitive};
use crate::coverage;
use crate::framework::{self, LoadedFrameworks};
use crate::rolestore::Limits;

#[test]
fn json_str_escapes_structural_and_control_chars() {
    assert_eq!(json_str("a\"b\\c"), r#""a\"b\\c""#);
    assert_eq!(json_str("a\nb\tc\r"), r#""a\nb\tc\r""#);
    // U+0000..U+001F other than the named ones use the \uXXXX form.
    assert_eq!(json_str("\u{0001}"), "\"\\u0001\"");
}

#[test]
fn json_str_escapes_js_line_terminators() {
    // U+2028 / U+2029 are valid JSON but ECMAScript line terminators; they
    // must be escaped so the output is safe to embed in a JS/JSONP string.
    assert_eq!(json_str("a\u{2028}b"), "\"a\\u2028b\"");
    assert_eq!(json_str("a\u{2029}b"), "\"a\\u2029b\"");
}

/// Write a role-store slice + a declaration whose single role-account, once
/// resolved, exactly matches the managed record below (→ empty plan). The
/// role declares NO supplementary groups so the group plan is empty
/// independent of the host's `getent` (these tests exercise account/registry
/// behavior, not group provisioning).
fn fixtures(dir: &Path) -> (PathBuf, PathBuf) {
    let store = dir.join("roles");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(
            store.join("oper.toml"),
            "role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"Operator\"\nlevel = 5\n[payload]\ngroups = []\n",
        )
        .unwrap();
    let decl = dir.join("declaration.toml");
    std::fs::write(
            &decl,
            format!(
                "version = 5\nrole_store = \"{}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"oper\"\nuid = 9010\n",
                store.display()
            ),
        )
        .unwrap();
    (decl, dir.join("managed.toml"))
}

#[test]
fn empty_plan_apply_does_not_rewrite_registry() {
    let tmp = tempfile::tempdir().unwrap();
    let (decl, managed) = fixtures(tmp.path());

    // Managed registry already matches the resolved target → empty plan.
    std::fs::write(
            &managed,
            "[[account]]\nname = \"oper\"\nuid = 9010\nshell = \"/bin/bash\"\ngroups = []\nfrom_version = 5\n",
        )
        .unwrap();
    let before = std::fs::read(&managed).unwrap();
    let mtime_before = std::fs::metadata(&managed).unwrap().modified().unwrap();

    let code = run_apply(ApplyOpts {
        declaration: &decl,
        managed: &managed,
        trust_fs: true,
        risk_acknowledged: false,
        rollback_root: tmp.path().join("rollback"),
        trust_anchor_path: tmp.path().join("trust.pub"),
        persist_dir: tmp.path().to_path_buf(),
        sessions_file: tmp.path().join("sessions.json"),
        catalog_roots: vec![tmp.path().join("permissions")],
        os_target: Some("linux-debian-12".to_owned()),
    });
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));

    // Byte-identical AND mtime untouched: spec R8, zero on-disk mutation.
    let after = std::fs::read(&managed).unwrap();
    assert_eq!(
        before, after,
        "empty-plan apply must not rewrite managed.toml"
    );
    let mtime_after = std::fs::metadata(&managed).unwrap().modified().unwrap();
    assert_eq!(
        mtime_before, mtime_after,
        "empty-plan apply must not bump mtime"
    );

    // And no rollback snapshot was created (empty plan never snapshots).
    assert!(
        !tmp.path().join("rollback").exists(),
        "empty plan must not create a rollback snapshot"
    );

    // Standalone (`--trust-fs`) must NOT move the anti-rollback floor.
    assert_eq!(
        trust::last_applied_version(tmp.path()).unwrap(),
        None,
        "standalone apply must not persist a version floor"
    );
}

/// Build a managed (signed) declaration + pinned trust-anchor whose single
/// role-account already matches the managed registry → empty plan. Returns
/// (decl path, managed path, anchor path).
fn signed_fixtures(
    dir: &Path,
    sk: &ed25519_dalek::SigningKey,
    version: u32,
) -> (PathBuf, PathBuf, PathBuf) {
    use ed25519_dalek::Signer;
    let store = dir.join("roles");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(
            store.join("oper.toml"),
            "role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"Operator\"\nlevel = 5\n[payload]\ngroups = []\n",
        )
        .unwrap();
    let head = format!(
        "version = {version}\nrole_store = \"{}\"\n",
        store.display()
    );
    let tail = "[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"oper\"\nuid = 9010\n";
    let payload = format!("{head}{tail}");
    let sig_hex = hex::encode(sk.sign(payload.as_bytes()).to_bytes());
    let decl = dir.join("declaration.toml");
    std::fs::write(&decl, format!("{head}signature = \"{sig_hex}\"\n{tail}")).unwrap();
    let anchor = dir.join("trust.pub");
    std::fs::write(&anchor, hex::encode(sk.verifying_key().to_bytes())).unwrap();
    (decl, dir.join("managed.toml"), anchor)
}

#[test]
fn managed_empty_plan_apply_persists_version_floor() {
    let tmp = tempfile::tempdir().unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
    let (decl, managed, anchor) = signed_fixtures(tmp.path(), &sk, 5);
    // Managed registry already matches → empty plan (no real mutations).
    std::fs::write(
            &managed,
            "[[account]]\nname = \"oper\"\nuid = 9010\nshell = \"/bin/bash\"\ngroups = []\nfrom_version = 5\n",
        )
        .unwrap();

    let code = run_apply(ApplyOpts {
        declaration: &decl,
        managed: &managed,
        trust_fs: false, // managed mode: signature + anti-rollback
        risk_acknowledged: false,
        rollback_root: tmp.path().join("rollback"),
        trust_anchor_path: anchor,
        persist_dir: tmp.path().to_path_buf(),
        sessions_file: tmp.path().join("sessions.json"),
        catalog_roots: vec![tmp.path().join("permissions")],
        os_target: Some("linux-debian-12".to_owned()),
    });
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));

    // Managed success persists the applied version floor.
    assert_eq!(trust::last_applied_version(tmp.path()).unwrap(), Some(5));
}

#[test]
fn managed_replay_lower_version_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
    let (decl, managed, anchor) = signed_fixtures(tmp.path(), &sk, 5);
    std::fs::write(
            &managed,
            "[[account]]\nname = \"oper\"\nuid = 9010\nshell = \"/bin/bash\"\ngroups = [\"wheel\"]\nfrom_version = 5\n",
        )
        .unwrap();
    // Floor already at 9 → the version-5 declaration is a replay.
    trust::persist_version(tmp.path(), 9).unwrap();

    let code = run_apply(ApplyOpts {
        declaration: &decl,
        managed: &managed,
        trust_fs: false,
        risk_acknowledged: false,
        rollback_root: tmp.path().join("rollback"),
        trust_anchor_path: anchor,
        persist_dir: tmp.path().to_path_buf(),
        sessions_file: tmp.path().join("sessions.json"),
        catalog_roots: vec![tmp.path().join("permissions")],
        os_target: Some("linux-debian-12".to_owned()),
    });
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
    // Floor untouched by a refused apply.
    assert_eq!(trust::last_applied_version(tmp.path()).unwrap(), Some(9));
}

#[test]
fn managed_unsigned_declaration_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    let (decl, managed) = fixtures(tmp.path()); // unsigned declaration
    std::fs::write(
            &managed,
            "[[account]]\nname = \"oper\"\nuid = 9010\nshell = \"/bin/bash\"\ngroups = [\"wheel\"]\nfrom_version = 5\n",
        )
        .unwrap();
    let code = run_apply(ApplyOpts {
        declaration: &decl,
        managed: &managed,
        trust_fs: false, // managed mode but no signature → fail-closed
        risk_acknowledged: false,
        rollback_root: tmp.path().join("rollback"),
        trust_anchor_path: tmp.path().join("trust.pub"),
        persist_dir: tmp.path().to_path_buf(),
        sessions_file: tmp.path().join("sessions.json"),
        catalog_roots: vec![tmp.path().join("permissions")],
        os_target: Some("linux-debian-12".to_owned()),
    });
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
    assert_eq!(
        trust::last_applied_version(tmp.path()).unwrap(),
        None,
        "refused apply must not persist a floor"
    );
}

// ---- doctor / status CLI-level (tasks 4.4) ----

use crate::doctor::{Finding, Severity};

fn finding(sev: Severity) -> Finding {
    Finding {
        severity: sev,
        check: "x",
        target: "t".into(),
        message: "m".into(),
    }
}

#[test]
fn apply_exit_code_maps_deferrals() {
    // No deferrals → success (0); any deferral → exit 3 (partial — retry),
    // distinct from a phase failure (FAILURE == 1).
    assert_eq!(
        format!("{:?}", apply_exit_code(0)),
        format!("{:?}", ExitCode::SUCCESS)
    );
    assert_eq!(
        format!("{:?}", apply_exit_code(2)),
        format!("{:?}", ExitCode::from(3))
    );
}

#[test]
fn doctor_exit_non_zero_when_errors() {
    let report = DoctorReport {
        findings: vec![finding(Severity::Error)],
    };
    assert_eq!(
        format!("{:?}", doctor_exit_code(&report)),
        format!("{:?}", ExitCode::FAILURE)
    );
}

#[test]
fn doctor_exit_zero_when_clean() {
    let report = DoctorReport::default();
    assert_eq!(
        format!("{:?}", doctor_exit_code(&report)),
        format!("{:?}", ExitCode::SUCCESS)
    );
}

#[test]
fn doctor_exit_zero_when_only_warnings() {
    let report = DoctorReport {
        findings: vec![finding(Severity::Warn)],
    };
    assert_eq!(
        format!("{:?}", doctor_exit_code(&report)),
        format!("{:?}", ExitCode::SUCCESS)
    );
}

#[test]
fn render_report_clean_and_tagged() {
    assert!(render_report(&DoctorReport::default()).contains("no findings"));
    let report = DoctorReport {
        findings: vec![finding(Severity::Error), finding(Severity::Warn)],
    };
    let text = render_report(&report);
    assert!(text.contains("ERROR ["));
    assert!(text.contains("WARN ["));
}

#[test]
fn status_always_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    // No declaration, no managed file, no persisted version → still 0.
    let code = run_status(None, &tmp.path().join("absent.toml"), tmp.path());
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
}

#[test]
fn status_with_declaration_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let (decl, managed) = fixtures(tmp.path());
    std::fs::write(
            &managed,
            "[[account]]\nname = \"oper\"\nuid = 9010\nshell = \"/bin/bash\"\ngroups = [\"wheel\"]\nfrom_version = 5\n",
        )
        .unwrap();
    let code = run_status(Some(&decl), &managed, tmp.path());
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
}

// ---- compile / show / lint (slice 5) ----

use crate::l10n::{Description, FakeL10n};

/// Build a `CompiledRole` directly (no filesystem) for pure-render tests.
fn sourced(value: &str, layer: &str, via: Option<&str>) -> SourcedPrimitive {
    SourcedPrimitive {
        value: value.to_owned(),
        layer: layer.to_owned(),
        via: via.map(str::to_owned),
        runas: None,
    }
}

/// A sourced sudo primitive narrowed to a service account (run-spec set).
fn sourced_runas(value: &str, layer: &str, runas: &str) -> SourcedPrimitive {
    SourcedPrimitive {
        value: value.to_owned(),
        layer: layer.to_owned(),
        via: None,
        runas: Some(runas.to_owned()),
    }
}

fn compiled_perm(
    id: &str,
    risk: Option<Risk>,
    groups: Vec<SourcedPrimitive>,
    sudo: Vec<SourcedPrimitive>,
) -> CompiledPermission {
    CompiledPermission {
        resolved: ResolvedPermission {
            id: id.to_owned(),
            risk,
            runas: None,
            groups,
            sudo,
            file_grants: Vec::new(),
            limits: None,
            limits_layer: None,
            category_members: Vec::new(),
            resolved_catalog_version: None,
        },
    }
}

/// A compiled permission carrying one resolved file grant.
fn compiled_perm_with_file(
    id: &str,
    path: &str,
    access: crate::catalog::Access,
    recursive: bool,
    via: Option<&str>,
) -> CompiledPermission {
    let grant = crate::catalog::FileGrant {
        path: path.to_owned(),
        access,
        recursive,
    };
    CompiledPermission {
        resolved: ResolvedPermission {
            id: id.to_owned(),
            risk: None,
            runas: None,
            groups: vec![],
            sudo: vec![],
            file_grants: vec![crate::catalog::ResolvedFileGrant {
                path: path.to_owned(),
                access,
                recursive,
                shape: grant.shape(),
                sources: vec![crate::catalog::SourcedFileGrant {
                    layer: "linux".to_owned(),
                    via: via.map(str::to_owned),
                }],
            }],
            limits: None,
            limits_layer: None,
            category_members: Vec::new(),
            resolved_catalog_version: None,
        },
    }
}

#[test]
fn render_compile_human_shows_primitives_and_provenance() {
    let compiled = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![compiled_perm(
            "net-admin",
            Some(Risk::EscalationCapable),
            vec![sourced("netdev", "linux-debian-12", None)],
            vec![sourced("/usr/sbin/ip", "linux-debian", None)],
        )],
        raw_groups: vec!["wheel".to_owned()],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    let text = render_compile_human(&compiled);
    // Group from the raw escape hatch is tagged [raw]; the permission group
    // carries the source layer; sudo carries its (different) layer.
    assert!(text.contains("wheel [raw]"), "{text}");
    assert!(
        text.contains("netdev [perm net-admin @ linux-debian-12]"),
        "{text}"
    );
    assert!(
        text.contains("/usr/sbin/ip [perm net-admin @ linux-debian]"),
        "{text}"
    );
}

#[test]
fn render_compile_human_shows_bundle_via_provenance() {
    // A primitive pulled in through a bundle member shows `via`.
    let compiled = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![compiled_perm(
            "network-config",
            Some(Risk::EscalationCapable),
            vec![],
            vec![sourced("/usr/sbin/ip", "linux", Some("network-admin"))],
        )],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    let text = render_compile_human(&compiled);
    assert!(
        text.contains("/usr/sbin/ip [perm network-config via network-admin @ linux]"),
        "{text}"
    );
}

#[test]
fn render_compile_json_is_well_formed_shape() {
    let compiled = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![compiled_perm(
            "net-admin",
            None,
            vec![sourced("netdev", "linux", None)],
            vec![],
        )],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits {
            nofile: Some(1024),
            nproc: None,
        },
    };
    let json = render_compile_json(&compiled);
    assert!(json.contains("\"role\":\"oper\""), "{json}");
    assert!(json.contains("\"value\":\"netdev\""), "{json}");
    assert!(json.contains("\"permission\":\"net-admin\""), "{json}");
    assert!(json.contains("\"layer\":\"linux\""), "{json}");
    assert!(json.contains("\"via\":null"), "{json}");
    assert!(json.contains("\"nofile\":1024"), "{json}");
    assert!(json.contains("\"nproc\":null"), "{json}");
}

// ---- runas in compile output (operator visibility) ----

#[test]
fn render_compile_human_shows_runas_on_service_account_command() {
    // A command narrowed to a service account must show `(runas <acct>)` next to
    // it so the operator can see it does not run as root.
    let compiled = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![compiled_perm(
            "svc-tool",
            None,
            vec![],
            vec![sourced_runas("/opt/QToolplus", "linux", "bfs_solutions")],
        )],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    let text = render_compile_human(&compiled);
    assert!(
        text.contains("/opt/QToolplus (runas bfs_solutions) [perm svc-tool @ linux]"),
        "{text}"
    );
}

#[test]
fn render_compile_human_omits_runas_for_root_command() {
    // The default (root) run-spec stays clean — no `(runas ...)` clutter.
    let compiled = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![compiled_perm(
            "net-admin",
            None,
            vec![],
            vec![sourced("/usr/sbin/ip", "linux", None)],
        )],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    let text = render_compile_human(&compiled);
    assert!(
        text.contains("/usr/sbin/ip [perm net-admin @ linux]"),
        "{text}"
    );
    assert!(
        !text.contains("runas"),
        "root command must not mention runas: {text}"
    );
}

#[test]
fn render_compile_json_emits_runas_field_on_sudo_entries() {
    // The sudo entry carries a `"runas"` field: the service account when narrowed,
    // `null` for a root command. Groups never gain the field.
    let compiled = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![compiled_perm(
            "svc-tool",
            None,
            vec![sourced("netdev", "linux", None)],
            vec![
                sourced_runas("/opt/QToolplus", "linux", "bfs_solutions"),
                sourced("/usr/sbin/ip", "linux", None),
            ],
        )],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    let json = render_compile_json(&compiled);
    assert!(
        json.contains(r#""value":"/opt/QToolplus","permission":"svc-tool","layer":"linux","via":null,"runas":"bfs_solutions""#),
        "narrowed command must carry its runas: {json}"
    );
    assert!(
        json.contains(r#""value":"/usr/sbin/ip","permission":"svc-tool","layer":"linux","via":null,"runas":null"#),
        "root command must carry runas:null: {json}"
    );
    // The groups array entry must NOT gain a runas key.
    assert!(
        json.contains(r#""value":"netdev","permission":"svc-tool","layer":"linux","via":null}"#),
        "groups entry must stay runas-free: {json}"
    );
}

// ---- file-grant rendering (slice 5) ----

#[test]
fn render_compile_human_shows_file_grants_dir_and_file() {
    use crate::catalog::Access;
    let compiled = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![
            // A rewrite-proof dir grant (open AclBackend) ...
            compiled_perm_with_file("ssh-edit", "/etc/ssh", Access::Rw, true, None),
            // ... and a per-file grant that needs a capable backend.
            compiled_perm_with_file("hosts-edit", "/etc/hosts", Access::Ro, false, None),
        ],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    let text = render_compile_human(&compiled);
    assert!(
        text.contains("/etc/ssh rw recursive via AclBackend (dir, rewrite-proof) [perm ssh-edit]"),
        "{text}"
    );
    assert!(
        text.contains("/etc/hosts ro via requires per-file-capable backend [perm hosts-edit]"),
        "{text}"
    );
}

#[test]
fn render_compile_json_emits_file_grants_array_escaped() {
    use crate::catalog::Access;
    let compiled = CompiledRole {
        role: "oper".to_owned(),
        // A path with a quote exercises the json_str escaper in the new array.
        permissions: vec![compiled_perm_with_file(
            "ssh-edit",
            "/etc/s\"sh",
            Access::Rw,
            true,
            None,
        )],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    let json = render_compile_json(&compiled);
    assert!(json.contains("\"file_grants\":["), "{json}");
    assert!(json.contains(r#""path":"/etc/s\"sh""#), "{json}");
    assert!(json.contains("\"access\":\"rw\""), "{json}");
    assert!(json.contains("\"recursive\":true"), "{json}");
    assert!(json.contains("\"shape\":\"dir\""), "{json}");
    assert!(
        json.contains("\"backend\":\"AclBackend (dir, rewrite-proof)\""),
        "{json}"
    );
    assert!(json.contains("\"permission\":\"ssh-edit\""), "{json}");
}

#[test]
fn render_show_tree_shows_file_grant_with_backend() {
    use crate::catalog::Access;
    let compiled = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![compiled_perm_with_file(
            "ssh-edit",
            "/etc/ssh",
            Access::Rw,
            true,
            None,
        )],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    let l10n = FakeL10n::new();
    let text = render_show_tree(&compiled, "en", &l10n);
    assert!(
        text.contains("file /etc/ssh rw recursive via AclBackend (dir, rewrite-proof)"),
        "{text}"
    );
}

// ---- risk lint (slice 5) ----

#[test]
fn risk_lint_flags_rw_on_root_equivalent() {
    use crate::catalog::Access;
    // rw on /etc/ssh is escalation-capable.
    let compiled = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![compiled_perm_with_file(
            "ssh-edit",
            "/etc/ssh",
            Access::Rw,
            true,
            None,
        )],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    let findings = file_grant_risk_findings(&compiled);
    let f = findings
        .iter()
        .find(|f| f.code == "rw-root-equivalent")
        .expect("rw-root-equivalent finding");
    assert_eq!(f.severity, LintSeverity::Warning);
    assert!(f.message.contains("/etc/ssh"));
}

#[test]
fn risk_lint_flags_secret_path_read() {
    use crate::catalog::Access;
    // A recursive grant on /etc that CONTAINS /etc/shadow is flagged even
    // though its declared path is the broader directory (boundary both ways).
    let compiled = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![compiled_perm_with_file(
            "etc-read",
            "/etc",
            Access::Ro,
            true,
            None,
        )],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    let findings = file_grant_risk_findings(&compiled);
    assert!(
        findings.iter().any(|f| f.code == "secret-path-access"),
        "recursive /etc grant must flag the contained secret: {findings:?}"
    );
}

#[test]
fn risk_lint_flags_ssh_host_key_read() {
    use crate::catalog::Access;
    // A direct (non-recursive) ro grant on an SSH host PRIVATE key must flag:
    // the key is a `ssh_host_*` file in /etc/ssh, which the component-boundary
    // matcher alone misses (it shares its dir with the public sshd_config), so
    // the basename rule in `path_is_secret` must catch it.
    let compiled = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![compiled_perm_with_file(
            "host-key-read",
            "/etc/ssh/ssh_host_rsa_key",
            Access::Ro,
            false,
            None,
        )],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    let findings = file_grant_risk_findings(&compiled);
    let f = findings
        .iter()
        .find(|f| f.code == "secret-path-access")
        .expect("ro grant on an ssh host key must flag secret-path-access");
    assert_eq!(f.severity, LintSeverity::Warning);
    assert!(f.message.contains("/etc/ssh/ssh_host_rsa_key"));
    // A NON-secret file in the same directory (the public config) must NOT flag.
    let public = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![compiled_perm_with_file(
            "sshd-config-read",
            "/etc/ssh/sshd_config",
            Access::Ro,
            false,
            None,
        )],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    assert!(
        !file_grant_risk_findings(&public)
            .iter()
            .any(|f| f.code == "secret-path-access"),
        "the public sshd_config in /etc/ssh must not be flagged secret"
    );
}

#[test]
fn risk_lint_clean_grant_no_finding() {
    use crate::catalog::Access;
    // rw on an app config dir that is neither root-equivalent nor a secret.
    let compiled = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![compiled_perm_with_file(
            "app-edit",
            "/etc/myapp",
            Access::Rw,
            true,
            None,
        )],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    assert!(file_grant_risk_findings(&compiled).is_empty());
}

// ---- group-grant escalation lint (slice 6) ----

/// A resolved group carrying the given sudo commands and file grants (the
/// fields the group lint inspects). Other fields are defaults.
fn resolved_group(
    name: &str,
    sudo: &[&str],
    file_grants: Vec<catalog::ResolvedFileGrant>,
) -> model::ResolvedGroup {
    model::ResolvedGroup {
        name: name.to_owned(),
        gid: None,
        provenance: model::Provenance::Created,
        members: Vec::new(),
        sudo_commands: sudo.iter().map(|s| model::SudoCommand::root(*s)).collect(),
        file_grants,
        limits: Limits::default(),
        bound_roles: Vec::new(),
    }
}

fn rfg(path: &str, access: catalog::Access, recursive: bool) -> catalog::ResolvedFileGrant {
    catalog::ResolvedFileGrant {
        path: path.to_owned(),
        access,
        recursive,
        shape: if recursive {
            catalog::Shape::Dir
        } else {
            catalog::Shape::File
        },
        sources: Vec::new(),
    }
}

#[test]
fn group_lint_flags_rw_root_equivalent_file_grant() {
    use crate::catalog::Access;
    let groups = vec![resolved_group(
        "netops",
        &[],
        vec![rfg("/etc/ssh", Access::Rw, true)],
    )];
    let findings = group_grant_risk_findings(&groups);
    let f = findings
        .iter()
        .find(|f| f.code == "group-rw-root-equivalent")
        .expect("group root-equivalent file finding");
    assert_eq!(f.severity, LintSeverity::Warning);
    // The note names the group and the inheritance (all members).
    assert!(f.message.contains("netops"));
    assert!(f.message.to_lowercase().contains("members"));
}

#[test]
fn group_lint_flags_root_equivalent_sudo() {
    // A `%group` sudo command that edits a root-equivalent path (here a
    // sudoers fragment) is escalation surface inherited by every member.
    let groups = vec![resolved_group(
        "netops",
        &["/usr/bin/tee /etc/sudoers.d/x"],
        vec![],
    )];
    let findings = group_grant_risk_findings(&groups);
    let f = findings
        .iter()
        .find(|f| f.code == "group-sudo-escalation")
        .expect("group sudo escalation finding");
    assert_eq!(f.severity, LintSeverity::Warning);
    assert!(f.message.contains("netops"));
}

#[test]
fn group_lint_flags_secret_path_grant() {
    use crate::catalog::Access;
    // A recursive grant on /etc that contains /etc/shadow is flagged (boundary
    // both ways), exactly as for an account grant.
    let groups = vec![resolved_group(
        "auditors",
        &[],
        vec![rfg("/etc", Access::Ro, true)],
    )];
    let findings = group_grant_risk_findings(&groups);
    let f = findings
        .iter()
        .find(|f| f.code == "group-secret-path-access")
        .expect("group secret-path finding");
    assert_eq!(f.severity, LintSeverity::Warning);
    assert!(f.message.contains("auditors"));
}

#[test]
fn group_lint_flags_ssh_host_key_grant() {
    use crate::catalog::Access;
    // A direct ro grant on an SSH host private key bound to a group must flag
    // (same basename rule as the account lint — every member would read the key).
    let groups = vec![resolved_group(
        "keyops",
        &[],
        vec![rfg("/etc/ssh/ssh_host_ed25519_key", Access::Ro, false)],
    )];
    let findings = group_grant_risk_findings(&groups);
    let f = findings
        .iter()
        .find(|f| f.code == "group-secret-path-access")
        .expect("group grant on an ssh host key must flag secret-path-access");
    assert_eq!(f.severity, LintSeverity::Warning);
    assert!(f.message.contains("keyops"));
    assert!(f.message.contains("/etc/ssh/ssh_host_ed25519_key"));
}

#[test]
fn group_lint_clean_group_has_no_finding() {
    use crate::catalog::Access;
    // A group with a benign app-dir grant and a non-root-equivalent sudo
    // command produces no escalation finding.
    let groups = vec![resolved_group(
        "appops",
        &["/usr/bin/systemctl restart atm-app"],
        vec![rfg("/etc/myapp", Access::Rw, true)],
    )];
    assert!(group_grant_risk_findings(&groups).is_empty());
}

/// Write a role-store slice + declaration referencing it, plus a catalog
/// layer dir. Returns the declaration path and the catalog root.
fn compile_fixture(
    dir: &Path,
    payload: &str,
    catalog_files: &[(&str, &str, &str)],
) -> (PathBuf, PathBuf) {
    let store = dir.join("roles");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(
            store.join("oper.toml"),
            format!("role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"Operator\"\nlevel = 5\n{payload}"),
        )
        .unwrap();
    let decl = dir.join("declaration.toml");
    std::fs::write(
            &decl,
            format!(
                "version = 1\nrole_store = \"{}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"oper\"\nuid = 9010\n",
                store.display()
            ),
        )
        .unwrap();
    let catalog_root = dir.join("permissions");
    for (layer, file, body) in catalog_files {
        let layer_dir = catalog_root.join(layer);
        std::fs::create_dir_all(&layer_dir).unwrap();
        std::fs::write(layer_dir.join(format!("{file}.toml")), body).unwrap();
    }
    (decl, catalog_root)
}

#[test]
fn compile_role_expands_with_provenance_over_tempdir() {
    let tmp = tempfile::tempdir().unwrap();
    let (decl_path, catalog_root) = compile_fixture(
            tmp.path(),
            "[payload]\npermissions = [\"net-admin\"]\n",
            &[(
                "linux",
                "net-admin",
                "id = \"net-admin\"\nrisk = \"escalation-capable\"\ngroups = [\"netdev\"]\nsudo = [\"/usr/sbin/ip\"]\n",
            )],
        );
    let decl = Declaration::parse(&std::fs::read_to_string(&decl_path).unwrap()).unwrap();
    let catalog = LiveCatalog::new(vec![catalog_root]);
    let os = OsTarget::new("linux", "debian", None).unwrap();
    let ctx = ResolveCtx::default();
    let inputs = CompileInputs {
        catalog: &catalog,
        os: &os,
        ctx: &ctx,
    };
    let (compiled, warnings) = compile_role("oper", &decl, &inputs).unwrap();
    assert_eq!(compiled.permissions.len(), 1);
    let groups = compiled.flat_groups();
    assert_eq!(groups[0].value, "netdev");
    assert_eq!(groups[0].permission.as_deref(), Some("net-admin"));
    assert_eq!(groups[0].layer.as_deref(), Some("linux"));
    assert!(
        warnings.is_empty(),
        "pure-permission role must not warn: {warnings:?}"
    );
}

#[test]
fn run_compile_clean_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let (decl, catalog_root) = compile_fixture(
        tmp.path(),
        "[payload]\npermissions = [\"net-admin\"]\n",
        &[(
            "linux",
            "net-admin",
            "id = \"net-admin\"\nrisk = \"contained\"\ngroups = [\"netdev\"]\n",
        )],
    );
    let code = run_compile(
        "oper",
        &decl,
        vec![catalog_root],
        Some("linux-debian-12"),
        false,
        false,
    );
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
}

#[test]
fn run_compile_lint_clean_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let (decl, catalog_root) = compile_fixture(
        tmp.path(),
        "[payload]\npermissions = [\"net-admin\"]\n",
        &[(
            "linux",
            "net-admin",
            "id = \"net-admin\"\nrisk = \"contained\"\ngroups = [\"netdev\"]\n",
        )],
    );
    // Pin the OS target so no UnknownOsVersion warning surfaces (still a
    // warning, not an error — but keep the test about the clean path).
    let code = run_compile(
        "oper",
        &decl,
        vec![catalog_root],
        Some("linux-debian"),
        true,
        false,
    );
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
}

#[test]
fn run_compile_lint_unknown_permission_exits_nonzero() {
    let tmp = tempfile::tempdir().unwrap();
    // Role references a permission no catalog layer defines → resolve ERROR.
    let (decl, catalog_root) = compile_fixture(
        tmp.path(),
        "[payload]\npermissions = [\"does-not-exist\"]\n",
        &[(
            "linux",
            "net-admin",
            "id = \"net-admin\"\ngroups = [\"netdev\"]\n",
        )],
    );
    let code = run_compile(
        "oper",
        &decl,
        vec![catalog_root],
        Some("linux-debian"),
        true,
        false,
    );
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
}

#[test]
fn run_compile_lint_cycle_exits_nonzero() {
    let tmp = tempfile::tempdir().unwrap();
    // a includes b, b includes a → cycle → resolve ERROR.
    let (decl, catalog_root) = compile_fixture(
        tmp.path(),
        "[payload]\npermissions = [\"a\"]\n",
        &[
            ("linux", "a", "id = \"a\"\nincludes = [\"b\"]\n"),
            ("linux", "b", "id = \"b\"\nincludes = [\"a\"]\n"),
        ],
    );
    let code = run_compile(
        "oper",
        &decl,
        vec![catalog_root],
        Some("linux-debian"),
        true,
        false,
    );
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
}

#[test]
fn lint_role_flags_raw_primitive_as_warning_not_error() {
    // A raw group alongside permissions is a WARNING; with only warnings,
    // compile --lint still exits 0.
    let tmp = tempfile::tempdir().unwrap();
    let (decl, catalog_root) = compile_fixture(
        tmp.path(),
        "[payload]\ngroups = [\"wheel\"]\npermissions = [\"net-admin\"]\n",
        &[(
            "linux",
            "net-admin",
            "id = \"net-admin\"\nrisk = \"contained\"\ngroups = [\"netdev\"]\n",
        )],
    );
    let code = run_compile(
        "oper",
        &decl,
        vec![catalog_root],
        Some("linux-debian"),
        true,
        false,
    );
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
}

#[test]
fn lint_role_emits_raw_and_missing_translation_warnings() {
    // Build a compiled role directly and lint it against a fake l10n source
    // that has no translation for the permission → missing-translation
    // warnings; the raw-primitive warning is carried in `warnings`.
    let compiled = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![compiled_perm(
            "net-admin",
            Some(Risk::Contained),
            vec![],
            vec![],
        )],
        raw_groups: vec!["wheel".to_owned()],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    let warnings = vec![model::ResolveWarning::RawPrimitiveAlongsidePermissions {
        role: "oper".to_owned(),
        primitive: "groups",
    }];
    let decl = Declaration::parse(
            "version = 1\nrole_store = \"/r\"\n[defaults]\nuid_range = [9000,9999]\nshell = \"/bin/bash\"\nhome_base = \"/h\"\n",
        )
        .unwrap();
    let os = OsTarget::new("linux", "debian", None).unwrap();
    let catalog = LiveCatalog::new(vec![]);
    // en has a title (so no missing for en), ru/zh do not.
    let l10n = FakeL10n::new().with(
        "en",
        "net-admin",
        Description {
            title: Some("Network".to_owned()),
            summary: None,
            risk_note: None,
        },
    );
    let findings = lint_role(&compiled, &warnings, &decl, &os, &catalog, &l10n);
    assert!(findings
        .iter()
        .any(|f| f.code == "raw-primitive" && f.severity == LintSeverity::Warning));
    assert!(
        findings
            .iter()
            .any(|f| f.code == "missing-translation" && f.message.contains("ru")),
        "expected ru missing-translation: {findings:?}"
    );
    // No ERROR-severity finding from a successful compile → would not gate.
    assert!(!findings.iter().any(|f| f.severity == LintSeverity::Error));
}

#[test]
fn render_show_tree_localizes_and_shows_risk() {
    let compiled = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![compiled_perm(
            "net-admin",
            Some(Risk::EscalationCapable),
            vec![sourced("netdev", "linux", None)],
            vec![sourced("/usr/sbin/ip", "linux", None)],
        )],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    let l10n = FakeL10n::new().with(
        "ru",
        "net-admin",
        Description {
            title: Some("Управление сетью".to_owned()),
            summary: Some("Настройка интерфейсов".to_owned()),
            risk_note: Some("Фактически root".to_owned()),
        },
    );
    let text = render_show_tree(&compiled, "ru", &l10n);
    assert!(
        text.contains("permission net-admin — Управление сетью [escalation-capable]"),
        "{text}"
    );
    assert!(text.contains("summary: Настройка интерфейсов"), "{text}");
    assert!(text.contains("group netdev"), "{text}");
    assert!(text.contains("sudo /usr/sbin/ip"), "{text}");
}

#[test]
fn render_show_tree_falls_back_to_id_when_untranslated() {
    let compiled = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![compiled_perm(
            "net-admin",
            Some(Risk::Contained),
            vec![],
            vec![],
        )],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    let l10n = FakeL10n::new();
    let text = render_show_tree(&compiled, "ru", &l10n);
    // Title falls back to the id, marked untranslated; risk class still shown.
    assert!(
        text.contains("permission net-admin — net-admin (untranslated) [contained]"),
        "{text}"
    );
}

// ---- catalog coverage (render + exit-code helpers; slice 3) ----

use crate::coverage::{
    ClassCoverage, CoverageReport, ObjectCoverage, Provenance, SurfaceClass, SurfaceObject,
};

/// A surface object for hand-built coverage reports.
fn cov_obj(class: SurfaceClass, key: &str, prov: Provenance) -> SurfaceObject {
    SurfaceObject {
        class,
        key: key.to_owned(),
        provenance: prov,
        detail: String::new(),
    }
}

/// A hand-built coverage report exercising every render branch: a covered and
/// an uncovered sudo_bin (the latter with a suggestion), an intentionally
/// uncovered group, and an orphan-setuid anomaly.
fn sample_report() -> CoverageReport {
    CoverageReport {
        by_class: vec![ClassCoverage {
            class: SurfaceClass::SudoBin,
            covered: 1,
            total: 2,
        }],
        objects: vec![
            ObjectCoverage {
                object: cov_obj(SurfaceClass::SudoBin, "/usr/sbin/ip", Provenance::Vendor),
                covered: true,
                suggested_permission: None,
                intentional_exclusion: None,
                backend_limited: None,
                coverage_note: None,
            },
            ObjectCoverage {
                object: cov_obj(
                    SurfaceClass::SudoBin,
                    "/usr/sbin/cryptsetup",
                    Provenance::Vendor,
                ),
                covered: false,
                suggested_permission: Some("luks-admin".to_owned()),
                intentional_exclusion: None,
                backend_limited: None,
                coverage_note: None,
            },
            ObjectCoverage {
                object: cov_obj(SurfaceClass::Group, "astra-admin", Provenance::Vendor),
                covered: false,
                suggested_permission: None,
                intentional_exclusion: Some("admin-by-design".to_owned()),
                backend_limited: None,
                coverage_note: None,
            },
            // A config object covered by a file grant carries the backend note.
            ObjectCoverage {
                object: cov_obj(
                    SurfaceClass::Config,
                    "/etc/ssh/sshd_config",
                    Provenance::Vendor,
                ),
                covered: true,
                suggested_permission: None,
                intentional_exclusion: None,
                backend_limited: None,
                coverage_note: Some("rw via AclBackend (dir)".to_owned()),
            },
            // A backend-limited config: a single file in /etc the dir-only
            // backend can't cover without an over-broad grant.
            ObjectCoverage {
                object: cov_obj(SurfaceClass::Config, "/etc/login.defs", Provenance::Vendor),
                covered: false,
                suggested_permission: None,
                intentional_exclusion: None,
                backend_limited: Some(
                    "single file in non-grantable parent; requires per-file-capable backend"
                        .to_owned(),
                ),
                coverage_note: None,
            },
        ],
        setuid_inventory: vec![],
        anomalies: vec![cov_obj(
            SurfaceClass::Setuid,
            "/opt/x/flasher",
            Provenance::Orphan,
        )],
        overall_pct: 50.0,
        catalog_version: Some("2026.06".to_owned()),
        os_target: "linux-debian-12".to_owned(),
        catalog_warnings: vec![],
    }
}

#[test]
fn resolve_roles_honours_catalog_dir_override() {
    // A role references a permission defined ONLY in a site catalog passed via
    // the same roots the coverage pass uses. resolve_roles must resolve it
    // against those roots (not the bare defaults) so the role contributes its
    // sudo binary to coverage.
    let tmp = tempfile::tempdir().unwrap();
    let site_root = tmp.path().join("site-permissions");
    let layer_dir = site_root.join("linux");
    std::fs::create_dir_all(&layer_dir).unwrap();
    std::fs::write(
        layer_dir.join("site-net.toml"),
        "id = \"site-net\"\nsudo = [\"/usr/sbin/site-tool\"]\n",
    )
    .unwrap();

    let roles_dir = tmp.path().join("roles");
    std::fs::create_dir_all(&roles_dir).unwrap();
    std::fs::write(
            roles_dir.join("oper.toml"),
            "role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"Operator\"\nlevel = 5\n[payload]\npermissions = [\"site-net\"]\n",
        )
        .unwrap();

    let os = OsTarget::new("linux", "debian", None).unwrap();
    let ctx = ResolveCtx::default();

    // With the site root passed through, the role resolves and contributes.
    let roles = resolve_roles(&roles_dir, std::slice::from_ref(&site_root), &os, &ctx);
    assert_eq!(roles.len(), 1);
    assert!(
        roles[0].sudo.iter().any(|c| c == "/usr/sbin/site-tool"),
        "role must resolve its site-catalog permission: {:?}",
        roles[0].sudo
    );

    // Without the site root, the same permission is unknown: the role
    // resolves to nothing (warns-and-skips), proving the override mattered.
    let empty_root = tmp.path().join("empty-permissions");
    std::fs::create_dir_all(&empty_root).unwrap();
    let roles_no_override = resolve_roles(&roles_dir, &[empty_root], &os, &ctx);
    assert_eq!(roles_no_override.len(), 1);
    assert!(
        roles_no_override[0].sudo.is_empty(),
        "without the site root the permission cannot resolve"
    );
}

#[test]
fn coverage_exit_code_gates_on_min_coverage() {
    // No threshold → always success even at 0%.
    assert_eq!(
        format!("{:?}", coverage_exit_code(0.0, None)),
        format!("{:?}", ExitCode::SUCCESS)
    );
    // Below threshold → exit 4 (CI-gate, distinct from FAILURE==1).
    assert_eq!(
        format!("{:?}", coverage_exit_code(81.0, Some(85.0))),
        format!("{:?}", ExitCode::from(4))
    );
    // At or above threshold → success.
    assert_eq!(
        format!("{:?}", coverage_exit_code(85.0, Some(85.0))),
        format!("{:?}", ExitCode::SUCCESS)
    );
    assert_eq!(
        format!("{:?}", coverage_exit_code(90.0, Some(85.0))),
        format!("{:?}", ExitCode::SUCCESS)
    );
}

#[test]
fn render_coverage_human_shows_all_sections() {
    let text = render_coverage_human(&sample_report(), false);
    assert!(text.contains("linux-debian-12"), "{text}");
    assert!(text.contains("sudo_bin  1/2"), "{text}");
    assert!(text.contains("overall: 50.0%"), "{text}");
    // Uncovered gap with its suggestion.
    assert!(
        text.contains("/usr/sbin/cryptsetup") && text.contains("luks-admin"),
        "{text}"
    );
    // Intentionally-uncovered with its reason.
    assert!(
        text.contains("astra-admin") && text.contains("admin-by-design"),
        "{text}"
    );
    // A config object covered by a file grant lists its backend note.
    assert!(
        text.contains("covered via file grants")
            && text.contains("/etc/ssh/sshd_config")
            && text.contains("rw via AclBackend (dir)"),
        "{text}"
    );
    // Backend-limited section present, with the bare /etc file and its reason.
    assert!(
        text.contains("backend-limited (requires per-file backend)")
            && text.contains("/etc/login.defs")
            && text.contains("requires per-file-capable backend"),
        "{text}"
    );
    // A backend-limited object must NOT appear in the uncovered gap section.
    assert!(
        !text.contains("[config] /etc/login.defs →"),
        "backend-limited must not be a gap with a suggestion arrow: {text}"
    );
    // Anomaly section present.
    assert!(
        text.contains("anomalies") && text.contains("/opt/x/flasher"),
        "{text}"
    );
    // The covered binary is NOT listed in the uncovered section (it appears
    // only in the class summary, never as a gap row with a suggestion arrow).
    assert!(
        !text.contains("[sudo_bin] /usr/sbin/ip"),
        "covered binary must not be rendered as a gap: {text}"
    );
}

#[test]
fn render_coverage_json_has_objects_and_summary() {
    let json = render_coverage_json(&sample_report());
    assert!(json.contains("\"objects\":["), "{json}");
    assert!(json.contains("\"key\":\"/usr/sbin/ip\""), "{json}");
    assert!(json.contains("\"covered\":true"), "{json}");
    assert!(
        json.contains("\"suggested_permission\":\"luks-admin\""),
        "{json}"
    );
    assert!(
        json.contains("\"intentional_exclusion\":\"admin-by-design\""),
        "{json}"
    );
    assert!(json.contains("\"provenance\":\"vendor\""), "{json}");
    assert!(json.contains("\"overall_pct\":50.0"), "{json}");
    assert!(json.contains("\"catalog_version\":\"2026.06\""), "{json}");
    assert!(json.contains("\"os_target\":\"linux-debian-12\""), "{json}");
    assert!(json.contains("\"anomalies\":["), "{json}");
    // The config object's coverage note is emitted; non-config objects carry null.
    assert!(
        json.contains("\"coverage_note\":\"rw via AclBackend (dir)\""),
        "{json}"
    );
    assert!(json.contains("\"coverage_note\":null"), "{json}");
    // The backend-limited config carries its reason; others carry null.
    assert!(
            json.contains("\"backend_limited\":\"single file in non-grantable parent; requires per-file-capable backend\""),
            "{json}"
        );
    assert!(json.contains("\"backend_limited\":null"), "{json}");
}

#[test]
fn render_coverage_json_escapes_special_chars() {
    // A key with a quote and a newline must not break the JSON document — the
    // shared json_str escaper handles it.
    let mut report = sample_report();
    report.objects[0].object.key = "/usr/sbin/x\"y\nz".to_owned();
    let json = render_coverage_json(&report);
    assert!(json.contains(r#""key":"/usr/sbin/x\"y\nz""#), "{json}");
    // Document remains single-line apart from the trailing newline the renderer
    // appends (no raw newline leaked into the body).
    assert_eq!(json.matches('\n').count(), 1, "{json}");
}

#[test]
fn parse_classes_parses_and_rejects_unknown() {
    let got = parse_classes("sudo_bin, group ,setuid").unwrap();
    assert_eq!(
        got,
        vec![
            SurfaceClass::SudoBin,
            SurfaceClass::Group,
            SurfaceClass::Setuid
        ]
    );
    // Duplicates collapse.
    assert_eq!(
        parse_classes("unit,unit").unwrap(),
        vec![SurfaceClass::Unit]
    );
    // Unknown token is a hard error (fail closed).
    assert!(parse_classes("sudo_bin,bogus").is_err());
    // A non-empty spec that yields zero classes is a hard error rather than a
    // silent widen to "all classes" — empty string and bare separators both
    // fail closed.
    assert!(parse_classes("").is_err());
    assert!(parse_classes(",").is_err());
    assert!(parse_classes("  ").is_err());
    assert!(parse_classes(" , , ").is_err());
}

// ---- catalog which-grants (reverse lookup) ----

fn sudo_match(perm: &str, detail: &str) -> coverage::GrantMatch {
    coverage::GrantMatch {
        permission: perm.to_owned(),
        target: coverage::GrantTarget::Account(perm.to_owned()),
        kind: coverage::GrantKind::Sudo,
        detail: detail.to_owned(),
        access: None,
        recursive: None,
        backend: None,
        risk: Some(Risk::EscalationCapable),
    }
}

fn file_match(perm: &str, path: &str) -> coverage::GrantMatch {
    coverage::GrantMatch {
        permission: perm.to_owned(),
        target: coverage::GrantTarget::Account(perm.to_owned()),
        kind: coverage::GrantKind::File,
        detail: path.to_owned(),
        access: Some(crate::catalog::Access::Rw),
        recursive: Some(true),
        backend: Some("AclBackend".to_owned()),
        risk: Some(Risk::Contained),
    }
}

/// A group-target sudo match — reached through `%group` sudoers; `group` is
/// the inheriting group.
fn group_sudo_match(group: &str, detail: &str) -> coverage::GrantMatch {
    coverage::GrantMatch {
        permission: group.to_owned(),
        target: coverage::GrantTarget::Group(group.to_owned()),
        kind: coverage::GrantKind::Sudo,
        detail: detail.to_owned(),
        access: None,
        recursive: None,
        backend: None,
        risk: None,
    }
}

/// A group-target file match — reached through a `g:group` ACL.
fn group_file_match(group: &str, path: &str) -> coverage::GrantMatch {
    coverage::GrantMatch {
        permission: group.to_owned(),
        target: coverage::GrantTarget::Group(group.to_owned()),
        kind: coverage::GrantKind::File,
        detail: path.to_owned(),
        access: Some(crate::catalog::Access::Rw),
        recursive: Some(true),
        backend: Some("AclBackend".to_owned()),
        risk: None,
    }
}

#[test]
fn render_which_grants_human_groups_matches() {
    let matches = vec![
        sudo_match("network-admin", "/usr/sbin/ip link set"),
        file_match("ssh-edit", "/etc/ssh"),
    ];
    let text = render_which_grants_human("/usr/sbin/ip", &matches);
    assert!(text.contains("/usr/sbin/ip granted by:"), "{text}");
    assert!(
        text.contains("network-admin — via sudo: /usr/sbin/ip link set [escalation-capable]"),
        "{text}"
    );
    assert!(
        text.contains("ssh-edit — via file (rw): /etc/ssh, recursive (AclBackend) [contained]"),
        "{text}"
    );
}

#[test]
fn render_which_grants_human_group_matches() {
    // Group matches render the group mechanism (%group sudoers / g:group ACL)
    // and name the inheriting group; account output is unchanged (covered by
    // render_which_grants_human_groups_matches above).
    let matches = vec![
        group_sudo_match("netops", "/usr/sbin/ip link set"),
        group_file_match("netops", "/etc/net"),
    ];
    let text = render_which_grants_human("/usr/sbin/ip", &matches);
    assert!(
        text.contains("netops — via %group sudoers (netops): /usr/sbin/ip link set"),
        "{text}"
    );
    assert!(
        text.contains("netops — via g:group ACL (netops) (rw): /etc/net, recursive (AclBackend)"),
        "{text}"
    );
}

#[test]
fn render_which_grants_json_distinguishes_group_target() {
    let matches = vec![
        sudo_match("network-admin", "/usr/sbin/ip link set"),
        group_sudo_match("netops", "/usr/sbin/ip route"),
    ];
    let json = render_which_grants_json(&matches);
    // Account match carries target=account, group=null.
    assert!(json.contains("\"target\":\"account\""), "{json}");
    // Group match carries target=group and the group name.
    assert!(json.contains("\"target\":\"group\""), "{json}");
    assert!(json.contains("\"group\":\"netops\""), "{json}");
    assert!(json.contains("\"group\":null"), "{json}");
}

#[test]
fn render_which_grants_human_no_match_message() {
    let text = render_which_grants_human("/usr/bin/nope", &[]);
    assert_eq!(text, "no permission grants access to /usr/bin/nope\n");
}

#[test]
fn render_which_grants_json_shape() {
    let matches = vec![
        sudo_match("network-admin", "/usr/sbin/ip link set"),
        file_match("ssh-edit", "/etc/ssh"),
    ];
    let json = render_which_grants_json(&matches);
    assert!(json.starts_with('['), "{json}");
    assert!(json.contains("\"permission\":\"network-admin\""), "{json}");
    assert!(json.contains("\"kind\":\"sudo\""), "{json}");
    assert!(
        json.contains("\"detail\":\"/usr/sbin/ip link set\""),
        "{json}"
    );
    // A sudo match carries null access/recursive/backend.
    assert!(json.contains("\"access\":null"), "{json}");
    assert!(json.contains("\"recursive\":null"), "{json}");
    // A file match carries concrete access/recursive/backend.
    assert!(json.contains("\"kind\":\"file\""), "{json}");
    assert!(json.contains("\"access\":\"rw\""), "{json}");
    assert!(json.contains("\"recursive\":true"), "{json}");
    assert!(json.contains("\"backend\":\"AclBackend\""), "{json}");
    assert!(json.contains("\"risk\":\"contained\""), "{json}");
}

#[test]
fn render_which_grants_json_empty_is_empty_array() {
    assert_eq!(render_which_grants_json(&[]), "[]\n");
}

#[test]
fn build_grant_sources_skips_templated_and_unresolvable() {
    // One concrete sudo perm, one templated (skipped because its {unit} is
    // unfilled with no role instance). build_grant_sources keeps only concrete.
    let tmp = tempfile::tempdir().unwrap();
    let (_decl, catalog_root) = compile_fixture(
        tmp.path(),
        "[payload]\npermissions = []\n",
        &[
            (
                "linux",
                "network-admin",
                "id = \"network-admin\"\nsudo = [\"/usr/sbin/ip\"]\n",
            ),
            (
                "linux",
                "service-restart",
                "id = \"service-restart\"\nsudo = [\"/usr/bin/systemctl restart {unit}\"]\n",
            ),
        ],
    );
    let catalog = LiveCatalog::new(vec![catalog_root]);
    let os = OsTarget::new("linux", "debian", None).unwrap();
    let ctx = ResolveCtx::default();
    let sources = build_grant_sources(&catalog, &os, &ctx).unwrap();
    // network-admin contributes a concrete command; service-restart's only
    // command is templated and dropped, so it contributes nothing and is omitted.
    assert!(sources
        .iter()
        .any(|s| s.id == "network-admin" && s.sudo.iter().any(|c| c == "/usr/sbin/ip")));
    assert!(
        !sources.iter().any(|s| s.id == "service-restart"),
        "a perm whose only grant is templated must be omitted: {sources:?}"
    );
}

#[test]
fn build_group_grant_sources_emits_group_targets() {
    // A declaration binding a role to a group yields a Group-target source
    // carrying the group's sudo + file grants; a group with no grants is
    // omitted.
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("roles");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(
            store.join("netops.toml"),
            "role = \"netops\"\nversion = 1\nos = \"linux\"\nname = \"netops\"\nlevel = 5\n[payload]\npermissions = [\"net-admin\"]\n",
        )
        .unwrap();
    let catalog_root = tmp.path().join("permissions");
    std::fs::create_dir_all(catalog_root.join("linux")).unwrap();
    std::fs::write(
            catalog_root.join("linux").join("net-admin.toml"),
            "id = \"net-admin\"\nsudo = [\"/usr/sbin/ip\"]\n\n[[file]]\npath = \"/etc/net\"\naccess = \"rw\"\nrecursive = true\n",
        )
        .unwrap();
    let decl_text = format!(
            "version = 1\nrole_store = \"{}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n\
             [[group]]\nname = \"netops\"\ngid = 8020\n\
             [[group]]\nname = \"empty-grp\"\ngid = 8021\n\
             [[role_group]]\nrole = \"netops\"\ngroup = \"netops\"\n",
            store.display()
        );
    let decl = Declaration::parse(&decl_text).unwrap();
    let catalog = LiveCatalog::new(vec![catalog_root]);
    let os = OsTarget::new("linux", "debian", None).unwrap();
    let ctx = ResolveCtx::default();
    let inputs = CompileInputs {
        catalog: &catalog,
        os: &os,
        ctx: &ctx,
    };

    let sources = build_group_grant_sources(&decl, &inputs).unwrap();
    // The bound group is a Group-target source with the role's grants.
    let g = sources
        .iter()
        .find(|s| s.id == "netops")
        .expect("group source for bound group");
    assert_eq!(g.target, coverage::GrantTarget::Group("netops".to_owned()));
    assert!(g.sudo.iter().any(|c| c == "/usr/sbin/ip"));
    assert!(g.file_grants.iter().any(|fg| fg.path == "/etc/net"));
    // The grantless group is omitted.
    assert!(
        !sources.iter().any(|s| s.id == "empty-grp"),
        "a group with no grants must be omitted: {sources:?}"
    );
}

#[test]
fn run_which_grants_finds_match_and_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let (_decl, catalog_root) = compile_fixture(
        tmp.path(),
        "[payload]\npermissions = []\n",
        &[(
            "linux",
            "network-admin",
            "id = \"network-admin\"\nsudo = [\"/usr/sbin/ip link\"]\n",
        )],
    );
    let code = run_which_grants(WhichGrantsOpts {
        arg: "/usr/sbin/ip".to_owned(),
        json: false,
        os_target: Some("linux-debian".to_owned()),
        catalog_roots: vec![catalog_root],
        declaration: None,
    });
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
}

#[test]
fn run_which_grants_no_match_still_exits_zero() {
    // Even when nothing grants the arg, the query succeeds (exit 0).
    let tmp = tempfile::tempdir().unwrap();
    let (_decl, catalog_root) = compile_fixture(
        tmp.path(),
        "[payload]\npermissions = []\n",
        &[(
            "linux",
            "network-admin",
            "id = \"network-admin\"\nsudo = [\"/usr/sbin/ip\"]\n",
        )],
    );
    let code = run_which_grants(WhichGrantsOpts {
        arg: "/usr/bin/nonexistent".to_owned(),
        json: true,
        os_target: Some("linux-debian".to_owned()),
        catalog_roots: vec![catalog_root],
        declaration: None,
    });
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
}

#[test]
fn run_show_over_tempdir_with_l10n_renders_localized() {
    let tmp = tempfile::tempdir().unwrap();
    let (decl, catalog_root) = compile_fixture(
        tmp.path(),
        "[payload]\npermissions = [\"net-admin\"]\n",
        &[(
            "linux",
            "net-admin",
            "id = \"net-admin\"\nrisk = \"escalation-capable\"\ngroups = [\"netdev\"]\n",
        )],
    );
    // l10n tree under the SAME root: <root>/l10n/ru/network.toml.
    let l10n_dir = catalog_root.join("l10n").join("ru");
    std::fs::create_dir_all(&l10n_dir).unwrap();
    std::fs::write(
        l10n_dir.join("network.toml"),
        "[net-admin]\ntitle = \"Управление сетью\"\n",
    )
    .unwrap();

    // Drive the public entry point; it reads the real env for LANG, but
    // explicit --lang ru wins regardless of the host env.
    let code = run_show(ShowOpts {
        role: "oper",
        declaration: &decl,
        catalog_roots: vec![catalog_root],
        os_target: Some("linux-debian"),
        lang: Some("ru"),
        framework: None,
        framework_roots: vec![],
        format: None,
    });
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
}

// ---- framework cross-reference (slices 3 & 4) ----

/// Build an artificial framework tree under `<dir>/frameworks/` and load it.
/// Mirrors the helper style in `framework.rs` tests: a `framework.toml`
/// manifest, `mappings/*.toml`, and an optional `controls.toml`. Returns the
/// loaded set over a flat OS target (enough for flat frameworks).
fn load_fw_tree(
    dir: &Path,
    manifests: &[(&str, &str)],
    mappings: &[(&str, &str)],
    controls: &[(&str, &str)],
) -> LoadedFrameworks {
    let root = dir.join("frameworks");
    for (relpath, body) in manifests.iter().chain(mappings).chain(controls) {
        let path = root.join(relpath);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, body).unwrap();
    }
    let os = OsTarget::new("linux", "debian", None).unwrap();
    framework::load_frameworks(&[root], &os).unwrap()
}

/// A `pci-dss` flat framework: maps `net-admin → 1.1, 1.2` and `log-read →
/// 10.1`; `legacy` (not mapped by any role permission here) exists too. The
/// structural `controls.toml` flags `1.1`/`1.2`/`10.1`/`9.9` owned and `2.1`
/// inherited; `9.9` is owned-but-uncovered (the gap). Control *titles* live in
/// the framework l10n tree (`l10n/{en,ru}/controls.toml`), never inline in the
/// structural file — so the title a report shows is resolved through l10n.
fn pci_dss_tree(dir: &Path) -> LoadedFrameworks {
    load_fw_tree(
            dir,
            &[(
                "pci-dss/framework.toml",
                "id = \"pci-dss\"\nversion = \"4.0\"\ntitle = \"PCI DSS\"\ndimension = \"flat\"\nprovides = [\"crossref\", \"controls\"]\n",
            )],
            &[
                ("pci-dss/mappings/a.toml", "[net-admin]\nsatisfies = [\"1.1\", \"1.2\"]\n"),
                ("pci-dss/mappings/b.toml", "[log-read]\nsatisfies = [\"10.1\"]\n"),
            ],
            &[
                (
                    "pci-dss/controls.toml",
                    "[\"1.1\"]\nowned = true\ndomain = \"Network\"\n\
                     [\"1.2\"]\nowned = true\n\
                     [\"2.1\"]\nowned = false\n\
                     [\"10.1\"]\nowned = true\n\
                     [\"9.9\"]\nowned = true\n",
                ),
                (
                    "pci-dss/l10n/en/controls.toml",
                    "[\"1.1\"]\ntitle = \"Firewall\"\n\
                     [\"1.2\"]\ntitle = \"Default deny\"\n\
                     [\"2.1\"]\ntitle = \"No vendor defaults\"\n\
                     [\"10.1\"]\ntitle = \"Audit logging\"\n\
                     [\"9.9\"]\ntitle = \"Uncovered owned\"\n",
                ),
            ],
        )
}

fn show_role() -> CompiledRole {
    CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![
            compiled_perm("net-admin", None, vec![], vec![]),
            // unmapped: present in the role but absent from the framework.
            compiled_perm("disk-admin", None, vec![], vec![]),
        ],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    }
}

// --- SLICE 3 ---

#[test]
fn show_framework_human_shows_controls_provenance_and_no_mapping() {
    let tmp = tempfile::tempdir().unwrap();
    let loaded = pci_dss_tree(tmp.path());
    let sel = FrameworkSelection::resolve("pci-dss", &loaded);
    let out = render_show_framework_human(&show_role(), &sel, &loaded);
    // Mapped permission shows its controls and provenance file path.
    assert!(out.contains("permission net-admin:"), "{out}");
    assert!(out.contains("✓ satisfies: 1.1, 1.2"), "{out}");
    assert!(out.contains("via pci-dss"), "{out}");
    assert!(out.contains("a.toml"), "{out}");
    // Unmapped permission carries the explicit marker, never omitted.
    assert!(out.contains("permission disk-admin (no mapping)"), "{out}");
    // Version stamp present in the human header too.
    assert!(out.contains("framework pci-dss (4.0)"), "{out}");
}

#[test]
fn show_framework_all_iterates_every_framework() {
    let tmp = tempfile::tempdir().unwrap();
    // Two frameworks in the tree.
    let loaded = load_fw_tree(
        tmp.path(),
        &[
            (
                "pci-dss/framework.toml",
                "id = \"pci-dss\"\nversion = \"4.0\"\ntitle = \"PCI\"\ndimension = \"flat\"\n",
            ),
            (
                "soc2/framework.toml",
                "id = \"soc2\"\nversion = \"2\"\ntitle = \"SOC 2\"\ndimension = \"flat\"\n",
            ),
        ],
        &[
            (
                "pci-dss/mappings/a.toml",
                "[net-admin]\nsatisfies = [\"1.1\"]\n",
            ),
            (
                "soc2/mappings/a.toml",
                "[net-admin]\nsatisfies = [\"CC6.1\"]\n",
            ),
        ],
        &[],
    );
    let sel = FrameworkSelection::resolve("all", &loaded);
    assert_eq!(sel.ids, vec!["pci-dss".to_owned(), "soc2".to_owned()]);
    let out = render_show_framework_human(&show_role(), &sel, &loaded);
    assert!(out.contains("framework pci-dss"), "{out}");
    assert!(out.contains("framework soc2"), "{out}");
    assert!(out.contains("1.1"), "{out}");
    assert!(out.contains("CC6.1"), "{out}");
}

#[test]
fn show_framework_json_has_version_stamp_and_mapped_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let loaded = pci_dss_tree(tmp.path());
    let sel = FrameworkSelection::resolve("pci-dss", &loaded);
    let out = render_show_framework_json(&show_role(), &sel, &loaded);
    // Version stamp (id + version) MUST be present.
    assert!(out.contains("\"id\":\"pci-dss\""), "{out}");
    assert!(out.contains("\"version\":\"4.0\""), "{out}");
    // Mapped + unmapped permissions both present, with the mapped flag.
    assert!(out.contains("\"permission\":\"net-admin\""), "{out}");
    assert!(out.contains("\"satisfies\":[\"1.1\",\"1.2\"]"), "{out}");
    assert!(out.contains("\"mapped\":true"), "{out}");
    assert!(out.contains("\"permission\":\"disk-admin\""), "{out}");
    assert!(out.contains("\"mapped\":false"), "{out}");
    // Well-formed: balanced braces, single trailing newline.
    assert!(out.ends_with("}\n"), "{out}");
}

#[test]
fn show_permissions_json_without_framework_has_no_frameworks_array() {
    let out = render_show_permissions_json(&show_role());
    assert!(out.contains("\"role\":\"oper\""), "{out}");
    assert!(
        out.contains("\"permissions\":[\"net-admin\",\"disk-admin\"]"),
        "{out}"
    );
    // No framework stamp when no framework was requested.
    assert!(!out.contains("frameworks"), "{out}");
}

// --- SLICE 4 ---

#[test]
fn framework_list_human_and_json_show_version_and_provides() {
    let tmp = tempfile::tempdir().unwrap();
    let loaded = pci_dss_tree(tmp.path());
    let human = render_framework_list_human(&loaded);
    assert!(human.contains("pci-dss 4.0"), "{human}");
    assert!(human.contains("provides: crossref, controls"), "{human}");
    let json = render_framework_list_json(&loaded);
    assert!(json.contains("\"id\":\"pci-dss\""), "{json}");
    assert!(json.contains("\"version\":\"4.0\""), "{json}");
    assert!(
        json.contains("\"provides\":[\"crossref\",\"controls\"]"),
        "{json}"
    );
}

#[test]
fn framework_list_empty_reports_none() {
    let tmp = tempfile::tempdir().unwrap();
    // An empty tree (no frameworks dir created) → empty load.
    let loaded = load_fw_tree(tmp.path(), &[], &[], &[]);
    assert_eq!(
        render_framework_list_human(&loaded),
        "no frameworks installed\n"
    );
    assert_eq!(render_framework_list_json(&loaded), "{\"frameworks\":[]}\n");
}

#[test]
fn framework_coverage_computes_owned_covered_gap_and_out_of_domain() {
    let tmp = tempfile::tempdir().unwrap();
    let loaded = pci_dss_tree(tmp.path());
    let cov = compute_framework_coverage(&loaded, "pci-dss");
    // Owned + covered: 1.1, 1.2, 10.1 (all owned and referenced by a mapping).
    assert_eq!(cov.covered, vec!["1.1", "1.2", "10.1"]);
    // Owned but never mapped → the gap.
    assert_eq!(cov.gap, vec!["9.9"]);
    // owned = false → out-of-domain, NOT counted in the gap.
    assert_eq!(cov.out_of_domain, vec!["2.1"]);
    assert!(!cov.gap.contains(&"2.1".to_owned()));
}

#[test]
fn framework_coverage_json_has_stamp_and_arrays() {
    let tmp = tempfile::tempdir().unwrap();
    let loaded = pci_dss_tree(tmp.path());
    let cov = compute_framework_coverage(&loaded, "pci-dss");
    let json = render_framework_coverage_json("pci-dss", &loaded, &cov);
    assert!(json.contains("\"id\":\"pci-dss\""), "{json}");
    assert!(json.contains("\"version\":\"4.0\""), "{json}");
    assert!(json.contains("\"gap\":[\"9.9\"]"), "{json}");
    assert!(json.contains("\"uncovered\":[\"9.9\"]"), "{json}");
    assert!(json.contains("\"out_of_domain\":[\"2.1\"]"), "{json}");
    assert!(
        json.contains("\"covered\":[\"1.1\",\"1.2\",\"10.1\"]"),
        "{json}"
    );
    assert!(json.ends_with("}\n"), "{json}");
}

#[test]
fn framework_show_human_lists_controls_and_owned_stats() {
    let tmp = tempfile::tempdir().unwrap();
    let loaded = pci_dss_tree(tmp.path());
    let out = render_framework_show_human("pci-dss", &loaded, "en");
    assert!(out.contains("framework pci-dss (4.0)"), "{out}");
    // Owned/covered annotations per control.
    assert!(out.contains("1.1 [owned] [covered]"), "{out}");
    assert!(out.contains("2.1 [inherited]"), "{out}");
    assert!(out.contains("9.9 [owned] [uncovered]"), "{out}");
    // Title resolved from the en l10n tree (the structural controls.toml has none).
    assert!(out.contains("— Firewall"), "{out}");
    // Owned coverage: 4 owned (1.1,1.2,10.1,9.9), 3 covered, 1 uncovered.
    assert!(
        out.contains("3/4 owned controls covered (1 uncovered)"),
        "{out}"
    );
}

#[test]
fn framework_show_resolves_titles_per_locale_with_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    // Structural controls.toml (no titles); ru titles one control, en the other.
    // 9.9 is untranslated in any locale → must fall back to the bare id.
    let loaded = load_fw_tree(
        tmp.path(),
        &[(
            "pci-dss/framework.toml",
            "id = \"pci-dss\"\nversion = \"4.0\"\ntitle = \"PCI DSS\"\ndimension = \"flat\"\nprovides = [\"crossref\", \"controls\"]\n",
        )],
        &[("pci-dss/mappings/a.toml", "[net-admin]\nsatisfies = [\"1.1\"]\n")],
        &[
            (
                "pci-dss/controls.toml",
                "[\"1.1\"]\nowned = true\n[\"9.9\"]\nowned = true\n",
            ),
            (
                "pci-dss/l10n/ru/controls.toml",
                "[\"1.1\"]\ntitle = \"Межсетевой экран\"\n",
            ),
            (
                "pci-dss/l10n/en/controls.toml",
                "[\"1.1\"]\ntitle = \"Firewall\"\n",
            ),
        ],
    );

    // ru requested → Russian title for 1.1; 9.9 untranslated → bare id.
    let ru = render_framework_show_human("pci-dss", &loaded, "ru");
    assert!(ru.contains("— Межсетевой экран"), "{ru}");
    assert!(ru.contains("9.9 [owned] [uncovered] — 9.9"), "{ru}");

    // zh requested but absent → en fallback for 1.1.
    let zh = render_framework_show_human("pci-dss", &loaded, "zh");
    assert!(zh.contains("— Firewall"), "{zh}");

    // JSON honors the locale too (ru title for 1.1).
    let json = render_framework_show_json("pci-dss", &loaded, "ru");
    assert!(json.contains("\"title\":\"Межсетевой экран\""), "{json}");
}

#[test]
fn run_framework_list_over_tempdir_tree() {
    let tmp = tempfile::tempdir().unwrap();
    // Materialize a tree and drive the public entry point against it.
    let _ = pci_dss_tree(tmp.path());
    let root = tmp.path().join("frameworks");
    let code = run_framework_list(vec![root], Some("linux-debian".to_owned()), false);
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
}

#[test]
fn run_framework_coverage_missing_framework_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let _ = pci_dss_tree(tmp.path());
    let root = tmp.path().join("frameworks");
    let code = run_framework_coverage("nope", vec![root], Some("linux-debian".to_owned()), true);
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
}

#[test]
fn framework_lint_human_empty_is_no_findings() {
    assert_eq!(
        render_framework_lint_human(&[]),
        "framework lint: no findings\n"
    );
}

#[test]
fn framework_lint_human_and_json_render_warning() {
    let findings = vec![framework::FrameworkLint {
        code: "orphaned-mapping",
        severity: framework::FrameworkLintSeverity::Warning,
        message: "x".into(),
    }];
    let human = render_framework_lint_human(&findings);
    assert!(human.contains("WARNING [orphaned-mapping]"), "{human}");
    let json = render_framework_lint_json(&findings);
    assert!(json.contains("\"severity\":\"warning\""), "{json}");
    assert!(json.contains("\"code\":\"orphaned-mapping\""), "{json}");
}

#[test]
fn framework_lint_id_collision_renders_error() {
    let findings = vec![framework::FrameworkLint {
        code: "id-collision",
        severity: framework::FrameworkLintSeverity::Error,
        message: "collision".into(),
    }];
    let human = render_framework_lint_human(&findings);
    assert!(human.contains("ERROR [id-collision]"), "{human}");
    let json = render_framework_lint_json(&findings);
    assert!(json.contains("\"severity\":\"error\""), "{json}");
}

#[test]
fn run_framework_lint_over_tempdir_tree_succeeds_with_warnings() {
    let tmp = tempfile::tempdir().unwrap();
    // Materialize the pci-dss tree: its mapped perms (net-admin, log-read) are
    // absent from an empty catalog → orphaned-mapping WARNINGS, no errors.
    let _ = pci_dss_tree(tmp.path());
    let fw_root = tmp.path().join("frameworks");
    // A fresh empty catalog root (no permission dirs).
    let cat_root = tmp.path().join("empty-catalog");
    std::fs::create_dir_all(&cat_root).unwrap();
    let code = run_framework_lint(
        vec![fw_root],
        vec![cat_root],
        Some("linux-debian".to_owned()),
        false,
    );
    // Warnings do not gate: exit SUCCESS.
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
}

/// Build a framework tree whose `controls.toml` defines `7.2.2` and `7.2.4` with
/// the supplied l10n files, then render the CLI lint's `control-missing-title`
/// findings over it as JSON so the emitted codes/messages can be asserted.
///
/// The full `run_framework_lint` wrapper prints to stdout, so the test exercises
/// it once for its exit code (a WARNING must not gate → SUCCESS) and asserts on the
/// same renderer + finding-builder the wrapper delegates to, fed the same loaded
/// tree. The catalog root is empty — the title-drift check is independent of
/// catalog coverage.
fn run_framework_lint_title_json_over(dir: &Path, controls: &[(&str, &str)]) -> String {
    let manifests = &[(
        "pci-dss/framework.toml",
        "id = \"pci-dss\"\nversion = \"4.0\"\ntitle = \"PCI DSS\"\ndimension = \"flat\"\nprovides = [\"crossref\", \"controls\"]\n",
    )];
    let mappings = &[(
        "pci-dss/mappings/a.toml",
        "[net-admin]\nsatisfies = [\"7.2.2\"]\n",
    )];
    let loaded = load_fw_tree(dir, manifests, mappings, controls);
    let fw_root = dir.join("frameworks");
    let cat_root = dir.join("empty-catalog");
    std::fs::create_dir_all(&cat_root).unwrap();
    let code = run_framework_lint(
        vec![fw_root],
        vec![cat_root],
        Some("linux-debian".to_owned()),
        true,
    );
    // control-missing-title is a WARNING, so the run still exits 0.
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    render_framework_lint_json(&control_missing_title_findings(&loaded))
}

#[test]
fn run_framework_lint_emits_control_missing_title_for_untranslated_id() {
    let tmp = tempfile::tempdir().unwrap();
    let json = run_framework_lint_title_json_over(
        tmp.path(),
        &[
            (
                "pci-dss/controls.toml",
                "[\"7.2.2\"]\nowned = true\n[\"7.2.4\"]\nowned = true\n",
            ),
            // en translates 7.2.2 only; 7.2.4 has no title in any locale.
            (
                "pci-dss/l10n/en/controls.toml",
                "[\"7.2.2\"]\ntitle = \"Least privilege\"\n",
            ),
        ],
    );
    assert!(
        json.contains("\"code\":\"control-missing-title\""),
        "{json}"
    );
    // The finding names the framework id and the offending control id.
    assert!(json.contains("pci-dss"), "{json}");
    assert!(json.contains("7.2.4"), "{json}");
    // The translated control must NOT be flagged.
    assert!(
        !json.contains("7.2.2\\\" has no title"),
        "translated control wrongly flagged: {json}"
    );
}

#[test]
fn run_framework_lint_no_control_missing_title_when_fully_translated() {
    let tmp = tempfile::tempdir().unwrap();
    let json = run_framework_lint_title_json_over(
        tmp.path(),
        &[
            (
                "pci-dss/controls.toml",
                "[\"7.2.2\"]\nowned = true\n[\"7.2.4\"]\nowned = true\n",
            ),
            // Every control has an en title → no control-missing-title finding.
            (
                "pci-dss/l10n/en/controls.toml",
                "[\"7.2.2\"]\ntitle = \"Least privilege\"\n[\"7.2.4\"]\ntitle = \"Access review\"\n",
            ),
        ],
    );
    assert!(
        !json.contains("control-missing-title"),
        "fully-translated framework must not flag a missing title: {json}"
    );
}

#[test]
fn show_framework_human_prints_polarity() {
    let tmp = tempfile::tempdir().unwrap();
    let loaded = load_fw_tree(
            tmp.path(),
            &[(
                "pci-dss/framework.toml",
                "id = \"pci-dss\"\nversion = \"4.0\"\ntitle = \"PCI\"\ndimension = \"flat\"\n",
            )],
            &[(
                "pci-dss/mappings/a.toml",
                "[net-admin]\nsatisfies = [\"1.1\"]\n[log-admin]\nrisk = [\"10.5.1\"]\n[audit]\nrelated = [\"10.2.1\"]\n",
            )],
            &[],
        );
    let role = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![
            compiled_perm("net-admin", None, vec![], vec![]),
            compiled_perm("log-admin", None, vec![], vec![]),
            compiled_perm("audit", None, vec![], vec![]),
            compiled_perm("ghost", None, vec![], vec![]),
        ],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    let sel = FrameworkSelection::resolve("pci-dss", &loaded);
    let out = render_show_framework_human(&role, &sel, &loaded);
    assert!(out.contains("✓ satisfies:"), "{out}");
    assert!(out.contains("⚠ risk:"), "{out}");
    assert!(out.contains("· related:"), "{out}");
    assert!(out.contains("permission ghost (no mapping)"), "{out}");
}

#[test]
fn show_framework_json_carries_each_polarity() {
    let tmp = tempfile::tempdir().unwrap();
    let loaded = load_fw_tree(
            tmp.path(),
            &[(
                "pci-dss/framework.toml",
                "id = \"pci-dss\"\nversion = \"4.0\"\ntitle = \"PCI\"\ndimension = \"flat\"\n",
            )],
            &[(
                "pci-dss/mappings/a.toml",
                "[net-admin]\nsatisfies = [\"1.1\"]\n[log-admin]\nrisk = [\"10.5.1\"]\n[audit]\nrelated = [\"10.2.1\"]\n",
            )],
            &[],
        );
    let role = CompiledRole {
        role: "oper".to_owned(),
        permissions: vec![
            compiled_perm("net-admin", None, vec![], vec![]),
            compiled_perm("log-admin", None, vec![], vec![]),
            compiled_perm("audit", None, vec![], vec![]),
        ],
        raw_groups: vec![],
        raw_sudo_role: None,
        raw_limits: Limits::default(),
    };
    let sel = FrameworkSelection::resolve("pci-dss", &loaded);
    let out = render_show_framework_json(&role, &sel, &loaded);
    assert!(out.contains("\"satisfies\":["), "{out}");
    assert!(out.contains("\"risk\":["), "{out}");
    assert!(out.contains("\"related\":["), "{out}");
    assert!(out.contains("\"id\":\"pci-dss\""), "{out}");
    assert!(out.contains("\"version\":"), "{out}");
}

#[test]
fn framework_risk_lists_controls_and_threats() {
    let tmp = tempfile::tempdir().unwrap();
    let loaded = load_fw_tree(
            tmp.path(),
            &[(
                "pci-dss/framework.toml",
                "id = \"pci-dss\"\nversion = \"4.0\"\ntitle = \"PCI\"\ndimension = \"flat\"\nprovides = [\"crossref\", \"controls\"]\n",
            )],
            &[("pci-dss/mappings/a.toml", "[log-admin]\nrisk = [\"10.5.1\"]\n")],
            &[
                ("pci-dss/controls.toml", "[\"10.5.1\"]\nowned = false\n"),
                ("pci-dss/l10n/en/controls.toml", "[\"10.5.1\"]\ntitle = \"Log integrity\"\n"),
            ],
        );
    let risk = compute_framework_risk(&loaded, "pci-dss");
    assert!(risk
        .controls
        .contains(&("10.5.1".to_owned(), vec!["log-admin".to_owned()])));
    let human = render_framework_risk_human("pci-dss", &loaded, &risk, "en");
    assert!(human.contains("⚠ 10.5.1"), "{human}");
    assert!(human.contains("[out-of-domain]"), "{human}");
    // Title resolved from the en l10n tree.
    assert!(human.contains("— Log integrity"), "{human}");
    assert!(human.contains("threatened by: log-admin"), "{human}");
    let json = render_framework_risk_json("pci-dss", &loaded, &risk);
    assert!(json.contains("\"id\":\"10.5.1\""), "{json}");
    assert!(json.contains("\"owned\":false"), "{json}");
    assert!(json.contains("\"threatened_by\":[\"log-admin\"]"), "{json}");
}

#[test]
fn framework_coverage_ignores_risk_and_related() {
    let tmp = tempfile::tempdir().unwrap();
    let loaded = load_fw_tree(
            tmp.path(),
            &[(
                "pci-dss/framework.toml",
                "id = \"pci-dss\"\nversion = \"4.0\"\ntitle = \"PCI\"\ndimension = \"flat\"\nprovides = [\"crossref\", \"controls\"]\n",
            )],
            &[("pci-dss/mappings/a.toml", "[log-admin]\nrisk = [\"7.2.2\"]\n")],
            &[("pci-dss/controls.toml", "[\"7.2.2\"]\nowned = true\n")],
        );
    let cov = compute_framework_coverage(&loaded, "pci-dss");
    assert!(!cov.covered.contains(&"7.2.2".to_owned()));
    assert!(cov.gap.contains(&"7.2.2".to_owned()));
}

#[test]
fn run_framework_risk_missing_framework_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let _ = pci_dss_tree(tmp.path());
    let root = tmp.path().join("frameworks");
    let code = run_framework_risk(
        "nope",
        vec![root],
        Some("linux-debian".to_owned()),
        None,
        true,
    );
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
}
