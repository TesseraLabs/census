//! The shipped example + packaged TOML files must parse through the REAL
//! parsers, not just validate against the golden schemas.
//!
//! `taplo check` (configured in `taplo.toml`) validates these files against the
//! generated JSON schemas, but taplo is an external CLI that may not be present
//! in every CI/dev environment — and a schema is only an approximation of what
//! the Rust parser accepts (path validation, the `replace`/`append` invariant,
//! namespace/location matching, the role-slice `[payload]` nesting, …). These
//! tests run each shipped file through the exact parser the binary uses, so a
//! file that drifts out of the format fails `cargo test` even with no taplo.
//!
//! Covered:
//!   - `examples/declaration.toml`     → `Declaration::parse`
//!   - `examples/roles/*.toml`         → `rolestore::read_composition` (the real role-slice parser,
//!     `[payload]`)
//!   - `share/permissions/<layer>/**`  → `LiveCatalog::read_layer` (parse + `validate` +
//!     namespace/location check)

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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use census::catalog::{
    resolve, resolve_with_params, Access, CatalogError, CatalogSource, LiveCatalog, OsTarget,
    ParamValue, ResolveCtx, ResolvedPermission, Risk,
};
use census::declaration::Declaration;
use census::rolestore::read_composition;

/// The census crate root (`CARGO_MANIFEST_DIR`), so the tests find the shipped
/// files regardless of the working directory the runner uses.
fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

#[test]
fn example_declaration_parses_through_real_parser() {
    let path = repo("examples/declaration.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    Declaration::parse(&text).unwrap_or_else(|e| {
        panic!(
            "shipped {} no longer parses as a Declaration: {e}",
            path.display()
        )
    });
}

#[test]
fn example_role_slices_parse_through_real_parser() {
    let store = repo("examples/roles");
    let mut count = 0usize;
    for entry in
        std::fs::read_dir(&store).unwrap_or_else(|e| panic!("cannot read {}: {e}", store.display()))
    {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let role = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("role slice has a file stem");
        // `read_composition` is the exact path the binary uses: it parses the
        // tolerant `Slice` shape and extracts the `[payload]` subset, including
        // the `PermissionRef` one-of (bare id string vs `{id, ...params}`).
        read_composition(&store, role).unwrap_or_else(|e| {
            panic!(
                "shipped role slice {} no longer parses: {e}",
                path.display()
            )
        });
        count += 1;
    }
    assert!(
        count > 0,
        "expected at least one example role slice under {}",
        store.display()
    );
}

#[test]
fn packaged_catalog_layers_parse_through_real_parser() {
    let perms = repo("share/permissions");
    // The catalog parser keys off OS-target layer directories (`linux`,
    // `linux-debian-12`, …). `l10n` is a sibling localization tree, NOT a
    // permission layer, so it is deliberately excluded — feeding it to the
    // permission parser would (correctly) fail, since its files are not
    // PermissionDefs. `read_layer` runs the real per-file parse + `validate` +
    // namespace/location check for every `*.toml` in the layer.
    let catalog = LiveCatalog::new(vec![perms.clone()]);
    let mut layers = 0usize;
    let mut records = 0usize;
    for entry in
        std::fs::read_dir(&perms).unwrap_or_else(|e| panic!("cannot read {}: {e}", perms.display()))
    {
        let path = entry.unwrap().path();
        if !path.is_dir() {
            continue;
        }
        let layer = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if layer == "l10n" {
            continue;
        }
        let defs = catalog
            .read_layer(layer)
            .unwrap_or_else(|e| panic!("packaged catalog layer {layer:?} no longer parses: {e}"));
        records += defs.len();
        layers += 1;
    }
    assert!(
        layers > 0,
        "expected at least one packaged catalog layer under {}",
        perms.display()
    );
    assert!(
        records > 0,
        "expected at least one packaged permission record"
    );
}

#[test]
fn packaged_frameworks_have_a_title_for_every_control() {
    use census::framework::{controls_missing_title, load_frameworks};
    use census::l10n::{L10nSource, LiveL10n, DEFAULT_LOCALE};

    // The shipped frameworks (cis-controls, pci-dss) must keep their structural
    // controls.toml and their independently-edited l10n title tree in lockstep: a
    // control with no title in ANY locale would render as the bare control id in
    // reports. This guards against that drift on the packaged data — the same
    // check `census framework lint` runs as a `control-missing-title` finding,
    // here asserted to produce NOTHING on the real tree (no false positive on
    // shipped data, and a real regression if a future edit drops a title).
    let frameworks_root = repo("share/frameworks");
    // A flat OS target is enough: the shipped frameworks' control SETS do not vary
    // by layer (only os-layered *mappings* would), so any valid target loads every
    // controls.toml.
    let os = census::catalog::OsTarget::new("linux", "debian", Some("12".to_owned()))
        .expect("valid os target");
    let loaded = load_frameworks(std::slice::from_ref(&frameworks_root), &os)
        .unwrap_or_else(|e| panic!("packaged frameworks no longer load: {e}"));

    assert!(
        !loaded.controls.is_empty(),
        "expected at least one packaged framework with a controls.toml under {}",
        frameworks_root.display()
    );

    for (fw, defs) in &loaded.controls {
        if defs.is_empty() {
            continue;
        }
        let dir = loaded
            .framework_dirs
            .get(fw)
            .unwrap_or_else(|| panic!("loaded framework {fw} has no recorded directory"));
        let l10n = LiveL10n::new(vec![dir.clone()]);
        let mut locales: Vec<String> = vec![DEFAULT_LOCALE.to_owned()];
        for loc in l10n.available_locales() {
            if !locales.iter().any(|l| l == &loc) {
                locales.push(loc);
            }
        }
        let locale_refs: Vec<&str> = locales.iter().map(String::as_str).collect();
        let ids: Vec<&str> = defs.keys().map(String::as_str).collect();
        let missing = controls_missing_title(&ids, &l10n, &locale_refs);
        assert!(
            missing.is_empty(),
            "packaged framework {fw} has control(s) with no title in any locale {locales:?}: {missing:?}"
        );
    }
}

/// Resolve the shipped `app-scope` bundle against the real packaged catalog with
/// the given `app` value(s), on `linux-debian-12`.
fn resolve_app_scope(app: ParamValue) -> Result<census::catalog::ResolvedPermission, CatalogError> {
    let catalog = LiveCatalog::new(vec![repo("share/permissions")]);
    let os = OsTarget::new("linux", "debian", Some("12".to_owned())).expect("valid os target");
    let mut params: BTreeMap<String, ParamValue> = BTreeMap::new();
    params.insert("app".to_owned(), app);
    resolve_with_params("app-scope", &params, &os, &catalog, &ResolveCtx::default())
        .map(|(resolved, _warnings)| resolved)
}

#[test]
fn packaged_app_scope_resolves_scalar_app_end_to_end() {
    // The curated app-scope bundle mixes its OWN file grants (/etc/<app> rw,
    // /var/log/<app> ro) with a parametrized include of service-control on the
    // same {app}. A single scalar app name must fill both: the bundle's own
    // templates AND the bound member, from one value.
    let resolved =
        resolve_app_scope(ParamValue::String("Supervisor".to_owned())).expect("app-scope resolves");

    // Bound service-control: every verb in both bare and `.service` form.
    let sudo: Vec<&str> = resolved.sudo.iter().map(|p| p.value.as_str()).collect();
    for expected in [
        "/usr/bin/systemctl start Supervisor",
        "/usr/bin/systemctl start Supervisor.service",
        "/usr/bin/systemctl stop Supervisor",
        "/usr/bin/systemctl stop Supervisor.service",
        "/usr/bin/systemctl restart Supervisor",
        "/usr/bin/systemctl restart Supervisor.service",
        "/usr/bin/systemctl reset-failed Supervisor",
        "/usr/bin/systemctl reset-failed Supervisor.service",
    ] {
        assert!(
            sudo.contains(&expected),
            "app-scope must emit `{expected}` via service-control; got {sudo:?}"
        );
    }

    // Bundle-own file grants, substituted by the same {app}.
    let paths: Vec<&str> = resolved
        .file_grants
        .iter()
        .map(|g| g.path.as_str())
        .collect();
    assert!(
        paths.contains(&"/etc/Supervisor"),
        "expected /etc/Supervisor grant; got {paths:?}"
    );
    assert!(
        paths.contains(&"/var/log/Supervisor"),
        "expected /var/log/Supervisor grant; got {paths:?}"
    );
}

#[test]
fn packaged_app_scope_fans_out_over_app_list() {
    // A LIST of app names fans the WHOLE bundle (own grants + bound member) out
    // per element — the per-app access set for both apps in one declaration.
    let resolved = resolve_app_scope(ParamValue::Array(vec![
        ParamValue::String("Supervisor".to_owned()),
        ParamValue::String("gateway".to_owned()),
    ]))
    .expect("app-scope resolves for a list");

    let sudo: Vec<&str> = resolved.sudo.iter().map(|p| p.value.as_str()).collect();
    for app in ["Supervisor", "gateway"] {
        assert!(
            sudo.contains(&format!("/usr/bin/systemctl restart {app}").as_str()),
            "expected a restart command for {app}; got {sudo:?}"
        );
    }

    let mut paths: Vec<&str> = resolved
        .file_grants
        .iter()
        .map(|g| g.path.as_str())
        .collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        vec![
            "/etc/Supervisor",
            "/etc/gateway",
            "/var/log/Supervisor",
            "/var/log/gateway",
        ],
        "list app must fan both /etc and /var/log grants per app"
    );
}

/// Resolve a packaged curated app package against the real catalog on
/// `linux-debian-12`, through `resolve_with_params` with an empty parameter map.
///
/// These packages are literal-bound (no role-facing parameters); their
/// `service-control`/`app-config-*` includes pin a fixed unit/app, so plain
/// `resolve` ALSO renders them eagerly (see `literal_bound_package_resolves_without_params`).
/// Going through `resolve_with_params` here exercises the same path the CLI uses.
fn resolve_app_package(id: &str) -> ResolvedPermission {
    let catalog = LiveCatalog::new(vec![repo("share/permissions")]);
    let os = OsTarget::new("linux", "debian", Some("12".to_owned())).expect("valid os target");
    let params: BTreeMap<String, ParamValue> = BTreeMap::new();
    resolve_with_params(id, &params, &os, &catalog, &ResolveCtx::default())
        .unwrap_or_else(|e| panic!("packaged {id} no longer resolves: {e}"))
        .0
}

#[test]
fn literal_bound_package_resolves_without_params() {
    // The coverage-regression guard: a literal-bound curated package (its
    // service-control / app-config-* includes pin a fixed unit/app, no role
    // `{param}`) must render its member grants under PLAIN `resolve()` — with NO
    // role parameters. Catalog-wide consumers (coverage / reverse-lookup) call
    // `resolve()` without params, so before eager literal-bound expansion these
    // concrete grants were silently missing for the whole curated catalog.
    let catalog = LiveCatalog::new(vec![repo("share/permissions")]);
    let os = OsTarget::new("linux", "debian", Some("12".to_owned())).expect("valid os target");

    // (id, the literal systemd unit it binds, the /etc config tree it grants).
    // The unit and config app are NOT always the namespace (zabbix-agent's unit is
    // `zabbix-agent` but its config app is `zabbix`), so they are stated explicitly.
    for (id, unit, etc) in [
        ("nginx.operate", "nginx", "/etc/nginx"),
        ("zabbix-agent.operate", "zabbix-agent", "/etc/zabbix"),
    ] {
        let (resolved, _warnings) = resolve(id, &os, &catalog, &ResolveCtx::default())
            .unwrap_or_else(|e| panic!("{id} must resolve without params: {e}"));

        // The bound service-control member must be EAGERLY expanded — its concrete
        // systemctl command is present, not deferred into bound_members.
        let sudo: Vec<&str> = resolved.sudo.iter().map(|p| p.value.as_str()).collect();
        assert!(
            sudo.contains(&format!("/usr/bin/systemctl restart {unit}").as_str()),
            "{id} under plain resolve() must emit the literal service-control command; got {sudo:?}"
        );

        // The member file grant (app-config-* on the fixed app) is present too.
        assert!(
            resolved.file_grants.iter().any(|g| g.path == etc),
            "{id} under plain resolve() must carry the {etc} grant; got {:?}",
            resolved
                .file_grants
                .iter()
                .map(|g| g.path.as_str())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn param_bound_package_stays_deferred_without_params() {
    // The counterpart: app-scope binds service-control on `{app}` — a bundle
    // param. Under plain `resolve()` (no `app`) it is correctly DEFERRED, so its
    // member sudo is NOT rendered; only `resolve_with_params` with a role-supplied
    // `app` renders it. This proves the literal-vs-param classification, not a
    // blanket eager expansion.
    let catalog = LiveCatalog::new(vec![repo("share/permissions")]);
    let os = OsTarget::new("linux", "debian", Some("12".to_owned())).expect("valid os target");

    let (deferred, _warnings) = resolve("app-scope", &os, &catalog, &ResolveCtx::default())
        .expect("app-scope resolves without params");
    assert!(
        deferred.sudo.is_empty(),
        "app-scope under plain resolve() must defer its {{app}}-bound member (no sudo); got {:?}",
        deferred
            .sudo
            .iter()
            .map(|p| p.value.as_str())
            .collect::<Vec<_>>()
    );

    // With the role param supplied, the same package renders the member grant.
    let mut params: BTreeMap<String, ParamValue> = BTreeMap::new();
    params.insert("app".to_owned(), ParamValue::String("gateway".to_owned()));
    let (rendered, _warnings) =
        resolve_with_params("app-scope", &params, &os, &catalog, &ResolveCtx::default())
            .expect("app-scope resolves with app param");
    let sudo: Vec<&str> = rendered.sudo.iter().map(|p| p.value.as_str()).collect();
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart gateway"),
        "app-scope with app=gateway must render the bound service-control; got {sudo:?}"
    );
}

/// The literal sudo command values of a resolved permission.
fn sudo_of(resolved: &ResolvedPermission) -> Vec<&str> {
    resolved.sudo.iter().map(|p| p.value.as_str()).collect()
}

/// The effective access on a given path, if the resolved permission grants it.
fn access_on(resolved: &ResolvedPermission, path: &str) -> Option<Access> {
    resolved
        .file_grants
        .iter()
        .find(|g| g.path == path)
        .map(|g| g.access)
}

/// The group names a resolved permission grants.
fn groups_of(resolved: &ResolvedPermission) -> Vec<&str> {
    resolved.groups.iter().map(|g| g.value.as_str()).collect()
}

#[test]
fn packaged_ssh_observe_is_read_only() {
    // ssh.observe must be strictly read-only: service-observe status/query only
    // (no start/stop/restart), and ro on /etc/ssh, never rw. The whole reason ssh
    // has no contained operate is that write to /etc/ssh is escalation (see
    // ssh.admin), so observe must not leak any mutation.
    let resolved = resolve_app_package("ssh.observe");

    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl status ssh"),
        "ssh.observe must allow status query; got {sudo:?}"
    );
    for forbidden in [
        "/usr/bin/systemctl start ssh",
        "/usr/bin/systemctl stop ssh",
        "/usr/bin/systemctl restart ssh",
    ] {
        assert!(
            !sudo.contains(&forbidden),
            "ssh.observe must NOT carry the mutating verb `{forbidden}`; got {sudo:?}"
        );
    }
    assert_eq!(
        access_on(&resolved, "/etc/ssh"),
        Some(Access::RO),
        "ssh.observe /etc/ssh must be read-only"
    );
}

#[test]
fn packaged_ssh_admin_is_escalation_capable_with_rw_etc_ssh() {
    // ssh.admin is the escalation showcase: it must be classed escalation-capable
    // (not contained) and grant rw on /etc/ssh — write to sshd_config is a path to
    // root login, which is exactly why it is admin and not a contained operate.
    let resolved = resolve_app_package("ssh.admin");

    assert_eq!(
        resolved.risk,
        Some(Risk::EscalationCapable),
        "ssh.admin must be escalation-capable, not contained; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/ssh"),
        Some(Access::RW),
        "ssh.admin must grant rw on /etc/ssh"
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart ssh"),
        "ssh.admin must carry service-control on the ssh unit; got {sudo:?}"
    );
}

#[test]
fn packaged_cups_operate_is_contained_ro_no_lpadmin() {
    // After the root-daemon re-audit, cups.operate is contained: lifecycle +
    // READ-ONLY config, no lpadmin group, no rw — because cupsd runs as root and
    // rw+lpadmin is a printer-backend RCE path that belongs in cups.admin.
    let resolved = resolve_app_package("cups.operate");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "cups.operate must be contained; got {:?}",
        resolved.risk
    );
    assert!(
        !groups_of(&resolved).contains(&"lpadmin"),
        "cups.operate must NOT grant lpadmin (that is admin); got {:?}",
        groups_of(&resolved)
    );
    assert_eq!(
        access_on(&resolved, "/etc/cups"),
        Some(Access::RO),
        "cups.operate /etc/cups must be read-only"
    );
}

#[test]
fn packaged_cups_admin_is_escalation_with_lpadmin_and_rw() {
    // cups.admin carries the escalation: rw /etc/cups + the lpadmin group, classed
    // escalation-capable (printer backend/filter runs as root).
    let resolved = resolve_app_package("cups.admin");

    assert_eq!(
        resolved.risk,
        Some(Risk::EscalationCapable),
        "cups.admin must be escalation-capable; got {:?}",
        resolved.risk
    );
    assert!(
        groups_of(&resolved).contains(&"lpadmin"),
        "cups.admin must grant the lpadmin group; got {:?}",
        groups_of(&resolved)
    );
    assert_eq!(
        access_on(&resolved, "/etc/cups"),
        Some(Access::RW),
        "cups.admin must grant rw on /etc/cups"
    );
}

#[test]
fn packaged_smartmontools_operate_is_contained_ro_config() {
    // After the root-daemon re-audit, smartmontools.operate is contained:
    // lifecycle + READ-ONLY config — rw is escalation (smartd -M exec runs a
    // script as root) and lives in smartmontools.admin.
    let resolved = resolve_app_package("smartmontools.operate");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "smartmontools.operate must be contained; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/smartd.conf"),
        Some(Access::RO),
        "smartmontools.operate /etc/smartd.conf must be read-only"
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart smartd"),
        "smartmontools.operate must carry service-control on the smartd unit; got {sudo:?}"
    );
}

#[test]
fn packaged_smartmontools_admin_is_escalation_with_rw() {
    // smartmontools.admin carries the escalation: rw /etc/smartd.conf, classed
    // escalation-capable (the -M exec directive runs a script as root).
    let resolved = resolve_app_package("smartmontools.admin");

    assert_eq!(
        resolved.risk,
        Some(Risk::EscalationCapable),
        "smartmontools.admin must be escalation-capable; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/smartd.conf"),
        Some(Access::RW),
        "smartmontools.admin must grant rw on /etc/smartd.conf"
    );
}

#[test]
fn packaged_nginx_operate_is_contained_ro_config() {
    // nginx.operate is contained: lifecycle + READ-ONLY config/logs. rw is
    // escalation (root master load_module) and lives in nginx.admin.
    let resolved = resolve_app_package("nginx.operate");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "nginx.operate must be contained; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/nginx"),
        Some(Access::RO),
        "nginx.operate /etc/nginx must be read-only"
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart nginx"),
        "nginx.operate must carry service-control on the nginx unit; got {sudo:?}"
    );
}

#[test]
fn packaged_nginx_admin_is_escalation_with_rw() {
    // nginx.admin carries the escalation: rw /etc/nginx, classed
    // escalation-capable (load_module loads a .so into the root master).
    let resolved = resolve_app_package("nginx.admin");

    assert_eq!(
        resolved.risk,
        Some(Risk::EscalationCapable),
        "nginx.admin must be escalation-capable; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/nginx"),
        Some(Access::RW),
        "nginx.admin must grant rw on /etc/nginx"
    );
}

#[test]
fn packaged_postgresql_admin_is_escalation_with_rw() {
    // postgresql.admin is escalation-capable + rw /etc/postgresql (pg_hba trust /
    // shared_preload_libraries is the data-root / code-load path), even though the
    // daemon itself runs as the non-root postgres user.
    let resolved = resolve_app_package("postgresql.admin");

    assert_eq!(
        resolved.risk,
        Some(Risk::EscalationCapable),
        "postgresql.admin must be escalation-capable; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/postgresql"),
        Some(Access::RW),
        "postgresql.admin must grant rw on /etc/postgresql"
    );
}

#[test]
fn packaged_redis_uses_redis_server_unit_and_operate_is_contained_rw() {
    // Redis: the Debian unit is `redis-server`, NOT `redis`. The daemon runs as
    // the non-root redis user, so operate MAY carry rw config and stay contained —
    // there is no redis.admin tier.
    let resolved = resolve_app_package("redis.operate");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "redis.operate must be contained; got {:?}",
        resolved.risk
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart redis-server"),
        "redis must use the Debian unit name redis-server; got {sudo:?}"
    );
    assert!(
        !sudo.contains(&"/usr/bin/systemctl restart redis"),
        "redis must NOT use the bare `redis` unit name; got {sudo:?}"
    );
    assert_eq!(
        access_on(&resolved, "/etc/redis"),
        Some(Access::RW),
        "redis.operate must grant rw on /etc/redis (non-root daemon, contained)"
    );
}

#[test]
fn packaged_zabbix_observe_is_read_only() {
    // The observe package must be strictly read-only: service-observe's
    // status/query verbs only — no start/stop/restart from service-control — and
    // ro file access, never rw, on both the config and log trees.
    let resolved = resolve_app_package("zabbix-agent.observe");

    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl status zabbix-agent"),
        "observe must allow status query; got {sudo:?}"
    );
    for forbidden in [
        "/usr/bin/systemctl start zabbix-agent",
        "/usr/bin/systemctl stop zabbix-agent",
        "/usr/bin/systemctl restart zabbix-agent",
    ] {
        assert!(
            !sudo.contains(&forbidden),
            "observe must NOT carry the mutating verb `{forbidden}`; got {sudo:?}"
        );
    }

    assert_eq!(
        access_on(&resolved, "/etc/zabbix"),
        Some(Access::RO),
        "observe /etc/zabbix must be read-only"
    );
    assert_eq!(
        access_on(&resolved, "/var/log/zabbix"),
        Some(Access::RO),
        "observe /var/log/zabbix must be read-only"
    );
}

#[test]
fn packaged_zabbix_operate_is_control_plus_rw_config_plus_ro_logs() {
    // The operate package bundles observe and adds the mutating half. It must
    // carry service-control's start/stop/restart, rw on the config tree, and keep
    // logs read-only (logs are contributed only by the bundled observe and never
    // widened by operate).
    let resolved = resolve_app_package("zabbix-agent.operate");

    let sudo = sudo_of(&resolved);
    for control in [
        "/usr/bin/systemctl start zabbix-agent",
        "/usr/bin/systemctl stop zabbix-agent",
        "/usr/bin/systemctl restart zabbix-agent",
        "/usr/bin/systemctl reset-failed zabbix-agent",
    ] {
        assert!(
            sudo.contains(&control),
            "operate must carry control verb `{control}`; got {sudo:?}"
        );
    }
    // The bundled observe's read-only status verb survives the bundle.
    assert!(
        sudo.contains(&"/usr/bin/systemctl status zabbix-agent"),
        "operate must bundle observe's status verb; got {sudo:?}"
    );

    assert_eq!(
        access_on(&resolved, "/var/log/zabbix"),
        Some(Access::RO),
        "operate logs must stay read-only"
    );
}

#[test]
fn packaged_zabbix_operate_unions_config_grant_to_rw() {
    // The rw-over-ro union: observe contributes /etc/zabbix as ro, operate
    // contributes the same path as rw. The resolver unions by path with a
    // bit-union on access, so the write bit must win — the effective grant is rw,
    // not ro. This is the load-bearing proof that a wider operate grant correctly
    // overrides the bundled observe's narrower one.
    let resolved = resolve_app_package("zabbix-agent.operate");

    let access = access_on(&resolved, "/etc/zabbix").expect("operate grants /etc/zabbix");
    assert_eq!(
        access,
        Access::RW,
        "rw-over-ro union must widen /etc/zabbix to rw; got {access:?}"
    );
    assert!(
        access.contains(Access::WRITE),
        "unioned /etc/zabbix grant must carry the write bit"
    );

    // Exactly one grant per path after the union — the two contributions on
    // /etc/zabbix collapse into a single rw grant, not two competing entries.
    let etc_zabbix_grants = resolved
        .file_grants
        .iter()
        .filter(|g| g.path == "/etc/zabbix")
        .count();
    assert_eq!(
        etc_zabbix_grants, 1,
        "the ro and rw contributions on /etc/zabbix must union into one grant"
    );
}

#[test]
fn packaged_nut_operate_is_contained_ro_both_units() {
    // The multi-unit package binds service-control twice with DIFFERENT literal
    // units (nut-server, nut-monitor). The binding-aware dedup must keep both:
    // collapsing on member id alone would silently drop one unit's control set.
    // After the root-daemon re-audit, operate is contained with READ-ONLY config:
    // rw on /etc/nut is escalation (upsmon SHUTDOWNCMD runs as root) and lives in
    // nut.admin.
    let resolved = resolve_app_package("nut.operate");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "nut.operate must be contained; got {:?}",
        resolved.risk
    );
    let sudo = sudo_of(&resolved);
    for unit in ["nut-server", "nut-monitor"] {
        assert!(
            sudo.contains(&format!("/usr/bin/systemctl restart {unit}").as_str()),
            "nut.operate must resolve a control set for {unit}; got {sudo:?}"
        );
    }
    assert_eq!(
        access_on(&resolved, "/etc/nut"),
        Some(Access::RO),
        "nut.operate /etc/nut must be read-only"
    );
}

#[test]
fn packaged_nut_admin_is_escalation_with_rw_both_units() {
    // nut.admin carries the escalation: rw /etc/nut + control on both units,
    // classed escalation-capable (upsmon runs SHUTDOWNCMD/NOTIFYCMD as root, so
    // writing upsmon.conf is a root command-exec path).
    let resolved = resolve_app_package("nut.admin");

    assert_eq!(
        resolved.risk,
        Some(Risk::EscalationCapable),
        "nut.admin must be escalation-capable; got {:?}",
        resolved.risk
    );
    let sudo = sudo_of(&resolved);
    for unit in ["nut-server", "nut-monitor"] {
        assert!(
            sudo.contains(&format!("/usr/bin/systemctl restart {unit}").as_str()),
            "nut.admin must resolve a control set for {unit}; got {sudo:?}"
        );
    }
    assert_eq!(
        access_on(&resolved, "/etc/nut"),
        Some(Access::RW),
        "nut.admin must grant rw on /etc/nut"
    );
}

/// Resolve a packaged convention file component (e.g. `app-config-rw`) with the
/// given `app` value against the real catalog on `linux-debian-12`.
fn resolve_file_component(id: &str, app: ParamValue) -> Result<ResolvedPermission, CatalogError> {
    let catalog = LiveCatalog::new(vec![repo("share/permissions")]);
    let os = OsTarget::new("linux", "debian", Some("12".to_owned())).expect("valid os target");
    let mut params: BTreeMap<String, ParamValue> = BTreeMap::new();
    params.insert("app".to_owned(), app);
    resolve_with_params(id, &params, &os, &catalog, &ResolveCtx::default())
        .map(|(resolved, _warnings)| resolved)
}

#[test]
fn packaged_app_config_rw_resolves_etc_app_rw() {
    // The reusable convention component, bound directly with a role-supplied app
    // name, must produce rw on /etc/<app>. This is the path the curated packages
    // exercise with a literal binding (app="zabbix"), here driven by a parameter.
    let resolved = resolve_file_component("app-config-rw", ParamValue::String("zabbix".to_owned()))
        .expect("app-config-rw resolves for a plain app name");
    assert_eq!(
        access_on(&resolved, "/etc/zabbix"),
        Some(Access::RW),
        "app-config-rw bound app=zabbix must grant rw on /etc/zabbix"
    );
}

#[test]
fn packaged_app_config_rw_segment_guard_rejects_escapes() {
    // The component's `[params.app]` is `kind = "segment"`: a value that would
    // escape /etc (`../x`) or add a second path level (`a/b`) must fail closed on
    // the `app` segment constraint, never reaching a materialized path.
    for bad in ["../x", "a/b"] {
        let err = resolve_file_component("app-config-rw", ParamValue::String(bad.to_owned()))
            .expect_err("segment guard must reject the escape value");
        assert!(
            matches!(
                err,
                CatalogError::ParamConstraintViolation { ref param, .. } if param == "app"
            ),
            "app={bad:?} must fail closed on the `app` segment constraint, got {err:?}"
        );
    }
}

#[test]
fn packaged_app_scope_segment_guard_rejects_escapes() {
    // The bundle's `[params.app]` is `kind = "segment"`: it must reject a value
    // that would escape the path tree (`..`, `/`) or that is not a plain unit
    // name (an instance unit `name@inst` carries `@`, which segment forbids).
    // Each fails closed at guard 1 (the bundle constraint), naming `app`.
    for bad in ["../x", "a/b", "wg-quick@wg0"] {
        let err = resolve_app_scope(ParamValue::String(bad.to_owned()))
            .expect_err("segment guard must reject the escape value");
        assert!(
            matches!(
                err,
                CatalogError::ParamConstraintViolation { ref param, .. } if param == "app"
            ),
            "app={bad:?} must fail closed on the `app` segment constraint, got {err:?}"
        );
    }
}

#[test]
fn packaged_docker_observe_has_no_group_or_socket() {
    // docker.observe is the contained tier: status + ro /etc/docker ONLY. There is
    // no contained way to list containers (docker ps needs the root-equivalent
    // daemon socket), so observe must grant NO docker group, NO socket file, and
    // keep /etc/docker read-only. Any group/socket here would silently turn the
    // contained tier into a root-equivalent one.
    let resolved = resolve_app_package("docker.observe");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "docker.observe must be contained; got {:?}",
        resolved.risk
    );
    assert!(
        groups_of(&resolved).is_empty(),
        "docker.observe must grant NO groups (no docker group); got {:?}",
        groups_of(&resolved)
    );
    assert!(
        !groups_of(&resolved).contains(&"docker"),
        "docker.observe must NOT grant the root-equivalent docker group"
    );
    // No socket file grant of any kind — observe never touches the daemon socket.
    assert!(
        access_on(&resolved, "/var/run/docker.sock").is_none()
            && access_on(&resolved, "/run/docker.sock").is_none(),
        "docker.observe must NOT grant the docker socket; got {:?}",
        resolved
            .file_grants
            .iter()
            .map(|g| g.path.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        access_on(&resolved, "/etc/docker"),
        Some(Access::RO),
        "docker.observe /etc/docker must be read-only"
    );
}

#[test]
fn packaged_docker_operate_is_escalation_with_group() {
    // docker.operate is escalation-capable, not a contained operate: the docker
    // group is daemon-socket access, which is root-equivalent (bind-mount host
    // root, --privileged). The label and the group membership must both reflect
    // that — there is no contained operate for docker.
    let resolved = resolve_app_package("docker.operate");

    assert_eq!(
        resolved.risk,
        Some(Risk::EscalationCapable),
        "docker.operate must be escalation-capable; got {:?}",
        resolved.risk
    );
    assert!(
        groups_of(&resolved).contains(&"docker"),
        "docker.operate must grant the docker group (socket = root-equivalent); got {:?}",
        groups_of(&resolved)
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/docker-compose"),
        "docker.operate must carry the docker-compose sudo; got {sudo:?}"
    );
}

#[test]
fn packaged_mosquitto_operate_is_contained_rw() {
    // mosquitto.operate is contained on Debian 12 (the unit pins User=mosquitto):
    // lifecycle + rw config + ro logs, with rw on /etc/mosquitto present. The
    // containment caveat (units lacking User=) is carried in the doc/risk_note;
    // here the packaged Debian-12 shape must be contained with rw config.
    let resolved = resolve_app_package("mosquitto.operate");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "mosquitto.operate must be contained on Debian 12; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/mosquitto"),
        Some(Access::RW),
        "mosquitto.operate must grant rw on /etc/mosquitto (non-root daemon, contained)"
    );
    assert_eq!(
        access_on(&resolved, "/var/log/mosquitto"),
        Some(Access::RO),
        "mosquitto.operate logs must stay read-only"
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart mosquitto"),
        "mosquitto.operate must carry service-control on the mosquitto unit; got {sudo:?}"
    );
}

#[test]
fn packaged_pcscd_operate_is_contained_no_rw_config() {
    // pcscd.operate is contained: lifecycle on both units + contained USB-reader
    // access via device-usb (plugdev). The escalation lever for pcscd is rw on
    // /etc/reader.conf.d (root .so load via LIBPATH) — operate must NOT carry it;
    // that is pcscd.admin. So no rw on the config tree, but the plugdev group must
    // be present.
    let resolved = resolve_app_package("pcscd.operate");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "pcscd.operate must be contained; got {:?}",
        resolved.risk
    );
    assert_ne!(
        access_on(&resolved, "/etc/reader.conf.d"),
        Some(Access::RW),
        "pcscd.operate must NOT grant rw on /etc/reader.conf.d (that is admin)"
    );
    assert!(
        groups_of(&resolved).contains(&"plugdev"),
        "pcscd.operate must grant the plugdev group via device-usb; got {:?}",
        groups_of(&resolved)
    );
}

#[test]
fn packaged_pcscd_admin_is_escalation_with_rw_both_units() {
    // pcscd.admin carries the escalation: rw /etc/reader.conf.d (LIBPATH → root .so
    // load) plus service-control on BOTH the daemon and its socket-activation unit.
    // pcscd is socket-activated, so collapsing to one unit would leave the socket
    // unmanaged — both must resolve.
    let resolved = resolve_app_package("pcscd.admin");

    assert_eq!(
        resolved.risk,
        Some(Risk::EscalationCapable),
        "pcscd.admin must be escalation-capable; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/reader.conf.d"),
        Some(Access::RW),
        "pcscd.admin must grant rw on /etc/reader.conf.d"
    );
    let sudo = sudo_of(&resolved);
    for unit in ["pcscd", "pcscd.socket"] {
        assert!(
            sudo.contains(&format!("/usr/bin/systemctl restart {unit}").as_str()),
            "pcscd.admin must resolve a control set for {unit}; got {sudo:?}"
        );
    }
}

#[test]
fn packaged_salt_minion_operate_is_ro_only() {
    // salt-minion.operate is contained because it is READ-ONLY config: the minion
    // runs as root, so rw /etc/salt (repoint master:) is escalation and lives in
    // salt-minion.admin. operate must keep /etc/salt ro, never rw.
    let resolved = resolve_app_package("salt-minion.operate");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "salt-minion.operate must be contained; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/salt"),
        Some(Access::RO),
        "salt-minion.operate /etc/salt must be read-only"
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart salt-minion"),
        "salt-minion.operate must carry service-control on the salt-minion unit; got {sudo:?}"
    );
}

#[test]
fn packaged_salt_minion_admin_is_escalation_with_rw() {
    // salt-minion.admin carries the escalation: rw /etc/salt, classed
    // escalation-capable — the root minion's master: address is in /etc/salt, so
    // rw repoints it at an attacker-controlled master = full host takeover.
    let resolved = resolve_app_package("salt-minion.admin");

    assert_eq!(
        resolved.risk,
        Some(Risk::EscalationCapable),
        "salt-minion.admin must be escalation-capable; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/salt"),
        Some(Access::RW),
        "salt-minion.admin must grant rw on /etc/salt"
    );
}

#[test]
fn packaged_rsyslog_observe_is_read_only_dropin_tree() {
    // rsyslog.observe grants service-observe plus ro on the drop-in tree
    // /etc/rsyslog.d only. The main /etc/rsyslog.conf is out of scope: a single
    // system file cannot be granted rewrite-proof without granting all of /etc, so
    // census (which requires a directory ACL for rewrite-proof enforcement) rejects
    // a per-file grant at apply on targets without a per-file backend.
    let resolved = resolve_app_package("rsyslog.observe");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "rsyslog.observe must be contained; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/rsyslog.d"),
        Some(Access::RO),
        "rsyslog.observe /etc/rsyslog.d must be read-only"
    );
    // Regression guard for the apply-rejection defect: the single-file grant on
    // /etc/rsyslog.conf must be gone — no per-file grant on the main config.
    assert_eq!(
        access_on(&resolved, "/etc/rsyslog.conf"),
        None,
        "rsyslog.observe must NOT grant the single file /etc/rsyslog.conf"
    );
}

#[test]
fn packaged_rsyslog_operate_is_contained_ro() {
    // rsyslog.operate is contained because it is READ-ONLY config: rsyslogd runs
    // as root, so rw config (omprog runs programs as root, module(load=…) loads a
    // .so into the root daemon) is escalation and lives in rsyslog.admin. operate
    // keeps the drop-in tree /etc/rsyslog.d ro, never rw. The main
    // /etc/rsyslog.conf is out of scope (a single-file grant is rejected at apply
    // on targets without a per-file backend), so it must not appear.
    let resolved = resolve_app_package("rsyslog.operate");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "rsyslog.operate must be contained; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/rsyslog.d"),
        Some(Access::RO),
        "rsyslog.operate /etc/rsyslog.d must be read-only"
    );
    // Regression guard for the apply-rejection defect: no per-file grant on the
    // main config /etc/rsyslog.conf.
    assert_eq!(
        access_on(&resolved, "/etc/rsyslog.conf"),
        None,
        "rsyslog.operate must NOT grant the single file /etc/rsyslog.conf"
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart rsyslog"),
        "rsyslog.operate must carry service-control on the rsyslog unit; got {sudo:?}"
    );
}

#[test]
fn packaged_rsyslog_admin_is_escalation_with_rw() {
    // rsyslog.admin carries the escalation: rw on the drop-in tree /etc/rsyslog.d,
    // classed escalation-capable — rsyslogd is root and a drop-in can load a .so /
    // run a program (omprog) AS ROOT. The main /etc/rsyslog.conf is out of scope (a
    // single-file grant is rejected at apply on targets without a per-file
    // backend), so admin grants only the directory tree.
    let resolved = resolve_app_package("rsyslog.admin");

    assert_eq!(
        resolved.risk,
        Some(Risk::EscalationCapable),
        "rsyslog.admin must be escalation-capable; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/rsyslog.d"),
        Some(Access::RW),
        "rsyslog.admin must grant rw on the drop-in tree /etc/rsyslog.d"
    );
    // Regression guard for the apply-rejection defect: no per-file grant on the
    // main config /etc/rsyslog.conf.
    assert_eq!(
        access_on(&resolved, "/etc/rsyslog.conf"),
        None,
        "rsyslog.admin must NOT grant the single file /etc/rsyslog.conf"
    );
}

#[test]
fn packaged_fluent_bit_admin_is_escalation_with_rw() {
    // fluent-bit.admin is escalation-capable + rw /etc/fluent-bit: Fluent Bit runs
    // as root on the baseline (the upstream/td-agent-bit unit sets no User=), so
    // rw config runs commands (exec/exec_wasi input) and loads .so plugins AS ROOT.
    let resolved = resolve_app_package("fluent-bit.admin");

    assert_eq!(
        resolved.risk,
        Some(Risk::EscalationCapable),
        "fluent-bit.admin must be escalation-capable; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/fluent-bit"),
        Some(Access::RW),
        "fluent-bit.admin must grant rw on /etc/fluent-bit"
    );
}

#[test]
fn packaged_fluent_bit_operate_is_contained_ro() {
    // fluent-bit.operate is contained because it is READ-ONLY config: the root
    // daemon means rw config is escalation (exec input runs commands as root, .so
    // plugin load) and lives in fluent-bit.admin. operate keeps /etc/fluent-bit ro.
    let resolved = resolve_app_package("fluent-bit.operate");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "fluent-bit.operate must be contained; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/fluent-bit"),
        Some(Access::RO),
        "fluent-bit.operate /etc/fluent-bit must be read-only"
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart fluent-bit"),
        "fluent-bit.operate must carry service-control on the fluent-bit unit; got {sudo:?}"
    );
}

#[test]
fn packaged_telegraf_operate_is_contained_rw() {
    // Telegraf: the daemon is structurally pinned non-root by the unit
    // User=telegraf, so operate MAY carry rw config and stay contained — rw config
    // grants exec/execd input as the telegraf user, not root (exec-as-app-user, the
    // redis precedent). There is no telegraf.admin tier. No log grant (journald).
    let resolved = resolve_app_package("telegraf.operate");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "telegraf.operate must be contained; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/telegraf"),
        Some(Access::RW),
        "telegraf.operate must grant rw on /etc/telegraf (non-root daemon, contained)"
    );
    assert_eq!(
        access_on(&resolved, "/var/log/telegraf"),
        None,
        "telegraf.operate must NOT grant a log tree (telegraf logs to journald)"
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart telegraf"),
        "telegraf.operate must carry service-control on the telegraf unit; got {sudo:?}"
    );
}

#[test]
fn packaged_openvpn_observe_is_contained_ro() {
    // openvpn.observe is contained: read-only status on the instance unit plus ro
    // /etc/openvpn, no mutation. The whole reason rw is escalation (admin) is that
    // up/down scripts and the plugin .so run as root, so observe must stay ro —
    // /etc/openvpn holds private keys, so even ro is credential-sensitive.
    let resolved = resolve_app_package("openvpn.observe");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "openvpn.observe must be contained; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/openvpn"),
        Some(Access::RO),
        "openvpn.observe /etc/openvpn must be read-only"
    );
    let sudo = sudo_of(&resolved);
    // The instance-unit (`@`-form) status verb resolves; no mutating verbs leak.
    assert!(
        sudo.contains(&"/usr/bin/systemctl status openvpn-server@server"),
        "openvpn.observe must carry status on the instance unit; got {sudo:?}"
    );
    assert!(
        !sudo.contains(&"/usr/bin/systemctl restart openvpn-server@server"),
        "openvpn.observe must NOT carry a mutating verb; got {sudo:?}"
    );
}

#[test]
fn packaged_openvpn_admin_is_escalation_with_rw() {
    // openvpn.admin carries the escalation: rw /etc/openvpn + control on the
    // instance unit, classed escalation-capable — up/down/route-up scripts run as
    // root under script-security 2 and the plugin directive loads a .so into the
    // root process, so rw config is a root code-exec path.
    let resolved = resolve_app_package("openvpn.admin");

    assert_eq!(
        resolved.risk,
        Some(Risk::EscalationCapable),
        "openvpn.admin must be escalation-capable; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/openvpn"),
        Some(Access::RW),
        "openvpn.admin must grant rw on /etc/openvpn"
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart openvpn-server@server"),
        "openvpn.admin must carry service-control on the instance unit; got {sudo:?}"
    );
}

#[test]
fn packaged_wireguard_admin_is_escalation_with_rw() {
    // wireguard.admin carries the escalation: rw /etc/wireguard + control on the
    // wg-quick instance unit, classed escalation-capable — PostUp/PostDown/PreUp/
    // PreDown run as root via wg-quick, so rw config is a root command-exec path.
    let resolved = resolve_app_package("wireguard.admin");

    assert_eq!(
        resolved.risk,
        Some(Risk::EscalationCapable),
        "wireguard.admin must be escalation-capable; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/wireguard"),
        Some(Access::RW),
        "wireguard.admin must grant rw on /etc/wireguard"
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart wg-quick@wg0"),
        "wireguard.admin must carry service-control on the wg-quick instance unit; got {sudo:?}"
    );
}

#[test]
fn packaged_node_red_operate_is_contained_rw() {
    // node-red.operate is contained even with RW config because the official
    // systemd install pins Node-RED non-root via the unit's User=: rw on the
    // userDir is command-exec as the non-root node-red user (exec node /
    // child_process), not root — the redis precedent (rw in operate, no admin
    // tier). It also carries the gpio group via device-bus. Assert the contained
    // non-root rw shape: rw on the userDir, the gpio group present, and NO root
    // path — the userDir is a home-dir tree, never /etc and never /.
    let resolved = resolve_app_package("node-red.operate");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "node-red.operate must be contained; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/var/lib/node-red"),
        Some(Access::RW),
        "node-red.operate must grant rw on the userDir (non-root daemon, contained)"
    );
    assert!(
        groups_of(&resolved).contains(&"gpio"),
        "node-red.operate must grant the gpio group via device-bus; got {:?}",
        groups_of(&resolved)
    );
    // No root path: the only file grant is the userDir, which is neither /etc nor
    // the filesystem root — the containment claim rests on the grant staying off
    // any system/root tree.
    for grant in &resolved.file_grants {
        assert!(
            grant.path.starts_with("/var/lib/node-red"),
            "node-red.operate must not grant any path outside the userDir; got {}",
            grant.path
        );
    }
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart nodered"),
        "node-red.operate must carry service-control on the nodered unit; got {sudo:?}"
    );
}

#[test]
fn packaged_openvpn_observe_keeps_config_ro() {
    // The ro-ness of observe IS the containment claim: /etc/openvpn holds the tunnel
    // private keys, and rw would be a root code-exec path (up/down scripts + plugin
    // .so run as root). So observe must resolve /etc/openvpn strictly RO, never rw —
    // this locks the private-key credential-exposure-but-contained contract.
    let resolved = resolve_app_package("openvpn.observe");

    let access = access_on(&resolved, "/etc/openvpn").expect("openvpn.observe grants /etc/openvpn");
    assert_eq!(
        access,
        Access::RO,
        "openvpn.observe /etc/openvpn must be read-only; got {access:?}"
    );
    assert!(
        !access.contains(Access::WRITE),
        "openvpn.observe /etc/openvpn must NOT carry the write bit"
    );
}

#[test]
fn packaged_wireguard_operate_keeps_config_ro() {
    // The ro-ness of operate IS the containment claim: bringing the interface up runs
    // the config's PostUp/PostDown hooks as root, so operate stays contained ONLY
    // because it cannot rewrite that config — rw is escalation (wireguard.admin). So
    // operate must resolve /etc/wireguard strictly RO, never rw, even though it
    // carries the wg-quick lifecycle that triggers the root hooks.
    let resolved = resolve_app_package("wireguard.operate");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "wireguard.operate must be contained; got {:?}",
        resolved.risk
    );
    let access =
        access_on(&resolved, "/etc/wireguard").expect("wireguard.operate grants /etc/wireguard");
    assert_eq!(
        access,
        Access::RO,
        "wireguard.operate /etc/wireguard must be read-only; got {access:?}"
    );
    assert!(
        !access.contains(Access::WRITE),
        "wireguard.operate /etc/wireguard must NOT carry the write bit"
    );
}

#[test]
fn packaged_greengrass_admin_is_escalation() {
    // greengrass.admin is escalation-capable, and there is NO contained operate
    // tier: the installer needs a sudo-ALL (root-equivalent) entry, the Core runs
    // as root, and rw on /greengrass/v2/config rewrites component recipes the root
    // Core executes = root code-exec. Assert the label plus rw config + Core control.
    let resolved = resolve_app_package("greengrass.admin");

    assert_eq!(
        resolved.risk,
        Some(Risk::EscalationCapable),
        "greengrass.admin must be escalation-capable; got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/greengrass/v2/config"),
        Some(Access::RW),
        "greengrass.admin must grant rw on /greengrass/v2/config (root code-exec via recipes)"
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart greengrass"),
        "greengrass.admin must carry control of the greengrass Core unit; got {sudo:?}"
    );
}

#[test]
fn packaged_azure_iot_edge_admin_is_escalation_with_docker_group() {
    // azure-iot-edge.admin is escalation-capable, and there is NO contained operate
    // tier: edgeAgent drives workload modules through the Docker socket, so the
    // package carries the root-equivalent docker group; aziot-edged is a privileged
    // security daemon; rw on /etc/aziot repoints provisioning + changes the module
    // set the privileged daemon launches via the root socket. Assert the label, the
    // docker group, and rw config.
    let resolved = resolve_app_package("azure-iot-edge.admin");

    assert_eq!(
        resolved.risk,
        Some(Risk::EscalationCapable),
        "azure-iot-edge.admin must be escalation-capable; got {:?}",
        resolved.risk
    );
    assert!(
        groups_of(&resolved).contains(&"docker"),
        "azure-iot-edge.admin must grant the docker group (Moby socket = root-equivalent); got {:?}",
        groups_of(&resolved)
    );
    assert_eq!(
        access_on(&resolved, "/etc/aziot"),
        Some(Access::RW),
        "azure-iot-edge.admin must grant rw on /etc/aziot (provisioning/module control)"
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart aziot-edged"),
        "azure-iot-edge.admin must carry control of the aziot-edged unit; got {sudo:?}"
    );
}

#[test]
fn packaged_edgex_operate_is_contained() {
    // edgex.operate (snap deployment) is contained as lifecycle + READ-ONLY config:
    // the EdgeX snap services run as ROOT (no User= pin), so rw config is escalation
    // (edgex.admin), and operate keeps config ro — the rsyslog/salt-minion
    // root-daemon shape. It carries the dialout group via device-serial for Modbus
    // RTU. Assert: contained, config RO (NOT rw), dialout present, snap-unit
    // lifecycle, and no rw on the config tree.
    let resolved = resolve_app_package("edgex.operate");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "edgex.operate must be contained (lifecycle + ro only, root daemon); got {:?}",
        resolved.risk
    );
    let config = access_on(&resolved, "/var/snap/edgexfoundry/current")
        .expect("edgex.operate grants the snap config tree");
    assert_eq!(
        config,
        Access::RO,
        "edgex.operate snap config must be READ-ONLY (root daemon → rw is admin); got {config:?}"
    );
    assert!(
        !config.contains(Access::WRITE),
        "edgex.operate must NOT carry the write bit on the snap config tree"
    );
    assert!(
        groups_of(&resolved).contains(&"dialout"),
        "edgex.operate must grant the dialout group via device-serial (Modbus RTU); got {:?}",
        groups_of(&resolved)
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart snap.edgexfoundry.device-modbus"),
        "edgex.operate must carry control of the representative snap device-service unit; got {sudo:?}"
    );
}

#[test]
fn packaged_edgex_admin_is_escalation_with_rw() {
    // edgex.admin carries the escalation: rw on the snap config tree + control of the
    // snap services, classed escalation-capable — the EdgeX snap services run as ROOT
    // (no User= pin), so rw config reconfigures what the root services load (device
    // endpoints, driver settings, registry/secrets endpoints) = a root-level
    // reconfiguration path. This is the rsyslog/salt-minion shape.
    let resolved = resolve_app_package("edgex.admin");

    assert_eq!(
        resolved.risk,
        Some(Risk::EscalationCapable),
        "edgex.admin must be escalation-capable (root snap daemon, rw config); got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/var/snap/edgexfoundry/current"),
        Some(Access::RW),
        "edgex.admin must grant rw on the snap config tree (root reconfiguration path)"
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart snap.edgexfoundry.core-data"),
        "edgex.admin must carry control of the snap services; got {sudo:?}"
    );
}

#[test]
fn packaged_x11vnc_operate_is_contained() {
    // x11vnc.operate is contained ONLY for the kiosk / guest-user-session case: it
    // attaches to a non-root kiosk session via console-access (a contained leaf), so
    // no host privilege is gained. Assert the contained label, the lifecycle, and
    // that no root file path leaks. ROOT-:0 CAVEAT (documented in the package and
    // l10n risk_note, not assertable here): if x11vnc instead attaches to the
    // display-manager / login screen on :0 it runs AS ROOT and injects into the root
    // login session = escalation — such a deployment must NOT ship this as contained
    // and must use a separate root-tier package. x11vnc always grants full live-
    // session control (view + input injection), a high-sensitivity grant even when
    // contained.
    let resolved = resolve_app_package("x11vnc.operate");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "x11vnc.operate must be contained for the kiosk-session case; got {:?}",
        resolved.risk
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart x11vnc"),
        "x11vnc.operate must carry service-control on the x11vnc unit; got {sudo:?}"
    );
    assert!(
        sudo.contains(&"/usr/bin/systemctl status x11vnc"),
        "x11vnc.operate must also carry the observe status verb; got {sudo:?}"
    );
    // No root file path: console-access is a group-only contained leaf, so operate
    // grants no file path at all — and certainly none under a system/root tree.
    for grant in &resolved.file_grants {
        assert!(
            grant.path != "/" && !grant.path.starts_with("/etc"),
            "x11vnc.operate must not grant a root/system file path; got {}",
            grant.path
        );
    }
}

#[test]
fn packaged_portainer_edge_admin_is_escalation() {
    // portainer-edge.admin is escalation-capable, and there is NO contained operate
    // tier: the Edge Agent drives the host docker socket (root-equivalent), so the
    // package composes docker.operate. The escalation comes from that docker-socket
    // access, independent of the agent's unit name. Assert the label and that the
    // composed docker.operate surface is present (docker group + compose sudo).
    let resolved = resolve_app_package("portainer-edge.admin");

    assert_eq!(
        resolved.risk,
        Some(Risk::EscalationCapable),
        "portainer-edge.admin must be escalation-capable (composes docker.operate); got {:?}",
        resolved.risk
    );
    assert!(
        groups_of(&resolved).contains(&"docker"),
        "portainer-edge.admin must grant the docker group via docker.operate (socket = root-equiv); got {:?}",
        groups_of(&resolved)
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/docker-compose"),
        "portainer-edge.admin must carry the docker-compose sudo from docker.operate; got {sudo:?}"
    );
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart PortainerEdgeAgent"),
        "portainer-edge.admin must carry lifecycle control of the agent unit; got {sudo:?}"
    );
}

#[test]
fn packaged_chromium_admin_is_contained_rw() {
    // chromium.admin grants rw on the enterprise managed-policy tree, but stays
    // CONTAINED (not escalation): the managed-policy files are root-owned, yet
    // Chromium reads them as the unprivileged guest browser user, so rw does not
    // run code as root — the worst it does is control a guest-level browser.
    // (The kiosk-escape / lockdown-integrity concern is real but contained — it is
    // carried in the package doc + l10n risk_note, not the risk enum.)
    let resolved = resolve_app_package("chromium.admin");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "chromium.admin must be contained (browser reads root-owned policy as the guest user, no root code-exec); got {:?}",
        resolved.risk
    );
    assert_eq!(
        access_on(&resolved, "/etc/chromium/policies/managed"),
        Some(Access::RW),
        "chromium.admin must grant rw on /etc/chromium/policies/managed"
    );
    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl restart kiosk"),
        "chromium.admin must carry service-control on the kiosk session unit; got {sudo:?}"
    );
}

#[test]
fn packaged_chromium_observe_keeps_policy_ro() {
    // The ro-ness of observe/operate IS the kiosk-lockdown integrity guarantee:
    // the managed policy defines the kiosk confinement, so observe must resolve
    // /etc/chromium/policies/managed strictly RO, never rw — rw (the kiosk-escape
    // authoring surface) lives only in chromium.admin. Also assert observe carries
    // no mutating session verb (status only).
    let resolved = resolve_app_package("chromium.observe");

    assert_eq!(
        resolved.risk,
        Some(Risk::Contained),
        "chromium.observe must be contained; got {:?}",
        resolved.risk
    );
    let access = access_on(&resolved, "/etc/chromium/policies/managed")
        .expect("chromium.observe grants the managed-policy tree");
    assert_eq!(
        access,
        Access::RO,
        "chromium.observe /etc/chromium/policies/managed must be read-only; got {access:?}"
    );
    assert!(
        !access.contains(Access::WRITE),
        "chromium.observe managed-policy grant must NOT carry the write bit"
    );

    let sudo = sudo_of(&resolved);
    assert!(
        sudo.contains(&"/usr/bin/systemctl status kiosk"),
        "chromium.observe must carry status on the kiosk session unit; got {sudo:?}"
    );
    assert!(
        !sudo.contains(&"/usr/bin/systemctl restart kiosk"),
        "chromium.observe must NOT carry a mutating session verb; got {sudo:?}"
    );
}
