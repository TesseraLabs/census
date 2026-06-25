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
