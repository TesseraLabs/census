//! Resolves a declaration + role-store composition into `ResolvedAccount`s —
//! the fully-specified target Unix accounts Census wants to exist.
//!
//! Permission expansion is part of resolve (design "Конвейер компиляции"):
//! each role's `payload.permissions` is expanded against the catalog into
//! concrete Unix primitives BEFORE the plan is built, so `plan`/`apply` work
//! with roles-in-permissions directly. The raw escape-hatch fields
//! (`groups`/`sudo_role`/`limits`) are unioned with the expansion; using a raw
//! primitive alongside permissions is allowed but lint-flagged.

use crate::catalog::{self, CatalogError, CatalogSource, OsTarget, ResolveCtx};
use crate::declaration::Declaration;
use crate::rolestore::{self, Limits, RoleStoreError};
use std::path::PathBuf;

/// How an object (account or group) came under Census management. Drives the
/// teardown contract: a `Created` object Census made itself, so removing it from
/// the declaration means a full delete (`userdel`/`groupdel`); an `Adopted`
/// object pre-existed and Census only took its grants under management, so
/// removal means *release* to baseline (strip Census's own grants/members) and
/// never delete the underlying user or group. Reused by the persisted state in a
/// later slice, so the resolve layer and the state layer agree on the contract.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// Census created the object; on removal it is fully deleted.
    #[default]
    Created,
    /// The object pre-existed and was taken under management; on removal Census
    /// releases it back to baseline and never deletes it.
    Adopted,
}

/// A fully-resolved target account: declaration account-layer merged with the
/// role-store composition (raw escape-hatch primitives unioned with the
/// permission expansion), plus Census invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAccount {
    /// Unix login name (equals the role id; spec "role = account").
    pub name: String,
    /// Stable UID.
    pub uid: u32,
    /// Login shell (real shell; reachability is gated elsewhere — spec §8).
    pub shell: String,
    /// Home directory.
    pub home: PathBuf,
    /// Supplementary groups: raw `payload.groups` ∪ permission-expanded groups
    /// (deduped, stable order).
    pub groups: Vec<String>,
    /// Sudo role, if any — the RAW escape-hatch path. Rendered as the legacy
    /// `Cmnd_Alias` sudoers fragment when no concrete `sudo_commands` are
    /// present. Kept distinct from `sudo_commands` so the two render paths do
    /// not collide.
    pub sudo_role: Option<String>,
    /// Concrete sudo commands expanded from the role's permissions (deduped,
    /// stable order). When non-empty these render a concrete NOPASSWD sudoers
    /// rule, replacing the external-`Cmnd_Alias` indirection.
    pub sudo_commands: Vec<String>,
    /// Resource limits. Raw `payload.limits` if set; otherwise merged from the
    /// permission expansion. An explicit raw limit wins over an expanded one.
    pub limits: Limits,
    /// File-access grants, unioned across every permission the role carries
    /// (by path: access widens to the max, `recursive` is the OR, provenance
    /// accumulates) — the same rule the catalog applies within one permission.
    /// Materialized by a [`crate::fileaccess::FileAccessBackend`] in the apply
    /// file-access phase; there is no raw escape-hatch for file grants (they
    /// only ever come from permissions).
    pub file_grants: Vec<catalog::ResolvedFileGrant>,
    /// Census invariant: role accounts always have a locked password (§8).
    pub locked_password: bool,
    /// How this account came under management. Resolve only ever produces
    /// `Created` accounts today — adopted accounts (bound to an existing user)
    /// are skipped here and apply in a later slice — but the field is carried so
    /// the value flows through to the state/plan layers without a second pass.
    pub provenance: Provenance,
}

/// A fully-resolved target group: the declared group object joined with the
/// grants every role bound to it contributes. Membership-style primitives are
/// projected to group-forms (`%group` sudoers, `g:group` ACL, `@group` limits)
/// by the apply layer; the in-group-membership sub-primitive (`groups`) has no
/// local meaning on a group target and is dropped with a warning at resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGroup {
    /// POSIX group name (the key used to reference / create the group).
    pub name: String,
    /// Pinned GID for a `Created` group, or `None`. An `Adopted` group always
    /// carries `None` here — its real GID is observed from the OS at apply time,
    /// never assigned by Census (adoption never renumbers).
    pub gid: Option<u32>,
    /// How this group came under management (from `[[group]].adopt`).
    pub provenance: Provenance,
    /// Members Census manages on this group, taken verbatim from
    /// `GroupSpec.members` (validation already restricted an adopted group's
    /// members to Census-managed users).
    pub members: Vec<String>,
    /// Sudo commands the bound roles grant the group, unioned across every
    /// bound role's permissions (deduped, stable order). Materialized as a
    /// `%group` NOPASSWD sudoers fragment.
    pub sudo_commands: Vec<String>,
    /// File-access grants the bound roles grant the group, unioned by path
    /// (access widens to the max, `recursive` is the OR, provenance accumulates)
    /// — the same rule resolve applies to an account. Materialized as `g:group`
    /// ACL entries.
    pub file_grants: Vec<catalog::ResolvedFileGrant>,
    /// Resource limits the bound roles grant the group, merged field-by-field
    /// (first role to set a field wins). Materialized as an `@group` block.
    pub limits: Limits,
    /// Role ids that contributed grants to this group, in insertion order with
    /// duplicates removed. Audit/reporting shows which roles a group's grants
    /// come from.
    pub bound_roles: Vec<String>,
}

/// A resolve-time warning surfaced as data (routed to stderr by the CLI, into
/// the apply log by the orchestrator). Carries catalog warnings plus Census's
/// own lint signals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveWarning {
    /// A raw escape-hatch primitive (`groups`/`sudo_role`/`limits`) was used on
    /// a role that also declares permissions. Allowed, but prefer permissions.
    RawPrimitiveAlongsidePermissions {
        /// Role the warning is about.
        role: String,
        /// Which raw primitive (`groups`/`sudo_role`/`limits`).
        primitive: &'static str,
    },
    /// A bound role expanded an in-group-membership sub-primitive (`groups`)
    /// onto a group target. There is no local group nesting to apply it to, so
    /// it is dropped. (LDAP-side nesting still works transparently through the
    /// group itself; this only concerns the local `usermod -aG` semantics.)
    GroupsPrimitiveOnGroupTarget {
        /// The bound role whose permission carried the `groups` primitive.
        role: String,
        /// The group target the binding pointed at.
        group: String,
    },
    /// A warning bubbled up from the catalog resolve (e.g. an unknown OS
    /// version resolved against the nearest lower layer, or a supplied
    /// permission parameter that matched no template placeholder).
    Catalog(catalog::Warning),
}

impl std::fmt::Display for ResolveWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveWarning::RawPrimitiveAlongsidePermissions { role, primitive } => write!(
                f,
                "role {role}: raw {primitive} used alongside permissions; prefer permissions"
            ),
            ResolveWarning::GroupsPrimitiveOnGroupTarget { role, group } => write!(
                f,
                "role {role}: permission `groups` (вступление в группу) не применимо к group-цели \
                 {group}; пропущено (локальной вложенности групп нет)"
            ),
            ResolveWarning::Catalog(catalog::Warning::UnknownOsVersion {
                missing_layer,
                resolved_against,
            }) => write!(
                f,
                "unknown OS version: layer {missing_layer} absent, resolved against {resolved_against}"
            ),
            ResolveWarning::Catalog(catalog::Warning::UnusedParam { permission, param }) => write!(
                f,
                "permission {permission}: parameter {param} matched no template placeholder (unused)"
            ),
        }
    }
}

/// Errors resolving a declaration into target accounts.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// Reading or parsing a role-store slice failed.
    #[error(transparent)]
    RoleStore(#[from] RoleStoreError),
    /// Expanding a permission against the catalog failed (unknown id, cycle,
    /// namespace collision, …). Fail-closed BEFORE apply — an unresolvable
    /// permission must never silently drop a primitive.
    #[error("role {role}: cannot expand permission: {source}")]
    Catalog {
        /// The role whose permission failed to resolve.
        role: String,
        /// The underlying catalog error.
        source: CatalogError,
    },
}

/// Inputs to permission expansion threaded through [`resolve`]. Bundles the
/// catalog source, the OS target, and the resolve context so the signature
/// stays small as later slices add fields (e.g. lint flags).
pub struct CompileInputs<'a> {
    /// The catalog to expand permissions against.
    pub catalog: &'a dyn CatalogSource,
    /// The OS target the device resolves for.
    pub os: &'a OsTarget,
    /// Resolve context (catalog version, …).
    pub ctx: &'a ResolveCtx,
}

/// Resolve every role account in the declaration against the role-store and the
/// permission catalog. Reads `<role_store>/<role>.toml` for each, expands its
/// permissions, and unions the expansion with the raw escape-hatch primitives.
///
/// Fails if any slice is missing/malformed, or if any permission cannot be
/// expanded (unknown id, cycle, …) — fail-closed before any plan/apply.
pub fn resolve(
    decl: &Declaration,
    inputs: &CompileInputs<'_>,
) -> Result<(Vec<ResolvedAccount>, Vec<ResolveWarning>), ResolveError> {
    let mut out = Vec::with_capacity(decl.role_accounts.len());
    let mut warnings = Vec::new();

    for acct in &decl.role_accounts {
        // Adopted accounts (no uid; bound to an existing user) do not project to
        // a created Unix account. Account-layer adoption — binding grants to the
        // existing user without `useradd` — lands in a later group-grants slice;
        // here they resolve to nothing so created accounts behave exactly as
        // before and no adopted user reaches the apply create path.
        let Some(uid) = acct.uid else {
            continue;
        };
        let comp = rolestore::read_composition(&decl.role_store, &acct.role)?;

        // Start from the raw escape-hatch primitives. The permission expansion
        // is unioned on top (raw wins for limits — see below).
        let mut groups: Vec<String> = comp.groups.clone();
        let mut sudo_commands: Vec<String> = Vec::new();
        // File grants come ONLY from permissions (no raw escape-hatch). Collect
        // every permission's resolved grants, then union by path below.
        let mut file_grants: Vec<catalog::ResolvedFileGrant> = Vec::new();
        // Raw limits win: capture whether the role set any so an expanded limit
        // never overwrites an explicit operator choice.
        let raw_limits_present = comp.limits != Limits::default();
        let mut limits = comp.limits.clone();

        // Lint: a raw primitive used alongside permissions. Emitted only when
        // the role ALSO declares permissions (raw-only roles are the legacy
        // path and not flagged).
        if !comp.permissions.is_empty() {
            if !comp.groups.is_empty() {
                warnings.push(ResolveWarning::RawPrimitiveAlongsidePermissions {
                    role: acct.role.clone(),
                    primitive: "groups",
                });
            }
            if comp.sudo_role.is_some() {
                warnings.push(ResolveWarning::RawPrimitiveAlongsidePermissions {
                    role: acct.role.clone(),
                    primitive: "sudo_role",
                });
            }
            if raw_limits_present {
                warnings.push(ResolveWarning::RawPrimitiveAlongsidePermissions {
                    role: acct.role.clone(),
                    primitive: "limits",
                });
            }
        }

        // Expand each permission ref, templating the catalog record's
        // `{placeholder}` strings against the ref's params (slice 3b). A bare ref
        // (empty params) on a placeholder-free record resolves exactly as before;
        // a parametrized ref substitutes — a list param emits one command per
        // element, an unfilled placeholder fails closed, an unused param warns.
        for perm in &comp.permissions {
            let (resolved, catalog_warnings) = catalog::resolve_with_params(
                &perm.id,
                &perm.params,
                inputs.os,
                inputs.catalog,
                inputs.ctx,
            )
            .map_err(|source| ResolveError::Catalog {
                role: acct.role.clone(),
                source,
            })?;
            for w in catalog_warnings {
                warnings.push(ResolveWarning::Catalog(w));
            }
            // Union expanded groups (dedup by value, preserving first-seen order).
            for g in resolved.groups {
                if !groups.contains(&g.value) {
                    groups.push(g.value);
                }
            }
            // Union expanded sudo commands (dedup by value, stable order).
            for s in resolved.sudo {
                if !sudo_commands.contains(&s.value) {
                    sudo_commands.push(s.value);
                }
            }
            // Accumulate this permission's resolved file grants; the by-path
            // union happens once after all permissions are collected.
            file_grants.extend(resolved.file_grants);
            // Limits: explicit raw limits win; otherwise the first expansion that
            // sets a field fills it in. We merge field-by-field so two
            // permissions can each contribute a different limit. Within a single
            // bundle the limit has already been collapsed first-wins by
            // catalog::resolve (the bundle's own/earlier-member limit wins over
            // later members), so `resolved.limits` here is one settled value per
            // permission — this loop only sequences across distinct permissions.
            if !raw_limits_present {
                if let Some(expanded) = resolved.limits {
                    merge_limits_first_wins(&mut limits, &expanded);
                }
            }
        }

        out.push(ResolvedAccount {
            name: acct.role.clone(),
            uid,
            shell: decl.shell_for(acct).to_owned(),
            home: decl.home_for(acct),
            groups,
            sudo_role: comp.sudo_role,
            sudo_commands,
            limits,
            file_grants: catalog::union_resolved_file_grants(file_grants),
            locked_password: true,
            // Only created accounts reach this point — adopted accounts (no uid)
            // are skipped above, so resolve never emits an Adopted account today.
            provenance: Provenance::Created,
        });
    }
    Ok((out, warnings))
}

/// Merge one permission's resolved limits into an accumulator, first-wins per
/// field: a field already set is left untouched, an unset field takes the
/// expansion's value. Shared by account and group resolution so both sequence
/// limits across permissions identically.
fn merge_limits_first_wins(acc: &mut Limits, expanded: &Limits) {
    if acc.nofile.is_none() {
        acc.nofile = expanded.nofile;
    }
    if acc.nproc.is_none() {
        acc.nproc = expanded.nproc;
    }
}

/// Resolve every `[[role_group]]` binding into the group grants Census wants to
/// materialize. Each declared `[[group]]` seeds a [`ResolvedGroup`] (name, GID
/// pin, provenance, members); each binding then reads the bound role's
/// composition, expands its permissions against the catalog, and unions the
/// resulting sudo commands, file grants, and limits onto the group. The
/// in-group-membership sub-primitive (`groups`) has no group-target meaning and
/// is dropped with a [`ResolveWarning::GroupsPrimitiveOnGroupTarget`].
///
/// Fails closed if a bound role's slice is missing/malformed (this is where a
/// `[[role_group]].role` is finally checked against the role-store — declaration
/// validation deliberately defers role existence to here) or if any permission
/// cannot be expanded.
pub fn resolve_groups(
    decl: &Declaration,
    inputs: &CompileInputs<'_>,
) -> Result<(Vec<ResolvedGroup>, Vec<ResolveWarning>), ResolveError> {
    let mut warnings = Vec::new();

    // Seed one ResolvedGroup per declared [[group]]. Provenance comes from the
    // group's `adopt` flag, NOT from any later `groups` pin — an adopted group is
    // observed, never assigned a GID. Bindings below accumulate grants onto these.
    let mut groups: Vec<ResolvedGroup> = decl
        .groups
        .iter()
        .map(|g| ResolvedGroup {
            name: g.name.clone(),
            gid: if g.adopt { None } else { g.gid },
            provenance: if g.adopt {
                Provenance::Adopted
            } else {
                Provenance::Created
            },
            members: g.members.clone(),
            sudo_commands: Vec::new(),
            file_grants: Vec::new(),
            limits: Limits::default(),
            bound_roles: Vec::new(),
        })
        .collect();

    for rg in &decl.role_groups {
        // Validation (slice 1) guarantees `rg.group` names a declared [[group]],
        // so the lookup always hits.
        let idx = groups
            .iter()
            .position(|g| g.name == rg.group)
            .expect("role_group target is a declared group (validated in slice 1)");

        // First point a role bound to a group is checked against the role-store.
        let comp = rolestore::read_composition(&decl.role_store, &rg.role)?;

        // Accumulate this binding's file grants separately, then union by path
        // once after every permission so the by-path widening is applied whole.
        let mut binding_file_grants: Vec<catalog::ResolvedFileGrant> = Vec::new();
        let mut emitted_groups_warning = false;

        for perm in &comp.permissions {
            let (resolved, catalog_warnings) = catalog::resolve_with_params(
                &perm.id,
                &perm.params,
                inputs.os,
                inputs.catalog,
                inputs.ctx,
            )
            .map_err(|source| ResolveError::Catalog {
                role: rg.role.clone(),
                source,
            })?;
            for w in catalog_warnings {
                warnings.push(ResolveWarning::Catalog(w));
            }
            // Union expanded sudo commands onto the group (dedup, stable order).
            for s in resolved.sudo {
                if !groups[idx].sudo_commands.contains(&s.value) {
                    groups[idx].sudo_commands.push(s.value);
                }
            }
            binding_file_grants.extend(resolved.file_grants);
            // Limits: first role/permission to set a field wins. Group targets
            // have no raw escape-hatch limits, so the accumulator starts empty
            // and fills field-by-field across permissions and bound roles.
            if let Some(expanded) = resolved.limits {
                let mut merged = groups[idx].limits.clone();
                merge_limits_first_wins(&mut merged, &expanded);
                groups[idx].limits = merged;
            }
            // The in-group-membership primitive has no group-target meaning;
            // drop it and warn once per binding if any permission carried one.
            if !resolved.groups.is_empty() && !emitted_groups_warning {
                warnings.push(ResolveWarning::GroupsPrimitiveOnGroupTarget {
                    role: rg.role.clone(),
                    group: rg.group.clone(),
                });
                emitted_groups_warning = true;
            }
        }

        // Union this binding's file grants into the group's, by path.
        if !binding_file_grants.is_empty() {
            let mut all = std::mem::take(&mut groups[idx].file_grants);
            all.extend(binding_file_grants);
            groups[idx].file_grants = catalog::union_resolved_file_grants(all);
        }

        // Record the contributing role (dedup, insertion order).
        if !groups[idx].bound_roles.contains(&rg.role) {
            groups[idx].bound_roles.push(rg.role.clone());
        }
    }

    Ok((groups, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{FakeCatalog, ListOverride, OsTarget, PermissionDef, ResolveCtx};
    use crate::rolestore::Limits;
    use std::io::Write;

    /// A fixed OS target for tests (no /etc/os-release dependency).
    fn os() -> OsTarget {
        OsTarget::new("linux", "debian", Some("12".to_owned())).unwrap()
    }

    /// An empty catalog + fixed OS + empty ctx — the "no permissions" path,
    /// behaving exactly as before (pure raw fields).
    fn empty_inputs<'a>(cat: &'a FakeCatalog, os: &'a OsTarget, ctx: &'a ResolveCtx) -> CompileInputs<'a> {
        CompileInputs { catalog: cat, os, ctx }
    }

    fn def(id: &str) -> PermissionDef {
        PermissionDef {
            id: id.to_owned(),
            risk: None,
            category: None,
            groups: ListOverride::default(),
            sudo: ListOverride::default(),
            limits: None,
            replace: false,
            includes: Vec::new(),
            include_categories: Vec::new(),
            files: Vec::new(),
        }
    }

    fn fixture(payload: &str) -> (tempfile::TempDir, Declaration) {
        let tmp = tempfile::tempdir().unwrap();
        let mut f = std::fs::File::create(tmp.path().join("oper.toml")).unwrap();
        f.write_all(
            format!(
                "role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"Operator\"\nlevel = 5\n{payload}"
            )
            .as_bytes(),
        )
        .unwrap();
        let store = tmp.path().display().to_string();
        let decl_text = format!(
            r#"
version = 4
role_store = "{store}"
[defaults]
uid_range = [9000, 9999]
shell = "/bin/bash"
home_base = "/var/lib/census/home"
[[role_account]]
role = "oper"
uid = 9010
"#
        );
        let decl = Declaration::parse(&decl_text).unwrap();
        (tmp, decl)
    }

    #[test]
    fn resolves_account_with_raw_composition_and_invariants() {
        // Legacy raw-only path: an empty catalog, no permissions → behaves
        // exactly as before permission expansion existed.
        let (_tmp, decl) = fixture("[payload]\ngroups = [\"wheel\"]\nsudo_role = \"ops\"\n");
        let cat = FakeCatalog::new();
        let ctx = ResolveCtx::default();
        let os = os();
        let (resolved, warnings) = resolve(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap();
        assert_eq!(resolved.len(), 1);
        let a = &resolved[0];
        assert_eq!(a.name, "oper");
        assert_eq!(a.uid, 9010);
        assert_eq!(a.shell, "/bin/bash");
        assert_eq!(a.home, PathBuf::from("/var/lib/census/home/oper"));
        assert_eq!(a.groups, vec!["wheel"]);
        assert_eq!(a.sudo_role.as_deref(), Some("ops"));
        assert!(a.sudo_commands.is_empty(), "raw-only role has no expanded sudo commands");
        assert!(a.locked_password, "role accounts must be password-locked");
        // No permissions → no lint about raw primitives.
        assert!(warnings.is_empty(), "raw-only role must not warn: {warnings:?}");
    }

    /// Mirror a resolved target account into the managed record Census would
    /// have persisted for it (the fields the plan diff compares).
    fn managed_from(acct: &ResolvedAccount) -> crate::state::ManagedAccount {
        crate::state::ManagedAccount {
            name: acct.name.clone(),
            uid: acct.uid,
            shell: acct.shell.clone(),
            groups: acct.groups.clone(),
            sudo_role: acct.sudo_role.clone(),
            sudo_commands: acct.sudo_commands.clone(),
            file_grants: acct
                .file_grants
                .iter()
                .map(crate::state::ManagedFileGrant::from_resolved)
                .collect(),
            provenance: acct.provenance,
            from_version: 1,
        }
    }

    /// Minimal in-test system state reporting a fixed set of managed accounts,
    /// so the model layer can exercise the plan diff without the apply layer.
    struct StateOf(std::collections::BTreeMap<String, crate::state::ManagedAccount>);
    impl crate::state::SystemState for StateOf {
        fn managed_accounts(
            &self,
        ) -> std::collections::BTreeMap<String, crate::state::ManagedAccount> {
            self.0.clone()
        }
    }

    #[test]
    fn concrete_command_role_round_trips_idempotently() {
        // Materialize a permission-expanded role into a ResolvedAccount, persist
        // it as the managed record, feed that back as current state, and assert
        // the plan is empty: a freshly-applied concrete-command role must not
        // re-diff against itself. The inverse (a changed command set) must Update,
        // locking the revocation contract.
        let (_tmp, decl) = fixture("[payload]\npermissions = [\"net-admin\"]\n");
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                groups: ListOverride::Replace(vec!["netdev".to_owned()]),
                sudo: ListOverride::Replace(vec![
                    "/usr/sbin/ip".to_owned(),
                    "/usr/bin/nmcli".to_owned(),
                ]),
                ..def("net-admin")
            },
        );
        let ctx = ResolveCtx::default();
        let os = os();
        let (resolved, _) = resolve(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap();
        let target = &resolved[0];

        // Round-trip: managed state mirrors the resolved target → empty plan.
        let mut managed = std::collections::BTreeMap::new();
        managed.insert(target.name.clone(), managed_from(target));
        let state = StateOf(managed);
        let plan = crate::plan::diff(&resolved, &state);
        assert!(
            plan.is_empty(),
            "a role applied then re-resolved must yield no changes: {plan:?}"
        );

        // Inverse: a managed record missing a command must produce an Update so
        // the NOPASSWD fragment is rewritten (no stale/leaked grant).
        let mut stale = managed_from(target);
        stale.sudo_commands = vec!["/usr/sbin/ip".to_owned()];
        let mut managed2 = std::collections::BTreeMap::new();
        managed2.insert(target.name.clone(), stale);
        let plan2 = crate::plan::diff(&resolved, &StateOf(managed2));
        assert!(
            matches!(plan2.actions.as_slice(), [crate::plan::Action::Update { .. }]),
            "a differing command set must Update: {plan2:?}"
        );
    }

    #[test]
    fn parametrized_permission_ref_templates_units() {
        // A parametrized ref now drives substitution (slice 3b): a list param
        // `unit` expands the `{unit}` template into one command per element.
        let (_tmp, decl) = fixture(
            "[payload]\npermissions = [{ id = \"service-restart\", unit = [\"nginx\", \"atm-app\"] }]\n",
        );
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec![
                    "/usr/bin/systemctl restart {unit}".to_owned(),
                    "/usr/bin/systemctl restart {unit}.service".to_owned(),
                ]),
                ..def("service-restart")
            },
        );
        let ctx = ResolveCtx::default();
        let os = os();
        let (resolved, warnings) = resolve(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap();
        // 2 templates x 2 units = 4 concrete commands, all braces resolved.
        assert_eq!(
            resolved[0].sudo_commands,
            vec![
                "/usr/bin/systemctl restart nginx",
                "/usr/bin/systemctl restart atm-app",
                "/usr/bin/systemctl restart nginx.service",
                "/usr/bin/systemctl restart atm-app.service",
            ]
        );
        // Fully-consumed params emit no UnusedParam warning (an unrelated
        // UnknownOsVersion may surface from the test's version-only OS target).
        assert!(
            !warnings.iter().any(|w| matches!(
                w,
                ResolveWarning::Catalog(catalog::Warning::UnusedParam { .. })
            )),
            "fully-consumed params must not warn unused: {warnings:?}"
        );
    }

    #[test]
    fn parametrized_ref_with_injection_value_fails_closed() {
        // A param value injecting a comma (which would split one sudoers Cmnd into
        // two, broadening the grant) must fail resolution, not silently expand.
        let (_tmp, decl) = fixture(
            "[payload]\npermissions = [{ id = \"service-restart\", unit = \"nginx,/bin/sh\" }]\n",
        );
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/systemctl restart {unit}".to_owned()]),
                ..def("service-restart")
            },
        );
        let ctx = ResolveCtx::default();
        let os = os();
        let err = resolve(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap_err();
        assert!(
            matches!(
                err,
                ResolveError::Catalog { source: CatalogError::InvalidParamValue { .. }, .. }
            ),
            "injection via param value must fail closed: {err:?}"
        );
    }

    #[test]
    fn parametrized_ref_missing_placeholder_param_fails_closed() {
        // A template with {unit} but a ref that supplies no `unit` param must
        // fail closed — an unfilled placeholder must never reach sudoers literally.
        let (_tmp, decl) = fixture(
            "[payload]\npermissions = [{ id = \"service-restart\", other = \"x\" }]\n",
        );
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/systemctl restart {unit}".to_owned()]),
                ..def("service-restart")
            },
        );
        let ctx = ResolveCtx::default();
        let os = os();
        let err = resolve(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap_err();
        assert!(
            matches!(
                err,
                ResolveError::Catalog { source: CatalogError::MissingParam { .. }, .. }
            ),
            "unfilled placeholder must fail closed: {err:?}"
        );
    }

    #[test]
    fn parametrized_ref_unused_param_warns() {
        // A supplied param that matches no placeholder surfaces as a warning
        // (forward-compat / typo signal), not an error.
        let (_tmp, decl) = fixture(
            "[payload]\npermissions = [{ id = \"net\", bogus = \"x\" }]\n",
        );
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                ..def("net")
            },
        );
        let ctx = ResolveCtx::default();
        let os = os();
        let (resolved, warnings) = resolve(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap();
        assert_eq!(resolved[0].sudo_commands, vec!["/usr/sbin/ip"]);
        assert!(
            warnings.iter().any(|w| matches!(
                w,
                ResolveWarning::Catalog(catalog::Warning::UnusedParam { permission, param })
                    if permission == "net" && param == "bogus"
            )),
            "unused param must warn: {warnings:?}"
        );
    }

    #[test]
    fn bare_permission_ref_resolves_without_template_warnings() {
        // A ref with no params on a placeholder-free record must resolve cleanly
        // with no template-related warnings.
        let (_tmp, decl) = fixture("[payload]\npermissions = [\"service-restart\"]\n");
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/bin/systemctl".to_owned()]),
                ..def("service-restart")
            },
        );
        let ctx = ResolveCtx::default();
        let os = os();
        let (resolved, warnings) = resolve(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap();
        assert_eq!(resolved[0].sudo_commands, vec!["/usr/bin/systemctl"]);
        // No template-related warnings (an unrelated UnknownOsVersion may surface
        // from the version-only OS target the fixture uses).
        assert!(
            !warnings.iter().any(|w| matches!(
                w,
                ResolveWarning::Catalog(catalog::Warning::UnusedParam { .. })
            )),
            "bare ref on plain record must not warn about params: {warnings:?}"
        );
    }

    #[test]
    fn missing_slice_fails_resolution() {
        let (_tmp, mut decl) = fixture("[payload]\ngroups = [\"wheel\"]\n");
        decl.role_accounts[0].role = "ghost".to_owned();
        let cat = FakeCatalog::new();
        let ctx = ResolveCtx::default();
        let os = os();
        assert!(resolve(&decl, &empty_inputs(&cat, &os, &ctx)).is_err());
    }

    #[test]
    fn permission_expands_into_groups_and_sudo_commands() {
        // Role authored purely in permissions; the catalog expands `net-admin`
        // into a group + two sudo commands.
        let (_tmp, decl) = fixture("[payload]\npermissions = [\"net-admin\"]\n");
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                groups: ListOverride::Replace(vec!["netdev".to_owned()]),
                sudo: ListOverride::Replace(vec![
                    "/usr/sbin/ip".to_owned(),
                    "/usr/bin/nmcli".to_owned(),
                ]),
                ..def("net-admin")
            },
        );
        let ctx = ResolveCtx::default();
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (resolved, warnings) = resolve(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap();
        let a = &resolved[0];
        assert_eq!(a.groups, vec!["netdev"]);
        assert_eq!(a.sudo_commands, vec!["/usr/sbin/ip", "/usr/bin/nmcli"]);
        // Pure permissions, no raw fields → no lint.
        assert!(warnings.is_empty(), "pure-permission role must not warn: {warnings:?}");
    }

    #[test]
    fn permission_carrying_dir_file_grant_lands_on_resolved_account() {
        use crate::catalog::{Access, FileGrant, Shape};
        let (_tmp, decl) = fixture("[payload]\npermissions = [\"fs-edit\"]\n");
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                files: vec![FileGrant {
                    path: "/etc/ssh".to_owned(),
                    access: Access::Rw,
                    recursive: true,
                }],
                ..def("fs-edit")
            },
        );
        let ctx = ResolveCtx::default();
        let os = os();
        let (resolved, _) = resolve(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap();
        let a = &resolved[0];
        assert_eq!(a.file_grants.len(), 1);
        assert_eq!(a.file_grants[0].path, "/etc/ssh");
        assert_eq!(a.file_grants[0].access, Access::Rw);
        assert!(a.file_grants[0].recursive);
        assert_eq!(a.file_grants[0].shape, Shape::Dir);
    }

    #[test]
    fn file_grants_union_across_two_permissions_by_path() {
        use crate::catalog::{Access, FileGrant};
        // Two permissions grant the SAME path: ro+non-recursive and rw+recursive.
        // The account-level union widens access to rw and ORs recursive to true.
        let (_tmp, decl) = fixture("[payload]\npermissions = [\"fs-read\", \"fs-edit\"]\n");
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    files: vec![FileGrant {
                        path: "/etc/ssh".to_owned(),
                        access: Access::Ro,
                        recursive: false,
                    }],
                    ..def("fs-read")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    files: vec![FileGrant {
                        path: "/etc/ssh".to_owned(),
                        access: Access::Rw,
                        recursive: true,
                    }],
                    ..def("fs-edit")
                },
            );
        let ctx = ResolveCtx::default();
        let os = os();
        let (resolved, _) = resolve(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap();
        let a = &resolved[0];
        assert_eq!(a.file_grants.len(), 1, "same path unions to one grant");
        assert_eq!(a.file_grants[0].access, Access::Rw, "access widens to rw");
        assert!(a.file_grants[0].recursive, "recursive ORs to true");
        assert_eq!(a.file_grants[0].sources.len(), 2, "both contributors recorded");
    }

    #[test]
    fn raw_and_permission_groups_union_with_lint_warning() {
        // Role declares BOTH a raw group and a permission. The result is the
        // union, and a lint warning flags the raw primitive.
        let (_tmp, decl) =
            fixture("[payload]\ngroups = [\"wheel\"]\npermissions = [\"net-admin\"]\n");
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                groups: ListOverride::Replace(vec!["netdev".to_owned()]),
                ..def("net-admin")
            },
        );
        let ctx = ResolveCtx::default();
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (resolved, warnings) = resolve(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap();
        let a = &resolved[0];
        // Raw group first (it seeds the accumulator), then the expanded one.
        assert_eq!(a.groups, vec!["wheel", "netdev"]);
        assert!(
            warnings.iter().any(|w| matches!(
                w,
                ResolveWarning::RawPrimitiveAlongsidePermissions { primitive: "groups", .. }
            )),
            "raw group alongside permissions must lint: {warnings:?}"
        );
    }

    #[test]
    fn duplicate_group_from_raw_and_permission_deduped() {
        let (_tmp, decl) =
            fixture("[payload]\ngroups = [\"netdev\"]\npermissions = [\"net-admin\"]\n");
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                groups: ListOverride::Replace(vec!["netdev".to_owned()]),
                ..def("net-admin")
            },
        );
        let ctx = ResolveCtx::default();
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (resolved, _) = resolve(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap();
        assert_eq!(resolved[0].groups, vec!["netdev"], "duplicate group deduped");
    }

    #[test]
    fn unknown_permission_id_is_resolve_error() {
        // A role references a permission no catalog layer defines → fail-closed.
        let (_tmp, decl) = fixture("[payload]\npermissions = [\"does-not-exist\"]\n");
        let cat = FakeCatalog::new();
        let ctx = ResolveCtx::default();
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let err = resolve(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap_err();
        assert!(
            matches!(err, ResolveError::Catalog { source: CatalogError::UnknownPermission(_), .. }),
            "unknown permission must fail closed: {err:?}"
        );
    }

    #[test]
    fn raw_limits_win_over_expanded() {
        // The role sets raw limits AND a permission that also expands limits;
        // the raw value wins (explicit operator choice).
        let (_tmp, decl) = fixture(
            "[payload]\npermissions = [\"big-files\"]\n[payload.limits]\nnofile = 1024\n",
        );
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                limits: Some(crate::catalog::CatalogLimits { nofile: Some(99999), nproc: Some(512) }),
                ..def("big-files")
            },
        );
        let ctx = ResolveCtx::default();
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (resolved, warnings) = resolve(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap();
        let a = &resolved[0];
        // Raw nofile wins; nproc is NOT filled from the expansion because raw
        // limits were present (raw wins wholesale to keep operator intent clear).
        assert_eq!(a.limits.nofile, Some(1024), "raw nofile wins");
        assert_eq!(a.limits.nproc, None, "raw-limits-present blocks expanded merge");
        assert!(
            warnings.iter().any(|w| matches!(
                w,
                ResolveWarning::RawPrimitiveAlongsidePermissions { primitive: "limits", .. }
            )),
            "raw limits alongside permissions must lint"
        );
    }

    #[test]
    fn expanded_limits_fill_in_when_no_raw() {
        let (_tmp, decl) = fixture("[payload]\npermissions = [\"big-files\"]\n");
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                limits: Some(crate::catalog::CatalogLimits { nofile: Some(4096), nproc: None }),
                ..def("big-files")
            },
        );
        let ctx = ResolveCtx::default();
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (resolved, _) = resolve(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap();
        assert_eq!(resolved[0].limits, Limits { nofile: Some(4096), nproc: None });
    }

    #[test]
    fn resolve_emits_created_provenance() {
        // A created account (uid present) carries Created provenance.
        let (_tmp, decl) = fixture("[payload]\ngroups = [\"wheel\"]\n");
        let cat = FakeCatalog::new();
        let ctx = ResolveCtx::default();
        let os = os();
        let (resolved, _) = resolve(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap();
        assert_eq!(resolved[0].provenance, Provenance::Created);
    }

    // ---- group-grants slice 2: resolve_groups + provenance ----

    /// A role-store directory holding the named slices, plus a declaration whose
    /// `[[group]]`/`[[role_group]]` blocks are appended via `decl_extra`. Each
    /// slice in `slices` is `(role, payload_body)` where `payload_body` is the
    /// `[payload]` section text. Returns the temp dir (kept alive) and the parsed
    /// declaration.
    fn group_fixture(
        slices: &[(&str, &str)],
        decl_extra: &str,
    ) -> (tempfile::TempDir, Declaration) {
        let tmp = tempfile::tempdir().unwrap();
        for (role, payload) in slices {
            let mut f = std::fs::File::create(tmp.path().join(format!("{role}.toml"))).unwrap();
            f.write_all(
                format!(
                    "role = \"{role}\"\nversion = 1\nos = \"linux\"\nname = \"{role}\"\nlevel = 5\n{payload}"
                )
                .as_bytes(),
            )
            .unwrap();
        }
        let store = tmp.path().display().to_string();
        let decl_text = format!(
            r#"
version = 4
role_store = "{store}"
[defaults]
uid_range = [9000, 9999]
shell = "/bin/bash"
home_base = "/var/lib/census/home"
{decl_extra}
"#
        );
        let decl = Declaration::parse(&decl_text).unwrap();
        (tmp, decl)
    }

    #[test]
    fn role_group_projects_role_grants_onto_group() {
        // A non-adopted group bound to a role gets the role's sudo, file grants,
        // and limits; provenance is Created and gid keeps its pin.
        let (_tmp, decl) = group_fixture(
            &[(
                "netops",
                "[payload]\npermissions = [\"net-admin\"]\n",
            )],
            "[[group]]\nname = \"ops\"\ngid = 8020\n[[role_group]]\nrole = \"netops\"\ngroup = \"ops\"\n",
        );
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                limits: Some(crate::catalog::CatalogLimits { nofile: Some(4096), nproc: None }),
                files: vec![crate::catalog::FileGrant {
                    path: "/etc/net".to_owned(),
                    access: crate::catalog::Access::Rw,
                    recursive: true,
                }],
                ..def("net-admin")
            },
        );
        let ctx = ResolveCtx::default();
        // Versionless OS so no UnknownOsVersion warning masks the clean-binding
        // assertion (mirrors the account-side clean-resolve tests).
        let os = OsTarget::new("linux", "debian", None).unwrap();
        let (groups, warnings) = resolve_groups(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap();
        assert_eq!(groups.len(), 1);
        let g = &groups[0];
        assert_eq!(g.name, "ops");
        assert_eq!(g.gid, Some(8020));
        assert_eq!(g.provenance, Provenance::Created);
        assert_eq!(g.sudo_commands, vec!["/usr/sbin/ip"]);
        assert_eq!(g.limits, Limits { nofile: Some(4096), nproc: None });
        assert_eq!(g.file_grants.len(), 1);
        assert_eq!(g.file_grants[0].path, "/etc/net");
        assert_eq!(g.bound_roles, vec!["netops"]);
        assert!(warnings.is_empty(), "clean binding must not warn: {warnings:?}");
    }

    #[test]
    fn adopted_group_has_none_gid_and_adopted_provenance() {
        // An adopted group: provenance Adopted, gid observed at apply (None here),
        // members carried verbatim.
        let (_tmp, decl) = group_fixture(
            &[("netops", "[payload]\npermissions = [\"net-admin\"]\n")],
            // `netops` must be a managed account to be a member of an adopted group
            // (slice-1 invariant: never drag a third party into a pre-existing group).
            "[[role_account]]\nrole = \"netops\"\nuid = 9010\n\
             [[group]]\nname = \"wheel\"\nadopt = true\nmembers = [\"netops\"]\n\
             [[role_group]]\nrole = \"netops\"\ngroup = \"wheel\"\n",
        );
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                ..def("net-admin")
            },
        );
        let ctx = ResolveCtx::default();
        let os = os();
        let (groups, _) = resolve_groups(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap();
        let g = &groups[0];
        assert_eq!(g.provenance, Provenance::Adopted);
        assert_eq!(g.gid, None, "adopted group's gid is observed, not assigned");
        assert_eq!(g.members, vec!["netops"]);
    }

    #[test]
    fn multiple_roles_on_one_group_union() {
        // Two roles bound to the same group: sudo commands union, bound_roles
        // holds both in insertion order.
        let (_tmp, decl) = group_fixture(
            &[
                ("netops", "[payload]\npermissions = [\"net\"]\n"),
                ("dbops", "[payload]\npermissions = [\"db\"]\n"),
            ],
            "[[group]]\nname = \"ops\"\n\
             [[role_group]]\nrole = \"netops\"\ngroup = \"ops\"\n\
             [[role_group]]\nrole = \"dbops\"\ngroup = \"ops\"\n",
        );
        let cat = FakeCatalog::new()
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                    ..def("net")
                },
            )
            .with(
                "linux",
                PermissionDef {
                    sudo: ListOverride::Replace(vec!["/usr/bin/psql".to_owned()]),
                    ..def("db")
                },
            );
        let ctx = ResolveCtx::default();
        let os = os();
        let (groups, _) = resolve_groups(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap();
        let g = &groups[0];
        assert_eq!(g.sudo_commands, vec!["/usr/sbin/ip", "/usr/bin/psql"]);
        assert_eq!(g.bound_roles, vec!["netops", "dbops"]);
    }

    #[test]
    fn groups_primitive_on_group_target_warns_and_is_dropped() {
        // A permission whose expansion includes a group-membership primitive
        // (`groups`) bound to a group target: warn-and-skip. ResolvedGroup carries
        // no `groups` field, so the only observable effect is the warning.
        let (_tmp, decl) = group_fixture(
            &[("netops", "[payload]\npermissions = [\"net-admin\"]\n")],
            "[[group]]\nname = \"ops\"\n[[role_group]]\nrole = \"netops\"\ngroup = \"ops\"\n",
        );
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                groups: ListOverride::Replace(vec!["netdev".to_owned()]),
                sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                ..def("net-admin")
            },
        );
        let ctx = ResolveCtx::default();
        let os = os();
        let (groups, warnings) = resolve_groups(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap();
        // The sudo grant still lands; only the membership primitive is dropped.
        assert_eq!(groups[0].sudo_commands, vec!["/usr/sbin/ip"]);
        assert!(
            warnings.iter().any(|w| matches!(
                w,
                ResolveWarning::GroupsPrimitiveOnGroupTarget { role, group }
                    if role == "netops" && group == "ops"
            )),
            "groups primitive on a group target must warn: {warnings:?}"
        );
    }

    #[test]
    fn role_group_to_missing_role_slice_fails_closed() {
        // The role bound to the group has no role-store slice → resolve_groups
        // fails closed (this is where role existence is finally checked).
        let (_tmp, decl) = group_fixture(
            &[("netops", "[payload]\npermissions = [\"net\"]\n")],
            "[[group]]\nname = \"ops\"\n[[role_group]]\nrole = \"ghost\"\ngroup = \"ops\"\n",
        );
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                sudo: ListOverride::Replace(vec!["/usr/sbin/ip".to_owned()]),
                ..def("net")
            },
        );
        let ctx = ResolveCtx::default();
        let os = os();
        let err = resolve_groups(&decl, &empty_inputs(&cat, &os, &ctx)).unwrap_err();
        assert!(
            matches!(err, ResolveError::RoleStore(RoleStoreError::NotFound(_))),
            "binding to a role with no slice must fail closed: {err:?}"
        );
    }
}
