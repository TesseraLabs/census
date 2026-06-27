//! `census apply` orchestrator (spec R-flow / tasks section 6).
//!
//! Flow (design "Поток apply"):
//! ```text
//! verify trust → parse + resolve (slice-1) → load managed state → diff
//!   → anti-lockout gate → snapshot → apply phases (create→update→delete)
//!   → on any phase error: restore → return error (non-zero)
//!   → on success: write managed registry (atomic, LAST) → drop snapshot
//! ```
//!
//! The orchestrator depends on the [`Provisioner`] trait (not on shadow-utils
//! directly), so it is fully unit-testable with a [`FakeProvisioner`]: happy
//! path, phase-failure → restore + no registry write, and idempotent empty plan.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::declaration::Declaration;
use crate::inspect::SystemInspector;
use crate::mutate::{ProvisionError, Provisioner};
use crate::plan::{self, Action, GroupAction};
use crate::state::{ManagedAccount, ManagedFileGrant, ManagedGroup, SystemState};
use crate::trust::{self, TrustMode, TrustOptions};

/// Errors that abort apply (each maps to a non-zero exit upstream).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApplyError {
    /// Declaration was not trusted (fail-closed); carries the reason.
    #[error("declaration not trusted: {0}")]
    NotTrusted(String),
    /// Trust evaluation itself failed.
    #[error(transparent)]
    Trust(#[from] trust::TrustError),
    /// Anti-lockout gate refused the plan.
    #[error(transparent)]
    Lockout(#[from] crate::lockout::LockoutError),
    /// A provisioning phase failed; rollback was attempted.
    #[error("apply failed during {phase}: {source}; rollback {rollback}")]
    Phase {
        /// Which phase failed (create/update/delete).
        phase: &'static str,
        /// The underlying provisioner error.
        source: ProvisionError,
        /// Outcome of the restore attempt.
        rollback: RollbackOutcome,
    },
    /// Writing the managed registry (last, atomic) failed after success.
    #[error("registry write failed: {0}")]
    Registry(String),
    /// Resolving the declaration (role-store read + permission expansion against
    /// the catalog) failed. Surfaced BEFORE any snapshot/mutation — an
    /// unresolvable permission (unknown id, cycle) must fail closed.
    #[error("resolve failed: {0}")]
    Resolve(String),
    /// Group planning failed (GID-pin conflict or managed-group GID drift). This
    /// is surfaced BEFORE any snapshot/mutation — Census never renumbers.
    #[error("group plan rejected: {0}")]
    GroupPlan(#[from] plan::GroupPlanError),
    /// The required group set contains an invalid name (e.g. a malformed
    /// role-store `payload.groups` entry). Surfaced before any mutation so apply
    /// fails closed rather than passing the name to `groupadd`.
    #[error(transparent)]
    Declaration(#[from] crate::declaration::DeclarationError),
    /// The live-session registry is present but unreadable/corrupt, AND the plan
    /// is destructive (≥1 Delete). We cannot prove no session is live, so we
    /// fail closed BEFORE snapshot rather than risk tearing down a live session.
    /// A non-destructive plan is never blocked by this (nothing to defer).
    #[error("live-session registry unreadable and plan is destructive: {0}")]
    SessionRegistry(String),
    /// A file-access grant could not be routed to a capable backend
    /// (capability-gating, fail-closed) or its materialization/revocation
    /// failed. The gating variant is surfaced BEFORE any snapshot or mutation —
    /// Census refuses an unenforceable grant rather than applying weaker access.
    #[error("file access: {0}")]
    FileAccess(#[from] crate::fileaccess::FileAccessError),
    /// A group action references a group that resolve never produced — the plan
    /// and the resolved set disagree, which can only happen if an internal
    /// invariant was broken (a corrupt or externally-tampered plan). Detected
    /// mid-apply, so rollback is attempted before the error surfaces; Census
    /// never proceeds on an inconsistent plan.
    #[error("corrupt plan: group action names {group:?} which resolve did not produce; rollback {rollback}")]
    CorruptPlan {
        /// The group name the plan action referenced.
        group: String,
        /// Outcome of the restore attempt.
        rollback: RollbackOutcome,
    },
}

/// A `userdel` that was deferred because the account has a live Tessera session.
/// Census skips the delete, retains ownership of the account, and reports it so
/// the caller can signal a partial apply (non-zero exit).
#[derive(Debug, Clone)]
pub struct DeferredDelete {
    /// Role-account name whose deletion was deferred.
    pub name: String,
    /// Its UID (from the managed registry).
    pub uid: u32,
}

/// Result of attempting a rollback after a phase failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackOutcome {
    /// Snapshot restored successfully — OS is back to the prior state.
    Restored,
    /// Restore itself failed; the snapshot is retained for manual recovery.
    Failed(String),
}

impl std::fmt::Display for RollbackOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RollbackOutcome::Restored => write!(f, "succeeded"),
            RollbackOutcome::Failed(e) => write!(f, "FAILED: {e}"),
        }
    }
}

/// A line for the caller to log (trust decisions, risk acknowledgements, etc.).
pub type LogLine = String;

/// Inputs to [`run`] beyond the trait object.
///
/// Generic over the catalog source `C` (carried by the embedded
/// [`CompileInputs`]) so permission expansion dispatches statically — one apply
/// runs against exactly one catalog source.
pub struct ApplyInputs<'a, C: crate::catalog::CatalogSource> {
    /// Parsed, schema-valid declaration.
    pub declaration: &'a Declaration,
    /// Raw declaration bytes (for managed-mode signature canonicalization). The
    /// signature covers these bytes with the `signature` line removed.
    pub declaration_bytes: &'a [u8],
    /// Current managed state (registry-backed in production).
    pub state: &'a dyn SystemState,
    /// Read-only live-system inspector, used to plan group actions (does a
    /// required group already exist? its GID?). Read-only — never mutates.
    pub inspector: &'a dyn SystemInspector,
    /// Trust options (`--trust-fs`, trust-anchor path, anti-rollback persist dir).
    pub trust: TrustOptions,
    /// Anti-lockout context (`rescue_present`, `--i-understand-no-rescue`).
    pub lockout: crate::lockout::LockoutContext,
    /// Directory the role sudoers fragments live in (default `/etc/sudoers.d`;
    /// injectable for tests). Used to compute the touched fragment paths added
    /// to the backup set before snapshot, and must match the provisioner's dir.
    pub sudoers_dir: PathBuf,
    /// Live-session source (§12). Consulted before the delete phase to DEFER
    /// `userdel` for any role-account that currently has a live session.
    pub session_source: &'a dyn crate::sessions::SessionSource,
    /// The registry path `session_source` consults — for a log line only (so the
    /// operator sees which file was read).
    pub sessions_file: PathBuf,
    /// Permission-expansion inputs (catalog source + OS target + resolve ctx).
    /// Threaded into [`crate::model::resolve`] so a role's `permissions` expand
    /// into concrete primitives before the plan is built.
    pub compile: crate::model::CompileInputs<'a, C>,
    /// File-access enforcement backend (production wires
    /// [`crate::fileaccess::AclBackend::production`]; tests pass a
    /// [`crate::fileaccess::FakeBackend`]). This is a SEPARATE seam from
    /// [`Provisioner`]: the provisioner drives shadow-utils (accounts / groups /
    /// sudoers) while this backend materializes / revokes / snapshots / restores
    /// file grants. Held as one backend for this slice, but routed through
    /// [`crate::fileaccess::route_grants`] so capability-gating is exercised and
    /// adding more backends later is a one-line change.
    pub file_access: &'a mut dyn crate::fileaccess::FileAccessBackend,
}

/// Outcome of a successful apply: the new managed registry contents and the log
/// lines accumulated along the way. The caller persists the registry atomically.
#[derive(Debug)]
pub struct ApplyReport {
    /// New managed accounts (to write to the registry, atomic & last).
    pub managed: Vec<ManagedAccount>,
    /// New managed groups (to write to the registry alongside accounts). Only
    /// groups Census created (went through `create_group`) and still-present
    /// owned groups are recorded; deleted orphans are dropped.
    pub managed_group_records: Vec<ManagedGroup>,
    /// Lines worth logging (trust decision, risk-ack, per-phase actions).
    pub log: Vec<LogLine>,
    /// Number of mutating operations performed (0 == idempotent no-op).
    pub mutations: usize,
    /// Whether the caller should persist the managed registry. `false` on an
    /// empty (idempotent no-op) plan: the registry already matches the target
    /// set, so a byte-identical rewrite would only bump mtime (spec R8: zero
    /// mutations means zero on-disk changes).
    pub registry_written: bool,
    /// The trust mode this apply ran under. The caller persists the
    /// anti-rollback version floor (only) when this is
    /// [`TrustMode::Managed`] AND the apply succeeded; standalone never persists.
    pub trust_mode: TrustMode,
    /// Deletes deferred because the account has a live session (§12). Empty when
    /// none were deferred. A non-empty list means the apply is a partial success
    /// (the caller exits non-zero, distinguishably from a phase failure).
    pub deferred_deletes: Vec<DeferredDelete>,
}

/// Run the apply orchestration over a provisioner. This is the unit-testable
/// core; CLI wiring (reading files, writing the registry to disk) lives in
/// [`crate::cli`].
///
/// On success returns the new managed set; the caller writes it to the registry
/// atomically and last. On any phase failure the provisioner has already been
/// asked to restore, and the error carries the rollback outcome.
pub fn run<C: crate::catalog::CatalogSource>(
    inputs: ApplyInputs<'_, C>,
    provisioner: &mut dyn Provisioner,
) -> Result<ApplyReport, ApplyError> {
    let mut log = Vec::new();

    // 1. Trust (fail-closed) — before any state read or mutation. Operates on
    // the RAW declaration bytes so managed mode can canonicalize the signature.
    let decision =
        trust::verify_trust(inputs.declaration, inputs.declaration_bytes, &inputs.trust)?;
    log.push(decision.reason().to_owned());
    let trust_mode = match decision.mode() {
        Some(mode) => mode.clone(),
        None => return Err(ApplyError::NotTrusted(decision.reason().to_owned())),
    };

    // 2-3. Resolve targets, expanding each role's permissions against the
    // catalog into concrete primitives BEFORE the diff (design "Конвейер
    // компиляции"). Resolve warnings (catalog lint + raw-primitive lint) flow
    // into the apply log. A failed expansion (unknown id, cycle) fails closed
    // here — before any snapshot or mutation.
    let (targets, resolve_warnings) = crate::model::resolve(inputs.declaration, &inputs.compile)
        .map_err(|e| ApplyError::Resolve(e.to_string()))?;
    for w in &resolve_warnings {
        log.push(format!("warning: {w}"));
    }

    // Resolve the declared groups too (the declaration-driven grants path):
    // each `[[group]]` joined with the grants every bound role contributes
    // (%group sudo commands, g:group file grants, added members) + provenance.
    // This is the AUTHORITY for a group's GRANTS; group EXISTENCE stays with the
    // membership-driven `diff_groups` below. Group resolve warnings flow into the
    // log just like account ones, and a failed expansion fails closed here.
    let (resolved_groups, group_resolve_warnings) =
        crate::model::resolve_groups(inputs.declaration, &inputs.compile)
            .map_err(|e| ApplyError::Resolve(e.to_string()))?;
    for w in &group_resolve_warnings {
        log.push(format!("warning: {w}"));
    }

    // 3b. Capability-gating (fail-closed) — BEFORE any snapshot or mutation, in
    // the same pre-mutation band as trust and anti-lockout. Every target's file
    // grants are routed against the installed backend(s); a grant whose shape no
    // backend can enforce (a per-file or pattern grant with only the dir-capable
    // ACL backend) returns `Unsupported` here and aborts apply before anything is
    // touched. The open build refuses an unenforceable grant rather than applying
    // weaker, rewrite-prone access (design "Capability-gating и честный отказ").
    // The SAME gate runs over each resolved group's `g:group` file grants: a
    // group grant Census cannot enforce must fail closed in this band exactly as
    // an account grant does — never materialized weaker.
    {
        let backends: [&dyn crate::fileaccess::FileAccessBackend; 1] = [&*inputs.file_access];
        for target in &targets {
            if target.file_grants.is_empty() {
                continue;
            }
            crate::fileaccess::route_grants(&target.file_grants, &backends)?;
        }
        for group in &resolved_groups {
            if group.file_grants.is_empty() {
                continue;
            }
            crate::fileaccess::route_grants(&group.file_grants, &backends)?;
        }
    }

    // 4-5. Diff vs managed state (accounts).
    let managed_now = inputs.state.managed_accounts();
    let managed_groups_now = inputs.state.managed_groups();
    let mut plan = plan::diff(&targets, inputs.state);

    // 5b. Group plan: required set (role groups ∪ [[group]]) vs the managed
    // group registry + live system. A GID-pin conflict or managed-group GID
    // drift aborts HERE — before lockout, snapshot, or any mutation (Census
    // never renumbers; design §Безопасность).
    let mut required_groups = crate::declaration::required_groups(inputs.declaration, &targets)?;
    plan.group_actions =
        plan::diff_groups_via_inspector(&required_groups, &managed_groups_now, inputs.inspector)?;

    // 5c. Group GRANT plan (declaration-driven, provenance-aware). This path is
    // the AUTHORITY for what Census materializes on a group — its `%group`
    // sudoers, `g:group` ACL, and added members — plus the Adopt/Release/Update
    // lifecycle. It deliberately does NOT groupadd/groupdel: existence is owned
    // by `diff_groups` above (its `Create` runs in Phase 1, its provenance-aware
    // `Delete` in Phase 4). We consume these actions only for the grant phases:
    // a resolved-path `Create`/`Adopt`/`Update` layers grants on; a `Release`
    // strips Census's own grants from an adopted group (no `groupdel`); a
    // resolved-path `Delete` (Created group dropped) drives the grant-teardown
    // that must precede the entity `groupdel` in Phase 4.
    let rgroup_actions = plan::diff_resolved_groups(&resolved_groups, &managed_groups_now);

    // 5c. Live-reconcile (§12): consult Tessera's live-session registry and DEFER
    // `userdel` for any account with a live session. This runs BEFORE the
    // anti-lockout gate on purpose: keeping an account (instead of deleting it)
    // can only ADD login paths, so the gate sees an equal-or-safer plan and can
    // never falsely trip because of a deferral.
    //
    // The read→partition→userdel sequence has a benign TOCTOU: the live set is a
    // snapshot. If a session ends just AFTER the read, we retain an account that
    // could have been deleted — at most one extra retain cycle, harmless. The
    // dangerous direction (a session starting after the read, then its account
    // torn down) cannot happen here: a Delete present in this plan was already
    // matched against the snapshot, and Census never kills sessions regardless.
    let plan_has_delete = plan.actions.iter().any(Action::is_destructive);
    let live = match inputs.session_source.live() {
        Ok(live) => live,
        // Fail-closed only when destructive: an unreadable registry cannot prove
        // "no live session", so a Delete must not proceed. A non-destructive plan
        // has nothing to defer, so the read error is irrelevant — ignore it.
        Err(e) if plan_has_delete => {
            return Err(ApplyError::SessionRegistry(e.to_string()));
        }
        Err(_) => crate::sessions::LiveSessions::default(),
    };
    let deferred_deletes = reconcile_live_sessions(&mut plan, &managed_now, &live, &mut log);
    for d in &deferred_deletes {
        tracing::info!(
            account = %d.name,
            uid = d.uid,
            "deferred userdel: live session present"
        );
        log.push(format!(
            "deferred delete of {} (uid {}): live session present (registry {})",
            d.name,
            d.uid,
            inputs.sessions_file.display()
        ));
        // A deferred account keeps its FULL prior privilege until the session ends
        // (see build_managed_set). The declaration dropped it entirely, so every
        // grant it held is now "retained-but-revoked" — live until the next apply.
        // Surface that delta as a structured warning so an operator can see which
        // sudo / file-access privilege is still standing on a session we did not
        // tear down, rather than the retention being silent.
        if let Some(record) = managed_now.get(&d.name) {
            let mut retained: Vec<String> = Vec::new();
            if let Some(role) = &record.sudo_role {
                retained.push(format!("sudo-role={role}"));
            }
            for cmd in &record.sudo_commands {
                retained.push(format!("sudo-command={cmd}"));
            }
            for grant in &record.file_grants {
                retained.push(format!("file-grant={}", grant.path));
            }
            if !retained.is_empty() {
                tracing::warn!(
                    account = %d.name,
                    retained = %retained.join(", "),
                    "deferred account retains revoked grants until its session ends"
                );
                log.push(format!(
                    "warning: deferred account {} retains revoked grants until its \
                     session ends: {}",
                    d.name,
                    retained.join(", ")
                ));
            }
        }
    }

    // Deferring a `userdel` is not enough: when the declaration drops a role, its
    // role-derived groups drop from the required set too and can become
    // `GroupAction::Delete`s. Tearing those groups out from under a still-live
    // session — supplementary groups, or worse the primary (role-named) group of
    // the active uid where `groupdel` fails "busy" and rolls back the whole apply
    // — defeats the partial-success design. So fold each deferred account's groups
    // back into the required set: drop their pending group-deletes AND retain them
    // in the registry (carried forward with their prior GID/from_version).
    let deferred_group_names = deferred_group_names(&deferred_deletes, &managed_now);
    if !deferred_group_names.is_empty() {
        plan.group_actions.retain(|ga| match ga {
            GroupAction::Delete { name } if deferred_group_names.contains(name) => {
                let acct = deferred_deletes
                    .iter()
                    .find(|d| group_owned_by(&d.name, &managed_now, name))
                    .map(|d| d.name.as_str())
                    .unwrap_or("?");
                log.push(format!(
                    "deferred delete of group {name}: retained by live-session account {acct}"
                ));
                false
            }
            _ => true,
        });
        // Fold into the required set so `build_managed_groups` carries these
        // groups forward from the prior registry (prior GID/from_version intact).
        for name in &deferred_group_names {
            required_groups.entry(name.clone()).or_insert(None);
        }
    }

    // 6. Anti-lockout gate (before snapshot / mutation).
    if inputs.lockout.risk_acknowledged {
        log.push("anti-lockout: proceeding under --i-understand-no-rescue".to_owned());
    }
    // Managed accounts the plan leaves entirely unchanged still hold login paths,
    // even though they produce no Action. Pass their recorded shells so the gate
    // counts them as surviving logins (otherwise it would over-refuse a plan that
    // only deletes a redundant account while a working one remains). Touched =
    // every name in any account action; an untouched name keeps its prior shell.
    let touched_account_names: std::collections::HashSet<&str> = plan
        .actions
        .iter()
        .map(|a| match a {
            Action::Create(acct) => acct.name.as_str(),
            Action::Update { account, .. } => account.name.as_str(),
            Action::Delete { name } => name.as_str(),
        })
        .collect();
    let untouched_login_shells: Vec<&str> = managed_now
        .iter()
        .filter(|(name, _)| !touched_account_names.contains(name.as_str()))
        .map(|(_, record)| record.shell.as_str())
        .collect();
    crate::lockout::gate(&plan, inputs.lockout, &untouched_login_shells)?;

    // Idempotence: empty plan (no account AND no group actions AND no group-grant
    // actions) → zero mutations, no snapshot, no registry churn (registry still
    // reflects the in-sync set).
    // NOTE: this branch is now also reachable when the ONLY planned change was a
    // delete that we just deferred. In that case the registry already holds the
    // deferred account (retained below with its prior from_version), so there are
    // no OS mutations — but the registry MUST still record the retention, hence
    // `registry_written` is forced true whenever a deferral happened (idempotent
    // in content: from_version is preserved, but we must not drop ownership).
    // `rgroup_actions` is folded into the emptiness test: a declaration-driven
    // group change (Adopt/Release/Update, or a grant-only diff) can have NO
    // membership-driven `plan` action behind it (an adopted foreign group is
    // SKIPped by `diff_groups`), yet it is real work that must snapshot and run.
    if plan.is_empty() && rgroup_actions.is_empty() {
        log.push("plan is empty — no changes".to_owned());
        return Ok(ApplyReport {
            managed: build_managed_set(
                &targets,
                inputs.declaration.version,
                &managed_now,
                &deferred_deletes,
            ),
            managed_group_records: build_managed_groups(
                &required_groups,
                &resolved_groups,
                &managed_groups_now,
                &[],
                &BTreeMap::new(),
                inputs.declaration.version,
                inputs.inspector,
            ),
            log,
            mutations: 0,
            registry_written: !deferred_deletes.is_empty(),
            trust_mode,
            deferred_deletes,
        });
    }

    // 7a. Register every touched sudoers fragment in the backup set BEFORE the
    // snapshot, so a later-phase failure rolls the fragment back too (spec R2).
    // Touched = every created/updated role that carries a sudo right (its
    // fragment is written/refreshed) + every deleted role's `census-<role>`
    // fragment (it is removed). Computed from the plan + the sudoers dir.
    for path in touched_sudoers_paths(&plan, &inputs.sudoers_dir) {
        provisioner.track_sudoers_backup(path);
    }
    // The group `%group` fragments (`census-grp-<g>`) touched by the group-grant
    // phases go into the SAME backup set, so a later-phase failure rolls a group
    // fragment back together with the account fragments and the auth-DB. A group
    // is touched when its resolved-path action writes or removes its fragment
    // (Create/Adopt/Update/Release/Delete). Backing up an absent fragment is a
    // benign no-op that correctly restores "absent" on rollback.
    for path in touched_group_sudoers_paths(&rgroup_actions, &inputs.sudoers_dir) {
        provisioner.track_sudoers_backup(path);
    }

    // 7b. Snapshot before any mutation.
    provisioner.snapshot().map_err(|e| ApplyError::Phase {
        phase: "snapshot",
        source: e,
        rollback: RollbackOutcome::Restored, // nothing mutated yet
    })?;

    // 7c. Snapshot the file-access state of every path the file-access phase will
    // touch (grants materialized for created/updated accounts + grants revoked
    // for changed/deleted accounts), BEFORE mutating it. This is the file-access
    // analogue of the full-file auth-DB backup (spec R2 / design "Откат"): a later
    // phase failure rolls the ACLs back from this snapshot just as it rolls back
    // /etc/passwd. The provisioner snapshot is already taken above, so the backend
    // restore composes with the auth-DB restore in `phase_failure`.
    let mut file_access_paths = file_access_touched_paths(&plan, &targets, &managed_now);
    // Group `g:group` ACL paths the grant phases will touch go into the SAME
    // file-access snapshot as the account paths, so a later-phase failure rolls a
    // group ACL back together with the account ACLs (dual-seam restore). Touched =
    // every resolved group's grant paths (materialized) + every prior recorded
    // grant path of a released/deleted group (revoked).
    for p in group_file_access_touched_paths(&rgroup_actions, &resolved_groups, &managed_groups_now)
    {
        if !file_access_paths.contains(&p) {
            file_access_paths.push(p);
        }
    }
    if !file_access_paths.is_empty() {
        let path_refs: Vec<&Path> = file_access_paths.iter().map(PathBuf::as_path).collect();
        if let Err(e) = inputs.file_access.snapshot(&path_refs) {
            // The provisioner snapshot exists but nothing has been mutated yet;
            // roll it back so we leave no partial state, and surface the error.
            let _ = provisioner.restore();
            return Err(ApplyError::FileAccess(e));
        }
    }

    // 8. Apply phases in order (design Р4):
    //   (1) create missing groups   — BEFORE accounts (membership needs them)
    //   (2) create/update accounts + sudoers
    //   (3) delete vanished accounts (sudoers fragment first, then userdel)
    //   (4) delete orphan managed groups — AFTER accounts (no members left)
    // On any error: restore from the snapshot, abort. `/etc/group`+`/etc/gshadow`
    // are in the full-file backup set (BackupTargets::auth_db_default), so a
    // failed group phase rolls back atomically with the rest.
    let mut mutations = 0usize;
    let mut created_groups: Vec<(String, Option<u32>)> = Vec::new();

    // Phase 1: create missing groups.
    for ga in &plan.group_actions {
        if let GroupAction::Create { name, gid } = ga {
            match provisioner.create_group(name, *gid) {
                Ok(()) => {
                    mutations += 1;
                    // For an unpinned group the OS assigned the GID; read it back
                    // through the SAME provisioner seam that just created it, so
                    // the registry records the real assigned GID rather than a
                    // value sampled from the pre-mutation snapshot inspector (which
                    // could not see a group that did not exist yet). A pin is kept
                    // verbatim — no read-back needed.
                    let assigned = gid.or_else(|| provisioner.group_gid(name));
                    created_groups.push((name.clone(), assigned));
                    let pin = gid
                        .map(|g| g.to_string())
                        .unwrap_or_else(|| "auto".to_owned());
                    tracing::info!(group = %name, gid = %pin, "created group");
                    log.push(format!("create-group: {name} (gid {pin})"));
                }
                Err(source) => {
                    return Err(phase_failure(
                        provisioner,
                        inputs.file_access,
                        "create-group",
                        source,
                    ));
                }
            }
        }
    }

    // Phases 2 & 3: account creates/updates, then deletes. The account `plan`
    // already orders creates/updates before deletes (plan::diff), so a single
    // pass preserves "deletes last" among accounts; group deletes come after.
    for action in &plan.actions {
        let (phase, result) = match action {
            Action::Create(acct) => (
                "create",
                provisioner
                    .create(acct)
                    .and_then(|()| provisioner.apply_sudoers(acct)),
            ),
            Action::Update { account, changes } => (
                "update",
                provisioner
                    .update(account, changes)
                    .and_then(|()| provisioner.apply_sudoers(account)),
            ),
            Action::Delete { name } => (
                "delete",
                provisioner
                    .remove_sudoers(name)
                    .and_then(|()| provisioner.delete(name)),
            ),
        };
        match result {
            Ok(()) => {
                mutations += 1;
                tracing::info!(phase, account = %action_label(action), "applied account action");
                log.push(format!("{phase}: {}", action_label(action)));
            }
            Err(source) => {
                return Err(phase_failure(
                    provisioner,
                    inputs.file_access,
                    phase,
                    source,
                ));
            }
        }
    }

    // Phase 3b: file-access — materialize grants for created/updated accounts and
    // revoke grants that disappeared (a grant dropped from an updated account, or
    // every grant of a deleted account). Runs AFTER the account create/update
    // (and its sudoers), before limits / group deletes — the account exists, so
    // its ACL entry is well-defined. Materialize is idempotent (setfacl -m of the
    // same entry is a no-op by content), so this phase adds no spurious mutation
    // count: it rides along with the account changes that already made the plan
    // non-empty, exactly as the sudoers write rides along with create/update. On
    // error BOTH seams roll back (file-access ACLs + the auth-DB/sudoers backup).
    for action in &plan.actions {
        let acct = match action {
            Action::Create(a) => a,
            Action::Update { account, .. } => account,
            Action::Delete { .. } => continue, // handled by revoke-deleted below
        };
        // Revoke grants this account no longer carries (set difference vs the
        // recorded managed grants), so a dropped grant's ACL does not leak.
        for removed in removed_grants(&acct.name, &acct.file_grants, &managed_now) {
            if let Err(e) = revoke_one(inputs.file_access, &acct.name, &removed) {
                return Err(phase_failure_file_access(
                    provisioner,
                    inputs.file_access,
                    e,
                ));
            }
        }
        if acct.file_grants.is_empty() {
            continue;
        }
        let principal = crate::fileaccess::Principal::User(acct.name.clone());
        if let Err(e) = inputs
            .file_access
            .materialize(&principal, &acct.file_grants)
        {
            return Err(phase_failure_file_access(
                provisioner,
                inputs.file_access,
                e,
            ));
        }
        log.push(format!(
            "file-access: materialized {} grant(s) for {}",
            acct.file_grants.len(),
            acct.name
        ));
    }
    // Revoke every grant of a deleted account (the account is gone; its ACL
    // entries must go too). The account's `userdel` already ran in the phase above,
    // so its name no longer resolves — revoke by the recorded numeric UID, which is
    // how the kernel stored the entry, rather than by a name `setfacl` can no longer
    // look up. The deleted account always has a managed record (the `Delete` came
    // from diffing it), so its UID is present.
    for action in &plan.actions {
        if let Action::Delete { name } = action {
            let uid = managed_now.get(name).map(|m| m.uid);
            for removed in removed_grants(name, &[], &managed_now) {
                let result = match uid {
                    Some(uid) => revoke_one_deleted(inputs.file_access, uid, &removed),
                    // No recorded UID (a record without one should not occur for a
                    // managed Delete): fall back to the name so teardown still
                    // attempts the revoke rather than silently skipping it.
                    None => revoke_one(inputs.file_access, name, &removed),
                };
                if let Err(e) = result {
                    return Err(phase_failure_file_access(
                        provisioner,
                        inputs.file_access,
                        e,
                    ));
                }
            }
        }
    }

    // Phase 3c: group GRANTS (declaration-driven). The group EXISTS by now — a
    // membership-driven `Create` ran in Phase 1, an adopted group pre-existed, an
    // updated/in-sync group was already there — so its `%group` sudoers, `g:group`
    // ACL, and membership are all well-defined to mutate. Runs AFTER account
    // grants, BEFORE the entity group-delete in Phase 4 (so a Created group
    // dropped from the declaration loses its grants here, then its empty shell is
    // groupdel'd next). Adopt baselines captured here flow into the registry via
    // `build_managed_groups`. Both seams roll back on any error.
    let mut adopt_baselines: BTreeMap<String, crate::state::GroupBaseline> = BTreeMap::new();
    for ga in &rgroup_actions {
        match ga {
            GroupAction::Create { name, .. }
            | GroupAction::Adopt { name }
            | GroupAction::Update { name, .. } => {
                // A group action must name a group resolve produced. If it does
                // not, the plan disagrees with the resolved set — a corrupt or
                // tampered plan. We are past the snapshot, so roll both seams back
                // and fail closed rather than mutate on an inconsistent plan.
                let Some(group) = resolved_group_by_name(&resolved_groups, name) else {
                    let rollback = abort_with_rollback(provisioner, inputs.file_access);
                    tracing::warn!(
                        group = %name,
                        rollback = %rollback,
                        "corrupt plan: group action names a group resolve did not produce; rolled back"
                    );
                    return Err(ApplyError::CorruptPlan {
                        group: name.clone(),
                        rollback,
                    });
                };
                // Adopt: the group comes under management for the first time —
                // snapshot its live baseline (GID + pre-existing members) BEFORE
                // layering Census's grants, so a later release returns it to
                // exactly this state without ever deleting the group.
                if matches!(ga, GroupAction::Adopt { .. }) && !managed_groups_now.contains_key(name)
                {
                    // `None` here means the OS could not report the GID (group not
                    // yet visible / getent failure); it is preserved as "unknown"
                    // and never coerced to 0, which is a real GID (root).
                    let gid = inputs.inspector.group(name).map(|f| f.gid);
                    let members = inputs.inspector.group_members(name);
                    adopt_baselines
                        .insert(name.clone(), crate::state::GroupBaseline { gid, members });
                    tracing::info!(group = %name, ?gid, "adopt-group: captured baseline");
                    log.push(format!("adopt-group: {name} (baseline gid {gid:?})"));
                }

                // (a) %group sudoers fragment (write when sudo commands present,
                // else ensure absent).
                if let Err(source) = provisioner.apply_group_sudoers(group) {
                    return Err(phase_failure(
                        provisioner,
                        inputs.file_access,
                        "group-sudoers",
                        source,
                    ));
                }
                // (b) g:group ACL — materialize the group's file grants.
                if !group.file_grants.is_empty() {
                    let principal = crate::fileaccess::Principal::Group(name.clone());
                    if let Err(e) = inputs
                        .file_access
                        .materialize(&principal, &group.file_grants)
                    {
                        return Err(phase_failure_file_access(
                            provisioner,
                            inputs.file_access,
                            e,
                        ));
                    }
                    // A revoked group grant (recorded but no longer targeted) must
                    // drop its ACL entry too — same set-difference the account path
                    // does, so a removed group grant cannot leak.
                    for removed in
                        removed_group_grants(name, &group.file_grants, &managed_groups_now)
                    {
                        if let Err(e) = revoke_one_group(inputs.file_access, name, &removed) {
                            return Err(phase_failure_file_access(
                                provisioner,
                                inputs.file_access,
                                e,
                            ));
                        }
                    }
                    log.push(format!(
                        "file-access: materialized {} group grant(s) for {}",
                        group.file_grants.len(),
                        name
                    ));
                } else {
                    // No target grants: revoke every grant Census previously recorded.
                    for removed in removed_group_grants(name, &[], &managed_groups_now) {
                        if let Err(e) = revoke_one_group(inputs.file_access, name, &removed) {
                            return Err(phase_failure_file_access(
                                provisioner,
                                inputs.file_access,
                                e,
                            ));
                        }
                    }
                }
                // (c) Members: reconcile toward `group.members`. Add targets not
                // already in our `members_added`; remove our own added members no
                // longer targeted. Never touch foreign/baseline members.
                let current = members_added_of(name, &managed_groups_now);
                for m in &group.members {
                    if !current.contains(m) {
                        if let Err(source) = provisioner.add_group_member(name, m) {
                            return Err(phase_failure(
                                provisioner,
                                inputs.file_access,
                                "group-member",
                                source,
                            ));
                        }
                        mutations += 1;
                    }
                }
                for m in &current {
                    if !group.members.contains(m) {
                        if let Err(source) = provisioner.remove_group_member(name, m) {
                            return Err(phase_failure(
                                provisioner,
                                inputs.file_access,
                                "group-member",
                                source,
                            ));
                        }
                        mutations += 1;
                    }
                }
                mutations += 1; // the grant application itself (sudoers/ACL)
                log.push(format!("group-grants: {name}"));
            }
            GroupAction::Release { name } | GroupAction::Delete { name } => {
                // Strip Census's own grants from the group. For Release the group
                // is Adopted (left alive, returned to baseline); for Delete the
                // group is Created and its empty shell is groupdel'd in Phase 4
                // AFTER this teardown. Both do the identical grant cleanup here.
                if let Err(source) = provisioner.remove_group_sudoers(name) {
                    return Err(phase_failure(
                        provisioner,
                        inputs.file_access,
                        "group-sudoers",
                        source,
                    ));
                }
                for removed in removed_group_grants(name, &[], &managed_groups_now) {
                    if let Err(e) = revoke_one_group(inputs.file_access, name, &removed) {
                        return Err(phase_failure_file_access(
                            provisioner,
                            inputs.file_access,
                            e,
                        ));
                    }
                }
                for m in &members_added_of(name, &managed_groups_now) {
                    if let Err(source) = provisioner.remove_group_member(name, m) {
                        return Err(phase_failure(
                            provisioner,
                            inputs.file_access,
                            "group-member",
                            source,
                        ));
                    }
                    mutations += 1;
                }
                let verb = if matches!(ga, GroupAction::Release { .. }) {
                    "release"
                } else {
                    "teardown"
                };
                tracing::info!(group = %name, action = verb, "group grant teardown");
                log.push(format!("group-{verb}: {name}"));
            }
        }
    }

    // Phase 4: delete orphan managed groups (after account deletes and after the
    // group-grant teardown above stripped any %group/ACL/members). The deleted
    // groups are dropped from the registry by `build_managed_groups` (no longer
    // required), so nothing to record here.
    for ga in &plan.group_actions {
        if let GroupAction::Delete { name } = ga {
            match provisioner.delete_group(name) {
                Ok(()) => {
                    mutations += 1;
                    tracing::info!(group = %name, "deleted group");
                    log.push(format!("delete-group: {name}"));
                }
                Err(source) => {
                    return Err(phase_failure(
                        provisioner,
                        inputs.file_access,
                        "delete-group",
                        source,
                    ));
                }
            }
        }
    }

    // 9. Success: drop the snapshot. Registry write is the caller's job (atomic,
    // last) — we return the new managed account + group sets.
    log.push("all phases succeeded".to_owned());
    Ok(ApplyReport {
        managed: build_managed_set(
            &targets,
            inputs.declaration.version,
            &managed_now,
            &deferred_deletes,
        ),
        managed_group_records: build_managed_groups(
            &required_groups,
            &resolved_groups,
            &managed_groups_now,
            &created_groups,
            &adopt_baselines,
            inputs.declaration.version,
            inputs.inspector,
        ),
        log,
        mutations,
        registry_written: true,
        trust_mode,
        deferred_deletes,
    })
}

/// Partition the account plan against the live-session set: every `Delete` whose
/// name OR uid has a live session is REMOVED from `plan.actions` (Census never
/// kills a session — it skips its own destructive step) and returned as a
/// [`DeferredDelete`]. The uid is read from `managed_now` (the deleted account's
/// recorded record); a managed Delete always has a corresponding managed record.
fn reconcile_live_sessions(
    plan: &mut plan::Plan,
    managed_now: &BTreeMap<String, ManagedAccount>,
    live: &crate::sessions::LiveSessions,
    log: &mut Vec<String>,
) -> Vec<DeferredDelete> {
    let mut deferred = Vec::new();
    plan.actions.retain(|action| {
        let Action::Delete { name } = action else {
            return true; // creates/updates are never deferred
        };
        // Every account `Delete` is produced by diffing the managed registry, so
        // its record (and thus its uid) is always present in `managed_now`. A
        // record with no managed entry must not be silently swallowed: surface it
        // as a warning in EVERY build (a bare `debug_assert!` would vanish in
        // release, hiding a real invariant break) and fall through as a normal
        // delete — the safe outcome, since a record we cannot find cannot be
        // retained or matched against a live session anyway.
        let Some(record) = managed_now.get(name) else {
            log.push(format!(
                "warning: account delete {name:?} has no managed registry record; \
                 cannot check for a live session, proceeding as a normal delete"
            ));
            return true;
        };
        if live.matches(name, record.uid) {
            deferred.push(DeferredDelete {
                name: name.clone(),
                uid: record.uid,
            });
            false // remove from the executed plan
        } else {
            true
        }
    });
    deferred
}

/// The union of all group names that belong to a deferred-delete account: each
/// account's recorded supplementary groups (`ManagedAccount.groups`) plus its
/// primary group. `useradd` (no `-g`/`-N`) creates a user-private primary group
/// named after the account/role, so the primary group name equals the account
/// name. These groups must NOT be torn down while the account's session is live.
fn deferred_group_names(
    deferred: &[DeferredDelete],
    managed_now: &BTreeMap<String, ManagedAccount>,
) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    for d in deferred {
        // Primary (role-named) group — same name as the account.
        names.insert(d.name.clone());
        if let Some(record) = managed_now.get(&d.name) {
            for g in &record.groups {
                names.insert(g.clone());
            }
        }
    }
    names
}

/// Whether `group` is one of `account`'s groups (supplementary or its role-named
/// primary). Used only to attribute a retained group to an account in the log.
fn group_owned_by(
    account: &str,
    managed_now: &BTreeMap<String, ManagedAccount>,
    group: &str,
) -> bool {
    if account == group {
        return true; // primary (role-named) group
    }
    managed_now
        .get(account)
        .is_some_and(|m| m.groups.iter().any(|g| g == group))
}

/// Run the rollback after a phase failure and package the resulting
/// [`ApplyError::Phase`] (shared by every phase arm).
///
/// BOTH seams are restored: the provisioner rolls back the auth-DB + sudoers
/// full-file backup, and the file-access backend rolls back the ACLs it
/// snapshotted. They are independent — a failure in either phase must undo the
/// other's already-applied mutations — so the outcome reports success only if
/// both restores succeed; otherwise the snapshots are retained for manual
/// recovery.
fn phase_failure(
    provisioner: &mut dyn Provisioner,
    file_access: &mut dyn crate::fileaccess::FileAccessBackend,
    phase: &'static str,
    source: ProvisionError,
) -> ApplyError {
    tracing::warn!(phase, error = %source, "apply phase failed; rolling back");
    let prov = provisioner.restore();
    let acl = file_access.restore();
    if let Err(e) = &prov {
        tracing::warn!(phase, error = %e, "rollback: provisioner restore failed");
    }
    if let Err(e) = &acl {
        tracing::warn!(phase, error = %e, "rollback: file-access restore failed");
    }
    let rollback = match (prov, acl) {
        (Ok(()), Ok(())) => RollbackOutcome::Restored,
        (Err(e), _) => RollbackOutcome::Failed(e.to_string()),
        (_, Err(e)) => RollbackOutcome::Failed(format!("file-access restore: {e}")),
    };
    ApplyError::Phase {
        phase,
        source,
        rollback,
    }
}

/// Roll back BOTH seams after a file-access phase failure (the symmetric case of
/// [`phase_failure`] when the failing operation is a `materialize`/`revoke`
/// rather than a shadow-utils command). The provisioner restores the auth-DB +
/// sudoers backup; the backend restores its own ACL snapshot. The returned error
/// carries the originating [`crate::fileaccess::FileAccessError`].
fn phase_failure_file_access(
    provisioner: &mut dyn Provisioner,
    file_access: &mut dyn crate::fileaccess::FileAccessBackend,
    source: crate::fileaccess::FileAccessError,
) -> ApplyError {
    // Undo the auth-DB/sudoers mutations of earlier phases and any ACL entries
    // this phase managed to apply before failing. Best-effort: the snapshots are
    // retained on a restore failure, and the originating error is what surfaces.
    tracing::warn!(error = %source, "file-access phase failed; rolling back");
    if let Err(e) = provisioner.restore() {
        tracing::warn!(error = %e, "rollback: provisioner restore failed");
    }
    if let Err(e) = file_access.restore() {
        tracing::warn!(error = %e, "rollback: file-access restore failed");
    }
    ApplyError::FileAccess(source)
}

/// Roll back BOTH seams best-effort and report the restore outcome, for an abort
/// that is not tied to a provisioner phase error (e.g. a corrupt-plan invariant
/// breach detected mid-apply). Mirrors [`phase_failure`]'s restore handling: the
/// provisioner undoes its auth-DB + sudoers backup and the backend undoes its ACL
/// snapshot, and the outcome reports success only if both restores succeed.
fn abort_with_rollback(
    provisioner: &mut dyn Provisioner,
    file_access: &mut dyn crate::fileaccess::FileAccessBackend,
) -> RollbackOutcome {
    let prov = provisioner.restore();
    let acl = file_access.restore();
    if let Err(e) = &prov {
        tracing::warn!(error = %e, "rollback: provisioner restore failed");
    }
    if let Err(e) = &acl {
        tracing::warn!(error = %e, "rollback: file-access restore failed");
    }
    match (prov, acl) {
        (Ok(()), Ok(())) => RollbackOutcome::Restored,
        (Err(e), _) => RollbackOutcome::Failed(e.to_string()),
        (_, Err(e)) => RollbackOutcome::Failed(format!("file-access restore: {e}")),
    }
}

/// Re-hydrate a recorded [`ManagedFileGrant`] into a [`crate::catalog::ResolvedFileGrant`]
/// for revocation. Provenance is irrelevant to revoke (the backend keys off the
/// path), so it is left empty; the shape is recomputed from the path + recursive
/// flag so the backend routes/handles it consistently with materialize.
fn resolved_from_managed(g: &ManagedFileGrant) -> crate::catalog::ResolvedFileGrant {
    crate::catalog::ResolvedFileGrant {
        path: g.path.clone(),
        access: g.access,
        recursive: g.recursive,
        shape: crate::catalog::FileGrant {
            path: g.path.clone(),
            access: g.access,
            recursive: g.recursive,
        }
        .shape(),
        sources: Vec::new(),
    }
}

/// The recorded managed grants for `name` whose path is NOT in `keep` — the set
/// to revoke. `keep` is the account's target grant set (empty for a deleted
/// account, so every recorded grant is revoked).
///
/// The path-based `keep` membership test is sound because both the recorded
/// grants and `keep` carry one entry per path: resolve unions every account's
/// grants through [`crate::catalog::union_resolved_file_grants`], which collapses
/// duplicate paths into a single widened entry. So a recorded grant is matched by
/// at most one `keep` entry, and "no `keep` entry for this path" unambiguously
/// means the path was dropped.
fn removed_grants(
    name: &str,
    keep: &[crate::catalog::ResolvedFileGrant],
    managed_now: &BTreeMap<String, ManagedAccount>,
) -> Vec<ManagedFileGrant> {
    let Some(record) = managed_now.get(name) else {
        return Vec::new();
    };
    record
        .file_grants
        .iter()
        .filter(|m| !keep.iter().any(|k| k.path == m.path))
        .cloned()
        .collect()
}

/// Revoke one recorded grant via the backend (re-hydrating it to the resolved
/// form the SPI expects), keying the ACL entry on the account's name.
///
/// Use this only while the account still exists (a grant dropped from an account
/// that survives the apply). For a *deleted* account the name no longer resolves,
/// so revoke by UID via [`revoke_one_deleted`] instead.
fn revoke_one(
    file_access: &mut dyn crate::fileaccess::FileAccessBackend,
    account: &str,
    grant: &ManagedFileGrant,
) -> Result<(), crate::fileaccess::FileAccessError> {
    let resolved = resolved_from_managed(grant);
    let principal = crate::fileaccess::Principal::User(account.to_owned());
    file_access.revoke(&principal, &resolved)
}

/// Revoke one recorded grant of an account that has already been deleted, keying
/// the ACL entry on the recorded numeric UID rather than the name.
///
/// The account-delete phase runs `userdel` before this file-access teardown, so by
/// now the name no longer resolves through `getpwnam`. `setfacl` resolves a named
/// qualifier and would reject `-x u:<name>` for a vanished name; the kernel stored
/// the entry by UID, so `-x u:<uid>` removes exactly the orphaned entry.
fn revoke_one_deleted(
    file_access: &mut dyn crate::fileaccess::FileAccessBackend,
    uid: u32,
    grant: &ManagedFileGrant,
) -> Result<(), crate::fileaccess::FileAccessError> {
    let resolved = resolved_from_managed(grant);
    let principal = crate::fileaccess::Principal::Uid(uid);
    file_access.revoke(&principal, &resolved)
}

/// Every filesystem path the file-access phase will touch — grant paths
/// materialized for created/updated accounts plus grant paths revoked for
/// changed/deleted accounts — so they can be snapshotted before mutation (spec
/// R2 parity with the full-file auth-DB backup). Deduplicated, order-stable.
fn file_access_touched_paths(
    plan: &plan::Plan,
    targets: &[crate::model::ResolvedAccount],
    managed_now: &BTreeMap<String, ManagedAccount>,
) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    let push = |p: &str, paths: &mut Vec<PathBuf>| {
        let pb = PathBuf::from(p);
        if !paths.contains(&pb) {
            paths.push(pb);
        }
    };
    // Materialized paths: every target's grants (a target is created or updated).
    for t in targets {
        // Only accounts that are actually in the plan (created/updated) mutate;
        // an in-sync account is not re-materialized. But an in-sync account never
        // reaches a non-empty-plan mutation either way, so snapshotting its paths
        // is harmless (a no-op snapshot restores the same state). Keep it simple
        // and snapshot every target's grant paths plus every removed path.
        for g in &t.file_grants {
            push(&g.path, &mut paths);
        }
    }
    // Revoked paths: removed grants of updated accounts + all grants of deletes.
    for action in &plan.actions {
        match action {
            Action::Create(a) | Action::Update { account: a, .. } => {
                for r in removed_grants(&a.name, &a.file_grants, managed_now) {
                    push(&r.path, &mut paths);
                }
            }
            Action::Delete { name } => {
                for r in removed_grants(name, &[], managed_now) {
                    push(&r.path, &mut paths);
                }
            }
        }
    }
    paths
}

/// The `census-grp-<group>` sudoers fragment paths the group-grant phases will
/// touch, for the pre-snapshot backup set (spec R2 parity with the account
/// fragments). A group is touched by every resolved-path action — Create/Adopt/
/// Update write or clear its `%group` fragment; Release/Delete remove it. Backing
/// up an absent fragment is a no-op that restores "absent" on rollback.
/// Deduplicated, order-stable.
fn touched_group_sudoers_paths(rgroup_actions: &[GroupAction], sudoers_dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    for ga in rgroup_actions {
        let name = match ga {
            GroupAction::Create { name, .. }
            | GroupAction::Adopt { name }
            | GroupAction::Update { name, .. }
            | GroupAction::Release { name }
            | GroupAction::Delete { name } => name,
        };
        let p = crate::sudoers::sudoers_group_path(sudoers_dir, name);
        if !paths.contains(&p) {
            paths.push(p);
        }
    }
    paths
}

/// Every filesystem path the group-grant file-access phase will touch — the
/// `g:group` grant paths materialized for a resolved group plus the prior
/// recorded grant paths revoked for a released/deleted/updated group — so they
/// can be snapshotted before mutation (spec R2 parity with the account paths).
/// Deduplicated, order-stable.
fn group_file_access_touched_paths(
    rgroup_actions: &[GroupAction],
    resolved_groups: &[crate::model::ResolvedGroup],
    managed_groups_now: &BTreeMap<String, ManagedGroup>,
) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    let push = |p: &str, paths: &mut Vec<PathBuf>| {
        let pb = PathBuf::from(p);
        if !paths.contains(&pb) {
            paths.push(pb);
        }
    };
    for ga in rgroup_actions {
        match ga {
            GroupAction::Create { name, .. }
            | GroupAction::Adopt { name }
            | GroupAction::Update { name, .. } => {
                if let Some(g) = resolved_group_by_name(resolved_groups, name) {
                    for grant in &g.file_grants {
                        push(&grant.path, &mut paths);
                    }
                }
                // Revoked group grants (recorded but no longer targeted).
                let keep = resolved_group_by_name(resolved_groups, name)
                    .map(|g| g.file_grants.as_slice())
                    .unwrap_or(&[]);
                for r in removed_group_grants(name, keep, managed_groups_now) {
                    push(&r.path, &mut paths);
                }
            }
            GroupAction::Release { name } | GroupAction::Delete { name } => {
                for r in removed_group_grants(name, &[], managed_groups_now) {
                    push(&r.path, &mut paths);
                }
            }
        }
    }
    paths
}

/// Find a resolved group by name (the resolved-path actions carry only the name).
fn resolved_group_by_name<'a>(
    groups: &'a [crate::model::ResolvedGroup],
    name: &str,
) -> Option<&'a crate::model::ResolvedGroup> {
    groups.iter().find(|g| g.name == name)
}

/// The recorded managed GROUP grants for `name` whose path is NOT in `keep` — the
/// set to revoke. `keep` is the group's target grant set (empty for a released/
/// deleted group, so every recorded grant is revoked). Mirrors `removed_grants`
/// for the account path.
fn removed_group_grants(
    name: &str,
    keep: &[crate::catalog::ResolvedFileGrant],
    managed_groups_now: &BTreeMap<String, ManagedGroup>,
) -> Vec<ManagedFileGrant> {
    let Some(record) = managed_groups_now.get(name) else {
        return Vec::new();
    };
    record
        .file_grants
        .iter()
        .filter(|m| !keep.iter().any(|k| k.path == m.path))
        .cloned()
        .collect()
}

/// Revoke one recorded GROUP grant via the backend (the `g:` principal). Mirrors
/// `revoke_one` for the account path, only the principal letter differs.
fn revoke_one_group(
    file_access: &mut dyn crate::fileaccess::FileAccessBackend,
    group: &str,
    grant: &ManagedFileGrant,
) -> Result<(), crate::fileaccess::FileAccessError> {
    let resolved = resolved_from_managed(grant);
    let principal = crate::fileaccess::Principal::Group(group.to_owned());
    file_access.revoke(&principal, &resolved)
}

/// The members Census itself recorded as added to `name` (its prior
/// `members_added`), or empty when the group has no prior record. The reconcile
/// baseline for the membership phase: only these are ever removed by Census.
fn members_added_of(
    name: &str,
    managed_groups_now: &BTreeMap<String, ManagedGroup>,
) -> Vec<String> {
    managed_groups_now
        .get(name)
        .map(|g| g.members_added.clone())
        .unwrap_or_default()
}

/// Compute the set of `census-<role>` sudoers fragment paths the plan will
/// touch, so they can be added to the backup set before the snapshot (spec R2).
///
/// A fragment is touched when:
/// * a created/updated role carries a sudo right (its fragment is written), OR
/// * a created/updated role does NOT carry sudo (its fragment, if any, is removed — drop-to-none
///   must also roll back), OR
/// * a role is deleted (its `census-<role>` fragment is removed).
///
/// We back up the path for every created/updated/deleted role unconditionally:
/// backing up an absent file is a no-op snapshot that correctly restores
/// "absent" on rollback, and it spares us re-reading the role-store here.
/// Deduplicated and order-stable.
fn touched_sudoers_paths(plan: &plan::Plan, sudoers_dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    for action in &plan.actions {
        let name = match action {
            Action::Create(acct) => &acct.name,
            Action::Update { account, .. } => &account.name,
            Action::Delete { name } => name,
        };
        let p = sudoers_dir.join(crate::sudoers::sudoers_filename(name));
        if !paths.contains(&p) {
            paths.push(p);
        }
    }
    paths
}

/// A short label for a planned action (for logs).
fn action_label(action: &Action) -> String {
    match action {
        Action::Create(a) => format!("create {} (uid {})", a.name, a.uid),
        Action::Update { account, changes } => {
            format!("update {} ({})", account.name, changes.join(", "))
        }
        Action::Delete { name } => format!("delete {name}"),
    }
}

/// Build the new managed registry set from the resolved targets, recording
/// `from_version`. Accounts already managed and unchanged keep their recorded
/// `from_version`; created/updated accounts get the declaration's version.
///
/// `deferred` are accounts whose deletion was skipped because they have a live
/// session (§12). They are NOT in `targets` (the declaration dropped them), so
/// without re-adding them here Census would forget it owns them: the account
/// would become foreign and never be deleted on a later run. We therefore carry
/// each deferred account forward from `current` with its PRIOR `from_version`
/// intact, so the next apply (after the session closes) sees it as managed and
/// completes the delete.
fn build_managed_set(
    targets: &[crate::model::ResolvedAccount],
    version: u32,
    current: &std::collections::BTreeMap<String, ManagedAccount>,
    deferred: &[DeferredDelete],
) -> Vec<ManagedAccount> {
    let mut out: Vec<ManagedAccount> = targets
        .iter()
        .map(|t| {
            let from_version = match current.get(&t.name) {
                Some(existing)
                    if existing.uid == t.uid
                    && existing.shell == t.shell
                    && groups_equal(&existing.groups, &t.groups)
                    && existing.sudo_role == t.sudo_role
                    // The concrete sudo command set is part of the account's
                    // recorded privilege; an unchanged set (order-insensitive, by
                    // (command, runas) pair) preserves from_version, a changed one
                    // — including a run-as re-target — is a real update.
                    && crate::plan::sudo_set_equal(&existing.sudo_commands, &t.sudo_commands)
                    // The file-grant set is likewise part of the recorded
                    // privilege: an unchanged set (set-equal) preserves
                    // from_version, a changed one is a real update.
                    && file_grants_equal(&existing.file_grants, &t.file_grants) =>
                {
                    existing.from_version
                }
                _ => version,
            };
            ManagedAccount {
                name: t.name.clone(),
                uid: t.uid,
                shell: t.shell.clone(),
                groups: t.groups.clone(),
                sudo_role: t.sudo_role.clone(),
                sudo_commands: t.sudo_commands.clone(),
                file_grants: t
                    .file_grants
                    .iter()
                    .map(ManagedFileGrant::from_resolved)
                    .collect(),
                provenance: crate::model::Provenance::Created,
                from_version,
            }
        })
        .collect();

    // Retain deferred-delete accounts with their original record (prior
    // from_version preserved). They are absent from `targets`, so there is no
    // overlap to deduplicate.
    //
    // SECURITY NOTE: the carried-forward record is the account's FULL prior
    // privilege — every group, sudo grant, and file-access grant it held before
    // the declaration dropped it. Census deliberately does NOT tear that access
    // down while a session is live (killing access mid-session is the larger
    // operational hazard), so any grant the new declaration revoked stays LIVE
    // until the session ends and the next apply completes the delete. The
    // orchestrator emits a `warning:` line naming each such account and the
    // grants it retains, so an operator can see what privilege is still standing.
    for d in deferred {
        if let Some(existing) = current.get(&d.name) {
            out.push(existing.clone());
        }
    }
    out
}

/// Build the new managed-group registry set. A group is recorded iff Census
/// OWNS it — it was already in the registry (carried forward) or Census created
/// it this run (`created` carries the names + optional pins). Deleted orphans
/// (in the old registry but no longer required) are dropped. The recorded GID
/// is the pin when known; otherwise the live GID read back via `inspector`
/// (OS-assigned). A carried-forward group keeps its prior GID record.
///
/// `required` is the required set (name → pin); `prior` is the old registry;
/// `created` is the list of (name, pin) Census created this run.
fn build_managed_groups(
    required: &BTreeMap<String, Option<u32>>,
    resolved_groups: &[crate::model::ResolvedGroup],
    prior: &BTreeMap<String, ManagedGroup>,
    created: &[(String, Option<u32>)],
    adopt_baselines: &BTreeMap<String, crate::state::GroupBaseline>,
    version: u32,
    inspector: &dyn SystemInspector,
) -> Vec<ManagedGroup> {
    let mut by_name: BTreeMap<String, ManagedGroup> = BTreeMap::new();

    // Membership-driven records (the plain groups accounts join, like `netdev`):
    // carry forward prior-registry groups still required, then add newly-created
    // ones. A declared `[[group]]` is overlaid with its full grant record below,
    // so this pass only finalizes the grant-less membership groups.
    for (name, mg) in prior {
        if required.contains_key(name) {
            by_name.insert(name.clone(), mg.clone());
        }
        // else: orphan — deleted (Created) or released (Adopted) this run; drop.
    }
    for (name, pin) in created {
        if by_name.contains_key(name) {
            continue;
        }
        // `pin` already carries the GID the OS assigned: Phase 1 read it back
        // through the provisioner immediately after groupadd. Fall back to the
        // pre-mutation snapshot inspector only if that read-back was also empty.
        // If both are empty the GID is genuinely unknown — recorded as `None`,
        // distinct from a real GID `0` (root group), so a later drift check skips
        // an unknown GID rather than spuriously flagging it.
        let gid = pin.or_else(|| inspector.group(name).map(|f| f.gid));
        by_name.insert(
            name.clone(),
            ManagedGroup {
                name: name.clone(),
                gid,
                provenance: crate::model::Provenance::Created,
                members_added: Vec::new(),
                sudo_commands: Vec::new(),
                file_grants: Vec::new(),
                adopt_baseline: None,
                from_version: version,
            },
        );
    }

    // Declaration-driven overlay: every currently-declared `[[group]]` carries
    // the grants Census materialized (sudo commands, `g:group` file grants) and
    // the members it added. This is the authority for those fields, so it
    // replaces any membership-only record built above for the same name. A group
    // that was Released/Deleted is absent from `resolved_groups` (no longer
    // declared) and therefore never recorded — its prior record was already
    // dropped above.
    for rg in resolved_groups {
        let prior_record = prior.get(&rg.name);
        // GID: a Created pin wins; otherwise carry the prior recorded GID; else
        // read the live GID back (adopted groups observe, never assign). If none
        // of those yields a GID it is genuinely unknown — recorded as `None`,
        // distinct from a real GID `0` (root group).
        let gid = rg
            .gid
            .or_else(|| prior_record.and_then(|p| p.gid))
            .or_else(|| inspector.group(&rg.name).map(|f| f.gid));

        // Adopt baseline: the one captured this run wins (first adoption);
        // otherwise carry the prior record's baseline forward across applies.
        let adopt_baseline = match rg.provenance {
            crate::model::Provenance::Created => None,
            crate::model::Provenance::Adopted => adopt_baselines
                .get(&rg.name)
                .cloned()
                .or_else(|| prior_record.and_then(|p| p.adopt_baseline.clone())),
        };

        let file_grants: Vec<ManagedFileGrant> = rg
            .file_grants
            .iter()
            .map(ManagedFileGrant::from_resolved)
            .collect();

        // Preserve from_version when the recorded grants/members/provenance are
        // unchanged (mirrors the account record); a real change bumps to the
        // declaration version.
        let from_version = match prior_record {
            Some(p)
                if p.provenance == rg.provenance
                    && crate::plan::sudo_set_equal(&p.sudo_commands, &rg.sudo_commands)
                    && groups_equal(&p.members_added, &rg.members)
                    && crate::plan::file_grants_set_equal(&p.file_grants, &rg.file_grants) =>
            {
                p.from_version
            }
            _ => version,
        };

        by_name.insert(
            rg.name.clone(),
            ManagedGroup {
                name: rg.name.clone(),
                gid,
                provenance: rg.provenance,
                // After the membership reconcile, Census-added members ARE the
                // target members (we add the missing, remove our own extras).
                members_added: rg.members.clone(),
                sudo_commands: rg.sudo_commands.clone(),
                file_grants,
                adopt_baseline,
                from_version,
            },
        );
    }

    let mut out: Vec<ManagedGroup> = by_name.into_values().collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn groups_equal(a: &[String], b: &[String]) -> bool {
    // Set-equal (order-insensitive). Short-circuit on length, then compare sorted
    // borrowed `&str` so neither side's String allocations are cloned — only two
    // pointer vectors are sorted.
    if a.len() != b.len() {
        return false;
    }
    let mut a: Vec<&str> = a.iter().map(String::as_str).collect();
    let mut b: Vec<&str> = b.iter().map(String::as_str).collect();
    a.sort_unstable();
    b.sort_unstable();
    a == b
}

/// Whether a recorded managed file-grant set equals a resolved target set,
/// compared set-equal (order-insensitive) by (path, access, recursive) — the
/// same comparison the plan diff uses. Lets `build_managed_set` preserve
/// `from_version` when only the order of grants differs.
fn file_grants_equal(
    managed: &[ManagedFileGrant],
    target: &[crate::catalog::ResolvedFileGrant],
) -> bool {
    crate::plan::file_grants_set_equal(managed, target)
}

/// Serialize a managed set (accounts + groups) to TOML and write it atomically
/// (temp + rename) to `path`. Used by the CLI as the final step after a
/// successful [`run`].
pub fn write_registry(
    path: &Path,
    managed: &[ManagedAccount],
    groups: &[ManagedGroup],
) -> Result<(), ApplyError> {
    let doc = RegistryDoc {
        account: managed.to_vec(),
        group: groups.to_vec(),
    };
    let text = toml::to_string(&doc).map_err(|e| ApplyError::Registry(e.to_string()))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp: PathBuf = parent.join(".census-managed.toml.tmp");
    std::fs::write(&tmp, text.as_bytes()).map_err(|e| ApplyError::Registry(e.to_string()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        ApplyError::Registry(e.to_string())
    })
}

#[derive(serde::Serialize)]
struct RegistryDoc {
    account: Vec<ManagedAccount>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    group: Vec<ManagedGroup>,
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;
    use crate::catalog::{FakeCatalog, OsTarget, ResolveCtx};
    use crate::fileaccess::{acl_capabilities, FakeBackend, FileAccessBackend};
    use crate::inspect::{FakeInspector, GroupFacts};
    use crate::lockout::LockoutContext;
    use crate::model::{CompileInputs, ResolvedAccount, SudoCommand};
    use crate::state::FakeState;

    /// A fresh dir-only (ACL-equivalent) backend for tests whose roles carry no
    /// per-file/pattern grants — the common case.
    fn dir_backend() -> FakeBackend {
        FakeBackend::new("acl", acl_capabilities())
    }

    /// An empty permission catalog + a fixed OS target for tests whose roles do
    /// not use `permissions` (the legacy raw-only path). Backed by statics so
    /// the borrowed `CompileInputs` can be `'static` and dropped into each
    /// `ApplyInputs` literal without a per-test local. Roles with no
    /// `permissions` never touch the catalog, so an empty one is exercised
    /// exactly as before permission expansion existed.
    fn empty_compile() -> CompileInputs<'static, FakeCatalog> {
        static CAT: OnceLock<FakeCatalog> = OnceLock::new();
        static OS: OnceLock<OsTarget> = OnceLock::new();
        static CTX: OnceLock<ResolveCtx> = OnceLock::new();
        CompileInputs {
            catalog: CAT.get_or_init(FakeCatalog::new),
            os: OS.get_or_init(|| OsTarget::new("linux", "debian", Some("12".to_owned())).unwrap()),
            ctx: CTX.get_or_init(ResolveCtx::default),
        }
    }

    /// Records every call and can be told to fail at a given phase.
    #[derive(Default)]
    struct FakeProvisioner {
        calls: Vec<String>,
        snapshotted: bool,
        restored: bool,
        /// Sudoers fragment paths registered for backup before snapshot.
        tracked_backups: Vec<std::path::PathBuf>,
        /// Phase name on which a mutating call should fail.
        fail_on: Option<&'static str>,
        /// GIDs to report from `group_gid` (the post-create read-back seam),
        /// keyed by group name. Absent ⇒ `None` (read-back failed).
        group_gids: std::collections::BTreeMap<String, u32>,
    }

    impl FakeProvisioner {
        fn failing(phase: &'static str) -> Self {
            FakeProvisioner {
                fail_on: Some(phase),
                ..Default::default()
            }
        }
        fn maybe_fail(&mut self, phase: &'static str, name: &str) -> Result<(), ProvisionError> {
            self.calls.push(format!("{phase}:{name}"));
            if self.fail_on == Some(phase) {
                Err(ProvisionError::Sudoers(format!(
                    "injected failure at {phase}"
                )))
            } else {
                Ok(())
            }
        }
    }

    impl Provisioner for FakeProvisioner {
        fn create(&mut self, acct: &ResolvedAccount) -> Result<(), ProvisionError> {
            self.maybe_fail("create", &acct.name)
        }
        fn update(&mut self, acct: &ResolvedAccount, _c: &[String]) -> Result<(), ProvisionError> {
            self.maybe_fail("update", &acct.name)
        }
        fn delete(&mut self, name: &str) -> Result<(), ProvisionError> {
            self.maybe_fail("delete", name)
        }
        fn create_group(&mut self, name: &str, _gid: Option<u32>) -> Result<(), ProvisionError> {
            self.maybe_fail("create_group", name)
        }
        fn group_gid(&self, name: &str) -> Option<u32> {
            self.group_gids.get(name).copied()
        }
        fn delete_group(&mut self, name: &str) -> Result<(), ProvisionError> {
            self.maybe_fail("delete_group", name)
        }
        fn apply_sudoers(&mut self, acct: &ResolvedAccount) -> Result<(), ProvisionError> {
            self.maybe_fail("apply_sudoers", &acct.name)
        }
        fn remove_sudoers(&mut self, name: &str) -> Result<(), ProvisionError> {
            self.maybe_fail("remove_sudoers", name)
        }
        fn apply_group_sudoers(
            &mut self,
            group: &crate::model::ResolvedGroup,
        ) -> Result<(), ProvisionError> {
            self.maybe_fail("apply_group_sudoers", &group.name)
        }
        fn remove_group_sudoers(&mut self, group: &str) -> Result<(), ProvisionError> {
            self.maybe_fail("remove_group_sudoers", group)
        }
        fn add_group_member(&mut self, group: &str, member: &str) -> Result<(), ProvisionError> {
            self.maybe_fail("add_member", &format!("{group}:{member}"))
        }
        fn remove_group_member(&mut self, group: &str, member: &str) -> Result<(), ProvisionError> {
            self.maybe_fail("del_member", &format!("{group}:{member}"))
        }
        fn track_sudoers_backup(&mut self, path: std::path::PathBuf) {
            self.calls.push(format!("track_backup:{}", path.display()));
            self.tracked_backups.push(path);
        }
        fn snapshot(&mut self) -> Result<(), ProvisionError> {
            self.snapshotted = true;
            self.calls.push("snapshot".to_owned());
            Ok(())
        }
        fn restore(&mut self) -> Result<(), ProvisionError> {
            self.restored = true;
            self.calls.push("restore".to_owned());
            Ok(())
        }
    }

    /// A FakeInspector reporting `wheel` as a pre-existing (foreign) system
    /// group. The default test role references `wheel`; without this the group
    /// plan would try to CREATE it. A pre-existing group is skipped (not
    /// adopted), so the account-only assertions in legacy tests hold.
    fn insp_with_wheel() -> FakeInspector {
        let mut f = FakeInspector::default();
        f.groups.insert("wheel".into(), GroupFacts { gid: 10 });
        f
    }

    fn decl(role: &str, uid: u32) -> (tempfile::TempDir, Declaration) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(format!("{role}.toml")),
            format!("role = \"{role}\"\nversion = 1\nos = \"linux\"\nname = \"X\"\nlevel = 0\n[payload]\ngroups = [\"wheel\"]\n"),
        )
        .unwrap();
        let store = tmp.path().display().to_string();
        let text = format!(
            "version = 5\nschema = 1\nrole_store = \"{store}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"{role}\"\nuid = {uid}\n"
        );
        let d = Declaration::parse(&text).unwrap();
        (tmp, d)
    }

    fn managed(name: &str, uid: u32, groups: &[&str], v: u32) -> ManagedAccount {
        ManagedAccount {
            name: name.to_owned(),
            uid,
            shell: "/bin/bash".to_owned(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            sudo_role: None,
            sudo_commands: Vec::new(),
            file_grants: Vec::new(),
            provenance: crate::model::Provenance::Created,
            from_version: v,
        }
    }

    fn fake_state(accts: Vec<ManagedAccount>) -> FakeState {
        FakeState {
            accounts: accts.into_iter().map(|a| (a.name.clone(), a)).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn fail_closed_without_trust_aborts_before_mutation() {
        let (_t, d) = decl("oper", 9010);
        let st = fake_state(vec![]);
        let mut p = FakeProvisioner::default();
        let insp = FakeInspector::default();
        let err = run(
            ApplyInputs {
                declaration: &d,
                declaration_bytes: b"",
                state: &st,
                inspector: &insp,
                trust: TrustOptions::default(), // no --trust-fs
                lockout: LockoutContext {
                    rescue_present: true,
                    ..Default::default()
                },
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
                compile: empty_compile(),
                file_access: Box::leak(Box::new(dir_backend())),
            },
            &mut p,
        )
        .unwrap_err();
        // Managed mode with no signature fails closed (missing signature) before
        // any snapshot or mutation.
        assert!(
            matches!(
                err,
                ApplyError::Trust(trust::TrustError::MissingSignature) | ApplyError::NotTrusted(_)
            ),
            "expected fail-closed trust error, got {err:?}"
        );
        assert!(!p.snapshotted, "no snapshot before trust passes");
        assert!(p.calls.is_empty(), "no mutations on untrusted declaration");
    }

    #[test]
    fn happy_path_creates_and_returns_registry() {
        let (_t, d) = decl("oper", 9010);
        let st = fake_state(vec![]);
        let mut p = FakeProvisioner::default();
        let insp = insp_with_wheel();
        let report = run(
            ApplyInputs {
                declaration: &d,
                declaration_bytes: b"",
                state: &st,
                inspector: &insp,
                trust: TrustOptions {
                    trust_fs: true,
                    ..Default::default()
                },
                lockout: LockoutContext::default(),
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
                compile: empty_compile(),
                file_access: Box::leak(Box::new(dir_backend())),
            },
            &mut p,
        )
        .unwrap();
        assert!(p.snapshotted);
        assert!(!p.restored, "no restore on success");
        assert_eq!(report.mutations, 1);
        assert!(
            report.registry_written,
            "mutating plan must persist the registry"
        );
        assert_eq!(report.managed.len(), 1);
        assert_eq!(report.managed[0].name, "oper");
        assert_eq!(report.managed[0].from_version, 5);
        assert!(p.calls.contains(&"create:oper".to_owned()));
    }

    #[test]
    fn phase_failure_triggers_restore_and_no_registry_commit() {
        let (_t, d) = decl("oper", 9010);
        let st = fake_state(vec![]);
        let mut p = FakeProvisioner::failing("create");
        let insp = FakeInspector::default();
        let err = run(
            ApplyInputs {
                declaration: &d,
                declaration_bytes: b"",
                state: &st,
                inspector: &insp,
                trust: TrustOptions {
                    trust_fs: true,
                    ..Default::default()
                },
                lockout: LockoutContext::default(),
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
                compile: empty_compile(),
                file_access: Box::leak(Box::new(dir_backend())),
            },
            &mut p,
        )
        .unwrap_err();
        match err {
            ApplyError::Phase {
                phase, rollback, ..
            } => {
                assert_eq!(phase, "create");
                assert_eq!(rollback, RollbackOutcome::Restored);
            }
            other => panic!("expected Phase error, got {other:?}"),
        }
        assert!(p.restored, "failure must trigger restore");
    }

    #[test]
    fn idempotent_empty_plan_does_zero_mutations() {
        // Managed state already matches the declaration → empty plan.
        let (_t, d) = decl("oper", 9010);
        let st = fake_state(vec![managed("oper", 9010, &["wheel"], 5)]);
        let mut p = FakeProvisioner::default();
        let insp = insp_with_wheel();
        let report = run(
            ApplyInputs {
                declaration: &d,
                declaration_bytes: b"",
                state: &st,
                inspector: &insp,
                trust: TrustOptions {
                    trust_fs: true,
                    ..Default::default()
                },
                lockout: LockoutContext::default(),
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
                compile: empty_compile(),
                file_access: Box::leak(Box::new(dir_backend())),
            },
            &mut p,
        )
        .unwrap();
        assert_eq!(report.mutations, 0);
        assert!(
            !report.registry_written,
            "empty plan must not request a registry write"
        );
        assert!(!p.snapshotted, "empty plan must not snapshot");
        assert!(p.calls.is_empty(), "empty plan must not mutate");
        // registry still reflects the in-sync account, preserving from_version.
        assert_eq!(report.managed[0].from_version, 5);
    }

    #[test]
    fn lockout_gate_refuses_before_snapshot() {
        // Declaration with no accounts, managed has one → delete-only plan, no rescue.
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().display().to_string();
        let text = format!(
            "version = 5\nschema = 1\nrole_store = \"{store}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n"
        );
        let d = Declaration::parse(&text).unwrap();
        let st = fake_state(vec![managed("oper", 9010, &["wheel"], 5)]);
        let mut p = FakeProvisioner::default();
        let insp = FakeInspector::default();
        let err = run(
            ApplyInputs {
                declaration: &d,
                declaration_bytes: b"",
                state: &st,
                inspector: &insp,
                trust: TrustOptions {
                    trust_fs: true,
                    ..Default::default()
                },
                lockout: LockoutContext::default(), // no rescue, no risk-ack
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
                compile: empty_compile(),
                file_access: Box::leak(Box::new(dir_backend())),
            },
            &mut p,
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::Lockout(_)));
        assert!(!p.snapshotted, "lockout refusal must precede snapshot");
    }

    /// Like `decl`, but the role slice carries a `sudo_role`, so the resolved
    /// account yields a sudoers fragment.
    fn decl_with_sudo(role: &str, uid: u32) -> (tempfile::TempDir, Declaration) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(format!("{role}.toml")),
            format!("role = \"{role}\"\nversion = 1\nos = \"linux\"\nname = \"X\"\nlevel = 0\n[payload]\ngroups = [\"wheel\"]\nsudo_role = \"ops\"\n"),
        )
        .unwrap();
        let store = tmp.path().display().to_string();
        let text = format!(
            "version = 5\nschema = 1\nrole_store = \"{store}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"{role}\"\nuid = {uid}\n"
        );
        let d = Declaration::parse(&text).unwrap();
        (tmp, d)
    }

    #[test]
    fn create_applies_sudoers_and_tracks_backup_before_snapshot() {
        let (_t, d) = decl_with_sudo("oper", 9010);
        let st = fake_state(vec![]);
        let mut p = FakeProvisioner::default();
        let insp = insp_with_wheel();
        let report = run(
            ApplyInputs {
                declaration: &d,
                declaration_bytes: b"",
                state: &st,
                inspector: &insp,
                trust: TrustOptions {
                    trust_fs: true,
                    ..Default::default()
                },
                lockout: LockoutContext::default(),
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
                compile: empty_compile(),
                file_access: Box::leak(Box::new(dir_backend())),
            },
            &mut p,
        )
        .unwrap();
        assert_eq!(report.mutations, 1);
        // The fragment path was registered for backup …
        assert_eq!(
            p.tracked_backups,
            vec![PathBuf::from("/etc/sudoers.d/census-oper")]
        );
        // … BEFORE the snapshot was taken (ordering via the recorded call log).
        let track_idx = p
            .calls
            .iter()
            .position(|c| c == "track_backup:/etc/sudoers.d/census-oper")
            .expect("track_backup recorded");
        let snap_idx = p
            .calls
            .iter()
            .position(|c| c == "snapshot")
            .expect("snapshot recorded");
        assert!(
            track_idx < snap_idx,
            "backup must be registered before snapshot"
        );
        // … and the sudoers fragment was materialized for the created role.
        assert!(p.calls.contains(&"create:oper".to_owned()));
        assert!(p.calls.contains(&"apply_sudoers:oper".to_owned()));
    }

    #[test]
    fn delete_removes_sudoers_and_tracks_backup() {
        // Declaration with no accounts, managed has one → delete-only plan.
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().display().to_string();
        let text = format!(
            "version = 5\nschema = 1\nrole_store = \"{store}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n"
        );
        let d = Declaration::parse(&text).unwrap();
        let st = fake_state(vec![managed("oper", 9010, &["wheel"], 5)]);
        let mut p = FakeProvisioner::default();
        let insp = FakeInspector::default();
        let report = run(
            ApplyInputs {
                declaration: &d,
                declaration_bytes: b"",
                state: &st,
                inspector: &insp,
                trust: TrustOptions {
                    trust_fs: true,
                    ..Default::default()
                },
                // Rescue present so the delete-only plan passes the lockout gate.
                lockout: LockoutContext {
                    rescue_present: true,
                    ..Default::default()
                },
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
                compile: empty_compile(),
                file_access: Box::leak(Box::new(dir_backend())),
            },
            &mut p,
        )
        .unwrap();
        assert_eq!(report.mutations, 1);
        assert!(p.calls.contains(&"remove_sudoers:oper".to_owned()));
        assert!(p.calls.contains(&"delete:oper".to_owned()));
        // sudoers removal precedes userdel.
        let rm_idx = p
            .calls
            .iter()
            .position(|c| c == "remove_sudoers:oper")
            .unwrap();
        let del_idx = p.calls.iter().position(|c| c == "delete:oper").unwrap();
        assert!(rm_idx < del_idx, "sudoers removal must precede userdel");
        // Deleted role's fragment was tracked for backup.
        assert_eq!(
            p.tracked_backups,
            vec![PathBuf::from("/etc/sudoers.d/census-oper")]
        );
    }

    #[test]
    fn sudoers_failure_triggers_restore_and_no_registry_write() {
        let (_t, d) = decl_with_sudo("oper", 9010);
        let st = fake_state(vec![]);
        // Account creation succeeds; the sudoers materialization fails.
        let mut p = FakeProvisioner::failing("apply_sudoers");
        let insp = FakeInspector::default();
        let err = run(
            ApplyInputs {
                declaration: &d,
                declaration_bytes: b"",
                state: &st,
                inspector: &insp,
                trust: TrustOptions {
                    trust_fs: true,
                    ..Default::default()
                },
                lockout: LockoutContext::default(),
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
                compile: empty_compile(),
                file_access: Box::leak(Box::new(dir_backend())),
            },
            &mut p,
        )
        .unwrap_err();
        match err {
            ApplyError::Phase {
                phase,
                rollback,
                source,
            } => {
                assert_eq!(phase, "create", "sudoers is part of the create phase");
                assert_eq!(rollback, RollbackOutcome::Restored);
                assert!(matches!(source, ProvisionError::Sudoers(_)));
            }
            other => panic!("expected Phase error, got {other:?}"),
        }
        assert!(p.restored, "sudoers failure must trigger restore");
        // create ran, apply_sudoers ran and failed; backup of the fragment was
        // registered before the snapshot so the restore covers it.
        assert!(p.calls.contains(&"create:oper".to_owned()));
        assert!(p.calls.contains(&"apply_sudoers:oper".to_owned()));
        assert_eq!(
            p.tracked_backups,
            vec![PathBuf::from("/etc/sudoers.d/census-oper")]
        );
    }

    #[test]
    fn write_registry_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("managed.toml");
        let mut sudo_acct = managed("oper", 9010, &["wheel"], 5);
        sudo_acct.sudo_role = Some("ops".to_owned());
        let set = vec![sudo_acct, managed("plain", 9011, &[], 5)];
        let groups = vec![ManagedGroup {
            name: "atm-operators".to_owned(),
            gid: Some(8010),
            provenance: crate::model::Provenance::Created,
            members_added: Vec::new(),
            sudo_commands: Vec::new(),
            file_grants: Vec::new(),
            adopt_baseline: None,
            from_version: 5,
        }];
        write_registry(&path, &set, &groups).unwrap();
        let reloaded = crate::state::RegistryState::load(&path).unwrap();
        let accts = reloaded.managed_accounts();
        assert_eq!(accts["oper"].uid, 9010);
        assert_eq!(accts["oper"].from_version, 5);
        // sudo_role must survive the registry roundtrip (the privilege-retention fix).
        assert_eq!(accts["oper"].sudo_role.as_deref(), Some("ops"));
        assert_eq!(accts["plain"].sudo_role, None);
        // managed groups round-trip alongside accounts.
        let grps = reloaded.managed_groups();
        assert_eq!(grps["atm-operators"].gid, Some(8010));
        assert_eq!(grps["atm-operators"].from_version, 5);
    }

    // ---- managed-mode integration (task 4.4) ----

    use ed25519_dalek::{Signer, SigningKey};

    /// Build a managed (signed) declaration that creates one role-account, plus
    /// a pinned trust-anchor file. Returns (tempdir, raw bytes, parsed decl,
    /// anchor path). The signature covers the doc minus the `signature` line.
    fn signed_managed(
        sk: &SigningKey,
        version: u32,
        role: &str,
        uid: u32,
    ) -> (tempfile::TempDir, String, Declaration, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(format!("{role}.toml")),
            format!("role = \"{role}\"\nversion = 1\nos = \"linux\"\nname = \"X\"\nlevel = 0\n[payload]\ngroups = [\"wheel\"]\n"),
        )
        .unwrap();
        let store = tmp.path().display().to_string();
        // signature line precedes the [defaults] table (TOML top-level key).
        let head = format!("version = {version}\nschema = 1\nrole_store = \"{store}\"\n");
        let tail = format!(
            "[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"{role}\"\nuid = {uid}\n"
        );
        let payload = format!("{head}{tail}");
        let sig_hex = hex::encode(sk.sign(payload.as_bytes()).to_bytes());
        let full = format!("{head}signature = \"{sig_hex}\"\n{tail}");
        let decl = Declaration::parse(&full).unwrap();
        let anchor = tmp.path().join("trust.pub");
        std::fs::write(&anchor, hex::encode(sk.verifying_key().to_bytes())).unwrap();
        (tmp, full, decl, anchor)
    }

    fn managed_opts(anchor: PathBuf, persist: PathBuf) -> TrustOptions {
        TrustOptions {
            trust_fs: false,
            trust_anchor_path: anchor,
            persist_dir: persist,
        }
    }

    #[test]
    fn managed_without_signature_refuses_before_snapshot() {
        // Managed mode, declaration has no signature line → fail-closed.
        let (_t, d) = decl("oper", 9010);
        let st = fake_state(vec![]);
        let mut p = FakeProvisioner::default();
        let insp = FakeInspector::default();
        let persist = tempfile::tempdir().unwrap();
        let err = run(
            ApplyInputs {
                declaration: &d,
                declaration_bytes: b"version = 5\n", // no signature line
                state: &st,
                inspector: &insp,
                trust: managed_opts(
                    PathBuf::from("/nonexistent.pub"),
                    persist.path().to_path_buf(),
                ),
                lockout: LockoutContext {
                    rescue_present: true,
                    ..Default::default()
                },
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
                compile: empty_compile(),
                file_access: Box::leak(Box::new(dir_backend())),
            },
            &mut p,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ApplyError::Trust(trust::TrustError::MissingSignature)
        ));
        assert!(
            !p.snapshotted,
            "managed-no-signature must refuse before snapshot"
        );
        assert!(p.calls.is_empty(), "no mutations");
    }

    #[test]
    fn managed_valid_signature_runs_and_reports_managed_mode() {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let persist = tempfile::tempdir().unwrap();
        let (_t, raw, d, anchor) = signed_managed(&sk, 5, "oper", 9010);
        let st = fake_state(vec![]);
        let mut p = FakeProvisioner::default();
        let insp = insp_with_wheel();
        let report = run(
            ApplyInputs {
                declaration: &d,
                declaration_bytes: raw.as_bytes(),
                state: &st,
                inspector: &insp,
                trust: managed_opts(anchor, persist.path().to_path_buf()),
                lockout: LockoutContext {
                    rescue_present: true,
                    ..Default::default()
                },
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
                compile: empty_compile(),
                file_access: Box::leak(Box::new(dir_backend())),
            },
            &mut p,
        )
        .unwrap();
        assert!(p.snapshotted);
        assert_eq!(report.mutations, 1);
        assert_eq!(report.trust_mode, TrustMode::Managed { version: 5 });
    }

    #[test]
    fn managed_replayed_lower_version_refuses_before_snapshot() {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let persist = tempfile::tempdir().unwrap();
        // Persist a higher floor than the declaration version.
        trust::persist_version(persist.path(), 9).unwrap();
        let (_t, raw, d, anchor) = signed_managed(&sk, 5, "oper", 9010);
        let st = fake_state(vec![]);
        let mut p = FakeProvisioner::default();
        let insp = FakeInspector::default();
        let err = run(
            ApplyInputs {
                declaration: &d,
                declaration_bytes: raw.as_bytes(),
                state: &st,
                inspector: &insp,
                trust: managed_opts(anchor, persist.path().to_path_buf()),
                lockout: LockoutContext {
                    rescue_present: true,
                    ..Default::default()
                },
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
                compile: empty_compile(),
                file_access: Box::leak(Box::new(dir_backend())),
            },
            &mut p,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ApplyError::Trust(trust::TrustError::Rollback { got: 5, floor: 9 })
        ));
        assert!(!p.snapshotted, "anti-rollback must refuse before snapshot");
        assert!(p.calls.is_empty());
    }

    #[test]
    fn managed_phase_failure_returns_err_so_caller_skips_persist() {
        // The caller (cli) only persists on Ok; a phase failure yields Err and the
        // persisted floor stays untouched.
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let persist = tempfile::tempdir().unwrap();
        let (_t, raw, d, anchor) = signed_managed(&sk, 5, "oper", 9010);
        let st = fake_state(vec![]);
        let mut p = FakeProvisioner::failing("create");
        let insp = FakeInspector::default();
        let err = run(
            ApplyInputs {
                declaration: &d,
                declaration_bytes: raw.as_bytes(),
                state: &st,
                inspector: &insp,
                trust: managed_opts(anchor, persist.path().to_path_buf()),
                lockout: LockoutContext {
                    rescue_present: true,
                    ..Default::default()
                },
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
                compile: empty_compile(),
                file_access: Box::leak(Box::new(dir_backend())),
            },
            &mut p,
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::Phase { .. }));
        // Floor was never persisted by `run` (persist is the caller's job, only on Ok).
        assert_eq!(trust::last_applied_version(persist.path()).unwrap(), None);
    }

    // ---- group provisioning phase ordering / safety (task 4.4) ----

    /// Build a `--trust-fs` declaration whose role references `group` as a
    /// supplementary group, optionally pinning it via a `[[group]]` block.
    /// Returns (tempdir, parsed declaration).
    fn decl_with_group(
        role: &str,
        uid: u32,
        group: &str,
        pin: Option<u32>,
    ) -> (tempfile::TempDir, Declaration) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(format!("{role}.toml")),
            format!("role = \"{role}\"\nversion = 1\nos = \"linux\"\nname = \"X\"\nlevel = 0\n[payload]\ngroups = [\"{group}\"]\n"),
        )
        .unwrap();
        let store = tmp.path().display().to_string();
        let mut text = format!(
            "version = 5\nschema = 1\nrole_store = \"{store}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"{role}\"\nuid = {uid}\n"
        );
        if let Some(g) = pin {
            text.push_str(&format!("[[group]]\nname = \"{group}\"\ngid = {g}\n"));
        }
        let d = Declaration::parse(&text).unwrap();
        (tmp, d)
    }

    fn trust_fs_inputs<'a>(
        d: &'a Declaration,
        st: &'a FakeState,
        insp: &'a FakeInspector,
        sessions: &'a dyn crate::sessions::SessionSource,
    ) -> ApplyInputs<'a, FakeCatalog> {
        ApplyInputs {
            declaration: d,
            declaration_bytes: b"",
            state: st,
            inspector: insp,
            trust: TrustOptions {
                trust_fs: true,
                ..Default::default()
            },
            lockout: LockoutContext {
                rescue_present: true,
                ..Default::default()
            },
            sudoers_dir: PathBuf::from("/etc/sudoers.d"),
            session_source: sessions,
            sessions_file: PathBuf::from("/run/tessera/sessions.json"),
            compile: empty_compile(),
            // The group/reconcile tests do not exercise file grants; a leaked
            // fresh dir backend keeps these call sites unchanged (a tiny per-test
            // leak in a test binary is harmless) while satisfying the `&'a mut`
            // field. Tests that assert on backend calls build their own inline.
            file_access: Box::leak(Box::new(dir_backend())),
        }
    }

    fn managed_group(name: &str, gid: u32, v: u32) -> ManagedGroup {
        ManagedGroup {
            name: name.to_owned(),
            gid: Some(gid),
            provenance: crate::model::Provenance::Created,
            members_added: Vec::new(),
            sudo_commands: Vec::new(),
            file_grants: Vec::new(),
            adopt_baseline: None,
            from_version: v,
        }
    }

    fn fake_state_with_groups(accts: Vec<ManagedAccount>, groups: Vec<ManagedGroup>) -> FakeState {
        FakeState {
            accounts: accts.into_iter().map(|a| (a.name.clone(), a)).collect(),
            groups: groups.into_iter().map(|g| (g.name.clone(), g)).collect(),
        }
    }

    #[test]
    fn group_create_precedes_account_create() {
        // Role references a group absent from the system → it must be created
        // BEFORE the account (membership needs it). Inspector reports no groups.
        let (_t, d) = decl_with_group("oper", 9010, "atm-operators", Some(8010));
        let st = FakeState::default();
        let insp = FakeInspector::default();
        let mut p = FakeProvisioner::default();
        let report = run(
            trust_fs_inputs(&d, &st, &insp, &crate::sessions::FakeSessionSource::empty()),
            &mut p,
        )
        .unwrap();
        let cg = p
            .calls
            .iter()
            .position(|c| c == "create_group:atm-operators")
            .expect("group create");
        let ca = p
            .calls
            .iter()
            .position(|c| c == "create:oper")
            .expect("account create");
        assert!(
            cg < ca,
            "group create must precede account create: {:?}",
            p.calls
        );
        // Registry records the created group with its pinned GID.
        assert_eq!(report.managed_group_records.len(), 1);
        assert_eq!(report.managed_group_records[0].name, "atm-operators");
        assert_eq!(report.managed_group_records[0].gid, Some(8010));
        assert_eq!(report.managed_group_records[0].from_version, 5);
    }

    #[test]
    fn unpinned_created_group_records_provisioner_readback_gid() {
        // An unpinned group is created with an OS-assigned GID. The registry must
        // record the GID read back THROUGH THE PROVISIONER (the seam that created
        // it), not 0 and not a value from the pre-mutation snapshot inspector
        // (which could not see a group that did not exist yet).
        let (_t, d) = decl_with_group("oper", 9010, "atm-operators", None);
        let st = FakeState::default();
        // Snapshot inspector has NO group — only the post-create provisioner
        // read-back knows the assigned GID.
        let insp = FakeInspector::default();
        let mut p = FakeProvisioner::default();
        p.group_gids.insert("atm-operators".into(), 8042);
        let report = run(
            trust_fs_inputs(&d, &st, &insp, &crate::sessions::FakeSessionSource::empty()),
            &mut p,
        )
        .unwrap();
        let g = report
            .managed_group_records
            .iter()
            .find(|g| g.name == "atm-operators")
            .expect("created group recorded");
        assert_eq!(
            g.gid,
            Some(8042),
            "registry must record the provisioner read-back GID"
        );
    }

    #[test]
    fn unpinned_created_group_records_none_gid_when_readback_fails() {
        // If neither the provisioner read-back nor the snapshot inspector can
        // resolve the GID, the record carries `None` ("GID unknown") rather than
        // overloading the root group's GID `0` — and never panics. A later doctor
        // run skips the drift check for an unknown GID instead of false-flagging.
        let (_t, d) = decl_with_group("oper", 9010, "atm-operators", None);
        let st = FakeState::default();
        let insp = FakeInspector::default(); // no group facts
        let mut p = FakeProvisioner::default(); // no group_gids entry → read-back None
        let report = run(
            trust_fs_inputs(&d, &st, &insp, &crate::sessions::FakeSessionSource::empty()),
            &mut p,
        )
        .unwrap();
        let g = report
            .managed_group_records
            .iter()
            .find(|g| g.name == "atm-operators")
            .expect("created group recorded");
        assert_eq!(
            g.gid, None,
            "unknown GID recorded as None, no panic, no 0 sentinel"
        );
    }

    #[test]
    fn group_delete_follows_account_delete() {
        // Declaration with no accounts/groups; registry owns an account AND a
        // group → both vanish. Account delete must precede group delete.
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().display().to_string();
        let text = format!(
            "version = 5\nschema = 1\nrole_store = \"{store}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n"
        );
        let d = Declaration::parse(&text).unwrap();
        let st = fake_state_with_groups(
            vec![managed("oper", 9010, &[], 5)],
            vec![managed_group("atm-operators", 8010, 5)],
        );
        // Group still live (so drift check passes) at its recorded gid.
        let mut insp = FakeInspector::default();
        insp.groups
            .insert("atm-operators".into(), GroupFacts { gid: 8010 });
        let mut p = FakeProvisioner::default();
        let report = run(
            trust_fs_inputs(&d, &st, &insp, &crate::sessions::FakeSessionSource::empty()),
            &mut p,
        )
        .unwrap();
        let da = p
            .calls
            .iter()
            .position(|c| c == "delete:oper")
            .expect("account delete");
        let dg = p
            .calls
            .iter()
            .position(|c| c == "delete_group:atm-operators")
            .expect("group delete");
        assert!(
            da < dg,
            "account delete must precede group delete: {:?}",
            p.calls
        );
        // The orphan group is dropped from the registry.
        assert!(
            report.managed_group_records.is_empty(),
            "orphan group must leave the registry"
        );
    }

    #[test]
    fn pin_conflict_aborts_before_any_mutation() {
        // Pin gid 8010 for atm-operators, but gid 8010 already belongs to a
        // DIFFERENT live group. Apply must refuse before snapshot/mutation.
        let (_t, d) = decl_with_group("oper", 9010, "atm-operators", Some(8010));
        let st = FakeState::default();
        let mut insp = FakeInspector::default();
        insp.groups.insert("other".into(), GroupFacts { gid: 8010 });
        let mut p = FakeProvisioner::default();
        let err = run(
            trust_fs_inputs(&d, &st, &insp, &crate::sessions::FakeSessionSource::empty()),
            &mut p,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApplyError::GroupPlan(_)),
            "expected GroupPlan error, got {err:?}"
        );
        assert!(!p.snapshotted, "pin conflict must abort before snapshot");
        assert!(
            p.calls.is_empty(),
            "pin conflict must abort before any mutation"
        );
    }

    #[test]
    fn foreign_existing_group_is_never_created_or_deleted() {
        // Role references `wheel`, which exists live but is NOT in the registry
        // (foreign). It must be neither created nor deleted nor recorded.
        let (_t, d) = decl_with_group("oper", 9010, "wheel", None);
        let st = FakeState::default();
        let mut insp = FakeInspector::default();
        insp.groups.insert("wheel".into(), GroupFacts { gid: 10 });
        let mut p = FakeProvisioner::default();
        let report = run(
            trust_fs_inputs(&d, &st, &insp, &crate::sessions::FakeSessionSource::empty()),
            &mut p,
        )
        .unwrap();
        assert!(
            !p.calls.iter().any(|c| c.starts_with("create_group")),
            "foreign group must not be created: {:?}",
            p.calls
        );
        assert!(
            !p.calls.iter().any(|c| c.starts_with("delete_group")),
            "foreign group must not be deleted: {:?}",
            p.calls
        );
        assert!(
            report.managed_group_records.is_empty(),
            "foreign group must not enter the registry"
        );
    }

    #[test]
    fn group_create_failure_triggers_restore() {
        let (_t, d) = decl_with_group("oper", 9010, "atm-operators", Some(8010));
        let st = FakeState::default();
        let insp = FakeInspector::default();
        let mut p = FakeProvisioner::failing("create_group");
        let err = run(
            trust_fs_inputs(&d, &st, &insp, &crate::sessions::FakeSessionSource::empty()),
            &mut p,
        )
        .unwrap_err();
        match err {
            ApplyError::Phase {
                phase, rollback, ..
            } => {
                assert_eq!(phase, "create-group");
                assert_eq!(rollback, RollbackOutcome::Restored);
            }
            other => panic!("expected Phase error, got {other:?}"),
        }
        assert!(p.restored, "group-create failure must trigger restore");
        // The account was never created (group phase failed first).
        assert!(!p.calls.iter().any(|c| c == "create:oper"));
    }

    // ---- live-reconcile (§12) ----

    use crate::sessions::{FakeSessionSource, LiveSessions, SessionSource};

    /// A declaration that declares NO role-accounts (so any managed account is a
    /// delete in the plan). Returns (tempdir, declaration).
    fn empty_decl() -> (tempfile::TempDir, Declaration) {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().display().to_string();
        let text = format!(
            "version = 5\nschema = 1\nrole_store = \"{store}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n"
        );
        let d = Declaration::parse(&text).unwrap();
        (tmp, d)
    }

    /// Build `ApplyInputs` for a `--trust-fs`, rescue-present run over the given
    /// state + session source (the live-reconcile tests vary only those).
    fn reconcile_inputs<'a>(
        d: &'a Declaration,
        st: &'a FakeState,
        insp: &'a FakeInspector,
        sessions: &'a dyn SessionSource,
    ) -> ApplyInputs<'a, FakeCatalog> {
        ApplyInputs {
            declaration: d,
            declaration_bytes: b"",
            state: st,
            inspector: insp,
            trust: TrustOptions {
                trust_fs: true,
                ..Default::default()
            },
            lockout: LockoutContext {
                rescue_present: true,
                ..Default::default()
            },
            sudoers_dir: PathBuf::from("/etc/sudoers.d"),
            session_source: sessions,
            sessions_file: PathBuf::from("/run/tessera/sessions.json"),
            compile: empty_compile(),
            file_access: Box::leak(Box::new(dir_backend())),
        }
    }

    fn live_by_name(name: &str) -> FakeSessionSource {
        let mut live = LiveSessions::default();
        live.names.insert(name.to_owned());
        FakeSessionSource::with_live(live)
    }

    fn live_by_uid(uid: u32) -> FakeSessionSource {
        let mut live = LiveSessions::default();
        live.uids.insert(uid);
        FakeSessionSource::with_live(live)
    }

    #[test]
    fn delete_with_live_session_by_name_is_deferred_and_retained() {
        // Declaration drops `oper`; the registry owns it at from_version 4; a live
        // session matches by name → userdel must NOT run and ownership is kept.
        let (_t, d) = empty_decl();
        let st = fake_state(vec![managed("oper", 9010, &[], 4)]);
        let insp = FakeInspector::default();
        let sessions = live_by_name("oper");
        let mut p = FakeProvisioner::default();
        let report = run(reconcile_inputs(&d, &st, &insp, &sessions), &mut p).unwrap();

        assert!(
            !p.calls.iter().any(|c| c == "delete:oper"),
            "userdel must be deferred: {:?}",
            p.calls
        );
        assert_eq!(report.mutations, 0, "a deferred delete is not a mutation");
        // Account retained in the managed set with its PRIOR from_version.
        let oper = report
            .managed
            .iter()
            .find(|m| m.name == "oper")
            .expect("oper retained in managed");
        assert_eq!(
            oper.from_version, 4,
            "deferred account keeps its prior from_version"
        );
        // Reported as a deferred delete (name + uid).
        assert_eq!(report.deferred_deletes.len(), 1);
        assert_eq!(report.deferred_deletes[0].name, "oper");
        assert_eq!(report.deferred_deletes[0].uid, 9010);
    }

    #[test]
    fn deferred_account_with_grants_emits_retained_grant_warning() {
        // A deferred account keeps its full prior privilege until its session ends.
        // When that record carries grants the declaration revoked, apply must emit
        // a structured `warning:` line naming the account and the retained grants,
        // so the retention is visible rather than silent.
        let (_t, d) = empty_decl();
        let mut rec = managed("oper", 9010, &["wheel"], 4);
        rec.sudo_commands = vec![SudoCommand::root("/usr/sbin/ip")];
        rec.file_grants = vec![ManagedFileGrant {
            path: "/etc/ssh".to_owned(),
            access: crate::catalog::Access::RW,
            recursive: true,
        }];
        let st = fake_state(vec![rec]);
        let insp = FakeInspector::default();
        let sessions = live_by_name("oper");
        let mut p = FakeProvisioner::default();
        let report = run(reconcile_inputs(&d, &st, &insp, &sessions), &mut p).unwrap();

        let warn = report
            .log
            .iter()
            .find(|l| l.starts_with("warning:") && l.contains("retains revoked grants"))
            .expect("retained-grant warning line");
        assert!(warn.contains("oper"), "warning names the account: {warn}");
        assert!(
            warn.contains("/usr/sbin/ip"),
            "warning lists retained sudo command: {warn}"
        );
        assert!(
            warn.contains("/etc/ssh"),
            "warning lists retained file grant: {warn}"
        );
    }

    #[test]
    fn delete_with_live_session_by_uid_only_is_deferred() {
        // Live set knows only the uid (e.g. the account was renamed live); the
        // uid match alone must defer the delete.
        let (_t, d) = empty_decl();
        let st = fake_state(vec![managed("oper", 9010, &[], 4)]);
        let insp = FakeInspector::default();
        let sessions = live_by_uid(9010);
        let mut p = FakeProvisioner::default();
        let report = run(reconcile_inputs(&d, &st, &insp, &sessions), &mut p).unwrap();

        assert!(
            !p.calls.iter().any(|c| c == "delete:oper"),
            "uid match must defer userdel"
        );
        assert_eq!(report.deferred_deletes.len(), 1);
        assert_eq!(report.deferred_deletes[0].uid, 9010);
        assert!(
            report.managed.iter().any(|m| m.name == "oper"),
            "uid-deferred account retained"
        );
    }

    #[test]
    fn delete_without_live_session_executes_normally() {
        // No session for `oper` → the delete runs as before.
        let (_t, d) = empty_decl();
        let st = fake_state(vec![managed("oper", 9010, &[], 4)]);
        let insp = FakeInspector::default();
        let sessions = FakeSessionSource::empty();
        let mut p = FakeProvisioner::default();
        let report = run(reconcile_inputs(&d, &st, &insp, &sessions), &mut p).unwrap();

        assert!(
            p.calls.iter().any(|c| c == "delete:oper"),
            "no session → userdel runs"
        );
        assert_eq!(report.mutations, 1);
        assert!(report.deferred_deletes.is_empty());
        assert!(
            !report.managed.iter().any(|m| m.name == "oper"),
            "deleted account leaves the registry"
        );
    }

    #[test]
    fn empty_live_set_executes_all_deletes() {
        // Two managed accounts, both dropped, empty live set → both delete.
        let (_t, d) = empty_decl();
        let st = fake_state(vec![
            managed("oper", 9010, &[], 4),
            managed("serv", 9011, &[], 4),
        ]);
        let insp = FakeInspector::default();
        let sessions = FakeSessionSource::empty();
        let mut p = FakeProvisioner::default();
        let report = run(reconcile_inputs(&d, &st, &insp, &sessions), &mut p).unwrap();

        assert!(p.calls.iter().any(|c| c == "delete:oper"));
        assert!(p.calls.iter().any(|c| c == "delete:serv"));
        assert_eq!(report.mutations, 2);
        assert!(report.deferred_deletes.is_empty());
        assert!(
            report.managed.is_empty(),
            "both accounts removed from the registry"
        );
    }

    #[test]
    fn plan_with_only_deferred_delete_does_no_mutations_but_retains() {
        // The single planned change is a delete that gets deferred → the plan is
        // empty after removal. No snapshot, no phase mutations, but the deferred
        // account is retained and the registry write is requested (so the
        // retention is persisted; from_version is preserved → idempotent content).
        let (_t, d) = empty_decl();
        let st = fake_state(vec![managed("oper", 9010, &[], 4)]);
        let insp = FakeInspector::default();
        let sessions = live_by_name("oper");
        let mut p = FakeProvisioner::default();
        let report = run(reconcile_inputs(&d, &st, &insp, &sessions), &mut p).unwrap();

        assert!(
            !p.snapshotted,
            "no snapshot when the only change was deferred"
        );
        assert!(
            p.calls.is_empty(),
            "no phase calls when the only change was deferred"
        );
        assert_eq!(report.mutations, 0);
        assert!(
            report.registry_written,
            "retention of the deferred account must be persisted"
        );
        let oper = report
            .managed
            .iter()
            .find(|m| m.name == "oper")
            .expect("oper retained");
        assert_eq!(oper.from_version, 4);
        assert_eq!(report.deferred_deletes.len(), 1);
    }

    #[test]
    fn non_delete_plan_ignores_session_read_error() {
        // A create-only plan must NOT be blocked by an unreadable registry: there
        // is nothing to defer, so the read error is irrelevant. Use a session
        // source that errors and assert apply still succeeds.
        let (_t, d) = decl("oper", 9010);
        let st = fake_state(vec![]); // nothing managed → plan is a create
        let insp = insp_with_wheel();
        let sessions = FakeSessionSource::failing();
        let mut p = FakeProvisioner::default();
        let report = run(reconcile_inputs(&d, &st, &insp, &sessions), &mut p).unwrap();

        assert!(
            p.calls.iter().any(|c| c == "create:oper"),
            "create runs despite registry read error"
        );
        assert_eq!(report.mutations, 1);
        assert!(report.deferred_deletes.is_empty());
    }

    #[test]
    fn destructive_plan_fails_closed_on_unreadable_registry() {
        // A delete plan + an unreadable registry → fail-closed BEFORE snapshot: we
        // cannot prove no session is live, so we must not risk tearing one down.
        let (_t, d) = empty_decl();
        let st = fake_state(vec![managed("oper", 9010, &[], 4)]);
        let insp = FakeInspector::default();
        let sessions = FakeSessionSource::failing();
        let mut p = FakeProvisioner::default();
        let err = run(reconcile_inputs(&d, &st, &insp, &sessions), &mut p).unwrap_err();

        assert!(
            matches!(err, ApplyError::SessionRegistry(_)),
            "expected fail-closed, got {err:?}"
        );
        assert!(!p.snapshotted, "fail-closed must precede snapshot");
        assert!(p.calls.is_empty(), "fail-closed must precede any mutation");
    }

    #[test]
    fn deferral_precedes_anti_lockout_gate() {
        // Delete-only plan with NO rescue and NO risk-ack would normally trip the
        // anti-lockout gate. But the account has a live session, so the delete is
        // deferred BEFORE the gate runs → the (now empty) plan passes, the account
        // is kept, and no lockout error is raised.
        let (_t, d) = empty_decl();
        let st = fake_state(vec![managed("oper", 9010, &[], 4)]);
        let insp = FakeInspector::default();
        let sessions = live_by_name("oper");
        let mut p = FakeProvisioner::default();
        let inputs = ApplyInputs {
            declaration: &d,
            declaration_bytes: b"",
            state: &st,
            inspector: &insp,
            trust: TrustOptions {
                trust_fs: true,
                ..Default::default()
            },
            lockout: LockoutContext::default(), // no rescue, no risk-ack
            sudoers_dir: PathBuf::from("/etc/sudoers.d"),
            session_source: &sessions,
            sessions_file: PathBuf::from("/run/tessera/sessions.json"),
            compile: empty_compile(),
            file_access: Box::leak(Box::new(dir_backend())),
        };
        let report = run(inputs, &mut p).unwrap();
        assert_eq!(
            report.deferred_deletes.len(),
            1,
            "delete deferred before the gate"
        );
        assert!(
            report.managed.iter().any(|m| m.name == "oper"),
            "account kept"
        );
    }

    #[test]
    fn deferred_account_supplementary_group_is_retained_not_deleted() {
        // `oper` (live) carries supplementary group `atm-operators`, which the
        // registry owns. Dropping `oper` would delete both; the live session must
        // defer the userdel AND keep the group (no groupdel, retained with its
        // prior GID/from_version) so nothing is torn from under the session.
        let (_t, d) = empty_decl();
        let st = fake_state_with_groups(
            vec![managed("oper", 9010, &["atm-operators"], 4)],
            vec![managed_group("atm-operators", 8010, 4)],
        );
        // Group live at its recorded gid so the drift check passes.
        let mut insp = FakeInspector::default();
        insp.groups
            .insert("atm-operators".into(), GroupFacts { gid: 8010 });
        let sessions = live_by_name("oper");
        let mut p = FakeProvisioner::default();
        let report = run(reconcile_inputs(&d, &st, &insp, &sessions), &mut p).unwrap();

        assert!(
            !p.calls.iter().any(|c| c == "delete_group:atm-operators"),
            "deferred account's group must not be deleted: {:?}",
            p.calls
        );
        assert!(
            !p.calls.iter().any(|c| c == "delete:oper"),
            "userdel deferred"
        );
        // Group retained in the registry with its PRIOR gid + from_version.
        let g = report
            .managed_group_records
            .iter()
            .find(|g| g.name == "atm-operators")
            .expect("group retained in registry");
        assert_eq!(g.gid, Some(8010), "retained group keeps prior GID");
        assert_eq!(g.from_version, 4, "retained group keeps prior from_version");
    }

    #[test]
    fn deferred_account_primary_role_group_delete_is_dropped() {
        // The role-named primary group (`useradd` user-private group, same name as
        // the account) would be deleted when `oper` is dropped. With a live
        // session, that delete must be dropped — never attempt `groupdel` on the
        // active uid's primary group (would fail "busy" and roll back the apply).
        let (_t, d) = empty_decl();
        let st = fake_state_with_groups(
            vec![managed("oper", 9010, &[], 4)],
            vec![managed_group("oper", 9010, 4)],
        );
        let mut insp = FakeInspector::default();
        insp.groups.insert("oper".into(), GroupFacts { gid: 9010 });
        let sessions = live_by_name("oper");
        let mut p = FakeProvisioner::default();
        let report = run(reconcile_inputs(&d, &st, &insp, &sessions), &mut p).unwrap();

        assert!(
            !p.calls.iter().any(|c| c == "delete_group:oper"),
            "primary group of a live account must not be groupdel'd: {:?}",
            p.calls
        );
        assert!(
            report
                .managed_group_records
                .iter()
                .any(|g| g.name == "oper"),
            "primary group retained"
        );
    }

    #[test]
    fn group_delete_unrelated_to_deferral_still_runs() {
        // Two accounts dropped: `oper` (live) owns group `ga`; `serv` (no session)
        // owns group `gb`. `oper`+`ga` defer; `serv`+`gb` must still be deleted —
        // the retention is scoped to the deferred account's groups only.
        let (_t, d) = empty_decl();
        let st = fake_state_with_groups(
            vec![
                managed("oper", 9010, &["ga"], 4),
                managed("serv", 9011, &["gb"], 4),
            ],
            vec![managed_group("ga", 8010, 4), managed_group("gb", 8011, 4)],
        );
        let mut insp = FakeInspector::default();
        insp.groups.insert("ga".into(), GroupFacts { gid: 8010 });
        insp.groups.insert("gb".into(), GroupFacts { gid: 8011 });
        let sessions = live_by_name("oper");
        let mut p = FakeProvisioner::default();
        let report = run(reconcile_inputs(&d, &st, &insp, &sessions), &mut p).unwrap();

        // oper deferred, ga retained; serv deleted, gb deleted.
        assert!(
            !p.calls.iter().any(|c| c == "delete:oper"),
            "oper userdel deferred"
        );
        assert!(
            !p.calls.iter().any(|c| c == "delete_group:ga"),
            "ga retained"
        );
        assert!(p.calls.iter().any(|c| c == "delete:serv"), "serv deleted");
        assert!(p.calls.iter().any(|c| c == "delete_group:gb"), "gb deleted");
        assert!(
            report.managed_group_records.iter().any(|g| g.name == "ga"),
            "ga retained in registry"
        );
        assert!(
            !report.managed_group_records.iter().any(|g| g.name == "gb"),
            "gb dropped from registry"
        );
    }

    // ---- file-access phase ----

    use crate::catalog::{Access, FileGrant, ListOverride, PermissionDef, Shape};
    use crate::fileaccess::FakeCall;

    /// A catalog (leaked, so the borrowed `CompileInputs` is `'static`) with one
    /// permission `fs-edit` carrying a single `[[file]]` grant of the given path/
    /// access/recursive, on the `linux` base layer.
    fn compile_with_file_perm(
        path: &str,
        access: Access,
        recursive: bool,
    ) -> CompileInputs<'static, FakeCatalog> {
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                id: "fs-edit".to_owned(),
                risk: None,
                category: None,
                groups: ListOverride::default(),
                sudo: ListOverride::default(),
                runas: None,
                limits: None,
                replace: false,
                includes: Vec::new(),
                include_categories: Vec::new(),
                files: vec![FileGrant {
                    path: path.to_owned(),
                    access,
                    recursive,
                }],
                params: std::collections::BTreeMap::new(),
            },
        );
        let os = OsTarget::new("linux", "debian", Some("12".to_owned())).unwrap();
        CompileInputs {
            catalog: Box::leak(Box::new(cat)),
            os: Box::leak(Box::new(os)),
            ctx: Box::leak(Box::new(ResolveCtx::default())),
        }
    }

    /// A `--trust-fs` declaration whose role references the `fs-edit` permission
    /// (so resolve attaches its file grant). Returns (tempdir, declaration).
    fn decl_with_file_perm(role: &str, uid: u32) -> (tempfile::TempDir, Declaration) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(format!("{role}.toml")),
            format!("role = \"{role}\"\nversion = 1\nos = \"linux\"\nname = \"X\"\nlevel = 0\n[payload]\npermissions = [\"fs-edit\"]\n"),
        )
        .unwrap();
        let store = tmp.path().display().to_string();
        let text = format!(
            "version = 5\nschema = 1\nrole_store = \"{store}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"{role}\"\nuid = {uid}\n"
        );
        let d = Declaration::parse(&text).unwrap();
        (tmp, d)
    }

    /// Build trust-fs ApplyInputs with a caller-supplied compile + file backend
    /// (so the test can inspect the backend's recorded calls afterward).
    fn fa_inputs<'a>(
        d: &'a Declaration,
        st: &'a FakeState,
        insp: &'a FakeInspector,
        sessions: &'a dyn SessionSource,
        compile: CompileInputs<'a, FakeCatalog>,
        file_access: &'a mut dyn FileAccessBackend,
    ) -> ApplyInputs<'a, FakeCatalog> {
        ApplyInputs {
            declaration: d,
            declaration_bytes: b"",
            state: st,
            inspector: insp,
            trust: TrustOptions {
                trust_fs: true,
                ..Default::default()
            },
            lockout: LockoutContext {
                rescue_present: true,
                ..Default::default()
            },
            sudoers_dir: PathBuf::from("/etc/sudoers.d"),
            session_source: sessions,
            sessions_file: PathBuf::from("/run/tessera/sessions.json"),
            compile,
            file_access,
        }
    }

    #[test]
    fn dir_grant_materializes_after_snapshot() {
        // A created account carries a recursive dir grant → the backend snapshots
        // the grant path BEFORE materializing it, and materialize receives the
        // grant for the account.
        let (_t, d) = decl_with_file_perm("oper", 9010);
        let st = FakeState::default();
        let insp = FakeInspector::default();
        let sessions = FakeSessionSource::empty();
        let mut fa = dir_backend();
        let mut p = FakeProvisioner::default();
        let compile = compile_with_file_perm("/etc/ssh", Access::RW, true);
        run(
            fa_inputs(&d, &st, &insp, &sessions, compile, &mut fa),
            &mut p,
        )
        .unwrap();

        // snapshot recorded with the grant path …
        let snap_idx = fa
            .calls
            .iter()
            .position(|c| matches!(c, FakeCall::Snapshot { paths } if paths == &vec!["/etc/ssh".to_owned()]))
            .expect("snapshot of the grant path");
        // … and materialize recorded with the account + path, AFTER the snapshot.
        let mat_idx = fa
            .calls
            .iter()
            .position(|c| {
                matches!(c, FakeCall::Materialize { principal, paths }
                if principal == &crate::fileaccess::Principal::User("oper".to_owned())
                    && paths == &vec!["/etc/ssh".to_owned()])
            })
            .expect("materialize of the grant");
        assert!(
            snap_idx < mat_idx,
            "snapshot must precede materialize: {:?}",
            fa.calls
        );
    }

    #[test]
    fn removed_grant_is_revoked() {
        // The registry records a grant the target no longer carries (the role's
        // permission was changed to grant a DIFFERENT path) → the old path is
        // revoked, the new one materialized.
        let (_t, d) = decl_with_file_perm("oper", 9010);
        let mut prior = managed("oper", 9010, &[], 5);
        prior.file_grants = vec![crate::state::ManagedFileGrant {
            path: "/etc/old".to_owned(),
            access: Access::RW,
            recursive: true,
        }];
        let st = fake_state(vec![prior]);
        let insp = FakeInspector::default();
        let sessions = FakeSessionSource::empty();
        let mut fa = dir_backend();
        let mut p = FakeProvisioner::default();
        let compile = compile_with_file_perm("/etc/ssh", Access::RW, true);
        run(
            fa_inputs(&d, &st, &insp, &sessions, compile, &mut fa),
            &mut p,
        )
        .unwrap();

        assert!(
            fa.calls
                .iter()
                .any(|c| matches!(c, FakeCall::Revoke { principal, path }
                if principal == &crate::fileaccess::Principal::User("oper".to_owned())
                    && path == "/etc/old")),
            "the dropped grant must be revoked: {:?}",
            fa.calls
        );
        assert!(
            fa.calls
                .iter()
                .any(|c| matches!(c, FakeCall::Materialize { paths, .. }
                if paths == &vec!["/etc/ssh".to_owned()])),
            "the new grant must be materialized: {:?}",
            fa.calls
        );
    }

    #[test]
    fn deleted_account_grants_are_revoked_by_numeric_uid() {
        // The declaration drops `oper`; the registry recorded a grant for it →
        // the grant is revoked (no live session, so the delete runs).
        //
        // Regression: the account-delete phase runs `userdel` BEFORE this
        // file-access teardown, so by the time the ACL is revoked the name `oper`
        // no longer resolves through `getpwnam`. `setfacl -x u:oper` would then be
        // rejected ("Option -x: invalid argument") and abort the whole apply. The
        // revoke must therefore key the entry on the recorded numeric UID
        // (`u:9010`), which is how the kernel stored it and which resolves with no
        // passwd entry. Asserts the principal is `Uid(9010)`, NOT `User("oper")`.
        let (_t, d) = empty_decl();
        let mut prior = managed("oper", 9010, &[], 4);
        prior.file_grants = vec![crate::state::ManagedFileGrant {
            path: "/etc/ssh".to_owned(),
            access: Access::RW,
            recursive: true,
        }];
        let st = fake_state(vec![prior]);
        let insp = FakeInspector::default();
        let sessions = FakeSessionSource::empty();
        let mut fa = dir_backend();
        let mut p = FakeProvisioner::default();
        run(
            fa_inputs(&d, &st, &insp, &sessions, empty_compile(), &mut fa),
            &mut p,
        )
        .unwrap();
        assert!(
            fa.calls
                .iter()
                .any(|c| matches!(c, FakeCall::Revoke { principal, path }
                if principal == &crate::fileaccess::Principal::Uid(9010)
                    && path == "/etc/ssh")),
            "the deleted account's grant must be revoked by numeric UID (u:9010): {:?}",
            fa.calls
        );
        // And never by the deleted name, which would not resolve once userdel ran.
        assert!(
            !fa.calls
                .iter()
                .any(|c| matches!(c, FakeCall::Revoke { principal, .. }
                if principal == &crate::fileaccess::Principal::User("oper".to_owned()))),
            "must not revoke a deleted account by its (now-unresolvable) name: {:?}",
            fa.calls
        );
    }

    #[test]
    fn file_shape_grant_without_capable_backend_fails_closed_before_mutation() {
        // A per-file grant (recursive=false, no glob → Shape::File) with only the
        // dir-capable ACL backend → gating returns FileAccess BEFORE any snapshot
        // or provisioner mutation.
        let (_t, d) = decl_with_file_perm("oper", 9010);
        let st = FakeState::default();
        let insp = FakeInspector::default();
        let sessions = FakeSessionSource::empty();
        let mut fa = dir_backend(); // dir-only capability
        let mut p = FakeProvisioner::default();
        let compile = compile_with_file_perm("/etc/ssh/sshd_config", Access::RW, false);
        let err = run(
            fa_inputs(&d, &st, &insp, &sessions, compile, &mut fa),
            &mut p,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApplyError::FileAccess(crate::fileaccess::FileAccessError::Unsupported { ref shape, .. }) if *shape == Shape::File),
            "per-file grant without a capable backend must fail closed: {err:?}"
        );
        // No provisioner mutation and no snapshot of either seam.
        assert!(
            !p.snapshotted,
            "gating must precede the provisioner snapshot"
        );
        assert!(
            p.calls.is_empty(),
            "gating must precede any provisioner mutation"
        );
        assert!(
            !fa.calls
                .iter()
                .any(|c| matches!(c, FakeCall::Snapshot { .. } | FakeCall::Materialize { .. })),
            "gating must precede any backend snapshot/materialize: {:?}",
            fa.calls
        );
    }

    #[test]
    fn provisioner_phase_failure_restores_file_access_backend() {
        // The account create (provisioner) fails AFTER the file-access snapshot
        // was taken → rollback must call the backend's restore (both seams roll
        // back together).
        let (_t, d) = decl_with_file_perm("oper", 9010);
        let st = FakeState::default();
        let insp = FakeInspector::default();
        let sessions = FakeSessionSource::empty();
        let mut fa = dir_backend();
        let mut p = FakeProvisioner::failing("create");
        let compile = compile_with_file_perm("/etc/ssh", Access::RW, true);
        let err = run(
            fa_inputs(&d, &st, &insp, &sessions, compile, &mut fa),
            &mut p,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ApplyError::Phase {
                    phase: "create",
                    ..
                }
            ),
            "got {err:?}"
        );
        assert!(p.restored, "provisioner must restore");
        assert!(
            fa.calls.iter().any(|c| matches!(c, FakeCall::Restore)),
            "file-access backend must restore on a provisioner phase failure: {:?}",
            fa.calls
        );
    }

    // ---- group-grants apply orchestration (slice 5c) ----

    /// A leaked catalog defining one permission `grp-perm` on `linux` carrying a
    /// `%group`-projectable sudo command + an optional dir file grant. Returned as
    /// `'static` so the borrowed `CompileInputs` drops into an `ApplyInputs`.
    fn compile_with_group_perm(
        sudo: &[&str],
        file: Option<&str>,
    ) -> CompileInputs<'static, FakeCatalog> {
        let files = file
            .map(|p| {
                vec![FileGrant {
                    path: p.to_owned(),
                    access: Access::RW,
                    recursive: true,
                }]
            })
            .unwrap_or_default();
        let cat = FakeCatalog::new().with(
            "linux",
            PermissionDef {
                id: "grp-perm".to_owned(),
                risk: None,
                category: None,
                groups: ListOverride::default(),
                sudo: ListOverride::Replace(sudo.iter().map(|s| s.to_string()).collect()),
                runas: None,
                limits: None,
                replace: false,
                includes: Vec::new(),
                include_categories: Vec::new(),
                files,
                params: std::collections::BTreeMap::new(),
            },
        );
        let os = OsTarget::new("linux", "debian", None).unwrap();
        CompileInputs {
            catalog: Box::leak(Box::new(cat)),
            os: Box::leak(Box::new(os)),
            ctx: Box::leak(Box::new(ResolveCtx::default())),
        }
    }

    /// Build a `--trust-fs` declaration with a role-store holding `role` (carrying
    /// `grp-perm`), a single `[[group]]` (optionally `adopt`, with `members`), and
    /// a `[[role_group]]` binding `role` to that group. `accounts` are extra
    /// `[[role_account]]` lines (so an adopted group's member can be a managed
    /// account). Returns (tempdir, declaration).
    fn decl_group_grant(
        role: &str,
        group: &str,
        adopt: bool,
        members: &[&str],
        accounts: &[(&str, u32)],
    ) -> (tempfile::TempDir, Declaration) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(format!("{role}.toml")),
            format!("role = \"{role}\"\nversion = 1\nos = \"linux\"\nname = \"X\"\nlevel = 0\n[payload]\npermissions = [\"grp-perm\"]\n"),
        )
        .unwrap();
        let store = tmp.path().display().to_string();
        let mut text = format!(
            "version = 5\nschema = 1\nrole_store = \"{store}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n"
        );
        for (r, uid) in accounts {
            text.push_str(&format!("[[role_account]]\nrole = \"{r}\"\nuid = {uid}\n"));
        }
        let members_lit = members
            .iter()
            .map(|m| format!("\"{m}\""))
            .collect::<Vec<_>>()
            .join(", ");
        text.push_str(&format!("[[group]]\nname = \"{group}\"\n"));
        if adopt {
            text.push_str("adopt = true\n");
        } else {
            text.push_str("gid = 8050\n");
        }
        text.push_str(&format!("members = [{members_lit}]\n"));
        text.push_str(&format!(
            "[[role_group]]\nrole = \"{role}\"\ngroup = \"{group}\"\n"
        ));
        let d = Declaration::parse(&text).unwrap();
        (tmp, d)
    }

    fn ag_inputs<'a>(
        d: &'a Declaration,
        st: &'a FakeState,
        insp: &'a FakeInspector,
        sessions: &'a dyn SessionSource,
        compile: CompileInputs<'a, FakeCatalog>,
        file_access: &'a mut dyn FileAccessBackend,
    ) -> ApplyInputs<'a, FakeCatalog> {
        ApplyInputs {
            declaration: d,
            declaration_bytes: b"",
            state: st,
            inspector: insp,
            trust: TrustOptions {
                trust_fs: true,
                ..Default::default()
            },
            lockout: LockoutContext {
                rescue_present: true,
                ..Default::default()
            },
            sudoers_dir: PathBuf::from("/etc/sudoers.d"),
            session_source: sessions,
            sessions_file: PathBuf::from("/run/tessera/sessions.json"),
            compile,
            file_access,
        }
    }

    #[test]
    fn created_group_grant_writes_sudoers_acl_and_members() {
        // A non-adopted [[group]] bound to a role with a sudo + file grant and a
        // member. apply must: groupadd (existence), write %group sudoers, set
        // g:group ACL, and gpasswd -a the member.
        let (_t, d) = decl_group_grant("netops", "ops", false, &["netops"], &[("netops", 9010)]);
        let st = FakeState::default();
        let insp = FakeInspector::default(); // group absent → diff_groups Create
        let sessions = FakeSessionSource::empty();
        let mut fa = dir_backend();
        let mut p = FakeProvisioner::default();
        let compile = compile_with_group_perm(&["/usr/sbin/ip"], Some("/etc/net"));
        let report = run(
            ag_inputs(&d, &st, &insp, &sessions, compile, &mut fa),
            &mut p,
        )
        .unwrap();

        // Entity create (membership path) then %group sudoers (resolved path).
        assert!(
            p.calls.iter().any(|c| c == "create_group:ops"),
            "groupadd: {:?}",
            p.calls
        );
        assert!(
            p.calls.iter().any(|c| c == "apply_group_sudoers:ops"),
            "%group sudoers: {:?}",
            p.calls
        );
        assert!(
            p.calls.iter().any(|c| c == "add_member:ops:netops"),
            "gpasswd add: {:?}",
            p.calls
        );
        // g:group ACL materialized.
        assert!(
            fa.calls
                .iter()
                .any(|c| matches!(c, FakeCall::Materialize { principal, paths }
                if principal == &crate::fileaccess::Principal::Group("ops".to_owned())
                    && paths == &vec!["/etc/net".to_owned()])),
            "group ACL must materialize: {:?}",
            fa.calls
        );
        // Registry record carries the grants/members/provenance.
        let g = report
            .managed_group_records
            .iter()
            .find(|g| g.name == "ops")
            .expect("ops recorded");
        assert_eq!(g.provenance, crate::model::Provenance::Created);
        assert_eq!(g.sudo_commands, vec![SudoCommand::root("/usr/sbin/ip")]);
        assert_eq!(g.members_added, vec!["netops"]);
        assert_eq!(g.file_grants.len(), 1);
        assert_eq!(g.gid, Some(8050));
        assert!(g.adopt_baseline.is_none());
    }

    #[test]
    fn adopt_group_skips_groupadd_and_records_baseline() {
        // An adopted [[group]] that already exists live. apply must NOT groupadd,
        // must snapshot the baseline (live gid + members read via inspector), and
        // must apply Census's grants on top.
        let (_t, d) = decl_group_grant("netops", "wheel", true, &["netops"], &[("netops", 9010)]);
        let st = FakeState::default();
        let mut insp = FakeInspector::default();
        insp.groups.insert("wheel".into(), GroupFacts { gid: 10 });
        insp.group_members
            .insert("wheel".into(), vec!["root".into(), "admin".into()]);
        let sessions = FakeSessionSource::empty();
        let mut fa = dir_backend();
        let mut p = FakeProvisioner::default();
        let compile = compile_with_group_perm(&["/usr/sbin/ip"], None);
        let report = run(
            ag_inputs(&d, &st, &insp, &sessions, compile, &mut fa),
            &mut p,
        )
        .unwrap();

        assert!(
            !p.calls.iter().any(|c| c.starts_with("create_group")),
            "adopt must not groupadd: {:?}",
            p.calls
        );
        assert!(
            p.calls.iter().any(|c| c == "apply_group_sudoers:wheel"),
            "grants applied: {:?}",
            p.calls
        );
        assert!(
            p.calls.iter().any(|c| c == "add_member:wheel:netops"),
            "our member added: {:?}",
            p.calls
        );
        let g = report
            .managed_group_records
            .iter()
            .find(|g| g.name == "wheel")
            .expect("wheel recorded");
        assert_eq!(g.provenance, crate::model::Provenance::Adopted);
        let baseline = g.adopt_baseline.as_ref().expect("adopt baseline recorded");
        assert_eq!(baseline.gid, Some(10), "baseline gid read from inspector");
        assert_eq!(
            baseline.members,
            vec!["root", "admin"],
            "baseline members read from inspector"
        );
        // Adopted group records the observed GID, not a pin.
        assert_eq!(g.gid, Some(10));
    }

    #[test]
    fn release_adopted_group_strips_grants_keeps_group_and_baseline_members() {
        // An adopted group, previously under management, vanishes from the
        // declaration. Release must: remove %group sudoers, revoke g:group ACL,
        // gpasswd -d our own members — but NEVER groupdel, and never touch the
        // baseline (foreign) members.
        let (_t, d) = empty_decl();
        let prior_group = ManagedGroup {
            name: "wheel".to_owned(),
            gid: Some(10),
            provenance: crate::model::Provenance::Adopted,
            members_added: vec!["netops".to_owned()],
            sudo_commands: vec![SudoCommand::root("/usr/sbin/ip")],
            file_grants: vec![ManagedFileGrant {
                path: "/etc/net".to_owned(),
                access: Access::RW,
                recursive: true,
            }],
            adopt_baseline: Some(crate::state::GroupBaseline {
                gid: Some(10),
                members: vec!["root".to_owned()],
            }),
            from_version: 4,
        };
        let st = fake_state_with_groups(vec![], vec![prior_group]);
        let mut insp = FakeInspector::default();
        insp.groups.insert("wheel".into(), GroupFacts { gid: 10 });
        let sessions = FakeSessionSource::empty();
        let mut fa = dir_backend();
        let mut p = FakeProvisioner::default();
        let report = run(
            ag_inputs(&d, &st, &insp, &sessions, empty_compile(), &mut fa),
            &mut p,
        )
        .unwrap();

        assert!(
            p.calls.iter().any(|c| c == "remove_group_sudoers:wheel"),
            "%group sudoers stripped: {:?}",
            p.calls
        );
        assert!(
            p.calls.iter().any(|c| c == "del_member:wheel:netops"),
            "our member removed: {:?}",
            p.calls
        );
        assert!(
            !p.calls.iter().any(|c| c.starts_with("delete_group")),
            "release must NOT groupdel: {:?}",
            p.calls
        );
        assert!(
            fa.calls.iter().any(|c| matches!(c, FakeCall::Revoke { principal, path }
                if principal == &crate::fileaccess::Principal::Group("wheel".to_owned()) && path == "/etc/net")),
            "group ACL revoked: {:?}", fa.calls
        );
        // The released group leaves the registry; its live group + baseline
        // members (root) are untouched (no del_member for root).
        assert!(
            !report
                .managed_group_records
                .iter()
                .any(|g| g.name == "wheel"),
            "released group dropped from registry"
        );
        assert!(
            !p.calls.iter().any(|c| c == "del_member:wheel:root"),
            "baseline member must be untouched: {:?}",
            p.calls
        );
    }

    #[test]
    fn created_group_dropped_tears_down_grants_then_groupdel() {
        // A Created [[group]] (with grants/members) vanishes. Grant-teardown
        // (%group sudoers + ACL + our members) must precede the entity groupdel.
        let (_t, d) = empty_decl();
        let prior_group = ManagedGroup {
            name: "ops".to_owned(),
            gid: Some(8050),
            provenance: crate::model::Provenance::Created,
            members_added: vec!["netops".to_owned()],
            sudo_commands: vec![SudoCommand::root("/usr/sbin/ip")],
            file_grants: vec![ManagedFileGrant {
                path: "/etc/net".to_owned(),
                access: Access::RW,
                recursive: true,
            }],
            adopt_baseline: None,
            from_version: 4,
        };
        let st = fake_state_with_groups(vec![], vec![prior_group]);
        let mut insp = FakeInspector::default();
        insp.groups.insert("ops".into(), GroupFacts { gid: 8050 });
        let sessions = FakeSessionSource::empty();
        let mut fa = dir_backend();
        let mut p = FakeProvisioner::default();
        let report = run(
            ag_inputs(&d, &st, &insp, &sessions, empty_compile(), &mut fa),
            &mut p,
        )
        .unwrap();

        let rm_sudo = p
            .calls
            .iter()
            .position(|c| c == "remove_group_sudoers:ops")
            .expect("grant teardown");
        let groupdel = p
            .calls
            .iter()
            .position(|c| c == "delete_group:ops")
            .expect("entity groupdel");
        assert!(
            rm_sudo < groupdel,
            "grant teardown must precede groupdel: {:?}",
            p.calls
        );
        assert!(
            p.calls.iter().any(|c| c == "del_member:ops:netops"),
            "our member removed: {:?}",
            p.calls
        );
        assert!(
            fa.calls.iter().any(|c| matches!(c, FakeCall::Revoke { principal, path }
                if principal == &crate::fileaccess::Principal::Group("ops".to_owned()) && path == "/etc/net")),
            "group ACL revoked before groupdel: {:?}", fa.calls
        );
        assert!(
            !report.managed_group_records.iter().any(|g| g.name == "ops"),
            "deleted group dropped from registry"
        );
    }

    #[test]
    fn adopted_group_dropped_never_groupdels() {
        // KEY safety test: an Adopted registry group that vanishes from the
        // declaration must produce a Release (no groupdel), never an entity
        // delete — even though it is no longer "required".
        let (_t, d) = empty_decl();
        let mut prior_group = managed_group("wheel", 10, 4);
        prior_group.provenance = crate::model::Provenance::Adopted;
        prior_group.adopt_baseline = Some(crate::state::GroupBaseline {
            gid: Some(10),
            members: vec![],
        });
        let st = fake_state_with_groups(vec![], vec![prior_group]);
        let mut insp = FakeInspector::default();
        insp.groups.insert("wheel".into(), GroupFacts { gid: 10 });
        let sessions = FakeSessionSource::empty();
        let mut fa = dir_backend();
        let mut p = FakeProvisioner::default();
        run(
            ag_inputs(&d, &st, &insp, &sessions, empty_compile(), &mut fa),
            &mut p,
        )
        .unwrap();

        assert!(
            !p.calls.iter().any(|c| c.starts_with("delete_group")),
            "adopted group must never be groupdel'd on teardown: {:?}",
            p.calls
        );
    }

    #[test]
    fn group_member_reconciliation_adds_and_removes_only_own() {
        // target.members changed: registry recorded {a} added; declaration now
        // targets {b}. gpasswd -a b (new) and gpasswd -d a (our own, dropped);
        // a foreign baseline member is never touched.
        // A Created group allows any member name (no managed-account constraint),
        // so `a`/`b` need not be declared accounts.
        let (_t, d) = decl_group_grant("netops", "ops", false, &["b"], &[("netops", 9010)]);
        let prior_group = ManagedGroup {
            name: "ops".to_owned(),
            gid: Some(8050),
            provenance: crate::model::Provenance::Created,
            members_added: vec!["a".to_owned()],
            sudo_commands: vec![SudoCommand::root("/usr/sbin/ip")],
            file_grants: vec![],
            adopt_baseline: None,
            from_version: 4,
        };
        let st = fake_state_with_groups(vec![], vec![prior_group]);
        let mut insp = FakeInspector::default();
        insp.groups.insert("ops".into(), GroupFacts { gid: 8050 });
        let sessions = FakeSessionSource::empty();
        let mut fa = dir_backend();
        let mut p = FakeProvisioner::default();
        let compile = compile_with_group_perm(&["/usr/sbin/ip"], None);
        let report = run(
            ag_inputs(&d, &st, &insp, &sessions, compile, &mut fa),
            &mut p,
        )
        .unwrap();

        assert!(
            p.calls.iter().any(|c| c == "add_member:ops:b"),
            "new member added: {:?}",
            p.calls
        );
        assert!(
            p.calls.iter().any(|c| c == "del_member:ops:a"),
            "dropped own member removed: {:?}",
            p.calls
        );
        let g = report
            .managed_group_records
            .iter()
            .find(|g| g.name == "ops")
            .unwrap();
        assert_eq!(
            g.members_added,
            vec!["b"],
            "registry records the new membership"
        );
    }

    #[test]
    fn group_grant_phase_failure_triggers_restore() {
        // A failure in the group-sudoers phase rolls back both seams (provisioner
        // restore + file-access restore).
        let (_t, d) = decl_group_grant("netops", "ops", false, &["netops"], &[("netops", 9010)]);
        let st = FakeState::default();
        let insp = FakeInspector::default();
        let sessions = FakeSessionSource::empty();
        let mut fa = dir_backend();
        let mut p = FakeProvisioner::failing("apply_group_sudoers");
        let compile = compile_with_group_perm(&["/usr/sbin/ip"], Some("/etc/net"));
        let err = run(
            ag_inputs(&d, &st, &insp, &sessions, compile, &mut fa),
            &mut p,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ApplyError::Phase {
                    phase: "group-sudoers",
                    ..
                }
            ),
            "got {err:?}"
        );
        assert!(
            p.restored,
            "provisioner must restore on group-grant failure"
        );
        assert!(
            fa.calls.iter().any(|c| matches!(c, FakeCall::Restore)),
            "file-access restores too: {:?}",
            fa.calls
        );
    }

    #[test]
    fn group_grant_apply_is_idempotent_on_rerun() {
        // After a first apply records the group, a re-apply with the SAME
        // declaration and the registry reflecting it must do no group mutations
        // (no add/del member, no sudoers churn that counts as a change) — the
        // resolved-group diff is in sync.
        let (_t, d) = decl_group_grant("netops", "ops", false, &["netops"], &[("netops", 9010)]);
        // Registry already reflects the applied state (group + account in sync).
        let applied_group = ManagedGroup {
            name: "ops".to_owned(),
            gid: Some(8050),
            provenance: crate::model::Provenance::Created,
            members_added: vec!["netops".to_owned()],
            sudo_commands: vec![SudoCommand::root("/usr/sbin/ip")],
            file_grants: vec![],
            adopt_baseline: None,
            from_version: 5,
        };
        // The account resolves `grp-perm` → sudo command `/usr/sbin/ip`; group
        // membership is managed on the GROUP (gpasswd), not the account's
        // supplementary groups, so the account record carries no `ops` group.
        let applied_acct = {
            let mut m = managed("netops", 9010, &[], 5);
            m.sudo_commands = vec![SudoCommand::root("/usr/sbin/ip")];
            m
        };
        let st = fake_state_with_groups(vec![applied_acct], vec![applied_group]);
        let mut insp = FakeInspector::default();
        insp.groups.insert("ops".into(), GroupFacts { gid: 8050 });
        let sessions = FakeSessionSource::empty();
        let mut fa = dir_backend();
        let mut p = FakeProvisioner::default();
        let compile = compile_with_group_perm(&["/usr/sbin/ip"], None);
        let report = run(
            ag_inputs(&d, &st, &insp, &sessions, compile, &mut fa),
            &mut p,
        )
        .unwrap();

        assert_eq!(
            report.mutations, 0,
            "in-sync re-apply is a no-op: {:?}",
            p.calls
        );
        assert!(!p.snapshotted, "no snapshot on an empty plan");
        assert!(
            p.calls.is_empty(),
            "no group mutations on a synced re-apply: {:?}",
            p.calls
        );
    }
}
