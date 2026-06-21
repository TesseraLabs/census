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

use crate::declaration::Declaration;
use crate::inspect::SystemInspector;
use crate::mutate::{Provisioner, ProvisionError};
use crate::plan::{self, Action, GroupAction};
use crate::state::{ManagedAccount, ManagedGroup, SystemState};
use crate::trust::{self, TrustMode, TrustOptions};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Errors that abort apply (each maps to a non-zero exit upstream).
#[derive(Debug, thiserror::Error)]
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
pub struct ApplyInputs<'a> {
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
pub fn run(
    inputs: ApplyInputs<'_>,
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

    // 2-3. Resolve targets (slice-1).
    let targets = crate::model::resolve(inputs.declaration)
        .map_err(|e| ApplyError::Registry(e.to_string()))?;

    // 4-5. Diff vs managed state (accounts).
    let managed_now = inputs.state.managed_accounts();
    let managed_groups_now = inputs.state.managed_groups();
    let mut plan = plan::diff(&targets, inputs.state);

    // 5b. Group plan: required set (role groups ∪ [[group]]) vs the managed
    // group registry + live system. A GID-pin conflict or managed-group GID
    // drift aborts HERE — before lockout, snapshot, or any mutation (Census
    // never renumbers; design §Безопасность).
    let mut required_groups = crate::declaration::required_groups(inputs.declaration, &targets)?;
    plan.group_actions = plan::diff_groups_via_inspector(
        &required_groups,
        &managed_groups_now,
        inputs.inspector,
    )?;

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
    let deferred_deletes = reconcile_live_sessions(&mut plan, &managed_now, &live);
    for d in &deferred_deletes {
        log.push(format!(
            "deferred delete of {} (uid {}): live session present (registry {})",
            d.name,
            d.uid,
            inputs.sessions_file.display()
        ));
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
    crate::lockout::gate(&plan, inputs.lockout)?;

    // Idempotence: empty plan (no account AND no group actions) → zero mutations,
    // no snapshot, no registry churn (registry still reflects the in-sync set).
    // NOTE: this branch is now also reachable when the ONLY planned change was a
    // delete that we just deferred. In that case the registry already holds the
    // deferred account (retained below with its prior from_version), so there are
    // no OS mutations — but the registry MUST still record the retention, hence
    // `registry_written` is forced true whenever a deferral happened (idempotent
    // in content: from_version is preserved, but we must not drop ownership).
    if plan.is_empty() {
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
                &managed_groups_now,
                &[],
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

    // 7b. Snapshot before any mutation.
    provisioner
        .snapshot()
        .map_err(|e| ApplyError::Phase {
            phase: "snapshot",
            source: e,
            rollback: RollbackOutcome::Restored, // nothing mutated yet
        })?;

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
                    created_groups.push((name.clone(), *gid));
                    let pin = gid.map(|g| g.to_string()).unwrap_or_else(|| "auto".to_owned());
                    log.push(format!("create-group: {name} (gid {pin})"));
                }
                Err(source) => {
                    return Err(phase_failure(provisioner, "create-group", source));
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
                log.push(format!("{phase}: {}", action_label(action)));
            }
            Err(source) => {
                return Err(phase_failure(provisioner, phase, source));
            }
        }
    }

    // Phase 4: delete orphan managed groups (after account deletes). The
    // deleted groups are dropped from the registry by `build_managed_groups`
    // (they are no longer in the required set), so nothing to record here.
    for ga in &plan.group_actions {
        if let GroupAction::Delete { name } = ga {
            match provisioner.delete_group(name) {
                Ok(()) => {
                    mutations += 1;
                    log.push(format!("delete-group: {name}"));
                }
                Err(source) => {
                    return Err(phase_failure(provisioner, "delete-group", source));
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
            &managed_groups_now,
            &created_groups,
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
) -> Vec<DeferredDelete> {
    let mut deferred = Vec::new();
    plan.actions.retain(|action| {
        let Action::Delete { name } = action else {
            return true; // creates/updates are never deferred
        };
        // Every account `Delete` is produced by diffing the managed registry, so
        // its record (and thus its uid) is always present in `managed_now`. A
        // record with no managed entry could not be retained anyway
        // (`build_managed_set` carries deferrals forward via `current.get(name)`),
        // so a missing entry simply falls through as a normal delete.
        let Some(record) = managed_now.get(name) else {
            debug_assert!(false, "account Delete {name:?} has no managed record");
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

/// Run the provisioner's restore after a phase failure and package the
/// resulting [`ApplyError::Phase`] (shared by every phase arm).
fn phase_failure(
    provisioner: &mut dyn Provisioner,
    phase: &'static str,
    source: ProvisionError,
) -> ApplyError {
    let rollback = match provisioner.restore() {
        Ok(()) => RollbackOutcome::Restored,
        Err(e) => RollbackOutcome::Failed(e.to_string()),
    };
    ApplyError::Phase { phase, source, rollback }
}

/// Compute the set of `census-<role>` sudoers fragment paths the plan will
/// touch, so they can be added to the backup set before the snapshot (spec R2).
///
/// A fragment is touched when:
/// * a created/updated role carries a sudo right (its fragment is written), OR
/// * a created/updated role does NOT carry sudo (its fragment, if any, is
///   removed — drop-to-none must also roll back), OR
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
                Some(existing) if existing.uid == t.uid
                    && existing.shell == t.shell
                    && groups_equal(&existing.groups, &t.groups)
                    && existing.sudo_role == t.sudo_role =>
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
                from_version,
            }
        })
        .collect();

    // Retain deferred-delete accounts with their original record (prior
    // from_version preserved). They are absent from `targets`, so there is no
    // overlap to deduplicate.
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
    prior: &BTreeMap<String, ManagedGroup>,
    created: &[(String, Option<u32>)],
    version: u32,
    inspector: &dyn SystemInspector,
) -> Vec<ManagedGroup> {
    let mut out = Vec::new();

    // Carry forward prior-registry groups that are still required (owned, kept).
    for (name, mg) in prior {
        if required.contains_key(name) {
            out.push(mg.clone());
        }
        // else: orphan — was deleted this run, drop from the registry.
    }

    // Add newly-created groups (not already carried forward).
    for (name, pin) in created {
        if prior.contains_key(name) {
            continue; // already carried forward above
        }
        // Prefer the pin; otherwise read the OS-assigned GID back from the live
        // system. If the read-back fails (should not happen right after a
        // successful groupadd), fall back to 0 rather than panicking — doctor
        // will flag a divergence on the next run.
        let gid = pin
            .or_else(|| inspector.group(name).map(|f| f.gid))
            .unwrap_or(0);
        out.push(ManagedGroup {
            name: name.clone(),
            gid,
            from_version: version,
        });
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn groups_equal(a: &[String], b: &[String]) -> bool {
    let mut a = a.to_vec();
    let mut b = b.to_vec();
    a.sort();
    b.sort();
    a == b
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
    use super::*;
    use crate::inspect::{FakeInspector, GroupFacts};
    use crate::lockout::LockoutContext;
    use crate::model::ResolvedAccount;
    use crate::state::{FakeState, ManagedGroup};

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
    }

    impl FakeProvisioner {
        fn failing(phase: &'static str) -> Self {
            FakeProvisioner { fail_on: Some(phase), ..Default::default() }
        }
        fn maybe_fail(&mut self, phase: &'static str, name: &str) -> Result<(), ProvisionError> {
            self.calls.push(format!("{phase}:{name}"));
            if self.fail_on == Some(phase) {
                Err(ProvisionError::Sudoers(format!("injected failure at {phase}")))
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
        fn delete_group(&mut self, name: &str) -> Result<(), ProvisionError> {
            self.maybe_fail("delete_group", name)
        }
        fn apply_sudoers(&mut self, acct: &ResolvedAccount) -> Result<(), ProvisionError> {
            self.maybe_fail("apply_sudoers", &acct.name)
        }
        fn remove_sudoers(&mut self, name: &str) -> Result<(), ProvisionError> {
            self.maybe_fail("remove_sudoers", name)
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
            "version = 5\nrole_store = \"{store}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"{role}\"\nuid = {uid}\n"
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
                lockout: LockoutContext { rescue_present: true, ..Default::default() },
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
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
                trust: TrustOptions { trust_fs: true, ..Default::default() },
                lockout: LockoutContext::default(),
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
            },
            &mut p,
        )
        .unwrap();
        assert!(p.snapshotted);
        assert!(!p.restored, "no restore on success");
        assert_eq!(report.mutations, 1);
        assert!(report.registry_written, "mutating plan must persist the registry");
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
                trust: TrustOptions { trust_fs: true, ..Default::default() },
                lockout: LockoutContext::default(),
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
            },
            &mut p,
        )
        .unwrap_err();
        match err {
            ApplyError::Phase { phase, rollback, .. } => {
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
                trust: TrustOptions { trust_fs: true, ..Default::default() },
                lockout: LockoutContext::default(),
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
            },
            &mut p,
        )
        .unwrap();
        assert_eq!(report.mutations, 0);
        assert!(!report.registry_written, "empty plan must not request a registry write");
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
            "version = 5\nrole_store = \"{store}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n"
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
                trust: TrustOptions { trust_fs: true, ..Default::default() },
                lockout: LockoutContext::default(), // no rescue, no risk-ack
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
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
            "version = 5\nrole_store = \"{store}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"{role}\"\nuid = {uid}\n"
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
                trust: TrustOptions { trust_fs: true, ..Default::default() },
                lockout: LockoutContext::default(),
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
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
        let snap_idx = p.calls.iter().position(|c| c == "snapshot").expect("snapshot recorded");
        assert!(track_idx < snap_idx, "backup must be registered before snapshot");
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
            "version = 5\nrole_store = \"{store}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n"
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
                trust: TrustOptions { trust_fs: true, ..Default::default() },
                // Rescue present so the delete-only plan passes the lockout gate.
                lockout: LockoutContext { rescue_present: true, ..Default::default() },
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
            },
            &mut p,
        )
        .unwrap();
        assert_eq!(report.mutations, 1);
        assert!(p.calls.contains(&"remove_sudoers:oper".to_owned()));
        assert!(p.calls.contains(&"delete:oper".to_owned()));
        // sudoers removal precedes userdel.
        let rm_idx = p.calls.iter().position(|c| c == "remove_sudoers:oper").unwrap();
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
                trust: TrustOptions { trust_fs: true, ..Default::default() },
                lockout: LockoutContext::default(),
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
            },
            &mut p,
        )
        .unwrap_err();
        match err {
            ApplyError::Phase { phase, rollback, source } => {
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
            gid: 8010,
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
        assert_eq!(grps["atm-operators"].gid, 8010);
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
        let head = format!("version = {version}\nrole_store = \"{store}\"\n");
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
        TrustOptions { trust_fs: false, trust_anchor_path: anchor, persist_dir: persist }
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
                trust: managed_opts(PathBuf::from("/nonexistent.pub"), persist.path().to_path_buf()),
                lockout: LockoutContext { rescue_present: true, ..Default::default() },
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
            },
            &mut p,
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::Trust(trust::TrustError::MissingSignature)));
        assert!(!p.snapshotted, "managed-no-signature must refuse before snapshot");
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
                lockout: LockoutContext { rescue_present: true, ..Default::default() },
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
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
                lockout: LockoutContext { rescue_present: true, ..Default::default() },
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
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
                lockout: LockoutContext { rescue_present: true, ..Default::default() },
                sudoers_dir: PathBuf::from("/etc/sudoers.d"),
                session_source: &crate::sessions::FakeSessionSource::empty(),
                sessions_file: PathBuf::from("/run/tessera/sessions.json"),
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
            "version = 5\nrole_store = \"{store}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n[[role_account]]\nrole = \"{role}\"\nuid = {uid}\n"
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
    ) -> ApplyInputs<'a> {
        ApplyInputs {
            declaration: d,
            declaration_bytes: b"",
            state: st,
            inspector: insp,
            trust: TrustOptions { trust_fs: true, ..Default::default() },
            lockout: LockoutContext { rescue_present: true, ..Default::default() },
            sudoers_dir: PathBuf::from("/etc/sudoers.d"),
            session_source: sessions,
            sessions_file: PathBuf::from("/run/tessera/sessions.json"),
        }
    }

    fn managed_group(name: &str, gid: u32, v: u32) -> ManagedGroup {
        ManagedGroup { name: name.to_owned(), gid, from_version: v }
    }

    fn fake_state_with_groups(
        accts: Vec<ManagedAccount>,
        groups: Vec<ManagedGroup>,
    ) -> FakeState {
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
        let report = run(trust_fs_inputs(&d, &st, &insp, &crate::sessions::FakeSessionSource::empty()), &mut p).unwrap();
        let cg = p.calls.iter().position(|c| c == "create_group:atm-operators").expect("group create");
        let ca = p.calls.iter().position(|c| c == "create:oper").expect("account create");
        assert!(cg < ca, "group create must precede account create: {:?}", p.calls);
        // Registry records the created group with its pinned GID.
        assert_eq!(report.managed_group_records.len(), 1);
        assert_eq!(report.managed_group_records[0].name, "atm-operators");
        assert_eq!(report.managed_group_records[0].gid, 8010);
        assert_eq!(report.managed_group_records[0].from_version, 5);
    }

    #[test]
    fn group_delete_follows_account_delete() {
        // Declaration with no accounts/groups; registry owns an account AND a
        // group → both vanish. Account delete must precede group delete.
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().display().to_string();
        let text = format!(
            "version = 5\nrole_store = \"{store}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n"
        );
        let d = Declaration::parse(&text).unwrap();
        let st = fake_state_with_groups(
            vec![managed("oper", 9010, &[], 5)],
            vec![managed_group("atm-operators", 8010, 5)],
        );
        // Group still live (so drift check passes) at its recorded gid.
        let mut insp = FakeInspector::default();
        insp.groups.insert("atm-operators".into(), GroupFacts { gid: 8010 });
        let mut p = FakeProvisioner::default();
        let report = run(trust_fs_inputs(&d, &st, &insp, &crate::sessions::FakeSessionSource::empty()), &mut p).unwrap();
        let da = p.calls.iter().position(|c| c == "delete:oper").expect("account delete");
        let dg = p.calls.iter().position(|c| c == "delete_group:atm-operators").expect("group delete");
        assert!(da < dg, "account delete must precede group delete: {:?}", p.calls);
        // The orphan group is dropped from the registry.
        assert!(report.managed_group_records.is_empty(), "orphan group must leave the registry");
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
        let err = run(trust_fs_inputs(&d, &st, &insp, &crate::sessions::FakeSessionSource::empty()), &mut p).unwrap_err();
        assert!(matches!(err, ApplyError::GroupPlan(_)), "expected GroupPlan error, got {err:?}");
        assert!(!p.snapshotted, "pin conflict must abort before snapshot");
        assert!(p.calls.is_empty(), "pin conflict must abort before any mutation");
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
        let report = run(trust_fs_inputs(&d, &st, &insp, &crate::sessions::FakeSessionSource::empty()), &mut p).unwrap();
        assert!(
            !p.calls.iter().any(|c| c.starts_with("create_group")),
            "foreign group must not be created: {:?}", p.calls
        );
        assert!(
            !p.calls.iter().any(|c| c.starts_with("delete_group")),
            "foreign group must not be deleted: {:?}", p.calls
        );
        assert!(report.managed_group_records.is_empty(), "foreign group must not enter the registry");
    }

    #[test]
    fn group_create_failure_triggers_restore() {
        let (_t, d) = decl_with_group("oper", 9010, "atm-operators", Some(8010));
        let st = FakeState::default();
        let insp = FakeInspector::default();
        let mut p = FakeProvisioner::failing("create_group");
        let err = run(trust_fs_inputs(&d, &st, &insp, &crate::sessions::FakeSessionSource::empty()), &mut p).unwrap_err();
        match err {
            ApplyError::Phase { phase, rollback, .. } => {
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
            "version = 5\nrole_store = \"{store}\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n"
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
    ) -> ApplyInputs<'a> {
        ApplyInputs {
            declaration: d,
            declaration_bytes: b"",
            state: st,
            inspector: insp,
            trust: TrustOptions { trust_fs: true, ..Default::default() },
            lockout: LockoutContext { rescue_present: true, ..Default::default() },
            sudoers_dir: PathBuf::from("/etc/sudoers.d"),
            session_source: sessions,
            sessions_file: PathBuf::from("/run/tessera/sessions.json"),
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

        assert!(!p.calls.iter().any(|c| c == "delete:oper"), "userdel must be deferred: {:?}", p.calls);
        assert_eq!(report.mutations, 0, "a deferred delete is not a mutation");
        // Account retained in the managed set with its PRIOR from_version.
        let oper = report.managed.iter().find(|m| m.name == "oper").expect("oper retained in managed");
        assert_eq!(oper.from_version, 4, "deferred account keeps its prior from_version");
        // Reported as a deferred delete (name + uid).
        assert_eq!(report.deferred_deletes.len(), 1);
        assert_eq!(report.deferred_deletes[0].name, "oper");
        assert_eq!(report.deferred_deletes[0].uid, 9010);
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

        assert!(!p.calls.iter().any(|c| c == "delete:oper"), "uid match must defer userdel");
        assert_eq!(report.deferred_deletes.len(), 1);
        assert_eq!(report.deferred_deletes[0].uid, 9010);
        assert!(report.managed.iter().any(|m| m.name == "oper"), "uid-deferred account retained");
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

        assert!(p.calls.iter().any(|c| c == "delete:oper"), "no session → userdel runs");
        assert_eq!(report.mutations, 1);
        assert!(report.deferred_deletes.is_empty());
        assert!(!report.managed.iter().any(|m| m.name == "oper"), "deleted account leaves the registry");
    }

    #[test]
    fn empty_live_set_executes_all_deletes() {
        // Two managed accounts, both dropped, empty live set → both delete.
        let (_t, d) = empty_decl();
        let st = fake_state(vec![managed("oper", 9010, &[], 4), managed("serv", 9011, &[], 4)]);
        let insp = FakeInspector::default();
        let sessions = FakeSessionSource::empty();
        let mut p = FakeProvisioner::default();
        let report = run(reconcile_inputs(&d, &st, &insp, &sessions), &mut p).unwrap();

        assert!(p.calls.iter().any(|c| c == "delete:oper"));
        assert!(p.calls.iter().any(|c| c == "delete:serv"));
        assert_eq!(report.mutations, 2);
        assert!(report.deferred_deletes.is_empty());
        assert!(report.managed.is_empty(), "both accounts removed from the registry");
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

        assert!(!p.snapshotted, "no snapshot when the only change was deferred");
        assert!(p.calls.is_empty(), "no phase calls when the only change was deferred");
        assert_eq!(report.mutations, 0);
        assert!(report.registry_written, "retention of the deferred account must be persisted");
        let oper = report.managed.iter().find(|m| m.name == "oper").expect("oper retained");
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

        assert!(p.calls.iter().any(|c| c == "create:oper"), "create runs despite registry read error");
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

        assert!(matches!(err, ApplyError::SessionRegistry(_)), "expected fail-closed, got {err:?}");
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
            trust: TrustOptions { trust_fs: true, ..Default::default() },
            lockout: LockoutContext::default(), // no rescue, no risk-ack
            sudoers_dir: PathBuf::from("/etc/sudoers.d"),
            session_source: &sessions,
            sessions_file: PathBuf::from("/run/tessera/sessions.json"),
        };
        let report = run(inputs, &mut p).unwrap();
        assert_eq!(report.deferred_deletes.len(), 1, "delete deferred before the gate");
        assert!(report.managed.iter().any(|m| m.name == "oper"), "account kept");
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
        insp.groups.insert("atm-operators".into(), GroupFacts { gid: 8010 });
        let sessions = live_by_name("oper");
        let mut p = FakeProvisioner::default();
        let report = run(reconcile_inputs(&d, &st, &insp, &sessions), &mut p).unwrap();

        assert!(
            !p.calls.iter().any(|c| c == "delete_group:atm-operators"),
            "deferred account's group must not be deleted: {:?}",
            p.calls
        );
        assert!(!p.calls.iter().any(|c| c == "delete:oper"), "userdel deferred");
        // Group retained in the registry with its PRIOR gid + from_version.
        let g = report
            .managed_group_records
            .iter()
            .find(|g| g.name == "atm-operators")
            .expect("group retained in registry");
        assert_eq!(g.gid, 8010, "retained group keeps prior GID");
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
            report.managed_group_records.iter().any(|g| g.name == "oper"),
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
        assert!(!p.calls.iter().any(|c| c == "delete:oper"), "oper userdel deferred");
        assert!(!p.calls.iter().any(|c| c == "delete_group:ga"), "ga retained");
        assert!(p.calls.iter().any(|c| c == "delete:serv"), "serv deleted");
        assert!(p.calls.iter().any(|c| c == "delete_group:gb"), "gb deleted");
        assert!(report.managed_group_records.iter().any(|g| g.name == "ga"), "ga retained in registry");
        assert!(!report.managed_group_records.iter().any(|g| g.name == "gb"), "gb dropped from registry");
    }
}
