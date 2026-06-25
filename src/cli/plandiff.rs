//! `plan --diff`: render the concrete on-disk artifacts a plan would write as a
//! unified-style diff, computed from the CURRENT managed state to the TARGET
//! resolution.
//!
//! The terse `plan` output names account-level actions (`CREATE/UPDATE/DELETE
//! svc (uid …)`) but hides WHAT and HOW Census would actually write: the sudoers
//! fragment content (including the run-as — `(bfs_solutions)` vs `(ALL)`), the
//! target file path (`/etc/sudoers.d/census-<role>`), and the file-access ACL
//! grants. An operator about to run a privileged `apply` as root must be able to
//! preview those artifacts — a wrong run-spec hands out a root shell where only
//! "be this service account for one command" was intended, and a stale ACL grant
//! leaks access. This module renders that preview.
//!
//! It is a PURE artifact diff: it renders the fragment Census would write from
//! the current managed record and from the resolved target through the SAME
//! renderers apply uses ([`crate::sudoers::build_account_sudoers_from_parts`] /
//! [`crate::sudoers::build_group_sudoers_from_parts`]), then line-diffs the two.
//! It reads NO filesystem and needs NO root — disk-vs-managed drift (what is
//! actually on disk now) is `doctor`'s job, not the plan preview's.

use std::collections::BTreeMap;

use crate::catalog::Access;
use crate::cli::render::backend_for_shape;
use crate::model::ResolvedGroup;
use crate::plan::{Action, GroupAction, Plan};
use crate::state::{ManagedAccount, ManagedFileGrant, ManagedGroup};
use crate::sudoers::{
    build_account_sudoers_from_parts, build_group_sudoers_from_parts, sudoers_filename,
    sudoers_group_filename, SUDOERS_DIR,
};

/// Render the artifact diff for a whole plan: for each account/group mutation,
/// the sudoers fragment diff (current managed → target) under its target file
/// path, plus the file-access grant delta. Pure: every input is borrowed data,
/// no filesystem is touched.
///
/// `managed_accounts`/`managed_groups` are the current managed registry records
/// (the "before"); `resolved_groups` are the resolved declaration groups (the
/// "after" for group fragments — the membership-driven [`Plan::group_actions`]
/// alone does not carry a group's grants). An empty plan renders the in-sync
/// line, matching the terse renderer.
pub fn render_plan_diff(
    plan: &Plan,
    managed_accounts: &BTreeMap<String, ManagedAccount>,
    managed_groups: &BTreeMap<String, ManagedGroup>,
    resolved_groups: &[ResolvedGroup],
) -> String {
    if plan.is_empty() {
        return "in sync — no changes\n".to_owned();
    }
    let mut out = String::new();

    // Group creates first (applied before accounts), then account actions, then
    // group deletes/releases — mirroring the terse renderer's ordering so the two
    // views sequence the same way.
    for ga in &plan.group_actions {
        if matches!(ga, GroupAction::Create { .. } | GroupAction::Adopt { .. }) {
            render_group_action(&mut out, ga, managed_groups, resolved_groups);
        }
    }
    for action in &plan.actions {
        render_account_action(&mut out, action, managed_accounts);
    }
    for ga in &plan.group_actions {
        if matches!(
            ga,
            GroupAction::Delete { .. } | GroupAction::Release { .. } | GroupAction::Update { .. }
        ) {
            render_group_action(&mut out, ga, managed_groups, resolved_groups);
        }
    }
    out
}

/// Render one account action: a header naming the object and its target sudoers
/// path, the fragment diff (current → target), and the file-grant delta.
fn render_account_action(
    out: &mut String,
    action: &Action,
    managed_accounts: &BTreeMap<String, ManagedAccount>,
) {
    let path = format!("{SUDOERS_DIR}/{}", sudoers_filename(account_name(action)));
    match action {
        Action::Create(target) => {
            out.push_str(&format!("+ CREATE {}  ->  {}\n", target.name, path));
            // Keep the existing concise field summary alongside the artifact view.
            out.push_str(&format!("    uid {}, shell {}\n", target.uid, target.shell));
            let current = build_account_sudoers_from_parts(&target.name, &[], None);
            let next = build_account_sudoers_from_parts(
                &target.name,
                &target.sudo_commands,
                target.sudo_role.as_deref(),
            );
            push_fragment_diff(out, current.as_deref(), next.as_deref());
            push_file_grant_delta(out, &[], &target.file_grants);
        }
        Action::Update { account, changes } => {
            out.push_str(&format!("~ UPDATE {}  ->  {}\n", account.name, path));
            out.push_str(&format!("    {}\n", changes.join(", ")));
            let managed = managed_accounts.get(&account.name);
            let current = managed.and_then(|m| {
                build_account_sudoers_from_parts(&m.name, &m.sudo_commands, m.sudo_role.as_deref())
            });
            let next = build_account_sudoers_from_parts(
                &account.name,
                &account.sudo_commands,
                account.sudo_role.as_deref(),
            );
            push_fragment_diff(out, current.as_deref(), next.as_deref());
            let before = managed.map(|m| m.file_grants.as_slice()).unwrap_or(&[]);
            push_file_grant_delta(out, before, &account.file_grants);
        }
        Action::Delete { name } => {
            out.push_str(&format!("- DELETE {name} (destructive)  ->  {path}\n"));
            let managed = managed_accounts.get(name);
            let current = managed.and_then(|m| {
                build_account_sudoers_from_parts(&m.name, &m.sudo_commands, m.sudo_role.as_deref())
            });
            // Delete removes the fragment entirely → the target is None (all `-`).
            push_fragment_diff(out, current.as_deref(), None);
            let before = managed.map(|m| m.file_grants.as_slice()).unwrap_or(&[]);
            push_managed_file_grant_revocations(out, before);
        }
    }
}

/// The login/account name an account action targets.
fn account_name(action: &Action) -> &str {
    match action {
        Action::Create(a) => &a.name,
        Action::Update { account, .. } => &account.name,
        Action::Delete { name } => name,
    }
}

/// Render one group action's `%group` fragment diff and file-grant delta. The
/// "current" side is the managed group record; the "target" side is the resolved
/// group (looked up by name), since the action enum alone does not carry grants.
fn render_group_action(
    out: &mut String,
    ga: &GroupAction,
    managed_groups: &BTreeMap<String, ManagedGroup>,
    resolved_groups: &[ResolvedGroup],
) {
    let name = group_action_name(ga);
    let path = format!("{SUDOERS_DIR}/{}", sudoers_group_filename(name));
    let managed = managed_groups.get(name);
    let target = resolved_groups.iter().find(|g| g.name == name);

    let current = managed.and_then(|m| build_group_sudoers_from_parts(&m.name, &m.sudo_commands));
    let next = match ga {
        // Release/Delete strip Census's grants → the target fragment is gone.
        GroupAction::Release { .. } | GroupAction::Delete { .. } => None,
        _ => target.and_then(|t| build_group_sudoers_from_parts(&t.name, &t.sudo_commands)),
    };

    let (marker, verb) = match ga {
        GroupAction::Create { .. } => ("+", "CREATE GROUP"),
        GroupAction::Adopt { .. } => ("+", "ADOPT GROUP"),
        GroupAction::Update { .. } => ("~", "UPDATE GROUP"),
        GroupAction::Release { .. } => ("-", "RELEASE GROUP"),
        GroupAction::Delete { .. } => ("-", "DELETE GROUP (destructive)"),
    };
    // Only render a header when there is a fragment or a file-grant delta — a
    // group whose action touches no sudoers/ACL artifact (a pure membership
    // create) would otherwise print an empty section.
    let before_grants = managed.map(|m| m.file_grants.as_slice()).unwrap_or(&[]);
    let after_grants: &[crate::catalog::ResolvedFileGrant] = match ga {
        GroupAction::Release { .. } | GroupAction::Delete { .. } => &[],
        _ => target.map(|t| t.file_grants.as_slice()).unwrap_or(&[]),
    };
    if current.is_none() && next.is_none() && before_grants.is_empty() && after_grants.is_empty() {
        return;
    }
    out.push_str(&format!("{marker} {verb} {name}  ->  {path}\n"));
    push_fragment_diff(out, current.as_deref(), next.as_deref());
    match ga {
        GroupAction::Release { .. } | GroupAction::Delete { .. } => {
            push_managed_file_grant_revocations(out, before_grants);
        }
        _ => push_file_grant_delta(out, before_grants, after_grants),
    }
}

/// The group name a group action targets.
fn group_action_name(ga: &GroupAction) -> &str {
    match ga {
        GroupAction::Create { name, .. }
        | GroupAction::Adopt { name }
        | GroupAction::Release { name }
        | GroupAction::Update { name, .. }
        | GroupAction::Delete { name } => name,
    }
}

/// Emit the line diff of a rendered sudoers fragment (current → target). A `None`
/// side is the empty fragment: CREATE diffs `None`→`Some` (all `+`), DELETE diffs
/// `Some`→`None` (all `-`), an UPDATE diffs the two rendered bodies line by line.
/// When neither side renders a fragment (an account/group with no sudo right on
/// either side), nothing is emitted.
fn push_fragment_diff(out: &mut String, current: Option<&str>, target: Option<&str>) {
    if current.is_none() && target.is_none() {
        return;
    }
    let cur_lines: Vec<&str> = current.map(non_empty_lines).unwrap_or_default();
    let tgt_lines: Vec<&str> = target.map(non_empty_lines).unwrap_or_default();
    for line in diff_lines(&cur_lines, &tgt_lines) {
        out.push_str("    ");
        out.push_str(&line);
        out.push('\n');
    }
}

/// The non-empty lines of a rendered fragment (drops the trailing blank from the
/// terminating newline). Comment header lines are kept so the diff shows the full
/// fragment Census would write.
fn non_empty_lines(s: &str) -> Vec<&str> {
    s.lines().filter(|l| !l.is_empty()).collect()
}

/// A minimal, deterministic line diff: emit only the changed lines (removed `-`,
/// then added `+`), skipping lines common to both sides. Uses a longest-common-
/// subsequence so a line that did not change registers as common (not as a
/// remove+add pair) even when surrounded by changes — keeping an UPDATE's diff to
/// exactly the lines that differ (e.g. just the rule line when only the run-spec
/// changed, the comment header unchanged).
fn diff_lines(a: &[&str], b: &[&str]) -> Vec<String> {
    let lcs = LcsTable::build(a, b);
    // Walk the LCS table from the end, classifying each line as common (skip),
    // removed, or added; collect in reverse, then flip to source order. All slice
    // access goes through `.get()` (returning `Option`) so an out-of-range index
    // can never panic; the loop guards keep every access in range regardless.
    let mut rev: Vec<String> = Vec::new();
    let (mut i, mut j) = (a.len(), b.len());
    while i > 0 && j > 0 {
        let (Some(ai), Some(bj)) = (a.get(i - 1), b.get(j - 1)) else {
            break;
        };
        // Tie-break toward an addition (`>` not `>=`) so that, after the final
        // reverse, a removal renders BEFORE its paired addition — the conventional
        // unified-diff order (the old `-` line then the new `+` line) the operator
        // expects when a run-spec changes root → service account.
        if ai == bj {
            // Common line — not part of the diff output.
            i -= 1;
            j -= 1;
        } else if lcs.at(i - 1, j) > lcs.at(i, j - 1) {
            rev.push(format!("- {ai}"));
            i -= 1;
        } else {
            rev.push(format!("+ {bj}"));
            j -= 1;
        }
    }
    // Drain the additions remaining first, then the removals: reversed, this puts
    // the removals ahead of the additions in the final order (same `-` before `+`
    // convention as the paired branch above).
    while j > 0 {
        if let Some(bj) = b.get(j - 1) {
            rev.push(format!("+ {bj}"));
        }
        j -= 1;
    }
    while i > 0 {
        if let Some(ai) = a.get(i - 1) {
            rev.push(format!("- {ai}"));
        }
        i -= 1;
    }
    rev.reverse();
    rev
}

/// A longest-common-subsequence length table over two line slices, stored as a
/// flat row-major buffer so cell access is bounds-checked through `.get()` rather
/// than `[]` indexing. `at(i, j)` is the LCS length of `a[..i]` and `b[..j]`. The
/// fragments are a handful of lines, so the quadratic buffer is trivially small.
struct LcsTable {
    cells: Vec<usize>,
    stride: usize,
}

impl LcsTable {
    /// Build the table for two line slices. Every read/write of a neighbouring
    /// cell goes through `at`/the local accumulator, never a panicking index.
    fn build(a: &[&str], b: &[&str]) -> Self {
        let stride = b.len() + 1;
        let mut table = LcsTable {
            cells: vec![0usize; (a.len() + 1) * stride],
            stride,
        };
        for (i, ai) in a.iter().enumerate() {
            for (j, bj) in b.iter().enumerate() {
                let value = if ai == bj {
                    table.at(i, j) + 1
                } else {
                    table.at(i, j + 1).max(table.at(i + 1, j))
                };
                table.set(i + 1, j + 1, value);
            }
        }
        table
    }

    /// The cell at row `i`, column `j`; `0` for any out-of-range coordinate (the
    /// LCS recurrence treats the borders as zero, so this is also the correct
    /// value, not just a panic-free fallback).
    fn at(&self, i: usize, j: usize) -> usize {
        self.cells.get(i * self.stride + j).copied().unwrap_or(0)
    }

    /// Set the cell at row `i`, column `j`. A coordinate outside the buffer is a
    /// no-op (it cannot occur given the build loop's bounds).
    fn set(&mut self, i: usize, j: usize, value: usize) {
        if let Some(cell) = self.cells.get_mut(i * self.stride + j) {
            *cell = value;
        }
    }
}

/// Emit the file-access grant delta between a recorded managed set (before) and a
/// resolved target set (after): `+ setfacl …` for a grant gained or widened,
/// `- revoke …` for one dropped. Compared by path (the ACL target); a path
/// present on both sides whose access/recursive changed renders as a revoke of
/// the old shape and a grant of the new. Deterministic: revocations first (sorted
/// by path), then grants (sorted by path).
fn push_file_grant_delta(
    out: &mut String,
    before: &[ManagedFileGrant],
    after: &[crate::catalog::ResolvedFileGrant],
) {
    let mut befores: BTreeMap<&str, (Access, bool)> = BTreeMap::new();
    for g in before {
        befores.insert(&g.path, (g.access, g.recursive));
    }
    let mut afters: BTreeMap<&str, (Access, bool, crate::catalog::Shape)> = BTreeMap::new();
    for g in after {
        afters.insert(&g.path, (g.access, g.recursive, g.shape));
    }

    // Revocations: a path in `before` whose (access, recursive) is not exactly
    // matched in `after` (gone, or changed shape) is revoked.
    for (path, (access, recursive)) in &befores {
        let unchanged = afters
            .get(path)
            .is_some_and(|(a, r, _)| a == access && r == recursive);
        if !unchanged {
            out.push_str(&format!(
                "    - revoke u:{path} ({})\n",
                access_recursive(*access, *recursive)
            ));
        }
    }
    // Grants: a path in `after` whose (access, recursive) is not exactly matched
    // in `before` (new, or changed shape) is (re)granted.
    for (path, (access, recursive, shape)) in &afters {
        let unchanged = befores
            .get(path)
            .is_some_and(|(a, r)| a == access && r == recursive);
        if !unchanged {
            out.push_str(&format!(
                "    + setfacl {path} ({}, via {})\n",
                access_recursive(*access, *recursive),
                backend_for_shape(*shape),
            ));
        }
    }
}

/// Emit the file-grant revocations for a delete/release: every recorded managed
/// grant is removed (there is no target side). Sorted by path for determinism.
fn push_managed_file_grant_revocations(out: &mut String, before: &[ManagedFileGrant]) {
    let mut sorted: BTreeMap<&str, (Access, bool)> = BTreeMap::new();
    for g in before {
        sorted.insert(&g.path, (g.access, g.recursive));
    }
    for (path, (access, recursive)) in &sorted {
        out.push_str(&format!(
            "    - revoke u:{path} ({})\n",
            access_recursive(*access, *recursive)
        ));
    }
}

/// A short `<access>[, recursive]` descriptor for a grant delta line, where
/// `<access>` is the grant's canonical token (`ro`/`rw` or sorted perm letters).
fn access_recursive(access: Access, recursive: bool) -> String {
    if recursive {
        format!("{access}, recursive")
    } else {
        access.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{ResolvedFileGrant, Shape, SourcedFileGrant};
    use crate::model::{Provenance, ResolvedAccount, SudoCommand};

    fn target(name: &str, uid: u32) -> ResolvedAccount {
        ResolvedAccount::builder(
            name,
            uid,
            "/bin/bash",
            format!("/var/lib/census/home/{name}"),
        )
        .build()
    }

    fn managed(name: &str, uid: u32) -> ManagedAccount {
        ManagedAccount {
            name: name.to_owned(),
            uid,
            shell: "/bin/bash".to_owned(),
            groups: Vec::new(),
            sudo_role: None,
            sudo_commands: Vec::new(),
            file_grants: Vec::new(),
            provenance: Provenance::Created,
            from_version: 1,
        }
    }

    fn rgrant(path: &str, access: Access, recursive: bool) -> ResolvedFileGrant {
        ResolvedFileGrant {
            path: path.to_owned(),
            access,
            recursive,
            shape: if recursive { Shape::Dir } else { Shape::File },
            sources: vec![SourcedFileGrant {
                layer: "linux".to_owned(),
                via: None,
                binding: None,
            }],
        }
    }

    fn accounts(list: Vec<ManagedAccount>) -> BTreeMap<String, ManagedAccount> {
        list.into_iter().map(|a| (a.name.clone(), a)).collect()
    }

    #[test]
    fn empty_plan_renders_in_sync() {
        let out = render_plan_diff(&Plan::default(), &BTreeMap::new(), &BTreeMap::new(), &[]);
        assert_eq!(out, "in sync — no changes\n");
    }

    #[test]
    fn create_shows_full_fragment_as_added_lines_with_path() {
        // A CREATE of an account whose permission runs a command as a service
        // account: the whole fragment is new → every rule line is `+`, the run-as
        // is visible, and the target path is named.
        let mut t = target("svc", 9100);
        t.sudo_commands = vec![SudoCommand::as_user("/usr/bin/id", "bfs_solutions")];
        let plan = Plan {
            actions: vec![Action::Create(t)],
            group_actions: Vec::new(),
        };
        let out = render_plan_diff(&plan, &BTreeMap::new(), &BTreeMap::new(), &[]);
        assert!(
            out.contains("+ CREATE svc  ->  /etc/sudoers.d/census-svc"),
            "{out}"
        );
        assert!(
            out.contains("+ svc ALL=(bfs_solutions) NOPASSWD: /usr/bin/id"),
            "the new fragment's rule line must be added with the run-as: {out}"
        );
        // The comment header lines are part of the new fragment too (all `+`).
        assert!(out.contains("+ # Managed by Census"), "{out}");
        // No `-` lines on a pure create.
        assert!(
            !out.lines().any(|l| l.trim_start().starts_with("- ")),
            "a create has no removed lines: {out}"
        );
    }

    #[test]
    fn runas_update_shows_root_removed_service_added() {
        // The managed record runs `/usr/bin/id` as root; the target narrows it to
        // a service account. Only the rule line changes — the comment header is
        // common, so the diff is exactly one `-` (root) and one `+` (service).
        let mut m = managed("svc", 9100);
        m.sudo_commands = vec![SudoCommand::root("/usr/bin/id")];
        let mut t = target("svc", 9100);
        t.sudo_commands = vec![SudoCommand::as_user("/usr/bin/id", "bfs_solutions")];
        let plan = Plan {
            actions: vec![Action::Update {
                account: t,
                changes: vec!["sudo-commands changed".to_owned()],
            }],
            group_actions: Vec::new(),
        };
        let out = render_plan_diff(&plan, &accounts(vec![m]), &BTreeMap::new(), &[]);
        assert!(
            out.contains("~ UPDATE svc  ->  /etc/sudoers.d/census-svc"),
            "{out}"
        );
        assert!(
            out.contains("- svc ALL=(ALL) NOPASSWD: /usr/bin/id"),
            "the old root run-spec must be removed: {out}"
        );
        assert!(
            out.contains("+ svc ALL=(bfs_solutions) NOPASSWD: /usr/bin/id"),
            "the new service-account run-spec must be added: {out}"
        );
        // The comment header is unchanged → it is NOT in the diff (no `+ #`/`- #`).
        assert!(
            !out.contains("+ # Managed by Census") && !out.contains("- # Managed by Census"),
            "the unchanged header must not appear in the diff: {out}"
        );
        // Conventional order: the removed (old) line renders before the added (new)
        // one, so the operator reads root → service top to bottom.
        let minus = out.find("- svc ALL=(ALL)").expect("removed line present");
        let plus = out
            .find("+ svc ALL=(bfs_solutions)")
            .expect("added line present");
        assert!(minus < plus, "removed line must precede added line: {out}");
    }

    #[test]
    fn delete_shows_whole_fragment_removed() {
        let mut m = managed("svc", 9100);
        m.sudo_commands = vec![SudoCommand::root("/usr/bin/id")];
        let plan = Plan {
            actions: vec![Action::Delete {
                name: "svc".to_owned(),
            }],
            group_actions: Vec::new(),
        };
        let out = render_plan_diff(&plan, &accounts(vec![m]), &BTreeMap::new(), &[]);
        assert!(
            out.contains("- DELETE svc (destructive)  ->  /etc/sudoers.d/census-svc"),
            "{out}"
        );
        assert!(
            out.contains("- svc ALL=(ALL) NOPASSWD: /usr/bin/id"),
            "the removed fragment's rule line must be `-`: {out}"
        );
        assert!(
            !out.lines().any(|l| l.trim_start().starts_with("+ ")),
            "a delete has no added lines: {out}"
        );
    }

    #[test]
    fn file_grant_delta_shows_setfacl_and_revoke() {
        // The target gains a /etc/ssh rw recursive grant and drops a /old/path one.
        let mut m = managed("svc", 9100);
        m.file_grants = vec![ManagedFileGrant {
            path: "/old/path".to_owned(),
            access: Access::RO,
            recursive: false,
        }];
        let mut t = target("svc", 9100);
        t.file_grants = vec![rgrant("/etc/ssh", Access::RW, true)];
        let plan = Plan {
            actions: vec![Action::Update {
                account: t,
                changes: vec!["file-grants changed".to_owned()],
            }],
            group_actions: Vec::new(),
        };
        let out = render_plan_diff(&plan, &accounts(vec![m]), &BTreeMap::new(), &[]);
        assert!(
            out.contains("+ setfacl /etc/ssh (rw, recursive, via AclBackend (dir, rewrite-proof))"),
            "gained grant must show a setfacl line with the backend: {out}"
        );
        assert!(
            out.contains("- revoke u:/old/path (ro)"),
            "dropped grant must show a revoke line: {out}"
        );
    }

    #[test]
    fn file_grant_widen_shows_revoke_then_setfacl_on_same_path() {
        // ro -> rw on the same path: a revoke of the old shape and a grant of the
        // new, so the backend re-materializes rather than leaving a stale entry.
        let mut m = managed("svc", 9100);
        m.file_grants = vec![ManagedFileGrant {
            path: "/etc/ssh".to_owned(),
            access: Access::RO,
            recursive: true,
        }];
        let mut t = target("svc", 9100);
        t.file_grants = vec![rgrant("/etc/ssh", Access::RW, true)];
        let plan = Plan {
            actions: vec![Action::Update {
                account: t,
                changes: vec!["file-grants changed".to_owned()],
            }],
            group_actions: Vec::new(),
        };
        let out = render_plan_diff(&plan, &accounts(vec![m]), &BTreeMap::new(), &[]);
        assert!(out.contains("- revoke u:/etc/ssh (ro, recursive)"), "{out}");
        assert!(
            out.contains("+ setfacl /etc/ssh (rw, recursive, via AclBackend (dir, rewrite-proof))"),
            "{out}"
        );
    }

    #[test]
    fn account_with_no_sudo_emits_no_fragment_lines() {
        // A create that grants no sudo right has no fragment to diff — only the
        // header + field summary, no `+`/`-` rule lines.
        let t = target("plain", 9200);
        let plan = Plan {
            actions: vec![Action::Create(t)],
            group_actions: Vec::new(),
        };
        let out = render_plan_diff(&plan, &BTreeMap::new(), &BTreeMap::new(), &[]);
        assert!(out.contains("+ CREATE plain"), "{out}");
        assert!(
            !out.contains("ALL="),
            "no sudo right → no fragment rule line: {out}"
        );
    }

    #[test]
    fn group_create_shows_percent_group_fragment_and_path() {
        // A group whose bound roles grant a service-account command: the
        // census-grp-<group> path and the %group rule (with run-as) are shown.
        let target_group = ResolvedGroup::builder("ops", Provenance::Created)
            .sudo_commands(vec![SudoCommand::as_user("/opt/tool", "svc")])
            .build();
        let plan = Plan {
            actions: Vec::new(),
            group_actions: vec![GroupAction::Create {
                name: "ops".to_owned(),
                gid: Some(8020),
            }],
        };
        let out = render_plan_diff(
            &plan,
            &BTreeMap::new(),
            &BTreeMap::new(),
            std::slice::from_ref(&target_group),
        );
        assert!(
            out.contains("+ CREATE GROUP ops  ->  /etc/sudoers.d/census-grp-ops"),
            "{out}"
        );
        assert!(
            out.contains("+ %ops ALL=(svc) NOPASSWD: /opt/tool"),
            "the %group rule must show the run-as: {out}"
        );
    }
}
