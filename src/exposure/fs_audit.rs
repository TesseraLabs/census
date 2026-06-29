//! The `audit fs` engine: the global, principal-independent posture map.
//!
//! ## What it produces
//!
//! Where the expose engine answers "what can THIS principal reach", [`audit_fs`]
//! answers the principal-independent question "what dangerous permission classes lie
//! in the filesystem at all". It walks the [`PermissionIndex`] and reports four axes
//! straight from each inode's mode bits and [`ObjectClass`] — no principal, no
//! reachability — so every [`Finding`] carries `principal = None`:
//!
//! 1. **world-writable** in a sensitive tree (a classified, non-generic, non-setuid
//!    object with the other-write bit) — risk/severity from the Срез-3 tables.
//! 2. **setuid/setgid inventory** — every `SetuidBinary`, reported as an escalation
//!    surface; one that is ALSO world-writable is critical (High vs Medium).
//! 3. **world-readable secret** — a `Secret` with the other-read bit — a leak.
//! 4. **broad-group-writable** — the group-write bit where the owning group is a wide
//!    group (`users`/`staff`/…), attributed `via=group:<g>` and classed `in-model`
//!    when that group is Census-managed.
//!
//! ## Deduplication
//!
//! The same inode can match several axes. Findings are deduplicated by
//! `(path, via, risk)`, keeping the highest [`Severity`] on a collision. This
//! collapses the genuine double-count (a writable setuid is both "setuid inventory"
//! and would be "world-writable" — same path, same `other_bits` via, same escalation
//! risk) while preserving genuinely distinct exposures: a different source (world vs a
//! broad group → different `via`) or a different harm (tamper-write vs secret-leak →
//! different risk) stays a separate finding. The world-writable axis deliberately
//! excludes `SetuidBinary` (its own axis) and `Generic` (scratch noise like `/tmp`).
//!
//! ## Managed context
//!
//! The injected [`RemediationContext`] only affects the broad-group axis (a
//! broad-group-writable object whose group Census manages is `in-model`). Callers
//! that have no managed binding pass
//! [`NoManagedContext`](super::taxonomy::NoManagedContext), making everything ambient.

use std::collections::HashMap;

use crate::inspect::SystemInspector;

use super::access::AccessVia;
use super::acl::{AclPerms, AclTag};
use super::index::{InodeRecord, PermissionIndex};
use super::taxonomy::{
    derive_risk, derive_severity, remediation, Finding, RemediationClass, RemediationContext, Risk,
    Severity,
};
use super::ObjectClass;

/// The default wide groups whose group-write access is a posture concern.
///
/// Matched by NAME (the `exposure.toml` `broad_groups` list overrides this default);
/// the owning group's name is resolved from the host's real `/etc/group`, so a
/// renumbered group is still caught. Documented so the chosen set is reviewable.
pub const DEFAULT_BROAD_GROUPS: &[&str] = &["adm", "wheel", "sudo", "staff", "users"];

/// Build the global, principal-independent posture map from `index`.
///
/// Enumerates the four dangerous-permission axes (world-writable, setuid/setgid
/// inventory, world-readable secret, broad-group-writable) over every indexed inode,
/// deduplicates by `(path, via, risk)` keeping the highest severity, and returns the
/// findings sorted by path. Every finding has `principal = None`.
///
/// `ctx` influences only the broad-group axis (a managed group → `in-model`).
/// `broad_groups` is the set of wide group NAMES to flag; the owning group's name is
/// resolved from the real `/etc/group` via `inspector` (best-effort — a gid with no
/// group entry is skipped), so the match is by name and survives a renumbered group.
#[must_use]
pub fn audit_fs(
    index: &PermissionIndex,
    ctx: &dyn RemediationContext,
    broad_groups: &[String],
    inspector: &dyn SystemInspector,
) -> Vec<Finding> {
    let mut candidates: Vec<Finding> = Vec::new();
    for record in index.records() {
        let class = record.class;
        collect_world_writable(record, class, ctx, &mut candidates);
        collect_setuid(record, class, &mut candidates);
        collect_world_readable_secret(record, class, ctx, &mut candidates);
        collect_broad_group_writable(record, class, ctx, broad_groups, inspector, &mut candidates);
    }
    dedup_keep_severest(candidates)
}

/// World-writable in a sensitive tree: a classified, non-generic, non-setuid object
/// with the other-write bit. (Setuid is handled by its own axis; generic scratch is
/// excluded as noise.)
fn collect_world_writable(
    record: &InodeRecord,
    class: ObjectClass,
    ctx: &dyn RemediationContext,
    out: &mut Vec<Finding>,
) {
    if !is_sensitive_writable_class(class) {
        return;
    }
    let world = world_perms(record.mode);
    if !world.write {
        return;
    }
    push_table_finding(record, class, world, AccessVia::OtherBits, ctx, out);
}

/// setuid/setgid inventory: every `SetuidBinary` is an escalation surface; one that is
/// also world-writable is critical (High vs the baseline Medium).
fn collect_setuid(record: &InodeRecord, class: ObjectClass, out: &mut Vec<Finding>) {
    if class != ObjectClass::SetuidBinary {
        return;
    }
    let world = world_perms(record.mode);
    let writable = world.write;
    let severity = if writable {
        Severity::High
    } else {
        Severity::Medium
    };
    // The setuid bit is a property of the foreign object; Census never sets it, so the
    // fix is always a manual investigation/chmod — never in-model.
    let hint = if writable {
        format!(
            "writable setuid/setgid binary — remove world write manually \
             (`chmod o-w {path}`) and investigate why it is writable",
            path = record.path
        )
    } else {
        format!(
            "setuid/setgid binary — verify it is expected and package-owned: `{path}`",
            path = record.path
        )
    };
    out.push(Finding {
        principal: None,
        path: record.path.clone(),
        access: world,
        via: AccessVia::OtherBits,
        class,
        risk: Risk::Escalation,
        severity,
        remediation_class: RemediationClass::Ambient,
        hint,
    });
}

/// World-readable secret: a `Secret` object with the other-read bit — a leak.
fn collect_world_readable_secret(
    record: &InodeRecord,
    class: ObjectClass,
    ctx: &dyn RemediationContext,
    out: &mut Vec<Finding>,
) {
    if class != ObjectClass::Secret {
        return;
    }
    let world = world_perms(record.mode);
    if !world.read {
        return;
    }
    // Report ONLY the read bit so the risk derives to Leak (a world-writable secret is
    // additionally reported as an escalation by the world-writable axis).
    let read_only = AclPerms {
        read: true,
        write: false,
        execute: false,
    };
    push_table_finding(record, class, read_only, AccessVia::OtherBits, ctx, out);
}

/// Broad-group-writable: the group-write bit where the owning group (resolved from the
/// real `/etc/group` by gid) is named in `broad_groups`. Attributed `via=group:<name>`;
/// in-model when Census manages the group. Best-effort: a gid with no group entry is
/// skipped.
fn collect_broad_group_writable(
    record: &InodeRecord,
    class: ObjectClass,
    ctx: &dyn RemediationContext,
    broad_groups: &[String],
    inspector: &dyn SystemInspector,
    out: &mut Vec<Finding>,
) {
    // The owning group's EFFECTIVE perms: on an inode with an extended ACL the mode
    // group bits are the ACL mask, not the owning group's access, so use the
    // `ACL_GROUP_OBJ` entry masked by the ACL mask; without an extended ACL the mode
    // group bits are authoritative.
    let group = owning_group_perms(record);
    if !group.write {
        return;
    }
    // Resolve the owning gid to its real name; match by name against the broad-group
    // list. Resolving the name (not a conventional gid) means a host that renumbered a
    // wide group is still caught, and the `via` carries its true name.
    let Some(name) = inspector.group_name_by_gid(record.gid) else {
        return;
    };
    if !broad_groups.iter().any(|g| g == &name) {
        return;
    }
    push_table_finding(record, class, group, AccessVia::Group(name), ctx, out);
}

/// The effective permissions of the inode's OWNING group.
///
/// On an inode carrying an extended POSIX ACL, the mode's group triple is the ACL
/// *mask*, not the owning group's access — so the owning group's effective access is
/// its `ACL_GROUP_OBJ` entry intersected with the mask. Without an extended ACL the mode
/// group bits are the owning group's access directly.
fn owning_group_perms(record: &InodeRecord) -> AclPerms {
    let Some(acl) = &record.acl else {
        return group_perms(record.mode);
    };
    let group_obj = acl
        .entries
        .iter()
        .find(|e| matches!(e.tag, AclTag::GroupObj))
        .map_or_else(|| group_perms(record.mode), |e| e.perms);
    let mask = acl
        .entries
        .iter()
        .find(|e| matches!(e.tag, AclTag::Mask))
        .map_or(AclPerms::ALL, |e| e.perms);
    group_obj.masked(mask)
}

/// Build a finding whose risk/severity come from the Срез-3 tables and whose
/// remediation comes from [`remediation`], pushing it only if the access is a
/// reportable risk.
fn push_table_finding(
    record: &InodeRecord,
    class: ObjectClass,
    access: AclPerms,
    via: AccessVia,
    ctx: &dyn RemediationContext,
    out: &mut Vec<Finding>,
) {
    let Some(risk) = derive_risk(access, class) else {
        return;
    };
    let severity = derive_severity(class, risk);
    let (remediation_class, hint) = remediation(&via, &record.path, class, access, ctx);
    out.push(Finding {
        principal: None,
        path: record.path.clone(),
        access,
        via,
        class,
        risk,
        severity,
        remediation_class,
        hint,
    });
}

/// Deduplicate by `(path, via, risk)`, keeping the highest-severity finding on a
/// collision, then sort by path (and `via` label) for deterministic output.
fn dedup_keep_severest(candidates: Vec<Finding>) -> Vec<Finding> {
    let mut best: HashMap<(String, String, Risk), Finding> = HashMap::new();
    for finding in candidates {
        let key = (finding.path.clone(), finding.via.label(), finding.risk);
        match best.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut slot) => {
                if finding.severity.rank() > slot.get().severity.rank() {
                    slot.insert(finding);
                }
            }
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(finding);
            }
        }
    }
    let mut out: Vec<Finding> = best.into_values().collect();
    out.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.via.label().cmp(&b.via.label()))
            .then_with(|| a.risk.as_str().cmp(b.risk.as_str()))
    });
    out
}

/// Whether `class` is a sensitive tree the world-writable axis reports. Excludes
/// `SetuidBinary` (its own axis) and `Generic` (scratch noise).
const fn is_sensitive_writable_class(class: ObjectClass) -> bool {
    matches!(
        class,
        ObjectClass::Cron
            | ObjectClass::Sudoers
            | ObjectClass::SystemdUnit
            | ObjectClass::Config
            | ObjectClass::PathBinary
            | ObjectClass::Secret
    )
}

/// The `other` (world) permission triple of a mode.
const fn world_perms(mode: u32) -> AclPerms {
    AclPerms {
        read: mode & 0o4 != 0,
        write: mode & 0o2 != 0,
        execute: mode & 0o1 != 0,
    }
}

/// The `group` permission triple of a mode.
const fn group_perms(mode: u32) -> AclPerms {
    AclPerms {
        read: mode & 0o40 != 0,
        write: mode & 0o20 != 0,
        execute: mode & 0o10 != 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    use crate::exposure::index::{FakeWalker, InodeStat};
    use crate::exposure::{AclEntries, AclEntry, FakeAclSource, NoManagedContext};
    use crate::inspect::{FakeInspector, GroupFacts};

    /// A managed-context fake: the named groups are Census-managed.
    struct FakeCtx {
        managed: BTreeSet<String>,
    }
    impl RemediationContext for FakeCtx {
        fn is_managed_group(&self, group: &str) -> bool {
            self.managed.contains(group)
        }
        fn covering_grant(&self, _path: &str) -> Option<String> {
            None
        }
    }

    fn stat(path: &str, gid: u32, mode: u32) -> InodeStat {
        InodeStat {
            path: path.to_owned(),
            uid: 0,
            gid,
            mode,
            // Directory iff the file-type bits are S_IFDIR.
            is_dir: (mode & 0o170_000) == 0o040_000,
        }
    }

    fn index_of(stats: Vec<InodeStat>) -> PermissionIndex {
        let mut walker = FakeWalker::new();
        for s in stats {
            walker = walker.with(s);
        }
        let mut acl = FakeAclSource::new();
        // A root that contains every test path.
        PermissionIndex::build(&walker, &mut acl, &[std::path::PathBuf::from("/")]).expect("build")
    }

    /// Build an index where some paths carry an extended POSIX ACL.
    fn index_with_acls(stats: Vec<InodeStat>, acls: Vec<(&str, AclEntries)>) -> PermissionIndex {
        let mut walker = FakeWalker::new();
        for s in stats {
            walker = walker.with(s);
        }
        let mut acl = FakeAclSource::new();
        for (path, entries) in acls {
            acl = acl.with(path, entries);
        }
        PermissionIndex::build(&walker, &mut acl, &[std::path::PathBuf::from("/")]).expect("build")
    }

    fn perms(r: bool, w: bool, x: bool) -> AclPerms {
        AclPerms {
            read: r,
            write: w,
            execute: x,
        }
    }

    fn find<'a>(findings: &'a [Finding], path: &str) -> Option<&'a Finding> {
        findings.iter().find(|f| f.path == path)
    }

    fn broad_groups() -> Vec<String> {
        DEFAULT_BROAD_GROUPS
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    }

    /// A fake `/etc/group` mapping each default broad group to its conventional gid, so
    /// `group_name_by_gid` resolves the test gids back to names.
    fn inspector() -> FakeInspector {
        let mut insp = FakeInspector::default();
        for (name, gid) in [
            ("adm", 4),
            ("wheel", 10),
            ("sudo", 27),
            ("staff", 50),
            ("users", 100),
        ] {
            insp.groups.insert(name.to_owned(), GroupFacts { gid });
        }
        insp
    }

    /// Run the posture map with the default broad groups and the fake group database.
    fn run(index: &PermissionIndex, ctx: &dyn RemediationContext) -> Vec<Finding> {
        audit_fs(index, ctx, &broad_groups(), &inspector())
    }

    /// Run with a custom group database (for the renumbered-group test).
    fn run_with(
        index: &PermissionIndex,
        ctx: &dyn RemediationContext,
        groups: BTreeMap<String, GroupFacts>,
    ) -> Vec<Finding> {
        let insp = FakeInspector {
            groups,
            ..FakeInspector::default()
        };
        audit_fs(index, ctx, &broad_groups(), &insp)
    }

    #[test]
    fn world_writable_cron_is_high_escalation() {
        // /var/spool/cron at 0777 (dir) → Cron class, world-writable → escalation High.
        let index = index_of(vec![stat("/var/spool/cron", 0, 0o040_777)]);
        let findings = run(&index, &NoManagedContext);
        let f = find(&findings, "/var/spool/cron").expect("in posture map");
        assert_eq!(f.class, ObjectClass::Cron);
        assert_eq!(f.risk, Risk::Escalation);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.via, AccessVia::OtherBits);
        assert!(
            f.principal.is_none(),
            "posture map is principal-independent"
        );
        assert!(f.access.write);
    }

    #[test]
    fn writable_setuid_binary_is_critical_high() {
        // A setuid binary (0o104755) that is ALSO world-writable (0o104757) is High.
        let index = index_of(vec![stat("/usr/bin/vuln", 0, 0o104_757)]);
        let findings = run(&index, &NoManagedContext);
        let f = find(&findings, "/usr/bin/vuln").expect("in setuid inventory");
        assert_eq!(f.class, ObjectClass::SetuidBinary);
        assert_eq!(f.risk, Risk::Escalation);
        assert_eq!(f.severity, Severity::High, "writable setuid is critical");
        assert!(f.hint.contains("writable setuid"), "hint: {}", f.hint);
        // Dedup: the writable setuid must yield exactly ONE finding (not also a
        // separate world-writable one), since both axes key (path, other_bits,
        // escalation).
        let same = findings
            .iter()
            .filter(|x| x.path == "/usr/bin/vuln")
            .count();
        assert_eq!(same, 1, "writable setuid is one deduped finding");
    }

    #[test]
    fn plain_setuid_binary_is_medium_inventory() {
        // A non-writable setuid binary (0o104755) is inventory at Medium.
        let index = index_of(vec![stat("/usr/bin/passwd", 0, 0o104_755)]);
        let findings = run(&index, &NoManagedContext);
        let f = find(&findings, "/usr/bin/passwd").expect("in setuid inventory");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.risk, Risk::Escalation);
        assert!(f.hint.contains("verify"), "inventory hint: {}", f.hint);
    }

    #[test]
    fn world_readable_secret_is_high_leak() {
        // /etc/shadow at 0644 → Secret, other-read → Leak High.
        let index = index_of(vec![stat("/etc/shadow", 0, 0o100_644)]);
        let findings = run(&index, &NoManagedContext);
        let f = find(&findings, "/etc/shadow").expect("in posture map");
        assert_eq!(f.class, ObjectClass::Secret);
        assert_eq!(f.risk, Risk::Leak);
        assert_eq!(f.severity, Severity::High);
        assert!(f.access.read && !f.access.write);
    }

    #[test]
    fn broad_group_writable_is_ambient_then_in_model_when_managed() {
        // A generic file group-owned by staff (gid 50) with the group-write bit.
        let index = index_of(vec![stat("/srv/data", 50, 0o100_664)]);

        // Foreign (un-managed) staff → ambient, via=group:staff.
        let ambient = run(&index, &NoManagedContext);
        let fa = find(&ambient, "/srv/data").expect("broad-group finding");
        assert_eq!(fa.via, AccessVia::Group("staff".to_owned()));
        assert_eq!(fa.remediation_class, RemediationClass::Ambient);
        assert!(fa.hint.contains("chmod g-w"), "hint: {}", fa.hint);

        // The SAME object when staff is Census-managed → in-model.
        let managed_ctx = FakeCtx {
            managed: std::iter::once("staff".to_owned()).collect(),
        };
        let in_model = run(&index, &managed_ctx);
        let fm = find(&in_model, "/srv/data").expect("broad-group finding");
        assert_eq!(fm.remediation_class, RemediationClass::InModel);
        assert!(fm.hint.contains("narrow"), "hint: {}", fm.hint);
    }

    #[test]
    fn renumbered_broad_group_is_caught_by_name_not_gid() {
        // On a host where `staff` was renumbered to a NON-conventional gid (999), the
        // owning group is resolved from /etc/group by gid and matched by NAME, so it is
        // still caught (the old conventional-gid table would have missed gid 999).
        let index = index_of(vec![stat("/srv/data", 999, 0o100_664)]);
        let mut groups = BTreeMap::new();
        groups.insert("staff".to_owned(), GroupFacts { gid: 999 });
        let findings = run_with(&index, &NoManagedContext, groups);
        let f = find(&findings, "/srv/data").expect("renumbered staff still caught");
        assert_eq!(f.via, AccessVia::Group("staff".to_owned()));
    }

    #[test]
    fn extended_acl_mask_caps_owning_group_below_writable() {
        // staff-owned file whose mode group triple is `rw` — but on an inode with an
        // extended ACL that triple is the MASK, not the owning group's access. The
        // `ACL_GROUP_OBJ` entry is `r--` (masked by `rw-` → `r--`), so `staff` cannot
        // actually write. The broad-group axis must NOT report it (using the mode
        // group bit would falsely flag it).
        let acl = AclEntries {
            entries: vec![
                AclEntry {
                    tag: AclTag::UserObj,
                    perms: perms(true, true, false),
                },
                AclEntry {
                    tag: AclTag::User("bob".to_owned()),
                    perms: perms(true, true, false),
                },
                AclEntry {
                    tag: AclTag::GroupObj,
                    perms: perms(true, false, false), // owning group: r--
                },
                AclEntry {
                    tag: AclTag::Mask,
                    perms: perms(true, true, false), // mask: rw- (the mode group bits)
                },
                AclEntry {
                    tag: AclTag::Other,
                    perms: AclPerms::default(),
                },
            ],
        };
        let index = index_with_acls(
            vec![stat("/srv/data", 50, 0o100_660)],
            vec![("/srv/data", acl)],
        );
        let findings = run(&index, &NoManagedContext);
        assert!(
            find(&findings, "/srv/data").is_none(),
            "owning group masked to r-- is not broad-group-writable"
        );
    }

    #[test]
    fn extended_acl_owning_group_with_write_is_broad_writable() {
        // The dual: the same shape but `ACL_GROUP_OBJ` = `rw-` (masked rw → rw-), so
        // `staff` truly can write → the axis fires.
        let acl = AclEntries {
            entries: vec![
                AclEntry {
                    tag: AclTag::UserObj,
                    perms: perms(true, true, false),
                },
                AclEntry {
                    tag: AclTag::User("bob".to_owned()),
                    perms: perms(true, false, false),
                },
                AclEntry {
                    tag: AclTag::GroupObj,
                    perms: perms(true, true, false), // owning group: rw-
                },
                AclEntry {
                    tag: AclTag::Mask,
                    perms: perms(true, true, false),
                },
                AclEntry {
                    tag: AclTag::Other,
                    perms: AclPerms::default(),
                },
            ],
        };
        let index = index_with_acls(
            vec![stat("/srv/data", 50, 0o100_660)],
            vec![("/srv/data", acl)],
        );
        let findings = run(&index, &NoManagedContext);
        let f = find(&findings, "/srv/data").expect("owning group rw → broad-writable");
        assert_eq!(f.via, AccessVia::Group("staff".to_owned()));
        assert!(f.access.write);
    }

    #[test]
    fn non_broad_group_writable_is_not_a_finding() {
        // A group-writable file owned by a project group not in `broad_groups` is not
        // flagged (only wide groups are a posture concern), and a gid that does not
        // resolve to any group is skipped best-effort.
        let index = index_of(vec![
            stat("/srv/proj", 800, 0o100_664),    // project group, not broad
            stat("/srv/orphan", 4242, 0o100_664), // gid with no /etc/group entry
        ]);
        let mut groups = BTreeMap::new();
        groups.insert("project".to_owned(), GroupFacts { gid: 800 });
        let findings = run_with(&index, &NoManagedContext, groups);
        assert!(
            find(&findings, "/srv/proj").is_none(),
            "narrow group not flagged"
        );
        assert!(
            find(&findings, "/srv/orphan").is_none(),
            "unresolved gid skipped"
        );
    }

    #[test]
    fn ordinary_file_with_no_dangerous_bits_is_not_in_map() {
        // A normal generic file (0644, root group) trips no axis.
        let index = index_of(vec![stat("/var/lib/app/data.db", 0, 0o100_644)]);
        let findings = run(&index, &NoManagedContext);
        assert!(
            findings.is_empty(),
            "no dangerous bits → not in the posture map"
        );
    }

    #[test]
    fn world_writable_generic_is_excluded_as_noise() {
        // A world-writable GENERIC file (e.g. /tmp-like scratch) is deliberately not
        // in the posture map (the world-writable axis covers only sensitive classes).
        let index = index_of(vec![stat("/var/tmp/scratch", 0, 0o100_666)]);
        let findings = run(&index, &NoManagedContext);
        assert!(
            find(&findings, "/var/tmp/scratch").is_none(),
            "generic world-writable is excluded"
        );
    }

    #[test]
    fn distinct_axes_on_one_object_stay_separate() {
        // A config file that is BOTH world-writable (other-write) and
        // broad-group-writable (staff group-write) yields two distinct findings: one
        // via other_bits and one via group:staff — different sources, not a dup.
        let index = index_of(vec![stat("/etc/ssh/sshd_config", 50, 0o100_662)]);
        let findings = run(&index, &NoManagedContext);
        let vias: BTreeSet<String> = findings
            .iter()
            .filter(|f| f.path == "/etc/ssh/sshd_config")
            .map(|f| f.via.label())
            .collect();
        assert!(vias.contains("other_bits"), "world-writable axis fired");
        assert!(vias.contains("group:staff"), "broad-group axis fired");
        assert_eq!(vias.len(), 2, "two distinct sources, no extra dups");
    }
}
