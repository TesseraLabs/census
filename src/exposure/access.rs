//! Principal resolution and the POSIX (`acl(5)`) discretionary access check.
//!
//! ## What this computes
//!
//! Given an indexed inode ([`InodeRecord`]) and a resolved [`Principal`] (uid +
//! primary/supplementary groups), [`effective`] returns the principal's effective
//! `read`/`write`/`execute` on that inode under the standard POSIX access algorithm,
//! together with the [`AccessVia`] reason the access was decided — the precedence
//! class that determined the verdict (owner, a named-user ACL entry, a group-class
//! entry, or the `other` bits). The `via` reason is what the finding taxonomy
//! (a later slice) attributes the exposure to.
//!
//! ## The algorithm (precedence + mask)
//!
//! `uid 0` short-circuits to full access. Otherwise, for an inode with only a
//! trivial ACL the classic mode bits decide: owner bits if the uid owns it, else the
//! group bits if any of the principal's groups owns it, else the `other` bits. For an
//! inode carrying an extended ACL the `acl(5)` precedence applies:
//!
//! 1. uid == owner → the `ACL_USER_OBJ` (owner) entry, **not** masked.
//! 2. else uid matches a named-user entry → that entry, intersected with the mask.
//! 3. else if the owning group or any named-group entry matches one of the
//!    principal's groups → granted if **any** matching group-class entry (after the
//!    mask) grants the bit; if a group class matched but none grants it, access is
//!    **denied** — it does NOT fall through to `other`.
//! 4. else → the `ACL_OTHER` entry, **not** masked.
//!
//! ## Advisory limit
//!
//! Principal resolution reads the **local** `/etc/passwd` and `/etc/group` only (via
//! the injected [`SystemInspector`]). NSS / LDAP group sources are not consulted, so
//! a resolved principal's supplementary groups are a local-database view — an
//! account whose membership lives only in a directory service will appear in fewer
//! groups than it effectively has, and the verdict is correspondingly a lower bound
//! on that account's reach. The eventual access verdict is also DAC-only; MAC layers
//! (`SELinux`, `AppArmor`, PARSEC) may restrict actual access further.

use crate::inspect::SystemInspector;

use super::acl::{AclEntries, AclPerms, AclTag};
use super::index::InodeRecord;

/// One group a principal belongs to: its name (for ACL named-group matching and the
/// `via` reason) and its numeric gid (for owning-group matching against an inode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGroup {
    /// The group name.
    pub name: String,
    /// The numeric gid.
    pub gid: u32,
}

/// A resolved principal: the identity an exposure check is evaluated for.
///
/// Carries the uid, the login name (to match named-user ACL entries), every group the
/// principal belongs to under `getgrouplist` semantics (primary + supplementary, each
/// with its name and gid), and the home directory (used by the intended-baseline
/// subtraction in the expose engine).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The login name (matches `user:<name>:` ACL entries).
    pub name: String,
    /// The numeric uid.
    pub uid: u32,
    /// Every group the principal belongs to (primary first, then supplementary).
    pub groups: Vec<ResolvedGroup>,
    /// The home directory from the passwd entry, or `None` for an orphan uid with no
    /// account. Used as part of the intended baseline for a managed principal.
    pub home: Option<std::path::PathBuf>,
}

impl Principal {
    /// Construct a principal directly (for tests and callers that already have the
    /// resolved identity). Home is `None`; set it with [`Self::with_home`] if needed.
    #[must_use]
    pub fn new(name: impl Into<String>, uid: u32, groups: Vec<ResolvedGroup>) -> Self {
        Self {
            name: name.into(),
            uid,
            groups,
            home: None,
        }
    }

    /// Set the principal's home directory (builder style).
    #[must_use]
    pub fn with_home(mut self, home: impl Into<std::path::PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// The name of the principal's group owning `gid`, if the principal belongs to
    /// it. Used for owning-group (mode and `ACL_GROUP_OBJ`) matching.
    fn group_name_for_gid(&self, gid: u32) -> Option<&str> {
        self.groups
            .iter()
            .find(|g| g.gid == gid)
            .map(|g| g.name.as_str())
    }

    /// Whether the principal belongs to a group named `name` (named-group ACL
    /// matching).
    fn in_named_group(&self, name: &str) -> bool {
        self.groups.iter().any(|g| g.name == name)
    }
}

/// Why an access verdict was reached: the `acl(5)` precedence class that decided it.
/// Carried alongside the effective permissions for the finding taxonomy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessVia {
    /// The principal owns the inode (owner mode bits or `ACL_USER_OBJ`).
    Owner,
    /// A named-user ACL entry (`user:<name>:`) matched the principal.
    AclUser(String),
    /// A named-group ACL entry (`group:<name>:`) matched one of the principal's
    /// groups.
    AclGroup(String),
    /// The owning-group class matched one of the principal's groups (mode group bits
    /// or `ACL_GROUP_OBJ`).
    Group(String),
    /// None of the above matched; the `other` bits decided.
    OtherBits,
}

impl AccessVia {
    /// The stable lowercase token for this reason (`owner`, `acl_user:<u>`,
    /// `acl_group:<g>`, `group:<g>`, `other_bits`), for JSON output and findings.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Owner => "owner".to_owned(),
            Self::AclUser(u) => format!("acl_user:{u}"),
            Self::AclGroup(g) => format!("acl_group:{g}"),
            Self::Group(g) => format!("group:{g}"),
            Self::OtherBits => "other_bits".to_owned(),
        }
    }
}

// Serialize as the single `label()` token (e.g. `"acl_user:role-x"`) rather than an
// enum object, so a finding's JSON `via` field is the same compact string the text
// output and filters use.
impl serde::Serialize for AccessVia {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.label())
    }
}

/// A principal's effective access to an inode, plus the reason it was decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    /// The effective `read`/`write`/`execute` bits.
    pub access: AclPerms,
    /// The precedence class that decided the access.
    pub via: AccessVia,
}

/// The principal's effective access to `record` under the POSIX (`acl(5)`) algorithm.
///
/// `uid 0` short-circuits to full access. An inode with only a trivial ACL is decided
/// by its mode bits; an extended ACL applies the `acl(5)` precedence and mask. See
/// the module docs for the full rule.
///
/// ## Qualifier-matching contract (names, not ids)
///
/// Named-user (`user:<name>:`) and named-group (`group:<name>:`) ACL entries are
/// matched against the principal's NAME, not its numeric id. This is correct for the
/// only ACL backend that exists — [`GetfaclReader`](super::GetfaclReader) runs
/// `getfacl` WITHOUT `-n`, so every qualifier in the parsed [`AclEntries`] is a name.
/// A future backend that emits numeric qualifiers (`getfacl -n`, or a native libacl
/// reader) would store ids instead, and this matcher would silently miss every named
/// entry — so such a backend MUST switch this matching to id-based. The
/// `getfacl_reader_uses_name_qualifiers` test pins the name contract to the actual
/// `getfacl` invocation flags so the two cannot drift apart.
#[must_use]
pub fn effective(record: &InodeRecord, principal: &Principal) -> Effective {
    if principal.uid == 0 {
        return Effective {
            access: AclPerms::ALL,
            via: AccessVia::Owner,
        };
    }
    match &record.acl {
        Some(acl) if acl.is_extended() => effective_acl(record, acl, principal),
        _ => effective_mode(record, principal),
    }
}

/// The classic mode-bit access check for an inode without an extended ACL.
fn effective_mode(record: &InodeRecord, principal: &Principal) -> Effective {
    if principal.uid == record.uid {
        return Effective {
            access: mode_triple(record.mode, 6),
            via: AccessVia::Owner,
        };
    }
    if let Some(name) = principal.group_name_for_gid(record.gid) {
        return Effective {
            access: mode_triple(record.mode, 3),
            via: AccessVia::Group(name.to_owned()),
        };
    }
    Effective {
        access: mode_triple(record.mode, 0),
        via: AccessVia::OtherBits,
    }
}

/// The POSIX ACL access check (precedence + mask) for an inode with an extended ACL.
fn effective_acl(record: &InodeRecord, acl: &AclEntries, principal: &Principal) -> Effective {
    let mask = acl_mask(acl);

    // 1) Owner: ACL_USER_OBJ, never masked.
    if principal.uid == record.uid {
        let access = acl_user_obj(acl).unwrap_or_else(|| mode_triple(record.mode, 6));
        return Effective {
            access,
            via: AccessVia::Owner,
        };
    }

    // 2) A named-user entry matching the principal's name, ANDed with the mask.
    if let Some(perms) = acl_named_user(acl, &principal.name) {
        return Effective {
            access: perms.masked(mask),
            via: AccessVia::AclUser(principal.name.clone()),
        };
    }

    // 3) Group class: every owning-group / named-group entry that applies to the
    // principal. The effective ACCESS is the union of all applying entries (after
    // mask); if a group class applied but none grants, access is denied — NOT a
    // fall-through to `other`.
    //
    // `via` attribution rule (deterministic, so the finding taxonomy can rely on it):
    // the applying entries are considered in a fixed precedence — the owning-group
    // (`ACL_GROUP_OBJ`) first, then the named-group entries in ACL order — and `via`
    // is credited to the FIRST entry in that order that actually grants a bit. If no
    // entry grants (a matched-but-denied group class), `via` is the first applying
    // entry in the same order. Access bits are unaffected by this choice; only the
    // attribution label is.
    let mut applying: Vec<(AccessVia, AclPerms)> = Vec::new();
    if let Some(name) = principal.group_name_for_gid(record.gid) {
        if let Some(perms) = acl_group_obj(acl) {
            applying.push((AccessVia::Group(name.to_owned()), perms));
        }
    }
    for entry in &acl.entries {
        if let AclTag::Group(name) = &entry.tag {
            if principal.in_named_group(name) {
                applying.push((AccessVia::AclGroup(name.clone()), entry.perms));
            }
        }
    }
    if let Some((first_via, _)) = applying.first() {
        let mut access = AclPerms::default();
        // Default attribution is the first applying entry (owning-group has highest
        // precedence); it is overridden by the first entry that actually grants.
        let mut chosen_via = first_via.clone();
        let mut granting_chosen = false;
        for (via, perms) in &applying {
            let masked = perms.masked(mask);
            access = access.union(masked);
            if masked.any() && !granting_chosen {
                chosen_via = via.clone();
                granting_chosen = true;
            }
        }
        return Effective {
            access,
            via: chosen_via,
        };
    }

    // 4) Other: ACL_OTHER, never masked.
    let access = acl_other(acl).unwrap_or_else(|| mode_triple(record.mode, 0));
    Effective {
        access,
        via: AccessVia::OtherBits,
    }
}

/// Extract one `rwx` triple from a mode word at the given bit shift (6 = owner,
/// 3 = group, 0 = other).
const fn mode_triple(mode: u32, shift: u32) -> AclPerms {
    let bits = (mode >> shift) & 0o7;
    AclPerms {
        read: bits & 0o4 != 0,
        write: bits & 0o2 != 0,
        execute: bits & 0o1 != 0,
    }
}

/// The ACL mask, or a fully-permissive mask when the ACL carries no mask entry (a
/// minimal ACL has none, but such an inode is reported as trivial and never reaches
/// the ACL path).
fn acl_mask(acl: &AclEntries) -> AclPerms {
    find_perms(acl, |tag| matches!(tag, AclTag::Mask)).unwrap_or(AclPerms::ALL)
}

/// The owner (`ACL_USER_OBJ`) entry's permissions.
fn acl_user_obj(acl: &AclEntries) -> Option<AclPerms> {
    find_perms(acl, |tag| matches!(tag, AclTag::UserObj))
}

/// The owning-group (`ACL_GROUP_OBJ`) entry's permissions.
fn acl_group_obj(acl: &AclEntries) -> Option<AclPerms> {
    find_perms(acl, |tag| matches!(tag, AclTag::GroupObj))
}

/// The `ACL_OTHER` entry's permissions.
fn acl_other(acl: &AclEntries) -> Option<AclPerms> {
    find_perms(acl, |tag| matches!(tag, AclTag::Other))
}

/// The named-user entry for `name`, if present.
///
/// Matches by NAME — see the qualifier-matching contract on [`effective`]: the
/// `getfacl` backend emits name qualifiers (no `-n`), so this compares the parsed
/// entry's name to the principal's name.
fn acl_named_user(acl: &AclEntries, name: &str) -> Option<AclPerms> {
    acl.entries
        .iter()
        .find(|e| matches!(&e.tag, AclTag::User(u) if u == name))
        .map(|e| e.perms)
}

/// The permissions of the first entry whose tag matches `pred`.
fn find_perms(acl: &AclEntries, pred: impl Fn(&AclTag) -> bool) -> Option<AclPerms> {
    acl.entries.iter().find(|e| pred(&e.tag)).map(|e| e.perms)
}

/// Resolve a principal given as a login name or a numeric uid into its uid, primary
/// group, and supplementary groups, under `getgrouplist` semantics.
///
/// The `inspector` is the injected read seam ([`SystemInspector`]); production reads
/// the live `/etc/passwd` and `/etc/group`, tests supply a fake.
///
/// A name with no passwd entry returns `None` (it cannot be audited). A bare numeric
/// uid with no passwd entry — an **orphan uid** that owns files but has no account —
/// still resolves: it yields a principal with that uid, the uid string as its name,
/// and **no groups** (an orphan uid has no primary or supplementary membership). The
/// audit then evaluates it by raw reachability with owner/other access only, which is
/// exactly the spec's "non-managed uid → raw reachability" path.
///
/// # Advisory limit
///
/// Group membership is read from the **local** passwd/group databases only; NSS/LDAP
/// sources are not consulted, so the resolved supplementary set is a local view (see
/// the module docs).
#[must_use]
pub fn resolve_principal<I>(inspector: &I, name_or_uid: &str) -> Option<Principal>
where
    I: SystemInspector + ?Sized,
{
    // A bare numeric argument is parsed as a uid; it resolves to its passwd name when
    // one exists, else it is treated as an orphan uid (handled below).
    let numeric_uid = if name_or_uid.is_empty() {
        None
    } else if name_or_uid.bytes().all(|b| b.is_ascii_digit()) {
        name_or_uid.parse::<u32>().ok()
    } else {
        None
    };
    let name = numeric_uid.map_or_else(
        || name_or_uid.to_owned(),
        |uid| {
            inspector
                .account_name_by_uid(uid)
                .unwrap_or_else(|| name_or_uid.to_owned())
        },
    );

    let Some(account) = inspector.account(&name) else {
        // No passwd entry. A numeric orphan uid is still auditable by raw
        // reachability (owner/other bits only); a bare unknown name is not. An orphan
        // uid has no home, so the intended baseline is empty.
        return numeric_uid.map(|uid| Principal {
            name: uid.to_string(),
            uid,
            groups: Vec::new(),
            home: None,
        });
    };

    let mut groups: Vec<ResolvedGroup> = Vec::new();
    // Primary group first. Its name comes from the gid (a gid with no group entry
    // still yields a usable principal — the gid is matched numerically, the name is
    // only for the `via` label). A passwd entry with an unreadable primary gid simply
    // contributes no primary group rather than failing the whole resolve.
    if let Some(primary_gid) = inspector.primary_gid(&name) {
        let primary_name = inspector
            .group_name_by_gid(primary_gid)
            .unwrap_or_else(|| primary_gid.to_string());
        push_unique_group(&mut groups, primary_name, primary_gid);
    }
    // Supplementary groups (names from the passwd/group member fields), each mapped
    // to its gid. A name the local group database cannot resolve is dropped — this is
    // the conservative (under-report) direction, so it is logged rather than silently
    // lost.
    for gname in account.groups {
        if let Some(facts) = inspector.group(&gname) {
            push_unique_group(&mut groups, gname, facts.gid);
        } else {
            tracing::debug!(
                principal = %name,
                group = %gname,
                "supplementary group did not resolve to a gid in the local group database; \
                 dropping it from the principal (membership under-reported)"
            );
        }
    }

    Some(Principal {
        name,
        uid: account.uid,
        groups,
        home: Some(account.home),
    })
}

/// Append a group if its gid is not already present (dedup primary vs supplementary).
fn push_unique_group(groups: &mut Vec<ResolvedGroup>, name: String, gid: u32) {
    if !groups.iter().any(|g| g.gid == gid) {
        groups.push(ResolvedGroup { name, gid });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exposure::acl::AclEntry;
    use crate::exposure::ObjectClass;
    use crate::inspect::{AccountFacts, FakeInspector, GroupFacts};

    fn perms(r: bool, w: bool, x: bool) -> AclPerms {
        AclPerms {
            read: r,
            write: w,
            execute: x,
        }
    }

    fn record(path: &str, uid: u32, gid: u32, mode: u32, acl: Option<AclEntries>) -> InodeRecord {
        InodeRecord {
            path: path.to_owned(),
            uid,
            gid,
            mode,
            acl,
            class: ObjectClass::Generic,
        }
    }

    fn principal(name: &str, uid: u32, groups: &[(&str, u32)]) -> Principal {
        Principal::new(
            name,
            uid,
            groups
                .iter()
                .map(|(n, g)| ResolvedGroup {
                    name: (*n).to_owned(),
                    gid: *g,
                })
                .collect(),
        )
    }

    fn extended(entries: Vec<AclEntry>) -> AclEntries {
        AclEntries { entries }
    }

    fn entry(tag: AclTag, p: AclPerms) -> AclEntry {
        AclEntry { tag, perms: p }
    }

    #[test]
    fn root_uid_has_full_access_via_owner() {
        let rec = record("/x", 1000, 1000, 0o100_000, None);
        let eff = effective(&rec, &principal("root", 0, &[]));
        assert_eq!(eff.access, AclPerms::ALL);
        assert_eq!(eff.via, AccessVia::Owner);
    }

    #[test]
    fn mode_owner_bits_apply_to_owner() {
        // mode 0640: owner rw, group r, other none. The owning uid gets rw via owner.
        let rec = record("/f", 1000, 50, 0o100_640, None);
        let eff = effective(&rec, &principal("alice", 1000, &[]));
        assert_eq!(eff.access, perms(true, true, false));
        assert_eq!(eff.via, AccessVia::Owner);
    }

    #[test]
    fn world_writable_grants_write_via_other_bits() {
        // A world-writable file (0666) reached by a non-owner, non-group principal:
        // write via the other bits.
        let rec = record("/tmp/x", 0, 0, 0o100_666, None);
        let eff = effective(&rec, &principal("bob", 1001, &[]));
        assert_eq!(eff.access, perms(true, true, false));
        assert_eq!(eff.via, AccessVia::OtherBits);
    }

    #[test]
    fn supplementary_group_grants_access_via_group() {
        // A group-writable file (mode 0660, group app gid 50). The principal is not
        // the owner but is a supplementary member of app → write via group:app.
        let rec = record("/srv/app/data", 0, 50, 0o100_660, None);
        let eff = effective(&rec, &principal("bob", 1001, &[("app", 50)]));
        assert_eq!(eff.access, perms(true, true, false));
        assert_eq!(eff.via, AccessVia::Group("app".to_owned()));
    }

    #[test]
    fn named_user_acl_grants_rw() {
        // ACL: owner r--, named user role-x rw-, mask rw-, other ---. The principal
        // role-x (not the owner) gets rw via the named-user entry.
        let acl = Some(extended(vec![
            entry(AclTag::UserObj, perms(true, false, false)),
            entry(AclTag::User("role-x".to_owned()), perms(true, true, false)),
            entry(AclTag::GroupObj, perms(true, false, false)),
            entry(AclTag::Mask, perms(true, true, false)),
            entry(AclTag::Other, perms(false, false, false)),
        ]));
        let rec = record("/etc/x", 0, 0, 0o100_640, acl);
        let eff = effective(&rec, &principal("role-x", 5012, &[]));
        assert_eq!(eff.access, perms(true, true, false));
        assert_eq!(eff.via, AccessVia::AclUser("role-x".to_owned()));
    }

    #[test]
    fn mask_caps_named_group_to_read() {
        // ACL named group app rwx but mask r-- → effective r only; write denied.
        let acl = Some(extended(vec![
            entry(AclTag::UserObj, perms(true, true, false)),
            entry(AclTag::GroupObj, perms(true, false, false)),
            entry(AclTag::Group("app".to_owned()), perms(true, true, true)),
            entry(AclTag::Mask, perms(true, false, false)),
            entry(AclTag::Other, perms(false, false, false)),
        ]));
        let rec = record("/srv/x", 0, 0, 0o100_640, acl);
        let eff = effective(&rec, &principal("bob", 1001, &[("app", 50)]));
        assert_eq!(
            eff.access,
            perms(true, false, false),
            "mask caps rwx to r--"
        );
        assert_eq!(eff.via, AccessVia::AclGroup("app".to_owned()));
    }

    #[test]
    fn matched_group_class_with_no_grant_does_not_fall_to_other() {
        // ACL named group app with NO permissions, but other has rwx. A principal in
        // app matches the group class → access is the (empty) group grant, NOT the
        // permissive other bits.
        let acl = Some(extended(vec![
            entry(AclTag::UserObj, perms(true, true, true)),
            entry(AclTag::GroupObj, perms(false, false, false)),
            entry(AclTag::Group("app".to_owned()), perms(false, false, false)),
            entry(AclTag::Mask, perms(true, true, true)),
            entry(AclTag::Other, perms(true, true, true)),
        ]));
        let rec = record("/srv/x", 0, 0, 0o100_647, acl);
        let eff = effective(&rec, &principal("bob", 1001, &[("app", 50)]));
        assert_eq!(
            eff.access,
            perms(false, false, false),
            "group class matched but grants nothing — must not use other"
        );
        assert_eq!(eff.via, AccessVia::AclGroup("app".to_owned()));
    }

    #[test]
    fn resolve_principal_by_numeric_uid() {
        // A fake passwd/group: account svc uid 5012, primary gid 5012 (group svc),
        // supplementary group app gid 50. Resolving by the numeric uid yields the
        // name, uid, and both groups.
        let mut insp = FakeInspector::default();
        insp.accounts.insert(
            "svc".to_owned(),
            AccountFacts {
                uid: 5012,
                shell: "/bin/bash".to_owned(),
                home: std::path::PathBuf::from("/home/svc"),
                groups: vec!["app".to_owned()],
            },
        );
        insp.primary_gids.insert("svc".to_owned(), 5012);
        insp.groups
            .insert("svc".to_owned(), GroupFacts { gid: 5012 });
        insp.groups.insert("app".to_owned(), GroupFacts { gid: 50 });

        let p = resolve_principal(&insp, "5012").expect("resolves by uid");
        assert_eq!(p.name, "svc");
        assert_eq!(p.uid, 5012);
        // Primary group svc(5012) first, then supplementary app(50).
        assert_eq!(
            p.groups,
            vec![
                ResolvedGroup {
                    name: "svc".to_owned(),
                    gid: 5012
                },
                ResolvedGroup {
                    name: "app".to_owned(),
                    gid: 50
                },
            ]
        );
        // And by name resolves identically.
        let by_name = resolve_principal(&insp, "svc").expect("resolves by name");
        assert_eq!(by_name, p);
    }

    #[test]
    fn resolve_orphan_numeric_uid_yields_groupless_principal() {
        // A numeric uid that owns files but has NO passwd entry (an orphan uid) must
        // still resolve — by raw reachability with no groups — so the audit can run.
        let insp = FakeInspector::default();
        let p = resolve_principal(&insp, "70123").expect("orphan uid still resolves");
        assert_eq!(p.uid, 70123);
        assert_eq!(p.name, "70123", "name falls back to the uid string");
        assert!(p.groups.is_empty(), "an orphan uid has no group membership");
    }

    #[test]
    fn resolve_unknown_name_is_none() {
        // A bare (non-numeric) name with no passwd entry cannot be audited.
        let insp = FakeInspector::default();
        assert!(resolve_principal(&insp, "ghost").is_none());
    }

    #[test]
    fn via_labels_render_tokens() {
        assert_eq!(AccessVia::Owner.label(), "owner");
        assert_eq!(AccessVia::OtherBits.label(), "other_bits");
        assert_eq!(AccessVia::AclUser("u".to_owned()).label(), "acl_user:u");
        assert_eq!(AccessVia::AclGroup("g".to_owned()).label(), "acl_group:g");
        assert_eq!(AccessVia::Group("g".to_owned()).label(), "group:g");
    }
}
