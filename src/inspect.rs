//! Live-OS read seam for diagnostics (`census doctor`).
//!
//! `plan`/`apply` reconcile against the managed *registry*; doctor additionally
//! reads the *live* system (shadow lock state, `authorized_keys`, GECOS markers,
//! login-capable accounts) to detect degradation of the §8 unreachability
//! invariant and §4 registry-integrity. This is the read counterpart of the
//! [`crate::mutate::Provisioner`] write seam.
//!
//! The trait lets doctor be unit-tested without root or a live system: tests use
//! [`FakeInspector`], production uses [`LiveInspector`] (which shells out to
//! `getent` with argv arrays — read-only, no shell, no mutation).

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use crate::mutate::GECOS_MARKER_PREFIX;

/// Facts about one live account, as read from `getent passwd`/`getent group`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountFacts {
    /// Numeric UID.
    pub uid: u32,
    /// Login shell (field 7 of the passwd entry).
    pub shell: String,
    /// Home directory (field 6 of the passwd entry). Authoritative for the
    /// `authorized_keys` location — the registry does not record home.
    pub home: std::path::PathBuf,
    /// Supplementary groups the account belongs to (from `getent group`).
    pub groups: Vec<String>,
}

/// Facts about one live group, as read from `getent group`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupFacts {
    /// Numeric GID.
    pub gid: u32,
}

/// Read-only view of the live system for diagnostics. Every method is
/// non-mutating; implementations MUST NOT change OS state.
pub trait SystemInspector {
    /// Facts for `name`, or `None` if the account is not present.
    fn account(&self, name: &str) -> Option<AccountFacts>;
    /// Facts for group `name`, or `None` if the group is not present. Used by
    /// the group diff (does it exist? its GID?) and doctor (GID drift).
    fn group(&self, name: &str) -> Option<GroupFacts>;
    /// The name of the group currently owning `gid`, or `None` if `gid` is
    /// free. Used to detect a GID-pin conflict against a DIFFERENT existing
    /// group (the pinned GID is already taken). Read-only.
    fn group_name_by_gid(&self, gid: u32) -> Option<String>;
    /// The members of group `name` as the OS currently lists them (the
    /// comma-separated member field of `getent group`). Empty when the group is
    /// absent or has no members. Read-only — used at adopt time to snapshot the
    /// group's pre-existing members into its baseline, so a later release can
    /// strip only Census-added members and leave the foreign ones intact. A
    /// default impl returns empty so pre-existing fakes/callers keep compiling.
    fn group_members(&self, _name: &str) -> Vec<String> {
        Vec::new()
    }
    /// `Some(true)` if the shadow password field is locked (starts with `!` or
    /// `*`), `Some(false)` if unlocked, `None` if the account/shadow entry is
    /// absent or unreadable.
    fn password_locked(&self, name: &str) -> Option<bool>;

    /// Read the WHOLE shadow database once, mapping each account name to its lock
    /// state (`true` = locked, `false` = unlocked).
    ///
    /// `None` means shadow could not be read AT ALL — on a non-root run `getent
    /// shadow` is unreadable, so we cannot evaluate ANY account's lock state. The
    /// caller must treat that as "cannot evaluate" (a degraded read), distinct
    /// from `Some(map)` where the database was read and an account simply absent
    /// from the map has no shadow entry. Reading once avoids a per-account
    /// `getent` spawn storm and a false anti-lockout warning on every non-root
    /// run. A default impl returns `None` so test doubles that predate this method
    /// keep compiling (and degrade safely).
    fn shadow_locks(&self) -> Option<std::collections::BTreeMap<String, bool>> {
        None
    }
    /// True if `<home>/.ssh/authorized_keys` exists.
    fn has_authorized_keys(&self, name: &str, home: &Path) -> bool;
    /// Accounts whose GECOS field carries a Census role marker
    /// (`census-role-…`). Used to detect a spoofed marker not in the registry.
    fn census_marked_accounts(&self) -> Vec<String>;
    /// Whether the `census-grp-<group>` sudoers fragment Census owns for `group`
    /// is present on disk.
    ///
    /// `Some(true)` if the fragment file exists, `Some(false)` if it is absent,
    /// `None` if presence cannot be determined (the sudoers directory is
    /// unreadable). Read-only — checks file existence only, never the contents.
    /// Used by doctor's adopted-group drift check: an adopted group whose
    /// registry records group sudo commands but whose fragment was removed out of
    /// band has drifted. A default impl returns `None` so fakes/callers that
    /// predate the check keep compiling and the check stays best-effort (a `None`
    /// is never a finding).
    fn group_sudoers_fragment_present(&self, _group: &str) -> Option<bool> {
        None
    }
    /// Whether `account` currently has its own POSIX ACL access entry on `path`.
    ///
    /// `Some(true)` if a `user:<account>:…` access entry is present, `Some(false)`
    /// if the path is readable but carries no such entry (a managed file grant that
    /// drifted away), `None` if the answer cannot be determined (no `getfacl`, path
    /// absent/unreadable). Read-only: `getfacl` never mutates. Used by doctor's
    /// file-access drift check, which is best-effort — a `None` is not a finding.
    fn file_access_present(&self, path: &str, account: &str) -> Option<bool>;

    /// Accounts NOT in `managed` that can actually log in — the rescue/break-glass
    /// set the anti-lockout check (§7) wants to be non-empty.
    ///
    /// An account counts as rescue only if it has a login shell AND can actually
    /// authenticate: its password is usable (`password_locked` returns
    /// `Some(false)`) OR it has `authorized_keys` under its live passwd home. A
    /// locked password with no keys, or an unreadable/absent shadow entry
    /// (`password_locked` → `None`), does NOT count — conservative, so we never
    /// suppress the warning on the strength of an account nobody can log into.
    fn login_capable_non_managed(&self, managed: &BTreeSet<String>) -> Vec<String>;
}

/// Production inspector backed by `getent` and the filesystem. Read-only.
#[derive(Debug, Default)]
pub struct LiveInspector;

impl LiveInspector {
    /// Construct a live inspector.
    pub fn new() -> Self {
        LiveInspector
    }

    /// Run `getent <db> [key]` and return stdout as a UTF-8 string, or `None` on
    /// any failure (spawn error, non-zero exit, non-UTF-8). Read-only: `getent`
    /// never mutates state. argv array — no shell, no injection surface.
    fn getent(db: &str, key: Option<&str>) -> Option<String> {
        let mut cmd = Command::new("getent");
        cmd.arg(db);
        if let Some(k) = key {
            cmd.arg(k);
        }
        let out = match cmd.output() {
            Ok(o) => o,
            Err(e) => {
                // A getent spawn failure degrades the read (we report "not found"
                // for the queried entity); log it so a misconfigured host is
                // diagnosable rather than silently looking empty.
                tracing::warn!(program = "getent", db, error = %e, "getent spawn failed");
                return None;
            }
        };
        if !out.status.success() {
            // Non-zero is the normal "no such entry" for a keyed lookup, so this
            // is a low-severity degraded-read signal, not a warning.
            tracing::debug!(program = "getent", db, status = ?out.status.code(), "getent non-zero exit");
            return None;
        }
        match String::from_utf8(out.stdout) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!(program = "getent", db, error = %e, "getent output not UTF-8");
                None
            }
        }
    }

    /// Parse one `passwd` line (`name:passwd:uid:gid:gecos:home:shell`) into
    /// `(name, uid, home, shell)`. Returns `None` on a malformed line.
    fn parse_passwd_line(line: &str) -> Option<(String, u32, String, String)> {
        let f: Vec<&str> = line.split(':').collect();
        let [name, _passwd, uid, _gid, _gecos, home, shell, ..] = f.as_slice() else {
            return None;
        };
        let uid = uid.parse::<u32>().ok()?;
        Some((
            (*name).to_owned(),
            uid,
            (*home).to_owned(),
            (*shell).to_owned(),
        ))
    }

    /// Parse one `group` line (`name:passwd:gid:members`) into `(name, gid)`.
    /// Returns `None` on a malformed line (short / non-numeric gid).
    fn parse_group_line(line: &str) -> Option<(String, u32)> {
        let f: Vec<&str> = line.split(':').collect();
        let [name, _passwd, gid, ..] = f.as_slice() else {
            return None;
        };
        let gid = gid.parse::<u32>().ok()?;
        Some(((*name).to_owned(), gid))
    }

    /// Supplementary groups for `name` from `getent group` output. A group line
    /// is `group:passwd:gid:member1,member2`; `name` is a member when listed in
    /// the comma-separated member field.
    fn groups_for(name: &str) -> Vec<String> {
        let Some(text) = Self::getent("group", None) else {
            return Vec::new();
        };
        let mut groups = Vec::new();
        for line in text.lines() {
            let f: Vec<&str> = line.split(':').collect();
            let [group, _passwd, _gid, member_field, ..] = f.as_slice() else {
                continue;
            };
            let mut members = member_field
                .split(',')
                .map(str::trim)
                .filter(|m| !m.is_empty());
            if members.any(|m| m == name) {
                groups.push((*group).to_owned());
            }
        }
        groups
    }

    /// True if `shell` is a real login shell (not a nologin/false stub).
    ///
    /// Heuristic (documented): a shell whose final path component is `nologin`
    /// or `false`, or an empty shell, is NOT login-capable; anything else is.
    /// This is the practical signal sysadmins use to disable login.
    fn is_login_shell(shell: &str) -> bool {
        if shell.is_empty() {
            return false;
        }
        let base = shell.rsplit('/').next().unwrap_or(shell);
        base != "nologin" && base != "false"
    }

    /// Decide whether an account qualifies as a rescue (login-capable) channel
    /// for the anti-lockout check, given its three live signals.
    ///
    /// True only if it has a login shell AND can actually authenticate: the
    /// password is usable (`password_locked` → `Some(false)`) OR it has
    /// `authorized_keys`. An unreadable/absent shadow entry (`None`) is treated
    /// conservatively as not usable, so a locked-or-unknown password with no keys
    /// never counts.
    fn is_rescue_eligible(
        is_login_shell: bool,
        password_locked: Option<bool>,
        has_keys: bool,
    ) -> bool {
        is_login_shell && (password_locked == Some(false) || has_keys)
    }

    /// Whether a `getfacl` dump carries a NAMED user ACL entry for `account`.
    ///
    /// `getfacl` lines look like `user:alice:rwx` (named) vs `user::rwx` (the file
    /// owner — an EMPTY name field). We must match only the named form for our
    /// account, so the check is on the exact `user:<account>:` prefix; the bare
    /// owner entry `user::…` never matches a non-empty account. A `default:user:…`
    /// (default-ACL) line for the account also counts — it is how a directory grant
    /// makes new files inherit access. Pure so it is unit-tested without `getfacl`.
    fn acl_has_user_entry(dump: &str, account: &str) -> bool {
        let named = format!("user:{account}:");
        let default_named = format!("default:user:{account}:");
        dump.lines()
            .map(str::trim)
            .any(|line| line.starts_with(&named) || line.starts_with(&default_named))
    }
}

impl SystemInspector for LiveInspector {
    fn account(&self, name: &str) -> Option<AccountFacts> {
        let text = Self::getent("passwd", Some(name))?;
        let line = text.lines().next()?;
        let (_n, uid, home, shell) = Self::parse_passwd_line(line)?;
        Some(AccountFacts {
            uid,
            shell,
            home: std::path::PathBuf::from(home),
            groups: Self::groups_for(name),
        })
    }

    fn group(&self, name: &str) -> Option<GroupFacts> {
        let text = Self::getent("group", Some(name))?;
        let line = text.lines().next()?;
        let (_n, gid) = Self::parse_group_line(line)?;
        Some(GroupFacts { gid })
    }

    fn group_name_by_gid(&self, gid: u32) -> Option<String> {
        // `getent group <gid>` resolves the group owning a numeric GID.
        let text = Self::getent("group", Some(&gid.to_string()))?;
        let line = text.lines().next()?;
        let (name, _gid) = Self::parse_group_line(line)?;
        Some(name)
    }

    fn group_members(&self, name: &str) -> Vec<String> {
        // `getent group <name>` → `name:passwd:gid:member1,member2`. Field 3 is
        // the comma-separated member list (empty when none). Absent group → none.
        let Some(text) = Self::getent("group", Some(name)) else {
            return Vec::new();
        };
        let Some(line) = text.lines().next() else {
            return Vec::new();
        };
        let f: Vec<&str> = line.split(':').collect();
        let [_group, _passwd, _gid, member_field, ..] = f.as_slice() else {
            return Vec::new();
        };
        member_field
            .split(',')
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .map(str::to_owned)
            .collect()
    }

    fn password_locked(&self, name: &str) -> Option<bool> {
        // `getent shadow <name>` → `name:passwd:...`. The second field is the
        // hash; a leading `!` or `*` means locked/no-login. Empty field = absent
        // hash, treated as not a positive lock.
        let text = Self::getent("shadow", Some(name))?;
        let line = text.lines().next()?;
        let f: Vec<&str> = line.split(':').collect();
        let hash = f.get(1)?;
        Some(hash.starts_with('!') || hash.starts_with('*'))
    }

    fn shadow_locks(&self) -> Option<std::collections::BTreeMap<String, bool>> {
        // One keyless `getent shadow` read of the whole database. Unreadable
        // (non-root, no shadow access) → None: the caller treats that as "cannot
        // evaluate", never as "every account is unlocked/absent". Each line is
        // `name:hash:…`; a leading `!`/`*` on the hash is a positive lock.
        let Some(text) = Self::getent("shadow", None) else {
            tracing::warn!(
                program = "getent",
                db = "shadow",
                reason = "unreadable (likely non-root); password-lock state cannot be evaluated",
                "shadow database read degraded"
            );
            return None;
        };
        let mut map = std::collections::BTreeMap::new();
        for line in text.lines() {
            let f: Vec<&str> = line.split(':').collect();
            let (Some(name), Some(hash)) = (f.first(), f.get(1)) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            map.insert(
                (*name).to_owned(),
                hash.starts_with('!') || hash.starts_with('*'),
            );
        }
        Some(map)
    }

    fn has_authorized_keys(&self, _name: &str, home: &Path) -> bool {
        home.join(".ssh").join("authorized_keys").exists()
    }

    fn group_sudoers_fragment_present(&self, group: &str) -> Option<bool> {
        // The fragment Census owns for a role-bound group lives at
        // `<SUDOERS_DIR>/census-grp-<group>`. Read-only existence check: if the
        // sudoers directory itself is unreadable we cannot tell (None), otherwise
        // the file either exists (Some(true)) or was removed (Some(false)).
        let dir = Path::new(crate::sudoers::SUDOERS_DIR);
        if std::fs::metadata(dir).is_err() {
            return None;
        }
        let fragment = dir.join(crate::sudoers::sudoers_group_filename(group));
        Some(fragment.exists())
    }

    fn census_marked_accounts(&self) -> Vec<String> {
        let Some(text) = Self::getent("passwd", None) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for line in text.lines() {
            let f: Vec<&str> = line.split(':').collect();
            // passwd is `name:passwd:uid:gid:gecos:home:shell`; GECOS is field 5.
            let [name, _passwd, _uid, _gid, gecos, _home, _shell, ..] = f.as_slice() else {
                continue;
            };
            // The Census marker is a single whitespace-/comma-free token; `:`
            // cannot appear in GECOS (it is the passwd field separator, so a `:`
            // would have split the line into another field), which is why
            // splitting on space, tab, and comma fully tokenizes the field for
            // marker detection.
            if gecos
                .split([' ', '\t', ','])
                .any(|t| t.starts_with(GECOS_MARKER_PREFIX))
            {
                out.push((*name).to_owned());
            }
        }
        out
    }

    fn file_access_present(&self, path: &str, account: &str) -> Option<bool> {
        // `getfacl --omit-header --absolute-names <path>` lists the ACL entries.
        // Read-only, argv array (no shell). A spawn failure (no getfacl) or a
        // non-zero exit (path absent/unreadable) yields `None` — best-effort, not a
        // finding. The `user:<account>:` entry is what `setfacl -m u:<acct>:…` set.
        let out = Command::new("getfacl")
            .arg("--omit-header")
            .arg("--absolute-names")
            .arg(path)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8(out.stdout).ok()?;
        Some(Self::acl_has_user_entry(&text, account))
    }

    fn login_capable_non_managed(&self, managed: &BTreeSet<String>) -> Vec<String> {
        let Some(text) = Self::getent("passwd", None) else {
            return Vec::new();
        };
        // Read shadow ONCE for the whole pass instead of spawning `getent shadow`
        // per account. `None` (degraded — non-root) leaves every per-account lock
        // state unknown, so eligibility falls back to authorized_keys alone, which
        // is the conservative behavior the rescue predicate already encodes.
        let shadow = self.shadow_locks();
        let mut out = Vec::new();
        for line in text.lines() {
            let Some((name, _uid, home, shell)) = Self::parse_passwd_line(line) else {
                continue;
            };
            if managed.contains(&name) {
                continue;
            }
            // A login shell alone is not enough: the account must be able to
            // authenticate. The `authorized_keys` home comes from this account's
            // live passwd entry (field 6), not the registry.
            let home_path = Path::new(&home);
            let locked = shadow.as_ref().and_then(|m| m.get(&name).copied());
            let eligible = Self::is_rescue_eligible(
                Self::is_login_shell(&shell),
                locked,
                self.has_authorized_keys(&name, home_path),
            );
            if eligible {
                out.push(name);
            }
        }
        out
    }
}

/// In-memory inspector for tests. Every field is directly settable.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct FakeInspector {
    /// Live accounts keyed by name.
    pub accounts: std::collections::BTreeMap<String, AccountFacts>,
    /// Live groups keyed by name.
    pub groups: std::collections::BTreeMap<String, GroupFacts>,
    /// Live group members keyed by group name (the OS member list). Used to
    /// snapshot an adopted group's baseline members.
    pub group_members: std::collections::BTreeMap<String, Vec<String>>,
    /// Per-account password lock state (absent = `None`).
    pub locked: std::collections::BTreeMap<String, bool>,
    /// When `true`, the shadow database cannot be read at all — `shadow_locks`
    /// returns `None` (degraded), modeling a non-root run where `getent shadow` is
    /// unreadable. Defaults to `false` (readable), so existing tests that populate
    /// `locked` see a readable shadow derived from that map.
    pub shadow_unreadable: bool,
    /// Accounts that have `authorized_keys`.
    pub authorized_keys: BTreeSet<String>,
    /// Accounts carrying a Census GECOS marker.
    pub marked: Vec<String>,
    /// Login-capable accounts (used to derive the non-managed rescue set).
    pub login_capable: BTreeSet<String>,
    /// File-access ACL state for the drift check, keyed by `(path, account)`:
    /// `true` = entry present, `false` = path readable but no entry. A key that is
    /// absent maps to `None` (cannot determine — best-effort).
    pub file_acls: std::collections::BTreeMap<(String, String), bool>,
    /// Presence of the `census-grp-<group>` sudoers fragment, keyed by group
    /// name: `true` = on disk, `false` = removed. An absent key maps to `None`
    /// (cannot determine — best-effort), matching the live inspector's behavior
    /// when the sudoers directory is unreadable.
    pub group_sudoers_fragments: std::collections::BTreeMap<String, bool>,
}

#[cfg(test)]
impl SystemInspector for FakeInspector {
    fn account(&self, name: &str) -> Option<AccountFacts> {
        self.accounts.get(name).cloned()
    }

    fn group(&self, name: &str) -> Option<GroupFacts> {
        self.groups.get(name).cloned()
    }

    fn group_name_by_gid(&self, gid: u32) -> Option<String> {
        self.groups
            .iter()
            .find(|(_, f)| f.gid == gid)
            .map(|(n, _)| n.clone())
    }

    fn group_members(&self, name: &str) -> Vec<String> {
        self.group_members.get(name).cloned().unwrap_or_default()
    }

    fn password_locked(&self, name: &str) -> Option<bool> {
        if self.shadow_unreadable {
            return None;
        }
        self.locked.get(name).copied()
    }

    fn shadow_locks(&self) -> Option<std::collections::BTreeMap<String, bool>> {
        if self.shadow_unreadable {
            return None;
        }
        Some(self.locked.clone())
    }

    fn has_authorized_keys(&self, name: &str, _home: &Path) -> bool {
        self.authorized_keys.contains(name)
    }

    fn group_sudoers_fragment_present(&self, group: &str) -> Option<bool> {
        self.group_sudoers_fragments.get(group).copied()
    }

    fn census_marked_accounts(&self) -> Vec<String> {
        self.marked.clone()
    }

    fn file_access_present(&self, path: &str, account: &str) -> Option<bool> {
        self.file_acls
            .get(&(path.to_owned(), account.to_owned()))
            .copied()
    }

    fn login_capable_non_managed(&self, managed: &BTreeSet<String>) -> Vec<String> {
        self.login_capable
            .iter()
            .filter(|n| !managed.contains(*n))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_passwd_line_extracts_fields() {
        let line = "oper:x:9010:9010:census-role-oper:/var/lib/census/home/oper:/bin/bash";
        let (name, uid, home, shell) = LiveInspector::parse_passwd_line(line).unwrap();
        assert_eq!(name, "oper");
        assert_eq!(uid, 9010);
        assert_eq!(home, "/var/lib/census/home/oper");
        assert_eq!(shell, "/bin/bash");
    }

    #[test]
    fn parse_passwd_line_rejects_short_line() {
        assert!(LiveInspector::parse_passwd_line("oper:x:9010").is_none());
    }

    #[test]
    fn parse_group_line_extracts_gid() {
        let (name, gid) = LiveInspector::parse_group_line("wheel:x:10:oper,serv").unwrap();
        assert_eq!(name, "wheel");
        assert_eq!(gid, 10);
        // member-less line is still valid (3 fields).
        let (n2, g2) = LiveInspector::parse_group_line("tellers:x:8011:").unwrap();
        assert_eq!(n2, "tellers");
        assert_eq!(g2, 8011);
    }

    #[test]
    fn parse_group_line_rejects_bad() {
        assert!(LiveInspector::parse_group_line("wheel:x").is_none());
        assert!(LiveInspector::parse_group_line("wheel:x:notnum:").is_none());
    }

    #[test]
    fn fake_group_round_trips() {
        let mut fake = FakeInspector::default();
        fake.groups
            .insert("atm-operators".into(), GroupFacts { gid: 8010 });
        assert_eq!(fake.group("atm-operators"), Some(GroupFacts { gid: 8010 }));
        assert_eq!(fake.group("absent"), None);
        // reverse lookup by gid (pin-conflict detection).
        assert_eq!(
            fake.group_name_by_gid(8010).as_deref(),
            Some("atm-operators")
        );
        assert_eq!(fake.group_name_by_gid(9999), None);
    }

    #[test]
    fn fake_group_members_round_trip() {
        let mut fake = FakeInspector::default();
        fake.group_members
            .insert("wheel".into(), vec!["root".into(), "admin".into()]);
        assert_eq!(fake.group_members("wheel"), vec!["root", "admin"]);
        // Absent group → empty member list (the default-impl behavior too).
        assert!(fake.group_members("absent").is_empty());
    }

    #[test]
    fn parse_passwd_line_rejects_non_numeric_uid() {
        let line = "oper:x:notanum:9010:gecos:/home/oper:/bin/bash";
        assert!(LiveInspector::parse_passwd_line(line).is_none());
    }

    #[test]
    fn is_login_shell_heuristic() {
        assert!(LiveInspector::is_login_shell("/bin/bash"));
        assert!(LiveInspector::is_login_shell("/bin/sh"));
        assert!(!LiveInspector::is_login_shell("/usr/sbin/nologin"));
        assert!(!LiveInspector::is_login_shell("/sbin/nologin"));
        assert!(!LiveInspector::is_login_shell("/bin/false"));
        assert!(!LiveInspector::is_login_shell(""));
    }

    #[test]
    fn rescue_requires_login_shell_and_real_auth() {
        // No login shell: never a rescue, regardless of auth.
        assert!(!LiveInspector::is_rescue_eligible(false, Some(false), true));

        // Login shell + locked password + no keys: NOT a rescue — nobody can log
        // in, so doctor must still emit the anti-lockout Warn.
        assert!(!LiveInspector::is_rescue_eligible(true, Some(true), false));

        // Login shell + unlocked password: IS a rescue (no warn).
        assert!(LiveInspector::is_rescue_eligible(true, Some(false), false));

        // Login shell + locked password + authorized_keys: IS a rescue.
        assert!(LiveInspector::is_rescue_eligible(true, Some(true), true));

        // Login shell + unreadable/absent shadow (None) + no keys: conservatively
        // NOT a rescue.
        assert!(!LiveInspector::is_rescue_eligible(true, None, false));

        // Login shell + unreadable shadow but has keys: IS a rescue.
        assert!(LiveInspector::is_rescue_eligible(true, None, true));
    }

    #[test]
    fn acl_has_user_entry_matches_named_not_owner() {
        // A getfacl dump: owner entry `user::`, named entries `user:alice:` and a
        // default-ACL `default:user:alice:`. Only the NAMED account matches; the
        // bare owner `user::rwx` must NOT be read as a match for "alice".
        let dump = "\
user::rwx
user:alice:r-x
group::r-x
mask::r-x
other::r-x
default:user:alice:rwx
";
        assert!(LiveInspector::acl_has_user_entry(dump, "alice"));
        assert!(LiveInspector::acl_has_user_entry(dump, "alice")); // default form too
                                                                   // A different account is not present.
        assert!(!LiveInspector::acl_has_user_entry(dump, "bob"));
        // The owner entry (empty name) must not match an account named "".
        let owner_only = "user::rwx\ngroup::r-x\nother::r-x\n";
        assert!(!LiveInspector::acl_has_user_entry(owner_only, "alice"));
    }

    #[test]
    fn fake_shadow_locks_batches_and_degrades() {
        let mut fake = FakeInspector::default();
        fake.locked.insert("oper".into(), true);
        fake.locked.insert("svc".into(), false);
        // Readable shadow → one batched map mirroring `locked`.
        let map = fake.shadow_locks().expect("readable shadow yields a map");
        assert_eq!(map.get("oper"), Some(&true));
        assert_eq!(map.get("svc"), Some(&false));
        assert_eq!(map.get("ghost"), None);

        // Unreadable shadow (non-root) → None, and per-account reads also degrade.
        fake.shadow_unreadable = true;
        assert!(
            fake.shadow_locks().is_none(),
            "degraded shadow read returns None"
        );
        assert_eq!(
            fake.password_locked("oper"),
            None,
            "per-account read degrades too"
        );
    }

    #[test]
    fn fake_inspector_round_trips() {
        let mut fake = FakeInspector::default();
        fake.accounts.insert(
            "oper".into(),
            AccountFacts {
                uid: 9010,
                shell: "/bin/bash".into(),
                home: Path::new("/var/lib/census/home/oper").to_path_buf(),
                groups: vec!["wheel".into()],
            },
        );
        fake.locked.insert("oper".into(), true);
        fake.authorized_keys.insert("oper".into());
        fake.marked.push("oper".into());
        fake.login_capable.insert("rescue".into());

        assert_eq!(fake.account("oper").unwrap().uid, 9010);
        assert_eq!(fake.account("ghost"), None);
        assert_eq!(fake.password_locked("oper"), Some(true));
        assert_eq!(fake.password_locked("ghost"), None);
        assert!(fake.has_authorized_keys("oper", Path::new("/x")));
        assert!(!fake.has_authorized_keys("ghost", Path::new("/x")));
        assert_eq!(fake.census_marked_accounts(), vec!["oper".to_owned()]);

        let mut managed = BTreeSet::new();
        managed.insert("oper".to_owned());
        assert_eq!(
            fake.login_capable_non_managed(&managed),
            vec!["rescue".to_owned()]
        );
    }
}
