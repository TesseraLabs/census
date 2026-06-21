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

use crate::mutate::GECOS_MARKER_PREFIX;
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

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
    /// `Some(true)` if the shadow password field is locked (starts with `!` or
    /// `*`), `Some(false)` if unlocked, `None` if the account/shadow entry is
    /// absent or unreadable.
    fn password_locked(&self, name: &str) -> Option<bool>;
    /// True if `<home>/.ssh/authorized_keys` exists.
    fn has_authorized_keys(&self, name: &str, home: &Path) -> bool;
    /// Accounts whose GECOS field carries a Census role marker
    /// (`census-role-…`). Used to detect a spoofed marker not in the registry.
    fn census_marked_accounts(&self) -> Vec<String>;
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
        let out = cmd.output().ok()?;
        if !out.status.success() {
            return None;
        }
        String::from_utf8(out.stdout).ok()
    }

    /// Parse one `passwd` line (`name:passwd:uid:gid:gecos:home:shell`) into
    /// `(name, uid, home, shell)`. Returns `None` on a malformed line.
    fn parse_passwd_line(line: &str) -> Option<(String, u32, String, String)> {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 {
            return None;
        }
        let uid = f[2].parse::<u32>().ok()?;
        Some((f[0].to_owned(), uid, f[5].to_owned(), f[6].to_owned()))
    }

    /// Parse one `group` line (`name:passwd:gid:members`) into `(name, gid)`.
    /// Returns `None` on a malformed line (short / non-numeric gid).
    fn parse_group_line(line: &str) -> Option<(String, u32)> {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 3 {
            return None;
        }
        let gid = f[2].parse::<u32>().ok()?;
        Some((f[0].to_owned(), gid))
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
            if f.len() < 4 {
                continue;
            }
            let members = f[3].split(',').map(str::trim).filter(|m| !m.is_empty());
            if members.into_iter().any(|m| m == name) {
                groups.push(f[0].to_owned());
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
    fn is_rescue_eligible(is_login_shell: bool, password_locked: Option<bool>, has_keys: bool) -> bool {
        is_login_shell && (password_locked == Some(false) || has_keys)
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

    fn has_authorized_keys(&self, _name: &str, home: &Path) -> bool {
        home.join(".ssh").join("authorized_keys").exists()
    }

    fn census_marked_accounts(&self) -> Vec<String> {
        let Some(text) = Self::getent("passwd", None) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for line in text.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 7 {
                continue;
            }
            // GECOS is field 5; the marker is a single token (no `:`/`=`).
            if f[4].split([' ', ',']).any(|t| t.starts_with(GECOS_MARKER_PREFIX)) {
                out.push(f[0].to_owned());
            }
        }
        out
    }

    fn login_capable_non_managed(&self, managed: &BTreeSet<String>) -> Vec<String> {
        let Some(text) = Self::getent("passwd", None) else {
            return Vec::new();
        };
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
            let eligible = Self::is_rescue_eligible(
                Self::is_login_shell(&shell),
                self.password_locked(&name),
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
    /// Per-account password lock state (absent = `None`).
    pub locked: std::collections::BTreeMap<String, bool>,
    /// Accounts that have `authorized_keys`.
    pub authorized_keys: BTreeSet<String>,
    /// Accounts carrying a Census GECOS marker.
    pub marked: Vec<String>,
    /// Login-capable accounts (used to derive the non-managed rescue set).
    pub login_capable: BTreeSet<String>,
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

    fn password_locked(&self, name: &str) -> Option<bool> {
        self.locked.get(name).copied()
    }

    fn has_authorized_keys(&self, name: &str, _home: &Path) -> bool {
        self.authorized_keys.contains(name)
    }

    fn census_marked_accounts(&self) -> Vec<String> {
        self.marked.clone()
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
        fake.groups.insert("atm-operators".into(), GroupFacts { gid: 8010 });
        assert_eq!(fake.group("atm-operators"), Some(GroupFacts { gid: 8010 }));
        assert_eq!(fake.group("absent"), None);
        // reverse lookup by gid (pin-conflict detection).
        assert_eq!(fake.group_name_by_gid(8010).as_deref(), Some("atm-operators"));
        assert_eq!(fake.group_name_by_gid(9999), None);
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
