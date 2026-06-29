//! Mount-point classification: decide which filesystems the walk descends.
//!
//! ## Why fstype, not a device-boundary blanket
//!
//! A naive `-xdev` walk that refuses every `st_dev` change silently drops *legitimate
//! local submounts* — `/var/log`, `/home`, or `/srv` on a separate partition or LVM
//! volume — and a security audit must not have silent blind spots. So the walk
//! classifies each mount by its filesystem type instead: it descends into local
//! filesystems (re-anchoring at the mount point) and skips only network filesystems
//! (`nfs`, `cifs`, `9p`, `fuse.sshfs`, …) and kernel pseudo-filesystems. Every skipped
//! mount is recorded so the operator knows coverage was trimmed, never silently.
//!
//! ## Source of truth
//!
//! [`MountTable::live`] reads `/proc/self/mountinfo` (best-effort: an unreadable or
//! absent mountinfo yields an empty table, so the walk simply descends everything on
//! the device, as before). [`MountTable::from_mountinfo`] parses the same format from
//! text so the classification is unit-testable without real mounts.

use std::collections::HashMap;
use std::path::Path;

/// Network / remote filesystem types whose mounts the walk does not descend: reading
/// them is slow, can hang on an unreachable server, and is out of scope for a local
/// access audit. Curated and documented so the boundary is reviewable.
const NETWORK_FSTYPES: &[&str] = &[
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "smbfs",
    "ncpfs",
    "afs",
    "9p",
    "ceph",
    "glusterfs",
    "lustre",
    "ocfs2",
    "fuse.sshfs",
    "sshfs",
    "fuse.davfs",
    "davfs",
    "fuse.glusterfs",
    "fuse.cephfs",
    "fuse.rclone",
];

/// Kernel pseudo / virtual filesystem types whose inode modes do not describe
/// persistent on-disk access. Skipped at the mount boundary (the well-known mount
/// points `/proc`, `/sys`, `/dev`, `/run` are also skipped by name in `scope.rs`, so
/// this catches the rest and any non-standard locations). `tmpfs` and `ramfs` are
/// deliberately NOT here: a `tmpfs` such as `/tmp` is a real, world-writable surface
/// the audit wants to see.
const PSEUDO_FSTYPES: &[&str] = &[
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "cgroup",
    "cgroup2",
    "bpf",
    "tracefs",
    "debugfs",
    "securityfs",
    "pstore",
    "mqueue",
    "hugetlbfs",
    "configfs",
    "fusectl",
    "binfmt_misc",
    "autofs",
    "rpc_pipefs",
    "nsfs",
    "efivarfs",
];

/// Whether a filesystem type is one the walk skips (network or pseudo).
#[must_use]
pub fn is_skip_fstype(fstype: &str) -> bool {
    NETWORK_FSTYPES.contains(&fstype) || PSEUDO_FSTYPES.contains(&fstype)
}

/// A map of skip-classified mount points to their filesystem type.
///
/// Only mounts whose fstype is network or pseudo are recorded; local mounts are
/// absent (the walk descends anything not listed here).
#[derive(Debug, Clone, Default)]
pub struct MountTable {
    /// Skip-classified mount points: absolute mount-point path → fstype.
    skip: HashMap<String, String>,
}

impl MountTable {
    /// Build the live table from `/proc/self/mountinfo`. Best-effort: an unreadable
    /// or absent mountinfo (non-Linux, restricted, or not mounted) yields an empty
    /// table, so the walk descends everything on the device.
    #[must_use]
    pub fn live() -> Self {
        std::fs::read_to_string("/proc/self/mountinfo")
            .map_or_else(|_| Self::default(), |text| Self::from_mountinfo(&text))
    }

    /// Parse a `/proc/self/mountinfo` dump, recording only the network/pseudo mounts.
    ///
    /// Each line's mount point is field 5 and its fstype is the token after the ` - `
    /// separator (see `man 5 proc`). Unparseable lines are skipped so a malformed
    /// entry cannot abort classification.
    #[must_use]
    pub fn from_mountinfo(text: &str) -> Self {
        let mut skip: HashMap<String, String> = HashMap::new();
        for line in text.lines() {
            if let Some((mount_point, fstype)) = parse_mountinfo_line(line) {
                if is_skip_fstype(&fstype) {
                    skip.insert(mount_point, fstype);
                }
            }
        }
        Self { skip }
    }

    /// The fstype of `path` if it is a skip-classified (network/pseudo) mount point,
    /// else `None`. Matched on exact mount-point path equality.
    #[must_use]
    pub fn skip_fstype(&self, path: &Path) -> Option<String> {
        self.skip.get(path.to_string_lossy().as_ref()).cloned()
    }
}

/// Parse one `mountinfo` line into `(mount_point, fstype)`, or `None` if malformed.
///
/// Layout: `id parent major:minor root mount_point options [tag...] - fstype source
/// super_opts`. The mount point is the 5th space-separated field; the fstype is the
/// first field after the ` - ` separator.
fn parse_mountinfo_line(line: &str) -> Option<(String, String)> {
    let mut it = line.split(' ');
    let _mount_id = it.next()?;
    let _parent_id = it.next()?;
    let _major_minor = it.next()?;
    let _root = it.next()?;
    let mount_point = it.next()?;
    // Skip the optional tag fields up to the `-` separator.
    loop {
        let token = it.next()?;
        if token == "-" {
            break;
        }
    }
    let fstype = it.next()?;
    Some((unescape_mountinfo(mount_point), fstype.to_owned()))
}

/// Decode the octal escapes `mountinfo` uses for space (`\040`), tab (`\011`),
/// newline (`\012`), and backslash (`\134`) in path fields.
fn unescape_mountinfo(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        // Take the three octal digits following the backslash; if they are not a
        // recognized escape, emit the backslash and the characters verbatim.
        let d0 = chars.peek().copied();
        match d0 {
            Some('0' | '1') => {
                let a = chars.next();
                let b = chars.next();
                let c2 = chars.next();
                match (a, b, c2) {
                    (Some('0'), Some('4'), Some('0')) => out.push(' '),
                    (Some('0'), Some('1'), Some('1')) => out.push('\t'),
                    (Some('0'), Some('1'), Some('2')) => out.push('\n'),
                    (Some('1'), Some('3'), Some('4')) => out.push('\\'),
                    (a, b, c2) => {
                        out.push('\\');
                        out.extend(a);
                        out.extend(b);
                        out.extend(c2);
                    }
                }
            }
            _ => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_fstype_classifies_network_and_pseudo() {
        assert!(is_skip_fstype("nfs4"));
        assert!(is_skip_fstype("cifs"));
        assert!(is_skip_fstype("fuse.sshfs"));
        assert!(is_skip_fstype("9p"));
        assert!(is_skip_fstype("proc"));
        assert!(is_skip_fstype("sysfs"));
    }

    #[test]
    fn skip_fstype_keeps_local_filesystems() {
        // Local on-disk and tmpfs are descended, not skipped.
        for fs in ["ext4", "xfs", "btrfs", "tmpfs", "ramfs", "vfat", "f2fs"] {
            assert!(!is_skip_fstype(fs), "{fs} must be treated as local");
        }
    }

    #[test]
    fn from_mountinfo_records_only_skip_mounts() {
        // A local LVM submount (ext4), a network mount (nfs4), and a pseudo mount
        // (proc). Only the network and pseudo ones are recorded for skipping.
        let text = "\
25 30 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
36 25 0:34 / /proc rw - proc proc rw
40 25 8:5 / /var/log rw,relatime shared:2 - ext4 /dev/sdb1 rw
50 25 0:44 / /mnt/share rw - nfs4 server:/export rw
";
        let table = MountTable::from_mountinfo(text);
        // Network and pseudo are skip-classified.
        assert_eq!(
            table.skip_fstype(Path::new("/mnt/share")).as_deref(),
            Some("nfs4")
        );
        assert_eq!(
            table.skip_fstype(Path::new("/proc")).as_deref(),
            Some("proc")
        );
        // Local mounts (root and /var/log on a separate device) are NOT skipped.
        assert!(
            table.skip_fstype(Path::new("/var/log")).is_none(),
            "local submount descended"
        );
        assert!(table.skip_fstype(Path::new("/")).is_none());
    }

    #[test]
    fn mountinfo_line_parses_mount_point_and_fstype() {
        let line = "50 25 0:44 / /mnt/share rw shared:7 - nfs4 server:/export rw,vers=4";
        assert_eq!(
            parse_mountinfo_line(line),
            Some(("/mnt/share".to_owned(), "nfs4".to_owned()))
        );
    }

    #[test]
    fn mountinfo_unescapes_spaces_in_mount_point() {
        let line = "60 25 8:6 / /mnt/my\\040share rw - ext4 /dev/sdc1 rw";
        let parsed = parse_mountinfo_line(line).expect("parses");
        assert_eq!(parsed.0, "/mnt/my share");
    }

    #[test]
    fn live_table_is_best_effort_off_linux() {
        // On a host without /proc/self/mountinfo the table is simply empty (the walk
        // then descends everything on the device); it never panics.
        let _ = MountTable::live();
    }
}
