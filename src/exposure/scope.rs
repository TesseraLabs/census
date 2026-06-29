//! Scan scope: the default security-relevant roots and the pseudo-filesystem
//! roots that are always skipped.
//!
//! ## Why a curated default scope
//!
//! A full walk from `/` is expensive and noisy on a real host, and most of the
//! filesystem (`/usr/share`, package payloads, application data) carries no
//! privilege-relevant ambient permission worth auditing. The default scope is the
//! set of trees whose contents gate authentication, scheduled execution, service
//! definitions, and operator/home data — the same privileged-config surface the
//! coverage audit already cares about, widened to the directories where an ambient
//! over-permission (a world-writable `cron` spool, a readable secret) actually
//! grants something. An operator can always override with explicit roots or a full
//! walk; this is only the no-flags default.
//!
//! ## Why pseudo-filesystems are unconditionally skipped
//!
//! `/proc`, `/sys`, `/dev`, and `/run` are kernel/virtual filesystems: their inode
//! modes do not describe on-disk discretionary access to persistent objects, and
//! descending `/proc` wanders into every process. They are skipped at every scan,
//! including a full walk from `/`. Network and other foreign mounts are skipped by
//! the walker's device-boundary check (it never crosses onto another `st_dev`), not
//! by name.

use std::path::{Path, PathBuf};

/// Built-in default scan roots: the privileged, ambient-permission-bearing trees.
///
/// Curated, not exhaustive. `/etc` holds the authentication/privilege config;
/// `/var` covers the cron/at spools and service state (`/var/spool/cron`); `/opt`,
/// `/usr/local`, and `/srv` hold site/third-party software and served data; `/home`
/// and `/root` are operator home directories. Documented here so the chosen default
/// denominator is honest and reviewable.
const DEFAULT_SCAN_ROOTS: &[&str] = &[
    "/etc",
    "/var",
    "/opt",
    "/usr/local",
    "/srv",
    "/home",
    "/root",
];

/// Virtual / pseudo filesystem roots never walked: kernel-backed mounts whose inode
/// modes do not describe persistent on-disk access. Matched on absolute-path
/// equality so a same-named directory elsewhere (a hypothetical `/opt/dev`) is not
/// mistakenly skipped.
const PSEUDO_FS_ROOTS: &[&str] = &["/proc", "/sys", "/dev", "/run"];

/// The default scan roots as owned [`PathBuf`]s, used when the operator gives no
/// explicit `--root`/`--full` scope.
#[must_use]
pub fn default_roots() -> Vec<PathBuf> {
    DEFAULT_SCAN_ROOTS
        .iter()
        .copied()
        .map(PathBuf::from)
        .collect()
}

/// Whether `path` is a pseudo-filesystem root that must never be walked.
///
/// The match is exact absolute-path equality against [`PSEUDO_FS_ROOTS`]: `/proc`
/// matches, `/proc/1` does not need to (the walker never descends a skipped root),
/// and an unrelated `/srv/proc` is not skipped.
#[must_use]
pub fn is_pseudo_fs(path: &Path) -> bool {
    PSEUDO_FS_ROOTS.iter().any(|p| path == Path::new(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_roots_cover_privileged_trees() {
        let roots = default_roots();
        for expected in [
            "/etc",
            "/var",
            "/opt",
            "/usr/local",
            "/srv",
            "/home",
            "/root",
        ] {
            assert!(
                roots.iter().any(|r| r == Path::new(expected)),
                "default roots must include {expected}"
            );
        }
    }

    #[test]
    fn pseudo_fs_roots_are_skipped() {
        for p in ["/proc", "/sys", "/dev", "/run"] {
            assert!(is_pseudo_fs(Path::new(p)), "{p} must be pseudo-fs");
        }
    }

    #[test]
    fn real_trees_are_not_pseudo_fs() {
        for p in ["/etc", "/var", "/srv/proc", "/opt/dev"] {
            assert!(!is_pseudo_fs(Path::new(p)), "{p} must not be pseudo-fs");
        }
    }
}
