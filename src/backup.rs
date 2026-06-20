//! Full-file backup & restore of auth-critical files (spec R2).
//!
//! Before any mutation, `census apply` snapshots the whole of
//! `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` plus each touched
//! `/etc/sudoers.d/census-*` into a `0700 root` directory under
//! `/var/lib/census/rollback/<timestamp>/`. On any phase failure it restores
//! those files (atomic rename back) and leaves the OS in the prior consistent
//! state.
//!
//! The auth-DB path set is **injectable** so unit tests can point at tempdir
//! fake files (no root, no real `/etc`). Retention: drop the snapshot on
//! success, keep it on failure.

use std::path::{Path, PathBuf};

/// The set of files to snapshot. Injectable for tests.
#[derive(Debug, Clone)]
pub struct BackupTargets {
    /// Auth DB + sudoers files to snapshot (absolute paths in production).
    pub files: Vec<PathBuf>,
}

impl BackupTargets {
    /// The canonical production auth-DB set (no sudoers — those are added per
    /// plan). Used by the real apply path.
    pub fn auth_db_default() -> Self {
        BackupTargets {
            files: ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"]
                .iter()
                .map(PathBuf::from)
                .collect(),
        }
    }

    /// Add a touched sudoers file to the snapshot set (deduplicated).
    pub fn add_file(&mut self, path: PathBuf) {
        if !self.files.contains(&path) {
            self.files.push(path);
        }
    }
}

/// Errors from snapshot / restore.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// Could not create the snapshot directory.
    #[error("cannot create snapshot dir {path}: {reason}")]
    Mkdir {
        /// Directory path.
        path: PathBuf,
        /// OS error.
        reason: String,
    },
    /// Could not copy a file into / out of the snapshot.
    #[error("cannot copy {from} -> {to}: {reason}")]
    Copy {
        /// Source path.
        from: PathBuf,
        /// Destination path.
        to: PathBuf,
        /// OS error.
        reason: String,
    },
    /// Restore was requested but no snapshot has been taken.
    #[error("restore requested but no snapshot exists")]
    NoSnapshot,
}

/// A backup session over a set of targets and a snapshot root directory.
///
/// Lifecycle: `snapshot()` copies each existing target into
/// `<root>/<timestamp>/<sanitized-name>`; `restore()` copies them back via a
/// temp-then-rename on the same filesystem (atomic replace); `commit_success()`
/// removes the snapshot dir; `keep_on_failure()` leaves it in place.
#[derive(Debug)]
pub struct Backup {
    targets: BackupTargets,
    root: PathBuf,
    /// Set once `snapshot()` runs: the per-run snapshot directory.
    snapshot_dir: Option<PathBuf>,
    /// Records, per snapshotted file, (original_path, snapshot_copy_path).
    saved: Vec<(PathBuf, PathBuf)>,
}

impl Backup {
    /// New backup over `targets`, storing snapshots under `root`.
    pub fn new(targets: BackupTargets, root: PathBuf) -> Self {
        Backup {
            targets,
            root,
            snapshot_dir: None,
            saved: Vec::new(),
        }
    }

    /// Whether a snapshot has been taken.
    pub fn has_snapshot(&self) -> bool {
        self.snapshot_dir.is_some()
    }

    /// Snapshot every existing target file. Missing files are skipped (they
    /// must be absent again after restore — recorded so restore can remove a
    /// file that the mutation may have created). The snapshot dir is created
    /// `0700`.
    pub fn snapshot(&mut self) -> Result<(), BackupError> {
        let dir = self.root.join(timestamp_component());
        create_dir_0700(&dir)?;
        let mut saved = Vec::new();
        for (i, original) in self.targets.files.iter().enumerate() {
            // Sanitize: a unique, collision-free name per index keeps copies flat.
            let copy_name = format!("{i:03}-{}", sanitize(original));
            let copy_path = dir.join(copy_name);
            if original.exists() {
                copy_file(original, &copy_path)?;
            }
            // Record regardless of existence: restore reproduces the prior
            // presence/absence exactly.
            saved.push((original.clone(), copy_path));
        }
        self.snapshot_dir = Some(dir);
        self.saved = saved;
        Ok(())
    }

    /// Restore every snapshotted file to its original path. Files that existed
    /// in the snapshot are atomically replaced; files that did NOT exist at
    /// snapshot time are removed (best-effort) so the prior state is exact.
    pub fn restore(&mut self) -> Result<(), BackupError> {
        if self.snapshot_dir.is_none() {
            return Err(BackupError::NoSnapshot);
        }
        for (original, copy_path) in &self.saved {
            if copy_path.exists() {
                atomic_replace(copy_path, original)?;
            } else {
                // Did not exist at snapshot time → ensure it does not exist now.
                let _ = std::fs::remove_file(original);
            }
        }
        Ok(())
    }

    /// Success path: drop the snapshot directory (retention policy).
    pub fn commit_success(&mut self) {
        if let Some(dir) = self.snapshot_dir.take() {
            let _ = std::fs::remove_dir_all(&dir);
        }
        self.saved.clear();
    }

    /// Failure path: keep the snapshot directory for forensics. Returns its path.
    pub fn keep_on_failure(&self) -> Option<&Path> {
        self.snapshot_dir.as_deref()
    }
}

/// A filesystem-safe component for a path (used as a flat snapshot copy name).
fn sanitize(path: &Path) -> String {
    path.to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// A monotonic-ish timestamp directory component. Falls back to a fixed token
/// if the clock is unavailable (no panic).
fn timestamp_component() -> String {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => format!("{}-{:09}", d.as_secs(), d.subsec_nanos()),
        Err(_) => "snapshot".to_owned(),
    }
}

#[cfg(unix)]
fn create_dir_0700(dir: &Path) -> Result<(), BackupError> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| BackupError::Mkdir {
            path: dir.to_path_buf(),
            reason: e.to_string(),
        })
}

#[cfg(not(unix))]
fn create_dir_0700(dir: &Path) -> Result<(), BackupError> {
    std::fs::create_dir_all(dir).map_err(|e| BackupError::Mkdir {
        path: dir.to_path_buf(),
        reason: e.to_string(),
    })
}

fn copy_file(from: &Path, to: &Path) -> Result<(), BackupError> {
    std::fs::copy(from, to).map(|_| ()).map_err(|e| BackupError::Copy {
        from: from.to_path_buf(),
        to: to.to_path_buf(),
        reason: e.to_string(),
    })
}

/// Atomically replace `dest` with the contents of `src`: copy to a temp sibling
/// of `dest`, then rename over `dest` (same filesystem → atomic).
fn atomic_replace(src: &Path, dest: &Path) -> Result<(), BackupError> {
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(
        ".census-restore-{}",
        dest.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "tmp".to_owned())
    ));
    copy_file(src, &tmp)?;
    std::fs::rename(&tmp, dest).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        BackupError::Copy {
            from: tmp.clone(),
            to: dest.to_path_buf(),
            reason: e.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(path: &Path, body: &[u8]) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(body).unwrap();
    }

    #[test]
    fn snapshot_mutate_restore_is_byte_identical() {
        let tmp = tempfile::tempdir().unwrap();
        let etc = tmp.path().join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        let passwd = etc.join("passwd");
        let shadow = etc.join("shadow");
        write(&passwd, b"root:x:0:0:root:/root:/bin/bash\n");
        write(&shadow, b"root:!:19000:0:99999:7:::\n");

        let targets = BackupTargets {
            files: vec![passwd.clone(), shadow.clone()],
        };
        let mut backup = Backup::new(targets, tmp.path().join("rollback"));
        backup.snapshot().unwrap();
        assert!(backup.has_snapshot());

        // Mutate both files (simulate shadow-utils).
        write(&passwd, b"CORRUPTED\n");
        write(&shadow, b"CORRUPTED\n");

        backup.restore().unwrap();
        assert_eq!(std::fs::read(&passwd).unwrap(), b"root:x:0:0:root:/root:/bin/bash\n");
        assert_eq!(std::fs::read(&shadow).unwrap(), b"root:!:19000:0:99999:7:::\n");
    }

    #[test]
    fn restore_removes_file_absent_at_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let sudoers = tmp.path().join("census-oper");
        // Did NOT exist at snapshot.
        let targets = BackupTargets { files: vec![sudoers.clone()] };
        let mut backup = Backup::new(targets, tmp.path().join("rollback"));
        backup.snapshot().unwrap();
        // Mutation creates it.
        write(&sudoers, b"oper ALL=(ALL) CENSUS_OPS\n");
        assert!(sudoers.exists());
        backup.restore().unwrap();
        assert!(!sudoers.exists(), "file absent at snapshot must be removed on restore");
    }

    #[test]
    fn restore_without_snapshot_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let mut backup = Backup::new(
            BackupTargets { files: vec![] },
            tmp.path().join("rollback"),
        );
        assert!(matches!(backup.restore().unwrap_err(), BackupError::NoSnapshot));
    }

    #[test]
    fn commit_success_drops_snapshot_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("passwd");
        write(&f, b"x\n");
        let mut backup = Backup::new(
            BackupTargets { files: vec![f] },
            tmp.path().join("rollback"),
        );
        backup.snapshot().unwrap();
        let dir = backup.snapshot_dir.clone().unwrap();
        assert!(dir.exists());
        backup.commit_success();
        assert!(!dir.exists(), "snapshot dropped on success");
        assert!(!backup.has_snapshot());
    }

    #[test]
    fn keep_on_failure_retains_snapshot_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("passwd");
        write(&f, b"x\n");
        let mut backup = Backup::new(
            BackupTargets { files: vec![f] },
            tmp.path().join("rollback"),
        );
        backup.snapshot().unwrap();
        let kept = backup.keep_on_failure().unwrap().to_path_buf();
        assert!(kept.exists(), "snapshot retained on failure");
    }

    #[test]
    fn add_file_dedups() {
        let mut t = BackupTargets { files: vec![PathBuf::from("/etc/passwd")] };
        t.add_file(PathBuf::from("/etc/sudoers.d/census-oper"));
        t.add_file(PathBuf::from("/etc/sudoers.d/census-oper"));
        assert_eq!(t.files.len(), 2);
    }
}
