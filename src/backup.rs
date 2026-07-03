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
#[non_exhaustive]
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

    /// Whether a snapshot has been taken. Test-only inspector for the rollback
    /// state (production drives rollback through the apply orchestrator, not by
    /// querying this).
    #[cfg(test)]
    pub fn has_snapshot(&self) -> bool {
        self.snapshot_dir.is_some()
    }

    /// Add a touched file (e.g. a `census-<role>` sudoers fragment) to the
    /// snapshot target set, deduplicated. Must be called BEFORE [`Backup::snapshot`]
    /// — files added after a snapshot is taken are not captured by it.
    pub fn add_file(&mut self, path: PathBuf) {
        self.targets.add_file(path);
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
                // Best-effort: an already-absent file is the desired state; any
                // other removal failure is logged but never fails the restore.
                if let Err(e) = std::fs::remove_file(original) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(
                            path = %original.display(),
                            error = %e,
                            "restore: failed to remove file absent at snapshot time"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Success path: drop the snapshot directory (retention policy).
    pub fn commit_success(&mut self) {
        if let Some(dir) = self.snapshot_dir.take() {
            // Best-effort cleanup: a retained snapshot dir is harmless (forensics
            // only) and must never turn a successful apply into a failure. A
            // `NotFound` is expected; anything else is logged.
            if let Err(e) = std::fs::remove_dir_all(&dir) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(
                        path = %dir.display(),
                        error = %e,
                        "failed to remove snapshot directory after successful apply"
                    );
                }
            }
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

/// A monotonic-ish timestamp directory component. If the clock reads before the
/// Unix epoch (so a duration is unavailable), fall back to a per-process,
/// per-call unique token `snapshot-<pid>-<n>` instead of a constant string —
/// otherwise two snapshots taken under a broken clock would target the same
/// directory and the second would clobber the first. Never panics.
fn timestamp_component() -> String {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => format!("{}-{:09}", d.as_secs(), d.subsec_nanos()),
        Err(_) => {
            static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            format!("snapshot-{}-{n}", std::process::id())
        }
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
    std::fs::copy(from, to)
        .map(|_| ())
        .map_err(|e| BackupError::Copy {
            from: from.to_path_buf(),
            to: to.to_path_buf(),
            reason: e.to_string(),
        })
}

/// Atomically replace `dest` with the contents of `src`: write to a temp sibling
/// of `dest`, then rename over `dest` (same filesystem → atomic).
///
/// The temp is created with `create_new(true)` (O_EXCL): the open fails if the
/// path already exists, including a symlink, so a pre-planted link at the
/// predictable temp name can never be followed to clobber an arbitrary file —
/// the same guard `sudoers::open_excl` uses for privileged writes. A stale
/// REGULAR temp (left by a crashed prior restore) is removed and the open
/// retried once; removing a symlink at that path drops the link, never its
/// target, so the retry creates a fresh real file.
fn atomic_replace(src: &Path, dest: &Path) -> Result<(), BackupError> {
    use std::io::Write;
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(
        ".census-restore-{}",
        dest.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "tmp".to_owned())
    ));

    let bytes = std::fs::read(src).map_err(|e| BackupError::Copy {
        from: src.to_path_buf(),
        to: tmp.clone(),
        reason: e.to_string(),
    })?;

    let mut file = match open_restore_temp(&tmp) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Stale temp or a planted symlink — drop the path entry and retry.
            cleanup_temp(&tmp);
            open_restore_temp(&tmp).map_err(|e| BackupError::Copy {
                from: src.to_path_buf(),
                to: tmp.clone(),
                reason: e.to_string(),
            })?
        }
        Err(e) => {
            return Err(BackupError::Copy {
                from: src.to_path_buf(),
                to: tmp.clone(),
                reason: e.to_string(),
            })
        }
    };
    file.write_all(&bytes).map_err(|e| {
        cleanup_temp(&tmp);
        BackupError::Copy {
            from: src.to_path_buf(),
            to: tmp.clone(),
            reason: e.to_string(),
        }
    })?;

    // Match the replacement file to the permissions and ownership of the file it
    // replaces. The temp was created owner-only (0600); renaming it in as-is would
    // strip, for example, /etc/shadow's group-read (0640 root:shadow) — but worse,
    // any file whose prior mode was more permissive would be silently narrowed, and
    // a default-created temp would EXPOSE an auth file (0644) to every local user.
    // Re-applying the destination's existing mode/owner keeps the restored file
    // exactly as protected as the one it stands in for; a target that did not exist
    // yet stays at the restrictive 0600 the temp was created with.
    //
    // Applied to the still-open descriptor before it is dropped: a path-based
    // chown/chmod after close would leave a window in which the predictably-named
    // temp could be swapped for a symlink by anyone who can write the parent dir,
    // redirecting the ownership/mode change onto the link target. Operating on the
    // fd removes that window entirely.
    preserve_dest_permissions(&file, dest).map_err(|e| {
        cleanup_temp(&tmp);
        BackupError::Copy {
            from: src.to_path_buf(),
            to: dest.to_path_buf(),
            reason: e.to_string(),
        }
    })?;
    drop(file);

    std::fs::rename(&tmp, dest).map_err(|e| {
        cleanup_temp(&tmp);
        BackupError::Copy {
            from: tmp.clone(),
            to: dest.to_path_buf(),
            reason: e.to_string(),
        }
    })
}

/// Open the restore temp for writing, failing if the path already exists (O_EXCL).
///
/// On Unix the file is created owner-only (0600) so a restored auth file is never
/// world-readable for the window between creation and applying its real mode.
fn open_restore_temp(tmp: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(tmp)
}

/// Copy `dest`'s existing mode, owner, and group onto the open temp `file` before
/// the rename.
///
/// Owner/group is set before the mode so that setuid/setgid bits (which the kernel
/// clears on ownership change) survive. Both are applied to the open file
/// descriptor — `fchown` for ownership, the fd-based [`std::fs::File::set_permissions`]
/// for the mode — never by path, so the predictable temp name cannot be swapped for
/// a symlink between close and a path-based call. A destination that does not exist
/// yet has no prior permissions to copy; the temp keeps the restrictive 0600 it was
/// created with rather than defaulting to a world-readable mode.
#[cfg(unix)]
fn preserve_dest_permissions(file: &std::fs::File, dest: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(dest) {
        Ok(meta) => {
            // `fchown` acts on the open descriptor (the crate forbids `unsafe`, so
            // this uses rustix's safe wrapper rather than a raw libc call). Ownership
            // before mode, so setuid/setgid survive the chmod.
            rustix::fs::fchown(
                file,
                Some(rustix::fs::Uid::from_raw(meta.uid())),
                Some(rustix::fs::Gid::from_raw(meta.gid())),
            )?;
            file.set_permissions(std::fs::Permissions::from_mode(meta.mode() & 0o7777))?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(not(unix))]
fn preserve_dest_permissions(_file: &std::fs::File, _dest: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Best-effort removal of a leftover backup temp file. Never propagates — a
/// cleanup failure must not mask the primary copy error. A `NotFound` is the
/// expected race (already gone / consumed by the rename) and is silent; any
/// other failure is logged at warn so a leaked temp file is visible.
fn cleanup_temp(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(path = %path.display(), error = %e, "failed to remove backup temp file");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

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
        assert_eq!(
            std::fs::read(&passwd).unwrap(),
            b"root:x:0:0:root:/root:/bin/bash\n"
        );
        assert_eq!(
            std::fs::read(&shadow).unwrap(),
            b"root:!:19000:0:99999:7:::\n"
        );
    }

    #[test]
    fn restore_removes_file_absent_at_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let sudoers = tmp.path().join("census-oper");
        // Did NOT exist at snapshot.
        let targets = BackupTargets {
            files: vec![sudoers.clone()],
        };
        let mut backup = Backup::new(targets, tmp.path().join("rollback"));
        backup.snapshot().unwrap();
        // Mutation creates it.
        write(&sudoers, b"oper ALL=(ALL) CENSUS_OPS\n");
        assert!(sudoers.exists());
        backup.restore().unwrap();
        assert!(
            !sudoers.exists(),
            "file absent at snapshot must be removed on restore"
        );
    }

    #[test]
    fn restore_without_snapshot_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let mut backup = Backup::new(BackupTargets { files: vec![] }, tmp.path().join("rollback"));
        assert!(matches!(
            backup.restore().unwrap_err(),
            BackupError::NoSnapshot
        ));
    }

    #[test]
    #[cfg(unix)]
    fn atomic_replace_does_not_follow_symlink_at_temp() {
        // Pre-plant a symlink at the predictable restore-temp path pointing at a
        // victim file outside the operation. The O_EXCL create must NOT write
        // through the link: the victim is left untouched and dest still gets the
        // src contents (the link is removed and a fresh real temp is created).
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        write(&src, b"NEW CONTENTS\n");
        let dest = tmp.path().join("passwd");
        write(&dest, b"OLD\n");

        let victim = tmp.path().join("victim");
        write(&victim, b"DO NOT TOUCH\n");

        // The temp name atomic_replace derives for `dest`.
        let temp = tmp.path().join(".census-restore-passwd");
        std::os::unix::fs::symlink(&victim, &temp).unwrap();

        atomic_replace(&src, &dest).unwrap();

        // The victim the symlink pointed at was never written through.
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"DO NOT TOUCH\n",
            "O_EXCL temp must not follow the planted symlink to the victim"
        );
        // dest got the new contents via the fresh real temp.
        assert_eq!(std::fs::read(&dest).unwrap(), b"NEW CONTENTS\n");
    }

    #[test]
    #[cfg(unix)]
    fn restore_preserves_mode_and_owner_of_replaced_file() {
        // A rollback must put the auth DB files back with the SAME permissions they
        // had, not a default world-readable mode. /etc/shadow is 0640 root:shadow;
        // restoring it 0644 would expose password hashes to every local user.
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let shadow = tmp.path().join("shadow");
        write(&shadow, b"root:$6$hash:19000:0:99999:7:::\n");
        std::fs::set_permissions(&shadow, std::fs::Permissions::from_mode(0o640)).unwrap();
        let orig_uid = std::fs::metadata(&shadow).unwrap().uid();
        let orig_gid = std::fs::metadata(&shadow).unwrap().gid();

        let targets = BackupTargets {
            files: vec![shadow.clone()],
        };
        let mut backup = Backup::new(targets, tmp.path().join("rollback"));
        backup.snapshot().unwrap();

        // Corrupt the live file (File::create truncates but keeps the 0640 mode).
        write(&shadow, b"CORRUPTED\n");
        backup.restore().unwrap();

        let restored = std::fs::metadata(&shadow).unwrap();
        assert_eq!(
            restored.mode() & 0o7777,
            0o640,
            "restored auth file must keep its original mode, not become world-readable"
        );
        assert_eq!(restored.uid(), orig_uid, "owner must be preserved");
        assert_eq!(restored.gid(), orig_gid, "group must be preserved");
        assert_eq!(
            std::fs::read(&shadow).unwrap(),
            b"root:$6$hash:19000:0:99999:7:::\n"
        );
    }

    #[test]
    #[cfg(unix)]
    fn atomic_replace_of_fresh_dest_is_owner_only() {
        // Restoring a file that did not exist at snapshot time (so has no prior mode
        // to copy) must land restrictive (0600), never the default world-readable
        // create mode.
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        write(&src, b"secret\n");
        let dest = tmp.path().join("newfile");
        // dest does not exist yet.
        atomic_replace(&src, &dest).unwrap();

        let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o7777;
        assert_eq!(
            mode, 0o600,
            "a freshly created restore target must be owner-only"
        );
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
        let mut t = BackupTargets {
            files: vec![PathBuf::from("/etc/passwd")],
        };
        t.add_file(PathBuf::from("/etc/sudoers.d/census-oper"));
        t.add_file(PathBuf::from("/etc/sudoers.d/census-oper"));
        assert_eq!(t.files.len(), 2);
    }
}
