//! The permission index: one read-only walk of the scan roots, stat + ACL per
//! inode, reused by every query of a run.
//!
//! ## Why scan once into an index
//!
//! The exposure audit answers several questions over the same filesystem state —
//! the global posture map and per-principal exposure — and a managed-role sweep may
//! ask the per-principal question for many accounts. Re-walking the filesystem per
//! question is wasteful and risks an inconsistent view between passes. So one walk
//! builds a [`PermissionIndex`] of [`InodeRecord`]s (`path, uid, gid, mode, acl,
//! class`), and every later slice reads that in-memory index.
//!
//! ## Why the walk is injectable
//!
//! The live walk shells out to the real filesystem (read-only). Mirroring
//! `coverage.rs`'s `LiveSurface`/`FakeSurface` split, the walk sits behind the
//! [`FsWalker`] trait so unit tests build an index from an in-memory
//! [`FakeWalker`] (or a `tempfile` fixture) without touching system paths, and the
//! thin [`LiveWalker`] is exercised against controlled fixtures only.
//!
//! ## Read-only and scoping invariants
//!
//! The walk only reads metadata — it never mutates an inode. It skips
//! pseudo-filesystems ([`is_pseudo_fs`](super::scope::is_pseudo_fs)), descends local
//! submounts but skips network mounts by filesystem type
//! ([`MountTable`](super::mounts::MountTable)) while recording every skipped mount as
//! a [`SkippedMount`] notice, never follows a symlink (a symlink is neither recorded
//! nor traversed), and guards against bind-mount cycles with a visited-inode set.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::acl::{AclEntries, AclSource};
use super::mounts::MountTable;
use super::scope::is_pseudo_fs;
use super::taxonomy::Classifier;
use super::{ExposureError, ObjectClass};

/// One inode's raw stat metadata, produced by the walk before ACL/class enrichment.
///
/// This is the per-inode part of the [`FsWalker`] output: just what an `lstat`
/// yields, plus a directory flag. The richer [`InodeRecord`] is assembled from this
/// by [`PermissionIndex::build`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InodeStat {
    /// Absolute path of the inode.
    pub path: String,
    /// Owning user id.
    pub uid: u32,
    /// Owning group id.
    pub gid: u32,
    /// Raw Unix mode bits (type + permission + setuid/setgid/sticky).
    pub mode: u32,
    /// Whether this inode is a directory.
    pub is_dir: bool,
}

/// A mount point the walk did not descend, recorded so the operator knows coverage
/// was trimmed (a silent blind spot is unacceptable in a security audit).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SkippedMount {
    /// Absolute mount-point path that was not descended.
    pub path: String,
    /// The filesystem type that caused the skip (a network or pseudo type).
    pub fstype: String,
}

/// The result of a walk: the indexed inode stats plus the mounts that were skipped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalkOutcome {
    /// One stat record per reachable inode.
    pub stats: Vec<InodeStat>,
    /// Mounts the walk did not descend (network/pseudo), for the coverage notice.
    pub skipped_mounts: Vec<SkippedMount>,
}

/// A source of inode stat records for a set of scan roots.
///
/// Abstracted so the index builder is unit-testable with an in-memory
/// [`FakeWalker`]; the production [`LiveWalker`] performs the real read-only walk.
pub trait FsWalker {
    /// Walk `roots` and return the inode stats plus any skipped mounts.
    ///
    /// # Errors
    ///
    /// Returns [`ExposureError::Walk`] only if a root that exists cannot be stat'd;
    /// an absent root is skipped, and an unreadable subtree below a root is skipped
    /// rather than aborting the walk (a read-only audit must not fail wholesale on
    /// one permission-denied directory).
    fn walk(&self, roots: &[PathBuf]) -> Result<WalkOutcome, ExposureError>;
}

/// The production [`FsWalker`]: a read-only depth-first walk of each root.
///
/// Descends local submounts, skips network/pseudo mounts (recording each as a
/// notice), never follows symlinks, and guards against bind-mount cycles.
#[derive(Debug, Clone, Default)]
pub struct LiveWalker {
    /// Classification of mount points (built from `/proc/self/mountinfo`). Empty off
    /// Linux or when mountinfo is unreadable, in which case the walk simply descends
    /// everything on the device.
    mounts: MountTable,
}

impl LiveWalker {
    /// Construct the live walker, reading the live mount table best-effort.
    #[must_use]
    pub fn new() -> Self {
        Self {
            mounts: MountTable::live(),
        }
    }

    /// Construct with an explicit mount table (so the walk's mount handling is
    /// testable without real mounts).
    #[cfg(test)]
    const fn with_mounts(mounts: MountTable) -> Self {
        Self { mounts }
    }
}

impl FsWalker for LiveWalker {
    fn walk(&self, roots: &[PathBuf]) -> Result<WalkOutcome, ExposureError> {
        use std::os::unix::fs::MetadataExt;

        let mut outcome = WalkOutcome::default();
        for root in roots {
            if is_pseudo_fs(root) {
                continue;
            }
            let root_meta = match std::fs::symlink_metadata(root) {
                Ok(m) => m,
                // An absent default root (e.g. a host without `/srv`) is normal, not
                // an error — skip it.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(ExposureError::Walk {
                        root: root.display().to_string(),
                        reason: e.to_string(),
                    });
                }
            };
            let ft = root_meta.file_type();
            // A symlinked root could redirect the whole scan out of scope; skip it
            // (the file-access layer refuses symlinked roots for the same reason).
            if ft.is_symlink() {
                continue;
            }
            // A scan ROOT that is itself a network/pseudo mount (a default `/home` on
            // NFS, or an explicit `--root /mnt/share`) must not be descended — the
            // child-only `skip_fstype` check below would never see it, so a dead NFS
            // root could hang the walk. Skip it and record the notice, exactly as the
            // child-level check does, so coverage is never silently trimmed.
            if let Some(fstype) = self.mounts.skip_fstype(root) {
                outcome.skipped_mounts.push(SkippedMount {
                    path: root.to_string_lossy().into_owned(),
                    fstype,
                });
                continue;
            }

            push_stat(&root_meta, root, &mut outcome.stats);
            if !ft.is_dir() {
                continue;
            }

            // Per-root visited set of (dev, ino) to break bind-mount cycles on the
            // same device (a directory reachable via two paths is descended once).
            let mut visited: HashSet<(u64, u64)> = HashSet::new();
            visited.insert((root_meta.dev(), root_meta.ino()));

            let mut stack: Vec<PathBuf> = vec![root.clone()];
            while let Some(dir) = stack.pop() {
                // An unreadable subtree is skipped, not aborted on.
                let Ok(entries) = std::fs::read_dir(&dir) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    // Pseudo-filesystem mount points (e.g. `/proc` on a full walk)
                    // are never descended or recorded.
                    if is_pseudo_fs(&path) {
                        continue;
                    }
                    // lstat: never follow a symlink off the device or into a loop.
                    let Ok(meta) = std::fs::symlink_metadata(&path) else {
                        continue;
                    };
                    let ft = meta.file_type();
                    // A symlink is neither recorded nor followed.
                    if ft.is_symlink() {
                        continue;
                    }
                    // The inode itself is in scope (its mode matters) even when it is
                    // a mount point we will not descend.
                    push_stat(&meta, &path, &mut outcome.stats);
                    if !ft.is_dir() {
                        continue;
                    }
                    // Bind-mount cycle guard: descend each directory inode once.
                    if !enter_dir(&mut visited, meta.dev(), meta.ino()) {
                        continue;
                    }
                    // Skip only network/pseudo mounts; descend local submounts
                    // (re-anchoring naturally — a local mount is just another
                    // directory we keep walking). Record every skip as a notice.
                    if let Some(fstype) = self.mounts.skip_fstype(&path) {
                        outcome.skipped_mounts.push(SkippedMount {
                            path: path.to_string_lossy().into_owned(),
                            fstype,
                        });
                        continue;
                    }
                    stack.push(path);
                }
            }
        }
        Ok(outcome)
    }
}

/// Record a directory inode in the per-root visited set; returns `true` if it is new
/// (safe to descend) and `false` if already seen (a bind-mount cycle on the same
/// device). Hardlinked *files* are recorded under each of their paths — the guard
/// gates directory descent only, never the recording of files.
fn enter_dir(visited: &mut HashSet<(u64, u64)>, dev: u64, ino: u64) -> bool {
    visited.insert((dev, ino))
}

/// Append one inode's stat record to the accumulator.
fn push_stat(meta: &std::fs::Metadata, path: &Path, out: &mut Vec<InodeStat>) {
    use std::os::unix::fs::MetadataExt;
    out.push(InodeStat {
        path: path.to_string_lossy().into_owned(),
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode(),
        is_dir: meta.is_dir(),
    });
}

/// One inode in the permission index: its ownership, mode, parsed ACL, and object
/// class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InodeRecord {
    /// Absolute path of the inode.
    pub path: String,
    /// Owning user id.
    pub uid: u32,
    /// Owning group id.
    pub gid: u32,
    /// Raw Unix mode bits (type + permission + setuid/setgid/sticky).
    pub mode: u32,
    /// The parsed extended POSIX ACL, or `None` when the inode has only a trivial
    /// ACL (its access is fully described by the mode bits).
    pub acl: Option<AclEntries>,
    /// The object class (cron / secret / generic …). A placeholder until the
    /// classifier lands; every inode is currently [`ObjectClass::Generic`].
    pub class: ObjectClass,
}

/// An in-memory [`FsWalker`] for tests: returns the canned stats that fall at or
/// under one of the requested roots.
#[derive(Debug, Clone, Default)]
pub struct FakeWalker {
    stats: Vec<InodeStat>,
}

impl FakeWalker {
    /// An empty fake walker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one inode stat to the fake filesystem.
    #[must_use]
    pub fn with(mut self, stat: InodeStat) -> Self {
        self.stats.push(stat);
        self
    }
}

impl FsWalker for FakeWalker {
    fn walk(&self, roots: &[PathBuf]) -> Result<WalkOutcome, ExposureError> {
        let stats = self
            .stats
            .iter()
            .filter(|s| roots.iter().any(|r| stat_under_root(&s.path, r)))
            .cloned()
            .collect();
        Ok(WalkOutcome {
            stats,
            skipped_mounts: Vec::new(),
        })
    }
}

/// Whether a stat path is at or under a root, on a path-component boundary.
fn stat_under_root(path: &str, root: &Path) -> bool {
    let root = root.to_string_lossy();
    crate::catalog::path_at_or_under(&root, path)
}

/// A permission index: the inode records from one read-only walk, with by-path
/// lookup, plus the mounts skipped during the walk.
///
/// Built once per run via [`PermissionIndex::build`] and read by every later query
/// slice. The internal storage (a record vector plus a path→index map) is private;
/// callers use the accessor methods.
#[derive(Debug, Clone)]
pub struct PermissionIndex {
    records: Vec<InodeRecord>,
    by_path: HashMap<String, usize>,
    skipped_mounts: Vec<SkippedMount>,
}

impl PermissionIndex {
    /// Build the index: walk `roots`, read the ACL of every walked inode, and
    /// assemble one [`InodeRecord`] per inode.
    ///
    /// The walk and the ACL read are injected ([`FsWalker`] + [`AclSource`]) so the
    /// builder is unit-testable without touching real system paths. The ACL read is
    /// keyed to exactly the paths the walker returned and is best-effort, so it never
    /// re-descends out of scope and never aborts the build. An inode whose ACL is
    /// only trivial (no named user/group/mask) stores `None` for `acl`.
    ///
    /// # Errors
    ///
    /// Propagates [`ExposureError::Walk`] from the walker (the only fallible step).
    pub fn build<W, A>(
        walker: &W,
        acl_source: &mut A,
        roots: &[PathBuf],
    ) -> Result<Self, ExposureError>
    where
        W: FsWalker + ?Sized,
        A: AclSource + ?Sized,
    {
        Self::build_with(walker, acl_source, roots, &Classifier::default())
    }

    /// Build the index with an explicit object [`Classifier`] (so the configurable
    /// secret globs from `exposure.toml` drive each inode's class).
    ///
    /// # Errors
    ///
    /// Propagates [`ExposureError::Walk`] from the walker (the only fallible step).
    pub fn build_with<W, A>(
        walker: &W,
        acl_source: &mut A,
        roots: &[PathBuf],
        classifier: &Classifier,
    ) -> Result<Self, ExposureError>
    where
        W: FsWalker + ?Sized,
        A: AclSource + ?Sized,
    {
        let outcome = walker.walk(roots)?;
        let paths: Vec<String> = outcome.stats.iter().map(|s| s.path.clone()).collect();
        let acl_pairs = acl_source.read_acls(&paths);
        let mut acl_map: HashMap<String, AclEntries> = acl_pairs
            .into_iter()
            .map(|(path, entries)| (path.to_string_lossy().into_owned(), entries))
            .collect();

        let mut records: Vec<InodeRecord> = Vec::with_capacity(outcome.stats.len());
        let mut by_path: HashMap<String, usize> = HashMap::with_capacity(outcome.stats.len());
        for stat in outcome.stats {
            // Keep only an extended ACL; a trivial ACL adds nothing over the mode.
            let acl = acl_map.remove(&stat.path).filter(AclEntries::is_extended);
            let class = classifier.classify(&stat.path, stat.mode);
            by_path.insert(stat.path.clone(), records.len());
            records.push(InodeRecord {
                path: stat.path,
                uid: stat.uid,
                gid: stat.gid,
                mode: stat.mode,
                acl,
                class,
            });
        }
        Ok(Self {
            records,
            by_path,
            skipped_mounts: outcome.skipped_mounts,
        })
    }

    /// Build the production index: live walk + real `getfacl`, over `roots`, with the
    /// given object [`Classifier`]. Shells out (read-only); not exercised by unit
    /// tests.
    ///
    /// # Errors
    ///
    /// Propagates [`ExposureError`] from the walk.
    pub fn live(roots: &[PathBuf], classifier: &Classifier) -> Result<Self, ExposureError> {
        let walker = LiveWalker::new();
        let mut acl = super::acl::GetfaclReader::production();
        Self::build_with(&walker, &mut acl, roots, classifier)
    }

    /// The indexed inode records, in walk order.
    #[must_use]
    pub fn records(&self) -> &[InodeRecord] {
        &self.records
    }

    /// The record for an exact path, if indexed.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&InodeRecord> {
        self.by_path.get(path).and_then(|&i| self.records.get(i))
    }

    /// The mounts skipped during the walk (network/pseudo), so a caller can warn the
    /// operator that coverage was trimmed.
    #[must_use]
    pub fn skipped_mounts(&self) -> &[SkippedMount] {
        &self.skipped_mounts
    }

    /// The number of indexed inodes.
    #[allow(
        clippy::missing_const_for_fn,
        reason = "Vec::len is not const-stable on the older musl cross toolchain used for the Astra target"
    )]
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the index is empty.
    #[allow(
        clippy::missing_const_for_fn,
        reason = "Vec::is_empty is not const-stable on the older musl cross toolchain used for the Astra target"
    )]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exposure::acl::{AclEntry, AclPerms, AclTag, FakeAclSource};

    fn stat(path: &str, uid: u32, gid: u32, mode: u32, is_dir: bool) -> InodeStat {
        InodeStat {
            path: path.to_owned(),
            uid,
            gid,
            mode,
            is_dir,
        }
    }

    fn extended_acl() -> AclEntries {
        AclEntries {
            entries: vec![AclEntry {
                tag: AclTag::User("svc".to_owned()),
                perms: AclPerms {
                    read: true,
                    write: true,
                    execute: false,
                },
            }],
        }
    }

    #[test]
    fn build_indexes_records_under_roots() {
        let walker = FakeWalker::new()
            .with(stat("/etc", 0, 0, 0o040_755, true))
            .with(stat("/etc/ssh", 0, 0, 0o040_750, true))
            .with(stat("/etc/ssh/sshd_config", 0, 0, 0o100_600, false));
        let mut acl = FakeAclSource::new();
        let idx = PermissionIndex::build(&walker, &mut acl, &[PathBuf::from("/etc")])
            .expect("build over fakes never fails");
        assert_eq!(idx.len(), 3);
        assert!(!idx.is_empty());
        let rec = idx.get("/etc/ssh/sshd_config").expect("indexed");
        assert_eq!(rec.uid, 0);
        assert_eq!(rec.gid, 0);
        assert_eq!(rec.mode & 0o7777, 0o600);
        // `/etc/ssh` is a security-relevant config prefix, so the classifier now
        // assigns Config (it was Generic while the classifier was a stub).
        assert_eq!(rec.class, ObjectClass::Config);
        assert!(rec.acl.is_none(), "no ACL supplied → None");
    }

    #[test]
    fn build_scopes_to_requested_roots() {
        // A stat outside the requested root must not be indexed.
        let walker = FakeWalker::new()
            .with(stat("/etc/ssh", 0, 0, 0o040_750, true))
            .with(stat("/var/spool/cron", 0, 0, 0o041_777, true));
        let mut acl = FakeAclSource::new();
        let idx = PermissionIndex::build(&walker, &mut acl, &[PathBuf::from("/etc")])
            .expect("never fails");
        assert_eq!(idx.len(), 1);
        assert!(idx.get("/etc/ssh").is_some());
        assert!(idx.get("/var/spool/cron").is_none(), "out of root scope");
    }

    #[test]
    fn build_attaches_extended_acl_and_drops_trivial() {
        let walker = FakeWalker::new()
            .with(stat("/srv/shared", 0, 100, 0o040_770, true))
            .with(stat("/srv/plain", 0, 0, 0o100_644, false));
        // Supply an ACL for both paths; only the extended one is kept. The trivial
        // ACL (base entries only) is filtered out at build.
        let trivial = AclEntries {
            entries: vec![AclEntry {
                tag: AclTag::Other,
                perms: AclPerms::default(),
            }],
        };
        let mut acl = FakeAclSource::new()
            .with("/srv/shared", extended_acl())
            .with("/srv/plain", trivial);
        let idx = PermissionIndex::build(&walker, &mut acl, &[PathBuf::from("/srv")])
            .expect("never fails");
        assert!(
            idx.get("/srv/shared").expect("indexed").acl.is_some(),
            "extended ACL attached"
        );
        assert!(
            idx.get("/srv/plain").expect("indexed").acl.is_none(),
            "trivial ACL dropped to None"
        );
    }

    #[test]
    fn enter_dir_guard_admits_once_then_blocks_cycle() {
        // The bind-mount cycle guard: the same (dev, ino) is descended once; a second
        // arrival (a directory reachable via a second path on the same device) is
        // refused, breaking what would otherwise be an unbounded walk.
        let mut visited: HashSet<(u64, u64)> = HashSet::new();
        assert!(enter_dir(&mut visited, 42, 100), "first visit descends");
        assert!(!enter_dir(&mut visited, 42, 100), "second visit is refused");
        assert!(
            enter_dir(&mut visited, 42, 101),
            "a different inode still descends"
        );
        assert!(
            enter_dir(&mut visited, 43, 100),
            "same ino on another device descends"
        );
    }

    #[test]
    fn live_walker_indexes_tempdir_tree_and_reads_mode() {
        // A controlled `tempfile` fixture — not a real system path — exercises the
        // live walk end to end without touching the OS surface.
        let tmp = tempfile::tempdir().expect("tempdir");
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).expect("mkdir");
        let file = sub.join("data");
        std::fs::write(&file, b"x").expect("write");

        let walker = LiveWalker::new();
        let outcome = walker
            .walk(&[tmp.path().to_path_buf()])
            .expect("walk tempdir");
        let paths: Vec<&str> = outcome.stats.iter().map(|s| s.path.as_str()).collect();
        assert!(
            paths.contains(&tmp.path().to_string_lossy().as_ref()),
            "root recorded"
        );
        assert!(
            paths.contains(&sub.to_string_lossy().as_ref()),
            "subdir recorded"
        );
        assert!(
            paths.contains(&file.to_string_lossy().as_ref()),
            "file recorded"
        );

        let file_stat = outcome
            .stats
            .iter()
            .find(|s| s.path == file.to_string_lossy())
            .expect("file stat present");
        assert!(!file_stat.is_dir);
        assert_ne!(file_stat.mode & 0o170_000, 0, "mode type bits read");
    }

    #[test]
    fn live_walker_does_not_follow_symlinks() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // A directory OUTSIDE the scanned root, holding a secret file.
        let outside = tempfile::tempdir().expect("outside tempdir");
        std::fs::write(outside.path().join("secret"), b"s").expect("write secret");
        // A symlink inside the scanned root pointing at the outside directory.
        let link = tmp.path().join("escape");
        std::os::unix::fs::symlink(outside.path(), &link).expect("symlink");

        let walker = LiveWalker::new();
        let outcome = walker
            .walk(&[tmp.path().to_path_buf()])
            .expect("walk tempdir");
        assert!(
            outcome.stats.iter().all(|s| !s.path.contains("escape")),
            "symlink itself not recorded"
        );
        assert!(
            outcome.stats.iter().all(|s| !s.path.contains("secret")),
            "symlink target not followed"
        );
    }

    #[test]
    fn live_walker_skips_absent_root() {
        let walker = LiveWalker::new();
        let outcome = walker
            .walk(&[PathBuf::from("/census-nonexistent-root-xyzzy")])
            .expect("absent root is skipped, not an error");
        assert!(outcome.stats.is_empty());
        assert!(outcome.skipped_mounts.is_empty());
    }

    #[test]
    fn live_walker_descends_local_submount_and_skips_network_with_notice() {
        // Two subdirectories of the scanned root; a mocked mount table marks one as a
        // network (nfs) mount point and leaves the other unlisted (local). The walk
        // must descend the local one (its child is recorded) and skip the network one
        // (its child is NOT recorded) while noting the skip — never a silent gap.
        let tmp = tempfile::tempdir().expect("tempdir");
        let local = tmp.path().join("localsub");
        let net = tmp.path().join("netmnt");
        std::fs::create_dir(&local).expect("mkdir local");
        std::fs::create_dir(&net).expect("mkdir net");
        std::fs::write(local.join("kept"), b"k").expect("write kept");
        std::fs::write(net.join("hidden"), b"h").expect("write hidden");

        // A mountinfo dump that classifies the `netmnt` path as nfs4. The local
        // submount is absent → treated as local and descended.
        let mountinfo = format!(
            "50 25 0:44 / {} rw shared:7 - nfs4 server:/export rw\n",
            net.display()
        );
        let walker = LiveWalker::with_mounts(MountTable::from_mountinfo(&mountinfo));
        let outcome = walker.walk(&[tmp.path().to_path_buf()]).expect("walk");

        let has = |needle: &str| outcome.stats.iter().any(|s| s.path.contains(needle));
        assert!(has("localsub"), "local mount point recorded");
        assert!(has("kept"), "local submount descended → child recorded");
        assert!(has("netmnt"), "network mount point itself recorded");
        assert!(!has("hidden"), "network mount NOT descended → child absent");

        assert_eq!(
            outcome.skipped_mounts.len(),
            1,
            "the network mount is noticed"
        );
        let skipped = &outcome.skipped_mounts[0];
        assert!(skipped.path.contains("netmnt"));
        assert_eq!(skipped.fstype, "nfs4");
    }

    #[test]
    fn scan_root_that_is_a_network_mount_is_skipped_not_walked() {
        // The scan ROOT itself is a network mount (a default `/home` on NFS, or an
        // explicit `--root /mnt/share`). It must NOT be recorded or descended — the
        // child-only mount check would never see it, so a dead NFS root could hang the
        // walk. It is skipped and noted, like a child mount.
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("hidden"), b"h").expect("write");
        // Mark the root path itself as an nfs4 mount.
        let mountinfo = format!(
            "50 25 0:44 / {} rw shared:7 - nfs4 server:/export rw\n",
            tmp.path().display()
        );
        let walker = LiveWalker::with_mounts(MountTable::from_mountinfo(&mountinfo));
        let outcome = walker
            .walk(&[tmp.path().to_path_buf()])
            .expect("walk a network root");
        assert!(
            outcome.stats.is_empty(),
            "a network-mount root is not recorded or descended"
        );
        assert_eq!(
            outcome.skipped_mounts.len(),
            1,
            "the network root is noticed"
        );
        assert_eq!(outcome.skipped_mounts[0].fstype, "nfs4");
        assert!(outcome.skipped_mounts[0]
            .path
            .contains(tmp.path().file_name().unwrap().to_str().unwrap()));
    }

    #[test]
    fn build_surfaces_skipped_mounts_from_walk() {
        // The build carries the walk's skipped-mount notices through to the index so
        // a caller (the CLI) can warn the operator that coverage was trimmed.
        let tmp = tempfile::tempdir().expect("tempdir");
        let net = tmp.path().join("nfsmnt");
        std::fs::create_dir(&net).expect("mkdir");
        let mountinfo = format!(
            "60 25 0:50 / {} rw - cifs //server/share rw\n",
            net.display()
        );
        let walker = LiveWalker::with_mounts(MountTable::from_mountinfo(&mountinfo));
        let mut acl = FakeAclSource::new();
        let idx =
            PermissionIndex::build(&walker, &mut acl, &[tmp.path().to_path_buf()]).expect("build");
        assert_eq!(idx.skipped_mounts().len(), 1);
        assert_eq!(idx.skipped_mounts()[0].fstype, "cifs");
    }
}
