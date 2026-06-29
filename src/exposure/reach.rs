//! Reachability: whether a principal can actually traverse to an inode.
//!
//! ## Why reachability is separate from the access check
//!
//! A permissive mode on an inode means nothing if the principal cannot walk the
//! directory chain to it. A file mode `0777` sitting under a directory `0700` owned
//! by root is unreachable to anyone else — the naive `find -perm` view would flag it,
//! but it is not real exposure. So an inode counts as reachable only when **every
//! ancestor directory** from the scan root down to the inode's parent grants the
//! principal effective `x` (search) by the same [`effective`] check the access
//! verdict uses.
//!
//! ## Memoization
//!
//! Reachability is a tree property: a directory is reachable-and-traversable iff its
//! parent is and it grants `x`. [`Reachability::compute`] walks the index once,
//! memoizing the reachable-and-traversable verdict per directory so each directory's
//! `x` is evaluated once regardless of how many inodes sit under it. `uid 0`
//! short-circuits to everything reachable.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::catalog::path_at_or_under;

use super::access::{effective, Principal};
use super::index::PermissionIndex;

/// The set of inode paths a principal can actually reach, computed once over an
/// index.
///
/// An inode is reachable when every ancestor directory from the scan root to its
/// parent grants the principal effective `x`. A later slice consults
/// [`Reachability::is_reachable`] so it never reports a finding on an unreachable
/// object.
#[derive(Debug, Clone)]
pub struct Reachability {
    reachable: HashSet<String>,
}

impl Reachability {
    /// Compute reachability for `principal` over `index`, given the scan `roots` that
    /// bound the ancestor climb.
    #[must_use]
    pub fn compute(index: &PermissionIndex, principal: &Principal, roots: &[PathBuf]) -> Self {
        let roots: Vec<String> = roots
            .iter()
            .map(|r| r.to_string_lossy().into_owned())
            .collect();
        let mut reachable: HashSet<String> = HashSet::new();

        if principal.uid == 0 {
            // Root reaches everything; no traversal check needed.
            for rec in index.records() {
                reachable.insert(rec.path.clone());
            }
            return Self { reachable };
        }

        let mut dir_cache: HashMap<String, bool> = HashMap::new();
        for rec in index.records() {
            let parent = parent_dir(&rec.path).to_owned();
            if reachable_dir(&parent, index, principal, &roots, &mut dir_cache) {
                reachable.insert(rec.path.clone());
            }
        }
        Self { reachable }
    }

    /// Whether `path` is reachable for the principal this was computed for.
    #[must_use]
    pub fn is_reachable(&self, path: &str) -> bool {
        self.reachable.contains(path)
    }

    /// The number of reachable inodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.reachable.len()
    }

    /// Whether nothing is reachable.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.reachable.is_empty()
    }
}

/// Whether directory `path` is reachable AND traversable: every ancestor up to the
/// scan root (inclusive) grants `x`, and so does `path` itself.
///
/// A `path` outside every scan root is the boundary above a root and is treated as
/// reachable (the climb stops there). The verdict is memoized in `cache`.
fn reachable_dir(
    path: &str,
    index: &PermissionIndex,
    principal: &Principal,
    roots: &[String],
    cache: &mut HashMap<String, bool>,
) -> bool {
    // Above the scan root: the boundary is reachable by definition (the climb stops).
    if !within_scope(path, roots) {
        return true;
    }
    if let Some(&cached) = cache.get(path) {
        return cached;
    }
    let parent = parent_dir(path);
    let verdict = if parent == path {
        // Top of the tree (`/`, or any single-component root whose `parent_dir` is
        // itself): there is no ancestor to climb, so reachability is just this
        // directory's own search bit. Terminating here BEFORE recursing is what
        // prevents an unbounded self-recursion on a `--full` / `--root /` scan.
        has_search(path, index, principal)
    } else {
        let parent = parent.to_owned();
        reachable_dir(&parent, index, principal, roots, cache) && has_search(path, index, principal)
    };
    cache.insert(path.to_owned(), verdict);
    verdict
}

/// Whether the principal has effective `x` (directory search) on the indexed inode at
/// `path`. An inode missing from the index (unreadable or skipped) yields `false` —
/// an unevaluable ancestor blocks reachability rather than fabricating traversal.
fn has_search(path: &str, index: &PermissionIndex, principal: &Principal) -> bool {
    index
        .get(path)
        .is_some_and(|rec| effective(rec, principal).access.execute)
}

/// Whether `path` is at or under any scan root (on a path-component boundary).
fn within_scope(path: &str, roots: &[String]) -> bool {
    roots.iter().any(|r| path_at_or_under(r, path))
}

/// The parent directory of a path (`/etc/ssh/sshd_config` → `/etc/ssh`). A top-level
/// path yields `/`; a path with no `/` yields itself.
fn parent_dir(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some(("", _)) => "/",
        Some((parent, _)) => parent,
        None => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exposure::access::ResolvedGroup;
    use crate::exposure::index::{FakeWalker, InodeStat};
    use crate::exposure::FakeAclSource;

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

    fn stat(path: &str, uid: u32, gid: u32, mode: u32, is_dir: bool) -> InodeStat {
        InodeStat {
            path: path.to_owned(),
            uid,
            gid,
            mode,
            is_dir,
        }
    }

    /// Build an index from canned stats (no ACLs) over a single root.
    fn index_of(stats: Vec<InodeStat>, root: &str) -> (PermissionIndex, Vec<PathBuf>) {
        let mut walker = FakeWalker::new();
        for s in stats {
            walker = walker.with(s);
        }
        let mut acl = FakeAclSource::new();
        let roots = vec![PathBuf::from(root)];
        let idx = PermissionIndex::build(&walker, &mut acl, &roots).expect("build");
        (idx, roots)
    }

    #[test]
    fn file_behind_closed_ancestor_is_unreachable() {
        // Root /p is mode 0700 owned by root; the file /p/f under it is mode 0777.
        // A non-root, non-owner principal cannot traverse /p, so /p/f is unreachable
        // and must NOT be a finding.
        let (idx, roots) = index_of(
            vec![
                stat("/p", 0, 0, 0o040_700, true),
                stat("/p/f", 0, 0, 0o100_777, false),
            ],
            "/p",
        );
        let r = Reachability::compute(&idx, &principal("bob", 1001, &[]), &roots);
        assert!(
            !r.is_reachable("/p/f"),
            "file behind 0700 root is unreachable"
        );
        // The root inode itself is reachable to stat (you were handed it), but its
        // children are gated by its missing x.
        assert!(r.is_reachable("/p"), "the root object itself is reachable");
    }

    #[test]
    fn all_ancestors_traversable_makes_target_reachable() {
        // Every ancestor is world-traversable (0755 dirs); the deep file is reached.
        let (idx, roots) = index_of(
            vec![
                stat("/p", 0, 0, 0o040_755, true),
                stat("/p/a", 0, 0, 0o040_755, true),
                stat("/p/a/f", 0, 0, 0o100_666, false),
            ],
            "/p",
        );
        let r = Reachability::compute(&idx, &principal("bob", 1001, &[]), &roots);
        assert!(r.is_reachable("/p/a/f"), "all ancestors give x → reachable");
    }

    #[test]
    fn group_x_on_ancestor_enables_reachability() {
        // The middle directory grants search only to group app (0710); a principal in
        // app can traverse it, a stranger cannot.
        let stats = vec![
            stat("/p", 0, 0, 0o040_755, true),
            stat("/p/a", 0, 50, 0o040_710, true),
            stat("/p/a/f", 0, 0, 0o100_666, false),
        ];
        let (idx, roots) = index_of(stats.clone(), "/p");
        let member = Reachability::compute(&idx, &principal("bob", 1001, &[("app", 50)]), &roots);
        assert!(
            member.is_reachable("/p/a/f"),
            "group member traverses 0710 dir"
        );

        let (idx2, roots2) = index_of(stats, "/p");
        let stranger = Reachability::compute(&idx2, &principal("eve", 1002, &[]), &roots2);
        assert!(
            !stranger.is_reachable("/p/a/f"),
            "non-member cannot traverse 0710 dir"
        );
    }

    #[test]
    fn root_uid_reaches_everything() {
        let (idx, roots) = index_of(
            vec![
                stat("/p", 0, 0, 0o040_700, true),
                stat("/p/f", 0, 0, 0o100_600, false),
            ],
            "/p",
        );
        let r = Reachability::compute(&idx, &principal("root", 0, &[]), &roots);
        assert!(r.is_reachable("/p/f"));
        assert_eq!(r.len(), 2);
        assert!(!r.is_empty());
    }

    #[test]
    fn root_filesystem_scope_does_not_recurse_forever() {
        // `--root /` for a non-root principal: `/` is its own parent, so the climb
        // must terminate at `/` instead of recursing into itself (the stack-overflow
        // regression). With `/` world-searchable, a top-level entry's reachability is
        // decided by the x bits on `/` and on itself.
        let (idx, roots) = index_of(
            vec![
                stat("/", 0, 0, 0o040_755, true),
                stat("/etc", 0, 0, 0o040_755, true),
                stat("/etc/passwd", 0, 0, 0o100_644, false),
            ],
            "/",
        );
        let r = Reachability::compute(&idx, &principal("bob", 1001, &[]), &roots);
        assert!(
            r.is_reachable("/etc"),
            "/ and /etc both give x → /etc reachable"
        );
        assert!(
            r.is_reachable("/etc/passwd"),
            "deep entry reachable under world-x /"
        );
    }

    #[test]
    fn root_filesystem_scope_closed_root_blocks_children() {
        // The same `--root /` shape but `/` is mode 0700 owned by root: a non-root
        // principal cannot search it, so everything below is unreachable — and the
        // computation still terminates (no infinite recursion).
        let (idx, roots) = index_of(
            vec![
                stat("/", 0, 0, 0o040_700, true),
                stat("/etc", 0, 0, 0o040_755, true),
            ],
            "/",
        );
        let r = Reachability::compute(&idx, &principal("bob", 1001, &[]), &roots);
        assert!(!r.is_reachable("/etc"), "/ closed → /etc unreachable");
    }
}
