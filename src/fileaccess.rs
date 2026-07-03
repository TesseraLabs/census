//! File-access enforcement SPI and the open built-in `AclBackend`.
//!
//! The catalog declares *what* file access a role gets ([`crate::catalog`]
//! resolves `[[file]]` grants into [`ResolvedFileGrant`]s); a *backend* decides
//! *how* to enforce it. This split mirrors the MAC-mask design (open core + SPI +
//! a commercial signed-`.so` backend): the open `AclBackend` enforces **directory**
//! grants via POSIX ACL, and per-file / pattern / real-time enforcement are
//! capability-gated upsell backends.
//!
//! ## Why directory-only in the open backend
//!
//! POSIX ACL hangs on the inode. Editing a file through rename (vim, `sed -i`,
//! `sudoedit`) creates a *new* inode, dropping any ACL set on the old one. On a
//! single file this cannot be fixed without a default-ACL on the parent — i.e. a
//! grant on the whole directory. On a *directory* it is fixed: a default-ACL is
//! inherited by every new file in the tree, so the grant survives edit-via-rename
//! and log rotation. The reliable open unit is therefore the directory, and the
//! `AclBackend` declares `rewrite_proof: true` for exactly that reason. File and
//! pattern grants are refused here (capability `false`) and routed to a capable
//! backend by [`route_grants`], or rejected fail-closed if none is installed.
//!
//! ## Why argv-only and `--physical`
//!
//! Every `setfacl`/`getfacl` invocation is built as an explicit argv vector and run
//! without a shell, so a path or account can never be reinterpreted as shell
//! syntax. `-R --physical` makes the recursive walk refuse to follow symlinks out
//! of the tree, so a symlink planted inside a granted directory cannot redirect the
//! ACL mutation onto an out-of-tree target as root.
//!
//! `--physical` only protects the in-tree walk, though: it still resolves any
//! symlink in the path it is *handed* before walking. So before each invocation the
//! grant path's ancestor chain is canonicalized once and the command targets that
//! resolved path (see [`resolve_grant_path`]). This tolerates benign symlinked
//! parents (`/home` → `/export/home`) — the resolved path no longer traverses an
//! attacker-swappable symlink — while still refusing a symlinked grant *target*,
//! which a recursive ACL would otherwise follow onto its link target.
//!
//! ## Why gating fails closed
//!
//! If no installed backend declares the capability a grant's shape requires,
//! [`route_grants`] returns [`FileAccessError::Unsupported`] *before any mutation*
//! rather than silently applying a weaker, rewrite-prone ACL. The principle is
//! "degradation in the open build is an honest refusal, not a quiet narrowing":
//! Census never materializes partial or unreliable access in place of what was
//! requested.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::catalog::{Access, ResolvedFileGrant, Shape};

/// An ACL principal: the role-account (`u:`) or the group (`g:`) a grant is
/// materialized for. The access semantics are identical — the same `-R --physical`
/// recursive walk, the same default-ACL inheritance pass, the same `-x` removal on
/// revoke — and only the entry prefix differs (`u:<account>` vs `g:<group>`). This
/// mirror is the whole point: a group grant is a user grant with a different first
/// letter, nothing else changes.
///
/// A principal's qualifier is either a *name* (`User`/`Group`) or a *numeric id*
/// (`Uid`/`Gid`). Materialization always uses the name (readable, and the account
/// exists at that point). Revocation of a principal that has already been removed
/// from the system databases must use the numeric id: `setfacl` resolves a named
/// qualifier through `getpwnam`/`getgrnam`, so once the account or group is gone
/// the name no longer resolves and `setfacl -x u:<name>` is rejected as an invalid
/// argument. The kernel stores every ACL entry by numeric id regardless, so
/// `setfacl -x u:<uid>` precisely targets the orphaned entry without needing the
/// name to resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// A role-account by name; materialized as `u:<account>`.
    User(String),
    /// A Unix group by name; materialized as `g:<group>`. Every member (including
    /// effectively-nested LDAP members) inherits the access.
    Group(String),
    /// A role-account by numeric UID; rendered as `u:<uid>`. Used to revoke the ACL
    /// entry of an account that has already been deleted, when the name no longer
    /// resolves.
    Uid(u32),
    /// A Unix group by numeric GID; rendered as `g:<gid>`. Used to revoke the ACL
    /// entry of a group that has already been removed, when the name no longer
    /// resolves.
    Gid(u32),
}

impl Principal {
    /// The ACL entry prefix: `"u"` for a user (named or numeric), `"g"` for a group.
    /// The single point where the `u:`/`g:` mirror diverges.
    pub fn acl_prefix(&self) -> &'static str {
        match self {
            Principal::User(_) | Principal::Uid(_) => "u",
            Principal::Group(_) | Principal::Gid(_) => "g",
        }
    }

    /// The qualifier placed after the prefix in the ACL entry: the name for a named
    /// principal, the decimal id for a numeric one. This is what `setfacl` parses, so
    /// a numeric qualifier lets a revoke succeed after the principal's name has been
    /// removed from the passwd/group databases.
    pub fn qualifier(&self) -> String {
        match self {
            Principal::User(name) | Principal::Group(name) => name.clone(),
            Principal::Uid(id) | Principal::Gid(id) => id.to_string(),
        }
    }

    /// A human-facing label for logging: the name for a named principal, the decimal
    /// id (uid/gid) for a numeric one.
    pub fn name(&self) -> String {
        self.qualifier()
    }
}

/// What a backend can enforce. Each grant [`Shape`] maps to one capability that a
/// covering backend must declare (`Dir` → `dir`, `File` → `per_path`,
/// `Pattern` → `pattern`). `realtime` and `rewrite_proof` are advisory guarantees
/// surfaced in coverage/reporting, not routing keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Enforces directory grants (recursive + inheritance).
    pub dir: bool,
    /// Enforces a grant on one concrete file.
    pub per_path: bool,
    /// Enforces a grant on a glob pattern.
    pub pattern: bool,
    /// Re-applies access in real time (in the write path), not post-facto.
    pub realtime: bool,
    /// New files in a granted tree inherit the access (survives rewrite/rotation).
    pub rewrite_proof: bool,
}

/// Errors materializing, revoking, or snapshotting file access.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FileAccessError {
    /// No installed backend can enforce a grant of this shape. Carries a message
    /// suggesting how to proceed (widen a file grant to its directory, or install a
    /// capable backend). Returned by [`route_grants`] before any mutation.
    #[error("file grant {path:?} ({shape:?}) is not supported by any installed backend: {reason}")]
    Unsupported {
        /// The grant path that could not be routed.
        path: String,
        /// The grant's derived shape.
        shape: Shape,
        /// Human-facing explanation + remediation suggestion.
        reason: String,
    },
    /// A `setfacl`/`getfacl` invocation failed (non-zero exit or spawn error).
    #[error("setfacl/getfacl failed for {path:?}: {source}")]
    Setfacl {
        /// The path the command targeted.
        path: String,
        /// The underlying command failure (spawn error or non-zero exit).
        #[source]
        source: CommandError,
    },
    /// An I/O error reading/writing a rollback snapshot file.
    #[error("file-access rollback I/O error at {path}: {reason}")]
    Io {
        /// The rollback path that failed.
        path: PathBuf,
        /// Underlying reason.
        reason: String,
    },
    /// The grant target itself (the final path component) is a symlink. The
    /// ancestor chain is resolved up front by canonicalization — a benign
    /// symlinked parent (`/home` → `/export/home`) is tolerated because the
    /// commands run against the resolved path — but a symlinked *leaf* is refused:
    /// `setfacl -R --physical` resolves a symlinked target before walking, so a
    /// recursive ACL applied through an attacker-chosen leaf symlink would land on
    /// its link target. Refused fail-closed before any `setfacl` runs.
    #[error("file grant target {path:?} is a symlink; refusing to apply ACLs through it")]
    Symlink {
        /// The symlinked grant target that was refused.
        path: String,
    },
    /// The grant path's ancestor chain could not be resolved to an absolute,
    /// symlink-free path: the parent directory does not exist yet, is unreadable,
    /// or a component is a dangling symlink. Census canonicalizes the ancestor
    /// chain up front and operates on the resolved path, so a benign symlinked
    /// parent is tolerated while an attacker-swappable one is designed out; if that
    /// resolution fails there is no safe path to target, so the grant is refused
    /// before any command runs.
    #[error("cannot resolve file grant path {path:?} to a safe target: {reason}")]
    Unresolvable {
        /// The grant path whose ancestor chain could not be resolved.
        path: String,
        /// Why resolution failed (the underlying `canonicalize`/`lstat` error).
        reason: String,
    },
}

/// The enforcement SPI. A backend declares its [`Capabilities`] and materializes /
/// revokes / snapshots / restores file access for a single principal (a role-account
/// or a group).
///
/// Implementors MUST touch only the principal's own access entry — never the owner,
/// mode, or other principals' entries (the managed registry is the authority for
/// what to remove on revoke).
pub trait FileAccessBackend {
    /// Stable backend name for reporting (`"acl"`, a commercial backend's id…).
    fn name(&self) -> &str;
    /// What this backend can enforce.
    fn capabilities(&self) -> Capabilities;
    /// Materialize the given grants for `principal` (idempotent: re-applying the same
    /// entry is a no-op by content).
    fn materialize(
        &mut self,
        principal: &Principal,
        grants: &[ResolvedFileGrant],
    ) -> Result<(), FileAccessError>;
    /// Remove `principal`'s own access entry for one grant. Other entries, owner, and
    /// mode are left intact.
    fn revoke(
        &mut self,
        principal: &Principal,
        grant: &ResolvedFileGrant,
    ) -> Result<(), FileAccessError>;
    /// Snapshot the current access of `paths` for later [`restore`](Self::restore)
    /// (called before a mutating phase so a failure can roll back).
    fn snapshot(&mut self, paths: &[&Path]) -> Result<(), FileAccessError>;
    /// Restore access from the most recent [`snapshot`](Self::snapshot).
    fn restore(&mut self) -> Result<(), FileAccessError>;
}

/// The three-character ACL permission string for an [`Access`] bit set.
///
/// The position layout is the POSIX `rwx` triple. The first two slots are the
/// plain `read`/`write` bits (`r`/`-`, `w`/`-`). The third (execute) slot encodes
/// the two distinct execute semantics Census distinguishes:
///
/// - lowercase `x` when `execute` is set — execute on a *file* inode (run a file),
///   which `setfacl` applies unconditionally to every file in the tree;
/// - capital `X` when only `traverse` is set — the conditional execute that
///   `setfacl` applies to directories (and files already executable by someone),
///   so a reader can walk into a directory tree without gaining execute on the
///   regular files inside;
/// - `-` when neither is set.
///
/// `execute` wins the slot over `traverse` (lowercase `x` already implies the
/// directory-search the capital `X` would grant, so emitting both is redundant).
/// This preserves the historical mapping byte-for-byte: legacy `ro`
/// (`{read, traverse}`) → `r-X` and legacy `rw` (`{read, write, traverse}`) →
/// `rwX`.
fn acl_perm(access: Access) -> String {
    let r = if access.contains(Access::READ) {
        'r'
    } else {
        '-'
    };
    let w = if access.contains(Access::WRITE) {
        'w'
    } else {
        '-'
    };
    let x = if access.contains(Access::EXECUTE) {
        'x'
    } else if access.contains(Access::TRAVERSE) {
        'X'
    } else {
        '-'
    };
    [r, w, x].into_iter().collect()
}

/// Build the two `setfacl` argv vectors that materialize one directory grant for
/// `principal`: the access ACL (`-m`) and the default ACL (`-d -m`, inherited by new
/// files in the tree). Pure (no execution) so the exact argv can be unit-tested
/// without shelling out.
///
/// `-R` recurses, `--physical` refuses to follow symlinks out of the tree, and the
/// only entry touched is `<u|g>:<principal>:<perm>` — owner/mode/other principals are
/// never named. The default-ACL pass is what makes a directory grant rewrite-proof:
/// files created later inherit the access.
pub fn setfacl_args(principal: &Principal, grant: &ResolvedFileGrant) -> Vec<Vec<String>> {
    let perm = acl_perm(grant.access);
    let entry = format!(
        "{}:{}:{}",
        principal.acl_prefix(),
        principal.qualifier(),
        perm
    );
    vec![
        vec![
            "-R".to_owned(),
            "--physical".to_owned(),
            "-m".to_owned(),
            entry.clone(),
            grant.path.clone(),
        ],
        vec![
            "-d".to_owned(),
            "-R".to_owned(),
            "--physical".to_owned(),
            "-m".to_owned(),
            entry,
            grant.path.clone(),
        ],
    ]
}

/// Build the two `setfacl` argv vectors that revoke `principal`'s entry for one
/// directory grant: the access entry (`-x`) and the default entry (`-d -x`). Only
/// `<u|g>:<qualifier>` is removed; no other entry, owner, or mode is touched. Pure.
///
/// The qualifier is the principal's name for a live account/group and its numeric
/// id once the account/group has been deleted — a removed principal's name no
/// longer resolves, so revoking by name would be rejected; the numeric id always
/// matches the entry the kernel stored.
pub fn revoke_args(principal: &Principal, grant: &ResolvedFileGrant) -> Vec<Vec<String>> {
    let entry = format!("{}:{}", principal.acl_prefix(), principal.qualifier());
    vec![
        vec![
            "-R".to_owned(),
            "--physical".to_owned(),
            "-x".to_owned(),
            entry.clone(),
            grant.path.clone(),
        ],
        vec![
            "-d".to_owned(),
            "-R".to_owned(),
            "--physical".to_owned(),
            "-x".to_owned(),
            entry,
            grant.path.clone(),
        ],
    ]
}

/// Build the `getfacl` argv vector that snapshots one path for rollback.
/// `--absolute-names` keeps the paths in the dump absolute (so `setfacl --restore`
/// targets the right files regardless of cwd); `-R` walks the tree; `--physical`
/// refuses to follow symlinks out of the tree so the snapshot walk matches the
/// mutation walk (every `setfacl` pass is `-R --physical`). Without it, a symlinked
/// subdir would dump an out-of-tree target's ACLs that `setfacl --restore` would
/// replay out of tree. A symlinked ROOT is guarded separately by `snapshot`
/// (`--physical` resolves a symlinked root before walking). Pure.
pub fn getfacl_args(path: impl AsRef<str>) -> Vec<String> {
    vec![
        "--absolute-names".to_owned(),
        "-R".to_owned(),
        "--physical".to_owned(),
        path.as_ref().to_owned(),
    ]
}

/// Build the `setfacl` argv vector that restores ACLs from a rollback dump file.
/// Pure.
pub fn restore_args(rollback_file: impl AsRef<Path>) -> Vec<String> {
    vec![format!("--restore={}", rollback_file.as_ref().display())]
}

/// Resolve a grant `path` to the absolute, symlink-free path the ACL commands
/// will actually operate on, or fail closed.
///
/// This is the one guard shared by `materialize`, `revoke`, and `snapshot`. Every
/// recursive `setfacl`/`getfacl` pass runs with `--physical`, but `--physical`
/// only refuses symlinks ENCOUNTERED DURING the in-tree walk — it still resolves
/// every symlink in the path it is HANDED before walking. So a symlink anywhere in
/// the path handed to the command is followed identically and could redirect the
/// recursive ACL mutation (or the snapshot dump) onto an out-of-tree target as
/// root.
///
/// The fix is to resolve, not reject, the ancestor chain: benign symlinked parents
/// are legitimate and common (`/home` → `/export/home`, `/var/run` → `/run`, macOS
/// `/tmp` → `/private/tmp`), and refusing them outright breaks working grants and,
/// worse, makes a *revoke* of an already-applied grant fail — leaving an ACL Census
/// can no longer remove. Instead the parent directory is canonicalized once here
/// and the final component re-joined onto it; every command then targets that
/// resolved path. The resolved path no longer traverses an attacker-swappable
/// symlink, and a symlink swapped in AFTER canonicalization is not on the resolved
/// path, so the attack is closed without punishing benign parents.
///
/// The FINAL component is canonicalized *around* rather than *through*: the parent
/// is resolved and the leaf re-joined, then the leaf is `lstat`ed and refused if it
/// is itself a symlink. Canonicalizing the whole path would silently follow a
/// symlinked leaf and apply the recursive ACL onto its link target; keeping the
/// leaf un-followed and rejecting a symlinked one is what preserves that guard.
///
/// Only the parent must exist: the leaf may not exist yet (a grant may target a
/// path setfacl will operate on but that is absent at resolve time). A missing leaf
/// is accepted because the resolved path no longer traverses a swappable symlink and
/// there is no leaf symlink to follow; the subsequent `setfacl`/`getfacl` surfaces a
/// genuinely-absent target as its own error.
///
/// Fails closed with [`FileAccessError::Unresolvable`] if the parent cannot be
/// canonicalized (does not exist, is unreadable, or has a dangling-symlink
/// component) or the leaf cannot be `lstat`ed for a reason other than not existing,
/// and with [`FileAccessError::Symlink`] if the resolved leaf is itself a symlink.
fn resolve_grant_path(path: &str) -> Result<String, FileAccessError> {
    let p = Path::new(path);
    // Split off the final component so its own symlink status can be judged after
    // the ancestors are resolved. A path with no ordinary final component (the
    // filesystem root, `.`/`..`) has no attacker-chosen leaf to redirect through,
    // so it is canonicalized whole.
    let resolved = match (p.parent(), p.file_name()) {
        (Some(parent), Some(leaf)) => {
            // An empty parent is a bare relative name; resolve it against the cwd
            // so a symlinked leaf is still `lstat`ed rather than followed.
            let parent_dir: &Path = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            let canonical_parent =
                std::fs::canonicalize(parent_dir).map_err(|e| FileAccessError::Unresolvable {
                    path: path.to_owned(),
                    reason: format!("parent {}: {e}", parent_dir.display()),
                })?;
            canonical_parent.join(leaf)
        }
        _ => std::fs::canonicalize(p).map_err(|e| FileAccessError::Unresolvable {
            path: path.to_owned(),
            reason: e.to_string(),
        })?,
    };
    match std::fs::symlink_metadata(&resolved) {
        Ok(meta) if meta.file_type().is_symlink() => Err(FileAccessError::Symlink {
            path: resolved.to_string_lossy().into_owned(),
        }),
        // The leaf exists and is not a symlink: safe to target.
        Ok(_) => Ok(resolved.to_string_lossy().into_owned()),
        // The leaf does not exist yet: the parent is resolved, so there is no
        // swappable symlink on the path and no leaf link to follow. setfacl will
        // create/operate on it, or surface its own missing-target error.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(resolved.to_string_lossy().into_owned())
        }
        Err(e) => Err(FileAccessError::Unresolvable {
            path: path.to_owned(),
            reason: format!("{}: {e}", resolved.display()),
        }),
    }
}

/// Why a [`CommandRunner`] invocation failed: the binary could not be spawned, or
/// it ran but exited non-zero. Typed (not stringly) so a caller can distinguish a
/// missing/denied binary (`Spawn`) from a tool that ran and rejected its input
/// (`NonZero`) — the two demand different operator responses.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CommandError {
    /// The binary could not be spawned (not found, permission denied, …).
    #[error("spawn {binary} failed: {source}")]
    Spawn {
        /// The binary that could not be spawned.
        binary: String,
        /// The underlying spawn error (preserves `io::ErrorKind`).
        #[source]
        source: std::io::Error,
    },
    /// The binary ran but exited with a non-zero status.
    #[error("{binary} exited {status}: {stderr}")]
    NonZero {
        /// The binary that exited non-zero.
        binary: String,
        /// The exit status, rendered (e.g. `exit status: 1`).
        status: String,
        /// The trimmed stderr the command produced.
        stderr: String,
    },
}

/// A command runner the [`AclBackend`] uses to execute `setfacl`/`getfacl`, so unit
/// tests can record argv without shelling out while production runs the real
/// binaries. `run` executes `<binary> <args...>` and returns stdout on success or
/// a typed [`CommandError`] (spawn failure, or non-zero exit with stderr).
pub trait CommandRunner {
    /// Run `binary` with `args`; return captured stdout on success.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::Spawn`] if the binary cannot be launched, or
    /// [`CommandError::NonZero`] if it runs but exits with a non-zero status.
    fn run(&mut self, binary: &str, args: &[String]) -> Result<Vec<u8>, CommandError>;
}

/// The production runner: spawns the real binary via [`std::process::Command`] with
/// no shell. argv is passed straight through, so no value can be reinterpreted as
/// shell syntax.
#[derive(Debug, Clone, Default)]
pub struct ProcessRunner;

impl CommandRunner for ProcessRunner {
    fn run(&mut self, binary: &str, args: &[String]) -> Result<Vec<u8>, CommandError> {
        let out =
            Command::new(binary)
                .args(args)
                .output()
                .map_err(|source| CommandError::Spawn {
                    binary: binary.to_owned(),
                    source,
                })?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(CommandError::NonZero {
                binary: binary.to_owned(),
                status: out.status.to_string(),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            })
        }
    }
}

/// The open built-in backend: directory grants via POSIX ACL (recursive +
/// default-ACL, rewrite-proof). File and pattern grants are refused (capability
/// `false`); the resolver routes those elsewhere or rejects fail-closed.
///
/// The `setfacl`/`getfacl` binary names and the [`CommandRunner`] are injectable so
/// unit tests exercise argv construction and control flow without executing real
/// commands; the rollback directory is injectable so tests (and container runs)
/// control where snapshots land.
pub struct AclBackend<R: CommandRunner> {
    runner: R,
    setfacl_bin: String,
    getfacl_bin: String,
    rollback_dir: PathBuf,
    /// The rollback file written by the last `snapshot`, restored by `restore`.
    last_snapshot: Option<PathBuf>,
}

// The runner is an injected dependency with no public `Debug` requirement, so
// the formatter reports the configuration that determines behaviour and elides
// the runner rather than constraining `R: Debug`.
impl<R: CommandRunner> std::fmt::Debug for AclBackend<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AclBackend")
            .field("setfacl_bin", &self.setfacl_bin)
            .field("getfacl_bin", &self.getfacl_bin)
            .field("rollback_dir", &self.rollback_dir)
            .field("last_snapshot", &self.last_snapshot)
            .finish_non_exhaustive()
    }
}

impl<R: CommandRunner> AclBackend<R> {
    /// Construct with an explicit runner, binary paths, and rollback directory.
    pub fn new(
        runner: R,
        setfacl_bin: impl Into<String>,
        getfacl_bin: impl Into<String>,
        rollback_dir: impl Into<PathBuf>,
    ) -> Self {
        AclBackend {
            runner,
            setfacl_bin: setfacl_bin.into(),
            getfacl_bin: getfacl_bin.into(),
            rollback_dir: rollback_dir.into(),
            last_snapshot: None,
        }
    }
}

impl AclBackend<ProcessRunner> {
    /// Construct the production backend (real `setfacl`/`getfacl` on `$PATH`) with
    /// the given rollback directory.
    pub fn production(rollback_dir: impl Into<PathBuf>) -> Self {
        AclBackend::new(ProcessRunner, "setfacl", "getfacl", rollback_dir)
    }
}

/// The capabilities of the open ACL backend: directory grants only, rewrite-proof
/// (default-ACL inheritance). Exposed as a free function so [`route_grants`] tests
/// and callers can reason about the open build's coverage without constructing a
/// backend.
pub fn acl_capabilities() -> Capabilities {
    Capabilities {
        dir: true,
        per_path: false,
        pattern: false,
        realtime: false,
        rewrite_proof: true,
    }
}

impl<R: CommandRunner> FileAccessBackend for AclBackend<R> {
    fn name(&self) -> &str {
        "acl"
    }

    fn capabilities(&self) -> Capabilities {
        acl_capabilities()
    }

    fn materialize(
        &mut self,
        principal: &Principal,
        grants: &[ResolvedFileGrant],
    ) -> Result<(), FileAccessError> {
        for grant in grants {
            // Defense in depth: the resolver gates by shape first, but the backend
            // also refuses a non-Dir grant rather than silently applying an ACL it
            // cannot keep rewrite-proof.
            if grant.shape != Shape::Dir {
                return Err(FileAccessError::Unsupported {
                    path: grant.path.clone(),
                    shape: grant.shape,
                    reason: "AclBackend enforces directory grants only".to_owned(),
                });
            }
            // Resolve the ancestor chain and target the canonical path: `--physical`
            // only protects the in-tree walk, so any symlink in the path handed to
            // setfacl is resolved before the walk. Benign symlinked parents are
            // tolerated (the command runs against the resolved path); a symlinked
            // target leaf is refused (see `resolve_grant_path`).
            let target_path = match resolve_grant_path(&grant.path) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        path = %grant.path,
                        principal = %principal.name(),
                        error = %e,
                        "refusing to apply ACLs: grant path did not resolve to a safe target"
                    );
                    return Err(e);
                }
            };
            let target = ResolvedFileGrant {
                path: target_path,
                ..grant.clone()
            };
            for args in setfacl_args(principal, &target) {
                self.runner
                    .run(&self.setfacl_bin, &args)
                    .map_err(|source| FileAccessError::Setfacl {
                        path: grant.path.clone(),
                        source,
                    })?;
            }
            tracing::info!(
                path = %target.path,
                declared = %grant.path,
                principal = %principal.name(),
                "materialized ACL grant"
            );
        }
        Ok(())
    }

    fn revoke(
        &mut self,
        principal: &Principal,
        grant: &ResolvedFileGrant,
    ) -> Result<(), FileAccessError> {
        // The same resolution materialize uses, on the teardown path. The grant
        // path comes from the managed registry, so its ancestors may legitimately
        // be symlinked (a benign parent symlinked since it was applied); resolving
        // rather than rejecting them lets a revoke of an already-applied grant
        // succeed instead of leaving a stale ACL Census can no longer remove. The
        // command still targets the canonical path, so a target leaf swapped for a
        // symlink (TOCTOU) is refused before `setfacl -R --physical -x` could
        // resolve it and remove the entry out of tree.
        let target_path = match resolve_grant_path(&grant.path) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    path = %grant.path,
                    principal = %principal.name(),
                    error = %e,
                    "refusing to revoke ACLs: grant path did not resolve to a safe target"
                );
                return Err(e);
            }
        };
        let target = ResolvedFileGrant {
            path: target_path,
            ..grant.clone()
        };
        for args in revoke_args(principal, &target) {
            self.runner
                .run(&self.setfacl_bin, &args)
                .map_err(|source| FileAccessError::Setfacl {
                    path: grant.path.clone(),
                    source,
                })?;
        }
        Ok(())
    }

    fn snapshot(&mut self, paths: &[&Path]) -> Result<(), FileAccessError> {
        // Capture each path's current ACLs into one rollback dump, then persist it
        // so a later restore can replay the prior state. Each path's getfacl output
        // is concatenated; `--absolute-names` keeps targets unambiguous.
        let mut dump: Vec<u8> = Vec::new();
        for path in paths {
            let path_str = path.to_string_lossy().into_owned();
            // Resolve the ancestor chain and dump the canonical path, mirroring the
            // materialize/revoke guards: `getfacl -R --physical` still resolves any
            // symlink in the path it is handed before walking, so a symlinked
            // target leaf would capture an out-of-tree target's ACLs that a later
            // `setfacl --restore` would replay out of tree. Benign symlinked parents
            // are resolved through; a symlinked leaf is refused before getfacl runs.
            let target_path = match resolve_grant_path(&path_str) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        path = %path_str,
                        error = %e,
                        "refusing to snapshot ACLs: path did not resolve to a safe target"
                    );
                    return Err(e);
                }
            };
            let out = self
                .runner
                .run(&self.getfacl_bin, &getfacl_args(&target_path))
                .map_err(|source| FileAccessError::Setfacl {
                    path: path_str.clone(),
                    source,
                })?;
            dump.extend_from_slice(&out);
        }
        std::fs::create_dir_all(&self.rollback_dir).map_err(|e| FileAccessError::Io {
            path: self.rollback_dir.clone(),
            reason: e.to_string(),
        })?;
        let file = self.rollback_dir.join("file-access-acl.snapshot");
        std::fs::write(&file, &dump).map_err(|e| FileAccessError::Io {
            path: file.clone(),
            reason: e.to_string(),
        })?;
        self.last_snapshot = Some(file);
        Ok(())
    }

    fn restore(&mut self) -> Result<(), FileAccessError> {
        let Some(file) = self.last_snapshot.clone() else {
            // Nothing was snapshotted — a restore with no prior snapshot is a no-op
            // (the mutating phase never ran), not an error.
            return Ok(());
        };
        self.runner
            .run(&self.setfacl_bin, &restore_args(&file))
            .map_err(|source| FileAccessError::Setfacl {
                path: file.to_string_lossy().into_owned(),
                source,
            })?;
        Ok(())
    }
}

/// The capability a grant's [`Shape`] requires of a covering backend.
fn shape_requires(shape: Shape, caps: &Capabilities) -> bool {
    match shape {
        Shape::Dir => caps.dir,
        Shape::File => caps.per_path,
        Shape::Pattern => caps.pattern,
    }
}

/// Route each grant to a backend whose capabilities cover its shape, fail-closed.
///
/// Returns, for each grant in order, the index of a covering backend (the first one
/// that declares the required capability) paired with the grant. If *no* installed
/// backend covers a grant's shape, returns [`FileAccessError::Unsupported`] for that
/// grant — **before** any backend is asked to mutate — with a message suggesting
/// how to proceed (widen a file grant to its directory, or install a capable
/// backend). This is the capability-gating contract: the open build refuses an
/// unenforceable grant rather than quietly applying weaker access.
pub fn route_grants<'a>(
    grants: &'a [ResolvedFileGrant],
    backends: &[&dyn FileAccessBackend],
) -> Result<Vec<(usize, &'a ResolvedFileGrant)>, FileAccessError> {
    let mut routed = Vec::with_capacity(grants.len());
    for grant in grants {
        let mut chosen = None;
        for (idx, backend) in backends.iter().enumerate() {
            if shape_requires(grant.shape, &backend.capabilities()) {
                chosen = Some(idx);
                break;
            }
        }
        match chosen {
            Some(idx) => routed.push((idx, grant)),
            None => {
                return Err(FileAccessError::Unsupported {
                    path: grant.path.clone(),
                    shape: grant.shape,
                    reason: unsupported_suggestion(grant.shape),
                });
            }
        }
    }
    Ok(routed)
}

/// The remediation suggestion for an unroutable grant, tailored to its shape. A
/// file grant can be widened to its directory (which the open `AclBackend` enforces
/// rewrite-proof); a pattern needs a capable backend.
fn unsupported_suggestion(shape: Shape) -> String {
    match shape {
        Shape::File => "no backend provides per-file enforcement; widen the grant to \
             its containing directory (which the open ACL backend enforces \
             rewrite-proof), or install a per-file-capable backend"
            .to_owned(),
        Shape::Pattern => "no backend provides pattern enforcement; install a \
             pattern-capable backend (watcher / MAC labels), or replace the glob \
             with a directory grant"
            .to_owned(),
        Shape::Dir => "no backend provides directory enforcement; install the ACL \
             backend"
            .to_owned(),
    }
}

/// A test/inspection backend that records every call and reports configurable
/// capabilities. Lets gating tests exercise both a backend that *does* support
/// per_path/pattern and one that does not, and lets materialize/revoke/snapshot/
/// restore be asserted without touching the filesystem.
#[derive(Debug, Clone)]
pub struct FakeBackend {
    name: String,
    caps: Capabilities,
    /// Every call this backend received, in order, for assertions.
    pub calls: Vec<FakeCall>,
}

/// A recorded [`FakeBackend`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeCall {
    /// `materialize(principal, grant_paths)`.
    Materialize {
        /// The principal passed.
        principal: Principal,
        /// The paths of the grants passed.
        paths: Vec<String>,
    },
    /// `revoke(principal, grant_path)`.
    Revoke {
        /// The principal passed.
        principal: Principal,
        /// The grant path passed.
        path: String,
    },
    /// `snapshot(paths)`.
    Snapshot {
        /// The paths passed.
        paths: Vec<String>,
    },
    /// `restore()`.
    Restore,
}

impl FakeBackend {
    /// A fake with the given name and capabilities.
    pub fn new(name: impl Into<String>, caps: Capabilities) -> Self {
        FakeBackend {
            name: name.into(),
            caps,
            calls: Vec::new(),
        }
    }
}

impl FileAccessBackend for FakeBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> Capabilities {
        self.caps
    }

    fn materialize(
        &mut self,
        principal: &Principal,
        grants: &[ResolvedFileGrant],
    ) -> Result<(), FileAccessError> {
        self.calls.push(FakeCall::Materialize {
            principal: principal.clone(),
            paths: grants.iter().map(|g| g.path.clone()).collect(),
        });
        Ok(())
    }

    fn revoke(
        &mut self,
        principal: &Principal,
        grant: &ResolvedFileGrant,
    ) -> Result<(), FileAccessError> {
        self.calls.push(FakeCall::Revoke {
            principal: principal.clone(),
            path: grant.path.clone(),
        });
        Ok(())
    }

    fn snapshot(&mut self, paths: &[&Path]) -> Result<(), FileAccessError> {
        self.calls.push(FakeCall::Snapshot {
            paths: paths
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
        });
        Ok(())
    }

    fn restore(&mut self) -> Result<(), FileAccessError> {
        self.calls.push(FakeCall::Restore);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::SourcedFileGrant;

    fn grant(path: &str, access: Access, recursive: bool, shape: Shape) -> ResolvedFileGrant {
        ResolvedFileGrant {
            path: path.to_owned(),
            access,
            recursive,
            shape,
            sources: vec![SourcedFileGrant {
                layer: "linux".to_owned(),
                via: None,
                binding: None,
            }],
        }
    }

    /// Create a real directory to grant on: a fresh tempdir with a `tree`
    /// subdirectory. The backend resolves the ancestor chain before running any
    /// command, so a grant path must exist on disk (an unresolvable path fails
    /// closed). Returns the tempdir guard (keep it alive for the directory to
    /// persist), the path to declare the grant on, and the canonical path the
    /// backend targets after resolving ancestors — which is what the emitted argv
    /// carries (a host may symlink the temp root, e.g. macOS `/tmp` →
    /// `/private/tmp`, so declared and canonical can differ).
    fn real_grant_dir() -> (tempfile::TempDir, String, String) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("tree");
        std::fs::create_dir(&dir).unwrap();
        let declared = dir.to_string_lossy().into_owned();
        let canonical = std::fs::canonicalize(&dir)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        (tmp, declared, canonical)
    }

    /// A runner that records every (binary, argv) it is asked to run and returns a
    /// fixed stdout, so the AclBackend's argv construction and control flow can be
    /// asserted without executing real commands.
    #[derive(Default)]
    struct RecordingRunner {
        calls: Vec<(String, Vec<String>)>,
        stdout: Vec<u8>,
    }

    impl CommandRunner for RecordingRunner {
        fn run(&mut self, binary: &str, args: &[String]) -> Result<Vec<u8>, CommandError> {
            self.calls.push((binary.to_owned(), args.to_vec()));
            Ok(self.stdout.clone())
        }
    }

    // --- ACL perm-string mapping (bit set → POSIX rwx triple) ---

    #[test]
    fn acl_perm_legacy_equivalence_is_byte_for_byte() {
        // THE migration invariant: the legacy `ro`/`rw` sets must materialize to
        // the exact ACL strings the two-value enum did, or every already-applied
        // ACL silently changes meaning on the next apply. Asserted byte-for-byte.
        assert_eq!(acl_perm(Access::RO), "r-X", "legacy ro == r-X");
        assert_eq!(acl_perm(Access::RW), "rwX", "legacy rw == rwX");
    }

    #[test]
    fn acl_perm_maps_each_bit_combo() {
        // read → r, write → w, execute → lowercase x (file exec), traverse →
        // capital X (dir-only exec). execute wins the x-slot over traverse.
        assert_eq!(acl_perm(Access::READ), "r--");
        assert_eq!(acl_perm(Access::READ | Access::TRAVERSE), "r-X");
        assert_eq!(acl_perm(Access::READ | Access::EXECUTE), "r-x");
        assert_eq!(acl_perm(Access::EXECUTE), "--x");
        assert_eq!(acl_perm(Access::TRAVERSE), "--X");
        assert_eq!(acl_perm(Access::READ | Access::WRITE), "rw-");
        assert_eq!(
            acl_perm(Access::READ | Access::WRITE | Access::EXECUTE),
            "rwx"
        );
        // execute set alongside traverse: lowercase x already covers dir search,
        // so the x-slot is lowercase, not capital.
        assert_eq!(
            acl_perm(Access::READ | Access::EXECUTE | Access::TRAVERSE),
            "r-x"
        );
    }

    // --- pure argv construction ---

    #[test]
    fn setfacl_args_ro_uses_rx_and_default_pass() {
        let g = grant("/srv/ssh", Access::RO, true, Shape::Dir);
        let args = setfacl_args(&Principal::User("alice".to_owned()), &g);
        assert_eq!(args.len(), 2, "access ACL + default ACL");
        // Access pass: -R --physical -m u:alice:r-X /srv/ssh
        assert_eq!(
            args[0],
            vec!["-R", "--physical", "-m", "u:alice:r-X", "/srv/ssh"]
        );
        // Default pass carries -d.
        assert_eq!(
            args[1],
            vec!["-d", "-R", "--physical", "-m", "u:alice:r-X", "/srv/ssh"]
        );
    }

    #[test]
    fn setfacl_args_rw_uses_rwx() {
        let g = grant("/etc/pam.d", Access::RW, true, Shape::Dir);
        let args = setfacl_args(&Principal::User("bob".to_owned()), &g);
        assert!(args[0].contains(&"u:bob:rwX".to_owned()));
        assert!(args[1].contains(&"-d".to_owned()));
    }

    #[test]
    fn setfacl_args_group_uses_g_prefix_with_default_pass() {
        // A group grant is the user grant with a `g:` prefix — same -R --physical,
        // same default-ACL pass, only the principal letter differs.
        let g = grant("/srv/shared", Access::RW, true, Shape::Dir);
        let args = setfacl_args(&Principal::Group("wheel".to_owned()), &g);
        assert_eq!(args.len(), 2, "access ACL + default ACL");
        assert_eq!(
            args[0],
            vec!["-R", "--physical", "-m", "g:wheel:rwX", "/srv/shared"]
        );
        // The default-ACL pass carries -d and the same g: entry.
        assert_eq!(
            args[1],
            vec!["-d", "-R", "--physical", "-m", "g:wheel:rwX", "/srv/shared"]
        );
    }

    #[test]
    fn setfacl_args_user_ro_regression_unchanged() {
        // The pre-group behavior for a user principal is intact: u: prefix, r-X.
        let g = grant("/srv/ssh", Access::RO, true, Shape::Dir);
        let args = setfacl_args(&Principal::User("alice".to_owned()), &g);
        assert_eq!(
            args[0],
            vec!["-R", "--physical", "-m", "u:alice:r-X", "/srv/ssh"]
        );
    }

    #[test]
    fn revoke_args_remove_only_account_entry() {
        let g = grant("/srv/ssh", Access::RW, true, Shape::Dir);
        let args = revoke_args(&Principal::User("alice".to_owned()), &g);
        assert_eq!(args.len(), 2);
        // -x with u:alice (no perm — removal), access + default. Never names owner
        // or other principals.
        assert_eq!(
            args[0],
            vec!["-R", "--physical", "-x", "u:alice", "/srv/ssh"]
        );
        assert_eq!(
            args[1],
            vec!["-d", "-R", "--physical", "-x", "u:alice", "/srv/ssh"]
        );
        // No argv mentions another principal or chmod/chown.
        for a in args.iter().flatten() {
            assert!(!a.contains("g:") && a != "u:other");
        }
    }

    #[test]
    fn revoke_args_numeric_uid_targets_orphaned_entry() {
        // After `userdel`, the account name no longer resolves through getpwnam, so
        // `setfacl -x u:<name>` is rejected as an invalid argument and the teardown
        // aborts. Revoking by the recorded numeric UID removes the exact entry the
        // kernel stored, which needs no passwd lookup. The argv must read `u:9010`,
        // not `u:<name>`, on both the access and default passes.
        let g = grant("/srv/salt", Access::RW, true, Shape::Dir);
        let args = revoke_args(&Principal::Uid(9010), &g);
        assert_eq!(args.len(), 2);
        assert_eq!(
            args[0],
            vec!["-R", "--physical", "-x", "u:9010", "/srv/salt"]
        );
        assert_eq!(
            args[1],
            vec!["-d", "-R", "--physical", "-x", "u:9010", "/srv/salt"]
        );
    }

    #[test]
    fn revoke_args_numeric_gid_uses_g_prefix() {
        // The group mirror of the numeric revoke: a removed group is revoked by GID.
        let g = grant("/srv/shared", Access::RW, true, Shape::Dir);
        let args = revoke_args(&Principal::Gid(4242), &g);
        assert_eq!(
            args[0],
            vec!["-R", "--physical", "-x", "g:4242", "/srv/shared"]
        );
        assert_eq!(
            args[1],
            vec!["-d", "-R", "--physical", "-x", "g:4242", "/srv/shared"]
        );
    }

    #[test]
    fn principal_numeric_qualifier_and_prefix() {
        let uid = Principal::Uid(9010);
        let gid = Principal::Gid(4242);
        assert_eq!(uid.acl_prefix(), "u");
        assert_eq!(uid.qualifier(), "9010");
        assert_eq!(gid.acl_prefix(), "g");
        assert_eq!(gid.qualifier(), "4242");
    }

    #[test]
    fn acl_revoke_by_uid_emits_numeric_argv_and_succeeds() {
        // End-to-end through the backend control flow: a revoke of a `Uid` principal
        // emits the numeric argv on both passes and (with a runner that returns exit
        // 0) reports success.
        let (_tmp, declared, canonical) = real_grant_dir();
        let mut b = acl_with(RecordingRunner::default());
        let g = grant(&declared, Access::RW, true, Shape::Dir);
        b.revoke(&Principal::Uid(9010), &g).unwrap();
        assert_eq!(b.runner.calls.len(), 2);
        // The argv targets the resolved canonical path, not the declared one.
        assert_eq!(
            b.runner.calls[0].1,
            vec!["-R", "--physical", "-x", "u:9010", canonical.as_str()]
        );
        assert_eq!(
            b.runner.calls[1].1,
            vec!["-d", "-R", "--physical", "-x", "u:9010", canonical.as_str()]
        );
    }

    #[test]
    fn acl_revoke_surfaces_setfacl_exit_two_as_setfacl_error() {
        // Pins how the backend interprets a non-zero setfacl exit on revoke: the
        // exact failure mode the live teardown hit — `setfacl` exiting 2 with an
        // "invalid argument" stderr because the (deleted) name no longer resolved.
        // A non-empty stderr alone must NOT be treated as failure; only a non-zero
        // status is, and it must surface as a `Setfacl` error naming the grant path,
        // carrying the underlying NonZero (binary/status/stderr) verbatim.
        struct ExitTwoRunner;
        impl CommandRunner for ExitTwoRunner {
            fn run(&mut self, binary: &str, _args: &[String]) -> Result<Vec<u8>, CommandError> {
                Err(CommandError::NonZero {
                    binary: binary.to_owned(),
                    status: "exit status: 2".to_owned(),
                    stderr: "setfacl: Option -x: Invalid argument near character 3".to_owned(),
                })
            }
        }
        let (_tmp, declared, _canonical) = real_grant_dir();
        let mut b = AclBackend::new(ExitTwoRunner, "setfacl", "getfacl", std::env::temp_dir());
        let g = grant(&declared, Access::RW, true, Shape::Dir);
        let err = b
            .revoke(&Principal::Uid(9010), &g)
            .expect_err("a non-zero setfacl exit must surface as an error");
        match err {
            FileAccessError::Setfacl { path, source } => {
                // The error names the declared grant path (what the operator can
                // act on), even though the command ran against the resolved path.
                assert_eq!(path, declared);
                assert!(
                    matches!(source, CommandError::NonZero { ref status, .. } if status == "exit status: 2"),
                    "must carry the underlying non-zero exit: {source:?}"
                );
            }
            other => panic!("expected Setfacl error, got {other:?}"),
        }
    }

    #[test]
    fn acl_revoke_treats_exit_zero_with_stderr_as_success() {
        // The dual: setfacl can emit advisory stderr while still exiting 0 (e.g. a
        // recursive pass over a tree where some files never carried the entry). The
        // runner keys success on the exit STATUS, not on stderr being empty, so a
        // zero exit with noisy stderr is a success and the revoke completes.
        struct ZeroWithStderrRunner {
            calls: usize,
        }
        impl CommandRunner for ZeroWithStderrRunner {
            fn run(&mut self, _binary: &str, _args: &[String]) -> Result<Vec<u8>, CommandError> {
                // The production ProcessRunner returns Ok(stdout) whenever the exit
                // status is success regardless of stderr; model that here.
                self.calls += 1;
                Ok(Vec::new())
            }
        }
        let (_tmp, declared, _canonical) = real_grant_dir();
        let mut b = AclBackend::new(
            ZeroWithStderrRunner { calls: 0 },
            "setfacl",
            "getfacl",
            std::env::temp_dir(),
        );
        let g = grant(&declared, Access::RW, true, Shape::Dir);
        b.revoke(&Principal::Uid(9010), &g)
            .expect("a zero exit must be a success even with stderr output");
        assert_eq!(b.runner.calls, 2, "both revoke passes ran");
    }

    #[test]
    fn revoke_args_group_removes_only_group_entry() {
        let g = grant("/srv/shared", Access::RW, true, Shape::Dir);
        let args = revoke_args(&Principal::Group("wheel".to_owned()), &g);
        assert_eq!(args.len(), 2);
        // -x with g:wheel (no perm — removal), access + default. Mirrors the user
        // revoke exactly but on the group entry.
        assert_eq!(
            args[0],
            vec!["-R", "--physical", "-x", "g:wheel", "/srv/shared"]
        );
        assert_eq!(
            args[1],
            vec!["-d", "-R", "--physical", "-x", "g:wheel", "/srv/shared"]
        );
    }

    #[test]
    fn principal_prefix_and_name() {
        let u = Principal::User("alice".to_owned());
        let g = Principal::Group("wheel".to_owned());
        assert_eq!(u.acl_prefix(), "u");
        assert_eq!(u.name(), "alice");
        assert_eq!(g.acl_prefix(), "g");
        assert_eq!(g.name(), "wheel");
    }

    #[test]
    fn getfacl_and_restore_args() {
        assert_eq!(
            getfacl_args("/srv/ssh"),
            vec!["--absolute-names", "-R", "--physical", "/srv/ssh"]
        );
        let f = Path::new("/var/lib/census/rollback/x.snapshot");
        assert_eq!(
            restore_args(f),
            vec!["--restore=/var/lib/census/rollback/x.snapshot"]
        );
    }

    // --- AclBackend control flow (via recording runner, no real setfacl) ---

    fn acl_with(runner: RecordingRunner) -> AclBackend<RecordingRunner> {
        AclBackend::new(runner, "setfacl", "getfacl", std::env::temp_dir())
    }

    #[test]
    fn acl_capabilities_are_dir_only_rewrite_proof() {
        let caps = acl_with(RecordingRunner::default()).capabilities();
        assert!(caps.dir);
        assert!(caps.rewrite_proof);
        assert!(!caps.per_path);
        assert!(!caps.pattern);
        assert!(!caps.realtime);
    }

    #[test]
    fn acl_materialize_runs_both_setfacl_passes() {
        let (_tmp, declared, _canonical) = real_grant_dir();
        let mut b = acl_with(RecordingRunner::default());
        let g = grant(&declared, Access::RW, true, Shape::Dir);
        b.materialize(
            &Principal::User("alice".to_owned()),
            std::slice::from_ref(&g),
        )
        .unwrap();
        assert_eq!(b.runner.calls.len(), 2);
        assert!(b.runner.calls.iter().all(|(bin, _)| bin == "setfacl"));
    }

    #[test]
    fn acl_materialize_group_writes_g_entries() {
        let (_tmp, declared, canonical) = real_grant_dir();
        let mut b = acl_with(RecordingRunner::default());
        let g = grant(&declared, Access::RW, true, Shape::Dir);
        b.materialize(
            &Principal::Group("wheel".to_owned()),
            std::slice::from_ref(&g),
        )
        .unwrap();
        // Both setfacl passes carry the g:wheel entry (access + default), proving the
        // group principal flows through to the real argv the backend would run,
        // targeting the resolved canonical path.
        assert_eq!(b.runner.calls.len(), 2);
        assert_eq!(
            b.runner.calls[0].1,
            vec!["-R", "--physical", "-m", "g:wheel:rwX", canonical.as_str()]
        );
        assert_eq!(
            b.runner.calls[1].1,
            vec![
                "-d",
                "-R",
                "--physical",
                "-m",
                "g:wheel:rwX",
                canonical.as_str()
            ]
        );
    }

    #[test]
    #[cfg(unix)]
    fn acl_refuses_symlinked_grant_target() {
        // The grant's FINAL component is itself a symlink. `setfacl -R --physical`
        // resolves a symlinked target before walking, so a recursive ACL applied
        // through it would land on the link target's tree. Resolving the ancestor
        // chain does not rescue this — the leaf is `lstat`ed, not followed — so a
        // symlinked target is refused before any command runs.
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real-tree");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("grant-link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let mut b = acl_with(RecordingRunner::default());
        let g = grant(&link.to_string_lossy(), Access::RW, true, Shape::Dir);
        let err = b
            .materialize(
                &Principal::User("alice".to_owned()),
                std::slice::from_ref(&g),
            )
            .unwrap_err();
        assert!(
            matches!(err, FileAccessError::Symlink { .. }),
            "symlinked grant target must be refused: {err:?}"
        );
        // Refused before running any setfacl.
        assert!(
            b.runner.calls.is_empty(),
            "no command must run for a symlinked target"
        );
    }

    #[test]
    #[cfg(unix)]
    fn acl_accepts_grant_with_symlinked_ancestor_on_canonical_path() {
        // The grant's FINAL component is a real directory, but an ANCESTOR is a
        // symlink — the common benign case (`/home` → `/export/home`). Refusing it
        // would break a working grant. The backend must resolve the ancestor chain
        // and target the CANONICAL path (which no longer traverses the symlink),
        // then run setfacl against it.
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let real_parent = base.join("real-parent");
        std::fs::create_dir(&real_parent).unwrap();
        let leaf = real_parent.join("proj");
        std::fs::create_dir(&leaf).unwrap();
        // A symlink standing in for a benign symlinked ancestor directory.
        let link_parent = base.join("link-parent");
        std::os::unix::fs::symlink(&real_parent, &link_parent).unwrap();
        // The declared grant path traverses the symlinked ancestor; its final
        // component is a real directory.
        let grant_path = link_parent.join("proj");
        // The path the command must target: the ancestor symlink resolved away.
        let expected = std::fs::canonicalize(&grant_path)
            .unwrap()
            .to_string_lossy()
            .into_owned();

        let mut b = acl_with(RecordingRunner::default());
        let g = grant(&grant_path.to_string_lossy(), Access::RW, true, Shape::Dir);
        b.materialize(
            &Principal::User("alice".to_owned()),
            std::slice::from_ref(&g),
        )
        .expect("a benign symlinked ancestor must be accepted on the canonical path");
        // Both setfacl passes ran, targeting the resolved canonical path — not the
        // declared path that traversed the symlink.
        assert_eq!(b.runner.calls.len(), 2);
        for (_, argv) in &b.runner.calls {
            assert_eq!(
                argv.last().map(String::as_str),
                Some(expected.as_str()),
                "command must target the canonical path, not the symlinked declared path"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn acl_refuses_grant_with_symlinked_leaf() {
        // The dual of the accepted-ancestor case: an ancestor is benign but the
        // FINAL component (the grant target) is itself a symlink. Resolving the
        // ancestor chain does not follow the leaf; it is `lstat`ed and refused,
        // because a recursive ACL applied through it would land on its link target.
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let real_parent = base.join("real-parent");
        std::fs::create_dir(&real_parent).unwrap();
        // The victim tree the leaf symlink points at.
        let victim = base.join("victim");
        std::fs::create_dir(&victim).unwrap();
        // A benign symlinked ancestor, plus a symlinked LEAF under it.
        let link_parent = base.join("link-parent");
        std::os::unix::fs::symlink(&real_parent, &link_parent).unwrap();
        let leaf_link = real_parent.join("proj");
        std::os::unix::fs::symlink(&victim, &leaf_link).unwrap();
        let grant_path = link_parent.join("proj");

        let mut b = acl_with(RecordingRunner::default());
        let g = grant(&grant_path.to_string_lossy(), Access::RW, true, Shape::Dir);
        let err = b
            .materialize(
                &Principal::User("alice".to_owned()),
                std::slice::from_ref(&g),
            )
            .unwrap_err();
        assert!(
            matches!(err, FileAccessError::Symlink { .. }),
            "a symlinked grant leaf must be refused: {err:?}"
        );
        assert!(
            b.runner.calls.is_empty(),
            "no command must run for a symlinked leaf"
        );
    }

    #[test]
    #[cfg(unix)]
    fn acl_revoke_accepts_symlinked_ancestor_on_canonical_path() {
        // The regression this whole fix targets: a revoke of an already-applied
        // grant whose parent has since become a benign symlink must still succeed,
        // targeting the canonical path — not error out and strand an ACL Census can
        // no longer remove.
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let real_parent = base.join("real-parent");
        std::fs::create_dir(&real_parent).unwrap();
        let leaf = real_parent.join("proj");
        std::fs::create_dir(&leaf).unwrap();
        let link_parent = base.join("link-parent");
        std::os::unix::fs::symlink(&real_parent, &link_parent).unwrap();
        let grant_path = link_parent.join("proj");
        let expected = std::fs::canonicalize(&grant_path)
            .unwrap()
            .to_string_lossy()
            .into_owned();

        let mut b = acl_with(RecordingRunner::default());
        let g = grant(&grant_path.to_string_lossy(), Access::RW, true, Shape::Dir);
        b.revoke(&Principal::User("alice".to_owned()), &g)
            .expect("revoke through a benign symlinked ancestor must succeed");
        assert_eq!(b.runner.calls.len(), 2);
        for (_, argv) in &b.runner.calls {
            assert_eq!(argv.last().map(String::as_str), Some(expected.as_str()));
        }
    }

    #[test]
    #[cfg(unix)]
    fn acl_refuses_grant_with_unresolvable_parent() {
        // Fail closed when the ancestor chain cannot be resolved at all: a parent
        // that does not exist leaves no safe path to target, so the grant is refused
        // before any command runs (distinct from a symlink finding).
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        // `missing` does not exist, so its child cannot be resolved.
        let grant_path = base.join("missing").join("proj");

        let mut b = acl_with(RecordingRunner::default());
        let g = grant(&grant_path.to_string_lossy(), Access::RW, true, Shape::Dir);
        let err = b
            .materialize(
                &Principal::User("alice".to_owned()),
                std::slice::from_ref(&g),
            )
            .unwrap_err();
        assert!(
            matches!(err, FileAccessError::Unresolvable { .. }),
            "an unresolvable parent must fail closed: {err:?}"
        );
        assert!(
            b.runner.calls.is_empty(),
            "no command must run when the path cannot be resolved"
        );
    }

    #[test]
    #[cfg(unix)]
    fn acl_accepts_grant_with_not_yet_existing_leaf() {
        // Only the parent must exist: a grant may target a leaf setfacl will operate
        // on that is absent at resolve time. The parent resolves, the missing leaf
        // is accepted (no symlink to follow), and both setfacl passes run against
        // the resolved path.
        let tmp = tempfile::tempdir().unwrap();
        let parent = std::fs::canonicalize(tmp.path()).unwrap();
        let grant_path = parent.join("not-created-yet");
        let expected = grant_path.to_string_lossy().into_owned();

        let mut b = acl_with(RecordingRunner::default());
        let g = grant(&grant_path.to_string_lossy(), Access::RW, true, Shape::Dir);
        b.materialize(
            &Principal::User("alice".to_owned()),
            std::slice::from_ref(&g),
        )
        .expect("a not-yet-existing leaf under a real parent must be accepted");
        assert_eq!(b.runner.calls.len(), 2);
        for (_, argv) in &b.runner.calls {
            assert_eq!(argv.last().map(String::as_str), Some(expected.as_str()));
        }
    }

    #[test]
    #[cfg(unix)]
    fn acl_revoke_refuses_symlinked_grant_root() {
        // A grant root swapped for a symlink (TOCTOU between applies) would let
        // `setfacl -R -x` resolve the root and walk the link target, removing the
        // entry out of the intended tree. revoke must lstat the root and refuse —
        // the same guard materialize uses — before running any command. The path
        // comes straight from the managed registry, so this is the teardown-side
        // counterpart of the materialize symlink guard.
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real-tree");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("grant-link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let mut b = acl_with(RecordingRunner::default());
        let g = grant(&link.to_string_lossy(), Access::RW, true, Shape::Dir);
        let err = b
            .revoke(&Principal::User("alice".to_owned()), &g)
            .unwrap_err();
        assert!(
            matches!(err, FileAccessError::Symlink { .. }),
            "symlinked grant root must be refused on revoke: {err:?}"
        );
        assert!(
            b.runner.calls.is_empty(),
            "no setfacl must run for a symlinked revoke root"
        );
    }

    #[test]
    #[cfg(unix)]
    fn acl_snapshot_refuses_symlinked_root() {
        // A symlinked snapshot root would dump an out-of-tree target's ACLs (the
        // getfacl root is resolved before the walk), which `setfacl --restore`
        // would later replay out of tree. snapshot must refuse it before running
        // getfacl, mirroring the materialize/revoke guards.
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real-tree");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("snap-link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let mut b = acl_with(RecordingRunner::default());
        let err = b.snapshot(&[&link]).unwrap_err();
        assert!(
            matches!(err, FileAccessError::Symlink { .. }),
            "symlinked snapshot root must be refused: {err:?}"
        );
        assert!(
            b.runner.calls.is_empty(),
            "no getfacl must run for a symlinked snapshot root"
        );
    }

    #[test]
    #[cfg(unix)]
    fn acl_materialize_allows_real_directory_root() {
        // The dual of the symlink rejection: a genuine (non-symlink) directory
        // passes resolution and the setfacl passes run. A symlinked temp root (e.g.
        // macOS `/tmp` → `/private/tmp`) is now resolved rather than refused, so no
        // manual canonicalize workaround is needed on the declared path.
        let (_tmp, declared, _canonical) = real_grant_dir();
        let mut b = acl_with(RecordingRunner::default());
        let g = grant(&declared, Access::RW, true, Shape::Dir);
        b.materialize(
            &Principal::User("alice".to_owned()),
            std::slice::from_ref(&g),
        )
        .unwrap();
        assert_eq!(
            b.runner.calls.len(),
            2,
            "both setfacl passes run for a real dir root"
        );
    }

    #[test]
    fn acl_refuses_non_dir_grant() {
        let mut b = acl_with(RecordingRunner::default());
        let g = grant("/srv/ssh/sshd_config", Access::RW, false, Shape::File);
        let err = b
            .materialize(
                &Principal::User("alice".to_owned()),
                std::slice::from_ref(&g),
            )
            .unwrap_err();
        assert!(
            matches!(err, FileAccessError::Unsupported { ref shape, .. } if *shape == Shape::File)
        );
        // It refused before running any command.
        assert!(b.runner.calls.is_empty());
    }

    #[test]
    fn acl_revoke_runs_two_passes() {
        let (_tmp, declared, _canonical) = real_grant_dir();
        let mut b = acl_with(RecordingRunner::default());
        let g = grant(&declared, Access::RW, true, Shape::Dir);
        b.revoke(&Principal::User("alice".to_owned()), &g).unwrap();
        assert_eq!(b.runner.calls.len(), 2);
    }

    #[test]
    fn acl_snapshot_writes_rollback_and_restore_replays_it() {
        let (_snap_target, declared, _canonical) = real_grant_dir();
        let tmp = tempfile::tempdir().unwrap();
        let runner = RecordingRunner {
            stdout: b"# file: /srv/ssh\nuser::rwx\n".to_vec(),
            ..Default::default()
        };
        let mut b = AclBackend::new(runner, "setfacl", "getfacl", tmp.path());
        let p = Path::new(&declared);
        b.snapshot(&[p]).unwrap();
        let snap = tmp.path().join("file-access-acl.snapshot");
        assert!(snap.exists(), "snapshot file must be written");
        assert_eq!(b.last_snapshot.as_deref(), Some(snap.as_path()));
        // restore replays via setfacl --restore=<file>.
        b.restore().unwrap();
        let last = b.runner.calls.last().unwrap();
        assert_eq!(last.0, "setfacl");
        assert!(last.1[0].starts_with("--restore="));
    }

    #[test]
    fn acl_restore_without_snapshot_is_noop() {
        let mut b = acl_with(RecordingRunner::default());
        b.restore().unwrap();
        assert!(b.runner.calls.is_empty());
    }

    #[test]
    fn acl_setfacl_failure_surfaces_error() {
        struct FailRunner;
        impl CommandRunner for FailRunner {
            fn run(&mut self, binary: &str, _args: &[String]) -> Result<Vec<u8>, CommandError> {
                Err(CommandError::NonZero {
                    binary: binary.to_owned(),
                    status: "exit status: 1".to_owned(),
                    stderr: "No such file".to_owned(),
                })
            }
        }
        let (_tmp, declared, _canonical) = real_grant_dir();
        let mut b = AclBackend::new(FailRunner, "setfacl", "getfacl", std::env::temp_dir());
        let g = grant(&declared, Access::RW, true, Shape::Dir);
        let err = b
            .materialize(
                &Principal::User("alice".to_owned()),
                std::slice::from_ref(&g),
            )
            .unwrap_err();
        // The Setfacl error names the declared grant path (what the operator acts on).
        assert!(matches!(err, FileAccessError::Setfacl { ref path, .. } if *path == declared));
    }

    // --- FakeBackend records calls ---

    #[test]
    fn fake_backend_records_calls() {
        let caps = Capabilities {
            dir: true,
            per_path: true,
            pattern: true,
            realtime: false,
            rewrite_proof: false,
        };
        let mut f = FakeBackend::new("fake", caps);
        let g = grant("/srv/ssh", Access::RW, true, Shape::Dir);
        f.materialize(
            &Principal::User("alice".to_owned()),
            std::slice::from_ref(&g),
        )
        .unwrap();
        f.revoke(&Principal::User("alice".to_owned()), &g).unwrap();
        f.snapshot(&[Path::new("/srv/ssh")]).unwrap();
        f.restore().unwrap();
        assert_eq!(
            f.calls,
            vec![
                FakeCall::Materialize {
                    principal: Principal::User("alice".to_owned()),
                    paths: vec!["/srv/ssh".to_owned()],
                },
                FakeCall::Revoke {
                    principal: Principal::User("alice".to_owned()),
                    path: "/srv/ssh".to_owned(),
                },
                FakeCall::Snapshot {
                    paths: vec!["/srv/ssh".to_owned()],
                },
                FakeCall::Restore,
            ]
        );
    }

    // --- capability gating (route_grants) ---

    fn acl_caps() -> Capabilities {
        acl_capabilities()
    }

    #[test]
    fn route_dir_grant_to_acl_backend() {
        let acl = FakeBackend::new("acl", acl_caps());
        let backends: Vec<&dyn FileAccessBackend> = vec![&acl];
        let grants = vec![grant("/srv/ssh", Access::RW, true, Shape::Dir)];
        let routed = route_grants(&grants, &backends).unwrap();
        assert_eq!(routed.len(), 1);
        assert_eq!(routed[0].0, 0, "routed to backend index 0 (acl)");
        assert_eq!(routed[0].1.path, "/srv/ssh");
    }

    #[test]
    fn route_file_grant_with_only_acl_is_unsupported() {
        let acl = FakeBackend::new("acl", acl_caps());
        let backends: Vec<&dyn FileAccessBackend> = vec![&acl];
        let grants = vec![grant(
            "/srv/ssh/sshd_config",
            Access::RW,
            false,
            Shape::File,
        )];
        let err = route_grants(&grants, &backends).unwrap_err();
        match err {
            FileAccessError::Unsupported { shape, reason, .. } => {
                assert_eq!(shape, Shape::File);
                assert!(
                    reason.contains("widen") && reason.contains("directory"),
                    "file-shape suggestion must mention widening to a directory: {reason}"
                );
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn route_pattern_grant_with_only_acl_is_unsupported() {
        let acl = FakeBackend::new("acl", acl_caps());
        let backends: Vec<&dyn FileAccessBackend> = vec![&acl];
        let grants = vec![grant("/var/log/*.log", Access::RO, false, Shape::Pattern)];
        let err = route_grants(&grants, &backends).unwrap_err();
        match err {
            FileAccessError::Unsupported { shape, reason, .. } => {
                assert_eq!(shape, Shape::Pattern);
                assert!(
                    reason.contains("pattern"),
                    "pattern suggestion must mention a pattern-capable backend: {reason}"
                );
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn route_file_and_pattern_to_capable_fake_backend() {
        // An ACL backend (dir only) plus a capable backend (per_path + pattern):
        // dir routes to acl, file/pattern route to the capable one.
        let acl = FakeBackend::new("acl", acl_caps());
        let capable = FakeBackend::new(
            "watch",
            Capabilities {
                dir: false,
                per_path: true,
                pattern: true,
                realtime: false,
                rewrite_proof: false,
            },
        );
        let backends: Vec<&dyn FileAccessBackend> = vec![&acl, &capable];
        let grants = vec![
            grant("/srv/ssh", Access::RW, true, Shape::Dir),
            grant("/srv/ssh/sshd_config", Access::RW, false, Shape::File),
            grant("/var/log/*.log", Access::RO, false, Shape::Pattern),
        ];
        let routed = route_grants(&grants, &backends).unwrap();
        assert_eq!(routed.len(), 3);
        assert_eq!(routed[0].0, 0, "dir → acl (index 0)");
        assert_eq!(routed[1].0, 1, "file → watch (index 1)");
        assert_eq!(routed[2].0, 1, "pattern → watch (index 1)");
    }

    #[test]
    fn route_fails_closed_on_first_unsupported() {
        // A mix where one grant is unroutable: the whole route fails (fail-closed),
        // it does not return a partial routing.
        let acl = FakeBackend::new("acl", acl_caps());
        let backends: Vec<&dyn FileAccessBackend> = vec![&acl];
        let grants = vec![
            grant("/srv/ssh", Access::RW, true, Shape::Dir),
            grant("/var/log/*.log", Access::RO, false, Shape::Pattern),
        ];
        assert!(route_grants(&grants, &backends).is_err());
    }
}
