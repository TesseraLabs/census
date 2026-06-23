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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// A role-account; materialized as `u:<account>`.
    User(String),
    /// A Unix group; materialized as `g:<group>`. Every member (including
    /// effectively-nested LDAP members) inherits the access.
    Group(String),
}

impl Principal {
    /// The ACL entry prefix: `"u"` for a user, `"g"` for a group. The single point
    /// where the `u:`/`g:` mirror diverges.
    pub fn acl_prefix(&self) -> &'static str {
        match self {
            Principal::User(_) => "u",
            Principal::Group(_) => "g",
        }
    }

    /// The principal's name (the account or group identifier) placed after the
    /// prefix in the ACL entry.
    pub fn name(&self) -> &str {
        match self {
            Principal::User(name) | Principal::Group(name) => name,
        }
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
    /// The top-level grant path is a symlink. `setfacl -R --physical` refuses to
    /// follow symlinks ENCOUNTERED DURING the in-tree walk, but it still resolves
    /// a symlinked ROOT before walking — so a symlinked grant root would point the
    /// recursive ACL mutation at an arbitrary target tree. Refused fail-closed
    /// before any `setfacl` runs.
    #[error("file grant path {path:?} is a symlink; refusing to apply ACLs through it")]
    Symlink {
        /// The symlinked grant path that was refused.
        path: String,
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

/// The ACL permission string for an [`Access`]: `r-X` (ro) or `rwX` (rw).
///
/// The capital `X` means "execute only on directories (and files already executable
/// by someone)": a reader can traverse a directory tree without gaining execute on
/// regular files. Lowercase `x` would set execute on every file, which is not what
/// a read grant intends.
fn acl_perm(access: Access) -> &'static str {
    match access {
        Access::Ro => "r-X",
        Access::Rw => "rwX",
    }
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
    let entry = format!("{}:{}:{}", principal.acl_prefix(), principal.name(), perm);
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
/// `<u|g>:<principal>` is removed; no other entry, owner, or mode is touched. Pure.
pub fn revoke_args(principal: &Principal, grant: &ResolvedFileGrant) -> Vec<Vec<String>> {
    let entry = format!("{}:{}", principal.acl_prefix(), principal.name());
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
/// targets the right files regardless of cwd); `-R` walks the tree. Pure.
pub fn getfacl_args(path: impl AsRef<str>) -> Vec<String> {
    vec![
        "--absolute-names".to_owned(),
        "-R".to_owned(),
        path.as_ref().to_owned(),
    ]
}

/// Build the `setfacl` argv vector that restores ACLs from a rollback dump file.
/// Pure.
pub fn restore_args(rollback_file: impl AsRef<Path>) -> Vec<String> {
    vec![format!("--restore={}", rollback_file.as_ref().display())]
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
            // Lstat the grant ROOT before any setfacl. `--physical` only protects
            // the in-tree walk; a symlinked root is resolved before the walk, so a
            // planted symlink at the grant path would redirect the recursive ACL
            // mutation onto an arbitrary tree. We refuse a symlink root fail-closed.
            // A path that does not exist (or is unreadable) is NOT a symlink finding
            // — the setfacl call below surfaces that as its own error — so only a
            // confirmed symlink is rejected here.
            if std::fs::symlink_metadata(&grant.path)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                tracing::warn!(
                    path = %grant.path,
                    principal = %principal.name(),
                    "refusing to apply ACLs through a symlinked grant root"
                );
                return Err(FileAccessError::Symlink {
                    path: grant.path.clone(),
                });
            }
            for args in setfacl_args(principal, grant) {
                self.runner
                    .run(&self.setfacl_bin, &args)
                    .map_err(|source| FileAccessError::Setfacl {
                        path: grant.path.clone(),
                        source,
                    })?;
            }
            tracing::info!(
                path = %grant.path,
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
        for args in revoke_args(principal, grant) {
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
            let out = self
                .runner
                .run(&self.getfacl_bin, &getfacl_args(&path_str))
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
            }],
        }
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

    // --- pure argv construction ---

    #[test]
    fn setfacl_args_ro_uses_rx_and_default_pass() {
        let g = grant("/etc/ssh", Access::Ro, true, Shape::Dir);
        let args = setfacl_args(&Principal::User("alice".to_owned()), &g);
        assert_eq!(args.len(), 2, "access ACL + default ACL");
        // Access pass: -R --physical -m u:alice:r-X /etc/ssh
        assert_eq!(
            args[0],
            vec!["-R", "--physical", "-m", "u:alice:r-X", "/etc/ssh"]
        );
        // Default pass carries -d.
        assert_eq!(
            args[1],
            vec!["-d", "-R", "--physical", "-m", "u:alice:r-X", "/etc/ssh"]
        );
    }

    #[test]
    fn setfacl_args_rw_uses_rwx() {
        let g = grant("/etc/pam.d", Access::Rw, true, Shape::Dir);
        let args = setfacl_args(&Principal::User("bob".to_owned()), &g);
        assert!(args[0].contains(&"u:bob:rwX".to_owned()));
        assert!(args[1].contains(&"-d".to_owned()));
    }

    #[test]
    fn setfacl_args_group_uses_g_prefix_with_default_pass() {
        // A group grant is the user grant with a `g:` prefix — same -R --physical,
        // same default-ACL pass, only the principal letter differs.
        let g = grant("/srv/shared", Access::Rw, true, Shape::Dir);
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
        let g = grant("/etc/ssh", Access::Ro, true, Shape::Dir);
        let args = setfacl_args(&Principal::User("alice".to_owned()), &g);
        assert_eq!(
            args[0],
            vec!["-R", "--physical", "-m", "u:alice:r-X", "/etc/ssh"]
        );
    }

    #[test]
    fn revoke_args_remove_only_account_entry() {
        let g = grant("/etc/ssh", Access::Rw, true, Shape::Dir);
        let args = revoke_args(&Principal::User("alice".to_owned()), &g);
        assert_eq!(args.len(), 2);
        // -x with u:alice (no perm — removal), access + default. Never names owner
        // or other principals.
        assert_eq!(
            args[0],
            vec!["-R", "--physical", "-x", "u:alice", "/etc/ssh"]
        );
        assert_eq!(
            args[1],
            vec!["-d", "-R", "--physical", "-x", "u:alice", "/etc/ssh"]
        );
        // No argv mentions another principal or chmod/chown.
        for a in args.iter().flatten() {
            assert!(!a.contains("g:") && a != "u:other");
        }
    }

    #[test]
    fn revoke_args_group_removes_only_group_entry() {
        let g = grant("/srv/shared", Access::Rw, true, Shape::Dir);
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
            getfacl_args("/etc/ssh"),
            vec!["--absolute-names", "-R", "/etc/ssh"]
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
        let mut b = acl_with(RecordingRunner::default());
        let g = grant("/etc/ssh", Access::Rw, true, Shape::Dir);
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
        let mut b = acl_with(RecordingRunner::default());
        let g = grant("/srv/shared", Access::Rw, true, Shape::Dir);
        b.materialize(
            &Principal::Group("wheel".to_owned()),
            std::slice::from_ref(&g),
        )
        .unwrap();
        // Both setfacl passes carry the g:wheel entry (access + default), proving the
        // group principal flows through to the real argv the backend would run.
        assert_eq!(b.runner.calls.len(), 2);
        assert_eq!(
            b.runner.calls[0].1,
            vec!["-R", "--physical", "-m", "g:wheel:rwX", "/srv/shared"]
        );
        assert_eq!(
            b.runner.calls[1].1,
            vec!["-d", "-R", "--physical", "-m", "g:wheel:rwX", "/srv/shared"]
        );
    }

    #[test]
    #[cfg(unix)]
    fn acl_refuses_symlinked_grant_root() {
        // A symlink planted AT the grant path would let `setfacl -R` resolve the
        // root and walk the link target, escaping the intended tree. The backend
        // must lstat the root and refuse before running any command.
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real-tree");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("grant-link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let mut b = acl_with(RecordingRunner::default());
        let g = grant(&link.to_string_lossy(), Access::Rw, true, Shape::Dir);
        let err = b
            .materialize(
                &Principal::User("alice".to_owned()),
                std::slice::from_ref(&g),
            )
            .unwrap_err();
        assert!(
            matches!(err, FileAccessError::Symlink { .. }),
            "symlinked grant root must be refused: {err:?}"
        );
        // Refused before running any setfacl.
        assert!(
            b.runner.calls.is_empty(),
            "no command must run for a symlink root"
        );
    }

    #[test]
    #[cfg(unix)]
    fn acl_materialize_allows_real_directory_root() {
        // The dual of the symlink rejection: a genuine (non-symlink) directory root
        // passes the lstat guard and the setfacl passes run.
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real-tree");
        std::fs::create_dir(&real).unwrap();
        let mut b = acl_with(RecordingRunner::default());
        let g = grant(&real.to_string_lossy(), Access::Rw, true, Shape::Dir);
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
        let g = grant("/etc/ssh/sshd_config", Access::Rw, false, Shape::File);
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
        let mut b = acl_with(RecordingRunner::default());
        let g = grant("/etc/ssh", Access::Rw, true, Shape::Dir);
        b.revoke(&Principal::User("alice".to_owned()), &g).unwrap();
        assert_eq!(b.runner.calls.len(), 2);
    }

    #[test]
    fn acl_snapshot_writes_rollback_and_restore_replays_it() {
        let tmp = tempfile::tempdir().unwrap();
        let runner = RecordingRunner {
            stdout: b"# file: /etc/ssh\nuser::rwx\n".to_vec(),
            ..Default::default()
        };
        let mut b = AclBackend::new(runner, "setfacl", "getfacl", tmp.path());
        let p = Path::new("/etc/ssh");
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
        let mut b = AclBackend::new(FailRunner, "setfacl", "getfacl", std::env::temp_dir());
        let g = grant("/etc/ssh", Access::Rw, true, Shape::Dir);
        let err = b
            .materialize(
                &Principal::User("alice".to_owned()),
                std::slice::from_ref(&g),
            )
            .unwrap_err();
        assert!(matches!(err, FileAccessError::Setfacl { ref path, .. } if path == "/etc/ssh"));
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
        let g = grant("/etc/ssh", Access::Rw, true, Shape::Dir);
        f.materialize(
            &Principal::User("alice".to_owned()),
            std::slice::from_ref(&g),
        )
        .unwrap();
        f.revoke(&Principal::User("alice".to_owned()), &g).unwrap();
        f.snapshot(&[Path::new("/etc/ssh")]).unwrap();
        f.restore().unwrap();
        assert_eq!(
            f.calls,
            vec![
                FakeCall::Materialize {
                    principal: Principal::User("alice".to_owned()),
                    paths: vec!["/etc/ssh".to_owned()],
                },
                FakeCall::Revoke {
                    principal: Principal::User("alice".to_owned()),
                    path: "/etc/ssh".to_owned(),
                },
                FakeCall::Snapshot {
                    paths: vec!["/etc/ssh".to_owned()],
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
        let grants = vec![grant("/etc/ssh", Access::Rw, true, Shape::Dir)];
        let routed = route_grants(&grants, &backends).unwrap();
        assert_eq!(routed.len(), 1);
        assert_eq!(routed[0].0, 0, "routed to backend index 0 (acl)");
        assert_eq!(routed[0].1.path, "/etc/ssh");
    }

    #[test]
    fn route_file_grant_with_only_acl_is_unsupported() {
        let acl = FakeBackend::new("acl", acl_caps());
        let backends: Vec<&dyn FileAccessBackend> = vec![&acl];
        let grants = vec![grant(
            "/etc/ssh/sshd_config",
            Access::Rw,
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
        let grants = vec![grant("/var/log/*.log", Access::Ro, false, Shape::Pattern)];
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
            grant("/etc/ssh", Access::Rw, true, Shape::Dir),
            grant("/etc/ssh/sshd_config", Access::Rw, false, Shape::File),
            grant("/var/log/*.log", Access::Ro, false, Shape::Pattern),
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
            grant("/etc/ssh", Access::Rw, true, Shape::Dir),
            grant("/var/log/*.log", Access::Ro, false, Shape::Pattern),
        ];
        assert!(route_grants(&grants, &backends).is_err());
    }
}
