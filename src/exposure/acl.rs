//! POSIX ACL reading and parsing into a structured form.
//!
//! ## Why structured, not raw text
//!
//! The exposure access-check (a later slice) must answer "can uid N with groups
//! {…} read/write this inode?" by consulting the named-user, named-group, and mask
//! entries individually. A raw `getfacl` blob cannot answer that without re-parsing
//! on every query, and string matching against ACL text is fragile. So each inode's
//! ACL is parsed once, at index-build time, into [`AclEntries`] — a typed list of
//! owner / owning-group / named-user / named-group / mask / other entries with their
//! `rwx` bits — and stored on the [`InodeRecord`](super::InodeRecord).
//!
//! ## Why ACLs are read over the walker's paths, best-effort
//!
//! The walker is the single source of scan coverage and its boundaries (it skips
//! pseudo-filesystems, network mounts, and symlinks). The ACL pass therefore reads
//! exactly the inode paths the walker returned — never a recursive `getfacl -R` over
//! a raw root, which would re-descend `/proc` and foreign mounts on a `--full` scan
//! and abort the whole audit the moment one default root (e.g. `/opt`, `/srv`) is
//! absent. Paths are read in argv-batched `getfacl` calls (no shell, no `-R`), and a
//! `getfacl` that fails or exits non-zero for some paths is tolerated: whatever it
//! printed is parsed, the rest are simply left without an ACL (their access falls
//! back to the mode bits). The read can never sink the build, which is why it is
//! infallible.
//!
//! ## Trivial vs extended ACLs
//!
//! Every file has a "minimal" ACL of just `user::`, `group::`, `other::` — those
//! merely restate the mode bits. Such a trivial ACL carries no information beyond the
//! mode and is reported as *no extended ACL* ([`AclEntries::is_extended`] is false);
//! the index stores `None` for it and the access-check falls back to the mode bits.
//! Only a named-user, named-group, or mask entry makes an ACL *extended* and worth
//! storing.

use std::path::PathBuf;
use std::process::Command;

/// The three POSIX permission bits of one ACL entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AclPerms {
    /// Read permission (`r`).
    pub read: bool,
    /// Write permission (`w`).
    pub write: bool,
    /// Execute / directory-search permission (`x`).
    pub execute: bool,
}

impl AclPerms {
    /// All three permission bits set (the access a root principal has, or a fully
    /// permissive entry).
    pub const ALL: Self = Self {
        read: true,
        write: true,
        execute: true,
    };

    /// The canonical `rwx` triple for these bits (`rw-`, `r-x`, `---`, …).
    #[must_use]
    pub fn rwx(self) -> String {
        let r = if self.read { 'r' } else { '-' };
        let w = if self.write { 'w' } else { '-' };
        let x = if self.execute { 'x' } else { '-' };
        [r, w, x].into_iter().collect()
    }

    /// These bits intersected with `mask` — the POSIX ACL mask ceiling on a named or
    /// owning-group entry.
    #[must_use]
    pub const fn masked(self, mask: Self) -> Self {
        Self {
            read: self.read && mask.read,
            write: self.write && mask.write,
            execute: self.execute && mask.execute,
        }
    }

    /// The bitwise union of two permission sets (a principal granted by any of
    /// several applicable group entries gets the OR of their effective bits).
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            read: self.read || other.read,
            write: self.write || other.write,
            execute: self.execute || other.execute,
        }
    }

    /// Whether any permission bit is set.
    #[must_use]
    pub const fn any(self) -> bool {
        self.read || self.write || self.execute
    }
}

/// The kind (tag) of a POSIX ACL entry, identifying which principal class it grants
/// to. Mirrors the `getfacl` entry tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclTag {
    /// The file owner (`user::`).
    UserObj,
    /// A named user (`user:<name>:`).
    User(String),
    /// The owning group (`group::`).
    GroupObj,
    /// A named group (`group:<name>:`).
    Group(String),
    /// The ACL mask (`mask::`) — the ceiling on every named entry and the owning
    /// group.
    Mask,
    /// Everyone else (`other::`).
    Other,
}

/// One parsed POSIX ACL entry: a tag and its permission bits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclEntry {
    /// Which principal class this entry grants to.
    pub tag: AclTag,
    /// The `rwx` bits this entry grants (before mask application).
    pub perms: AclPerms,
}

/// The parsed access ACL of one inode: an ordered list of [`AclEntry`].
///
/// Default-ACL entries (`getfacl`'s `default:` lines, which control inheritance for
/// new files rather than access to this inode) are intentionally dropped — they do
/// not affect this inode's own access.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AclEntries {
    /// The entries, in the order `getfacl` reported them.
    pub entries: Vec<AclEntry>,
}

impl AclEntries {
    /// Whether this ACL is *extended* — carries a named user, named group, or mask
    /// entry, i.e. more than the trivial `user::`/`group::`/`other::` that merely
    /// restates the mode bits. Only an extended ACL is worth storing on an inode.
    #[must_use]
    pub fn is_extended(&self) -> bool {
        self.entries
            .iter()
            .any(|e| matches!(e.tag, AclTag::User(_) | AclTag::Group(_) | AclTag::Mask))
    }

    /// Whether this ACL has no entries at all.
    #[allow(
        clippy::missing_const_for_fn,
        reason = "Vec::is_empty is not const-stable on the older musl cross toolchain used for the Astra target"
    )]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// How many inode paths to pass to one `getfacl` invocation. Chosen well under
/// `ARG_MAX` even with long paths, so a full-scan path list never overruns the argv
/// on a single spawn; a chunk that fails degrades only its own paths.
const GETFACL_PATH_CHUNK: usize = 256;

/// A best-effort command runner for scan-time reads: returns captured stdout
/// **regardless of exit status**, and an empty buffer if the binary cannot be
/// spawned.
///
/// This is deliberately distinct from the file-access
/// [`CommandRunner`](crate::fileaccess::CommandRunner), which returns an error and
/// discards stdout on a non-zero exit — correct for a mutation, wrong for a scan that
/// must tolerate `getfacl` exiting non-zero on some paths while still printing the
/// rest. Kept argv-only (no shell), so no path can be reinterpreted as shell syntax.
pub trait ScanRunner {
    /// Run `binary args`, returning whatever it wrote to stdout (possibly empty).
    fn run_capture(&mut self, binary: &str, args: &[String]) -> Vec<u8>;
}

// Forward `ScanRunner` through a mutable reference so a caller can keep ownership of
// a runner (e.g. to inspect its recorded calls) while still handing it to a reader.
impl<R: ScanRunner + ?Sized> ScanRunner for &mut R {
    fn run_capture(&mut self, binary: &str, args: &[String]) -> Vec<u8> {
        (**self).run_capture(binary, args)
    }
}

/// The production [`ScanRunner`]: spawns the real binary with no shell and returns
/// its stdout even on a non-zero exit; an un-spawnable binary yields an empty buffer.
#[derive(Debug, Clone, Default)]
pub struct BestEffortRunner;

impl ScanRunner for BestEffortRunner {
    fn run_capture(&mut self, binary: &str, args: &[String]) -> Vec<u8> {
        match Command::new(binary).args(args).output() {
            Ok(out) => out.stdout,
            Err(_) => Vec::new(),
        }
    }
}

/// A source of parsed per-inode POSIX ACLs for the inode paths the walker returned.
///
/// Abstracted (rather than calling `getfacl` directly) so the index builder is
/// testable with an in-memory ACL set and so a future native backend can replace the
/// `getfacl` shell-out without changing the index code. Infallible by contract: the
/// ACL read is best-effort and must never sink the build (see the module docs).
pub trait AclSource {
    /// Read and parse the ACLs of the given inode `paths`.
    ///
    /// Returns `(path, entries)` pairs keyed by absolute path. A path absent from the
    /// result has no extended ACL readable (its access is the plain mode bits).
    fn read_acls(&mut self, paths: &[String]) -> Vec<(PathBuf, AclEntries)>;
}

/// The production [`AclSource`]: argv-batched `getfacl` reads over the walker's
/// paths, parsed into structured entries.
///
/// The `getfacl` binary name and the [`ScanRunner`] are injectable so tests drive the
/// parser through a recording runner without executing real commands.
pub struct GetfaclReader<R: ScanRunner> {
    runner: R,
    getfacl_bin: String,
}

// The runner is an injected dependency with no `Debug` bound, so the formatter
// reports the binary name and elides the runner rather than constraining `R: Debug`.
impl<R: ScanRunner> std::fmt::Debug for GetfaclReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetfaclReader")
            .field("getfacl_bin", &self.getfacl_bin)
            .finish_non_exhaustive()
    }
}

impl<R: ScanRunner> GetfaclReader<R> {
    /// Construct with an explicit runner and `getfacl` binary name.
    pub fn new(runner: R, getfacl_bin: impl Into<String>) -> Self {
        Self {
            runner,
            getfacl_bin: getfacl_bin.into(),
        }
    }
}

impl GetfaclReader<BestEffortRunner> {
    /// The production reader: the real `getfacl` on `$PATH`, read best-effort.
    #[must_use]
    pub fn production() -> Self {
        Self::new(BestEffortRunner, "getfacl")
    }
}

impl<R: ScanRunner> AclSource for GetfaclReader<R> {
    fn read_acls(&mut self, paths: &[String]) -> Vec<(PathBuf, AclEntries)> {
        let mut out: Vec<(PathBuf, AclEntries)> = Vec::new();
        for chunk in paths.chunks(GETFACL_PATH_CHUNK) {
            // `--absolute-names` keeps the dumped `# file:` paths absolute so they
            // match the walker's inode paths. No `-R`: each named path is read on its
            // own, so the read can never descend below the walker's scope.
            let mut args: Vec<String> = Vec::with_capacity(chunk.len() + 1);
            args.push("--absolute-names".to_owned());
            args.extend(chunk.iter().cloned());
            let stdout = self.runner.run_capture(&self.getfacl_bin, &args);
            let text = String::from_utf8_lossy(&stdout);
            for (path, entries) in parse_getfacl_dump(&text) {
                out.push((PathBuf::from(path), entries));
            }
        }
        out
    }
}

/// An in-memory [`AclSource`] for tests: returns its canned `(path, entries)` pairs
/// verbatim, ignoring the requested paths.
#[derive(Debug, Clone, Default)]
pub struct FakeAclSource {
    acls: Vec<(PathBuf, AclEntries)>,
}

impl FakeAclSource {
    /// An empty fake (no inode has an ACL).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one inode's parsed ACL.
    #[must_use]
    pub fn with(mut self, path: impl Into<PathBuf>, entries: AclEntries) -> Self {
        self.acls.push((path.into(), entries));
        self
    }
}

impl AclSource for FakeAclSource {
    fn read_acls(&mut self, _paths: &[String]) -> Vec<(PathBuf, AclEntries)> {
        self.acls.clone()
    }
}

/// Parse a `getfacl --absolute-names` dump into per-inode ACLs.
///
/// The dump is a sequence of records separated by blank lines, each beginning with a
/// `# file: <path>` header followed by `# owner:` / `# group:` comments and the ACL
/// entry lines. Returns one `(path, entries)` pair per record. Comment lines and
/// `default:` (inheritance) entries are skipped; unrecognized lines are ignored so a
/// malformed line cannot abort the whole parse.
#[must_use]
pub fn parse_getfacl_dump(text: &str) -> Vec<(String, AclEntries)> {
    let mut out: Vec<(String, AclEntries)> = Vec::new();
    let mut current: Option<(String, Vec<AclEntry>)> = None;

    for line in text.lines() {
        let trimmed = line.trim_end();
        if let Some(rest) = trimmed.strip_prefix("# file:") {
            if let Some((path, entries)) = current.take() {
                out.push((path, AclEntries { entries }));
            }
            current = Some((rest.trim().to_owned(), Vec::new()));
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        if let Some((_, entries)) = current.as_mut() {
            if let Some(entry) = parse_acl_entry(trimmed) {
                entries.push(entry);
            }
        }
    }
    if let Some((path, entries)) = current {
        out.push((path, AclEntries { entries }));
    }
    out
}

/// Parse one `getfacl` entry line into an [`AclEntry`], or `None` if the line is a
/// comment, a `default:` (inheritance) entry, or not a recognizable entry.
///
/// Handles the optional `#effective:` suffix `getfacl` appends when the mask narrows
/// an entry (`group:app:rwx\t#effective:rw-`): only the granted bits before the mask
/// are recorded here; mask application is the access-check's job.
fn parse_acl_entry(line: &str) -> Option<AclEntry> {
    // Drop any `#effective:` (or other) trailing comment, then trim.
    let core = line.split('#').next().unwrap_or("").trim();
    if core.is_empty() {
        return None;
    }
    // Default-ACL entries govern inheritance for new files, not access to this
    // inode; they are out of scope for the access-check.
    if core.starts_with("default:") {
        return None;
    }

    let mut parts = core.splitn(3, ':');
    let tag_word = parts.next()?;
    let qualifier = parts.next()?;
    let perm_field = parts.next()?;
    let perms = parse_perms(perm_field)?;

    let tag = match (tag_word, qualifier.is_empty()) {
        ("user" | "u", true) => AclTag::UserObj,
        ("user" | "u", false) => AclTag::User(qualifier.to_owned()),
        ("group" | "g", true) => AclTag::GroupObj,
        ("group" | "g", false) => AclTag::Group(qualifier.to_owned()),
        ("mask" | "m", _) => AclTag::Mask,
        ("other" | "o", _) => AclTag::Other,
        _ => return None,
    };
    Some(AclEntry { tag, perms })
}

/// Parse an exactly-three-character `rwx` permission field (`rw-`, `r-x`, `---`).
/// Returns `None` for any other length or an unexpected character.
fn parse_perms(field: &str) -> Option<AclPerms> {
    let mut chars = field.chars();
    let r = perm_bit(chars.next()?, 'r')?;
    let w = perm_bit(chars.next()?, 'w')?;
    let x = perm_bit(chars.next()?, 'x')?;
    if chars.next().is_some() {
        return None; // longer than three characters: not a permission triple
    }
    Some(AclPerms {
        read: r,
        write: w,
        execute: x,
    })
}

/// Interpret one permission character: the set letter (`r`/`w`/`x`) means granted,
/// `-` means absent, anything else is unparseable.
const fn perm_bit(c: char, set: char) -> Option<bool> {
    if c == set {
        Some(true)
    } else if c == '-' {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scan runner returning a fixed dump for any invocation, to drive the parser
    /// through `GetfaclReader` without executing real `getfacl`.
    struct CannedRunner {
        stdout: Vec<u8>,
    }
    impl ScanRunner for CannedRunner {
        fn run_capture(&mut self, _binary: &str, _args: &[String]) -> Vec<u8> {
            self.stdout.clone()
        }
    }

    /// A scan runner that records the binary + argv of each call (and returns empty
    /// stdout), so a test can pin the exact `getfacl` flags.
    #[derive(Default)]
    struct RecordingRunner {
        calls: Vec<(String, Vec<String>)>,
    }
    impl ScanRunner for RecordingRunner {
        fn run_capture(&mut self, binary: &str, args: &[String]) -> Vec<u8> {
            self.calls.push((binary.to_owned(), args.to_vec()));
            Vec::new()
        }
    }

    #[test]
    fn getfacl_reader_uses_name_qualifiers() {
        // The access check matches named-user/named-group ACL entries by NAME, which
        // is only correct because `getfacl` is invoked WITHOUT `-n` (numeric). Pin
        // that here so the contract documented on `effective` cannot silently drift:
        // the argv must carry `--absolute-names` and the path, and must NOT carry
        // `-n` / `--numeric` (which would make qualifiers ids and break name matching).
        let mut runner = RecordingRunner::default();
        {
            // Borrow the runner into the reader so we can inspect its recorded calls
            // after the read (the `&mut R: ScanRunner` forward makes this work).
            let mut reader = GetfaclReader::new(&mut runner, "getfacl");
            let _ = reader.read_acls(&["/etc/ssh".to_owned(), "/etc/pam.d".to_owned()]);
        }
        assert_eq!(
            runner.calls.len(),
            1,
            "one batched getfacl call for both paths"
        );
        let (binary, args) = &runner.calls[0];
        assert_eq!(binary, "getfacl");
        assert!(
            args.contains(&"--absolute-names".to_owned()),
            "args: {args:?}"
        );
        assert!(args.contains(&"/etc/ssh".to_owned()));
        assert!(args.contains(&"/etc/pam.d".to_owned()));
        assert!(
            !args.iter().any(|a| a == "-n" || a == "--numeric"),
            "qualifiers must stay names (no -n): {args:?}"
        );
    }

    fn perms(s: &str) -> AclPerms {
        parse_perms(s).expect("test perm triple must parse")
    }

    #[test]
    fn parse_perms_maps_each_slot() {
        assert_eq!(
            perms("rwx"),
            AclPerms {
                read: true,
                write: true,
                execute: true
            }
        );
        assert_eq!(
            perms("r--"),
            AclPerms {
                read: true,
                write: false,
                execute: false
            }
        );
        assert_eq!(
            perms("rw-"),
            AclPerms {
                read: true,
                write: true,
                execute: false
            }
        );
        assert_eq!(
            perms("--x"),
            AclPerms {
                read: false,
                write: false,
                execute: true
            }
        );
        assert_eq!(perms("---"), AclPerms::default());
    }

    #[test]
    fn parse_perms_rejects_bad_field() {
        assert!(parse_perms("rw").is_none(), "too short");
        assert!(parse_perms("rwxr").is_none(), "too long");
        assert!(parse_perms("rwz").is_none(), "bad character");
    }

    #[test]
    fn rwx_round_trips() {
        assert_eq!(perms("r-x").rwx(), "r-x");
        assert_eq!(AclPerms::default().rwx(), "---");
    }

    #[test]
    fn parse_entry_owner_and_owning_group_and_other() {
        assert_eq!(
            parse_acl_entry("user::rwx"),
            Some(AclEntry {
                tag: AclTag::UserObj,
                perms: perms("rwx")
            })
        );
        assert_eq!(
            parse_acl_entry("group::r-x"),
            Some(AclEntry {
                tag: AclTag::GroupObj,
                perms: perms("r-x")
            })
        );
        assert_eq!(
            parse_acl_entry("other::r--"),
            Some(AclEntry {
                tag: AclTag::Other,
                perms: perms("r--")
            })
        );
    }

    #[test]
    fn parse_entry_named_user_group_and_mask() {
        assert_eq!(
            parse_acl_entry("user:role-x:rw-"),
            Some(AclEntry {
                tag: AclTag::User("role-x".to_owned()),
                perms: perms("rw-")
            })
        );
        assert_eq!(
            parse_acl_entry("group:app:rwx"),
            Some(AclEntry {
                tag: AclTag::Group("app".to_owned()),
                perms: perms("rwx")
            })
        );
        assert_eq!(
            parse_acl_entry("mask::rw-"),
            Some(AclEntry {
                tag: AclTag::Mask,
                perms: perms("rw-")
            })
        );
    }

    #[test]
    fn parse_entry_strips_effective_comment() {
        // getfacl appends `#effective:` when the mask narrows an entry; the granted
        // bits before the mask are what we record.
        assert_eq!(
            parse_acl_entry("group:app:rwx\t\t#effective:rw-"),
            Some(AclEntry {
                tag: AclTag::Group("app".to_owned()),
                perms: perms("rwx")
            })
        );
    }

    #[test]
    fn parse_entry_skips_comments_and_default_entries() {
        assert_eq!(parse_acl_entry("# file: /etc/ssh"), None);
        assert_eq!(parse_acl_entry("# owner: root"), None);
        assert_eq!(parse_acl_entry("default:user::rwx"), None);
        assert_eq!(parse_acl_entry("garbage line"), None);
    }

    #[test]
    fn dump_with_named_user_group_and_mask_parses_to_one_record() {
        let dump = "\
# file: /etc/ssh
# owner: root
# group: root
user::rwx
user:role-x:rw-
group::r-x
group:app:rwx
mask::rw-
other::r--
";
        let parsed = parse_getfacl_dump(dump);
        assert_eq!(parsed.len(), 1);
        let (path, acl) = &parsed[0];
        assert_eq!(path, "/etc/ssh");
        assert_eq!(acl.entries.len(), 6);
        assert!(
            acl.is_extended(),
            "named user + named group + mask is extended"
        );
        assert!(acl.entries.contains(&AclEntry {
            tag: AclTag::User("role-x".to_owned()),
            perms: perms("rw-"),
        }));
        assert!(acl.entries.contains(&AclEntry {
            tag: AclTag::Group("app".to_owned()),
            perms: perms("rwx"),
        }));
        assert!(acl.entries.iter().any(|e| matches!(e.tag, AclTag::Mask)));
    }

    #[test]
    fn dump_multiple_records_keyed_by_absolute_path() {
        let dump = "\
# file: /etc/ssh
user::rwx
group::r-x
other::r--

# file: /etc/ssh/sshd_config
user::rw-
user:auditor:r--
group::r--
mask::r--
other::---
";
        let parsed = parse_getfacl_dump(dump);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "/etc/ssh");
        assert_eq!(parsed[1].0, "/etc/ssh/sshd_config");
        assert!(!parsed[0].1.is_extended());
        assert!(parsed[1].1.is_extended());
    }

    #[test]
    fn trivial_acl_is_not_extended() {
        let dump = "\
# file: /etc/hostname
user::rw-
group::r--
other::r--
";
        let parsed = parse_getfacl_dump(dump);
        assert_eq!(parsed.len(), 1);
        assert!(
            !parsed[0].1.is_extended(),
            "only base entries means no extended ACL"
        );
    }

    #[test]
    fn getfacl_reader_runs_runner_and_parses() {
        let dump =
            b"# file: /srv/data\nuser::rwx\nuser:svc:rw-\ngroup::r-x\nmask::rw-\nother::---\n";
        let mut reader = GetfaclReader::new(
            CannedRunner {
                stdout: dump.to_vec(),
            },
            "getfacl",
        );
        let pairs = reader.read_acls(&["/srv/data".to_owned()]);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, PathBuf::from("/srv/data"));
        assert!(pairs[0].1.is_extended());
    }

    #[test]
    fn getfacl_reader_best_effort_returns_only_readable_paths() {
        // getfacl was asked for two paths but could only read one (the other failed,
        // e.g. removed mid-scan): the runner returns a partial dump and the reader
        // returns just the path it could parse — no abort, no fabricated entry.
        let dump = b"# file: /srv/ok\nuser::rwx\nuser:svc:rw-\ngroup::r-x\nmask::rw-\nother::---\n";
        let mut reader = GetfaclReader::new(
            CannedRunner {
                stdout: dump.to_vec(),
            },
            "getfacl",
        );
        let pairs = reader.read_acls(&["/srv/ok".to_owned(), "/srv/gone".to_owned()]);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, PathBuf::from("/srv/ok"));
    }

    #[test]
    fn getfacl_reader_total_failure_yields_empty_not_abort() {
        // getfacl absent or every path failed: empty stdout → no pairs, never panics.
        let mut reader = GetfaclReader::new(CannedRunner { stdout: Vec::new() }, "getfacl");
        let pairs = reader.read_acls(&["/srv/a".to_owned(), "/srv/b".to_owned()]);
        assert!(pairs.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn best_effort_runner_returns_stdout_despite_nonzero_exit() {
        // `ls` over a good and a missing path prints the good listing to stdout and
        // exits non-zero. The best-effort runner must still hand back that stdout —
        // the contract the file-access CommandRunner deliberately does NOT provide.
        let mut runner = BestEffortRunner;
        let out = runner.run_capture("ls", &["/".to_owned(), "/census-no-such-xyzzy".to_owned()]);
        assert!(
            !out.is_empty(),
            "stdout from the good path must survive a non-zero exit"
        );
    }

    #[test]
    #[cfg(unix)]
    fn best_effort_runner_unspawnable_binary_is_empty() {
        let mut runner = BestEffortRunner;
        let out = runner.run_capture("census-no-such-binary-xyzzy", &[]);
        assert!(
            out.is_empty(),
            "an un-spawnable binary yields empty, not a panic"
        );
    }

    #[test]
    fn fake_acl_source_returns_canned_pairs() {
        let acl = AclEntries {
            entries: vec![AclEntry {
                tag: AclTag::User("svc".to_owned()),
                perms: perms("rw-"),
            }],
        };
        let mut src = FakeAclSource::new().with("/srv/x", acl.clone());
        let pairs = src.read_acls(&[]);
        assert_eq!(pairs, vec![(PathBuf::from("/srv/x"), acl)]);
    }
}
