//! Bounded filesystem reads for root-side config/declaration inputs.
//!
//! Census parses operator-authored TOML (declarations, role-store slices,
//! catalog records, localization, os-release) while running as root. A plain
//! [`std::fs::read_to_string`] is unbounded: a hostile or accidentally enormous
//! file would be slurped whole into memory before parsing, a denial-of-service
//! (and potential OOM) with root privileges. [`read_capped`] bounds every such
//! read to a fixed byte ceiling and fails closed past it.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Maximum size, in bytes, of a single config/declaration/state file Census will
/// read into memory.
///
/// Census inputs (a declaration, a role-store slice, a catalog record, an
/// os-release file, a localization table, a trust anchor) are hand-authored TOML
/// measured in kilobytes. 4 MiB is orders of magnitude above any legitimate
/// input yet small enough that reading it is harmless even as root — a value
/// larger than this is treated as malformed rather than parsed.
pub const MAX_INPUT_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Read the file at `path` into a `String`, refusing to read more than
/// `max_bytes`.
///
/// A bounded replacement for [`std::fs::read_to_string`] for root-side inputs:
/// an over-cap file yields an [`io::ErrorKind::InvalidData`] error instead of
/// being read whole into memory.
///
/// The size is checked twice — once against the file's reported length (to
/// reject obvious oversize before any large allocation) and once against the
/// bytes actually read (because the reported length is only advisory: the file
/// could grow between the stat and the read, or be a special file that reports a
/// misleading length). The actual read is bounded with [`Read::take`] so a file
/// that grows past the cap mid-read still cannot exhaust memory.
///
/// # Errors
///
/// Returns an [`io::Error`] if the file cannot be opened or read, if its
/// contents are not valid UTF-8, or if it exceeds `max_bytes` (kind
/// [`io::ErrorKind::InvalidData`]).
pub fn read_capped(path: &Path, max_bytes: u64) -> io::Result<String> {
    let file = File::open(path)?;
    let reported = file.metadata()?.len();
    if reported > max_bytes {
        return Err(oversize_error(path, max_bytes));
    }
    // Read at most one byte past the cap: if that extra byte materializes the
    // file grew after the stat, so fail closed rather than keep reading.
    let mut buf = String::new();
    let read = file
        .take(max_bytes.saturating_add(1))
        .read_to_string(&mut buf)?;
    if read as u64 > max_bytes {
        return Err(oversize_error(path, max_bytes));
    }
    Ok(buf)
}

/// The canonical oversize rejection, shared by both size checks in
/// [`read_capped`] so the message is identical regardless of which fired.
fn oversize_error(path: &Path, max_bytes: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("file {} exceeds the {max_bytes}-byte limit", path.display()),
    )
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn read_capped_accepts_a_file_within_the_cap() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"id = \"ok\"\n").unwrap();
        let text = read_capped(f.path(), MAX_INPUT_FILE_BYTES).unwrap();
        assert_eq!(text, "id = \"ok\"\n");
    }

    #[test]
    fn read_capped_rejects_an_over_cap_file() {
        // A file one byte past a small cap must fail closed with a clean
        // InvalidData error rather than being read into memory.
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let cap: u64 = 16;
        f.write_all(&vec![b'a'; usize::try_from(cap).unwrap() + 1])
            .unwrap();
        let err = read_capped(f.path(), cap).expect_err("over-cap file must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("exceeds"),
            "error should explain the size limit, got: {err}"
        );
    }

    #[test]
    fn read_capped_accepts_a_file_exactly_at_the_cap() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let cap: u64 = 16;
        f.write_all(&vec![b'a'; usize::try_from(cap).unwrap()])
            .unwrap();
        let text = read_capped(f.path(), cap).unwrap();
        assert_eq!(text.len(), usize::try_from(cap).unwrap());
    }
}
