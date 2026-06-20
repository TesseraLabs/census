//! Declaration trust gate (fail-closed).
//!
//! `census apply` mutates auth-critical OS state, so it must only proceed on a
//! *trusted* declaration. Two trust modes (spec R7 / requirement
//! "Доверие к декларации до мутаций"):
//!
//! - **managed**: a valid Ed25519 signature over the declaration bytes (the
//!   `signature` line removed) verified against the pinned trust-anchor, plus an
//!   anti-rollback check against the last successfully applied `version`.
//! - **standalone**: explicit `--trust-fs` — the operator vouches for the
//!   integrity of the (root-only) filesystem holding the declaration. This is a
//!   conscious decision and is logged.
//!
//! Any other case → not trusted → caller MUST refuse before any mutation.
//!
//! The signature convention mirrors the Tessera role-store manifest (one Control
//! root of trust): pure EdDSA over the raw declaration bytes with the
//! `signature` line removed byte-for-byte. The algorithm is swappable behind
//! [`verify_ed25519`] (GOST is a future extension through the same point).

use crate::declaration::Declaration;
use ed25519_dalek::{Signature, VerifyingKey};
use std::path::{Path, PathBuf};

/// Production default for the pinned trust-anchor (Control public key).
pub const DEFAULT_TRUST_ANCHOR: &str = "/etc/census/trust.pub";
/// Production default directory for the persisted anti-rollback version floor.
pub const DEFAULT_PERSIST_DIR: &str = "/var/lib/census";
/// File name (within the persist dir) holding the last applied version.
pub const VERSION_FILE: &str = "declaration.version";
/// Sanity cap on the declaration buffer (256 KiB), matching Tessera's
/// `MAX_MANIFEST_BYTES`. Fail-closed before allocation/parse on anything
/// larger — a real declaration is a few hundred roles at most.
pub const MAX_DECLARATION_BYTES: usize = 256 * 1024;

/// Options governing the trust decision (CLI-derived, paths injectable).
#[derive(Debug, Clone)]
pub struct TrustOptions {
    /// `--trust-fs`: trust filesystem integrity (standalone mode).
    pub trust_fs: bool,
    /// Path to the pinned trust-anchor (hex of a 32-byte raw Ed25519 pubkey).
    pub trust_anchor_path: PathBuf,
    /// Directory holding the persisted anti-rollback version floor.
    pub persist_dir: PathBuf,
}

impl Default for TrustOptions {
    fn default() -> Self {
        TrustOptions {
            trust_fs: false,
            trust_anchor_path: PathBuf::from(DEFAULT_TRUST_ANCHOR),
            persist_dir: PathBuf::from(DEFAULT_PERSIST_DIR),
        }
    }
}

/// Trust mode under which a declaration was accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustMode {
    /// `--trust-fs`: filesystem-integrity trust (no signature, no anti-rollback).
    Standalone,
    /// Managed: signature verified + anti-rollback passed at this `version`.
    Managed {
        /// The declaration version that passed verification (to persist on success).
        version: u32,
    },
}

/// Outcome of a trust evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustDecision {
    /// Declaration is trusted; carries the mode and a human-readable log line.
    Trusted {
        /// How trust was granted (standalone vs managed).
        mode: TrustMode,
        /// Why trust was granted (logged before any mutation).
        reason: String,
    },
    /// Declaration is not trusted; `reason` explains why.
    NotTrusted {
        /// Why trust was denied.
        reason: String,
    },
}

impl TrustDecision {
    /// True if the declaration may be applied.
    pub fn is_trusted(&self) -> bool {
        matches!(self, TrustDecision::Trusted { .. })
    }

    /// The human-readable reason carried by either variant.
    pub fn reason(&self) -> &str {
        match self {
            TrustDecision::Trusted { reason, .. } | TrustDecision::NotTrusted { reason } => reason,
        }
    }

    /// The trust mode if trusted (None when not trusted).
    pub fn mode(&self) -> Option<&TrustMode> {
        match self {
            TrustDecision::Trusted { mode, .. } => Some(mode),
            TrustDecision::NotTrusted { .. } => None,
        }
    }
}

/// Errors from trust evaluation (fail-closed: every variant denies apply).
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    /// The declaration carries no `signature` line (managed mode requires one).
    #[error("managed apply requires a signed declaration but no `signature` line is present")]
    MissingSignature,
    /// The declaration bytes are not valid UTF-8 (matches Tessera `NotUtf8`).
    #[error("declaration is not valid UTF-8: {reason}")]
    NotUtf8 {
        /// Underlying decode error message.
        reason: String,
    },
    /// The declaration buffer exceeds the size cap (fail-closed before parse).
    #[error("declaration is {size} bytes, exceeds the {max}-byte cap")]
    Oversize {
        /// Actual byte length.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// A signature was present but its hex was malformed or not 64 bytes.
    #[error("declaration signature hex is malformed: {0}")]
    BadSignatureHex(String),
    /// The trust-anchor file is absent or unreadable.
    #[error("trust-anchor {path} is missing or unreadable: {source}")]
    AnchorUnreadable {
        /// The trust-anchor path that could not be read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The trust-anchor contents are not a valid hex 32-byte Ed25519 key.
    #[error("trust-anchor {path} is not a valid hex 32-byte Ed25519 public key: {reason}")]
    BadKey {
        /// The trust-anchor path.
        path: PathBuf,
        /// What was wrong with the contents.
        reason: String,
    },
    /// The signature did not verify against the trust-anchor.
    #[error("declaration signature does not verify against the trust-anchor")]
    SignatureMismatch,
    /// The declaration version is below the persisted anti-rollback floor.
    #[error("anti-rollback: declaration version {got} is below the last applied version {floor}")]
    Rollback {
        /// The version carried by the declaration under evaluation.
        got: u32,
        /// The last successfully applied version (the floor).
        floor: u32,
    },
    /// Reading the persisted version file failed (present but unreadable/garbage).
    #[error("persisted version at {path} is unreadable or malformed: {reason}")]
    PersistUnreadable {
        /// The version file path.
        path: PathBuf,
        /// What was wrong.
        reason: String,
    },
    /// Writing the persisted version file failed.
    #[error("failed to persist applied version to {path}: {reason}")]
    PersistWrite {
        /// The version file path.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
}

/// Canonicalize declaration bytes for signing/verification: return the bytes
/// with the `signature` line removed entirely (including its trailing newline).
///
/// The signature line is the line whose first non-whitespace token is
/// `signature` immediately followed (after optional whitespace) by `=`. This
/// must match Tessera manifest canonicalization byte-for-byte: the signature
/// covers the raw bytes minus that single line. Exactly one signature line is
/// expected; its absence is [`TrustError::MissingSignature`] (managed mode
/// requires a signature). If multiple lines match, only the first is removed
/// (a well-formed declaration carries exactly one).
pub fn signed_payload(bytes: &[u8]) -> Result<Vec<u8>, TrustError> {
    // Fail-closed on an oversized buffer before any allocation/parse work.
    if bytes.len() > MAX_DECLARATION_BYTES {
        return Err(TrustError::Oversize {
            size: bytes.len(),
            max: MAX_DECLARATION_BYTES,
        });
    }
    // The signed payload must be valid UTF-8 (matches Tessera `signed_payload`,
    // which decodes with `str::from_utf8` first). This also guarantees the
    // line-by-line `is_signature_line` UTF-8 decode below can never silently
    // mis-handle invalid bytes.
    std::str::from_utf8(bytes).map_err(|e| TrustError::NotUtf8 {
        reason: e.to_string(),
    })?;
    let mut out = Vec::with_capacity(bytes.len());
    let mut removed = false;
    let mut idx = 0usize;
    while idx < bytes.len() {
        // Find the end of the current line (index just past the '\n', or EOF).
        let line_end = match bytes[idx..].iter().position(|&b| b == b'\n') {
            Some(rel) => idx + rel + 1, // include the '\n'
            None => bytes.len(),
        };
        let line = &bytes[idx..line_end];
        if !removed && is_signature_line(line) {
            removed = true; // drop this line entirely, including its '\n'
        } else {
            out.extend_from_slice(line);
        }
        idx = line_end;
    }
    if removed {
        Ok(out)
    } else {
        Err(TrustError::MissingSignature)
    }
}

/// True if `line` (which may include a trailing `\n`) is a `signature = ...`
/// line: first non-whitespace token is exactly `signature`, then optional
/// whitespace, then `=`.
///
/// The whitespace class is `str::trim_start()` (all Unicode whitespace) for
/// both the leading trim and the gap before `=`, mirroring Tessera's manifest
/// `is_signature_line` byte-for-byte. A non-UTF-8 line is never the signature
/// line (the signed payload is validated as UTF-8 elsewhere).
fn is_signature_line(line: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(line) else {
        return false;
    };
    let trimmed = s.trim_start();
    match trimmed.strip_prefix("signature") {
        Some(rest) => rest.trim_start().starts_with('='),
        None => false,
    }
}

/// Read and parse the pinned trust-anchor: hex of a 32-byte raw Ed25519 public
/// key. Whitespace (including a trailing newline) is tolerated.
pub fn read_trust_anchor(path: &Path) -> Result<VerifyingKey, TrustError> {
    let raw = std::fs::read_to_string(path).map_err(|source| TrustError::AnchorUnreadable {
        path: path.to_path_buf(),
        source,
    })?;
    let hexed = raw.trim();
    let bytes = hex::decode(hexed).map_err(|e| TrustError::BadKey {
        path: path.to_path_buf(),
        reason: format!("invalid hex: {e}"),
    })?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| TrustError::BadKey {
        path: path.to_path_buf(),
        reason: format!("expected 32 bytes, got {}", bytes.len()),
    })?;
    VerifyingKey::from_bytes(&arr).map_err(|e| TrustError::BadKey {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })
}

/// Verify a detached Ed25519 signature (hex of 64 bytes) over `payload` using
/// `pubkey`. Strict verification (rejects malleable / non-canonical signatures).
pub fn verify_ed25519(
    pubkey: &VerifyingKey,
    payload: &[u8],
    sig_hex: &str,
) -> Result<(), TrustError> {
    let sig_bytes = hex::decode(sig_hex.trim())
        .map_err(|e| TrustError::BadSignatureHex(format!("invalid hex: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| TrustError::BadSignatureHex(format!("expected 64 bytes, got {}", sig_bytes.len())))?;
    let sig = Signature::from_bytes(&sig_arr);
    pubkey
        .verify_strict(payload, &sig)
        .map_err(|_| TrustError::SignatureMismatch)
}

/// Read the persisted anti-rollback floor from `<dir>/declaration.version`.
/// An absent file means "no floor" (`Ok(None)`).
pub fn last_applied_version(dir: &Path) -> Result<Option<u32>, TrustError> {
    let path = dir.join(VERSION_FILE);
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            let v = s.trim().parse::<u32>().map_err(|e| TrustError::PersistUnreadable {
                path: path.clone(),
                reason: e.to_string(),
            })?;
            Ok(Some(v))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TrustError::PersistUnreadable {
            path,
            reason: e.to_string(),
        }),
    }
}

/// Persist the last successfully applied `version` to
/// `<dir>/declaration.version` atomically (temp + rename), 0600 (root-only
/// intent). Called as a SEPARATE step AFTER a successful managed apply — never
/// inside [`verify_trust`].
pub fn persist_version(dir: &Path, version: u32) -> Result<(), TrustError> {
    let path = dir.join(VERSION_FILE);
    let tmp = dir.join(".declaration.version.tmp");
    let body = format!("{version}\n");

    write_private(&tmp, body.as_bytes()).map_err(|e| TrustError::PersistWrite {
        path: tmp.clone(),
        reason: e.to_string(),
    })?;
    std::fs::rename(&tmp, &path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        TrustError::PersistWrite {
            path: path.clone(),
            reason: e.to_string(),
        }
    })?;
    // fsync the parent directory so the rename is durable. Without this a crash
    // right after a successful apply could lose the anti-rollback floor and
    // weaken rollback protection. A directory that cannot be opened/synced is a
    // hard error — never silently ignored.
    sync_parent_dir(&path)
}

/// Open the parent directory of `path` and `sync_all()` it, making a prior
/// `rename` into that directory durable. Surfaces a clear [`TrustError`] if the
/// directory cannot be opened or synced.
fn sync_parent_dir(path: &Path) -> Result<(), TrustError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let dir = std::fs::File::open(parent).map_err(|e| TrustError::PersistWrite {
        path: parent.to_path_buf(),
        reason: format!("open parent dir for fsync failed: {e}"),
    })?;
    dir.sync_all().map_err(|e| TrustError::PersistWrite {
        path: parent.to_path_buf(),
        reason: format!("fsync parent dir failed: {e}"),
    })
}

/// Write `bytes` to `path`, creating it 0600 on Unix (root-only intent).
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Apply the anti-rollback rule: `version < floor` → reject; `==`/`>` → ok.
/// An absent floor (`None`) accepts any version.
fn check_rollback(version: u32, floor: Option<u32>) -> Result<(), TrustError> {
    match floor {
        Some(f) if version < f => Err(TrustError::Rollback { got: version, floor: f }),
        _ => Ok(()),
    }
}

/// Evaluate whether `decl` (with raw `decl_bytes` for signature canonicalization)
/// may be applied. Fail-closed: any failure → `Err`, refuse before any mutation.
///
/// Order (design Р4):
/// 1. `--trust-fs` → `Trusted(Standalone)` + log (no signature, no anti-rollback).
/// 2. managed: read trust-anchor → `signed_payload` → Ed25519 verify →
///    anti-rollback (`decl.version` vs persisted floor) → `Trusted(Managed)`.
///
/// Persisting the new floor is a SEPARATE step done by the caller AFTER a
/// successful apply (see [`persist_version`]).
pub fn verify_trust(
    decl: &Declaration,
    decl_bytes: &[u8],
    opts: &TrustOptions,
) -> Result<TrustDecision, TrustError> {
    if opts.trust_fs {
        return Ok(TrustDecision::Trusted {
            mode: TrustMode::Standalone,
            reason: format!(
                "filesystem trust granted via --trust-fs (standalone), declaration version {}",
                decl.version
            ),
        });
    }

    // Managed path (fail-closed). Signature must be present.
    let sig_hex = decl
        .signature
        .as_deref()
        .ok_or(TrustError::MissingSignature)?;

    let pubkey = read_trust_anchor(&opts.trust_anchor_path)?;
    let payload = signed_payload(decl_bytes)?;
    verify_ed25519(&pubkey, &payload, sig_hex)?;

    // Anti-rollback: reject a version below the persisted floor.
    let floor = last_applied_version(&opts.persist_dir)?;
    check_rollback(decl.version, floor)?;

    Ok(TrustDecision::Trusted {
        mode: TrustMode::Managed { version: decl.version },
        reason: format!(
            "managed trust granted: Ed25519 signature verified, anti-rollback ok, version {}",
            decl.version
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // ---- canonicalization (task 1.3) ----

    #[test]
    fn signed_payload_removes_signature_line_byte_exact() {
        let with_sig = b"version = 5\nrole_store = \"/x\"\nsignature = \"deadbeef\"\nshell = \"/bin/sh\"\n";
        let without = b"version = 5\nrole_store = \"/x\"\nshell = \"/bin/sh\"\n";
        let payload = signed_payload(with_sig).unwrap();
        assert_eq!(payload, without.to_vec(), "signature line + its newline must be gone");
    }

    #[test]
    fn signed_payload_removes_signature_line_at_eof_no_trailing_newline() {
        let with_sig = b"version = 5\nsignature = \"ab\"";
        let payload = signed_payload(with_sig).unwrap();
        assert_eq!(payload, b"version = 5\n".to_vec());
    }

    #[test]
    fn signed_payload_handles_leading_whitespace_and_spaced_equals() {
        let with_sig = b"version = 5\n   signature   =   \"ab\"\nx = 1\n";
        let payload = signed_payload(with_sig).unwrap();
        assert_eq!(payload, b"version = 5\nx = 1\n".to_vec());
    }

    #[test]
    fn signed_payload_missing_signature_is_error() {
        let no_sig = b"version = 5\nrole_store = \"/x\"\n";
        assert!(matches!(signed_payload(no_sig), Err(TrustError::MissingSignature)));
    }

    #[test]
    fn signed_payload_does_not_match_signature_prefix_keys() {
        // `signature_extra` must NOT be treated as the signature line.
        let doc = b"signature_extra = 1\nsignature = \"ab\"\n";
        let payload = signed_payload(doc).unwrap();
        assert_eq!(payload, b"signature_extra = 1\n".to_vec());
    }

    #[test]
    fn signed_payload_my_signature_prefix_does_not_match() {
        // A key that merely ENDS in `signature` (`my_signature`) must not be the
        // signature line; only a line whose trimmed start is `signature` is.
        let doc = b"my_signature = 1\nsignature = \"ab\"\n";
        let payload = signed_payload(doc).unwrap();
        assert_eq!(payload, b"my_signature = 1\n".to_vec());
    }

    #[test]
    fn signed_payload_first_signature_line_wins() {
        // Only the FIRST matching line is removed; a second stays verbatim.
        let doc = b"signature = \"aa\"\nsignature = \"bb\"\n";
        let payload = signed_payload(doc).unwrap();
        assert_eq!(payload, b"signature = \"bb\"\n".to_vec());
    }

    /// H1: the whitespace class must match Tessera's `str::trim_start()` (all
    /// Unicode whitespace), not just ASCII space/tab. A `signature` line led by
    /// `\r`, by NBSP, or with form-feed/`\r` between `signature` and `=` is the
    /// signature line and must be removed — otherwise census would reject a line
    /// Tessera signs, breaking byte-for-byte parity.
    #[test]
    fn signed_payload_unicode_whitespace_parity_with_tessera() {
        // Leading CR before `signature`.
        let cr_led = b"version = 1\n\rsignature = \"ab\"\nx = 1\n";
        assert_eq!(
            signed_payload(cr_led).unwrap(),
            b"version = 1\nx = 1\n".to_vec(),
            "CR-led signature line must be removed"
        );

        // Leading NBSP (U+00A0) before `signature`.
        let nbsp_led = "version = 1\n\u{a0}signature = \"ab\"\nx = 1\n".as_bytes();
        assert_eq!(
            signed_payload(nbsp_led).unwrap(),
            b"version = 1\nx = 1\n".to_vec(),
            "NBSP-led signature line must be removed"
        );

        // Form-feed then CR between `signature` and `=`.
        let gap = "version = 1\nsignature\u{0c}\r= \"ab\"\nx = 1\n".as_bytes();
        assert_eq!(
            signed_payload(gap).unwrap(),
            b"version = 1\nx = 1\n".to_vec(),
            "form-feed/CR gap before `=` must still match the signature line"
        );
    }

    // ---- M1: UTF-8 validation ----

    #[test]
    fn signed_payload_invalid_utf8_is_error() {
        // 0xFF is never valid UTF-8.
        let bad = b"version = 1\nsignature = \"ab\"\n\xff\xfe";
        assert!(matches!(
            signed_payload(bad),
            Err(TrustError::NotUtf8 { .. })
        ));
    }

    // ---- M2: size cap ----

    #[test]
    fn signed_payload_oversize_is_error() {
        // One byte over the cap → Oversize, before any parse/allocation.
        let big = vec![b'a'; MAX_DECLARATION_BYTES + 1];
        match signed_payload(&big) {
            Err(TrustError::Oversize { size, max }) => {
                assert_eq!(size, MAX_DECLARATION_BYTES + 1);
                assert_eq!(max, MAX_DECLARATION_BYTES);
            }
            other => panic!("expected Oversize, got {other:?}"),
        }
    }

    #[test]
    fn signed_payload_at_cap_is_not_oversize() {
        // Exactly at the cap must NOT trip Oversize (it fails later for lack of
        // a signature line, proving the size gate let it through).
        let at_cap = vec![b'a'; MAX_DECLARATION_BYTES];
        assert!(matches!(
            signed_payload(&at_cap),
            Err(TrustError::MissingSignature)
        ));
    }

    // ---- Ed25519 verify (task 2.4) ----

    fn keypair() -> SigningKey {
        // Fixed secret bytes for deterministic tests.
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn anchor_file(dir: &Path, key: &SigningKey) -> PathBuf {
        let p = dir.join("trust.pub");
        let hexed = hex::encode(key.verifying_key().to_bytes());
        std::fs::write(&p, hexed).unwrap();
        p
    }

    #[test]
    fn read_trust_anchor_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = keypair();
        let p = anchor_file(tmp.path(), &sk);
        let vk = read_trust_anchor(&p).unwrap();
        assert_eq!(vk.to_bytes(), sk.verifying_key().to_bytes());
    }

    #[test]
    fn read_trust_anchor_missing_is_error() {
        let tmp = tempfile::tempdir().unwrap();
        let err = read_trust_anchor(&tmp.path().join("nope.pub")).unwrap_err();
        assert!(matches!(err, TrustError::AnchorUnreadable { .. }));
    }

    #[test]
    fn read_trust_anchor_bad_hex_is_error() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("trust.pub");
        std::fs::write(&p, "zznothex").unwrap();
        assert!(matches!(read_trust_anchor(&p).unwrap_err(), TrustError::BadKey { .. }));
    }

    #[test]
    fn read_trust_anchor_wrong_length_is_error() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("trust.pub");
        std::fs::write(&p, hex::encode([1u8; 16])).unwrap(); // 16 bytes, not 32
        assert!(matches!(read_trust_anchor(&p).unwrap_err(), TrustError::BadKey { .. }));
    }

    #[test]
    fn verify_ed25519_valid_signature_passes() {
        let sk = keypair();
        let payload = b"hello payload";
        let sig = sk.sign(payload);
        let sig_hex = hex::encode(sig.to_bytes());
        verify_ed25519(&sk.verifying_key(), payload, &sig_hex).unwrap();
    }

    #[test]
    fn verify_ed25519_tampered_payload_fails() {
        let sk = keypair();
        let sig = sk.sign(b"original");
        let sig_hex = hex::encode(sig.to_bytes());
        let err = verify_ed25519(&sk.verifying_key(), b"tampered", &sig_hex).unwrap_err();
        assert!(matches!(err, TrustError::SignatureMismatch));
    }

    #[test]
    fn verify_ed25519_wrong_key_fails() {
        let sk = keypair();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let sig = sk.sign(b"data");
        let sig_hex = hex::encode(sig.to_bytes());
        let err = verify_ed25519(&other.verifying_key(), b"data", &sig_hex).unwrap_err();
        assert!(matches!(err, TrustError::SignatureMismatch));
    }

    #[test]
    fn verify_ed25519_bad_hex_fails() {
        let sk = keypair();
        let err = verify_ed25519(&sk.verifying_key(), b"data", "nothex!!").unwrap_err();
        assert!(matches!(err, TrustError::BadSignatureHex(_)));
    }

    #[test]
    fn verify_ed25519_wrong_length_sig_fails() {
        let sk = keypair();
        let err = verify_ed25519(&sk.verifying_key(), b"data", "abcd").unwrap_err();
        assert!(matches!(err, TrustError::BadSignatureHex(_)));
    }

    // ---- anti-rollback (task 3.3) ----

    #[test]
    fn check_rollback_three_cases() {
        assert!(matches!(
            check_rollback(4, Some(5)),
            Err(TrustError::Rollback { got: 4, floor: 5 })
        ));
        assert!(check_rollback(5, Some(5)).is_ok()); // equal → ok (idempotent)
        assert!(check_rollback(6, Some(5)).is_ok()); // greater → ok
        assert!(check_rollback(1, None).is_ok()); // absent floor → ok
    }

    #[test]
    fn persist_version_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(last_applied_version(tmp.path()).unwrap(), None, "absent → no floor");
        persist_version(tmp.path(), 42).unwrap();
        assert_eq!(last_applied_version(tmp.path()).unwrap(), Some(42));
        persist_version(tmp.path(), 43).unwrap();
        assert_eq!(last_applied_version(tmp.path()).unwrap(), Some(43));
    }

    /// L1: after adding the parent-directory fsync, persist must still
    /// round-trip cleanly (write then read back the same value).
    #[test]
    fn persist_version_round_trips_with_parent_fsync() {
        let tmp = tempfile::tempdir().unwrap();
        persist_version(tmp.path(), 100).unwrap();
        assert_eq!(last_applied_version(tmp.path()).unwrap(), Some(100));
        // Overwrite a second time to exercise the rename-over-existing path.
        persist_version(tmp.path(), 101).unwrap();
        assert_eq!(last_applied_version(tmp.path()).unwrap(), Some(101));
    }

    #[test]
    fn persist_version_is_root_only_mode() {
        let tmp = tempfile::tempdir().unwrap();
        persist_version(tmp.path(), 1).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(tmp.path().join(VERSION_FILE)).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn last_applied_version_garbage_is_error() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(VERSION_FILE), "not-a-number").unwrap();
        assert!(matches!(
            last_applied_version(tmp.path()).unwrap_err(),
            TrustError::PersistUnreadable { .. }
        ));
    }

    // ---- verify_trust integration (task 2/4) ----

    /// Build a signed declaration: returns (raw_bytes, parsed). The `signature`
    /// line sits among the top-level scalars (before `[defaults]`, as TOML
    /// requires for a top-level key) and the signature covers the canonical
    /// payload = the full doc with that line removed.
    fn signed_decl(sk: &SigningKey, version: u32) -> (String, Declaration) {
        // The exact bytes that will appear on disk, signature line included.
        // We sign `signed_payload(full)` so canonicalization is exercised end-to-end.
        let head = format!("version = {version}\nrole_store = \"/var/lib/tessera/roles\"\n");
        let tail = "[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/var/lib/census/home\"\n";
        // First splice in a placeholder to get the canonical payload (= head+tail).
        let payload = format!("{head}{tail}");
        let sig = sk.sign(payload.as_bytes());
        let sig_hex = hex::encode(sig.to_bytes());
        let full = format!("{head}signature = \"{sig_hex}\"\n{tail}");
        // Sanity: stripping the signature line reproduces the signed payload.
        assert_eq!(signed_payload(full.as_bytes()).unwrap(), payload.as_bytes());
        let decl = Declaration::parse(&full).unwrap();
        (full, decl)
    }

    fn opts(anchor: PathBuf, persist: PathBuf) -> TrustOptions {
        TrustOptions {
            trust_fs: false,
            trust_anchor_path: anchor,
            persist_dir: persist,
        }
    }

    #[test]
    fn verify_trust_standalone_grants_without_signature() {
        let decl = Declaration::parse(
            "version = 7\nrole_store = \"/x\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/h\"\n",
        )
        .unwrap();
        let o = TrustOptions { trust_fs: true, ..Default::default() };
        let d = verify_trust(&decl, b"irrelevant", &o).unwrap();
        assert!(d.is_trusted());
        assert_eq!(d.mode(), Some(&TrustMode::Standalone));
        assert!(d.reason().contains("--trust-fs"));
    }

    #[test]
    fn verify_trust_managed_valid_signature_passes() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = keypair();
        let anchor = anchor_file(tmp.path(), &sk);
        let (raw, decl) = signed_decl(&sk, 5);
        let d = verify_trust(&decl, raw.as_bytes(), &opts(anchor, tmp.path().to_path_buf())).unwrap();
        assert!(d.is_trusted());
        assert_eq!(d.mode(), Some(&TrustMode::Managed { version: 5 }));
    }

    #[test]
    fn verify_trust_managed_missing_signature_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = keypair();
        let anchor = anchor_file(tmp.path(), &sk);
        let decl = Declaration::parse(
            "version = 5\nrole_store = \"/x\"\n[defaults]\nuid_range = [9000, 9999]\nshell = \"/bin/bash\"\nhome_base = \"/h\"\n",
        )
        .unwrap();
        let err = verify_trust(&decl, b"version = 5\n", &opts(anchor, tmp.path().to_path_buf())).unwrap_err();
        assert!(matches!(err, TrustError::MissingSignature));
    }

    #[test]
    fn verify_trust_managed_tampered_payload_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = keypair();
        let anchor = anchor_file(tmp.path(), &sk);
        let (raw, decl) = signed_decl(&sk, 5);
        // Tamper a byte in the payload portion (flip the role_store path).
        let tampered = raw.replace("/var/lib/tessera/roles", "/var/lib/tessera/rolez");
        let err = verify_trust(&decl, tampered.as_bytes(), &opts(anchor, tmp.path().to_path_buf())).unwrap_err();
        assert!(matches!(err, TrustError::SignatureMismatch));
    }

    #[test]
    fn verify_trust_managed_wrong_anchor_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = keypair();
        // Pin a DIFFERENT key as the anchor.
        let other = SigningKey::from_bytes(&[3u8; 32]);
        let anchor = anchor_file(tmp.path(), &other);
        let (raw, decl) = signed_decl(&sk, 5);
        let err = verify_trust(&decl, raw.as_bytes(), &opts(anchor, tmp.path().to_path_buf())).unwrap_err();
        assert!(matches!(err, TrustError::SignatureMismatch));
    }

    #[test]
    fn verify_trust_managed_missing_anchor_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = keypair();
        let (raw, decl) = signed_decl(&sk, 5);
        let missing = tmp.path().join("absent.pub");
        let err = verify_trust(&decl, raw.as_bytes(), &opts(missing, tmp.path().to_path_buf())).unwrap_err();
        assert!(matches!(err, TrustError::AnchorUnreadable { .. }));
    }

    #[test]
    fn verify_trust_managed_rollback_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = keypair();
        let anchor = anchor_file(tmp.path(), &sk);
        // Persist a floor of 9; a version-5 declaration must be rejected.
        persist_version(tmp.path(), 9).unwrap();
        let (raw, decl) = signed_decl(&sk, 5);
        let err = verify_trust(&decl, raw.as_bytes(), &opts(anchor, tmp.path().to_path_buf())).unwrap_err();
        assert!(matches!(err, TrustError::Rollback { got: 5, floor: 9 }));
    }

    #[test]
    fn verify_trust_managed_equal_version_passes() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = keypair();
        let anchor = anchor_file(tmp.path(), &sk);
        persist_version(tmp.path(), 5).unwrap();
        let (raw, decl) = signed_decl(&sk, 5);
        let d = verify_trust(&decl, raw.as_bytes(), &opts(anchor, tmp.path().to_path_buf())).unwrap();
        assert!(d.is_trusted());
    }
}
