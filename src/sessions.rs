//! Live-session read seam for the §12 live-reconcile gate.
//!
//! Before the delete phase, `apply` consults Tessera's live-session registry
//! (`/run/tessera/sessions.json`, root-only `0600`, published atomically by
//! `tessera-monitord`) and DEFERS `userdel` for any role-account that currently
//! has a live session. Census never kills sessions — it only skips its own
//! destructive step (design "Поток apply").
//!
//! The registry is read *leniently*: Census extracts only `pam_user` (the
//! role-account name) and `uid`, ignoring every other field. This keeps Census
//! decoupled from Tessera's Rust types — the contract is two JSON fields, not a
//! shared struct, so the registry schema can grow without breaking Census.
//!
//! The trait lets the orchestrator be unit-tested without a filesystem: tests
//! use [`FakeSessionSource`], production uses [`LiveSessionSource`] (which reads
//! the file). This mirrors the [`crate::inspect`] inspector seam.

use std::collections::HashSet;
use std::path::PathBuf;

/// The set of role-accounts with a live Tessera session, matchable by name OR
/// by numeric UID (either key is sufficient — uid is stable, name is secondary).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveSessions {
    /// `pam_user` values (role-account names) with a live session.
    pub names: HashSet<String>,
    /// `uid` values with a live session.
    pub uids: HashSet<u32>,
}

impl LiveSessions {
    /// Whether the account identified by `name`/`uid` currently has a live
    /// session. Matches on either key — a name OR a uid hit is enough.
    pub fn matches(&self, name: &str, uid: u32) -> bool {
        self.names.contains(name) || self.uids.contains(&uid)
    }
}

/// One registry entry, parsed leniently. Only `pam_user` and `uid` are read;
/// serde ignores all other fields (session_id, pam_service, cert_cn, …) by
/// default, so Tessera adding fields never breaks this read.
#[derive(Debug, serde::Deserialize)]
struct SessionEntry {
    // Both fields are intentionally REQUIRED (no `#[serde(default)]`): a missing,
    // null, or wrong-type `pam_user`/`uid` is registry corruption, and corruption
    // must make the whole array parse FAIL (→ fail-closed when destructive), never
    // silently blank an entry and shrink the live set — which could drop a real
    // session and let a `userdel` tear it down.
    pam_user: String,
    uid: u32,
}

/// Errors reading the live-session registry. Surfaced as an apply abort
/// (fail-closed) ONLY when the plan is destructive — see [`crate::apply`].
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The registry file is present but could not be read.
    #[error("cannot read live-session registry {path}: {reason}")]
    Io {
        /// The registry path consulted.
        path: PathBuf,
        /// The underlying IO error.
        reason: String,
    },
    /// The registry file is present but its JSON is malformed/truncated. A
    /// corrupt registry is NOT treated as "no sessions" — see fail-closed below.
    #[error("live-session registry {path} is invalid JSON: {reason}")]
    Parse {
        /// The registry path consulted.
        path: PathBuf,
        /// The parse error.
        reason: String,
    },
}

/// Read-only source of the live-session set. Implementations MUST NOT mutate
/// any state (the registry is owned by Tessera; Census only reads it).
pub trait SessionSource {
    /// The set of role-accounts with a live session. A missing registry file
    /// yields an empty set (standalone — no Tessera). An unreadable/corrupt
    /// registry yields `Err` (the caller decides whether to fail closed).
    fn live(&self) -> Result<LiveSessions, SessionError>;
}

/// Production source: reads and leniently parses `/run/tessera/sessions.json`.
#[derive(Debug)]
pub struct LiveSessionSource {
    /// Registry path (default `/run/tessera/sessions.json`, overridable for
    /// tests / non-standard runtime dirs via `--sessions-file`).
    path: PathBuf,
}

impl LiveSessionSource {
    /// Construct a source reading the registry at `path`.
    pub fn new(path: PathBuf) -> Self {
        LiveSessionSource { path }
    }
}

impl SessionSource for LiveSessionSource {
    fn live(&self) -> Result<LiveSessions, SessionError> {
        // Absent file → standalone invariant: no Tessera-managed sessions, so the
        // live set is empty and destructive applies proceed (§12).
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LiveSessions::default());
            }
            Err(e) => {
                return Err(SessionError::Io {
                    path: self.path.clone(),
                    reason: e.to_string(),
                });
            }
        };
        // The writer publishes via temp + rename, so a present file is always a
        // whole snapshot. Corrupt/truncated JSON is therefore a genuine read
        // error, NOT an empty registry — never silently treat it as "no sessions".
        let entries: Vec<SessionEntry> =
            serde_json::from_str(&text).map_err(|e| SessionError::Parse {
                path: self.path.clone(),
                reason: e.to_string(),
            })?;
        let mut live = LiveSessions::default();
        for e in entries {
            live.names.insert(e.pam_user);
            live.uids.insert(e.uid);
        }
        Ok(live)
    }
}

/// In-memory source for tests (orchestrator units without a filesystem).
#[cfg(test)]
pub struct FakeSessionSource {
    /// The live set this fake reports, or an error to simulate an unreadable
    /// registry.
    pub result: Result<LiveSessions, SessionError>,
}

#[cfg(test)]
impl FakeSessionSource {
    /// A source reporting the given live set.
    pub fn with_live(live: LiveSessions) -> Self {
        FakeSessionSource { result: Ok(live) }
    }

    /// A source reporting an empty live set.
    pub fn empty() -> Self {
        FakeSessionSource { result: Ok(LiveSessions::default()) }
    }

    /// A source that fails the read (corrupt/unreadable registry).
    pub fn failing() -> Self {
        FakeSessionSource {
            result: Err(SessionError::Parse {
                path: PathBuf::from("/run/tessera/sessions.json"),
                reason: "injected".to_owned(),
            }),
        }
    }
}

#[cfg(test)]
impl SessionSource for FakeSessionSource {
    fn live(&self) -> Result<LiveSessions, SessionError> {
        match &self.result {
            Ok(live) => Ok(live.clone()),
            Err(SessionError::Io { path, reason }) => Err(SessionError::Io {
                path: path.clone(),
                reason: reason.clone(),
            }),
            Err(SessionError::Parse { path, reason }) => Err(SessionError::Parse {
                path: path.clone(),
                reason: reason.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_tessera_shape_ignoring_extra_fields() {
        // The real `ActiveSession` shape carries many fields beyond pam_user/uid;
        // Census must extract just the two it needs and ignore the rest.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sessions.json");
        std::fs::write(
            &path,
            r#"[
              {"session_id":"abc-123","pam_user":"oper","uid":5001,
               "pam_service":"sshd","target":"host-7","cert_cn":"Engineer A"},
              {"session_id":"def-456","pam_user":"serv","uid":5002,
               "pam_service":"login","cert_cn":"Engineer B","extra":{"nested":true}}
            ]"#,
        )
        .unwrap();
        let live = LiveSessionSource::new(path).live().unwrap();
        assert!(live.names.contains("oper"));
        assert!(live.names.contains("serv"));
        assert!(live.uids.contains(&5001));
        assert!(live.uids.contains(&5002));
        assert_eq!(live.names.len(), 2);
        assert_eq!(live.uids.len(), 2);
    }

    #[test]
    fn missing_file_yields_empty_set() {
        let tmp = tempfile::tempdir().unwrap();
        let live = LiveSessionSource::new(tmp.path().join("absent.json"))
            .live()
            .unwrap();
        assert_eq!(live, LiveSessions::default());
    }

    #[test]
    fn corrupt_json_yields_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sessions.json");
        std::fs::write(&path, "{not json").unwrap();
        let err = LiveSessionSource::new(path).live().unwrap_err();
        assert!(matches!(err, SessionError::Parse { .. }), "got {err:?}");
    }

    #[test]
    fn empty_array_yields_empty_set() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sessions.json");
        std::fs::write(&path, "[]").unwrap();
        let live = LiveSessionSource::new(path).live().unwrap();
        assert_eq!(live, LiveSessions::default());
    }

    #[test]
    fn entry_missing_required_field_yields_error() {
        // Both fields are required: an entry missing `uid` (or with it null) is
        // corruption → the array parse must FAIL, never silently blank the entry
        // and produce a short live set (which could drop a real session).
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing.json");
        std::fs::write(&missing, r#"[{"pam_user":"oper"}]"#).unwrap();
        assert!(
            matches!(
                LiveSessionSource::new(missing).live().unwrap_err(),
                SessionError::Parse { .. }
            ),
            "entry missing uid must fail the parse"
        );

        let null_uid = tmp.path().join("null.json");
        std::fs::write(&null_uid, r#"[{"pam_user":"oper","uid":null}]"#).unwrap();
        assert!(
            matches!(
                LiveSessionSource::new(null_uid).live().unwrap_err(),
                SessionError::Parse { .. }
            ),
            "entry with null uid must fail the parse"
        );
    }

    #[test]
    fn matches_by_uid_only() {
        let mut live = LiveSessions::default();
        live.uids.insert(5001);
        // Name differs, uid hits → match (uid is the stable key).
        assert!(live.matches("renamed", 5001));
        assert!(!live.matches("renamed", 9999));
    }

    #[test]
    fn matches_by_name_only() {
        let mut live = LiveSessions::default();
        live.names.insert("oper".to_owned());
        // Uid differs, name hits → match (name is the secondary key).
        assert!(live.matches("oper", 9999));
        assert!(!live.matches("other", 9999));
    }
}
