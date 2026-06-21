//! sudoers.d materialization for role accounts (spec R6).
//!
//! If a role carries a sudo role, Census owns a single file
//! `/etc/sudoers.d/census-<role>`. The **content builder** here is pure and
//! unit-tested; the actual write (temp file → `visudo -c -f <temp>` →
//! atomic rename) is an OS-execution concern done at apply time / integration
//! and is intentionally NOT unit-tested (it requires `visudo`).
//!
//! Census never edits foreign sudoers files — only `census-*`.

use crate::model::ResolvedAccount;
use std::path::{Path, PathBuf};

/// Default directory Census owns role sudoers fragments in. Injectable as a
/// parameter so tests/containers can point at a writable temp dir.
pub const SUDOERS_DIR: &str = "/etc/sudoers.d";

/// Filename (basename) Census owns for a role's sudoers fragment.
pub fn sudoers_filename(role: &str) -> String {
    format!("census-{role}")
}

/// Errors raised while materializing or removing a role sudoers fragment.
#[derive(Debug, thiserror::Error)]
pub enum SudoersError {
    /// Could not write the temporary fragment before validation.
    #[error("cannot write temp sudoers file {path}: {reason}")]
    WriteTemp {
        /// Temp file path.
        path: PathBuf,
        /// OS error.
        reason: String,
    },
    /// Could not set the 0440 mode on the temp fragment.
    #[error("cannot set mode on temp sudoers file {path}: {reason}")]
    Mode {
        /// Temp file path.
        path: PathBuf,
        /// OS error.
        reason: String,
    },
    /// `visudo -c` could not be spawned.
    #[error("cannot run visudo: {reason}")]
    VisudoSpawn {
        /// OS error.
        reason: String,
    },
    /// `visudo -c -f <temp>` rejected the generated fragment. The temp file has
    /// been removed; the live fragment is NOT activated.
    #[error("visudo -c rejected sudoers fragment for role {role}: {stderr}")]
    VisudoRejected {
        /// Role whose fragment failed validation.
        role: String,
        /// Captured visudo stderr (trimmed).
        stderr: String,
    },
    /// The validated temp fragment could not be atomically renamed into place.
    #[error("cannot activate sudoers fragment {dest}: {reason}")]
    Activate {
        /// Destination path.
        dest: PathBuf,
        /// OS error.
        reason: String,
    },
    /// An existing live fragment could not be removed.
    #[error("cannot remove sudoers fragment {path}: {reason}")]
    Remove {
        /// Fragment path.
        path: PathBuf,
        /// OS error.
        reason: String,
    },
}

/// Absolute path of the live fragment Census owns for `role` under `dir`.
pub fn sudoers_path(dir: &Path, role: &str) -> PathBuf {
    dir.join(sudoers_filename(role))
}

/// Materialize a role sudoers fragment: write `content` to a temp file in `dir`,
/// validate it with `visudo -c -f <temp>`, and only on success atomically rename
/// it into `<dir>/census-<role>`. The file is `0440` (sudoers convention) before
/// activation. On `visudo -c` failure the temp file is removed and the live
/// fragment is left untouched (never activated). Atomic: a partial/invalid file
/// is never visible at the canonical path.
pub fn write_sudoers(dir: &Path, role: &str, content: &str) -> Result<(), SudoersError> {
    let tmp = dir.join(format!(".census-{role}.tmp"));

    // Write the candidate fragment via O_EXCL (`create_new`): the open fails if
    // the path already exists, so a pre-planted symlink at this temp path cannot
    // redirect our write to an attacker-chosen file. A leftover temp from a
    // killed run is benign — remove it once and retry, then give up.
    let mut handle = match open_excl(&tmp) {
        Ok(h) => h,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Stale temp from a previous run: clear it and retry exactly once.
            let _ = std::fs::remove_file(&tmp);
            open_excl(&tmp).map_err(|e| SudoersError::WriteTemp {
                path: tmp.clone(),
                reason: e.to_string(),
            })?
        }
        Err(e) => {
            return Err(SudoersError::WriteTemp {
                path: tmp.clone(),
                reason: e.to_string(),
            });
        }
    };
    {
        use std::io::Write as _;
        if let Err(e) = handle.write_all(content.as_bytes()) {
            let _ = std::fs::remove_file(&tmp);
            return Err(SudoersError::WriteTemp {
                path: tmp.clone(),
                reason: e.to_string(),
            });
        }
    }
    drop(handle);

    // sudoers fragments must be 0440 or visudo/sudo refuse them.
    if let Err(e) = set_mode_0440(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // Validate the fragment in isolation (-f points visudo at the temp file).
    let output = std::process::Command::new("visudo")
        .arg("-c")
        .arg("-f")
        .arg(&tmp)
        .output();
    let output = match output {
        Ok(o) => o,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(SudoersError::VisudoSpawn {
                reason: e.to_string(),
            });
        }
    };
    if !output.status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(SudoersError::VisudoRejected {
            role: role.to_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    // Atomic activation: rename the validated temp over the canonical path.
    let dest = sudoers_path(dir, role);
    std::fs::rename(&tmp, &dest).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        SudoersError::Activate {
            dest: dest.clone(),
            reason: e.to_string(),
        }
    })
}

/// Remove the role sudoers fragment Census owns under `dir`. Idempotent: an
/// absent fragment is success (a role that lost its sudo right, or was never
/// granted one, must have no fragment).
pub fn remove_sudoers(dir: &Path, role: &str) -> Result<(), SudoersError> {
    let path = sudoers_path(dir, role);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(SudoersError::Remove {
            path,
            reason: e.to_string(),
        }),
    }
}

/// Create the temp file with O_EXCL semantics: fails with `AlreadyExists` if
/// the path is already present (including a symlink), so we never follow a
/// pre-planted link to clobber an arbitrary file.
fn open_excl(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(unix)]
fn set_mode_0440(path: &Path) -> Result<(), SudoersError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o440)).map_err(|e| {
        SudoersError::Mode {
            path: path.to_path_buf(),
            reason: e.to_string(),
        }
    })
}

#[cfg(not(unix))]
fn set_mode_0440(_path: &Path) -> Result<(), SudoersError> {
    // sudoers is a Unix concept; on non-unix this is a no-op (apply only runs on
    // Linux as root). Kept compilable for cross-platform `cargo test`.
    Ok(())
}

/// Build the sudoers.d file content for an account, or `None` if the role
/// carries no sudo right (no file should exist).
///
/// Two render paths:
/// * **Concrete commands** (preferred, permission-expanded): when
///   `acct.sudo_commands` is non-empty, emit a single per-user rule listing
///   those exact commands comma-joined — `<user> ALL=(ALL) NOPASSWD: /usr/sbin/ip, /usr/bin/nmcli`.
///   `NOPASSWD` because role accounts have locked passwords (§8): there is no
///   password to prompt for, so without `NOPASSWD` sudo would be unusable.
///   Commands come from the catalog, where each value is validated at parse to
///   be a single-line absolute path (control chars — including the newline that
///   would inject a second directive line — are rejected there). As a second
///   layer, every command is run through `escape_sudoers_command`, which
///   neutralises the sudoers metacharacters `, : = \ ( ) !` so each entry
///   renders as exactly one literal Cmnd and cannot split the list or act as a
///   runas/negation directive.
/// * **Escape-hatch alias** (legacy): when there are no concrete commands but a
///   raw `sudo_role` is set, defer the command set to a site-provisioned
///   `Cmnd_Alias` (the prior behaviour, unchanged).
///
/// When both are empty → `None` (no fragment file).
pub fn build_sudoers_content(acct: &ResolvedAccount) -> Option<String> {
    if !acct.sudo_commands.is_empty() {
        let cmds = acct
            .sudo_commands
            .iter()
            .map(|c| escape_sudoers_command(c))
            .collect::<Vec<_>>()
            .join(", ");
        return Some(format!(
            "# Managed by Census — role {role}. Do not edit by hand.\n\
             # Concrete commands expanded from the role's permissions.\n\
             # NOPASSWD: role accounts have locked passwords (no password to prompt).\n\
             {user} ALL=(ALL) NOPASSWD: {cmds}\n",
            role = acct.name,
            user = acct.name,
        ));
    }

    let sudo_role = acct.sudo_role.as_ref()?;
    Some(format!(
        "# Managed by Census — role {role}. Do not edit by hand.\n\
         # Command set is the site-provisioned Cmnd_Alias {alias}.\n\
         {user} ALL=(ALL) {alias}\n",
        role = acct.name,
        user = acct.name,
        alias = sudo_role_alias(sudo_role),
    ))
}

/// Escape a command string for inclusion in a comma-separated sudoers Cmnd list.
///
/// Control characters (notably a newline, which would split the rule into a
/// second physical sudoers directive line) are rejected upstream at catalog
/// parse, so a value reaching here is already a single-line absolute path. This
/// escaper is the second layer: it neutralises the sudoers metacharacters
/// `, : = \ ( ) !` by backslash-escaping each, so every entry renders as exactly
/// one literal Cmnd. `,` is the Cmnd-list separator; `( )` open a per-command
/// runas override; `!` is the negation operator; `: =` are rule punctuation.
/// Without escaping, any of these in a command string could broaden the rule or
/// alter its meaning rather than name a command.
fn escape_sudoers_command(cmd: &str) -> String {
    let mut out = String::with_capacity(cmd.len());
    for ch in cmd.chars() {
        if matches!(ch, ',' | ':' | '=' | '\\' | '(' | ')' | '!') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Map a role-store `sudo_role` string into a sudoers `Cmnd_Alias` token.
/// Uppercased, non-alphanumeric → `_`, to satisfy sudoers alias syntax
/// (`[A-Z][A-Z0-9_]*`). Leading non-alpha is prefixed.
fn sudo_role_alias(sudo_role: &str) -> String {
    let mut out = String::with_capacity(sudo_role.len() + 8);
    out.push_str("CENSUS_");
    for ch in sudo_role.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rolestore::Limits;
    use std::path::PathBuf;

    fn acct(name: &str, sudo_role: Option<&str>) -> ResolvedAccount {
        ResolvedAccount {
            name: name.to_owned(),
            uid: 9010,
            shell: "/bin/bash".to_owned(),
            home: PathBuf::from(format!("/var/lib/census/home/{name}")),
            groups: vec![],
            sudo_role: sudo_role.map(|s| s.to_owned()),
            sudo_commands: Vec::new(),
            limits: Limits::default(),
            locked_password: true,
        }
    }

    /// An account whose sudo right is a set of concrete commands (the
    /// permission-expanded path).
    fn acct_cmds(name: &str, cmds: &[&str]) -> ResolvedAccount {
        ResolvedAccount {
            sudo_commands: cmds.iter().map(|c| c.to_string()).collect(),
            ..acct(name, None)
        }
    }

    #[test]
    fn no_sudo_role_yields_no_file() {
        assert!(build_sudoers_content(&acct("oper", None)).is_none());
    }

    #[test]
    fn sudo_role_yields_rule_referencing_alias() {
        let content = build_sudoers_content(&acct("oper", Some("ops"))).unwrap();
        assert!(content.contains("oper ALL=(ALL) CENSUS_OPS"));
        assert!(content.contains("Managed by Census"));
        // No stray ':' that would break a basic rule line shape.
        for line in content.lines().filter(|l| !l.starts_with('#')) {
            assert!(line.contains("ALL=(ALL)"));
        }
    }

    #[test]
    fn concrete_commands_render_nopasswd_rule() {
        let content = build_sudoers_content(&acct_cmds("oper", &["/usr/sbin/ip", "/usr/bin/nmcli"]))
            .expect("concrete commands yield content");
        // Single per-user NOPASSWD rule with comma-joined commands.
        assert!(
            content.contains("oper ALL=(ALL) NOPASSWD: /usr/sbin/ip, /usr/bin/nmcli"),
            "got: {content}"
        );
        assert!(content.contains("Managed by Census"));
        // NOPASSWD rationale documented (locked passwords).
        assert!(content.contains("NOPASSWD"));
        // No external Cmnd_Alias indirection on the concrete path.
        assert!(!content.contains("CENSUS_"), "concrete path must not emit an alias: {content}");
    }

    #[test]
    fn concrete_commands_win_over_sudo_role() {
        // If both a raw sudo_role AND concrete commands are present, the concrete
        // commands render (the expanded path is the source of truth).
        let mut a = acct_cmds("oper", &["/usr/sbin/ip"]);
        a.sudo_role = Some("ops".to_owned());
        let content = build_sudoers_content(&a).unwrap();
        assert!(content.contains("NOPASSWD: /usr/sbin/ip"));
        assert!(!content.contains("CENSUS_OPS"), "concrete commands take precedence");
    }

    #[test]
    fn concrete_rule_has_valid_sudoers_shape() {
        // Every non-comment line is a single rule with the expected `ALL=(ALL)`
        // run-spec and a NOPASSWD tag; no stray separators that would break it.
        let content = build_sudoers_content(&acct_cmds("oper", &["/usr/sbin/ip", "/usr/bin/nmcli"])).unwrap();
        let rule_lines: Vec<&str> = content.lines().filter(|l| !l.starts_with('#') && !l.is_empty()).collect();
        assert_eq!(rule_lines.len(), 1, "exactly one rule line: {content}");
        let line = rule_lines[0];
        assert!(line.starts_with("oper ALL=(ALL) NOPASSWD: "));
        // The user field is a single token (no embedded space before ALL).
        assert_eq!(line.split_whitespace().next(), Some("oper"));
    }

    #[test]
    fn comma_in_command_is_escaped_so_it_is_not_a_list_separator() {
        // A (contrived) command containing a literal comma must be escaped as
        // `\,` so sudoers treats it as one Cmnd, not two.
        let content = build_sudoers_content(&acct_cmds("oper", &["/usr/bin/odd,name"])).unwrap();
        assert!(content.contains(r"/usr/bin/odd\,name"), "comma must be escaped: {content}");
    }

    #[test]
    fn runas_metacharacters_are_escaped() {
        // sudoers `(`/`)` open a per-command runas override and `!` is the
        // negation operator. The catalog gate rejects such values upstream, but
        // the escaper is the second layer: if one ever reached the renderer it
        // must be neutralised, not act as a directive. Render a contrived value
        // and assert each metacharacter is backslash-escaped (one literal Cmnd).
        let content =
            build_sudoers_content(&acct_cmds("oper", &["(root) /bin/sh", "/bin/x!y"])).unwrap();
        assert!(content.contains(r"\(root\) /bin/sh"), "runas parens must be escaped: {content}");
        assert!(content.contains(r"/bin/x\!y"), "negation bang must be escaped: {content}");
        // No bare `(` / `)` / `!` survive on the rule line.
        for line in content.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            assert!(
                !line.contains("(root)") && !line.contains("x!y"),
                "unescaped metacharacter leaked: {line}"
            );
        }
    }

    #[test]
    fn no_sudo_commands_and_no_role_yields_no_file() {
        assert!(build_sudoers_content(&acct("oper", None)).is_none());
    }

    #[test]
    fn alias_token_is_valid_sudoers_syntax() {
        // alias must match [A-Z][A-Z0-9_]*
        let a = sudo_role_alias("ops-admin.2");
        assert_eq!(a, "CENSUS_OPS_ADMIN_2");
        assert!(a.chars().next().unwrap().is_ascii_uppercase());
        assert!(a.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'));
    }

    #[test]
    fn census_owns_only_prefixed_files() {
        assert_eq!(sudoers_filename("oper"), "census-oper");
        assert!(sudoers_filename("oper").starts_with("census-"));
    }

    #[test]
    fn remove_sudoers_is_ok_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        // No file present → idempotent success.
        remove_sudoers(dir.path(), "oper").unwrap();
        assert!(!sudoers_path(dir.path(), "oper").exists());
    }

    #[test]
    fn remove_sudoers_deletes_present_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = sudoers_path(dir.path(), "oper");
        std::fs::write(&path, b"oper ALL=(ALL) CENSUS_OPS\n").unwrap();
        assert!(path.exists());
        remove_sudoers(dir.path(), "oper").unwrap();
        assert!(!path.exists(), "present fragment must be removed");
    }

    /// Whether `visudo` is on PATH; the write path requires it. Dev machines
    /// without sudo installed skip the live-write assertions rather than fail.
    fn visudo_available() -> bool {
        std::process::Command::new("visudo")
            .arg("-V")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn write_sudoers_validates_and_activates_atomically() {
        if !visudo_available() {
            eprintln!("skipping write_sudoers test: visudo not available");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let content =
            build_sudoers_content(&acct("oper", Some("ops"))).expect("sudo role yields content");
        write_sudoers(dir.path(), "oper", &content).unwrap();
        let dest = sudoers_path(dir.path(), "oper");
        assert!(dest.exists(), "validated fragment must be activated");
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), content);
        // No temp file left behind.
        assert!(!dir.path().join(".census-oper.tmp").exists());
    }

    #[test]
    fn write_sudoers_validates_concrete_command_fragment() {
        // The concrete-command NOPASSWD fragment must pass `visudo -c`.
        if !visudo_available() {
            eprintln!("skipping concrete-command visudo test: visudo not available");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let content = build_sudoers_content(&acct_cmds("oper", &["/usr/sbin/ip", "/usr/bin/nmcli"]))
            .expect("concrete commands yield content");
        write_sudoers(dir.path(), "oper", &content).unwrap();
        let dest = sudoers_path(dir.path(), "oper");
        assert!(dest.exists(), "validated concrete fragment must be activated");
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), content);
    }

    #[cfg(unix)]
    #[test]
    fn write_sudoers_refuses_to_follow_a_preplanted_symlink() {
        // A symlink squatting at the temp path must not redirect our write.
        // O_EXCL fails (AlreadyExists for a symlink) — but a stale REGULAR temp
        // is benign and cleared. Here we plant a symlink to a sentinel target
        // and assert the sentinel is never written through.
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"original\n").unwrap();
        let tmp = dir.path().join(".census-oper.tmp");
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();

        // create_new on a symlink path returns AlreadyExists; remove_file removes
        // the symlink (not its target) and the retry writes a fresh regular file.
        let err = open_excl(&tmp).expect_err("symlink must trip O_EXCL");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        // Victim is untouched by the failed exclusive open.
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "original\n");
    }

    #[test]
    fn write_sudoers_rejects_invalid_fragment_and_does_not_activate() {
        if !visudo_available() {
            eprintln!("skipping invalid-fragment test: visudo not available");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        // Syntactically broken sudoers content → visudo -c must reject it.
        let err = write_sudoers(dir.path(), "oper", "this is not valid sudoers !!!\n")
            .expect_err("invalid sudoers must be rejected");
        assert!(matches!(err, SudoersError::VisudoRejected { .. }));
        assert!(
            !sudoers_path(dir.path(), "oper").exists(),
            "invalid fragment must NOT be activated"
        );
        assert!(!dir.path().join(".census-oper.tmp").exists(), "temp must be cleaned up");
    }
}
