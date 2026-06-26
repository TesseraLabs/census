//! sudoers.d materialization for role accounts and role-bound groups (spec R6).
//!
//! If a role carries a sudo role, Census owns a single file
//! `/etc/sudoers.d/census-<role>` with a per-user rule. A role-bound group whose
//! roles grant sudo commands gets `/etc/sudoers.d/census-grp-<group>` with a
//! `%group` rule. The **content builders** here are pure and unit-tested; the
//! actual write (temp file → `visudo -c -f <temp>` → atomic rename) is an
//! OS-execution concern done at apply time / integration and is intentionally
//! NOT unit-tested (it requires `visudo`).
//!
//! Census never edits foreign sudoers files — only `census-*` / `census-grp-*`.

use std::path::{Path, PathBuf};

use crate::model::{ResolvedAccount, ResolvedGroup};

/// Default directory Census owns role sudoers fragments in. Injectable as a
/// parameter so tests/containers can point at a writable temp dir.
pub const SUDOERS_DIR: &str = "/etc/sudoers.d";

/// Filename (basename) Census owns for a role's sudoers fragment.
pub fn sudoers_filename(role: &str) -> String {
    format!("census-{role}")
}

/// Filename (basename) Census owns for a group's `%group` sudoers fragment. The
/// `grp-` infix keeps group fragments in a distinct namespace from per-role
/// account fragments so a group can never collide with a same-named role.
pub fn sudoers_group_filename(group: &str) -> String {
    format!("census-grp-{group}")
}

/// Errors raised while materializing or removing a role sudoers fragment.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
    #[error("visudo -c rejected sudoers fragment for {subject}: {stderr}")]
    VisudoRejected {
        /// Subject whose fragment failed validation — a role name for an account
        /// fragment, or a group name for a `%group` fragment.
        subject: String,
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
/// Test-only convenience over [`sudoers_filename`] (production code joins the
/// filename onto the sudoers dir directly).
#[cfg(test)]
pub fn sudoers_path(dir: &Path, role: &str) -> PathBuf {
    dir.join(sudoers_filename(role))
}

/// Absolute path of the live `%group` fragment Census owns for `group` under `dir`.
pub fn sudoers_group_path(dir: &Path, group: &str) -> PathBuf {
    dir.join(sudoers_group_filename(group))
}

/// Materialize a role sudoers fragment: write `content` to a temp file in `dir`,
/// validate it with `visudo -c -f <temp>`, and only on success atomically rename
/// it into `<dir>/census-<role>`. The file is `0440` (sudoers convention) before
/// activation. On `visudo -c` failure the temp file is removed and the live
/// fragment is left untouched (never activated). Atomic: a partial/invalid file
/// is never visible at the canonical path.
pub fn write_sudoers(dir: &Path, role: &str, content: &str) -> Result<(), SudoersError> {
    write_fragment(dir, &sudoers_filename(role), content, role)
}

/// Remove the role sudoers fragment Census owns under `dir`. Idempotent: an
/// absent fragment is success (a role that lost its sudo right, or was never
/// granted one, must have no fragment).
pub fn remove_sudoers(dir: &Path, role: &str) -> Result<(), SudoersError> {
    remove_fragment(dir, &sudoers_filename(role))
}

/// Materialize a group `%group` sudoers fragment into `<dir>/census-grp-<group>`.
/// Behaves exactly like [`write_sudoers`] (temp → `visudo -c -f` → atomic
/// rename, 0440, never activates an invalid fragment), only the target file and
/// the diagnostic subject differ.
pub fn write_group_sudoers(dir: &Path, group: &str, content: &str) -> Result<(), SudoersError> {
    write_fragment(dir, &sudoers_group_filename(group), content, group)
}

/// Remove the group `%group` sudoers fragment Census owns under `dir`.
/// Idempotent: an absent fragment is success (a group that lost its sudo grant,
/// or never had one, must have no fragment).
pub fn remove_group_sudoers(dir: &Path, group: &str) -> Result<(), SudoersError> {
    remove_fragment(dir, &sudoers_group_filename(group))
}

/// Shared write core for any Census-owned sudoers fragment (account `census-<role>`
/// or group `census-grp-<group>`). Writes `content` to a temp file in `dir`,
/// validates it with `visudo -c -f <temp>`, and only on success atomically
/// renames it into `<dir>/<filename>`. The file is `0440` (sudoers convention)
/// before activation. On `visudo -c` failure the temp file is removed and the
/// live fragment is left untouched (never activated). Atomic: a partial/invalid
/// file is never visible at the canonical path. `subject` labels the fragment in
/// a [`SudoersError::VisudoRejected`] (a role or group name) for diagnostics only.
fn write_fragment(
    dir: &Path,
    filename: &str,
    content: &str,
    subject: &str,
) -> Result<(), SudoersError> {
    let tmp = dir.join(format!(".{filename}.tmp"));

    // Write the candidate fragment via O_EXCL (`create_new`): the open fails if
    // the path already exists, so a pre-planted symlink at this temp path cannot
    // redirect our write to an attacker-chosen file. A leftover temp from a
    // killed run is benign — remove it once and retry, then give up.
    let mut handle = match open_excl(&tmp) {
        Ok(h) => h,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Stale temp from a previous run: clear it and retry exactly once.
            cleanup_temp(&tmp);
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
            cleanup_temp(&tmp);
            return Err(SudoersError::WriteTemp {
                path: tmp.clone(),
                reason: e.to_string(),
            });
        }
    }
    drop(handle);

    // sudoers fragments must be 0440 or visudo/sudo refuse them.
    if let Err(e) = set_mode_0440(&tmp) {
        cleanup_temp(&tmp);
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
            cleanup_temp(&tmp);
            return Err(SudoersError::VisudoSpawn {
                reason: e.to_string(),
            });
        }
    };
    if !output.status.success() {
        cleanup_temp(&tmp);
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        tracing::warn!(subject, stderr = %stderr, "visudo rejected sudoers fragment");
        return Err(SudoersError::VisudoRejected {
            subject: subject.to_owned(),
            stderr,
        });
    }

    // Atomic activation: rename the validated temp over the canonical path.
    let dest = dir.join(filename);
    std::fs::rename(&tmp, &dest).map_err(|e| {
        cleanup_temp(&tmp);
        SudoersError::Activate {
            dest: dest.clone(),
            reason: e.to_string(),
        }
    })?;
    tracing::info!(subject, path = %dest.display(), "activated sudoers fragment");
    Ok(())
}

/// Best-effort removal of a leftover sudoers temp fragment. Never propagates —
/// a cleanup failure must not mask the primary error. A `NotFound` is expected
/// (already gone / consumed by the rename) and silent; any other failure is
/// logged at warn so a leaked temp file is visible.
fn cleanup_temp(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(path = %path.display(), error = %e, "failed to remove temp sudoers fragment");
        }
    }
}

/// Shared idempotent remove for any Census-owned sudoers fragment. An absent
/// fragment is success.
fn remove_fragment(dir: &Path, filename: &str) -> Result<(), SudoersError> {
    let path = dir.join(filename);
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
/// * **Concrete commands** (preferred, permission-expanded): when `acct.sudo_commands` is
///   non-empty, emit a single per-user rule listing those exact commands comma-joined — `<user>
///   ALL=(ALL) NOPASSWD: /usr/sbin/ip, /usr/bin/nmcli`. `NOPASSWD` because role accounts have
///   locked passwords (§8): there is no password to prompt for, so without `NOPASSWD` sudo would be
///   unusable. Commands come from the catalog, where each value is validated at parse to be a
///   single-line absolute path (control chars — including the newline that would inject a second
///   directive line — are rejected there). As a second layer, every command is run through
///   `escape_sudoers_command`, which neutralises the sudoers metacharacters `, : = \ ( ) !` so each
///   entry renders as exactly one literal Cmnd and cannot split the list or act as a runas/negation
///   directive.
/// * **Escape-hatch alias** (legacy): when there are no concrete commands but a raw `sudo_role` is
///   set, defer the command set to a site-provisioned `Cmnd_Alias` (the prior behaviour,
///   unchanged).
///
/// When both are empty → `None` (no fragment file).
pub fn build_sudoers_content(acct: &ResolvedAccount) -> Option<String> {
    build_account_sudoers_from_parts(&acct.name, &acct.sudo_commands, acct.sudo_role.as_deref())
}

/// Render an account's `census-<name>` fragment from the exact fields the
/// fragment depends on — the login name, the concrete sudo commands, and the raw
/// `sudo_role` escape hatch — rather than a whole [`ResolvedAccount`].
///
/// This is the single rendering path [`build_sudoers_content`] delegates to. It
/// is factored out so a CALLER that only has the persisted managed record (which
/// carries `name`/`sudo_commands`/`sudo_role` but not the identity fields a
/// resolved account has) can render the SAME fragment the resolved target would
/// produce — letting `plan --diff` compute a fragment diff (current managed →
/// target) without fabricating a dummy `ResolvedAccount`. The rendered bytes are
/// identical to the resolved path: same renderer, same escaping, same NOPASSWD
/// rationale, so the diff reflects exactly what apply would write.
pub fn build_account_sudoers_from_parts(
    name: &str,
    sudo_commands: &[crate::model::SudoCommand],
    sudo_role: Option<&str>,
) -> Option<String> {
    if !sudo_commands.is_empty() {
        let run_spec = render_runspec(sudo_commands);
        return Some(format!(
            "# Managed by Census — role {role}. Do not edit by hand.\n\
             # Concrete commands expanded from the role's permissions.\n\
             # NOPASSWD: role accounts have locked passwords (no password to prompt).\n\
             {user} ALL={run_spec}\n",
            role = name,
            user = name,
        ));
    }

    let sudo_role = sudo_role?;
    Some(format!(
        "# Managed by Census — role {role}. Do not edit by hand.\n\
         # Command set is the site-provisioned Cmnd_Alias {alias}.\n\
         {user} ALL=(ALL) {alias}\n",
        role = name,
        user = name,
        alias = sudo_role_alias(sudo_role),
    ))
}

/// Build the `%group` sudoers.d fragment content for a role-bound group, or
/// `None` when the group's bound roles grant no sudo commands (no file exists).
///
/// The subject is the Unix group, written `%<group>`, so the rule applies to
/// every effective member of that group — including users folded in by LDAP
/// nested-group membership, which the kernel resolves transparently behind the
/// group name. The command set is the group's concrete `sudo_commands` (already
/// unioned across every bound role at resolve), comma-joined as one Cmnd list.
///
/// `NOPASSWD` mirrors the account fragment: the group's members are real, often
/// human users with their own passwords, but the design grants the `%group`
/// rule without a password prompt deliberately — a group sudo grant is a managed
/// capability, not an interactive re-auth checkpoint. (See [`build_sudoers_content`]
/// for the account-side rationale; here it is a conscious design choice, not a
/// consequence of locked passwords.)
///
/// Unlike the account builder there is no `Cmnd_Alias` escape-hatch path: a
/// [`ResolvedGroup`] carries only concrete `sudo_commands`, never a raw
/// `sudo_role`. Each command is run through [`escape_sudoers_command`] so a
/// metacharacter can neither split the list nor act as a runas/negation directive.
pub fn build_group_sudoers_content(group: &ResolvedGroup) -> Option<String> {
    build_group_sudoers_from_parts(&group.name, &group.sudo_commands)
}

/// Render a group's `census-grp-<group>` `%group` fragment from just the group
/// name and its concrete sudo commands. The single rendering path
/// [`build_group_sudoers_content`] delegates to, factored out for the same reason
/// as [`build_account_sudoers_from_parts`]: `plan --diff` can render the fragment
/// from the persisted managed group record (current) and the resolved group
/// (target) through one renderer, so the diff shows exactly what apply would
/// write, runas and all.
pub fn build_group_sudoers_from_parts(
    name: &str,
    sudo_commands: &[crate::model::SudoCommand],
) -> Option<String> {
    if sudo_commands.is_empty() {
        return None;
    }
    let run_spec = render_runspec(sudo_commands);
    Some(format!(
        "# Managed by Census — group {group}. Do not edit by hand.\n\
         # Concrete commands expanded from the bound roles' permissions.\n\
         # Subject is the Unix group (%): every effective member inherits the rule,\n\
         # including LDAP nested-group members resolved behind the group name.\n\
         # NOPASSWD: a managed group sudo grant is not an interactive re-auth point.\n\
         %{group} ALL={run_spec}\n",
        group = name,
    ))
}

/// Render the run-spec body that follows `ALL=` for a set of sudo commands,
/// grouping commands by their run-as account.
///
/// Each distinct run-as account becomes one `(<runas>) NOPASSWD: <cmds...>`
/// group; the groups are concatenated into a single rule line. A command with
/// `runas: None` renders under `(ALL)` (run as root) — the historical default.
///
/// Two invariants matter here:
/// * **Backward-compat / determinism.** Groups appear in the first-appearance
///   order of their run-as account across the command list, and commands keep
///   their accumulated order within a group. When every command has `runas:
///   None` there is exactly one group — `(ALL) NOPASSWD: c1, c2` — byte-identical
///   to the pre-`runas` output, so existing fragments and goldens are unchanged.
/// * **Defense in depth.** Both the command and the run-as token are run through
///   [`escape_sudoers_command`] so a stray metacharacter neutralizes to a literal
///   rather than altering the rule. The catalog `runas` gate is the primary
///   guard (a validated token carries no metacharacter and renders verbatim);
///   this is the second layer for anything that somehow reaches the renderer.
fn render_runspec(commands: &[crate::model::SudoCommand]) -> String {
    // Preserve first-appearance order of each run-as account. A Vec of
    // (runas, joined-commands) keeps that order without a separate ordering pass.
    let mut groups: Vec<(Option<String>, Vec<String>)> = Vec::new();
    for cmd in commands {
        let escaped = escape_sudoers_command(&cmd.command);
        match groups.iter_mut().find(|(r, _)| *r == cmd.runas) {
            Some((_, cmds)) => cmds.push(escaped),
            None => groups.push((cmd.runas.clone(), vec![escaped])),
        }
    }
    groups
        .into_iter()
        .map(|(runas, cmds)| {
            let spec = match runas {
                // `None` is the default run-spec: run as root, rendered `(ALL)`.
                None => "ALL".to_owned(),
                // A validated username has no metacharacters, but escape anyway as
                // defense in depth so it can only ever render as one literal token.
                Some(u) => escape_sudoers_command(&u),
            };
            format!("({spec}) NOPASSWD: {}", cmds.join(", "))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Escape a command string for inclusion in a comma-separated sudoers Cmnd list.
///
/// Control characters (notably a newline, which would split the rule into a
/// second physical sudoers directive line) are rejected upstream at catalog
/// parse, so a value reaching here is already a single-line absolute path. This
/// escaper is the second layer: it neutralises the sudoers metacharacters
/// `, : = \ ( ) ! #` by backslash-escaping each, so every entry renders as exactly
/// one literal Cmnd. `,` is the Cmnd-list separator; `( )` open a per-command
/// runas override; `!` is the negation operator; `: =` are rule punctuation; `#`
/// starts a comment that would silently truncate the rest of the line. Without
/// escaping, any of these in a command string could broaden the rule, comment out
/// part of it, or alter its meaning rather than name a command.
fn escape_sudoers_command(cmd: &str) -> String {
    let mut out = String::with_capacity(cmd.len());
    for ch in cmd.chars() {
        if matches!(ch, ',' | ':' | '=' | '\\' | '(' | ')' | '!' | '#') {
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
            file_grants: Vec::new(),
            locked_password: true,
            provenance: crate::model::Provenance::Created,
        }
    }

    use crate::model::SudoCommand;

    /// An account whose sudo right is a set of concrete root commands (the
    /// permission-expanded path; every command runs as root / `(ALL)`).
    fn acct_cmds(name: &str, cmds: &[&str]) -> ResolvedAccount {
        ResolvedAccount {
            sudo_commands: cmds.iter().map(|c| SudoCommand::root(*c)).collect(),
            ..acct(name, None)
        }
    }

    /// An account whose sudo right is an explicit list of `SudoCommand`s (used to
    /// exercise the run-as grouping).
    fn acct_runas(name: &str, cmds: Vec<SudoCommand>) -> ResolvedAccount {
        ResolvedAccount {
            sudo_commands: cmds,
            ..acct(name, None)
        }
    }

    /// A resolved group carrying the given concrete root sudo commands (the only
    /// field the `%group` sudoers builder reads).
    fn group_cmds(name: &str, cmds: &[&str]) -> ResolvedGroup {
        group_runas(name, cmds.iter().map(|c| SudoCommand::root(*c)).collect())
    }

    /// A resolved group carrying an explicit list of `SudoCommand`s.
    fn group_runas(name: &str, cmds: Vec<SudoCommand>) -> ResolvedGroup {
        ResolvedGroup {
            name: name.to_owned(),
            gid: None,
            provenance: crate::model::Provenance::Created,
            members: Vec::new(),
            sudo_commands: cmds,
            file_grants: Vec::new(),
            limits: Limits::default(),
            bound_roles: Vec::new(),
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
        let content =
            build_sudoers_content(&acct_cmds("oper", &["/usr/sbin/ip", "/usr/bin/nmcli"]))
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
        assert!(
            !content.contains("CENSUS_"),
            "concrete path must not emit an alias: {content}"
        );
    }

    #[test]
    fn concrete_commands_win_over_sudo_role() {
        // If both a raw sudo_role AND concrete commands are present, the concrete
        // commands render (the expanded path is the source of truth).
        let mut a = acct_cmds("oper", &["/usr/sbin/ip"]);
        a.sudo_role = Some("ops".to_owned());
        let content = build_sudoers_content(&a).unwrap();
        assert!(content.contains("NOPASSWD: /usr/sbin/ip"));
        assert!(
            !content.contains("CENSUS_OPS"),
            "concrete commands take precedence"
        );
    }

    #[test]
    fn concrete_rule_has_valid_sudoers_shape() {
        // Every non-comment line is a single rule with the expected `ALL=(ALL)`
        // run-spec and a NOPASSWD tag; no stray separators that would break it.
        let content =
            build_sudoers_content(&acct_cmds("oper", &["/usr/sbin/ip", "/usr/bin/nmcli"])).unwrap();
        let rule_lines: Vec<&str> = content
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .collect();
        assert_eq!(rule_lines.len(), 1, "exactly one rule line: {content}");
        let line = rule_lines[0];
        assert!(line.starts_with("oper ALL=(ALL) NOPASSWD: "));
        // The user field is a single token (no embedded space before ALL).
        assert_eq!(line.split_whitespace().next(), Some("oper"));
    }

    #[test]
    fn all_root_commands_render_byte_identical_to_the_legacy_all_runspec() {
        // Backward-compat invariant: when every command runs as root (runas:
        // None), the rule line MUST be exactly the pre-`runas` `(ALL)` form. Build
        // the same account two ways — through the root helper and through an
        // explicit all-None list — and assert both produce the historical line.
        let via_helper =
            build_sudoers_content(&acct_cmds("oper", &["/usr/sbin/ip", "/usr/bin/nmcli"]))
                .expect("root commands yield content");
        let via_explicit = build_sudoers_content(&acct_runas(
            "oper",
            vec![
                SudoCommand::root("/usr/sbin/ip"),
                SudoCommand::root("/usr/bin/nmcli"),
            ],
        ))
        .expect("explicit None commands yield content");
        assert_eq!(via_helper, via_explicit, "the two forms must be identical");
        let rule = via_helper
            .lines()
            .find(|l| !l.starts_with('#') && !l.is_empty())
            .expect("a rule line");
        assert_eq!(
            rule,
            "oper ALL=(ALL) NOPASSWD: /usr/sbin/ip, /usr/bin/nmcli"
        );
    }

    #[test]
    fn mixed_runas_groups_commands_by_runspec_in_first_appearance_order() {
        // A permission narrowing two commands to a service account, plus one root
        // command. The service-account group appears first (its commands came
        // first), then the `(ALL)` group — exactly one rule line.
        let content = build_sudoers_content(&acct_runas(
            "oper",
            vec![
                SudoCommand::as_user("/opt/x", "bfs_solutions"),
                SudoCommand::as_user("/opt/y", "bfs_solutions"),
                SudoCommand::root("/usr/sbin/ip"),
            ],
        ))
        .expect("mixed runas yields content");
        let rule = content
            .lines()
            .find(|l| !l.starts_with('#') && !l.is_empty())
            .expect("a rule line");
        assert_eq!(
            rule,
            "oper ALL=(bfs_solutions) NOPASSWD: /opt/x, /opt/y, (ALL) NOPASSWD: /usr/sbin/ip"
        );
    }

    #[test]
    fn group_mixed_runas_groups_commands_by_runspec() {
        // The same grouping on the `%group` builder.
        let content = build_group_sudoers_content(&group_runas(
            "wheel",
            vec![
                SudoCommand::as_user("/opt/x", "bfs_solutions"),
                SudoCommand::as_user("/opt/y", "bfs_solutions"),
                SudoCommand::root("/usr/sbin/ip"),
            ],
        ))
        .expect("mixed runas yields content");
        let rule = content
            .lines()
            .find(|l| !l.starts_with('#') && !l.is_empty())
            .expect("a rule line");
        assert_eq!(
            rule,
            "%wheel ALL=(bfs_solutions) NOPASSWD: /opt/x, /opt/y, (ALL) NOPASSWD: /usr/sbin/ip"
        );
    }

    #[test]
    fn group_all_root_renders_byte_identical_to_legacy() {
        // Backward-compat for the %group builder: an all-root group is the
        // historical `(ALL)` line, unchanged.
        let content =
            build_group_sudoers_content(&group_cmds("wheel", &["/usr/sbin/ip", "/usr/bin/nmcli"]))
                .expect("root commands yield content");
        let rule = content
            .lines()
            .find(|l| !l.starts_with('#') && !l.is_empty())
            .expect("a rule line");
        assert_eq!(
            rule,
            "%wheel ALL=(ALL) NOPASSWD: /usr/sbin/ip, /usr/bin/nmcli"
        );
    }

    #[test]
    fn write_sudoers_validates_mixed_runas_fragment() {
        // The mixed-runas fragment must pass `visudo -c`: a service-account group
        // followed by the root group is valid sudoers.
        if !visudo_available() {
            eprintln!("skipping mixed-runas visudo test: visudo not available");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let content = build_sudoers_content(&acct_runas(
            "oper",
            vec![
                SudoCommand::as_user("/opt/x", "bfs_solutions"),
                SudoCommand::root("/usr/sbin/ip"),
            ],
        ))
        .expect("mixed runas yields content");
        write_sudoers(dir.path(), "oper", &content).unwrap();
        let dest = sudoers_path(dir.path(), "oper");
        assert!(
            dest.exists(),
            "validated mixed-runas fragment must activate"
        );
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), content);
    }

    #[test]
    fn comma_in_command_is_escaped_so_it_is_not_a_list_separator() {
        // A (contrived) command containing a literal comma must be escaped as
        // `\,` so sudoers treats it as one Cmnd, not two.
        let content = build_sudoers_content(&acct_cmds("oper", &["/usr/bin/odd,name"])).unwrap();
        assert!(
            content.contains(r"/usr/bin/odd\,name"),
            "comma must be escaped: {content}"
        );
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
        assert!(
            content.contains(r"\(root\) /bin/sh"),
            "runas parens must be escaped: {content}"
        );
        assert!(
            content.contains(r"/bin/x\!y"),
            "negation bang must be escaped: {content}"
        );
        // No bare `(` / `)` / `!` survive on the rule line.
        for line in content
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
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
        assert!(a
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'));
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
        let content =
            build_sudoers_content(&acct_cmds("oper", &["/usr/sbin/ip", "/usr/bin/nmcli"]))
                .expect("concrete commands yield content");
        write_sudoers(dir.path(), "oper", &content).unwrap();
        let dest = sudoers_path(dir.path(), "oper");
        assert!(
            dest.exists(),
            "validated concrete fragment must be activated"
        );
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
        assert!(
            !dir.path().join(".census-oper.tmp").exists(),
            "temp must be cleaned up"
        );
    }

    // ---- group-grants slice 5b: %group sudoers fragment ----

    #[test]
    fn group_concrete_commands_render_nopasswd_percent_rule() {
        let content =
            build_group_sudoers_content(&group_cmds("wheel", &["/usr/sbin/ip", "/usr/bin/nmcli"]))
                .expect("non-empty sudo commands yield content");
        // Subject is the Unix group (`%`), comma-joined Cmnd list, NOPASSWD.
        assert!(
            content.contains("%wheel ALL=(ALL) NOPASSWD: /usr/sbin/ip, /usr/bin/nmcli"),
            "got: {content}"
        );
        assert!(
            content.contains("Managed by Census"),
            "must carry the managed header"
        );
        assert!(content.contains("NOPASSWD"));
        // Group fragments never emit a Cmnd_Alias indirection (no sudo_role path).
        assert!(
            !content.contains("CENSUS_"),
            "group path must not emit an alias: {content}"
        );
    }

    #[test]
    fn group_no_sudo_commands_yields_no_file() {
        assert!(build_group_sudoers_content(&group_cmds("wheel", &[])).is_none());
    }

    #[test]
    fn group_rule_has_valid_sudoers_shape() {
        // Exactly one rule line, subject is a single `%group` token, NOPASSWD tag.
        let content =
            build_group_sudoers_content(&group_cmds("wheel", &["/usr/sbin/ip", "/usr/bin/nmcli"]))
                .unwrap();
        let rule_lines: Vec<&str> = content
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .collect();
        assert_eq!(rule_lines.len(), 1, "exactly one rule line: {content}");
        let line = rule_lines[0];
        assert!(line.starts_with("%wheel ALL=(ALL) NOPASSWD: "));
        assert_eq!(line.split_whitespace().next(), Some("%wheel"));
    }

    #[test]
    fn group_command_metacharacters_are_escaped() {
        // The same escaper guards the group path: a comma must not split the list.
        let content =
            build_group_sudoers_content(&group_cmds("wheel", &["/usr/bin/odd,name"])).unwrap();
        assert!(
            content.contains(r"/usr/bin/odd\,name"),
            "comma must be escaped: {content}"
        );
    }

    #[test]
    fn census_owns_only_grp_prefixed_group_files() {
        assert_eq!(sudoers_group_filename("wheel"), "census-grp-wheel");
        assert!(sudoers_group_filename("wheel").starts_with("census-grp-"));
        assert_eq!(
            sudoers_group_path(std::path::Path::new("/etc/sudoers.d"), "wheel"),
            PathBuf::from("/etc/sudoers.d/census-grp-wheel")
        );
    }

    #[test]
    fn remove_group_sudoers_is_ok_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        remove_group_sudoers(dir.path(), "wheel").unwrap();
        assert!(!sudoers_group_path(dir.path(), "wheel").exists());
    }

    #[test]
    fn remove_group_sudoers_deletes_present_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = sudoers_group_path(dir.path(), "wheel");
        std::fs::write(&path, b"%wheel ALL=(ALL) NOPASSWD: /usr/sbin/ip\n").unwrap();
        assert!(path.exists());
        remove_group_sudoers(dir.path(), "wheel").unwrap();
        assert!(!path.exists(), "present fragment must be removed");
    }

    #[test]
    fn write_group_sudoers_validates_and_activates_atomically() {
        if !visudo_available() {
            eprintln!("skipping write_group_sudoers test: visudo not available");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let content =
            build_group_sudoers_content(&group_cmds("wheel", &["/usr/sbin/ip", "/usr/bin/nmcli"]))
                .expect("non-empty sudo commands yield content");
        write_group_sudoers(dir.path(), "wheel", &content).unwrap();
        let dest = sudoers_group_path(dir.path(), "wheel");
        assert!(dest.exists(), "validated group fragment must be activated");
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), content);
        // No temp file left behind.
        assert!(!dir.path().join(".census-grp-wheel.tmp").exists());
    }

    #[test]
    fn write_group_sudoers_rejects_invalid_fragment_and_does_not_activate() {
        if !visudo_available() {
            eprintln!("skipping invalid group-fragment test: visudo not available");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let err = write_group_sudoers(dir.path(), "wheel", "this is not valid sudoers !!!\n")
            .expect_err("invalid sudoers must be rejected");
        assert!(matches!(err, SudoersError::VisudoRejected { .. }));
        assert!(
            !sudoers_group_path(dir.path(), "wheel").exists(),
            "invalid fragment must NOT be activated"
        );
        assert!(
            !dir.path().join(".census-grp-wheel.tmp").exists(),
            "temp must be cleaned up"
        );
    }
}
