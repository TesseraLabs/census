//! The risk-lint engine for `census compile --lint`.
//!
//! Classifies a role's (and bound groups') resolved file grants and `%group`
//! sudo commands for escalation-capable / secret-leaking access, plus the
//! lint-finding types and the role-level lint that folds in resolve warnings and
//! l10n completeness. All findings are advisory WARNINGs — like the catalog's own
//! `risk` labelling, they inform but never gate (only a resolve ERROR, surfaced
//! before lint runs, fails `compile --lint`).
//!
//! The escalation/secret classification (`ROOT_EQUIVALENT_RW_PREFIXES`,
//! `SECRET_PATH_PREFIXES`, `path_is_secret`, `path_boundary_overlaps`) is shared
//! between the account-side file-grant lint and the group-grant lint so the rule
//! cannot drift between the two.

use crate::catalog::OsTarget;
use crate::cli::compile::CompiledRole;
use crate::cli::render::access_token;
use crate::declaration::Declaration;
use crate::l10n::{self, L10nSource};
use crate::{catalog, model, LiveCatalog};

/// Lint severity. ERRORs make `compile --lint` exit non-zero (for CI); WARNINGs
/// are advisory and do not gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintSeverity {
    /// A blocking problem (catalog could not resolve, …).
    Error,
    /// An advisory signal (raw primitive used, missing translation, …).
    Warning,
}

impl LintSeverity {
    /// Short tag for output.
    pub fn tag(self) -> &'static str {
        match self {
            LintSeverity::Error => "ERROR",
            LintSeverity::Warning => "WARNING",
        }
    }
}

/// One lint finding: a stable code, a severity, and a human message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintFinding {
    /// A stable short code for the rule (e.g. `raw-primitive`, `unknown-os-version`).
    pub code: &'static str,
    /// ERROR (gates) vs WARNING (advisory).
    pub severity: LintSeverity,
    /// Human-readable detail.
    pub message: String,
}

/// Root-equivalent file paths: write access to any of these is effectively a path
/// to root (a writable sudoers fragment grants arbitrary sudo; a writable PAM/ssh
/// config subverts authentication; a writable PATH bin is run as whoever invokes
/// it). An `rw` grant on one of these (or under a recursive one) is flagged
/// escalation-capable. Curated and documented so the rule is reviewable, not a
/// magic list buried in code.
const ROOT_EQUIVALENT_RW_PREFIXES: &[&str] = &[
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/sudo.conf",
    "/etc/ssh",
    "/etc/pam.d",
    "/etc/polkit-1",
    "/etc/security",
    "/etc/sysctl.d",
    "/etc/sysctl.conf",
    "/etc/modprobe.d",
    "/etc/apparmor.d",
    "/etc/selinux",
    "/etc/systemd",
    // PATH binary directories: a writable executable here runs with the caller's
    // privilege the next time it is invoked (often root via cron/sudo).
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
];

/// Secret file/dir paths: even READ access leaks credentials/keys (password
/// hashes, TLS private keys). An `ro` (or `rw`) grant on one of these — or under
/// a recursive grant that contains it — is flagged. Every entry here is either an
/// exact file (`/etc/shadow`, `/etc/krb5.keytab`) or a real directory
/// (`/etc/ssl/private`), so the component-boundary matcher [`path_boundary_overlaps`]
/// classifies it correctly. SSH host keys live as a FILENAME family
/// (`/etc/ssh/ssh_host_*`) inside the otherwise-public `/etc/ssh`, so they cannot
/// be a component-boundary prefix here (that would also flag the public
/// `sshd_config`); they are matched separately by [`path_is_secret`] — by
/// host-key-directory containment for a grant on `/etc/ssh` or an ancestor, and by
/// basename for a grant directly on `/etc/ssh/ssh_host_rsa_key`.
const SECRET_PATH_PREFIXES: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/ssl/private",
    "/etc/pki/tls/private",
    "/etc/krb5.keytab",
];

/// The directory holding the SSH host private/public keys, and the filename
/// prefix that marks one. The host keys are a filename family (`ssh_host_rsa_key`,
/// `ssh_host_ed25519_key`, …) under a shared, non-secret directory (`/etc/ssh`
/// also holds the public `sshd_config`), so they cannot be a component-boundary
/// prefix in [`SECRET_PATH_PREFIXES`]. [`path_is_secret`] reaches them two ways: a
/// grant on `/etc/ssh` or an ancestor CONTAINS the keys (directory containment),
/// and a grant directly on `/etc/ssh/ssh_host_*` matches by basename.
const SSH_HOST_KEY_DIR: &str = "/etc/ssh";
const SSH_HOST_KEY_PREFIX: &str = "ssh_host_";

/// Whether `candidate` is at or under `base` on a `/`-component boundary, OR
/// `base` is at or under `candidate` on a boundary. The second direction matters
/// for a recursive grant: a recursive grant on `/etc` (or `/`) CONTAINS a
/// sensitive `/etc/shadow`, so the grant must be flagged even though its declared
/// path is the broader one. A plain prefix test would miss the parent-grant case
/// or wrongly match a textual neighbour.
fn path_boundary_overlaps(base: &str, candidate: &str) -> bool {
    use crate::catalog::path_at_or_under;
    path_at_or_under(base, candidate) || path_at_or_under(candidate, base)
}

/// Whether a grant on `path` touches a secret. The single classifier for both the
/// account ([`file_grant_risk_findings`]) and group ([`group_grant_risk_findings`])
/// lints, so the rule cannot drift between the two. A path is secret when:
///
/// - it overlaps a curated secret file/dir on a `/`-component boundary (`/etc/shadow`,
///   `/etc/ssl/private`, …) — including a recursive grant on a parent that CONTAINS one; or
/// - its grant tree CONTAINS the SSH host private keys — the `ssh_host_*` family lives directly in
///   `/etc/ssh`, so any grant on `/etc/ssh` or an ancestor (`/etc`, `/`) reaches them. This is
///   matched by asking whether the host-key directory is at or under the grant path; or
/// - it is a grant directly on a host-key file (`/etc/ssh/ssh_host_rsa_key`) — matched by basename,
///   since the key shares its directory with the non-secret `sshd_config` and so cannot be a
///   component-boundary prefix.
fn path_is_secret(path: &str) -> bool {
    if SECRET_PATH_PREFIXES
        .iter()
        .any(|p| path_boundary_overlaps(p, path))
    {
        return true;
    }
    // A grant whose tree CONTAINS the SSH host keys leaks them even read-only: the
    // private keys are `ssh_host_*` files inside `/etc/ssh`, so a grant on
    // `/etc/ssh` or any ancestor (`/etc`, `/`) reaches them. Flag when the host-key
    // directory is at or under the grant path. The reverse direction is
    // deliberately NOT used here: a grant on a sibling file under `/etc/ssh` (the
    // public `sshd_config`) does not expose the private keys, and a bidirectional
    // overlap would over-warn on it as a "secret" leak.
    if catalog::path_at_or_under(path, SSH_HOST_KEY_DIR) {
        return true;
    }
    // A grant directly on a host-key file: the exact-file case the directory
    // containment above does not reach (the key is under, not at-or-above,
    // `/etc/ssh`). Matched by basename.
    if let Some((parent, name)) = path.rsplit_once('/') {
        if parent == SSH_HOST_KEY_DIR && name.starts_with(SSH_HOST_KEY_PREFIX) {
            return true;
        }
    }
    false
}

/// Risk-lint a role's resolved file grants for escalation-capable / secret-leaking
/// access. Returns WARNING findings (advisory — they inform but do not gate
/// `compile --lint`, mirroring how the catalog's own `risk` labelling is advisory,
/// not enforcement). A grant is flagged when:
///
/// - it is `rw` and overlaps a root-equivalent path (writable sudoers/ssh/PATH);
/// - it touches (ro or rw) a secret path (shadow, private keys).
///
/// Overlap uses a path-component boundary in BOTH directions so a recursive grant
/// on a parent of a secret (e.g. recursive `/etc` containing `/etc/shadow`) is
/// caught, not just an exact match.
pub(crate) fn file_grant_risk_findings(compiled: &CompiledRole) -> Vec<LintFinding> {
    let mut out: Vec<LintFinding> = Vec::new();
    for f in compiled.flat_file_grants() {
        let path = &f.grant.path;

        if f.grant.access.contains(catalog::Access::WRITE)
            && ROOT_EQUIVALENT_RW_PREFIXES
                .iter()
                .any(|p| path_boundary_overlaps(p, path))
        {
            out.push(LintFinding {
                code: "rw-root-equivalent",
                severity: LintSeverity::Warning,
                message: format!(
                    "rw file grant on root-equivalent path {path} (perm {}) is escalation-capable",
                    f.permission
                ),
            });
        }

        if path_is_secret(path) {
            out.push(LintFinding {
                code: "secret-path-access",
                severity: LintSeverity::Warning,
                message: format!(
                    "{} file grant on secret path {path} (perm {}) leaks credentials/keys",
                    access_token(f.grant.access),
                    f.permission
                ),
            });
        }
    }
    out
}

/// Whether a `%group` sudo command references a root-equivalent path: any argument
/// token (everything after the leading binary) overlaps a root-equivalent prefix.
/// This is the generic, reviewable escalation signal for a sudo grant — letting a
/// member run e.g. `vi /etc/sudoers` or `tee /etc/ssh/sshd_config` as root is a
/// path to root. We deliberately do NOT flag on the binary's own directory
/// (almost every sudo command runs a `/usr/bin` or `/usr/sbin` binary — that is
/// normal, not escalation); the root-equivalent PATH-dir prefixes describe WRITE
/// access to files there, the `g:group` file-grant lint's concern, not which
/// binary sudo runs. The match does not distinguish read/write/execute of the
/// argument (a `cat /etc/sudoers` is flagged too) — for an advisory WARNING this
/// conservatism is intended, so the wording says "references", not "edits".
fn sudo_command_edits_root_equivalent(command: &str) -> bool {
    command
        .split_whitespace()
        .skip(1) // skip the leading binary token
        .filter(|tok| tok.starts_with('/'))
        .any(|tok| {
            ROOT_EQUIVALENT_RW_PREFIXES
                .iter()
                .any(|p| path_boundary_overlaps(p, tok))
        })
}

/// Risk-lint the resolved group bindings for escalation-capable grants that
/// EVERY group member inherits (including effectively-nested LDAP members). A
/// group grant widens the blast radius beyond a single account, so the same
/// root-equivalent / secret-path risk classification used for `u:account` file
/// grants ([`ROOT_EQUIVALENT_RW_PREFIXES`] / [`SECRET_PATH_PREFIXES`], matched by
/// [`path_boundary_overlaps`]) is applied to `g:group` grants, and a root-
/// equivalent `%group` sudo command is flagged too. Findings are advisory
/// WARNINGs (like the account-side file-grant lint), each naming the group and
/// the inheritance so the reviewer sees the expanded surface.
///
/// Pure (groups in, findings out) so it is unit-tested from hand-built
/// `ResolvedGroup`s.
pub(crate) fn group_grant_risk_findings(groups: &[model::ResolvedGroup]) -> Vec<LintFinding> {
    let mut out: Vec<LintFinding> = Vec::new();
    for g in groups {
        let group = &g.name;

        // `%group` sudo that edits a root-equivalent path: every member can use
        // it to reach root, so it is an escalation surface for the whole group.
        //
        // The command's run-as account is deliberately ignored here: a
        // root-equivalent command narrowed to a service account is still worth
        // flagging — that account may itself be privileged, and "edits a
        // root-equivalent path" is an escalation surface regardless of which
        // identity runs it. Ignoring `runas` only ever over-warns (the safe
        // direction), never under-warns.
        for sudo_cmd in &g.sudo_commands {
            let cmd = &sudo_cmd.command;
            if sudo_command_edits_root_equivalent(cmd) {
                out.push(LintFinding {
                    code: "group-sudo-escalation",
                    severity: LintSeverity::Warning,
                    message: format!(
                        "%{group} sudo grant `{cmd}` references a root-equivalent path (escalation-capable); \
                         ALL members of group {group} (incl. effectively-nested LDAP) inherit it"
                    ),
                });
            }
        }

        // `g:group` file grants, classified exactly like a `u:account` grant.
        for grant in &g.file_grants {
            let path = &grant.path;
            if grant.access.contains(catalog::Access::WRITE)
                && ROOT_EQUIVALENT_RW_PREFIXES
                    .iter()
                    .any(|p| path_boundary_overlaps(p, path))
            {
                out.push(LintFinding {
                    code: "group-rw-root-equivalent",
                    severity: LintSeverity::Warning,
                    message: format!(
                        "g:{group} rw file grant on root-equivalent path {path} is escalation-capable; \
                         ALL members of group {group} (incl. effectively-nested LDAP) inherit it"
                    ),
                });
            }
            if path_is_secret(path) {
                out.push(LintFinding {
                    code: "group-secret-path-access",
                    severity: LintSeverity::Warning,
                    message: format!(
                        "g:{group} {} file grant on secret path {path} leaks credentials/keys; \
                         ALL members of group {group} (incl. effectively-nested LDAP) inherit it",
                        access_token(grant.access)
                    ),
                });
            }
        }
    }
    out
}

/// Lint a successfully-compiled role plus its resolve warnings.
///
/// Resolve-time ERRORs (unknown permission, cycle, namespace collision, lowered
/// bundle risk, invalid sudo/param) are surfaced by `compile_role` returning
/// `Err` — they never reach a `CompiledRole`, so `run_compile` reports them as a
/// fatal error before lint runs. This function lints what a *successful* compile
/// can still flag: the warning-class signals (raw primitives, unknown OS
/// version, unused params) and the l10n completeness of the role's permission set
/// (missing / orphan translations).
///
/// The locale set linted is: the requested `--lang` (when given) plus a default
/// set (`en`, `ru`, `zh`) and any locale materially present in the l10n tree
/// (`available_locales`). This covers the vendor-declared starter set without a
/// separate locale-manifest input (which the catalog format does not carry yet).
///
/// Returns findings in a stable order (warnings from resolve, then l10n).
pub fn lint_role(
    compiled: &CompiledRole,
    warnings: &[model::ResolveWarning],
    _decl: &Declaration,
    _os: &OsTarget,
    _catalog: &LiveCatalog,
    l10n: &dyn L10nSource,
) -> Vec<LintFinding> {
    let mut out: Vec<LintFinding> = Vec::new();

    // Resolve-class warnings → lint warnings (never errors).
    for w in warnings {
        let (code, message): (&'static str, String) = match w {
            // Inline payload.sudo shares the raw-primitive marker with the other
            // escape-hatch primitives: it is an uncurated escalation-capable
            // primitive a reviewer must see flagged the same way.
            model::ResolveWarning::RawPrimitiveAlongsidePermissions { .. }
            | model::ResolveWarning::InlineSudoUnlabeled { .. } => ("raw-primitive", w.to_string()),
            model::ResolveWarning::GroupsPrimitiveOnGroupTarget { .. } => {
                ("groups-on-group-target", w.to_string())
            }
            model::ResolveWarning::InlineSudoDroppedOnGroupTarget { .. } => {
                ("inline-sudo-on-group-target", w.to_string())
            }
            model::ResolveWarning::Catalog(catalog::Warning::UnknownOsVersion { .. }) => {
                ("unknown-os-version", w.to_string())
            }
            model::ResolveWarning::Catalog(catalog::Warning::UnusedParam { .. }) => {
                ("unused-param", w.to_string())
            }
        };
        out.push(LintFinding {
            code,
            severity: LintSeverity::Warning,
            message,
        });
    }

    // File-grant risk lint: rw on root-equivalent paths / access to secret paths.
    // Advisory warnings (like the catalog's own risk labelling), placed after the
    // resolve warnings and before l10n so the output order is stable.
    out.extend(file_grant_risk_findings(compiled));

    // l10n completeness over the role's permission ids. Missing translation and
    // orphan translation are warnings (a missing/broken text must never break
    // apply — spec). We lint over the role's own permission ids (the ids this
    // role actually references) so the signal is scoped to what was compiled.
    let ids: Vec<String> = compiled
        .permissions
        .iter()
        .map(|p| p.resolved.id.clone())
        .collect();
    let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();

    let mut locales: Vec<String> = vec!["en".to_owned(), "ru".to_owned(), "zh".to_owned()];
    for l in l10n.available_locales() {
        if !locales.iter().any(|x| x == &l) {
            locales.push(l);
        }
    }
    let locale_refs: Vec<&str> = locales.iter().map(String::as_str).collect();

    for m in l10n::missing_translations(l10n, &locale_refs, &id_refs) {
        out.push(LintFinding {
            code: "missing-translation",
            severity: LintSeverity::Warning,
            message: format!("permission {} has no title in locale {}", m.id, m.locale),
        });
    }
    for o in l10n::orphan_translations(l10n, &locale_refs, &id_refs) {
        out.push(LintFinding {
            code: "orphan-translation",
            severity: LintSeverity::Warning,
            message: format!(
                "translation key {} in locale {} matches no referenced permission",
                o.id, o.locale
            ),
        });
    }

    out
}
