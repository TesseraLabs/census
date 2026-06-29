//! `census audit fs` and `census audit expose` — the read-only exposure audit CLI.
//!
//! `audit fs` is the global, principal-independent posture map (world-writable
//! objects in sensitive trees, the setuid inventory, world-readable secrets, broad
//! group-writable objects). `audit expose --principal <name|uid>` reports what one
//! principal can actually reach, with the intended baseline subtracted for a
//! Census-managed account. Both are strictly read-only: they walk and stat the
//! filesystem (and shell out to `getfacl`), never mutating anything, and the render
//! prints only metadata (path, effective access, class, risk, severity, via, hint,
//! remediation) — never file content, so a secret finding shows its path and access
//! but never the secret.
//!
//! The engines live in [`crate::exposure`]; this CLI layer only resolves the scan
//! scope, builds the index, picks the managed context, renders the report, and maps
//! findings to the process exit code.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use crate::cli_def::AuditFormat;
use crate::exposure::{
    audit_fs, exposure_report, resolve_principal, ExposureConfig, ExposureReport, Finding,
    ManagedContext, PermissionIndex, Reachability, Severity, SkippedMount,
};
use crate::inspect::LiveInspector;
use crate::state::RegistryState;

/// Options for `census audit fs` (CLI-derived).
#[derive(Debug)]
pub struct AuditFsOpts {
    /// Explicit scan roots (empty ⇒ default / `--full` / interactive).
    pub roots: Vec<PathBuf>,
    /// `--full`: scan from `/`.
    pub full: bool,
    /// Output format.
    pub format: AuditFormat,
    /// Managed registry path (for broad-group in-model attribution).
    pub managed: PathBuf,
    /// `exposure.toml` config path (scan scope, secret globs, broad groups).
    pub config: PathBuf,
}

/// Options for `census audit expose` (CLI-derived).
#[derive(Debug)]
pub struct AuditExposeOpts {
    /// The principal to audit: a login name or a numeric uid.
    pub principal: String,
    /// Explicit scan roots (empty ⇒ default / `--full` / interactive).
    pub roots: Vec<PathBuf>,
    /// `--full`: scan from `/`.
    pub full: bool,
    /// Output format.
    pub format: AuditFormat,
    /// Managed registry path (for the intended-baseline subtraction).
    pub managed: PathBuf,
    /// `exposure.toml` config path (scan scope, secret globs).
    pub config: PathBuf,
}

/// Run `census audit fs`: build the live permission index over the resolved scope
/// and print the principal-independent posture map. Non-zero exit on any
/// high-severity finding. Read-only.
pub fn run_audit_fs(opts: AuditFsOpts) -> ExitCode {
    let config = match ExposureConfig::load(&opts.config) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let roots = scan_roots(opts.roots, opts.full, &config.scan_roots);
    if let Err(e) = ensure_absolute_roots(&roots) {
        eprintln!("census: {e}");
        return ExitCode::FAILURE;
    }
    let index = match PermissionIndex::live(&roots, &config.classifier()) {
        Ok(index) => index,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let state = match RegistryState::load(&opts.managed) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let ctx = ManagedContext::global(&state);
    let inspector = LiveInspector::new();
    let findings = audit_fs(&index, &ctx, &config.broad_groups, &inspector);
    let output = match opts.format {
        AuditFormat::Text => render_fs_text(&findings, index.skipped_mounts()),
        AuditFormat::Json => render_fs_json(&findings, index.skipped_mounts()),
    };
    print!("{output}");
    audit_exit_code(&findings)
}

/// Run `census audit expose`: resolve the principal, build the live index, compute
/// reachability, and print the (baseline-subtracted) exposure report. Non-zero exit
/// on any high-severity finding, or if the principal cannot be resolved. Read-only.
pub fn run_audit_expose(opts: AuditExposeOpts) -> ExitCode {
    let config = match ExposureConfig::load(&opts.config) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let roots = scan_roots(opts.roots, opts.full, &config.scan_roots);
    if let Err(e) = ensure_absolute_roots(&roots) {
        eprintln!("census: {e}");
        return ExitCode::FAILURE;
    }
    let inspector = LiveInspector::new();
    let Some(principal) = resolve_principal(&inspector, &opts.principal) else {
        eprintln!(
            "census: cannot resolve principal '{}' (not found in the local passwd/group databases)",
            opts.principal
        );
        return ExitCode::FAILURE;
    };
    let index = match PermissionIndex::live(&roots, &config.classifier()) {
        Ok(index) => index,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let reachability = Reachability::compute(&index, &principal, &roots);
    let state = match RegistryState::load(&opts.managed) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("census: {e}");
            return ExitCode::FAILURE;
        }
    };
    let report = exposure_report(&index, &principal, &roots, &reachability, &state);
    let output = match opts.format {
        AuditFormat::Text => render_expose_text(&report),
        AuditFormat::Json => render_expose_json(&report),
    };
    print!("{output}");
    audit_exit_code(&report.findings)
}

/// Resolve the scan scope from the flags, prompting interactively when on a TTY with
/// no explicit scope.
///
/// Explicit `--root`s win; `--full` scans from `/`; otherwise the configured default
/// roots (`exposure.toml` `scan_roots`, or the built-in security-relevant set) are
/// used — except on an interactive terminal, where the operator is offered a choice. A
/// non-interactive run (piped / no TTY) never blocks: it silently uses the defaults.
/// Reject any non-absolute scan root (a `--root` flag or an interactive custom root).
///
/// A relative root makes the walk run relative to the working directory and emit
/// relative inode paths, which the absolute classifier globs would never match —
/// silently dropping high-severity findings. Mirrors the same check the config applies
/// to `scan_roots`, so every path into the walk is held to one rule: absolute only.
fn ensure_absolute_roots(roots: &[PathBuf]) -> Result<(), String> {
    for root in roots {
        if !root.is_absolute() {
            return Err(format!(
                "scan root {} is not absolute; pass an absolute path",
                root.display()
            ));
        }
    }
    Ok(())
}

fn scan_roots(roots: Vec<PathBuf>, full: bool, default_roots: &[PathBuf]) -> Vec<PathBuf> {
    if !roots.is_empty() {
        return roots;
    }
    if full {
        return vec![PathBuf::from("/")];
    }
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        if let Some(chosen) = prompt_scope() {
            return chosen;
        }
    }
    default_roots.to_vec()
}

/// Offer the interactive scope choice on a TTY: security-relevant (default), full, or
/// custom roots. Prompts on stderr (keeping stdout clean for `--format json`).
/// Returns `None` to fall back to the default roots.
fn prompt_scope() -> Option<Vec<PathBuf>> {
    eprint!(
        "census audit scope — [1] security-relevant roots (default), [2] full (/), \
         [3] custom roots: "
    );
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return None;
    }
    match line.trim() {
        "2" => Some(vec![PathBuf::from("/")]),
        "3" => {
            eprint!("enter space-separated roots: ");
            let _ = std::io::stderr().flush();
            let mut custom = String::new();
            if std::io::stdin().read_line(&mut custom).is_err() {
                return None;
            }
            let roots: Vec<PathBuf> = custom.split_whitespace().map(PathBuf::from).collect();
            if roots.is_empty() {
                None
            } else {
                Some(roots)
            }
        }
        // "" / "1" / anything else → the default security-relevant roots.
        _ => None,
    }
}

/// Map the findings to a process exit code: non-zero iff any finding is at or above
/// the high-severity threshold (the default gate, mirroring `doctor`). Pure so the
/// policy is unit-testable.
pub(crate) fn audit_exit_code(findings: &[Finding]) -> ExitCode {
    if findings
        .iter()
        .any(|f| f.severity.rank() >= Severity::High.rank())
    {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// One finding rendered as a human line: severity, risk, class, path, effective
/// access (`rwx`), the `via` reason, the remediation class, and the hint. No file
/// content — only metadata.
fn finding_line(f: &Finding) -> String {
    format!(
        "{sev:<6} {risk:<11} {class:<13} {path} (access {access}, via {via}, fix {rc}) — {hint}\n",
        sev = f.severity.as_str(),
        risk = f.risk.as_str(),
        class = f.class.as_str(),
        path = f.path,
        access = f.access.rwx(),
        via = f.via.label(),
        rc = f.remediation_class.as_str(),
        hint = f.hint,
    )
}

/// The advisory notice for mounts the walk did not descend (coverage trimmed).
fn skipped_notice(skipped: &[SkippedMount]) -> String {
    let mut out = String::new();
    for mount in skipped {
        out.push_str(&format!(
            "note: not scanned (coverage trimmed at a {} mount): {}\n",
            mount.fstype, mount.path
        ));
    }
    out
}

/// Render the `audit fs` posture map as human-readable lines. Pure.
#[must_use]
pub fn render_fs_text(findings: &[Finding], skipped: &[SkippedMount]) -> String {
    let mut out = String::new();
    if findings.is_empty() {
        out.push_str("audit fs: no dangerous permission classes found\n");
    } else {
        out.push_str(&format!("audit fs: {} finding(s)\n", findings.len()));
        for f in findings {
            out.push_str(&finding_line(f));
        }
    }
    out.push_str(&skipped_notice(skipped));
    out
}

/// Render the `audit fs` posture map as JSON `{ findings, skipped_mounts }`. Pure;
/// emits only finding metadata (never file content).
#[must_use]
pub fn render_fs_json(findings: &[Finding], skipped: &[SkippedMount]) -> String {
    let value = serde_json::json!({
        "findings": findings,
        "skipped_mounts": skipped,
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_owned())
}

/// Render the `audit expose` report as human-readable lines: a header with the
/// principal and managed flag, the DAC-only caveat, the findings, and any skipped
/// mounts (carried on the report). Pure.
#[must_use]
pub fn render_expose_text(report: &ExposureReport) -> String {
    let mut out = format!(
        "audit expose: principal {} ({})\n",
        report.principal,
        if report.managed {
            "managed"
        } else {
            "unmanaged"
        },
    );
    out.push_str(&format!("note: {}\n", report.dac_only_note));
    if report.findings.is_empty() {
        out.push_str("no reachable risky access found\n");
    } else {
        out.push_str(&format!("{} finding(s)\n", report.findings.len()));
        for f in &report.findings {
            out.push_str(&finding_line(f));
        }
    }
    out.push_str(&skipped_notice(&report.skipped_mounts));
    out
}

/// Render the `audit expose` report as JSON (its locked `exposure-report.schema.json`
/// shape: principal, managed, findings, `dac_only_note`, `skipped_mounts`). Pure; only
/// metadata, never file content.
#[must_use]
pub fn render_expose_json(report: &ExposureReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exposure::{AccessVia, AclPerms, ObjectClass, RemediationClass, Risk};

    fn finding(path: &str, class: ObjectClass, risk: Risk, severity: Severity) -> Finding {
        Finding {
            principal: None,
            path: path.to_owned(),
            access: AclPerms {
                read: true,
                write: true,
                execute: false,
            },
            via: AccessVia::OtherBits,
            class,
            risk,
            severity,
            remediation_class: RemediationClass::Ambient,
            hint: "remove world write manually: `chmod o-w <path>`".to_owned(),
        }
    }

    #[test]
    fn exit_code_fails_on_high_severity() {
        let high = vec![finding(
            "/var/spool/cron",
            ObjectClass::Cron,
            Risk::Escalation,
            Severity::High,
        )];
        assert_eq!(
            format!("{:?}", audit_exit_code(&high)),
            format!("{:?}", ExitCode::FAILURE),
            "a high finding gates the exit code"
        );
    }

    #[test]
    fn exit_code_succeeds_below_threshold() {
        let medium = vec![finding(
            "/etc/ssh/sshd_config",
            ObjectClass::Config,
            Risk::Tamper,
            Severity::Medium,
        )];
        assert_eq!(
            format!("{:?}", audit_exit_code(&medium)),
            format!("{:?}", ExitCode::SUCCESS)
        );
        assert_eq!(
            format!("{:?}", audit_exit_code(&[])),
            format!("{:?}", ExitCode::SUCCESS),
            "no findings → success"
        );
    }

    #[test]
    fn fs_text_render_shows_metadata_not_content() {
        let findings = vec![finding(
            "/etc/shadow",
            ObjectClass::Secret,
            Risk::Leak,
            Severity::High,
        )];
        let text = render_fs_text(&findings, &[]);
        assert!(text.contains("/etc/shadow"), "{text}");
        assert!(text.contains("secret"), "class is shown: {text}");
        assert!(text.contains("high"), "severity is shown");
        assert!(text.contains("leak"), "risk is shown");
        assert!(text.contains("other_bits"), "via is shown");
        // Only metadata — the renderer never reads the file, so no secret content can
        // appear. The Finding type carries no content field; assert the access token
        // (rwx) is present rather than any file bytes.
        assert!(text.contains("rw-"), "access token shown: {text}");
    }

    #[test]
    fn fs_json_render_is_valid_and_metadata_only() {
        let findings = vec![finding(
            "/var/spool/cron",
            ObjectClass::Cron,
            Risk::Escalation,
            Severity::High,
        )];
        let json = render_fs_json(&findings, &[]);
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(value["findings"][0]["path"], "/var/spool/cron");
        assert_eq!(value["findings"][0]["class"], "cron");
        assert_eq!(value["findings"][0]["severity"], "high");
        assert_eq!(value["findings"][0]["via"], "other_bits");
        assert!(value["skipped_mounts"].is_array());
        // No content key anywhere.
        assert!(!json.contains("content"), "JSON carries no file content");
    }

    #[test]
    fn expose_text_render_carries_dac_note_and_header() {
        let report = ExposureReport {
            principal: "svc".to_owned(),
            managed: true,
            findings: vec![finding(
                "/var/spool/cron",
                ObjectClass::Cron,
                Risk::Escalation,
                Severity::High,
            )],
            dac_only_note: crate::exposure::DAC_ONLY_NOTE,
            skipped_mounts: vec![],
        };
        let text = render_expose_text(&report);
        assert!(text.contains("principal svc"), "{text}");
        assert!(text.contains("managed"), "managed flag shown");
        assert!(text.contains("DAC-only"), "DAC-only caveat present");
        assert!(text.contains("/var/spool/cron"));
    }

    #[test]
    fn expose_json_render_carries_report_and_skipped_mounts() {
        let report = ExposureReport {
            principal: "svc".to_owned(),
            managed: false,
            findings: vec![],
            dac_only_note: crate::exposure::DAC_ONLY_NOTE,
            skipped_mounts: vec![SkippedMount {
                path: "/mnt/share".to_owned(),
                fstype: "nfs4".to_owned(),
            }],
        };
        let json = render_expose_json(&report);
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(value["principal"], "svc");
        assert_eq!(value["managed"], false);
        assert!(value["dac_only_note"]
            .as_str()
            .unwrap()
            .contains("DAC-only"));
        assert_eq!(value["skipped_mounts"][0]["fstype"], "nfs4");
    }

    #[test]
    fn scan_roots_honours_explicit_and_full_flags() {
        let defaults = crate::exposure::default_roots();
        // Explicit roots win.
        let explicit = scan_roots(vec![PathBuf::from("/opt/app")], false, &defaults);
        assert_eq!(explicit, vec![PathBuf::from("/opt/app")]);
        // --full → the whole filesystem.
        assert_eq!(
            scan_roots(Vec::new(), true, &defaults),
            vec![PathBuf::from("/")]
        );
        // No scope, non-interactive (the test harness has no TTY) → the default roots.
        assert_eq!(scan_roots(Vec::new(), false, &defaults), defaults);
    }

    #[test]
    fn relative_cli_root_is_rejected() {
        // A relative `--root` (or interactive custom root) would walk relative to cwd
        // and never match the absolute classifier globs — rejected before any scan.
        assert!(ensure_absolute_roots(&[PathBuf::from("etc")]).is_err());
        assert!(ensure_absolute_roots(&[PathBuf::from("/etc"), PathBuf::from("rel")]).is_err());
        // All-absolute roots pass.
        assert!(ensure_absolute_roots(&[PathBuf::from("/etc"), PathBuf::from("/opt")]).is_ok());
    }
}
