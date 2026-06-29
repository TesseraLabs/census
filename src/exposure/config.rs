//! The `exposure.toml` configuration: scan scope and classifier overrides.
//!
//! The exposure audit ships sane built-in defaults (the security-relevant scan roots,
//! the secret-classifying globs, the wide-group list). A site can override any of them
//! in `exposure.toml`; an absent file is not an error — the defaults apply. Parsing is
//! strict (`deny_unknown_fields`, like the crate's other declarations), so a typo or a
//! smuggled key is rejected rather than silently ignored.

use std::path::{Path, PathBuf};

use super::fs_audit::DEFAULT_BROAD_GROUPS;
use super::scope::default_roots;
use super::taxonomy::{Classifier, DEFAULT_SECRET_GLOBS};

/// The default scan roots (the security-relevant trees).
fn default_scan_roots() -> Vec<PathBuf> {
    default_roots()
}

/// The default secret-classifying globs.
fn default_secret_globs() -> Vec<String> {
    DEFAULT_SECRET_GLOBS
        .iter()
        .map(|g| (*g).to_owned())
        .collect()
}

/// The default wide-group names.
fn default_broad_groups() -> Vec<String> {
    DEFAULT_BROAD_GROUPS
        .iter()
        .map(|g| (*g).to_owned())
        .collect()
}

/// The on-disk `exposure.toml` shape: scan scope and classifier overrides.
///
/// Each field defaults to the audit's built-in value when omitted, so a partial config
/// (or an absent file) keeps the standard behaviour. Strict-parsed.
#[derive(Debug, Clone, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ExposureConfig {
    /// The roots scanned when no `--root`/`--full` is given (default: the
    /// security-relevant trees).
    #[serde(default = "default_scan_roots")]
    pub scan_roots: Vec<PathBuf>,
    /// The globs that classify an inode as a `secret` (default: the built-in secret
    /// set — shadow, keys, PEM, `id_rsa*`, `.env*`, `*credentials*`).
    #[serde(default = "default_secret_globs")]
    pub secret_globs: Vec<String>,
    /// The wide group NAMES whose group-write access is a posture concern (default:
    /// `adm`, `wheel`, `sudo`, `staff`, `users`).
    #[serde(default = "default_broad_groups")]
    pub broad_groups: Vec<String>,
}

impl Default for ExposureConfig {
    fn default() -> Self {
        Self {
            scan_roots: default_scan_roots(),
            secret_globs: default_secret_globs(),
            broad_groups: default_broad_groups(),
        }
    }
}

/// Errors reading the `exposure.toml` config.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExposureConfigError {
    /// The config file exists but cannot be read.
    #[error("cannot read exposure config {path}: {source}")]
    Io {
        /// The config path consulted.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The config TOML is malformed or carries an unknown key.
    #[error("exposure config {path} is invalid: {source}")]
    Toml {
        /// The config path consulted.
        path: PathBuf,
        /// The underlying TOML deserialization error.
        #[source]
        source: toml::de::Error,
    },
    /// The config parsed but is semantically invalid (empty / relative `scan_roots`,
    /// or a `secret_glob` with more than one `**`).
    #[error("exposure config {path} is invalid: {reason}")]
    Invalid {
        /// The config path consulted.
        path: PathBuf,
        /// What is wrong with the config.
        reason: String,
    },
}

impl ExposureConfig {
    /// Load the config from `path`. A missing file yields the built-in defaults (not
    /// an error); a present-but-malformed file is an error.
    ///
    /// # Errors
    ///
    /// Returns the defaults only when the file is genuinely absent
    /// (`ErrorKind::NotFound`). Any OTHER read failure — permission denied, an I/O
    /// error — is [`ExposureConfigError::Io`] (a restricted deploy reading the wrong
    /// policy must not silently look successful). A malformed file is
    /// [`ExposureConfigError::Toml`]; a parseable-but-invalid config (empty / relative
    /// `scan_roots`, a `secret_glob` with more than one `**`) is
    /// [`ExposureConfigError::Invalid`].
    pub fn load(path: &Path) -> Result<Self, ExposureConfigError> {
        // Attempt the read rather than checking `exists()` first: `Path::exists()`
        // returns false on a non-NotFound metadata error (e.g. permission denied),
        // which would silently fall back to the defaults. Distinguish NotFound (use
        // defaults) from every other I/O error (fail honestly).
        let text = match crate::fsutil::read_capped(path, crate::fsutil::MAX_INPUT_FILE_BYTES) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(source) => {
                return Err(ExposureConfigError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let config: Self = toml::from_str(&text).map_err(|source| ExposureConfigError::Toml {
            path: path.to_path_buf(),
            source,
        })?;
        config.validate(path)?;
        Ok(config)
    }

    /// Validate the parsed config: `scan_roots` non-empty and absolute, and every
    /// `secret_glob` carrying at most one `**`. Returns
    /// [`ExposureConfigError::Invalid`] on any violation.
    fn validate(&self, path: &Path) -> Result<(), ExposureConfigError> {
        let invalid = |reason: String| ExposureConfigError::Invalid {
            path: path.to_path_buf(),
            reason,
        };
        // An explicit `scan_roots = []` bypasses `serde(default)` (the key is present),
        // so the audit would scan NOTHING and exit 0 — a silent misconfig.
        if self.scan_roots.is_empty() {
            return Err(invalid(
                "scan_roots is empty: the audit would scan nothing and report all-clear".to_owned(),
            ));
        }
        for root in &self.scan_roots {
            if !root.is_absolute() {
                return Err(invalid(format!(
                    "scan_root {} is not absolute: the walk would run relative to the \
                     working directory and the absolute classifier globs would never \
                     match, silently dropping high-severity findings",
                    root.display()
                )));
            }
        }
        // The glob matcher backtracks across `**`, so two `**` in one pattern is
        // exponential. The built-in tables hold to one `**`; the config must too, even
        // though it is operator-controlled.
        for glob in &self.secret_globs {
            if double_star_count(glob) > 1 {
                return Err(invalid(format!(
                    "secret_glob {glob:?} contains more than one `**`: the matcher \
                     backtracks across `**`, so this risks exponential blowup on a full scan"
                )));
            }
        }
        Ok(())
    }

    /// The object [`Classifier`] built from the configured secret globs.
    #[must_use]
    pub fn classifier(&self) -> Classifier {
        Classifier::new(self.secret_globs.clone())
    }
}

/// The number of `**` path segments in a glob.
fn double_star_count(glob: &str) -> usize {
    glob.split('/').filter(|segment| *segment == "**").count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_file_yields_defaults() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = ExposureConfig::load(&tmp.path().join("absent.toml")).expect("absent → defaults");
        assert_eq!(cfg.scan_roots, default_roots());
        assert_eq!(cfg.broad_groups, default_broad_groups());
        assert_eq!(cfg.secret_globs, default_secret_globs());
    }

    #[test]
    fn partial_config_fills_defaults() {
        // Only broad_groups overridden; the rest fall back to defaults.
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("exposure.toml");
        std::fs::write(&path, "broad_groups = [\"wheel\", \"app-admins\"]\n").expect("write");
        let cfg = ExposureConfig::load(&path).expect("loads");
        assert_eq!(cfg.broad_groups, vec!["wheel", "app-admins"]);
        assert_eq!(cfg.scan_roots, default_roots(), "scan_roots defaulted");
        assert_eq!(
            cfg.secret_globs,
            default_secret_globs(),
            "secret_globs defaulted"
        );
    }

    #[test]
    fn full_config_round_trips() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("exposure.toml");
        std::fs::write(
            &path,
            "scan_roots = [\"/etc\", \"/opt\"]\n\
             secret_globs = [\"**/*.token\"]\n\
             broad_groups = [\"staff\"]\n",
        )
        .expect("write");
        let cfg = ExposureConfig::load(&path).expect("loads");
        assert_eq!(
            cfg.scan_roots,
            vec![PathBuf::from("/etc"), PathBuf::from("/opt")]
        );
        assert_eq!(cfg.secret_globs, vec!["**/*.token"]);
        assert_eq!(cfg.broad_groups, vec!["staff"]);
        // The classifier reflects the configured secret globs.
        assert_eq!(
            cfg.classifier().classify("/srv/app/api.token", 0o100_644),
            crate::exposure::ObjectClass::Secret
        );
    }

    #[test]
    fn unknown_key_is_rejected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("exposure.toml");
        std::fs::write(&path, "bogus = true\n").expect("write");
        assert!(
            matches!(
                ExposureConfig::load(&path),
                Err(ExposureConfigError::Toml { .. })
            ),
            "an unknown key must be rejected (strict parse)"
        );
    }

    #[test]
    fn empty_scan_roots_is_rejected() {
        // An explicit `scan_roots = []` bypasses serde(default) and would scan nothing,
        // exiting 0 — a silent misconfig. It must be an error.
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("exposure.toml");
        std::fs::write(&path, "scan_roots = []\n").expect("write");
        assert!(matches!(
            ExposureConfig::load(&path),
            Err(ExposureConfigError::Invalid { .. })
        ));
    }

    #[test]
    fn relative_scan_root_is_rejected() {
        // A relative root would walk relative to cwd and never match the absolute
        // classifier globs, silently dropping high-severity findings.
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("exposure.toml");
        std::fs::write(&path, "scan_roots = [\"etc\", \"/var\"]\n").expect("write");
        assert!(matches!(
            ExposureConfig::load(&path),
            Err(ExposureConfigError::Invalid { .. })
        ));
    }

    #[test]
    fn secret_glob_with_two_double_stars_is_rejected() {
        // The matcher backtracks across `**`; two `**` in one pattern risks exponential
        // blowup, so the config (operator-controlled though it is) is held to one.
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("exposure.toml");
        std::fs::write(&path, "secret_globs = [\"**/x/**/*.key\"]\n").expect("write");
        assert!(matches!(
            ExposureConfig::load(&path),
            Err(ExposureConfigError::Invalid { .. })
        ));
        // One `**` is fine.
        let ok = tmp.path().join("ok.toml");
        std::fs::write(&ok, "secret_globs = [\"**/*.key\"]\n").expect("write");
        assert!(ExposureConfig::load(&ok).is_ok());
    }

    #[test]
    fn non_notfound_io_error_is_not_silently_defaulted() {
        // Pointing at a directory makes the read fail with a non-NotFound I/O error
        // (modelling permission-denied / restricted deploys); that must surface as an
        // error, NOT fall back silently to the defaults.
        let tmp = tempfile::tempdir().expect("tempdir");
        let result = ExposureConfig::load(tmp.path());
        assert!(
            matches!(result, Err(ExposureConfigError::Io { .. })),
            "a non-NotFound read failure must be an honest error, not a silent default: {result:?}"
        );
    }
}
