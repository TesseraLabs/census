//! Localization (l10n) of permission descriptions: a tree of human-readable
//! texts kept *separately* from the policy records the catalog resolves.
//!
//! Human texts (`title` / `summary` / `risk_note`) live in
//! `<root>/l10n/<locale>/<group>.toml`, keyed by permission id (including an
//! add-on namespace, `[docker.ps]`). The catalog's policy records stay purely
//! structural so a translation is a self-contained community contribution — a PR
//! against one language file — that never touches security fields. Reviewing a
//! translation is therefore not reviewing rights.
//!
//! ## Why l10n is OS-agnostic (unlike the catalog's layer chain)
//!
//! The catalog resolves a permission *down the OS-target layer chain*
//! (`linux` → `linux-debian` → `linux-debian-12`) because the concrete primitives
//! differ per distro/version (netplan vs ifupdown). A *description* of a
//! capability does not depend on the distro, so the l10n tree is flat per locale:
//! the layer chain does **not** apply here. The only layering is root precedence —
//! a later root (`/etc/census/permissions.d/l10n/...`) overrides an earlier root
//! (`/usr/share/census/permissions/l10n/...`) for the same locale + id + field,
//! exactly like systemd's `/etc` over `/usr/lib`.
//!
//! ## Why best-effort / metadata-only
//!
//! Texts are metadata: they MUST NOT affect primitive expansion, risk classes,
//! resolve, or rights checks. A missing or malformed translation must never break
//! `apply` — so an individual unreadable/invalid file is *skipped with a warning*,
//! not surfaced as a hard error. Lint (slice 5) reports missing and orphan keys;
//! the runtime path degrades gracefully to the `en` fallback and ultimately to the
//! id itself, so `title` always yields *something*.
//!
//! ## Why unknown-id tolerant but unknown-field strict
//!
//! A translation file may name ids that are not in the installed catalog
//! (forward/back-compat: the translation set can lead or lag the policy set) — that
//! is a lint signal (an orphan), not a load error, so unknown *ids* are accepted.
//! But an unknown *field* inside a description (`titel = ...`) is a typo that would
//! silently drop the translator's text, so the inner struct is
//! `deny_unknown_fields` (fail-closed on structure, tolerant on membership).

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;

/// One permission's texts for one locale. Every field is optional because a
/// translation may be partial (a translator filled `title` but not yet
/// `risk_note`); the per-field fallback chain ([`resolve_text`]) fills gaps from
/// `en`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Description {
    /// Short human name of the capability.
    #[serde(default)]
    pub title: Option<String>,
    /// What the capability grants.
    #[serde(default)]
    pub summary: Option<String>,
    /// What it risks (honest note, e.g. "effectively root").
    #[serde(default)]
    pub risk_note: Option<String>,
}

impl Description {
    /// Whether this description carries no text at all (all fields `None`).
    /// An all-empty description is treated as "no translation present" for the
    /// purposes of the fallback chain and lint.
    fn is_empty(&self) -> bool {
        self.title.is_none() && self.summary.is_none() && self.risk_note.is_none()
    }

    /// Overlay `other` onto `self` field-by-field: a `Some` in `other` wins, a
    /// `None` in `other` leaves `self`'s field untouched. Used for root precedence
    /// (later root overrides) so a partial higher-precedence translation does not
    /// clobber lower-precedence text it left untranslated.
    fn overlay(&mut self, other: Description) {
        if other.title.is_some() {
            self.title = other.title;
        }
        if other.summary.is_some() {
            self.summary = other.summary;
        }
        if other.risk_note.is_some() {
            self.risk_note = other.risk_note;
        }
    }
}

/// A best-effort warning recorded while loading a locale: a file that could not
/// be read or parsed was skipped. Surfaced as data (not printed) so slice 5 can
/// route it to lint; the load itself still succeeds (metadata-only, best-effort).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L10nWarning {
    /// The file that was skipped.
    pub path: PathBuf,
    /// Why it was skipped (IO or TOML error text).
    pub reason: String,
}

/// Unrecoverable l10n errors. Note these are *not* used for individual bad
/// files (those are [`L10nWarning`]s — best-effort). Reserved for failures a
/// caller genuinely cannot proceed past; kept as a typed enum to mirror
/// [`crate::catalog::CatalogError`] and leave room for future hard cases without
/// changing the trait signature.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum L10nError {
    /// A locale code is not usable as a path component (e.g. contains a
    /// separator or `..`). Locale codes reach the filesystem as
    /// `<root>/l10n/<locale>/`, so an unsafe code is a path-traversal primitive,
    /// same as the catalog's OS-target fields.
    #[error("invalid locale {0:?}: must match [a-z0-9_-]+ and not be a path component")]
    InvalidLocale(String),
}

/// The result of loading one locale: the merged id→description map plus any
/// best-effort warnings (skipped files). The map is `BTreeMap` so iteration is
/// deterministic (stable lint output, reproducible tests).
pub type LoadedLocale = (BTreeMap<String, Description>, Vec<L10nWarning>);

/// A source of localized descriptions, abstracted (like
/// [`crate::catalog::CatalogSource`]) so lookup/lint logic is pure and tests can
/// supply in-memory data without a filesystem.
pub trait L10nSource {
    /// Load and merge every description for `locale`, returning the merged map
    /// and any warnings from skipped (malformed/unreadable) files.
    ///
    /// An absent locale (no directory) is not an error — it yields an empty map.
    /// Merge order: roots in precedence order, then files within a root; a later
    /// contribution overlays an earlier one field-by-field (a `None` field never
    /// clobbers an existing `Some`).
    fn load_locale(&self, locale: &str) -> Result<LoadedLocale, L10nError>;

    /// The locale codes materially present in this source (a locale dir exists,
    /// or, for the fake, has data). Order is unspecified; callers sort if needed.
    fn available_locales(&self) -> Vec<String>;
}

/// Whether `name` is safe to use as a single filesystem path component (locale
/// code). Locale codes are joined onto roots (`<root>/l10n/<locale>`) and the
/// files there are read, so an unsanitised `../x` or `a/b` would escape the tree.
/// Mirrors the catalog's path-component rule (lowercase ascii + digits + `_`/`-`;
/// no separators, no bare `.`/`..`). Locales do not use `.`, so it is excluded.
fn is_safe_locale(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return false;
    }
    name.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

/// Production l10n source: reads `<root>/l10n/<locale>/*.toml` across roots in
/// precedence order (later roots override earlier — `/etc` over `/usr/share`).
/// All files of a locale are merged; group filenames (`network.toml`,
/// `docker.toml`) are organization only, not semantics.
#[derive(Debug, Clone)]
pub struct LiveL10n {
    /// Catalog roots in precedence order (lowest precedence first). The same
    /// roots the catalog uses; the `l10n/` subdir is appended here.
    pub roots: Vec<PathBuf>,
}

impl LiveL10n {
    /// Construct from roots in precedence order (lowest precedence first).
    pub fn new(roots: Vec<PathBuf>) -> Self {
        LiveL10n { roots }
    }

    /// Parse one locale file into an id→description map. The file is a TOML table
    /// of `id -> { title?, summary?, risk_note? }`; unknown *fields* inside a
    /// description are rejected (typo guard), unknown *ids* are accepted.
    fn parse_file(text: &str) -> Result<BTreeMap<String, Description>, toml::de::Error> {
        toml::from_str::<BTreeMap<String, Description>>(text)
    }
}

impl L10nSource for LiveL10n {
    fn load_locale(&self, locale: &str) -> Result<LoadedLocale, L10nError> {
        if !is_safe_locale(locale) {
            return Err(L10nError::InvalidLocale(locale.to_owned()));
        }

        let mut merged: BTreeMap<String, Description> = BTreeMap::new();
        let mut warnings: Vec<L10nWarning> = Vec::new();

        for root in &self.roots {
            let locale_dir = root.join("l10n").join(locale);
            if !locale_dir.is_dir() {
                // A root that does not translate this locale simply contributes
                // nothing — not an error (the chain may legitimately lack it).
                continue;
            }

            // Collect and sort file paths so merge order within a root is
            // deterministic regardless of readdir order (stable, testable).
            let mut paths: Vec<PathBuf> = Vec::new();
            let entries = match std::fs::read_dir(&locale_dir) {
                Ok(e) => e,
                Err(e) => {
                    // The dir exists (is_dir) but cannot be enumerated: best-effort,
                    // record and move on rather than fail apply.
                    warnings.push(L10nWarning {
                        path: locale_dir.clone(),
                        reason: e.to_string(),
                    });
                    continue;
                }
            };
            for entry in entries.flatten() {
                let path = entry.path();
                // Skip symlinks: as root, a symlink planted in the l10n tree could
                // otherwise read an out-of-tree file. Texts are metadata, but the
                // read still happens as root, so apply the catalog's symlink guard.
                if path.is_symlink() {
                    continue;
                }
                if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("toml") {
                    paths.push(path);
                }
            }
            paths.sort();

            for path in paths {
                let text =
                    match crate::fsutil::read_capped(&path, crate::fsutil::MAX_INPUT_FILE_BYTES) {
                        Ok(t) => t,
                        Err(e) => {
                            warnings.push(L10nWarning {
                                path,
                                reason: e.to_string(),
                            });
                            continue;
                        }
                    };
                let map = match Self::parse_file(&text) {
                    Ok(m) => m,
                    Err(e) => {
                        // A malformed individual file is skipped (best-effort);
                        // other files of the locale still load.
                        warnings.push(L10nWarning {
                            path,
                            reason: e.to_string(),
                        });
                        continue;
                    }
                };
                for (id, desc) in map {
                    merged.entry(id).or_default().overlay(desc);
                }
            }
        }

        Ok((merged, warnings))
    }

    fn available_locales(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for root in &self.roots {
            let l10n_dir = root.join("l10n");
            let Ok(entries) = std::fs::read_dir(&l10n_dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_symlink() || !path.is_dir() {
                    continue;
                }
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if is_safe_locale(name) && !out.iter().any(|l| l == name) {
                        out.push(name.to_owned());
                    }
                }
            }
        }
        out
    }
}

/// In-memory l10n source for tests: `(locale, id) -> Description`.
#[derive(Debug, Clone, Default)]
pub struct FakeL10n {
    entries: Vec<(String, String, Description)>,
}

impl FakeL10n {
    /// Empty source.
    pub fn new() -> Self {
        FakeL10n::default()
    }

    /// Add a description for `(locale, id)`. A later `.with` for the same
    /// locale+id overlays field-by-field (mirrors root precedence) so tests can
    /// model overlay without a filesystem.
    pub fn with(mut self, locale: &str, id: &str, desc: Description) -> Self {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|(l, i, _)| l == locale && i == id)
        {
            existing.2.overlay(desc);
        } else {
            self.entries.push((locale.to_owned(), id.to_owned(), desc));
        }
        self
    }
}

impl L10nSource for FakeL10n {
    fn load_locale(&self, locale: &str) -> Result<LoadedLocale, L10nError> {
        let mut merged: BTreeMap<String, Description> = BTreeMap::new();
        for (_, id, desc) in self.entries.iter().filter(|(l, _, _)| l == locale) {
            merged.entry(id.clone()).or_default().overlay(desc.clone());
        }
        Ok((merged, Vec::new()))
    }

    fn available_locales(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for (locale, _, _) in &self.entries {
            if !out.iter().any(|l| l == locale) {
                out.push(locale.clone());
            }
        }
        out
    }
}

/// The default fallback locale: every starter set ships `en`, and the spec's
/// fallback chain is "requested → en → id".
pub const DEFAULT_LOCALE: &str = "en";

/// Resolved display texts for one permission id, after the fallback chain.
///
/// `title` always yields a string (the id itself as last resort) so a UI always
/// has a label; `summary` / `risk_note` may be `None` if untranslated anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedText {
    /// Display title — never empty (id as ultimate fallback).
    pub title: String,
    /// Summary, if translated in the requested locale or `en`.
    pub summary: Option<String>,
    /// Risk note, if translated in the requested locale or `en`.
    pub risk_note: Option<String>,
    /// Which locale satisfied the `title`, or `None` when `title` fell back to
    /// the id (no translation anywhere). Lets callers show "(untranslated)".
    pub locale_used: Option<String>,
}

/// Resolve display texts for `id` with the fallback chain
/// `requested_locale → en → id`, applied **per field**.
///
/// Each field is taken from the requested locale if present there, else from
/// `en`, independently — so a `ru` translation with only `title` still picks up
/// the English `summary`/`risk_note`. `title` falls back finally to the id
/// itself (always non-empty); `summary`/`risk_note` stay `None` if untranslated.
/// `locale_used` records which locale supplied the `title` (the primary field).
///
/// Best-effort: a load error for a locale (e.g. invalid code) is treated as
/// "no data for that locale" so display never fails — metadata must not break the
/// caller.
pub fn resolve_text(sources: &dyn L10nSource, requested_locale: &str, id: &str) -> ResolvedText {
    let requested = sources
        .load_locale(requested_locale)
        .ok()
        .and_then(|(map, _)| map.get(id).cloned())
        .filter(|d| !d.is_empty());

    // Only load `en` separately when it differs from the requested locale.
    let english = if requested_locale == DEFAULT_LOCALE {
        requested.clone()
    } else {
        sources
            .load_locale(DEFAULT_LOCALE)
            .ok()
            .and_then(|(map, _)| map.get(id).cloned())
            .filter(|d| !d.is_empty())
    };

    // Per-field pick: requested wins, else en. `locale_used` follows `title`.
    let (title, locale_used) = match requested.as_ref().and_then(|d| d.title.clone()) {
        Some(t) => (t, Some(requested_locale.to_owned())),
        None => match english.as_ref().and_then(|d| d.title.clone()) {
            Some(t) => (t, Some(DEFAULT_LOCALE.to_owned())),
            // Last resort: the id itself. Always non-empty so a UI has a label.
            None => (id.to_owned(), None),
        },
    };

    let pick = |f: fn(&Description) -> Option<String>| {
        requested
            .as_ref()
            .and_then(f)
            .or_else(|| english.as_ref().and_then(f))
    };

    ResolvedText {
        title,
        summary: pick(|d| d.summary.clone()),
        risk_note: pick(|d| d.risk_note.clone()),
        locale_used,
    }
}

/// Pick the display language from explicit and environment-derived inputs,
/// purely (no process env read here — the caller, slice 5, reads the real env and
/// passes the values in, keeping this testable).
///
/// Precedence: explicit (`--lang`) → `LC_MESSAGES` → `LANG` → `en`. Environment
/// values are stripped to the base code: `ru_RU.UTF-8` → `ru` (cut at the first
/// `_`, `.`, or `@`). An empty/blank value is ignored (falls through).
pub fn lang_from_env(
    explicit: Option<&str>,
    lc_messages: Option<&str>,
    lang: Option<&str>,
) -> String {
    if let Some(e) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        return e.to_owned();
    }
    for raw in [lc_messages, lang].into_iter().flatten() {
        let base = base_locale(raw);
        if !base.is_empty() {
            return base;
        }
    }
    DEFAULT_LOCALE.to_owned()
}

/// Strip a POSIX locale string to its base language code:
/// `ru_RU.UTF-8` → `ru`, `en@euro` → `en`, `C`/`POSIX` → themselves (cut at the
/// first `_`, `.`, or `@`; trimmed).
fn base_locale(raw: &str) -> String {
    let raw = raw.trim();
    let end = raw.find(['_', '.', '@']).unwrap_or(raw.len());
    raw[..end].to_owned()
}

/// A permission id missing a translation (no `title`) for a given locale.
/// Lint surfaces these for declared vendor locales (slice 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missing {
    /// The permission id with no title in `locale`.
    pub id: String,
    /// The locale that lacks a title for `id`.
    pub locale: String,
}

/// A translation key that names an id not in the installed catalog (a typo or a
/// stale/leading translation). A lint signal, never a load error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Orphan {
    /// The translated id that has no matching catalog permission.
    pub id: String,
    /// The locale the orphan key appears in.
    pub locale: String,
}

/// Catalog ids that have no usable `title` in a given locale (per the fallback's
/// primary field). Pure over the source; deterministic order (locales as given,
/// ids as given). An id whose translation exists but lacks a `title` still counts
/// as missing — the title is the field a UI must always show.
pub fn missing_translations(
    sources: &dyn L10nSource,
    locales: &[&str],
    catalog_ids: &[&str],
) -> Vec<Missing> {
    let mut out = Vec::new();
    for &locale in locales {
        let map = sources
            .load_locale(locale)
            .map(|(m, _)| m)
            .unwrap_or_default();
        for &id in catalog_ids {
            let has_title = map.get(id).and_then(|d| d.title.as_ref()).is_some();
            if !has_title {
                out.push(Missing {
                    id: id.to_owned(),
                    locale: locale.to_owned(),
                });
            }
        }
    }
    out
}

/// Translation keys (ids) present in a locale but absent from the catalog —
/// orphaned translations. Pure over the source; deterministic order.
pub fn orphan_translations(
    sources: &dyn L10nSource,
    locales: &[&str],
    catalog_ids: &[&str],
) -> Vec<Orphan> {
    let mut out = Vec::new();
    for &locale in locales {
        let map = sources
            .load_locale(locale)
            .map(|(m, _)| m)
            .unwrap_or_default();
        // BTreeMap iteration is sorted → stable orphan order.
        for id in map.keys() {
            if !catalog_ids.iter().any(|c| c == id) {
                out.push(Orphan {
                    id: id.clone(),
                    locale: locale.to_owned(),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::Path;

    use super::*;

    // --- helpers ---

    fn desc(title: Option<&str>, summary: Option<&str>, risk: Option<&str>) -> Description {
        Description {
            title: title.map(str::to_owned),
            summary: summary.map(str::to_owned),
            risk_note: risk.map(str::to_owned),
        }
    }

    /// Write `body` to `<root>/l10n/<locale>/<group>.toml`, creating dirs.
    fn write_l10n(root: &Path, locale: &str, group: &str, body: &str) {
        let dir = root.join("l10n").join(locale);
        std::fs::create_dir_all(&dir).unwrap();
        let mut f = std::fs::File::create(dir.join(format!("{group}.toml"))).unwrap();
        f.write_all(body.as_bytes()).unwrap();
    }

    // --- parsing ---

    #[test]
    fn parses_locale_file_with_multiple_ids() {
        let map = LiveL10n::parse_file(
            r#"
[network-admin]
title     = "Управление сетью"
summary   = "Настройка интерфейсов."
risk_note = "Фактически root."

[firewall-admin]
title = "Межсетевой экран"
"#,
        )
        .unwrap();
        assert_eq!(map.len(), 2);
        let na = &map["network-admin"];
        assert_eq!(na.title.as_deref(), Some("Управление сетью"));
        assert_eq!(na.summary.as_deref(), Some("Настройка интерфейсов."));
        assert_eq!(na.risk_note.as_deref(), Some("Фактически root."));
        // Partial translation: firewall-admin has only a title.
        let fa = &map["firewall-admin"];
        assert_eq!(fa.title.as_deref(), Some("Межсетевой экран"));
        assert_eq!(fa.summary, None);
        assert_eq!(fa.risk_note, None);
    }

    #[test]
    fn unknown_field_rejected() {
        // A typo in a field name would silently drop the translator's text —
        // reject it (deny_unknown_fields on the inner description struct).
        let err = LiveL10n::parse_file("[a]\ntitel = \"x\"\n");
        assert!(err.is_err(), "unknown field must be rejected");
    }

    #[test]
    fn unknown_id_accepted() {
        // An id not in the catalog is forward/back-compat tolerated at load time
        // (it becomes a lint orphan, not a load error).
        let map = LiveL10n::parse_file("[not-a-real-permission]\ntitle = \"x\"\n").unwrap();
        assert!(map.contains_key("not-a-real-permission"));
    }

    #[test]
    fn namespaced_id_key_parses() {
        // Key may include an add-on namespace, e.g. [docker.ps].
        let map = LiveL10n::parse_file("[\"docker.ps\"]\ntitle = \"Docker ps\"\n").unwrap();
        assert_eq!(map["docker.ps"].title.as_deref(), Some("Docker ps"));
    }

    // --- merge / overlay precedence ---

    #[test]
    fn merge_two_files_same_locale_different_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_l10n(root, "ru", "network", "[network-admin]\ntitle = \"Сеть\"\n");
        write_l10n(root, "ru", "log", "[log-read]\ntitle = \"Логи\"\n");
        let src = LiveL10n::new(vec![root.to_path_buf()]);
        let (map, warnings) = src.load_locale("ru").unwrap();
        assert!(warnings.is_empty());
        assert_eq!(map["network-admin"].title.as_deref(), Some("Сеть"));
        assert_eq!(map["log-read"].title.as_deref(), Some("Логи"));
    }

    #[test]
    fn later_root_overrides_per_field_and_none_does_not_clobber() {
        let usr = tempfile::tempdir().unwrap();
        let etc = tempfile::tempdir().unwrap();
        // vendor (lower precedence): full description.
        write_l10n(
            usr.path(),
            "ru",
            "network",
            "[network-admin]\ntitle = \"Сеть\"\nsummary = \"vendor summary\"\nrisk_note = \"vendor risk\"\n",
        );
        // customer overlay (higher precedence): overrides only title; leaves
        // summary/risk_note untranslated → must NOT clobber vendor's.
        write_l10n(
            etc.path(),
            "ru",
            "network",
            "[network-admin]\ntitle = \"Сеть (заказчик)\"\n",
        );
        let src = LiveL10n::new(vec![usr.path().to_path_buf(), etc.path().to_path_buf()]);
        let (map, _) = src.load_locale("ru").unwrap();
        let d = &map["network-admin"];
        assert_eq!(d.title.as_deref(), Some("Сеть (заказчик)")); // overridden
        assert_eq!(d.summary.as_deref(), Some("vendor summary")); // not clobbered
        assert_eq!(d.risk_note.as_deref(), Some("vendor risk")); // not clobbered
    }

    #[test]
    fn live_overlay_precedence_usr_then_etc() {
        // The /usr-ish then /etc-ish ordering: etc wins for the same id+field.
        let usr = tempfile::tempdir().unwrap();
        let etc = tempfile::tempdir().unwrap();
        write_l10n(usr.path(), "en", "net", "[net]\ntitle = \"vendor\"\n");
        write_l10n(etc.path(), "en", "net", "[net]\ntitle = \"customer\"\n");
        let src = LiveL10n::new(vec![usr.path().to_path_buf(), etc.path().to_path_buf()]);
        let (map, _) = src.load_locale("en").unwrap();
        assert_eq!(map["net"].title.as_deref(), Some("customer"));
    }

    // --- best-effort: malformed file skipped ---

    #[test]
    fn malformed_file_skipped_others_load_with_warning() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // Good file and a structurally broken one in the same locale.
        write_l10n(root, "ru", "good", "[network-admin]\ntitle = \"Сеть\"\n");
        write_l10n(root, "ru", "broken", "this is = not valid = toml [[[\n");
        let src = LiveL10n::new(vec![root.to_path_buf()]);
        let (map, warnings) = src.load_locale("ru").unwrap();
        // Good file still loaded.
        assert_eq!(map["network-admin"].title.as_deref(), Some("Сеть"));
        // Broken file recorded as a warning, not a hard error.
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].path.ends_with("broken.toml"));
    }

    #[test]
    fn unknown_field_in_one_file_skips_only_that_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_l10n(root, "en", "good", "[a]\ntitle = \"A\"\n");
        write_l10n(root, "en", "typo", "[b]\ntitel = \"B\"\n");
        let src = LiveL10n::new(vec![root.to_path_buf()]);
        let (map, warnings) = src.load_locale("en").unwrap();
        assert!(map.contains_key("a"));
        assert!(!map.contains_key("b"));
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn absent_locale_is_empty_not_error() {
        let tmp = tempfile::tempdir().unwrap();
        let src = LiveL10n::new(vec![tmp.path().to_path_buf()]);
        let (map, warnings) = src.load_locale("zh").unwrap();
        assert!(map.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn invalid_locale_is_error() {
        let tmp = tempfile::tempdir().unwrap();
        let src = LiveL10n::new(vec![tmp.path().to_path_buf()]);
        assert!(matches!(
            src.load_locale("../etc"),
            Err(L10nError::InvalidLocale(_))
        ));
    }

    // --- available_locales ---

    #[test]
    fn live_available_locales_lists_present_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_l10n(root, "en", "x", "[a]\ntitle = \"A\"\n");
        write_l10n(root, "ru", "x", "[a]\ntitle = \"А\"\n");
        let src = LiveL10n::new(vec![root.to_path_buf()]);
        let mut locs = src.available_locales();
        locs.sort();
        assert_eq!(locs, vec!["en", "ru"]);
    }

    // --- fallback chain (resolve_text) ---

    #[test]
    fn fallback_requested_locale_present() {
        let src = FakeL10n::new().with(
            "ru",
            "network-admin",
            desc(Some("Управление сетью"), Some("сводка"), Some("риск")),
        );
        let r = resolve_text(&src, "ru", "network-admin");
        assert_eq!(r.title, "Управление сетью");
        assert_eq!(r.summary.as_deref(), Some("сводка"));
        assert_eq!(r.risk_note.as_deref(), Some("риск"));
        assert_eq!(r.locale_used.as_deref(), Some("ru"));
    }

    #[test]
    fn fallback_to_en_when_requested_absent() {
        let src = FakeL10n::new().with(
            "en",
            "network-admin",
            desc(Some("Network admin"), Some("summary"), None),
        );
        // zh has nothing → fall back to en.
        let r = resolve_text(&src, "zh", "network-admin");
        assert_eq!(r.title, "Network admin");
        assert_eq!(r.summary.as_deref(), Some("summary"));
        assert_eq!(r.risk_note, None);
        assert_eq!(r.locale_used.as_deref(), Some("en"));
    }

    #[test]
    fn fallback_to_id_when_nothing_translated() {
        let src = FakeL10n::new();
        let r = resolve_text(&src, "ru", "network-admin");
        assert_eq!(r.title, "network-admin"); // id as last resort
        assert_eq!(r.summary, None);
        assert_eq!(r.risk_note, None);
        assert_eq!(r.locale_used, None);
    }

    #[test]
    fn fallback_per_field_mixes_requested_and_en() {
        // ru has only a title; en has summary + risk_note. Each field is picked
        // independently: title from ru, summary/risk_note from en.
        let src = FakeL10n::new()
            .with("ru", "net", desc(Some("Сеть"), None, None))
            .with(
                "en",
                "net",
                desc(Some("Network"), Some("EN summary"), Some("EN risk")),
            );
        let r = resolve_text(&src, "ru", "net");
        assert_eq!(r.title, "Сеть"); // from ru
        assert_eq!(r.summary.as_deref(), Some("EN summary")); // from en
        assert_eq!(r.risk_note.as_deref(), Some("EN risk")); // from en
        assert_eq!(r.locale_used.as_deref(), Some("ru")); // title came from ru
    }

    #[test]
    fn empty_description_treated_as_absent() {
        // A description with all None must not satisfy the requested locale; the
        // fallback chain skips past it to en, then id.
        let src = FakeL10n::new()
            .with("ru", "net", desc(None, None, None))
            .with("en", "net", desc(Some("Network"), None, None));
        let r = resolve_text(&src, "ru", "net");
        assert_eq!(r.title, "Network");
        assert_eq!(r.locale_used.as_deref(), Some("en"));
    }

    // --- lang_from_env (pure) ---

    #[test]
    fn lang_from_env_explicit_wins() {
        assert_eq!(
            lang_from_env(Some("ru"), Some("de_DE.UTF-8"), Some("fr_FR")),
            "ru"
        );
    }

    #[test]
    fn lang_from_env_strips_posix_suffixes() {
        assert_eq!(lang_from_env(None, Some("ru_RU.UTF-8"), None), "ru");
        assert_eq!(lang_from_env(None, None, Some("en_US.UTF-8")), "en");
        assert_eq!(lang_from_env(None, Some("en@euro"), None), "en");
    }

    #[test]
    fn lang_from_env_lc_messages_beats_lang() {
        assert_eq!(lang_from_env(None, Some("ru_RU"), Some("en_US")), "ru");
    }

    #[test]
    fn lang_from_env_defaults_to_en() {
        assert_eq!(lang_from_env(None, None, None), "en");
        // Blank/whitespace values are ignored, fall through to en.
        assert_eq!(lang_from_env(Some("  "), Some(""), None), "en");
    }

    // --- lint helpers ---

    #[test]
    fn missing_translations_flags_absent_and_titleless() {
        let src = FakeL10n::new()
            .with("ru", "a", desc(Some("А"), None, None))
            // b present in ru but with no title → still missing.
            .with("ru", "b", desc(None, Some("сводка"), None));
        let catalog = ["a", "b", "c"];
        let missing = missing_translations(&src, &["ru"], &catalog);
        // a has a title → not missing; b (no title) and c (absent) → missing.
        assert_eq!(
            missing,
            vec![
                Missing {
                    id: "b".to_owned(),
                    locale: "ru".to_owned()
                },
                Missing {
                    id: "c".to_owned(),
                    locale: "ru".to_owned()
                },
            ]
        );
    }

    #[test]
    fn orphan_translations_flags_unknown_ids() {
        let src = FakeL10n::new()
            .with("ru", "a", desc(Some("А"), None, None))
            .with("ru", "ghost", desc(Some("Призрак"), None, None));
        let catalog = ["a"];
        let orphans = orphan_translations(&src, &["ru"], &catalog);
        assert_eq!(
            orphans,
            vec![Orphan {
                id: "ghost".to_owned(),
                locale: "ru".to_owned()
            }]
        );
    }

    #[test]
    fn lint_helpers_handle_multiple_locales() {
        let src = FakeL10n::new()
            .with("en", "a", desc(Some("A"), None, None))
            .with("ru", "a", desc(Some("А"), None, None));
        let catalog = ["a"];
        assert!(missing_translations(&src, &["en", "ru"], &catalog).is_empty());
        assert!(orphan_translations(&src, &["en", "ru"], &catalog).is_empty());
    }
}
