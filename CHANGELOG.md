# Changelog

All notable changes to Census are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and Census adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The CLI surface and TOML formats are additionally locked by a versioned
interface contract (`contract/`, see `contract/VERSION`); breaking changes to
that surface follow the rules in the interface-contract design.

## [Unreleased]

## [0.1.0] — 2026-06-27

First tagged release. Census is a declarative provisioner of Unix access
objects (role-accounts, groups, `sudoers.d`, file ACLs) from a Tessera
role-store — it runs as root, outside the authentication path, and brings a
device into conformance with a signed declaration.

### Added

- **Provisioning core** — `plan` / `apply` / `doctor` / `status`; atomic apply
  with full-file + ACL snapshot rollback (dual-seam), idempotent re-apply.
- **Declaration trust** — Ed25519-signed declarations verified against a
  root-only trust anchor (fail-closed before any mutation); monotonic
  anti-rollback version floor; standalone `--trust-fs` mode for air-gapped use.
- **Role-accounts** — create / update / delete managed accounts (locked
  password, real shell, no `authorized_keys` — login only via the Tessera
  certificate path); GECOS-spoof detection.
- **Groups & group-grants** — created vs adopted provenance; `[[role_group]]`
  projects a role's grants onto a Unix group as `%group` sudoers and `g:group`
  ACLs; adopted groups are never `groupdel`'d and foreign members are preserved
  (release returns to baseline).
- **Permission catalog** — operators declare *capabilities*; Census compiles
  them per OS target (layered `linux → distro → version → /etc`) into concrete
  groups / sudoers commands / limits, with bundles, categories, namespaces,
  risk labelling and an `l10n` tree (`en` / `ru` / `zh`). `compile` / `show` /
  `lint` CLI; a starter vendor catalog under `share/permissions`.
- **File access** — `ro`/`rw` directory grants materialized as POSIX ACLs +
  default-ACL (rewrite-proof) via the open `AclBackend`; per-file / pattern
  grants are capability-gated and fail closed in the open build.
- **Catalog coverage** — `catalog coverage` audits the live privileged surface
  (setuid, sudo binaries, configs, units, groups, capability files) against the
  installed catalog and reports what is uncovered; `--min-coverage` CI gate
  (fails closed on scan-tool degradation).
- **Framework cross-reference** — read-only compliance annotation
  (`show --framework`, `framework coverage`) with starter `pci-dss` /
  `cis-controls` mappings.
- **Live reconcile** — defers `userdel` (and an orphaned group) while a managed
  account holds a live session; completes the delete on a later apply.
- **Per-permission run-as** — sudo commands carry their own run-spec; a
  de-rooted command cannot be silently widened back to `root` through a bundle.
- **Interface contract** — CLI and TOML formats locked by `schemars` + `clap`
  golden tests (`contract/`).

### Security

- Layered sudoers-injection defenses (param charset → per-param constraint →
  post-substitution defect check → escape → `visudo -c`).
- `allow_prefix` path containment matched on a `/`-component boundary
  (no sibling-directory escape); a trailing slash is required at parse.
- Symlinked grant-root fail-closed on materialize / revoke / snapshot; capped
  reads (4 MiB) on all root-parsed inputs.

[Unreleased]: https://github.com/TesseraLabs/census/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/TesseraLabs/census/releases/tag/v0.1.0
