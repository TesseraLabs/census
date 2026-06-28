# Census deb/rpm packaging in CI — design

**Date:** 2026-06-28
**Status:** approved (brainstorming)
**Scope:** Add native Debian (`.deb`) and RPM (`.rpm`) package artifacts to the
census release pipeline, alongside the existing static musl binary.

## Goal

On a pushed `v*` tag, `release.yml` currently builds a `static-pie`, stripped,
musl-linked `census` binary and publishes it on a GitHub Release with a SHA-256
checksum. This design adds two more publishable artifacts built from that same
binary: a `.deb` and a `.rpm`, each with its own `.sha256`. Operators on
Debian/Ubuntu/Astra and RHEL-family hosts can then install census with their
native package manager instead of dropping a loose binary and hand-placing the
data trees.

## Why now / constraints

- census already bakes its runtime FHS paths into the binary (verified in code):
  - binary: `/usr/bin/census`
  - permission catalog: `/usr/share/census/permissions` (+ `/etc/census/permissions.d` override) — `src/cli/mod.rs::default_catalog_roots`
  - frameworks: `/usr/share/census/frameworks` (+ `/etc/census/frameworks.d` override) — `src/framework.rs`
  - l10n lives **inside** the permissions tree (`/usr/share/census/permissions/l10n/...`) — `src/l10n.rs`
  - declaration default: `/etc/census/declaration.toml` (operator-supplied, NOT shipped)
- The release binary is `static-pie` musl with no libc version dependency, so the
  packages declare **no runtime Depends** — they install cleanly on old glibc
  targets (e.g. Astra Linux SE 1.8).
- The package layout MUST match these baked-in paths exactly, or an installed
  census finds an empty catalog.

## Tooling decision

**nfpm** (`github.com/goreleaser/nfpm`). One declarative config
(`packaging/nfpm.yaml`) emits both `.deb` and `.rpm` from the same file list. No
`rpmbuild` chroot or `dpkg-dev` toolchain needed in CI — nfpm is a single pinned
binary (installed the same way `taplo` already is in `ci.yml`).

Rejected: `cargo-deb` + `cargo-generate-rpm`. Cargo-native metadata is nice, but
it is two separate tools with two configs, and census ships large arbitrary data
trees (`share/permissions/**`, `share/frameworks/**`) that would have to be
enumerated as assets twice. nfpm keeps a single source of truth.

## Package layout (FHS)

| Source (repo) | Destination | Mode | Notes |
|---|---|---|---|
| `target/.../release/census` (stripped musl) | `/usr/bin/census` | 0755 | |
| `share/permissions/**` | `/usr/share/census/permissions/` | 0644 | includes the `l10n/` subtree |
| `share/frameworks/**` | `/usr/share/census/frameworks/` | 0644 | |
| `examples/**` | `/usr/share/doc/census/examples/` | 0644 | reference only, not active config |
| `README.md`, `CHANGELOG.md`, `LICENSE` | `/usr/share/doc/census/` | 0644 | |
| _(empty dir)_ | `/etc/census/permissions.d/` | 0755 | drop-in override location, shipped empty |
| _(empty dir)_ | `/etc/census/frameworks.d/` | 0755 | drop-in override location, shipped empty |

The empty `/etc/census/*.d` directories are shipped so operators immediately see
where overrides go; the binary already treats their absence as "no overrides", so
shipping them empty is non-behavioral and conflict-free.

## Package metadata

- name: `census`
- arch: `amd64` (deb) / `x86_64` (rpm) — single arch, matching the current
  release target. arm64 is explicitly out of scope for now.
- version: derived from the tag (`${GITHUB_REF_NAME}` with leading `v` stripped),
  passed to nfpm via an env var the config interpolates. The existing
  tag-vs-`Cargo.toml` guard in `release.yml` already prevents a version mismatch.
- depends: **none** (static musl binary).
- section/group: `admin`
- vendor: `TesseraLabs`
- license: `AGPL-3.0-only`
- homepage: `https://github.com/TesseraLabs/census`
- maintainer: TesseraLabs release identity (same as repo).

## Release pipeline changes (`release.yml`)

Extend the existing single `build` job — the musl binary is built and stripped
exactly once and reused for packaging. Added steps, in order, after the current
`Package` step:

1. **Install nfpm** — download a pinned nfpm release binary to `/usr/local/bin`
   (mirrors the existing `taplo` install pattern: fixed version, checksum-stable
   URL, no `apt`/compile).
2. **Build packages** — `VERSION=${GITHUB_REF_NAME#v} nfpm package -f packaging/nfpm.yaml -p deb -t .`
   and the same with `-p rpm -t .`. nfpm resolves the source paths relative to
   the repo root.
3. **Checksum** — `sha256sum` each produced `census_*.deb` / `census-*.rpm` into
   a matching `.sha256`.
4. **Publish** — extend the existing `softprops/action-gh-release` `files:` list
   to include the `.deb`, `.rpm`, and their `.sha256` alongside the musl binary
   already published.

No new job, no new trigger: packaging runs only on `v*` tags, same as today. PRs
and `main` pushes are unaffected (no per-PR package smoke build — explicitly
deferred per the brainstorming decision).

## New files

- `packaging/nfpm.yaml` — the single nfpm config (file map + metadata above).

## Out of scope (YAGNI)

- No systemd unit — census is an on-demand CLI provisioner, not a daemon.
- No maintainer scripts (postinst/postrm/preinst) — data is static, config is
  operator-owned; nothing to enable, migrate, or clean up on install/remove.
- No shipped `/etc/census/declaration.toml` — that is the operator's access
  policy, not a package default. The `examples/` tree ships only as
  documentation under `/usr/share/doc/census/examples/`, never as active `/etc`
  config.
- No arm64 / multi-arch.
- No per-PR package build (catching nfpm-config breakage early was offered and
  declined; config errors surface at tag time).
- No apt/yum repository hosting — artifacts are GitHub Release downloads only.

## Verification

- nfpm config validity is exercised at release time; a malformed `nfpm.yaml`
  fails the `Build packages` step and aborts the release before publish.
- Manual post-release acceptance (one-time, documented for the release runbook,
  not automated here): on a Debian/Astra host, `dpkg -i census_*.deb` then
  `census --help` and a `census plan` against a sample declaration resolves the
  catalog from `/usr/share/census/permissions` with no extra flags; same for
  `rpm -i` on a RHEL-family host. This confirms the package paths match the
  baked-in roots.

## Testing strategy

This is release-infra config (CI YAML + nfpm YAML), not product code — there are
no unit tests to add. Correctness is established by:

1. The path table above being checked against the in-binary constants (done
   during brainstorming: `default_catalog_roots`, `framework.rs` roots, `l10n.rs`).
2. The release-time build step failing loudly on config errors.
3. The one-time manual install acceptance on a real target before the artifacts
   are trusted.
