# Census

**Declarative provisioner of Unix access objects.**

Census brings a device's Unix access layer — role-accounts, group memberships,
`sudoers.d` rules, systemd limits — into conformance with a signed declaration.
It is idempotent, fail-safe, and runs **off the authentication path**: Census
materializes the OS objects that an authenticator (such as
[Tessera](https://github.com/TesseraLabs/tessera)) gates at login, but it does
not itself authenticate anyone. Census also runs perfectly well **standalone**,
without any central server.

> Status: **pre-release (v0.1.0)**, under active development. Interfaces may change.

## Why

Owners of large device fleets (ATMs, industrial controllers, KIOSKs, edge nodes)
face a bad choice between one shared account (no accountability) and a personal
account per person per device (`N×M`, unmanageable). Census takes a third path:
a handful of **role-accounts** per device — `oper`, `serv`, `admin` — each a real
Unix account whose interactive entry is closed (locked password, no
`authorized_keys`), reachable only through a certificate authenticator. Identity
lives in the credential, not in the account; the role-account just carries the
*rights* of the role. Census is what makes those role-accounts, groups and sudo
rules exist, consistently and reproducibly, across the fleet.

## The model: *role = account*

A role-account is an ordinary account with a real shell, gated shut at the
credential layer:

- password locked (`!` in shadow) — Census sets it on creation;
- no `~/.ssh/authorized_keys` — Census never writes one;
- the only entry path is the authenticator's PAM service.

Census owns only what it created (tracked in a root-only registry,
`/var/lib/census/managed.toml`) and never touches foreign accounts or groups.

## Permission catalog

Instead of hand-writing `sudoers` and group lists, roles are described in named
**permissions** — capabilities such as `network-admin`, `log-read`,
`service-restart` — that Census expands into the concrete OS primitives
(`groups`, `sudo` commands, `limits`) for the device's distribution:

```toml
# a role in the role-store
[payload]
permissions = ["network-admin", "log-read", { id = "service-restart", units = ["app.service"] }]
```

- **Per-OS layering.** The catalog resolves a chain
  `linux → linux-debian → linux-debian-12` (and `linux-ubuntu`, `linux-astra`),
  so the same permission expands to `nft` vs `ufw`, `netplan` vs `ifupdown`, or
  Astra-specific groups as appropriate.
- **Bundles.** A permission can aggregate others
  (`network-config = network-diag + network-admin + firewall-admin + dns-config`),
  resolved transitively; a bundle's risk class is the maximum of its members.
- **Add-on packages.** Software-specific capabilities (e.g. `docker.*`) ship as
  separate namespaced packages that drop into the same catalog tree.
- **Honest risk classes.** Every permission is marked `contained` or
  `escalation-capable` — no illusion of "restricted sudo" where a path to root
  exists (`docker` group, `modprobe`, `setcap`, `strace`, …).
- **Localized descriptions.** Human text (`title` / `summary` / `risk_note`)
  lives in a separate `l10n/<locale>/` tree (shipped in English, Russian, and
  Chinese), so translators contribute without touching security definitions.

The starter catalog ships ~75 permissions across 14 domains for Debian, Ubuntu,
and Astra Linux.

## Safety

- **Fail-closed trust.** In managed mode the declaration is verified
  (Ed25519 signature + monotonic anti-rollback version) before any mutation; an
  invalid signature or a rolled-back version aborts before touching the system.
- **Atomic apply.** A full-file snapshot of `/etc/passwd`, `/etc/shadow`,
  `/etc/group`, `/etc/gshadow` and touched `sudoers.d/census-*` is taken before
  any change; a phase failure restores it atomically. Mutations go through
  shadow-utils (`useradd`/`usermod`/`gpasswd`/`userdel`), never by editing the
  databases directly; sudoers fragments are validated with `visudo -c` before
  activation.
- **Anti-lockout.** `apply` refuses a plan that would remove the last working
  login path.
- **Live-session reconcile.** Destructive changes to a role-account with a live
  session are deferred — Census never tears down an in-progress session.
- **Catalog hardening.** Catalog files are parsed strictly; `sudo` commands must
  be absolute paths, control characters and parameter-injection are rejected.

## CLI

```
census plan      [--declaration P] [--managed P]        # diff, no mutations
census apply     [--declaration P] [--managed P] ...     # verify → plan → backup → apply
census doctor    [--declaration P] [--managed P]         # read-only readiness/integrity checks
census status    [--declaration P] [--managed P]         # managed accounts, version, drift
census compile   <role> [--os-target T] [--additional-catalog-dir D] [--lint]   # expand permissions → primitives + provenance
census show      <role> [--lang ru|en|zh] [--os-target T] [--framework F]   # tree of permissions → primitives, localized; with --framework, control ids per permission
census framework list                                                # installed compliance frameworks (id, version, provides)
census framework show     <fw>                                       # a framework's controls + coverage stats
census framework coverage <fw>                                       # gap-oracle: owned controls with no mapping
census framework risk     <fw>                                       # controls a mapping undermines (risk links) + threatening permissions
census framework lint     [--additional-catalog-dir D]                          # validate mappings against the catalog
census audit fs      [--root P]... [--full] [--format text|json] [--config P]   # read-only filesystem posture map
census audit expose  --principal <name|uid> [--root P]... [--full] [--format text|json]   # read-only per-principal exposure
```

(`census catalog coverage` — auditing which privileged surface is not covered by
the catalog — is designed and planned.)

## Exposure audit (`census audit`)

Census provisions access *forward* (grants, groups, sudoers); `census audit`
answers the *reverse*, read-only question — **what can actually be read/written on
this filesystem?** — so an ambient over-permission (a world-writable
`/var/spool/cron`, a world-readable secret) that undermines a least-privilege
role cannot hide. It never mutates anything; it walks and `stat`s the filesystem
and reads POSIX ACLs via `getfacl`. Two modes share one scan:

- **`census audit fs`** — a global, principal-independent **posture map**:
  world-writable objects in sensitive trees, the setuid/setgid inventory (a
  *writable* setuid binary is critical), world-readable secrets, and
  broad-group-writable objects.
- **`census audit expose --principal <name|uid>`** — what one principal can
  actually **reach** (effective access + ancestor `x`-traversal). For a
  Census-managed role-account the *intended baseline* (its home and granted
  paths) is subtracted, so only the **excess** access beyond the declared intent
  remains; for an arbitrary uid the raw reachability is shown.

Each finding carries the path, effective access, object class, risk
(escalation / leak / tamper), severity, the `via` reason, and a remediation hint
classed `ambient` (a foreign object — manual `chmod`/`setfacl`) or `in-model` (a
Census-owned group or grant — narrow the declaration). A finding at or above
**High** severity makes the process exit non-zero (for CI/monitoring, like
`doctor`).

> **Caveats (read these):**
>
> - **DAC-only — the verdict is an upper bound.** The audit considers only
>   discretionary access (mode, owner, POSIX ACL). A MAC layer (SELinux,
>   AppArmor, PARSEC) may restrict actual access *further*; every `expose` report
>   states this.
> - **Local passwd/group only (NSS advisory).** Principal resolution and group
>   membership read the local `/etc/passwd` and `/etc/group`. NSS/LDAP sources are
>   not consulted, so an account whose membership lives only in a directory
>   service is under-reported.
> - **The report is itself a sensitive artifact.** It is a map of the system's
>   weak spots. The output carries only metadata (paths, modes, classes) and never
>   secret *content*, but do not log it or share it carelessly.

Scan scope and the classifiers are configurable in `exposure.toml`
(`--config`, default `/etc/census/exposure.toml`; an absent file uses the
built-in defaults). Comments are English; the file is strict-parsed
(`deny_unknown_fields`):

```toml
# /etc/census/exposure.toml — read-only exposure-audit configuration.

# Roots scanned when no --root/--full is given. Default: the security-relevant
# trees (/etc /var /opt /usr/local /srv /home /root).
scan_roots = ["/etc", "/var", "/opt", "/usr/local", "/srv", "/home", "/root"]

# Globs that classify an inode as a `secret`. Default: shadow, keys, PEM,
# id_rsa*, .env*, *credentials*. `**` spans path segments; `*` is within a segment.
# At most one `**` per glob (more is rejected at load — it risks exponential blowup).
secret_globs = [
  "/etc/shadow*",
  "**/*.key",
  "**/*.pem",
  "**/id_rsa*",
  "**/.env*",
  "**/*credentials*",
]

# Wide group NAMES whose group-write access is a posture concern. Matched by
# name against the host's real /etc/group, so a renumbered group is still caught.
broad_groups = ["adm", "wheel", "sudo", "staff", "users"]
```

## Compliance frameworks

A read-only **cross-reference** layer maps catalog permissions to the access-governance
requirements of compliance frameworks (ships with `pci-dss` and `cis-controls`; more add as
data, no code change). It is **advisory** — it never participates in `compile`/grant/`apply`,
so a tampered mapping cannot escalate privilege, only mislabel coverage. Frameworks live in
`frameworks/<fw>/` (a `framework.toml` manifest with `dimension` = `flat` | `os-layered`,
`mappings/*.toml` keyed by permission id, and an optional `controls.toml` whose `owned` flag
marks the boundary of what Census actually covers — host-hardening is out of scope).
Each mapping link carries a polarity — `satisfies` (addresses the control, the only polarity
coverage counts), `risk` (undermines it — surfaced by `framework risk`), or `related`
(neutrally touches it).
`framework coverage` then reports which `owned` controls no role yet satisfies.

## Documentation

Full guides live under [`docs/`](docs/), in **English**, **Russian**, and
**Chinese**:

- **[Getting started](docs/en/getting-started.md)** — install, configure, first
  `apply`, and operate a device end to end.
- **[TOML format reference](docs/en/toml-reference.md)** — every field of the
  declaration and role slice, plus the `plan --diff` preview mode.
- Index: [English](docs/en/index.md) · [Русский](docs/ru/index.md) ·
  [中文](docs/zh/index.md).

Catalog/package authoring: [`docs/catalog-authoring.md`](docs/catalog-authoring.md)
and [`docs/authoring-packages.md`](docs/authoring-packages.md) (Russian).

## Build

```sh
cargo build --release
./target/release/census --help
```

Rust stable, no network access required at runtime. See `examples/` for a sample
role-store and declaration.

## Open core / commercial

Census is open-core: **local application is open; managing a fleet is commercial.**

| Area | Open (`census`) | Commercial |
|---|---|---|
| Engine | declaration format, plan/apply/doctor/status, permission catalog (compile/show/lint), local signature verification, fail-safe, rollback | — |
| Delivery | `apply` of a locally-signed declaration (no server) | declaration delivery via a control plane |
| Compliance | framework cross-reference engine + starter `pci-dss` / `cis-controls` mappings, `show --framework`, `framework coverage` | framework curation subscription, per-fleet conformance reports |
| Fleet | — | inventory + aggregated drift, staged rollout / canary, catalog curation |

The open core is self-sufficient: applying a locally-signed declaration works
without any server — Census is not crippleware.

## License

Dual-licensed: [GNU AGPL-3.0](LICENSE) OR [commercial](LICENSE.commercial).
Choose AGPL-3.0 and accept its obligations (including source disclosure of
derivative works), or see [LICENSE.commercial](LICENSE.commercial) for a
commercial license without AGPL obligations.

Contributions are accepted under a Contributor License Agreement — see
[`docs/cla/`](docs/cla/). The CLA bot guides you on your first pull request.
