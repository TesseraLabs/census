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
census compile   <role> [--os-target T] [--catalog-dir D] [--lint]   # expand permissions → primitives + provenance
census show      <role> [--lang ru|en|zh] [--os-target T]            # tree of permissions → primitives, localized
```

(`census catalog coverage` — auditing which privileged surface is not covered by
the catalog — is designed and planned.)

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
| Fleet | — | inventory + aggregated drift, staged rollout / canary, catalog curation |

The open core is self-sufficient: applying a locally-signed declaration works
without any server — Census is not crippleware.

## License

[AGPL-3.0-only](https://www.gnu.org/licenses/agpl-3.0.en.html).
