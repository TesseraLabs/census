# Getting started with Census

This guide walks an operator through **installing**, **configuring**, and
**running** Census on a single device, end to end: from placing the binary to
applying a first declaration and verifying the result, then operating it over
time.

Census is a *declarative provisioner of Unix access objects*. You describe the
access a device should have — which role-accounts exist, what groups, `sudo`
rules, systemd limits and file ACLs they carry — in a **declaration**, and
`census apply` brings the machine into conformance. It is idempotent (re-running
changes nothing if already in conformance), atomic (a failed apply rolls back),
and runs **off the authentication path** — it materializes the OS objects an
authenticator gates at login, it does not authenticate anyone.

This guide covers the **standalone** mode (a locally-trusted declaration, no
server — the open-core path). A short section at the end points to the
**managed** mode (a centrally-signed declaration).

> Status: Census is pre-release (v0.1.0). Commands and paths below are current
> for that version.

---

## 0. Prerequisites

Census runs on a Linux device and mutates the local access databases, so it
needs:

- **root** to apply (it calls `useradd`/`usermod`/`gpasswd`/`userdel`,
  writes `sudoers.d`, sets ACLs). Read-only subcommands (`plan`, `compile`,
  `show`, `status`, `doctor`) do not need root.
- **shadow-utils** — `useradd`, `usermod`, `gpasswd`, `userdel` (present on
  every mainstream distro).
- **`sudo`** with `visudo` — Census validates every fragment with `visudo -c`
  before activating it.
- **`acl`** — `setfacl`/`getfacl`, required **only if** any role grants
  file-access permissions (ACLs on config/log trees). Install with
  `apt-get install acl` (Debian/Ubuntu/Astra) if absent. File-access grants are
  **directory-level** (a directory ACL is rewrite-proof; a single-file grant is
  refused at apply unless a per-file backend is installed).
- **systemd** — for the `service-*` permissions (which authorize
  `systemctl …`) and for scheduling periodic reconcile (§4.1).

Supported distribution families ship in the starter catalog: **Debian 12**,
**Ubuntu 22.04**, **Astra Linux 1.8**. Other Linux works; per-OS specifics fall
back to the family base.

---

## 1. Install

Census is a single static binary. There is no daemon and no runtime network
dependency.

### 1.1 Obtain the binary

**Option A — build from source** (on a build host with Rust stable):

```sh
git clone https://github.com/TesseraLabs/census.git
cd census
cargo build --release
./target/release/census --version
```

**Option B — cross-compile a static binary for the device** (recommended for
fleet devices, e.g. when the build host differs from the target). A
`x86_64-unknown-linux-musl` build is statically linked (static-pie) and has no
libc/runtime dependency, so it runs on any glibc/musl Linux of that arch,
including Astra:

```sh
# on the build host (needs `cross` + Docker, or a musl toolchain)
cross build --release --target x86_64-unknown-linux-musl
file target/x86_64-unknown-linux-musl/release/census
#   ... ELF 64-bit LSB pie executable, x86-64, static-pie linked, stripped
```

Copy the resulting `census` to the device.

### 1.2 Place and mark executable

Install the binary to a directory on root's `PATH` (so scheduled runs find it):

```sh
sudo install -m 0755 census /usr/local/sbin/census
sudo census --version
```

> **Astra Linux note.** Under Astra's mandatory integrity control (МКЦ), a
> non-root user cannot `chmod +x` a freshly copied file — use `sudo install`
> (as above) or `sudo chmod +x`. Astra's closed-software-environment (ЗПС /
> digsig) does **not** block the binary from running once it is executable;
> Census executes normally.

### 1.3 Verify the install

```sh
census --version
census --help          # lists subcommands: plan, apply, doctor, status,
                       #   compile, show, catalog, framework
command -v setfacl     # required only for file-access permissions (§0)
```

---

## 2. Configure

A working configuration is three things: a **declaration** (which accounts to
provision), a **role-store** (what each role means), and the **catalog** (how a
permission expands into OS primitives for this distro). The starter catalog
ships with Census, so in practice you write the declaration and the role-store.

The `examples/` directory in the repo is a complete, runnable sample — copy it
as a starting point.

### 2.1 The declaration — `/etc/census/declaration.toml`

The declaration lists the role-accounts this device should have and binds each
to a stable UID:

```toml
schema     = 1                # parser format version — required (fail-closed if
                              #   this Census build does not support it)
version    = 1                # monotonic anti-rollback content counter
                              #   (enforced only in managed/signed mode)
role_store = "roles"          # path to the role-store, relative to the
                              #   working directory `census` runs from

[defaults]
uid_range = [9000, 9999]      # role-account UIDs must fall in this range
shell     = "/bin/bash"
home_base = "/var/lib/census/home"

[[role_account]]
role = "oper"                 # must match a role slice in the role-store
uid  = 9001

[[role_account]]
role = "admin"
uid  = 9002
```

- `schema` is the **parser format version** and is **required**. Census refuses
  a declaration whose `schema` it does not support, before any mutation — copy
  the `schema = 1` line into every declaration you write.
- `version` is a separate, monotonic **anti-rollback counter for the
  declaration's content**; it is enforced only in managed (signed) mode and is
  not checked under `--trust-fs`. See the [TOML reference](toml-reference.md#11-top-level)
  for the full `schema` vs `version` distinction.
- `role_store` is resolved **relative to the working directory** Census runs
  from. Either run Census from the directory that contains `roles/`, or use an
  absolute path.
- Every `uid` must fall inside `[defaults].uid_range`.
- `role` must name a slice present in the role-store (§2.2).

### 2.2 The role-store — one slice per role

The role-store is a directory of role slices, one `<role>.toml` per role. A
slice names the **permissions** the role carries:

```toml
# roles/oper.toml
role    = "oper"
version = 1
os      = "linux"
name    = "Device operator"
level   = 3

[payload]
permissions = [
    "service-restart",                                   # a leaf permission
    "log-read",                                          # another leaf
    { id = "service-control", units = "nginx" },         # a parametrized permission
    "nginx.operate",                                     # a curated app package
]
```

A permission is one of:

- a **leaf** — a single capability (`log-read`, `network-admin`);
- a **bundle** — a permission that aggregates others, resolved transitively
  (`network-config` = `network-diag` + `network-admin` + `firewall-admin` + …);
- a **parametrized permission** — `{ id = "service-control", units = "nginx" }`
  binds the unit(s) the permission applies to;
- a **curated app package** — `<app>.{observe|operate|admin}` (e.g.
  `nginx.operate`, `salt-minion.admin`), a ready-made tier for a common service.
  See §2.4.

To see what permissions exist, browse the catalog tree (§2.3) or expand a role
with `census compile` / `census show` (§3.2).

### 2.3 The catalog and per-OS targeting

The **catalog** turns permissions into concrete OS primitives (`groups`,
`sudo` commands, `limits`, file ACLs). The starter catalog ships inside Census
under `share/permissions/`. Census also looks in the default catalog roots
`/usr/share/census/permissions` and `/etc/census/permissions.d`. Point Census at
an **additional** catalog root with `--additional-catalog-dir` (repeatable; it
appends to the defaults, and later roots win on an id collision):

```sh
census compile oper --additional-catalog-dir /opt/census/share/permissions
```

To run against **only** your own roots — an isolated run that ignores the
built-in defaults — add `--no-default-catalog-dirs`:

```sh
census compile oper \
  --no-default-catalog-dirs \
  --additional-catalog-dir /opt/census/share/permissions
```

`--no-default-catalog-dirs` drops both built-in defaults from the root list.
Given **without** any `--additional-catalog-dir` it would leave zero catalog
roots, so Census refuses it with a non-zero exit (it never resolves against an
empty catalog). The old `--catalog-dir` flag — which only appended — has been
removed; use `--additional-catalog-dir` instead.

The catalog is **layered per OS**: a permission resolves along a chain
`linux → linux-debian → linux-debian-12` (and `linux-ubuntu`, `linux-astra`),
so the same `firewall-admin` expands to `nft` vs `ufw` as appropriate. Census
**auto-detects** the OS from `/etc/os-release`; override it explicitly when
compiling on a different host:

```sh
census compile oper --os-target linux-astra-1.8
census compile oper --os-target linux-debian-12
```

> If the exact version layer is absent (e.g. `linux-astra-1.8`), Census resolves
> against the nearest base layer (`linux-astra`) and warns — this is expected,
> not an error.

### 2.4 Curated app packages

For common services, the catalog ships ready-made permission packages following
the convention `<app>.{observe | operate | admin}`:

- **observe** — read-only: service status + read-only ACL on the app's config
  and logs. Always `contained`.
- **operate** — lifecycle (start/stop/restart) plus read access; for a service
  whose daemon runs **non-root**, `operate` may also carry read-write config.
- **admin** — read-write configuration; `escalation-capable` when the daemon
  runs as root and its config can load code (rewriting it is a root code path).

Packages ship for monitoring/logging/edge/kiosk services (e.g. `nginx`,
`postgresql`, `redis`, `mosquitto`, `salt-minion`, `rsyslog`, `docker`, `pcscd`,
`chromium`, …). Each tier carries an **honest risk class** (`contained` vs
`escalation-capable`) — see §2.5.

### 2.5 Risk classes

Every permission and package tier is marked:

- **`contained`** — the access cannot, by itself, escalate a non-root principal
  to root (read-only, pure lifecycle, or read-write config of a non-root
  daemon).
- **`escalation-capable`** — the access provides a path to root (the `docker`
  group, `sudo ALL`, or read-write config of a root daemon that can load a
  shared object / run a program — `nginx` `load_module`, `salt-minion` master
  re-point, `rsyslog` `omprog`, …).

Census never pretends a permission is "restricted" when a path to root exists.
Inspect the class of any role with `census show <role>` (§3.2).

### 2.6 Standalone vs managed trust

- **Standalone** (this guide): the declaration is trusted by **filesystem
  integrity** — you pass `--trust-fs` at apply. No server, no signature. This is
  the open-core path.
- **Managed**: the declaration is **Ed25519-signed** with a monotonic
  anti-rollback version, verified before any mutation. Delivery of the signed
  declaration is handled by a control plane (e.g. Tessera). See §5.

---

## 3. First run

Work through `plan` → `compile`/`show` (inspect) → `apply` (mutate) → verify.

> Run the read-only commands first; nothing below `apply` changes the system.

### 3.1 Preview the plan

`plan` shows the create/update/delete actions without touching anything:

```sh
cd /etc/census          # so role_store="roles" resolves
census plan --declaration declaration.toml --additional-catalog-dir /opt/census/share/permissions
#   CREATE oper  (uid 9001, shell /bin/bash)
#   CREATE admin (uid 9002, shell /bin/bash)
```

### 3.2 Inspect a role's expansion

`compile` expands a role into its flat OS primitives with provenance (which
permission produced each `sudo` line / group / file grant):

```sh
census compile oper --declaration declaration.toml \
  --additional-catalog-dir /opt/census/share/permissions --os-target linux-astra-1.8 --lint
```

`show` renders the same as a localized tree of permissions → primitives, with
the risk class of each (use `--lang en|ru|zh`):

```sh
census show oper --lang en --additional-catalog-dir /opt/census/share/permissions
```

Use `--lint` on `compile` in CI: it exits non-zero on any catalog lint error.

### 3.3 Apply

`apply` runs **verify → plan → backup → apply**. In standalone mode pass
`--trust-fs`. On a device with no other login path configured, `apply` refuses
to proceed (anti-lockout) unless you acknowledge with
`--i-understand-no-rescue`:

```sh
cd /etc/census
sudo census apply \
  --declaration declaration.toml \
  --additional-catalog-dir /opt/census/share/permissions \
  --trust-fs \
  --i-understand-no-rescue
#   census: create: create oper (uid 9001)
#   census: create: create admin (uid 9002)
#   census: file-access: materialized N grant(s) for oper
#   census: all phases succeeded
#   applied: 2 mutation(s)
```

What `apply` does, in order:

1. **Verify** trust (filesystem in standalone; signature + anti-rollback in
   managed).
2. **Snapshot** `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` and
   the touched `sudoers.d/census-*`, plus the ACLs of any granted paths. A
   phase failure restores this **atomically** — Census never half-applies.
3. **Create/update/delete** accounts via shadow-utils. Each role-account is
   created with a **locked password** (`!` in shadow) and **no
   `authorized_keys`** — its only entry path is the authenticator's PAM service.
4. **Write `sudoers.d/census-<role>`**, validated with `visudo -c`. Role-account
   sudoers are `NOPASSWD` (the account has no password to prompt for).
5. **Set group memberships and file ACLs.**

Census tracks only what it created, in a root-only registry
(`/var/lib/census/managed.toml`), and never touches foreign accounts or groups.

> **Live-session reconcile.** A destructive change to a role-account that has a
> live session is deferred — Census reads Tessera's session registry from
> `--sessions-file` (default `/run/tessera/sessions.json`; an absent file means
> no live sessions) and never tears down an in-progress session.

### 3.4 Verify the result

```sh
getent passwd oper admin                 # accounts exist with the declared UIDs
sudo cat /etc/sudoers.d/census-oper      # the expanded sudo rules
id oper                                  # group memberships
sudo getfacl -p /etc/nginx               # file ACLs (if a file-access grant)
sudo -l -U oper                          # what oper is authorized to run
```

You can also confirm reverse-lookup — which permissions would grant access to a
path:

```sh
census catalog which-grants /etc/nginx --additional-catalog-dir /opt/census/share/permissions --os-target linux-astra-1.8
```

---

## 4. Operate

### 4.1 Scheduled reconcile

Census is meant to run **periodically**, re-asserting conformance and picking up
declaration changes. A systemd timer is the simplest scheduler:

```ini
# /etc/systemd/system/census-apply.service
[Unit]
Description=Census reconcile
ConditionPathExists=/etc/census/declaration.toml

[Service]
Type=oneshot
WorkingDirectory=/etc/census
ExecStart=/usr/local/sbin/census apply \
  --declaration declaration.toml \
  --additional-catalog-dir /opt/census/share/permissions \
  --trust-fs --i-understand-no-rescue
```

```ini
# /etc/systemd/system/census-apply.timer
[Unit]
Description=Run Census reconcile periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
sudo systemctl enable --now census-apply.timer
```

(A `cron` entry running the same `census apply` line works equally well.)

### 4.2 Check state and drift

```sh
census status   --declaration declaration.toml   # managed accounts, version, drift; always exits 0
census doctor   --declaration declaration.toml   # read-only integrity/readiness checks; non-zero on error-severity findings
```

`doctor` is the one to wire into monitoring — it exits non-zero when an invariant
is violated.

### 4.2.1 Audit the device's actual permissions

`doctor` checks Census's *own* invariants; the **exposure audit** checks the
device's *ambient* filesystem permissions — what a principal can already read and
write, regardless of what Census provisioned. It is read-only and also exits
non-zero on a high-severity finding, so it wires into monitoring the same way:

```sh
sudo census audit fs                       # device posture map (world-writable, setuid, readable secrets, …)
sudo census audit expose --principal oper  # what the `oper` account can actually reach, beyond its grants
```

Run `audit expose` whenever you create or tighten a restricted account, to confirm
the ambient filesystem isn't handing it more than you intended. See
[audit.md](audit.md) for the full guide.

### 4.3 Change a role

Edit the role-store (or the declaration), preview, then apply:

```sh
# edit roles/oper.toml — add or remove a permission
census plan  --declaration declaration.toml --additional-catalog-dir /opt/census/share/permissions   # preview the delta
sudo census apply --declaration declaration.toml --additional-catalog-dir /opt/census/share/permissions --trust-fs --i-understand-no-rescue
```

Census computes the minimal update (add/remove the changed sudo lines, groups,
ACLs) — it does not recreate the account.

### 4.4 Remove a role-account (teardown)

Remove the `[[role_account]]` from the declaration (or apply an empty
declaration to remove **all** managed accounts), then apply. Census deletes the
account, its `sudoers.d` fragment, its group memberships and its file ACLs —
fail-closed and atomic:

```sh
census plan --declaration declaration.toml ...        #   DELETE oper (destructive)
sudo census apply --declaration declaration.toml ... --trust-fs --i-understand-no-rescue
```

> Teardown only removes what Census provisioned (tracked in
> `/var/lib/census/managed.toml`). Foreign accounts and pre-existing ACLs are
> never touched.

---

## 5. Managed mode (brief)

In a fleet, you do not hand-edit a declaration on each device. Instead a control
plane delivers a **signed** declaration:

- the declaration carries an **Ed25519 signature** and a **monotonic version**;
- `census apply` (without `--trust-fs`) verifies the signature and refuses a
  rolled-back version **before any mutation**;
- delivery, inventory, aggregated drift and staged rollout are control-plane
  features (commercial — see the README's open-core table).

Everything in §§1–4 applies unchanged; you drop `--trust-fs` and the
declaration arrives signed rather than being edited in place.

---

## Further reading

- [`catalog-authoring.md`](../catalog-authoring.md) — authoring catalog
  permissions and per-OS layers (Russian).
- [`authoring-packages.md`](../authoring-packages.md) — authoring add-on
  packages and curated app tiers (Russian).
- The repo `README.md` — model, safety properties, CLI reference, and the
  open-core boundary.
- `examples/` — a complete runnable role-store + declaration.
