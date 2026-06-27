# Census TOML format reference

A complete field-by-field reference for every TOML file Census reads. It
complements [`getting-started.md`](getting-started.md) (which shows the common
case) with the full surface: every field, its type, whether it is required, its
default, and its meaning.

Census reads these file kinds:

| File | Who writes it | Strictness | This doc |
|---|---|---|---|
| **Declaration** (`declaration.toml`) | operator / control plane | strict (unknown keys rejected) | §1 |
| **Role slice** (role-store `<role>.toml`) | operator / Tessera | tolerant top-level; strict `[[payload.files]]` | §2 |
| **Catalog permission** (`share/permissions/**/*.toml`) | catalog author | strict | §3 (summary + links) |
| **Framework** (`frameworks/<fw>/*.toml`) | compliance author | strict | §4 (summary + links) |
| **Managed registry** (`/var/lib/census/managed.toml`) | **Census only** | — | §5 (do not edit) |

The authoritative, machine-readable schemas live in `contract/*.schema.json`
(generated from the parsers, golden-locked). This document is the prose mirror;
on any disagreement the schema wins.

> **Conventions.** "Required" means the parse fails without it. "strict" means
> `deny_unknown_fields` — a typo'd key is an error (fail-closed), not silently
> ignored. "tolerant" means unknown keys are skipped (a format another tool
> co-owns).

---

## 1. Declaration — `declaration.toml`

The declaration is the device's desired state: which role-accounts and groups
should exist. It is parsed **strictly** — an unknown key anywhere is an error.

### 1.1 Top level

| Key | Type | Required | Meaning |
|---|---|---|---|
| `schema` | integer | yes | **Parser format version** of the declaration. `1` today. Census checks it **first**, before any other validation, and refuses a declaration whose `schema` exceeds what this build supports (fail-closed, no mutation) — see §1.1.1. |
| `version` | integer | yes | **Monotonic anti-rollback counter for the declaration's content** (replay protection for the signature) — *not* a format version. Enforced only in managed/signed mode; **not checked** under `--trust-fs`. Bump it on every newly signed declaration. See §1.1.1. |
| `role_store` | path | yes | Path to the role-store directory, resolved **relative to the working directory** Census runs from (or absolute). |
| `[defaults]` | table | yes | Default account attributes (§1.2). |
| `[[role_account]]` | array of tables | no | The role-accounts to provision (§1.3). |
| `[[group]]` | array of tables | no | Standalone groups to provision (§1.4). |
| `[[role_group]]` | array of tables | no | Bind a role's grants to a declared group (§1.5). |
| `signature` | string (hex) | only in managed mode | Detached Ed25519 signature over the declaration bytes. Present when the declaration is centrally signed; **absent** under `--trust-fs` (standalone). You do not write this by hand — the control plane adds it. |

#### 1.1.1 `schema` vs `version` — two different numbers

These two integer fields look alike and are easy to confuse, but they answer
different questions:

| Field | Answers | Enforced |
|---|---|---|
| `schema` | *"Which TOML format is this?"* — the parser format version. | Always. Checked **first**, before any other field; a `schema` newer than this build supports → refuse, fail-closed, no mutation. |
| `version` | *"How recent is this content?"* — a monotonic anti-rollback counter that protects the signature against replay. | Only in managed (signed) mode; **not** checked under `--trust-fs`. |

- **`schema`** is about the *shape* of the file. Bump it only when the format
  itself changes incompatibly; a build that does not understand a newer `schema`
  stops cleanly with a clear message instead of failing deep inside on an
  unknown key.
- **`version`** is about the *contents*. Bump it on **every newly signed
  declaration** so an attacker cannot replay an older signed copy to roll a
  device back to stale access. In standalone (`--trust-fs`) mode there is no
  signature to replay, so `version` is recorded but not enforced.

They move independently: re-issuing a device's access bumps `version` while
`schema` stays put; migrating the file format bumps `schema` while `version` is
unaffected. Collapsing them into one field would force either a false rollback
refusal on a format upgrade, or a hole in replay protection on a schema
refactor.

### 1.2 `[defaults]`

Applied to every role-account unless the account overrides them. Strict.

| Key | Type | Required | Meaning |
|---|---|---|---|
| `uid_range` | `[integer, integer]` | yes | Inclusive `[low, high]` UID window. Every account `uid` must fall inside it; an auto-assigned UID is drawn from it. |
| `shell` | string | yes | Default login shell (e.g. `/bin/bash`). |
| `home_base` | path | yes | Parent directory for role-account homes; an account's home defaults to `<home_base>/<role>`. |

```toml
[defaults]
uid_range = [9000, 9999]
shell     = "/bin/bash"
home_base = "/var/lib/census/home"
```

### 1.3 `[[role_account]]`

One entry per role-account. Strict. An account is one of **two mutually
exclusive kinds**, distinguished by its identity source:

- **Created** — carries an explicit `uid`. Census creates the Unix user (named
  after the role) at that fleet-stable UID. This is the normal case.
- **Adopted** — carries `user` (the name of an **existing** OS account) and
  `adopt = true`, and **must not** carry `uid`. Census binds the role's grants
  to that pre-existing account and never runs `useradd`/`userdel` — it does not
  assign a UID to a user it did not create.

`uid` and `user` are mutually exclusive; declaring both is rejected.

| Key | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `role` | string | yes | — | The role name; must match a slice in the role-store (§2). |
| `uid` | integer | **Created**: yes | — | Explicit, fleet-stable UID. Must be inside `uid_range`. Absent ⇒ the account must be Adopted. |
| `user` | string | **Adopted**: yes | — | Name of the existing OS user to adopt. Mutually exclusive with `uid`; requires `adopt = true`. |
| `adopt` | bool | no | `false` | `true` marks the account Adopted (requires `user`, forbids `uid`). `false` is a Created account keyed by `uid`. |
| `shell` | string | no | `[defaults].shell` | Per-account login-shell override. |
| `home` | path | no | `<home_base>/<role>` | Per-account home override. |

```toml
# Created account (the normal case)
[[role_account]]
role = "oper"
uid  = 9001

# Adopted account — bind the role's grants to an existing `svc` user
[[role_account]]
role  = "legacy-svc"
user  = "svc"
adopt = true
```

> A **Created** role-account is provisioned with a **locked password** and **no
> `authorized_keys`** — its only entry path is the authenticator's PAM service.
> These are not declaration fields; Census enforces them on creation. An
> **Adopted** account's credential state is left as-is (Census never runs
> `useradd`/`userdel` on it).

### 1.4 `[[group]]`

Standalone groups Census should own. Strict.

| Key | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `name` | string | yes | — | Group name. |
| `gid` | integer | no | auto | Pinned GID. If the GID already belongs to a *different* group, `apply` refuses — it never renumbers. |
| `adopt` | bool | no | `false` | Adopt a pre-existing group of this name instead of creating it. |
| `members` | array of string | no | `[]` | Member account names. |

```toml
[[group]]
name    = "kiosk-ops"
members = ["oper"]
```

### 1.5 `[[role_group]]`

A grant binding: attach a **role's resolved permissions** to a group, so every
member of the group inherits them (many-to-one — several roles may bind to the
same group). Strict.

| Key | Type | Required | Meaning |
|---|---|---|---|
| `role` | string | yes | The role whose grants are bound. |
| `group` | string | yes | Target group — **must** name a `[[group]]` declared in the same declaration (§1.4). |

```toml
[[group]]
name = "kiosk-ops"

[[role_group]]
role  = "oper"
group = "kiosk-ops"
```

---

## 2. Role slice — `<role-store>/<role>.toml`

One file per role. The **top level is tolerant** — Census reads only the keys it
consumes and ignores the rest (the role schema is co-owned by Tessera, which
adds adapter fields Census does not need). Everything Census acts on lives under
`[payload]`.

### 2.1 Top level (role-wide)

| Key | Type | Used by Census | Meaning |
|---|---|---|---|
| `role` | string | informational | Role name (should match the declaration's `role`). |
| `version` | integer | informational | Slice schema version. |
| `os` | string | informational | Target OS family (e.g. `linux`). |
| `name` | string | informational | Human-readable role title. |
| `level` | integer | informational | Role tier/level (Tessera-owned). |
| `[payload]` | table | **yes** | The access Census materializes (§2.2). |

Unknown top-level keys are ignored (tolerant).

### 2.2 `[payload]`

All fields optional; tolerant (unknown keys ignored). The raw primitives
(`groups`, `sudo`, `sudo_role`, `limits`, `files`) are an **escape hatch** that
is **unioned** with the expansion of `permissions` — you can use either, or both.

| Key | Type | Meaning |
|---|---|---|
| `permissions` | array | Permission references expanded against the catalog (§2.3). The normal way to grant access. |
| `groups` | array of string | Raw supplementary groups added directly (escape hatch — bypasses the catalog). |
| `sudo` | array of string | Raw inline `sudo` command rules carried directly (escape hatch — bypasses the catalog). Literal absolute command paths only; see §2.7. |
| `sudo_role` | string | A raw sudo role name carried directly (escape hatch). |
| `[payload.limits]` | table | Resource limits (§2.4). |
| `[[payload.files]]` | array of tables | Raw inline file-access grants (§2.5). |

```toml
role    = "oper"
version = 1
os      = "linux"
name    = "Device operator"
level   = 3

[payload]
permissions = ["service-restart", "log-read", { id = "service-control", units = "nginx" }, "nginx.operate"]
groups      = ["video"]                 # escape hatch, unioned in
sudo        = ["/usr/sbin/reboot"]      # escape hatch, raw sudo command (§2.7)
sudo_role   = "operations"              # escape hatch

[payload.limits]
nofile = 8192

[[payload.files]]
path      = "/var/lib/app/state"
access    = "rw"
recursive = true
```

### 2.3 `permissions` — the three forms

Each element of `permissions` is one of:

1. **Bare id** — a string naming a leaf, bundle, or package:
   ```toml
   permissions = ["log-read", "network-config", "nginx.operate"]
   ```
2. **Parametrized** — a table with a required `id` plus parameters that fill the
   permission's `{placeholder}` templates (e.g. the unit(s) a `service-*`
   permission applies to). A list parameter expands to one rendered rule per
   element:
   ```toml
   permissions = [
     { id = "service-control", units = "nginx" },
     { id = "service-observe", units = ["nginx", "mosquitto"] },
   ]
   ```
   The table form is **tolerant**: keys other than `id` are captured as
   parameters, so a parameter name the catalog record does not use is simply
   inert (not an error).

A **leaf** is a single capability; a **bundle** aggregates others (resolved
transitively, its risk class = the max of its members); a **package** is a
curated `<app>.{observe|operate|admin}` tier. See §3 and the catalog itself for
the full permission list.

### 2.4 `[payload.limits]`

| Key | Type | Meaning |
|---|---|---|
| `nofile` | integer | `RLIMIT_NOFILE` (max open files). |
| `nproc` | integer | `RLIMIT_NPROC` (max processes). |

### 2.5 `[[payload.files]]`

Inline file-access grants, the same shape as a catalog `[[file]]` grant. Unlike
the rest of the payload this block is **strict** (`deny_unknown_fields`): a role
file grant is materialized as root via `setfacl`, so a typo'd key fails closed.

| Key | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `path` | string | yes | — | **Absolute** path to a directory, file, or glob. Must be **literal** — a placeholder/template is rejected in a role file grant (no `{…}`). |
| `access` | string | yes | — | The access bits — see §2.6. |
| `recursive` | bool | no | `false` | For a directory: apply recursively **and** set a default-ACL so new files inherit the access. |

> **Directory vs single file.** A directory grant (`recursive = true`) is
> rewrite-proof and enforced by the always-available ACL backend. A grant on a
> **single file** requires a per-file backend; on a system without one, `apply`
> refuses it (atomically — nothing applies). Prefer directory grants.

### 2.6 `access` values

`access` is a set of bits — read (`r`), write (`w`), execute (`x`), traverse
(`X`, directory search / conditional execute). Two legacy aliases cover the
common cases, and there are canonical compact strings for the rest:

| Value | Bits | Use |
|---|---|---|
| `"ro"` | `{read, traverse}` (`r-X`) | read-only access to a tree |
| `"rw"` | `{read, write, traverse}` (`rwX`) | read-write access to a tree |
| canonical compact strings | any combination of `r` `w` `x` `X` | precise control |

For most grants `"ro"` and `"rw"` are what you want.

### 2.7 `payload.sudo` — raw sudo commands (escape hatch)

`sudo` under `[payload]` is the command-level twin of `[[payload.files]]`: a raw
list of `sudo` command rules carried **directly** into the role, **unioned** with
whatever the role's `permissions` expand to — the same way a catalog permission's
`sudo` field is. Use it for a command that has no catalog permission yet.

```toml
[payload]
sudo = ["/usr/sbin/reboot", "/usr/bin/systemctl"]
```

Constraints — validated **before** anything is written to `sudoers`, fail-closed
on a violation:

- **Literal absolute command paths only** — each entry must start with `/`.
- **No arguments and no `{placeholder}` templates.** Parametrization with
  confinement (a `{unit}` guarded by `[params]` constraints) stays the
  prerogative of a catalog id — there is nothing to bound an inline parameter, so
  it is rejected.
- **Printable ASCII, no shell metacharacters** (`; | & $ < >` …) — refused so a
  value cannot smuggle a second command into the sudoers line.

Each entry materializes into `sudoers.d/census-<role>` **as root**, so it is a
genuine privilege grant. Because it bypasses the curated catalog it carries **no
risk label** — `census show` and `census compile --lint` therefore flag inline
`payload.sudo` (like `[[payload.files]]`) as **raw / unlabeled
escalation-capable**, so a reviewer always sees it. Prefer a catalog permission
when one exists; reach for `payload.sudo` only as a deliberate escape hatch.

---

## 3. Catalog permission files (summary)

Catalog files under `share/permissions/<layer>/*.toml` define the permissions a
role references. Authoring them is covered in depth in
[`catalog-authoring.md`](../catalog-authoring.md) and
[`authoring-packages.md`](../authoring-packages.md) (both in Russian); the shape in brief:

| Key | Type | Meaning |
|---|---|---|
| `id` | string | Permission id (dotted for packages, e.g. `nginx.operate`). |
| `risk` | string | `contained` or `escalation-capable` (a bundle's = max of members). |
| `category` | string | Domain grouping (e.g. `network`, `app`, `os-config`). |
| `sudo` | array of string | Absolute `sudo` command rules (may carry `{placeholder}` templates). |
| `groups` | array of string | Supplementary groups granted. |
| `[limits]` | table | `nofile` / `nproc`. |
| `[[file]]` | array of tables | File-access grants (same shape as §2.5; catalog grants **may** use `{placeholder}` templates). |
| `includes` | array | Other permission ids this one aggregates (bundle); a table element `{ id, <bindings> }` binds a member's parameters. |
| `include_categories` | array of string | Aggregate every permission in the named categories. |
| `[params.<name>]` | table | A parameter guard rail (`kind = token | path | enum | segment`, with `allow_prefix` / values) that constrains a `{placeholder}`. |

Per-OS layering: a permission resolves along `linux → linux-<distro> →
linux-<distro>-<version>`; a layer can `replace` or `append` fields of the base.
Human text (`title` / `summary` / `risk_note`) lives in the separate
`l10n/<locale>/` tree, keyed by `[<id>]`, not in the permission file.

Authoritative schema: `contract/catalog-permission.schema.json`.

---

## 4. Framework files (summary)

The advisory compliance cross-reference. Frameworks live under `frameworks/<fw>/`:

- `framework.toml` — manifest (`dimension = flat | os-layered`, version, provides).
- `mappings/*.toml` — keyed by permission id; each link carries a **polarity**:
  `satisfies` (addresses the control — the only polarity coverage counts),
  `risk` (undermines it), or `related` (neutral).
- `controls.toml` (optional) — the control list; an `owned` flag marks the
  controls Census actually covers (so `framework coverage` can report gaps).

It is **read-only and advisory** — it never participates in `compile`/grant/
`apply`, so a tampered mapping can only mislabel coverage, never escalate
privilege. Authoritative schema: `contract/framework.schema.json`. See the
README's "Compliance frameworks" section.

---

## 5. Managed registry — `/var/lib/census/managed.toml`

The root-only record of what Census has provisioned (accounts, groups, the
grants attached to each, the applied declaration version). **Census owns this
file — do not hand-edit it.** It is how Census knows what is *its* to reconcile
or tear down, so editing it can orphan real OS objects or make Census touch
something it did not create. Inspect it read-only with `census status`.
Authoritative schema: `contract/managed-registry.schema.json`.

---

## 6. Previewing changes — the diff mode

`census plan` prints the high-level create/update/delete actions. Add `--diff`
to see the **concrete artifacts** each change would write, as a unified diff —
current managed state vs the resolved target:

```sh
census plan --declaration declaration.toml --additional-catalog-dir /opt/census/share/permissions --diff
```

`plan --diff` shows, per changed account:

- the **`sudoers` fragment** that would be written (including the run-as spec)
  and its **target file path** (`/etc/sudoers.d/census-<role>`);
- the **file-access ACL grant delta** — which path grants are added or removed.

It is **read-only**: no filesystem mutation, no root required. Use it to review
exactly what an `apply` would change before running it — especially after
editing a role's permissions, to confirm the resulting sudo lines and ACLs are
what you intend.

---

## Further reading

- [`getting-started.md`](getting-started.md) — install, configure, first apply,
  operate.
- [`catalog-authoring.md`](../catalog-authoring.md) — authoring catalog permissions
  and per-OS layers (Russian).
- [`authoring-packages.md`](../authoring-packages.md) — authoring add-on packages
  and curated app tiers (Russian).
- `contract/*.schema.json` — the authoritative machine-readable schemas.
