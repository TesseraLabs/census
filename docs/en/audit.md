# Exposure audit — what a principal can already reach

`census audit` is a **read-only** review of the filesystem's *actual* permission
state. It answers the question provisioning cannot: given the access objects on a
device — not the ones Census declared, but everything already on disk — **what can
a principal really read and write, beyond what least-privilege intended?**

This is the reverse of `apply`. `apply` grants access forward (role-accounts,
groups, `sudoers.d`, file ACLs). `audit` looks at the device as it *is* and
surfaces ambient over-permission that quietly undermines a restricted account: a
world-writable `cron` spool, a world-readable key, a `sudoers.d` drop-in a service
account can edit. You make an account restricted, but a world-writable file lets it
escalate anyway — `audit` is how you find that.

`audit` **never mutates anything**. Like `doctor`, it only reads. It does not, and
cannot, `chmod` or `setfacl` a file — it reports the problem and tells you the fix.

Two modes, one engine:

| Command | Question it answers |
|---|---|
| `census audit fs` | *What dangerous permission classes exist on this device?* (principal-independent posture map) |
| `census audit expose --principal <name\|uid>` | *What can this specific account actually reach — beyond what it was granted?* |

> **Run as root for a complete picture.** The audit reads file modes, owners and
> POSIX ACLs; reading secret-class files (e.g. `/etc/shadow`) to judge their
> exposure needs root. Run it under `sudo` for full coverage — it is read-only, so
> running it as root is safe.

---

## 1. `audit fs` — the device posture map

`audit fs` walks the in-scope trees and enumerates the dangerous permission
classes, independent of any principal:

- **world-writable** objects in sensitive trees (cron, `sudoers.d`, systemd units,
  config, `PATH` binaries);
- the **setuid/setgid inventory** — every setuid/setgid binary, with the ones that
  are *also* world-writable flagged as critical;
- **world-readable secrets** — key/credential/shadow-class files an `other` can read;
- **broad-group-writable** objects — writable by a wide group (`adm`, `wheel`,
  `sudo`, `staff`, `users`).

```sh
sudo census audit fs --root /etc --root /var/spool
#   audit fs: 1 finding(s)
#   high   leak  secret  /etc/ssl/certs/ssl-cert-snakeoil.pem (access r--, via other_bits, fix ambient)
#       — remove world read of a secret manually: `chmod 640 /etc/ssl/certs/ssl-cert-snakeoil.pem`
```

Each finding carries: the **path**, the effective **access** (`rwx`), **how** the
access is obtained (`via` — `other_bits`, `group:<g>`, `acl_user:<u>`, …), the
object **class**, the **risk** (`escalation` / `leak` / `tamper`), a derived
**severity**, the **remediation class** (§4), and a concrete **fix hint**.

---

## 2. `audit expose` — what one account reaches

`audit expose` slices the same scan through a single principal. It resolves the
account's identity — UID plus primary and supplementary groups — and evaluates the
POSIX access check against every in-scope object **for that principal**, then
reports only what the account can actually reach.

```sh
sudo census audit expose --principal daemon --root /etc --root /var/spool
#   audit expose: principal daemon (unmanaged)
#   note: verdict is DAC-only (mode, owner, POSIX ACL) and is an upper bound:
#         MAC layers (SELinux, AppArmor, PARSEC) may restrict actual access further
#   1 finding(s)
#   high   leak  secret  /etc/ssl/certs/ssl-cert-snakeoil.pem (access r--, via other_bits, fix ambient) — …
```

A principal is named by **login name or numeric UID**. Identity is resolved from
the **local** `/etc/passwd` and `/etc/group` only — NSS/LDAP-supplied group
membership is *not* consulted (an advisory limitation: group-based reach may be
under-reported on a directory-backed host). A bare UID with no passwd entry still
audits, by raw reachability with no group memberships.

### 2.1 Reachability is rigorous — no false positives from a closed parent

A file is only "reachable" by a principal if **every ancestor directory grants it
search (`x`)**. A file with mode `0777` sitting behind a `0700` directory owned by
root is **unreachable** by a non-owner and is *not* reported — exactly the
false-positive a naive `find -perm` would raise. The access check itself follows
the POSIX ACL algorithm (owner → named-user → group-class with mask → other),
honouring the ACL mask and the "matched-but-denied does not fall through to other"
rule.

### 2.2 The verdict is DAC-only — an honest upper bound

`audit` evaluates **discretionary** access control only: mode bits, ownership and
POSIX ACLs. It does **not** model mandatory access control (SELinux, AppArmor, or
Astra's PARSEC mandatory integrity). A MAC layer can restrict access further, so the
verdict is an **upper bound** — "reachable under DAC". Every `expose` report states
this.

### 2.3 The killer filter — only the *excess* for a managed account

When the principal is a **Census-managed role-account**, `expose` subtracts its
**intended baseline** — its home directory plus the paths the catalog granted it —
and reports only the access it has *beyond* that intent. You declared the account
should reach `/etc/ssh`; if it can *also* write `/var/spool/cron`, only the cron
finding remains. For an account Census does not manage, there is no baseline to
subtract, so the raw reachability is shown.

This is what makes `expose` Census-specific rather than a generic permission
scanner: it knows what the account was *supposed* to have, and shows you the
difference.

---

## 3. Risk, severity, and object classes

Each in-scope object is classified by a glob table (and the setuid/setgid bits):

| Class | Examples |
|---|---|
| `cron` | `/var/spool/cron/**`, `/etc/cron*/**`, `/etc/crontab` |
| `systemd-unit` | `/etc/systemd/**`, `/lib/systemd/system/**` |
| `sudoers` | `/etc/sudoers`, `/etc/sudoers.d/**` |
| `path-binary` | `/usr/bin/**`, `/bin/**`, `/usr/local/bin/**`, `/sbin/**` |
| `secret` | `/etc/shadow*`, `**/*.key`, `**/*.pem`, `**/id_rsa*`, `**/.env*`, `**/*credentials*` |
| `config` | security-relevant `/etc` configuration |
| `setuid-binary` | any setuid/setgid executable |
| `generic` | everything else |

Risk and severity are derived deterministically:

- **write** to cron / sudoers / systemd-unit / `PATH` binary / setuid binary →
  `escalation`, **High**;
- **read** of a secret → `leak`, **High**;
- **write** to a config file → `tamper`, **Medium**;
- a world-writable generic object → **Low**;
- reading a non-secret file is *not* a finding.

`audit` exits **non-zero** when any finding is at or above **High** severity (the
same convention as `doctor`), so it can gate a CI or monitoring check; a clean scan
(or only sub-threshold findings) exits `0`.

---

## 4. Remediation class — Census is honest about what it can fix

Every finding is tagged with a **remediation class** that tells you *who* fixes it:

- **`ambient`** — the access comes from an object Census does **not** own: a
  world-writable foreign directory, a world-readable secret, a foreign group. Census
  **cannot** remove this — a declaration provisions Census's *own* objects, it does
  not touch a file's base mode or a foreign ACL. The hint is a **manual** command
  (`chmod o-w …`, `chmod 640 …`, `setfacl -x …`); Census never claims it will fix it
  for you.
- **`in-model`** — the access comes from an object Census **owns**: membership in a
  Census-managed group, or one of the account's own file-access grants that is wider
  than it needs to be. Here the fix *is* a declaration change, and the hint says so
  ("narrow the declaration").

This split resolves the obvious objection — *"a declaration can't revoke
world-write on every file."* Correct: it can't, and `audit` does not pretend
otherwise. For ambient over-permission its job is to **report the problem
precisely** — which principal, which path, why the access exists, and the manual
command that closes it.

> **The report is itself a sensitive artifact.** It is a map of the device's
> weaknesses. The output carries only metadata — path, mode, class — and **never the
> contents** of a secret file, but treat the report itself as confidential: do not
> paste it into a public channel or an unrestricted log.

---

## 5. Scope, output, and flags

```
census audit fs      [--root <PATH>]… [--full] [--format text|json]
                     [--config <PATH>] [--managed <PATH>]
census audit expose  --principal <name|uid>
                     [--root <PATH>]… [--full] [--format text|json]
                     [--config <PATH>] [--managed <PATH>]
```

| Flag | Meaning |
|---|---|
| `--root <PATH>` | Scan root (repeatable). Conflicts with `--full`. Must be **absolute**. |
| `--full` | Walk the whole filesystem from `/` (pseudo-filesystems still skipped). |
| `--principal <name\|uid>` | (`expose` only) the account to evaluate. |
| `--format text\|json` | Output format. `text` (default) is human-readable; `json` is a stable, schema-locked contract on stdout. |
| `--config <PATH>` | Audit config (default `/etc/census/exposure.toml`); absent file ⇒ built-in defaults. |
| `--managed <PATH>` | Managed registry (default `/var/lib/census/managed.toml`), for the managed-account baseline. |

**Default scope** is a curated set of security-relevant trees (`/etc`, `/var`,
`/opt`, `/usr/local`, `/srv`, `/home`, `/root`). Pseudo-filesystems (`/proc`,
`/sys`, `/dev`, `/run`) and **network mounts** are always skipped — including under
`--full` — and any skipped mount is reported in a notice so coverage is never
silently trimmed. A scan **does not cross onto another local volume implicitly**:
local sub-mounts (a separate `/var/log` or `/home` partition) *are* descended;
network filesystems (NFS, CIFS, …) are not.

When run on an interactive terminal with **no** `--root`/`--full`, `audit` offers a
scope prompt (security-relevant / full / custom roots). A non-interactive run (CI,
a pipe) never blocks on the prompt — it uses the default scope silently. Diagnostics
and the prompt go to **stderr**, so `--format json` keeps stdout clean and parsable.

The JSON output is locked by a golden schema (`contract/exposure-report.schema.json`).

---

## 6. Configuration — `exposure.toml`

The scan scope and classifiers are configurable. The file is **strictly parsed**
(`deny_unknown_fields`); an absent file or absent key falls back to the built-in
default, but a present, malformed file is an honest error (never a silent default).

```toml
# /etc/census/exposure.toml — all keys optional; absent ⇒ built-in default

# Trees the default scan covers. Must be absolute paths; an empty list is rejected
# (a security tool that scans nothing and reports "all clear" is a trap).
scan_roots   = ["/etc", "/var", "/opt", "/usr/local", "/srv", "/home", "/root"]

# Globs that mark an object as secret-class. Each pattern holds at most one `**`
# (the matcher backtracks across `**`; multiple would be exponential on a --full scan).
secret_globs = ["/etc/shadow*", "**/*.key", "**/*.pem", "**/id_rsa*", "**/.env*", "**/*credentials*"]

# Group names treated as "broad" for the broad-group-writable axis. Matched by the
# group's real name resolved from /etc/group (so a renumbered gid is still caught).
broad_groups = ["adm", "wheel", "sudo", "staff", "users"]
```

> **Tuning note.** The default `**/*.pem` glob also matches *public* certificates
> (e.g. `/etc/ssl/certs`), which are world-readable by design — these surface as
> low-signal `secret` findings. Narrow `secret_globs`, or exclude the public-cert
> tree, if that noise is unwanted on your hosts.

See the [TOML reference](toml-reference.md) for the field table.

---

## 7. Typical use

```sh
# Posture sweep of the whole device, JSON for a monitoring pipeline:
sudo census audit fs --full --format json > posture.json

# What does this restricted service account actually reach?
sudo census audit expose --principal app-svc

# Focused check after provisioning a new restricted role:
sudo census audit expose --principal kiosk-oper --root /etc --root /var
```

`audit` is read-only and needs no declaration — point it at a device and it
reports. Wire `audit fs` into the same monitoring path as `doctor` (both exit
non-zero on a real problem), and run `audit expose` whenever you create or tighten
a restricted account, to confirm the ambient filesystem isn't handing it more than
you intended.

---

## Further reading

- [`getting-started.md`](getting-started.md) — install, configure, first apply, operate.
- [`toml-reference.md`](toml-reference.md) — every TOML file Census reads, including `exposure.toml`.
- The repo `README.md` — product model, safety properties, and the full CLI reference.
