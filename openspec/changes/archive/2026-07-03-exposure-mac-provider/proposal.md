# Change: exposure-mac-provider

## Why

`exposure-audit` evaluates discretionary access only (mode/owner/POSIX ACL) and
labels every verdict a DAC upper bound: a DAC-writable file that the host's
mandatory access control (Astra PARSEC, later SELinux) actually forbids still shows
as a finding. This change adds the **open-core seam** to refine the verdict against
mandatory access control — a **MAC-system-neutral** SPI — while keeping all
mandatory-rule knowledge (Biba/BLP/type-enforcement, `libpdp`/`libselinux`) out of
the open AGPL core. Full design and the commercial-split reasoning: private
`specs/2026-07-01-exposure-mac-design.md` (tessera-ws).

**Scope of THIS change: open core only.** The commercial backend
(`census_mac_parsec`) and the `census-enterprise` overlay are a separate private
track. After this change the open build is behaviourally identical to today (a
`NullMacProvider` default) — MAC refinement activates only when a commercial backend
is injected.

## What Changes

- **SPI `MacProvider`** (MAC-system-neutral): `system()` (`Parsec`|`Selinux`),
  `object_label(path) -> Option<MacLabelId>`, `principal_contexts(uid) ->
  Vec<MacContextId>`, `permits(ctx, label, access) -> bool`, `render_context` /
  `render_label`. `MacLabelId`/`MacContextId` are **opaque** interned handles — the
  core never parses a label, assumes **no lattice and no ordering** (so SELinux
  type-enforcement fits like PARSEC's lattice), and treats `permits` as a black box.
  All mandatory semantics live behind the backend's `permits`.
- **`NullMacProvider`** — the open-build default: `object_label` → `None`, `permits`
  → `true`. Behaviour is unchanged from today; the verdict note stays `DAC_ONLY_NOTE`.
- **DAC ∧ MAC composite** in `expose.rs`/`fs_audit.rs`, layered **on top of** the
  existing `effective()` (which stays pure DAC). Per DAC-finding, with a provider
  active: `ctxs = principal_contexts(uid).filter(|c| permits(c, object_label(path),
  access))`; empty ⇒ **suppress** (MAC blocks at every assumable context — provably
  unreachable); else keep and annotate `mac.reachable_in = [render_context…]`.
- **Finding schema**: new field `mac: { system, reachable_in: [String] } | null`
  (`null` = no provider / unlabeled object). With a provider active the report note
  becomes `DAC + <system>`. In `fs` (principal-independent) mode the provider only
  **annotates** each object with its label — no suppression.
- **CLI enable**: enterprise build auto-detects a linked provider (and host MAC
  availability) or takes `--mac`; the open build rejects `--mac` with an honest "no
  MAC backend in this build"; a non-MAC host leaves the provider a no-op.
- **`FakeMacProvider`** for tests — the composite (suppress/annotate) is fully unit-
  tested with no `libpdp`/`libselinux`. Golden JSON schema extended with `mac`.

## Capabilities

### New Capabilities

<!-- none — this extends the existing exposure-audit capability -->

### Modified Capabilities

- `exposure-audit`: adds the MAC-provider SPI seam, the DAC ∧ MAC composite
  (suppress/annotate by assumable context), the `mac` finding field and the
  `DAC + <system>` note, and the `--mac` enable/gating — all behaviourally neutral
  under the `NullMacProvider` default.

## Impact

- Affected specs: `exposure-audit` (modified — new SPI/composite requirements,
  extended finding schema).
- Affected code (Rust, open `census`): new `src/exposure/mac.rs` (`MacProvider`
  trait, `MacSystem`, opaque id types, `NullMacProvider`, `FakeMacProvider`);
  `expose.rs`/`fs_audit.rs` (composite over `effective()`, suppression + annotation);
  `taxonomy.rs`/`expose.rs` (`Finding`/`ExposureReport` gain `mac`, `JsonSchema`);
  `cli/audit.rs`/`cli_def.rs` (`--mac` flag + gating, note selection);
  `contract/exposure-report.schema.json` (golden schema + regen).
- **Zero new dependencies in the open build**; no `libpdp`/`libselinux`; the only
  providers in-tree are `NullMacProvider` (default) and `FakeMacProvider` (tests).
- Reuses the established `FileAccessBackend`-SPI + overlay-injection pattern and the
  exposure-audit conventions (Fake injection, golden contract).
- The commercial `census_mac_parsec` backend + `census-enterprise` overlay are a
  **separate private track** and are out of scope here.
