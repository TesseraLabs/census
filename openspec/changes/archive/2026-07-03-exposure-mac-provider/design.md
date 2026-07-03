## Context

`exposure-audit` (shipped) is DAC-only: `effective(record, principal)` in
`src/exposure/access.rs` computes discretionary access, and every report carries
`DAC_ONLY_NOTE` (verdict is an upper bound — MAC may restrict further). This change
adds the open-core seam to fold in mandatory access control without teaching the
open AGPL core any mandatory rule. Full design + commercial-split reasoning: private
`specs/2026-07-01-exposure-mac-design.md`. This document is the open-core how; the
commercial backend (`census_mac_parsec`) and `census-enterprise` overlay are a
separate private track.

The established idiom is the `FileAccessBackend` SPI (`src/fileaccess.rs`): open core
defines a trait + a default, a commercial backend is injected by the enterprise
overlay (submodule + patch). This change follows it for MAC.

## Goals / Non-Goals

**Goals:**

- One MAC-system-neutral SPI the open core composes with — works for PARSEC now and
  SELinux later with **no core change**.
- Refine findings: suppress when MAC blocks at every assumable context; else keep +
  annotate the context(s) where the access holds. Covers write (integrity) and read
  (confidentiality) alike, since the core is agnostic to which.
- Behaviourally neutral under the default (`NullMacProvider`); zero new deps.

**Non-Goals:**

- No mandatory-rule logic in the open core (no Biba/BLP/TE; only DAC ∧ MAC via SPI).
- No `libpdp`/`libselinux`, no real MAC backend in the open tree (only Null + Fake).
- No label mutation (read-only); no live-process/session evaluation.
- No severity re-derivation by context ordering (SELinux TE is unordered).

## Decisions

**SPI is MAC-neutral with opaque handles and a black-box permit.** `MacLabelId`
and `MacContextId` are interned ids the core never interprets; `permits(ctx, label,
access)` is the single method carrying the mandatory rule, entirely inside the
backend; `principal_contexts` returns an **unordered** set. The core assumes no
lattice and no order, which is exactly what lets SELinux type-enforcement (no order)
drop into the same trait as PARSEC's lattice. Rendering for output goes through
`render_context`/`render_label` so the core prints labels it cannot parse.

**Composite layers over `effective()`, does not edit it.** `effective()` stays pure
DAC. The MAC step runs in `expose.rs` (per principal) and `fs_audit.rs` (annotate-
only, no principal). For a finding with a provider active:
`principal_contexts(uid)` filtered by `permits(c, object_label(path), access)`;
empty ⇒ suppress; else annotate `mac.reachable_in`. `NullMacProvider`
(`object_label`→None, `permits`→true) makes this a no-op — identical output and note
to today.

**Enable/gating mirrors capability-gating.** The active provider is chosen at
build/config time (a linked provider vs the `NullMacProvider` default). `--mac` on
the open build fails closed with "no MAC backend in this build"; a non-MAC host
leaves the provider a no-op and the note DAC-only. This keeps `--mac` honest — it
never silently does nothing when asked for MAC.

**Finding schema carries `mac` nullable.** `mac: { system, reachable_in } | null`
(`null` = no provider / unlabeled). Provider active ⇒ note `DAC + <system>`. The
golden JSON schema is extended and regenerated (`UPDATE_CONTRACT=1`).

## Risks / Trade-offs

- [Shipping an SPI seam with no real open backend (dead until injected)] → matches
  the `FileAccessBackend` precedent; the seam is behaviourally neutral (Null default)
  and unit-covered via `FakeMacProvider`, so it is not untested dead code.
- [A future SELinux backend must not force a core change] → guarded by opaque
  handles + no-order assumption + black-box `permits`; verified now by exercising the
  composite through `FakeMacProvider` with non-lattice contexts.
- [Unlabeled object / principal with no MAC contexts] → documented defaults:
  `object_label` None ⇒ MAC does not restrict (finding kept — no MAC data to tighten
  with); a principal with an empty context set from the backend ⇒ no suppression
  possible, findings kept (the backend, not the core, decides the base context).

## Migration Plan

Additive and behaviour-neutral. Ships the SPI, `NullMacProvider` default, composite,
`mac` field + schema, and `FakeMacProvider`. Open build output is unchanged until a
commercial backend is injected by the overlay (separate private track). Rollback is
trivial — the composite collapses to a no-op under the default.

## Open Questions

- Enable UX: auto-detect vs explicit `--mac` vs both (lean: auto + `--mac` override)
  — decided at implementation, but the open build's `--mac`-fails-closed contract is
  fixed here.
- `fs`-mode posture: annotate every object's label or only labeled objects in
  sensitive classes (avoid noise on a fully-labeled host).
- Whether a later ordering-hint on `MacProvider` (for severity-by-context) earns its
  surface, given SELinux TE has no natural order — deferred.
