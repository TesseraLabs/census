# Census documentation

**Declarative provisioner of Unix access objects.** Census brings a device's
access layer — role-accounts, groups, `sudoers.d`, limits, file ACLs — into
conformance with a declaration. Idempotent, fail-safe, off the authentication
path.

Languages: **English** · [Русский](../ru/index.md) · [中文](../zh/index.md)

## By role

### Operator — deploying Census on a device

1. [getting-started.md](getting-started.md) — install, configure, first `apply`,
   and operate (scheduled reconcile, drift checks, teardown). Start here.
2. [toml-reference.md](toml-reference.md) — the complete TOML format: every field
   of the declaration and role slice, plus the `plan --diff` preview mode.

### Catalog / package author — extending the permission catalog

1. [`catalog-authoring.md`](../catalog-authoring.md) — authoring catalog
   permissions and per-OS layers *(Russian)*.
2. [`authoring-packages.md`](../authoring-packages.md) — authoring add-on
   packages and curated `<app>.{observe|operate|admin}` tiers *(Russian)*.

## Reference

- `../../README.md` — product model, safety properties, full CLI reference, and
  the open-core boundary.
- `../../contract/*.schema.json` — the authoritative, machine-readable schemas
  (declaration, role-store, catalog permission, framework, managed registry).
- `../../examples/` — a complete runnable role-store + declaration.
