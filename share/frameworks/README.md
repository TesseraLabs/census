# Compliance framework cross-reference data

Each `<fw>/` subtree maps Census catalog permissions to the access-governance controls of one
compliance framework, for the read-only `framework-crossref` layer. Installed to
`/usr/share/census/frameworks/`; site overlays go in `/etc/census/frameworks.d/`.

Layout per framework:

```
<fw>/framework.toml          # manifest: id, version, title, dimension (flat|os-layered), provides
<fw>/mappings/*.toml         # permission-id → controls = [control-id, ...]  (flat)
<fw>/mappings/<os>/*.toml    # same, resolved over the catalog OS-layer chain (os-layered)
<fw>/controls.toml           # control-id → { title, owned, domain? }  (optional, for coverage)
```

`owned = true` marks a control inside Census's domain (role-accounts, group membership, sudo
grants). `owned = false` marks one Census deliberately does **not** cover (auth = Tessera,
host-hardening, directory centralization) — excluded from the coverage gap.

## Licensing of control references

Control **identifiers** (e.g. `7.2.1`, `6.8`) are facts and are used directly. Control
**titles** are written in our own words — the normative requirement text of PCI DSS (© PCI
Security Standards Council) and the CIS Controls (© Center for Internet Security) is
copyrighted and is **not** reproduced here. Contributors adding or translating titles must
paraphrase, never copy the source wording.
