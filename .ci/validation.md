# Census SourceCraft CI bootstrap

Preserve all five existing quality gates. Required normal PR signatures use
verifier/key files from the protected base, full history and authoritative
SourceCraft PR revisions. The one-time manual bootstrap proof instead pins the
reviewed verifier and original public signer file by SHA-256 before execution;
it exists because the initial imported base has no .ci files. It remains a
manual workflow, cannot replace normal mandatory PR checks, and receives no
private signing keys, deployment credentials or GitHub token.

GitHub remains unchanged until fresh SourceCraft CI and publication checks pass.
The bootstrap candidate must pass both frozen-bootstrap-signatures and quality,
plus exact-revision independent review, before installing this config in main.

The frozen bootstrap candidate passed all five quality gates in cloud run 1.
This follow-up exercises normal mandatory signatures and quality workflows
from the newly protected main, without bootstrap inputs or config overrides.
