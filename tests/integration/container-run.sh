#!/usr/bin/env bash
# Host-side launcher: runs container-apply.sh inside a throwaway root Linux
# container with the crate mounted. The container gets useradd + visudo and a
# private target dir, so it never touches the host /etc or host target/.
#
# Usage: tests/integration/container-run.sh   (run from the crate root)
set -euo pipefail

CRATE="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="rust:bookworm"

exec docker run --rm \
  -v "$CRATE":/work:ro \
  -v "$HOME/.cargo/registry":/usr/local/cargo/registry \
  -w /work \
  "$IMAGE" \
  bash -c '
    set -e
    apt-get update -qq && apt-get install -y -qq sudo >/dev/null
    # /work is read-only (host crate); copy out so cargo can write nothing into it
    # (build target is redirected via CARGO_TARGET_DIR in the script).
    bash /work/tests/integration/container-apply.sh
  '
