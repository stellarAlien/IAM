#!/usr/bin/env bash
set -euo pipefail
umask 077
DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ ${CONFIRM:-} == lab-only ]] || { printf '%s\n' 'Requires CONFIRM=lab-only; additive synthetic sandbox mutation only.' >&2; exit 1; }
mkdir -p "$DIR/.runtime"
chmod 700 "$DIR/.runtime"
# Shared sandbox administrative lock, UID mapping and Docker checks.
# shellcheck source=../../conjur-sandbox-lab/scripts/common.sh
source "$DIR/../conjur-sandbox-lab/scripts/common.sh"
require_docker
lock_runtime
[[ -s .runtime/admin_api_key ]] || die 'Initialize the existing Conjur sandbox first.'
dc run --rm --no-deps --entrypoint python \
  -v "$DIR/scripts:/agent-code:ro" -v "$DIR/policy:/agent-policy:ro" \
  -v "$DIR/.runtime:/agent-runtime" manager /agent-code/provision.py
