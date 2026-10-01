#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
require_docker
lock_runtime
log 'Applying additive policies; existing host credentials are preserved.'
dc run --rm --no-deps manager policies
