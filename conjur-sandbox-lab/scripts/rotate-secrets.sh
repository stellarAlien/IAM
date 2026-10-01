#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
require_docker
lock_runtime
log 'Rotating payment and fraud credentials without restarting workloads.'
dc run --rm --no-deps manager rotate
