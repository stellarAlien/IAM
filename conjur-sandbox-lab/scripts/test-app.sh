#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
require_docker
lock_runtime
for workload in checkout fraud; do
  dc exec -T "$workload" python app.py check
done
dc run --rm --no-deps manager test
log 'Authentication, isolation, live rotation, and HTTP workload checks passed.'
