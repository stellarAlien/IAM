#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
require_docker
[[ ${CONFIRM:-} == destroy ]] || die 'Destructive cleanup requires make clean CONFIRM=destroy (deletes DB, data key, and all credentials).'
lock_runtime
dc --profile workloads --profile tools --profile exercise --profile tenants down --volumes --remove-orphans
find .runtime -mindepth 1 -maxdepth 1 ! -name operation.lock -exec rm -rf -- {} +
log 'Database and runtime credentials destroyed. The non-secret .env configuration is retained.'
