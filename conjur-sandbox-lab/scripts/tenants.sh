#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
require_docker
lock_runtime
mode=${1:-}
case "$mode" in
  init)
    [[ -s .runtime/admin_api_key ]] || die 'Run make up && make init first.'
    dc build manager
    dc run --rm --no-deps --entrypoint python manager /tools/tenants.py init
    dc --profile tenants up -d --wait --wait-timeout 180 acme-dev acme-prod globex-dev globex-prod tenant-gateway
    ;;
  test)
    for service in acme-dev acme-prod globex-dev globex-prod; do
      dc exec -T "$service" python message.py check
    done
    dc run --rm --no-deps --entrypoint python manager /tools/tenants.py test
    python3 scripts/test-gateway.py
    ;;
  rotate)
    dc run --rm --no-deps --entrypoint python manager /tools/tenants.py rotate "${2:-acme}" "${3:-dev}"
    ;;
  *) die 'Usage: tenants.sh init|test|rotate TENANT ENVIRONMENT' ;;
esac
