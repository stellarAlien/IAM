#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
require_docker
lock_runtime
[[ -e .runtime/bootstrapped ]] || die 'Run make up first.'
if [[ ! -s .runtime/admin_api_key && ! -s .runtime/bootstrap.out ]]; then
  log 'Creating the account; bootstrap credentials stay in the private runtime directory.'
  # shellcheck disable=SC2016
  dc exec -T conjur bash -c 'bash /opt/lab/conjur-entrypoint.sh account create "$CONJUR_ACCOUNT"' > .runtime/bootstrap.out.tmp
  mv .runtime/bootstrap.out.tmp .runtime/bootstrap.out
fi
dc build manager
dc run --rm --no-deps manager init
dc --profile workloads up -d --wait --wait-timeout 120 checkout fraud
log 'Both workloads are healthy. Run make test-app for authentication, RBAC, and rotation checks.'
