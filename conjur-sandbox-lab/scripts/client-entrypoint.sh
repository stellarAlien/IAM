#!/usr/bin/env bash
set -euo pipefail
export CONJUR_AUTHN_API_KEY
CONJUR_AUTHN_API_KEY=$(cat /run/secrets/admin_api_key)
exec conjur "$@"
