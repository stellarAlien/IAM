#!/usr/bin/env bash
set -euo pipefail
export CONJUR_DATA_KEY
CONJUR_DATA_KEY=$(cat /run/secrets/data_key)
database_password=$(cat /run/secrets/db_password)
DATABASE_URL="postgresql://conjur:${database_password}@database:5432/conjur"
export DATABASE_URL
exec conjurctl "$@"
