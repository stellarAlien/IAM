#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
require_docker
command -v openssl >/dev/null || die 'OpenSSL is required.'
lock_runtime
if [[ ! -f .env ]]; then cp .env.example .env; fi
if [[ ! -s .runtime/db_password ]]; then
  [[ ! -e .runtime/bootstrapped ]] || die 'Database credentials are missing; restore the runtime backup.'
  openssl rand -hex 32 > .runtime/db_password
fi
if [[ ! -s .runtime/data_key ]]; then
  [[ ! -e .runtime/bootstrapped ]] || die 'Encryption key is missing; restore it rather than generating a new one.'
  log 'Generating the Conjur data-at-rest encryption key.'
  : > .runtime/data_key
  dc run --rm --no-deps --entrypoint conjurctl conjur data-key generate > .runtime/data_key.tmp
  [[ -s .runtime/data_key.tmp ]] || die 'Conjur returned an empty encryption key.'
  mv .runtime/data_key.tmp .runtime/data_key
fi
if [[ ! -s .runtime/tls.key || ! -s .runtime/tls.crt ]]; then
  [[ ! -e .runtime/bootstrapped ]] || die 'TLS material is missing; restore it or perform a planned certificate renewal.'
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 \
    -subj '/CN=proxy' -addext 'subjectAltName=DNS:proxy,DNS:localhost,IP:127.0.0.1' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -keyout .runtime/tls.key -out .runtime/tls.crt 2>/dev/null
  chmod 444 .runtime/tls.crt
fi
for key in admin checkout fraud; do
  [[ -e .runtime/${key}_api_key ]] || : > ".runtime/${key}_api_key"
done
log 'Starting Postgres, Conjur, and the TLS gateway.'
dc up -d --wait --wait-timeout 300 database conjur proxy
touch .runtime/bootstrapped
log 'Infrastructure is healthy. Run make init to provision the account and identities.'
