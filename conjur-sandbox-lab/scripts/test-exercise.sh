#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
require_docker
log 'Checking the baseline access matrix without modifying permissions or secret values.'
for row in 'alice metadata allow' 'alice payment deny' 'alice fraud deny' \
  'bob payment allow' 'bob fraud deny' 'bob escalate deny' \
  'eve canary allow' 'eve payment deny' 'eve fraud deny' 'eve tamper deny' 'eve escalate deny'; do
  read -r actor action expected <<< "$row"
  bash scripts/exercise.sh act "$actor" "$action" "$expected"
done
log 'Baseline multi-user matrix passed. Tamper is checked only as Eve; Bob has intentional payment update rights.'
