#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
require_docker
mode=${1:-}
mkdir -p .runtime/evidence
if [[ $mode == act ]]; then
  actor=${2:-eve}
  action=${3:-canary}
  expected=${4:-observe}
  case "$actor" in alice|bob|eve) ;; *) die 'ACTOR must be alice, bob, or eve.' ;; esac
  case "$action" in metadata|payment|fraud|canary|tamper|escalate|watch-payment) ;; *) die 'Unknown ACTION; see docs/security-exercise.md.' ;; esac
  case "$expected" in observe|allow|deny) ;; *) die 'EXPECT must be observe, allow, or deny.' ;; esac
  [[ -s .runtime/${actor}_api_key ]] || die 'Run make exercise-init first.'
  export EXERCISE_ACTOR=$actor
  # Only this identity key is mounted; actor sessions never receive admin state.
  dc run --rm --no-deps actor "$action" "$expected" | tee -a .runtime/evidence/events.jsonl
else
  case "$mode" in setup|expose|contain|reset|recover) ;; *) die 'Unknown facilitator action.' ;; esac
  lock_runtime
  [[ -s .runtime/admin_api_key ]] || die 'Run make up && make init first.'
  if [[ $mode == expose && ${CONFIRM:-} != lab-only ]]; then
    die 'Intentional overgrant requires CONFIRM=lab-only; synthetic lab only.'
  fi
  dc run --rm --no-deps -e "EXERCISE_CONFIRM=${CONFIRM:-}" --entrypoint python \
    manager /tools/exercise.py admin "$mode" | tee -a .runtime/evidence/events.jsonl
fi
