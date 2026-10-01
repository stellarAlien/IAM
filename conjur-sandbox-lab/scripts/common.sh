#!/usr/bin/env bash
set -euo pipefail
umask 077
LAB_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$LAB_DIR"
export LOCAL_UID LOCAL_GID
LOCAL_UID=$(id -u)
LOCAL_GID=$(id -g)
log() { printf '\033[1;36m[conjur-lab]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }
trap 'printf "\033[1;31m[error]\033[0m Operation failed at line %s (credentials were not printed).\n" "$LINENO" >&2' ERR
dc() { docker compose "$@"; }
require_docker() {
  command -v docker >/dev/null || die 'Docker and Compose v2 are required.'
  docker info >/dev/null 2>&1 || die 'Docker daemon is unavailable.'
  docker compose version >/dev/null
}
lock_runtime() {
  mkdir -p .runtime
  chmod 700 .runtime
  mkdir .runtime/operation.lock 2>/dev/null || die 'Another management operation is running; remove .runtime/operation.lock only after checking it is stale.'
  trap 'rmdir .runtime/operation.lock' EXIT
}
