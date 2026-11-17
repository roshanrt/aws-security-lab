#!/usr/bin/env bash
# Shared helpers for attack and validation scripts. Source it, don't run it.

set -euo pipefail

LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$LAB_ROOT/terraform"
TF_BIN="${TF_BIN:-terraform}"   # set TF_BIN=tofu for OpenTofu

export AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-http://localhost:4566}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export AWS_PAGER=""
unset AWS_PROFILE AWS_SESSION_TOKEN 2>/dev/null || true

EXIT_SUCCEEDED=0
EXIT_BLOCKED=10

log()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
good() { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[-]\033[0m %s\n' "$*"; }

require() {
  for bin in "$@"; do
    command -v "$bin" >/dev/null 2>&1 || { fail "Missing dependency: $bin"; exit 1; }
  done
}

tf_out() {
  "$TF_BIN" -chdir="$TF_DIR" output -raw "$1"
}

# Switch the AWS CLI to one of the lab identities: intern, ops or app.
use_identity() {
  local who="$1" creds
  creds="$("$TF_BIN" -chdir="$TF_DIR" output -json credentials)"
  AWS_ACCESS_KEY_ID="$(jq -r ".${who}.access_key_id" <<<"$creds")"
  AWS_SECRET_ACCESS_KEY="$(jq -r ".${who}.secret_access_key" <<<"$creds")"
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
  log "Now acting as lab-${who} (${AWS_ACCESS_KEY_ID})"
}

# LocalStack root identity, used only for setup and cleanup.
use_admin() {
  export AWS_ACCESS_KEY_ID="test" AWS_SECRET_ACCESS_KEY="test"
}

# Run an AWS CLI call; print output on success, the error on failure.
attempt() {
  local out
  if out="$(aws "$@" 2>&1)"; then
    printf '%s\n' "$out"
    return 0
  fi
  fail "Denied or failed: aws $*"
  printf '    %s\n' "$(head -n 2 <<<"$out")"
  return 1
}

finish() {
  if [[ "$1" == "succeeded" ]]; then
    fail "RESULT: ATTACK SUCCEEDED"
    exit "$EXIT_SUCCEEDED"
  fi
  good "RESULT: ATTACK BLOCKED"
  exit "$EXIT_BLOCKED"
}

require aws jq "$TF_BIN"
