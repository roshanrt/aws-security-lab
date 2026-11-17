#!/usr/bin/env bash
# Checks the lab is ready: LocalStack reachable, Terraform applied,
# CloudTrail event history working, and IAM enforcement ON.
source "$(dirname "$0")/../attacks/common.sh"
require curl

OK=1

log "LocalStack health at ${AWS_ENDPOINT_URL}"
if curl -fsS "${AWS_ENDPOINT_URL}/_localstack/health" >/dev/null; then
  good "LocalStack is reachable"
else
  fail "LocalStack not reachable. Run: lstk start"; exit 1
fi

log "Terraform outputs"
if MODE="$(tf_out lab_mode 2>/dev/null)"; then
  good "Lab deployed in '${MODE}' mode"
else
  fail "No Terraform outputs. Run: scripts/reset.sh vulnerable"; exit 1
fi

log "CloudTrail event history (needed by detections/detect.py)"
use_admin
if aws cloudtrail lookup-events --max-results 1 >/dev/null 2>&1; then
  good "LookupEvents works"
else
  warn "LookupEvents failed. Detections will have no data on this LocalStack tier/version."
  OK=0
fi

log "IAM enforcement probe: lab-app tries iam:CreateUser (never allowed in either mode)"
use_identity app
if aws iam create-user --user-name lab-enforcement-probe >/dev/null 2>&1; then
  fail "IAM enforcement is OFF. Every attack will 'succeed' and hardened mode proves nothing."
  warn "Start LocalStack with ENFORCE_IAM=1 (see README, 'Turn on IAM enforcement')."
  use_admin
  aws iam delete-user --user-name lab-enforcement-probe >/dev/null 2>&1 || true
  OK=0
else
  good "IAM enforcement is ON"
fi

if (( OK )); then good "Preflight passed"; else warn "Preflight finished with warnings"; exit 1; fi
