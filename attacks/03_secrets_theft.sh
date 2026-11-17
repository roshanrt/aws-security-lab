#!/usr/bin/env bash
# Scenario 3: Credential theft from Secrets Manager
# ATT&CK: T1555.006
source "$(dirname "$0")/common.sh"

APP_SECRET="$(tf_out app_secret_name)"
PROD_SECRET="$(tf_out prod_secret_name)"
use_identity app

log "Step 1: Legitimate access to my own secret (should always work)"
if ! attempt secretsmanager get-secret-value --secret-id "$APP_SECRET" --query Name --output text; then
  warn "The app can't read its own secret. The hardened policy may be too tight for this LocalStack version."
fi

log "Step 2: Enumerate other secrets"
TARGETS=""
if TARGETS="$(aws secretsmanager list-secrets --query 'SecretList[].Name' --output text 2>/dev/null)"; then
  good "ListSecrets allowed: ${TARGETS}"
else
  fail "ListSecrets denied. Falling back to guessing common names, as a real attacker would."
  TARGETS="$PROD_SECRET lab/prod/db lab/prod/database"
fi

log "Step 3: Try to read every secret that isn't mine"
STOLEN=0
for name in $TARGETS; do
  [[ "$name" == "$APP_SECRET" ]] && continue
  if VALUE="$(aws secretsmanager get-secret-value --secret-id "$name" --query SecretString --output text 2>/dev/null)"; then
    fail "Read ${name}: $(jq -c '.password |= (.[0:9] + "****")' <<<"$VALUE" 2>/dev/null || echo '[value hidden]')"
    STOLEN=$((STOLEN + 1))
  else
    good "Denied: ${name}"
  fi
done

if (( STOLEN > 0 )); then
  finish succeeded
fi
finish blocked
