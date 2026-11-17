#!/usr/bin/env bash
# Scenario 4: Valid account without MFA
# ATT&CK: T1078.004 (Stratus: aws.initial-access.console-login-without-mfa)
source "$(dirname "$0")/common.sh"

use_identity contractor

log "Step 1: Who am I? (a stolen key or phished password, no MFA)"
attempt sts get-caller-identity || true

log "Step 2: Enumerate the account with view-only access"
HITS=0
attempt iam list-users --query 'Users[].UserName' --output text && HITS=$((HITS + 1))
attempt iam list-roles --query 'Roles[].RoleName' --output text && HITS=$((HITS + 1))
attempt s3api list-buckets --query 'Buckets[].Name' --output text && HITS=$((HITS + 1))

warn "The console path needs a ConsoleLogin event, which LocalStack cannot produce. LAB-007 covers it in tests/sample_events.json."

if (( HITS > 0 )); then
  finish succeeded
fi
finish blocked
