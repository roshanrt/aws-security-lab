#!/usr/bin/env bash
# Runs all three attacks against the current lab mode and checks the outcome:
#   vulnerable -> every attack should SUCCEED and be detected
#   hardened   -> every attack should be BLOCKED and still be detected
# Exit code 0 only when every scenario behaves as expected.
source "$(dirname "$0")/../attacks/common.sh"
require python3

MODE="$(tf_out lab_mode)"
ATTACKS="$LAB_ROOT/attacks"
EXPECT=$([[ "$MODE" == "vulnerable" ]] && echo "$EXIT_SUCCEEDED" || echo "$EXIT_BLOCKED")
PASS=0; TOTAL=0

"$LAB_ROOT/scripts/preflight.sh" || { fail "Fix preflight warnings first"; exit 1; }

START="$(date -u +%s)"
# CloudTrail tampering runs last so it can't affect logging for the other scenarios.
for script in 01_iam_privesc.sh 03_secrets_theft.sh 02_cloudtrail_tamper.sh; do
  TOTAL=$((TOTAL + 1))
  printf '\n========== %s (%s mode) ==========\n' "$script" "$MODE"
  set +e; bash "$ATTACKS/$script"; RC=$?; set -e
  if [[ "$RC" == "$EXPECT" ]]; then
    good "PASS: outcome matches ${MODE} mode"; PASS=$((PASS + 1))
  else
    fail "FAIL: exit ${RC}, expected ${EXPECT}"
  fi
done

MINUTES=$(( ( $(date -u +%s) - START ) / 60 + 2 ))
printf '\n========== Detections (last %s min) ==========\n' "$MINUTES"
set +e
python3 "$LAB_ROOT/detections/detect.py" --minutes "$MINUTES"
set -e

printf '\nScenario outcomes: %s/%s as expected in %s mode\n' "$PASS" "$TOTAL" "$MODE"
warn "Check the findings above: each scenario should have at least one detection."
[[ "$MODE" == "vulnerable" ]] && warn "Restore with: scripts/reset.sh vulnerable  (or: scripts/reset.sh hardened)"
(( PASS == TOTAL ))
