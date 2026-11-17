#!/usr/bin/env bash
# Deploy or restore the lab in a given mode.
#   scripts/reset.sh vulnerable
#   scripts/reset.sh hardened
source "$(dirname "$0")/../attacks/common.sh"

MODE="${1:-vulnerable}"
[[ "$MODE" == "vulnerable" || "$MODE" == "hardened" ]] || { fail "Usage: $0 vulnerable|hardened"; exit 1; }

use_admin

# Undo scenario 1 leftovers: IAM keeps at most 5 policy versions, so delete
# every non-default version before Terraform writes a fresh one.
if POLICY_ARN="$(tf_out intern_policy_arn 2>/dev/null)"; then
  for v in $(aws iam list-policy-versions --policy-arn "$POLICY_ARN" \
               --query 'Versions[?IsDefaultVersion==`false`].VersionId' --output text 2>/dev/null); do
    aws iam delete-policy-version --policy-arn "$POLICY_ARN" --version-id "$v" >/dev/null 2>&1 \
      && log "Deleted leftover policy version $v"
  done
fi

log "Applying Terraform in '${MODE}' mode"
"$TF_BIN" -chdir="$TF_DIR" init -input=false >/dev/null
"$TF_BIN" -chdir="$TF_DIR" apply -input=false -auto-approve -var "lab_mode=${MODE}"

good "Lab is in '${MODE}' mode. Next: scripts/preflight.sh"
