#!/usr/bin/env bash
# Scenario 5: Public bucket and data exfiltration
# ATT&CK: T1530 Data from Cloud Storage
source "$(dirname "$0")/common.sh"

BUCKET="$(tf_out data_bucket)"
use_identity dev

log "Step 1: Legitimate access (should always work)"
attempt s3api head-object --bucket "$BUCKET" --key customers.csv || true

log "Step 2: Turn off Block Public Access and publish the bucket"
attempt s3api delete-public-access-block --bucket "$BUCKET" || true
DOC="$(mktemp)"
printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"}]}' "$BUCKET" > "$DOC"
if ! attempt s3api put-bucket-policy --bucket "$BUCKET" --policy "file://$DOC"; then
  rm -f "$DOC"; finish blocked
fi
rm -f "$DOC"

log "Step 3: Read the data with no credentials at all"
OUT="$(mktemp)"
if env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY aws --no-cli-pager --no-sign-request \
     s3api get-object --bucket "$BUCKET" --key customers.csv "$OUT" >/dev/null 2>&1 && [[ -s "$OUT" ]]; then
  fail "Anonymous read worked: $(head -n 1 "$OUT")"
  rm -f "$OUT"; finish succeeded
fi
rm -f "$OUT"
good "Policy was accepted but anonymous read is denied (Block Public Access)"
finish blocked
