# Deploy or restore the lab in a given mode.
#   .\windows\reset.ps1 vulnerable
#   .\windows\reset.ps1 hardened
. "$PSScriptRoot\common.ps1"

$Mode = if ($args.Count -gt 0) { $args[0] } else { 'vulnerable' }
if ($Mode -ne 'vulnerable' -and $Mode -ne 'hardened') { Fail 'Usage: .\windows\reset.ps1 vulnerable|hardened'; exit 1 }

Use-Admin

# Undo scenario 1 leftovers: IAM keeps at most 5 policy versions, so delete
# every non-default version before Terraform writes a fresh one.
$PolicyArn = Tf-Out intern_policy_arn
if ($PolicyArn) {
  $versions = Get-Aws iam list-policy-versions --policy-arn $PolicyArn --query 'Versions[?IsDefaultVersion==`false`].VersionId' --output text
  foreach ($v in ("$versions" -split '\s+' | Where-Object { $_ })) {
    if ($null -ne (Get-Aws iam delete-policy-version --policy-arn $PolicyArn --version-id $v)) {
      Log "Deleted leftover policy version $v"
    }
  }
}

Log "Applying Terraform in '$Mode' mode"
& $TfBin "-chdir=$TfDir" init -input=false | Out-Null
if ($LASTEXITCODE -ne 0) { Fail 'terraform init failed. Re-run it by hand to see the error.'; exit 1 }
& $TfBin "-chdir=$TfDir" apply -input=false -auto-approve -var "lab_mode=$Mode"
if ($LASTEXITCODE -ne 0) { Fail 'terraform apply failed'; exit 1 }

Good "Lab is in '$Mode' mode. Next: .\windows\preflight.ps1"
