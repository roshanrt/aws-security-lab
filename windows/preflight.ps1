# Checks the lab is ready: LocalStack reachable, Terraform applied,
# CloudTrail event history working, and IAM enforcement ON.
. "$PSScriptRoot\common.ps1"

$Ok = $true

Log "LocalStack health at $($env:AWS_ENDPOINT_URL)"
try {
  $null = Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 "$($env:AWS_ENDPOINT_URL)/_localstack/health"
  Good 'LocalStack is reachable'
} catch {
  Fail 'LocalStack not reachable. Run: lstk start'; exit 1
}

Log 'Terraform outputs'
$Mode = Tf-Out lab_mode
if ($Mode) {
  Good "Lab deployed in '$Mode' mode"
} else {
  Fail 'No Terraform outputs. Run: .\windows\reset.ps1 vulnerable'; exit 1
}

Log 'CloudTrail event history (needed by detections\detect.py)'
Use-Admin
if ($null -ne (Get-Aws cloudtrail lookup-events --max-results 1)) {
  Good 'LookupEvents works'
} else {
  Warn 'LookupEvents failed. Detections will have no data on this LocalStack tier/version.'
  $Ok = $false
}

Log 'IAM enforcement probe: lab-app tries iam:CreateUser (never allowed in either mode)'
Use-Identity app
if ($null -ne (Get-Aws iam create-user --user-name lab-enforcement-probe)) {
  Fail "IAM enforcement is OFF. Every attack will 'succeed' and hardened mode proves nothing."
  Warn "Start LocalStack with ENFORCE_IAM=1 (see README, 'Turn on IAM enforcement')."
  Use-Admin
  $null = Get-Aws iam delete-user --user-name lab-enforcement-probe
  $Ok = $false
} else {
  Good 'IAM enforcement is ON'
}

if ($Ok) { Good 'Preflight passed'; exit 0 }
Warn 'Preflight finished with warnings'
exit 1
