# Scenario 4: Valid account without MFA
# ATT&CK: T1078.004 (Stratus: aws.initial-access.console-login-without-mfa)
. "$PSScriptRoot\common.ps1"

Use-Identity contractor

Log 'Step 1: Who am I? (a stolen key or phished password, no MFA)'
$null = Attempt sts get-caller-identity

Log 'Step 2: Enumerate the account with view-only access'
$hits = 0
if (Attempt iam list-users --query 'Users[].UserName' --output text)   { $hits++ }
if (Attempt iam list-roles --query 'Roles[].RoleName' --output text)   { $hits++ }
if (Attempt s3api list-buckets --query 'Buckets[].Name' --output text) { $hits++ }

Warn 'The console path needs a ConsoleLogin event, which LocalStack cannot produce. LAB-007 covers it in tests/sample_events.json.'

if ($hits -gt 0) { Finish succeeded }
Finish blocked
