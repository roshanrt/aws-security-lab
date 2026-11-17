# Shared helpers for deploy.ps1, destroy.ps1 and the tests. Dot-source it.
# Works on Windows PowerShell 5.1 and PowerShell 7.

# 'Continue' on purpose: on 5.1, redirecting a native command's stderr under 'Stop'
# raises a terminating error. Native calls are checked through $LASTEXITCODE.
$ErrorActionPreference = 'Continue'

$EntRoot = $PSScriptRoot
$TfBin   = if ($env:TF_BIN) { $env:TF_BIN } else { 'terraform' }

# Only ever LocalStack. The config/credentials paths point at files that do not
# exist, so neither the CLI nor boto3 can read the real ~/.aws.
$env:AWS_ENDPOINT_URL            = 'http://localhost:4566'
$env:AWS_DEFAULT_REGION          = 'us-east-1'
$env:AWS_CONFIG_FILE             = Join-Path $EntRoot '.no-aws-config'
$env:AWS_SHARED_CREDENTIALS_FILE = Join-Path $EntRoot '.no-aws-credentials'
$env:AWS_EC2_METADATA_DISABLED   = 'true'
Remove-Item Env:AWS_PROFILE, Env:AWS_SESSION_TOKEN -ErrorAction SilentlyContinue

# LocalStack-only overrides for the toggles in variables.tf (see COVERAGE.md).
$LocalTfVars = @('-var', 'enable_backup_vault_lock=false', '-var', 'enable_event_forwarding=false', '-var', 'central_trail_delivery=false')

$Acct = [ordered]@{
  mgmt = '999999999999'; log_archive = '111111111111'; security = '222222222222'
  network = '333333333333'; prod = '444444444444'; nonprod = '555555555555'
}

function Tf { & $TfBin "-chdir=$EntRoot" @args }

function Tf-Out([string]$Name) {
  $out = & $TfBin "-chdir=$EntRoot" output -raw $Name 2>$null
  if ($LASTEXITCODE -ne 0) { return $null }
  return (@($out) -join "`n")
}

function Tf-OutJson([string]$Name) {
  $out = & $TfBin "-chdir=$EntRoot" output -json $Name 2>$null
  if ($LASTEXITCODE -ne 0) { return $null }
  return ((@($out) -join "`n") | ConvertFrom-Json)
}

# Act as the root (deployer) identity of an account. Used for read-only checks and setup.
function Use-Account([string]$Id) {
  $env:AWS_ACCESS_KEY_ID = $Id; $env:AWS_SECRET_ACCESS_KEY = 'test'
  Remove-Item Env:AWS_SESSION_TOKEN -ErrorAction SilentlyContinue
}

function Use-Creds($Creds) {
  $env:AWS_ACCESS_KEY_ID = $Creds.AccessKeyId; $env:AWS_SECRET_ACCESS_KEY = $Creds.SecretAccessKey
  if ($Creds.SessionToken) { $env:AWS_SESSION_TOKEN = $Creds.SessionToken } else { Remove-Item Env:AWS_SESSION_TOKEN -ErrorAction SilentlyContinue }
}

# Run an AWS CLI call. Returns Ok, Out (stdout+stderr lines), Text, and Denied
# (true only for an authorization failure, never for a validation or emulator error).
function Aws {
  # aws.exe, not aws: PowerShell names are case-insensitive, so 'aws' would be this function.
  $lines = @(& aws.exe --no-cli-pager @args 2>&1 | ForEach-Object { "$_" } |
    Where-Object { $_.Trim() -and $_ -notmatch '^System\.Management\.Automation\.' })
  $text = $lines -join "`n"
  [pscustomobject]@{
    Ok     = ($LASTEXITCODE -eq 0)
    Out    = $lines
    Text   = $text
    Denied = ($LASTEXITCODE -ne 0 -and $text -match 'AccessDenied|UnauthorizedOperation|not authorized to perform|explicit deny')
  }
}

# Run an AWS CLI call and parse its JSON output. $null when the call fails.
function Aws-Json {
  $out = & aws.exe --no-cli-pager @args --output json 2>$null
  if ($LASTEXITCODE -ne 0) { return $null }
  $text = (@($out) -join "`n").Trim()
  if (-not $text) { return $null }
  return ($text | ConvertFrom-Json)
}

# Write JSON to a temp file without a BOM and return a file:// reference for the CLI.
function Json-File([string]$Text) {
  $path = [IO.Path]::GetTempFileName()
  [IO.File]::WriteAllText($path, $Text)
  return "file://$path"
}

# Assume a role with the current identity. Returns credentials, or $null with the
# reason in $script:LastAssumeError.
function Assume-Role([string]$RoleArn, [string]$ExternalId) {
  $a = @('sts', 'assume-role', '--role-arn', $RoleArn, '--role-session-name', 'lab-session', '--output', 'json')
  if ($ExternalId) { $a += @('--external-id', $ExternalId) }
  $r = Aws @a
  if (-not $r.Ok) { $script:LastAssumeError = $r.Text; return $null }
  return ($r.Text | ConvertFrom-Json).Credentials
}

# Become the lab-only bootstrap identity (the one long-lived key in the landing zone).
function Use-Bootstrap {
  $c = Tf-OutJson bootstrap_credentials
  if (-not $c) { Write-Host 'No bootstrap credentials. Run .\deploy.ps1 first.' -ForegroundColor Red; exit 1 }
  Use-Creds ([pscustomobject]@{ AccessKeyId = $c.access_key_id; SecretAccessKey = $c.secret_access_key })
}

# Become the pipeline role in a workload account, the way a compromised CI job would.
function Use-CiRole([string]$AccountId) {
  Use-Bootstrap
  $c = Assume-Role "arn:aws:iam::${AccountId}:role/lz-ci-deployer" (Tf-Out ci_external_id)
  if (-not $c) { Write-Host "Could not assume lz-ci-deployer in ${AccountId}: $script:LastAssumeError" -ForegroundColor Red; exit 1 }
  Use-Creds $c
}
