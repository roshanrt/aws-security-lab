# Shared helpers for the Windows attack and validation scripts. Dot-source it, don't run it.
# PowerShell port of attacks/common.sh. Works on Windows PowerShell 5.1 and PowerShell 7.

# 'Continue' on purpose: on 5.1, redirecting a native command's stderr under 'Stop'
# raises a terminating error. Every native call is checked through $LASTEXITCODE instead.
$ErrorActionPreference = 'Continue'

$LabRoot = Split-Path -Parent $PSScriptRoot
$TfDir   = Join-Path $LabRoot 'terraform'
$TfBin   = if ($env:TF_BIN) { $env:TF_BIN } else { 'terraform' }   # set TF_BIN=tofu for OpenTofu

if (-not $env:AWS_ENDPOINT_URL)   { $env:AWS_ENDPOINT_URL = 'http://localhost:4566' }
if (-not $env:AWS_DEFAULT_REGION) { $env:AWS_DEFAULT_REGION = 'us-east-1' }
Remove-Item Env:AWS_PROFILE, Env:AWS_SESSION_TOKEN -ErrorAction SilentlyContinue

# Point the CLI and boto3 at files that do not exist, so nothing here can ever read
# the real ~/.aws config or credentials.
$env:AWS_CONFIG_FILE             = Join-Path $LabRoot '.no-aws-config'
$env:AWS_SHARED_CREDENTIALS_FILE = Join-Path $LabRoot '.no-aws-credentials'
$env:AWS_EC2_METADATA_DISABLED   = 'true'

$EXIT_SUCCEEDED = 0
$EXIT_BLOCKED   = 10

function Log  { Write-Host '[*] ' -ForegroundColor Blue   -NoNewline; Write-Host "$args" }
function Good { Write-Host '[+] ' -ForegroundColor Green  -NoNewline; Write-Host "$args" }
function Warn { Write-Host '[!] ' -ForegroundColor Yellow -NoNewline; Write-Host "$args" }
function Fail { Write-Host '[-] ' -ForegroundColor Red    -NoNewline; Write-Host "$args" }

function Require {
  foreach ($bin in $args) {
    if (-not (Get-Command $bin -ErrorAction SilentlyContinue)) { Fail "Missing dependency: $bin"; exit 1 }
  }
}

# Terraform output as text, or $null when the output does not exist.
function Tf-Out([string]$Name) {
  $out = & $TfBin "-chdir=$TfDir" output -raw $Name 2>$null
  if ($LASTEXITCODE -ne 0) { return $null }
  return (@($out) -join "`n")
}

# Switch the AWS CLI to one of the lab identities: intern, ops or app.
function Use-Identity([string]$Who) {
  $json = & $TfBin "-chdir=$TfDir" output -json credentials 2>$null
  if ($LASTEXITCODE -ne 0) { Fail 'No Terraform credentials output. Run: .\windows\reset.ps1 vulnerable'; exit 1 }
  $creds = (@($json) -join "`n") | ConvertFrom-Json
  $env:AWS_ACCESS_KEY_ID     = $creds.$Who.access_key_id
  $env:AWS_SECRET_ACCESS_KEY = $creds.$Who.secret_access_key
  Log "Now acting as lab-$Who ($($env:AWS_ACCESS_KEY_ID))"
}

# LocalStack root identity, used only for setup and cleanup.
function Use-Admin {
  $env:AWS_ACCESS_KEY_ID     = 'test'
  $env:AWS_SECRET_ACCESS_KEY = 'test'
}

# Run an AWS CLI call; print output on success, the error on failure. Returns $true/$false.
function Attempt {
  $out = @(& aws --no-cli-pager @args 2>&1 | ForEach-Object { "$_" })
  if ($LASTEXITCODE -eq 0) {
    $out | ForEach-Object { Write-Host $_ }
    return $true
  }
  Fail "Denied or failed: aws $args"
  # 5.1 renders the CLI's leading blank stderr line as a bare exception type name; drop it.
  $out | Where-Object { $_.Trim() -and $_ -notmatch '^System\.Management\.Automation\.' } | Select-Object -First 2 | ForEach-Object { Write-Host "    $_" }
  return $false
}

# Run an AWS CLI call quietly. Returns its stdout as text, or $null when the call fails.
function Get-Aws {
  $out = & aws --no-cli-pager @args 2>$null
  if ($LASTEXITCODE -ne 0) { return $null }
  return (@($out) -join "`n")
}

function Finish([string]$Outcome) {
  if ($Outcome -eq 'succeeded') {
    Fail 'RESULT: ATTACK SUCCEEDED'
    exit $EXIT_SUCCEEDED
  }
  Good 'RESULT: ATTACK BLOCKED'
  exit $EXIT_BLOCKED
}

Require aws $TfBin
