# Runs all three attacks against the current lab mode and checks the outcome:
#   vulnerable -> every attack should SUCCEED and be detected
#   hardened   -> every attack should be BLOCKED and still be detected
# Exit code 0 only when every scenario behaves as expected.
. "$PSScriptRoot\common.ps1"

$Python = if (Get-Command py -ErrorAction SilentlyContinue) { 'py' } else { 'python' }
Require $Python

# Each script ends with 'exit N', so run it in a child PowerShell (same edition as
# this one) and read the outcome from $LASTEXITCODE.
$PsExe = (Get-Process -Id $PID).Path
function Invoke-Script([string]$Path) {
  & $PsExe -NoProfile -ExecutionPolicy Bypass -File $Path
}

$Mode   = Tf-Out lab_mode
$Expect = if ($Mode -eq 'vulnerable') { $EXIT_SUCCEEDED } else { $EXIT_BLOCKED }
$Pass = 0; $Total = 0

Invoke-Script "$PSScriptRoot\preflight.ps1"
if ($LASTEXITCODE -ne 0) { Fail 'Fix preflight warnings first'; exit 1 }

$Start = [DateTime]::UtcNow
# CloudTrail tampering runs last so it can't affect logging for the other scenarios.
foreach ($script in '01_iam_privesc.ps1', '03_secrets_theft.ps1', '02_cloudtrail_tamper.ps1') {
  $Total++
  Write-Host "`n========== $script ($Mode mode) =========="
  Invoke-Script "$PSScriptRoot\$script"
  $rc = $LASTEXITCODE
  if ($rc -eq $Expect) {
    Good "PASS: outcome matches $Mode mode"; $Pass++
  } else {
    Fail "FAIL: exit $rc, expected $Expect"
  }
}

$Minutes = [int][Math]::Floor(([DateTime]::UtcNow - $Start).TotalMinutes) + 2
Write-Host "`n========== Detections (last $Minutes min) =========="
Use-Admin
& $Python "$LabRoot\detections\detect.py" --minutes $Minutes

Write-Host "`nScenario outcomes: $Pass/$Total as expected in $Mode mode"
Warn 'Check the findings above: each scenario should have at least one detection.'
if ($Mode -eq 'vulnerable') { Warn 'Restore with: .\windows\reset.ps1 vulnerable  (or: .\windows\reset.ps1 hardened)' }
if ($Pass -eq $Total) { exit 0 }
exit 1
