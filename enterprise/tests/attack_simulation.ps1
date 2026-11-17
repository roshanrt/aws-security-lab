# Runs attacker actions against the landing zone and reports, for each one, whether it
# was prevented, detected, both, or missed.
#
#   prevented : the API call was refused with an authorization error
#   detected  : the detection pipeline wrote a finding for THIS run (rule, principal, time)
#   both      : refused and still reported
#   missed    : it worked and nobody noticed   -> exit code 1
#   error     : the call failed for a non-security reason (not counted as prevented) -> exit code 1
#
# The attacker is a compromised pipeline role (lz-ci-deployer in prod) unless stated.
# Works on Windows PowerShell 5.1 and PowerShell 7.

. "$PSScriptRoot\..\lib.ps1"

$Start  = [DateTime]::UtcNow
$Stamp  = $Start.ToString('HHmmss')
$Prod   = $Acct.prod
$W      = Tf-OutJson prod_workload
$Keys   = Tf-OutJson prod_key_ids
$Vpcs   = Tf-OutJson vpc_ids
$Det    = Tf-OutJson detection
$Canary = Tf-Out scp_canary_account_id
if (-not $W -or -not $Det) { Write-Host 'Landing zone is not deployed. Run .\deploy.ps1 first.' -ForegroundColor Red; exit 1 }

$script:Attacks = @()
# $Rule/$Marker describe the finding that would count as detection of this attack.
function Attack([string]$Id, [string]$Name, [string]$Technique, $Result, [string]$Rule, [string]$Marker, [string]$Who = 'lz-ci-deployer') {
  $state = if ($Result.Denied) { 'denied' } elseif ($Result.Ok) { 'succeeded' } else { 'error' }
  $color = if ($state -eq 'denied') { 'Green' } elseif ($state -eq 'succeeded') { 'Yellow' } else { 'Red' }
  Write-Host "[$Id] $Name -> call $state" -ForegroundColor $color
  if ($state -ne 'succeeded') { Write-Host "       $($Result.Out | Select-Object -Last 1)" }
  $script:Attacks += [pscustomobject]@{ Id = $Id; Name = $Name; Technique = $Technique; State = $state; Rule = $Rule; Marker = $Marker; Who = $Who; Finding = $null }
}

Write-Host "== Attacks (started $($Start.ToString('u'))) ==" -ForegroundColor Cyan

# --- A1: log tampering by a compromised workload identity ---
Use-CiRole $Prod
Attack 'A1' 'Stop CloudTrail logging (pipeline role, prod)' 'T1562.008' (Aws cloudtrail stop-logging --name lz-trail) 'ENT-001' 'lz-trail'

# --- A2: log tampering by the root of an organization member account (only an SCP can stop root) ---
Use-Account $Canary
Attack 'A2' 'Stop CloudTrail logging (account root, org member)' 'T1562.008' (Aws cloudtrail stop-logging --name lz-trail) 'ENT-001' 'lz-trail' 'root'

# --- A3: open a security group to the internet (the pipeline role is allowed to manage groups) ---
Use-CiRole $Prod
$sgName = "attack-sim-$Stamp"
$sg = Aws-Json ec2 create-security-group --group-name $sgName --description 'attack simulation' --vpc-id $Vpcs.prod
$SgId = $sg.GroupId
Attack 'A3' "Open SSH to 0.0.0.0/0 on $SgId" 'T1562.007' (Aws ec2 authorize-security-group-ingress --group-id $SgId --protocol tcp --port 22 --cidr 0.0.0.0/0) 'ENT-004' $SgId

# --- A4: privilege escalation: give the compromised role AdministratorAccess ---
Attack 'A4' 'Attach AdministratorAccess to own role' 'T1098.003' (Aws iam attach-role-policy --role-name lz-ci-deployer --policy-arn arn:aws:iam::aws:policy/AdministratorAccess) 'ENT-003' 'lz-ci-deployer'

# --- A5: privilege escalation: create a new role with no permissions boundary ---
$roleName = "app-attack-$Stamp"
$trust = Json-File '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
Attack 'A5' "Create unbounded backdoor role $roleName" 'T1098' (Aws iam create-role --role-name $roleName --assume-role-policy-document $trust) 'ENT-002' $roleName

# --- A6: credential theft: read the production database secret ---
Attack 'A6' 'Read the prod database secret' 'T1555.006' (Aws secretsmanager get-secret-value --secret-id $W.secret_arn) 'ENT-007' $W.secret_name

# --- A7: data exposure: make the data bucket public ---
$public = Json-File ('{"Version":"2012-10-17","Statement":[{"Sid":"Public","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::' + $W.bucket_name + '/*"}]}')
Attack 'A7' 'Replace the data bucket policy with a public one' 'T1530' (Aws s3api put-bucket-policy --bucket $W.bucket_name --policy $public) 'ENT-005' $W.bucket_name

# --- A8: data destruction: schedule deletion of the key that protects the secrets ---
Attack 'A8' 'Schedule deletion of the secrets KMS key' 'T1485' (Aws kms schedule-key-deletion --key-id $Keys.secrets --pending-window-in-days 7) 'ENT-006' $Keys.secrets

# --- A9: stolen human credentials without MFA: try the break-glass role ---
Use-Bootstrap
Attack 'A9' 'Assume lz-break-glass without MFA' 'T1078.004' (Aws sts assume-role --role-arn "arn:aws:iam::${Prod}:role/lz-break-glass" --role-session-name attacker) 'ENT-008' 'lz-break-glass' 'lab-bootstrap'

# =====================================================================
# Detection: wait for the pipeline (one-minute schedule) to report this run.
# =====================================================================
Write-Host "`n== Detection pipeline ==" -ForegroundColor Cyan
Use-Account $Acct.security

function Get-RunFindings {
  $items = @((Aws-Json dynamodb scan --table-name $Det.findings_table).Items | Where-Object { $_.rule_id })
  foreach ($i in $items) {
    $when = [DateTime]::MinValue
    $null = [DateTime]::TryParse($i.event_time.S, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$when)
    if ($when -ge $Start.AddSeconds(-5)) {
      [pscustomobject]@{ Rule = $i.rule_id.S; Principal = $i.principal.S; Detail = $i.detail.S; Event = $i.event_name.S; Outcome = $i.outcome.S; Containment = $i.containment.S }
    }
  }
}

function Match-Findings($Findings) {
  foreach ($a in $script:Attacks) {
    if ($a.Finding) { continue }
    $a.Finding = $Findings | Where-Object {
      $_.Rule -eq $a.Rule -and ("$($_.Detail) $($_.Event)" -like "*$($a.Marker)*") -and ($_.Principal -like "*$($a.Who)*")
    } | Select-Object -First 1
  }
}

# Attacks whose API call succeeded MUST be detected; wait for those (and the rest) up to 4 minutes.
$invokedDirectly = $false
$deadline = [DateTime]::UtcNow.AddSeconds(240)
do {
  Start-Sleep -Seconds 20
  $found = @(Get-RunFindings)
  Match-Findings $found
  $pending = @($script:Attacks | Where-Object { -not $_.Finding })
  Write-Host "  findings for this run: $($found.Count); attacks not yet matched: $($pending.Count)"
  if ($found.Count -eq 0 -and -not $invokedDirectly -and [DateTime]::UtcNow -gt $Start.AddSeconds(150)) {
    Write-Host '  schedule has not produced findings after 150 s; invoking the detector directly' -ForegroundColor Yellow
    $tmp = [IO.Path]::GetTempFileName()
    $null = Aws lambda invoke --function-name $Det.function_name --cli-read-timeout 300 $tmp
    Remove-Item $tmp -ErrorAction SilentlyContinue
    $invokedDirectly = $true
  }
} while ($pending.Count -gt 0 -and [DateTime]::UtcNow -lt $deadline)

# Containment check for A3: the rule must be gone again.
$a3 = $script:Attacks | Where-Object { $_.Id -eq 'A3' }
$contained = $null
if ($a3.State -eq 'succeeded') {
  Use-Account $Prod
  $perms = @((Aws-Json ec2 describe-security-groups --group-ids $SgId).SecurityGroups[0].IpPermissions)
  $stillOpen = @($perms | Where-Object { @($_.IpRanges | Where-Object { $_.CidrIp -eq '0.0.0.0/0' }).Count -gt 0 }).Count -gt 0
  $contained = -not $stillOpen
}


# Cleanup (as the account root; the attacker role is not used for cleanup).
Use-Account $Prod
if ($SgId) { $null = Aws ec2 delete-security-group --group-id $SgId }
$null = Aws iam delete-role --role-name $roleName

# =====================================================================
Write-Host "`n== Results ==" -ForegroundColor Cyan
$bad = 0
foreach ($a in $script:Attacks) {
  $detected = [bool]$a.Finding
  $verdict = if ($a.State -eq 'error') { 'error' }
    elseif ($a.State -eq 'denied' -and $detected) { 'both' }
    elseif ($a.State -eq 'denied') { 'prevented' }
    elseif ($detected) { 'detected' }
    else { 'missed' }
  if ($verdict -in 'missed', 'error') { $bad++ }
  $color = if ($verdict -in 'missed', 'error') { 'Red' } else { 'Green' }
  Write-Host ("{0,-10}" -f $verdict.ToUpper()) -ForegroundColor $color -NoNewline
  Write-Host "$($a.Id)  $($a.Name)  [$($a.Technique)]"
  if ($detected) {
    Write-Host "           finding $($a.Finding.Rule): $($a.Finding.Detail) (event outcome per CloudTrail: $($a.Finding.Outcome))"
    if ($a.Finding.Containment) { Write-Host "           containment: $($a.Finding.Containment)" }
  }
}
if ($null -ne $contained) {
  if ($contained) { Write-Host "A3 containment verified: $SgId no longer allows 0.0.0.0/0" -ForegroundColor Green }
  else { Write-Host "A3 containment FAILED: $SgId still allows 0.0.0.0/0" -ForegroundColor Red; $bad++ }
}
Write-Host "Alerts: each new finding is published to $($Det.alert_topic_arn) (the detector fails its run if the publish fails)."
if ($invokedDirectly) { Write-Host 'Note: the one-minute schedule did not fire in time; the detector was invoked directly.' -ForegroundColor Yellow }

$summary = $script:Attacks | Group-Object { if ($_.State -eq 'error') { 'error' } elseif ($_.State -eq 'denied' -and $_.Finding) { 'both' } elseif ($_.State -eq 'denied') { 'prevented' } elseif ($_.Finding) { 'detected' } else { 'missed' } } | ForEach-Object { "$($_.Name)=$($_.Count)" }
Write-Host "`nAttack simulation: $($script:Attacks.Count) attacks; $($summary -join ', ')"
if ($bad -gt 0) { exit 1 }
exit 0
