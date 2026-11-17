# Destroys the enterprise landing zone on LocalStack. One command:
#
#   .\enterprise\destroy.ps1
#
# Three protections exist to stop exactly this, so the script has to lift them first,
# explicitly and visibly:
#   1. Deletion protection on RDS, DynamoDB and the ALB is switched off.
#   2. The database secret is purged instead of waiting out its 7-day recovery window.
#   3. Log buckets under Object Lock (COMPLIANCE) cannot be emptied by anyone. They are
#      removed from Terraform state and stay in LocalStack until the emulator is reset.
#
# Works on Windows PowerShell 5.1 and PowerShell 7.

. "$PSScriptRoot\lib.ps1"

$state = @(Tf state list 2>$null)
if ($state.Count -eq 0) { Write-Host '[!] Nothing in Terraform state. Nothing to destroy.' -ForegroundColor Yellow; exit 0 }

$W   = Tf-OutJson prod_workload
$E   = Tf-OutJson prod_edge
$Det = Tf-OutJson detection

Write-Host '[*] 1/4 Switching off deletion protection' -ForegroundColor Blue
Use-Account $Acct.prod
if ($W) {
  $null = Aws rds modify-db-instance --db-instance-identifier $W.db_identifier --no-deletion-protection --apply-immediately
  $null = Aws dynamodb update-table --table-name $W.table_name --no-deletion-protection-enabled
}
if ($E) { $null = Aws elbv2 modify-load-balancer-attributes --load-balancer-arn $E.alb_arn --attributes Key=deletion_protection.enabled,Value=false }
if ($Det) {
  Use-Account $Acct.security
  $null = Aws dynamodb update-table --table-name $Det.findings_table --no-deletion-protection-enabled
}
# Tell Terraform about the change so destroy does not re-read stale values.
Tf apply -refresh-only -input=false -auto-approve @LocalTfVars | Out-Null

Write-Host '[*] 2/4 Releasing Object-Locked log buckets from Terraform state (they cannot be deleted)' -ForegroundColor Blue
$locked = @($state | Where-Object { $_ -match '^module\.logging\.(module\.trail_\w+\.)?module\.(central_bucket|local_bucket\[0\])\.' })
foreach ($addr in $locked) { Tf state rm $addr | Out-Null }
Write-Host "    released $($locked.Count) resources"

Write-Host '[*] 3/4 terraform destroy' -ForegroundColor Blue
Tf destroy -input=false -auto-approve @LocalTfVars
$rc = $LASTEXITCODE

Write-Host '[*] 4/4 Purging the database secret' -ForegroundColor Blue
if ($W) {
  Use-Account $Acct.prod
  $null = Aws secretsmanager delete-secret --secret-id $W.secret_name --force-delete-without-recovery
}

if ($rc -ne 0) { Write-Host '[-] terraform destroy reported errors (see above).' -ForegroundColor Red; exit 1 }
Write-Host '[+] Landing zone destroyed.' -ForegroundColor Green
Write-Host '[!] Log buckets under Object Lock remain in LocalStack by design.' -ForegroundColor Yellow
Write-Host '    Before the next deploy, reset the emulator: lstk restart   (then .\windows\reset.ps1 for the base lab)'
