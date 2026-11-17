# Deploys the enterprise landing zone to LocalStack. One command:
#
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\enterprise\deploy.ps1
#
# Only ever talks to http://localhost:4566 (lib.ps1 blocks the real ~/.aws files).
# Works on Windows PowerShell 5.1 and PowerShell 7.

. "$PSScriptRoot\lib.ps1"

Write-Host '[*] Checking LocalStack' -ForegroundColor Blue
try {
  $health = (Invoke-WebRequest -UseBasicParsing -TimeoutSec 15 "$($env:AWS_ENDPOINT_URL)/_localstack/health").Content | ConvertFrom-Json
} catch {
  Write-Host '[-] LocalStack is not reachable at http://localhost:4566. Run: lstk start' -ForegroundColor Red; exit 1
}
Write-Host "[+] LocalStack $($health.version) ($($health.edition))" -ForegroundColor Green

# A bucket under Object Lock survives destroy.ps1 by design. If one is still there
# but Terraform no longer tracks it, the emulator has to be reset first.
Use-Account $Acct.log_archive
$bucket = "lz-log-archive-$($Acct.log_archive)"
$exists = (Aws s3api head-bucket --bucket $bucket).Ok
$tracked = (Tf state list 2>$null | Select-String -SimpleMatch 'module.logging.module.central_bucket.aws_s3_bucket.this')
if ($exists -and -not $tracked) {
  Write-Host "[-] $bucket already exists but is not in Terraform state (left behind by destroy.ps1: Object Lock)." -ForegroundColor Red
  Write-Host '    Reset the emulator first: lstk restart   (this also clears the base lab; re-run .\windows\reset.ps1 afterwards)' -ForegroundColor Yellow
  exit 1
}

Write-Host '[*] terraform init' -ForegroundColor Blue
Tf init -input=false | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host '[-] terraform init failed. Run it by hand to see the error.' -ForegroundColor Red; exit 1 }

Write-Host '[*] terraform apply (organization, identity, logging, data-protection, network, workload, edge, detection)' -ForegroundColor Blue
Write-Host "    LocalStack overrides: $($LocalTfVars -join ' ')"
Tf apply -input=false -auto-approve @LocalTfVars
if ($LASTEXITCODE -ne 0) { Write-Host '[-] terraform apply failed' -ForegroundColor Red; exit 1 }

Write-Host '[+] Landing zone deployed.' -ForegroundColor Green
Write-Host '    Next: .\enterprise\tests\security_assertions.ps1'
Write-Host '          .\enterprise\tests\attack_simulation.ps1'
