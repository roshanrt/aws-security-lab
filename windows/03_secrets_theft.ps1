# Scenario 3: Credential theft from Secrets Manager
# ATT&CK: T1555.006
. "$PSScriptRoot\common.ps1"

$AppSecret  = Tf-Out app_secret_name
$ProdSecret = Tf-Out prod_secret_name
Use-Identity app

Log 'Step 1: Legitimate access to my own secret (should always work)'
if (-not (Attempt secretsmanager get-secret-value --secret-id $AppSecret --query Name --output text)) {
  Warn "The app can't read its own secret. The hardened policy may be too tight for this LocalStack version."
}

Log 'Step 2: Enumerate other secrets'
$Listed = Get-Aws secretsmanager list-secrets --query 'SecretList[].Name' --output text
if ($null -ne $Listed) {
  Good "ListSecrets allowed: $Listed"
  $Targets = $Listed -split '\s+' | Where-Object { $_ }
} else {
  Fail 'ListSecrets denied. Falling back to guessing common names, as a real attacker would.'
  $Targets = @($ProdSecret, 'lab/prod/db', 'lab/prod/database')
}

Log "Step 3: Try to read every secret that isn't mine"
$Stolen = 0
foreach ($name in $Targets) {
  if ($name -eq $AppSecret) { continue }
  $value = Get-Aws secretsmanager get-secret-value --secret-id $name --query SecretString --output text
  if ($null -ne $value) {
    $shown = '[value hidden]'
    try {
      $obj = $value | ConvertFrom-Json
      if ($obj.password) { $obj.password = $obj.password.Substring(0, [Math]::Min(9, $obj.password.Length)) + '****' }
      $shown = $obj | ConvertTo-Json -Compress
    } catch { }
    Fail "Read ${name}: $shown"
    $Stolen++
  } else {
    Good "Denied: $name"
  }
}

if ($Stolen -gt 0) { Finish succeeded }
Finish blocked
