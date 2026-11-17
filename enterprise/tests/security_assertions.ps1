# One check per security control. Queries LocalStack and prints PASS/FAIL.
# Exit code is non-zero when any check fails.
#
#   .\tests\security_assertions.ps1                      # everything
#   .\tests\security_assertions.ps1 -Layer identity      # one or more layers
#
# Every check reports how many resources it inspected, so a check that looked at
# nothing cannot pass silently.
param([string[]]$Layer = @())

. "$PSScriptRoot\..\lib.ps1"

# 'powershell -File x.ps1 -Layer a,b' delivers "a,b" as one string; split it.
$Layer = @($Layer | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

$script:Results = @()
$script:Current = ''

function Section([string]$Name) { $script:Current = $Name; if (Want) { Write-Host "`n== $Name ==" -ForegroundColor Cyan } }
function Want { return ($Layer.Count -eq 0 -or $Layer -contains $script:Current) }

# $Test returns a hashtable: @{ Pass = <bool>; Detail = <string> }.
function Check([string]$Id, [string]$Control, [scriptblock]$Test) {
  if (-not (Want)) { return }
  try { $r = & $Test } catch { $r = @{ Pass = $false; Detail = "check threw: $($_.Exception.Message)" } }
  if ($r.Pass) { Write-Host 'PASS ' -ForegroundColor Green -NoNewline } else { Write-Host 'FAIL ' -ForegroundColor Red -NoNewline }
  Write-Host "$Id  $Control  [$($r.Detail)]"
  $script:Results += [pscustomobject]@{ Id = $Id; Pass = [bool]$r.Pass }
}

# A control that is defined in code but cannot be enforced or observed on LocalStack.
# Reported separately: it is neither a pass nor a fail.
$script:Skipped = @()
function Skip([string]$Id, [string]$Control, [string]$Why) {
  if (-not (Want)) { return }
  Write-Host 'SKIP ' -ForegroundColor Yellow -NoNewline
  Write-Host "$Id  $Control  [$Why]"
  $script:Skipped += $Id
}

# Pass when nothing violates and at least one resource was inspected.
function Verdict([int]$Inspected, $Violations, [string]$What) {
  $v = @($Violations | Where-Object { $_ })
  if ($Inspected -eq 0) { return @{ Pass = $false; Detail = "inspected 0 $What (nothing to check is a failure)" } }
  if ($v.Count -gt 0) { return @{ Pass = $false; Detail = "inspected $Inspected $What; violations: $($v -join ', ')" } }
  return @{ Pass = $true; Detail = "inspected $Inspected $What" }
}

# Expect an authorization failure. A validation or emulator error is not a pass.
function Expect-Denied($Result, [string]$What) {
  if ($Result.Denied) { return @{ Pass = $true; Detail = "$What denied" } }
  if ($Result.Ok) { return @{ Pass = $false; Detail = "$What was ALLOWED" } }
  return @{ Pass = $false; Detail = "$What failed for another reason: $($Result.Out | Select-Object -Last 1)" }
}

function Expect-Allowed($Result, [string]$What) {
  if ($Result.Ok) { return @{ Pass = $true; Detail = "$What allowed" } }
  return @{ Pass = $false; Detail = "$What failed: $($Result.Out | Select-Object -Last 1)" }
}

$Members   = 'log_archive', 'security', 'network', 'prod', 'nonprod'
$Workloads = 'prod', 'nonprod'
$LambdaTrust = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

# =====================================================================
Section 'organization'
# =====================================================================

Check 'ORG-01' 'Four SCPs exist and each is attached to every OU' {
  Use-Account $Acct.mgmt
  $scps = @((Aws-Json organizations list-policies --filter SERVICE_CONTROL_POLICY).Policies | Where-Object { $_.Name -like 'deny-*' })
  $bad = @()
  foreach ($p in $scps) {
    $targets = @((Aws-Json organizations list-targets-for-policy --policy-id $p.Id).Targets)
    if ($targets.Count -lt 3) { $bad += "$($p.Name) attached to $($targets.Count) targets" }
  }
  if ($scps.Count -ne 4) { $bad += "expected 4 SCPs, found $($scps.Count)" }
  Verdict $scps.Count $bad 'SCPs'
}

$Canary = Tf-Out scp_canary_account_id

Check 'ORG-02' 'Control case: SCP canary account can make an approved call' {
  Use-Account $Canary
  Expect-Allowed (Aws ec2 describe-vpcs --region us-east-1 --query 'length(Vpcs)') "ec2:DescribeVpcs in us-east-1 as account $Canary"
}
Check 'ORG-03' 'SCP denies CloudTrail tampering in a member account' {
  Use-Account $Canary
  Expect-Denied (Aws cloudtrail stop-logging --name any-trail) 'cloudtrail:StopLogging'
}
Check 'ORG-04' 'SCP denies leaving the organization' {
  Use-Account $Canary
  Expect-Denied (Aws organizations leave-organization) 'organizations:LeaveOrganization'
}
Check 'ORG-05' 'SCP denies unapproved regions' {
  Use-Account $Canary
  Expect-Denied (Aws ec2 describe-vpcs --region eu-west-1) 'ec2:DescribeVpcs in eu-west-1'
}
Check 'ORG-06' 'SCP denies IAM users and access keys' {
  Use-Account $Canary
  Expect-Denied (Aws iam create-user --user-name scp-probe-user) 'iam:CreateUser'
}

# =====================================================================
Section 'identity'
# =====================================================================

Check 'IAM-01' 'No IAM user has an access key, except the lab-only bootstrap identity' {
  $n = 0; $bad = @()
  foreach ($a in $Members) {
    Use-Account $Acct[$a]
    foreach ($u in @((Aws-Json iam list-users).Users)) {
      $n++
      $keys = @((Aws-Json iam list-access-keys --user-name $u.UserName).AccessKeyMetadata)
      $isBootstrap = ($a -eq 'security' -and $u.UserName -eq 'lab-bootstrap' -and $u.Path -eq '/lab-only/')
      if ($keys.Count -gt 0 -and -not $isBootstrap) { $bad += "$a/$($u.UserName)" }
      if (-not $isBootstrap) { $bad += "$a/$($u.UserName) (unexpected IAM user)" }
    }
  }
  $v = Verdict $n $bad 'IAM users across 5 accounts'
  if ($n -ne 1) { $v.Pass = $false; $v.Detail += "; expected exactly 1 user (lab-bootstrap)" }
  $v
}

# All lz-* roles in an account, with trust policy and boundary.
function Get-LzRoles([string]$AccountKey) {
  Use-Account $Acct[$AccountKey]
  # One call per account: every role with its trust policy, tags and boundary.
  $roles = @((Aws-Json iam get-account-authorization-details --filter Role).RoleDetailList | Where-Object { $_.RoleName -like 'lz-*' })
  foreach ($full in $roles) {
    $class = ($full.Tags | Where-Object { $_.Key -eq 'RoleClass' }).Value
    [pscustomobject]@{ Account = $AccountKey; Name = $full.RoleName; Class = $class; Trust = $full.AssumeRolePolicyDocument; Boundary = $full.PermissionsBoundary.PermissionsBoundaryArn }
  }
}
$AllRoles = if ($Layer.Count -eq 0 -or $Layer -contains 'identity') { $Members | ForEach-Object { Get-LzRoles $_ } } else { @() }

Check 'IAM-02' 'Every human role requires MFA in its trust policy' {
  $human = @($AllRoles | Where-Object { $_.Class -eq 'human' })
  $bad = foreach ($r in $human) {
    foreach ($s in @($r.Trust.Statement)) {
      if ($s.Effect -eq 'Allow' -and $s.Condition.Bool.'aws:MultiFactorAuthPresent' -ne 'true') { "$($r.Account)/$($r.Name)" }
    }
  }
  $v = Verdict $human.Count $bad 'human roles'
  if ($human.Count -ne 25) { $v.Pass = $false; $v.Detail += '; expected 25 (5 roles x 5 accounts)' }
  $v
}

Check 'IAM-03' 'Every machine role trusts one exact principal (ExternalId or PrincipalArn condition)' {
  $machine = @($AllRoles | Where-Object { $_.Class -eq 'machine' })
  $bad = foreach ($r in $machine) {
    foreach ($s in @($r.Trust.Statement)) {
      $pinned = $s.Condition.StringEquals.'sts:ExternalId' -or $s.Condition.ArnEquals.'aws:PrincipalArn'
      if ($s.Effect -eq 'Allow' -and (-not $pinned -or $s.Principal.AWS -eq '*')) { "$($r.Account)/$($r.Name)" }
    }
  }
  Verdict $machine.Count $bad 'machine roles'
}

Check 'IAM-04' 'Every landing-zone role is classified and carries the guardrail permissions boundary' {
  $bad = foreach ($r in $AllRoles) {
    if ($r.Boundary -notlike '*:policy/lz-guardrail-boundary') { "$($r.Account)/$($r.Name) boundary=$($r.Boundary)" }
    if ($r.Class -notin 'human', 'machine', 'service') { "$($r.Account)/$($r.Name) RoleClass=$($r.Class)" }
  }
  Verdict @($AllRoles).Count $bad 'lz-* roles'
}

Check 'IAM-05' 'Human roles cannot be assumed without MFA (bootstrap identity tries lz-admin in prod)' {
  Use-Bootstrap
  Expect-Denied (Aws sts assume-role --role-arn "arn:aws:iam::$($Acct.prod):role/lz-admin" --role-session-name no-mfa) 'AssumeRole lz-admin without MFA'
}

Check 'IAM-06' 'Pipeline role cannot be assumed without the ExternalId' {
  Use-Bootstrap
  Expect-Denied (Aws sts assume-role --role-arn "arn:aws:iam::$($Acct.prod):role/lz-ci-deployer" --role-session-name no-extid) 'AssumeRole lz-ci-deployer without ExternalId'
}

Check 'IAM-07' 'Control case: pipeline role works with the ExternalId and is who we think it is' {
  Use-CiRole $Acct.prod
  $r = Aws sts get-caller-identity --query Arn --output text
  if ($r.Text -like "*:assumed-role/lz-ci-deployer/*") { @{ Pass = $true; Detail = $r.Text } } else { @{ Pass = $false; Detail = "unexpected identity: $($r.Text)" } }
}

Check 'IAM-08' 'Pipeline role cannot create a role without the workload boundary' {
  Use-CiRole $Acct.prod
  Expect-Denied (Aws iam create-role --role-name app-assert-noboundary --assume-role-policy-document (Json-File $LambdaTrust)) 'iam:CreateRole without boundary'
}

Check 'IAM-09' 'Control case: pipeline role can create an app-* role that carries the workload boundary' {
  Use-CiRole $Acct.prod
  $r = Aws iam create-role --role-name app-assert-bounded --assume-role-policy-document (Json-File $LambdaTrust) --permissions-boundary "arn:aws:iam::$($Acct.prod):policy/lz-workload-boundary"
  if ($r.Ok) { $null = Aws iam delete-role --role-name app-assert-bounded }
  Expect-Allowed $r 'iam:CreateRole app-* with lz-workload-boundary'
}

Check 'IAM-10' 'Pipeline role cannot grant itself more (attach AdministratorAccess to a landing-zone role)' {
  Use-CiRole $Acct.prod
  Expect-Denied (Aws iam attach-role-policy --role-name lz-ci-deployer --policy-arn arn:aws:iam::aws:policy/AdministratorAccess) 'iam:AttachRolePolicy on lz-ci-deployer'
}

Check 'IAM-11' 'Guardrail boundary denies long-lived credentials (pipeline role tries iam:CreateUser)' {
  Use-CiRole $Acct.prod
  Expect-Denied (Aws iam create-user --user-name assert-backdoor-user) 'iam:CreateUser'
}

Check 'IAM-12' 'Guardrail boundary denies unapproved regions (pipeline role, eu-west-1)' {
  Use-CiRole $Acct.prod
  $ok = Aws ec2 describe-security-groups --region us-east-1 --query 'length(SecurityGroups)'
  if (-not $ok.Ok) { return @{ Pass = $false; Detail = "control call in us-east-1 failed: $($ok.Out | Select-Object -Last 1)" } }
  Expect-Denied (Aws ec2 describe-security-groups --region eu-west-1) 'ec2:DescribeSecurityGroups in eu-west-1 (allowed in us-east-1)'
}

Check 'IAM-13' 'Account-wide S3 Block Public Access is fully on in every account' {
  $bad = foreach ($a in $Members) {
    Use-Account $Acct[$a]
    $env:AWS_ENDPOINT_URL_S3_CONTROL = 'http://localhost.localstack.cloud:4566'
    $c = (Aws-Json s3control get-public-access-block --account-id $Acct[$a]).PublicAccessBlockConfiguration
    if (-not ($c.BlockPublicAcls -and $c.BlockPublicPolicy -and $c.IgnorePublicAcls -and $c.RestrictPublicBuckets)) { $a }
  }
  Verdict $Members.Count $bad 'accounts'
}

Check 'IAM-14' 'EBS encryption by default is on in every account' {
  $bad = foreach ($a in $Members) {
    Use-Account $Acct[$a]
    if (-not (Aws-Json ec2 get-ebs-encryption-by-default).EbsEncryptionByDefault) { $a }
  }
  Verdict $Members.Count $bad 'accounts'
}

Check 'IAM-15' 'Password policy: 14+ characters, complexity, reuse prevention' {
  $bad = foreach ($a in $Members) {
    Use-Account $Acct[$a]
    $p = (Aws-Json iam get-account-password-policy).PasswordPolicy
    if (-not ($p.MinimumPasswordLength -ge 14 -and $p.RequireSymbols -and $p.RequireNumbers -and $p.PasswordReusePrevention -ge 24)) { $a }
  }
  Verdict $Members.Count $bad 'accounts'
}

# =====================================================================
Section 'logging'
# =====================================================================

$TrailBuckets = Tf-OutJson trail_buckets
$CentralBucket = Tf-Out log_bucket
# account key => bucket, plus the central bucket (owned by log_archive)
$LogBuckets = @{}
if ($TrailBuckets) { foreach ($a in $Members) { $LogBuckets[$TrailBuckets.$a] = $a } }
if ($CentralBucket) { $LogBuckets[$CentralBucket] = 'log_archive' }

Check 'LOG-01' 'Every account has a multi-region, validated, KMS-encrypted trail that is logging' {
  $n = 0
  $bad = foreach ($a in $Members) {
    Use-Account $Acct[$a]
    $t = @((Aws-Json cloudtrail describe-trails).trailList | Where-Object { $_.Name -eq 'lz-trail' })
    if ($t.Count -ne 1) { "$a has $($t.Count) lz-trail"; continue }
    $n++
    $s = Aws-Json cloudtrail get-trail-status --name lz-trail
    if (-not $s.IsLogging) { "$a not logging" }
    if (-not $t[0].IsMultiRegionTrail) { "$a not multi-region" }
    if (-not $t[0].LogFileValidationEnabled) { "$a no log file validation" }
    if (-not $t[0].KmsKeyId) { "$a no KMS key" }
    if (-not $t[0].IncludeGlobalServiceEvents) { "$a no global service events" }
  }
  Verdict $n $bad 'trails'
}

Check 'LOG-02' 'Every log bucket is versioned, Object-Locked (COMPLIANCE, 365+ days), KMS-encrypted and blocks public access' {
  $bad = foreach ($b in $LogBuckets.Keys) {
    Use-Account $Acct[$LogBuckets[$b]]
    if ((Aws-Json s3api get-bucket-versioning --bucket $b).Status -ne 'Enabled') { "$b versioning" }
    $l = (Aws-Json s3api get-object-lock-configuration --bucket $b).ObjectLockConfiguration
    if ($l.ObjectLockEnabled -ne 'Enabled' -or $l.Rule.DefaultRetention.Mode -ne 'COMPLIANCE' -or $l.Rule.DefaultRetention.Days -lt 365) { "$b object lock" }
    $e = (Aws-Json s3api get-bucket-encryption --bucket $b).ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault
    if ($e.SSEAlgorithm -ne 'aws:kms' -or -not $e.KMSMasterKeyID) { "$b encryption" }
    $p = (Aws-Json s3api get-public-access-block --bucket $b).PublicAccessBlockConfiguration
    if (-not ($p.BlockPublicAcls -and $p.BlockPublicPolicy -and $p.IgnorePublicAcls -and $p.RestrictPublicBuckets)) { "$b public access block" }
  }
  Verdict $LogBuckets.Count $bad 'log buckets'
}

$script:LockedKey = "assertions/lock-test-$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss')).txt"
Check 'LOG-03' 'Object Lock is enforced: the bucket owner (account root) cannot delete a log object version' {
  Use-Account $Acct.log_archive
  $body = [IO.Path]::GetTempFileName(); [IO.File]::WriteAllText($body, 'immutability test')
  $put = Aws-Json s3api put-object --bucket $CentralBucket --key $script:LockedKey --body $body
  Remove-Item $body -ErrorAction SilentlyContinue
  if (-not $put.VersionId) { return @{ Pass = $false; Detail = 'could not write the test object' } }
  Expect-Denied (Aws s3api delete-object --bucket $CentralBucket --key $script:LockedKey --version-id $put.VersionId) 'DeleteObject on a locked version as bucket-owner root'
}

Check 'LOG-04' 'Every log bucket policy denies non-TLS access (defined; LocalStack does not evaluate aws:SecureTransport)' {
  $bad = foreach ($b in $LogBuckets.Keys) {
    Use-Account $Acct[$LogBuckets[$b]]
    $pol = (Aws-Json s3api get-bucket-policy --bucket $b).Policy | ConvertFrom-Json
    $tls = @($pol.Statement | Where-Object { $_.Effect -eq 'Deny' -and $_.Condition.Bool.'aws:SecureTransport' -eq 'false' })
    if ($tls.Count -eq 0) { $b }
  }
  Verdict $LogBuckets.Count $bad 'log bucket policies'
}

Check 'LOG-05' 'Log objects cannot be read by a workload identity (pipeline role in prod reads the central bucket)' {
  Use-CiRole $Acct.prod
  Expect-Denied (Aws s3api get-object --bucket $CentralBucket --key $script:LockedKey "$env:TEMP\lz-should-not-exist.txt") 'GetObject on the log archive as lz-ci-deployer'
}

Check 'LOG-06' 'CloudTrail is actually delivering log files to every trail bucket' {
  $bad = foreach ($a in $Members) {
    Use-Account $Acct[$a]
    $r = Aws-Json s3api list-objects-v2 --bucket $TrailBuckets.$a --prefix "AWSLogs/$($Acct[$a])/CloudTrail/" --max-keys 5
    if (@($r.Contents | Where-Object { $_.Key -like '*.json.gz' }).Count -eq 0) { "$a ($($TrailBuckets.$a)) has no log files" }
  }
  Verdict $Members.Count $bad 'trail buckets'
}

# =====================================================================
Section 'data-protection'
# =====================================================================

# Every enabled customer managed key in an account (cached: each CLI call is slow).
$script:KeyCache = @{}
function Get-CustomerKeys([string]$AccountKey) {
  Use-Account $Acct[$AccountKey]
  if (-not $script:KeyCache.ContainsKey($AccountKey)) {
    $script:KeyCache[$AccountKey] = @(foreach ($k in @((Aws-Json kms list-keys).Keys)) {
        $m = (Aws-Json kms describe-key --key-id $k.KeyId).KeyMetadata
        if ($m.KeyManager -eq 'CUSTOMER' -and $m.KeyState -eq 'Enabled') { $m }
      })
  }
  return $script:KeyCache[$AccountKey]
}

Check 'KMS-01' 'Every customer managed key in every account has rotation enabled' {
  $n = 0
  $bad = foreach ($a in $Members) {
    foreach ($m in @(Get-CustomerKeys $a)) {
      $n++
      if (-not (Aws-Json kms get-key-rotation-status --key-id $m.KeyId).KeyRotationEnabled) { "$a/$($m.KeyId)" }
    }
  }
  Verdict $n $bad 'customer managed keys'
}

Check 'KMS-02' 'Key policies separate administration from use: no kms:*, admins hold no crypto actions, wildcard principals are pinned to one service and this account' {
  $n = 0
  $crypto = 'kms:Decrypt', 'kms:Encrypt', 'kms:GenerateDataKey*', 'kms:GenerateDataKey', 'kms:ReEncrypt*'
  $bad = foreach ($a in $Members) {
    foreach ($m in @(Get-CustomerKeys $a)) {
      $n++
      $pol = (Aws-Json kms get-key-policy --key-id $m.KeyId --policy-name default).Policy | ConvertFrom-Json
      foreach ($s in @($pol.Statement)) {
        $actions = @($s.Action)
        if ($actions -contains 'kms:*' -or $actions -contains '*') { "$a/$($m.KeyId) grants kms:*" }
        if ($s.Sid -eq 'KeyAdministrationNoCryptoUse' -and @($actions | Where-Object { $crypto -contains $_ }).Count -gt 0) { "$a/$($m.KeyId) admins can use the key" }
        $wild = ($s.Principal -eq '*' -or $s.Principal.AWS -eq '*')
        if ($wild -and -not ($s.Condition.StringEquals.'kms:ViaService' -and $s.Condition.StringEquals.'kms:CallerAccount')) { "$a/$($m.KeyId) open principal in $($s.Sid)" }
      }
      if (@($pol.Statement | Where-Object { $_.Sid -eq 'KeyAdministrationNoCryptoUse' }).Count -ne 1) { "$a/$($m.KeyId) has no admin statement" }
    }
  }
  Verdict $n $bad 'key policies'
}

$ProdKeys = Tf-OutJson prod_key_ids

Check 'KMS-03' 'One key per data class in prod (rds, dynamodb, s3, secrets, backup)' {
  $want = 'rds', 'dynamodb', 's3', 'secrets', 'backup'
  $bad = foreach ($c in $want) { if (-not $ProdKeys.$c) { "missing $c" } }
  $ids = @($want | ForEach-Object { $ProdKeys.$_ } | Where-Object { $_ } | Select-Object -Unique)
  if ($ids.Count -ne $want.Count) { $bad = @($bad) + 'keys are shared between data classes' }
  Verdict $ids.Count $bad 'distinct data-class keys'
}

Check 'KMS-04' 'A workload identity cannot schedule deletion of a data key (pipeline role in prod)' {
  Use-CiRole $Acct.prod
  Expect-Denied (Aws kms schedule-key-deletion --key-id $ProdKeys.secrets --pending-window-in-days 7) 'kms:ScheduleKeyDeletion'
}

Check 'KMS-05' 'A workload identity cannot use a data key directly, outside its service (pipeline role calls kms:GenerateDataKey)' {
  Use-CiRole $Acct.prod
  Expect-Denied (Aws kms generate-data-key --key-id $ProdKeys.secrets --key-spec AES_256) 'kms:GenerateDataKey'
}

Check 'BKP-01' 'Backup plan keeps 35 days and copies every backup to a separate vault; both vaults exist' {
  Use-Account $Acct.prod
  $vaults = Tf-OutJson prod_backup_vaults
  $bad = @()
  foreach ($v in $vaults.primary, $vaults.copy) {
    if (-not (Aws-Json backup describe-backup-vault --backup-vault-name $v).BackupVaultArn) { $bad += "vault $v missing" }
  }
  $plans = @((Aws-Json backup list-backup-plans).BackupPlansList)
  $n = 0
  foreach ($p in $plans) {
    foreach ($r in @((Aws-Json backup get-backup-plan --backup-plan-id $p.BackupPlanId).BackupPlan.Rules)) {
      $n++
      if ($r.TargetBackupVaultName -ne $vaults.primary) { $bad += "$($r.RuleName) targets $($r.TargetBackupVaultName)" }
      $copies = @($r.CopyActions | Where-Object { $_.DestinationBackupVaultArn -like "*:backup-vault:$($vaults.copy)" })
      if ($copies.Count -eq 0) { $bad += "$($r.RuleName) has no copy to $($vaults.copy)" }
      if ($r.Lifecycle.DeleteAfterDays -lt 35) { $bad += "$($r.RuleName) retention under 35 days" }
    }
    $sel = @((Aws-Json backup list-backup-selections --backup-plan-id $p.BackupPlanId).BackupSelectionsList)
    if ($sel.Count -eq 0) { $bad += "plan $($p.BackupPlanName) selects nothing" }
  }
  Verdict $n $bad 'backup rules'
}

Skip 'BKP-03' 'Backup vaults are encrypted with the backup customer managed key' 'LocalStack accepts kms_key_arn on CreateBackupVault but does not store or return EncryptionKeyArn. Defined in modules/data-protection; verify on real AWS with: aws backup describe-backup-vault (EncryptionKeyArn).'

Skip 'BKP-02' 'Backup Vault Lock (compliance mode)' 'LocalStack does not implement PutBackupVaultLockConfiguration. Defined in modules/data-protection, on by default; verify on real AWS with: aws backup describe-backup-vault (Locked = true).'

# =====================================================================
Section 'network'
# =====================================================================

$VpcIds = Tf-OutJson vpc_ids
$NetAccounts = 'prod', 'nonprod', 'network'

# One describe call per resource type per account, cached, filtered to the landing-zone VPC.
$script:Net = @{}
function Net([string]$AccountKey) {
  if (-not $script:Net.ContainsKey($AccountKey)) {
    Use-Account $Acct[$AccountKey]
    $vpc = $VpcIds.$AccountKey
    $f = "Name=vpc-id,Values=$vpc"
    $script:Net[$AccountKey] = [pscustomobject]@{
      Vpc       = $vpc
      Subnets   = @((Aws-Json ec2 describe-subnets --filters $f).Subnets)
      Routes    = @((Aws-Json ec2 describe-route-tables --filters $f).RouteTables)
      Groups    = @((Aws-Json ec2 describe-security-groups --filters $f).SecurityGroups)
      AllGroups = @((Aws-Json ec2 describe-security-groups).SecurityGroups)
      Endpoints = @((Aws-Json ec2 describe-vpc-endpoints --filters $f).VpcEndpoints)
      Nat       = @((Aws-Json ec2 describe-nat-gateways).NatGateways | Where-Object { $_.State -ne 'deleted' })
      Acls      = @((Aws-Json ec2 describe-network-acls --filters $f).NetworkAcls)
      FlowLogs  = @((Aws-Json ec2 describe-flow-logs).FlowLogs)
    }
  }
  return $script:Net[$AccountKey]
}
function Tag($Resource, [string]$Key) { return ($Resource.Tags | Where-Object { $_.Key -eq $Key }).Value }

Check 'NET-01' 'Each VPC has public, private-app and isolated-data subnets in 2 AZs, and no subnet auto-assigns public IPs' {
  $n = 0
  $bad = foreach ($a in $NetAccounts) {
    $s = (Net $a).Subnets; $n += $s.Count
    foreach ($tier in 'public', 'app', 'data') {
      $t = @($s | Where-Object { (Tag $_ 'Tier') -eq $tier })
      if ($t.Count -ne 2 -or @($t.AvailabilityZone | Select-Object -Unique).Count -ne 2) { "$a/$tier has $($t.Count) subnets" }
    }
    foreach ($x in $s) { if ($x.MapPublicIpOnLaunch) { "$a/$($x.SubnetId) maps public IPs" } }
  }
  Verdict $n $bad 'subnets'
}

Check 'NET-02' 'Only the public tier has a route to the internet; app and data tiers have no default route' {
  $n = 0
  $bad = foreach ($a in $NetAccounts) {
    foreach ($rt in @((Net $a).Routes | Where-Object { Tag $_ 'Tier' })) {
      $n++
      $tier = Tag $rt 'Tier'
      $default = @($rt.Routes | Where-Object { $_.DestinationCidrBlock -eq '0.0.0.0/0' -or $_.DestinationIpv6CidrBlock -eq '::/0' })
      if ($tier -eq 'public' -and $default.Count -ne 1) { "$a public tier has no internet route" }
      if ($tier -ne 'public' -and $default.Count -gt 0) { "$a/$tier has a default route" }
      if ($tier -eq 'data' -and @($rt.Routes | Where-Object { $_.GatewayId -ne 'local' }).Count -gt 0) { "$a data tier has a non-local route" }
    }
  }
  $v = Verdict $n $bad 'tier route tables'
  if ($n -ne 9) { $v.Pass = $false; $v.Detail += '; expected 9 (3 tiers x 3 VPCs)' }
  $v
}

Check 'NET-03' 'No NAT gateways: nothing in a landing-zone VPC can open a connection to the internet' {
  $bad = foreach ($a in $NetAccounts) { if ((Net $a).Nat.Count -gt 0) { "$a has $((Net $a).Nat.Count) NAT gateways" } }
  Verdict $NetAccounts.Count $bad 'accounts'
}

Check 'NET-04' 'No security group in any account allows 0.0.0.0/0 ingress, except the ALB group on 443' {
  $n = 0
  $bad = foreach ($a in $NetAccounts) {
    foreach ($g in (Net $a).AllGroups) {
      $n++
      foreach ($p in @($g.IpPermissions)) {
        $open = @($p.IpRanges | Where-Object { $_.CidrIp -eq '0.0.0.0/0' }).Count + @($p.Ipv6Ranges | Where-Object { $_.CidrIpv6 -eq '::/0' }).Count
        if ($open -eq 0) { continue }
        $isAlb443 = ((Tag $g 'lz:public-ingress') -eq 'allowed-443' -and $p.IpProtocol -eq 'tcp' -and $p.FromPort -eq 443 -and $p.ToPort -eq 443)
        if (-not $isAlb443) { "$a/$($g.GroupName) $($p.IpProtocol)/$($p.FromPort)-$($p.ToPort)" }
      }
    }
  }
  Verdict $n $bad 'security groups'
}

Check 'NET-05' 'Security groups are chained by group ID: app only from ALB, data only from app, endpoints only from app; no CIDR ingress' {
  $n = 0
  $bad = foreach ($a in $NetAccounts) {
    $g = @{}; foreach ($x in (Net $a).Groups) { $g[$x.GroupName] = $x }
    $name = if ($a -eq 'network') { 'hub' } else { $a }
    $expect = @{ "$name-app" = "$name-alb"; "$name-data" = "$name-app"; "$name-endpoints" = "$name-app" }
    foreach ($target in $expect.Keys) {
      $n++
      $sg = $g[$target]
      if (-not $sg) { "$a/$target missing"; continue }
      if (@($sg.IpPermissions).Count -eq 0) { "$a/$target has no ingress rule" }
      foreach ($p in @($sg.IpPermissions)) {
        if (@($p.IpRanges).Count -gt 0 -or @($p.Ipv6Ranges).Count -gt 0) { "$a/$target has CIDR ingress" }
        foreach ($pair in @($p.UserIdGroupPairs)) { if ($pair.GroupId -ne $g[$expect[$target]].GroupId) { "$a/$target allows $($pair.GroupId)" } }
      }
    }
    if (@($g["$name-data"].IpPermissionsEgress).Count -gt 0) { "$a/$name-data has egress rules" }
    foreach ($src in "$name-alb", "$name-app") {
      foreach ($p in @($g[$src].IpPermissionsEgress)) { if (@($p.IpRanges).Count -gt 0 -or @($p.Ipv6Ranges).Count -gt 0) { "$a/$src has CIDR egress" } }
    }
  }
  Verdict $n $bad 'chained security groups'
}

Check 'NET-06' 'The default security group of each VPC has no rules' {
  $n = 0
  $bad = foreach ($a in $NetAccounts) {
    foreach ($sg in @((Net $a).Groups | Where-Object { $_.GroupName -eq 'default' })) {
      $n++
      if (@($sg.IpPermissions).Count -gt 0 -or @($sg.IpPermissionsEgress).Count -gt 0) { "$a default group has rules" }
    }
  }
  Verdict $n $bad 'default security groups'
}

Check 'NET-07' 'Each VPC has endpoints for S3, DynamoDB (gateway) and Secrets Manager, KMS, STS (interface)' {
  $n = 0
  $bad = foreach ($a in $NetAccounts) {
    $eps = (Net $a).Endpoints; $n += $eps.Count
    foreach ($svc in 's3', 'dynamodb', 'secretsmanager', 'kms', 'sts') {
      $e = @($eps | Where-Object { $_.ServiceName -like "*.$svc" })
      if ($e.Count -ne 1) { "$a missing $svc endpoint"; continue }
      $want = if ($svc -in 's3', 'dynamodb') { 'Gateway' } else { 'Interface' }
      if ($e[0].VpcEndpointType -ne $want) { "$a/$svc is $($e[0].VpcEndpointType)" }
    }
  }
  Verdict $n $bad 'VPC endpoints'
}

Check 'NET-08' 'Each VPC sends ALL-traffic flow logs to the log-archive bucket' {
  $n = 0
  $bad = foreach ($a in $NetAccounts) {
    $fl = @((Net $a).FlowLogs | Where-Object { $_.ResourceId -eq (Net $a).Vpc })
    $n += $fl.Count
    if ($fl.Count -eq 0) { "$a has no flow log"; continue }
    if ($fl[0].TrafficType -ne 'ALL') { "$a traffic type $($fl[0].TrafficType)" }
    if ($fl[0].LogDestination -notlike "arn:aws:s3:::$CentralBucket/flow-logs/*") { "$a destination $($fl[0].LogDestination)" }
  }
  Verdict $n $bad 'flow logs'
}

Check 'NET-09' 'The data-tier network ACL only admits the app subnets on the database port' {
  $n = 0
  $bad = foreach ($a in $NetAccounts) {
    $appCidrs = @((Net $a).Subnets | Where-Object { (Tag $_ 'Tier') -eq 'app' } | ForEach-Object { $_.CidrBlock })
    foreach ($acl in @((Net $a).Acls | Where-Object { (Tag $_ 'Tier') -eq 'data' })) {
      $n++
      if (@($acl.Associations).Count -ne 2) { "$a data ACL is on $(@($acl.Associations).Count) subnets" }
      foreach ($e in @($acl.Entries | Where-Object { $_.RuleAction -eq 'allow' })) {
        if ($appCidrs -notcontains $e.CidrBlock) { "$a data ACL allows $($e.CidrBlock)" }
        if (-not $e.Egress -and ($e.PortRange.From -ne 5432 -or $e.PortRange.To -ne 5432)) { "$a data ACL admits ports $($e.PortRange.From)-$($e.PortRange.To)" }
      }
    }
  }
  Verdict $n $bad 'data-tier network ACLs'
}

Skip 'NET-10' 'Network paths are actually blocked (packet-level)' 'LocalStack stores security groups, routes and ACLs but does not filter traffic. NET-01..09 prove the configuration; verify reachability on real AWS with VPC Reachability Analyzer.'

# =====================================================================
Section 'workload'
# =====================================================================

$W = Tf-OutJson prod_workload
$ProdSg = Tf-OutJson prod_security_groups

Check 'WKL-01' 'RDS is private, encrypted with the rds key, deletion-protected, backed up, multi-AZ, and sits in the data tier' {
  Use-Account $Acct.prod
  $dbs = @((Aws-Json rds describe-db-instances).DBInstances)
  $bad = foreach ($d in $dbs) {
    $id = $d.DBInstanceIdentifier
    if ($d.PubliclyAccessible) { "$id is publicly accessible" }
    if (-not $d.StorageEncrypted) { "$id not encrypted" }
    if ($d.KmsKeyId -notlike "*$($ProdKeys.rds)") { "$id not using the rds key" }
    if (-not $d.DeletionProtection) { "$id no deletion protection" }
    if ($d.BackupRetentionPeriod -lt 7) { "$id backup retention $($d.BackupRetentionPeriod)" }
    if (-not $d.MultiAZ) { "$id single-AZ" }
    if (-not $d.IAMDatabaseAuthenticationEnabled) { "$id no IAM auth" }
    $sgs = @($d.VpcSecurityGroups | ForEach-Object { $_.VpcSecurityGroupId })
    if ($sgs.Count -ne 1 -or $sgs[0] -ne $ProdSg.data) { "$id security groups: $($sgs -join ',')" }
    $dataSubnets = @((Net 'prod').Subnets | Where-Object { (Tag $_ 'Tier') -eq 'data' } | ForEach-Object { $_.SubnetId })
    foreach ($s in @($d.DBSubnetGroup.Subnets)) { if ($dataSubnets -notcontains $s.SubnetIdentifier) { "$id uses non-data subnet $($s.SubnetIdentifier)" } }
  }
  Verdict $dbs.Count $bad 'RDS instances'
}

Check 'WKL-02' 'DynamoDB tables use the dynamodb key, point-in-time recovery and deletion protection' {
  Use-Account $Acct.prod
  $tables = @((Aws-Json dynamodb list-tables).TableNames)
  $bad = foreach ($t in $tables) {
    $d = (Aws-Json dynamodb describe-table --table-name $t).Table
    if ($d.SSEDescription.SSEType -ne 'KMS' -or $d.SSEDescription.KMSMasterKeyArn -notlike "*$($ProdKeys.dynamodb)") { "$t encryption" }
    if (-not $d.DeletionProtectionEnabled) { "$t deletion protection" }
    $pitr = (Aws-Json dynamodb describe-continuous-backups --table-name $t).ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus
    if ($pitr -ne 'ENABLED') { "$t point-in-time recovery" }
  }
  Verdict $tables.Count $bad 'DynamoDB tables'
}

Check 'WKL-03' 'Every bucket in every account blocks public access, is versioned, encrypted with KMS, and has a TLS-only policy' {
  $n = 0
  $bad = foreach ($a in $Members) {
    Use-Account $Acct[$a]
    foreach ($b in @((Aws-Json s3api list-buckets).Buckets | ForEach-Object { $_.Name })) {
      $n++
      $p = (Aws-Json s3api get-public-access-block --bucket $b).PublicAccessBlockConfiguration
      if (-not ($p.BlockPublicAcls -and $p.BlockPublicPolicy -and $p.IgnorePublicAcls -and $p.RestrictPublicBuckets)) { "$a/$b public access block" }
      if ((Aws-Json s3api get-bucket-versioning --bucket $b).Status -ne 'Enabled') { "$a/$b versioning" }
      $e = (Aws-Json s3api get-bucket-encryption --bucket $b).ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault
      if ($e.SSEAlgorithm -ne 'aws:kms') { "$a/$b encryption" }
      $pol = (Aws-Json s3api get-bucket-policy --bucket $b).Policy
      $tls = if ($pol) { @(($pol | ConvertFrom-Json).Statement | Where-Object { $_.Effect -eq 'Deny' -and $_.Condition.Bool.'aws:SecureTransport' -eq 'false' }) } else { @() }
      if ($tls.Count -eq 0) { "$a/$b no TLS-only statement" }
    }
  }
  Verdict $n $bad 'buckets'
}

Check 'WKL-04' 'Database credentials are in Secrets Manager under the secrets key, with a resource policy that denies everyone but the app role and break-glass' {
  Use-Account $Acct.prod
  $d = Aws-Json secretsmanager describe-secret --secret-id $W.secret_arn
  $bad = @()
  if ($d.KmsKeyId -notlike "*$($ProdKeys.secrets)") { $bad += 'not using the secrets key' }
  $pol = (Aws-Json secretsmanager get-resource-policy --secret-id $W.secret_arn).ResourcePolicy
  $deny = if ($pol) { @(($pol | ConvertFrom-Json).Statement | Where-Object { $_.Effect -eq 'Deny' -and $_.Condition.ArnNotEquals.'aws:PrincipalArn' }) } else { @() }
  if ($deny.Count -eq 0) { $bad += 'no deny-by-default resource policy' }
  elseif (@($deny[0].Condition.ArnNotEquals.'aws:PrincipalArn') -notcontains $W.app_role_arn) { $bad += 'app role is not an allowed reader' }
  Verdict 1 $bad 'secret'
}

Check 'WKL-05' 'A different workload identity cannot read the database credentials (pipeline role)' {
  Use-CiRole $Acct.prod
  Expect-Denied (Aws secretsmanager get-secret-value --secret-id $W.secret_arn) 'secretsmanager:GetSecretValue on the DB secret'
}

Check 'WKL-06' 'A different workload identity cannot read the data bucket, even though its IAM policy allows s3:* (bucket policy deny)' {
  Use-CiRole $Acct.prod
  Expect-Denied (Aws s3api get-object --bucket $W.bucket_name --key 'any/object.txt' "$env:TEMP\lz-should-not-exist.txt") 's3:GetObject on the data bucket as lz-ci-deployer'
}

Check 'WKL-07' 'The application runs in the private-app subnets with the app security group, under a role capped by the workload boundary' {
  Use-Account $Acct.prod
  $f = (Aws-Json lambda get-function-configuration --function-name $W.lambda_name)
  $bad = @()
  $appSubnets = @((Net 'prod').Subnets | Where-Object { (Tag $_ 'Tier') -eq 'app' } | ForEach-Object { $_.SubnetId })
  foreach ($s in @($f.VpcConfig.SubnetIds)) { if ($appSubnets -notcontains $s) { $bad += "subnet $s is not app tier" } }
  if (@($f.VpcConfig.SubnetIds).Count -ne 2) { $bad += 'not in 2 app subnets' }
  if (@($f.VpcConfig.SecurityGroupIds).Count -ne 1 -or $f.VpcConfig.SecurityGroupIds[0] -ne $ProdSg.app) { $bad += 'wrong security group' }
  $role = (Aws-Json iam get-role --role-name ($W.app_role_arn -split '/')[-1]).Role
  if ($role.PermissionsBoundary.PermissionsBoundaryArn -notlike '*:policy/lz-workload-boundary') { $bad += 'app role has no workload boundary' }
  Verdict 1 $bad 'Lambda function'
}

Check 'WKL-08' 'Control case: the application itself can read its secret and its table (invoke returns 200)' {
  Use-Account $Acct.prod
  $out = [IO.Path]::GetTempFileName()
  $r = Aws lambda invoke --function-name $W.lambda_name --cli-read-timeout 180 $out
  $payload = Get-Content $out -Raw -ErrorAction SilentlyContinue; Remove-Item $out -ErrorAction SilentlyContinue
  if (-not $r.Ok) { return @{ Pass = $false; Detail = "invoke failed: $($r.Out | Select-Object -Last 1)" } }
  if ($payload -match '"statusCode":\s*200' -and $payload -match 'app_admin') { @{ Pass = $true; Detail = 'app returned 200 and read its DB secret and table' } }
  else { @{ Pass = $false; Detail = "unexpected response: $($payload.Substring(0, [Math]::Min(300, $payload.Length)))" } }
}

# =====================================================================
Section 'edge'
# =====================================================================

$Edge = Tf-OutJson prod_edge

Check 'EDG-01' 'The ALB is the only load balancer, listens only on HTTPS with a TLS 1.2+ policy, drops invalid headers and is deletion-protected' {
  Use-Account $Acct.prod
  $lbs = @((Aws-Json elbv2 describe-load-balancers).LoadBalancers)
  $bad = @()
  foreach ($lb in $lbs) {
    $listeners = @((Aws-Json elbv2 describe-listeners --load-balancer-arn $lb.LoadBalancerArn).Listeners)
    if ($listeners.Count -eq 0) { $bad += "$($lb.LoadBalancerName) has no listener" }
    foreach ($l in $listeners) {
      if ($l.Protocol -ne 'HTTPS' -or $l.Port -ne 443) { $bad += "listener $($l.Protocol)/$($l.Port)" }
      if ($l.SslPolicy -notmatch 'TLS13|TLS-1-2') { $bad += "weak TLS policy $($l.SslPolicy)" }
      if (@($l.DefaultActions | Where-Object { $_.Type -eq 'fixed-response' -and $_.FixedResponseConfig.StatusCode -eq '403' }).Count -ne 1) { $bad += 'default action is not 403 (CloudFront bypass possible)' }
    }
    $attrs = @{}; foreach ($a in @((Aws-Json elbv2 describe-load-balancer-attributes --load-balancer-arn $lb.LoadBalancerArn).Attributes)) { $attrs[$a.Key] = $a.Value }
    if ($attrs['routing.http.drop_invalid_header_fields.enabled'] -ne 'true') { $bad += 'invalid headers not dropped' }
    if ($attrs['deletion_protection.enabled'] -ne 'true') { $bad += 'no deletion protection' }
    if (@($lb.SecurityGroups).Count -ne 1 -or $lb.SecurityGroups[0] -ne $ProdSg.alb) { $bad += 'ALB is not using the ALB security group' }
  }
  $v = Verdict $lbs.Count $bad 'load balancers'
  if ($lbs.Count -ne 1) { $v.Pass = $false; $v.Detail += '; expected exactly 1' }
  $v
}

Check 'EDG-02' 'WAF web ACLs (ALB and CloudFront) carry the managed rule groups and a rate limit; the ALB ACL is associated' {
  Use-Account $Acct.prod
  $bad = @(); $n = 0
  foreach ($scope in 'REGIONAL', 'CLOUDFRONT') {
    foreach ($s in @((Aws-Json wafv2 list-web-acls --scope $scope).WebACLs)) {
      $n++
      $acl = (Aws-Json wafv2 get-web-acl --scope $scope --name $s.Name --id $s.Id).WebACL
      $names = @($acl.Rules | ForEach-Object { $_.Name })
      foreach ($want in 'rate-limit-per-ip', 'AWSManagedRulesCommonRuleSet', 'AWSManagedRulesKnownBadInputsRuleSet', 'AWSManagedRulesSQLiRuleSet', 'AWSManagedRulesAmazonIpReputationList') {
        if ($names -notcontains $want) { $bad += "$($s.Name) missing $want" }
      }
    }
  }
  $assoc = Aws-Json wafv2 get-web-acl-for-resource --resource-arn $Edge.alb_arn
  if ($assoc.WebACL.ARN -ne $Edge.web_acl_arns.alb) { $bad += 'ALB has no web ACL associated' }
  $v = Verdict $n $bad 'web ACLs'
  if ($n -ne 2) { $v.Pass = $false; $v.Detail += '; expected 2' }
  $v
}

Check 'EDG-03' 'CloudFront forces HTTPS to viewers and to the origin, requires TLS 1.2, and has the WAF attached' {
  Use-Account $Acct.prod
  $d = (Aws-Json cloudfront get-distribution-config --id $Edge.distribution_id).DistributionConfig
  $bad = @()
  if ($d.DefaultCacheBehavior.ViewerProtocolPolicy -notin 'redirect-to-https', 'https-only') { $bad += "viewer policy $($d.DefaultCacheBehavior.ViewerProtocolPolicy)" }
  if ($d.ViewerCertificate.MinimumProtocolVersion -notlike 'TLSv1.2*') { $bad += "viewer TLS $($d.ViewerCertificate.MinimumProtocolVersion)" }
  foreach ($o in @($d.Origins.Items)) {
    if ($o.CustomOriginConfig.OriginProtocolPolicy -ne 'https-only') { $bad += "origin $($o.Id) not https-only" }
    if (@($o.CustomHeaders.Items | Where-Object { $_.HeaderName -eq 'X-Origin-Verify' }).Count -ne 1) { $bad += "origin $($o.Id) has no origin-verify header" }
  }
  if ($d.WebACLId -ne $Edge.web_acl_arns.cloudfront) { $bad += 'no WAF on the distribution' }
  Verdict 1 $bad 'CloudFront distribution'
}

Skip 'EDG-04' 'WAF and CloudFront actually filter requests' 'LocalStack stores WAF and CloudFront configuration but does not put them in the request path. Verify on real AWS by sending a request that the managed rules block (expect 403) and by calling the ALB directly without the origin header (expect 403).'

# =====================================================================
Section 'detection'
# =====================================================================

$Det = Tf-OutJson detection

Check 'DET-01' 'Findings table is KMS-encrypted with point-in-time recovery and deletion protection' {
  Use-Account $Acct.security
  $d = (Aws-Json dynamodb describe-table --table-name $Det.findings_table).Table
  $bad = @()
  if ($d.SSEDescription.SSEType -ne 'KMS') { $bad += 'not KMS-encrypted' }
  if (-not $d.DeletionProtectionEnabled) { $bad += 'no deletion protection' }
  if ((Aws-Json dynamodb describe-continuous-backups --table-name $Det.findings_table).ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus -ne 'ENABLED') { $bad += 'no point-in-time recovery' }
  Verdict 1 $bad 'table'
}

Check 'DET-02' 'Alert topic is KMS-encrypted' {
  Use-Account $Acct.security
  $bad = @()
  if (-not (Aws-Json sns get-topic-attributes --topic-arn $Det.alert_topic_arn).Attributes.KmsMasterKeyId) { $bad += 'topic not encrypted' }
  Verdict 1 $bad 'alert topic'
}

Check 'DET-03' 'The detector runs every minute and the security event bus rule exists' {
  Use-Account $Acct.security
  $bad = @()
  $poll = Aws-Json events describe-rule --name lz-detector-poll
  if ($poll.State -ne 'ENABLED' -or $poll.ScheduleExpression -ne 'rate(1 minute)') { $bad += 'poll rule not enabled at rate(1 minute)' }
  if (@((Aws-Json events list-targets-by-rule --rule lz-detector-poll).Targets).Count -ne 1) { $bad += 'poll rule has no target' }
  $fwd = Aws-Json events describe-rule --name lz-detector-forwarded-cloudtrail --event-bus-name lz-security-bus
  if ($fwd.State -ne 'ENABLED') { $bad += 'security bus rule missing' }
  Verdict 2 $bad 'event rules'
}

Check 'DET-04' 'The detector can collect evidence from all five accounts (direct invoke, no errors)' {
  Use-Account $Acct.security
  $out = [IO.Path]::GetTempFileName()
  $r = Aws lambda invoke --function-name $Det.function_name --cli-read-timeout 300 $out
  $payload = Get-Content $out -Raw -ErrorAction SilentlyContinue; Remove-Item $out -ErrorAction SilentlyContinue
  if (-not $r.Ok) { return @{ Pass = $false; Detail = "invoke failed: $($r.Out | Select-Object -Last 1)" } }
  $p = $null; try { $p = $payload | ConvertFrom-Json } catch { }
  if (-not $p -or $null -eq $p.events) { return @{ Pass = $false; Detail = "unexpected response: $($payload.Substring(0, [Math]::Min(300, $payload.Length)))" } }
  if (@($p.errors).Count -gt 0) { return @{ Pass = $false; Detail = "errors: $($p.errors -join '; ')" } }
  @{ Pass = $true; Detail = "polled 5 accounts, $($p.events) events read, no errors" }
}

Check 'DET-05' 'Nobody but the detector can use the evidence and response roles (pipeline role tries lz-security-response)' {
  Use-CiRole $Acct.prod
  Expect-Denied (Aws sts assume-role --role-arn "arn:aws:iam::$($Acct.prod):role/lz-security-response" --role-session-name not-the-detector) 'AssumeRole lz-security-response as lz-ci-deployer'
}

Skip 'DET-06' 'Cross-account EventBridge forwarding to the security bus' 'LocalStack rejects a rule target on another account''s event bus. The forwarder rules are defined (modules/detection/forwarder), on by default, off locally; the detector polls LookupEvents instead. Verify on real AWS that a member-account API call reaches the lz-security-bus rule.'

#<<LAYERS>>

# =====================================================================
$failed = @($script:Results | Where-Object { -not $_.Pass })
$total  = $script:Results.Count
Write-Host "`nAssertions: $($total - $failed.Count) passed, $($failed.Count) failed, $total total; $($script:Skipped.Count) not enforceable locally (skipped: $($script:Skipped -join ', '))"
if ($failed.Count -gt 0) { Write-Host "Failed: $($failed.Id -join ', ')" -ForegroundColor Red; exit 1 }
if ($total -eq 0) { Write-Host 'No checks ran.' -ForegroundColor Red; exit 1 }
exit 0
