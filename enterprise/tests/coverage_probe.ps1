# Step 0 coverage probe: one cheap read-only call per service against LocalStack.
# Prints "service | OK/FAIL | command | first error line". Used to build COVERAGE.md.
$ErrorActionPreference = 'Continue'
$env:AWS_ENDPOINT_URL            = 'http://localhost:4566'
$env:AWS_DEFAULT_REGION          = 'us-east-1'
$env:AWS_ACCESS_KEY_ID           = 'test'
$env:AWS_SECRET_ACCESS_KEY       = 'test'
$env:AWS_CONFIG_FILE             = Join-Path $PSScriptRoot '.no-aws-config'
$env:AWS_SHARED_CREDENTIALS_FILE = Join-Path $PSScriptRoot '.no-aws-credentials'
$env:AWS_EC2_METADATA_DISABLED   = 'true'
Remove-Item Env:AWS_PROFILE, Env:AWS_SESSION_TOKEN -ErrorAction SilentlyContinue

$probes = [ordered]@{
  'EC2/VPC'         = 'ec2 describe-vpcs'
  'VPC endpoints'   = 'ec2 describe-vpc-endpoint-services --max-results 5'
  'VPC Flow Logs'   = 'ec2 describe-flow-logs'
  'ELBv2'           = 'elbv2 describe-load-balancers'
  'ECS'             = 'ecs list-clusters'
  'Lambda'          = 'lambda list-functions'
  'API Gateway'     = 'apigateway get-rest-apis'
  'IAM'             = 'iam list-roles --max-items 1'
  'STS'             = 'sts get-caller-identity'
  'KMS'             = 'kms list-keys --limit 1'
  'Secrets Manager' = 'secretsmanager list-secrets --max-results 1'
  'ACM'             = 'acm list-certificates'
  'S3'              = 's3api list-buckets'
  'RDS'             = 'rds describe-db-instances'
  'DynamoDB'        = 'dynamodb list-tables'
  'CloudTrail'      = 'cloudtrail describe-trails'
  'CloudWatch Logs' = 'logs describe-log-groups --limit 1'
  'EventBridge'     = 'events list-rules --limit 1'
  'SNS'             = 'sns list-topics'
  'SQS'             = 'sqs list-queues'
  'SSM'             = 'ssm describe-parameters --max-results 1'
  'Backup'          = 'backup list-backup-vaults'
  'Route 53'        = 'route53 list-hosted-zones'
  'CloudFront'      = 'cloudfront list-distributions'
  'WAFv2'           = 'wafv2 list-web-acls --scope REGIONAL'
  'Cognito'         = 'cognito-idp list-user-pools --max-results 1'
  'Organizations'   = 'organizations list-roots'
  'GuardDuty'       = 'guardduty list-detectors'
  'Security Hub'    = 'securityhub describe-hub'
}

foreach ($svc in $probes.Keys) {
  $cmd = $probes[$svc]
  $out = @(& aws --no-cli-pager ($cmd -split ' ') 2>&1 | ForEach-Object { "$_" })
  if ($LASTEXITCODE -eq 0) { "$svc | OK | aws $cmd |" }
  else {
    $err = $out | Where-Object { $_.Trim() -and $_ -notmatch '^System\.Management\.Automation\.' } | Select-Object -First 1
    "$svc | FAIL | aws $cmd | $err"
  }
}
