# Scenario 5: Public bucket and data exfiltration
# ATT&CK: T1530 Data from Cloud Storage
. "$PSScriptRoot\common.ps1"

$Bucket = Tf-Out data_bucket
Use-Identity dev

Log 'Step 1: Legitimate access (should always work)'
$null = Attempt s3api head-object --bucket $Bucket --key customers.csv

Log 'Step 2: Turn off Block Public Access and publish the bucket'
$null = Attempt s3api delete-public-access-block --bucket $Bucket
$Doc = [IO.Path]::GetTempFileName()
[IO.File]::WriteAllText($Doc, (@{ Version = '2012-10-17'; Statement = @(@{ Effect = 'Allow'; Principal = '*'; Action = 's3:GetObject'; Resource = "arn:aws:s3:::$Bucket/*" }) } | ConvertTo-Json -Depth 5 -Compress))
$published = Attempt s3api put-bucket-policy --bucket $Bucket --policy "file://$Doc"
Remove-Item $Doc -ErrorAction SilentlyContinue
if (-not $published) { Finish blocked }

Log 'Step 3: Read the data with no credentials at all'
$Out = [IO.Path]::GetTempFileName()
$env:AWS_ACCESS_KEY_ID = ''; $env:AWS_SECRET_ACCESS_KEY = ''
& aws --no-cli-pager --no-sign-request s3api get-object --bucket $Bucket --key customers.csv $Out *> $null
if ($LASTEXITCODE -eq 0 -and (Get-Item $Out).Length -gt 0) {
  Fail "Anonymous read worked: $((Get-Content $Out -TotalCount 1))"
  Remove-Item $Out -ErrorAction SilentlyContinue
  Finish succeeded
}
Remove-Item $Out -ErrorAction SilentlyContinue
Good 'Policy was accepted but anonymous read is denied (Block Public Access)'
Finish blocked
