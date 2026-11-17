# LocalStack coverage

What the enterprise landing zone could and could not prove on this machine.

- Emulator: LocalStack Pro 2026.10.7, started with `lstk`, `ENFORCE_IAM=1`
- Checked on: 2026-11-17
- Probe script: `tests\coverage_probe.ps1` (one read-only call per service)
- Every command below was run with `AWS_ENDPOINT_URL=http://localhost:4566` and LocalStack test credentials. Nothing touched real AWS.

**Reading the tables**

| Status | Meaning |
|---|---|
| supported | The API works and the security behaviour that matters here was observed. |
| partial | The API stores the configuration, but some behaviour is missing or not enforced. Config is asserted; behaviour must be verified on real AWS. |
| unsupported | The API or operation does not exist. Designed around it. |

## Services

| Service | Status | Probe command (`aws ...`) | Notes |
|---|---|---|---|
| IAM | supported | `iam list-roles --max-items 1` | Identity policies, permission boundaries (allow ceiling and explicit deny), `iam:PermissionsBoundary` and `iam:PassedToService` conditions are enforced. |
| STS | supported | `sts get-caller-identity` | Cross-account `AssumeRole`, `sts:ExternalId` and `aws:MultiFactorAuthPresent` trust conditions are enforced. MFA can never be satisfied locally, so human roles cannot be assumed at all. |
| Organizations | partial | `organizations list-roots` | Org, OUs, SCPs and attachments work, and **SCPs are enforced** on org-created accounts (even for the account root). `InviteAccountToOrganization` is not implemented, so the five fixed-ID accounts cannot join. |
| KMS | partial | `kms list-keys --limit 1` | Keys, rotation and key policies are stored. Access was denied by IAM identity policy in every test, so key-policy conditions (`kms:ViaService`, `kms:CallerAccount`) were never the deciding control. |
| Secrets Manager | supported | `secretsmanager list-secrets --max-results 1` | Resource policy stored; reads by other identities are denied. |
| S3 | partial | `s3api list-buckets` | Versioning, Block Public Access, SSE-KMS config and **Object Lock (COMPLIANCE) are enforced**. `aws:SecureTransport` is not evaluated: the TLS-only deny has no effect over `http://`. |
| S3 Control | supported | `s3control get-public-access-block --account-id <id>` | Needs a wildcard DNS name because the account ID goes in the hostname. Endpoint used: `http://localhost.localstack.cloud:4566` (resolves to 127.0.0.1). |
| CloudTrail | partial | `cloudtrail describe-trails` | Trails, S3 delivery and `LookupEvents` work. Four gaps: see "CloudTrail gaps" below. |
| EventBridge | partial | `events list-rules --limit 1` | Same-account rules, schedules and CloudTrail API events work (the target needs a resource policy). A rule target on another account's event bus is rejected. |
| Lambda | supported | `lambda list-functions` | Runs in Docker; role permissions are enforced. VPC settings are stored, not applied. |
| DynamoDB | supported | `dynamodb list-tables` | SSE-KMS, point-in-time recovery and deletion protection are stored and reported. |
| SNS / SQS | supported | `sns list-topics`, `sqs list-queues` | Topic to queue delivery works with a queue policy. |
| RDS | partial | `rds describe-db-instances` | Starts a real PostgreSQL. Encryption, Multi-AZ, IAM auth, backups and deletion protection are stored as attributes, not implemented. |
| EC2 / VPC | partial | `ec2 describe-vpcs` | VPCs, subnets, routes, security groups, NACLs, endpoints and flow logs are stored. **No traffic is filtered or routed.** |
| ELBv2 | partial | `elbv2 describe-load-balancers` | ALB, listener, rules and attributes are stored. Not a real data path here. |
| WAFv2 | partial | `wafv2 list-web-acls --scope REGIONAL` | Web ACLs and associations are stored. Requests are not inspected. |
| CloudFront | partial | `cloudfront list-distributions` | Distribution config is stored. Not in the request path. |
| ACM | partial | `acm list-certificates` | Certificate requests are accepted without validation. |
| Backup | partial | `backup list-backup-vaults` | Vaults, plans and selections work. Vault Lock is not implemented, the vault's KMS key is not stored, and no backup jobs run. |
| CloudWatch Logs | supported | `logs describe-log-groups --limit 1` | Used for Lambda log groups. |
| API Gateway, ECS, SSM, Route 53, Cognito | supported (not used) | `apigateway get-rest-apis`, `ecs list-clusters`, `ssm describe-parameters --max-results 1`, `route53 list-hosted-zones`, `cognito-idp list-user-pools --max-results 1` | Probed, not needed by this design. |
| GuardDuty | unsupported | `guardduty list-detectors` | "service is not currently supported". Replaced by the detection pipeline. |
| Security Hub | unsupported | `securityhub describe-hub` | "service is not currently supported". Replaced by the findings table. |
| Inspector, Macie, Detective, Security Lake | unsupported | not probed (excluded by the brief) | Not used. |

## Substitutions

| Not available locally | What this design does instead |
|---|---|
| GuardDuty, Security Hub | `modules/detection`: Lambda rules engine mapped to MITRE ATT&CK, findings in DynamoDB, alerts through SNS, one containment playbook. |
| Fixed-ID accounts as organization members | SCPs are defined and attached to every OU, and proven on an org-created canary account (`ORG-02..06`, attack `A2`). The same intent is enforced inside the five accounts by the `lz-guardrail-boundary` permissions boundary on every role (`IAM-08..12`). |
| Organization trail | One multi-region trail per account. |
| Cross-account EventBridge delivery | The detector polls `LookupEvents` in each account every minute through the read-only `lz-security-audit` role. |
| MFA devices and an identity provider | One lab-only IAM user, `lab-bootstrap`, that can only call `sts:AssumeRole` on `lz-*` roles. MFA-gated roles stay MFA-gated and are therefore unusable locally. |
| Human SSO / CI OIDC for pipelines | `lz-ci-deployer` trusts the bootstrap user's exact ARN plus an ExternalId. |

## Defined in code, not enforced locally

Each row is real Terraform. The "local" column is what `deploy.ps1` does; the default in `variables.tf` is always the real-AWS setting.

| Control | Where | Local behaviour | Verify on real AWS |
|---|---|---|---|
| Backup Vault Lock (compliance mode) | `modules/data-protection`, `enable_backup_vault_lock` (default `true`) | Off: `PutBackupVaultLockConfiguration` is not implemented. Assertion `BKP-02` is reported as SKIP. | `aws backup describe-backup-vault` shows `Locked: true`; deleting a recovery point early is refused. |
| Backup vault encryption with the backup key | `modules/data-protection` | Sent, but LocalStack drops `kms_key_arn`, so Terraform re-creates both vaults on every apply. `BKP-03` is SKIP. | `EncryptionKeyArn` on both vaults is the `prod-backup` key. |
| Central CloudTrail delivery to log-archive | `modules/logging`, `central_trail_delivery` (default `true`) | Off: LocalStack refuses a trail that names another account's KMS key. Each account's trail uses its own customer managed key and its own Object-Locked bucket, built from the same modules. The log-archive account's trail does use the central bucket. | All five trails deliver to `lz-log-archive-<id>`; the bucket policy conditions (`aws:SourceArn`, `s3:x-amz-acl`) and the key policy encryption-context condition admit them. |
| Cross-account event forwarding | `modules/detection/forwarder`, `enable_event_forwarding` (default `true`) | Off: cross-account bus targets are rejected. Detector polls instead. `DET-06` is SKIP. | An API call in a member account invokes the detector through `lz-security-bus` within seconds. |
| TLS-only bucket policies (`aws:SecureTransport`) | every bucket policy | Present and asserted (`LOG-04`, `WKL-03`), but not evaluated by LocalStack. | `aws s3api get-object --endpoint-url http://...` is denied. |
| Log-bucket read restriction and KMS key-policy conditions | `modules/logging`, `modules/cmk` | Reads by other identities were denied (`LOG-05`, `KMS-04`, `KMS-05`), but the denial came from IAM, not from these resource policies. | Give a test role `s3:*` and `kms:*` in IAM and confirm the bucket and key policies still deny it. |
| Network segmentation (routes, security groups, NACLs, endpoints) | `modules/network` | Configuration asserted (`NET-01..09`). No packets are filtered. `NET-10` is SKIP. | VPC Reachability Analyzer: internet to app tier and to data tier must be unreachable; app to database on 5432 reachable. |
| WAF, CloudFront, ALB origin-header check | `modules/edge` | Configuration asserted (`EDG-01..03`). Not in any request path. `EDG-04` is SKIP. | A request matching a managed rule returns 403; a direct call to the ALB without the origin header returns 403. |
| RDS encryption, Multi-AZ, IAM auth, `rds.force_ssl` | `modules/workload` | Stored as attributes (`WKL-01`). | Connect without TLS (must fail); check the storage key in the console. |
| Human-role MFA | `modules/identity` | The condition is enforced (`IAM-05`), but nobody can pass it locally, so the admin, developer, read-only, analyst and break-glass role *permissions* were never exercised. | Assume each role with MFA and run its allowed and denied actions. |

## CloudTrail gaps that affect detection

1. **CloudTrail's own API calls are not recorded.** `StopLogging`, `DeleteTrail` and the rest never appear in `LookupEvents` or on EventBridge. Rule `ENT-001` therefore cannot fire from an event locally. Compensating control: the detector checks `GetTrailStatus` on every run and raises `ENT-001` if a trail is not logging. Prevention of the call is proven (`ORG-03`, attacks `A1`, `A2`).
2. **Denied calls carry no `errorCode`.** A blocked attempt and a successful call look the same in the event. Findings therefore say "succeeded or unknown". Where it matters the detector checks real state before acting (it reads the security group before revoking anything), and the attack simulation takes "prevented" from the API response, not from the finding.
3. **`userIdentity.type` is always `Root`** and `userName` is missing. The detector identifies principals by ARN only.
4. **Event history is per account.** The detector assumes a role in each account to read it.

## Known local drift (cosmetic)

`terraform plan` after a clean apply still shows changes on LocalStack:

- `aws_backup_vault` x2 "must be replaced" (LocalStack does not store `kms_key_arn`).
- `aws_vpc_security_group_*_rule` in-place updates (LocalStack returns `account/sg-id` for `referenced_security_group_id`).

Neither changes a security setting.
