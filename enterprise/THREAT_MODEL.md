# Threat model

Scope: the landing zone in `enterprise\` as deployed to LocalStack. Method: trust
boundaries first, then the ten threats most likely to matter, each tied to the
control that answers it and the test that proves the control.

Test IDs refer to `tests\security_assertions.ps1` (ORG, IAM, LOG, KMS, BKP, NET, WKL,
EDG, DET) and `tests\attack_simulation.ps1` (A1 to A9). "Local proof" says how far
LocalStack could take the proof; see `COVERAGE.md` for every gap.

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| Production database and its credentials | RDS and `prod/db/master` in workload-prod | Customer data; the secret is the shortest path to it. |
| Application data | DynamoDB `prod-orders`, S3 `prod-data-*` | Customer data. |
| Audit logs | Object-Locked buckets, CloudTrail in every account | Without them nothing below can be detected or investigated. |
| KMS keys | One per data class in prod, plus logs and security keys | Losing a key loses the data; using a key reads the data. |
| The landing zone itself | `lz-*` roles, boundaries, SCPs, detector | Whoever changes these changes every other control. |

## Trust boundaries

| # | Boundary | What crosses it | Control at the boundary |
|---|---|---|---|
| TB1 | Internet to edge | HTTPS requests | CloudFront + WAF, ALB on 443 only, origin-verify header |
| TB2 | Public tier to app tier | ALB to application | Security group chain (ALB group to app group only) |
| TB3 | App tier to data tier | Application to database | Security group chain, data NACL, no route out of the data tier |
| TB4 | Workload to AWS control plane | API calls from the app and the pipeline | Least-privilege roles, permission boundaries, VPC endpoints |
| TB5 | Identity hub to every account | `sts:AssumeRole` | MFA for humans; exact principal plus ExternalId or PrincipalArn for machines |
| TB6 | Member accounts to log-archive | Log delivery (write-only) | Service-principal bucket policy, Object Lock, read restricted to security roles |
| TB7 | Security-tooling to member accounts | Evidence reads, containment | `lz-security-audit` (read-only) and `lz-security-response` (can only remove SG ingress), assumable only by the detector |
| TB8 | Organization to accounts | SCPs | Deny tampering, leaving, unapproved regions, long-lived credentials; applies to account root too |
| TB9 | Operator workstation to LocalStack | Terraform, tests | Lab only: Terraform runs as each account's root. On real AWS this is a pipeline deploy role (see residual risks). |

## Top 10 threats

| # | Threat | ATT&CK | Preventive control | Detective / responsive control | Test | Local proof |
|---|---|---|---|---|---|---|
| T1 | A compromised pipeline or workload identity turns off audit logging to hide what follows. | T1562.008 | Guardrail boundary denies CloudTrail tampering on every role; SCP denies it for the whole account, root included. | ENT-001 on the event, plus a state check every minute for any trail that is not logging. | A1, A2, ORG-03, LOG-01 | Prevention proven. The event-based finding cannot fire (LocalStack does not record CloudTrail's own API calls); the state check is the local detection path. |
| T2 | The compromised identity escalates: attaches AdministratorAccess, edits its own role, or creates a new unbounded role. | T1098, T1098.003 | Boundary denies changes to any `lz-*` role and denies `CreateRole` without an approved boundary; pipeline may only create `app-*` roles carrying `lz-workload-boundary`. | ENT-002 (IAM change), ENT-003 (admin attach). | A4, A5, IAM-08, IAM-09, IAM-10 | Proven: both denied, both reported. |
| T3 | Stolen human credentials are used to assume an admin or break-glass role. | T1078.004 | Every human role requires MFA with a maximum age; break-glass 15 minutes. No IAM users or access keys exist to steal (SCP + boundary), except the labelled lab bootstrap user. | ENT-008 on any break-glass use. | A9, IAM-01, IAM-02, IAM-05, ORG-06, IAM-11 | Prevention proven. Successful MFA use cannot be simulated locally. |
| T4 | A different workload identity reads the production database credentials. | T1555.006 | Secret resource policy denies everyone except the app role and break-glass; the secrets key is usable only through Secrets Manager; the pipeline role has no `GetSecretValue`. | ENT-007: any read outside the allowlist. | A6, WKL-04, WKL-05, KMS-05 | Proven: denied and reported. |
| T5 | Someone opens a security group to the internet (mistake or foothold). | T1562.007 | Not prevented for delivery roles, by design: they manage security groups. Tier chaining limits what a new rule can reach. | ENT-004, then automatic containment: the detector confirms the rule exists and revokes it through `lz-security-response`. | A3, NET-04, NET-05 | Proven end to end: rule created, finding raised, rule removed. Packet filtering itself is not emulated. |
| T6 | Data is exposed by making a bucket public. | T1530 | Block Public Access on every bucket and at account level; data bucket policy denies object access to all but the app role. | ENT-005 on public policies, public ACLs and any weakening of Block Public Access. | A7, WKL-03, WKL-06, WKL-09, IAM-13 | A7 is prevented: the guardrail boundary denies bucket policy, ACL and Block Public Access changes for all but the MFA-gated roles. |
| T7 | Data is destroyed: KMS key scheduled for deletion, database or table deleted, backups removed. | T1485 | Key admin is separate from key use and no workload identity holds it; 30-day deletion window; deletion protection on RDS, DynamoDB and the ALB; backups copied to a second vault under Vault Lock. | ENT-006 on key deletion or disabling. | A8, KMS-02, KMS-04, WKL-01, WKL-02, BKP-01 | Prevention and detection proven for the key. Vault Lock is not implemented by LocalStack (BKP-02 skipped). |
| T8 | Audit logs are deleted or altered after the fact. | T1070, T1565.001 | Object Lock in COMPLIANCE mode on every log bucket (the bucket owner's root cannot delete a version), versioning, log file validation, reads limited to security roles. | CloudTrail records S3 management calls on the log account. | LOG-02, LOG-03, LOG-05, LOG-06 | Proven: root delete of a locked version is refused. |
| T9 | Activity moves to a region nobody watches, or the account leaves the organization. | T1535 | SCP and boundary deny unapproved regions and `LeaveOrganization`. Trails are multi-region. | None needed beyond the trail. | ORG-04, ORG-05, IAM-12, LOG-01 | Proven. |
| T10 | Direct attack on the application from the internet (injection, known-bad inputs, volumetric abuse, bypassing the edge). | T1190 | CloudFront and WAF managed rule groups with a rate limit; TLS 1.2+; the ALB refuses requests without the CloudFront origin header; the app tier has no internet route; the database is two security groups away. | WAF metrics (request logging is a next step). | EDG-01, EDG-02, EDG-03, NET-02, NET-03 | Configuration only. LocalStack does not put WAF, CloudFront or security groups in a request path (EDG-04, NET-10 skipped). |

## Residual risks and assumptions

- **Deployment identity.** Locally, Terraform is each account's root and the detector trusts root activity. On real AWS that must become one pipeline deploy role per account, and root activity must itself be a finding. The detector takes this list as `trusted_deployer_arns`.
- **The detector is a single Lambda in one account.** Disabling it blinds detection. Its role, table and schedule sit behind the same guardrails as everything else, but nothing watches the watcher yet (a heartbeat alarm is a next step).
- **Detection latency is up to a minute locally** (polling). On real AWS the event path is seconds.
- **A denied call and a successful call look alike in LocalStack's CloudTrail.** Findings are therefore attempt-level, and the simulation takes "prevented" from the API response.
- **Security-group changes are detected and reverted, not prevented.** For about a minute an opened rule exists.
- **Secrets rotation, WAF/ALB/CloudFront request logging, GuardDuty-class anomaly detection and cross-region copies** are not built. They are listed as next steps in `README.md`.
- **Terraform state** holds the bootstrap access key, the database password and the origin-verify secret. It is git-ignored; on real AWS use an encrypted remote backend with restricted access.
