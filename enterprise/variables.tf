variable "region" {
  description = "Home region."
  type        = string
  default     = "us-east-1"
}

variable "approved_regions" {
  description = "Regions workloads may use. Everything else is denied by SCP and by the guardrail boundary."
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]
}

variable "localstack_endpoint" {
  description = "LocalStack edge endpoint. Every provider alias is pinned to it."
  type        = string
  default     = "http://localhost:4566"
}

variable "ci_external_id" {
  description = "ExternalId the lab bootstrap identity must present to assume lz-ci-deployer."
  type        = string
  default     = "lz-ci-lab-external-id"
}

# ---- Local-emulator toggles -------------------------------------------------
# Defaults are the real-AWS setting. deploy.ps1 passes the LocalStack override,
# and COVERAGE.md lists every toggle as "defined, not enforced locally".

variable "enable_backup_vault_lock" {
  description = "AWS Backup Vault Lock. LocalStack does not implement PutBackupVaultLockConfiguration."
  type        = bool
  default     = true
}

variable "enable_event_forwarding" {
  description = "Per-account EventBridge rules that forward CloudTrail API events to the security-tooling bus. LocalStack rejects cross-account bus targets, so locally the detector polls LookupEvents instead."
  type        = bool
  default     = true
}

variable "s3control_endpoint" {
  description = "S3 Control puts the account ID in the hostname, so it needs a wildcard DNS name. *.localhost.localstack.cloud resolves to 127.0.0.1."
  type        = string
  default     = "http://localhost.localstack.cloud:4566"
}

variable "central_trail_delivery" {
  description = "Every account's trail delivers to the log-archive bucket. With IAM enforcement on, LocalStack refuses a trail that names another account's KMS key, so locally each trail uses a customer managed key and an immutable bucket in its own account."
  type        = bool
  default     = true
}
