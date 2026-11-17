# Layer: data protection (one instance per workload account).
#
# - One customer managed key per data class, rotation on, admin/use separated.
#   Each key can be used only through its own service and only from this account.
# - AWS Backup: daily plan, primary vault, copy to a separate vault, Vault Lock.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

variable "account_id" { type = string }
variable "workload" { type = string }
variable "region" { type = string }
variable "enable_backup_vault_lock" { type = bool }

locals {
  # data class => the only AWS service allowed to use that key
  data_classes = {
    rds      = "rds"
    dynamodb = "dynamodb"
    s3       = "s3"
    secrets  = "secretsmanager"
    backup   = "backup"
  }
}

module "key" {
  source      = "../cmk"
  for_each    = local.data_classes
  alias       = "${var.workload}-${each.key}"
  description = "${var.workload} ${each.key} data. Usable only via ${each.value}."
  admin_arns  = ["arn:aws:iam::${var.account_id}:root"]

  usage_statements = [{
    Sid       = "UseOnlyThroughOwningService"
    Effect    = "Allow"
    Principal = { AWS = "*" }
    Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey", "kms:CreateGrant"]
    Resource  = "*"
    # Principal "*" is narrowed to this account and to calls made by the service
    # on a principal's behalf, so a stolen credential cannot call kms:Decrypt directly.
    Condition = {
      StringEquals = {
        "kms:CallerAccount" = var.account_id
        "kms:ViaService"    = "${each.value}.${var.region}.amazonaws.com"
      }
    }
  }]
}

# ---------- AWS Backup ----------

resource "aws_backup_vault" "primary" {
  name        = "${var.workload}-backup-primary"
  kms_key_arn = module.key["backup"].arn
}

resource "aws_backup_vault" "copy" {
  name        = "${var.workload}-backup-copy"
  kms_key_arn = module.key["backup"].arn
}

# Vault Lock in compliance mode: after the cooling-off period nobody, including
# root, can delete recovery points early or shorten retention.
# Not implemented by LocalStack; deploy.ps1 turns it off locally (see COVERAGE.md).
resource "aws_backup_vault_lock_configuration" "this" {
  for_each            = var.enable_backup_vault_lock ? { primary = aws_backup_vault.primary.name, copy = aws_backup_vault.copy.name } : {}
  backup_vault_name   = each.value
  min_retention_days  = 7
  max_retention_days  = 365
  changeable_for_days = 3
}

resource "aws_iam_role" "backup" {
  name = "svc-backup"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { RoleClass = "service" }
}

resource "aws_iam_role_policy_attachment" "backup" {
  for_each = toset([
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores",
  ])
  role       = aws_iam_role.backup.name
  policy_arn = each.value
}

resource "aws_backup_plan" "daily" {
  name = "${var.workload}-daily"

  rule {
    rule_name         = "daily-35-days-with-copy"
    target_vault_name = aws_backup_vault.primary.name
    schedule          = "cron(0 3 * * ? *)"

    lifecycle {
      delete_after = 35
    }

    copy_action {
      # Static ARN: the provider cannot plan a copy_action whose ARN is unknown.
      destination_vault_arn = "arn:aws:backup:${var.region}:${var.account_id}:backup-vault:${var.workload}-backup-copy"
      lifecycle {
        delete_after = 90
      }
    }
  }

  depends_on = [aws_backup_vault.copy]
}

# Anything tagged Backup=true in this account is protected.
resource "aws_backup_selection" "tagged" {
  name         = "tagged-backup-true"
  plan_id      = aws_backup_plan.daily.id
  iam_role_arn = aws_iam_role.backup.arn

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "true"
  }
}

output "key_arns" {
  value = { for k, m in module.key : k => m.arn }
}

output "key_ids" {
  value = { for k, m in module.key : k => m.key_id }
}

output "backup_vaults" {
  value = { primary = aws_backup_vault.primary.name, copy = aws_backup_vault.copy.name }
}
