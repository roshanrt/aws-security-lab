# One CloudTrail trail in one account.
#
# Real AWS (central_delivery = true): the trail delivers to the central bucket in
# log-archive.
#
# LocalStack (central_delivery = false): with IAM enforcement on, LocalStack treats
# a request that names another account's ARN (here the central KMS key) as a call
# into that account and refuses it. The trail then uses a customer managed key and
# an immutable bucket in its own account, built from the same modules.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

variable "account_id" { type = string }
variable "central_delivery" { type = bool }
variable "central_bucket_name" { type = string }
variable "kms_key_arn" { type = string }
variable "retention_days" { type = number }

module "local_key" {
  source      = "../../cmk"
  count       = var.central_delivery ? 0 : 1
  alias       = "lz-trail-local"
  description = "Encrypts this account's CloudTrail logs (LocalStack-only layout)."
  admin_arns  = ["arn:aws:iam::${var.account_id}:root"]

  usage_statements = [{
    Sid       = "CloudTrailEncryptsItsOwnTrailsOnly"
    Effect    = "Allow"
    Principal = { Service = "cloudtrail.amazonaws.com" }
    Action    = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    Resource  = "*"
    Condition = { StringLike = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${var.account_id}:trail/*" } }
  }]
}

locals {
  key_arn = var.central_delivery ? var.kms_key_arn : module.local_key[0].arn
}

module "local_bucket" {
  source         = "../immutable-bucket"
  count          = var.central_delivery ? 0 : 1
  name           = "lz-trail-local-${var.account_id}"
  kms_key_arn    = local.key_arn
  retention_days = var.retention_days
}

resource "aws_s3_bucket_policy" "local" {
  count  = var.central_delivery ? 0 : 1
  bucket = module.local_bucket[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = module.local_bucket[0].arn
      },
      {
        Sid       = "CloudTrailWriteOwnPrefixOnly"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${module.local_bucket[0].arn}/AWSLogs/${var.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [module.local_bucket[0].arn, "${module.local_bucket[0].arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })

  depends_on = [module.local_bucket]
}

resource "aws_cloudtrail" "this" {
  #checkov:skip=CKV2_AWS_10:Logs go to an immutable bucket and the detection pipeline reads CloudTrail directly; a CloudWatch Logs copy per account adds cost without adding a control here.
  #checkov:skip=CKV_AWS_252:Alerting is done by the detection pipeline (SNS topic lz-security-alerts), not per-trail SNS delivery notices.
  name                          = "lz-trail"
  s3_bucket_name                = var.central_delivery ? var.central_bucket_name : module.local_bucket[0].id
  kms_key_id                    = local.key_arn
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  enable_logging                = true

  depends_on = [aws_s3_bucket_policy.local]
}

output "arn" {
  value = aws_cloudtrail.this.arn
}

output "bucket_name" {
  value = aws_cloudtrail.this.s3_bucket_name
}
