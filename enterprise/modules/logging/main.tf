# Layer: logging.
#
# Organization trails need member accounts inside the organization, which LocalStack
# cannot do for the fixed-ID accounts, so this is one trail per account. On real AWS
# every trail delivers to a single bucket in log-archive that is versioned,
# Object-Locked (COMPLIANCE), encrypted with a customer managed key, and readable
# only by security roles. See trail/main.tf for the LocalStack delivery limitation.

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      configuration_aliases = [aws.log_archive, aws.security, aws.network, aws.prod, aws.nonprod]
    }
  }
}

variable "accounts" {
  description = "Map of account key => account ID for every account that logs here."
  type        = map(string)
}
variable "log_archive_account_id" { type = string }
variable "security_account_id" { type = string }
variable "region" { type = string }
variable "central_trail_delivery" {
  description = "True: every trail delivers to the log-archive bucket. False (LocalStack only): each account's trail delivers to an immutable bucket in its own account."
  type        = bool
}
variable "retention_days" {
  description = "Object Lock retention for every log object."
  type        = number
  default     = 365
}

locals {
  bucket_name = "lz-log-archive-${var.log_archive_account_id}"
  bucket_arn  = "arn:aws:s3:::${local.bucket_name}"

  # The only principals that may read log objects.
  log_readers = [
    "arn:aws:iam::${var.log_archive_account_id}:role/lz-security-analyst",
    "arn:aws:iam::${var.log_archive_account_id}:role/lz-break-glass",
    "arn:aws:iam::${var.security_account_id}:role/lz-security-analyst",
  ]
}

# ---------- Key for all logs ----------

module "logs_key" {
  source      = "../cmk"
  providers   = { aws = aws.log_archive }
  alias       = "lz-logs"
  description = "Encrypts CloudTrail and VPC Flow Logs in the log archive."
  admin_arns  = ["arn:aws:iam::${var.log_archive_account_id}:root"]

  usage_statements = [
    {
      Sid       = "CloudTrailEncryptsItsOwnTrailsOnly"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = ["kms:GenerateDataKey*", "kms:DescribeKey"]
      Resource  = "*"
      Condition = {
        StringLike = { "kms:EncryptionContext:aws:cloudtrail:arn" = [for id in values(var.accounts) : "arn:aws:cloudtrail:*:${id}:trail/*"] }
      }
    },
    {
      Sid       = "LogDeliveryEncryptsFlowLogs"
      Effect    = "Allow"
      Principal = { Service = "delivery.logs.amazonaws.com" }
      Action    = ["kms:GenerateDataKey*", "kms:DescribeKey", "kms:Encrypt"]
      Resource  = "*"
    },
    {
      Sid       = "SecurityRolesDecryptLogs"
      Effect    = "Allow"
      Principal = { AWS = [for id in [var.log_archive_account_id, var.security_account_id] : "arn:aws:iam::${id}:root"] }
      Action    = ["kms:Decrypt", "kms:DescribeKey"]
      Resource  = "*"
      Condition = { ArnEquals = { "aws:PrincipalArn" = local.log_readers } }
    }
  ]
}

# ---------- Central immutable log bucket ----------

module "central_bucket" {
  source         = "./immutable-bucket"
  providers      = { aws = aws.log_archive }
  name           = local.bucket_name
  kms_key_arn    = module.logs_key.arn
  retention_days = var.retention_days
}

resource "aws_s3_bucket_policy" "logs" {
  provider = aws.log_archive
  bucket   = module.central_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = local.bucket_arn
      },
      {
        Sid       = "CloudTrailWriteOwnPrefixOnly"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = [for id in values(var.accounts) : "${local.bucket_arn}/AWSLogs/${id}/*"]
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
          ArnLike      = { "aws:SourceArn" = [for id in values(var.accounts) : "arn:aws:cloudtrail:*:${id}:trail/*"] }
        }
      },
      {
        Sid       = "FlowLogDeliveryAclCheck"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource  = local.bucket_arn
      },
      {
        Sid       = "FlowLogDeliveryWrite"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${local.bucket_arn}/flow-logs/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = values(var.accounts)
          }
        }
      },
      {
        Sid       = "SecurityAnalystsReadLogs"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.security_account_id}:root" }
        Action    = ["s3:GetObject", "s3:ListBucket"]
        Resource  = [local.bucket_arn, "${local.bucket_arn}/*"]
        Condition = { ArnEquals = { "aws:PrincipalArn" = local.log_readers } }
      },
      {
        Sid       = "DenyReadsByAnyoneElse"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource  = "${local.bucket_arn}/*"
        Condition = {
          ArnNotEquals = { "aws:PrincipalArn" = local.log_readers }
          Bool         = { "aws:PrincipalIsAWSService" = "false" }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [local.bucket_arn, "${local.bucket_arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })

  depends_on = [module.central_bucket]
}

# ---------- One trail per account ----------
# The log-archive account's own trail always uses the central bucket (same account).

module "trail_log_archive" {
  source              = "./trail"
  providers           = { aws = aws.log_archive }
  account_id          = var.accounts.log_archive
  central_delivery    = true
  central_bucket_name = module.central_bucket.id
  kms_key_arn         = module.logs_key.arn
  retention_days      = var.retention_days
  depends_on          = [aws_s3_bucket_policy.logs]
}

module "trail_security" {
  source              = "./trail"
  providers           = { aws = aws.security }
  account_id          = var.accounts.security
  central_delivery    = var.central_trail_delivery
  central_bucket_name = module.central_bucket.id
  kms_key_arn         = module.logs_key.arn
  retention_days      = var.retention_days
  depends_on          = [aws_s3_bucket_policy.logs]
}

module "trail_network" {
  source              = "./trail"
  providers           = { aws = aws.network }
  account_id          = var.accounts.network
  central_delivery    = var.central_trail_delivery
  central_bucket_name = module.central_bucket.id
  kms_key_arn         = module.logs_key.arn
  retention_days      = var.retention_days
  depends_on          = [aws_s3_bucket_policy.logs]
}

module "trail_prod" {
  source              = "./trail"
  providers           = { aws = aws.prod }
  account_id          = var.accounts.prod
  central_delivery    = var.central_trail_delivery
  central_bucket_name = module.central_bucket.id
  kms_key_arn         = module.logs_key.arn
  retention_days      = var.retention_days
  depends_on          = [aws_s3_bucket_policy.logs]
}

module "trail_nonprod" {
  source              = "./trail"
  providers           = { aws = aws.nonprod }
  account_id          = var.accounts.nonprod
  central_delivery    = var.central_trail_delivery
  central_bucket_name = module.central_bucket.id
  kms_key_arn         = module.logs_key.arn
  retention_days      = var.retention_days
  depends_on          = [aws_s3_bucket_policy.logs]
}

output "bucket_name" {
  value = module.central_bucket.id
}

output "bucket_arn" {
  value = module.central_bucket.arn
}

output "logs_key_arn" {
  value = module.logs_key.arn
}

output "trail_buckets" {
  value = {
    log_archive = module.trail_log_archive.bucket_name
    security    = module.trail_security.bucket_name
    network     = module.trail_network.bucket_name
    prod        = module.trail_prod.bucket_name
    nonprod     = module.trail_nonprod.bucket_name
  }
}
