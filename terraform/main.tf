# Baseline shared by all scenarios: KMS key, CloudTrail with a protected
# log bucket, and two secrets (one the app owns, one it must never read).

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  vulnerable = var.lab_mode == "vulnerable"
}

# ---------- KMS ----------

resource "aws_kms_key" "lab" {
  description             = "Lab key for Secrets Manager"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "lab" {
  name          = "alias/lab-secrets"
  target_key_id = aws_kms_key.lab.key_id
}

# ---------- CloudTrail log bucket ----------

resource "aws_s3_bucket" "trail_logs" {
  bucket        = "lab-cloudtrail-logs-${local.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "trail_logs" {
  bucket                  = aws_s3_bucket.trail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail_logs.arn
      },
      {
        Sid       = "CloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail_logs.arn}/AWSLogs/${local.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
      # On real AWS, also add a Deny on aws:SecureTransport = false. It is left
      # out here because the LocalStack endpoint is plain HTTP and the deny
      # would lock Terraform out of its own bucket.
    ]
  })
}

# ---------- CloudTrail ----------

resource "aws_cloudtrail" "lab" {
  name                          = "lab-trail"
  s3_bucket_name                = aws_s3_bucket.trail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  enable_logging                = true # reset.sh re-applies this after the tamper scenario

  depends_on = [aws_s3_bucket_policy.trail_logs]
}

# ---------- Secrets ----------

resource "aws_secretsmanager_secret" "app_api_key" {
  name                    = "lab/app/api-key"
  description             = "Owned by lab-app. Legitimate access."
  kms_key_id              = aws_kms_key.lab.arn
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "app_api_key" {
  secret_id     = aws_secretsmanager_secret.app_api_key.id
  secret_string = jsonencode({ api_key = "app-key-not-sensitive-lab-value" })
}

resource "aws_secretsmanager_secret" "prod_db" {
  name                    = "lab/prod/db-credentials"
  description             = "Crown jewel. lab-app must never read this."
  kms_key_id              = aws_kms_key.lab.arn
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "prod_db" {
  secret_id = aws_secretsmanager_secret.prod_db.id
  secret_string = jsonencode({
    username = "prod_admin"
    password = "FLAG{prod-db-credentials-exfiltrated}"
    host     = "prod-db.internal.example"
  })
}
