# A write-once log bucket: versioned, Object Lock in COMPLIANCE mode, encrypted with
# a customer managed key, all public access blocked. The bucket policy is attached
# by the caller, because who may write differs per use.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

variable "name" { type = string }
variable "kms_key_arn" { type = string }
variable "retention_days" { type = number }

resource "aws_s3_bucket" "this" {
  #checkov:skip=CKV_AWS_18:This is a log destination; its own access is recorded by CloudTrail and it must not log to itself.
  #checkov:skip=CKV_AWS_144:Cross-region replication needs a second region; listed as a next step in README.md.
  #checkov:skip=CKV2_AWS_62:No consumer for bucket event notifications; the detection pipeline reads CloudTrail.
  bucket              = var.name
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    default_retention {
      mode = "COMPLIANCE" # not even the account root can delete or shorten
      days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "archive-then-expire-after-retention"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    noncurrent_version_expiration {
      noncurrent_days = var.retention_days + 30
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

output "id" {
  value = aws_s3_bucket.this.id
}

output "arn" {
  value = aws_s3_bucket.this.arn
}

# Lets callers order their bucket policy after Block Public Access is in place.
output "public_access_block_id" {
  value = aws_s3_bucket_public_access_block.this.id
}
