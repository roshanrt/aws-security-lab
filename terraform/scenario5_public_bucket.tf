# Scenario 5: Public bucket and data exfiltration
# ATT&CK: T1530 Data from Cloud Storage
#
# Vulnerable: a developer holds s3:* on the customer-data bucket and Block Public
# Access is off, so they can publish the bucket with one policy and anyone can read it.
# Hardened: Block Public Access is on, and the developer can read and write objects
# but cannot change bucket policy, ACLs or Block Public Access.

locals {
  data_bucket = "lab-customer-data-${local.account_id}"

  dev_policy_vulnerable = {
    Sid      = "OverbroadBucketAdmin"
    Effect   = "Allow"
    Action   = "s3:*"
    Resource = [aws_s3_bucket.customer_data.arn, "${aws_s3_bucket.customer_data.arn}/*"]
  }

  dev_policy_hardened = [
    {
      Sid      = "ObjectReadWriteOnly"
      Effect   = "Allow"
      Action   = ["s3:ListBucket", "s3:GetObject", "s3:PutObject"]
      Resource = [aws_s3_bucket.customer_data.arn, "${aws_s3_bucket.customer_data.arn}/*"]
    },
    {
      Sid    = "DenyExposureChanges"
      Effect = "Deny"
      Action = [
        "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
        "s3:PutBucketAcl", "s3:PutObjectAcl",
        "s3:PutBucketPublicAccessBlock", "s3:DeleteBucketPublicAccessBlock"
      ]
      Resource = [aws_s3_bucket.customer_data.arn, "${aws_s3_bucket.customer_data.arn}/*"]
    }
  ]
}

resource "aws_s3_bucket" "customer_data" {
  bucket        = local.data_bucket
  force_destroy = true
}

# Fake data only.
resource "aws_s3_object" "customers" {
  bucket  = aws_s3_bucket.customer_data.id
  key     = "customers.csv"
  content = "id,name,email\n1,Test User One,user1@example.invalid\n2,Test User Two,user2@example.invalid\n"
}

resource "aws_s3_bucket_public_access_block" "customer_data" {
  bucket                  = aws_s3_bucket.customer_data.id
  block_public_acls       = !local.vulnerable
  block_public_policy     = !local.vulnerable
  ignore_public_acls      = !local.vulnerable
  restrict_public_buckets = !local.vulnerable
}

resource "aws_iam_user" "dev" {
  name = "lab-dev"
}

resource "aws_iam_access_key" "dev" {
  user = aws_iam_user.dev.name
}

resource "aws_iam_user_policy" "dev" {
  name = "lab-dev-data"
  user = aws_iam_user.dev.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = concat(local.vulnerable ? [local.dev_policy_vulnerable] : [], local.vulnerable ? [] : local.dev_policy_hardened)
  })
}
