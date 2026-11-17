# Layer: workload (prod).
#
# Lambda application tier in the private-app subnets, RDS PostgreSQL in the
# isolated-data subnets, a DynamoDB table, an S3 data bucket and the database
# credentials in Secrets Manager. Every data store uses its own customer managed key.

terraform {
  required_providers {
    aws     = { source = "hashicorp/aws" }
    archive = { source = "hashicorp/archive" }
    random  = { source = "hashicorp/random" }
  }
}

variable "name" { type = string }
variable "account_id" { type = string }
variable "region" { type = string }
variable "app_subnet_ids" { type = list(string) }
variable "data_subnet_ids" { type = list(string) }
variable "app_security_group_id" { type = string }
variable "data_security_group_id" { type = string }
variable "key_arns" {
  description = "Data class => KMS key ARN (rds, dynamodb, s3, secrets)."
  type        = map(string)
}
variable "workload_boundary_arn" { type = string }
variable "postgres_version" {
  type    = string
  default = "17.9"
}

locals {
  app_role_name = "app-${var.name}-api"
  app_role_arn  = "arn:aws:iam::${var.account_id}:role/${local.app_role_name}"
  bucket_name   = "${var.name}-data-${var.account_id}"

  # The only principals that may read the database credentials.
  secret_readers = [local.app_role_arn, "arn:aws:iam::${var.account_id}:role/lz-break-glass"]
}

# ---------- Database credentials ----------

resource "random_password" "db" {
  length           = 32
  special          = true
  override_special = "!#$%^&*()-_=+"
}

resource "aws_secretsmanager_secret" "db" {
  #checkov:skip=CKV2_AWS_57:Automatic rotation needs a rotation Lambda inside the VPC; listed as a next step in README.md.
  name                    = "${var.name}/db/master"
  description             = "RDS master credentials. Readable only by the application role and break-glass."
  kms_key_id              = var.key_arns["secrets"]
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "db" {
  secret_id = aws_secretsmanager_secret.db.id
  secret_string = jsonencode({
    username = "app_admin"
    password = random_password.db.result
    engine   = "postgres"
    dbname   = "appdb"
    port     = 5432
  })
}

# Resource policy: even an identity whose IAM policy allows secretsmanager:* is
# denied unless it is one of the two named roles.
resource "aws_secretsmanager_secret_policy" "db" {
  secret_arn          = aws_secretsmanager_secret.db.arn
  block_public_policy = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyReadsExceptAppAndBreakGlass"
      Effect    = "Deny"
      Principal = "*"
      Action    = "secretsmanager:GetSecretValue"
      Resource  = "*"
      Condition = { ArnNotEquals = { "aws:PrincipalArn" = local.secret_readers } }
    }]
  })
}

# ---------- DynamoDB ----------

resource "aws_dynamodb_table" "orders" {
  name                        = "${var.name}-orders"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "pk"
  deletion_protection_enabled = true

  attribute {
    name = "pk"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.key_arns["dynamodb"]
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = { Backup = "true", DataClass = "dynamodb" }
}

# ---------- S3 data bucket ----------

resource "aws_s3_bucket" "data" {
  #checkov:skip=CKV_AWS_18:Server access logging needs a same-account log bucket; object-level access is listed as a next step (CloudTrail data events).
  #checkov:skip=CKV_AWS_144:Cross-region replication needs a second region; listed as a next step in README.md.
  #checkov:skip=CKV2_AWS_62:No consumer for bucket event notifications.
  bucket = local.bucket_name
  tags   = { DataClass = "s3" }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.key_arns["s3"]
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    id     = "tidy-up"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }

  depends_on = [aws_s3_bucket_versioning.data]
}

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyObjectAccessExceptAppAndBreakGlass"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource  = "${aws_s3_bucket.data.arn}/*"
        Condition = { ArnNotEquals = { "aws:PrincipalArn" = local.secret_readers } }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.data]
}

# ---------- RDS PostgreSQL ----------

resource "aws_db_subnet_group" "data" {
  name       = "${var.name}-data"
  subnet_ids = var.data_subnet_ids
}

resource "aws_db_parameter_group" "tls" {
  name   = "${var.name}-postgres-tls"
  family = "postgres${split(".", var.postgres_version)[0]}"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_connections"
    value = "1"
  }
}

resource "aws_db_instance" "main" {
  #checkov:skip=CKV_AWS_118:Enhanced monitoring needs an extra service role; logs are exported to CloudWatch instead. Listed as a next step.
  #checkov:skip=CKV_AWS_353:Performance Insights is an observability feature, not a security control; left off to keep the lab small.
  #checkov:skip=CKV2_AWS_60:copy_tags_to_snapshot is set below.
  identifier     = "${var.name}-db"
  engine         = "postgres"
  engine_version = var.postgres_version
  instance_class = "db.t3.micro"

  allocated_storage = 20
  storage_type      = "gp3"
  storage_encrypted = true
  kms_key_id        = var.key_arns["rds"]

  db_name  = "appdb"
  username = "app_admin"
  password = random_password.db.result

  db_subnet_group_name   = aws_db_subnet_group.data.name
  vpc_security_group_ids = [var.data_security_group_id]
  publicly_accessible    = false
  multi_az               = true
  parameter_group_name   = aws_db_parameter_group.tls.name

  iam_database_authentication_enabled = true
  deletion_protection                 = true
  backup_retention_period             = 7
  copy_tags_to_snapshot               = true
  auto_minor_version_upgrade          = true
  enabled_cloudwatch_logs_exports     = ["postgresql", "upgrade"]
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "${var.name}-db-final"

  tags = { Backup = "true", DataClass = "rds" }
}

# ---------- Application role (created the way a pipeline must: with the workload boundary) ----------

resource "aws_iam_role" "app" {
  name                 = local.app_role_name
  permissions_boundary = var.workload_boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { RoleClass = "service" }
}

resource "aws_iam_role_policy" "app" {
  #checkov:skip=CKV_AWS_355:Only the ENI and log actions use Resource "*"; they do not support resource-level scoping for VPC Lambdas.
  #checkov:skip=CKV_AWS_290:Same: the unscoped writes are ENI management and log delivery for a VPC Lambda.
  name = "least-privilege"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "OwnSecretOnly"
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = aws_secretsmanager_secret.db.arn
      },
      {
        Sid      = "OwnTableOnly"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"]
        Resource = aws_dynamodb_table.orders.arn
      },
      {
        Sid      = "OwnBucketOnly"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${aws_s3_bucket.data.arn}/*"
      },
      {
        Sid      = "DecryptOwnDataThroughItsService"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [var.key_arns["secrets"], var.key_arns["dynamodb"], var.key_arns["s3"]]
      },
      {
        Sid      = "VpcLambdaPlumbing"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces", "ec2:DeleteNetworkInterface", "xray:PutTraceSegments"]
        Resource = "*"
      }
    ]
  })
}

# ---------- Application (Lambda in the private-app subnets) ----------

data "archive_file" "app" {
  type        = "zip"
  source_file = "${path.module}/app.py"
  output_path = "${path.root}/.build/app.zip"
}

resource "aws_cloudwatch_log_group" "app" {
  #checkov:skip=CKV_AWS_158:Application logs carry no secrets or customer data; a logs-service key is listed as a next step.
  name              = "/aws/lambda/${var.name}-api"
  retention_in_days = 365
}

resource "aws_lambda_function" "app" {
  #checkov:skip=CKV_AWS_116:Invoked synchronously by the ALB; a dead-letter queue only applies to asynchronous invocations.
  #checkov:skip=CKV_AWS_272:Code signing needs an AWS Signer profile, which LocalStack does not emulate; listed as a next step.
  #checkov:skip=CKV_AWS_173:Environment variables hold only resource names and an ARN, no secrets; the password stays in Secrets Manager.
  function_name                  = "${var.name}-api"
  role                           = aws_iam_role.app.arn
  runtime                        = "python3.12"
  handler                        = "app.handler"
  filename                       = data.archive_file.app.output_path
  source_code_hash               = data.archive_file.app.output_base64sha256
  timeout                        = 15
  memory_size                    = 256
  reserved_concurrent_executions = 10

  vpc_config {
    subnet_ids         = var.app_subnet_ids
    security_group_ids = [var.app_security_group_id]
  }

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      TABLE_NAME    = aws_dynamodb_table.orders.name
      DB_SECRET_ARN = aws_secretsmanager_secret.db.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.app, aws_iam_role_policy.app]
}

output "lambda_arn" {
  value = aws_lambda_function.app.arn
}

output "lambda_name" {
  value = aws_lambda_function.app.function_name
}

output "table_name" {
  value = aws_dynamodb_table.orders.name
}

output "bucket_name" {
  value = aws_s3_bucket.data.id
}

output "secret_arn" {
  value = aws_secretsmanager_secret.db.arn
}

output "secret_name" {
  value = aws_secretsmanager_secret.db.name
}

output "db_identifier" {
  value = aws_db_instance.main.identifier
}

output "app_role_arn" {
  value = aws_iam_role.app.arn
}
