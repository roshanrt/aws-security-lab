# Layer: detection and response (security-tooling account).
#
#   CloudTrail (every account)
#     real AWS  : EventBridge rule per account -> security bus -> detector Lambda
#     LocalStack: one-minute schedule -> detector Lambda -> LookupEvents via lz-security-audit
#   detector -> DynamoDB findings (deduplicated) -> SNS alerts (subscribe the on-call channel)
#   detector -> lz-security-response (containment: close a security group opened to the internet)
#
# Replaces GuardDuty and Security Hub, which LocalStack does not emulate.

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      configuration_aliases = [aws.security, aws.log_archive, aws.network, aws.prod, aws.nonprod]
    }
    archive = { source = "hashicorp/archive" }
  }
}

variable "account_id" { type = string }
variable "region" { type = string }
variable "member_accounts" {
  description = "Account key => ID for every account the detector watches."
  type        = map(string)
}
variable "workload_account_ids" {
  description = "Accounts that have lz-security-response (containment)."
  type        = list(string)
}
variable "trusted_deployer_arns" {
  description = "Principals whose changes are deployments, not attacks. Locally: the account roots Terraform runs as. On real AWS: the pipeline's deploy role."
  type        = list(string)
}
variable "secret_allowlist" {
  description = "Secret name fragment => role names allowed to read it. Every other read is a finding."
  type        = map(list(string))
}
variable "guardrail_boundary_arn" { type = string }
variable "enable_event_forwarding" { type = bool }

locals {
  name = "lz-detector"
}

# ---------- Key for findings and alerts ----------

module "key" {
  source      = "../cmk"
  providers   = { aws = aws.security }
  alias       = "lz-security"
  description = "Findings table and alert topic."
  admin_arns  = ["arn:aws:iam::${var.account_id}:root"]

  usage_statements = [
    {
      Sid       = "UseOnlyThroughFindingAndAlertServices"
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey", "kms:CreateGrant"]
      Resource  = "*"
      Condition = {
        StringEquals = {
          "kms:CallerAccount" = var.account_id
          "kms:ViaService"    = [for s in ["dynamodb", "sns"] : "${s}.${var.region}.amazonaws.com"]
        }
      }
    }
  ]
}

# ---------- Findings store ----------

resource "aws_dynamodb_table" "findings" {
  provider                    = aws.security
  name                        = "lz-findings"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "pk"
  deletion_protection_enabled = true

  attribute {
    name = "pk"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = module.key.arn
  }

  point_in_time_recovery {
    enabled = true
  }
}

# ---------- Alerts ----------

resource "aws_sns_topic" "alerts" {
  provider          = aws.security
  name              = "lz-security-alerts"
  kms_master_key_id = module.key.key_id
}

# ---------- Detector role ----------

resource "aws_iam_role" "detector" {
  provider             = aws.security
  name                 = local.name
  description          = "Detection Lambda. Reads evidence and runs containment through roles in each account."
  permissions_boundary = var.guardrail_boundary_arn
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

resource "aws_iam_role_policy" "detector" {
  #checkov:skip=CKV_AWS_355:Only log delivery uses Resource "*".
  #checkov:skip=CKV_AWS_290:Only log delivery uses Resource "*".
  provider = aws.security
  name     = "detect-and-respond"
  role     = aws_iam_role.detector.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AssumeEvidenceAndResponseRolesOnly"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = ["arn:aws:iam::*:role/lz-security-audit", "arn:aws:iam::*:role/lz-security-response"]
      },
      {
        Sid      = "WriteFindings"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.findings.arn
      },
      {
        Sid      = "SendAlerts"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Sid      = "UseSecurityKeyThroughItsServices"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = module.key.arn
      },
      {
        Sid      = "Logs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "xray:PutTraceSegments"]
        Resource = "*"
      }
    ]
  })
}

# ---------- Detector Lambda ----------

data "archive_file" "detector" {
  type        = "zip"
  source_file = "${path.module}/detector.py"
  output_path = "${path.root}/.build/detector.zip"
}

resource "aws_cloudwatch_log_group" "detector" {
  #checkov:skip=CKV_AWS_158:Detector logs hold counts and error codes only; findings live in the KMS-encrypted table.
  provider          = aws.security
  name              = "/aws/lambda/${local.name}"
  retention_in_days = 365
}

resource "aws_lambda_function" "detector" {
  #checkov:skip=CKV_AWS_117:Runs outside a VPC on purpose: it only calls AWS APIs in other accounts and must keep working if a workload VPC is misconfigured.
  #checkov:skip=CKV_AWS_116:Runs every minute and is idempotent (checkpoint + eventID dedupe), so a failed run is retried by the next one.
  #checkov:skip=CKV_AWS_272:Code signing needs an AWS Signer profile, which LocalStack does not emulate; listed as a next step.
  #checkov:skip=CKV_AWS_173:Environment variables hold account IDs, names and ARNs only.
  provider                       = aws.security
  function_name                  = local.name
  role                           = aws_iam_role.detector.arn
  runtime                        = "python3.12"
  handler                        = "detector.handler"
  filename                       = data.archive_file.detector.output_path
  source_code_hash               = data.archive_file.detector.output_base64sha256
  timeout                        = 300
  memory_size                    = 256
  reserved_concurrent_executions = 1 # one poller at a time keeps checkpoints consistent

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      ACCOUNTS              = jsonencode({ for k, id in var.member_accounts : id => k })
      WORKLOAD_ACCOUNTS     = jsonencode(var.workload_account_ids)
      TRUSTED_DEPLOYER_ARNS = jsonencode(var.trusted_deployer_arns)
      SECRET_ALLOWLIST      = jsonencode(var.secret_allowlist)
      FINDINGS_TABLE        = aws_dynamodb_table.findings.name
      TOPIC_ARN             = aws_sns_topic.alerts.arn
      LOOKBACK_MINUTES      = "15"
    }
  }

  depends_on = [aws_cloudwatch_log_group.detector, aws_iam_role_policy.detector]
}

# ---------- Trigger 1: schedule (always on; the only path on LocalStack) ----------

resource "aws_cloudwatch_event_rule" "poll" {
  provider            = aws.security
  name                = "lz-detector-poll"
  description         = "Poll CloudTrail in every account and check trail state."
  schedule_expression = "rate(1 minute)"
}

resource "aws_cloudwatch_event_target" "poll" {
  provider = aws.security
  rule     = aws_cloudwatch_event_rule.poll.name
  arn      = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "poll" {
  provider      = aws.security
  statement_id  = "AllowSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.poll.arn
}

# ---------- Trigger 2: security event bus (real-AWS path) ----------

resource "aws_cloudwatch_event_bus" "security" {
  provider = aws.security
  name     = "lz-security-bus"
}

resource "aws_cloudwatch_event_bus_policy" "security" {
  provider       = aws.security
  event_bus_name = aws_cloudwatch_event_bus.security.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "MemberAccountsMayForwardEvents"
      Effect    = "Allow"
      Principal = { AWS = [for id in values(var.member_accounts) : "arn:aws:iam::${id}:root"] }
      Action    = "events:PutEvents"
      Resource  = aws_cloudwatch_event_bus.security.arn
    }]
  })
}

resource "aws_cloudwatch_event_rule" "forwarded" {
  provider       = aws.security
  name           = "lz-detector-forwarded-cloudtrail"
  description    = "CloudTrail API calls forwarded from member accounts."
  event_bus_name = aws_cloudwatch_event_bus.security.name
  event_pattern  = jsonencode({ "detail-type" = ["AWS API Call via CloudTrail"] })
}

resource "aws_cloudwatch_event_target" "forwarded" {
  provider       = aws.security
  rule           = aws_cloudwatch_event_rule.forwarded.name
  event_bus_name = aws_cloudwatch_event_bus.security.name
  arn            = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "forwarded" {
  provider      = aws.security
  statement_id  = "AllowSecurityBus"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.forwarded.arn
}

module "forward_log_archive" {
  source           = "./forwarder"
  providers        = { aws = aws.log_archive }
  enabled          = var.enable_event_forwarding
  security_bus_arn = aws_cloudwatch_event_bus.security.arn
}

module "forward_network" {
  source           = "./forwarder"
  providers        = { aws = aws.network }
  enabled          = var.enable_event_forwarding
  security_bus_arn = aws_cloudwatch_event_bus.security.arn
}

module "forward_prod" {
  source           = "./forwarder"
  providers        = { aws = aws.prod }
  enabled          = var.enable_event_forwarding
  security_bus_arn = aws_cloudwatch_event_bus.security.arn
}

module "forward_nonprod" {
  source           = "./forwarder"
  providers        = { aws = aws.nonprod }
  enabled          = var.enable_event_forwarding
  security_bus_arn = aws_cloudwatch_event_bus.security.arn
}

output "function_name" {
  value = aws_lambda_function.detector.function_name
}

output "findings_table" {
  value = aws_dynamodb_table.findings.name
}

output "alert_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

