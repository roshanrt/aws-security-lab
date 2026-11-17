# Forwards this account's CloudTrail API events to the security-tooling event bus.
# Real-AWS path. LocalStack rejects cross-account bus targets, so the root module
# turns this off locally and the detector polls LookupEvents instead.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

variable "enabled" { type = bool }
variable "security_bus_arn" { type = string }

resource "aws_iam_role" "forwarder" {
  count = var.enabled ? 1 : 0
  name  = "svc-event-forwarder"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { RoleClass = "service" }
}

resource "aws_iam_role_policy" "forwarder" {
  count = var.enabled ? 1 : 0
  name  = "put-events-on-security-bus"
  role  = aws_iam_role.forwarder[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "events:PutEvents"
      Resource = var.security_bus_arn
    }]
  })
}

resource "aws_cloudwatch_event_rule" "cloudtrail" {
  count       = var.enabled ? 1 : 0
  name        = "lz-forward-cloudtrail-to-security"
  description = "Every CloudTrail management API call goes to the security-tooling bus."
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
  })
}

resource "aws_cloudwatch_event_target" "security_bus" {
  count    = var.enabled ? 1 : 0
  rule     = aws_cloudwatch_event_rule.cloudtrail[0].name
  arn      = var.security_bus_arn
  role_arn = aws_iam_role.forwarder[0].arn
}
