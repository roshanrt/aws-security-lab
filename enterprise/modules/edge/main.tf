# Layer: edge (prod).
#
#   internet -> CloudFront (+ WAF) -> ALB (+ WAF) -> application
#
# - The ALB is the only public resource in the VPC and only listens on 443 (TLS 1.2+).
# - The ALB forwards only requests that carry a secret header that CloudFront adds,
#   so going around CloudFront straight to the ALB returns 403.
# - WAFv2 web ACLs (AWS managed rule groups plus a rate limit) on both CloudFront and the ALB.
#
# On LocalStack these resources are stored and can be asserted, but no traffic is
# filtered (see COVERAGE.md).

terraform {
  required_providers {
    aws    = { source = "hashicorp/aws" }
    random = { source = "hashicorp/random" }
  }
}

variable "name" { type = string }
variable "domain_name" { type = string }
variable "vpc_id" { type = string }
variable "public_subnet_ids" { type = list(string) }
variable "alb_security_group_id" { type = string }
variable "lambda_arn" { type = string }
variable "lambda_name" { type = string }

locals {
  managed_rule_groups = [
    "AWSManagedRulesAmazonIpReputationList",
    "AWSManagedRulesCommonRuleSet",
    "AWSManagedRulesKnownBadInputsRuleSet", # includes the Log4j rules
    "AWSManagedRulesSQLiRuleSet",
  ]
  origin_header = "X-Origin-Verify"
}

resource "aws_acm_certificate" "this" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

# ---------- WAF: one web ACL per scope, same rules ----------

resource "aws_wafv2_web_acl" "this" {
  #checkov:skip=CKV2_AWS_31:WAF logging needs a Kinesis Firehose or aws-waf-logs-* log group delivery; listed as a next step in README.md.
  for_each    = { alb = "REGIONAL", cloudfront = "CLOUDFRONT" }
  name        = "${var.name}-${each.key}"
  description = "Managed rule groups and a per-IP rate limit."
  scope       = each.value

  default_action {
    allow {}
  }

  rule {
    name     = "rate-limit-per-ip"
    priority = 0
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-${each.key}-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  dynamic "rule" {
    for_each = local.managed_rule_groups
    content {
      name     = rule.value
      priority = rule.key + 1
      override_action {
        none {}
      }
      statement {
        managed_rule_group_statement {
          name        = rule.value
          vendor_name = "AWS"
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-${each.key}-${rule.value}"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-${each.key}"
    sampled_requests_enabled   = true
  }
}

# ---------- ALB: the only public resource ----------

resource "aws_lb" "this" {
  #checkov:skip=CKV_AWS_91:ALB access logs need an S3 delivery policy for the regional ELB account; request logging is listed as a next step (WAF and ALB logs together).
  name                       = "${var.name}-alb"
  internal                   = false
  load_balancer_type         = "application"
  subnets                    = var.public_subnet_ids
  security_groups            = [var.alb_security_group_id]
  drop_invalid_header_fields = true
  enable_deletion_protection = true
}

resource "aws_lb_target_group" "app" {
  #checkov:skip=CKV_AWS_378:Lambda target groups have no protocol; TLS ends at the ALB and the ALB invokes the function through the Lambda API (HTTPS).
  name        = "${var.name}-app"
  target_type = "lambda"
}

resource "aws_lambda_permission" "alb" {
  statement_id  = "AllowInvokeFromAlbTargetGroup"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_name
  principal     = "elasticloadbalancing.amazonaws.com"
  source_arn    = aws_lb_target_group.app.arn
}

resource "aws_lb_target_group_attachment" "app" {
  target_group_arn = aws_lb_target_group.app.arn
  target_id        = var.lambda_arn
  depends_on       = [aws_lambda_permission.alb]
}

# Shared secret between CloudFront and the ALB.
resource "random_password" "origin_verify" {
  length  = 40
  special = false
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.this.arn

  # Anything that did not come through CloudFront is refused.
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Forbidden"
      status_code  = "403"
    }
  }
}

resource "aws_lb_listener_rule" "from_cloudfront_only" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10

  condition {
    http_header {
      http_header_name = local.origin_header
      values           = [random_password.origin_verify.result]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.this.arn
  web_acl_arn  = aws_wafv2_web_acl.this["alb"].arn
}

# ---------- CloudFront ----------

resource "aws_cloudfront_response_headers_policy" "security" {
  name = "${var.name}-security-headers"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
  }
}

resource "aws_cloudfront_distribution" "this" {
  #checkov:skip=CKV_AWS_86:CloudFront access logs need an ACL-enabled bucket; request logging is listed as a next step.
  #checkov:skip=CKV_AWS_310:Single origin; there is one ALB. Origin failover needs a second region.
  #checkov:skip=CKV_AWS_374:No geo restriction requirement for this lab workload.
  #checkov:skip=CKV2_AWS_47:The attached web ACL includes AWSManagedRulesKnownBadInputsRuleSet (Log4j).
  enabled         = true
  comment         = "${var.name} edge"
  aliases         = [var.domain_name]
  web_acl_id      = aws_wafv2_web_acl.this["cloudfront"].arn
  is_ipv6_enabled = true
  http_version    = "http2and3"

  origin {
    origin_id   = "alb"
    domain_name = aws_lb.this.dns_name

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = local.origin_header
      value = random_password.origin_verify.result
    }
  }

  default_cache_behavior {
    target_origin_id           = "alb"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods             = ["GET", "HEAD"]
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id
    compress                   = true

    forwarded_values {
      query_string = true
      cookies {
        forward = "all"
      }
    }

    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 0
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.this.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
}

output "alb_arn" {
  value = aws_lb.this.arn
}

output "distribution_id" {
  value = aws_cloudfront_distribution.this.id
}

output "web_acl_arns" {
  value = { for k, v in aws_wafv2_web_acl.this : k => v.arn }
}
