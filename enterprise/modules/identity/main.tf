# Layer: identity. Instantiated once per account.
#
# - Role-based access only. Human roles trust the identity hub account and require MFA.
# - Machine roles trust one exact principal (plus ExternalId for the pipeline role).
# - Every role carries the guardrail permissions boundary, which enforces the same
#   intent as the organization SCPs inside accounts that cannot join the org locally.
# - Roles created by developers or pipelines must carry the workload boundary.
# - Account baseline: password policy, account-wide S3 Block Public Access,
#   EBS encryption by default.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

variable "account_id" { type = string }
variable "account_name" { type = string }
variable "identity_account_id" {
  description = "Account that holds the human identities (the identity hub)."
  type        = string
}
variable "approved_regions" { type = list(string) }
variable "is_identity_hub" {
  type    = bool
  default = false
}
variable "is_workload" {
  type    = bool
  default = false
}
variable "bootstrap_user_arn" {
  description = "Lab-only bootstrap identity allowed to assume lz-ci-deployer. Empty in the hub itself."
  type        = string
  default     = ""
}
variable "ci_external_id" { type = string }
variable "detector_role_arn" {
  description = "Detection Lambda role in security-tooling; the only principal that may assume the audit and response roles."
  type        = string
}

locals {
  arn_prefix             = "arn:aws:iam::${var.account_id}"
  guardrail_boundary_arn = "${local.arn_prefix}:policy/lz-guardrail-boundary"
  workload_boundary_arn  = "${local.arn_prefix}:policy/lz-workload-boundary"
  identity_root          = "arn:aws:iam::${var.identity_account_id}:root"

  tamper_actions = ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors", "cloudtrail:PutInsightSelectors"]

  human_roles = {
    admin            = { managed = ["arn:aws:iam::aws:policy/AdministratorAccess"], mfa_age = 3600, session = 3600 }
    developer        = { managed = [], mfa_age = 28800, session = 14400 }
    readonly         = { managed = ["arn:aws:iam::aws:policy/ReadOnlyAccess"], mfa_age = 28800, session = 14400 }
    security-analyst = { managed = ["arn:aws:iam::aws:policy/SecurityAudit"], mfa_age = 28800, session = 14400 }
    break-glass      = { managed = ["arn:aws:iam::aws:policy/AdministratorAccess"], mfa_age = 900, session = 3600 }
  }

  # Build-and-run permissions shared by the developer role and the pipeline role.
  # IAM writes are limited to app-* roles that carry the workload boundary.
  delivery_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BuildAndRunWorkloads"
        Effect = "Allow"
        Action = [
          "lambda:*", "dynamodb:*", "s3:*", "logs:*", "cloudwatch:*", "events:*", "sns:*", "sqs:*",
          "ec2:Describe*", "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup", "ec2:CreateTags",
          "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress", "ec2:RevokeSecurityGroupEgress",
          "secretsmanager:DescribeSecret", "secretsmanager:ListSecrets",
          "kms:DescribeKey", "kms:ListKeys", "kms:ListAliases",
          "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:LookupEvents",
          "iam:Get*", "iam:List*", "sts:GetCallerIdentity"
        ]
        Resource = "*"
      },
      {
        Sid       = "CreateAppRolesOnlyWithWorkloadBoundary"
        Effect    = "Allow"
        Action    = ["iam:CreateRole", "iam:PutRolePermissionsBoundary"]
        Resource  = "${local.arn_prefix}:role/app-*"
        Condition = { StringEquals = { "iam:PermissionsBoundary" = local.workload_boundary_arn } }
      },
      {
        Sid      = "ManageAppRoles"
        Effect   = "Allow"
        Action   = ["iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:DeleteRole", "iam:TagRole"]
        Resource = "${local.arn_prefix}:role/app-*"
      },
      {
        Sid       = "PassAppRolesToLambdaOnly"
        Effect    = "Allow"
        Action    = "iam:PassRole"
        Resource  = "${local.arn_prefix}:role/app-*"
        Condition = { StringEquals = { "iam:PassedToService" = "lambda.amazonaws.com" } }
      }
    ]
  })
}

# ---------- Account baseline ----------

resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  password_reuse_prevention      = 24
  max_password_age               = 90
  allow_users_to_change_password = true
}

resource "aws_s3_account_public_access_block" "this" {
  account_id              = var.account_id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

# ---------- Permission boundaries ----------

# Ceiling for every lz-* role. Mirrors the organization SCPs and protects the
# landing zone itself (its roles and its boundaries) from the roles it governs.
resource "aws_iam_policy" "guardrail_boundary" {
  name        = "lz-guardrail-boundary"
  description = "Permissions boundary on every landing-zone role. Same intent as the organization SCPs."
  #checkov:skip=CKV_AWS_289:Boundary ceiling, not a grant. Effective permissions are the intersection with each role's own policy.
  #checkov:skip=CKV_AWS_355:Boundary ceiling, not a grant. Effective permissions are the intersection with each role's own policy.
  #checkov:skip=CKV_AWS_290:Boundary ceiling, not a grant. Effective permissions are the intersection with each role's own policy.
  #checkov:skip=CKV_AWS_286:Boundary ceiling; the deny statements below block the privilege-escalation paths.
  #checkov:skip=CKV_AWS_287:Boundary ceiling; credential-creating actions are explicitly denied below.
  #checkov:skip=CKV_AWS_288:Boundary ceiling; data access is decided by role, resource and key policies.
  #checkov:skip=CKV_AWS_63:Boundary ceiling. Allow * here grants nothing by itself.
  #checkov:skip=CKV_AWS_62:Boundary ceiling. Allow * here grants nothing by itself.
  #checkov:skip=CKV2_AWS_40:Boundary ceiling. Allow * here grants nothing by itself.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CeilingAllowsEverythingNotDeniedBelow"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
      {
        Sid      = "DenyCloudTrailTamper"
        Effect   = "Deny"
        Action   = local.tamper_actions
        Resource = "*"
      },
      {
        Sid      = "DenyLeaveOrganization"
        Effect   = "Deny"
        Action   = "organizations:LeaveOrganization"
        Resource = "*"
      },
      {
        Sid       = "DenyUnapprovedRegions"
        Effect    = "Deny"
        NotAction = ["iam:*", "sts:*", "organizations:*", "route53:*", "cloudfront:*", "wafv2:*", "support:*"]
        Resource  = "*"
        Condition = { StringNotEquals = { "aws:RequestedRegion" = var.approved_regions } }
      },
      {
        Sid      = "DenyLongLivedCredentials"
        Effect   = "Deny"
        Action   = ["iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile"]
        Resource = "*"
      },
      {
        Sid      = "DenyBoundaryRemoval"
        Effect   = "Deny"
        Action   = ["iam:DeleteRolePermissionsBoundary", "iam:DeleteUserPermissionsBoundary"]
        Resource = "*"
      },
      {
        Sid      = "DenyBoundaryPolicyEdits"
        Effect   = "Deny"
        Action   = ["iam:CreatePolicyVersion", "iam:DeletePolicy", "iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion"]
        Resource = [local.guardrail_boundary_arn, local.workload_boundary_arn]
      },
      {
        Sid       = "DenyRolesWithoutBoundary"
        Effect    = "Deny"
        Action    = ["iam:CreateRole", "iam:PutRolePermissionsBoundary"]
        Resource  = "*"
        Condition = { StringNotEquals = { "iam:PermissionsBoundary" = [local.guardrail_boundary_arn, local.workload_boundary_arn] } }
      },
      {
        Sid    = "DenyLandingZoneRoleTamper"
        Effect = "Deny"
        Action = [
          "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy",
          "iam:UpdateAssumeRolePolicy", "iam:DeleteRole", "iam:UpdateRole", "iam:PutRolePermissionsBoundary"
        ]
        Resource = "${local.arn_prefix}:role/lz-*"
      }
    ]
  })
}

# Ceiling for roles that developers and pipelines create for applications.
resource "aws_iam_policy" "workload_boundary" {
  name        = "lz-workload-boundary"
  description = "Permissions boundary required on every role created by a developer or pipeline."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AppRuntimeCeiling"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
          "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query",
          "s3:GetObject", "s3:PutObject", "s3:ListBucket",
          "secretsmanager:GetSecretValue", "kms:Decrypt", "kms:GenerateDataKey",
          "ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces", "ec2:DeleteNetworkInterface",
          "xray:PutTraceSegments"
        ]
        Resource = "*"
      },
      {
        Sid      = "NeverIamOrgOrTrailChanges"
        Effect   = "Deny"
        Action   = concat(["iam:*", "organizations:*"], local.tamper_actions)
        Resource = "*"
      }
    ]
  })
}

# ---------- Human roles (MFA required) ----------

resource "aws_iam_role" "human" {
  for_each             = local.human_roles
  name                 = "lz-${each.key}"
  description          = "Human role, assumed from the identity hub with MFA."
  permissions_boundary = aws_iam_policy.guardrail_boundary.arn
  max_session_duration = each.value.session

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "IdentityHubWithMfa"
      Effect    = "Allow"
      Principal = { AWS = local.identity_root }
      Action    = "sts:AssumeRole"
      Condition = {
        Bool            = { "aws:MultiFactorAuthPresent" = "true" }
        NumericLessThan = { "aws:MultiFactorAuthAge" = tostring(each.value.mfa_age) }
      }
    }]
  })

  tags = { RoleClass = "human" }
}

locals {
  human_attachments = merge([
    for role, cfg in local.human_roles : { for arn in cfg.managed : "${role}|${arn}" => { role = role, arn = arn } }
  ]...)
}

resource "aws_iam_role_policy_attachment" "human" {
  #checkov:skip=CKV_AWS_274:Admin and break-glass are deliberate, MFA-gated, boundary-capped roles; break-glass use raises finding ENT-008.
  for_each   = local.human_attachments
  role       = aws_iam_role.human[each.value.role].name
  policy_arn = each.value.arn
}

resource "aws_iam_role_policy" "developer" {
  #checkov:skip=CKV_AWS_355:Build services need Resource "*"; the role is capped by lz-guardrail-boundary and data is protected by resource and key policies.
  #checkov:skip=CKV_AWS_290:Same as above: write access is scoped by the boundary and by resource policies.
  #checkov:skip=CKV_AWS_288:Sensitive buckets and tables restrict access in their own resource and key policies.
  #checkov:skip=CKV_AWS_289:IAM writes are limited to app-* roles that carry lz-workload-boundary.
  #checkov:skip=CKV_AWS_286:IAM writes are limited to app-* roles that carry lz-workload-boundary.
  #checkov:skip=CKV_AWS_287:No credential-exposing actions are granted; GetSecretValue and key use are absent.
  name   = "delivery"
  role   = aws_iam_role.human["developer"].id
  policy = local.delivery_policy
}

# ---------- Machine roles (exact principal, no MFA) ----------

# Pipeline role. Lab-only: assumed by the bootstrap identity with an ExternalId.
# On real AWS the trust would be an OIDC provider for the CI system.
resource "aws_iam_role" "ci_deployer" {
  count                = var.is_workload ? 1 : 0
  name                 = "lz-ci-deployer"
  description          = "Pipeline role. Same delivery permissions as developers, capped by the guardrail boundary."
  permissions_boundary = aws_iam_policy.guardrail_boundary.arn
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PipelineIdentityWithExternalId"
      Effect    = "Allow"
      Principal = { AWS = var.bootstrap_user_arn }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "sts:ExternalId" = var.ci_external_id } }
    }]
  })

  tags = { RoleClass = "machine" }
}

resource "aws_iam_role_policy" "ci_deployer" {
  #checkov:skip=CKV_AWS_355:Build services need Resource "*"; the role is capped by lz-guardrail-boundary and data is protected by resource and key policies.
  #checkov:skip=CKV_AWS_290:Same as above: write access is scoped by the boundary and by resource policies.
  #checkov:skip=CKV_AWS_288:Sensitive buckets and tables restrict access in their own resource and key policies.
  #checkov:skip=CKV_AWS_289:IAM writes are limited to app-* roles that carry lz-workload-boundary.
  #checkov:skip=CKV_AWS_286:IAM writes are limited to app-* roles that carry lz-workload-boundary.
  #checkov:skip=CKV_AWS_287:No credential-exposing actions are granted; GetSecretValue and key use are absent.
  count  = var.is_workload ? 1 : 0
  name   = "delivery"
  role   = aws_iam_role.ci_deployer[0].id
  policy = local.delivery_policy
}

locals {
  detector_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DetectorRoleOnly"
      Effect    = "Allow"
      Principal = { AWS = local.identity_root }
      Action    = "sts:AssumeRole"
      # Root principal plus an exact PrincipalArn match: only the detector role
      # qualifies, and the trust does not break if that role is re-created.
      Condition = { ArnEquals = { "aws:PrincipalArn" = var.detector_role_arn } }
    }]
  })
}

resource "aws_iam_role" "security_audit" {
  name                 = "lz-security-audit"
  description          = "Read-only evidence collection for the detection pipeline."
  permissions_boundary = aws_iam_policy.guardrail_boundary.arn
  assume_role_policy   = local.detector_trust
  tags                 = { RoleClass = "machine" }
}

resource "aws_iam_role_policy" "security_audit" {
  #checkov:skip=CKV_AWS_355:Read-only describe and lookup actions do not support resource-level scoping.
  name = "evidence-read"
  role = aws_iam_role.security_audit.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadEvidence"
      Effect   = "Allow"
      Action   = ["cloudtrail:LookupEvents", "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "ec2:DescribeSecurityGroups", "ec2:DescribeSecurityGroupRules"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "security_response" {
  count                = var.is_workload ? 1 : 0
  name                 = "lz-security-response"
  description          = "Containment actions for the detection pipeline. Can only remove security group ingress."
  permissions_boundary = aws_iam_policy.guardrail_boundary.arn
  assume_role_policy   = local.detector_trust
  tags                 = { RoleClass = "machine" }
}

resource "aws_iam_role_policy" "security_response" {
  #checkov:skip=CKV_AWS_355:Describe actions do not support resource-level scoping; the only write is RevokeSecurityGroupIngress, which removes access.
  #checkov:skip=CKV_AWS_290:The only write is RevokeSecurityGroupIngress, which can only remove access.
  count = var.is_workload ? 1 : 0
  name  = "containment"
  role  = aws_iam_role.security_response[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "QuarantineSecurityGroupRules"
      Effect   = "Allow"
      Action   = ["ec2:DescribeSecurityGroups", "ec2:DescribeSecurityGroupRules", "ec2:RevokeSecurityGroupIngress", "ec2:CreateTags"]
      Resource = "*"
    }]
  })
}

# ---------- Lab-only bootstrap identity (identity hub only) ----------
# The single IAM user with a long-lived key in the whole landing zone. It stands
# in for the corporate IdP / CI OIDC provider, which LocalStack cannot provide.
# It can do nothing except ask to assume lz-* roles.

resource "aws_iam_user" "bootstrap" {
  #checkov:skip=CKV_AWS_273:Lab-only stand-in for SSO/OIDC, which LocalStack cannot emulate. It can only call sts:AssumeRole.
  count = var.is_identity_hub ? 1 : 0
  name  = "lab-bootstrap"
  path  = "/lab-only/"
  tags  = { LabOnly = "true", Purpose = "Stand-in for IdP and CI OIDC. Remove on real AWS." }
}

resource "aws_iam_user_policy" "bootstrap" {
  #checkov:skip=CKV_AWS_40:Lab-only bootstrap identity; a group adds nothing for a single stand-in user.
  count = var.is_identity_hub ? 1 : 0
  name  = "assume-landing-zone-roles-only"
  user  = aws_iam_user.bootstrap[0].name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AssumeLandingZoneRoles"
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = "arn:aws:iam::*:role/lz-*"
    }]
  })
}

resource "aws_iam_access_key" "bootstrap" {
  count = var.is_identity_hub ? 1 : 0
  user  = aws_iam_user.bootstrap[0].name
}

# ---------- Outputs ----------

output "bootstrap_user_arn" {
  value = var.is_identity_hub ? aws_iam_user.bootstrap[0].arn : ""
}

output "bootstrap_credentials" {
  sensitive = true
  value = var.is_identity_hub ? {
    access_key_id     = aws_iam_access_key.bootstrap[0].id
    secret_access_key = aws_iam_access_key.bootstrap[0].secret
  } : null
}

output "role_arns" {
  value = merge(
    { for k, r in aws_iam_role.human : k => r.arn },
    { security-audit = aws_iam_role.security_audit.arn },
    var.is_workload ? { ci-deployer = aws_iam_role.ci_deployer[0].arn, security-response = aws_iam_role.security_response[0].arn } : {}
  )
}

output "guardrail_boundary_arn" {
  value = aws_iam_policy.guardrail_boundary.arn
}

output "workload_boundary_arn" {
  value = aws_iam_policy.workload_boundary.arn
}
