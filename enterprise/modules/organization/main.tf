# Layer: organization. OU structure and service control policies, owned by the
# management account.
#
# LocalStack cannot invite existing accounts (InviteAccountToOrganization is not
# implemented), so the five fixed-ID landing-zone accounts cannot become members.
# The SCPs are therefore proven on an org-created canary account, and the same
# intent is enforced in the fixed accounts by modules/identity (guardrail boundary).

terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

variable "approved_regions" {
  type = list(string)
}

resource "aws_organizations_organization" "this" {
  feature_set          = "ALL"
  enabled_policy_types = ["SERVICE_CONTROL_POLICY"]
}

locals {
  root_id = aws_organizations_organization.this.roots[0].id

  scps = {
    deny-cloudtrail-tamper = {
      description = "Nobody in a member account may stop, delete or blind CloudTrail."
      statement = {
        Sid      = "DenyCloudTrailTamper"
        Effect   = "Deny"
        Action   = ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors", "cloudtrail:PutInsightSelectors"]
        Resource = "*"
      }
    }
    deny-leave-org = {
      description = "Member accounts may not leave the organization."
      statement = {
        Sid      = "DenyLeaveOrganization"
        Effect   = "Deny"
        Action   = "organizations:LeaveOrganization"
        Resource = "*"
      }
    }
    deny-unapproved-regions = {
      description = "Regional services may only be used in approved regions."
      statement = {
        Sid    = "DenyUnapprovedRegions"
        Effect = "Deny"
        # Global services are exempt: their requests are always signed for us-east-1.
        NotAction = ["iam:*", "sts:*", "organizations:*", "route53:*", "cloudfront:*", "wafv2:*", "support:*"]
        Resource  = "*"
        Condition = { StringNotEquals = { "aws:RequestedRegion" = var.approved_regions } }
      }
    }
    deny-iam-user-keys = {
      description = "No IAM users or long-lived access keys. Humans and pipelines use roles."
      statement = {
        Sid      = "DenyLongLivedCredentials"
        Effect   = "Deny"
        Action   = ["iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile"]
        Resource = "*"
      }
    }
  }
}

resource "aws_organizations_organizational_unit" "security" {
  name      = "Security"
  parent_id = local.root_id
}

resource "aws_organizations_organizational_unit" "infrastructure" {
  name      = "Infrastructure"
  parent_id = local.root_id
}

resource "aws_organizations_organizational_unit" "workloads" {
  name      = "Workloads"
  parent_id = local.root_id
}

resource "aws_organizations_organizational_unit" "prod" {
  name      = "Prod"
  parent_id = aws_organizations_organizational_unit.workloads.id
}

resource "aws_organizations_organizational_unit" "nonprod" {
  name      = "NonProd"
  parent_id = aws_organizations_organizational_unit.workloads.id
}

resource "aws_organizations_policy" "scp" {
  for_each    = local.scps
  name        = each.key
  description = each.value.description
  type        = "SERVICE_CONTROL_POLICY"
  content     = jsonencode({ Version = "2012-10-17", Statement = [each.value.statement] })

  # SCPs can only be created once the organization exists with the policy type enabled.
  depends_on = [aws_organizations_organization.this]
}

# Every SCP applies to every OU. The management account is exempt by design, which
# is why nothing but the organization itself lives there.
locals {
  ous = {
    security       = aws_organizations_organizational_unit.security.id
    infrastructure = aws_organizations_organizational_unit.infrastructure.id
    workloads      = aws_organizations_organizational_unit.workloads.id
  }
  attachments = { for pair in setproduct(keys(local.scps), keys(local.ous)) : "${pair[0]}/${pair[1]}" => { scp = pair[0], ou = pair[1] } }
}

resource "aws_organizations_policy_attachment" "scp" {
  for_each  = local.attachments
  policy_id = aws_organizations_policy.scp[each.value.scp].id
  target_id = local.ous[each.value.ou]
}

# Org-created member account used only to prove the SCPs are enforced.
resource "aws_organizations_account" "scp_canary" {
  name              = "scp-canary"
  email             = "scp-canary@example.com"
  parent_id         = aws_organizations_organizational_unit.prod.id
  close_on_deletion = true

  depends_on = [aws_organizations_policy_attachment.scp]
}

output "organization_id" {
  value = aws_organizations_organization.this.id
}

output "scp_canary_account_id" {
  value = aws_organizations_account.scp_canary.id
}

output "scp_names" {
  value = keys(local.scps)
}
