# Scenario 1: IAM privilege escalation via iam:CreatePolicyVersion
# ATT&CK: T1098.003 Account Manipulation: Additional Cloud Roles
#
# Vulnerable: the intern may "maintain their own policy", which lets them
# write a new default version granting "*:*".
# Hardened: self-read only, plus a permissions boundary that denies IAM writes.

locals {
  intern_policy_name = "lab-intern-policy"
  intern_policy_arn  = "arn:aws:iam::${local.account_id}:policy/${local.intern_policy_name}"

  intern_self_read = {
    Sid    = "SelfRead"
    Effect = "Allow"
    Action = [
      "iam:GetUser",
      "iam:ListAttachedUserPolicies",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListPolicyVersions"
    ]
    Resource = [
      "arn:aws:iam::${local.account_id}:user/lab-intern",
      local.intern_policy_arn
    ]
  }

  intern_policy_maintenance = {
    Sid      = "MaintainOwnPolicy"
    Effect   = "Allow"
    Action   = ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"]
    Resource = local.intern_policy_arn
  }
}

resource "aws_iam_policy" "intern_boundary" {
  name        = "lab-intern-boundary"
  description = "Permissions boundary: caps the intern even if their policy is changed."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowReadOnlyCeiling"
        Effect   = "Allow"
        Action   = ["iam:Get*", "iam:List*", "sts:GetCallerIdentity"]
        Resource = "*"
      },
      {
        Sid    = "DenyIamWrites"
        Effect = "Deny"
        Action = [
          "iam:CreatePolicyVersion",
          "iam:SetDefaultPolicyVersion",
          "iam:Attach*Policy",
          "iam:Put*Policy",
          "iam:CreateAccessKey",
          "iam:UpdateAssumeRolePolicy"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user" "intern" {
  name                 = "lab-intern"
  permissions_boundary = local.vulnerable ? null : aws_iam_policy.intern_boundary.arn
}

resource "aws_iam_access_key" "intern" {
  user = aws_iam_user.intern.name
}

resource "aws_iam_policy" "intern" {
  name = local.intern_policy_name
  policy = local.vulnerable ? jsonencode({
    Version   = "2012-10-17"
    Statement = [local.intern_self_read, local.intern_policy_maintenance]
    }) : jsonencode({
    Version   = "2012-10-17"
    Statement = [local.intern_self_read]
  })
}

resource "aws_iam_user_policy_attachment" "intern" {
  user       = aws_iam_user.intern.name
  policy_arn = aws_iam_policy.intern.arn
}
