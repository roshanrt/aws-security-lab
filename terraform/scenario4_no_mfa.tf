# Scenario 4: Valid account without MFA (console or key login)
# ATT&CK: T1078.004 Valid Accounts: Cloud Accounts
# Stratus Red Team equivalent: aws.initial-access.console-login-without-mfa
#
# Vulnerable: a contractor has a console password and an access key, no MFA,
# and a view-only policy that never asks for MFA. A phished password or a leaked
# key is enough to enumerate the account.
# Hardened: same view-only access, plus an explicit deny on everything except MFA
# self-service whenever the request was not authenticated with MFA.

locals {
  contractor_viewonly = {
    Sid      = "ViewOnly"
    Effect   = "Allow"
    Action   = ["iam:ListUsers", "iam:ListRoles", "iam:GetUser", "s3:ListAllMyBuckets", "ec2:DescribeInstances"]
    Resource = "*"
  }

  # AWS's documented "require MFA" pattern: BoolIfExists also catches long-lived keys,
  # which carry no MFA context at all.
  contractor_require_mfa = {
    Sid    = "DenyEverythingWithoutMFA"
    Effect = "Deny"
    NotAction = [
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:ResyncMFADevice",
      "iam:ChangePassword",
      "sts:GetSessionToken"
    ]
    Resource  = "*"
    Condition = { BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" } }
  }
}

resource "aws_iam_user" "contractor" {
  name = "lab-contractor"
}

# The console password is what makes ConsoleLogin possible. LocalStack stores it but
# has no sign-in endpoint, so the console login itself cannot be replayed locally.
resource "aws_iam_user_login_profile" "contractor" {
  user                    = aws_iam_user.contractor.name
  password_reset_required = false
}

resource "aws_iam_access_key" "contractor" {
  user = aws_iam_user.contractor.name
}

resource "aws_iam_user_policy" "contractor" {
  name = "lab-contractor-viewonly"
  user = aws_iam_user.contractor.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = concat([local.contractor_viewonly], local.vulnerable ? [] : [local.contractor_require_mfa])
  })
}
