# Scenario 2: Defense evasion by disabling CloudTrail
# ATT&CK: T1562.008 Impair Defenses: Disable or Modify Cloud Logs
#
# Vulnerable: an automation user was given cloudtrail:* "to manage trails".
# Hardened: read-only CloudTrail access plus an explicit deny on tampering.

locals {
  ops_policy_vulnerable = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "OverbroadTrailAdmin"
        Effect   = "Allow"
        Action   = "cloudtrail:*"
        Resource = "*"
      }
    ]
  })

  ops_policy_hardened = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TrailReadOnly"
        Effect = "Allow"
        Action = [
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrail",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:GetEventSelectors",
          "cloudtrail:ListTrails",
          "cloudtrail:LookupEvents"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyLogTampering"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail",
          "cloudtrail:UpdateTrail",
          "cloudtrail:PutEventSelectors",
          "cloudtrail:PutInsightSelectors"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user" "ops" {
  name = "lab-ops"
}

resource "aws_iam_access_key" "ops" {
  user = aws_iam_user.ops.name
}

resource "aws_iam_user_policy" "ops" {
  name   = "lab-ops-cloudtrail"
  user   = aws_iam_user.ops.name
  policy = local.vulnerable ? local.ops_policy_vulnerable : local.ops_policy_hardened
}
