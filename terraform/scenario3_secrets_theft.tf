# Scenario 3: Credential theft from Secrets Manager
# ATT&CK: T1555.006 Credentials from Password Stores: Cloud Secrets Management Stores
#
# Vulnerable: the app identity can read and decrypt every secret.
# Hardened: GetSecretValue on its own secret only, and kms:Decrypt only
# when the call comes through Secrets Manager.

locals {
  app_policy_vulnerable = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "OverbroadSecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret", "secretsmanager:ListSecrets"]
        Resource = "*"
      },
      {
        Sid      = "OverbroadDecrypt"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = "*"
      }
    ]
  })

  app_policy_hardened = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "OwnSecretOnly"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = aws_secretsmanager_secret.app_api_key.arn
      },
      {
        Sid      = "DecryptViaSecretsManagerOnly"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = aws_kms_key.lab.arn
        Condition = {
          StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" }
        }
      }
    ]
  })
}

resource "aws_iam_user" "app" {
  name = "lab-app"
}

resource "aws_iam_access_key" "app" {
  user = aws_iam_user.app.name
}

resource "aws_iam_user_policy" "app" {
  name   = "lab-app-secrets"
  user   = aws_iam_user.app.name
  policy = local.vulnerable ? local.app_policy_vulnerable : local.app_policy_hardened
}
