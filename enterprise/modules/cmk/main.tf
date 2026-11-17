# Helper: one customer managed KMS key with rotation and a key policy that keeps
# key administration and key use apart.
#
# - Administrators can manage the key but hold no cryptographic actions.
# - Use is granted only by the usage statements passed in (normally "only through
#   service X, only from this account").
# - There is no "kms:*" statement, so even an account administrator cannot decrypt
#   without changing the key policy, which is a logged, detected event (ENT-002/006).

terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

variable "alias" { type = string }
variable "description" { type = string }
variable "admin_arns" {
  description = "Principals allowed to administer (not use) the key."
  type        = list(string)
}
variable "usage_statements" {
  description = "Key policy statements that grant use of the key."
  type        = any
  default     = []
}

resource "aws_kms_key" "this" {
  description             = var.description
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid       = "KeyAdministrationNoCryptoUse"
        Effect    = "Allow"
        Principal = { AWS = var.admin_arns }
        Action = [
          "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*",
          "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*", "kms:TagResource", "kms:UntagResource",
          "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:RotateKeyOnDemand",
          # Redundant with kms:Put* on real AWS; LocalStack's lockout check does not
          # expand wildcards and rejects the policy without the explicit action.
          "kms:PutKeyPolicy"
        ]
        Resource = "*"
      }
    ], var.usage_statements)
  })

  tags = { DataClass = var.alias }
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.alias}"
  target_key_id = aws_kms_key.this.key_id
}

output "arn" {
  value = aws_kms_key.this.arn
}

output "key_id" {
  value = aws_kms_key.this.key_id
}
