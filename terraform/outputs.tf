output "lab_mode" {
  value = var.lab_mode
}

output "trail_name" {
  value = aws_cloudtrail.lab.name
}

output "intern_policy_arn" {
  value = aws_iam_policy.intern.arn
}

output "app_secret_name" {
  value = aws_secretsmanager_secret.app_api_key.name
}

output "prod_secret_name" {
  value = aws_secretsmanager_secret.prod_db.name
}

# Lab-only keys for the five attacker identities. They exist only in LocalStack.
output "credentials" {
  sensitive = true
  value = {
    intern = {
      access_key_id     = aws_iam_access_key.intern.id
      secret_access_key = aws_iam_access_key.intern.secret
    }
    ops = {
      access_key_id     = aws_iam_access_key.ops.id
      secret_access_key = aws_iam_access_key.ops.secret
    }
    app = {
      access_key_id     = aws_iam_access_key.app.id
      secret_access_key = aws_iam_access_key.app.secret
    }
    dev = {
      access_key_id     = aws_iam_access_key.dev.id
      secret_access_key = aws_iam_access_key.dev.secret
    }
    contractor = {
      access_key_id     = aws_iam_access_key.contractor.id
      secret_access_key = aws_iam_access_key.contractor.secret
    }
  }
}

output "data_bucket" {
  value = aws_s3_bucket.customer_data.id
}
