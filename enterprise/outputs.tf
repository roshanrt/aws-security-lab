output "accounts" {
  value = local.accounts
}

output "scp_canary_account_id" {
  value = module.organization.scp_canary_account_id
}

output "ci_external_id" {
  value = var.ci_external_id
}

# Lab-only bootstrap identity. Exists only inside LocalStack.
output "bootstrap_credentials" {
  sensitive = true
  value     = module.identity_security.bootstrap_credentials
}

output "log_bucket" {
  value = module.logging.bucket_name
}

output "trail_buckets" {
  value = module.logging.trail_buckets
}

output "prod_key_ids" {
  value = module.data_protection_prod.key_ids
}

output "prod_backup_vaults" {
  value = module.data_protection_prod.backup_vaults
}

output "vpc_ids" {
  value = { prod = module.network_prod.vpc_id, nonprod = module.network_nonprod.vpc_id, network = module.network_hub.vpc_id }
}

output "prod_security_groups" {
  value = module.network_prod.security_group_ids
}

output "prod_workload" {
  value = {
    lambda_name   = module.workload_prod.lambda_name
    table_name    = module.workload_prod.table_name
    bucket_name   = module.workload_prod.bucket_name
    secret_arn    = module.workload_prod.secret_arn
    secret_name   = module.workload_prod.secret_name
    db_identifier = module.workload_prod.db_identifier
    app_role_arn  = module.workload_prod.app_role_arn
  }
}

output "prod_edge" {
  value = {
    alb_arn         = module.edge_prod.alb_arn
    distribution_id = module.edge_prod.distribution_id
    web_acl_arns    = module.edge_prod.web_acl_arns
  }
}

output "detection" {
  value = {
    function_name   = module.detection.function_name
    findings_table  = module.detection.findings_table
    alert_topic_arn = module.detection.alert_topic_arn
  }
}
