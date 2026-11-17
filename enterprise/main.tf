# Enterprise landing zone on LocalStack. One module per layer, applied in this
# order: organization, identity, logging, data-protection, network, workload,
# edge, detection.

locals {
  accounts = {
    mgmt        = "999999999999" # organization management: OUs and SCPs only
    log_archive = "111111111111" # immutable log storage
    security    = "222222222222" # identity hub, detection pipeline, findings, response
    network     = "333333333333" # shared ingress/egress hub
    prod        = "444444444444"
    nonprod     = "555555555555"
  }

  detector_role_arn = "arn:aws:iam::${local.accounts.security}:role/lz-detector"
}

# ---------- Layer: organization ----------

module "organization" {
  source           = "./modules/organization"
  providers        = { aws = aws.mgmt }
  approved_regions = var.approved_regions
}

# ---------- Layer: identity (one instance per account) ----------

module "identity_security" {
  source              = "./modules/identity"
  providers           = { aws = aws.security }
  account_id          = local.accounts.security
  account_name        = "security-tooling"
  identity_account_id = local.accounts.security
  approved_regions    = var.approved_regions
  is_identity_hub     = true
  ci_external_id      = var.ci_external_id
  detector_role_arn   = local.detector_role_arn
}

module "identity_log_archive" {
  source              = "./modules/identity"
  providers           = { aws = aws.log_archive }
  account_id          = local.accounts.log_archive
  account_name        = "log-archive"
  identity_account_id = local.accounts.security
  approved_regions    = var.approved_regions
  ci_external_id      = var.ci_external_id
  detector_role_arn   = local.detector_role_arn
}

module "identity_network" {
  source              = "./modules/identity"
  providers           = { aws = aws.network }
  account_id          = local.accounts.network
  account_name        = "network"
  identity_account_id = local.accounts.security
  approved_regions    = var.approved_regions
  ci_external_id      = var.ci_external_id
  detector_role_arn   = local.detector_role_arn
}

module "identity_prod" {
  source              = "./modules/identity"
  providers           = { aws = aws.prod }
  account_id          = local.accounts.prod
  account_name        = "workload-prod"
  identity_account_id = local.accounts.security
  approved_regions    = var.approved_regions
  is_workload         = true
  bootstrap_user_arn  = module.identity_security.bootstrap_user_arn
  ci_external_id      = var.ci_external_id
  detector_role_arn   = local.detector_role_arn
}

module "identity_nonprod" {
  source              = "./modules/identity"
  providers           = { aws = aws.nonprod }
  account_id          = local.accounts.nonprod
  account_name        = "workload-nonprod"
  identity_account_id = local.accounts.security
  approved_regions    = var.approved_regions
  is_workload         = true
  bootstrap_user_arn  = module.identity_security.bootstrap_user_arn
  ci_external_id      = var.ci_external_id
  detector_role_arn   = local.detector_role_arn
}

# ---------- Layer: logging ----------

module "logging" {
  source = "./modules/logging"
  providers = {
    aws.log_archive = aws.log_archive
    aws.security    = aws.security
    aws.network     = aws.network
    aws.prod        = aws.prod
    aws.nonprod     = aws.nonprod
  }
  accounts               = { for k, v in local.accounts : k => v if k != "mgmt" }
  log_archive_account_id = local.accounts.log_archive
  security_account_id    = local.accounts.security
  region                 = var.region

  central_trail_delivery = var.central_trail_delivery

  depends_on = [module.identity_log_archive, module.identity_security]
}

# ---------- Layer: data protection ----------

module "data_protection_prod" {
  source                   = "./modules/data-protection"
  providers                = { aws = aws.prod }
  account_id               = local.accounts.prod
  workload                 = "prod"
  region                   = var.region
  enable_backup_vault_lock = var.enable_backup_vault_lock

  depends_on = [module.identity_prod]
}

# ---------- Layer: network ----------
# Same three-tier module in each workload account, plus the shared hub VPC in the
# network account (design only locally: there is no transit gateway attachment).

module "network_prod" {
  source              = "./modules/network"
  providers           = { aws = aws.prod }
  name                = "prod"
  cidr                = "10.10.0.0/16"
  region              = var.region
  flow_log_bucket_arn = module.logging.bucket_arn
}

module "network_nonprod" {
  source              = "./modules/network"
  providers           = { aws = aws.nonprod }
  name                = "nonprod"
  cidr                = "10.20.0.0/16"
  region              = var.region
  flow_log_bucket_arn = module.logging.bucket_arn
}

module "network_hub" {
  source              = "./modules/network"
  providers           = { aws = aws.network }
  name                = "hub"
  cidr                = "10.0.0.0/16"
  region              = var.region
  flow_log_bucket_arn = module.logging.bucket_arn
}

# ---------- Layer: workload (prod) ----------

module "workload_prod" {
  source                 = "./modules/workload"
  providers              = { aws = aws.prod }
  name                   = "prod"
  account_id             = local.accounts.prod
  region                 = var.region
  app_subnet_ids         = module.network_prod.subnet_ids["app"]
  data_subnet_ids        = module.network_prod.subnet_ids["data"]
  app_security_group_id  = module.network_prod.security_group_ids["app"]
  data_security_group_id = module.network_prod.security_group_ids["data"]
  key_arns               = module.data_protection_prod.key_arns
  workload_boundary_arn  = module.identity_prod.workload_boundary_arn
}

# ---------- Layer: edge (prod) ----------

module "edge_prod" {
  source                = "./modules/edge"
  providers             = { aws = aws.prod }
  name                  = "prod"
  domain_name           = "app.prod.lab.example"
  vpc_id                = module.network_prod.vpc_id
  public_subnet_ids     = module.network_prod.subnet_ids["public"]
  alb_security_group_id = module.network_prod.security_group_ids["alb"]
  lambda_arn            = module.workload_prod.lambda_arn
  lambda_name           = module.workload_prod.lambda_name
}

# ---------- Layer: detection and response (security-tooling) ----------

module "detection" {
  source = "./modules/detection"
  providers = {
    aws.security    = aws.security
    aws.log_archive = aws.log_archive
    aws.network     = aws.network
    aws.prod        = aws.prod
    aws.nonprod     = aws.nonprod
  }
  account_id              = local.accounts.security
  region                  = var.region
  member_accounts         = { for k, v in local.accounts : k => v if k != "mgmt" }
  workload_account_ids    = [local.accounts.prod, local.accounts.nonprod]
  guardrail_boundary_arn  = module.identity_security.guardrail_boundary_arn
  enable_event_forwarding = var.enable_event_forwarding

  # Lab: Terraform runs as each account's root. On real AWS, list the pipeline's
  # deploy role here and treat any root activity as a finding.
  trusted_deployer_arns = [for k, v in local.accounts : "arn:aws:iam::${v}:root"]

  secret_allowlist = {
    (module.workload_prod.secret_name) = ["app-prod-api", "lz-break-glass"]
  }

  depends_on = [module.identity_log_archive, module.identity_network, module.identity_prod, module.identity_nonprod]
}
