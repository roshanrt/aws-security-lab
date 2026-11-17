# GENERATED LAYOUT: one provider alias per account. LocalStack maps a 12-digit
# access key ID to that account, so each alias is the root (deployer) identity of
# one account. Every service the modules use is pinned to the LocalStack endpoint;
# a service missing from an endpoints block would resolve to real AWS, so keep the
# six blocks identical.

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}
provider "aws" {
  alias                       = "mgmt"
  region                      = var.region
  access_key                  = local.accounts.mgmt
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true

  endpoints {
    acm            = var.localstack_endpoint
    backup         = var.localstack_endpoint
    cloudfront     = var.localstack_endpoint
    cloudtrail     = var.localstack_endpoint
    cloudwatch     = var.localstack_endpoint
    dynamodb       = var.localstack_endpoint
    ec2            = var.localstack_endpoint
    elbv2          = var.localstack_endpoint
    events         = var.localstack_endpoint
    iam            = var.localstack_endpoint
    kms            = var.localstack_endpoint
    lambda         = var.localstack_endpoint
    logs           = var.localstack_endpoint
    organizations  = var.localstack_endpoint
    rds            = var.localstack_endpoint
    route53        = var.localstack_endpoint
    s3             = var.localstack_endpoint
    s3control      = var.s3control_endpoint
    secretsmanager = var.localstack_endpoint
    sns            = var.localstack_endpoint
    sqs            = var.localstack_endpoint
    ssm            = var.localstack_endpoint
    sts            = var.localstack_endpoint
    wafv2          = var.localstack_endpoint
  }

  default_tags {
    tags = { Project = "aws-security-lab-enterprise", ManagedBy = "terraform", Account = "mgmt" }
  }
}

provider "aws" {
  alias                       = "log_archive"
  region                      = var.region
  access_key                  = local.accounts.log_archive
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true

  endpoints {
    acm            = var.localstack_endpoint
    backup         = var.localstack_endpoint
    cloudfront     = var.localstack_endpoint
    cloudtrail     = var.localstack_endpoint
    cloudwatch     = var.localstack_endpoint
    dynamodb       = var.localstack_endpoint
    ec2            = var.localstack_endpoint
    elbv2          = var.localstack_endpoint
    events         = var.localstack_endpoint
    iam            = var.localstack_endpoint
    kms            = var.localstack_endpoint
    lambda         = var.localstack_endpoint
    logs           = var.localstack_endpoint
    organizations  = var.localstack_endpoint
    rds            = var.localstack_endpoint
    route53        = var.localstack_endpoint
    s3             = var.localstack_endpoint
    s3control      = var.s3control_endpoint
    secretsmanager = var.localstack_endpoint
    sns            = var.localstack_endpoint
    sqs            = var.localstack_endpoint
    ssm            = var.localstack_endpoint
    sts            = var.localstack_endpoint
    wafv2          = var.localstack_endpoint
  }

  default_tags {
    tags = { Project = "aws-security-lab-enterprise", ManagedBy = "terraform", Account = "log_archive" }
  }
}

provider "aws" {
  alias                       = "security"
  region                      = var.region
  access_key                  = local.accounts.security
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true

  endpoints {
    acm            = var.localstack_endpoint
    backup         = var.localstack_endpoint
    cloudfront     = var.localstack_endpoint
    cloudtrail     = var.localstack_endpoint
    cloudwatch     = var.localstack_endpoint
    dynamodb       = var.localstack_endpoint
    ec2            = var.localstack_endpoint
    elbv2          = var.localstack_endpoint
    events         = var.localstack_endpoint
    iam            = var.localstack_endpoint
    kms            = var.localstack_endpoint
    lambda         = var.localstack_endpoint
    logs           = var.localstack_endpoint
    organizations  = var.localstack_endpoint
    rds            = var.localstack_endpoint
    route53        = var.localstack_endpoint
    s3             = var.localstack_endpoint
    s3control      = var.s3control_endpoint
    secretsmanager = var.localstack_endpoint
    sns            = var.localstack_endpoint
    sqs            = var.localstack_endpoint
    ssm            = var.localstack_endpoint
    sts            = var.localstack_endpoint
    wafv2          = var.localstack_endpoint
  }

  default_tags {
    tags = { Project = "aws-security-lab-enterprise", ManagedBy = "terraform", Account = "security" }
  }
}

provider "aws" {
  alias                       = "network"
  region                      = var.region
  access_key                  = local.accounts.network
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true

  endpoints {
    acm            = var.localstack_endpoint
    backup         = var.localstack_endpoint
    cloudfront     = var.localstack_endpoint
    cloudtrail     = var.localstack_endpoint
    cloudwatch     = var.localstack_endpoint
    dynamodb       = var.localstack_endpoint
    ec2            = var.localstack_endpoint
    elbv2          = var.localstack_endpoint
    events         = var.localstack_endpoint
    iam            = var.localstack_endpoint
    kms            = var.localstack_endpoint
    lambda         = var.localstack_endpoint
    logs           = var.localstack_endpoint
    organizations  = var.localstack_endpoint
    rds            = var.localstack_endpoint
    route53        = var.localstack_endpoint
    s3             = var.localstack_endpoint
    s3control      = var.s3control_endpoint
    secretsmanager = var.localstack_endpoint
    sns            = var.localstack_endpoint
    sqs            = var.localstack_endpoint
    ssm            = var.localstack_endpoint
    sts            = var.localstack_endpoint
    wafv2          = var.localstack_endpoint
  }

  default_tags {
    tags = { Project = "aws-security-lab-enterprise", ManagedBy = "terraform", Account = "network" }
  }
}

provider "aws" {
  alias                       = "prod"
  region                      = var.region
  access_key                  = local.accounts.prod
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true

  endpoints {
    acm            = var.localstack_endpoint
    backup         = var.localstack_endpoint
    cloudfront     = var.localstack_endpoint
    cloudtrail     = var.localstack_endpoint
    cloudwatch     = var.localstack_endpoint
    dynamodb       = var.localstack_endpoint
    ec2            = var.localstack_endpoint
    elbv2          = var.localstack_endpoint
    events         = var.localstack_endpoint
    iam            = var.localstack_endpoint
    kms            = var.localstack_endpoint
    lambda         = var.localstack_endpoint
    logs           = var.localstack_endpoint
    organizations  = var.localstack_endpoint
    rds            = var.localstack_endpoint
    route53        = var.localstack_endpoint
    s3             = var.localstack_endpoint
    s3control      = var.s3control_endpoint
    secretsmanager = var.localstack_endpoint
    sns            = var.localstack_endpoint
    sqs            = var.localstack_endpoint
    ssm            = var.localstack_endpoint
    sts            = var.localstack_endpoint
    wafv2          = var.localstack_endpoint
  }

  default_tags {
    tags = { Project = "aws-security-lab-enterprise", ManagedBy = "terraform", Account = "prod" }
  }
}

provider "aws" {
  alias                       = "nonprod"
  region                      = var.region
  access_key                  = local.accounts.nonprod
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true

  endpoints {
    acm            = var.localstack_endpoint
    backup         = var.localstack_endpoint
    cloudfront     = var.localstack_endpoint
    cloudtrail     = var.localstack_endpoint
    cloudwatch     = var.localstack_endpoint
    dynamodb       = var.localstack_endpoint
    ec2            = var.localstack_endpoint
    elbv2          = var.localstack_endpoint
    events         = var.localstack_endpoint
    iam            = var.localstack_endpoint
    kms            = var.localstack_endpoint
    lambda         = var.localstack_endpoint
    logs           = var.localstack_endpoint
    organizations  = var.localstack_endpoint
    rds            = var.localstack_endpoint
    route53        = var.localstack_endpoint
    s3             = var.localstack_endpoint
    s3control      = var.s3control_endpoint
    secretsmanager = var.localstack_endpoint
    sns            = var.localstack_endpoint
    sqs            = var.localstack_endpoint
    ssm            = var.localstack_endpoint
    sts            = var.localstack_endpoint
    wafv2          = var.localstack_endpoint
  }

  default_tags {
    tags = { Project = "aws-security-lab-enterprise", ManagedBy = "terraform", Account = "nonprod" }
  }
}
