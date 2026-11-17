# Layer: network. One VPC, three tiers, two AZs.
#
#   public       : ALB only. Route to the internet gateway.
#   private-app  : application. No internet route at all; reaches AWS through VPC endpoints.
#   isolated-data: databases. No route out of the VPC, and a NACL that only talks to the app tier.
#
# Security groups reference each other by ID, never by CIDR. The single exception is
# the ALB, which accepts 443 from the internet.
# There is no NAT gateway: nothing in a workload VPC can start a connection to the internet.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

variable "name" { type = string }
variable "cidr" {
  description = "A /16. Tiers are carved out as /20s."
  type        = string
}
variable "region" { type = string }
variable "flow_log_bucket_arn" {
  description = "Log-archive bucket that receives VPC Flow Logs."
  type        = string
}
variable "app_port" {
  type    = number
  default = 8080
}
variable "db_port" {
  type    = number
  default = 5432
}

locals {
  azs = ["${var.region}a", "${var.region}b"]

  # tier => index offset for cidrsubnet
  tiers = { public = 0, app = 2, data = 4 }

  subnets = merge([
    for tier, offset in local.tiers : {
      for i, az in local.azs : "${tier}-${i}" => {
        tier = tier
        az   = az
        cidr = cidrsubnet(var.cidr, 4, offset + i)
      }
    }
  ]...)

  interface_endpoints = ["secretsmanager", "kms", "sts"]
}

resource "aws_vpc" "this" {
  cidr_block           = var.cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = var.name }
}

# The default security group allows nothing, so a resource launched without an
# explicit group gets no connectivity.
resource "aws_default_security_group" "locked" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-default-locked" }
}

resource "aws_subnet" "this" {
  #checkov:skip=CKV_AWS_130:map_public_ip_on_launch is false on every subnet, public tier included; only the ALB lives there.
  for_each                = local.subnets
  vpc_id                  = aws_vpc.this.id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.az
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name}-${each.key}", Tier = each.value.tier }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = var.name }
}

# ---------- Routing: only the public tier has a default route ----------

resource "aws_route_table" "tier" {
  for_each = local.tiers
  vpc_id   = aws_vpc.this.id
  tags     = { Name = "${var.name}-${each.key}", Tier = each.key }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.tier["public"].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "this" {
  for_each       = local.subnets
  subnet_id      = aws_subnet.this[each.key].id
  route_table_id = aws_route_table.tier[each.value.tier].id
}

# ---------- Data tier NACL: app tier in, replies out, nothing else ----------

resource "aws_network_acl" "data" {
  vpc_id     = aws_vpc.this.id
  subnet_ids = [for k, s in aws_subnet.this : s.id if local.subnets[k].tier == "data"]
  tags       = { Name = "${var.name}-data", Tier = "data" }
}

locals {
  app_cidrs = { for k, s in local.subnets : k => s.cidr if s.tier == "app" }
}

resource "aws_network_acl_rule" "data_in_from_app" {
  for_each       = local.app_cidrs
  network_acl_id = aws_network_acl.data.id
  rule_number    = 100 + index(keys(local.app_cidrs), each.key)
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = each.value
  from_port      = var.db_port
  to_port        = var.db_port
}

resource "aws_network_acl_rule" "data_out_to_app" {
  for_each       = local.app_cidrs
  network_acl_id = aws_network_acl.data.id
  rule_number    = 100 + index(keys(local.app_cidrs), each.key)
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = each.value
  from_port      = 1024
  to_port        = 65535
}

# ---------- Security groups, chained by ID ----------

resource "aws_security_group" "alb" {
  #checkov:skip=CKV2_AWS_5:Attached to the ALB by the edge module.
  name        = "${var.name}-alb"
  description = "Public entry point. HTTPS from the internet, forwards only to the app tier."
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-alb", Tier = "public", "lz:public-ingress" = "allowed-443" }
}

resource "aws_security_group" "app" {
  #checkov:skip=CKV2_AWS_5:Attached to the application by the workload module.
  name        = "${var.name}-app"
  description = "Application tier. Reachable only from the ALB."
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-app", Tier = "app" }
}

resource "aws_security_group" "data" {
  #checkov:skip=CKV2_AWS_5:Attached to the database by the workload module.
  name        = "${var.name}-data"
  description = "Data tier. Reachable only from the application tier. No egress."
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-data", Tier = "data" }
}

resource "aws_security_group" "endpoints" {
  name        = "${var.name}-endpoints"
  description = "VPC interface endpoints. Reachable only from the application tier."
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-endpoints", Tier = "app" }
}

resource "aws_vpc_security_group_ingress_rule" "alb_https_from_internet" {
  #checkov:skip=CKV_AWS_260:Not port 80. This is the one intended public listener (443) for the whole VPC.
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from the internet (the only public ingress in the VPC)"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Forward to the application tier only"
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
}

resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = aws_security_group.app.id
  description                  = "From the ALB only"
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
}

resource "aws_vpc_security_group_egress_rule" "app_to_data" {
  security_group_id            = aws_security_group.app.id
  description                  = "To the database"
  referenced_security_group_id = aws_security_group.data.id
  ip_protocol                  = "tcp"
  from_port                    = var.db_port
  to_port                      = var.db_port
}

resource "aws_vpc_security_group_egress_rule" "app_to_endpoints" {
  security_group_id            = aws_security_group.app.id
  description                  = "To AWS APIs through interface endpoints"
  referenced_security_group_id = aws_security_group.endpoints.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_egress_rule" "app_to_s3_gateway" {
  security_group_id = aws_security_group.app.id
  description       = "To S3 and DynamoDB through gateway endpoints (prefix lists, not CIDRs)"
  for_each          = aws_vpc_endpoint.gateway
  prefix_list_id    = each.value.prefix_list_id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_ingress_rule" "data_from_app" {
  security_group_id            = aws_security_group.data.id
  description                  = "From the application tier only"
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = var.db_port
  to_port                      = var.db_port
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_app" {
  security_group_id            = aws_security_group.endpoints.id
  description                  = "From the application tier only"
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

# ---------- VPC endpoints: AWS APIs without an internet path ----------

resource "aws_vpc_endpoint" "gateway" {
  for_each          = toset(["s3", "dynamodb"])
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.tier["app"].id]
  tags              = { Name = "${var.name}-${each.key}" }
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = toset(local.interface_endpoints)
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for k, s in aws_subnet.this : s.id if local.subnets[k].tier == "app"]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = { Name = "${var.name}-${each.key}" }
}

# ---------- Flow logs to the log archive ----------

resource "aws_flow_log" "vpc" {
  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = "${var.flow_log_bucket_arn}/flow-logs/${var.name}/"
  max_aggregation_interval = 60
  tags                     = { Name = "${var.name}-flow-logs" }
}

output "vpc_id" {
  value = aws_vpc.this.id
}

output "subnet_ids" {
  value = { for tier in keys(local.tiers) : tier => [for k, s in aws_subnet.this : s.id if local.subnets[k].tier == tier] }
}

output "security_group_ids" {
  value = {
    alb       = aws_security_group.alb.id
    app       = aws_security_group.app.id
    data      = aws_security_group.data.id
    endpoints = aws_security_group.endpoints.id
  }
}
