variable "region" {
  description = "AWS region emulated by LocalStack."
  type        = string
  default     = "us-east-1"
}

variable "localstack_endpoint" {
  description = "LocalStack edge endpoint."
  type        = string
  default     = "http://localhost:4566"
}

variable "lab_mode" {
  description = "vulnerable = deliberate misconfigurations, hardened = fixed controls."
  type        = string
  default     = "vulnerable"

  validation {
    condition     = contains(["vulnerable", "hardened"], var.lab_mode)
    error_message = "lab_mode must be \"vulnerable\" or \"hardened\"."
  }
}
