provider "aws" {
  region = var.region

  # Never applied in this project (validate-only). Set to true so a stray
  # `terraform plan` without credentials fails fast instead of calling AWS.
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true

  default_tags {
    tags = {
      Project     = "tamper-proof-audit-trail"
      ManagedBy   = "terraform"
      Environment = var.environment
      Compliance  = "audit-worm"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id   = data.aws_caller_identity.current.account_id
  name_prefix  = "audit-trail-${var.environment}"
  audit_bucket = coalesce(var.audit_bucket_name, "${local.name_prefix}-logs")
  log_bucket   = coalesce(var.log_bucket_name, "${local.name_prefix}-access-logs")
}
