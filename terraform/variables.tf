variable "region" {
  description = "AWS region for the audit-log storage."
  type        = string
  default     = "eu-north-1"
}

variable "environment" {
  description = "Deployment environment (dev/stage/prod). Used in tags and names."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "stage", "prod"], var.environment)
    error_message = "environment must be one of: dev, stage, prod."
  }
}

variable "audit_bucket_name" {
  description = "Override name for the WORM audit-log bucket. Empty = derive from prefix."
  type        = string
  default     = null
}

variable "log_bucket_name" {
  description = "Override name for the S3 server-access-log bucket. Empty = derive from prefix."
  type        = string
  default     = null
}

variable "retention_days" {
  description = "S3 Object Lock COMPLIANCE retention for every audit object, in days (default 10 years)."
  type        = number
  default     = 3650

  validation {
    condition     = var.retention_days >= 1
    error_message = "retention_days must be at least 1."
  }
}

variable "kms_deletion_window_days" {
  description = "Waiting period before the CMK is actually deleted after a destroy."
  type        = number
  default     = 30
}

variable "noncurrent_version_expiration_days" {
  description = "Expire noncurrent object versions in the audit bucket after this many days."
  type        = number
  default     = 365
}

variable "log_bucket_expiration_days" {
  description = "Expire access-log objects after this many days."
  type        = number
  default     = 90
}
