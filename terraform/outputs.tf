output "audit_bucket_id" {
  description = "Name of the WORM audit-log bucket."
  value       = aws_s3_bucket.audit.id
}

output "audit_bucket_arn" {
  description = "ARN of the WORM audit-log bucket."
  value       = aws_s3_bucket.audit.arn
}

output "log_bucket_id" {
  description = "Name of the S3 server-access-log bucket."
  value       = aws_s3_bucket.logs.id
}

output "log_bucket_arn" {
  description = "ARN of the S3 server-access-log bucket."
  value       = aws_s3_bucket.logs.arn
}

output "kms_key_arn" {
  description = "ARN of the CMK protecting the audit logs."
  value       = aws_kms_key.audit.arn
}

output "kms_alias" {
  description = "Alias of the CMK protecting the audit logs."
  value       = aws_kms_alias.audit.name
}
