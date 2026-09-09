# Customer-managed KMS key for all audit-log encryption at rest.
# - key rotation ON            (CKV_AWS_7)
# - explicit key policy, no wildcard principal   (CKV_AWS_33 / CKV2_AWS_64)
resource "aws_kms_key" "audit" {
  description             = "CMK for tamper-proof audit-trail S3 encryption (${var.environment})"
  deletion_window_in_days = var.kms_deletion_window_days
  enable_key_rotation     = true
  multi_region            = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableAccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowS3ServiceUseForThisAccount"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      },
    ]
  })
}

resource "aws_kms_alias" "audit" {
  name          = "alias/${local.name_prefix}"
  target_key_id = aws_kms_key.audit.key_id
}
