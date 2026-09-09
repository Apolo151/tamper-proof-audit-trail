# Local backend keeps this module self-contained for `terraform validate` and
# Checkov scanning in CI. A real deployment would supply an encrypted, locked
# remote backend at init time, e.g.:
#
#   terraform init \
#     -backend-config="bucket=my-tfstate" \
#     -backend-config="key=audit-trail/terraform.tfstate" \
#     -backend-config="region=eu-north-1" \
#     -backend-config="dynamodb_table=my-tf-locks" \
#     -backend-config="encrypt=true"
terraform {
  backend "local" {}
}
