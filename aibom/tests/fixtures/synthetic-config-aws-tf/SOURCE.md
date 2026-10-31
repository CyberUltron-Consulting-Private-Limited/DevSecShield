# synthetic-config-aws-tf

Hand-derived 2026-10-27. Values come from reading `main.tf` and the AWS
Defaults_Registry rows, never from running the product.

- `aws_db_instance.plain` sets `storage_encrypted = false`. That is an explicit
  disable, so the at-rest Layer and Verdict are `NOT_ENCRYPTED` and
  `UNENCRYPTED_AT_REST` fires (coverage row `aws.rds.storage_encrypted`).
- `aws_s3_bucket.logs` omits a server-side encryption block. The reviewed S3
  provider-default row (`aws.s3.default_encryption`) yields
  `ENCRYPTED_PROVIDER_DEFAULT` with an empty finding set.

No secrets are planted in this tree. Broader AWS scenarios (KMS rotation,
replicas, monorepo, policy documents) land in later commits under this same tree.
