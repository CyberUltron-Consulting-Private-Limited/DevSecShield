# synthetic-config-aws-tf

Hand-written Terraform. `aws_db_instance.plain` sets `storage_encrypted = false`. `aws_s3_bucket.logs` omits encryption, so the reviewed S3 row applies. No secrets are planted in this tree.
