# synthetic-config-cfn

Hand-derived 2026-10-27 from `stack.yaml` and the AWS coverage table (same
verdicts as `test_cbom_posture_cloudformation.py` / the Terraform twin in
`synthetic-config-aws-tf`).

- `PlainDb` (`AWS::RDS::DBInstance`) sets `StorageEncrypted: false` → service
  layer `NOT_ENCRYPTED`, `UNENCRYPTED_AT_REST`.
- `LogsBucket` (`AWS::S3::Bucket`) omits bucket encryption → provider default
  row `aws.s3.sse_default` → `ENCRYPTED_PROVIDER_DEFAULT`, no finding.

No secrets in this tree.
