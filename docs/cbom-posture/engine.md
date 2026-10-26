# Configuration posture lane

`scan_crypto` runs the seven posture scanners and returns a `CbomScanResult`. Fact components use kind `infra` and property `crypto:factId`. They stay out of `cbom_graph`. `cbom_posture` is added only when the result is a `CbomScanResult`.

The committed tree `aibom/tests/fixtures/synthetic-config-aws-tf` is scanned by `tests/test_cbom_posture_fixture_scan.py`. `aws_db_instance.plain` is `NOT_ENCRYPTED` and raises `UNENCRYPTED_AT_REST`. `aws_s3_bucket.logs` is `ENCRYPTED_PROVIDER_DEFAULT`.

The 18 `synthetic-crypto-*` digests are unchanged. This lane does not call an LLM and does not open a network connection.
