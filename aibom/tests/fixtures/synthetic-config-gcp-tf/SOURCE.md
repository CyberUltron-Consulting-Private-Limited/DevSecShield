# synthetic-config-gcp-tf

Hand-derived 2026-10-27. Values come from reading `main.tf` and the GCP
coverage/default rows, cross-checked with `scan_crypto` on this tree.

- `google_kms_crypto_key.app` omits `rotation_period`. Posture leaves rotation
  `UNKNOWN` with `default_unknown` and does **not** raise
  `KMS_KEY_ROTATION_DISABLED` (K-18).
- `google_storage_bucket.data` names the bucket only; the GCS service layer is
  `attribute_not_modeled` with no at-rest finding.
- `google_kms_crypto_key_iam_binding.open` grants `allUsers` on the crypto key
  role; `KMS_KEY_POLICY_PUBLIC` fires on the binding fact.

No live Terraform apply. No secrets beyond the public IAM member literal.
