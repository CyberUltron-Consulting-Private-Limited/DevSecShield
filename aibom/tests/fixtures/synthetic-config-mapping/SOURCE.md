# synthetic-config-mapping

Hand-derived 2026-10-27. Business mapping files do not emit encryption facts by
themselves; this tree adds a minimal Terraform S3 resource so linkage can
attach (patterns from `test_cbom_posture_business.py`).

- `cbom-mapping.yaml` — version 1, defaults `system: billing` / `owner:
  declared-owner`, entry matching `kind: object_store` + `path: main.tf` sets
  `system: payments`.
- `CODEOWNERS` — `* @platform` supplies `owner_hint` (mapping file wins for
  `system`/`owner`, CODEOWNERS for hint).
- `main.tf` — `aws_s3_bucket.logs` → one object_store fact,
  `ENCRYPTED_PROVIDER_DEFAULT`, no posture finding codes.

No secrets in this tree.
