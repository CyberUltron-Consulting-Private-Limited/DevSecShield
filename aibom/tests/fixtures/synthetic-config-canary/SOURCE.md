# synthetic-config-canary

Hand-derived 2026-10-27. One deliberate canary for redaction tests later.

- `main.tf` — `aws_db_instance.canary` with `storage_encrypted = false` and
  `password = "CANARY_POSTURE_SECRET_9f3a"`. The password must appear in the
  committed source but must not surface in `scan_crypto` components, flags,
  diagnostics, or the normalized run object (see `test_cbom_posture_canaries.py`).

Oracle row matches the Terraform fact only; the canary string is never an
oracle field.
