# synthetic-config-hostile

Hand-derived 2026-10-27. Small committed samples that exercise diagnostics without
emitting encryption facts. Large symlink loops, FIFOs, and 6 MiB files are **not**
committed; generate those in a temporary directory at test time (R45.5).

## Committed samples

- `broken.tf` — unclosed Terraform block; HCL parse fails locally (facts stay
  empty; parse diagnostics are not wired from `extract_terraform` into the global
  sink today).
- `truncated.yaml` — malformed Kubernetes manifest (indexed as `kubernetes`, zero
  facts).
- `corrupt_testssl.json` — `scanResult` JSON truncated mid-object →
  `unsupported_result_format` for `testssl_pretty`.
- `bad_nmap.xml` — `nmaprun` with external `DOCTYPE` → `unsafe_xml`.
- `binary_skipped.json` — leading NUL byte before JSON → `binary_skipped`.

## unsupported/ (documentation-only out of scope)

- `stub.tfstate` — Terraform state snapshot; not classified by the posture index
  (no `state_file_ignored` emission yet).
- `playbook.yml` — Ansible stub without Kubernetes `apiVersion`; not indexed.

## Generated at test time (not in this tree)

- Symlink loops, FIFOs, `/etc/passwd` symlink targets, multi-megabyte lines, and
  alias bombs per `test_cbom_posture_limits.py` / R45.5.

No canary secrets here (use `synthetic-config-canary`).
