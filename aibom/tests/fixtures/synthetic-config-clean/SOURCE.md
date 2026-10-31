# synthetic-config-clean

Hand-derived 2026-10-27. This tree intentionally contains no Terraform,
Kubernetes, server TLS, database, or other configuration that the posture lane
classifies as an encryption resource.

- `README.md` and an empty `.gitignore` only.
- Expected oracle: zero `facts`; all total counters empty or zero.

No secrets are planted in this tree.
