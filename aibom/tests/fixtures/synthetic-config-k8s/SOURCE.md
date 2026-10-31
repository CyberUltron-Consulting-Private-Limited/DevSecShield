# synthetic-config-k8s

Hand-derived 2026-10-27. Manifests mirror patterns in
`test_cbom_posture_kubernetes.py`; oracle rows verified with `scan_crypto`.

- `encryption-config.yaml` — `EncryptionConfiguration` with a `secretbox`
  provider for `secrets` → `ENCRYPTED_DECLARED` / `local_file` on the etcd
  encryption fact. The inline provider secret is posture-canary material only
  (crypto misuse may flag separately; posture fact finding_codes stay empty).
- `secret.yaml` — empty `Opaque` Secret → `secret_store` with
  `layer_not_observable`.
- `ingress.yaml` — `networking.k8s.io/v1` Ingress with `tls.secretName`
  `edge-tls` → TLS endpoint `ENCRYPTED_DECLARED`.

StorageClass is intentionally omitted: the kubernetes extractor does not emit a
fact for `StorageClass` in the current coverage wiring.
