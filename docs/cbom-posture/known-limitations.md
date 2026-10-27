# Known limitations

Terraform `locals`, modules, remote state, and `.tfvars` values that differ from a variable default stay unresolved. The lane does not evaluate Pulumi, Ansible, or Helm templates. A directory that contains `Chart.yaml` skips `templates/`. A `kustomization.yaml` is reported and Kustomize is not applied. Terraform state files are skipped.

`stream` servers and TCP passthrough stay UNKNOWN on the transport layer. A protocol floor taken from a software default is the documented default for a pinned version. The host TLS library may only tighten it.

The scan budget is reserved in two groups: configuration classes first, then `source` and `shell`. Included files are read only in the includer's context, up to the include-depth limit.

`scale.max_raw` stays 112 so existing scores keep their divisor. Posture findings can still push a single scan to a normalized score of 100.

The dashboard card counts every CycloneDX component, including fact components. `backend/utilities/dashboard/scan.py` is unchanged.

`bomcheck.py` is not in this tree. The shipped block cap is `POSTURE_BLOCK_BYTES` (8,388,608). The 15 MiB adapter-dict governor described in the design is not a second constant here.

Live HSM firmware, custodianship, and escrow are not inspected. Declared settings are not proof of operation.
