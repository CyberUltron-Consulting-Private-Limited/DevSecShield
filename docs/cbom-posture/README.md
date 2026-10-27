# Configuration encryption posture

This lane reads declared configuration and customer-produced TLS result files. It records encryption facts, ordinary CycloneDX crypto assets, and posture findings. It does not call a cloud API, open a network connection, or inspect stored data.

`scan_crypto(path)` runs the seven posture scanners with the rest of the CBOM lane. Fact components use kind `infra`, property prefix `crypto:fact`, and bom-ref prefix `crypto-cfg_`. A scan that ran the lanes emits `cbom_posture`. A scan with no posture marker is not assessed.

## Who reads which document

| Document | Number | Reader |
| --- | --- | --- |
| Infrastructure & Cloud Encryption Posture | 5 | Platform and cloud owners |
| Network, TLS & Crypto Protocol Assessment | 6 | Network and application owners |
| Data-at-Rest Encryption Assessment | 9 | Data owners |

The Board line is `Configuration posture findings: N (R resources, M sources not assessed)`.

## How to read a verdict

| Verdict | Meaning |
| --- | --- |
| ENCRYPTED_DECLARED | A resolved attribute explicitly enables encryption |
| ENCRYPTED_PROVIDER_DEFAULT | The attribute is absent and the documented default is encrypted |
| NOT_ENCRYPTED | A resolved attribute disables encryption, or an assessable default is unencrypted |
| UNKNOWN | The attribute is unresolved, unmodeled, or not evidenceable from the declaration |

UNKNOWN does not raise `UNENCRYPTED_AT_REST`, `UNENCRYPTED_IN_TRANSIT`, or `PLAINTEXT_LISTENER`. The other posture codes fire only from an explicit signal. `non_production_hint` is a path label. It does not change severity.

A Google Cloud KMS key with no `rotation_period` is UNKNOWN `default_unknown` and does not raise `KMS_KEY_ROTATION_DISABLED`. Every `azurerm_key_vault_key` records rotation as `not_applicable`.

## Lanes

<!-- table:lanes -->
| name | order |
| --- | --- |
| posture_iac | 31 |
| posture_server | 32 |
| posture_database | 33 |
| posture_tls_import | 34 |
| posture_verification | 36 |
| posture_linkage | 38 |
| posture_findings | 45 |

Each scanner module has one `name` line and one `order` line, and `level = 1`.
