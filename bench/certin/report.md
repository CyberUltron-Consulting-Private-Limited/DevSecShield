# CERT-In Phase 6 — Multi-BOM benchmark report

> Advisory alignment to CERT-In Technical Guidelines v2.0 only.
> **Does not constitute CERT-In certification.**

## Claim language (evidence only)

- **Oracle parity:** `true-miss == 0` vs published/frozen oracles where a
  snapshot exists (CBOM: cbomkit-theia + cdxgen; SBOM: cdxgen inventory;
  AIBOM: Trusera/Cisco when runnable).
- **OurUnique > 0:** source-level depth the filesystem/dep oracles
  structurally cannot see (algorithms in code, AI model refs, etc.).

## CBOM oracle baselines

- `00-synthetic.cbomkit.cdx.json` (5538 bytes)
- `00-synthetic.cdxgen.cdx.json` (1605 bytes)
- `01-pyjwt.cbomkit.cdx.json` (19245 bytes)
- `02-pyopenssl.cbomkit.cdx.json` (832 bytes)
- `02-pyopenssl.cdxgen.cdx.json` (764 bytes)
- `03-cryptography.cbomkit.cdx.json` (1849 bytes)
- `03-cryptography.cdxgen.cdx.json` (1846 bytes)
- `04-mitmproxy.cbomkit.cdx.json` (722 bytes)
- `04-mitmproxy.cdxgen.cdx.json` (1876 bytes)
- `05-paramiko.cbomkit.cdx.json` (32870 bytes)
- `05-paramiko.cdxgen.cdx.json` (2569 bytes)

## SBOM inventory baselines

- `01-requests.cdxgen.pkgs.json`
- `02-flask.cdxgen.pkgs.json`
- `03-urllib3.cdxgen.pkgs.json`
- `04-sqlalchemy.cdxgen.pkgs.json`
- `05-click.cdxgen.pkgs.json`

## Live product matrix

- ok: `True`
- cells: `15`
- `c1` lane=cbom status=success scan_id=61 secs=7.3 cert_in=True posture=True
- `c2` lane=cbom status=success scan_id=62 secs=7.3 cert_in=True posture=True
- `c3` lane=cbom status=success scan_id=63 secs=22.0 cert_in=True posture=True
- `c4` lane=cbom status=success scan_id=64 secs=19.5 cert_in=True posture=True
- `c5` lane=cbom status=success scan_id=65 secs=7.4 cert_in=True posture=True
- `a1` lane=ai_bom status=success scan_id=66 secs=7.3 cert_in=True posture=True
- `a2` lane=ai_bom status=success scan_id=67 secs=44.9 cert_in=True posture=True
- `a3` lane=ai_bom status=success scan_id=68 secs=24.7 cert_in=True posture=True
- `a4` lane=ai_bom status=success scan_id=69 secs=29.7 cert_in=True posture=True
- `a5` lane=ai_bom status=success scan_id=70 secs=7.3 cert_in=True posture=True
- `s1` lane=sbom_sca status=success scan_id=71 secs=12.4 cert_in=True posture=True
- `s2` lane=sbom_sca status=success scan_id=72 secs=17.5 cert_in=True posture=True
- `s3` lane=sbom_sca status=success scan_id=73 secs=32.8 cert_in=True posture=True
- `s4` lane=sbom_sca status=success scan_id=74 secs=14.4 cert_in=True posture=True
- `s5` lane=sbom_sca status=success scan_id=75 secs=17.5 cert_in=True posture=True

### Deep attest/sign/VEX/pack

- `cbom`: `{'lane': 'cbom', 'scan_id': 61, 'attest': 200, 'attest_req': 'T9-Algorithms-Mode', 'sign': 200, 'signature': True, 'vex': 200, 'evidence_pack': 200, 'evidence_zip': True}`
- `ai_bom`: `{'lane': 'ai_bom', 'scan_id': 66, 'attest': 200, 'attest_req': 'T10-Model-Type', 'sign': 200, 'signature': True, 'vex': 200, 'evidence_pack': 200, 'evidence_zip': True}`
- `sbom_sca`: `{'lane': 'sbom_sca', 'scan_id': 71, 'attest': 200, 'attest_req': 'T5-Component-Origin', 'sign': 200, 'signature': True, 'vex': 200, 'evidence_pack': 200, 'evidence_zip': True}`

## Product UI locks

- India / CERT-In chip present; `defaultGroup` remains `all`
- Zero product-FE `\bQBOM\b`
- HBOM deferred copy on CertInRollup

