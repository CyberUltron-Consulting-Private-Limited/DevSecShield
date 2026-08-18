# synthetic-crypto-certs-harden — provenance

License-safe public crypto material for CBOM certificate-hardening tests.

| File | Source | License / notes |
|------|--------|-----------------|
| `isrg-root-x1.ca-bundle` | [Let's Encrypt ISRG Root X1](https://letsencrypt.org/certs/isrgrootx1.pem) (fetched 2026-08-09) | Public CA root; redistributed for detection/fixture use. Extension `.ca-bundle` matches cbomkit-theia certificate plugin enumeration (`certificates.go` v1.1.2). |
| `server.key` | Throwaway RSA private key excerpt from in-repo `synthetic-crypto-app/crypto_app.py` (already labeled non-production) | Test-only PEM private key. |
| `opaque-truststore.jks` | Synthetic JKS magic `0xFEEDFEED` stub | **Not** a decryptable keystore. Inventories as opaque related-crypto-material. |
| `opaque-client.p12` / `opaque-client.pfx` | Synthetic ASN.1 SEQUENCE stubs | **Not** password-decryptable. No passwords invented. Opaque inventory only. |

## Research decision (JKS / P12 / PFX)

**Opaque `related-crypto-material` (`materialKind=credential`) — no password parse.**

Citations:

1. cbomkit-theia Certificate File Plugin enumerates `.pem/.cer/.cert/.der/.ca-bundle/.crt` + PKCS#7; **no** `.jks/.p12/.pfx` decrypt path — [certificates.go v1.1.2](https://github.com/cbomkit/cbomkit-theia/blob/v1.1.2/scanner/plugins/certificates/certificates.go).
2. cbomkit-theia README: X.509 plugin finds certificates; secrets plugin finds keys — no keystore password workflow — [README](https://github.com/cbomkit/cbomkit-theia).
3. CycloneDX 1.6 `relatedCryptoMaterialType` includes `credential` for identity containers — bundled `bom-1.6.schema.json`.
4. OpenSSL `PKCS12_parse` requires password/MAC verification — do not invent passwords.

## Pre-harden miss (evidence)

Before this story, `scan_crypto` on this directory returned **0** certificate assets and **0** related-crypto-material (`.ca-bundle` not in `_CERT_EXTS`; keystores ignored; empty scan).
