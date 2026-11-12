# CBOM Certificate expiry chart — harden plan + verify

**Status:** IMPLEMENTED + verified (local gates)  
**Date:** 2026-08-09  
**Ruflo:** `cbom/cbom-cert-expiry-harden-research` · `cbom-cert-expiry-harden-verified`

---

## Research decision — JKS / P12 / PFX

**Chosen approach: opaque `related-crypto-material` (`materialKind=credential`) — no password parse.**

| Option | Verdict |
|--------|---------|
| Passwordless X.509 extract from PKCS#12/JKS | **Rejected** — invents capability; OpenSSL `PKCS12_parse` needs password/MAC; empty≠NULL password |
| Opaque related-crypto-material inventory | **Accepted** — honest presence signal without fake `notValidAfter` |
| Out of scope entirely | Rejected for UX — empty expiry chart looked like a miss when keystores/keys exist |

### Citations

1. **cbomkit-theia certificates plugin** (`v1.1.2` `certificates.go`): enumerates `.pem/.cer/.cert/.der/.ca-bundle/.crt` + PKCS#7; **no** `.jks/.p12/.pfx` decrypt path. Default branch only tries PEM cert blocks on other files.  
   https://github.com/cbomkit/cbomkit-theia/blob/v1.1.2/scanner/plugins/certificates/certificates.go
2. **cbomkit-theia README**: X.509 Certificate Plugin finds certificates; secrets plugin finds keys — no keystore password workflow.  
   https://github.com/cbomkit/cbomkit-theia
3. **CycloneDX 1.6** `relatedCryptoMaterialType` includes `credential` for identity containers (bundled `bom-1.6.schema.json`).
4. **OpenSSL** `PKCS12_parse` / password+MAC semantics — do not invent passwords.

Also shipped **`.ca-bundle`** extension parity (theia lists it; we previously missed → proven 0 certs on harden fixture before change).

---

## Fixture source

`aibom/tests/fixtures/synthetic-crypto-certs-harden/` — see `SOURCE.md`

| File | Provenance |
|------|------------|
| `isrg-root-x1.ca-bundle` | Let's Encrypt ISRG Root X1 PEM (`https://letsencrypt.org/certs/isrgrootx1.pem`) |
| `server.key` | Throwaway RSA PEM via OpenSSL (test-only) |
| `opaque-*.jks/.p12/.pfx` | Magic stubs — **not** decryptable |

**Pre-harden evidence:** `scan_crypto` on this dir → **0** certificates, **0** material.

---

## Implementation summary

1. `certificate_scan.py` — `.ca-bundle` + `_scan_keystores` (opaque credential)
2. `normalize.py` — `key_material[]` sibling distribution; finding join fields
3. `CbomCryptoCharts.tsx` — dual section (X.509 + key/keystore); FE join fallback from graph/findings; clearer empty copy
4. Tests — `test_cbom_certs_harden.py` + contract extensions
5. LEDGER row for opaque keystore + `.ca-bundle` parity

---

## Verify checklist

- [x] Harden fixture: certificates + key_material non-empty after scan
- [x] Contract: synthetic-crypto-app still has certificates + private-key key_material
- [x] `pytest` scoped CBOM cert/normalize/contract/benchmark green (70)
- [x] Worker restarted (`cert-harden@… ready` in `/tmp/celery_worker.log`)
- [x] Live adapter evidence: `scan_crypto_to_devsecshield(harden)` → 1 cert + 4 key_material; app → 1 cert + 1 private-key
- [ ] Full click-to-result browser pass deferred (backend/frontend were down at verify time; adapter + worker ready)
- [x] Ruflo `cbom-cert-expiry-harden-verified`

---

## Devil's advocate (survived)

- Claiming X.509 from encrypted PKCS#12 without password would be a **false** `notValidAfter` — rejected.
- Chart-only FE join without scanner harden would not fix `.ca-bundle` miss — both shipped.
- Opaque keystore FPs on renamed binaries mitigated by JKS magic / ASN.1 SEQUENCE gate.
