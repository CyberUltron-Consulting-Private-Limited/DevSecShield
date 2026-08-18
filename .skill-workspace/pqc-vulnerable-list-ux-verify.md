# PQC vulnerable-list HoverCard fields — live verify

**Date:** 2026-08-09  
**Status:** PASS  
**Route:** `http://localhost:3000/pqc-vuln-verify` (temp; keep until product QA done)  
**Script:** `.skill-workspace/pqc-vulnerable-list-ux-verify.cjs`  
**Worker:** restarted after `normalize.py` enrichment (`aibomdemo@… ready`)

---

## Root cause

Legacy `pqc.migration[]` rows (live scan #79 shape) carry `migration_target` / `migration_roadmap` but **omit** `location`, `bom_ref`, `description`, `suggested_fix`. HoverCard read only `description` + `suggested_fix` → showed `—` / `Location not recorded`.

Fresh `normalize_crypto` already emits those fields; the gap was FE fallbacks + findings-join for legacy.

---

## Fixes shipped

| Layer | Change |
|-------|--------|
| `normalize.py` | `_pqc_migration_rows` includes `location`, `bom_ref`, `description`, `suggested_fix`, `finding_codes` (prior + locked by tests) |
| `pqcMigrationGroup.ts` | `pqcHowToFix` (suggested_fix → roadmap → target; never `—` when roadmap/target exist); `pqcDescription` (finding text or constructed primitive/size/curve/quantum); `enrichPqcMigrationFromFindings` for legacy join |
| `CbomCryptoCharts.tsx` | HoverCard Why / Description / How to fix / Location + View finding via `bom_ref`; Accordion grouping preserved (index values `vuln-N` / `road-N`) |
| `CbomResults.tsx` | Already passes `findings` + `onOpenFinding` into charts |

---

## Live evidence (Playwright)

```json
{
  "ok": true,
  "vulnGroups": 17,
  "roadmapGroups": 17,
  "instancesAfterExpand": 15,
  "openedFinding": "opened:crypto-algo-rsa-0",
  "hoverCard": {
    "why": "Quantum-vulnerable (NIST level 0) · High",
    "description": "Quantum-vulnerable algorithm RSA (NIST level 0).",
    "howToFix": "Migrate to ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
    "location": "src/crypto/rsa_0.py",
    "fixtureDescription": "Quantum-vulnerable algorithm RSA-1024: broken by Shor's algorithm…",
    "fixtureHowToFix": "Plan migration to post-quantum cryptography (ML-KEM (FIPS 203) / ML-DSA (FIPS 204)); …",
    "fixtureLocation": "crypto_app.py",
    "hoverOk": true
  },
  "consoleErrors": []
}
```

**Gotcha:** drive Playwright against `localhost` (not `127.0.0.1`) — Next 16 HMR websocket fails on `127.0.0.1` and leaves the page non-interactive (Accordion/HoverCard appear dead).

---

## Unit / contract gates

- `npx tsx frontend/components/cbom/pqcMigrationGroup.test.ts` → ok  
- `pytest …test_pqc_migration_rows_carry_location_and_bom_ref` → pass  
- `pytest …test_pqc_migration_rows_present_for_every_vulnerable_algorithm` → pass  
- `pytest …test_pqc_migration_bom_ref_matches_finding_row` → pass  

---

## Accordion grouping

Unchanged contract: presentation-only groups by `name|key_size|curve|roadmap`; instance count stays 1:1 with `quantum_vulnerable`. Large lists (scan79: 146 → 17 groups) default-collapsed; expand → instance HoverCards.
