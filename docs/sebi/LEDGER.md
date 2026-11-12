# SEBI CSCRF Compliance Ledger

## Scope

Source: **SEBI Circular `SEBI/HO/ITD-1/ITD_CSC_EXT/P/CIR/2024/113` dated 20.08.2024 — Cybersecurity and Cyber Resilience Framework (CSCRF) for SEBI Regulated Entities, Version 1.0** (`docs/1724326790365.pdf`, 205 pages).

This ledger is the human-readable twin of `aibom/src/aibom/compliance/sebi_cscrf/ledger.yaml`. Requirement **id** sets must match exactly.

**Depth:** BOM-evidenceable CSCRF subset only — not full Market SOC / CCI / cyber-audit timeline matrix.

**Advisory only:** alignment does **not** constitute SEBI certification, audit opinion, or satisfaction of SEBI / stock-exchange obligations.

**Out of product scope:**
- Full SOC / Market SOC continuous monitoring as auto checks
- Inventing AI-specific SEBI controls (CIR has no AI/ML/AIBOM text)
- QBOM product scan type
- Claiming SEBI certification

## Frameworks

| key | label | lane |
|-----|-------|------|
| `sebi_cscrf_cbom` | SEBI CSCRF (CBOM) | cbom |
| `sebi_cscrf_aibom` | SEBI CSCRF (AIBOM) | aibom |
| `sebi_cscrf_sbom` | SEBI CSCRF (SBOM) | sbom |

## CBOM — Box Item 7 + PR.DS + GV.SC.S5(d)

### Auto

| id | CIR | title | missing |
|----|-----|-------|---------|
| `CSCRF-QC-1` | Box 7.1 | Cryptographic asset inventory present | fail |
| `CSCRF-QC-2` | Box 7.1/7.2 | QV ⇒ `crypto:pqcMigrationTarget` | fail |
| `CSCRF-QC-9` | Box 7.4 | QV ⇒ `crypto:nistQuantumSecurityLevel` | fail |
| `CSCRF-DS-1` | PR.DS.S1 | No weak transport protocols | fail |
| `CSCRF-DS-2` | PR.DS | Asymmetric keys ≥2048-bit floor | fail |
| `CSCRF-DS-6` | PR.DS | No broken/deprecated algorithms | fail |
| `CSCRF-DS-7` | PR.DS | Classical strength ≥112 bits | fail |
| `CSCRF-SC-1` | GV.SC.S5(d) | Encryption-relevant crypto assets present | fail |

### Manual (NBE)

`CSCRF-QC-3`, `CSCRF-QC-5`, `CSCRF-QC-6`, `CSCRF-QC-7`, `CSCRF-QC-8`, `CSCRF-QC-10`, `CSCRF-DS-3`, `CSCRF-DS-4`, `CSCRF-DS-5`, `CSCRF-RA-1`

## AIBOM — honest software-inventory reading

CIR has **no** AI/ML/AIBOM controls. Autos map inventoriable model software facts only.

### Auto

| id | CIR | title | missing |
|----|-----|-------|---------|
| `CSCRF-ID.AM.S1-inv` | ID.AM | Model name | fail |
| `CSCRF-ID.AM.S1-ver` | ID.AM / S5 | Model version | fail |
| `CSCRF-GV.SC.S5-dep` | GV.SC.S5 | Named framework deps when edged (NA if none) | fail |
| `CSCRF-GV.SC.S5-lic` | S5.4.a | License | nbe |
| `CSCRF-GV.SC.S5-hash` | S5.4.e | Integrity hash | nbe |

### Manual (NBE)

`CSCRF-ID.AM.S1-proc`, `CSCRF-ID.AM.S4-proc`, `CSCRF-ID.RA.S1-proc`, `CSCRF-ID.RA.S2-proc`, `CSCRF-GV.SC.S2-proc`, `CSCRF-GV.SC.S4-proc`, `CSCRF-GV.SC.S5-proc`, `CSCRF-GV.SC.S5-legacy`, `CSCRF-PR.IP.S4-proc`, `CSCRF-PR.IP.S4-vapt`, `CSCRF-PR.IP.S6-proc`, `CSCRF-PR.DS.S5-proc`, `CSCRF-DE.CM.S5-scope`, `CSCRF-PR.AT.GenAI-proc`

## SBOM — GV.SC.S5 + ID.AM / ID.RA

### Auto

| id | CIR | title | missing |
|----|-----|-------|---------|
| `CSCRF-GV.SC.S5-name` | S5.2 / S5.4 | Component names | fail |
| `CSCRF-GV.SC.S5-ver` | S5.2 / S5.4 | Component versions | fail |
| `CSCRF-GV.SC.S5-sup` | S5.4.b | Supplier / purl | fail |
| `CSCRF-GV.SC.S5-uid` | Box 6 | Unique identifiers | fail |
| `CSCRF-GV.SC.S5-lic` | S5.4.a | License | nbe |
| `CSCRF-GV.SC.S5-lic-risk` | S5.2 | High-risk licenses | fail |
| `CSCRF-GV.SC.S5-deps` | S5.4.c | Dependency relationship set | fail |
| `CSCRF-GV.SC.S5-hash` | S5.4.e | Hashes | nbe |
| `CSCRF-GV.SC.S5-patch` | S5.2 | Patch status | nbe |
| `CSCRF-GV.SC.S5-enc` | S5.4.d | Encryption used (stamped only) | nbe |
| `CSCRF-GV.SC.S5-known-unknown` | S5.4.g | Known-unknown / graph_complete | nbe |
| `CSCRF-ID.AM-inv` | ID.AM | Inventory non-empty + name/version | fail |
| `CSCRF-ID.RA-vuln-track` | ID.RA | Vuln scanner / assessed | fail |
| `CSCRF-ID.RA-high` | ID.RA | No Critical/High impact | fail |
| `CSCRF-GV.SC.S5-author` | provenance | BOM author | fail |
| `CSCRF-GV.SC.S5-ts` | provenance | BOM timestamp | fail |

### Manual (NBE)

`CSCRF-GV.SC.S5-legacy-critical`, `CSCRF-GV.SC.S5-procurement`, `CSCRF-GV.SC.S5-mii`, `CSCRF-GV.SC.S5-board-legacy`, `CSCRF-GV.SC.S5-update-freq`, `CSCRF-GV.SC.S5-access`, `CSCRF-GV.SC.S5-errors`, `CSCRF-GV.SC.S5-mitigate`
