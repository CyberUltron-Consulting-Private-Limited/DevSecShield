# CERT-In BOM Compliance — DETAILED Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `.cursor/skills/skill-executing-plans` to implement task-by-task **after** Agent mode is approved. **Execute Phase 0 only** until the user authorizes later phases.
>
> **Skills:** writing-plans, executing-plans, TDD, defense-in-depth, verification-before-completion, dispatching-parallel-agents, VIBE-CODE (explore→plan→contradict before code).
>
> **Ruflo:** namespace `certin-compliance`; always `memory_search` → work → `memory_store`; `hooks_route` before batches.

**Goal:** Advisory alignment to CERT-In Technical Guidelines v2.0 (09.07.2025) for SBOM + CBOM + AIBOM, with a shared compliance core under `aibom/compliance/cert_in/` (not under `cbom/`), no QBOM product surface.

**Architecture:** Shared ledger + Requirement factories + FE matrix extraction in Phase 0; lane check modules under `compliance/cert_in/{crypto,ai,sbom}.py` registered only into each lane’s runner list; separate `certin_posture` rollup; signing inside `aibom`; attestation API; evidence pack API + client ZIP.

**Tech stack:** `aibom.compliance` tri-state engine, CycloneDX 1.6, FastAPI, Celery, Next.js, YAML ledgers.

**Source PDF:** `docs/TechnicalGuidelines-on-SBOM,QBOM&CBOM,AIBOM_and_HBOM_ver2.0.pdf` (Version 2.0, 09.07.2025).

---

## Locked decisions (complete)

### Product (round 1)

| ID | Choice | Lock |
|----|--------|------|
| P1 | A | SBOM + CBOM + AIBOM only |
| P2 | C | Full tri-state + attestation |
| P3 | Official anchors else B | Frameworks `cert_in_cbom`, `cert_in_aibom`, `cert_in_sbom`; req IDs = PDF sections or `T5/T9/T10-…` |
| P4 | **Removed** | **No QBOM** (no readiness FW, no UI) |
| P5 | A | HBOM deferred |
| P6 | All Table-5 fields | Auto or **NBE** — never invent |
| P7 | D | UI + CDX/SPDX + PDF + evidence pack |
| P8 | C | Matrix + team CERT-In rollup |
| P9 | D | Signing + VEX |
| P10 | B | India gov **advisory** (not certification) |
| P11 | CBOM → AIBOM → SBOM | Build order |
| P12 | D | Contract + live API + browser + export + regression |
| P13 | B | Additive + India/CERT-In filter **group** (shown; see F8) |
| P14 | B | Process items = manual attestation |
| Arch | Shared core | Extend `aibom/compliance/` — **never** nest shared under `cbom/` |

### Follow-ups (round 2) — locked 2026-08-09

| ID | Choice | Lock |
|----|--------|------|
| F1 | A | Phase 0 extracts shared FE `ComplianceMatrix` + verdict tokens **first** |
| F2 | B | `ledger.yaml` + `docs/certin/LEDGER.md` kept in sync by test |
| F3 | B | Checks live under `compliance/cert_in/{crypto,ai,sbom}.py`; **runners stay separate** |
| F4 | B | **Signing inside `aibom` package** |
| F5 | C | VEX default: **Not Affected unless proven** |
| F6 | A | New **attestation API** + re-run compliance |
| F7 | A | Separate `certin_posture.py` + `cert-in-rollup.yaml` |
| F8 | C | Always **show** India/CERT-In group; **never auto-default** filter |
| F9 | B | OID: known → pass; unknown → **NBE** |
| F10 | A | Label “CERT-In CBOM (Guidelines v2.0)” — never say QBOM in product |
| F11 | C | Evidence pack: **backend ZIP endpoint + client ZIP** |
| F12 | Phase 0 only now | Write this DETAILED.md; implement **Phase 0 only** when Agent mode allowed |

**Disclaimer (mandatory):** Alignment to CERT-In Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM, Version 2.0 dated 09.07.2025. Does **not** constitute CERT-In certification.

---

## Target tree (end state)

```
aibom/src/aibom/compliance/
  base.py, engine.py, __init__.py          # existing shared engine
  cert_in/
    __init__.py
    ledger.yaml                            # canonical IDs (F2)
    common.py                              # load ledger → Requirement factories
    predicates.py                          # BOM-agnostic field helpers (no cbom imports)
    crypto.py                              # cert_in_cbom checks (F3) — imported by CBOM runner only
    ai.py                                  # cert_in_aibom checks — imported via engine.FRAMEWORKS
    sbom.py                                # cert_in_sbom checks — imported by SBOM runner only
    sign.py                                # Phase 4 — signing inside aibom (F4)
    vex.py                                 # Phase 4 — VEX emit (F5)

aibom/config/cert-in-rollup.yaml           # Phase 5 (F7)
docs/certin/LEDGER.md                      # human ledger (F2)
docs/certin/DETAILED.md                    # repo copy when Agent mode runs

frontend/components/compliance/            # Phase 0 (F1)
  verdictTokens.ts
  frameworkLabels.ts
  ComplianceMatrix.tsx
  types.ts

backend/utilities/dashboard/certin_posture.py   # Phase 5
backend/routers/… attestation + evidence-pack   # Phases 4/6 (F6, F11)
```

**Import rule (hard):** `compliance/cert_in/crypto.py` may import pure `aibom.cbom.strength` / property readers. `compliance/__init__.py` and `engine.run_all` must **never** import `crypto.py`. CBOM runner imports `cert_in.crypto` to register. AIBOM `run_all` only sees `cert_in.ai`.

---

# Phase 0 — Shared core + FE extract + ledger (EXECUTE FIRST / ONLY FOR NOW)

**Status:** Spec locked. **Code execution waiting on Agent mode approval** (mode switch was rejected).

**Outcome:** Shared CERT-In package skeleton + full ledger + FE matrix extraction with **zero new framework keys registered into runners yet** (no behavior change on live scans until Phase 1). Contract tests prove ledger↔docs sync and FE tokens import cleanly.

### Task 0.1 — Write failing ledger sync test

**Files:**
- Create: `aibom/tests/test_certin_ledger_sync.py`

**Steps:**
1. Write test that loads `compliance/cert_in/ledger.yaml` and `docs/certin/LEDGER.md` requirement ID set; assert equal (F2).
2. Run test → expect fail (files missing).
3. Do not implement production code yet.

### Task 0.2 — Create `docs/certin/LEDGER.md`

**Files:**
- Create: `docs/certin/LEDGER.md`

**Content requirements (every row):**
- `id` | PDF anchor | title | lane (`cbom`/`aibom`/`sbom`/`process`) | mode (`auto`/`manual`) | default if missing (`fail`/`nbe`) | evidence hint

**Must include:**
- All Table 5 data fields (21) + Automation Support + Practices pointers → `T5-…` / `7.1.x`
- All Table 9 crypto asset elements → `T9-…`
- All Table 10 AIBOM elements → `T10-…`
- Manuals `8.4.1.1–8.4.1.13`, `9.4.1.1–9.4.1.13`, key `7.1.x`
- Explicit note: Table 8 QBOM **out of product scope**
- HBOM Table 11 **deferred**
- Framework display names: `cert_in_cbom` → “CERT-In CBOM (Guidelines v2.0)” (F10)

### Task 0.3 — Create `ledger.yaml` matching LEDGER.md

**Files:**
- Create: `aibom/src/aibom/compliance/cert_in/ledger.yaml`
- Create: `aibom/src/aibom/compliance/cert_in/__init__.py`

**Schema (example):**
```yaml
guideline:
  title: "CERT-In Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM"
  version: "2.0"
  dated: "2025-07-09"
  disclaimer: "Advisory alignment only; not CERT-In certification."
frameworks:
  cert_in_cbom:
    label: "CERT-In CBOM (Guidelines v2.0)"
    lane: cbom
  cert_in_aibom:
    label: "CERT-In AIBOM (Guidelines v2.0)"
    lane: aibom
  cert_in_sbom:
    label: "CERT-In SBOM (Guidelines v2.0)"
    lane: sbom
requirements:
  - id: T9-Algorithms-Name
    pdf: "Table 9 / Algorithms / Name"
    title: "Cryptographic algorithm name present"
    lane: cbom
    mode: auto
    missing: fail
  - id: T9-Algorithms-OID
    pdf: "Table 9 / Algorithms / OID"
    title: "Algorithm OID known or not BOM-evidenceable"
    lane: cbom
    mode: auto
    missing: nbe
```

### Task 0.4 — `common.py` + `predicates.py` (no runner registration)

**Files:**
- Create: `aibom/src/aibom/compliance/cert_in/common.py`
- Create: `aibom/src/aibom/compliance/cert_in/predicates.py`
- Create stubs (empty register): `crypto.py`, `ai.py`, `sbom.py` with module docstrings only

**`common.py` must:**
- Load ledger via importlib.resources / path fallback
- `requirements_for(lane|framework) -> list[Requirement]`
- Export `CERTIN_DISCLAIMER`, framework label map
- **Not** call `register_check` yet (Phase 1+)

**`predicates.py` must:**
- Pure helpers: `prop(comp, key)`, `has_nonempty`, `has_purl_like`, etc.
- No imports from `aibom.cbom` package bootstrap

**Test:** `test_certin_common_loads_ledger` — count requirements > 0; disclaimer non-empty.

### Task 0.5 — FE `verdictTokens.ts` + `types.ts`

**Files:**
- Create: `frontend/components/compliance/types.ts`
- Create: `frontend/components/compliance/verdictTokens.ts`

**Extract from** `AiBomVisualizations.tsx` + `CbomCryptoCharts.tsx`:
- `VERDICT_COLOR`, `VERDICT_BADGE`, `VERDICT_LABEL`, `VERDICT_ORDER`
- Shared types

**Step:** Add tokens → both files import shared → `tsc --noEmit` clean.

### Task 0.6 — FE `frameworkLabels.ts`

**Files:**
- Create: `frontend/components/compliance/frameworkLabels.ts`

Merge AIBOM + CBOM labels; add CERT-In labels (F10). Export `FRAMEWORK_GROUPS_CERTIN` stub (F8: shown later, never auto-default).

### Task 0.7 — FE `ComplianceMatrix.tsx` extract (F1)

**Files:**
- Create: `frontend/components/compliance/ComplianceMatrix.tsx`
- Modify: `CbomCryptoCharts.tsx` — thin wrapper
- Modify: `AiBomVisualizations.tsx` — wrap/re-export
- Keep CBOM `groups?` / `failingOnly?`; keep AIBOM attestation UI for now

### Task 0.8 — Phase 0 verification gate

- [ ] pytest ledger sync + common load pass
- [ ] Ledger ID set == LEDGER.md ID set
- [ ] No new keys in runner framework lists yet
- [ ] frontend `tsc --noEmit` pass
- [ ] No product “QBOM” label
- [ ] Ruflo memory_store Phase 0 evidence
- [ ] **Do not mark complete** until all checked

**Phase 0 excludes:** registering checks, signing, VEX, attestation API, rollup, evidence pack.

---

# Phase 1 — `cert_in_cbom`

1. Failing contract test on synthetic-crypto-app (OID unknown → NBE)
2. Implement `cert_in/crypto.py` (Table 9 auto + `8.4.1.*` manuals)
3. Wire into `CBOM_FRAMEWORKS` only; FE India/CERT-In group chip (not default)
4. Verify pytest + worker restart + live CBOM + browser

---

# Phase 2 — `cert_in_aibom`

1. Failing tests
2. Implement `cert_in/ai.py` (Table 10 + `9.4.1.*`)
3. Add to `engine.FRAMEWORKS` + `__init__.py`
4. FE + live ai_bom E2E + browser

---

# Phase 3 — `cert_in_sbom` (all Table 5)

1. Failing tests (every T5 id)
2. Implement `cert_in/sbom.py` with NBE matrix from ledger
3. Enrich SBOM projection without inventing values
4. Wire `SBOM_FRAMEWORKS`; FE; live sbom_sca E2E

---

# Phase 4 — Signing + VEX + Evidence pack + Attestation API

1. `cert_in/sign.py` inside aibom (F4)
2. `cert_in/vex.py` — default **not_affected** unless proven (F5)
3. Attestation API + re-run (F6)
4. Evidence pack backend ZIP + client ZIP (F11); PDF CERT-In section
5. E2E verify signature + VEX parse + downloads

---

# Phase 5 — CERT-In rollup + India group UX

1. `cert-in-rollup.yaml` + `certin_posture.py` (F7)
2. Metadata + team dashboard
3. `CertInRollup` FE
4. India/CERT-In group always listed when keys exist; never auto-default (F8)
5. HBOM deferred copy; zero QBOM UI (F10)

---

# Phase 6 — Full verification gate

1. Contract/unit locks
2. Live API all three BOM types
3. Browser matrices + attestation + packs
4. Export CDX/VEX/signature/PDF
5. Regression on frozen fixtures
6. Performance smoke
7. Ruflo final evidence store

---

## Phase 0 checklist (for TodoWrite when executing)

- [ ] 0.1 Failing ledger sync test
- [ ] 0.2 `docs/certin/LEDGER.md`
- [ ] 0.3 `ledger.yaml` + package init
- [ ] 0.4 `common.py` + `predicates.py` + stubs
- [ ] 0.5 FE verdictTokens + types; wire imports
- [ ] 0.6 FE frameworkLabels
- [ ] 0.7 FE ComplianceMatrix extract
- [ ] 0.8 Phase 0 verification gate

---

## Explicit non-goals

- QBOM scanner / framework / product wording (except PDF citation in docs)
- HBOM scanner
- Nesting shared compliance under `aibom/cbom/`
- Claiming CERT-In certification
- Registering CERT-In frameworks in Phase 0
