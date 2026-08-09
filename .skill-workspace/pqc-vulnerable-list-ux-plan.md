# PQC vulnerable list + migration roadmap UX (diagnosis + plan)

> **Status:** DIAGNOSIS + PLAN ONLY — do not implement until user confirms.
> **Date:** 2026-08-09
> **Style authority:** `frontend/components/cbom/CbomCryptoCharts.tsx` (F2) + Shadow AI HoverCard pattern in `AiBomVisualizations.tsx` + existing finding Dialog in `CbomResults.tsx`.
> **Evidence:** live CBOM scan **#79** (team 1, `INDIA c3 pyca/cryptography`) and peers #63/#24 (same shape); code in `normalize._pqc_migration_rows` + algorithm `bom_ref` identity.

---

## Goal

1. Show **all** quantum-vulnerable occurrences, including **location** and related finding detail (parity with Shadow AI hover / “view finding”).
2. When the list is large (~100+), **do not** dominate the results page — **group** into a clean, neat UI.
3. Keep full drill-down: expand group → instances → HoverCard and/or open existing finding Dialog.

---

## Brainstorm — 3 architectural hypotheses (pre-fix)

| # | Hypothesis | Likelihood |
|---|------------|------------|
| H1 | Duplication is intentional inventory semantics: one component per `(algorithm name, file location)`, so F2’s 1:1 `migration[]` repeats the same family many times. | **Confirmed** (scanner bom_ref + live #79) |
| H2 | Location is already on finding rows; F2 panels just never receive it because `_pqc_migration_rows` omits it. | **Confirmed** (#79 loc fill **146/146**; migration keys have no `location`) |
| H3 | Best UX is FE-only grouping of today’s `migration[]` without backend work. | **Partial** — grouping yes; location/description/fix need enrichment or a findings join |

---

## Component / data map

| Item | Path |
|------|------|
| Quantum-vulnerable list | `CbomCryptoCharts.tsx` → `QuantumVulnerableList` (~L388–438) |
| Migration roadmap | `CbomCryptoCharts.tsx` → `MigrationRoadmap` (~L442–504) |
| Wired from | `CbomResults.tsx` → `<CbomCryptoCharts distributions={…}>` (**findings not passed today**) |
| Migration producer | `aibom/src/aibom/cbom/normalize.py` → `_pqc_migration_rows` |
| Finding row (has location) | same normalize `_finding_row` / adapter results — `location` ← `crypto:source` \|\| `discovery:source` |
| Inventory identity | `algorithm_scan.py` (and peers): `bom_ref = crypto-algo-{slug(name)}-{slug(location)}` |
| Style peer | Shadow AI: full list + `max-h` scroll + HoverCard + optional `onOpenFinding` |
| Cap peer in same file | `CertificateExpiry` uses `CERT_LIST_CAP = 8` + overflow text (lossy — **not** desired here) |

---

## Root cause of duplication

### Inventory is per-occurrence, not unique-algorithm

Algorithm components are keyed by **name + source file**:

```text
bom_ref = f"crypto-algo-{_slug(asset.name)}-{_slug(asset.location)}"
```

So `ECDSA` in 24 files → **24** algorithm assets, each graded quantum-vulnerable, each with the same (or near-same) migration target.

### F2 migration rows are 1:1 with those assets

`_pqc_migration_rows` explicitly emits **one row per quantum-vulnerable algorithm asset**:

```python
# normalize.py — fields today
{
  "name", "primitive", "key_size", "curve",
  "nist_quantum_security_level",
  "migration_target", "migration_roadmap",
  "impact",
}
```

Contract test locks `len(migration) == pqc["quantum_vulnerable"]` — so collapsing in the backend would break the F2 contract unless the contract is updated to distinguish **instances** vs **groups**.

### Frontend renders a flat unbounded list

Both panels `migration.map(...)` with **no** grouping, **no** `max-h` scroll, **no** HoverCard. On a large scan this doubles page length (list + roadmap both repeat).

### Live evidence (team 1, CBOM #79)

| Metric | Value |
|--------|-------|
| `pqc.migration` length / `quantum_vulnerable` | **146** |
| Unique algorithm **names** | **13** |
| Top repeats | DSA×28, Ed25519×25, ECDSA×24, Ed448×21, X25519×17, RSA×15, ECDH×9 |
| Finding `location` fill on q-v rows | **146/146** |
| Migration row keys | no `location` / `description` / `suggested_fix` / `bom_ref` |

Grouping simulation on #79:

| Group key | Group count |
|-----------|-------------|
| `name` only | 13 |
| `name + key_size + curve + roadmap` | ~21 |
| `name + primitive + key_size + curve + roadmap + impact` | ~22 |

Intra-name variance exists (keep params in the group key):

- **Impact** can differ (e.g. RSA Medium vs High when weak flags stack).
- **Curve / roadmap** can differ (e.g. ECDH + SECP384R1 → ML-KEM-1024 roadmap).
- **Curve casing** noise (`ed25519` / `Ed25519` / `ED25519`) would split groups unless normalized.

---

## Fields available today

### On `PqcMigrationRow` (FE type + normalize)

| Field | Present | Notes |
|-------|---------|-------|
| `name` | ✅ | Display name (RSA, ECDSA, Ed25519, …) |
| `primitive` | ✅ | pke / signature / key-agree |
| `key_size` | ✅ nullable | Often null for ECC |
| `curve` | ✅ nullable | Casing inconsistent across detections |
| `nist_quantum_security_level` | ✅ | 0 for vulnerable |
| `migration_target` | ✅ | Unsized family string |
| `migration_roadmap` | ✅ | Sized target string |
| `impact` | ✅ | Stacked severity band |
| `location` | ❌ | **Missing from migration** (present on findings) |
| `description` / `suggested_fix` / `finding_codes` | ❌ | On findings only |
| `bom_ref` / finding `id` | ❌ | Needed for reliable “view finding” join |

### On CBOM finding rows (already persisted)

`location`, `description`, `suggested_fix`, `finding_codes`, `primitive`, `key_size`, `curve`, `pqc_migration_target`, `pqc_migration_roadmap`, `impact`, `quantum_vulnerable` — all populated on #79 for q-v algorithms.

---

## Data enrichment needed (location + detail)

**Preferred (single source for F2):** extend `_pqc_migration_rows` additively:

| New field | Source | Why |
|-----------|--------|-----|
| `location` | `props["discovery:source"]` or `crypto:source` (same as findings) | Exact file path per instance |
| `bom_ref` | `c.bom_ref` | Stable join / React key |
| `description` | join of `result.flags_for(ref)` messages (already used in finding rows) | Hover “why / description” |
| `suggested_fix` | optional short fix (adapter already synthesizes PQC migrate text on findings) | Hover “how to fix” |
| `finding_codes` | sorted flag codes | Transparency / weak+q-v stacking |

**FE join alternative (no normalize change):** pass `findingsList` into `CbomCryptoCharts`, filter `quantum_vulnerable`, group those. Works for live detail today, but duplicates F2’s dual source (`migration[]` vs findings) and legacy scans without rich findings stay awkward. Prefer enriching `migration[]` so charts stay self-contained (F2 precedent).

**Contract impact:** keep `len(migration) == quantum_vulnerable` (instance rows stay); grouping is **presentation-only**. Add assertions that each migration row carries `location` (non-empty on fixture sources that stamp `discovery:source`). Update `PqcMigrationRow` TS interface + `test_cbom_chart_data_contract.py`.

**Worker restart:** yes if normalize/adapter changes (I1/F2 precedent).

**Curve normalize (FE group key only):** `curve?.toLowerCase()` so casing does not inflate groups.

---

## UX options (2–3)

### Option A — Accordion groups + count badge + instance expand (recommended)

**Vulnerable list**

- Collapse instances by group key:  
  `name | primitive | key_size | lower(curve) | migration_roadmap`  
  (include `impact` only if product wants High/Medium split visible at group level — default: **max impact** badge on group, instances keep own impact).
- Accordion trigger: algorithm name · descriptor · **`N` badge** · Level 0 · impact.
- Content: scrollable instance list (`location` mono, optional impact chip).
- Per instance: **HoverCard** (Shadow AI sections: Why / Description / How to fix / Location) + **View finding** → existing `CbomResults` Dialog via `onOpenFinding`.
- Card: `max-h` + overflow on accordion body if many groups; default **all collapsed**.

**Migration roadmap**

- Keep CNSA milestone strip once.
- Replace flat `name → roadmap` repeats with **one row per unique `(name, roadmap)`** (or per group key), badge `×N` when N>1.
- Optional: click/`N` expands to same instance locations (shared group model).

**Pros:** Matches shadcn Accordion already in repo; density like a neat inventory; full data retained; Shadow AI hover/dialog reuse.  
**Cons:** Slightly more FE state; group-key decision needed.

### Option B — Table with expandable rows

Single table: columns Algorithm | Primitive | Params | Impact | Instances | Target. Expand row → location list.

**Pros:** Dense, scannable, good for power users.  
**Cons:** Less consistent with current Card-list chart aesthetics in `CbomCryptoCharts` / AiBom cards; heavier markup.

### Option C — Flat list capped visually via Collapsible “N instances” only (no Accordion)

Show unique names; each row is a Collapsible “Ed25519 · 25 instances”; HoverCard on row.

**Pros:** Minimal chrome.  
**Cons:** Weaker structure when many families; Accordion (A) is clearer for 13–22 groups.

---

## Recommended option

**Option A**, styled like current F2 Cards + Shadow AI HoverCard:

1. Enrich `migration[]` with `location` (+ `bom_ref`, `description`, `suggested_fix` / codes as available).
2. FE-group both panels; Accordion default collapsed; count badges; instance locations; HoverCard; wire `onOpenFinding` from `CbomResults` (same Dialog already used by the findings table).
3. Do **not** use `CERT_LIST_CAP`-style hard truncate — that hides data. Use grouping + scroll instead.
4. Do **not** change inventory semantics (still one asset per file) — only presentation + additive fields.

Confidence: **High** on root cause and location gap; **Medium-High** on group key details pending user answers below.

---

## Confirmation questions (block implementation)

1. **Group key?** Prefer  
   - (a) `name + key_size/curve + roadmap` (~21 on #79), or  
   - (b) `name` only (13, simpler but merges param/impact variance), or  
   - (c) include `impact` so High/Medium RSA stay separate?
2. **Default collapsed?** Recommend yes for all groups when `N_groups > 5` or `N_instances > 20`; else expand singles.
3. **Max visible groups before inner scroll?** e.g. show all groups in Accordion but `max-h-[28rem]` on card content (Shadow AI pattern), or paginate?
4. **HoverCard vs expand vs both?** Recommend **both**: expand for locations list; HoverCard for finding-quality detail; button opens full Dialog.
5. **Migration panel:** unique target rows with `×N`, or mirror the same Accordion as the vulnerable list?
6. **Join to Dialog:** match by `bom_ref` (after enrichment) vs `title + location` on findings (works today without bom_ref)?
7. **Scope:** FE-only first with findings join, or normalize enrichment in the same story?

---

## Effort / files

| Layer | Files | Effort |
|-------|-------|--------|
| Normalize enrichment | `aibom/src/aibom/cbom/normalize.py` (`_pqc_migration_rows`) | S (~0.5–1h) |
| Contract / normalize tests | `aibom/tests/test_cbom_chart_data_contract.py`, `test_cbom_normalize.py` | S |
| FE types + grouping UI | `frontend/components/cbom/CbomCryptoCharts.tsx` (`PqcMigrationRow`, `QuantumVulnerableList`, `MigrationRoadmap`) | M (~0.5–1d) |
| Wire finding open | `frontend/components/CbomResults.tsx` (pass `onOpenFinding` / findings if needed) | S |
| Optional UI primitives | `@/components/ui/accordion`, `hover-card` (already present) | — |
| Worker restart | after aibom normalize change | ops |
| Dev-browser verify | CBOM #79 / #106 results page | S |

**Rough total:** ~1–1.5 engineer-days for recommended path (enrichment + Option A + tests + live verify).  
**FE-only findings-join spike:** ~0.5–1 day, with follow-up normalize story for self-contained `migration[]`.

---

## Out of scope / non-goals

- Changing scanner dedup to one-component-per-algorithm (would break location fidelity and bench/compliance counts).
- Hard-capping to 8 like certificates (hides occurrences).
- New aesthetic / new chart library.
- Replacing the PQC gauge or compliance matrix.

---

## Implementation checklist (when approved)

1. Confirm answers to questions above.
2. TDD: extend chart-data contract for new migration fields; add FE grouping unit or contract on group counts for fixture + document expected #79 collapse 146→~13–22.
3. Implement normalize additive fields; restart worker; re-scan or use existing #79 metadata only after new scans.
4. Implement Accordion + HoverCard + roadmap dedupe in `CbomCryptoCharts`; wire Dialog.
5. Verify on #79 (or fresh cryptography/paramiko scan): page height reasonable; every instance reachable; location visible; no console errors; `tsc` + scoped eslint + `pytest -k "cbom or crypto"` green.

---

## Evidence appendix

- Scanner identity: `aibom/src/aibom/cbom/scanners/algorithm_scan.py` (~L383–414).
- Migration builder: `aibom/src/aibom/cbom/normalize.py` `_pqc_migration_rows` (~L133–165); finding `location` at ~L107.
- Flat UI: `QuantumVulnerableList` / `MigrationRoadmap` map all rows.
- Shadow AI peer: `AiBomVisualizations.tsx` HoverCard + `max-h-[28rem]` + `onOpenFinding`.
- Live API: `GET /1/cbom/scan/79` → `scan_metadata.cbom_distributions.pqc.migration.length === 146`, finding locations filled.
