# BOM "Unknown" Elimination — Diagnosis + Implementation Plan

**Status:** PLAN ONLY — do not implement until user confirms questions in §6  
**Date:** 2026-08-09  
**Scope:** SBOM / CBOM / AIBOM — zero literal `unknown` / `Unknown` in in-scope distributions + findings after re-scan  
**Evidence base:** Live local stack (`:8081`), team 1, user `cbom-demo@cyberultron.com`

---

## 1. Executive summary

**What the user still sees:** SBOM **license distribution** is dominated by **Unknown**. On live team dashboard: `licenses_distribution.unknown = 820` vs `permissive = 130`. Per-scan example SBOM `#91` (pallets/click): **97/102** findings have `license_type: "unknown"` (~95%).

**Why (root cause, evidence-backed):**

1. **Primary (SBOM inventory path):** Syft/cdxgen CycloneDX components often omit `licenses[]`. `inventory_to_finding_rows` then writes the literal string `"unknown"` into `license_type` (`merge_inventory.py:110`). Inventory rows are the majority of modern SBOM findings (e.g. 97 inventory vs 5 vuln on `#91`). Vuln rows get LLM `LicenseCategory` values (`permissive`, …); inventory does not.

2. **Secondary (SBOM chart aggregation):** When Syft *does* emit SPDX IDs (`MIT`, `0BSD`, `PSF-2.0`), they are stored as-is in `license_type`. Dashboard aggregation only counts fixed category keys (`permissive`…`unknown`) — **raw SPDX is silently dropped from the chart** (not counted as unknown either). Observed on `#87`/`#90`: MIT/0BSD/PSF present in findings but absent from `licenses_distribution`.

3. **AIBOM (partially fixed):** Chart + findings serializers already remap via `resolve_aibom_license` / `resolve_aibom_provider` → **0** `unknown` in dashboard distributions and `findings[]`. **Residual:** persisted `scan_data.results` / response `data` still carries `source: "unknown"` (**357/672** over 10 success scans) and empty `license` (**312/672**). UI charts/findings hide this; raw data does not.

4. **CBOM (live-clean, code-residual):** Over 10 success scans (**2812** findings): **0** empty/unknown `crypto_strength` or `algorithm_type`; team `quantum_readiness.unknown = 0`. Residual risk: adapter `_legacy_algorithm_type` can `return "unknown"` (`cbom_devsecshield.py:71`); FE `crypto_strength ?? "unknown"` (`CbomResults.tsx:1480/1608`); normalize defaults `primitive or "unknown"`.

**Bottom line:** Coding should start with **SBOM license resolution + SPDX→category mapping + honest residual label** (mirror AIBOM pattern). AIBOM needs **emit-time** hardening so `data` matches findings. CBOM needs **defensive** cleanup so future edge assets cannot paint "Unknown".

---

## 2. Full inventory of unknown surfaces

Legend — **Severity:** P0 user-visible chart/table pollution · P1 raw payload / future risk · P2 UI fallback only · OK intentional N/A (must not use word `unknown`)

| BOM | Field | Where shown | Live sample count | Severity | Root cause (file:line) | Proposed fix strategy |
|-----|-------|-------------|-------------------|----------|------------------------|------------------------|
| **SBOM** | `license_type` = `unknown` | Results license chart (`licenses_distribution`), findings table, top-risks rows, team list dashboard | Team: **820**; `#91`: **97/102**; 15-scan aggregate: **819** unknown vs **54** permissive vs **23** SPDX | **P0** | Emit: `merge_inventory.py:110` (`lic or "unknown"`). Aggregate: `scan.py:843–897`, `scan_list.py:999–1048`. FE labels: `SbomResults.tsx:178–188`, `sbom_sca/page.tsx:168–178`. Enum allows UNKNOWN: `enums.py:54` | **Resolver + map:** (1) keep SPDX in `license` field; (2) map SPDX→`LicenseCategory`; (3) package-name enrichment (curated map + optional metadata); (4) residual → `not_declared` (never `unknown`); (5) read-time remap for legacy scans |
| **SBOM** | Raw SPDX in `license_type` (`MIT`, …) not charted | Chart under-counts; table shows SPDX string | `#87`: 5 MIT; `#90`: MIT/0BSD/PSF | **P0** | Same aggregator only indexes category keys (`scan.py:897`) | SPDX→category at emit + dashboard `resolve_sbom_license_category()` |
| **SBOM** | `reachability` = `unknown` | Reachability chart / badges | Team: **1**; `#91`: **0** | P1 | Default `item.get("reachability") or "unknown"` (`scan.py:839`); FE `reachability ?? "unknown"` (`SbomResults.tsx:165`) | Default inventory to `not_reachable` (already mostly true); residual → `not_assessed` label, not `unknown` |
| **SBOM** | Impact UI fallback `"Unknown"` | Chat/export copy paths | Rare if impact always set | P2 | `SbomResults.tsx:803,847` | Prefer `Low` for inventory; never `"Unknown"` string |
| **SBOM** | PDF `impact`/`fix_state` defaults | PDF export | N/A this pass | P2 | `sbom_sca_pdf.py` | Align with category resolver |
| **AIBOM** | `license` / `license_type` chart | License distribution chart | Team + `#95`: **0** `unknown` (uses `LicenseRef-*` / SPDX) | OK (fixed) | `aibom_license.py`, `scan.py:1378–1380`, `findings.py:224` | Keep; extend emit-time so `data.license` matches |
| **AIBOM** | `provider` chart | Provider distribution | **0** unknown | OK (fixed) | `aibom_provider.py`, `findings.py:221` | Keep |
| **AIBOM** | `data.source` = `unknown` | Raw scan payload (not findings serializer) | **357/672** (10 scans); `#95`: **23/49** | **P1** | Worker/legacy emit; remapped only on read for findings/dashboard | Emit-time `resolve` in `devsecshield` adapter; optional read-time patch of `data` in GET scan |
| **AIBOM** | `data.license` empty | Raw payload | **312/672**; `#95`: **21/49** | **P1** | Same as above | Emit `LicenseRef-not-declared` / package SPDX at scan time |
| **AIBOM** | `framework` / `version` empty | Detail panel | `#95`: framework empty **40/49**, version **49/49** | P2 (not labeled Unknown) | Honest gaps | Optional `not-declared`; out of license scope unless user expands |
| **AIBOM** | Drift `drift_status ?? "unknown"` | Model-card viz | Edge | P2 | `AiBomVisualizations.tsx:409` | Use `not-assessed` |
| **CBOM** | `crypto_strength` / `algorithm_type` | Strength + type charts, table | **0/2812** unknown/empty on 10 live scans | OK live | Adapter `_legacy_*` | Harden `_legacy_algorithm_type` never `"unknown"` → use `asset_type` or `other` |
| **CBOM** | `quantum_readiness.unknown` | Legacy key (chart excludes it) | Team + `#94`: **0** | OK | `scan.py:1186–1228` algorithm-only | Keep excluding N/A; remove dead `unknown` key or leave at 0 |
| **CBOM** | `quantum_safe` null | Not charted as Unknown | `#94`: **67** null (certs/keys/protocols) | OK N/A | `cbom_devsecshield.py:88–92` | Keep `null`; UI must not coerce to `"unknown"` |
| **CBOM** | FE `crypto_strength ?? "unknown"` | Findings table / detail | 0 hits live (field always set) | P2 | `CbomResults.tsx:1480,1608` | Fallback `not-applicable` / `—` |
| **CBOM** | Adapter `return "unknown"` | Future odd asset_type | 0 live | P1 | `cbom_devsecshield.py:71` | Map to `other` / concrete assetType |
| **CBOM** | `crypto:primitive` default `"unknown"` | Normalize / compliance | Rare | P1 | `normalize.py:113`, `algorithm_scan.py:388–389` | Prefer omit / `other`; compliance already treats unknown primitive specially |
| **CBOM** | Chart label map `unknown: "Unknown"` | Algo primitive labels | Only if primitive=unknown | P2 | `CbomCryptoCharts.tsx:152` | Relabel `other` / hide |
| **All** | Scan UI mode `"unknown"` | Options sidebars before mode chosen | UX state only | OK | `*-options-sidebar.tsx` | Out of scope (not BOM data) |
| **All** | `scan_status \|\| "unknown"` | Loading | Transient | OK | scan pages | Out of scope |

### Prior Ruflo memories (already done)

| Key | Status |
|-----|--------|
| `aibom-license-no-unknown-verified` | Verified — chart/findings |
| `aibom-provider-no-unknown-verified` | Verified — chart/findings |
| `bom-unknowns-elimination-kickoff` | Diagnosing → this plan |

---

## 3. Proposed fix groups (dependency order — PLAN ONLY)

### Group A — SBOM license taxonomy + mapper (foundation)

**Depends on:** nothing  
**Deliverables:**

- New pure module (suggested): `backend/utilities/dashboard/sbom_license.py` + worker twin or shared util under `aibom` if worker can import it.
- `spdx_to_license_category(spdx: str) -> category` covering common SPDX (`MIT`/`Apache-2.0`/`BSD-*` → permissive; `LGPL-*` → weak_copyleft; `GPL-*` → strong_copyleft; `AGPL-*` → network_copyleft; `MPL-*`/`SSPL` → source_available; `CC-*` → creative_commons; `0BSD`/`Unlicense`/`CC0` → public_domain; commercial markers → commercial).
- Replace enum/chart bucket `unknown` with **`not_declared`** (risk: treat like today’s unknown = low risk for scoring, but **label honestly**). Update `LicenseCategory`, FE `LICENSE_CATEGORIES` / labels, `LICENSE_ALL_CATEGORIES`, PDF, compliance tests that assert on `"unknown"`.

### Group B — SBOM emit-time enrichment (stops new unknowns)

**Depends on:** Group A  
**Deliverables:**

- Change `inventory_to_finding_rows` (`merge_inventory.py`):
  - Always set `license` = raw SPDX/name when Syft/cdxgen provides it.
  - Set `license_type` = category via mapper; **never** write `"unknown"`.
  - If no license: resolve by package name / purl (reuse patterns from `aibom/scan/parsers/license_resolver.py` curated map; optional `importlib.metadata` / offline-only — confirm network policy with user).
  - Last resort: `license_type = "not_declared"` (+ optional `license = "LicenseRef-not-declared"`).
- Consider Syft flags / license catalog enablement if docs show licenses omitted by default (investigate during implement; do not assume without evidence).
- `enrich_sbom_scan` may optionally re-normalize all rows before persist.

### Group C — SBOM read-time remap (legacy scans + dashboard honesty)

**Depends on:** Group A  
**Deliverables:**

- `resolve_sbom_license_category(item)` used in:
  - `generate_scan_dashboard` SBOM branch (`scan.py`)
  - `generate_dashboard_data_for_scan_list` (`scan_list.py`)
  - `findings.py` sbom_sca branch (pass resolved `license_type`)
- Ensures old DB rows chart correctly **without** requiring re-scan for demos; acceptance still requires **re-scan** for emit-path proof.

### Group D — AIBOM emit-time parity (eliminate residual `data.source=unknown`)

**Depends on:** existing `aibom_license` / `aibom_provider` (done)  
**Deliverables:**

- In `aibom.integrations.devsecshield` (and/or worker parser): write concrete `source`/`provider` and concrete `license` at persist time (same rules as resolvers).
- Optionally have GET scan `data` pass through the same resolvers so API `data` never shows `unknown` even for legacy rows.
- Acceptance: both `dashboard.*` and `data[]` / `findings[]` have **zero** literal `unknown` for provider/license/source.

### Group E — CBOM defensive hardening

**Depends on:** nothing (parallelizable)  
**Deliverables:**

- `_legacy_algorithm_type`: never return `"unknown"`; use `asset_type` or `"other"`.
- FE: replace `?? "unknown"` with `not-applicable` / em dash.
- Normalize: avoid inventing `primitive: "unknown"` when property missing (omit or `other`).
- Keep quantum N/A as `null` (do **not** coerce to a fake strength).

### Group F — Tests + gates

**Depends on:** A–E  
**Deliverables:**

- Unit: SPDX→category matrix; package enrichment; residual `not_declared`.
- Contract: dashboard distributions contain no key/value `unknown` for in-scope fields.
- Hermetic fixture scan (synthetic CycloneDX with/without licenses).
- Optional regression: extend worker `test_empty_matches.py`.

---

## 4. Verification plan — 30 live scans (10 per BOM)

### Trigger / re-run

1. Ensure worker restarted after code changes (Celery does not hot-reload).
2. Backend `:8081`, frontend `:3000`, RabbitMQ worker on `scan_worker_queue`.
3. Auth: mint JWT with `create_access_token("cbom-demo@cyberultron.com")` after `session_active=True`.
4. For each BOM type, create **10 new** scans via `POST /1/{type}/scan` + start (or UI New Scan) against diverse public repos already used in INDIA/P6 sets:

| Type | Suggested repos (reuse known-good) |
|------|-------------------------------------|
| `sbom_sca` | psf/requests, pallets/flask, urllib3/urllib3, sqlalchemy/sqlalchemy, pallets/click, + 5 more (e.g. encode/httpx, pallets/jinja, pytest-dev/pytest, redis/redis-py, psf/black) |
| `cbom` | jpadilla/pyjwt, pyca/pyopenssl, pyca/cryptography, mitmproxy/mitmproxy, paramiko/paramiko, + 5 more crypto-heavy |
| `ai_bom` | karpathy/nanoGPT, langchain-ai/langchain, microsoft/autogen, openai/openai-python, modelcontextprotocol/servers, + 5 more |

5. Wait until `scan_status == success` for all 30.

### Acceptance checks (automated script preferred)

For each success scan id:

```
GET /1/{type}/scan/{id}
```

Assert **zero** occurrences of case-insensitive token `unknown` in:

| Type | In-scope fields |
|------|-----------------|
| SBOM | `dashboard.licenses_distribution` keys/values; each finding/`data` row `license_type`; top-vuln `license_type`; (optional) reachability |
| AIBOM | `dashboard.license_distribution`, `dashboard.provider_distribution`; `findings[].license_type`, `findings[].provider`; `data[].license`, `data[].source` |
| CBOM | `dashboard.strength_distribution`, `algorithm_type_distribution`, `quantum_readiness`; each row `crypto_strength`, `algorithm_type` |

Allowed honest labels: `not_declared`, `LicenseRef-not-declared`, `LicenseRef-not-applicable`, `LicenseRef-proprietary`, `not_assessed`, `not-applicable`, `other`, `null` for quantum N/A.

Also assert team list dashboards after the 10 new scans: no `unknown` bucket for licenses (SBOM) / providers+licenses (AIBOM).

### UI spot-check (3 scans)

Playwright or manual: open results pages; license/provider charts must not show an "Unknown" legend entry.

---

## 5. Risks / honest N/A cases

| Case | Do **not** fake | Prefer label |
|------|-----------------|--------------|
| Package truly has no declared license in SBOM/metadata | Guessing GPL/MIT | `not_declared` / `LicenseRef-not-declared` |
| Hosted API / credential / `.bin` artifact (AIBOM) | SPDX of unrelated OSS | `LicenseRef-not-applicable` or proprietary |
| Proprietary model weights | "MIT" | `LicenseRef-proprietary` |
| CBOM cert/key/protocol quantum | `quantum_safe=false` | keep `null` (N/A) |
| Reachability not analyzed | `reachable` | `not_assessed` / keep `not_reachable` for pure inventory |
| GitHub Actions (`pkg:github/actions/...`) without license in Syft | Random category | Resolve via known Action licenses **or** `not_declared` |
| Dual field model | Overwriting SPDX with only category | Keep raw SPDX in `license`; category in `license_type` |

**Risk:** Treating `not_declared` as zero-risk may understate license compliance debt — keep it visible in charts (dedicated bucket) and in SBOM compliance checks (NTIA license presence).

**Risk:** Enabling live PyPI/network license lookup breaks hermetic CI — prefer curated map + optional offline metadata; gate network behind explicit flag.

**Two-writer hazard:** commit only story files with explicit `git add <paths>`; never `git add -A`; never `git stash`.

---

## 6. Questions for user confirmation (gate before coding)

1. **SBOM chart model:** Keep **risk-category** chart (`permissive` / `not_declared` / …) with SPDX stored separately, **or** switch SBOM license chart to **SPDX/LicenseRef** bars like AIBOM?
2. **Residual policy:** Is **`not_declared`** acceptable for packages Syft+curated-map cannot resolve, as long as literal `unknown` is gone? Or must we attempt online PyPI/GitHub license APIs for ≥95% resolution?
3. **Legacy scans:** Must old scans (e.g. `#91`) look fixed via **read-time remap** immediately, or is **re-scan only** enough for acceptance?
4. **Scope freeze:** Confirm in-scope = **license (all BOMs) + AIBOM provider/source + CBOM strength/type**; out-of-scope for this pass = empty framework/version, reachability (except removing the word unknown), PDF polish?
5. **Verification repos:** OK to reuse the INDIA/P6 repo sets above for the 30 re-scans, or do you want a fixed `repos.tsv`?
6. **Enum break:** Renaming `LicenseCategory.UNKNOWN` → `NOT_DECLARED` will touch worker schema + FE + tests — confirm OK (no backward compat for the string `"unknown"` in new emits)?

---

## 7. Evidence appendix (live pulls)

| Probe | Result |
|-------|--------|
| `GET /1/sbom_sca/scans` dashboard | `licenses_distribution`: permissive 130, **unknown 820** |
| `GET /1/sbom_sca/scan/91` | 102 findings; license_type unknown **97**, permissive **5**; dash unknown **97** |
| `GET /1/sbom_sca/scan/87` | unknown 23 + raw MIT×5 (chart still unknown-heavy; SPDX not in category bars) |
| `GET /1/ai_bom/scan/95` | dash licenses/providers: **no unknown**; findings resolved; `data.source` unknown **23** |
| AIBOM ×10 scans | findings provider/license unknown **0**; data.source unknown **357/672** |
| CBOM ×10 scans | strength/algo unknown **0/2812**; qr.unknown **0** |
| Contrast `#58` | Old vuln-only style: 11× permissive, **0** unknown (no inventory path) |

---

## 8. Implementation readiness

**Do not code until §6 answers are confirmed.**

Recommended first coding slice after confirmation: **Groups A → B → C** (SBOM), then D (AIBOM emit), then E (CBOM), then F + 30-scan verification.
