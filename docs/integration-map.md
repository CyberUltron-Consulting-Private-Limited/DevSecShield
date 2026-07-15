# AI BOM ↔ DevSecShield Integration Map (Phase-5 recon, contract LOCKED)

**Status:** recon complete, contract locked in Ruflo memory (`devsecshield/contract/*`, `devsecshield/state/aibom-current`). **No code changed.** Stop for review.

Method: traced ONE reference scanner (**SBOM** = `sbom_sca`, the closest analog) end-to-end from UI click to rendered result, root-cause style (every claim cites `file:line`/symbol). Two parallel explorers (backend + frontend) converged here.

---

## 0. The headline finding — there are TWO AI BOM codebases

| | **Wired worker agent** (live) | **Standalone package** (Phases 0–4) |
|---|---|---|
| Path | `RabbitMQ/worker/helpers/tools/ai_bom_agent/` | `aibom/` (uv package, repo root) |
| Entry | `AIBOMAgent` (`main.py:23`) | `aibom.scan.pipeline.scan_repo` |
| Output | `AIComponentVulnerability` findings + `ai_bom_json` (CycloneDX 1.6) + `ai_bom_compliance` | `ScanResult{components, edges, flags, scores, compliance}` + CycloneDX/SPDX/SARIF + shadow/Cedar/dashboard |
| Integration | **Already WIRED end-to-end** (worker task `scan_worker.ai_bom`, all ~20 backend touch points, full frontend) | **Not wired** — standalone CLI only |

**So Phase-5 "integration" is NOT greenfield.** AI BOM already runs through the exact same async scan/job/status mechanism as SBOM, with a complete UI mirroring `sbom_sca` 1:1. The real work is **reconciling the richer standalone engine into the already-locked wired contract** (per `devsecshield/rule/additive` — additive, behind a scanner adapter, lanes intact; and `devsecshield/rule/match-dont-invent` — reuse the existing UI primitives). This document locks that contract.

---

## 1. Reference flow — SBOM from click to render

```
UI: list page → "New Scan" → create → estimate → start
  POST /{team}/{type}/scan                 create_scan        scans.py:100  → {scan_id}
  POST /{team}/{type}/scan/{id}/estimate…  estimate_credits   scans.py:822
  POST /{team}/{type}/scan/{id}/start      start_scan         scans.py:411  → {message}
        │  atomic claim NOT_STARTED→pending (scans.py:482), deduct credits
        ▼
  Celery send_task("scan_worker.<type>", queue="scan_worker_queue")   start_scan.py:36-53
        │  broker=RabbitMQ(amqp)  result-backend=MongoDB
        ▼
  Worker @app.task handler (scan_worker.py)  ── runs scanner ──▶ returns run-dict
        │  (worker NEVER pushes status; lifecycle is POLL-DRIVEN)
        ▼
  UI polls GET /{team}/{type}/scan/{id}  get_scan  scans.py:269
        │  if non-terminal+task_id → get_status_and_update_db (celery_connection.py:67)
        │  on SUCCESS transition → ingest AsyncResult.result into Scan.scan_data
        │                          + create_findings → Mongo scan_findings
        ▼
  Results route renders findings + dashboard + ai_bom_json/compliance
```

Job record = **PostgreSQL** `Scan` row; findings = **MongoDB** `scan_findings`; Celery result = **MongoDB** backend. Progress `%` rides `Scan.info.current`.

---

## 2. Backend contract (LOCKED)

### 2a. API endpoints (`backend/routers/scans.py`, prefix `/{team_id}/{type}`)
| Verb + path | Function:line | Body / returns |
|---|---|---|
| `POST …/scan` | `create_scan` :100 | `CreateScanData{title}` → `{scan_id:int}` |
| `POST …/scan/{id}/estimate_credits` | `estimate_credits_for_scan` :822 | multipart `start_scan_payload_string` (+file) → credit estimate |
| `POST …/scan/{id}/start` | `start_scan` :411 | multipart `start_scan_payload_string` (422 on invalid :432) (+file) → `{message}` |
| `GET …/scan/{id}` | `get_scan` :269 | **the poll + detail endpoint**; refreshes Celery state; returns `{title, scan_metadata, scan_status, findings, dashboard, messages, integration_settings, info, data}` :356 |
| `GET …/scans` | `list_scans` :52 | list + dashboard aggregates; background status refresh |
| `GET …/scan/{id}/export` | :697 | PDF (`pdf/combined.py:32`) |

`type` ∈ `scan_types` (`backend/new_models.py:4`): `sast, llm, mcp, iac, leakage, sbom_sca, agent_discovery, dast, cbom, **ai_bom**`.

### 2b. Orchestration — Celery over RabbitMQ, Mongo result backend
- Client: `get_celery_app` (`backend/utilities/celery/celery_connection.py:19`).
- Publish: `start_scan_and_update_db` (`backend/utilities/scan/start_scan.py:17`) → explicit `send_task(name="scan_worker.<type>", kwargs=…, queue="scan_worker_queue")` (per-type `if/elif`, ai_bom at :50). Estimation mirror: `estimate_scan.py:85`.
- Routing = **task-name + explicit `queue=`** (no routing-key table). Worker binds queue via launch cmd `celery -A scan_worker worker -P threads -Q scan_worker_queue` (`compose/worker-compose/docker-compose.yml:8`). DAST is a separate worker/queue (`dast_worker.dast`/`dast_worker_queue`).
- Consume: `RabbitMQ/worker/scan_worker.py:70` `app = Celery('worker', broker, backend=mongo)`; each scanner is an `@app.task`-decorated function — **Celery name-routing replaces any central dispatcher**.

### 2c. Job model + lifecycle (`backend/new_models.py:78` `Scan`, Postgres)
Fields: `id, team_id, owner_user_id, credit_consumed, scan_type, title, task_id, scan_metadata(JSON), scan_status, created_at, last_updated, scan_data(JSON), info(JSON), integration_settings(JSON)`.
`scan_status: Literal["NOT_STARTED","pending","started","retry","failure","success"]` — **lowercased Celery states**, written only when a GET refreshes via `get_status_and_update_db` (`celery_connection.py:67`): `started`→`info.current` progress; `success`→ ingest `AsyncResult.result`→`scan_data` + create findings (once, on transition :131); `failure`→`info.error` + refund. **Poll-driven: nothing lands until a GET fires.**

### 2d. Result schema — what AI BOM normalizes INTO (LOCKED)
**Run object** (worker return → `Scan.scan_data`, ai_bom at `scan_worker.py:731`):
```
{ results: list[dict],            # findings, each an AIComponentVulnerability dump
  ai_bom_json: dict | None,       # CycloneDX 1.6 ML-BOM
  ai_bom_compliance: dict | None, # framework pass/fail/na report
  duration_of_scan: float }
```
**Per-finding** `AIComponentVulnerability(BaseVulnerability)` (`RabbitMQ/worker/helpers/context/schema.py:119`):
`title, description, impact, owasp_top_10[], compliance_controls[], suggested_fix` (base) + `component_name, component_type(AIComponentType), framework?, version?, source(ModelProvider), license?, location, snippet, risk_category(AIRiskCategory), owasp_top_10_llm[]`.
**SEVERITY field = `impact`** ∈ `{"Low","Medium","High","Critical"}` (`enums.py:266`). No stored numeric severity — `risk_score` (0–10) derived at read: `_ai_bom_risk_score` (`db/findings.py:52`, crit 9/high 7/med 5/low 2); dashboard scale 10/7.5/5/2.5 (`dashboard/scan.py:13`).
**Mongo finding doc** `ScanFindings` (`mongo_models.py:23`): `scan_id, created_at, finding_data, finding_status∈{fixed,ignored,in_progress,not_started}, fixed_at, ignored_at, info`. Ingest: `create_findings.py:136` (shared `cbom`/`ai_bom` branch, one doc per `results[]` element, idempotent delete-then-insert). Summary counts are computed on read, not stored.

### 2e. Scanner registration — the distributed "registry" (~20 touch points)
There is **no single registry file**; a scan type is registered across these sites (all present for `ai_bom`):
1. `new_models.py:4,83` enum + `Scan.scan_type` · 2. `mongo_models.py:15` `ConversationType` · 3. `utilities/db/schemas.py:233,253` `StartAIBOMScanData` + `StartScanPayload` · 4. `utilities/scan/format_input.py:206` kwargs builder · 5. `utilities/db/metadata.py:75` · 6. `utilities/scan/start_scan.py:50` run dispatch · 7. `utilities/scan/estimate_scan.py:85` estimate dispatch · 8. `RabbitMQ/worker/scan_worker.py:694` (`ai_bom`) + `:860` (`ai_bom_estimation`) `@app.task` · 9. agent `helpers/tools/ai_bom_agent/main.py:23` · 10. finding model `helpers/context/schema.py:119` · 11. ingest `create_findings.py:136` · 12. read/UI surfaces: `db/findings.py:196`, `dashboard/scan.py:1291`, `dashboard/scan_list.py:130`, `db/scan_list_item.py:496`, `dashboard/scan_metadata.py:135`, `db/functions.py:136`, `pdf/combined.py:32`, `ai/chatbot.py:68`, `ai/remediation.py:73`.
> **Note:** the "add a scanner = one file" ideal is aspirational here — a scan type realistically touches ~20 sites. For AI BOM all 20 already exist, so reconciling the standalone engine means **swapping the agent body (#9) behind the same contract**, not re-registering.

---

## 3. Frontend contract (LOCKED) — `frontend/` (Next.js 16, app-router)

### 3a. Stack (discovered, named)
- **shadcn/ui** (new-york, base `zinc`, lucide icons) on **Tailwind v4** (CSS-first, *no* `tailwind.config`); primitives in `components/ui/`. (`components.json`)
- **Charts: Recharts 2.15** via the shadcn wrapper `components/ui/chart.tsx` (`ChartContainer`/`ChartTooltip`/`ChartConfig`). AI BOM charts MUST use this.
- **Data/state: TanStack React Query v5**; `QueryClient` per route-group (`app/[team_id]/layout.tsx:259`). HTTP = **axios** (`utils/backend_api.ts`). SSE (`@microsoft/fetch-event-source`) ONLY for chat.
- Graph lib present: **`@xyflow/react`** (used for IAC `dependency_diagram`) — relevant to AI BOM edges (§5).

### 3b. Theme tokens + severity palette
- Tokens: **oklch CSS variables** in `app/globals.css` (`:root`/`.dark`, `@theme inline`). No JS theme config.
- **Severity palette is HARDCODED Tailwind utilities, NOT tokens** — reuse verbatim (`getImpactBadgeClass`, identical in `SbomResults.tsx:122` & `AiBomResults.tsx:103`): **critical `bg-red-600` · high `bg-orange-500` · medium `bg-amber-500` · low `bg-blue-500` · info `bg-zinc-500`**. Chart fills (HSL, `sbom_sca/page.tsx:161`): crit `hsl(0 72% 51%)` / high `hsl(25 95% 53%)` / med `hsl(45 93% 47%)` / low `hsl(217 91% 60%)`. Risk bands: crit ≥9, high 7–9, med 5–7, low <5.

### 3c. Patterns
- **Results page:** thin route `…/[scan_id]/results/page.tsx` (`useQuery` → `isLoading` `Loader2 text-blue-600` / `isError`) → big presentational component (`SbomResults.tsx` ~1500 ln): header (`ArrowLeft` back, `h1`, Download + "Chat with the Results") → underline tabs → metadata `Card` tiles → summary stat tiles + `Progress` → Recharts severity charts → findings `Table` (search/filter/bulk-Jira/`RemediationPanel`).
- **Scanner "card" = sidebar nav row** in `toolsItems` (`app/[team_id]/layout.tsx:149`): `{name:"AI BOM", path:"ai_bom", icon:Bot}` already at :153.
- **Routing:** `/{team}/<scanner>`, `/{team}/<scanner>/{id}`, `/{team}/<scanner>/{id}/results`.
- **In-progress:** **6 s `setTimeout`→`invalidateQueries` poll** while `scan_status∈{pending,started}` (`ai_bom/[scan_id]/page.tsx:35`); progress = `info.current`. Loading=`Loader2` spinner (no `Skeleton`); empty/error = centered muted text. List pages = manual Refresh only.

---

## 4. Current AI BOM state — **WIRED (complete), both tiers**
`devsecshield/state/aibom-current`: AI BOM is a first-class scan type, NOT stubbed/missing.
- **Backend:** worker tasks `ai_bom` + `ai_bom_estimation`; agent `helpers/tools/ai_bom_agent/` (source/binary scanner, `parser.py` CycloneDX 1.6 generator, `compliance/` with hipaa/fda_524b/eu_ai_act_annexIV/gmlp/nist_rmf); all 20 registration sites; tests (`backend/tests/test_bom_api_regressions.py`, `RabbitMQ/worker/tests/test_bom_regressions.py`, `test_compliance_mapping.py`).
- **Frontend:** nav entry, list page `ai_bom/page.tsx`, scan page `ai_bom/[scan_id]/page.tsx`, results `AiBomResults.tsx` (1544 ln), `ai-bom-options-sidebar.tsx`, API client (`getAIBOMScans`/`getAIBOMScanData`/`createAIBOMScan`), `use-sse.ts` `valid_types` includes `ai_bom`.
- **Gap:** the standalone `aibom/` package (richer ScanResult graph + SPDX/SARIF + shadow + multi-site + Cedar + dashboard) is **NOT** the wired path — it's a parallel engine. Reconciling it is the remaining Phase-5+ work.

---

## 5. Data-type → presentation mapping (the integration crux)
How each standalone-`ScanResult` data type lands in the wired UI — **existing primitive vs new**:

| ScanResult type | Normalizes to (wired contract) | Presentation primitive | New? |
|---|---|---|---|
| **components** (27 kinds) | `results[]` rows → `AIComponentVulnerability` (`component_name/type`, `source`, `framework`, `version`, `license`) | findings `Table` (`AiBomResults.tsx`) | **reuse** |
| **flags** (semantic findings) | one `result` per flag; `severity`→`impact` (`note/warning/error`→`Low/Medium/High/Critical`) | severity `Badge` (`getImpactBadgeClass`) | **reuse** |
| **scores** (`risk_total`, `risk_normalized` 0–100, `risk_band`) | rescale 0–100→0–10 `risk_score`; `risk_band`→severity bucket | risk-score cards + Avg-Risk tile + Recharts severity-distribution | **reuse** (needs a 0–100↔0–10 scale adapter) |
| **compliance** (5 frameworks pass/fail/na) | `ai_bom_compliance` dict | compliance/policy cards + `Progress` bars (already in `AiBomResults`) | **reuse** |
| **raw BOM artifacts** (CycloneDX) | `ai_bom_json` | "AI BOM JSON" export button | **reuse** |
| raw BOM (SPDX / SARIF) | *no wired field* — add `ai_bom_spdx`/`ai_bom_sarif` to run object OR multi-format export | Download/export button (extra menu items) | **reuse primitive, new field** |
| **edges** (`trained_on`/`depends_on`/`served_by`/`deployed_at`) | *no wired field* — closest precedent is IAC `dependency_diagram` | **`@xyflow/react` graph** (exists; IAC uses it) — needs a new AI-BOM graph tab | **NEW wiring** (lib already present) |
| **per-site** (multi-site `deployed_at` + `site:drift_status`) | per-site rows/group in `ai_bom_compliance` or a sites section | `Table` / `Card` tiles | **reuse** (new section) |

**Net:** 6 of 8 data types map to existing primitives unchanged; only **edges/graph** needs genuinely new wiring (and the lib — `@xyflow/react` — already ships), plus SPDX/SARIF need extra run-object fields + export menu items.

---

## 6. Extension points (exact)
**Backend** (swap engine behind the contract — keep all 20 sites): replace/augment the agent at `RabbitMQ/worker/helpers/tools/ai_bom_agent/main.py:23` (`AIBOMAgent`) so it normalizes a standalone `ScanResult`→`{results: AIComponentVulnerability[], ai_bom_json, ai_bom_compliance, duration_of_scan}` (a `ScanResult`→`AIComponentVulnerability[]` adapter is the one new module). New run-object fields (`ai_bom_spdx`, `ai_bom_sarif`, `ai_bom_graph`) are additive in `scan_worker.py:731` + read surfaces.
**Frontend** (parity, not scaffolding): nav (`layout.tsx:153`) ✓, routes ✓, results component `AiBomResults.tsx` ✓ — add a graph tab (`@xyflow/react`) for edges + extra export items for SPDX/SARIF; everything else reuses `Card`/`Badge`/`Table`/`Progress`/`ChartContainer` + the locked severity palette.

---

## 7. Open questions for review
1. **Engine reconciliation:** does the standalone `aibom/` engine REPLACE the wired `ai_bom_agent`, or feed it (adapter)? (Recommend: adapter — `ScanResult`→`AIComponentVulnerability[]` — to keep the additive/zero-regression guarantee.)
2. **Score scale:** wired UI is 0–10 (`impact`-derived); standalone is 0–100 `risk_normalized` + bands. Lock one mapping (proposed in §5).
3. **Edges/graph:** confirm `@xyflow/react` is the sanctioned primitive for the dependency graph (IAC precedent) before building the tab.
4. **SPDX/SARIF/shadow/Cedar/dashboard:** which standalone-only outputs surface in the product UI vs remain CLI/export-only?
