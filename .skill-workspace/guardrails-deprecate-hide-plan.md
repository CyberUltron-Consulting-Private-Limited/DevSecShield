# Guardrails — Hide from user-facing FE + Deprecate (do not delete)

**Date:** 2026-08-09  
**Repo:** DevSecShield  
**Constraint:** Two-writer — touch only Guardrails-related files. No CBOM/AIBOM. No git push.

---

## Goals

1. Remove Guardrails from all **customer-visible** frontend entry points (nav, dashboards, charts, landing).
2. **Deprecate, do not delete** FE components/pages/API helpers and BE routers/workers/utilities.
3. Deep links: soft deprecation notice + link to team home (route kept; no API calls from the notice).
4. Backend APIs/workers stay importable and runnable for internal/API callers.

---

## Discovered architecture (evidence)

| Layer | Path | Role |
|-------|------|------|
| Sidebar | `frontend/app/[team_id]/layout.tsx` `workflowItems` | Nav entry `Guardrails` → `guardrails` |
| Home utilization | `frontend/app/home/page.tsx` | Radial segment + copy mentioning Guardrails |
| Team dashboard | `frontend/app/[team_id]/page.tsx` | Integrations area chart series `Guardrails` |
| List page | `frontend/app/[team_id]/guardrails/page.tsx` | CRUD UI (calls APIs) |
| Detail page | `frontend/app/[team_id]/guardrails/[integration_id]/page.tsx` | Dashboard/settings/docs |
| Components | `frontend/components/Guardrails{DashboardData,ApiDocs}.tsx` | Charts + API docs |
| FE client | `frontend/utils/backend_api.ts` Guardrails section ~L3060+ | API helpers |
| BE routers | `backend/routers/guardrails.py`, `guardrails_public.py` | REST |
| BE utils | `backend/utilities/guardrails/*`, `dashboard/guardrail*` | Auth/schemas/dashboards |
| Worker | `RabbitMQ/guardrail_worker/*` | Celery tasks |
| Mount | `backend/main.py` include_router | Still mounted |

`SCAN_TYPE_LABELS` has **no** `guardrails` key (Guardrails is an integration, not a scan_type) — no change needed there.

Admin `guardrails_integrations_count` is admin-facing, not product nav — leave data path; mark BE helpers deprecated only.

---

## Hypotheses & confidence

| # | Hypothesis | Confidence |
|---|------------|------------|
| H1 | Hiding sidebar + home/team chart series + soft-notice pages is sufficient for "user-facing" removal | High |
| H2 | Keeping named `Deprecated*` exports + `@deprecated` comments satisfies "do not delete" | High |
| H3 | Backend needs docstring/`deprecated=True` OpenAPI markers only; do not disable APIs | High |
| H4 | Leaving admin count fields alone is correct (not customer product UI) | Medium-High |

---

## Approaches considered

1. **Hard delete routes/components** — rejected (user: do not delete).
2. **Feature flag off + keep UI behind flag** — overkill; notice is clearer.
3. **Recommended:** Hide entry points + soft notice on deep links + deprecate markers everywhere; APIs/workers stay.

---

## Implementation plan

### Frontend (user-facing hide)

1. `layout.tsx` — remove Guardrails from `workflowItems`; drop unused `Shield` import if unused.
2. `home/page.tsx` — remove Guardrails from utilization aggregation **display** (`utilLabels`); update CardDescription copy to CI/CD only.
3. `[team_id]/page.tsx` — integrations chart: CI/CD only; update copy; remove Guardrails series/gradient/config.
4. New `frontend/components/GuardrailsDeprecatedNotice.tsx` — polite notice + link to `/{team_id}`.
5. `guardrails/page.tsx` + `[integration_id]/page.tsx` — default export renders notice only (no API calls); preserve full prior UI as named `@deprecated` export (`DeprecatedGuardrailsPage` / `DeprecatedGuardrailsIntegrationPage`).
6. `GuardrailsDashboardData.tsx`, `GuardrailsApiDocs.tsx` — file-level `@deprecated` TSDoc.
7. `backend_api.ts` Guardrails section — `@deprecated` on interfaces + helpers; keep exports.

### Backend (deprecate only)

8. Module docstrings `# DEPRECATED` / `"""DEPRECATED: ..."""` on:
   - `routers/guardrails.py`, `routers/guardrails_public.py`
   - `utilities/guardrails/auth.py`, `schemas.py`
   - `utilities/dashboard/guardrail_integration.py`, `guardrails_list.py`
   - `RabbitMQ/guardrail_worker/guardrail_worker.py` (+ runner if primary entry)
9. FastAPI: tag `Guardrails (deprecated)` and `deprecated=True` on public route decorators (or router-level where supported).
10. `main.py` — short comment at `include_router(guardrails_*)`.

### Out of scope

- Do not delete workers, compose files, models, mongo collections, team-delete cascades.
- Do not change CBOM/AIBOM/BOM.
- Do not git push / open PR.

### Verification

- Grep FE for user-visible "Guardrails" in nav/home/team charts → none (except deprecation notice + comments).
- tsc `--noEmit` + scoped eslint on touched FE files.
- Write `guardrails-deprecate-hide-verify.md`.
- Ruflo `memory_store` key `guardrails-deprecate-hide-verified`.

---

## Risks

| Risk | Mitigation |
|------|------------|
| Named deprecated page exports trip unused lint | Prefer `export` (not local unused); suppress only if needed |
| Bookmarked deep links confuse users | Soft notice + back to team home |
| Parallel writer touches same layout | Only edit Guardrails line / Shield import |
| Backend OpenAPI clients see deprecation | Intended |

---

## Success criteria

- [ ] No Guardrails in sidebar
- [ ] No Guardrails segment on home utilization chart
- [ ] No Guardrails series on team integrations chart
- [ ] `/[team]/guardrails` and `/[team]/guardrails/[id]` show soft notice, no API calls
- [ ] All Guardrails modules marked deprecated; implementations retained
- [ ] BE APIs still mounted
- [ ] FE typecheck/lint clean on touched files
