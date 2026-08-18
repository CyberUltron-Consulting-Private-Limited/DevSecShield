# Guardrails deprecate/hide — verification

**Date:** 2026-08-09  
**Plan:** `.skill-workspace/guardrails-deprecate-hide-plan.md`

## Checks

| Check | Result |
|-------|--------|
| Sidebar `workflowItems` has no Guardrails | PASS (`rg` no `name: "Guardrails"`) |
| Home utilization chart omits Guardrails segment | PASS (utilLabels: SAST/IAC/SBOM/SCA/CI/CD only) |
| Team integrations chart is CI/CD-only | PASS (Guardrails Area/series removed) |
| Deep links `/[team]/guardrails` + `/[id]` | PASS — soft `GuardrailsDeprecatedNotice` only, no API calls |
| Full UI retained (not deleted) | PASS — `frontend/components/deprecated/DeprecatedGuardrails{Page,IntegrationPage}.tsx` |
| FE API helpers marked `@deprecated` | PASS — `backend_api.ts` Guardrails section |
| BE routers/utils/worker module docs + OpenAPI `deprecated=True` | PASS |
| BE routers still mounted in `main.py` | PASS |
| `py_compile` on touched BE modules | PASS |
| eslint on thin routes + notice + home | PASS (exit 0) |
| tsc: no new guardrails-related errors | PASS (pre-existing CBOM tsc noise unrelated) |

## Hidden user-facing entry points

1. Sidebar Workflows → Guardrails (`layout.tsx` `workflowItems`)
2. Home “Utilization across all teams” radial Guardrails segment + copy
3. Team dashboard “Your Team's Integrations” Guardrails area series + copy
4. Interactive Guardrails list page (replaced by soft notice)
5. Interactive Guardrails integration dashboard (replaced by soft notice)

## Deprecated modules (implementations retained)

### Frontend
- `frontend/app/[team_id]/guardrails/page.tsx` (notice wrapper)
- `frontend/app/[team_id]/guardrails/[integration_id]/page.tsx` (notice wrapper)
- `frontend/components/GuardrailsDeprecatedNotice.tsx`
- `frontend/components/deprecated/DeprecatedGuardrailsPage.tsx`
- `frontend/components/deprecated/DeprecatedGuardrailsIntegrationPage.tsx`
- `frontend/components/GuardrailsDashboardData.tsx`
- `frontend/components/GuardrailsApiDocs.tsx`
- `frontend/utils/backend_api.ts` (Guardrails section helpers/types)

### Backend / worker
- `backend/routers/guardrails.py`
- `backend/routers/guardrails_public.py`
- `backend/utilities/guardrails/auth.py`
- `backend/utilities/guardrails/schemas.py`
- `backend/utilities/dashboard/guardrail_integration.py`
- `backend/utilities/dashboard/guardrails_list.py`
- `backend/new_models.py` (`GuardrailsIntegration`)
- `backend/mongo_models.py` (`GuardrailLogs`)
- `backend/main.py` (mount comment)
- `RabbitMQ/guardrail_worker/guardrail_worker.py`
- `RabbitMQ/guardrail_worker/guardrail_runner.py`

## Out of scope (intentionally untouched)

- CBOM/AIBOM/BOM code
- Admin count fields / team-delete cascades
- Worker compose / demo packages (still exist; worker marked deprecated)

## Notes

- Pre-existing eslint issues on `layout.tsx` / `[team_id]/page.tsx` (unrelated to this change) remain; scoped lint on Guardrails thin routes is clean.
- No git push performed.
