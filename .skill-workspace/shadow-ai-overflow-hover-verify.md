# Shadow AI overflow + hover + enrichment — verification

**Date:** 2026-08-09  
**Status:** VERIFIED  
**Subjects:** AIBOM scan **#95** findings dump (team 1); `aibom` clinical-imaging + nested `.bin` fixture

---

## What shipped

### Frontend (`AiBomVisualizations.ShadowAI` + `AiBomResults`)

1. **Overflow / wrap** — row uses `min-w-0 flex-1` on the text column, `break-all` / `break-words` on name/subline, `shrink-0` on the impact badge, `gap-2` on the flex row (CBOM migration-list style).
2. **Show all** — removed `shadow.slice(0, 8)`; full list renders in a `max-h-[28rem] overflow-y-auto` container (count badge in title).
3. **HoverCard** — shadcn HoverCard with Why / Description / How to fix / Location / Transparency; controlled open via row `onMouseEnter` / click (Trigger `asChild` was swallowing handlers).
4. **View full finding** — HoverCard action calls `onOpenFinding`; `AiBomResults` wires it to `setSelectedFinding` (same dialog as table click).

### Scanner enrichment (`model_file_scan.py`)

Root cause of empty `.bin` locations: weight-file components only set `model:weight_file=true`.

**Fix:** stamp `discovery:source` with the path relative to the scan root (`wf.relative_to(ctx.root).as_posix()`). Adapter already maps `discovery:source` → finding `location`.

---

## Evidence

### Unit / golden

| Check | Result |
|-------|--------|
| `tests/test_model_file_discovery_source.py` | PASS — `discovery:source` on model_file; adapter `location == "model.safetensors"` |
| Nested temp `.bin` under `weights/` | `discovery:source` / location = `weights/<hash>.bin` |
| `tests/test_scan.py` (incl. golden) | PASS — golden updated with alphabetical `discovery:source` prop |
| `npx tsc --noEmit` | PASS (after removing temp verify routes) |

### Live UI (AIBOM #95 dump)

Playwright script: `.skill-workspace/shadow-ai-overflow-hover-verify.cjs`  
Raw result: `.skill-workspace/shadow-ai-overflow-hover-verify-raw.json`  
Screenshot: `.skill-workspace/shadow-ai-overflow-hover-shot.png`

```json
{
  "ok": true,
  "rowCount": 43,
  "longBinRows": 12,
  "badgesInsideCard": true,
  "hoverOpened": true,
  "hoverHasWhy": true,
  "hoverHasDescription": true,
  "hoverHasFix": true,
  "hoverHasLocation": true,
  "viewFullOpensDialog": true,
  "dialogTitle": "173417d553406f034f643e5db3f8d591fb691ebac56f5ae39a22cc7d455c5353.bin"
}
```

**Note on Next 16.2.3 `next dev`:** headless Playwright did not hydrate client handlers (HMR WebSocket `ERR_INVALID_HTTP_RESPONSE`). Verification used `npm run build && npm run start` against auth-free temp route `/shadow-ai-verify` seeded with the live API dump of scan #95 (route deleted after). Horizontal badge-in-card checks also passed under `next dev` (SSR layout).

### Persisted scan #95 honesty

Existing DB rows for hash `.bin` assets still have **empty `location`** until a **new scan** with the enriched scanner (worker restart after deploy). Hover shows **"Location not recorded"** for those legacy rows — correct. New scans get real relative paths.

---

## Files changed

| Path | Change |
|------|--------|
| `frontend/components/ai-bom/AiBomVisualizations.tsx` | ShadowAI wrap + HoverCard + show-all + `onOpenFinding` |
| `frontend/components/AiBomResults.tsx` | Wire `onOpenFinding` → finding dialog |
| `aibom/src/aibom/scan/scanners/model_file_scan.py` | `discovery:source` enrichment |
| `aibom/examples/clinical-imaging/expected/chestxr.cdx.json` | Golden prop |
| `aibom/tests/test_model_file_discovery_source.py` | New lock tests |
| `.skill-workspace/shadow-ai-overflow-hover-verify.cjs` | Playwright verify |
| `.skill-workspace/shadow-ai-overflow-hover-verify.md` | This doc |

---

## Acceptance mapping

| Criterion | Status |
|-----------|--------|
| Long `.bin` names never push badge past card (horizontal) | PASS |
| Wrap preferred over truncate | PASS (`break-all`) |
| HoverCard sections | PASS |
| Empty location honest fallback | PASS |
| Show all (no slice 8) | PASS (43 rows) |
| View full finding → dialog | PASS |
| Scanner populates location when known | PASS (unit + nested `.bin`) |
