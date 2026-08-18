# BOM Dependency Graph UX — Verify Evidence

**Date:** 2026-08-09  
**Status:** VERIFIED (Expand zero-height Dialog fixed same day)  
**Subjects:** CBOM scan `#94` (team 1), AIBOM scan `#95` (team 1)  
**User:** `cbom-demo@cyberultron.com`  
**Backend:** `http://127.0.0.1:8081`  
**Frontend:** `http://localhost:3000`

## Locked answers (implemented)

1. Compact default = clustered  
2. CBOM collapse orphans/duplicate labels = yes  
3. AIBOM hub/family clustering = yes  
4. Limits = 40 compact / 120 expanded  
5. Shared component = `frontend/components/bom/*`  
6. `@dagrejs/dagre` for connected subgraph = yes  
7. Fullscreen = Dialog  
8. Frontend **and** backend prune = yes (`*_graph` intact; additive `*_graph_compact` / `*_graph_expanded`)

## Expand Dialog fix (2026-08-09)

**Root cause:** DialogContent had `max-h` only → flex shell ~75px → React Flow height 0 (nodes in DOM, invisible).  
**Fix:** `h-[90vh]` on DialogContent + canvas `flex-1 min-h-0` + FitOnResize.  
**Plan:** `.skill-workspace/bom-graph-expand-fix-plan.md`  
**Gate:** CBOM #94 visibleNodes=26 / dialogH=810; AIBOM #95 visibleNodes=49 / dialogH=810; Escape+close OK; tsc/eslint clean.

## Backend prune (live API)

`GET /1/{type}/scan/{id}` → `scan_metadata` (legacy scans projected on read):

| Scan | Full nodes | Compact | Expanded | Edges kept |
|------|-----------:|--------:|---------:|-----------:|
| CBOM `#94` | 96 | **9** (clustered 91) | **26** (clustered 79) | 4 |
| AIBOM `#95` | 175 | **27** (clustered 174) | **49** (clustered 148) | 22 (from 148) |

## Frontend E2E (Playwright headless) — post Expand fix

| Check | CBOM `#94` | AIBOM `#95` |
|-------|------------|-------------|
| Compact `.react-flow__node` count | 9 | 27 |
| Expand button visible | yes | yes |
| Dialog height | **810** | **810** |
| Dialog visible node count | **26** | **49** |
| MiniMap / Controls in Dialog | yes | yes |
| Escape + close button | yes | yes |
| Console errors (excl. HMR) | **0** | **0** |

## Frontend gates

- `npx tsc --noEmit` → clean  
- `npx eslint components/bom --max-warnings 0` → clean

## Key files

- `frontend/components/bom/{BomGraphCanvas,BomGraphCard,BomGraphFullscreen,layout,types}.tsx`  
- Wrappers: `AiBomVisualizations.DependencyGraph`, `CbomCryptoCharts.CryptoDependencyGraph`  
- `aibom/src/aibom/graph_view.py` + `backend/utilities/dashboard/scan_metadata.py`

## Notes

- Prior Expand “verify” that only counted DOM nodes was a **false positive** — always assert canvas height + visible intersection.  
- Compact Card keeps `minZoom={0.55}`; fullscreen `minZoom={0.15}`.  
- No git commit/push (per instructions).
