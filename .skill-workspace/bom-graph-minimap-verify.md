# BOM Graph MiniMap — Fix Verification

**Date:** 2026-08-09  
**Ruflo:** `bom-graph-minimap-fixed`  
**Subjects:** CBOM `#94`, AIBOM `#95` Expand

## Root cause

`@xyflow/react` MiniMap only paints nodes when `nodeHasDimensions(userNode)` is true — it checks `width` / `height` / `measured` / `initialWidth|Height` on the **user** node, **not** `style.width`.

`layoutBomGraph` set `style.width: 168` only → MiniMap skipped every node → SVG contained only the dark viewport mask → solid black inset.

## Fix

| File | Change |
|------|--------|
| `frontend/components/bom/layout.ts` | Set `width`/`height` (`NODE_W`/`NODE_H`) on each RF node; include `height` in `nodeStyleFor` |
| `frontend/components/bom/BomGraphCanvas.tsx` | Preserve dims when `styleFor` overrides; MiniMap uses lane `style.background` fills + theme-aware `bgColor`/`maskColor`/`maskStrokeColor` |
| Controls | Left intact from agent `4dc1b2b0` (zinc contrast + `colorMode` sync) |

Expand shell (`h-[90vh]`, `flex-1`, `min-h-0`) unchanged.

## Before → after (CBOM #94 Expand, dark)

| Metric | Before | After |
|--------|--------|-------|
| `.react-flow__minimap-node` | **0** | **26** |
| Sample fills | (none) | indigo / sky / amber lane colors |
| Controls icons | light on dark (readable) | same |
| Dialog / RF height | 810 / ~682 | 810 / 682 (no regression) |

AIBOM `#95`: **49** MiniMap nodes, teal + indigo fills, height OK.

## Gates

- `npx tsc --noEmit` — clean  
- `npx eslint` on touched bom files — clean  
- Playwright evidence: `/tmp/bom_minimap_after.json`, screenshots `/tmp/bom_minimap_after_{cbom94,aibom95}.png`

## Plan

`.skill-workspace/bom-graph-minimap-fix-plan.md`
