# BOM Graph MiniMap — Root Cause + Fix Plan

**Date:** 2026-08-09  
**Subjects:** CBOM `#94` Expand (and shared AIBOM Expand)  
**Ruflo key:** `bom-graph-minimap-fixed`

## Evidence (before)

Playwright on `http://localhost:3000/1/cbom/94/results` → Expand:

| Check | Result |
|-------|--------|
| `.react-flow__node` count | **26** |
| `.react-flow__minimap-node` count | **0** |
| MiniMap SVG children | title + **mask path only** |
| `userNode` keys | `id`, `position`, `data`, `style` |
| `userNode.width/height/measured` | **undefined** |
| Internal `measured` | `{ width: 168, height: 33 }` (present but unused by MiniMap gate) |
| `maskColor` | `rgba(9,9,11,0.65)` over dark `#141414` / zinc-900 → solid black look |

Screenshot: `/tmp/bom_minimap_before.png`

## Root cause (confirmed)

`@xyflow/react` MiniMap renders a node only when `nodeHasDimensions(internals.userNode)` is true:

```js
// @xyflow/system
nodeHasDimensions(node) =>
  (node.measured?.width ?? node.width ?? node.initialWidth) !== undefined &&
  (node.measured?.height ?? node.height ?? node.initialHeight) !== undefined
```

`layoutBomGraph` sets `style.width: 168` but **never** sets node-level `width`/`height` (or `initialWidth`/`initialHeight`). Style dimensions do **not** count. MiniMap therefore skips every node → empty overview → dark mask fills the inset → looks solid black.

Secondary: even after nodes appear, fixed `nodeColor="#52525b"` on dark bg is low contrast; better to use each node's `style.background` (lane colors).

## Hypotheses rejected

- **H-color-only:** Colors alone cannot explain zero `.react-flow__minimap-node` elements.
- **H-zero-size shell:** MiniMap rect is 202×152; SVG 200×150 — sized correctly.
- **H-nodes not in store:** `nodeLookup.size === 26`.

## Locked fix

1. **`layout.ts`:** set explicit `width: NODE_W`, `height: NODE_H` on every laid-out RF node (and `style.height` for DOM consistency).
2. **`BomGraphCanvas.tsx` MiniMap:**  
   - `nodeColor={(n) => String(n.style?.background ?? "#71717a")}`  
   - theme-aware `bgColor` / `maskColor` / `maskStrokeColor`  
   - keep `MINIMAP_CLASS` border/shadow  
3. **Controls:** leave agent `4dc1b2b0` Contasts polish intact (already readable: light icons on dark buttons).
4. **Do not** change `h-[90vh]` / `flex-1` / `min-h-0` Expand shell.

## Verification

- Playwright: `mmNodeCount > 0`, sample fills ≠ black, Controls still contrast-OK.
- `tsc --noEmit` + scoped eslint on touched files.
- Docs + Ruflo `bom-graph-minimap-fixed`.
