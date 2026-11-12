# BOM Graph Expand — UI Polish Plan

**Date:** 2026-08-09  
**Scope:** Controls / MiniMap / Expand dialog chrome  
**Subjects:** CBOM `#94`, AIBOM `#95`

## Hypotheses (brainstorm)

1. **H1 (primary):** `ReactFlow` defaults `colorMode="light"` so `--xy-controls-button-color-default: inherit`. Under app `.dark`, inherited text is near-white while button bg stays `#fefefe` → white-on-white icons.
2. **H2:** MiniMap light defaults wash out on dark canvas even with existing `!bg-zinc-900` class.
3. **H3:** Expand header is sparse (title only); cheap node/edge counts improve findability.

## Locked fix

1. Sync `colorMode` to `document.documentElement.classList.contains("dark")`.
2. Explicit zinc Controls className (dark-friendly fill + icon + hover + focus-visible rings) — belt-and-suspenders vs CSS-var inherit.
3. MiniMap: stronger mask + zinc border/shadow.
4. Fullscreen header: keep `h-[90vh]` / `flex-1 min-h-0`; clearer description with node·edge counts; slightly tighter chrome.

## Non-goals

- No Syft/Celery changes
- No new design system / new chart aesthetic
- No height-layout regression
