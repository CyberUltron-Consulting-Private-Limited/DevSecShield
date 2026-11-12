# BOM Graph Expand — Root Cause + Fix Plan

**Date:** 2026-08-09  
**Status:** FIXED + VERIFIED  
**Subjects:** CBOM `#94`, AIBOM `#95` (team 1)

## Symptom

Clicking **Expand** on the dependency graph opens a Dialog, but the user sees essentially nothing (header-only overlay). Prior Playwright falsely “verified” Expand because it only asserted `dialog-content` visible + `.react-flow__node` **DOM count** — nodes were present but **not visible**.

## Live evidence (before)

Script: `.skill-workspace/bom-graph-expand-diag.cjs`

| Metric | CBOM #94 | AIBOM #95 |
|--------|----------|-----------|
| Dialog height | **75px** (header only) | **75px** |
| `.react-flow` height | **0** | **0** |
| Node DOM count | 26 | 49 |
| Nodes intersecting canvas | **0** | **0** |

API metadata was fine (`*_graph_expanded` present) — **not** a missing-data bug.

## Root cause (one-liner)

`BomGraphFullscreen` DialogContent used `max-h-[92vh]` **without an explicit height**, so the flex column shrink-wrapped to the header (~75px); the canvas collapsed to **0px** and `overflow-hidden` clipped the nodes.

## Locked fix (implemented)

1. **`BomGraphFullscreen.tsx`** — `h-[90vh] max-h-[92vh]`; canvas shell `flex-1 min-h-0` (removed brittle calc height).
2. **`BomGraphCanvas.tsx`** — stronger `FitOnOpen` + scoped `FitOnResize` (ResizeObserver on this canvas shell) so Dialog size transitions still fitView.

## Verify (after)

| Check | CBOM #94 | AIBOM #95 |
|-------|----------|-----------|
| Dialog height | **810** | **810** |
| React Flow height | **735** | **735** |
| Visible nodes in canvas | **26** | **49** |
| Escape / close button | yes | yes |
| Non-HMR console errors | 0 | 0 |
| `tsc --noEmit` | clean | |
| eslint `components/bom/*` | clean | |

Artifacts: `/tmp/bom_expand_diag_after.json`, `/tmp/bom_graph_ux_after_fix.json`, `/tmp/bom_expand_cbom94.png`
