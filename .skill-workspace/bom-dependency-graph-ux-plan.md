# BOM Dependency Graph UX — Diagnosis + Implementation Plan

**Status:** PLAN ONLY — awaiting user confirmation before any product code edits  
**Date:** 2026-08-09  
**Live subjects:** CBOM scan `#94` (team 1), AIBOM scan `#95` (team 1), user `cbom-demo@cyberultron.com`, backend `http://127.0.0.1:8081`  
**Evidence dump:** `.skill-workspace/bom-graph-live-evidence.json`  
**Ruflo memory:** `bom-graph-ux` / `bom-graph-ux-diagnosis`

---

## 1. Evidence — current state

### 1.1 Live API graph sizes

| Scan | Repo | Nodes | Edges | Viewport height | Est. hand-layout height | Overflow factor |
|------|------|------:|------:|----------------:|------------------------:|----------------:|
| CBOM `#94` | `jpadilla/pyjwt` | **96** | **4** | 360px | ~4,156px | **~11.5×** |
| AIBOM `#95` | `openai/openai-python` | **175** | **148** | 340px | ~17,740px | **~52×** |

Source: `GET /1/cbom/scan/94` → `scan_metadata.cbom_graph`; `GET /1/ai_bom/scan/95` → `scan_metadata.ai_bom_graph` (JWT minted for demo user; both 200).

### 1.2 Layout algorithms in product code (no dagre/elk)

**AIBOM** — `frontend/components/ai-bom/AiBomVisualizations.tsx` `DependencyGraph` (~L165–228):

- Hand-rolled **2-column** layout comment: *"simple layered layout: models left, their neighbours fanned right"*
- Models: `x=40`, `y=60 + i*120`
- Non-models: `x=360`, `y=20 + i*70`
- Fixed node width 160px
- `ReactFlow` + `Background` + `Controls showInteractive={false}` + `fitView`
- **No** MiniMap, **no** expand/fullscreen, **no** dagre/elk

**CBOM** — `frontend/components/cbom/CbomCryptoCharts.tsx` `CryptoDependencyGraph` (~L743–816):

- Hand-rolled **6-column** layout by asset class:  
  `certificate → protocol → related-crypto-material → algorithm → library → other`
- Positions: `x=40 + col*210`, `y=24 + row*66`
- Same ReactFlow stack; `Controls showInteractive={false}`; **no** MiniMap / fullscreen

### 1.3 Dependency reality

| Package | Status |
|---------|--------|
| `@xyflow/react` `^12.9.3` | **Direct** product dep — keep |
| `elkjs` | **Absent** |
| `@dagrejs/dagre` / `dagre` | **Not** a direct dep |
| `dagre-d3-es` | Transitive via **mermaid** only — do **not** import into product graphs |

shadcn `Dialog` + `Sheet` already exist (`frontend/components/ui/dialog.tsx`, `sheet.tsx`). Finding-detail dialogs already use large `DialogContent` patterns in `CbomResults` / `AiBomResults` — style authority for overlays.

### 1.4 Why it looks messy (root causes, ranked)

1. **Viewport crush (primary):** `fitView` scales a multi-thousand-pixel hand layout into ~340–360px → nodes become unreadable dots; edges look like spaghetti even when few.
2. **Inventory ≠ lineage (CBOM):** 91/96 nodes (**94.8%**) are **orphans** (no edge). Tallest column = `related-crypto-material` **63** rows (~4k px). Many duplicate labels (e.g. 37× `secret-key (secret, test_api_jwt.py)`). Graph is mostly an inventory dump, not a dependency graph.
3. **Star fan-in (AIBOM):** 148 `model` nodes all `depends_on` → single hub `lib-openai` (`in_degree=148`). Left column alone is ~17k px tall; parallel edges to one target look chaotic under fitView. 26 additional orphan nodes (model_file / unused libs / cloud / secrets).
4. **No recovery UX:** Interactive pan/zoom disabled (`showInteractive={false}`), no MiniMap, no fullscreen — user cannot expand the crushed canvas.
5. **Edge crossings are secondary:** CBOM has only 4 edges (3 long-span). Classic “need ELK to untangle dense DAG crossings” is **not** the dominant CBOM failure mode.

---

## 2. Hypotheses (≥3) — evidence verdict

### H1 — Layout engine missing; fixed gaps + fitView crush the view
**Claim:** Messiness is primarily from hand-placed columns with fixed row spacing far taller than the Card, then `fitView` shrinking everything.

**Evidence:** Est. heights 4.1k / 17.7k vs viewports 360 / 340; no dagre/elk in layout code; `fitView` present on both.

**Verdict:** **SUPPORTED** (primary shared cause).

### H2 — Too many peer nodes (duplicates / orphans / star leaves) without clustering
**Claim:** Rendering every inventory asset as a first-class node overwhelms any layout; CBOM orphans + duplicate secret-key labels; AIBOM 148 models as peers into one hub.

**Evidence:** CBOM orphan 94.8%; duplicate label counts; AIBOM hub `lib-openai` in_degree 148.

**Verdict:** **SUPPORTED** (primary data-shape cause; layout alone cannot “neat” 96–175 peers in a Card).

### H3 — Edge crossings from missing dagre/elk are the main visual defect
**Claim:** Mess = crossed edges that a hierarchical layout would fix.

**Evidence:** CBOM only 4 edges / density 0.0004; AIBOM is a near-pure star (max out-degree 1), not a deep multi-path DAG.

**Verdict:** **WEAK / PARTIAL** — a dagre layer helps the **connected subgraph** and hub placement, but will not fix orphan columns or 148-leaf stars without clustering. Do not treat “add elk” as the whole fix.

### H4 (bonus) — Missing fullscreen / MiniMap / interactive controls blocks recovery
**Claim:** Even with better layout, users need a GitHub-diagram-style expand surface.

**Evidence:** No expand button; `showInteractive={false}`; Card height fixed; Dialog pattern already in results pages.

**Verdict:** **SUPPORTED** as required UX (independent of layout math).

---

## 3. Brainstorm — solution space (Phase 1)

| Option | Idea | Pros | Cons |
|--------|------|------|------|
| A | Add `@dagrejs/dagre` only; keep all nodes | Better connected layout | Orphans + stars still dense; new direct dep |
| B | Cluster-first (collapse duplicates / orphans / model-family) + compact preview | Readable Card; matches inventory reality | Need clear expand-to-detail semantics |
| C | Fullscreen Dialog overlay (shared) with MiniMap + Controls + fitView on open | GitHub-like recoverability; reuses shadcn Dialog | Needs shared component to avoid AIBOM/CBOM drift |
| D | Backend trim graph | Smaller payload | Out of scope for UX story; breaks chart contracts; reject unless user insists |
| E | Sheet side panel | Existing primitive | Less “fullscreen diagram” than Dialog; prefer Dialog |

**Recommended combo (pending confirmation):** **B + C**, with **optional A** applied to the **connected / expanded** subgraph inside the overlay (not as the sole fix).

Devil’s advocate: “Just raise Card height to 800px” fails AIBOM (still 22× overflow) and CBOM orphans. “Show all nodes always” fights the Card constraint. Backend graph rewrite is out of style-authority scope for this UX ask.

---

## 4. Implementation plan (DO NOT EXECUTE until confirmed)

### 4.1 Architecture

```
BomGraphCanvas (shared)
  ├─ layoutMode: compact | expanded
  ├─ clustering (AIBOM vs CBOM strategies)
  ├─ ReactFlow: Background, Controls, MiniMap (overlay), fitView
  └─ styling: reuse KIND_COLOR / ASSET_TYPE_COLOR / weak|qv rings

BomGraphFullscreen (shared Dialog)
  ├─ trigger: Maximize2 button on Card header
  ├─ DialogContent: ~max-w-[96vw] h-[90vh] p-0 (override sm:max-w-lg)
  └─ embeds BomGraphCanvas layoutMode=expanded

AiBomVisualizations.DependencyGraph  → thin wrapper
CbomCryptoCharts.CryptoDependencyGraph → thin wrapper
```

### 4.2 Files to change (expected)

| File | Change |
|------|--------|
| `frontend/components/bom/BomGraphCanvas.tsx` | **NEW** shared ReactFlow canvas + layout helpers |
| `frontend/components/bom/BomGraphFullscreen.tsx` | **NEW** shared Dialog overlay + header actions |
| `frontend/components/bom/layout.ts` (or `.tsx`) | **NEW** clustering + column/dagre layout pure helpers |
| `frontend/components/ai-bom/AiBomVisualizations.tsx` | Replace inline layout with shared wrappers; keep Card chrome / legend |
| `frontend/components/cbom/CbomCryptoCharts.tsx` | Same for CBOM |
| `frontend/package.json` | **Only if confirmed:** add `@dagrejs/dagre` (+ `@types` if needed) |
| Contract tests | Extend / add FE-facing expectations only if props change; prefer no aibom worker restart (pure FE) |

**Do not:** invent a new aesthetic, purple glow, new chart lib, or change `cbom_graph` / `ai_bom_graph` backend shape unless a later story requires it.

### 4.3 Layout strategy (deterministic)

**Compact Card (default):**

1. **AIBOM**
   - Cluster `model` leaves by hub target (e.g. one node `Models → openai (148)` expandable) OR by label-family prefix (`gpt-3.5*`, `gpt-4*`, …) — **confirm preference in §Questions**.
   - Keep hub libs / cloud / secrets as first-class when degree > 0.
   - Orphans: collapse into `Unlinked (N)` summary nodes by kind, or hide behind a toggle.
2. **CBOM**
   - Keep column semantics for **connected** assets (cert / protocol / material → algorithm).
   - Collapse duplicate labels within an asset_type into `Ed25519 (6)` / `secret-key… (37)` cluster nodes.
   - Orphans (no edge): default **cluster by asset_type** into summary columns, not 63 individual rows — **confirm**.
3. Cap: if after clustering still `> maxVisibleNodes` (propose **40** compact / **120** expanded), show banner + “Open fullscreen / Show all” — **confirm threshold**.

**Fullscreen / expanded:**

1. Larger canvas (`h` ≈ `calc(90vh - header)`).
2. Enable `Controls` interactive + `MiniMap` + `fitView` on open (`onInit` / `useReactFlow().fitView({ padding: 0.15 })`).
3. Optional **dagre** LR/TB on the **connected component only**; place orphan clusters in a side rail or filtered list — avoids dagre wasting space on isolates.
4. Keyboard: Esc closes Dialog (Radix default).

### 4.4 Shared fullscreen UX (GitHub-diagram-like)

- Header: title + node/edge counts + Close
- Toolbar: Fit view, Zoom ± (via Controls), optional “Clustered / All nodes” toggle
- Body: full-bleed ReactFlow (no nested Card chrome inside overlay)
- Trigger: icon button `Maximize2` on existing Card header (interaction Card stays; overlay is Dialog)

### 4.5 Explicit non-goals (this story)

- Backend normalize / emitter graph rewrite
- Changing CBOM CycloneDX refs
- New visual language / new graph library beyond xyflow (+ optional dagre)
- Worker restart (pure frontend expected)

---

## 5. Acceptance criteria — Phase 6 verify (Playwright)

Using demo user on CBOM `#94` and AIBOM `#95` results pages (or temp fixture route if auth/dev-server flaky — prefer real results once `.next` healthy):

1. Compact graph Card renders with **readable** node labels (not sub-pixel dots) for default clustered view.
2. **Expand** button opens Dialog overlay; overlay canvas height ≥ 70vh; nodes visible (`.react-flow__node` count ≥ 1).
3. Overlay: MiniMap present (if planned), Controls zoom works, Esc / close dismisses.
4. **Zero** console errors on open/close (ignore pre-existing HMR noise).
5. CBOM weak / quantum ring legend still correct; AIBOM kind colors unchanged.
6. `tsc --noEmit` clean; scoped eslint clean on touched files.
7. Legacy scans without `*_graph` still skip graph (null-safe) — no crash.

---

## 6. Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Clustering hides a real edge | Never cluster away nodes that participate in an edge; only cluster orphans / same-label peers |
| dagre adds bundle size | Optional; gate behind confirmation; tree-shake; only load in graph module |
| Dialog `sm:max-w-lg` default | Override with explicit `className` like existing finding dialogs |
| Two-writer FE drift | Shared `components/bom/*` single source |
| Contract tests count raw nodes | Keep backend graph intact; FE clustering only |

---

## 7. Questions for user confirmation (STOP)

Answer these before coding:

1. **Default compact view:** show **clustered** inventory (recommended) or attempt to show **all** nodes and rely on fullscreen + dagre?
2. **Cluster policy — CBOM:** collapse orphan / duplicate-label nodes by default? (Recommended: yes for orphans + same-label peers.)
3. **Cluster policy — AIBOM:** collapse the 148 models into (a) **one hub-leaf cluster per library**, (b) **family groups** (`gpt-4*`, …), or (c) show all models only in fullscreen?
4. **Simplify threshold:** max nodes before force-cluster / banner? Proposed **40** compact / **120** fullscreen.
5. **Shared component:** single `BomGraphCanvas` for both AIBOM + CBOM (recommended) vs keep duplicated ReactFlow shells with only shared Dialog?
6. **Add `@dagrejs/dagre` as a direct dependency?** Recommended **yes for expanded connected subgraph**; compact can stay column+cluster without dagre.
7. **Fullscreen primitive:** `Dialog` (recommended, near-fullscreen) vs `Sheet`?
8. **Scope:** frontend-only this story (recommended) — no backend graph pruning?

---

## 8. Execution order (after confirmation)

1. Lock answers to §7 into this plan (amend file).  
2. Add shared canvas + fullscreen (TDD: layout helper unit tests for cluster counts on frozen live-evidence shapes).  
3. Wire AIBOM + CBOM wrappers.  
4. Optional dagre dep.  
5. Playwright verify on `#94` / `#95`.  
6. Ruflo `memory_store` milestone `bom-graph-ux-implemented`.

**No product code until user confirms §7.**
