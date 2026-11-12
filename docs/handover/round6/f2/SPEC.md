# F2: (i) info tooltips — spec

Owner's words: "small i button on which you hover then it shows details what it is and like that with example or a
popup something that gives info".

## Design

### Component: `frontend/components/ui/info-tip.tsx`
- Built on the existing shadcn `components/ui/tooltip.tsx` (Radix `@radix-ui/react-tooltip` 1.2.8, already a
  dependency; no package.json change). Radix Popover is not installed, so the tooltip is used as a *toggletip*:
  - **hover** (mouse): opens after 150 ms (Radix pointermove; touch pointers are ignored by Radix);
  - **keyboard focus**: Radix opens on focus; **Esc** closes (Radix DismissableLayer); blur closes;
  - **tap** (touch/pen): Radix never opens on touch and closes on click, so the component is *controlled*: it records
    `open` and `pointerType` at pointerdown and, on click, calls `preventDefault()` (skips Radix's close) and toggles.
    A tap outside closes (DismissableLayer `onPointerDownOutside`). Mouse click keeps it open; Enter/Space toggles.
- Trigger: a real `<button type="button">` with a 14 px lucide `Info` icon, a 24×24 hit area, visible focus ring,
  `aria-label="About <label>"`; Radix sets `aria-describedby` to a visually hidden `role="tooltip"` copy of the
  content while open, so screen readers read the description.
- Content: "what it is", then "Example: …", optional "Learn more" link. `max-w-xs` (320 px) and never wider than the
  viewport minus 2 rem; collision padding 12 px; left-aligned text.
- Never placed inside a `<label>` (a button inside a label would be added to the input's accessible name):
  `FieldLabel` renders `<Label>` and the tip side by side.

### Registry: `frontend/content/infotips.ts`
```ts
export interface InfoTipEntry { label: string; what: string; example: string; learnMore?: { href: string; label?: string } }
export const INFO_TIPS = { "sast.new.title": { ... }, ... } as const satisfies Record<string, InfoTipEntry>;
export type InfoTipId = keyof typeof INFO_TIPS;
```
- Ids are stable, dotted: `<surface>.<area>.<field>` (`sast.kpi.pending`, `scan.table.credits`, `cbom.src.server.port`).
  Ids shared by several products are used only where the backend code path is the same (e.g. the shared list
  endpoint `utilities/dashboard/scan_list.py`).
- Every entry is preceded by `// src: <repo-relative path>:<line>[, <path>:<line>] — <what was verified>`.
  Anything that could not be verified is left out (no tip text about it) and listed in the PR.

### Enforcement (two layers)
1. **TypeScript:** `InfoTip.id`, `FieldLabel.infoId` and the `infoId` of the CBOM Sources building blocks
   (`Field`, `SecretField`, `StatCard`, `ChoiceCards`, `Checkbox2`) are *required* and typed `InfoTipId`, so an
   unknown id or a missing prop fails `tsc --noEmit`.
2. **`frontend/content/infotips.test.ts`** (run by CI's `*.test.ts` step):
   - registry integrity: every entry has label/what/example within length limits, ends with punctuation, no TODO;
     every entry has a `// src:` note whose file exists and whose line is within the file;
   - every id used in source (`infoId="…"`, `infoId: "…"`, `<InfoTip id="…"`) exists; every entry is used (no dead
     text);
   - **coverage** over the covered files (globs, so new files are covered automatically):
     - `<Label` (ui/label) is not used directly: `FieldLabel` (required `infoId`) instead;
     - every control (`<Input`, `<Textarea`, `<SelectTrigger`, `<Switch`, `<Checkbox`, `<input`, `<PathArraysInput`,
       `<NodeSelect`) has an info marker (`infoId=` or `<InfoTip`) between it and the previous control, unless an
       explicit `infotip-shared: <reason>` comment says it shares the previous tip;
     - every `<CardTitle>`, `<TableHead>` with text (except a short list of self-explanatory headers: Actions, Title,
       Name), dashboard `<h2>`/`<h3>`, and KPI tile label (`<p className="text-xs font-medium …">`) contains an
       `<InfoTip`.
   - a negative self-test: the scanner run on a fixture string with an unlabelled control reports it.

## Coverage (files)
- Eight products: list page (`app/[team_id]/<p>/page.tsx`: KPI tiles, charts, filters, table headers, New Scan
  dialog) and scan configuration (`components/<p>-options-sidebar.tsx` and its parts: `repository-card.tsx`,
  `path-arrays-input.tsx`, `sast-scan-settings-form.tsx`, `cbom-ci-scan-settings-form.tsx`) for SAST, SCA+SBOM,
  CBOM, AI BOM, MCP, LLM, IaC, DAST.
- CBOM Sources and Nodes: `app/[team_id]/cbom/sources/page.tsx`, `components/cbom/sources/*.tsx`.
- Dashboards: `app/[team_id]/page.tsx`.
- Settings: `app/[team_id]/settings/page.tsx` (team, members), `components/integrations/IntegrationsPage.tsx`,
  `components/ticketing-integrations-settings.tsx`.
- Account: `app/[team_id]/account/page.tsx`. Admin: `app/admin/page.tsx`.
- Out of scope: results pages, deprecated Guardrails/Leakage (`components/Settings.tsx` is deprecated Guardrails).

## PR split
1. PR 1: component, registry, coverage test, SAST and SCA+SBOM (list page + scan configuration), shared scan ids.
2. PR 2: the remaining six products, CBOM Sources/Nodes, dashboards, Settings, Account, Admin.

## Risks
- Wrong content is worse than none: each tip is checked against backend code; unverifiable facts are omitted.
- Layout: an (i) inside dense table headers and KPI tiles; checked by screenshot at 1440 and 390 px.
- Tooltip inside scroll containers closes on scroll (Radix) — acceptable.
- Merge conflicts with other tracks touching the same pages (F1.x touches CBOM Sources): keep edits additive.

## How each criterion is proven
| Criterion | Proof |
|---|---|
| `<InfoTip>` hover/focus/tap, Esc, mobile, SR label | `components/ui/info-tip.test.ts` (logic of the toggle state machine) + Playwright script `e2e/infotip.spec`-style run against the stack: hover, Tab+Esc, `tap()` at 390×844, `aria-label`/`aria-describedby` asserted; screenshots |
| what + example, one registry | `content/infotips.test.ts` registry integrity |
| every field has a tip; test fails when one is missing | `content/infotips.test.ts` coverage + its negative self-test; tsc required props |
| content accurate | `// src:` note per entry, verified file/line by the test; reviewer checks |
| browser QA desktop + 390×844, axe 0 serious | separate QA agent; my quick screenshots under `flock stack.lock` |
