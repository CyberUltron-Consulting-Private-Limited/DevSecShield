# Implementation Plan — CBOM Frontend Consistency Refactor

## Goal
Make the CBOM frontend (results page = table + overview/dashboard, and the scan-list/overview page)
structurally and visually consistent with the canonical scan pattern, using **SBOM/SCA** as the reference.

## Confirmed decisions
1. Reference template: **SBOM/SCA** (`SbomResults.tsx`, `app/[team_id]/sbom_sca/**`).
2. Theme: **convert** CBOM's hardcoded pure-dark (`bg-zinc-900`/`text-white`) to the canonical light+dark theme (`dark:` prefixes).
3. Domain data: **keep** CBOM crypto-specific columns/charts (algorithm, strength, quantum-safe, algorithm-type / crypto-strength / quantum-readiness charts) but render them in the canonical layout/structure/styling.
4. Extra fixes: **all** — add missing `[scan_id]/layout.tsx`, conditional routing to `/results`, metadata dialog, list risk-score filter + clear-filters.

## Root cause
`CbomResults.tsx` and `cbom/page.tsx` were authored as a standalone dark-theme/custom-layout variant
instead of following the shared skeleton SAST/SBOM/IAC/DAST use. No backend changes needed — the CBOM
list/detail APIs already return every field the canonical UI requires.

## Constraints
- All changes LOCAL only on branch `ansh`. No git push / merge / PR (skill rule).
- No backend changes. Frontend-only.
- Preserve all existing CBOM functionality (CycloneDX JSON export, quantum filters, RemediationPanel, Jira ticketing, bulk status).

---

## Fix Group 1 — Scan-list / overview page: `app/[team_id]/cbom/page.tsx`
Match `app/[team_id]/sbom_sca/page.tsx`.
- Page wrapper: `flex h-screen` (was `ScrollArea h-screen`).
- Tabs: rename "All Scans" → "Table"; use canonical `<Tabs>` styling.
- Theme: convert hardcoded dark → light/dark canonical throughout (colored-icon cards, etc.).
- `CBOMScanListDashboard`: restyle aggregate cards (colored icon boxes), chart cards (canonical `Card`/`CardHeader`/empty-states); keep crypto charts (severity radar, algorithm-type bar, crypto-strength bar, quantum-readiness bar, top-risks table) + canonical 4-bar remediation card.
- Table: expand to canonical columns — Title / Created at / Last updated / Scan status (+progress bar) / Risks (C/H/M/L colored dots + QV badge) / Risk score / Repo / Branch / Credits / Owner (avatar) / Actions. Wrap in `ScrollArea` + horizontal `ScrollBar`.
- Filter bar: add colored risk-score filter dropdown + Clear-filters button (match SBOM); keep search + status + sort.
- Status: canonical `getStatusBadge` (badge + in-progress progress bar); dates via `lib/datetime_parser`.
- Row nav: success → `/[team_id]/cbom/[scan_id]/results`, else → `/[team_id]/cbom/[scan_id]`.
- Dialogs: add **Metadata** dialog (4th) alongside Create/Rename/Delete; Actions menu = View results (success) / View metadata / Rename / Delete.
- Verify: `getCBOMScans` already returns all required fields (confirmed).

## Fix Group 2 — Results component: `components/CbomResults.tsx`
Match `components/SbomResults.tsx`.
- Root wrapper: `min-h-screen ...` + `container mx-auto p-6 space-y-6` (was `ScrollArea h-screen` / `max-w-7xl`).
- Header: canonical title bar (light/dark); keep CBOM export buttons (CycloneDX JSON + PDF + Chat) restyled.
- Tabs: icon+text — "Results" (`BarChart3`) / "Ticketing integrations" (`Ticket`) — canonical styling/labels.
- Scan metadata: canonical colored-icon card grid before dashboard; keep CBOM-specific fields.
- Dashboard: convert every chart card to canonical `Card border-zinc-200 dark:border-zinc-800` + `CardHeader`/`CardTitle`/`CardDescription` + canonical "No data" empty states; keep all CBOM charts + remediation KPIs.
- Summary cards: canonical colored-icon style; keep 7 crypto cards.
- Findings table: canonical structure (`ScrollArea h-[500px]` border, `min-w-max`, canonical `TableHead min-w-[..]`, checkbox col, canonical search `Input` + Impact `Select` + risk-score `DropdownMenu`); KEEP crypto columns (Algorithm, Type, Strength, Quantum, Key Size) + canonical Impact/Risk/Status/Location/OWASP/Compliance/Actions; keep strength/type/quantum filters restyled; Actions dropdown canonical style.
- Finding detail / RemediationPanel: align opening pattern + dialog styling to canonical.
- Align `getImpactBadgeClass` / `getFindingStatusBadgeClass` to canonical implementations.

## Fix Group 3 — Add `app/[team_id]/cbom/[scan_id]/layout.tsx`
Passthrough layout identical to `sbom_sca/[scan_id]/layout.tsx`.

## Fix Group 4 — Verify (Phase 6)
- Typecheck/build: `cd frontend && npm run build` (or `npx tsc --noEmit` / `next lint`) — zero new errors.
- Run dev server; Playwright the CBOM list page, results page (Dashboard + Table tabs, light & dark), compare side-by-side with SBOM for structural parity.
- Confirm preserved behavior: CycloneDX JSON export, quantum/strength/type filters, status toggle, bulk status, Jira ticketing, RemediationPanel, conditional routing, metadata dialog.

## Risk / rollback
- Risk: large rewrites of 2 big files; mitigated by using canonical files as scaffold + build/typecheck + live verify.
- Rollback: `git checkout -- frontend/components/CbomResults.tsx frontend/app/[team_id]/cbom/...` (all local, uncommitted or on branch `ansh`).
