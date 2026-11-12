# Shadow AI list — overflow + hover detail (diagnosis + plan)

> **Status:** DIAGNOSIS + PLAN ONLY — do not implement until user confirms.
> **Date:** 2026-08-09
> **Style authority:** `frontend/components/ai-bom/AiBomVisualizations.tsx` + existing shadcn Card/Badge/Tooltip/HoverCard; peer truncate pattern in `CbomCryptoCharts.tsx` (migration list).
> **Evidence:** screenshot `assets/image-fe693b24-4747-4e58-8155-db64525cc61e.png`; live AIBOM scan **#95** (team 1, `cbom-demo@cyberultron.com`).

---

## Goal

1. Stop long Shadow AI asset names (esp. 64-char hash `.bin` filenames) from pushing impact badges outside the card.
2. On hover, surface enough detail to understand **why**, **description**, **how to fix**, **exact location**, and **related transparency** — without inventing a new aesthetic.

---

## Brainstorm — 3 architectural hypotheses (pre-fix)

| # | Hypothesis | Likelihood |
|---|------------|------------|
| H1 | Flex row lacks `min-w-0` / `truncate` / `shrink-0`, so unbreakable hash names force the badge past the card edge. | **Confirmed** (code + screenshot) |
| H2 | Hover can be pure-frontend: findings already carry `description`, `suggested_fix`, `location`, `risk_category`, compliance/OWASP. | **Mostly true** for credentials; **thin** for `.bin` inventory rows |
| H3 | Best UX is click-to-open the existing `AiBomResults` finding dialog (already has full detail). | Viable alternative; hover alone is what user asked for |

---

## Component location

| Item | Path |
|------|------|
| Shadow AI panel | `frontend/components/ai-bom/AiBomVisualizations.tsx` → `export function ShadowAI` (~L257–305) |
| Wired from | `AiBomResults.tsx` → `<AiBomVisualizations findings={findingsList} …>` |
| Filter | `risk_category` contains `missing_model_card_lineage` **OR** `asset_type === "external_provider"` |
| Cap | `shadow.slice(0, 8)` — only first 8 of N (scan #95: **46** shadow / **12** `.bin`) |

---

## Root cause — overflow (CSS)

### Current markup (broken)

```tsx
<li className="flex items-center justify-between rounded-lg border … px-3 py-2">
  <div>
    <div className="text-sm font-medium …">
      {String(f.asset_name ?? f.title ?? "—")}
    </div>
    <div className="text-xs text-zinc-500">
      {asset_type}{provider ? ` · ${provider}` : ""}
    </div>
  </div>
  <Badge …>{impact}</Badge>
</li>
```

### Why badges escape the card

1. Flex item default `min-width: auto` — the text column will not shrink below the intrinsic width of the hash string.
2. No `truncate` / `overflow-hidden` / `text-overflow: ellipsis` on the name.
3. Text column has no `min-w-0` and no `flex-1`.
4. Badge has no `shrink-0` (secondary; main issue is the text column refusing to shrink).
5. Hash `.bin` names are single tokens with no spaces — they cannot wrap; they must truncate or overflow.

### Screenshot evidence

- Short names (`generic_credential`) — badges stay inside the amber card.
- Long names (`173417d55…5353.bin`) — **Low** badges sit outside the panel boundary.

### Style-authority fix pattern (already in CBOM)

`CbomCryptoCharts.tsx` migration list uses the correct flex truncate recipe:

- text column: `min-w-0` (+ optional `flex-1`)
- name/descriptor: `truncate`
- badges: `shrink-0`
- row: `gap-3` (or `gap-2`)

`AiBomResults` findings table already truncates asset names with `max-w-[180px] truncate` + `title={…}`.

**Confidence:** High (code inspection + live UI screenshot + known flex gotcha).

---

## Data fields available for hover (live AIBOM #95)

Frontend type: `AiBomFinding` in `frontend/utils/backend_api.ts`.

Backend projection (`backend/utilities/db/findings.py` ai_bom branch) maps worker `finding_data` →:

| Field | Role for hover | Fill rate on #95 shadow (n=46) | Notes |
|-------|----------------|--------------------------------|-------|
| `asset_name` / `title` | Identity | 46/46 | Name shown in list |
| `asset_type` | Type line | 46/46 | e.g. `external_provider` |
| `provider` | Type line | 46/46 | e.g. `openai`, `local` |
| `impact` | Badge | 46/46 | Critical / Low … |
| `description` | **Why / description** | 46/46 | Credential rows: concrete secret message; `.bin`: generic *"Inventoried AI component (model_file)."* |
| `suggested_fix` | **How to fix** | 46/46 | Often `_DEFAULT_FIX`: *"Review this AI/ML component and bring it under AI governance."* |
| `location` | **Exact location** | **6/46** | Present on credential paths; **empty for all 12 `.bin` rows** |
| `snippet` | Code context | **0/46** | Empty on this scan |
| `risk_category` | Governance bucket / why | 46/46 | e.g. `model_theft_exposure`, `missing_model_card_lineage` |
| `compliance_controls` | **Related transparency** | 3/46 | ISO42001 / NIST maps when flagged |
| `owasp_top_10_llm` | **Related transparency** | 10/46 | e.g. LLM02 |
| `license_type` | Transparency | 46/46 | e.g. `LicenseRef-not-declared` |
| `remediation` | Ticketing/status | **0/46** | User-driven; not inventory text |
| `framework` / `version` | Extra | sparse | Usually null for shadow rows |

### `.bin` honesty gap (not a CSS bug)

Live #95 BOM components for hash `.bin` files carry only `model:weight_file=true` — **no** `discovery:source` / path. Adapter sets:

```text
location = props["discovery:source"] || props["discovery:host"] || ""
```

So hover **cannot** invent a file path for those rows without a separate scanner/enrichment story. UI should show **"—"** / *"Location not recorded"* when empty, not fabricate.

Credential rows **do** have useful `description` + `location` (e.g. `src/openai/_client.py`).

---

## Proposed UI (no new aesthetic)

### A. Overflow fix (required, mechanical)

In `ShadowAI` list item only:

1. Row: keep `flex items-center justify-between`, add `gap-2` (or `gap-3`).
2. Text column: `min-w-0 flex-1`.
3. Name: `truncate` (optional `title={fullName}` as progressive enhancement).
4. Subline: `truncate` for long type·provider.
5. Badge: `shrink-0`.

Mirror CBOM migration-list classes; do **not** change colors/borders/card chrome.

### B. Hover detail (prefer existing shadcn)

**Recommendation: `HoverCard`** (`@/components/ui/hover-card`) over `Tooltip` or native `title`.

| Option | Pros | Cons |
|--------|------|------|
| **HoverCard** (preferred) | Multi-section content; already in repo; readable for why/how/location | Slightly more markup; need open-delay for dense lists |
| Tooltip | Already used (`GuardrailsDashboardData`, sidebar) | Designed for short strings; multi-paragraph is cramped / a11y-awkward |
| Native `title=` | Zero deps | Truncate-only; cannot structure why/how/location |
| Click → existing Dialog | Full detail already in `AiBomResults` | Needs optional `onSelectFinding` callback; not “hover” |

**HoverCard content sections** (labels match findings dialog tone):

| Section label | Source field(s) | Fallback |
|---------------|-----------------|----------|
| Why | `risk_category` (humanize `_` → spaces) + optional impact | "Ungoverned / third-party AI surface" |
| Description | `description` | "—" |
| How to fix | `suggested_fix` | "—" |
| Location | `location` (+ `snippet` if non-empty, mono/pre) | "Location not recorded" |
| Transparency | `compliance_controls` entries; `owasp_top_10_llm` keys/labels; `license_type` | Omit empty groups |

Layout: compact `w-80` / `max-w-sm` panel, `text-xs`/`text-sm`, zinc/amber tokens already on the card — no new palette.

**Optional:** "View full finding" control only if parent passes `onOpenFinding(f)` — out of minimal scope unless user wants click path.

### C. Truncation style for hash filenames

| Option | Behavior |
|--------|----------|
| **End truncate (CSS `truncate`)** — default recommend | `173417d553406f034f…` keeps prefix; matches AiBom table + CBOM |
| Middle truncate | `173417d5…455c5353.bin` keeps extension; needs small helper (none exists in FE today) |

Recommend **end truncate** unless user prefers middle for `.bin` hashes.

---

## Out of scope (call out, do not silently expand)

- Enriching `discovery:source` on `model_file` scanners (backend/`aibom`) so `.bin` rows get real paths.
- Raising `shadow.slice(0, 8)` cap / “show more”.
- Changing Shadow AI filter semantics or severity badge colors.
- New chart library or redesign.

---

## Implementation plan (after confirmation only)

1. CSS truncate + flex fix on `ShadowAI` `<li>` (peer CBOM classes).
2. Wrap each row (or name column) in `HoverCard` / `HoverCardTrigger` / `HoverCardContent`.
3. Render the five sections from existing finding fields; empty → honest fallbacks.
4. No worker/backend changes in the UI story.
5. Verify: `tsc --noEmit`; scoped eslint on touched file; Playwright (or global-playwright `.cjs`) on AIBOM #95 results — assert badge within card bounding box for a long `.bin` name + hover content visible.

---

## Acceptance criteria

1. Long `.bin` / hash asset names **never** push the impact badge outside the Shadow AI card or parent column.
2. Name shows ellipsis; full name still available (HoverCard title and/or `title` attr).
3. Hovering a row shows Why, Description, How to fix, Location, Transparency (omit empty transparency groups).
4. Empty `location` / thin inventory description shows explicit fallback text — no invented paths.
5. Visual language unchanged (amber border/badge, Card chrome, shadcn).
6. `npx tsc --noEmit` (frontend) exit 0 for the change.
7. Playwright/headless: on `/1/ai_bom/95/results` (or equivalent), Shadow AI Low badges for `.bin` rows have `getBoundingClientRect()` fully inside the list card; hover reveals Description + How to fix text.

---

## Verification recipe

```bash
# typecheck
cd frontend && npx tsc --noEmit

# optional: scoped lint
npx eslint components/ai-bom/AiBomVisualizations.tsx

# live: auth as cbom-demo, open AIBOM #95 results, screenshot Shadow AI,
# assert badge inside card for hash .bin rows + HoverCard sections on hover
```

Use existing DEV-BROWSER auth notes (JWT `sub` = email string; `session_active=True`).

---

## Confirmation questions (parent / user)

1. **Hover surface:** Prefer **HoverCard** (recommended), **Tooltip**, or **click-to-open** the existing finding detail dialog (with optional hover as secondary)?
2. **Hash filenames:** **End truncate** (CSS default, matches table/CBOM) or **middle truncate** keeping `.bin` suffix?
3. **Empty location on `.bin`:** UI-only honesty ("Location not recorded") now, or expand scope to a follow-up scanner story that stamps `discovery:source`?
4. **Show more:** Keep `slice(0, 8)` or add "Show all N" in the same story?
5. **View full finding:** Should HoverCard include a control that selects the finding in the table/dialog (`onOpenFinding`), or hover-only?

---

## Devil's advocate / risks

- HoverCard on every row in a dense list can feel sticky — use modest `openDelay` (~200–300ms).
- Touch devices: hover is weak; click-to-dialog is the durable a11y path if we add it later.
- Filling HoverCard with only `_DEFAULT_FIX` + generic description for `.bin` may disappoint — set expectations: overflow is guaranteed; rich hover is **data-dependent**.
- Do not map `remediation` (ticketing object) into "how to fix" — that is workflow state, not guidance text.

---

## Evidence appendix — live #95 samples

**Credential (rich hover):**

- name: `generic_credential`
- description: hardcoded secret message with path
- location: e.g. `src/openai/_client.py`
- risk: `model_theft_exposure` / Critical
- transparency: ISO42001_2, NIST80053_AC, LLM02

**`.bin` (thin hover):**

- name: `173417d553406f034f643e5db3f8d591fb691ebac56f5ae39a22cc7d455c5353.bin`
- description: `Inventoried AI component (model_file).`
- location: `""`
- suggested_fix: default governance review string
- risk: `missing_model_card_lineage` / Low
- compliance/OWASP: empty
