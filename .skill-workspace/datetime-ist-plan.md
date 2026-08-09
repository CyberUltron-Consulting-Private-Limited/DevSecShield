# Datetime IST display — plan

## Discovery

- **No shared date helper** today; each scanner list page defines a local `formatDate` via `toLocaleDateString("en-US", …)` (browser TZ).
- Surfaces: SAST/IAC/SBOM/CBOM/AI BOM/DAST/LLM/MCP/leakage/CI-CD tables; team dashboard chart axis labels; home team-created; Guardrails charts; `chart-area-interactive`.
- Backend stores/emits **UTC** ISO (`timezone.utc`); no pre-formatted local strings for UI.
- No dayjs/moment/date-fns. No relative “2h ago” absolute-timestamp competitors found.
- Attestation UI shows filenames, not absolute timestamps.

## Hypotheses (brainstorm)

1. **Central `Intl` helper + `timeZone: Asia/Kolkata`** — recommended; zero deps; display-only.
2. Add dayjs+timezone plugin — unnecessary dependency.
3. Backend reformat to IST strings — violates “keep API UTC”; reject.

## Approach

1. Add `frontend/utils/datetime.ts`: `DISPLAY_TIMEZONE`, `parseDisplayDate`, `formatDateIst` (datetime + ` IST`), `formatDateOnlyIst`, `formatChartDateIst`.
2. Replace local `formatDate` / inline `toLocaleDateString` display call sites with the helper (sort/compare `new Date(...).getTime()` unchanged).
3. Hermetic tests (`datetime.test.ts`) for UTC→IST, date-only, invalid input.
4. Live spot-check one CBOM/SAST list timestamp; write `datetime-ist-verify.md`.
5. Ruflo claim `datetime-ist-verified`. No git push.

## Out of scope

- DB/API timestamp storage changes
- Relative time strings (none found; note if any appear later)
- PDF export timestamps (server-side reportlab) unless they already mirror UI helper

## Confidence

High — pattern is mechanical and isolated to display formatting.
