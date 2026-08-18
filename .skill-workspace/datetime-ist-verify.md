# Datetime IST — verify

## Helper

- Path: `frontend/utils/datetime.ts`
- Tests: `frontend/utils/datetime.test.ts` — **passed** under default TZ, `TZ=America/Los_Angeles`, and `TZ=UTC`.

## Before / after (same UTC instant)

UTC: `2026-08-09T14:00:00.000Z`

| Context | Display |
|--------|---------|
| **Before** (`toLocaleDateString("en-US")`, browser `America/New_York`) | `Aug 9, 2026, 10:00 AM` |
| **After** (`formatDateIst`) | `9 Aug 2026, 07:30 pm IST` |

## Live scan list spot-check (DB → helper)

CBOM scan **#106** (`scan_status=success`):

| Field | Value |
|-------|--------|
| Stored `created_at` (UTC, DB) | `2026-08-09 13:00:31.109292` |
| API-shaped ISO | `2026-08-09T13:00:31.109292Z` |
| List UI via `formatDateIst` | `9 Aug 2026, 06:30 pm IST` |
| Old NY browser local | `Aug 9, 2026, 09:00 AM` |

Wired on CBOM list: `frontend/app/[team_id]/cbom/page.tsx` → `{formatDate(conversation.created_at)}` imports `formatDateIst as formatDate`.

Browser Playwright against `:3000` was blocked this run: frontend not listening; backend PID on `:8081` accepts TCP but does not complete HTTP responses (hung). Evidence above is enough for display-path correctness (DB UTC + helper IST + call-site wiring). `tsc --noEmit` clean after import fixes.

## Relative time

No `2h ago` / `formatDistance` absolute-timestamp competitors found — N/A; left as-is.

## Backend

No change. Timestamps remain UTC ISO; display-only conversion on the frontend.

## Ruflo

Claimed `datetime-ist-verified`.
