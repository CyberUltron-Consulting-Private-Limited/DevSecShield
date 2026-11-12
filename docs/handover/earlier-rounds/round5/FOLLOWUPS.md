# Follow-ups found while integrating (do in a cleanup package before validation)

1. Clone history depth plumbing (WP3b): engine supports `scan_history=True`; frontend/backend/worker option for repo clones
   (opt-in "scan git history for keys", deeper clone with caps) not wired. Zip uploads with `.git` already scan history.
2. `utilities/ai/llm.py` writes to a developer-laptop log path (WP9 found; same as removed one in estimate_scan.py).
3. `/send_code` returns 200 even when the email send fails (WP12 found: backend logged `Error sending email: 'TENANT_ID'`).
   Should return a clear 5xx/503 "could not send the code" without leaking config; log the cause.
4. `passlib` and `fastapi-throttle` unused after WP1 — drop from backend pyproject/uv.lock.
5. WP1: accounts whose emails differ only in case resolve to the lowest user id — decide/document; check for duplicates in data.
6. Scorer gates (round5/scorer): default settings fail EVA-12 only (vendored opt-in). Report both.
7. CI/CD scan path doesn't carry `include_vendored` (WP2).
8. AIBOM (non-CBOM) scanners still use rglob and follow symlinks (WP2) — same leak class as the CBOM one; out of CBOM scope but a
   real security issue: fix with the shared iterator.
9. WP5: `tlsprobe.connect` raises raw OSError when the host lacks IPv6 (pre-existing).
10. WP3a: advisory row bom_refs changed (one per package version); backend label tables for PROVIDER_MANAGED_KEY/EOL_BASE_IMAGE
    (`cbom_posture_text.py`, `cbom_rows.CONFIG_CODES`, roll-up severity map) — verify after WP9/WP10.
11. RabbitMQ worker `helpers/tests/langsmith_test.py` makes a live Bedrock call at import (non-CBOM, pre-existing): make it skip.
