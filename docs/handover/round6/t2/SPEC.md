# T2 — #33 reinitialize charges what a new input costs (spec)

Branch `fix/reinitialize-credits` from `origin/dev` 3399452.

## What exists today (evidence, dev 3399452)

| Path | Charges | Evidence |
|---|---|---|
| `POST /{team}/{type}/scan` (create) | nothing; a scan is created NOT_STARTED | scans.py:127 |
| `POST .../estimate_credits` | nothing; stores `credit_consumed` + `credit_estimate` {digest, formula, credits, minimum} in one conditional UPDATE while NOT_STARTED | scans.py:1009, `_store_estimate` |
| `POST .../start` | atomic claim NOT_STARTED→pending (task_id None), re-estimates when the digest/formula differs (409 `estimate_changed`, nothing charged), atomic debit, `credit_charged`, dispatch; dispatch failure refunds + releases claim | scans.py:516-692 |
| **`POST .../reinitialize`** | **nothing**: status must be `pending` (any task_id, even None), owner only, then `start_scan_and_update_db` sends a NEW task with the NEW payload and overwrites `task_id`. Old task is not withdrawn. | scans.py:944-1002 |
| cancel | CAS running→cancelled + refund `credit_charged` (else `credit_consumed`) in one tx | cancel_scan.py |
| failure poll | CAS →failure, refund `credit_charged` once (separate session) | celery_connection.py:160-195 |
| DAST profile Run now / schedule / Jenkins | new Scan per run, `credits_for_auto_dast(max_urls)`, SSRF rule, in-flight guard; `credit_consumed` = charge (no `credit_charged`) | dast/dispatch.py |
| CI/CD | estimate + debit per run, refund on dispatch failure | cicd.py:179+ |
| CBOM Sources runs | per job, `connection_version` (targets included) invalidates a job whose source changed after charging | cbom_sources/jobs.py:258, :476 |
| Frontend "Run again" | creates a NEW scan (POST /scan) and pre-fills the form; estimate + /start charge it | components/scan-run-again.tsx, utils/scanRerun.ts |
| Frontend "Reinitialize Scan" | shown on every product while `scan_status == "pending"`; sends the CURRENT form (may differ from what was paid) | 8 `*-options-sidebar.tsx`, backend_api.ts |

* **No credits ledger table exists** (`grep -ri ledger backend` → only CERT-In text; $R6/f1/CONTRACT.md: "Credits ledger. No ledger table."). Balance is `team.credit_balance`; per scan `credit_charged`.
* Target checks of a new scan: git host allow-list = pydantic validators on `StartScanPayload` (schemas.py → git_hosts.check_repo_url); DAST address rule, 50 MB limit, zip validity = `format_input_for_scan` (called by both the estimator and the dispatcher). **MCP and custom-LLM URLs have no check for new scans either** (schemas.py `StartMCPScanData` only non-empty; worker mcp_client has no address rule) → follow-up issue, not this PR (would change new-scan behaviour).
* Reinitialize today already runs pydantic + `format_input_for_scan` (inside `start_scan_and_update_db`), so blocked DAST/git targets ARE refused today; the gap is billing + concurrency + the replaced task.

## Gaps found (root causes)

1. **Billing**: reinitialize never prices the new input → pay for a tiny target, reinitialize with a huge one for free (#33).
2. **Duplicate free runs**: the replaced task is never withdrawn → N reinitializes of the same input = N worker runs for one charge (rate limit 10/min only).
3. **Reinitialize during /start**: allowed when `task_id` is None (a /start mid-claim, which can last ~10 min while it re-estimates) → a second, unpaid dispatch.
4. **Reinitialize of a scan the worker already started/finished** (DB still says pending until a poll) → old run's work thrown away, new run started.
5. **Stale polls**: `get_status_and_update_db` transitions are conditional on status only, not on the task polled. `update_status_of_scan_in_main_db` runs as a background task with (scan_id, task_id) captured at list time, so a poll of the REPLACED task can store its success (old target's results on a scan that paid for the new one) or its failure (refund), or write `revoked`.
6. `start_scan_and_update_db`: an exception after `send_task` (DB error storing the task) leaves the sent task running unpaid (caller refunds).

## Design (binding decision from the coordinator, plus the hardening above)

`POST /{team}/{type}/scan/{id}/reinitialize`:
1. Parse `StartScanPayload` (422, git host allow-list). Team member (403). Scan of this team+type (404). Owner (400, unchanged).
2. State: `pending` (400, unchanged) **and dispatched** (`task_id` set; else 409 `starting`). Sync with the worker (`get_status_and_update_db`, as /start does); unless the worker still reports PENDING → 409 `already_started`.
3. Price the new input: `input_digest(type, section, file)`; same digest as the stored estimate → price = stored `credits` (no worker round trip; the formula version is ignored: same input never costs more). Otherwise `estimate_credits` (same estimator + `priced` minimum as a new scan; it runs `format_input_for_scan`, so target checks refuse before anything is charged).
4. `paid = refunded_credits(scan)` (credit_charged, else credit_consumed — exactly what a cancel/failure gives back). `difference = round(max(0, price - paid), 2)`. Never refunded on a smaller input.
5. Balance pre-check → **402** `insufficient_credits` with price/paid/difference/balance; nothing charged or queued.
6. `format_input_for_scan` (same target checks and upload as a new scan's dispatch) BEFORE the charge, always (also when the estimate was skipped).
7. **One transaction**: CAS `scan` (id, team, type, status pending, task_id == old) → task_id = claim token `reinit-<uuid>`, credit_charged = paid + difference, credit_consumed = same, credit_estimate = new digest (only when re-estimated); conditional team debit (`balance >= difference`); ledger row. CAS lost → 409 `reinitialize_conflict`; debit refused → 402. Nothing charged in either case (rollback).
8. Dispatch with the prebuilt kwargs; the store is conditional on task_id == claim token and status pending. Failure → one transaction: CAS back to the old task + refund the difference + ledger row (only if the row is still ours; a cancel that won already refunded everything). New task withdrawn.
9. Success → withdraw the replaced task (`tell_workers`: revoke + mark, as cancel does).
10. Response adds `credits_charged`, `credits_total`, `credits_required`.

Poller (`get_status_and_update_db`): every transition also requires `task_id == <task polled>`; a poll of a replaced task changes nothing and reports the stored row.

Ledger: new append-only table `creditledger` (id, team_id, scan_id, user_id, delta, balance_after, reason, detail JSON, created_at), no FKs (outlives scan/team deletion). Written in the SAME transaction as the balance change. This PR writes `scan_reinitialize_charge` and `scan_reinitialize_refund`; routing every other movement through it is a follow-up issue. Alembic migration chained on `rv6p1nodename001` (re-chain before merge).

## Risks
* Concurrency (two reinitializes, reinitialize vs cancel, vs stale failure/success poll): covered by the CAS on task_id + one-transaction debit; proved on SQLite with deterministic interleavings and on real PostgreSQL with threads.
* Long request: re-estimation can take minutes (same as /start re-estimate); the claim happens after it, so no lock is held meanwhile.
* Migration head conflicts with F3/F4 (both chain on rv6p1nodename001): re-chain at merge time.
* Frontend shows "scan restarted" only; the charged difference is in the response. Follow-up (after #30 lands): toast names the extra charge and refreshes the balance.

## Acceptance criteria → proof
| Criterion | Test (backend/tests/test_scan_reinitialize_credits.py unless noted) |
|---|---|
| bigger input charges the difference (ledger row) | test_a_bigger_input_charges_the_difference_once_and_records_it |
| same input charges 0 | test_the_same_input_charges_nothing_and_replaces_the_queued_run |
| smaller input never refunded | test_a_smaller_input_is_charged_nothing_and_never_refunded |
| insufficient balance refused, nothing queued | test_too_small_a_balance_is_refused_with_402_and_nothing_is_queued |
| blocked target refused (DAST private/metadata, git host) | test_a_blocked_dast_target_is_refused_before_anything_is_charged, test_a_disallowed_git_host_is_refused |
| concurrency: one charge per difference, no negative balance | test_two_reinitializes_at_once_charge_the_difference_once (deterministic) + test_reinitialize_race_postgres.py (threads, real PostgreSQL) |
| cancel / failure refunds still behave | test_cancel_after_a_top_up_refunds_everything_once, test_failure_after_a_top_up_refunds_everything_once, test_a_reinitialize_racing_a_cancel_ends_cancelled_and_refunded_once |
| stale polls of the replaced task | test_a_poll_of_the_replaced_task_changes_nothing |
| reinitialize during /start or after the worker started | test_reinitialize_waits_for_dispatch, test_reinitialize_is_refused_once_the_worker_started |
| Run again is charged | test_run_again_is_a_new_scan_charged_at_start |
