# F3: code repositories at scale (spec)

Owner's problem: thousands of code repositories must be scannable without adding them one by one.
Branch: `feat/f3-repos-at-scale` from `origin/dev` 3399452. Two PRs: (1) backend + bench, (2) frontend (stacked on 1).

## What exists today (evidence, `dev` 3399452)

| Area | Today | Where |
|---|---|---|
| How a scan gets a repo | per scan: zip upload, or `repo_context {mode github/gitlab/bitbucket, repo_url, PAT, branch}`; the URL is checked against github.com / gitlab.com / bitbucket.org or `GIT_ALLOWED_HOSTS` in both backend and worker (byte-identical `git_hosts.py`) | `backend/utilities/db/schemas.py:61-109`, `backend/utilities/git_hosts.py`, `RabbitMQ/worker/helpers/context/scan_context.py:87-143` |
| Clone credentials | GitHub: token as URL user; GitLab: `oauth2:<token>`; Bitbucket: `x-token-auth:<token>` | `scan_context.py:107,123,139` |
| Org-level SCM | none: no GitHub App, no GitLab group, no inbound webhook, no org listing | grep; research C.5 |
| Flow | create -> estimate (worker clones the repo to measure) -> start (owner only, atomic NOT_STARTED->pending claim, deduct, `send_task`) | `backend/routers/scans.py:127-692` |
| Queues | Celery over RabbitMQ: `scan_worker_queue` (sast/iac/sbom_sca/cbom/ai_bom), prefetch 1; no concurrency bound or fairness on our side: every start goes straight to the broker | `backend/utilities/scan/start_scan.py` |
| Completion | pulled, not pushed: `get_status_and_update_db` reads the Celery state on poll, stores results, ingests findings into Mongo, refunds `credit_charged` on failure (compare-and-set, once) | `backend/utilities/celery/celery_connection.py` |
| Credits | atomic `UPDATE team SET credit_balance = credit_balance - x WHERE credit_balance >= x`; worker formulas: 1 credit per 0.5 MB of source (+0.0478 for sast/ai_bom), sbom_sca flat 0.0120, cbom min 1 | `backend/utilities/team/credits.py`, `RabbitMQ/worker/helpers/tools/*/main.py` |
| Programmatic scans | DAST auto: Scan row -> claim -> deduct formula price -> send_task, refund on dispatch failure | `backend/utilities/dast/dispatch.py` |
| Schedulers | loop processes with `--once`, also started as threads from the cloud worker; slots fire once (CAS) | `backend/workers/cbom_scheduler.py`, `backend/utilities/dast/beat.py` |
| Roll-up per team | CBOM only (`cbom_team_rollup`: latest scan per repo@branch). Other products: per-scan only | `backend/utilities/dashboard/cbom_team_rollup.py` |

## Design

### Connections (typed credentials)
`scmconnection` rows, team-scoped, admin-only writes, secrets write-only (Fernet, `encrypt_secrets`), never returned.
* GitHub: `github_app` (app_id, installation_id, private key PEM -> RS256 JWT -> installation token, cached in-process
  until 5 min before expiry) or `token` (scope org | user). GHES via `api_base`.
* GitLab: group access token (scope group path, include_subgroups). Self-managed via `api_base`.
* Bitbucket: workspace access token (scope workspace). Data Center later (same shape).
* `api_base` other than the SaaS default must be https (or http only when listed so) and its host must be in
  `GIT_ALLOWED_HOSTS`, the same operator allow-list that already gates cloning. Redirects are never followed; pagination
  links are followed only on the api_base host.
* Each connection gets a `webhook_uid` (public route key) and a generated webhook secret, shown once at creation /
  rotation, stored encrypted (it must be recoverable to verify HMACs).

### Discovery and the inventory
* `scmrepository`: unique (connection_id, external_id). Sync is an idempotent upsert keyed on the provider's stable id,
  so a rename updates the row instead of duplicating it. Only a COMPLETE sync marks unseen repos `removed_at`; a sync cut
  short by rate limits is `partial` and removes nothing.
* Paginated (100 per page; GitHub Link, GitLab keyset/Link, Bitbucket `next`), rate-limit aware: reads
  `X-RateLimit-Remaining/Reset` (GitHub), `RateLimit-*` (GitLab), `Retry-After` (all, 403/429 secondary limits), waits
  when under a reserve, retries 5xx with backoff, stops as `partial` when the wait would exceed a cap and sets
  `next_sync_at` to the reset time. Every page's numbers go into `last_sync_summary` (api_calls, waits, remaining).
* Include/exclude filters (pure, deterministic, unit-tested): include/exclude name globs (on `owner/name` and `name`),
  topics any-of / excluded topics, languages, archived, forks, visibility, max size. Each repo gets `in_scope` and a
  `scope_reason` (first rule that excluded it). Manual override per repo (`include` / `exclude`) wins over filters.
* Sync runs from `POST .../sync` (FastAPI background task) and from the repo scheduler (due `next_sync_at`), under a
  lease (`sync_lease_until`, CAS) so two runners never sync the same connection at once.

### Scan policies (per repo group)
`scmscanpolicy`: selector (same filter grammar), products (subset of sast, iac, sbom_sca, cbom, ai_bom), branch
(empty = repo default branch), on_push, schedule (off/daily/weekly/monthly at HH:MM in an IANA zone), options (IaC
modes). Evaluation is deterministic: enabled policies in (position, id) order, first selector match wins; a repo's
pinned `policy_id` wins over selectors. The inventory shows the winning policy and why.

### Triggering
* Scheduled: the repo scheduler fires due policies (slot CAS on `next_run_at`, so a slot fires once across replicas),
  creating a run over the policy's in-scope repos.
* Webhooks: `POST /scm/webhooks/{github|gitlab|bitbucket}/{webhook_uid}`, public, body capped, rate-limited by IP.
  GitHub `X-Hub-Signature-256` HMAC-SHA256, GitLab `X-Gitlab-Token` (constant-time), Bitbucket `X-Hub-Signature`
  HMAC-SHA256. Unsigned or bad signature: 401 and nothing happens. Push to the policy branch of an in-scope repo whose
  policy has on_push -> enqueue at push priority. `repository` / `installation_repositories` events re-sync that repo.
  Redelivery and replay are idempotent: the queue's dedupe key is (repo, product, branch, commit).
* Manual: bulk "scan now" from the inventory, or "run policy now".

### Bounded-concurrency queue with per-team fairness
`scmscanrequest` is the queue (one row per repo x product). Priority push(0) > manual(1) > schedule(2). Each tick the
dispatcher takes a Postgres advisory lock (single decider), counts in-flight per team, and fills free global slots by
water-filling: repeatedly give one slot to the team with the FEWEST in-flight scans (ties: least recently served)
that is under the per-team cap, taking that team's highest-priority oldest request. Claim is a CAS
(`queued -> dispatching`). Caps: `REPO_SCAN_MAX_INFLIGHT` (default 8) and `REPO_SCAN_TEAM_MAX_INFLIGHT` (default 4).
Repo scans therefore never occupy more than the cap of Celery's `scan_worker_queue`, leaving room for interactive scans.
Completion: in-flight scans are polled through the existing `get_status_and_update_db` (results, findings, refund on
failure all unchanged), then the request is closed and the roll-up folded.

### Credits
* Price per (repo, product) from the SCM-reported size with the worker's own rates (formula `scm-size-v1`), cents.
  GitHub's `size` includes history, so it is an upper bound of the checked-out source the worker measures. Cloning
  1,000 repos to estimate is not feasible; this is a decision for the owner (stated in the PR).
* `POST /runs/estimate` gives repos, scans, credits per product, total, balance, affordable. `POST /runs` requires
  `expected_credits` equal to the fresh estimate (else 409 `estimate_changed`, nothing charged), then charges the run
  total in ONE atomic deduction and records it per request (credits per run). Push-triggered scans are charged per
  request at enqueue. A scheduled run that cannot be afforded is skipped and says so on the policy.
* Refunds: a request cancelled / skipped before dispatch is refunded by us (once, CAS on `refunded`); after dispatch
  the Scan row carries `credit_charged` and the existing failure / cancel paths refund it (never twice).

### Results: roll-up and dedup across repos
`scmfinding` (unique team, product, fingerprint) + `scmfindingoccurrence` (unique finding, repo). Fingerprints are
product-specific and location-free so the same issue in many repos is ONE finding with a repo count: sbom_sca =
package@version + CVEs; sast/iac = normalised title (+ category / CWE); cbom = asset type + algorithm + finding codes
(findings only, `cbom_rows.is_finding`); ai_bom = component + provider + version. A rescan of a repo replaces that
repo's occurrences for that product; a finding with no repos left gets `resolved_at`. Folded from `Scan.scan_data`
(Postgres) with the same per-type shapes as `create_findings`. Rows keep using the existing Scan model and
scan_metadata, so per-product pages and the CBOM team roll-up see repo scans like manual ones.

### API (`/{team_id}/scm/...`, CBOM Sources conventions: 400 never 403, admin for writes, row_version 409)
connections (list, create, get, update, delete, test, sync, rotate webhook secret, preview filters + estimate,
import = save filters and apply), repositories (list with filters/facets/pages, bulk include/exclude/reset/assign
policy/scan now), policies (CRUD, preview), runs (estimate, create, list, get, cancel), queue (stats), findings
(dedup list, detail), rollup (per product), webhooks (public).

### UI (PR 2): "Repositories" in the sidebar
Import wizard (connect -> discover -> filter with live count and credit estimate -> import), inventory table with
filters and bulk actions (estimate shown before any scan), policy editor (selector, products, branch, schedule, on
push, live preview), runs/queue view, findings roll-up.

## Risks
* GitHub App installation tokens: the worker clones with the token as URL user; GitHub documents
  `x-access-token:<token>` for installation tokens. Fix in the worker (ghs_ prefix) with a test.
* Size-based pricing differs from the clone-measured price of a manual scan of the same repo (documented decision).
* Webhook secret per connection is a recoverable secret (Fernet) because HMAC verification needs it.
* F4 (RBAC) will add per-route permission declarations; these routes use `require_admin` today and will need entries.
* Huge monorepos: max size filter, per-repo price shown before a run.

## How each acceptance criterion is proven
| Criterion | Proof |
|---|---|
| Org import GitHub/GitLab/Bitbucket, app install or token, auto-discovery, include/exclude filters | unit tests per provider against the fake servers (pagination, auth headers, app JWT), filter tests, API tests; live GitHub smoke through the proxy (repo-scoped; list endpoints refused by the proxy are recorded as such) |
| 1,000 repos imported in < 5 min | `bench/scm/import_bench.py` against `bench/scm/fake_scm.py` (real HTTP server, 100/page, rate limit + secondary limit + 5xx), PostgreSQL; plus a CI test with 1,000 repos on SQLite |
| Scheduled + webhook (push) scans, bounded concurrency, per-team fairness | dispatcher unit tests (caps never exceeded, fairness, priority), PG race test (two dispatchers, no double dispatch), webhook signature tests, `bench/scm/fairness_bench.py` 1,000-repo scheduled run with fairness numbers vs a FIFO baseline |
| Dedup and rollup across repos | rollup tests (same CVE in N repos = 1 finding with repo_count N; rescan replaces; resolved) |
| Credits per run | estimate / 409 estimate_changed / single deduction / refunds-once tests |
