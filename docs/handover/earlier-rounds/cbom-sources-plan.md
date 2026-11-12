# CBOM Sources: implementation plan (DevSecShield, branch `ansh`)

Repo: `/home/claude/devsecshield` (HEAD f0ea1bc). Design reference: 9 artboards in `/tmp/claude-0/-home-claude/976896a4-2e24-5405-8100-31f07ced9160/scratchpad/design/project/*.dc.html`.

## 0. User decisions (binding)

| Decision | Choice |
|---|---|
| Delivery | Commit directly to `ansh` |
| Scope | Frontend + backend + APIs + persistence + scan-node API. The collector engine (SSH, WinRM, k8s API, DB, TLS probing) is out of scope. |
| Secrets | Browser may post raw passwords, keys and kubeconfigs. Stored encrypted at rest. |
| Credits | Per-target rates: server 0.2, Kubernetes cluster 2, database 1, cloud account 4, network 1 per /24 (after never-scan exclusions). CAs, IdPs, domains and evidence are free. |
| Start scan (non-code sources) | Queue jobs for scan nodes. They wait ("Waiting for scan node") until a node claims them through the node API. |
| AWS validate | Real AWS STS calls from the backend. Azure and GCP: "validation not available yet". |
| Permissions | Any team member can view. Only the creator or a team admin can change or delete (DAST profile rule). |

## 1. Discovered architecture (evidence from the exploration)

**Backend**
- FastAPI, `backend/main.py`. There is no URL prefix. Team routes take the shape `/{team_id}/<area>/...`, and the first registered router wins.
- Auth: `get_user_from_header_or_raise_exception(engine, Authorization)` (JWT Bearer) plus `check_if_user_is_in_team` (raises 403) and `check_if_user_is_admin_of_team`. No FastAPI auth dependency is used.
- Database: SQLModel on Postgres (`backend/get_db.py`). All models live in `backend/new_models.py`.
- Migrations: Alembic in `prod_database_migrations/migrations/versions/`, head `d9e4b2c5st02`, written by hand. They run at container start. Tests use `create_all` on SQLite.
- Secrets: Fernet in `backend/utilities/db/encryption.py` (`encrypt_value`, `decrypt_value`), key from `ENCRYPTION_KEY`. Closest precedent: `DastScanProfile.auth_encrypted` with `public_profile()` redaction (`utilities/dast/*`).
- Machine auth precedent: `utilities/cicd/auth.py` shows an API key once and stores only its SHA-256 hash, behind an `APIKeyHeader` `Security` dependency.
- Rate limiting: `fastapi_throttle.RateLimiter` must be attached in the decorator (`dependencies=[Depends(limiter)]`). The parameter-default form used by older routers does nothing. `cbom_deliverables.py` keys the limiter on a token hash (`_token_key`).
- Credits: `utilities/team/credits.py` has `check_if_team_has_enough_credits`, the atomic `deduct_credits_from_team` and `refund_credits_to_team`. DAST has a deterministic backend formula (`utilities/dast/credits.py`).
- Celery/RabbitMQ are internal only and cannot reach a customer-network node. A DB-backed job queue that nodes poll is required. The `with_for_update(skip_locked=True)` claim pattern exists in `utilities/dast/beat.py`.
- Team delete cascades by hand in two places: `routers/team.py:delete_team` and `utilities/db/admin.py:delete_team_associated_data`. DAST profiles are missing from both today (existing bug, noted, not fixed here).
- Logging: rich `console.print`. Newer code writes one greppable line per request with `markup=False, highlight=False, soft_wrap=True`. There are no metrics, no tracing and no audit table.
- Naming collision: "source" already means a code origin in `utilities/dashboard/cbom_team_rollup.py` (`source_key_for`, `X-Cbom-Sources`). The new models use a distinct prefix, `CbomCollection*`, so nothing in the roll-up changes.
- The posture spec `.kiro/specs/cbom-config-encryption-posture` defines nothing about collection sources. Its rules that still apply:
  - The CBOM engine stays air-gapped, so the new code adds no network calls inside `aibom/`.
  - Raw secrets never reach `scan_data`, the BOM or PDFs.
  - Git hygiene: explicit pathspecs, no `add -A`, no `stash`, no `--no-verify`.

**Frontend**
- Next.js 16, every page a client component. `app/[team_id]/layout.tsx` owns the nav arrays and the single QueryClient (TanStack v5 defaults: 3 retries, staleTime 0).
- API: `utils/backend_api.ts` (axios `api` from `utils/interceptors.js`, base `NEXT_PUBLIC_BACKEND_URL`). Types are inline, with one `export {}` block per section. `showErrorToast` comes from `utils/error-handler.ts`.
  - **On a 403 the frontend logs the user out.** New endpoints must not return 403 for ordinary denials.
  - 422, 404 and 500 show generic text; 400 and 409 show `detail`.
- Forms are plain `useState`; there is no form library. Write-only secret pattern: `components/dast/DastProfilesTab.tsx` (`type=password`, "Leave blank to keep").
- The CBOM Configuration sidebar is `components/cbom-options-sidebar.tsx`, rendered on `app/[team_id]/cbom/[scan_id]/page.tsx`, not on the list page.
- Tabs follow the Radix pill style (`data-[state=active]:bg-blue-600`). Tables use shadcn `Table` inside `ScrollArea`. Dialogs follow the CBOM list page. Spinner: `Loader2` (`text-blue-600`).
- Polling: a `useEffect` on `dataUpdatedAt` with a 6 s `setTimeout` that invalidates the query.
- The nav highlight uses `pathname.startsWith`, so `/cbom/sources` keeps CBOM highlighted (wanted).
- Checks: `npx tsc --noEmit`, plus eslint on changed files. CI runs tsc on the cbom paths. Unit "tests" are `tsx` scripts.

**Run/test environment**
- No Docker daemon and no Mongo or RabbitMQ. The Postgres 16 server is installed (cluster down; start it with `pg_ctlcluster 16 main start`).
- Neither CBOM Sources nor login and signup needs Mongo or RabbitMQ, so Option B (native Postgres, real Alembic, `fastapi dev`) can exercise everything new.
- Playwright 1.63 is installed globally with chromium-1243; I'll use it directly for the customer-perspective tests.

## 2. Current behaviour

- The product collects only code (zip, repo, CBOM file). There are no models, routes or UI for scan nodes, servers, clusters, databases, cloud accounts, certificates and identity, network scope or evidence.
- Some design copy claims things this build will not do:
  - "secrets encrypted to the node's key, so ZeroShield's cloud cannot read them" is false under the raw-secrets decision.
  - "mutual TLS client certificate" is not built.
  - "updates.zeroshield.ai" and the CMDB/vCenter/CT-log import buttons have no backend.

## 3. Data model (new tables in `backend/new_models.py`, one Alembic revision `e3b7c9a1cs01`, down_revision `d9e4b2c5st02`)

1. **`CbomScanNode`** (`cbomscannode`)
   - Columns: `id`, `team_id` FK (indexed), `owner_user_id` FK, `name` (≤64), `segment` (≤64), `timezone`, `deployment` (`docker|ova|ami|helm`), `proxy_url`, `proxy_ca_pem` (text, optional), `proxy_tls_inspect` (bool).
   - Registration: `registration_token_hash`, `registration_expires_at`, `enrolled_at`, `node_token_hash` (unique, indexed).
   - Reported by the node: `hostname`, `version`, `source_ips` (JSON), `ssh_public_key`, `capabilities` (JSON), `clock_skew_s`, `last_heartbeat_at`.
   - `created_at`, `last_updated`.
   - Status is derived, never stored:
     - `pending_registration`: never enrolled.
     - `online`: heartbeat within 120 s.
     - `offline`: otherwise.
2. **`CbomCollectionSource`** (`cbomcollectionsource`)
   - Columns: `id`, `team_id` (indexed), `owner_user_id`, `kind`, `name`, `node_id` (nullable FK to `cbomscannode`), `config` (JSON, never secret), `secret_encrypted` (text: Fernet of a JSON dict), `secret_fields` (JSON list of names that are set), `enabled`, `target_count` (int, computed at save), `last_test_status`, `last_test_at`, `last_test_summary`, `created_at`, `last_updated`.
   - `kind` is one of: `linux_servers`, `windows_servers`, `active_directory`, `kubernetes`, `database`, `aws_account`, `azure_subscription`, `gcp_project`, `ca_connector`, `idp`, `network_range`.
3. **`CbomCollectionJob`** (`cbomcollectionjob`)
   - Columns: `id`, `team_id` (indexed), `run_id` (nullable), `source_id` (nullable), `node_id` (nullable, indexed), `kind` (`test_connection|collect|discovery`), `status` (`pending|claimed|success|failure|cancelled|expired`), `params` (JSON, no secrets), `attempts`, `lease_expires_at`, `created_at`, `claimed_at`, `finished_at`, `result` (JSON, size-capped to 256 KB, secret-scrubbed), `error` (≤1 KB).
4. **`CbomCollectionRun`** (`cbomcollectionrun`)
   - Columns: `id`, `team_id`, `owner_user_id`, `scan_id` (nullable link to a CBOM `Scan`), `status` (`queued|running|done|partial|cancelled`, derived from jobs and cached), `credits_charged`, `credits_refunded`, `breakdown` (JSON), `created_at`, `last_updated`.
5. **`CbomCollectionSettings`** (`cbomcollectionsettings`, one row per team, unique `team_id`)
   - `aws_external_id`: `zs-ext-XXXX-XXXX-XXXX-XXXX`, created once and never changed.
   - Certificates: `cert_domains` (JSON).
   - Network: `network_exclusions` (JSON `[{cidr, reason}]`), `sni_hostnames` (JSON), `ports` (JSON `[{port, label}]`), `zeek_span` (bool), `scan_window` (JSON 7×24 bools), `window_timezone`.
   - Rate limits: `rate_conn_per_s`, `rate_parallel_per_server`, `rate_handshakes_per_endpoint`.
   - SOC contacts: `soc_email`, `emergency_contact`.
   - `stop_all_network` (bool), `soc_ack_at`.
6. **`CbomEvidenceArea`** (`cbomevidencearea`, unique (`team_id`, `area_key`))
   - `area_key` is one of six: `key_hierarchy`, `key_ceremonies`, `escrow_recovery`, `hsm_firmware`, `backup_encryption`, `third_party_vendors`.
   - Columns: `owner`, `confidence` (`Q0..Q3`), `answers` (JSON), `evidence_title`, `evidence_url`, `evidence_date`, `due_date`, `updated_by`, `last_updated`.
   - Effective confidence drops to Q0 when `evidence_date` is more than 365 days old.
7. **`CbomEvidenceVendor`** (`cbomevidencevendor`)
   - Columns: `id`, `team_id`, `name`, `contact_email`, `area_key`, `link_token_hash` (nullable, unique), `link_expires_at`, `link_created_at`, `answered_at`, `answers` (JSON), `confidence`, `created_at`.
   - The link is single use and lasts 14 days. Once it is answered or expired, the token is unusable.

Every table has `team_id` and every query filters on it. Delete cascades are explicit: deleting a node is refused while sources still point at it (400, with the list).

## 4. Backend API

New modules:
- `backend/utilities/cbom_sources/`:
  - `schemas.py`: Pydantic v2, with a discriminated union per kind.
  - `crypto.py`: encrypt and decrypt the secret blob, plus `scrub()`.
  - `serialize.py`: public shapes, never secrets.
  - `targets.py`: target parsing and counting, with exclusions, through `ipaddress`.
  - `credits.py`: the `RATES` dict and `estimate()`.
  - `jobs.py`: create, claim, lease expiry, finish, run status roll-up.
  - `aws_validate.py`: boto3 STS checks.
  - `evidence.py`: area catalog and confidence rules.
  - `templates.py`: CloudFormation template, sudoers, ClusterRoles, DB grants, all served as static text.
- Routers:
  - `backend/routers/cbom_sources.py` (JWT, team-scoped)
  - `backend/routers/cbom_node.py` (node token)
  - `backend/routers/cbom_vendor_public.py` (single-use link)

All registered in `main.py` before `scans_router`, so `/{team_id}/{type}/scan` patterns can't shadow them. None of the new paths contain `/scan/`.

**Team routes** (`/{team_id}/cbom/sources/...`, with `TeamId = Path(ge=1, le=2147483647)`):
- Limiter in the decorator: 60 requests per 60 s, keyed on a token hash.
- `_authorize` runs in the threadpool, as in `cbom_deliverables`.
- An owner/admin denial returns **400**, never 403.
- Not found or another team's id returns **404**.

| Method | Path | Purpose |
|---|---|---|
| GET | `/{team_id}/cbom/sources/overview` | Counts for the stat cards, the sidebar accordions and the Review coverage table. Also returns the skipped-items list and the estimate. |
| GET/POST | `/{team_id}/cbom/sources/nodes` | List nodes. Create a node: returns `registration_token` once (`zsr_` + 32 random url-safe bytes, sha256 stored, expires in 24 h). |
| GET/PATCH/DELETE | `/{team_id}/cbom/sources/nodes/{id}` | Get, edit, delete. Delete is refused with 400 while sources reference the node. |
| POST | `/{team_id}/cbom/sources/nodes/{id}/registration-token` | Regenerate. Invalidates the old token. Only allowed before enrollment. |
| GET/POST | `/{team_id}/cbom/sources/items?kind=` | List and create sources. Create validates per kind, encrypts secrets and computes `target_count`. |
| GET/PATCH/DELETE | `/{team_id}/cbom/sources/items/{id}` | PATCH treats a missing or empty secret as "keep existing". Clearing a secret needs `clear_secrets: [..]`. |
| POST | `/{team_id}/cbom/sources/items/{id}/test` | Node kinds: creates a `test_connection` job for the source's node (samples are the first 5 targets) and returns the job. `aws_account`: runs the STS checks synchronously (threadpool, 20 s budget) and returns the result. Azure and GCP: 200 `{status: "not_available"}`. |
| GET | `/{team_id}/cbom/sources/jobs/{job_id}` | Poll. The lease is checked lazily here. |
| GET/PUT | `/{team_id}/cbom/sources/settings` | Network scope, certificate domains, SOC contacts, stop-all. Creating the row also creates `aws_external_id`. |
| GET | `/{team_id}/cbom/sources/aws/template?scope=account\|organization` | CloudFormation YAML with the team's external ID and `CBOM_AWS_PRINCIPAL_ARN` (env) filled in. |
| GET | `/{team_id}/cbom/sources/templates/{name}` | Static text: `sudoers`, `k8s-tier1`, `k8s-tier2`, `grant-postgres`, `grant-mysql`, ... |
| POST | `/{team_id}/cbom/sources/discovery` | One `discovery` job per node that has network ranges. Refused while `stop_all_network` is set. |
| GET/PUT | `/{team_id}/cbom/sources/evidence` | Areas, plus PUT of a single area by `area_key`. |
| GET/POST/PATCH/DELETE | `/{team_id}/cbom/sources/evidence/vendors[/{id}]` | Vendor CRUD. |
| POST | `/{team_id}/cbom/sources/evidence/vendors/{id}/link` | Creates or replaces the single-use link and returns the URL once. |
| POST | `/{team_id}/cbom/sources/estimate` | Body `{include: {servers, kubernetes, databases, cloud, network}, source_ids?}`. Returns per-group credits and the total. |
| POST | `/{team_id}/cbom/sources/runs` | Body `{include, scan_id?, soc_ack: true}`. In order: validates the SOC acknowledgement when network is included, estimates, checks credits, deducts atomically, creates the run and one `collect` job per included source. If job creation fails, the credits are refunded. |
| GET | `/{team_id}/cbom/sources/runs` | List runs. |
| GET | `/{team_id}/cbom/sources/runs/{id}` | Run with its jobs. |
| POST | `/{team_id}/cbom/sources/runs/{id}/cancel` | Cancels the pending jobs. Refunds credits for jobs never claimed, pro rata by job weight. |

**Node routes** (`APIKeyHeader("X-ZS-Node-Token")`, limiter keyed on the token hash):

| Method | Path | Purpose |
|---|---|---|
| POST | `/cbom/node/enroll` | Body `{registration_token, hostname, version, source_ips, ssh_public_key?, capabilities?, clock}`. Single use and expiry enforced. Returns `{node_id, node_token (zsn_...), heartbeat_interval_s: 30}`. |
| POST | `/cbom/node/heartbeat` | Updates `last_heartbeat_at`, version, IPs and clock skew. Returns `{server_time, stop_all_network, pending_jobs}`. |
| POST | `/cbom/node/jobs/claim` | Claims the oldest pending job for this node: `with_for_update(skip_locked=True)` on Postgres, plus a guarded `UPDATE ... WHERE status='pending'`. Leases for 15 min. Returns the job with **decrypted secrets for that job's source only**, plus the scope (targets minus team exclusions). Network jobs are skipped while stop-all is set. |
| POST | `/cbom/node/jobs/{id}/result` | Body `{status: success\|failure, result, error}`. Accepted only from the node that holds the lease. Result size cap 256 KB (413 above), scrubbed. Updates the source's `last_test_*` for test jobs. Recomputes the run status. |

Lease rules:
- An expired claim goes back to `pending` while attempts < 3. After that it becomes `failure` ("Scan node stopped responding").
- A pending test job older than 24 h becomes `expired`.

**Public vendor routes** (no JWT; limiter keyed on the link-token hash):
- `GET /cbom/vendor-questionnaire/{token}` returns the questionnaire (area questions, vendor name, team name). It returns 404 for unknown, used or expired tokens.
- `POST /cbom/vendor-questionnaire/{token}` stores the answers and consumes the link. Body cap 32 KB.

**Logging**
- One greppable line per mutating request: `cbom sources <action> team=.. id=.. kind=.. by=user:..`. It never includes secrets or tokens.
- Failures use `_log_failure` and return a generic 500.

**Team delete:** add the seven tables, children first, to both cascade functions.

## 5. Frontend

**New files**
- Page: `app/[team_id]/cbom/sources/page.tsx`.
  - Seven Radix pill tabs, with the tab state in `?tab=` so refresh, back and forward keep it.
  - Header: title, subtitle, and a contextual primary button per tab.
- Tabs, in `components/cbom/sources/`:
  - `ScanNodesTab.tsx`: stat cards, node table, the "Add a scan node" wizard (name/segment/timezone, deployment radio, install command built with the one-time token, outbound table, proxy, the register steps from live node status), and a "What the node does" card.
  - `ServersTab.tsx`: Linux/Windows/AD toggle, targets textarea with a live count from the backend, never-scan, node select, port, host key policy, credential type (node key / SSH certificate / vault reference / password; secrets write-only), tier with sudoers download and command list, limits, window, connection test table, sources list.
  - `ClustersDatabasesTab.tsx`: cluster form (kubeconfig file read client-side into a secret, or a vault reference, tier with ClusterRole preview), database form (engine, host, port, login, password or vault path, TLS, CA), configured list with test status.
  - `CloudIdentityTab.tsx`:
    - AWS wizard: scope, external ID with copy, template download, role ARN, regions, Validate with the checks table.
    - Azure and GCP forms (saved, "validation not available yet").
    - Connected accounts table.
    - Certificate domains, CA/CLM connectors (dialog per connector), identity providers (dialog), SAML/OIDC metadata URLs.
  - `NetworkTab.tsx`: allowed ranges, never-scan, SNI hostnames (paste or import text file), ports, Zeek toggle, a 7×24 window grid (click and drag), rate limits, SOC table with node source IPs, discovery sweep, the stop-all toggle.
  - `EvidenceTab.tsx`: Q-level counts, areas table with an edit dialog (owner, confidence, evidence title/URL/date, due date, answers), vendors table with a "Create link" dialog (shows the URL once, with copy), and a questionnaire preview.
  - `ReviewRunTab.tsx`: coverage table, "Will be skipped" list (offline nodes, failed tests, sources without a node, Q0 areas, stop-all), "What you get", credits estimate, SOC checkbox, Start scan, and run history with status polling.
- Shared pieces, `components/cbom/sources/shared.tsx`:
  - `StatusBadge` (green/red/amber/blue tinted outline badges)
  - `SectionCard`, `NodeSelect`, `SecretField` (write-only), `useJobPoll` (6 s house pattern)
  - `CodeBlock` with copy
  - Formatting helpers
- Pure helpers in `components/cbom/sources/logic.ts`, with `logic.test.ts` run through tsx: target-line parsing, window-grid serialisation, Ansible snippet, install-command builder.
- Public page: `app/q/[token]/page.tsx`, the vendor questionnaire. It is outside `[team_id]`, so no login is needed.

**Changed files**
- `utils/backend_api.ts`: a `// ---------- CBOM Sources API Routes ----------` section with types and functions.
  - Mutations toast success. Pollers and the overview fetcher never toast, following the `getCbomDeliverables` precedent.
- `app/[team_id]/cbom/page.tsx`: a "CBOM Sources" outline button in the header row.
- `components/cbom-options-sidebar.tsx`: new accordion items:
  - "Analyze Servers & Clusters": node select, counts, Manage link.
  - "Analyze Cloud, Keys & Identity".
  - "Analyze Network TLS".
  - "Evidence & Attestation".
  - Each item has an include switch (default on when that group has sources).
  - Estimate shows the breakdown "Code N · Servers N · Cloud N · Network N · Evidence free".
  - Run scan starts the code scan exactly as today. When any group is included, it then calls `POST /runs` with `scan_id`.
  - The code-input requirement stays. Sources-only runs go through Review & Run, and the sidebar says so.

**Copy changes for honesty**
- Secrets: "Encrypted at rest by ZeroShield and sent only to the scan node that runs the job."
- The "mutual TLS client certificate" step becomes "Node credential issued".
- The outbound table shows the real API host (`apiBaseURL`).
- No import buttons for vCenter, CMDB or CT logs.

## 6. Suspected issues / risks (with confidence)

| # | Risk | Confidence | Mitigation |
|---|---|---|---|
| R1 | A 403 from `check_if_user_is_in_team` logs out a user who opens another team's URL | High (existing behaviour) | Out of scope. New routes add no new 403s. |
| R2 | Secrets leak through logs, responses, job params or results | Medium | Secrets live only in `secret_encrypted`. Serialisers whitelist fields. Results are scrubbed. A test plants canaries and greps every response and the logs. |
| R3 | Double claim of one job by two nodes, or by concurrent calls from the same node | Medium | `skip_locked` plus a conditional UPDATE. A concurrency test with threads on Postgres. |
| R4 | Credits are deducted but run creation fails | Medium | Deduct, create, and refund in `except`, as in `dast/dispatch.py`. Test it with an injected failure. |
| R5 | Huge CIDR (a /0, or an IPv6 /64) means a CPU blow-up and huge credits | High if not guarded | Server sources: each entry must be /16 or narrower (65,536 addresses), at most 1,000 lines, total ≤ 262,144 addresses. Network ranges: IPv4 /16 or narrower, IPv6 /112 or narrower. Counting uses arithmetic, never enumeration. |
| R6 | Naive vs aware datetimes | High (known) | Store naive UTC. An `_aware()` helper for comparisons. |
| R7 | Alembic revision drifts from the models (tests use `create_all`) | Medium | Run the real `alembic upgrade head` and then `downgrade -1` on the local Postgres. Compare columns. |
| R8 | The AWS checks hang the request | Medium | botocore `connect_timeout=5`, `read_timeout=10`, `max_attempts=2`, run in the threadpool. Errors are mapped to readable check rows, never a 500. |
| R9 | The vendor public endpoint is abused | Medium | sha256 token lookup, a limiter keyed on the token hash, a 32 KB cap, single use, 14-day expiry, and no team data beyond the team name. |
| R10 | Frontend error toasts on every poll | Medium | Poll fetchers don't toast. Query `retry: 1` on pollers. |
| R11 | The sidebar change breaks the existing code-scan flow | Medium | Code-scan path unchanged. The sources run starts only after `startScan` succeeds, and its failure only toasts. |
| R12 | Encryption-key fallback to `JWT_SECRET_KEY` | Known | Documented. A loud warning log at startup of the router when `ENCRYPTION_KEY` is unset. |
| R13 | Node token brute force | Low | 32-byte tokens. Unknown token returns 401 with no detail. The limiter applies. |
| R14 | Never-scan exclusions bypassed by a job's scope | Medium | Exclusions are applied server-side when building the job scope at claim time and are also sent as `deny` for the node to enforce. |

## 7. Dependencies

- Python: nothing new. boto3 is already present through langchain-aws/instructor and used by `utilities/db/s3_utils.py`. `ipaddress` and `secrets` are stdlib.
- JS: nothing new (lucide-react, shadcn primitives in `components/ui`).
- Env:
  - `ENCRYPTION_KEY` (strongly recommended)
  - `CBOM_AWS_PRINCIPAL_ARN` (the ZeroShield principal trusted by the customer role; the template shows a placeholder if unset)
  - `CBOM_PUBLIC_APP_URL` (vendor links; default `https://devsecshield.zeroshield.ai`)

## 8. Validation plan (CLAUDE.md phases 6–8)

1. Hermetic pytest (`backend/tests/test_cbom_sources_*.py`) on in-memory SQLite:
   - CRUD per kind.
   - Secret write-only behaviour and canary scans.
   - Cross-team 404.
   - Owner/admin 400.
   - Target counting edge cases.
   - Credits and refunds.
   - Node enroll, heartbeat, claim and result, including the lease paths.
   - Vendor link single use and expiry.
   - Malformed bodies.
2. Live backend on Postgres 16 with real Alembic:
   - curl/httpx scripts for boundary values, concurrent claims (threads), restart persistence (kill and restart uvicorn) and timeouts.
   - Check the logs contain no secrets.
3. Frontend: `npx tsc --noEmit`, eslint on changed files, the `logic.test.ts` script, `next build`.
4. Playwright (chromium-1243) as a customer:
   - Sign up, open CBOM, open Sources, do every tab's create/edit/delete, refresh, back/forward.
   - Two tabs at once, an expired token.
   - Desktop, tablet and mobile widths.
   - Screenshots.
   - A simulated node (python script) enrolls and answers jobs, and the UI updates.
   - Cross-check UI, API JSON and DB rows.
5. Edge cases:
   - Maximum lengths, the empty team, 1,000 targets, rapid double-clicks on Start scan (credits charged once), network drop during save, stale session.

---
# v2: amendments after the five contradiction reviews and the devil's-advocate pass (BINDING; overrides the sections above where they conflict)

## Security / tenancy
- Every id sent in a body or query (`node_id`, `scan_id`, `source_ids`, `cloud_source_id`) is checked to belong to the path team. If not: 404, or 400 for a body field ("node not found").
- Claim is only possible when `job.team_id == node.team_id == source.team_id` and `source.node_id == node.id` and `source.version == job.source_version`. Otherwise the job is cancelled, and credits are refunded for collect jobs.
- A team the user is not a member of keeps the existing 403. A record that belongs to another team returns 404. Owner/admin denials return 400 with a string detail. The new code adds no 403s.
- Scope is snapshotted into `job.params` when the job is created (targets, ranges, port, node). At claim, the snapshot is intersected with the current never-scan list, so the scope can only shrink.
- Changing the host, targets, port, node, API URL or role ARN of a source that has stored secrets clears those secrets unless they are re-entered. If the credential type still needs a secret, that is a 400 ("Re-enter the password: it is cleared when the target changes").
- Changing the credential type replaces the whole secret blob.
- Node lifecycle:
  - **Reset** (owner/admin): nulls `node_token_hash`, issues a new registration token, requeues the node's claimed jobs and cancels any lease.
  - **Delete**: refused while sources reference the node (400, string detail).
  - **Enroll**: a guarded UPDATE so the token works once, even under concurrent calls.
  - **Regenerate token**: guarded on `enrolled_at IS NULL`.
- Permissions:
  - Sources, nodes, tests: owner or admin.
  - Settings (network scope, SOC, domains): admin. Stop-all ON: any member. Stop-all OFF: admin.
  - Runs: any member may start; owner or admin may cancel.
  - Evidence and vendors: any member.
- Install command and Ansible text:
  - Name and segment must match `^[A-Za-z0-9 ._-]{1,64}$`.
  - `proxy_url` must be strict http(s) with a host and optional port, and no userinfo, quotes or spaces.
  - The builders single-quote-escape every value.
- Secret leaks:
  - A custom `route_class` on the new routers turns `RequestValidationError` into a 400 carrying `{detail: "<field>: <msg>"}` and never the input.
  - `create_engine(..., hide_parameters=True)`.
  - `scrub()` removes the source's known secret values, PEM PRIVATE KEY blocks and `zsr_`/`zsn_` tokens.
  - The canary test greps responses, job rows and captured logs.
- AWS validation:
  - Credentials: optional dedicated `CBOM_AWS_ACCESS_KEY_ID`/`CBOM_AWS_SECRET_ACCESS_KEY`, otherwise the default chain.
  - Role ARNs in ZeroShield's own account are rejected. Regions must match the AWS region regex.
  - `RoleSessionName=zs-cbom-validate-<team>`.
  - The deadline is checked inside the worker. No DB session is held during STS calls.
  - Check rows are `pass`/`fail`/`skipped`/`error`. Checks after a failed AssumeRole are `skipped`. Platform faults are `error` and come with a ref.
  - Secret probe: AccessDenied is a pass. ResourceNotFound is a fail ("the role can read secrets").
  - Deny check: read the role's inline policies (ListRolePolicies/GetRolePolicy) and look for an explicit Deny covering the required actions.
- Vendor public page:
  - Uses plain `fetch`, outside the axios interceptor.
  - Sets `Referrer-Policy: no-referrer`.
  - The token is consumed by a guarded UPDATE (`answered_at IS NULL AND link_expires_at > now`).
  - `evidence_url` must be http(s). Answers are capped and always rendered as text.
- Body caps are applied before parsing, through a streaming reader (`_read_capped_json`): node result 256 KB, heartbeat 16 KB, vendor POST 32 KB.

## Credits and runs
- All arithmetic is in integer centi-credits; values are returned as 2-dp floats. Rates (`utilities/cbom_sources/credits.py`):
  - server 20
  - cluster 200
  - database 100
  - cloud 400
  - network 100 per distinct /24 block (IPv6: per /120)
  - CA, IdP, domains and evidence: 0
- A single `plan_run(session, team_id, include, source_ids, now)` drives the overview, `/estimate`, `POST /runs` and the sidebar.
  - **Charged and queued:** enabled, enrolled node, more than 0 targets, last test not failed.
  - **Skipped, no charge**, each with a reason:
    - disabled
    - no node, or the node is pending/expired/reset
    - 0 targets after exclusions
    - last test failed
    - kind has no collector yet (aws/azure/gcp/ca/idp: "cloud collection not available yet"; the 4-credit rate is kept in config)
    - network while stop-all is on
    - already queued in an active run (409 if every included source is already queued)
  - An offline node does not make a source skipped. It stays queued and charged, labelled "Waiting for scan node".
- `POST /runs`:
  - Requires `client_request_id`, unique per (team, id); a replay returns the existing run.
  - `expected_credits` must equal the server total, otherwise 409 with the new total.
  - `soc_ack` is required when network is included.
  - `scan_id` must be a CBOM scan of this team (404 or 400).
  - The deduction is a conditional UPDATE on team credit in the **same transaction** as the run and job inserts. Insufficient credits is a 400 with "required X, balance Y". A zero-cost run skips the deduction.
- Cancel:
  - Per-job conditional UPDATE (`WHERE status='pending'`), refunding only the rows that changed, in the same transaction, with the last-remainder rule so refunded ≤ charged.
  - A second cancel is a 200 no-op.
  - Claimed jobs keep running ("Finishing on node").
- Refunded automatically: expired, lease-exhausted and cancelled collect jobs. A failure the node reports is charged.
- Reaper `reap(session, now, team_id=None, node_id=None)`:
  - Claimed jobs past their lease go back to pending (attempts < 3) or become failure ("Scan node stopped responding"), with a refund.
  - Pending test jobs older than 24 h expire.
  - Pending collect jobs older than 7 days expire, with a refund.
  - Run status is recomputed.
  - It runs from claim, heartbeat, job GET, runs list/get and overview, wrapped so a failure is logged but the read still succeeds.
- A heartbeat renews the lease of every job that node holds. Leases are 15 min.
- `lease_id` is random per claim and the result must echo it. Results for a job that is not `claimed`, or whose lease_id doesn't match, get a 409.
- Run status is one of:
  - `queued`: no job claimed yet.
  - `running`: some claimed or pending after a claim.
  - `done`: all success.
  - `partial`: mixed terminal outcomes.
  - `failed`: all failure or expired.
  - `cancelled`: cancelled before any claim.

## State and concurrency
- An integer `version` on source, node, settings, evidence area and vendor. PATCH may carry `expected_version`; a mismatch is a 409 "Changed elsewhere; reload". The frontend invalidates in `onSettled` and closes the dialog on 404/409.
- Settings: sectioned PATCH (`exclude_unset`) plus a separate `POST /settings/stop-all {on}`. The settings row and evidence rows are created with `get_or_create`: insert, catch IntegrityError, re-select.
- `target_count` is computed on read with arithmetic, never stored, so it never goes stale. Sources are capped at 500 per team.
- Unique (`team_id`, `kind`, `name_lower`) on sources: duplicates get a 409.
- Times are stored as naive UTC and serialised with `Z`. The backend returns derived values (node `status`, `server_time`, `effective_confidence`, `overdue`, `waiting_reason`, `next_window_start`). Dates are `YYYY-MM-DD`.
- `PRAGMA foreign_keys=ON` in tests. IntegrityError maps to 400/409. `Run.scan_id` and every `owner_user_id`/`*_by` column is a plain int with no FK, so the scan, user and team deletes cannot break. `node_id`/`source_id`/`run_id` are FKs between the new tables only. Team delete cleans the new tables first, children first, in both cascade functions.
- Postgres-only safety: Pydantic `max_length` equals the column length, node-supplied strings have NULs stripped and are truncated, JSON columns are reassigned rather than mutated in place, and no `func.now()`.

## Observability
- `_log(action, **fields)`: ints, enums and ids only; `markup=False, highlight=False, soft_wrap=True`; called after commit inside try/except.
  - Logged: every state change, including reaper transitions, and a node coming back after a gap.
  - Not logged: heartbeats, polls, empty claims.
- `CbomCollectionAuditEvent` (`id`, `team_id`, `at`, `actor_type` user|node|vendor|system, `actor_id`, `action`, `object_type`, `object_id`, `changed_fields` JSON with names only), written in the same transaction as the change.
- New columns:
  - `updated_by_user_id` on node, source and settings.
  - Run: `cancelled_by`, `cancelled_at`, `soc_ack_by`, `soc_ack_at`.
  - Node: `last_claim_at`, `last_seen_ip`, `last_node_error` (≤512, scrubbed), `registration_issued_at`.
- Status vocabularies:
  - node: `pending_registration|registration_expired|online|offline`
  - `last_test_status`: `never|pending|passed|partial|failed|not_available|error`, plus `last_test_job_id` (newest wins)
  - evidence: `confidence` + `effective_confidence`, with Q2+ requiring evidence
  - vendor: `not_sent|link_created|overdue|answered|expired` (overdue is 7 days after link creation)
  - the third-party area takes the lowest vendor confidence
- A 500 returns `"<message> (ref <8hex>)"` and the ref is logged. Every `detail` is a string.
- Limiters, all in decorators:
  - GET/polling: 300/min per token
  - mutations: 60/min per token
  - node routes: 120/min per token hash
  - enroll: 20/min per client IP
  - vendor: 20/min per link hash

## Frontend
- One key factory, `cbomSourcesKeys` → `["cbom-sources", teamIdNumber, ...]`. Mutations invalidate the prefix in `onSettled`. Runs also invalidate `["teams"]` and the scan's `["cbom-conversation-data", team, scan]`.
- Polling uses `refetchInterval` (function form) with `retry: 1`, and stops on terminal or 404:
  - jobs and runs: 6 s
  - nodes and overview: 30 s while visible
- The page keeps the tab in `?tab=`. Wizard state, the one-time registration token and the vendor link live in page state, so a tab switch doesn't lose them; the UI warns that they are lost on refresh and offers Regenerate.
- Clipboard falls back to selecting the text plus a "copy manually" toast. File inputs check size, NUL bytes and UTF-8.
- The 7×24 window grid uses buttons with `aria-pressed`, click-drag and keyboard toggling; it scrolls inside its container on mobile.
- Sidebar:
  - Include switches default **OFF**.
  - One Estimate click snapshots code and sources together.
  - The reset deps include `branch` and the switches.
  - `POST /runs` runs after `startScan` succeeds, with `scan_id`, `expected_credits` and `client_request_id`.
  - `GET /runs?scan_id=` shows the run status after a reload.
- Honesty in the UI copy:
  - "Encrypted at rest by ZeroShield; sent only to the scan node that runs the job"
  - "Node credential issued", not mTLS
  - the API host comes from `apiBaseURL`
  - no vCenter/CMDB/CT-log/k8s-ingress import, no "Launch StackSet" (use "Open CloudFormation console" + Download template), no updates host, no transcript or security-sheet claims, no contradiction banner
  - email actions are relabelled as copy-link
  - "Targets assigned" replaces "Targets reachable"
  - "Save and test" replaces "test before saving"
  - "What you get" is toned down to what exists
- The node image name comes from `NEXT_PUBLIC_CBOM_NODE_IMAGE` (default `registry.zeroshield.ai/cbom/scan-node:1.0`); the final report notes the image is not published yet.
- Design items kept:
  - network range mode (full/fragile; fragile wins on overlap)
  - ports with a protocol
  - Zeek flag
  - managed-cluster flag
  - grants for postgres/mysql/mssql/oracle/mongodb/redis
  - AD CS through a node
  - SAML/OIDC metadata URLs stored and never fetched by the backend (no SSRF)
  - per-source scan window
  - `known_hosts` text
  - login user (default `zs-cbom`)
  - limits (parallel 1–64, timeout 10–3600 s)
  - next window start
  - a "Code and pipelines" row from the team's CBOM scans
  - segment as free text with suggestions
  - install snippets for docker/helm/ami/ova
  - DNS zone file parsing on the client
