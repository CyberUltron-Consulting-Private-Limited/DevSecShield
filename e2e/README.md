# dss-e2e: Docker + Playwright proof harness for the CBOM team deliverables

Everything needed to build the product images from this worktree, bring up a throw-away
`postgres + mongo + backend + frontend` stack, seed it with real scan data, drive the UI with
Playwright (video + screenshots), and collect machine-indexed evidence. It is dev tooling only: it
is never shipped and no product code imports it.

Scope of this directory: WP6a is the **infrastructure** (compose, images, scripts); WP6b is the **seed and the
specs** (`seed/`, `fixtures/expected.json`, `fixtures.ts`, `lib/`, `specs/`, `selftest/`, described in
"Seed, oracle and specs (WP6b)" below); the full run and its evidence belong to WP7.

Status when WP6a landed: `preflight.sh`, `build.sh`, `fixtures/build_trees.sh`, `teardown.sh`,
`collect-evidence.sh` and the compose policy check were run and their failure paths exercised. The
stack itself was deliberately **not** brought up (that is WP7), so the happy paths of `up.sh`,
`seed.sh`, `run-specs.sh` and `all.sh` are untested end to end. The pieces they rely on were checked on
their own: the postgres / mongo / frontend / backend healthchecks and the backend start command ran in
standalone containers, the scanner image ran all eight trees under the compose restrictions and matched
a host scan byte for byte, and the Playwright 1.62.0 toolchain recorded a 1440x900 video headless.

## Layout

```
e2e/
  compose/docker-compose.e2e.yml   project "dss-e2e": postgres, mongo, backend, frontend (+ profile "seed": aibom-scan, seed)
  compose/.env.e2e                 GENERATED per run, git-ignored, throw-away secrets (never committed, never printed)
  docker/*.Dockerfile              backend + frontend are verbatim copies of the production Dockerfiles; aibom-scan is E2E-only
  docker/*.Dockerfile.dockerignore per-Dockerfile ignore files (BuildKit prefers them over a context-root .dockerignore)
  fixtures/build_trees.sh          assembles the ephemeral scan trees (Appendix B of the plan) under .work/trees
  fixtures/expected.json           the hand-/openssl-derived oracle every spec judges the PDFs against (WP6b)
  scripts/                         preflight build up seed run-specs collect-evidence teardown all (+ lib.sh and two python helpers)
  seed/                            scan_trees.py, seed_team.py, plan.py, oracle_check.py, check_determinism.sh, dryrun_world.py (WP6b)
  fixtures.ts, lib/, specs/        Playwright fixtures, evidence + oracle libraries, the eleven specs (WP6b)
  selftest/oracle.spec.ts          offline proof that the oracle accepts real PDFs and rejects corrupted ones (WP6b)
  package.json, package-lock.json  @playwright/test pinned EXACTLY to 1.62.0
  playwright.config.ts             workers 1, retries 0, 1440x900 viewport and video, screenshots on, downloads accepted
  .work/                           git-ignored scratch (trees, scan outputs, seed.json); removed by teardown.sh
```

## Quick start

```bash
bash e2e/scripts/all.sh --teardown        # preflight -> build -> up -> seed -> specs -> collect -> teardown
bash e2e/scripts/all.sh --skip-build      # reuse the images, leave the stack up for inspection
bash e2e/scripts/teardown.sh              # remove every dss-e2e object, scratch and the generated .env.e2e
```

Run the steps one by one with `preflight.sh`, `build.sh`, `up.sh`, `seed.sh [--perf]`,
`run-specs.sh [playwright args]`, `collect-evidence.sh [--strict]`, `teardown.sh [--purge-images]`.
Every script is `set -euo pipefail`, prints what it does, and writes its own log under the evidence
directory. Long steps (image builds) run in the background with their own log and are waited on by
exit code; readiness is a bounded poll on a condition (container health, HTTP 200), never a blind sleep.

| script | what it does | refuses / fails when |
|---|---|---|
| `preflight.sh` | tool versions, daemon + `dss-fast` builder, disk/RAM/AVX, ports 43000/43080 free (`ss`), no leftover `dss-e2e` object, Playwright cache has the 1.62.0 revisions, compose file valid **and** policy-checked, committed inputs not drifted; snapshots `docker ps -a / volume ls / network ls` | any clash or failed check (exit 1) |
| `build.sh` | populates the gitignored `backend/_migrations` from `prod_database_migrations/`, generates `.env.e2e`, pulls the two stock images, builds the three images in parallel (`--builder dss-fast --load`), asserts no `.env` is inside them | a failed build or assertion; an image that fails its secret assertion is deleted |
| `up.sh` | `compose up -d --no-build`, waits for health + `/docs` 200 + `/login` 200, checks ports are loopback-only | a missing image, an unhealthy container, a non-loopback port |
| `seed.sh` | builds the trees, runs the real scanner in the `aibom-scan` container (no network), runs `seed_team.py`, writes a redacted copy of `seed.json` to the evidence logs | backend not healthy, WP6b seed code missing |
| `run-specs.sh` | `npm ci` (browser download disabled), checks Playwright 1.62.0 + cached browser revisions, runs `playwright test`, proves the browser cache did not change | stack not up/seeded, wrong Playwright version |
| `collect-evidence.sh` | harvests videos/screenshots, sidecars (`.sha256`, `.ffprobe.json`), backend no-egress proof, per-deliverable completeness, `reports/index.json`, `SUMMARY.md` | `--strict`: anything incomplete |
| `teardown.sh` | the only `down -v`; label-guarded; diffs the daemon against the preflight snapshot | an unlabelled object in the project, a foreign object that vanished |
| `all.sh` | the chain above; exit code is the worst step | |

## The stack

* Compose project name is exactly `dss-e2e`. Host exposure is **only** `127.0.0.1:43000` (frontend) and
  `127.0.0.1:43080` (backend). postgres and mongo are not published and live on the project network.
* Every object carries the label `com.dss-e2e=1`: containers, the three volumes
  (`dss-e2e_pgdata`, `_mongodata`, `_mongoconfig`), the network `dss-e2e_default`, and the built images.
* The backend mounts `compose/aibom-config-overlay` read-only at `/aibom/config`; without it the CBOM
  results page 500s (`get_scan_metadata` reads the rbi/cert-in rollup YAMLs from there).
* No RabbitMQ and no worker: seeded scans have `task_id=None`, so the backend never reaches Celery.
* The one-shot containers (profile `seed`) run as the invoking host uid:gid so the files they write
  into `.work/` stay deletable. `aibom-scan` also runs `network_mode: none`, a read-only root
  filesystem and no capabilities.
* `scripts/compose_policy.py` (called by `preflight.sh`) asserts the resolved compose model: exact
  published ports, labels on everything, no external objects, pinned images, `pull_policy: never` for
  our images, no privileged/host-namespace/docker.sock, no `MONGO_INITDB_*`.

### Security notes

* mongo runs **without authentication** (no `MONGO_INITDB_*` is ever set; that is also what makes
  `backend/get_db.py` use the no-auth URL). It is reachable only from the project network.
* The backend serves its OpenAPI docs unauthenticated; it is reachable only from loopback.
* `.env.e2e` holds random `openssl rand` values for the JWT/HMAC secrets, DB password and OTP, and
  **format-only dummy** `AWS_*` values (`backend/utilities/ai/chatbot.py` raises at import when they
  are unset). Nothing is ever copied from any repo `.env`, and the file is git-ignored with mode 600.
  `backend/.env` and `backend/utilities/ai/.env` ARE tracked in this repo and hold real AWS key ids;
  the E2E dockerignores keep them out of the images and `build.sh` asserts it.

## Docker safety rules (binding for everything in `e2e/`)

* Images are built with `--builder dss-fast --load`; **never `--push`**. The builder is never created,
  removed or pruned.
* **Never** `docker system|image|volume|buildx prune`. `down -v` exists only in `teardown.sh`, for the
  project `dss-e2e`, after its label guard. `--purge-images` removes only the three
  `dss-e2e/*:local` tags.
* Never touch `ai-dspm-dev-*`, `intelowl_*`, `buildx_buildkit_*`, any `dss-local/*` image or the
  `prod-worker-fix` worktree. `grep -rn "docker.*prune" e2e/` finds only comments (the one other
  hit for "prune" is `find -prune` inside an image assertion).
* Files are deleted only through `safe_rm_rf` (absolute path, resolved, must be inside
  `e2e/.work`, `e2e/test-results` or the generated `.env.e2e`).
* `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm ci`; **never `playwright install`**. 1.62.0 declares
  chromium / chromium-headless-shell **1234** and ffmpeg **1011**, exactly what is in
  `~/.cache/ms-playwright`; `run-specs.sh` diffs the cache listing before and after.
* Chromium on this host needs `--no-sandbox` (AppArmor restricts unprivileged user namespaces).
  Playwright's default `chromiumSandbox: false` supplies it; do not enable the sandbox.

## No LLM, no third-party calls

The CBOM lane is in-house: the scanner is deterministic pure Python and `aibom-scan` runs with no
network at all; the backend has dummy AWS values and no code path that calls AWS is exercised;
`collect-evidence.sh` decodes `/proc/net/tcp{,6}` of `dss-e2e-backend` and fails (`--strict`) if any
outbound peer is not postgres, mongo or loopback; the specs (WP6b) additionally assert that the browser
only ever talks to `127.0.0.1:43000` / `127.0.0.1:43080`.

## Images

| image | built from | notes |
|---|---|---|
| `dss-e2e/backend:local` | `docker/backend.e2e.Dockerfile` (= `backend/Dockerfile`, byte for byte) on context `backend/` | `.env` excluded by `docker/backend.e2e.Dockerfile.dockerignore`; `build.sh` first syncs `backend/_migrations` (gitignored, copied to `/prod_database_migrations`) |
| `dss-e2e/frontend:local` | `docker/frontend.e2e.Dockerfile` (= `frontend/Dockerfile`) on `frontend/`, `--build-arg NEXT_PUBLIC_BACKEND_URL=http://127.0.0.1:43080` | a fresh `next build`, so no stale-Turbopack problems |
| `dss-e2e/aibom-scan:local` | `docker/aibom-scan.Dockerfile` on `aibom/` (allowlist ignore file) | editable install like the worker, deps pinned to `aibom/uv.lock`; Python 3.12 |

`preflight.sh` fails if either verbatim Dockerfile copy drifts from its source (`cp` it again), or if
an E2E ignore file lost a line of the production ignore file.
`E2E_BUILD_CTX_MODE=copy bash e2e/scripts/build.sh` builds backend/frontend from a sanitized rsync
copy under `.work/` instead; use it only if BuildKit ever stops honouring the per-Dockerfile ignore
(the post-build assertions would say so).

## Evidence directory

`E2E_EVIDENCE_DIR` or, by default, `<main checkout>/.agents/tasks/cbom-medium-renderers-evidence/`
(untracked; derived from `git rev-parse --git-common-dir`, so it resolves to the main checkout when
run from this worktree):

```
videos/ screenshots/ downloads/ pdf-pages/ logs/ reports/   + SUMMARY.md (generated)
logs/00-preflight.txt 01-build*.txt 02-up.txt 03-seed.txt 04-specs.txt 05-collect.txt 06-all.txt 80-no-egress-proc-net-tcp.txt 90-teardown.txt
logs/docker-{ps,volume,network}-{before,after}.txt  playwright-cache-{before,after}.txt
reports/playwright.json  reports/html/  reports/index.json
```

Artefact naming that `collect-evidence.sh --strict` checks for each of the six deliverables
(`NN` = 07, 16, 03, 15, 01, 10; slugs as in the plan): `videos/NN-<slug>.webm` (>= 10 s, 1440x900),
`screenshots/NN-*.png` (>= 5), `downloads/NN-*.pdf` (+ `.sha256`, written by the collector),
`logs/NN-*pdfinfo*`, `NN-*pdftotext*`, `NN-*pdffonts*`, `NN-*api*`, `pdf-pages/NN-*.png`,
`logs/pytest-NN*`, and a passing Playwright test whose spec file starts with `NN-`. Playwright's own
per-test video/screenshot attachments are copied to `videos/<spec>.webm` / `screenshots/<spec>-auto-NN.png`
when a spec did not already save them under its own name. Playwright empties its `outputDir`
(`<evidence>/test-results`) on every run, which is why that is a sub-folder and not the evidence root.

## Contract for WP6b (seed + specs)

Environment given to the one-shot containers (`docker-compose.e2e.yml`):

| service | mounts | env | command |
|---|---|---|---|
| `aibom-scan` | `.work/trees` -> `/work/trees` (ro), `.work/out` -> `/work/out`, `e2e/seed` -> `/e2e/seed` (ro) | `E2E_TREES_DIR=/work/trees`, `E2E_OUT_DIR=/work/out` | `python /e2e/seed/scan_trees.py` (writes `<tree>.scan_data.json`) |
| `seed` (backend image) | `.work` -> `/work`, `e2e/seed` -> `/e2e/seed` (ro), `e2e/fixtures` -> `/e2e/fixtures` (ro, added by WP6b: `expected.json`), `backend/tests/fixtures` -> `/e2e/backend-fixtures` (ro) | `E2E_WORK_DIR=/work`, `E2E_LEGACY_SCAN_DATA=/e2e/backend-fixtures/cbom_export_scandata.json`, `E2E_SEED_PERF=1` with `seed.sh --perf`, plus `.env.e2e` | `/backend/.venv/bin/python /e2e/seed/seed_team.py` (writes `/work/seed.json`) |

Trees produced by `fixtures/build_trees.sh` (all dated relative to the run day): `payments-service-v1`,
`payments-service-v2`, `identity-gateway`, `crypto-misuse-lab`, `pqc-pilot`, `vendor-sdk-manifests`,
`cert-lifecycle-lab` (`expired.crt` -35 d, `expiring-soon.crt` +20 d) and `other-team-app`
(`other-team-canary.crt`, team 2 only). The script self-checks the independent oracle: 17 certificate
files across the team-1 trees give 14 unique SHA-256 fingerprints, bands 1 expired / 1 <=30 d / 12 valid.

`.env.e2e` keys (names only): `POSTGRES_USER/PASSWORD/DB`, `PG_USER/PG_USER_PASS/PG_DB/PG_HOST/PG_PORT`,
`MONGO_HOST/PORT`, `IS_DOCKER_CONTAINER`, `CORS_ORIGINS`, `JWT_SECRET_KEY`, `JWT_REFRESH_SECRET_KEY`,
`CERTIN_HMAC_SECRET`, `DSS_DEV_MODE=1` (required for the next two; also set on the backend service),
`LOCAL_DEV_VERIFICATION_EMAIL/CODE` (fixed OTP for the admin user, no mail is sent; accepted only by a
`DSS_DEV_MODE=1` backend and never by `/reset_password`), `RABBIT_ADMIN_USERNAME/PASSWORD` (dummy), `AWS_ACCESS_KEY_ID/SECRET_ACCESS_KEY/DEFAULT_REGION`
(dummy), and the seed identities `E2E_ADMIN_EMAIL/PASSWORD`, `E2E_OTHER_EMAIL/PASSWORD`,
`E2E_EMPTY_EMAIL/PASSWORD`. The admin email equals `LOCAL_DEV_VERIFICATION_EMAIL`.

`run-specs.sh` exports `E2E_EVIDENCE_DIR`, `E2E_BASE_URL` (frontend), `E2E_API_URL` (backend),
`E2E_WORK_DIR` (host path of `.work`) and `E2E_SEED_JSON` (`.work/seed.json`). `playwright.config.ts`
also honours `E2E_TEST_DIR` (spec directory override, for local debugging). The backend rate limiter
allows 30 PDF requests per 60 s per token, so specs must pace downloads (>= 1.5 s apart).

## Seed, oracle and specs (WP6b)

### The world that is seeded

`seed/plan.py` writes plan Appendix B down as data and `seed/seed_team.py` stores it through the product's own
code: users with `get_hashed_password`, teams and memberships, 14 scans with **explicit ids equal to the
Appendix-B numbers** (the PDFs print "scan #4"), `created_at = now - age_days`, `task_id = None`,
`scan_metadata` shaped like `metadata.py`, and the real `create_findings_in_mongo_db` for every success scan.
`scan_data` is what `seed/scan_trees.py` produced in the `aibom-scan` container with
`scan_crypto_to_devsecshield(path, level=4)`; the Tier-B legacy scan is the committed
`cbom_export_scandata.json`. Teams: 1 "E2E Demo Team" (admin persona), 2 "Other Team" (canary certificate,
other persona), 3 "Empty Team" (empty persona), 4 "Perf Team" (`seed.sh --perf`: 200 scans, 40 sources,
1 007 unique certificates). The stack must start from fresh volumes; the seed refuses a database that already
holds teams, users or scans (exit 3).

Before it stores anything, the seed verifies Appendix B with an **independent oracle**
(`seed/oracle_check.py`, plain code, no product aggregator, plus the DER SHA-256 of the certificate files).
A drifting scanner, fixture or date therefore fails at seed time (exit 4) with the differing quantity named.
`seed.json` (mode 600) is the hand-over to the specs: ids, personas with their throw-away credentials, and
every scan's `created_at`.

Personas log in through the real `POST /login`. The admin's one-time code is the backend's
`LOCAL_DEV_VERIFICATION_CODE`; the other two get a 24-hour one-time-code row in `verificationcode`. A login
consumes it, so `lib/api.ts` caches the tokens in `.work/auth-cache.json` (mode 600, keyed by `seeded_at`) and
renews them through `POST /refresh`.

### `fixtures/expected.json`

Every literal is hand- or openssl-derived: Appendix B's numbers re-derived by `oracle_check.py`; the 14
certificates from `openssl x509 -text` over the 17 files; the library table, QSL table and requirement counts
by plain counting; public text (NIST / CNSA timeline, URLs, disclaimers, framework labels) from plan
Appendix C and the pre-existing product constants. Date-relative values are **not** stored: first/last seen, ages
and the data window come from `seed.json`, the two authored certificates' validity from `openssl` on the files in
`.work/trees`, the report date from the PDF's own "Generated" line. `freshness.oracle_valid_through`
(2027-03-30) is the day `synthetic-crypto-app/cert.pem` enters the <=90-day band; both the seed and the
certificate check fail with that explanation afterwards.

`python3 e2e/seed/oracle_check.py` proves `expected.json` against `backend/tests/fixtures/
cbom_team_rollup_scans.json` (the real scanner output at its frozen date); run it whenever the scanner, the
fixture trees or the file change.

### The specs (`specs/`, sorted so the one that changes data runs last)

| spec | proves |
|---|---|
| `00-login-ui` | the real form: wrong one-time code refused (400), right code lands on `/home` with both tokens, the session opens `/1/cbom`; the bundle logs the E2E backend URL |
| `01`, `03`, `07`, `10`, `15`, `16` | one deliverable each, **runnable alone** (`npx playwright test specs/07-certificate-estate-register.spec.ts`): menu -> download -> `X-Cbom-*` headers -> poppler -> the pages shown in the recorded page -> every expected string and count matched in the **PDF text** -> canaries absent |
| `17-style-parity` | the existing single-scan "PDF Report" next to the six new PDFs: page-1 contact sheet, `pdffonts` of every new PDF is a subset of the existing report's, same brand header |
| `90-negative-isolation` | 401 (no / bad / wrong-scheme token), 403 (another tenant), own-team 200 with its own canary and none of team 1, 404 / 422, canaries and URL credentials absent, empty team in the UI (disabled items, inert click, banner PDFs) and over the API |
| `91-attestation-before-after` | the #10 ledger moves from "Attested 0/5" to "Attested 1/5" with file, note and date after an upload to scan #2; #3 and #16 pool the new verdict (OMB 80.0% -> 81.8%). **Changes the seeded data once** (see its header); reseed to repeat |
| `92-perf` | every PDF within its budget: demo team 3 s (x3), perf team 10 s, 15 s for a register beyond the 2 000-row cap |

Each spec writes its evidence under `E2E_EVIDENCE_DIR` with the number prefix the collector looks for
(`screenshots/07-...-NN-label.png`, `downloads/07-<slug>.pdf`, `logs/07-api.json`, `07-pdfinfo.txt`,
`07-pdftotext.txt`, `07-pdffonts.txt`, `07-oracle.json`, `07-console.json`, `07-egress.json`,
`pdf-pages/07-<slug>-pNN.png`, `viewer-07.html`). The `egressGuard` fixture aborts and fails on any request
outside `127.0.0.1:43000` / `127.0.0.1:43080` (plus `data:`, `blob:` and the local evidence viewer);
the `consoleLog` fixture fails a spec on an uncaught page error or an HTTP 5xx.

### Offline rehearsal (no Docker)

`selftest/oracle.spec.ts` runs the very oracle the specs use against PDFs produced by
`seed/dryrun_world.py` (the real seed code against a SQLite file, the real renderers) and then proves the
oracle can fail: 15 corrupted copies must each be rejected.

```bash
WT=$PWD; bash e2e/fixtures/build_trees.sh                              # trees under e2e/.work
E2E_TREES_DIR=$WT/e2e/.work/trees E2E_OUT_DIR=$WT/e2e/.work/out PYTHONPATH=$WT/aibom/src \
  <aibom venv>/bin/python e2e/seed/scan_trees.py
PYTHONPATH=$WT <backend venv>/bin/python e2e/seed/dryrun_world.py --out /tmp/dss-dryrun
cd e2e && E2E_SELFTEST_DIR=/tmp/dss-dryrun E2E_SEED_JSON=/tmp/dss-dryrun/seed.json \
  E2E_EVIDENCE_DIR=/tmp/dss-selftest E2E_TEST_DIR=$PWD/selftest npx playwright test
```

`dryrun_world.py --serve PORT` additionally serves the real FastAPI app (all routers) over HTTP from that SQLite
file, so the browser specs can be rehearsed against a `next dev` frontend on other ports
(`E2E_BASE_URL`, `E2E_API_URL`) without the stack. That is a debugging aid only; the proof is the Docker run.

### Known behaviours of the product worth knowing when a spec fails

* `DELETE .../attestations/...` removes the record but leaves the verdict at "pass with evidence"
  (`recompute_compliance_for_scan` only ever flips verdicts forward), so spec 91 cannot undo itself.
* The attestation routes do not touch `Scan.last_updated`, so the data fingerprint also hashes the attestation
  records of the included scans (addendum A-2): one `(scan_id, framework, req_id, uploaded_at)` entry per record,
  sorted, appended after the `scan_id:last_updated` list only when at least one record exists. An upload therefore
  moves the fingerprint, and with it the Document ID suffix of all six documents of the team (the fingerprint is
  team-wide), as the methodology (#3) says. A scan set without attestations keeps its old value (`6a1e31ae946c`
  for the unit fixture). Spec 91 asserts that the value changes and records both values.
* New passwords are 8 to 128 characters (`POST /login` accepts 1 to 128); the generator makes 20.

## Troubleshooting

* `preflight.sh` says a port is in use: something else listens on 43000/43080; stop it or wait. The
  harness never kills foreign processes.
* `preflight.sh` reports leftover `dss-e2e` objects from an earlier run: `bash e2e/scripts/teardown.sh`.
* A build fails on a registry pull: Docker Hub / ghcr / npm / PyPI must be reachable; re-run `build.sh`
  (layers are cached on the `dss-fast` builder).
* `docker compose -p dss-e2e -f e2e/compose/docker-compose.e2e.yml config -q` validates the compose file
  without `.env.e2e`. Do not run plain `config`: once `.env.e2e` exists it prints the secrets.

## Observation worth knowing

`pip install ./aibom` (a wheel build) currently fails with a recent hatchling: `pyproject.toml` lists
`src/aibom` under `packages` and also force-includes `src/aibom/schemas` and `src/aibom/dashboard`,
which hatchling now rejects as duplicate wheel entries. The worker avoids it by installing aibom
editable, and so does `docker/aibom-scan.Dockerfile`. No file under `aibom/` was changed here.
