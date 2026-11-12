# Round 5 plan v2 (after 5 adversarial reviews + devil's advocate)

Base: branch `ansh` at `ee5aa54` (adds extension seams: `scripts/crypto_kb/kb_ext/`, `backend/utilities/cbom_sources/classify_ext/`
with `classify.register()`, node `jobctx.register_asset_types()`). v1 plan: `PLAN.md` in this folder (still the evidence base;
v2 overrides it where they differ).

## User decisions
- D0 scope: everything in the guide (7 open items, known issues, smaller points, air-gap limits, 21 capabilities).
- D-Lambda/Glue: opt-in in the reader template, off by default, proven in a small AWS lab (destroyed after).
- D-Passwords: Argon2id, 128-character limit.
- D-Staging: production deploy files in the repo; the user runs them.
- D1 fixed sign-in codes: keep them behind a dev-only flag: they work only when `DSS_DEV_MODE=1` is set on that server, and
  never on password reset.
- D2 secrets: keep the tracked `.env`/`.pem` files tracked; stop baking them into images (.dockerignore), add `.env.example`
  files and a rotation list. Do NOT `git rm` them.
- D3 minimum charge: 1 credit per CBOM code scan (repo or zip). Uploaded CBOM files keep the flat 0.01.
- D4 Azure/GCP: the user will give sandbox access; build the collectors now, prove later.

## Devil's-advocate outcomes (these override v1)
1. Rate limiting: NOT a Postgres limiter. In-process limiter (own small module, sliding/fixed window, periodic sweep, key cap),
   keyed on the VERIFIED JWT `sub` (or verified CI key id / node id), falling back to the client IP (IPv6 by /64,
   `::ffff:` normalised). Client IP = `request.client.host` only (uvicorn already applies gunicorn `forwarded_allow_ips`;
   set `FORWARDED_ALLOW_IPS` from deployment config, never parse X-Forwarded-For in app code; fix `cbom_sources/http.py:79-83`).
   Security-critical counters live in Postgres instead: one live sign-in code per email, failed attempts per email (lock
   the codes after 5), `send_code` per email, atomic consume (`DELETE … RETURNING`). Per-worker limits are documented.
   429 responses carry `Retry-After`. Frontend: back off and keep polling on 429; a 429 on `/refresh` retries, never logs out;
   single-flight refresh.
2. Trap scoring in the lab scorer: a trap counts as hit only when a component at that path carries a weakness finding code
   (QUANTUM_VULNERABLE is inventory, not a weakness: ground truth marks those traps `quantum_vulnerable: true`); count per
   component, not per occurrence; precision includes spurious rows (the scorer's own comment at `score_cbom.py:403` says
   so); manual items (COD-187/188) excluded explicitly. The scorer reads finding codes from the downloaded CycloneDX file,
   so the code-scan export must carry them. Report old-rule and new-rule numbers side by side.
3. Vendored/build directories (`vendor/`, `dist/`, `build/`, `node_modules/`): scanning them is an opt-in scan option
   (default off). Lab measured both ways and reported honestly.
4. Lambda switch semantics: "Also decrypt Lambda environments encrypted with a customer-managed KMS key". Default-key
   environments are inspected as today (ListFunctions returns them to SecurityAudit; shape only is kept).
5. Clean rows: one read-time rule, not a stored-data change. A row is a finding only if it has weakness codes; legacy rows
   with no `finding_codes` key keep their impact. Inventory distributions stay over all rows.
6. Argon2 default on; rollback to an image without Argon2 locks out rehashed users — written in the deploy notes.
7. JWT secrets: the backend refuses to start when the two JWT secrets are equal or shorter than 32 bytes, unless
   `DSS_DEV_MODE=1`.

## Rules for every work package (agents)
- Work only in your own worktree/branch. Commit there with explicit pathspecs (never `git add -A`, never `git stash`, never
  `--no-verify`, never push, never amend or force). Commit message ends with:
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_01SDCVQSqoacevwbyX9VGquR`.
- Never open, print, or copy the contents of any `.env*` or `*.pem` file (listing names is fine). Exclude `.env*` from greps.
  Never commit secrets, `scan_node/.venv`, `zs-node-state`, node_modules or build output.
- Python envs live in the MAIN checkout (not tracked, so not in your worktree): backend `/home/claude/devsecshield/backend/.venv`,
  engine `/home/claude/devsecshield/aibom/.venv`, scan node `/home/claude/devsecshield/scan_node/.venv`, worker
  `/tmp/claude-0/wvenv`. Run them against YOUR worktree's code (cd into your worktree; set PYTHONPATH to your worktree root
  and `<worktree>/aibom/src` as needed). Frontend: symlink `<worktree>/frontend/node_modules` to
  `/home/claude/devsecshield/frontend/node_modules` (do not commit the link) and run `npx tsc --noEmit`.
  New Python packages: add to the right `pyproject.toml` and lock (`uv lock` / pip) — they must be pure-Python or have
  manylinux wheels and work offline once in the image. Install into the shared venv only additively.
- Machine: 2 vCPU, 7 GB RAM, ~12 GB free disk, shared with other agents. Run focused tests, not whole suites in a loop;
  `timeout` long commands; delete large temp files you create; don't pull Docker images over 1.5 GB without need.
  Docker: no daemon runs between commands. When you need containers, start `dockerd` inside the same bounded command
  that uses them (`dockerd >/tmp/.../wp<N>-dockerd.log 2>&1 & … wait until docker info works … your steps … docker compose
  down / docker rm -f … kill that dockerd`), wrapped in `timeout`, and make sure it is stopped when the command ends.
  Images already pulled stay on disk. Name containers `wp<N>-*`.
- New knowledge-base codes go in `scripts/crypto_kb/kb_ext/<your_area>.py` (see README there); new classifier asset types in
  `backend/utilities/cbom_sources/classify_ext/<your_area>.py` via `classify.register()`; new node asset types via
  `jobctx.register_asset_types()`. Do NOT rebuild `crypto_kb.json` (the integrator does it once); your tests may build a KB
  into a temp file with `scripts/crypto_kb/build_kb.py <version> <out>`. Every new code also needs: a demo family in
  `backend/utilities/cbom_sources/exploit_demo.py` `_BY_CODE` (test_every_kb_code_gets_a_demo_or_read_only_proof), and, for
  code-scan codes, the backend label/severity tables (`cbom_posture_text.py`, `cbom_rows.CONFIG_CODES`, roll-up severity map)
  when they apply. The shipped KB is now version 2026.11.02.1 (includes WP3a's PROVIDER_MANAGED_KEY, EOL_BASE_IMAGE).
- New DB columns/tables: one Alembic revision in `prod_database_migrations/migrations/versions/` with
  `down_revision = 'e3b7c9a1cs03'` and a revision id starting with your package id (e.g. `wp1a…`); the integrator re-chains.
  Update the SQLModel models in `backend/new_models.py` (and `sqllite_migrations` if the repo keeps them in step).
- New frontend API calls go in a new file `frontend/utils/api/<area>.ts` using the axios instance from
  `frontend/utils/interceptors.js`; keep edits to `backend_api.ts` minimal.
- Root cause, not workaround. Keep it simple. Every behaviour change gets tests (unit + an API/integration test where the
  path exists). Evidence over assumption: when a claim depends on external behaviour (AWS, a protocol), cite the doc or test it.
- Log security-relevant events with the standard logger (no `print`, no secrets, no emails in plain logs beyond what the
  existing redaction filter allows).
- Finish with a short report: what changed (files), tests run with counts, anything not done and why, risks. Max 600 words.

## Work packages
WP1 auth+limits · WP2 engine foundation · WP3a engine IaC/deps/data · WP3b engine code detectors · WP4 cloud collectors ·
WP5 node core · WP6 node DB/HSM/PKI · WP7 node network/OT/appliance/mesh · WP8 images/binaries/agent mode ·
WP9 outputs A · WP10 outputs B · WP11 integrations · WP12 deploy+hygiene.
Briefs: `wp/WP<N>.md` in this folder.
