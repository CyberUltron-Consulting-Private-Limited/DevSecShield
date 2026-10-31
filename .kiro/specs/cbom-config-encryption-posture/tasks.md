# CBOM Config Encryption Posture Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Use superpowers:test-driven-development for every product change. Use superpowers:verification-before-completion before checking any box. Do not check a box until the evidence named in that task exists.

**Goal:** Add a deterministic, air-gapped CBOM posture lane that turns configuration, infrastructure-as-code, server configuration and customer-produced TLS result files into Encryption_Facts, ordinary CycloneDX crypto assets, ten posture findings, a `cbom_posture` run-object key, and team PDFs #5, #6 and #9.

**Architecture:** Seven new CBOM scanners (orders 31, 32, 33, 34, 36, 38, 45), all `level = 1`, stay thin. Library code lives in `aibom/src/aibom/cbom/posture/`. Facts travel as `infra` components with `crypto:fact*` properties. Diagnostics, imports and counts travel on `CbomScanContext` / `CbomScanResult` subclasses so `ScanResult` and `aibom/scan/**` stay untouched. `normalize_crypto` emits `cbom_posture`. The backend roll-up and three PDF renderers consume that block. `scale.max_raw: 112` keeps existing scores stable.

**Tech stack:** Engine Python `>=3.11` (stdlib, pydantic, pyyaml only). Backend Python 3.10 and reportlab. Frontend change is three entries in `frontend/utils/backend_api.ts`. Data files are UTF-8 JSON under `aibom/src/aibom/cbom/data/`, loaded with `importlib.resources`. Tests: pytest, ruff, mypy, Playwright 1.62.0, Docker Compose v2.24.4+.

**Source of truth:** `requirements.md` (R1–R52) and `design.md` (D-1–D-30, sections 3–17). This file is the execution plan. When they disagree, requirements win, then the design's recorded corrections in design section 17.

**Base_Commit:** `f7385517523212e50b20ec6f1947831a5ef19872` (HEAD of `feat/cbom-team-deliverables` in `.worktrees/cbom-team-deliverables`). Verified 2026-10-26: that worktree is exactly that commit; `scanners/__init__.py` imports nine modules and no posture scanner; `crypto-risk-weights.yaml` `scale:` has `bands` and no `max_raw`; `CBOM_DELIVERABLES` has the six slugs below. The checkout this plan was written from is `ansh` at `29e8c876`, which does **not** contain the MEDIUM deliverables. Product code is written only in a new worktree (task 1).

**Branch:** `ansh`. On 2026-10-26 it was fast-forwarded from `29e8c876` to `f7385517523212e50b20ec6f1947831a5ef19872` by merging `feat/cbom-team-deliverables`. `backend/utilities/pdf/cbom_deliverables.py` is present. The branch is 16 commits ahead of `origin/ansh` and has not been pushed. `git stash` is forbidden. No `.env` is staged. No hook is skipped.

**Status of this plan:** planning artifact only. No product code, fixture, test, CI file or Docker object was created while writing it. Every checkbox below is open, including the 441 criterion rows. A checkbox stays open until the named test output and evidence file exist. Section 0 is unanswered. Do not start task 1 until those answers are recorded in `.agents/tasks/cbom-high-deliverables-evidence/reports/plan-confirmation.md`.

---

## 0. Plan confirmation (blocks every later task)

The design treats D-1 through D-29 as final unless vetoed here. D-30 is explicitly waiting. Answer these before task 1. The recommended default is the design. Record the answers in `.agents/tasks/cbom-high-deliverables-evidence/reports/plan-confirmation.md` (untracked). If an answer differs from the default, amend `design.md` in the same note before any package starts; do not silently diverge.

- [x] 0.1 Confirm the worktree rule
  - **Done 2026-10-26.** Work stays on `ansh`. `git merge feat/cbom-team-deliverables` fast-forwarded `29e8c876` to `f7385517523212e50b20ec6f1947831a5ef19872`. `backend/utilities/pdf/cbom_deliverables.py` is present. Not pushed.
  - _Was: a new worktree and branch `feat/cbom-high-deliverables`. Requirements: 52.1_

- [x] 0.2 Confirm D-30, the dashboard crypto-asset count
  - **Decided 2026-10-26: count every component, including facts.** Do not edit `backend/utilities/dashboard/scan.py`. D-30 is rejected. `test_cbom_posture_consumers.py` asserts the card total includes components that carry `crypto:factSchema`. Adding the filter would be the defect, so mutant M54 is retired.
  - _Was: skip fact components. Requirements: 30.7, 51.2. Design: D-30_

- [x] 0.3 Confirm or veto D-13 (OI-4)
  - **Decided 2026-10-26: amend both.** Change `SCOPE_OF_METHOD` and method-limits bullet 4 so documents #3 and #16 agree with document #9. The Board prints both, so every team's Board changes. Task 0.16 amends two further sentences.
  - _Requirements: 39.1, 39.6, 39.7_

- [x] 0.4 Confirm OI-6
  - **Decided 2026-10-26: project, including Jira.** A fact component that carries at least one `POSTURE_CODES` flag becomes one `results[]` row through the existing `_finding` shape in `normalize.py`. `create_findings.py` already copies every `results[]` row into `scan_findings` for `cbom`. `jira_ticketing.py` already tickets every `scan_findings` row, with no code filter, so do not edit it and do not add a posture exclusion. A fact with no posture finding stays out of `results[]`. `cbom_graph` and `cbom_distributions` still exclude fact components. A contract test asserts a posture row is eligible for that Jira loop.
  - _Was: do not project. Requirements: 30.7. Assumption A-10 is overridden for `results[]` and the findings store only._

- [x] 0.5 Confirm OI-7
  - Pin `scale.max_raw: 112` (the Base_Commit weight sum). Ten new weights sum to 57. Without the pin the divisor becomes 169 and every existing score drops. With the pin, a scan with many posture findings can reach `risk_normalized` 100. Recalibration is a later decision.
  - **Decided 2026-10-26: pin 112.** Requirements: 28

- [x] 0.6 Confirm OI-5, the air-gap proof shape
  - **Decided 2026-10-26: full stack.** This amends D-12. Keep the internal network, the gateway, and the egress failures. Also add RabbitMQ, the scan worker, and an S3-compatible object store addressed by `AWS_ENDPOINT_URL_S3`, and prove a zip upload through the UI. The `/proc/net/tcp` allow-list grows to postgres, mongo, RabbitMQ, the object store, and loopback. A public address still fails the run.
  - _Was: overlay, no worker. Requirements: 43, 47.1_

- [x] 0.7 Confirm the remainder of OI-1
  - The design authors the rows that can raise a finding from an absent attribute (ten `assessable` rows, three `finding_default` rows) plus the TLS policies the fixtures use. Remaining rows are written in WP5 under design section 4.6.6. A row raises a finding from an absent attribute only when a second person adds it to `aibom/tests/cbom_posture_reviewed_rows.txt`.
  - **Decided 2026-10-26: reviewed rows only.** Requirements: 9, 15.2

- [x] 0.8 Confirm the finding-derivation split (design section 17, item 38)
  - Read literally, R6.9 and R15.2 say an UNKNOWN verdict empties the finding set. R11.7, R21.7 and R23.3 require `TLS_VERIFICATION_DISABLED` and the key-governance codes from an explicit signal even when the transport verdict is UNKNOWN. The design splits codes: verdict-derived (`UNENCRYPTED_AT_REST`, `UNENCRYPTED_IN_TRANSIT`, `PLAINTEXT_LISTENER`) stay empty on UNKNOWN; the other seven fire only from an explicit signal.
  - **Decided 2026-10-26: accept the split.** Requirements: 6.9, 11.7, 15.2, 21.7, 23.3

- [x] 0.9 Confirm K-18 and K-20
  - A Google Cloud KMS key with no `rotation_period` is UNKNOWN `default_unknown` and raises no `KMS_KEY_ROTATION_DISABLED` (no vendor page states the omission). Every `azurerm_key_vault_key` records rotation as `not_applicable` because R11.4 treats asymmetric keys that way and the design does not read `rotation_policy`.
  - **Decided 2026-10-26: accept both.** Requirements: 11.4

- [x] 0.10 Confirm OI-8
  - Paths whose segments are `test`, `tests`, `__tests__`, `spec`, `fixtures`, `testdata`, `example`, `examples`, `sample`, `samples`, `docs`, `e2e`, `dev`, `local` or `sandbox` are labelled `non_production_hint`. Severity does not change.
  - **Decided 2026-10-26: label only.** Requirements: 5.8

- [x] 0.11 Confirm the byte-identical boundary
  - **Decided 2026-10-26: a file outside the original allow-list may change only when `requirements.md`, `design.md`, or a recorded decision requires that file.** `backend/utilities/dashboard/scan.py` and `jira_ticketing.py` stay unchanged, because the decisions say the current code already counts every component and already tickets every finding. The frozen modules stay unchanged unless a requirement cannot be met without them; stop and name the file before such an edit. `emit/cyclonedx.py` may still take the one family-map edit.
  - _Requirements: 1, 13.9, 29, 31.6, 42.8, 45.8, 51_

- [x] 0.12 Confirm the release boundary
  - This spec ends at the evidence directory, the build report and the production runbook. No image is deployed. Restoring the scan worker (A-14) is a rollout precondition, not a task here.
  - **Decided 2026-10-26: stop at evidence, the build report, and the runbook. Do not deploy.** Requirements: 52.3, 52.4. Assumption A-14


- [x] 0.13 Confirm the performance-team budget (design section 17, item 41)
  - Requirement 49.5 says the performance team answers within 10 seconds. Measured PDF cost puts that one call at about 11 to 13 seconds with plain table cells, so the design recalibrates it to 15 seconds. The 3 second demo budget, the 15 second register-cap budget, and the 512 MiB growth limit stay as written.
  - **Decided 2026-10-26: 15 seconds.** Requirements: 49.5

- [x] 0.14 Confirm where the slug contract runs (design section 17, item 48)
  - Requirement 46.6 names the slug contract in the frontend job. The contract is pytest `test_frontend_menu_equals_the_backend_registry`, which needs the backend environment. The design runs it in the backend job. The frontend job runs `tsc --noEmit` and `eslint_delta.py`.
  - **Decided 2026-10-26: backend job.** Requirements: 46.6

- [x] 0.15 Confirm the Board grade input (design section 17, item 49)
  - Count current posture facts that carry at least one finding, bucketed by stacked impact. Print "Configuration posture findings: N (R resources, M sources not assessed)". Do not add one grade point per finding.
  - **Decided 2026-10-26: count facts that carry findings, and print all three numbers.** Requirements: 39.2

- [x] 0.16 Confirm the two MEDIUM statements that stay (design section 17, item 50)
  - **Decided 2026-10-26: amend both, with these sentences.** Method-limits bullet 3 becomes "Declared KMS and HSM settings in configuration are assessed. Live HSM firmware, custodianship, and escrow are not inspected." The manual-discovery item becomes "Whether stored data is actually encrypted. Declared settings are assessed in document #9 and are not proof of operation."
  - _Was: leave both. Requirements: 39.6_

---

## How a task is executed

Every package below follows the same cycle. Do not skip a step.

1. Write the failing tests named in the task. Commit them only when the design says the red run is stored off-tree (`wp-<id>-red.txt`). Do not leave the shared branch red (design section 13.3, data-package rule).
2. Run the test. Expected: FAIL for the reason named in the task.
3. Write the minimal implementation. Binding signatures in design sections 3.5 and 3.7 are not optional. A type from a later package is never named, including in a string annotation (D-27).
4. Run the test. Expected: PASS.
5. Run the boundary suite named in the task. A red test that belongs to another package is a graph defect, not an accepted state.
6. Commit with an explicit pathspec:

```bash
git add -- <owned paths>
git commit -m "$(cat <<'EOF'
<package>: <why>

WP: <id>
EOF
)" -- <owned paths>
```

Forbidden: `git add -A`, `git add .`, `git commit -a`, `git stash`, `git reset`, `git checkout -- .`, `--amend` of a commit another package built on, `--no-verify`. On `index.lock`, retry up to 5 times, 3 seconds apart. Do not delete the lock.

Engine tests: `aibom/.venv` (Python 3.11+). Backend tests: `backend/.venv` (Python 3.10). Neither environment gains a dependency. New engine modules must pass `ast.parse(..., feature_version=(3, 11))`. New backend modules must import on Python 3.10. Ruff line length is 88 on `src/aibom/cbom` and 100 on new backend files. Do not ruff-format anything under `tests/fixtures`.

Pairs (D-26) are one commit with both pathspecs and both `WP:` trailers: WP7 with WP7b, WP12 with WP13.

---

## 1. WP0 — worktree, goldens, import graph

Depends on task 0. Owns the files in design section 13.2 row WP0. Requirements: 1.6, 44.4, 46.1, 46.2, 51, 52.1.

- [x] 1.1 MEDIUM base is on `ansh`
  - Fast-forward merge of `feat/cbom-team-deliverables`. `git rev-parse HEAD` is `f7385517523212e50b20ec6f1947831a5ef19872`. `backend/utilities/pdf/cbom_deliverables.py` exists. No product posture code was added in this commit.
  - _Requirements: 52.1_

- [x] 1.2 Capture Frozen_Goldens before any product change
  - Create `aibom/tests/support/make_goldens.py`, `baseline_counts.py`, `base_commit.py`.
  - For each of the 18 `synthetic-crypto-*` trees, write SHA-256 of canonical JSON (`sort_keys=True`) for `scan_crypto(...).to_dict()`, `normalize_crypto(...)` minus `duration_of_scan`, and `emit_cyclonedx(...)`.
  - Commit `aibom/tests/fixtures/frozen_goldens/base_commit_digests.json`, `adapter_signature.txt` (`inspect.signature(scan_crypto_to_devsecshield)`), and `baseline_counts.json` (per-file pass/skip/fail of the pre-feature suite, chroma clone absent).
  - `baseline_counts.py` prints `not comparable: chroma clone present` and exits 0 when `aibom/tests/fixtures/chroma` exists. CI, which has no clone, is the comparison that counts.
  - Create `aibom/tests/test_cbom_posture_frozen_goldens.py`. It recomputes the three digests and fails on any difference. `cbom_posture` is excluded from the run-object digest once it exists.
  - Run: `cd aibom && uv run python -m pytest tests/test_cbom_posture_frozen_goldens.py -q`
  - Expected at this commit: PASS against the just-captured digests. Store the log at `.agents/tasks/cbom-high-deliverables-evidence/reports/wp-00-green.txt` (untracked).
  - _Requirements: 46.1, 46.2, 26.6, 28.2, 29.1_

- [x] 1.3 Capture MEDIUM PDF text and fixture pins
  - `backend/tests/support/pdf_text.py` and `base_commit.py`.
  - `backend/tests/fixtures/make_medium_base_text.py` extracts the six MEDIUM documents built from the committed `cbom_team_rollup_scans.json` view at a fixed time into `medium_base_text.json`.
  - `backend/tests/fixtures/base_commit_fixture_digests.json` pins the SHA-256 of `cbom_team_rollup_scans.json`.
  - `backend/tests/test_cbom_posture_fixture_pins.py` fails if that blob changes.
  - Run with `backend/.venv`: `python -m pytest tests/test_cbom_posture_fixture_pins.py -q`
  - Expected: PASS.
  - _Requirements: 39.1, 46.1_

- [x] 1.4 Import-edge checker
  - Create `aibom/tests/support/wp_graph.py` with `OWNER`, `EDGES`, `PAIRS`, `ancestors`, `project_imports`, `violations` exactly as design section 3.1.5.
  - Create `aibom/tests/test_cbom_posture_wp_graph.py`.
  - Controls that must be reported: a WP1 module importing a WP2 module; the same under `TYPE_CHECKING`; a relative import of a later module; an import inside a function; a cycle; a module with no owner.
  - Controls that must pass: same-package import, earlier-package import, pair partner.
  - Modules that do not exist yet are skipped, so the test is green at WP0.
  - Assert `EDGES` is acyclic and names every work package of section 13.2.
  - Run: `cd aibom && uv run python -m pytest tests/test_cbom_posture_wp_graph.py -q`
  - Expected: PASS. This test is the first step of `.github/workflows/cbom-posture-gates.yml` later.
  - _Requirements: 44.4, 1.2_

- [x] 1.5 Commit WP0
  - Pathspec is only the WP0 row. Message trailer `WP: 0`.
  - Boundary: `cd aibom && uv run python -m pytest tests/test_cbom_posture_frozen_goldens.py tests/test_cbom_posture_wp_graph.py -q` and the backend pin test. Both green.

---

## 2. WP1 — limits, diagnostics, safe I/O, model, codec

Depends on task 1. Package `aibom/src/aibom/cbom/posture/`. Requirements: 2, 4, 5.

Constants in `limits.py` (R4-A, do not invent other numbers):

| Limit | Value |
|---|---|
| Config / IaC / server file | 5,242,880 bytes |
| TLS result file | 20,971,520 bytes |
| Bytes read per scan | 268,435,456 |
| Candidate files parsed | 10,000 |
| Nesting depth | 100 |
| YAML aliases per document | 1,000 |
| Expanded YAML nodes | 500,000 |
| Bytes examined per line | 1,048,576 |
| Include depth | 5 |
| Encryption facts | 50,000 |
| Stored diagnostics | 1,000 |
| Business mapping entries | 10,000 |
| Serialized Posture_Block | 8,388,608 bytes |
| Posture CycloneDX components | 20,000 |
| Glob steps | 20,000,000 |

- [x] 2.1 Write failing tests, then the modules
  - Tests: `aibom/tests/test_cbom_posture_{limits,diagnostics,safeio,index,context,model,codec,regex_policy}.py`.
  - Modules: `__init__.py` (`SCHEMA_VERSION = 1`, `LANE_NAMES`, re-exports of WP1 names only), `limits.py`, `diagnostics.py`, `safeio.py`, `context.py`, `model.py`, `codec.py`.
  - Binding shapes are design sections 3.5 and 3.7. `ciphers` on the sink is `object | None`. Do not import `ciphers`, `coverage`, `verdict` or any WP2+ module.
  - `HIDDEN_SUBSTRINGS` is the eleven names of R5.5: `password`, `passwd`, `secret`, `token`, `api_key`, `access_key`, `private_key`, `credential`, `connection_string`, `encryption_key`, `key_material`. `is_hidden_path` is case-insensitive on any dotted segment.
  - Walker rules (R2): ascending repository-relative POSIX path; skip `.git`, `.terraform`, `.terragrunt-cache`, `node_modules`, `vendor`, `.venv`, `venv`, `site-packages`, `__pycache__`, `dist`, `build`, `target`, `cdk.out`, `.serverless`, `.aws-sam`, `.next` at any depth; open only regular files whose resolved path is inside the root; symlink, FIFO, socket and device become `special_file_skipped` without being opened; `O_NOFOLLOW` via `getattr(os, "O_NOFOLLOW", 0)` plus lstat/fstat swap detection.
  - One `PostureSink.index()` walk reserves budgets in two groups: configuration classes first, `source` and `shell` second. Seven lanes must not walk again (mutant M28). `DiagnosticSink.add` is idempotent on `(code, path, line)` (mutant M29). `guard` re-raises `SoftTimeLimitExceeded` and `TimeLimitExceeded` by class name (mutant M30).
  - Sniff predicates are pure functions of the first 65,536 bytes: `sniff_cloudformation`, `sniff_kubernetes`, `sniff_compose`, `sniff_traefik`, `sniff_tls_result`.
  - `encode_fact` / `decode_fact` round-trip every Encryption_Fact field of table R5-A. Property values are strings. Fact id is a SHA-256 prefix over kind, provider, native type, address and repository-relative path.
  - `posture_sink` raises `TypeError` on a plain `ScanContext`.
  - Run: `cd aibom && uv run python -m pytest tests/test_cbom_posture_limits.py tests/test_cbom_posture_diagnostics.py tests/test_cbom_posture_safeio.py tests/test_cbom_posture_index.py tests/test_cbom_posture_context.py tests/test_cbom_posture_model.py tests/test_cbom_posture_codec.py tests/test_cbom_posture_regex_policy.py tests/test_cbom_posture_wp_graph.py -q`
  - Expected: PASS, including the index cases (walk order `a.txt` before `a/b`, symlink-to-`/etc/passwd` not opened, FIFO, size one byte over the cap, NUL in the first 8,192 bytes, UTF-16 BOM, path sanitizing to 512 bytes, two-group reservation with 50 source files before `infra/`, `read_included` charging the budget).
  - Boundary: full `aibom` suite green. Store `wp-01-red.txt` and `wp-01-green.txt`.
  - Commit trailer `WP: 1`.
  - _Requirements: 2.1–2.9, 4.1–4.7, 4.11–4.12, 5.1–5.9_

---

## 3. WP2 — in-house parsers

Depends on task 2. May run in parallel with task 4 after WP1. Requirements: 3, 4, 7 (expression nodes only), 8 (include parsing only).

- [x] 3.1 Parsers and the single-pass rule
  - Modules: `hcl.py`, `yamlsafe.py`, `xmlsafe.py`, `jsonsafe.py`, `tomlsafe.py`, `textscan.py`, `directives.py`, `sqllabels.py`, `codeowners.py`, `globmatch.py`.
  - Tests: `aibom/tests/test_cbom_posture_{hcl,yaml,xml,json,toml,textscan,directives,sqllabels,codeowners,globmatch,redos,perf_hostile}.py` and `aibom/tests/support/generators.py`.
  - HCL (R3.1): labelled blocks, attributes, string/number/bool/null, lists, objects, heredocs, line and block comments. Interpolations, conditionals, function calls, `for` and splats are unresolved nodes. Do not evaluate them. Tokenizer is driven by `match(text, pos)`. The `/` operator alternative must be `/(?![*/])` (mutant M32). No fallback that makes `'/* '` quadratic (experiment E-15).
  - YAML (R3.3, R3.4): pure-Python `yaml.SafeLoader` subclasses only, never `CSafeLoader`. Register constructors with `add_constructor` (defining the method is not enough, E-19). CloudFormation short tags (`!Ref`, `!GetAtt`, `!Sub`, `!Join`, `!If`, `!FindInMap`, `!ImportValue`, `!Select`, `!Split`, `!Equals`, `!And`, `!Or`, `!Not`, `!Condition`, `!Base64`, `!Cidr`, `!GetAZs`, `!Transform`) become tagged unresolved nodes. `!!python/object` and `!!python/object/apply` become `unsafe_tag` and execute nothing. Alias count comes from the event stream; expansion size from the composed DAG with a memo, before any Python object is built. Caps: 1,000 aliases, 500,000 nodes. On a capped document, drain events to `DocumentEndEvent` and reset anchors, then continue the stream (mutants M39, M40). Duplicate keys keep the last value and record `duplicate_key`.
  - JSON (R3.2): stdlib `json` with `object_pairs_hook` for duplicates, `parse_constant` rejecting `NaN`/`Infinity`. `json_scan` rejects depth 101 and accepts 100 on every interpreter (F-34). Do not use the quadratic pre-scan (mutant M31).
  - XML (R3.6–R3.8): stdlib `ElementTree`. Reject a DOCTYPE with an internal subset, an `ENTITY`, or an external identifier (`unsafe_xml`) before the parser runs. Accept a bare `<!DOCTYPE nmaprun>`. `blank_spans` blanks comments and CDATA in one pass (mutant M33).
  - TOML: `toml_scan` then `tomllib`. Depth cap 100.
  - Directives: nginx, Apache, HAProxy, `sshd_config`, `postgresql.conf`, `pg_hba.conf`, MySQL/MariaDB `.cnf`, `redis.conf`, `crypttab`, Java `.properties`. Include directives are recorded, not followed here; following is `PostureSink.read_included` (depth 5, cycle detection).
  - Duplicate keys: mappings keep the last value and record `duplicate_key`. `tomllib` rejects a repeated key, so that file is `parse_error`. OpenSSH keeps the first value of a keyword and still records `duplicate_key` (design section 17, item 47). Pin `PasswordAuthentication yes` followed by `PasswordAuthentication no`.
  - SQL labeller: closed vocabulary, no statement text retained.
  - CODEOWNERS and globs: dynamic-program matcher charged to `GlobBudget`. No regular expression built from file text (D-19).
  - `blank_noncode` must agree with `detect.strip_noncode` on 20,000 random texts and must not call `detect.strip_noncode` (K-13).
  - Every parser entry point is wrapped by `safe_parse`: any byte string returns a result or one Diagnostic, never an exception (R3.9).
  - Imports in these modules: stdlib, and `limits`, `diagnostics`, `textscan` only. No `cryptography`, no `lxml`, no `hcl2`.
  - Property tests (R44.2): 1,000 cases, `random.Random` seeds 1–20 recorded in the test id. Mutating fixture bytes 1–5 times never raises.
  - Hostile timing: each in-house scanner finishes in under 1 second on 1 MiB of `'/* '`, `'""" '`, and `'"' + '\\"' * k` shapes. `test_cbom_posture_perf_hostile.py` enforces this.
  - Run the parser tests plus `test_cbom_posture_wp_graph.py`. Expected: PASS.
  - Boundary: full `aibom` suite. Commit trailer `WP: 2`.
  - _Requirements: 3.1–3.10, 4.3–4.10, 8.8_

---

## 4. WP3 — registry and coverage loaders

Depends on task 2. Parallel with task 3. Requirements: 9, 5.5 (redaction check), 10 (table shape).

- [x] 4.1 Loaders against synthetic blobs
  - Modules: `defaults.py`, `coverage.py`.
  - Tests: `test_cbom_posture_{registry,coverage,packaging,lint}.py`.
  - Allow-lists committed as text, not inferred from code: `aibom/tests/cbom_posture_url_allowlist.txt`, `aibom/tests/cbom_posture_reviewed_rows.txt`.
  - `build_registry` / `build_coverage` validate schema, hash rows, reject a bad URL, reject a `when`/`unless_attrs` that names only one syntax (D-29), and reject a consulted hidden path that is in neither `refs` nor `presence` (D-23, mutant M43, M50).
  - `READER_NAMES` is the closed set of eight reader names. The loader stores names only. Implementations arrive in WP6.
  - `read_data_bytes` uses `files("aibom.cbom").joinpath("data").joinpath(name).read_bytes()`. No `Path(__file__)`, no environment variable.
  - Packaging test copies `src/aibom` to a temp tree, writes `probe_registry.json`, and reads the same SHA-256 from a directory import, an extracted layout, and a zip import. The hatchling wheel build is `xfail(strict=False)` with reason K-1. Do not edit `pyproject.toml`.
  - Pattern linter: registry patterns have a strict shape and one of three matcher kinds. A control pattern that would backtrack must fail the linter.
  - These tests use synthetic blobs. They must pass before any shipped JSON exists.
  - Run the four tests plus the import-graph test. Boundary: full `aibom` suite. Commit trailer `WP: 3`.
  - _Requirements: 9.1–9.9, 5.5, 10.5_

---

## 5. WP4 — resolution, verdict, findings, weights

Depends on tasks 3 and 4. Freezes the interfaces WP6 codes against. Requirements: 6, 7, 8 (linking types), 15, 28.1–28.4.

- [x] 5.1 Pure engines
  - Modules: `resolve.py`, `records.py`, `verdict.py`, `findings.py`, `extract_common.py`.
  - Edit: `aibom/config/crypto-risk-weights.yaml` only. Add the ten flags and `scale.max_raw: 112`. Do not change `severity`, `default`, or `scale.bands`.
  - Tests: `test_cbom_posture_{resolve,verdict,findings,weights,path_context,records}.py`, `aibom/tests/support/oracle.py`, `aibom/tests/support/generators_resources.py`.
  - Resolution (A-7): literals and `variable` defaults resolve. A `.tfvars` value that differs from the default makes dependents `Unresolved("variable_overridden")` (mutant M03). `locals`, modules, remote state and `data.*` are unresolved, except `data "aws_iam_policy_document"`, which phase 1a translates into the object `jsonencode` would receive and stores on `Scope.documents` (D-28, mutant M52). `variable_no_default` is `Unresolved`, not `Absent` (mutant M23).
  - Verdict decision table of design section 4.4.2, including step 0, `as_absent`, version rule, and override value. `ENCRYPTED_DECLARED` outranks `ENCRYPTED_PROVIDER_DEFAULT` (mutant M22). A literal that is neither enabling nor disabling is not enabling (mutant M21). `assessable_as_unencrypted` false means an absent unencrypted default is UNKNOWN, not `NOT_ENCRYPTED` (mutant M25, D-10). An unpinned version does not pick the newest row (mutant M24).
  - Tri-state: pass and fail only for `ENCRYPTED_*` and `NOT_ENCRYPTED`. UNKNOWN is `not_bom_evidenceable`, never pass (mutant M02). Coverage is pass/(pass+fail), null when that sum is zero.
  - `derive_findings(fact, scored)` is pure. `POSTURE_CODES` is exactly the ten codes of table R15-A, disjoint from `WEAK_CRYPTO_CODES`. Severities: High `error` weight 8, Medium `warning` weight 4, Low `note` weight 1. Verdict-derived codes are the three named in task 0.8. An UNKNOWN verdict yields none of them (mutant M36). Signal-derived codes fire only on an explicit signal. `finding_default` does not fire when the governing attribute is unresolved (mutant M44).
  - Weights tests: frozen snapshot of the 15 Base_Commit weights is unchanged; each `POSTURE_CODES` member has its table weight; key set equals snapshot union `POSTURE_CODES`; `scale.max_raw == 112 == sum(snapshot)`; Frozen_Golden score fields match the WP0 digests (mutant M17).
  - `AttrView` stores only consulted paths. Unlisted attributes are not readable (R5.4). An expression over 2,000 nodes becomes `Unresolved("unresolved_expression")` (K-14). `path_context` labels only (task 0.10).
  - `FactBuilder` keeps its own bom-ref set and dict. It does not call `by_ref`, `neighbors`, `out_edges`, `flags_for`, or `has_ref`.
  - `listener_reader` lives here and is the one reader every extractor shares. There is no module-level `READERS` registry (D-27).
  - Run the WP4 tests, the golden digest test, and `test_cbom_scorer.py`. Expected: existing scorer assertions stay green because `max_raw` is pinned (ledger 13.3.1).
  - Boundary: full `aibom` suite. Commit trailer `WP: 4`.
  - _Requirements: 6.1–6.9, 7.1–7.6, 15.1–15.5, 15.7, 28.1–28.4, 5.8, 5.10_

---

## 6. WP5 — shipped reference data

Depends on task 5. WP5a–WP5e are data only and may run in parallel. WP5f owns the content tests. Requirements: 9, 10, 13.3, 22.8, 31 (URLs).

Data files, one row per line, `sort_keys`, LF, UTF-8:

| Package | Files |
|---|---|
| 5a | `aibom/src/aibom/cbom/data/provider_defaults_aws.json` |
| 5b | `provider_defaults_{azure,gcp,k8s,software}.json` |
| 5c | `coverage_table.json` |
| 5d | `tls_policies.json`, `cipher_suites.json`, `named_groups.json` |
| 5e | `key_specs.json`, `datastore_images.json`, `verification_patterns.json`, `named_vulnerabilities.json`, `tls_import_formats.json`, `key_policy_conditions.json` |

- [ ] 6.1 Red run of the content tests, before any data file
  - Author `test_cbom_posture_{registry_content,coverage_content,redos_registry}.py` first. Run them once. They fail because `DATA_FILES` names files that are absent.
  - Store that log as `wp-5f-red.txt` with the SHA-256 of each test file. Do not commit a red tree. The failing run lives only in the evidence directory.
  - _Requirements: 44.1_

- [ ] 6.2 Author rows from public vendor pages
  - Every row carries a public URL, a `valid_as_of` date, the documented default, the encryption effect, and a caveat. No text copied from another scanner's source.
  - Reviewed-row list (already in WP3) contains exactly the ten assessable ids and three `finding_default` ids from design section 4.6.1. Do not add a finding-from-absence row without a second reviewer.
  - Vendor corrections already measured (F-27, F-41, F-42, K-18): ElastiCache at-rest is non-assessable; nginx `ssl_protocols` has three version ranges; Google omitted `rotation_period` is not a finding; CloudFormation replica, snapshot and serverless predicates are stated for both Terraform and CloudFormation (D-29).
  - Coverage_Table minimum content is requirement 10. `build_coverage` must accept the shipped table: predicate paths are in `consulted`, `refs` and `presence` satisfy the hidden-path check, and Terraform/CloudFormation pairs share one semantic rule (R10.5).
  - Each data package's report cites the `wp-5f-red.txt` test ids its files turn green.
  - _Requirements: 9, 10, 13, 22_

- [ ] 6.3 Green content tests
  - After 5a–5e, commit the test files and store `wp-5f-green.txt` with the same test-file hashes.
  - Assert: every shipped file loads in the three packaging layouts; URL allow-list matches; reviewed-row list matches; Coverage_Table families cover R10-A; shipped patterns finish under 1 second on the ReDoS corpus.
  - Boundary: full `aibom` suite. Trailers `WP: 5a` … `WP: 5f`, each commit only its files.
  - _Requirements: 9.1, 44.1, 4.10_

---

## 7. WP8 — hand-derived fixture oracles

Depends on task 6. A different author than the matching WP6 extractor. Oracles are written by reading the fixture and the registry row, never by running the product. Requirements: 45.

Trees under `aibom/tests/fixtures/`, each with `expected_config_<tree>.json` and `SOURCE.md`. `conftest.py` already has `collect_ignore=["fixtures"]`. Do not ruff these trees.

| Package | Trees |
|---|---|
| 8a | `synthetic-config-aws-tf` |
| 8b | `synthetic-config-azure-tf`, `synthetic-config-gcp-tf`, `synthetic-config-cfn` |
| 8c | `synthetic-config-k8s`, `synthetic-config-compose` |
| 8d | `synthetic-config-servers`, `synthetic-config-databases`, `synthetic-config-code-tls` |
| 8e | `synthetic-config-tls-results`, `-mapping`, `-clean`, `-canary`, `-hostile`, plus `test_cbom_posture_manifest_consistency.py` |

- [x] 7.1 Author trees and oracles
  - **Done 2026-10-28.** All 14 `synthetic-config-*` trees present with `expected_config_*.json` + `SOURCE.md`. `test_cbom_posture_manifest_consistency.py` green (29). Scan vs oracle MATCH for every tree. Evidence: `.agents/tasks/cbom-high-deliverables-evidence/reports/wp8-trees-complete.txt`.
  - Each Coverage_Table resource or child row has one positive and one negative oracle resource. Each default row has a resource that omits the attribute and one that sets it. Each of the 14 `unknown_reason` values has a case. Each `POSTURE_CODES` member has a raising case and a same-kind non-raising case. Each diagnostic code has a hostile case. Each `refs` entry has a resolved and an unresolved case.
  - CloudFormation twins of every Terraform predicate case (replica, snapshot restore, serverless). Apache `SSLProtocol` rows from experiment E-23, including `TLSv1.2 TLSv1.3`. PostgreSQL: `ssl = on` with no `pg_hba.conf`; `pg_hba` that is only loopback, `local`, `reject`, or empty.
  - Canary tree plants distinct secrets in every parsed format, including Kubernetes `data`/`stringData`, a Terraform module source with `oauth2:CANARY@`, and a testssl `version` of 5 MiB. Mapping-file free text is the only canary allowed to appear, and only in the declared columns.
  - Hostile tree: 6 MiB file, 1 MiB line, symlink loop, symlink to `/etc/passwd`, FIFO, nesting 99/100/101, alias bomb, 1,001 aliases, bare nmap DOCTYPE, DOCTYPE with `SYSTEM`, `include *;` over 10,000 generated files (generated at test time, not all committed).
  - Certificates and DH parameters (512, 1024, 2048) are authored with `openssl` once and committed. No external tool runs in a gate.
  - `test_cbom_posture_manifest_consistency.py` checks oracle shape only. It does not call `scan_crypto`.
  - Do not edit any `synthetic-crypto-*` tree or any `expected_crypto.json`.
  - Commit per package. Trailers `WP: 8a` … `WP: 8e`.
  - _Requirements: 45.1–45.8_

---

## 8. WP6 — extractors

Depends on tasks 6 and 7, and on WP6h before any extractor that evaluates cipher strings. Test-first: commit the red extractor tests against the oracles before the extractor, but only in the package commit that also turns them green if the shared branch cannot stay red. The design allows the red log in the evidence directory and the green commit as the package commit. Follow that. Requirements: 10–14, 16–23.

Parallel after their edges in design section 13.3:

| Package | Modules | Tests | Needs |
|---|---|---|---|
| 6h | `ciphers.py` | cipher tests, `aibom/tests/support/naive_ciphers.py` written by a different author | 5d |
| 6a | `extract_terraform.py`, `extract_cloudformation.py` | `test_cbom_posture_{terraform,cloudformation,memory}.py` | 5a–5e, 8a, 8b |
| 6b | `extract_kubernetes.py`, `extract_compose.py` | k8s and compose tests | 5b–5e, 6h, 8c |
| 6c | `extract_servers.py`, `dhparam.py` | `test_cbom_posture_settings_servers.py` | 5b, 5d, 6h, 8d |
| 6d | `extract_databases.py` | `test_cbom_posture_settings_databases.py` | 5b, 6h, 8d |
| 6e | `verification.py` | code-tls tests | 5e, 8d |
| 6f | `business.py` | mapping tests | 8e |
| 6g | `tls_import.py`, `tls_import_testssl.py`, `tls_import_sslyze.py`, `tls_import_nmap.py` | import tests | 5d, 5e, 6h, 8e |

- [ ] 8.1 Cipher evaluator (WP6h) first
  - `CipherEvaluator` is per scan, memoized on `sink.ciphers` by `evaluator_for`. No `id()` cache (E-24). `cap_suites` keeps every suite the existing weakness predicate would flag, then fills to 256 names.
  - Agreement with `naive_ciphers.py` on the property corpus. Documented OpenSSL examples, including `!` permanence versus `-` (mutants M06, M07, M08) and `@SECLEVEL`.
  - DH reader uses the existing private DER helpers in `x509.py` through a thin wrapper. Do not edit `x509.py`. Sizes 512, 1024, 2048 match the committed files.
  - _Requirements: 22_

- [ ] 8.2 Terraform and CloudFormation (WP6a)
  - Readers `key_policy`, `deny_insecure_transport`, `gcp_iam_bindings` live in the Terraform module. CloudFormation imports them. No module-level registry imported by WP4.
  - Parity: a Terraform resource and its CloudFormation twin produce the same verdict (R10.5), including replica, snapshot-restore and serverless cases (mutant M50).
  - `data "aws_iam_policy_document"` matches the `jsonencode` form, including conditions (mutant M52, F-42).
  - `count = 0` emits no fact (mutant M09). Companion resource wins over an inline block (mutant M05).
  - Memory: `tracemalloc` peak at most 250 MB on a generated 5 MiB HCL file; growth at most 3 KB per record after ten reduced 1 MiB files (mutant M35). Parse trees are dropped after `ResourceRecord`.
  - `refs` reads: resolved and unresolved secret and key references. A canary with spaces and quotes in a `refs` value does not appear in the fact.
  - A GCP binding or member of `allUsers` or `allAuthenticatedUsers` raises `KMS_KEY_POLICY_PUBLIC` with or without a `condition` block (design section 17, item 39). Set `attrs.exposure_conditional` when a condition is present.
  - Each `kms_key` fact lists at most 500 protected fact ids, sorted. `attrs.protects_total` is the exact count (design section 17, item 60).
  - _Requirements: 10, 11, 12, 14, 8_

- [ ] 8.3 Kubernetes and compose (WP6b)
  - EncryptionConfiguration uses the first provider (mutant M10). Ingress, Istio, Traefik and cert-manager secret names are read only through `refs`.
  - Recognised data-store images come from `datastore_images.json`, matched without registry host and without tag (R16.2).
  - `volumeClaimTemplates`, named volumes, `emptyDir` and `hostPath` follow R16.3. StorageClass provisioner rows drive the volume layer (R16.4).
  - Ingress `ssl-ciphers` goes through `evaluator_for`.
  - A recognised self-hosted queue, stream, or object-store image (RabbitMQ, Kafka, NATS, ActiveMQ, Redpanda, MinIO) gets Layers `database`, `volume`, and `transport`, each UNKNOWN `layer_not_observable` unless evidence exists (design section 17, item 58). Do not drop those images.
  - _Requirements: 12, 14, 16, 17_

- [ ] 8.4 Servers and SSH (WP6c)
  - nginx, Apache, HAProxy, Envoy, Traefik static, Tomcat, Jetty, Spring Boot, OpenSSH. Every setting in design section 4.5.10 has an oracle row.
  - Apache arithmetic matches E-23. An unprefixed token after the first replaces the set within the documented bound (mutant M46).
  - `crypto:listen` includes wildcard binds, not only endpoint candidates (mutant M53).
  - A plaintext listener with a redirect is not `NOT_ENCRYPTED` (mutant M26).
  - `config_context` pins from Dockerfile `FROM` and compose image tags (K-2, K-16).
  - Stream and TCP passthrough stay `transport` UNKNOWN (K-4).
  - _Requirements: 13, 20_

- [ ] 8.5 Databases, disk, SQL (WP6d)
  - Readers `pg_transport`, `redis_transport`, `cryptsetup`, `sql_labels`.
  - `pg_transport` decision table: a `reject` record is not plaintext (mutant M37); absent `pg_hba.conf` with `ssl = on` is not `ENCRYPTED_DECLARED` (mutant M48); a file of only loopback, `local`, `reject`, or nothing is not `ENCRYPTED_DECLARED` (mutant M49).
  - `crypttab` and `cryptsetup luksFormat|luksOpen|open` are disk evidence (A-12). SQL files are labelled, not stored.
  - A `crypttab` keyfile records custody `local_file` and does not raise `AT_REST_ENCRYPTION_WEAK`. A database file keyring does raise it (design section 17, item 15).
  - _Requirements: 16, 18, 21_

- [ ] 8.6 Verification detector (WP6e)
  - Disabled certificate verification and legacy protocol pins in code, environment and commands (R23).
  - The pin pattern must not match `jdk.tls.disabledAlgorithms` (F-19). Patterns are LINE or TOKEN patterns only.
  - Emits `protocol` assets with `crypto:verification=disabled`. Findings come later from the signal, not from this module.
  - One fact and one protocol asset per file and pattern id, not per line. Keep the first 20 line numbers in `attrs.match_lines`. Every match still raises the finding (design section 17, item 44).
  - The transport verdict of a verification fact is UNKNOWN `attribute_not_modeled`. `TLS_VERIFICATION_DISABLED` still fires from the explicit signal (task 0.8).
  - _Requirements: 23_

- [ ] 8.7 Business mapping (WP6f)
  - Optional in-repo YAML or JSON. Unknown keys: `mapping_unknown_key`. Invalid entries: `mapping_entry_invalid`. Cap 10,000 entries.
  - CODEOWNERS owner hints. No database table, API field or UI form (A-8).
  - _Requirements: 19_

- [ ] 8.8 TLS result importer (WP6g)
  - `detect` calls `safeio.sniff_tls_result`, then the Format Register version rule. Unsupported tool or version is `unsupported_result_format` with tool and version, never a silent skip.
  - Positive and negative sample for each register row. Staleness strings. Host sanitizing. 20 MiB plus one byte is `size_cap`.
  - `tool_version`, `scan_started` and `scan_finished` are clipped (mutant M45). Suite lists go through `cap_suites`. Group names go through `classify_groups`.
  - An import never yields `NOT_ENCRYPTED`. A connection error or a `not_tested` item is UNKNOWN `import_not_tested` and raises nothing (design section 17, item 17).
  - Same host and port in two files stays two facts. Samples use only `example.com`, `example.org`, `.test`, `.invalid`, and the documentation ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
  - Scored vulnerabilities are the R25-A rows marked scored. BEAST, LUCKY13, CRIME, and BREACH are printed as reported and do not raise `KNOWN_TLS_VULNERABILITY`.
  - _Requirements: 24, 25_

- [ ] 8.9 Boundary for every WP6 package
  - Each package commit runs the full `aibom` suite and `test_cbom_posture_wp_graph.py`. Trailers `WP: 6a` through `WP: 6h`.
  - Extractors are not registered yet. `scan_crypto` on the 18 frozen trees is unchanged because nothing imports the new modules from `scanners/__init__.py`.

---

## 9. WP7 + WP7b — wire the engine (one commit)

Depends on tasks 6 and 8. This is a pair (D-26). One commit, two trailers: `WP: 7` and `WP: 7b`. Requirements: 1, 26, 27, 28.5–28.7, 29, 30, 39.4.

- [ ] 9.1 Scanners
  - Seven modules, each with exactly one `name = "..."` line and one `order = N` line, `level = 1`, and `posture_role`:

| Module | name | order | role |
|---|---|---|---|
| `posture_iac_scan.py` | `posture_iac` | 31 | extractor |
| `posture_server_scan.py` | `posture_server` | 32 | extractor |
| `posture_database_scan.py` | `posture_database` | 33 | extractor |
| `posture_tls_import_scan.py` | `posture_tls_import` | 34 | extractor |
| `posture_verification_scan.py` | `posture_verification` | 36 | extractor |
| `posture_linkage_scan.py` | `posture_linkage` | 38 | enricher |
| `posture_findings_scan.py` | `posture_findings` | 45 | flagger |

  - Add them to the one parenthesised import in `scanners/__init__.py` and to `__all__`, sorted, trailing commas. Do not import `jvm_go_crypto_scan`, `native_crypto_scan`, or `web_native_crypto_scan` (OI-12).
  - Each `scan()` starts with `posture_sink(ctx).enter(self.name)` and runs the body in `guard`.
  - The flagger decodes fact components, calls `derive_findings`, `add_flag`s on the fact bom-ref, and writes sorted `crypto:factFindingCodes`. It emits no component.
  - `posture_linkage` (order 38, role `enricher`) links facts and adds no component and no flag. Links: Terraform `<type>.<name>.<attr>` to a resource in the scanned input; CloudFormation `Ref` and `Fn::GetAtt` in the same template; PVC and StatefulSet claim templates to StorageClass; Ingress `tls.secretName` to a Secret or cert-manager Certificate; a compose bind mount to the fact of the mounted file. A missing target is `unresolved_reference`. Include following stays in `read_included`.
  - _Requirements: 1.1, 1.4, 1.5, 15.3, 8_

- [ ] 9.2 Pipeline, normalizer, adapter, emitter
  - `pipeline.py`: construct `CbomScanContext`, call `finalize_posture` inside `try`, return `CbomScanResult`. Scoring and compliance calls stay as they are. Declared return type stays `ScanResult`.
  - If `finalize_posture` raises, drop every posture component, edge and flag, record `internal_error`, set `assembly_failed=True`. The block then reads as Not_Assessed, "posture lanes failed in the scan", not as zero facts (R38.4).
  - `normalize.py`: exclude fact components (`kind == "infra"` and `crypto:factId`) from `_crypto_graph` nodes; keep posture-created `crypto_asset` nodes. Add optional keyword `enrich=None`. Emit `cbom_posture` only for `CbomScanResult`. A plain `ScanResult` stays the Base_Commit dict.
  - Governor `fit_run_object`: pre-prune by `est(f) = K_EST + 90 * suite names`; fitting renders are not schema-validated; the accepted BOM is validated once; above 1,500 components use the linear validator in `bomcheck.py` (`Validator.evolve`, no new import of `jsonschema` inside `bomcheck`). Final object, after the adapter enrich hook, is at most 15 MiB. Findings-first retention (mutants M18, M27, M34, M42).
  - `cbom_devsecshield.py`: pass `enrich=_enrich` into `normalize_crypto`. Signature, parameter names, and progress values `(10, 80, 100)` stay identical to `adapter_signature.txt`.
  - `emit/cyclonedx.py`: add `_family_map` and optional `by_family=None` on `_suite_algorithm_refs`. `by_family=None` is the old path. At most 6 deleted lines. `test_cbom_posture_emit_family_map.py` proves byte identity on the 18 frozen trees.
  - `docs/cbom-posture/posture-block.schema.json` is owned here, not by WP15.
  - Block keys are the R30.2 set plus `disabled_resources`, `dropped`, and `failed_lanes`. `schema_version` is 1. A scan that ran the lanes and found nothing still emits the block.
  - Truncation sets `crypto:postureTruncated` and `crypto:postureDropped` together, and only when something was dropped. Findings-first applies to facts and to the component cap.
  - If `finalize_posture` raises, drop posture components, edges, and flags, record `internal_error`, and set `assembly_failed`. That Source is Not_Assessed, reason "posture lanes failed in the scan".
  - _Requirements: 26, 27, 30, 1.7_

- [ ] 9.3 Contract tests in the same commit
  - `test_cbom_posture_{assemble,governor,bomcheck,pipeline,normalize,exclusions,compliance,scanners_contract,block_schema,no_quadratic_helpers,perf_normalize,emit_family_map,readers}.py`.
  - Scanner contract tests and their controls are the table in design section 10.7 (registration, import graph, order bands, role behaviour, level 1 equals level 4, AIBOM lane does not load posture, adapter signature).
  - `test_cbom_posture_compliance.py`: Frozen_Golden compliance is byte-identical; framework keys stay the Base_Commit 13; a configuration TLS 1.0 asset fails the existing weak-protocol checks and TLS 1.2 does not; `enable_key_rotation = true` does not flip manual rotation requirements off `not_bom_evidenceable`; clearing flags does not change a verdict.
  - `test_cbom_posture_exclusions.py`: a fact with a posture finding produces one `results[]` row whose `finding_codes` contain that code (task 0.4). A fact with no posture finding produces none. Distributions of Frozen_Goldens stay byte-identical. `cbom_graph` still drops fact components.
  - Pipeline tests (5) and (6) of design section 4.9.2: every raised code is in the weights file; `scores.by_flag[code] == weight * counts.findings_by_code[code]`.
  - _Requirements: 1, 28.5–28.7, 29_

- [ ] 9.4 WP7b pins, same commit
  - `make_cbom_team_rollup_fixture.py` gains `--only {scans,registry}`. Default behaviour unchanged.
  - Regenerate only `backend/tests/fixtures/cbom_scanner_registry.json` with `--only registry --allow-dirty`. Do not regenerate `cbom_team_rollup_scans.json`. The WP0 pin must stay green.
  - First sequential edit of `backend/utilities/pdf/cbom_deliverable_text.py`: add the seven `CBOM_SCANNERS` entries. Do not amend `SCOPE_OF_METHOD` here.
  - Update the scanner-count assertions in `test_cbom_deliverables_contract.py` and `test_cbom_deliverable_methodology.py` from 9 to 16. Do not change the document-count tests (those are WP12).
  - Backend tests that read the engine source (`test_scanner_registry_fixture_equals_the_engine_source` and the methodology scanner table) must be green in this same commit. They go red the moment `__init__.py` changes (F-37).
  - _Requirements: 39.4, 1.1_

- [ ] 9.5 Boundary
  - `cd aibom && uv run ruff check src/aibom/cbom src/aibom/emit/cyclonedx.py && uv run mypy src/aibom/cbom src/aibom/emit/cyclonedx.py && uv run python -m pytest tests -q`
  - Backend: the scanner contract tests, the fixture pin, and the MEDIUM regression files named in design section 11.8 that WP7b touches.
  - `bash bench/cbom/ci_repos.sh` from the aibom tree, or the hermetic `pytest tests/test_cbom_benchmark_gate.py`. Expected: true-miss 0.
  - Expected: full aibom suite green; frozen digests green; benchmark gate green.

---

## 10. WP9 — guards, completeness, mutants, properties

Depends on task 9. May run in parallel with tasks 11 and 16. Requirements: 41, 42, 44.2–44.5.

- [ ] 10.1 Engine half of the guards
  - `aibom/tests/support/{airgap,mutants}.py`.
  - Tests: `test_cbom_posture_{airgap_static,airgap_runtime,imports,completeness,mutants,properties,canaries,bomref,redos_all}.py`.
  - Static guard: new engine modules import only stdlib, pydantic, pyyaml and `aibom`. Forbidden: network and process modules, `eval`/`exec`/`compile`/`__import__`, dynamic import, LLM SDK names. `importlib.resources` is the one allowed `importlib` use.
  - Runtime guard: socket and process calls raise inside a posture scan. A control that opens a socket must be caught.
  - Import-closure probe: the posture package closure contains no third-party module outside pydantic and pyyaml.
  - Completeness test reads oracles and fails on a missing positive/negative case (design section 10.4). `completeness_exceptions.json` starts empty.
  - Mutants M01–M18 and M21–M53 are killed by the named tests in design section 10.5. M19, M20 and M54 are not this package.
  - Canary scan: zero occurrences of each planted secret in `cbom_json`, the run-object and diagnostics.
  - Property tests of design section 10.3: file-order independence (20 shuffles), enabling monotonicity, unresolved is UNKNOWN, codec identity, scan idempotence, cipher agreement.
  - bom-ref: `crypto-cfg_` prefix, unique inside a scan, stable across path separator and `PYTHONHASHSEED`.
  - Boundary: full `aibom` suite. Commit trailer `WP: 9`.
  - _Requirements: 41, 42, 44, 5.6, 27_

---

## 11. WP10 — team roll-up

Depends on task 9. Requirements: 33, 38.

- [ ] 11.1 Additive roll-up fields
  - Edit `backend/utilities/dashboard/cbom_team_rollup.py`. Add fields with defaults. Do not change existing field meanings, function signatures, `HISTORY_WINDOW`, `HARD_MAX_SCANS`, `BATCH_SIZE`, or the fingerprint formula.
  - A bad `cbom_posture` record is skipped and counted in `warnings` without echoing scanned text.
  - A Source is Not_Assessed when its current scan has no Posture_Marker. An uploaded BOM file (`file_context`, F-3) is Not_Assessed with reason "uploaded BOM file", not "re-scan needed". A Tier A scan without the marker stays Tier A.
  - Fact identity inside a Source is `(source key, fact id)`. Current facts come from the newest scan. Older-only facts go to the "previously seen" appendix and stay out of headline counts. Do not merge facts across Sources.
  - Failed latest attempt still falls back to the older successful scan and keeps the existing failed-latest note.
  - Register cap 2,000 rows, with the omitted count carried to the renderer.
  - Cap accumulators at `MAX_POSTURE_ACCS = 100_000`. Facts of the newest scan of a Source are always kept. Above the cap, previously-seen prints "at least N" and `previously_seen_exact` is false (design section 17, item 55).
  - Oldest `valid_as_of` across current assessed scans is exposed.
  - `PostureCounts` shape is design section 3.7. `PostureCounts.zero()` is the empty value.
  - Edit only the `FROZEN_FIELDS` entries of `ScanFacts` and `TeamCbomView` in `backend/tests/test_cbom_team_rollup.py`, appending `posture`. Do not change `test_function_signatures_match_the_wp1a_freeze`.
  - New tests: `test_cbom_posture_{rollup,degradation,mutants_backend}.py`, `backend/tests/support/airgap.py`.
  - Fixtures: `make_cbom_posture_fixture.py` produces `cbom_posture_scans.json` and `cbom_posture_registry.json` by running the engine. Refuse to run on a dirty `aibom/` tree unless `--allow-dirty`.
  - Mutants M19 (previously seen marked current) and M20 (Not_Assessed treated as zero facts) must fail their killing tests.
  - Degradation matrix R38: no marker, zero facts with marker, partial `failed_lanes`, `assembly_failed`, mixed sources. Counts never treat Not_Assessed as a pass.
  - Python 3.10. No network or LLM import.
  - Boundary: backend roll-up tests and the fingerprint tests. Expected: fingerprint of any scan set equals the Base_Commit value (R33.9).
  - Commit trailer `WP: 10`.
  - _Requirements: 33.1–33.12, 38_

---

## 12. WP10b — shared PDF scaffolding

Depends on task 11. Second sequential edit of `cbom_deliverable_text.py`. Requirements: 15.6, 34, 49.5.

- [ ] 12.1 Shared builders and text
  - New: `backend/utilities/pdf/cbom_posture_common.py`, `cbom_posture_text.py`.
  - Edit: `cbom_deliverable_common.py` (`build_document` gains `basis_extra`, `disclaimer_paragraphs`, `extra_banners`; defaults reproduce today's bytes), `report_branding.py` (three `REPORT_META` keys), `cbom_deliverable_text.py` (ten finding labels and actions only, each with a `# Source:` comment).
  - Do not add scanner rows here. Do not amend `SCOPE_OF_METHOD` here.
  - `posture_table` uses pre-wrapped plain cells. Do not change `dense_table` (D-22).
  - Keys, in registry order: `cbom_infra_posture`, `cbom_network_tls`, `cbom_data_at_rest`.
  - Update `test_cbom_deliverable_common.py`: `NEW_KEYS` gains the three keys; `ALLOWED_SOURCE_URLS` gains CWE 284, 295, 311, 312, 319, 326 and RFC 7507. Add tests that the three new keywords default to the old bytes.
  - New: `test_cbom_posture_text.py` (includes `test_posture_modules_pass_the_static_no_llm_guard`) and `test_cbom_posture_common.py`.
  - Banned substrings of the backend static guard apply to comments. Do not write `bedrock`, `anthropic`, `openai`, `get_llm`, or `chatbedrock` anywhere in these files.
  - Fonts: Helvetica, Helvetica-Bold, Courier only. Non-Latin text becomes `?` (OI-15). Do not add a font.
  - Boundary: the six MEDIUM renderer tests stay green because the new keywords default. `test_every_authored_action_is_printed_whole` now also exercises the ten actions.
  - Commit trailer `WP: 10b`.
  - _Requirements: 15.6, 34.1, 34.7, 42_

---

## 13. WP11 — the three PDFs

Depends on task 12. WP11a, WP11b and WP11c may run in parallel. Requirements: 34, 35, 36, 37, 38.

| Package | Renderer | Test | Document |
|---|---|---|---|
| 11a | `cbom_infra_posture_pdf.py` | `test_cbom_deliverable_infra_posture.py` | #5 `CBOM-D05-`, slug `infrastructure-cloud-encryption-posture` |
| 11b | `cbom_network_tls_pdf.py` | `test_cbom_deliverable_network_tls.py` | #6 `CBOM-D06-`, slug `network-tls-protocol-assessment` |
| 11c | `cbom_data_at_rest_pdf.py` | `test_cbom_deliverable_data_at_rest.py` | #9 `CBOM-D09-`, slug `data-at-rest-encryption-assessment` |

- [x] 13.1 Each renderer
  - **Passed this run.** `tests/test_cbom_deliverable_infra_posture.py`, `tests/test_cbom_deliverable_network_tls.py`, and `tests/test_cbom_deliverable_data_at_rest.py` were in the backend pytest run of 488 passed.
  - Call `build_document`. Do not open a second PDF stack.
  - Basis lines: "Posture coverage: A of B current sources assessed; C not assessed (re-scan needed)"; "Posture facts are counted separately from crypto asset occurrences"; one line per data file with `data_version` and `valid_as_of`.
  - Not_Assessed banner, UNKNOWN section, previously-seen appendix, diagnostics block, "(assessor)" cells left blank.
  - A view with no posture block still returns a PDF larger than 3,000 bytes (E-27). The static no-LLM glob `cbom_*_pdf.py` covers these modules the moment they exist, so they must be clean before the commit.
  - Document #5 (`test_cbom_deliverable_infra_posture.py`) prints, in order: KPI strip (facts, four at-rest labels, findings by impact, KMS keys and the share with rotation, sources assessed over sources total); coverage by format and provider, out-of-scope, disabled, diagnostics by code, and one data-file line each; KMS register (key, provider, specification, usage, protection, rotation, deletion protection, exposure, resources protected, source, location, two assessor columns); resource register grouped by provider and kind; managed TLS endpoint table; secrets and certificate-provisioning table; findings table (label, count, impact, anchor, remediation, and the 25 highest-impact resources); UNKNOWN grouped by reason; previously-seen appendix; assessor forms; sign-off; the sentence "declared configuration is not proof of operation".
  - Document #6 (`test_cbom_deliverable_network_tls.py`) prints: endpoint KPI strip; endpoint register; protocol matrix for SSLv3 and TLS 1.0 through 1.3 with offered / not offered / unknown; weak-suite table; endpoint certificate table; downgrade and vulnerability table marking unscored R25-A entries "reported, not scored"; SSH and database transport table; disabled-verification table with `path_context`; import provenance table; adjacent rows when a static fact and an import share a `host:port` string; UNKNOWN section; previously-seen appendix; assessor forms; the sentence that the platform did not probe any endpoint.
  - Document #9 (`test_cbom_deliverable_data_at_rest.py`) prints: data-store KPI strip; store register with declared linkage or assessor cells; backup register; Kubernetes secrets table; database-native and disk table; application-level evidence labelled "capability evidence, not proof that stored data is protected" without changing a verdict; classification roll-up or the sentence that none was declared; UNKNOWN section; previously-seen appendix; assessor forms; the sentence that stored data was not inspected.
  - Truncation: when the block is truncated, every register prints the dropped count.
  - Text assertions use the existing content-stream reader (`pdf_text`), not a screenshot.
  - Python 3.10, reportlab only.
  - Commit trailers `WP: 11a`, `WP: 11b`, `WP: 11c`.
  - _Requirements: 34, 35, 36, 37, 38_

---

## 14. WP12 + WP13 — registry, router, Board, menu (one commit)

Depends on task 13. Pair with the frontend menu. Requirements: 32, 39, 40, 30.8, and D-30 if task 0.2 accepted it.

- [ ] 14.1 Registry and router
  - `cbom_deliverables.py`: three `_spec(...)` lines, `data_dependent`, numbers 5, 6, 9. Manifest order becomes 1, 3, 5, 6, 7, 9, 10, 15, 16.
  - `cbom_deliverables.py` router: header `X-Cbom-Posture` is `assessed`, `mixed`, `not_assessed`, or `none`. Description text "six" becomes "nine". Status codes, the 30/60s limiter, and `Cache-Control: no-store` stay. PDF body starts with `%PDF-`. Filename `cbom-<slug>-team<id>-<YYYYMMDD>.pdf`.
  - Third sequential edit of `cbom_deliverable_text.py`: apply task 0.3 when it is answered, and apply task 0.16. Task 0.16 amends method-limits bullet 3 and the manual-discovery item "Data-at-rest encryption", using the sentences recorded in the plan-confirmation note. Do not draft those sentences inside the commit. Keep the phrases "static analysis" and "live-network" unless a recorded sentence removes them.
  - Board (`cbom_board_report_pdf.py`): grade input adds current posture facts that carry at least one finding, bucketed by stacked impact, plus the printed line of finding count, resource count, and Not_Assessed source count (D-14). Extend `_not_assessed_reason` so a team whose only content is posture facts is not "NOT ASSESSED" for lack of crypto assets (F-14).
  - Methodology (`cbom_methodology_pdf.py`): subsection "Configuration posture lanes" naming the seven scanners, the data files, and the limits.
  - Task 0.2 was rejected. Do not edit `backend/utilities/dashboard/scan.py`. The card total includes fact components.
  - _Requirements: 32.1–32.8, 39.1–39.8, 30.7_

- [ ] 14.2 Contract tests edited in this commit
  - Document-count tests move from six to nine (`EXPECTED`, `RENDERERS`, `DATA_DEPENDENT`, `SLUGS`, `NUMBERS`, `NEW_KEYS` already done in WP10b).
  - `test_cbom_deliverables_no_llm.py`: `SLUGS` gains the three slugs; `new_product_files()` gains glob `cbom_posture_*.py`; `KNOWN_NEW_FILES` gains the two shared posture modules. The three builders must clear 3,000 bytes on the four views that have no posture content.
  - New: `test_cbom_posture_{contract,consumers,medium_regression,airgap_static,airgap_runtime,canaries,imports}.py`.
  - `test_cbom_posture_medium_regression.py` rebuilds the six MEDIUM documents from `medium_base_text.json`, substitutes every amended sentence named by tasks 0.3 and 0.16 back to the Base_Commit literals, strips the seven new scanner rows and the new methodology subsection, and fails on any other line difference.
  - `test_cbom_posture_consumers.py` asserts the dashboard card total includes fact components (task 0.2). Mutant M54 is retired. Add cases to `test_bom_export.py` and `test_cbom_scan_metadata_contract.py` without changing existing assertions. `cbom_posture` is not surfaced through `get_scan_metadata` (the charts do not read it). A Jira eligibility test shows a posture `results[]` row is not filtered out of the existing `scan_findings` loop.
  - Backend canary: zero planted secrets in the three PDFs.
  - _Requirements: 32.7, 39, 42, 5.6, 30.8_

- [x] 14.3 Frontend menu, same commit
  - **Passed this run.** `test_frontend_menu_equals_the_backend_registry` is in `tests/test_cbom_deliverables_contract.py`, which was in the backend pytest run of 488 passed. `npx tsc --noEmit` exited 0. `frontend/app/[team_id]/cbom/page.tsx` already renders `data-testid` from `CBOM_DELIVERABLES` and was not edited.
  - Edit only `frontend/utils/backend_api.ts`. Insert, in number order:

```ts
{ slug: "infrastructure-cloud-encryption-posture", number: 5, title: "Infrastructure & Cloud Encryption Posture" },
{ slug: "network-tls-protocol-assessment", number: 6, title: "Network, TLS & Crypto Protocol Assessment" },
{ slug: "data-at-rest-encryption-assessment", number: 9, title: "Data-at-Rest Encryption Assessment" },
```

  - Do not edit `frontend/app/[team_id]/cbom/page.tsx`. The menu already renders `CBOM_DELIVERABLES`. Requirement 40.4 names that file; design section 17 item 22 records that it already maps the array, so the diff stays empty. `data-testid="cbom-deliverable-<slug>"` must already be rendered from the array. If a test shows it is not, stop and ask before editing the page.
  - `test_frontend_menu_equals_the_backend_registry` reads this file from the working tree, so it must change in this commit.
  - Frontend gate: `npx tsc --noEmit` and `python e2e/scripts/eslint_delta.py` against the Base_Commit baseline of `backend_api.ts`. Do not require a full `next build` (pre-existing dashboard lint).
  - _Requirements: 40.1–40.6_

- [ ] 14.4 Boundary
  - Backend job set of design section 12.1, on Python 3.10: posture tests, deliverable tests, roll-up, scan-metadata, bom export, MEDIUM regression suites, `compileall`.
  - No other package runs these suites while this pair is in progress.

---

## 15. WP14 — Docker and Playwright proof

Depends on tasks 10 and 14. This is the end-to-end gate. Unit tests are not a substitute. Requirements: 43, 47, 48, 49, 50.

- [ ] 15.1 Air-gap overlay probe, first
  - `e2e/compose/docker-compose.airgap.yml` extends design section 7.4. Task 0.6 adds RabbitMQ, the scan worker, and an S3-compatible object store to that overlay. Extend `e2e/scripts/compose_policy.py` with `--airgap` so the added services are expected. Default mode, without `--airgap`, stays unchanged. The UI zip-upload spec runs through the gateway against this stack.
  - `e2e/selftest/oracle.spec.ts` gains one failing case per new rule.
  - Probe: bring the overlay up, confirm the project network is internal, confirm backend and frontend have no published ports, confirm the gateway forwards the two loopback ports, confirm `aibom-scan` still has `network_mode: none`.
  - From inside the backend container and from inside the scan container, attempt a TCP connection to a public IPv4 literal, a TCP connection to a public IPv6 literal, and a DNS lookup of a public name. Record each result. The run fails if any attempt succeeds.
  - Decode `/proc/net/tcp` and `/proc/net/tcp6` of the backend container. The run fails when an outbound peer is not postgres, mongo, RabbitMQ, the object store, or loopback (task 0.6). A public address is still a failure.
  - Write `logs/NN-airgap-*.txt` in the evidence directory.
  - If the probe fails, stop and ask. Do not invent a second compose file.
  - _Requirements: 43.1–43.6, 47.1_

- [ ] 15.2 Seed world and specs
  - `e2e/seed/posture_*.py` builds the posture seed from the fixture trees through the adapter, inside the no-network container.
  - New specs: `05`, `06`, `09` (one per deliverable), `18` (states), `19` (degradation), `20` (style parity of the three PDFs), `94`–`97` (cross-cutting), `96-airgap-egress`, `98-medium-oracle-regression`.
  - Edit `17-style-parity.spec.ts` and `90-negative-isolation.spec.ts` to take MEDIUM slugs from `MEDIUM_SLUGS`. Add the three posture slugs to the 401 and cross-team loops. Do not weaken the six-document assertions.
  - Edit `e2e/lib/flow.ts` so the menu assertion expects nine items in order 1, 3, 5, 6, 7, 9, 10, 15, 16.
  - Edit `e2e/fixtures/expected.json`: manifest order and numbers, seven scanner rows, and the amended sentences from tasks 0.3 and 0.16. Do not edit the oracle sentences for 0.16 until their wording is recorded.
  - Playwright: one worker, paced requests, retries disabled. A failure is reported, not retried into a pass.
  - Each deliverable spec, as a customer: open the team CBOM page, open Deliverables, download the PDF, assert `%PDF-`, the document id, the Not_Assessed banner on a legacy team, the assessed tables on the seed team, and the absence of canary secrets.
  - Seed a new team. Do not change the Base_Commit seed numbers of team 1. The posture world contains assessed sources, one stored scan with no marker, one assessed source with zero facts, one failed scan that carries a canary, a canary in another team, and a performance team of 500 facts per scan.
  - For specs 05, 06, and 09, store a `.webm` of at least 10 seconds at 1440 by 900, at least five screenshots, the PDF and its SHA-256, `pdfinfo`, `pdftotext`, and `pdffonts` logs, an API log with status and `X-Cbom-*` headers, one PNG per PDF page, and a pytest log.
  - Assert on PDF text: seeded resource names and verdict labels, counts by verdict, kind, and finding code, each `unknown_reason` label, blank assessor cells, declared linkage with the word "declared", data-file as-of lines, the document id, the same fingerprint in the header and the body, and the Basis coverage line.
  - Pace PDF requests at least 1.5 seconds apart. One Playwright worker. Retries stay disabled.
  - Air-gap spec: from inside the internal network, an outbound connection to a public address fails; the gateway path to the app succeeds.
  - _Requirements: 40, 47, 43_

- [ ] 15.3 Independent verifier
  - `e2e/verify/verify_posture.py` recomputes expected verdicts and finding codes from the raw fixture files and the downloaded PDF text. It does not import product modules.
  - At least 60 checks per deliverable. At least 10 negative controls: mutated PDF text, altered counts, a swapped team, a removed row. Each control must fail.
  - Also check: no canary in any team PDF; no redaction canary in `cbom_json`, the run-object, or diagnostics; style parity; the egress proof; the image content hash equals the final commit, with a mismatch control that fails.
  - Record the procedure and the check counts in `e2e/verify/VERIFY.md`. A failed check blocks the definition of done.
  - _Requirements: 48_

- [ ] 15.4 Performance shapes
  - `e2e/perf/` generates S1–S4 and writes `logs/92-perf-*.json`.
  - Budgets: S1 under 120 seconds and 1 GiB; S2 under 60 seconds; a demo team of about 10 scans under 3 seconds; the register cap under 15 seconds. The performance-team budget is 15 seconds only if task 0.13 is accepted, and 10 seconds if it is vetoed. Peak growth for that team stays 512 MiB.
  - S4 records the real peak when scans sit near the 15 MiB run-object budget (K-19). That peak may exceed the 512 MiB figure. Record it. Do not change `load_team_cbom_view` to hide it.
  - Governor test 16 and `test_cbom_posture_perf_normalize.py` stay the in-process half of this budget.
  - _Requirements: 49.1–49.6_

- [ ] 15.5 Evidence bundle
  - All of this runs at the final product commit, images rebuilt from that commit. Earlier evidence moves to `_superseded-<sha>` with a README.
  - Store videos, screenshots, downloaded PDFs, compose logs and the verifier report under `.agents/tasks/cbom-high-deliverables-evidence/`. The directory stays untracked.
  - A secret scan of that directory, with a self-test that finds each planted secret, reports zero hits (R50.5).
  - Teardown removes only Docker objects labelled `com.dss-e2e=1` and leaves every other Docker object identical (R50.4).
  - Commit trailer `WP: 14` for the tracked `e2e/**` files only. Evidence stays untracked.
  - _Requirements: 47, 50_

---

## 16. WP15 — docs, ledger, CI

Depends on task 9. Parallel with task 15. The workflow file is added last, after the test names are final. Requirements: 31, 46.6, 51.

- [x] 16.1 Documentation set `docs/cbom-posture/`
  - **Passed this run.** `tests/test_cbom_posture_docs.py` and `tests/test_cbom_posture_property_dictionary.py` passed. `posture-block.schema.json` was not edited.
  - `README.md`, `supported-formats.md`, `limits.md`, `unknown-reasons.md`, `business-mapping.md`, `property-dictionary.md`, `defaults-registry.md`, `airgap.md`, `known-limitations.md`.
  - Do not edit `posture-block.schema.json` (WP7 owns it).
  - `test_cbom_posture_docs.py` fails when a table drifts from `CLASS_RULES`, `LANE_ROUTES`, `SERVER_SETTINGS`, `DB_SETTINGS`, `limits.py`, `UNKNOWN_REASONS`, or `codec.PROPERTY_KEYS`.
  - `test_cbom_posture_property_dictionary.py` locks the `crypto:` keys of design section 8.2. No new namespace (OI-3).
  - _Requirements: 31.4, 19.12, 26.5_

- [ ] 16.2 Ledger and conventions
  - Append rows to `docs/cbom-research/LEDGER.md` in the existing format: public URL, clean-room note, gap note, work-package id, status `implemented`, product path. One row per parser family, coverage family, import format, finding code, cipher evaluator, DH reader, size governor, and the isolated-network proof.
  - `test_cbom_posture_ledger.py` fails when a `POSTURE_CODES` member, a coverage family, or an import format has no row.
  - Append the conventions of design section 12.4 to `AGENTS.md`. Do not rewrite existing bullets.
  - Do not edit `bench/cbom/**`.
  - _Requirements: 31.1–31.3, 31.5, 31.6_

- [ ] 16.3 Workflow `.github/workflows/cbom-posture-gates.yml`
  - Triggers and jobs are design section 12.1. Do not edit `cbom-gates.yml` or `cbom-deliverables.yml`.
  - `aibom` job: matrix 3.11 and 3.12; `pytest tests/test_cbom_posture_wp_graph.py` first; ruff and mypy on `src/aibom/cbom` and `src/aibom/emit/cyclonedx.py`; `pytest tests -k "cbom_posture or cbom or crypto"`; full pytest; `baseline_counts.py`; `bash ../bench/cbom/ci_repos.sh`; `python ../e2e/scripts/scope_gate.py`.
  - `backend` job: Python 3.10, ruff line length 100, the test file set of section 12.1, `compileall`.
  - `frontend` job: `npm ci`, `tsc --noEmit`, `eslint_delta.py`. The slug contract stays in the backend job unless task 0.14 is vetoed.
  - `scope_gate.py` forbids the prefixes in design section 12.5 and allows only the enumerated paths. The `scan.py` allowance exists only if task 0.2 was accepted, and then only inside the cbom branch with at most six changed lines. `emit/cyclonedx.py` allows at most six deleted lines. `model/component.py` must have an empty diff. Ten manifest and lock files unchanged. No `.env` in the diff.
  - Commit trailer `WP: 15`.
  - _Requirements: 46.6, 46.7, 51_

---

## 17. WP16 — evidence, build report, runbook

Depends on tasks 15 and 16. Nothing in this task is done until the commands have been run at the final commit. Requirements: 50, 52.

- [ ] 17.1 Re-proof
  - If any product commit landed after a deliverable's evidence, move that evidence to `_superseded-<sha>` and re-run the affected specs and the full suite at the final commit.
  - Record, for every commit between the evidence commit and the final commit, whether it can change rendered output.
  - _Requirements: 50.2, 52.2, 52.7_

- [ ] 17.2 Commit-ownership check
  - For every commit on the branch, read `WP:` trailers and check every changed path against the ownership row of those packages. List violations in the build report. A violation blocks the release gate.
  - _Requirements: 52.1_

- [ ] 17.3 Build report
  - Write `.agents/tasks/cbom-high-deliverables-build-report.md` (untracked is acceptable; the design places it under `.agents/tasks/`).
  - Contents: commits per package, test and gate results with command and exit code, the R50-A definition-of-done table with evidence paths, deviations from design section 17, known issues K-1 through K-20, evidence commit, final commit.
  - Every row is PASS or an explicit recorded deviation. A missing log is not a pass.
  - _Requirements: 50.1, 50.3_

- [ ] 17.4 Runbook, not an action
  - Write `.agents/tasks/cbom-high-deliverables-runbook.md` from design section 14.3: preconditions (build report all PASS, user approval, scan worker running, backend memory sized for K-19), three image rebuilds (backend, frontend, scan worker), rollback tags taken first, baked-key suffix gate, recreate services one by one with `--no-deps --force-recreate`, never `down -v`, post-deploy checks (manifest returns nine items; legacy team PDFs show "POSTURE NOT ASSESSED - RE-SCAN NEEDED"; a fresh scan carries `cbom_posture`), rollback returns the manifest to six items.
  - Do not execute the runbook.
  - _Requirements: 52.4, 52.5, 52.6_

- [ ] 17.5 Release gate
  - The gate stays closed until the user writes approval in the evidence directory. No production action is part of this spec.
  - _Requirements: 52.3_

---


## Design readings that change a literal criterion

Design section 17 is binding unless a section 0 answer vetoes it. Where that section rewrites a SHALL, implement the reading and pin it with the fixture the design names.

| Item | Criteria | Implement this |
|---|---|---|
| 9 | 5.5, 8.5, 11.8, 14.5 | Hide a path when any dotted segment contains an R5.5 substring. `refs` may store an identifier only. `presence` may test existence only. A consulted hidden path in neither list fails Coverage_Table load. |
| 15 | 18.4 | A database file keyring raises `AT_REST_ENCRYPTION_WEAK`. A `crypttab` keyfile records custody `local_file` and raises nothing. |
| 17 | 25 | An import never yields `NOT_ENCRYPTED`. A connection error is UNKNOWN `import_not_tested`. |
| 20 | 30.2 | The block also carries `disabled_resources`, `dropped`, and `failed_lanes`. |
| 26 | 28.5 | `scores.by_flag[code]` is summed weight. The count lives in `cbom_posture.counts.findings_by_code`. Assert `by_flag[code] == weight * count`. |
| 28 | 2.7 | Reserve the scan budget in two groups: configuration classes first, then `source` and `shell`, each in path order. Charge indexed files at index time. Charge includes only in `read_included`, after that reservation. |
| 35 | 30.3, 38.4 | A crashed lane is not "zero facts". `failed_lanes` is set, `lanes` lists only lanes that finished, and the roll-up state is `failed` with reason "posture lanes failed in the scan". |
| 36, 37 | 26.1, 30.4 | The governor measures the adapter dict. Fitting renders are not schema-validated. Above 1,500 components, `bomcheck.py` uses `Validator.evolve` and does not import `jsonschema`. |
| 38 | 6.9, 15.2, 11.7, 21.7, 23.3 | Verdict-derived codes stay empty on UNKNOWN. The other seven fire only from an explicit signal. Task 0.8 gates the wording. |
| 39 | 11.5 | A GCP binding of `allUsers` or `allAuthenticatedUsers` raises `KMS_KEY_POLICY_PUBLIC` even with a `condition` block. Record `attrs.exposure_conditional`. An unresolved members list stays UNKNOWN. |
| 40 | 21.4 | `reject` is not plaintext. `ENCRYPTED_DECLARED` requires `ssl = on` and at least one non-loopback `hostssl` or `hostgssenc` record. A missing, empty, loopback-only, or reject-only `pg_hba.conf` is UNKNOWN. |
| 43 | 1.4 | `posture_linkage` is an enricher at order 38. It is not a flagger and not an extractor. |
| 44 | 23.3 | One verification fact and one protocol asset per file and pattern id. The first 20 lines are `attrs.match_lines`. Every match still raises the finding. |
| 45 | 6.4 | DynamoDB `server_side_encryption.enabled = false` is `as_absent`. The verdict is `ENCRYPTED_PROVIDER_DEFAULT`. |
| 46 | 11.3, 15.2 | An omitted Google `rotation_period` is UNKNOWN `default_unknown` and raises nothing. Task 0.9 gates this. |
| 47 | 4.9 | Mappings keep the last duplicate key. TOML rejects a repeated key as `parse_error`. OpenSSH keeps the first value of a keyword and still records `duplicate_key`. |
| 51 | 2.5, 8.8 | A file included by another classified file of the same lane is analysed only in the includer's context. The first path in byte order is the entry. A glob include stops at 10,000 directory entries and records `glob_budget`. |
| 53 | 20.3 | Apache `SSLProtocol` uses the result when the add reading and the replace reading agree. When they differ, record only a floor bound. |
| 55 | 33.5, 33.8 | Cap posture accumulators at 100,000 entries. Facts of the newest scan are always kept. Above the cap, previously-seen prints "at least N". |
| 56 | 30.8, 51.2 | Task 0.2 gates the dashboard filter. Until it is accepted, do not edit `backend/utilities/dashboard/scan.py`. |
| 57 | 7.5, 11.5 | `data.aws_iam_policy_document` is the one `data.*` exception. Phase 1a stores the `jsonencode` object on `Scope.documents`. Every other `data.*` stays unresolved. |
| 58 | 6.14, 10, 16.2 | A recognised self-hosted queue, stream, or object store gets Layers `database`, `volume`, and `transport`, UNKNOWN unless evidence exists. |
| 60 | 11.10 | A key lists at most 500 protected fact ids. `attrs.protects_total` holds the exact number. |

## Criterion index

441 acceptance criteria. Each row is open until the named test has passed and its evidence log exists. A passing unit test does not close a row whose proof is an end-to-end spec. Design readings above win over a conflicting sentence in the criterion text.

- [ ] R1.1 — tasks 9.1, 9.3 — test_cbom_posture_scanners_contract.py — THE Config_Extractor and THE TLS_Result_Importer SHALL register every new scanner only through `cbom_register` in `aibom/src/aibom/cbom/registry.py` and SHALL import every new scanner module in `aibom/src/aibom/cbom/s...
- [ ] R1.2 — tasks 9.1, 9.3 — test_cbom_posture_scanners_contract.py — WHEN a new scanner, parser or data-loader module imports any `aibom.scan` module other than `aibom.scan.registry`, THE Test_Suite SHALL fail through a static import-graph test.
- [ ] R1.3 — tasks 9.1, 9.3 — test_cbom_posture_scanners_contract.py — WHEN a module outside `aibom/src/aibom/cbom/`, `aibom/src/aibom/integrations/cbom_devsecshield.py` and the test directories imports a new scanner, parser or data-loader module, THE Test_Suite SHALL fail through the sa...
- [ ] R1.4 — tasks 9.1, 9.3 — test_cbom_posture_scanners_contract.py — WHEN `ordered_cbom_scanners()` is evaluated, THE CBOM_Engine SHALL list every new scanner that emits components at an `order` below 40 and every new scanner that only raises flags at an `order` from 41 to 49 inclusive...
- [ ] R1.5 — tasks 9.1, 9.3 — test_cbom_posture_scanners_contract.py — THE Config_Extractor and THE TLS_Result_Importer SHALL declare `level = 1` for every new scanner, and WHEN `scan_crypto` runs on one Scanned_Input with `level=1` and with `level=4`, THE CBOM_Engine SHALL return ScanRe...
- [ ] R1.6 — tasks 9.3, 9.5 — test_cbom_posture_scanners_contract.py — WHEN `scan_repo` of the AIBOM_Lane runs on every fixture used by the existing AIBOM tests, THE AIBOM_Lane SHALL emit output byte-identical to the Base_Commit output.
- [ ] R1.7 — tasks 9.2, 9.3 — test_cbom_posture_scanners_contract.py — WHEN the Scan_Worker executes a CBOM_Scan, THE Worker_Adapter SHALL reach the new scanners only through `scan_crypto_to_devsecshield`, whose name, parameters and return type remain unchanged.
- [ ] R2.1 — tasks 2.1 — test_cbom_posture_index.py and test_cbom_posture_safeio.py — THE Config_Extractor SHALL walk the Scanned_Input in ascending byte order of the repository-relative POSIX path, so that the order of examined files does not depend on the file system.
- [ ] R2.2 — tasks 2.1 — test_cbom_posture_index.py and test_cbom_posture_safeio.py — THE Config_Extractor SHALL skip, at any depth, directories named `.git`, `.terraform`, `.terragrunt-cache`, `node_modules`, `vendor`, `.venv`, `venv`, `site-packages`, `__pycache__`, `dist`, `build`, `target`, `cdk.ou...
- [ ] R2.3 — tasks 2.1 — test_cbom_posture_index.py and test_cbom_posture_safeio.py — THE Config_Extractor SHALL open only regular files that are not symbolic links and whose resolved path lies inside the Scanned_Input.
- [ ] R2.4 — tasks 2.1 — test_cbom_posture_index.py and test_cbom_posture_safeio.py — IF a directory entry is a symbolic link, FIFO, socket or device node, THEN THE Config_Extractor SHALL skip the entry without opening it and SHALL record a `special_file_skipped` Diagnostic with the sanitized path.
- [ ] R2.5 — tasks 2.1 — test_cbom_posture_index.py and test_cbom_posture_safeio.py — THE Config_Extractor SHALL classify each candidate file with the File Classification Table below before parsing, and SHALL ignore a file that matches no row without recording a Diagnostic.
- [ ] R2.6 — tasks 2.1 — test_cbom_posture_index.py and test_cbom_posture_safeio.py — IF a candidate file is larger than the per-file byte limit of the Limits Table, THEN THE Config_Extractor SHALL skip the file and SHALL record a `size_cap` Diagnostic carrying the sanitized path and the size.
- [ ] R2.7 — tasks 2.1 — test_cbom_posture_index.py and test_cbom_posture_safeio.py — IF the bytes read by the new scanners in one scan reach the per-scan byte limit or the parsed-file limit of the Limits Table, THEN THE Config_Extractor SHALL stop reading further files in path order and SHALL record o...
- [ ] R2.8 — tasks 2.1 — test_cbom_posture_index.py and test_cbom_posture_safeio.py — THE Config_Extractor SHALL write every path into outputs as repository-relative POSIX text with control characters replaced by `?` and a length of at most 512 bytes.
- [ ] R2.9 — tasks 2.1 — test_cbom_posture_index.py and test_cbom_posture_safeio.py — WHEN the Scanned_Input contains no file that matches the File Classification Table, THE Config_Extractor SHALL complete without error and SHALL emit zero Encryption_Facts.
- [ ] R3.1 — tasks 3.1 — parser tests named in task 3.1 — THE Config_Extractor SHALL parse HashiCorp Configuration Language files with an in-house parser that handles labelled blocks, attributes, string, number, boolean and null literals, lists, objects, heredocs, line comme...
- [ ] R3.2 — tasks 3.1 — parser tests named in task 3.1 — THE Config_Extractor SHALL parse `.tf.json` files with the standard-library `json` module according to the Terraform JSON syntax.
- [ ] R3.3 — tasks 3.1 — parser tests named in task 3.1 — THE Config_Extractor SHALL parse YAML only with `yaml.safe_load_all` semantics through the `pyyaml` dependency that `aibom` already declares.
- [ ] R3.4 — tasks 3.1 — parser tests named in task 3.1 — WHEN a YAML document contains a CloudFormation short-form tag (`!Ref`, `!GetAtt`, `!Sub`, `!Join`, `!If`, `!FindInMap`, `!ImportValue`, `!Select`, `!Split`, `!Equals`, `!And`, `!Or`, `!Not`, `!Condition`, `!Base64`, `...
- [ ] R3.5 — tasks 3.1 — parser tests named in task 3.1 — THE Config_Extractor SHALL parse directive-style files (nginx, Apache httpd, HAProxy, `sshd_config`, `postgresql.conf`, `pg_hba.conf`, MySQL and MariaDB `.cnf`, `redis.conf`, `crypttab`, Java `.properties`) with in-ho...
- [ ] R3.6 — tasks 3.1 — parser tests named in task 3.1 — THE Config_Extractor SHALL parse TOML with the standard-library `tomllib` and XML with the standard-library `xml.etree.ElementTree`.
- [ ] R3.7 — tasks 3.1 — parser tests named in task 3.1 — WHEN an XML document contains a DOCTYPE declaration with an internal subset, an ENTITY declaration or an external identifier, THE Config_Extractor SHALL reject the document before parsing and SHALL record an `unsafe_x...
- [ ] R3.8 — tasks 3.1 — parser tests named in task 3.1 — WHEN an XML document contains a bare DOCTYPE declaration with no internal subset and no external identifier, THE Config_Extractor SHALL parse the document.
- [ ] R3.9 — tasks 3.1 — parser tests named in task 3.1 — WHEN any parser receives any byte string, THE Config_Extractor SHALL return either a parse result or one Diagnostic and SHALL contain every internal parser error, so that none reaches the scanner.
- [ ] R3.10 — tasks 10.1 — parser tests named in task 3.1 — THE Config_Extractor and THE TLS_Result_Importer SHALL import, in their own modules, only the Python standard library, `pydantic`, `pyyaml` and `aibom` modules.
- [ ] R4.1 — tasks 2.1, 3.1 — test_cbom_posture_perf_hostile.py and the hostile fixture — IF a file is malformed, truncated, binary or unparsable, THEN THE Config_Extractor SHALL record one Diagnostic with a closed-vocabulary code and SHALL continue with the next file.
- [ ] R4.2 — tasks 2.1, 3.1 — test_cbom_posture_perf_hostile.py and the hostile fixture — THE Config_Extractor SHALL enforce every limit of the Limits Table below in deterministic units (bytes, lines, tokens, nodes, nesting depth, expansions), independent of elapsed time, timers and signals.
- [ ] R4.3 — tasks 2.1, 3.1 — test_cbom_posture_perf_hostile.py and the hostile fixture — IF nesting depth in an HCL, YAML, JSON or XML structure exceeds the depth limit, THEN THE Config_Extractor SHALL discard that structure and SHALL record a `depth_cap` Diagnostic.
- [ ] R4.4 — tasks 2.1, 3.1 — test_cbom_posture_perf_hostile.py and the hostile fixture — IF a YAML document holds more alias references than the alias limit or expands to more nodes than the expansion limit, THEN THE Config_Extractor SHALL reject the document before it constructs Python objects and SHALL...
- [ ] R4.5 — tasks 2.1, 3.1 — test_cbom_posture_perf_hostile.py and the hostile fixture — IF a file contains a NUL byte within its first 8,192 bytes, THEN THE Config_Extractor SHALL skip the file and SHALL record a `binary_skipped` Diagnostic.
- [ ] R4.6 — tasks 2.1, 3.1 — test_cbom_posture_perf_hostile.py and the hostile fixture — THE Config_Extractor SHALL decode UTF-8 with or without a byte-order mark and UTF-16 with a byte-order mark, and for any other byte sequence SHALL decode with replacement characters and record an `encoding_fallback` D...
- [ ] R4.7 — tasks 2.1, 3.1 — test_cbom_posture_perf_hostile.py and the hostile fixture — WHEN a line is longer than the line limit, THE Config_Extractor SHALL examine only the first bytes of that line up to the limit and SHALL record a `line_cap` Diagnostic.
- [ ] R4.8 — tasks 3.1 — test_cbom_posture_perf_hostile.py and the hostile fixture — IF a YAML document uses a tag that constructs a Python object (for example `!!python/object/apply:os.system`), THEN THE Config_Extractor SHALL reject the document, SHALL execute nothing and SHALL record an `unsafe_tag...
- [ ] R4.9 — tasks 3.1 — test_cbom_posture_perf_hostile.py and the hostile fixture — WHEN a mapping contains the same key more than once, THE Config_Extractor SHALL apply the last definition and SHALL record a `duplicate_key` Diagnostic, so that a later `encrypted: false` cannot be hidden behind an ea...
- [ ] R4.10 — tasks 3.1, 6.3, 10.1 — test_cbom_posture_perf_hostile.py and the hostile fixture — THE Config_Extractor SHALL use only regular expressions that finish within 1 second on every 1 MiB single-line adversarial input in the ReDoS corpus of the Test_Suite.
- [ ] R4.11 — tasks 2.1, 3.1 — test_cbom_posture_perf_hostile.py and the hostile fixture — THE CBOM_Engine SHALL store at most the Diagnostic limit of the Limits Table per scan, SHALL keep exact per-code totals beyond that limit, and SHALL sort stored Diagnostics by path, line and code.
- [ ] R4.12 — tasks 2.1, 3.1 — test_cbom_posture_perf_hostile.py and the hostile fixture — THE Config_Extractor SHALL put into a Diagnostic only the sanitized path, the line number and a closed-vocabulary code, so that scanned text cannot reach logs or PDFs through a Diagnostic.
- [ ] R5.1 — tasks 2.1 — test_cbom_posture_codec.py and test_cbom_posture_canaries.py — THE Config_Extractor SHALL give every Encryption_Fact the fields of Table R5-A.
- [ ] R5.2 — tasks 2.1 — test_cbom_posture_codec.py and test_cbom_posture_canaries.py — THE Config_Extractor SHALL derive the `id` of an Encryption_Fact as a SHA-256 prefix over kind, provider, native type, address and repository-relative path, so that the `id` is stable across runs, hosts and operating...
- [ ] R5.3 — tasks 2.1 — test_cbom_posture_codec.py and test_cbom_posture_canaries.py — THE Config_Extractor SHALL record in `basis` only attributes that the Defaults_Registry rule for the resource kind names, each as an attribute name with either its resolved literal or its `unknown_reason`.
- [ ] R5.4 — tasks 2.1 — test_cbom_posture_codec.py and test_cbom_posture_canaries.py — THE Config_Extractor SHALL discard at parse time the value of every attribute that the rule for the resource kind does not name.
- [ ] R5.5 — tasks 2.1 — test_cbom_posture_codec.py and test_cbom_posture_canaries.py — THE Config_Extractor SHALL exclude from every output the value of an attribute whose name contains `password`, `passwd`, `secret`, `token`, `api_key`, `access_key`, `private_key`, `credential`, `connection_string`, `e...
- [ ] R5.6 — tasks 10.1, 14.2 — test_cbom_posture_codec.py and test_cbom_posture_canaries.py — THE Test_Suite SHALL plant canary secret strings in every fixture tree and SHALL assert zero occurrences of each canary in `cbom_json`, the run-object, the Diagnostics and the text of every Posture_Deliverable.
- [ ] R5.7 — tasks 2.1 — test_cbom_posture_codec.py and test_cbom_posture_canaries.py — THE Config_Extractor SHALL record the 1-based line of the declaring block as the evidence line.
- [ ] R5.8 — tasks 0.10, 5.1 — test_cbom_posture_codec.py and test_cbom_posture_canaries.py — THE Config_Extractor SHALL set `path_context` to `non_production_hint` when any path segment equals, ignoring case, `test`, `tests`, `__tests__`, `spec`, `fixtures`, `testdata`, `example`, `examples`, `sample`, `sampl...
- [ ] R5.9 — tasks 2.1 — test_cbom_posture_codec.py and test_cbom_posture_canaries.py — THE Config_Extractor SHALL sort Encryption_Facts by kind, path, line, address and id.
- [ ] R5.10 — tasks 9.2 — test_cbom_posture_codec.py and test_cbom_posture_canaries.py — IF the number of Encryption_Facts would exceed the fact limit, THEN THE Config_Extractor SHALL keep facts that carry findings first, SHALL drop the rest in sorted order, SHALL set `truncated` to true in the Posture_Bl...
- [ ] R6.1 — tasks 5.1 — test_cbom_posture_verdict.py — THE Verdict_Engine SHALL assign every Encryption_Fact exactly one resource-level Verdict from ENCRYPTED_DECLARED, ENCRYPTED_PROVIDER_DEFAULT, NOT_ENCRYPTED and UNKNOWN, and SHALL record one Verdict for each Layer that...
- [ ] R6.2 — tasks 5.1 — test_cbom_posture_verdict.py — WHEN every decisive attribute of a Layer resolves to an explicitly enabling value, THE Verdict_Engine SHALL assign ENCRYPTED_DECLARED to that Layer.
- [ ] R6.3 — tasks 5.1 — test_cbom_posture_verdict.py — WHEN a decisive attribute is absent and the matching Provider_Defaults_Table row states an encrypted default, THE Verdict_Engine SHALL assign ENCRYPTED_PROVIDER_DEFAULT to that Layer and SHALL record the row id in `de...
- [ ] R6.4 — tasks 5.1 — test_cbom_posture_verdict.py — WHEN a decisive attribute resolves to an explicitly disabling value, or is absent and the matching row states an unencrypted default and is marked `assessable_as_unencrypted`, THE Verdict_Engine SHALL assign NOT_ENCRY...
- [ ] R6.5 — tasks 5.1 — test_cbom_posture_verdict.py — IF a decisive attribute is unresolved, dynamic, templated, defined in an unreachable include, absent without a matching row, or overridden outside the Scanned_Input, THEN THE Verdict_Engine SHALL assign UNKNOWN to tha...
- [ ] R6.6 — tasks 5.1 — test_cbom_posture_verdict.py — THE Verdict_Engine SHALL derive the at-rest Verdict of a resource from its `application`, `database`, `volume`, `service` and `backup` Layers: an encrypted Verdict when any of those Layers is encrypted (ENCRYPTED_DECL...
- [ ] R6.7 — tasks 5.1 — test_cbom_posture_verdict.py — THE Verdict_Engine SHALL keep the `transport` Layer Verdict separate from the at-rest Verdict, and SHALL use the `transport` Verdict as the resource-level Verdict for kinds whose only Layer is `transport`.
- [ ] R6.8 — tasks 5.1 — test_cbom_posture_verdict.py — WHEN a self-hosted software configuration omits a native encryption or transport-security directive, THE Verdict_Engine SHALL assign UNKNOWN with reason `layer_not_observable` to that Layer, and SHALL assign NOT_ENCRY...
- [ ] R6.9 — tasks 0.8, 5.1 — test_cbom_posture_verdict.py — IF a Verdict is UNKNOWN or an attribute is unresolved, THEN THE Verdict_Engine SHALL leave the Posture_Finding set of that Encryption_Fact empty.
- [ ] R6.10 — tasks 5.1 — test_cbom_posture_verdict.py — THE Verdict_Engine SHALL map ENCRYPTED_DECLARED and ENCRYPTED_PROVIDER_DEFAULT to Tri_State pass, NOT_ENCRYPTED to fail and UNKNOWN to NOT_BOM_EVIDENCEABLE, separately for the at-rest Verdict and for the `transport` V...
- [ ] R6.11 — tasks 5.1 — test_cbom_posture_verdict.py — WHEN a declared resource has a native type outside the Coverage_Table, THE Config_Extractor SHALL record the resource only as an OUT_OF_SCOPE count in the Posture_Block counts.
- [ ] R6.12 — tasks 5.1 — test_cbom_posture_verdict.py — THE Verdict_Engine SHALL compute Coverage_Percentage as pass divided by (pass plus fail), SHALL report NOT_BOM_EVIDENCEABLE and OUT_OF_SCOPE as separate counts, and SHALL report null when pass plus fail is zero.
- [ ] R6.13 — tasks 5.1 — test_cbom_posture_verdict.py — THE Verdict_Engine SHALL depend only on parsed attributes and Defaults_Registry rows, with no file access, no clock read and no network access.
- [ ] R6.14 — tasks 5.1 — test_cbom_posture_verdict.py — THE Verdict_Engine SHALL assess the Layers that Table R6-A assigns to each kind and no others.
- [ ] R7.1 — tasks 5.1 — test_cbom_posture_resolve.py — THE Config_Extractor SHALL resolve string, number, boolean and null literals and lists and maps of literals.
- [ ] R7.2 — tasks 5.1 — test_cbom_posture_resolve.py — WHEN a Terraform attribute references `var.<name>`, the `variable` block has a literal `default`, and no `.tfvars` or `.tfvars.json` file in the Scanned_Input assigns a different value, THE Config_Extractor SHALL reso...
- [ ] R7.3 — tasks 5.1 — test_cbom_posture_resolve.py — IF a `.tfvars` or `.tfvars.json` file in the Scanned_Input assigns a variable a value different from its default, THEN THE Config_Extractor SHALL resolve every attribute that references the variable to UNKNOWN with re...
- [ ] R7.4 — tasks 5.1 — test_cbom_posture_resolve.py — IF `var.<name>` has no `default`, THEN THE Config_Extractor SHALL resolve the attribute to UNKNOWN with reason `variable_no_default`.
- [ ] R7.5 — tasks 5.1, 8.2 — test_cbom_posture_resolve.py — IF an attribute is, or contains, a `local.*`, `data.*`, `module.*`, `each.*` or `count.*` reference, a function call, a conditional expression, a `for` expression or a splat, THEN THE Config_Extractor SHALL resolve th...
- [ ] R7.6 — tasks 5.1 — test_cbom_posture_resolve.py — WHEN `count` is the literal 0, THE Config_Extractor SHALL record the resource only in `disabled_resources` of the Posture_Block.
- [ ] R7.7 — tasks 5.1 — test_cbom_posture_resolve.py — WHEN `count` or `for_each` is unresolved, THE Config_Extractor SHALL create the Encryption_Fact with `multiplicity` set to `unknown` and SHALL compute its Verdict from its own attributes.
- [ ] R7.8 — tasks 5.1 — test_cbom_posture_resolve.py — THE Config_Extractor SHALL resolve every attribute inside a `dynamic` block to UNKNOWN with reason `dynamic_block`.
- [ ] R7.9 — tasks 5.1 — test_cbom_posture_resolve.py — WHEN a `module` block is read, THE Config_Extractor SHALL record a `module_call` Diagnostic with the sanitized source string, SHALL treat the module as an unresolved boundary, and SHALL analyse module directories that...
- [ ] R7.10 — tasks 5.1 — test_cbom_posture_resolve.py — WHEN a CloudFormation `Ref` names a Parameter with a `Default`, or an `Fn::Sub` contains only such Parameter references, THE Config_Extractor SHALL resolve the value; WHEN a value depends on `Fn::If`, `Conditions`, `M...
- [ ] R7.11 — tasks 5.1 — test_cbom_posture_resolve.py — WHEN a CloudFormation value is `AWS::NoValue`, THE Config_Extractor SHALL treat the attribute as absent.
- [ ] R7.12 — tasks 5.1 — test_cbom_posture_resolve.py — WHEN a Kubernetes, compose or Dockerfile value contains `{{`, `{%`, `${` or `$(`, THE Config_Extractor SHALL resolve it to UNKNOWN with reason `template_marker`.
- [ ] R7.13 — tasks 5.1 — test_cbom_posture_resolve.py — WHEN a directory contains `Chart.yaml`, THE Config_Extractor SHALL skip its `templates/` subtree and record a `helm_template_skipped` Diagnostic; WHEN a `kustomization.yaml` is present, THE Config_Extractor SHALL reco...
- [ ] R8.1 — tasks 8.2, 9.1 — terraform oracle and the linkage role test — WHEN a Terraform attribute holds a reference `<type>.<name>.<attribute>` that names a resource declared in the Scanned_Input, THE Config_Extractor SHALL link the two Encryption_Facts.
- [ ] R8.2 — tasks 8.2, 9.1 — terraform oracle and the linkage role test — THE Config_Extractor SHALL support both the inline-block form and the separate companion-resource form for every resource kind whose provider moved encryption configuration into a companion resource, so that the same...
- [ ] R8.3 — tasks 8.2, 9.1 — terraform oracle and the linkage role test — WHEN no companion resource references a parent resource, THE Verdict_Engine SHALL apply the Provider_Defaults_Table row for the absent configuration.
- [ ] R8.4 — tasks 8.2, 9.1 — terraform oracle and the linkage role test — THE Config_Extractor SHALL link CloudFormation resources through `Ref` and `Fn::GetAtt` to logical IDs in the same template.
- [ ] R8.5 — tasks 8.2, 9.1 — terraform oracle and the linkage role test — THE Config_Extractor SHALL link Kubernetes `PersistentVolumeClaim` to `StorageClass` through `storageClassName`, `StatefulSet.volumeClaimTemplates` to `StorageClass`, `Ingress` to `Secret` through `tls.secretName`, an...
- [ ] R8.6 — tasks 8.2, 9.1 — terraform oracle and the linkage role test — WHERE a compose service bind-mounts a file that exists in the Scanned_Input, THE Config_Extractor SHALL attach the service name to the Encryption_Fact of that file.
- [ ] R8.7 — tasks 8.2, 9.1 — terraform oracle and the linkage role test — IF a reference names a resource that is not declared in the Scanned_Input, THEN THE Config_Extractor SHALL resolve the dependent attribute to UNKNOWN with reason `unresolved_reference`.
- [ ] R8.8 — tasks 8.2, 9.1 — terraform oracle and the linkage role test — WHEN an nginx `include`, Apache `Include` or `IncludeOptional`, or `sshd_config` `Include` directive names files inside the Scanned_Input, THE Config_Extractor SHALL read those files, expanding globs in ascending path...
- [ ] R8.9 — tasks 8.2, 9.1 — terraform oracle and the linkage role test — IF an include names a file outside the Scanned_Input or beyond the include depth, THEN THE Config_Extractor SHALL resolve the settings that depend on it to UNKNOWN with reason `unresolved_include`.
- [ ] R8.10 — tasks 8.2, 9.1 — terraform oracle and the linkage role test — THE Config_Extractor SHALL produce the same set of linked facts whatever order the files are visited in.
- [ ] R9.1 — tasks 4.1, 6.2, 6.3 — test_cbom_posture_registry_content.py — THE Defaults_Registry SHALL be packaged as versioned data files that the CBOM_Engine loads through `importlib.resources`, so that loading works from the wheel and from the source tree.
- [ ] R9.2 — tasks 4.1, 6.2, 6.3 — test_cbom_posture_registry_content.py — THE Defaults_Registry SHALL give every row these fields: provider or software, resource type or directive, attribute, documented default, encryption effect (ENCRYPTED, NOT_ENCRYPTED or UNKNOWN), `assessable_as_unencry...
- [ ] R9.3 — tasks 4.1, 6.2, 6.3 — test_cbom_posture_registry_content.py — WHEN a row lacks a field, has a non-https URL, or has a URL missing from the reviewed URL allow-list in the Test_Suite, THE Test_Suite SHALL fail.
- [ ] R9.4 — tasks 4.1, 6.2, 6.3 — test_cbom_posture_registry_content.py — THE Defaults_Registry SHALL carry for each data file a `data_version` and a `valid_as_of` date, and THE CBOM_Engine SHALL record the name, `data_version`, `valid_as_of` and SHA-256 of every data file it used in the Po...
- [ ] R9.5 — tasks 4.1, 6.2, 6.3 — test_cbom_posture_registry_content.py — WHEN a Verdict comes from a default, THE Verdict_Engine SHALL record the row id in the Encryption_Fact.
- [ ] R9.6 — tasks 4.1, 6.2, 6.3 — test_cbom_posture_registry_content.py — WHERE a row depends on an account-level or organisation-level setting that can override the default, THE Defaults_Registry SHALL name the overriding resource type, and WHEN the Scanned_Input declares that resource in...
- [ ] R9.7 — tasks 4.1, 6.2, 6.3 — test_cbom_posture_registry_content.py — THE Defaults_Registry SHALL contain at least one row for every attribute the Coverage_Table consults, and at least one TLS_Policy_Registry row for every named policy value the Coverage_Table accepts.
- [ ] R9.8 — tasks 4.1, 6.2, 6.3 — test_cbom_posture_registry_content.py — WHEN a provider or software default varies by provider or software version (for example an nginx, OpenSSH or cloud-provider default) and the Scanned_Input does not pin the version, THE Verdict_Engine SHALL assign UNKN...
- [ ] R9.9 — tasks 4.1, 6.2, 6.3 — test_cbom_posture_registry_content.py — THE CBOM_Engine SHALL read the Defaults_Registry from the installed package only, with no network refresh and no path taken from the environment or from the Scanned_Input.
- [ ] R9.10 — tasks 4.1, 6.2, 6.3 — test_cbom_posture_registry_content.py — THE Repository SHALL author every row only from the vendor or standards documentation named in its URL, and no row SHALL be derived from the rule sources of an open-source scanner.
- [ ] R10.1 — tasks 6.2, 8.2 — test_cbom_posture_coverage_content.py and the parity oracles — THE Config_Extractor SHALL assess in version 1: Terraform (`.tf`, `.tf.json`) for AWS, Azure and GCP; CloudFormation in YAML and JSON; Kubernetes in YAML and JSON; docker-compose; Dockerfile; and the server and databa...
- [ ] R10.2 — tasks 6.2, 8.2 — test_cbom_posture_coverage_content.py and the parity oracles — THE Coverage_Table SHALL contain at least every native type named in Table R10-A and, for each AWS Terraform type that has a CloudFormation equivalent, the CloudFormation type.
- [ ] R10.3 — tasks 6.2, 8.2 — test_cbom_posture_coverage_content.py and the parity oracles — THE Coverage_Table SHALL list, for every native type, the attribute names the Verdict_Engine consults.
- [ ] R10.4 — tasks 6.2, 8.2 — test_cbom_posture_coverage_content.py and the parity oracles — IF a Coverage_Table native type has no positive fixture resource and no negative fixture resource in the Test_Suite, THEN THE Test_Suite SHALL fail.
- [ ] R10.5 — tasks 6.2, 8.2 — test_cbom_posture_coverage_content.py and the parity oracles — FOR EACH AWS Terraform type that has a CloudFormation equivalent, THE Test_Suite SHALL contain a Terraform and CloudFormation fixture pair that express the same intent and SHALL assert that both yield the same Verdict.
- [ ] R10.6 — tasks 6.2, 8.2 — test_cbom_posture_coverage_content.py and the parity oracles — THE Config_Extractor SHALL treat all Terraform files in one directory as one configuration for variable and reference resolution.
- [ ] R10.7 — tasks 6.2, 8.2 — test_cbom_posture_coverage_content.py and the parity oracles — WHEN the Scanned_Input contains a Pulumi project (`Pulumi.yaml`), an Ansible playbook (a YAML list whose items carry `hosts` and `tasks`) or Helm template sources, THE Config_Extractor SHALL parse none of them and SHA...
- [ ] R10.8 — tasks 6.2, 8.2 — test_cbom_posture_coverage_content.py and the parity oracles — WHEN the Scanned_Input contains a `*.tfstate` file, THE Config_Extractor SHALL skip the file and SHALL record a `state_file_ignored` Diagnostic.
- [ ] R10.9 — tasks 6.2, 8.2 — test_cbom_posture_coverage_content.py and the parity oracles — THE Posture_Block SHALL report the number of declared resources by format and provider, the number of Encryption_Facts, the number of OUT_OF_SCOPE resources and the number of disabled resources.
- [ ] R11.1 — tasks 8.2 — synthetic-config-aws-tf oracle — WHEN the Scanned_Input declares a key of a `kms_key` type in Table R10-A, THE Config_Extractor SHALL emit an Encryption_Fact of kind `kms_key` and a linked `related-crypto-material` crypto asset of material kind `key`...
- [ ] R11.2 — tasks 8.2 — synthetic-config-aws-tf oracle — WHEN a key specification maps to an algorithm in the Defaults_Registry (symmetric, asymmetric or message-authentication), THE Config_Extractor SHALL also emit the matching `algorithm` crypto asset with algorithm famil...
- [ ] R11.3 — tasks 8.2 — synthetic-config-aws-tf oracle — WHEN a customer-managed symmetric encryption key supports automatic rotation and the Scanned_Input disables rotation, or omits it where the matching row states a disabled default, THE Config_Extractor SHALL raise `KMS...
- [ ] R11.4 — tasks 8.2 — synthetic-config-aws-tf oracle — WHEN a key is asymmetric, a message-authentication key, an external-origin key, a custom-key-store key or otherwise marked `rotation_supported` false in the Defaults_Registry, THE Config_Extractor SHALL record rotatio...
- [ ] R11.5 — tasks 8.2 — synthetic-config-aws-tf oracle — WHEN an AWS key policy (a `jsonencode` expression, a heredoc JSON string, an `aws_iam_policy_document` data source or a CloudFormation `KeyPolicy`) contains an Allow statement whose principal is `*` or `{"AWS": "*"}`...
- [ ] R11.6 — tasks 8.2 — synthetic-config-aws-tf oracle — WHEN an Azure Key Vault or managed HSM declares purge protection disabled, or omits it where the matching row states a disabled default, THE Config_Extractor SHALL raise `KMS_KEY_DELETION_UNPROTECTED`.
- [ ] R11.7 — tasks 8.2 — synthetic-config-aws-tf oracle — IF a key policy or binding cannot be reduced to statements because its content is dynamic, THEN THE Config_Extractor SHALL record exposure as UNKNOWN with reason `unresolved_expression` and SHALL leave the exposure fi...
- [ ] R11.8 — tasks 8.2 — synthetic-config-aws-tf oracle — WHEN a resource references a key declared in the Scanned_Input through an alias, an ARN expression, a key identifier or a key URL, THE Config_Extractor SHALL set `key_ref` to the `bom-ref` of that key and `key_managem...
- [ ] R11.9 — tasks 8.2 — synthetic-config-aws-tf oracle — WHEN a resource references a provider-managed key alias listed in the Defaults_Registry (for example an AWS-managed alias), THE Config_Extractor SHALL set `key_management` to `provider_managed`.
- [ ] R11.10 — tasks 8.2 — synthetic-config-aws-tf oracle — THE Posture_Block SHALL list for each `kms_key` fact the `id` values of the facts it protects, so that the Posture_Deliverables can show key usage.
- [ ] R12.1 — tasks 8.2, 8.3 — terraform and CloudFormation oracles — FOR EACH declared resource of the kinds `object_store`, `block_volume`, `file_system`, `relational_db`, `nosql_db`, `cache`, `search_index`, `message_queue`, `message_topic`, `data_stream`, `data_warehouse` and `log_s...
- [ ] R12.2 — tasks 8.2, 8.3 — terraform and CloudFormation oracles — WHEN the resource-level Verdict of such a fact is NOT_ENCRYPTED at rest, THE Config_Extractor SHALL raise `UNENCRYPTED_AT_REST`.
- [ ] R12.3 — tasks 8.2, 8.3 — terraform and CloudFormation oracles — WHEN a managed data service declares that plaintext client connections are allowed or that in-transit encryption is disabled (for example a cache with transit encryption off, a broker listener without TLS, a search do...
- [ ] R12.4 — tasks 8.2, 8.3 — terraform and CloudFormation oracles — WHEN a managed data service declares a customer-managed key reference, THE Config_Extractor SHALL apply Requirement 11 criterion 8; WHEN it declares encryption enabled and no key, THE Config_Extractor SHALL set `key_m...
- [ ] R12.5 — tasks 8.2, 8.3 — terraform and CloudFormation oracles — WHEN the Scanned_Input declares an account-level or region-level default-encryption resource (for example `aws_ebs_encryption_by_default`) in the same Terraform configuration and the same provider alias as a volume th...
- [ ] R12.6 — tasks 8.2, 8.3 — terraform and CloudFormation oracles — WHEN a CloudFormation `AWS::EC2::Volume`, `AWS::RDS::DBInstance` or other covered type omits its encryption attribute, THE Verdict_Engine SHALL apply the same Provider_Defaults_Table row that applies to the equivalent...
- [ ] R12.7 — tasks 8.2, 8.3 — terraform and CloudFormation oracles — THE Config_Extractor SHALL record for each fact the declared key custody class (`provider_managed`, `customer_managed`, `unspecified`) so that later specs can use it without re-parsing.
- [ ] R13.1 — tasks 6.2, 8.4 — TLS policy rows in the AWS and CloudFormation oracles — WHEN the Scanned_Input declares a resource of a `tls_endpoint` type in Table R10-A, THE Config_Extractor SHALL emit an Encryption_Fact of kind `tls_endpoint` with a `transport` Layer and a linked `protocol` crypto ass...
- [ ] R13.2 — tasks 6.2, 8.4 — TLS policy rows in the AWS and CloudFormation oracles — THE Config_Extractor SHALL set on that `protocol` asset `crypto:protocolVersion` to the minimum protocol version the declared policy permits, `crypto:maxProtocolVersion` where the policy states one, `crypto:cipherSuit...
- [ ] R13.3 — tasks 6.2, 8.4 — TLS policy rows in the AWS and CloudFormation oracles — WHEN a policy is declared by name, THE Config_Extractor SHALL resolve the minimum version and cipher set through the TLS_Policy_Registry, and WHEN the name is absent from the registry THE Config_Extractor SHALL assign...
- [ ] R13.4 — tasks 6.2, 8.4 — TLS policy rows in the AWS and CloudFormation oracles — WHEN a listener or distribution omits a policy, THE Verdict_Engine SHALL apply the TLS_Policy_Registry row for the default of that resource type, and WHEN the default depends on a version the Scanned_Input does not pi...
- [ ] R13.5 — tasks 6.2, 8.4 — TLS policy rows in the AWS and CloudFormation oracles — WHEN the declared viewer certificate or listener certificate is the provider's default certificate, THE Verdict_Engine SHALL apply the TLS_Policy_Registry row that the registry defines for that case.
- [ ] R13.6 — tasks 6.2, 8.4 — TLS policy rows in the AWS and CloudFormation oracles — WHEN a load balancer, CDN, API gateway or web-app listener serves plaintext (an HTTP protocol, a viewer protocol policy that allows HTTP, a TCP listener without TLS) and declares no redirect to HTTPS and no forced-HTT...
- [ ] R13.7 — tasks 6.2, 8.4 — TLS policy rows in the AWS and CloudFormation oracles — WHEN such a listener declares a redirect to HTTPS or a forced-HTTPS flag, THE Config_Extractor SHALL record the `transport` Layer as ENCRYPTED_DECLARED and SHALL leave the listener finding set empty.
- [ ] R13.8 — tasks 6.2, 8.4 — TLS policy rows in the AWS and CloudFormation oracles — WHEN a CDN origin connection is declared plaintext (for example an origin protocol policy of HTTP only), THE Config_Extractor SHALL raise `UNENCRYPTED_IN_TRANSIT`.
- [ ] R13.9 — tasks 6.2, 8.4 — TLS policy rows in the AWS and CloudFormation oracles — THE CBOM_Engine SHALL raise `WEAK_PROTOCOL` and `WEAK_CIPHER_SUITE` on these `protocol` assets through the existing predicates in `aibom/src/aibom/cbom/weakness.py`, and THE Repository SHALL keep those predicates unch...
- [ ] R14.1 — tasks 8.2, 8.3 — Kubernetes and cert-manager oracles — WHEN the Scanned_Input declares a resource of a `secret_store` type in Table R10-A, THE Config_Extractor SHALL emit an Encryption_Fact with a `service` Layer Verdict and a `key_management` value, and SHALL exclude sec...
- [ ] R14.2 — tasks 8.2, 8.3 — Kubernetes and cert-manager oracles — WHEN a Kubernetes `Secret` is read, THE Config_Extractor SHALL record only its name, namespace and type.
- [ ] R14.3 — tasks 8.2, 8.3 — Kubernetes and cert-manager oracles — WHEN a resource of a `certificate_policy` type declares a private-key algorithm together with a key size or curve (for example `key_algorithm`, `privateKey.algorithm`, `privateKey.size`, `key_properties`), THE Config_...
- [ ] R14.4 — tasks 8.2, 8.3 — Kubernetes and cert-manager oracles — WHEN a certificate policy declares whether the private key is reused or rotated on renewal (for example cert-manager `rotationPolicy`, Key Vault `reuse_key`), THE Config_Extractor SHALL record the setting as an attrib...
- [ ] R14.5 — tasks 8.2, 8.3 — Kubernetes and cert-manager oracles — WHEN an `Ingress`, Istio `Gateway` or Traefik route terminates TLS with a secret that no `Secret`, `Certificate` or external-secret declaration in the Scanned_Input provides, THE Config_Extractor SHALL record `key_ref...
- [ ] R14.6 — tasks 8.2, 8.3 — Kubernetes and cert-manager oracles — WHEN a certificate authority resource declares a signing algorithm, THE Config_Extractor SHALL emit an `algorithm` crypto asset for the signing algorithm and the key algorithm.
- [ ] R15.1 — tasks 5.1 — test_cbom_posture_findings.py and test_cbom_posture_text.py — THE Finding_Catalog SHALL define exactly the codes of Table R15-A, each with severity class, SARIF level, weight, trigger and anchor.
- [ ] R15.2 — tasks 0.8, 5.1 — test_cbom_posture_findings.py and test_cbom_posture_text.py — THE Config_Extractor SHALL raise a Finding_Catalog code only from an explicit declaration, an explicit imported result, or a Defaults_Registry row marked `assessable_as_unencrypted`; an UNKNOWN Verdict SHALL leave the...
- [ ] R15.3 — tasks 5.1 — test_cbom_posture_findings.py and test_cbom_posture_text.py — THE Config_Extractor SHALL map severity class High to SARIF level `error`, Medium to `warning` and Low to `note`.
- [ ] R15.4 — tasks 5.1 — test_cbom_posture_findings.py and test_cbom_posture_text.py — THE Config_Extractor SHALL give every Posture_Finding a message that names the resource, the evidence path and line, and the remediation action, and that contains no excluded secret value.
- [ ] R15.5 — tasks 5.1 — test_cbom_posture_findings.py and test_cbom_posture_text.py — THE CBOM_Engine SHALL export the Finding_Catalog codes as a frozen set `POSTURE_CODES` that is distinct from `WEAK_CRYPTO_CODES`.
- [ ] R15.6 — tasks 12.1 — test_cbom_posture_findings.py and test_cbom_posture_text.py — THE Deliverable_Renderer SHALL take the label and remediation text of each code from the authored-text module `backend/utilities/pdf/cbom_deliverable_text.py`, each remediation carrying a `# Source:` comment with a pu...
- [ ] R15.7 — tasks 9.3 — test_cbom_posture_findings.py and test_cbom_posture_text.py — WHEN new assets raise the existing codes WEAK_PROTOCOL, WEAK_CIPHER_SUITE, WEAK_KEY_SIZE, WEAK_ALGORITHM, WEAK_CERTIFICATE_SIGNATURE, WEAK_CERTIFICATE_KEY, EXPIRED_CERTIFICATE, SELF_SIGNED_LEAF, QUANTUM_VULNERABLE or...
- [ ] R16.1 — tasks 8.3, 8.5 — compose, Kubernetes, and database oracles — THE Config_Extractor SHALL inventory data stores of the kinds `object_store`, `block_volume`, `file_system`, `relational_db`, `nosql_db`, `cache`, `search_index`, `message_queue`, `data_stream`, `data_warehouse`, `bac...
- [ ] R16.2 — tasks 8.3, 8.5 — compose, Kubernetes, and database oracles — THE Config_Extractor SHALL recognise a self-hosted data-store service when a compose service image or a Kubernetes container image has a repository name in the curated data-store image list of the Defaults_Registry, m...
- [ ] R16.3 — tasks 8.3, 8.5 — compose, Kubernetes, and database oracles — WHEN a Kubernetes `StatefulSet` declares `volumeClaimTemplates`, or a compose service declares a volume, THE Config_Extractor SHALL link the service to its volume; named volumes, `emptyDir` and `hostPath` volumes SHAL...
- [ ] R16.4 — tasks 8.3, 8.5 — compose, Kubernetes, and database oracles — WHEN a `StorageClass` declares a provisioner and parameters, THE Verdict_Engine SHALL assign the `volume` Layer Verdict of every claim that references it from the per-provisioner rows of the Provider_Defaults_Table.
- [ ] R16.5 — tasks 8.3, 8.5 — compose, Kubernetes, and database oracles — WHEN a backup, snapshot or copy resource declares an encryption attribute or key, THE Config_Extractor SHALL assign the `backup` Layer Verdict from it.
- [ ] R16.6 — tasks 8.3, 8.5 — compose, Kubernetes, and database oracles — WHEN a snapshot inherits encryption from a source resource declared in the Scanned_Input, THE Verdict_Engine SHALL inherit the Verdict of the source, and WHEN the source Verdict is UNKNOWN THE Verdict_Engine SHALL ass...
- [ ] R16.7 — tasks 8.3, 8.5 — compose, Kubernetes, and database oracles — WHEN a data store declares backup retention or point-in-time recovery, THE Config_Extractor SHALL record the setting as an attribute.
- [ ] R16.8 — tasks 8.3, 8.5 — compose, Kubernetes, and database oracles — THE Posture_Block SHALL report counts of Encryption_Facts by kind, provider and Verdict.
- [ ] R17.1 — tasks 8.3 — synthetic-config-k8s oracle — WHEN an `EncryptionConfiguration` document (API group `apiserver.config.k8s.io`) is read, THE Config_Extractor SHALL emit an Encryption_Fact of kind `k8s_secrets_etcd` and SHALL evaluate the provider list of the resou...
- [ ] R17.2 — tasks 8.3 — synthetic-config-k8s oracle — IF the first provider is `identity`, or no resource entry includes `secrets`, THEN THE Verdict_Engine SHALL assign the `database` Layer NOT_ENCRYPTED and THE Config_Extractor SHALL raise `UNENCRYPTED_AT_REST`.
- [ ] R17.3 — tasks 8.3 — synthetic-config-k8s oracle — WHEN the first provider is `kms`, THE Verdict_Engine SHALL assign ENCRYPTED_DECLARED and `key_management` `customer_managed`.
- [ ] R17.4 — tasks 8.3 — synthetic-config-k8s oracle — WHEN the first provider is `secretbox`, THE Verdict_Engine SHALL assign ENCRYPTED_DECLARED and record key custody as `local_file`.
- [ ] R17.5 — tasks 8.3 — synthetic-config-k8s oracle — WHEN the first provider is `aescbc` or `aesgcm`, THE Verdict_Engine SHALL assign ENCRYPTED_DECLARED, record key custody as `local_file`, and THE Config_Extractor SHALL raise `AT_REST_ENCRYPTION_WEAK` with the rational...
- [ ] R17.6 — tasks 8.3 — synthetic-config-k8s oracle — WHEN a provider entry carries a literal key value in the file, THE Config_Extractor SHALL emit a `related-crypto-material` crypto asset of material kind `secret-key` with `crypto:hardcoded` set to true and without the...
- [ ] R17.7 — tasks 8.3 — synthetic-config-k8s oracle — WHEN a managed-cluster resource (`aws_eks_cluster`, `azurerm_kubernetes_cluster`, `google_container_cluster`) declares or omits its secrets-encryption option, THE Verdict_Engine SHALL assign the Verdict from the match...
- [ ] R17.8 — tasks 8.3 — synthetic-config-k8s oracle — WHEN a kube-apiserver static pod manifest is read, THE Config_Extractor SHALL record whether `--encryption-provider-config` is present and SHALL link it to an `EncryptionConfiguration` file inside the Scanned_Input by...
- [ ] R17.9 — tasks 8.3 — synthetic-config-k8s oracle — WHEN the Scanned_Input holds no `EncryptionConfiguration`, no kube-apiserver manifest and no managed-cluster resource, THE Config_Extractor SHALL emit zero `k8s_secrets_etcd` facts.
- [ ] R18.1 — tasks 8.5 — test_cbom_posture_settings_databases.py — WHEN a database configuration file sets a native at-rest directive listed in Table R18-A, THE Verdict_Engine SHALL assign the `database` Layer ENCRYPTED_DECLARED.
- [ ] R18.2 — tasks 8.5 — test_cbom_posture_settings_databases.py — WHEN a directive of Table R18-A is explicitly set to a disabling value, THE Verdict_Engine SHALL assign the `database` Layer NOT_ENCRYPTED, and the resource-level Verdict SHALL follow Requirement 6 criterion 6.
- [ ] R18.3 — tasks 8.5 — test_cbom_posture_settings_databases.py — WHEN a database configuration for PostgreSQL, Redis or Elasticsearch has no native at-rest directive, THE Verdict_Engine SHALL assign the `database` Layer UNKNOWN with reason `layer_not_observable`.
- [ ] R18.4 — tasks 8.5 — test_cbom_posture_settings_databases.py — WHEN local-file key custody is declared (a file keyring plugin, an encryption key file), THE Config_Extractor SHALL raise `AT_REST_ENCRYPTION_WEAK`.
- [ ] R18.5 — tasks 8.5 — test_cbom_posture_settings_databases.py — WHEN an `/etc/crypttab` file or a `cryptsetup` `luksFormat`, `luksOpen` or `open` invocation is read, THE Config_Extractor SHALL emit an Encryption_Fact of kind `disk_encryption` with the `volume` Layer ENCRYPTED_DECL...
- [ ] R18.6 — tasks 8.5 — test_cbom_posture_settings_databases.py — WHEN a `crypttab` entry uses a random keyfile such as `/dev/urandom`, THE Config_Extractor SHALL record the volume as `ephemeral` encryption; WHEN the keyfile field is `none`, THE Config_Extractor SHALL record the key...
- [ ] R18.7 — tasks 8.5 — test_cbom_posture_settings_databases.py — WHEN a `*.sql` file contains `CREATE DATABASE ENCRYPTION KEY`, `ALTER DATABASE ... SET ENCRYPTION ON`, `ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY`, a MySQL table option `ENCRYPTION='Y'`, or a PostgreSQL `pgp_sym_encrypt`...
- [ ] R18.8 — tasks 8.5 — test_cbom_posture_settings_databases.py — WHEN a database configuration loads an extension that the Defaults_Registry lists as a native at-rest mechanism, THE Config_Extractor SHALL treat the load as evidence at the `database` Layer.
- [ ] R18.9 — tasks 8.5 — test_cbom_posture_settings_databases.py — THE Config_Extractor SHALL take SDK-level encryption evidence from the existing algorithm and library inventory only, and that evidence SHALL leave the Verdict of every resource unchanged.
- [ ] R19.1 — tasks 8.7 — synthetic-config-mapping oracle and test_cbom_posture_docs.py — THE Config_Extractor SHALL read an optional Business_Mapping_File from the Scanned_Input root, using the first existing file in this order: `.devsecshield/cbom-mapping.yaml`, `.devsecshield/cbom-mapping.json`, `cbom-m...
- [ ] R19.2 — tasks 8.7 — synthetic-config-mapping oracle and test_cbom_posture_docs.py — THE Business_Mapping_File SHALL follow the schema of Table R19-A.
- [ ] R19.3 — tasks 8.7 — synthetic-config-mapping oracle and test_cbom_posture_docs.py — WHEN an entry gives `resource`, `path` or `kind` selectors, THE Config_Extractor SHALL apply the entry to an Encryption_Fact only when every given selector matches, and WHEN several entries match THE Config_Extractor...
- [ ] R19.4 — tasks 8.7 — synthetic-config-mapping oracle and test_cbom_posture_docs.py — THE Config_Extractor SHALL accept each string value up to 256 characters after removing control characters, SHALL ignore unknown keys with a `mapping_unknown_key` Diagnostic, SHALL skip an invalid entry with a `mappin...
- [ ] R19.5 — tasks 8.7 — synthetic-config-mapping oracle and test_cbom_posture_docs.py — THE Config_Extractor SHALL store matched values in the `linkage` field with source `mapping_file`, and THE Deliverable_Renderer SHALL print them labelled as declared in the repository mapping file and not verified.
- [ ] R19.6 — tasks 8.7 — synthetic-config-mapping oracle and test_cbom_posture_docs.py — THE Config_Extractor SHALL read the first existing file of `.github/CODEOWNERS`, `CODEOWNERS` and `docs/CODEOWNERS` with GitHub semantics: the last matching pattern wins, patterns are gitignore-style globs (`*`, `**`,...
- [ ] R19.7 — tasks 8.7 — synthetic-config-mapping oracle and test_cbom_posture_docs.py — IF a CODEOWNERS pattern uses unsupported syntax (negation, character classes), THEN THE Config_Extractor SHALL skip that pattern and record a `codeowners_pattern_unsupported` Diagnostic.
- [ ] R19.8 — tasks 8.7 — synthetic-config-mapping oracle and test_cbom_posture_docs.py — THE Config_Extractor SHALL set the Owner_Hint (`owner_hint`) from the owners of the last CODEOWNERS pattern that matches the evidence path of the fact, with source `codeowners`, and THE Deliverable_Renderer SHALL show...
- [ ] R19.9 — tasks 8.7 — synthetic-config-mapping oracle and test_cbom_posture_docs.py — WHEN neither a Business_Mapping_File entry nor a CODEOWNERS pattern applies to a fact, THE Deliverable_Renderer SHALL print Assessor_Cells for system, owner, data classification and data lifetime.
- [ ] R19.10 — tasks 8.7 — synthetic-config-mapping oracle and test_cbom_posture_docs.py — THE Config_Extractor SHALL treat data classification and data lifetime values as free text and SHALL assign no classification grade or Q-level.
- [ ] R19.11 — tasks 8.7 — synthetic-config-mapping oracle and test_cbom_posture_docs.py — THE Config_Extractor SHALL obtain the mapping from the Scanned_Input alone, with zero new database tables, API fields and user-interface forms.
- [ ] R19.12 — tasks 16.1 — synthetic-config-mapping oracle and test_cbom_posture_docs.py — THE Repository SHALL document the schema, selector semantics, precedence and an example in `docs/cbom-posture/`.
- [ ] R20.1 — tasks 8.4 — test_cbom_posture_settings_servers.py — THE Config_Extractor SHALL read the settings of Table R20-A for each supported server and SHALL emit, per listener, virtual host, connector or server block, an Encryption_Fact of kind `tls_endpoint` (or `ssh_service`)...
- [ ] R20.2 — tasks 8.4 — test_cbom_posture_settings_servers.py — THE Config_Extractor SHALL apply the documented scope, inheritance and override rules of each server: the `http`, `server` and `location` contexts of nginx, the global and `VirtualHost` contexts of Apache httpd, the `...
- [ ] R20.3 — tasks 8.4 — test_cbom_posture_settings_servers.py — THE Config_Extractor SHALL interpret protocol and cipher exclusions by their meaning (for example an Apache `SSLProtocol -all +TLSv1.2`, an HAProxy `no-tlsv10`, a Jetty `ExcludeProtocols`), so that a directive that di...
- [ ] R20.4 — tasks 8.4 — test_cbom_posture_settings_servers.py — WHEN a directive that fixes the protocol floor is absent and the server default depends on the server version, THE Verdict_Engine SHALL assign UNKNOWN with reason `provider_version_dependent`, and the `protocol` asset...
- [ ] R20.5 — tasks 8.4 — test_cbom_posture_settings_servers.py — WHEN a server block listens without TLS and configures no redirect to HTTPS in that block, THE Config_Extractor SHALL raise `PLAINTEXT_LISTENER`, and WHEN the block redirects to HTTPS THE Config_Extractor SHALL record...
- [ ] R20.6 — tasks 8.4 — test_cbom_posture_settings_servers.py — WHEN an Istio `PeerAuthentication` sets mutual-TLS mode `PERMISSIVE` or `DISABLE`, THE Config_Extractor SHALL raise `PLAINTEXT_LISTENER`.
- [ ] R20.7 — tasks 8.4 — test_cbom_posture_settings_servers.py — WHEN an OpenSSH algorithm list is written, THE Config_Extractor SHALL evaluate weakness from the algorithms the file names explicitly, counting a `+` addition as enabled and assuming no algorithm of the version-depend...
- [ ] R20.8 — tasks 8.4 — test_cbom_posture_settings_servers.py — WHEN an explicit protocol floor of TLS 1.2 or later and an explicit cipher list that the existing predicates classify as acceptable are both declared, THE Config_Extractor SHALL set `crypto:strength` to `strong`.
- [ ] R20.9 — tasks 8.4 — test_cbom_posture_settings_servers.py — WHEN a `Strict-Transport-Security` header is configured, THE Config_Extractor SHALL record its presence and `max-age` as an attribute, and the absence of the header SHALL leave the finding set empty.
- [ ] R20.10 — tasks 8.4 — test_cbom_posture_settings_servers.py — WHEN a certificate or key file path is declared and the file exists in the Scanned_Input, THE Config_Extractor SHALL link the `protocol` asset to the existing certificate asset of that file.
- [ ] R21.1 — tasks 8.5 — test_cbom_posture_settings_databases.py — THE Config_Extractor SHALL read the settings of Table R21-A for PostgreSQL, MySQL and MariaDB, MongoDB, Elasticsearch and Redis, and SHALL emit an Encryption_Fact of kind `relational_db`, `nosql_db`, `cache` or `searc...
- [ ] R21.2 — tasks 8.5 — test_cbom_posture_settings_databases.py — WHEN a configuration explicitly disables TLS (`ssl = off`, `net.tls.mode: disabled`, `xpack.security.http.ssl.enabled: false`, `skip_ssl`), THE Verdict_Engine SHALL assign the `transport` Layer NOT_ENCRYPTED and THE C...
- [ ] R21.3 — tasks 8.5 — test_cbom_posture_settings_databases.py — WHEN a configuration explicitly permits plaintext next to TLS (`net.tls.mode` of `allowTLS` or `preferTLS`, or a Redis `port` greater than 0 together with a non-loopback `bind`), THE Verdict_Engine SHALL assign the `t...
- [ ] R21.4 — tasks 8.5 — test_cbom_posture_settings_databases.py — WHEN a PostgreSQL `pg_hba.conf` record of type `host` or `hostnossl` covers a non-loopback address, THE Verdict_Engine SHALL assign the `transport` Layer NOT_ENCRYPTED, and WHEN every non-loopback record is of type `h...
- [ ] R21.5 — tasks 8.5 — test_cbom_posture_settings_databases.py — WHEN a setting that decides transport security is absent from a self-hosted configuration, THE Verdict_Engine SHALL apply Requirement 6 criterion 8.
- [ ] R21.6 — tasks 8.5 — test_cbom_posture_settings_databases.py — WHEN a configuration names a protocol floor, a protocol list, a cipher list or a curve list, THE Config_Extractor SHALL emit a linked `protocol` crypto asset with the same properties as Requirement 20 criterion 1, so...
- [ ] R21.7 — tasks 8.5 — test_cbom_posture_settings_databases.py — WHEN a configuration switches peer-certificate validation off (`net.tls.allowInvalidCertificates: true`, `net.tls.allowInvalidHostnames: true`, `xpack.security.transport.ssl.verification_mode: none`), THE Config_Extra...
- [ ] R22.1 — tasks 8.1 — cipher tests against naive_ciphers.py — THE Config_Extractor SHALL expand OpenSSL cipher strings (nginx `ssl_ciphers`, Apache `SSLCipherSuite`, HAProxy `ciphers`, PostgreSQL `ssl_ciphers`, MySQL `ssl_cipher`, Redis `tls-ciphers`) against the cipher registry...
- [ ] R22.2 — tasks 8.1 — cipher tests against naive_ciphers.py — WHEN a cipher string contains a token the evaluator cannot expand, THE Config_Extractor SHALL mark the cipher set UNKNOWN with reason `unresolved_expression`, SHALL not set `crypto:strength` to `strong`, and SHALL sti...
- [ ] R22.3 — tasks 8.1 — cipher tests against naive_ciphers.py — THE Config_Extractor SHALL map every permitted suite to its IANA name through the cipher registry and SHALL pass the result in `crypto:cipherSuite` to the existing `cipher_suite_findings` predicate, so that code-sourc...
- [ ] R22.4 — tasks 8.1 — cipher tests against naive_ciphers.py — THE Config_Extractor SHALL evaluate TLS 1.3 suite lists (`ciphersuites`, `tls-ciphersuites`, `ssl-default-bind-ciphersuites`) by name against the cipher registry.
- [ ] R22.5 — tasks 8.1 — cipher tests against naive_ciphers.py — THE Config_Extractor SHALL classify named curve and group lists (`ssl_ecdh_curve`, `curves`, `ecdh_curves`, `curvePreferences`) against the key-exchange registry and SHALL record each curve below 224 bits as weak.
- [ ] R22.6 — tasks 8.1 — cipher tests against naive_ciphers.py — WHEN `ssl_dhparam` or `SSLOpenSSLConfCmd DHParameters` names a PEM file inside the Scanned_Input, THE Config_Extractor SHALL read the prime size from it and SHALL emit a Diffie-Hellman `algorithm` crypto asset with th...
- [ ] R22.7 — tasks 8.1 — cipher tests against naive_ciphers.py — THE Config_Extractor SHALL be total and deterministic: for every string of a seeded random corpus it SHALL return a result without raising, and for every documented example string in the Oracle it SHALL return the han...
- [ ] R22.8 — tasks 6.2, 6.3 — cipher tests against naive_ciphers.py — THE Defaults_Registry SHALL derive the cipher registry from the public IANA TLS parameters registry and the public OpenSSL cipher-list documentation, each with a source URL and a `valid_as_of` date.
- [ ] R23.1 — tasks 8.6 — synthetic-config-code-tls oracle — THE Config_Extractor SHALL detect the patterns of the verification pattern list in the Defaults_Registry in source files of the languages in `LANGUAGE_EXTENSIONS`, in Dockerfiles, in compose `environment` and `command...
- [ ] R23.2 — tasks 8.6 — synthetic-config-code-tls oracle — THE verification pattern list SHALL contain at least: Python `verify=False` on `requests`, `httpx` and `urllib3` calls, `ssl._create_unverified_context`, `ssl.CERT_NONE` and `check_hostname = False`; Go `InsecureSkipV...
- [ ] R23.3 — tasks 8.6 — synthetic-config-code-tls oracle — WHEN a pattern matches in code that is not a comment or a docstring, THE Config_Extractor SHALL emit a `protocol` crypto asset of type `tls` with `crypto:verification` set to `disabled` and SHALL raise `TLS_VERIFICATI...
- [ ] R23.4 — tasks 8.6 — synthetic-config-code-tls oracle — THE Config_Extractor SHALL blank comments and docstrings before matching, so that prose cannot produce a finding.
- [ ] R23.5 — tasks 8.6 — synthetic-config-code-tls oracle — WHEN a Java option, Node.js option or environment variable pins a protocol version below TLS 1.2 (for example `-Dhttps.protocols=TLSv1`, `-Djdk.tls.client.protocols=TLSv1`, `--tls-min-v1.0`), THE Config_Extractor SHAL...
- [ ] R23.6 — tasks 8.6 — synthetic-config-code-tls oracle — WHEN a match lies under a path whose `path_context` is `non_production_hint`, THE Config_Extractor SHALL still raise the finding and SHALL record the `path_context` so that the report shows it.
- [ ] R23.7 — tasks 8.6 — synthetic-config-code-tls oracle — THE Config_Extractor SHALL leave the behaviour of the existing source-level `ProtocolScanner` unchanged, and SHALL produce zero additional components and flags on every Frozen_Golden fixture.
- [ ] R23.8 — tasks 8.6 — synthetic-config-code-tls oracle — THE verification pattern list SHALL cite for each entry a public URL and the anchor CWE-295.
- [ ] R24.1 — tasks 8.8 — TLS import tests — THE TLS_Result_Importer SHALL decide the producing tool by content signature and not by file name: testssl.sh JSON in its flat form (an array of objects with `id`, `finding`, `severity`, `ip` and `port`) and its prett...
- [ ] R24.2 — tasks 8.8 — TLS import tests — THE TLS_Result_Importer SHALL support every format variant that the design lists in its Format Register, and each variant SHALL have a committed sample authored by hand from the public documentation of the tool's output.
- [ ] R24.3 — tasks 8.8 — TLS import tests — IF a candidate file's tool or format version is absent from the Format Register, THEN THE TLS_Result_Importer SHALL import nothing from it and SHALL record an `unsupported_result_format` Diagnostic with the tool name...
- [ ] R24.4 — tasks 8.8 — TLS import tests — THE TLS_Result_Importer SHALL treat every host name, IP address, URL and port in a file as an inert string: it SHALL open no socket, resolve no name, contact no host and start no process.
- [ ] R24.5 — tasks 8.8 — TLS import tests — WHEN an nmap XML file starts with a bare `<!DOCTYPE nmaprun>` declaration, THE TLS_Result_Importer SHALL parse it, and WHEN an XML file declares an internal subset, an entity or an external identifier, THE TLS_Result_...
- [ ] R24.6 — tasks 8.8 — TLS import tests — THE TLS_Result_Importer SHALL apply the TLS result file size limit, the nesting depth limit and the Requirement 4 criteria on duplicate keys and control characters to every result file.
- [ ] R24.7 — tasks 8.8 — TLS import tests — THE TLS_Result_Importer SHALL emit one Encryption_Fact of kind `tls_endpoint` with `format` `import` for each endpoint of a file, identified by host, port and source file, and SHALL sanitize host strings to at most 51...
- [ ] R24.8 — tasks 8.8 — TLS import tests — THE TLS_Result_Importer SHALL record per file the sanitized path, the tool, the tool version and the scan start and end times exactly as the file states them (null when absent), and SHALL read neither the wall clock n...
- [ ] R24.9 — tasks 8.8 — TLS import tests — THE Test_Suite SHALL use only reserved example domains (`example.com`, `example.org`, `.test`, `.invalid`) and documentation address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) in result-file samples.
- [ ] R25.1 — tasks 8.8 — TLS import tests and deliverable #6 — FOR EACH endpoint, THE TLS_Result_Importer SHALL extract, when the tool reports them: the protocol versions offered (SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3), the cipher suites accepted per version, forward-secrecy suppo...
- [ ] R25.2 — tasks 8.8 — TLS import tests and deliverable #6 — THE TLS_Result_Importer SHALL emit per endpoint one `protocol` crypto asset of type `tls` with `crypto:protocolVersion` set to the lowest version offered, `crypto:maxProtocolVersion` to the highest, `crypto:cipherSuit...
- [ ] R25.3 — tasks 8.8 — TLS import tests and deliverable #6 — WHEN a result contains peer certificate attributes, THE TLS_Result_Importer SHALL emit a `certificate` crypto asset with the existing `crypto:` certificate properties, with `discovery:source` set to the result file an...
- [ ] R25.4 — tasks 8.8 — TLS import tests and deliverable #6 — WHEN a result reports a Diffie-Hellman or ephemeral key size below 2048 bits, THE TLS_Result_Importer SHALL emit a Diffie-Hellman `algorithm` asset with that size.
- [ ] R25.5 — tasks 8.8 — TLS import tests and deliverable #6 — WHEN a result shows SSLv3, TLS 1.0 or TLS 1.1 offered and TLS_FALLBACK_SCSV reported as not supported, THE TLS_Result_Importer SHALL raise `DOWNGRADE_PROTECTION_MISSING`.
- [ ] R25.6 — tasks 8.8 — TLS import tests and deliverable #6 — WHEN a result reports an entry of Table R25-A marked scored as vulnerable, THE TLS_Result_Importer SHALL raise `KNOWN_TLS_VULNERABILITY` with `crypto:vulnerability` naming the entry.
- [ ] R25.7 — tasks 8.8 — TLS import tests and deliverable #6 — THE TLS_Result_Importer SHALL map every tool-reported status to the closed vocabulary `vulnerable`, `not_vulnerable`, `potentially`, `not_tested`, `error`, and SHALL raise findings only for `vulnerable`.
- [ ] R25.8 — tasks 8.8 — TLS import tests and deliverable #6 — WHEN an item is `not_tested` or `error`, THE TLS_Result_Importer SHALL record UNKNOWN with reason `import_not_tested` and SHALL raise no finding.
- [ ] R25.9 — tasks 8.8 — TLS import tests and deliverable #6 — WHEN the same host and port appear in more than one imported file, THE TLS_Result_Importer SHALL keep each as a separate Encryption_Fact tagged with its file.
- [ ] R25.10 — tasks 11.1, 13.1 — TLS import tests and deliverable #6 — WHEN a static server fact and an imported result carry the identical `host:port` string, THE Team_Rollup SHALL list both rows adjacent and SHALL flag a discrepancy when the static protocol floor is higher than the low...
- [ ] R26.1 — tasks 9.2 — test_cbom_posture_block_schema.py and the emit tests — WHEN a ScanResult is emitted, THE CBOM_Emitter SHALL produce a document that validates against the bundled CycloneDX 1.6 schema through the existing `emit_and_validate` path, and a schema-invalid document SHALL fail t...
- [ ] R26.2 — tasks 9.2 — test_cbom_posture_block_schema.py and the emit tests — THE CBOM_Emitter SHALL represent facts that are cryptographic assets under CycloneDX 1.6 (KMS keys, TLS and SSH protocols, algorithms, certificates, hard-coded key material) as components of type `cryptographic-asset`...
- [ ] R26.3 — tasks 9.2 — test_cbom_posture_block_schema.py and the emit tests — THE CBOM_Emitter SHALL represent every other Encryption_Fact as a component whose `type` is a CycloneDX 1.6 component type and whose detail is carried in namespaced `properties` using the `crypto:` namespace (and `dis...
- [ ] R26.4 — tasks 9.2 — test_cbom_posture_block_schema.py and the emit tests — WHEN a resource is protected by a key that is declared in the Scanned_Input, THE CBOM_Emitter SHALL express the link as a CycloneDX `dependencies` entry in which the resource depends on the key.
- [ ] R26.5 — tasks 16.1 — test_cbom_posture_block_schema.py and the emit tests — THE Repository SHALL list every new `crypto:` property key, its type and its allowed values in a property dictionary under `docs/cbom-posture/`, and THE Test_Suite SHALL fail WHEN an emitted key is missing from the di...
- [ ] R26.6 — tasks 1.2, 9.2 — test_cbom_posture_block_schema.py and the emit tests — WHEN a ScanResult holds zero Encryption_Facts and zero new crypto assets, THE CBOM_Emitter SHALL produce a document byte-identical to the Base_Commit output.
- [ ] R26.7 — tasks 9.2 — test_cbom_posture_block_schema.py and the emit tests — IF the components added by the posture lanes would exceed the component limit, THEN THE CBOM_Emitter SHALL keep the components of facts with findings first, SHALL set the BOM property `crypto:postureTruncated` to true...
- [ ] R26.8 — tasks 9.2 — test_cbom_posture_block_schema.py and the emit tests — THE Test_Suite SHALL validate the emitted BOM of every new fixture tree against the bundled schema.
- [ ] R26.9 — tasks 9.2 — test_cbom_posture_block_schema.py and the emit tests — THE CERT-In VEX builder, the BOM signer, the evidence-pack route, the single-scan CBOM PDF export and the client-side CycloneDX download SHALL accept a BOM that contains posture components, and THE Test_Suite SHALL ru...
- [ ] R26.10 — tasks 0.11 — test_cbom_posture_block_schema.py and the emit tests — WHERE a component kind is added to `aibom/src/aibom/model/component.py`, THE Repository SHALL add it as an additive change that leaves every AIBOM emit golden byte-identical.
- [ ] R27.1 — tasks 9.2, 10.1 — test_cbom_posture_properties.py — WHEN the same Scanned_Input is scanned three times, in one process and in separate processes, THE CBOM_Engine SHALL return byte-identical `cbom_json` and Posture_Block, excluding `duration_of_scan`.
- [ ] R27.2 — tasks 9.2, 10.1 — test_cbom_posture_properties.py — THE CBOM_Engine SHALL return the same output regardless of file creation order, modification times, permissions, directory-listing order, `PYTHONHASHSEED`, locale (`LC_ALL=C` and `en_US.UTF-8`) and host path separators.
- [ ] R27.3 — tasks 9.2, 10.1 — test_cbom_posture_properties.py — THE Config_Extractor and THE TLS_Result_Importer SHALL read no wall clock.
- [ ] R27.4 — tasks 9.2, 10.1 — test_cbom_posture_properties.py — THE Config_Extractor SHALL sort every collection it emits by the keys of Requirement 5 criterion 9, with ties broken by `id`.
- [ ] R27.5 — tasks 9.2, 10.1 — test_cbom_posture_properties.py — THE Config_Extractor SHALL hold no mutable module-level state, and THE Defaults_Registry SHALL be loaded once into immutable structures.
- [ ] R27.6 — tasks 9.2, 10.1 — test_cbom_posture_properties.py — FOR EACH Encryption_Fact of every fixture, encoding it into `crypto:` properties and decoding it SHALL yield an equal Encryption_Fact (round-trip property test with seeded generators).
- [ ] R27.7 — tasks 9.2, 10.1 — test_cbom_posture_properties.py — THE Run_Object_Normalizer SHALL serialize the Posture_Block so that `json.dumps(..., sort_keys=True)` of equal inputs yields equal bytes.
- [ ] R28.1 — tasks 5.1 — test_cbom_posture_weights.py and test_cbom_posture_pipeline.py — THE Weights_File SHALL contain an explicit entry for every code in `POSTURE_CODES` with the weight of Table R15-A, and THE Test_Suite SHALL fail WHEN a code emitted by any new scanner has no entry, so that no code sil...
- [ ] R28.2 — tasks 5.1 — test_cbom_posture_weights.py and test_cbom_posture_pipeline.py — THE Weights_File SHALL set `scale.max_raw` to the sum of the positive flag weights that the file held at the Base_Commit (112 when the Base_Commit file is summed at the time of writing), so that `risk_total`, `risk_no...
- [ ] R28.3 — tasks 5.1 — test_cbom_posture_weights.py and test_cbom_posture_pipeline.py — THE Weights_File SHALL keep the existing `severity` thresholds and `scale.bands` unchanged.
- [ ] R28.4 — tasks 5.1 — test_cbom_posture_weights.py and test_cbom_posture_pipeline.py — THE Risk_Scorer SHALL stack the weights of all flags on one component, and a component with two posture findings SHALL show their summed weight in `scores.by_component`.
- [ ] R28.5 — tasks 9.3 — test_cbom_posture_weights.py and test_cbom_posture_pipeline.py — THE Risk_Scorer SHALL list the new codes with their counts in `scores.by_flag`.
- [ ] R28.6 — tasks 9.3 — test_cbom_posture_weights.py and test_cbom_posture_pipeline.py — THE CBOM_Engine SHALL leave the new codes out of `WEAK_CRYPTO_CODES` and out of the normalizer's weakness-distribution set, so that the five existing chart structures stay unchanged.
- [ ] R28.7 — tasks 5.1 — test_cbom_posture_weights.py and test_cbom_posture_pipeline.py — THE Risk_Scorer SHALL remain a delegate of the shared scoring engine and SHALL add no scoring algorithm.
- [ ] R29.1 — tasks 9.3 — test_cbom_posture_compliance.py — THE Compliance_Engine SHALL leave the requirement list, the verdict logic and the evidence text of all 13 frameworks in `CBOM_FRAMEWORKS` unchanged, so that `cbom_compliance` of every Frozen_Golden fixture is byte-ide...
- [ ] R29.2 — tasks 9.3 — test_cbom_posture_compliance.py — THE Compliance_Engine SHALL add no framework key to `CBOM_FRAMEWORKS` or to `cbom_compliance` in this feature.
- [ ] R29.3 — tasks 9.3 — test_cbom_posture_compliance.py — WHEN a scan contains crypto assets emitted by the Config_Extractor or the TLS_Result_Importer, THE existing graph-queried checks SHALL evaluate them through the same `crypto:` property predicates without a code change...
- [ ] R29.4 — tasks 9.3 — test_cbom_posture_compliance.py — THE Compliance_Engine SHALL keep reading graph properties only and SHALL never read `result.flags`, and the existing `test_compliance_never_reads_flags` SHALL pass unmodified.
- [ ] R29.5 — tasks 9.3 — test_cbom_posture_compliance.py — THE Compliance_Engine SHALL keep the operational key-lifecycle requirements (the registered manual requirements for key rotation cadence, key custody and key periods) as NOT_BOM_EVIDENCEABLE even when the Scanned_Inpu...
- [ ] R29.6 — tasks 9.3 — test_cbom_posture_compliance.py — THE Run_Object_Normalizer SHALL report the Tri_State counts and Coverage_Percentage of the at-rest Verdicts and of the `transport` Verdicts in the Posture_Block, computed with the formula of Requirement 6 criterion 12.
- [ ] R29.7 — tasks 9.3 — test_cbom_posture_compliance.py — WHERE an attestation exists for a requirement, THE Compliance_Engine SHALL keep its existing behaviour of flipping NOT_BOM_EVIDENCEABLE to pass-with-evidence.
- [ ] R30.1 — tasks 9.2 — test_cbom_posture_normalize.py and test_cbom_posture_consumers.py — THE Run_Object_Normalizer SHALL add exactly one top-level key, `cbom_posture`, and WHEN given any Frozen_Golden fixture it SHALL return every other key byte-identical to the Base_Commit output, excluding `duration_of_...
- [ ] R30.2 — tasks 9.2 — test_cbom_posture_normalize.py and test_cbom_posture_consumers.py — THE Posture_Block SHALL contain `schema_version` (integer 1), `lanes` (the sorted identifiers of the posture lanes executed), `data_tables` (name, `data_version`, `valid_as_of` and SHA-256 per file), `counts` (declare...
- [ ] R30.3 — tasks 9.2 — test_cbom_posture_normalize.py and test_cbom_posture_consumers.py — THE Run_Object_Normalizer SHALL emit the Posture_Block for every scan that ran the posture lanes, including a scan with zero Encryption_Facts, so that "assessed with zero resources" differs from Not_Assessed.
- [ ] R30.4 — tasks 9.2 — test_cbom_posture_normalize.py and test_cbom_posture_consumers.py — IF the serialized Posture_Block would exceed the size limit, THEN THE Run_Object_Normalizer SHALL drop facts without findings in reverse sorted order until the block fits, SHALL set `truncated` to true and SHALL recor...
- [ ] R30.5 — tasks 9.2 — test_cbom_posture_normalize.py and test_cbom_posture_consumers.py — THE Worker_Adapter SHALL return the Posture_Block without changing its signature, and its progress percentages SHALL not decrease.
- [ ] R30.6 — tasks 9.2 — test_cbom_posture_normalize.py and test_cbom_posture_consumers.py — THE existing worker persistence path SHALL store the Posture_Block in `Scan.scan_data` with no backend change and no database schema change.
- [ ] R30.7 — tasks 9.2 — test_cbom_posture_normalize.py and test_cbom_posture_consumers.py — THE Run_Object_Normalizer SHALL keep `results[]`, `cbom_graph`, `cbom_graph_compact`, `cbom_graph_expanded`, `cbom_graph_view` and `cbom_distributions` limited to crypto-asset content, so that Encryption_Facts without...
- [ ] R30.8 — tasks 0.2, 14.1, 14.2 — test_cbom_posture_normalize.py and test_cbom_posture_consumers.py — WHEN the CBOM results page, the findings serializer, the dashboard aggregation or the single-scan PDF export reads a run-object that contains `cbom_posture`, THEY SHALL behave as for a run-object without it, as proved...
- [ ] R30.9 — tasks 10.1, 14.2 — test_cbom_posture_normalize.py and test_cbom_posture_consumers.py — THE Run_Object_Normalizer SHALL keep the Posture_Block free of excluded secret values and of unsanitized scanned text.
- [ ] R31.1 — tasks 16.1, 16.2 — test_cbom_posture_ledger.py and test_cbom_posture_docs.py — FOR EACH shipped capability (each parser family, each Coverage_Table family, each import format and each Finding_Catalog code), THE Repository SHALL contain a row in `docs/cbom-research/LEDGER.md` with a public specif...
- [ ] R31.2 — tasks 16.1, 16.2 — test_cbom_posture_ledger.py and test_cbom_posture_docs.py — THE Repository SHALL cite open-source scanners (checkov, tfsec, trivy, KICS, terrascan, testssl.sh, sslyze, nmap and the CBOMkit family) only as behaviour or output-format references, and no such tool SHALL appear on...
- [ ] R31.3 — tasks 16.1, 16.2 — test_cbom_posture_ledger.py and test_cbom_posture_docs.py — WHEN a code in `POSTURE_CODES`, a Coverage_Table family or an import format has no ledger row, THE Test_Suite SHALL fail.
- [ ] R31.4 — tasks 16.1, 16.2 — test_cbom_posture_ledger.py and test_cbom_posture_docs.py — THE Repository SHALL publish `docs/cbom-posture/` containing the supported formats and resource types, the Limits Table, the UNKNOWN reasons, the Business_Mapping_File schema and example, the property dictionary, the...
- [ ] R31.5 — tasks 16.1, 16.2 — test_cbom_posture_ledger.py and test_cbom_posture_docs.py — THE Repository SHALL append the conventions found during this work (scanner orders used, the `max_raw` pin, the `cbom_posture` key, the registry additions, test gotchas) to the "Discovered conventions" section of `AGE...
- [ ] R31.6 — tasks 16.1, 16.2 — test_cbom_posture_ledger.py and test_cbom_posture_docs.py — THE Repository SHALL leave the benchmark harness under `bench/cbom/` unchanged, and its CI gates (true-miss count 0 and our-unique count greater than 0 for every repository) SHALL pass.
- [ ] R32.1 — tasks 14.1, 14.2 — test_cbom_posture_contract.py — THE Deliverables_Registry SHALL register the three entries of Table R32-A and SHALL list all nine documents in ascending `number` order: 1, 3, 5, 6, 7, 9, 10, 15, 16.
- [ ] R32.2 — tasks 14.1, 14.2 — test_cbom_posture_contract.py — THE Deliverables_Registry SHALL mark all three new entries `data_dependent`.
- [ ] R32.3 — tasks 14.1, 14.2 — test_cbom_posture_contract.py — WHEN `GET /{team_id}/cbom/deliverables` is called, THE Deliverables_Router SHALL return the manifest with nine items in the existing shape, SHALL derive `available` from scan heads only and SHALL read no `scan_data`.
- [ ] R32.4 — tasks 14.1, 14.2 — test_cbom_posture_contract.py — WHEN a team member requests `GET /{team_id}/cbom/deliverables/{slug}` with one of the three new slugs, THE Deliverables_Router SHALL answer 200 with an `application/pdf` body that starts with `%PDF-`, the header `Cach...
- [ ] R32.5 — tasks 14.1, 14.2 — test_cbom_posture_contract.py — THE Deliverables_Router SHALL keep its status codes (401 for a bad token, 403 for a non-member or inactive session, 404 for an unknown slug only, 429, and 500 with the generic body), its limiter budget of 30 requests...
- [ ] R32.6 — tasks 14.1, 14.2 — test_cbom_posture_contract.py — THE Deliverable_Renderer SHALL print the Document IDs `CBOM-D05-...`, `CBOM-D06-...` and `CBOM-D09-...` built by the existing `document_id` function.
- [ ] R32.7 — tasks 14.1, 14.2 — test_cbom_posture_contract.py — IF the frontend list `CBOM_DELIVERABLES` and the Deliverables_Registry differ in a slug, a number or a title, or a registry entry has no `REPORT_META` key, THEN THE Test_Suite SHALL fail through an extension of the ex...
- [ ] R32.8 — tasks 14.1, 14.2 — test_cbom_posture_contract.py — THE Deliverables_Registry, THE Deliverables_Router and the new renderers SHALL import only modules that the existing T-NOLLM allow-list permits.
- [ ] R33.1 — tasks 11.1 — test_cbom_posture_rollup.py — THE Team_Rollup SHALL read posture data only from the scans that the MEDIUM_Documents already include, and SHALL read `cbom_posture` defensively: a bad record SHALL be skipped and counted in `warnings` without echoing...
- [ ] R33.2 — tasks 11.1 — test_cbom_posture_rollup.py — THE Team_Rollup SHALL keep every existing field of `TeamCbomView`, `ScanFacts` and the aggregates with its existing meaning and SHALL add only new fields with defaults, so that the MEDIUM renderers need no change.
- [ ] R33.3 — tasks 11.1 — test_cbom_posture_rollup.py — THE Team_Rollup SHALL track posture coverage as a dimension separate from Fidelity_Tier: a Source is Not_Assessed when its current scan has no Posture_Marker, and a Tier A scan without the marker SHALL remain Tier A f...
- [ ] R33.4 — tasks 11.1 — test_cbom_posture_rollup.py — THE Team_Rollup SHALL identify a fact within a Source by the pair of source key and fact `id`, SHALL take its attributes from the newest scan that contains it, SHALL compute first-seen, last-seen and scan count over e...
- [ ] R33.5 — tasks 11.1 — test_cbom_posture_rollup.py — THE Team_Rollup SHALL list facts seen only in older scans in a "previously seen, not in latest scan" appendix and SHALL exclude them from headline counts.
- [ ] R33.6 — tasks 11.1 — test_cbom_posture_rollup.py — THE Team_Rollup SHALL compute headline posture counts from current facts of assessed Sources only and SHALL not merge facts across Sources.
- [ ] R33.7 — tasks 11.1 — test_cbom_posture_rollup.py — WHEN the newest attempt of a Source failed and an older successful scan exists, THE Team_Rollup SHALL use the older scan and carry the existing failed-latest note.
- [ ] R33.8 — tasks 11.1 — test_cbom_posture_rollup.py — THE Team_Rollup SHALL cap each register at 2,000 rows and SHALL carry the count of omitted rows to the renderer.
- [ ] R33.9 — tasks 11.1 — test_cbom_posture_rollup.py — THE Team_Rollup SHALL leave the fingerprint formula unchanged, so that the fingerprint of any scan set is identical to its Base_Commit value.
- [ ] R33.10 — tasks 11.1 — test_cbom_posture_rollup.py — THE Team_Rollup SHALL read facts only of the requesting team's successful CBOM scans, and no fact of another team, of a failed or unfinished scan, or of another scan type SHALL reach any document.
- [ ] R33.11 — tasks 11.1 — test_cbom_posture_rollup.py — THE Team_Rollup SHALL expose, for each Defaults_Registry data file named in current assessed scans, the oldest `valid_as_of` date, so that the documents print the oldest reference date they relied on.
- [ ] R33.12 — tasks 11.1 — test_cbom_posture_rollup.py — THE Team_Rollup SHALL stay free of network and LLM imports and compatible with Python 3.10.
- [ ] R34.1 — tasks 12.1, 13.1 — test_cbom_posture_common.py — THE Deliverable_Renderer SHALL build each Posture_Deliverable with `build_document`, so that each PDF has the existing masthead, Document-control table, Basis box, Disclaimer box, "(assessor)" legend, page chrome with...
- [ ] R34.2 — tasks 12.1, 13.1 — test_cbom_posture_common.py — THE Deliverable_Renderer SHALL add to the Basis box the line "Posture coverage: A of B current sources assessed; C not assessed (re-scan needed)", the line "Posture facts are counted separately from crypto asset occur...
- [ ] R34.3 — tasks 12.1, 13.1 — test_cbom_posture_common.py — WHEN the oldest `valid_as_of` date of a data file is more than 365 days before the document's as-of date, THE Deliverable_Renderer SHALL print the notice "Reference data may be out of date".
- [ ] R34.4 — tasks 12.1, 13.1 — test_cbom_posture_common.py — THE Deliverable_Renderer SHALL replace, in the Posture_Deliverables only, the existing method-scope paragraph by a paragraph that states: analysis of declared configuration and offline import of customer-produced resu...
- [ ] R34.5 — tasks 12.1, 13.1 — test_cbom_posture_common.py — THE Deliverable_Renderer SHALL pass every string derived from scanned input (resource names, paths, owners, classification text, host names, tool versions) through `pdf_text` or `pdf_plain`, so that hostile markup, co...
- [ ] R34.6 — tasks 12.1, 13.1 — test_cbom_posture_common.py — THE Deliverable_Renderer SHALL print the four Verdicts as "Encrypted (declared)", "Encrypted (provider default)", "Not encrypted" and "Not evidenceable from BOM (unknown)", and SHALL print Tri_State words with the exi...
- [ ] R34.7 — tasks 12.1, 13.1 — test_cbom_posture_common.py — WHEN a register row is UNKNOWN, THE Deliverable_Renderer SHALL print the plain-language label of its `unknown_reason` from the authored-text module.
- [ ] R34.8 — tasks 12.1, 13.1 — test_cbom_posture_common.py — THE Deliverable_Renderer SHALL leave Assessor_Cells blank and SHALL mark their columns "(assessor)"; a value declared in the Business_Mapping_File SHALL print with the label "declared" and SHALL not appear in an Asses...
- [ ] R34.9 — tasks 12.1, 13.1 — test_cbom_posture_common.py — THE Deliverable_Renderer SHALL produce byte-identical PDFs for the same view and the same injected time.
- [ ] R34.10 — tasks 12.1, 13.1 — test_cbom_posture_common.py — THE authored text SHALL carry a `# Source:` comment with a public URL for every standards or vendor claim, and the existing URL allow-list test SHALL fail WHEN a URL is not on the reviewed list.
- [ ] R35.1 — tasks 13.1 — test_cbom_deliverable_infra_posture.py and e2e spec 05 — THE Deliverable_Renderer (deliverable #5) SHALL print a KPI strip with: Encryption_Facts assessed, at-rest Verdict counts under the four labels of Requirement 34, Posture_Findings by impact, KMS keys with the share th...
- [ ] R35.2 — tasks 13.1 — test_cbom_deliverable_infra_posture.py and e2e spec 05 — THE Deliverable_Renderer (deliverable #5) SHALL print a coverage and method section with declared resources by format and provider, Encryption_Facts, OUT_OF_SCOPE and disabled resources, Diagnostic totals by code, and...
- [ ] R35.3 — tasks 13.1 — test_cbom_deliverable_infra_posture.py and e2e spec 05 — THE Deliverable_Renderer (deliverable #5) SHALL print a KMS key register with the columns key, provider, specification, usage, protection level, rotation, deletion protection, exposure, resources protected, source, lo...
- [ ] R35.4 — tasks 13.1 — test_cbom_deliverable_infra_posture.py and e2e spec 05 — THE Deliverable_Renderer (deliverable #5) SHALL print a resource encryption register grouped by provider and kind with the columns resource, native type, at-rest Verdict, transport Verdict, key management, basis, find...
- [ ] R35.5 — tasks 13.1 — test_cbom_deliverable_infra_posture.py and e2e spec 05 — THE Deliverable_Renderer (deliverable #5) SHALL print a managed TLS endpoint table with endpoint, policy name, minimum protocol version, listener behaviour (TLS, redirect, plaintext), Verdict and finding codes.
- [ ] R35.6 — tasks 13.1 — test_cbom_deliverable_infra_posture.py and e2e spec 05 — THE Deliverable_Renderer (deliverable #5) SHALL print a secrets and certificate provisioning table with resource, kind, key algorithm and size or curve, key management and the rotation-on-renewal setting.
- [ ] R35.7 — tasks 13.1 — test_cbom_deliverable_infra_posture.py and e2e spec 05 — THE Deliverable_Renderer (deliverable #5) SHALL print a findings table with, per Finding_Catalog code present, its label, count, impact, anchor and remediation text, and the resource and location of the 25 highest-imp...
- [ ] R35.8 — tasks 13.1 — test_cbom_deliverable_infra_posture.py and e2e spec 05 — THE Deliverable_Renderer (deliverable #5) SHALL print a "Not evidenceable from BOM" section that groups every UNKNOWN fact by `unknown_reason` with counts and one "what to check manually" line per reason.
- [ ] R35.9 — tasks 13.1 — test_cbom_deliverable_infra_posture.py and e2e spec 05 — THE Deliverable_Renderer (deliverable #5) SHALL print the previously-seen appendix, manual forms (cloud account, subscription and project inventory; environment classification; key custodian assignments) and a sign-of...
- [ ] R35.10 — tasks 13.1 — test_cbom_deliverable_infra_posture.py and e2e spec 05 — THE Deliverable_Renderer (deliverable #5) SHALL close with a limits statement that includes "declared configuration is not proof of operation".
- [ ] R36.1 — tasks 13.1 — test_cbom_deliverable_network_tls.py and e2e spec 06 — THE Deliverable_Renderer (deliverable #6) SHALL print a KPI strip with: endpoints (static and imported), endpoints that offer a legacy protocol, endpoints with weak cipher suites, certificates seen on endpoints, impor...
- [ ] R36.2 — tasks 13.1 — test_cbom_deliverable_network_tls.py and e2e spec 06 — THE Deliverable_Renderer (deliverable #6) SHALL print an endpoint register with endpoint, evidence kind (static server or `imported:<tool>`), minimum and maximum protocol version, whether TLS 1.3 is offered (offered,...
- [ ] R36.3 — tasks 13.1 — test_cbom_deliverable_network_tls.py and e2e spec 06 — THE Deliverable_Renderer (deliverable #6) SHALL print a protocol-version matrix of endpoints against SSLv3, TLS 1.0, TLS 1.1, TLS 1.2 and TLS 1.3 using the words "offered", "not offered" and "unknown".
- [ ] R36.4 — tasks 13.1 — test_cbom_deliverable_network_tls.py and e2e spec 06 — THE Deliverable_Renderer (deliverable #6) SHALL print a weak cipher suite table with endpoint, suite and the attack or rationale text of the existing suite catalog.
- [ ] R36.5 — tasks 13.1 — test_cbom_deliverable_network_tls.py and e2e spec 06 — THE Deliverable_Renderer (deliverable #6) SHALL print a certificate table for certificates seen on endpoints with subject, issuer, validity, signature algorithm, key size and certificate finding codes.
- [ ] R36.6 — tasks 13.1 — test_cbom_deliverable_network_tls.py and e2e spec 06 — THE Deliverable_Renderer (deliverable #6) SHALL print a downgrade and vulnerability table with endpoint, item, reported status and source tool, marking the entries of Table R25-A that are not scored as "reported, not...
- [ ] R36.7 — tasks 13.1 — test_cbom_deliverable_network_tls.py and e2e spec 06 — THE Deliverable_Renderer (deliverable #6) SHALL print a table of SSH and database transport settings and a table of disabled certificate verification with location, pattern label and `path_context`.
- [ ] R36.8 — tasks 13.1 — test_cbom_deliverable_network_tls.py and e2e spec 06 — THE Deliverable_Renderer (deliverable #6) SHALL print an import provenance table with file, tool, tool version, scan start and end exactly as the file states them, and endpoint count.
- [ ] R36.9 — tasks 13.1 — test_cbom_deliverable_network_tls.py and e2e spec 06 — WHEN a static server fact and an imported result share the identical `host:port` string, THE Deliverable_Renderer (deliverable #6) SHALL print both rows adjacent with the discrepancy flag of Requirement 25 criterion 10.
- [ ] R36.10 — tasks 13.1 — test_cbom_deliverable_network_tls.py and e2e spec 06 — THE Deliverable_Renderer (deliverable #6) SHALL print the "Not evidenceable from BOM" section, the previously-seen appendix, manual forms (endpoint owner, exposure internet or internal, compensating controls, live ver...
- [ ] R36.11 — tasks 13.1 — test_cbom_deliverable_network_tls.py and e2e spec 06 — THE Deliverable_Renderer (deliverable #6) SHALL state that the platform did not probe any endpoint and that imported results reflect the time the customer's tool ran.
- [ ] R37.1 — tasks 13.1 — test_cbom_deliverable_data_at_rest.py and e2e spec 09 — THE Deliverable_Renderer (deliverable #9) SHALL print a KPI strip with: data stores by at-rest Verdict, backups by Verdict, Kubernetes secrets status, stores with a declared data classification, and Sources assessed a...
- [ ] R37.2 — tasks 13.1 — test_cbom_deliverable_data_at_rest.py and e2e spec 09 — THE Deliverable_Renderer (deliverable #9) SHALL print a data store register with store, kind, provider or self-hosted, Layers with Verdicts, key management, system, owner, owner hint, data classification, data lifetim...
- [ ] R37.3 — tasks 13.1 — test_cbom_deliverable_data_at_rest.py and e2e spec 09 — THE Deliverable_Renderer (deliverable #9) SHALL print a backup and snapshot register, a Kubernetes secrets-at-rest table and a database-native and disk-level evidence table (directives, `crypttab` entries, `cryptsetup...
- [ ] R37.4 — tasks 13.1 — test_cbom_deliverable_data_at_rest.py and e2e spec 09 — THE Deliverable_Renderer (deliverable #9) SHALL print application-level encryption evidence taken from the existing algorithm and library inventory, labelled "capability evidence, not proof that stored data is protect...
- [ ] R37.5 — tasks 13.1 — test_cbom_deliverable_data_at_rest.py and e2e spec 09 — WHEN at least one fact carries a declared data classification, THE Deliverable_Renderer (deliverable #9) SHALL print a roll-up of counts by declared classification and at-rest Verdict, and WHEN no fact carries one it...
- [ ] R37.6 — tasks 13.1 — test_cbom_deliverable_data_at_rest.py and e2e spec 09 — THE Deliverable_Renderer (deliverable #9) SHALL print the "Not evidenceable from BOM" section, the previously-seen appendix, manual forms (regulated-data mapping, key-management evidence reference, retention schedule,...
- [ ] R37.7 — tasks 13.1 — test_cbom_deliverable_data_at_rest.py and e2e spec 09 — THE Deliverable_Renderer (deliverable #9) SHALL close with the statement that the platform does not inspect stored data and that a declared setting is not proof of operation.
- [ ] R38.1 — tasks 11.1, 13.1 — test_cbom_posture_degradation.py and e2e specs 18 and 19 — WHEN a team has no eligible scan, THE Deliverable_Renderer SHALL produce a 200 PDF with the existing banner "NO COMPLETED CBOM SCANS", all counts zero and no verdict statement.
- [ ] R38.2 — tasks 11.1, 13.1 — test_cbom_posture_degradation.py and e2e specs 18 and 19 — WHEN every current Source is Not_Assessed, THE Deliverable_Renderer SHALL show the banner "POSTURE NOT ASSESSED - RE-SCAN NEEDED" with each Source and its last scan date, SHALL show KPI values as "n/a" and registers a...
- [ ] R38.3 — tasks 11.1, 13.1 — test_cbom_posture_degradation.py and e2e specs 18 and 19 — WHEN some current Sources are assessed and some are not, THE Deliverable_Renderer SHALL print a per-Source status table with the words "assessed" and "not assessed", SHALL build registers from assessed Sources only an...
- [ ] R38.4 — tasks 11.1, 13.1 — test_cbom_posture_degradation.py and e2e specs 18 and 19 — WHEN an assessed Source has zero Encryption_Facts, THE Deliverable_Renderer SHALL state that no in-scope infrastructure or configuration files were found in it and that this is not evidence that no cloud resources or...
- [ ] R38.5 — tasks 11.1, 13.1 — test_cbom_posture_degradation.py and e2e specs 18 and 19 — IF a `cbom_posture` value is malformed (not an object, an unsupported `schema_version`, wrong list types), THEN THE Team_Rollup SHALL treat the Source as Not_Assessed, count a warning and raise no error; WHEN `schema_...
- [ ] R38.6 — tasks 11.1, 13.1 — test_cbom_posture_degradation.py and e2e specs 18 and 19 — WHEN the Posture_Block is truncated, THE Deliverable_Renderer SHALL print the number of facts dropped.
- [ ] R38.7 — tasks 11.1, 13.1 — test_cbom_posture_degradation.py and e2e specs 18 and 19 — WHEN the Posture_Block carries Diagnostics, THE Deliverable_Renderer SHALL print the total by code and a list capped at 50 entries sorted by path and line.
- [ ] R38.8 — tasks 11.1, 13.1 — test_cbom_posture_degradation.py and e2e specs 18 and 19 — WHEN a Source's newest attempt failed, THE Deliverable_Renderer SHALL print the existing failed-latest note.
- [ ] R38.9 — tasks 11.1, 13.1 — test_cbom_posture_degradation.py and e2e specs 18 and 19 — THE Deliverable_Renderer SHALL list Not_Assessed Sources sorted by Source label.
- [ ] R38.10 — tasks 11.1, 13.1 — test_cbom_posture_degradation.py and e2e specs 18 and 19 — THE Deliverable_Renderer SHALL never print an encryption verdict for a Not_Assessed Source.
- [ ] R39.1 — tasks 0.3, 14.2 — test_cbom_posture_medium_regression.py and e2e spec 98 — WHEN no current Source is assessed, THE Deliverable_Renderer for document #16 SHALL produce bytes identical to the Base_Commit renderer for the same view and the same injected time, except for the sentences that crite...
- [ ] R39.2 — tasks 14.1, 14.2 — test_cbom_posture_medium_regression.py and e2e spec 98 — WHEN at least one assessed Source has current Posture_Findings, THE Deliverable_Renderer for document #16 SHALL add them by impact to the grade input as a separate count, SHALL print a "Configuration posture findings"...
- [ ] R39.3 — tasks 14.1, 14.2 — test_cbom_posture_medium_regression.py and e2e spec 98 — THE MEDIUM_Documents SHALL ignore the Posture_Block.
- [ ] R39.4 — tasks 9.4, 14.1 — test_cbom_posture_medium_regression.py and e2e spec 98 — THE Deliverable_Renderer for document #3 SHALL list every registered CBOM scanner including the new ones in registry order, and the scanner contract test SHALL be regenerated from the registry fixture.
- [ ] R39.5 — tasks 14.1, 14.2 — test_cbom_posture_medium_regression.py and e2e spec 98 — THE Deliverable_Renderer for document #3 SHALL add a subsection that names the posture lanes, the Defaults_Registry data files and the limits of the Limits Table.
- [ ] R39.6 — tasks 0.3, 14.1 — test_cbom_posture_medium_regression.py and e2e spec 98 — WHERE the shared method-scope sentence of the six MEDIUM_Documents is amended (Open item OI-4), THE Repository SHALL change that sentence and, because it states the same limit, the fourth bullet of the method limits t...
- [ ] R39.7 — tasks 14.1, 14.2 — test_cbom_posture_medium_regression.py and e2e spec 98 — FOR the seeds of the Base_Commit E2E world, THE MEDIUM_Documents SHALL differ from their Base_Commit text extraction only in: the scanner table and the registered-scanner count of #3, the posture subsection of #3, and...
- [ ] R39.8 — tasks 14.1, 14.2 — test_cbom_posture_medium_regression.py and e2e spec 98 — THE crypto assets that the new lanes emit (KMS key material, protocols, algorithms, certificates) SHALL count as crypto assets in the MEDIUM_Documents for scans that contain them.
- [ ] R40.1 — tasks 14.3, 15.2 — test_frontend_menu_equals_the_backend_registry and the menu spec — THE Deliverables_Menu SHALL list nine items in registry order, each with `data-testid="cbom-deliverable-<slug>"` and the registry title as its label.
- [ ] R40.2 — tasks 14.3, 15.2 — test_frontend_menu_equals_the_backend_registry and the menu spec — WHEN the manifest marks an item unavailable, THE Deliverables_Menu SHALL disable it and show the manifest reason as its tooltip, and WHILE the manifest loads or fails to load THE Deliverables_Menu SHALL keep every ite...
- [ ] R40.3 — tasks 14.3, 15.2 — test_frontend_menu_equals_the_backend_registry and the menu spec — WHEN a user selects an item, THE Deliverables_Menu SHALL download the PDF with the file name `cbom-<slug>-team<id>-<YYYYMMDD>.pdf` and show the existing success toast, and SHALL show the existing error toast on failure.
- [ ] R40.4 — tasks 14.3 — test_frontend_menu_equals_the_backend_registry and the menu spec — THE change SHALL be limited to `frontend/utils/backend_api.ts` and `frontend/app/[team_id]/cbom/page.tsx`, and SHALL add no page and no route.
- [ ] R40.5 — tasks 14.3, 15.2 — test_frontend_menu_equals_the_backend_registry and the menu spec — THE Deliverables_Menu SHALL request no CDN, font, analytics or other external resource.
- [ ] R40.6 — tasks 14.3, 15.2 — test_frontend_menu_equals_the_backend_registry and the menu spec — WHEN `npx tsc --noEmit` runs, it SHALL exit 0, and WHEN eslint runs on the two changed files, THE Repository SHALL show no error that is absent from the Base_Commit baseline when compared by rule and source-line text.
- [ ] R41.1 — tasks 10.1, 15.1 — test_cbom_posture_airgap_runtime.py and the air-gap spec — WHILE a CBOM_Scan runs and WHILE a Posture_Deliverable renders, THE CBOM_Engine, THE Team_Rollup and THE Deliverable_Renderer SHALL perform no DNS lookup, open no socket, issue no HTTP request, start no subprocess, ca...
- [ ] R41.2 — tasks 10.1, 15.1 — test_cbom_posture_airgap_runtime.py and the air-gap spec — THE CBOM_Engine SHALL take all reference knowledge (provider defaults, TLS policies, cipher and curve registries, OID tables, pattern lists) from the Defaults_Registry packaged in the product.
- [ ] R41.3 — tasks 10.1, 15.1 — test_cbom_posture_airgap_runtime.py and the air-gap spec — WHEN the CBOM_Engine and the Deliverables_Router run on a host whose only network interface is loopback, THEY SHALL produce the same scan output and the same PDF bytes as on a networked host for the same Scanned_Input...
- [ ] R41.4 — tasks 10.1, 15.1 — test_cbom_posture_airgap_runtime.py and the air-gap spec — THE posture lanes SHALL not call the optional enrichment provider interface, and no configuration switch SHALL enable a language-model call in them.
- [ ] R41.5 — tasks 10.1, 15.1 — test_cbom_posture_airgap_runtime.py and the air-gap spec — THE git-clone input path SHALL stay unchanged and outside this guarantee, and the supported air-gapped input SHALL be a zip upload.
- [ ] R42.1 — tasks 10.1, 14.2 — test_cbom_posture_airgap_static.py and test_cbom_posture_imports.py — THE Airgap_Guard SHALL parse with `ast` every Python module that this feature adds under `aibom/src/aibom/cbom/` and every backend module of Requirement 32, discovering new files by glob, and SHALL fail on any import...
- [ ] R42.2 — tasks 10.1, 14.2 — test_cbom_posture_airgap_static.py and test_cbom_posture_imports.py — THE Airgap_Guard SHALL fail on a call to `eval`, `exec`, `compile`, `__import__`, `os.system`, `os.popen`, `os.exec*`, `os.spawn*` or `os.fork`, and on the tokens `get_llm`, `chatbedrock`, `bedrock`, `anthropic` and `...
- [ ] R42.3 — tasks 10.1, 14.2 — test_cbom_posture_airgap_static.py and test_cbom_posture_imports.py — THE Airgap_Guard SHALL permit, in the new `aibom` modules, only the standard library, `pydantic`, `yaml` and `aibom` imports, and, in the new backend modules, the existing T-NOLLM allow-list.
- [ ] R42.4 — tasks 10.1, 14.2 — test_cbom_posture_airgap_static.py and test_cbom_posture_imports.py — THE Airgap_Guard SHALL import the new `aibom` modules and the new backend modules in fresh interpreters and SHALL fail WHEN `sys.modules` then holds `boto3`, `botocore`, `langchain`, `openai`, `anthropic`, `instructor...
- [ ] R42.5 — tasks 10.1, 14.2 — test_cbom_posture_airgap_static.py and test_cbom_posture_imports.py — THE Airgap_Guard SHALL run `scan_crypto`, `normalize_crypto`, CycloneDX emission and the three PDF builders on every new fixture, including the hostile fixtures and fixtures that contain URLs, host names, IP addresses...
- [ ] R42.6 — tasks 10.1, 14.2 — test_cbom_posture_airgap_static.py and test_cbom_posture_imports.py — THE Airgap_Guard SHALL include a control test for each guard that proves it fires on a deliberate violation.
- [ ] R42.7 — tasks 10.1, 14.2 — test_cbom_posture_airgap_static.py and test_cbom_posture_imports.py — THE Airgap_Guard SHALL run every new route test under the runtime guard through an autouse fixture.
- [ ] R42.8 — tasks 16.3 — test_cbom_posture_airgap_static.py and test_cbom_posture_imports.py — THE Repository SHALL show an empty `git diff --name-only` against the Base_Commit for `backend/pyproject.toml`, `backend/uv.lock`, `frontend/package.json`, `frontend/package-lock.json`, `aibom/pyproject.toml`, `aibom/...
- [ ] R43.1 — tasks 15.1, 15.2 — e2e air-gap spec and logs/NN-airgap-*.txt — THE E2E_Harness SHALL start the backend, the database containers and the scan container of the HIGH run on a network that has no route to the internet.
- [ ] R43.2 — tasks 15.1, 15.2 — e2e air-gap spec and logs/NN-airgap-*.txt — THE E2E_Harness SHALL attempt, from inside the backend container and from inside the scan container, a TCP connection to a public IPv4 literal, a TCP connection to a public IPv6 literal and a DNS lookup of a public na...
- [ ] R43.3 — tasks 15.1, 15.2 — e2e air-gap spec and logs/NN-airgap-*.txt — THE E2E_Harness SHALL decode `/proc/net/tcp` and `/proc/net/tcp6` of the backend container and SHALL fail the run WHEN an outbound peer is not postgres, mongo or loopback.
- [ ] R43.4 — tasks 15.1, 15.2 — e2e air-gap spec and logs/NN-airgap-*.txt — THE E2E_Harness SHALL run the scans of the posture world with the real scan engine over a local directory or extracted zip in a container with `network_mode: none`, and SHALL state in the evidence that the git-clone p...
- [ ] R43.5 — tasks 15.1, 15.2 — e2e air-gap spec and logs/NN-airgap-*.txt — THE Playwright specs SHALL record every browser request and SHALL assert that all go to the frontend and backend loopback origins, with zero requests to another origin and zero requests for fonts or scripts from a CDN.
- [ ] R43.6 — tasks 15.1, 15.2 — e2e air-gap spec and logs/NN-airgap-*.txt — THE E2E_Harness SHALL keep the Docker safety rules of the MEDIUM harness: label guard `com.dss-e2e=1`, no prune, `safe_rm_rf`, no push of images.
- [ ] R43.7 — tasks 15.1, 15.2 — e2e air-gap spec and logs/NN-airgap-*.txt — THE E2E_Harness SHALL write the isolation proof to `logs/NN-airgap-*.txt` files in the Evidence_Directory of Requirement 50.
- [ ] R44.1 — tasks 10.1 — stored red logs, property tests, and mutants.py — WHEN a work package is completed, THE Repository SHALL hold in its work-package report the failing run of the package's new tests recorded before implementation and the passing run recorded after.
- [ ] R44.2 — tasks 10.1 — stored red logs, property tests, and mutants.py — THE Test_Suite SHALL include property tests that use the standard-library `random` module with recorded seeds and at least 1,000 generated cases each, with no new dependency, for these properties: every parser returns...
- [ ] R44.3 — tasks 10.1 — stored red logs, property tests, and mutants.py — THE Test_Suite SHALL include completeness tests that fail WHEN a Coverage_Table row, a Defaults_Registry row, an `unknown_reason` or a Finding_Catalog code lacks at least one positive and one negative fixture case.
- [ ] R44.4 — tasks 10.1 — stored red logs, property tests, and mutants.py — THE Test_Suite SHALL include at least 10 hand-seeded mutants of the Verdict_Engine and the resolvers (for example flipping a default effect, treating UNKNOWN as pass, ignoring `variable_overridden`), each of which SHA...
- [ ] R44.5 — tasks 10.1 — stored red logs, property tests, and mutants.py — THE Test_Suite SHALL include the hostile-input corpus tests of Requirement 4 and the secret-canary test of Requirement 5 criterion 6.
- [ ] R44.6 — tasks 10.1 — stored red logs, property tests, and mutants.py — THE Test_Suite SHALL run the backend tests on the backend virtual environment's Python 3.10 and the `aibom` tests on the `aibom` virtual environment.
- [ ] R45.1 — tasks 7.1 — test_cbom_posture_manifest_consistency.py — THE Repository SHALL add the fixture trees of Table R45-A under `aibom/tests/fixtures/`, each with an `expected_*.json` Oracle and a `SOURCE.md` that explains how each expected value was derived by reading the files.
- [ ] R45.2 — tasks 7.1 — test_cbom_posture_manifest_consistency.py — THE Oracle SHALL hold, per resource, the path, line, address, kind, Verdict per Layer, key management, finding codes and `unknown_reason`, and per tree the totals, and no Oracle value SHALL be computed by product code.
- [ ] R45.3 — tasks 7.1 — test_cbom_posture_manifest_consistency.py — THE Test_Suite SHALL include a manifest-consistency test, a peer of `test_crypto_fixture_manifest.py`, that checks the totals equal the sum of the per-resource entries before it compares the scanner output with the Or...
- [ ] R45.4 — tasks 7.1 — test_cbom_posture_manifest_consistency.py — THE fixture trees SHALL contain negative controls: encrypted resources that must raise nothing and cases that must stay UNKNOWN.
- [ ] R45.5 — tasks 7.1 — test_cbom_posture_manifest_consistency.py — THE Test_Suite SHALL commit the small hostile files and SHALL generate the large files, symbolic links and FIFOs in a temporary directory at test time.
- [ ] R45.6 — tasks 7.1 — test_cbom_posture_manifest_consistency.py — THE fixture authors MAY use `openssl` at authoring time to craft certificates and Diffie-Hellman parameter files, and no external tool SHALL run in any gate.
- [ ] R45.7 — tasks 7.1 — test_cbom_posture_manifest_consistency.py — THE result-file samples SHALL be authored by hand from the public documentation of each tool's output and SHALL use only the reserved names and address ranges of Requirement 24 criterion 9.
- [ ] R45.8 — tasks 7.1 — test_cbom_posture_manifest_consistency.py — THE Repository SHALL leave every `synthetic-crypto-*` fixture and `expected_crypto.json` unmodified, as shown by an empty `git diff` against the Base_Commit.
- [ ] R45.9 — tasks 7.1 — test_cbom_posture_manifest_consistency.py — THE fixture trees SHALL stay excluded from ruff and from pytest collection, as the existing fixtures are.
- [ ] R46.1 — tasks 1.2, 9.5, 16.3 — test_cbom_posture_frozen_goldens.py and cbom-posture-gates.yml — THE Repository SHALL commit, before any product change, a snapshot of SHA-256 digests of the Base_Commit outputs of `scan_crypto`, `normalize_crypto` and the CycloneDX emitter on every `synthetic-crypto-*` tree, and W...
- [ ] R46.2 — tasks 1.2, 9.5, 16.3 — test_cbom_posture_frozen_goldens.py and cbom-posture-gates.yml — THE pre-feature `aibom` pytest suite SHALL pass unmodified, with pass and skip counts equal to the counts recorded at the Base_Commit.
- [ ] R46.3 — tasks 1.2, 9.5, 16.3 — test_cbom_posture_frozen_goldens.py and cbom-posture-gates.yml — THE benchmark gates of `bench/cbom` and `aibom/tests/test_cbom_benchmark_gate.py` SHALL pass with a true-miss count of 0 and an our-unique count greater than 0 for every repository.
- [ ] R46.4 — tasks 1.2, 9.5, 16.3 — test_cbom_posture_frozen_goldens.py and cbom-posture-gates.yml — THE backend suites of the MEDIUM branch (1,113 passed and 1 expected failure at the Base_Commit) and its regression suites (77 passed) SHALL pass, except for the tests that Requirements 32, 39 and 40 change, which the...
- [ ] R46.5 — tasks 1.2, 9.5, 16.3 — test_cbom_posture_frozen_goldens.py and cbom-posture-gates.yml — WHEN `ruff check src/aibom/cbom` and `mypy` run on `aibom`, they SHALL report no finding, and WHEN ruff runs with line length 100 and target `py310` on the new backend files, it SHALL report no finding.
- [ ] R46.6 — tasks 0.14, 16.3 — test_cbom_posture_frozen_goldens.py and cbom-posture-gates.yml — THE CI workflow `.github/workflows/cbom-posture-gates.yml` SHALL run hermetic gates, without Docker or network, on pull requests and pushes that touch `aibom/src/aibom/cbom/**`, the Weights_File, the new data files, t...
- [ ] R46.7 — tasks 1.2, 9.5, 16.3 — test_cbom_posture_frozen_goldens.py and cbom-posture-gates.yml — THE existing workflows `cbom-gates.yml` and `cbom-deliverables.yml` SHALL keep running unchanged.
- [ ] R47.1 — tasks 15.2, 15.5 — e2e specs 05, 06, 09, 18, 19, 20, 94-98 — THE E2E_Harness SHALL extend the MEDIUM harness under `e2e/` and not fork it, SHALL use a distinct Evidence_Directory, and SHALL leave the MEDIUM evidence directory untouched.
- [ ] R47.2 — tasks 15.2, 15.5 — e2e specs 05, 06, 09, 18, 19, 20, 94-98 — THE E2E_Harness SHALL seed the posture world into a new team, so that the Base_Commit seed numbers of team 1 stay valid, using the real scan engine over the posture fixture trees to produce each stored `scan_data`.
- [ ] R47.3 — tasks 15.2, 15.5 — e2e specs 05, 06, 09, 18, 19, 20, 94-98 — THE posture world SHALL contain: assessed Sources from the fixture trees; one Not_Assessed Source from a committed run-object without a Posture_Marker; one assessed Source with zero facts; one failed scan that carries...
- [ ] R47.4 — tasks 15.2, 15.5 — e2e specs 05, 06, 09, 18, 19, 20, 94-98 — FOR EACH of deliverables #5, #6 and #9, THE E2E_Harness SHALL provide its own Playwright spec, run alone and again inside the full suite, that produces: one `.webm` video of at least 10 seconds at 1440 by 900; at leas...
- [ ] R47.5 — tasks 15.2, 15.5 — e2e specs 05, 06, 09, 18, 19, 20, 94-98 — THE specs SHALL assert against the PDF text, not the DOM: each seeded resource name with its Verdict label; counts per Verdict, per kind and per finding code; each `unknown_reason` label; blank Assessor_Cells; declare...
- [ ] R47.6 — tasks 15.2, 15.5 — e2e specs 05, 06, 09, 18, 19, 20, 94-98 — THE E2E_Harness SHALL provide cross-cutting specs for: a team with only Not_Assessed Sources; mixed coverage; an empty team (200, banner, disabled data-dependent items); negative isolation (canaries from a failed scan...
- [ ] R47.7 — tasks 15.2, 15.5 — e2e specs 05, 06, 09, 18, 19, 20, 94-98 — THE E2E_Harness SHALL pace PDF requests at least 1.5 seconds apart to respect the limiter, and SHALL run the full suite with one worker.
- [ ] R47.8 — tasks 15.2, 15.5 — e2e specs 05, 06, 09, 18, 19, 20, 94-98 — THE E2E_Harness SHALL write every artefact into the Evidence_Directory under the MEDIUM naming scheme with the numbers 05, 06 and 09.
- [ ] R48.1 — tasks 15.3 — e2e/verify/verify_posture.py — THE Independent_Verifier SHALL recompute the expected values of each Posture_Deliverable from the raw fixture trees and the downloaded PDFs with its own simple parsers, SHALL import no product code, and SHALL run at l...
- [ ] R48.2 — tasks 15.3 — e2e/verify/verify_posture.py — THE Independent_Verifier SHALL include at least 10 negative controls (mutated PDF text, altered counts, a swapped team, a removed row) and SHALL fail on each of them.
- [ ] R48.3 — tasks 15.3 — e2e/verify/verify_posture.py — THE Independent_Verifier SHALL check the absence of every canary in all PDFs of all teams, the absence of redaction canaries in `cbom_json`, the run-object and the Diagnostics, the style parity, and the egress and iso...
- [ ] R48.4 — tasks 15.3 — e2e/verify/verify_posture.py — THE Independent_Verifier SHALL check by content hash that the images under test were built from the final commit, with a negative control that reports a mismatch.
- [ ] R48.5 — tasks 15.3 — e2e/verify/verify_posture.py — THE Independent_Verifier SHALL write `VERIFY.md` with the check counts per category, and any failed check SHALL block the Definition of Done.
- [ ] R49.1 — tasks 15.4 — e2e/perf logs/92-perf-*.json — WHEN the new scanners scan the generated stress tree S1 (2,000 Terraform files holding 20,000 resources, about 40 MiB) on the reference VM (16 cores, 58 GB), THE CBOM_Engine SHALL finish within 120 seconds with a peak...
- [ ] R49.2 — tasks 15.4 — e2e/perf logs/92-perf-*.json — WHEN the new scanners scan the generated stress tree S2 (1,000 Kubernetes YAML files holding 10,000 documents), THE CBOM_Engine SHALL finish within 60 seconds.
- [ ] R49.3 — tasks 15.4 — e2e/perf logs/92-perf-*.json — WHEN the new scanners run on the benchmark repositories of `bench/cbom/repos.tsv` that exist locally, THEY SHALL add at most 5 percent or 2 seconds, whichever is larger, to the scan time of the Base_Commit scanners.
- [ ] R49.4 — tasks 15.4 — e2e/perf logs/92-perf-*.json — WHEN the demo team of about 10 scans requests a Posture_Deliverable, THE Deliverables_Router SHALL answer within 3 seconds.
- [ ] R49.5 — tasks 0.13, 15.4 — e2e/perf logs/92-perf-*.json — WHEN the performance team (200 scans, 40 sources, 500 Encryption_Facts per scan) requests a Posture_Deliverable, THE Deliverables_Router SHALL answer within 10 seconds with a peak resident memory growth of at most 512...
- [ ] R49.6 — tasks 15.4 — e2e/perf logs/92-perf-*.json — WHEN a register reaches the 2,000-row cap, THE Deliverables_Router SHALL answer within 15 seconds.
- [ ] R49.7 — tasks 15.4 — e2e/perf logs/92-perf-*.json — THE E2E_Harness SHALL record every measurement in `logs/92-perf-*.json` for the run alone and the full suite, and the Test_Suite SHALL fail WHEN a measurement exceeds its budget.
- [ ] R50.1 — tasks 15.5, 17 — evidence index, SUMMARY.md, and the build report — THE E2E_Harness SHALL write the Evidence_Directory `.agents/tasks/cbom-high-deliverables-evidence/` with the MEDIUM layout (`videos/`, `screenshots/`, `downloads/`, `pdf-pages/`, `logs/`, `reports/index.json`, `SUMMAR...
- [ ] R50.2 — tasks 15.5, 17 — evidence index, SUMMARY.md, and the build report — THE E2E_Harness SHALL produce all Docker and Playwright evidence at the final product-code commit, with the images rebuilt from it, and SHALL move any earlier evidence to a `_superseded-<sha>` folder with a README.
- [ ] R50.3 — tasks 15.5, 17 — evidence index, SUMMARY.md, and the build report — THE Repository SHALL contain a build report `.agents/tasks/cbom-high-deliverables-build-report.md` that lists the commits per work package, the test and gate results, the Definition of Done table of R50-A with evidenc...
- [ ] R50.4 — tasks 15.5, 17 — evidence index, SUMMARY.md, and the build report — WHEN teardown runs, THE E2E_Harness SHALL leave no object that carries its labels, and the Docker containers, volumes and networks that do not carry them SHALL be identical before and after.
- [ ] R50.5 — tasks 15.5, 17 — evidence index, SUMMARY.md, and the build report — THE E2E_Harness SHALL run a text scan of the Evidence_Directory for secret values, with a self-test that finds every planted secret, and the result SHALL be zero hits; no `.env` file SHALL be present in any image or i...
- [ ] R50.6 — tasks 15.5, 17 — evidence index, SUMMARY.md, and the build report — THE evidence SHALL contain only synthetic seed data and throw-away values of the local stack.
- [ ] R51.1 — tasks 0.11, 16.3 — e2e/scripts/scope_gate.py — WHEN `git diff --stat` runs between the Base_Commit and HEAD, THE Repository SHALL show no change under `RabbitMQ/worker/helpers/tools/iac_agent/`, `RabbitMQ/dast_worker/`, `RabbitMQ/worker/helpers/tools/sast_agent/`,...
- [ ] R51.2 — tasks 0.2, 0.11, 16.3 — e2e/scripts/scope_gate.py — THE Repository SHALL limit changes to: `aibom/src/aibom/cbom/`, `aibom/src/aibom/integrations/cbom_devsecshield.py`, additive changes to `aibom/src/aibom/emit/cyclonedx.py` and `aibom/src/aibom/model/component.py`, `a...
- [ ] R51.3 — tasks 0.11, 16.3 — e2e/scripts/scope_gate.py — THE Deliverables_Router SHALL add no route, since the three new slugs use the existing slug route.
- [ ] R51.4 — tasks 0.11, 16.3 — e2e/scripts/scope_gate.py — THE Repository SHALL add no export format other than the three PDFs, no user-interface page, no database table or column, and no third-party dependency.
- [ ] R51.5 — tasks 0.11, 16.3 — e2e/scripts/scope_gate.py — THE new backend modules SHALL compile and import on Python 3.10, and the new `aibom` modules SHALL compile and import on the `requires-python` minimum that `aibom/pyproject.toml` declares.
- [ ] R52.1 — tasks 1.1, 17 — build report and the unexecuted runbook — THE Repository SHALL hold the work on the branch `feat/cbom-high-deliverables`, created from the Base_Commit in a separate git worktree, and SHALL commit nothing to `ansh` or `feat/cbom-team-deliverables`, push or mer...
- [ ] R52.2 — tasks 17.1 — build report and the unexecuted runbook — WHEN a commit changes product code after the evidence of a deliverable was collected, THE E2E_Harness SHALL re-run the affected specs and the full suite at the final commit before the build report is final.
- [ ] R52.3 — tasks 17.5 — build report and the unexecuted runbook — THE Release_Gate SHALL block every production action until the build report shows every Definition-of-Done item PASS at the final commit and the explicit approval of the user is recorded in the Evidence_Directory.
- [ ] R52.4 — tasks 0.12, 17.4 — build report and the unexecuted runbook — THE tasks of this spec SHALL end with the evidence, the build report and a production runbook, and SHALL perform no production action.
- [ ] R52.5 — tasks 17.4 — build report and the unexecuted runbook — THE runbook SHALL state that the posture lanes run in the scan-worker image, so that the rollout rebuilds and deploys the scan-worker image in addition to the backend and frontend images, and SHALL carry forward the s...
- [ ] R52.6 — tasks 17.4 — build report and the unexecuted runbook — THE runbook SHALL list the post-deploy checks: a manifest with nine items; nine PDFs for a team with only stored scans returning 200, with the three new ones showing the "POSTURE NOT ASSESSED - RE-SCAN NEEDED" banner;...
- [ ] R52.7 — tasks 1.1, 17 — build report and the unexecuted runbook — THE build report SHALL list both the evidence commit and the final commit and, for each commit between them, whether it can change rendered output.

## Requirement coverage

The package table below is the short map. The criterion index is the complete map.

| Requirements | Tasks |
|---|---|
| 1 | 9.1, 9.3, 9.4 |
| 2 | 2.1 |
| 3 | 3.1 |
| 4 | 2.1, 3.1 |
| 5 | 2.1, 5.1, 10.1, 14.2 |
| 6 | 5.1 |
| 7 | 5.1 |
| 8 | 3.1, 8.2 |
| 9 | 4.1, 6 |
| 10 | 4.1, 6, 8.2 |
| 11 | 8.2 |
| 12 | 8.2, 8.3 |
| 13 | 6, 8.4 |
| 14 | 8.2, 8.3 |
| 15 | 5.1, 12.1 |
| 16 | 8.2, 8.3, 8.5 |
| 17 | 8.3 |
| 18 | 8.5 |
| 19 | 8.7, 16.1 |
| 20 | 8.4 |
| 21 | 8.5 |
| 22 | 6, 8.1 |
| 23 | 8.6 |
| 24 | 8.8 |
| 25 | 8.8 |
| 26 | 9.2, 16.1 |
| 27 | 9.2, 10.1 |
| 28 | 5.1, 9.3 |
| 29 | 9.3 |
| 30 | 9.2, 14.2 |
| 31 | 16.1, 16.2 |
| 32 | 14.1, 14.2 |
| 33 | 11.1 |
| 34 | 12.1, 13.1 |
| 35 | 13.1 (11a), 15.2 |
| 36 | 13.1 (11b), 15.2 |
| 37 | 13.1 (11c), 15.2 |
| 38 | 11.1, 13.1 |
| 39 | 9.4, 14.1, 14.2 |
| 40 | 14.3, 15.2 |
| 41 | 10.1, 15.1 |
| 42 | 10.1, 12.1, 14.2 |
| 43 | 15.1, 15.2 |
| 44 | 1.4, 3.1, 6.1, 10.1 |
| 45 | 7.1 |
| 46 | 1.2, 9.5, 16.3 |
| 47 | 15.2, 15.5 |
| 48 | 15.3 |
| 49 | 8.2, 12.1, 15.4 |
| 50 | 15.5, 17 |
| 51 | 0.11, 16.3 |
| 52 | 1.1, 17 |

## What this plan does not do

- No new compliance framework key (R29).
- No new component kind and no edit to `model/result.py` or `aibom/scan/**`.
- No LLM, network call, subprocess, or new third-party library in product code.
- No live TLS probing.
- No Helm, Kustomize, Pulumi, Ansible, Terraform state, or `.terraform.lock.hcl` evaluation (K-5, K-12).
- Posture findings do enter `results[]` and `scan_findings` (task 0.4). Facts with no posture finding stay out of `results[]`. Graph and distribution charts stay crypto-asset only. Jira is not decided.
- No production deploy.

## Execution handoff

Plan saved at `.kiro/specs/cbom-config-encryption-posture/tasks.md`.

The confirmation questions are answered and the MEDIUM base is on `ansh` at `f738551`. Product posture code has not been started. No product end-to-end run exists yet. Execution of task 1.2 onward:

1. Subagent-driven, in this session: one fresh implementer per work package, review between packages, pathspec commits.
2. A separate session in `.worktrees/cbom-high-deliverables`, using the executing-plans skill, in the dependency order of design section 13.3.

Do not check a task complete from this plan's existence. Completion requires the named pytest, ruff, mypy, Playwright, verifier and teardown logs.
