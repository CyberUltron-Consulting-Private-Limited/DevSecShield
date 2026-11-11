# DevSecShield CI/CD and review pipelines

This folder documents the GitHub Actions pipelines in `.github/workflows/`. Every pull request depends on them, and
other repositories can reuse them.

- [How a pull request is checked](#how-a-pull-request-is-checked)
- [The gating rule: no new findings](#the-gating-rule-no-new-findings)
- [Workflows](#workflows)
- [Reusing the workflows in another repository](#reusing-the-workflows-in-another-repository)
- [Secrets, variables and apps](#secrets-variables-and-apps)
- [Branch protection (release manager)](#branch-protection-release-manager)
- [Audit of the workflows this replaced](#audit-of-the-workflows-this-replaced)
- [Current debt the pipelines report](#current-debt-the-pipelines-report)
- [Running the checks locally](#running-the-checks-locally)
- [Known limits](#known-limits)

## How a pull request is checked

```
pull_request / push to dev, staging, main
        │
        ▼
   ci.yml ── changes (dorny/paths-filter) ─────────────┬───────────────┬──────────────┐
        │                                              │               │              │
        ├── pr-checks (PRs only)                       ▼               ▼              ▼
        │     ├── branch-flow                       backend          aibom        frontend
        │     └── pr-hygiene                        (pytest +        (pytest +    (tsc, eslint,
        ├── security                                 PostgreSQL)      ruff/mypy)   tests, build)
        │     ├── secrets  (gitleaks, ggshield)     cbom-action      scan-node    codeql
        │     └── scanners (semgrep, osv, trivy,    images (backend, frontend, scan-node,
        │                   checkov, hadolint,               scan-worker, dast-worker)
        │                   shellcheck, actionlint)
        ▼
     ci-gate  ← the one required status check: passes when every job passed or was skipped as not affected
```

- **Path filters.** A suite runs only when its files change. A change to `ci.yml` or any `reusable-*.yml` runs
  every suite, so a pipeline change is tested end to end. `workflow_dispatch` runs everything.
- **Concurrency.** A new push to a PR cancels that PR's older run. Runs on `dev`, `staging` and `main` are never
  cancelled.
- **Permissions.** The workflow defaults to `contents: read`, and each job asks only for what it needs.
- **Pinned actions.** Every action is pinned to a full commit SHA with the version in a comment. Tool binaries
  (gitleaks, Trivy, OSV-Scanner, Hadolint, ShellCheck, actionlint) are pinned by version and SHA-256. Dependabot
  updates the action SHAs only. It cannot see the `*-version` / `*-sha256` inputs, or the PyPI and npm tools
  (Semgrep, Checkov, ggshield, tsx), which are pinned by top-level version only, so bump those by hand.

## The gating rule: no new findings

The repository carries a lot of existing findings (see [Current debt](#current-debt-the-pipelines-report)). A gate
that failed on all of them would block every pull request, so people would learn to ignore it. That is exactly
what happened to the old `cbom-gates.yml`, which was red on 59 of 59 runs. The rule instead is:

- **Pull requests and pushes ("diff" mode):** each scanner and linter also runs on the base commit. Findings are
  compared by (rule, file, message) with line numbers ignored, so code that only moved is not new. The job **fails
  only on findings the change adds.** Semgrep uses its own `--baseline-commit`. gitleaks scans only the new commits
  and blocks on anything it finds there.
- **Schedule and manual runs ("full" mode):** everything is scanned and **reported**: SARIF and JSON in the
  artifacts, counts in the run summary. Nothing is gated, gitleaks included (`gitleaks-fail-full: false`). Until the
  history is cleaned, a full scan that is always red would be ignored. New secrets are already blocked by the
  diff-mode scan of every pull request and push.
- **Tests, type checks and builds always block.** pytest, `tsc --noEmit`, the tsx tests, `next build`, the
  `uv lock --check` and the image builds have no "existing debt" mode. They must pass.

Every run's summary page shows a table per tool: findings now, findings on the base commit, new findings, and the
result.

### What a change cannot do to the secret gate

A pull request runs its own workflows and configs, so gitleaks is set up so that a change cannot exempt its own
secret. These cases were reproduced with fabricated tokens (security review on PR #16):

| A change that... | is still caught because |
|---|---|
| adds a `[[allowlists]]` entry to `.gitleaks.toml` | diff mode reads `.gitleaks.toml` from the **base** commit |
| adds its own fingerprint to `.gitleaksignore` | diff mode reads `.gitleaksignore` from the base commit and deletes the checkout's copy |
| ends the line with `# gitleaks:allow` | `--ignore-gitleaks-allow` |
| marks the file `-diff` in `.gitattributes` | `git log --text` |
| hides the secret in a merge's conflict resolution | `git log --diff-merges=remerge` shows what a merge adds beyond the automatic merge |
| puts a real `.env` under `tests/fixtures/` | there is no path allowlist any more (see below) |

GitGuardian gets the same treatment: `.gitguardian.yaml` is taken from the base commit.

**Fabricated secrets for detector tests.** A gitleaks finding whose file is under a `tests/fixtures/` directory
passes only when the PR carries the **`secret-fixtures-reviewed`** label. A reviewer adds the label after checking
that every value is fabricated, then re-runs the failed jobs. A finding anywhere else can never be waived by a
label. pr-hygiene applies the same label to forbidden key files under fixture directories. Existing fixture findings
in history get commit-pinned fingerprints in `.gitleaksignore` (`commit:file:rule:line`, which no future change can
reuse), copied from the first full-history scan on `main`.

**Changes to the gates themselves.** pr-hygiene fails when a PR changes `.github/**`, `.gitleaks.toml`,
`.gitleaksignore`, `.gitattributes`, `CODEOWNERS`, `.coderabbit.yaml` or any scanner config (`.semgrepignore`,
`.trivyignore`, `trivy.yaml`, `osv-scanner.toml`, `.hadolint.yaml`, `.shellcheckrc`, `.checkov.yaml`,
`.gitguardian.yaml`). Such a PR passes only once a security reviewer adds the **`security-config-reviewed`**
label. The touched files are listed in the job summary. pr-hygiene reads the title, body and labels from the API
when it runs, so after editing the PR or adding a label, use *Re-run failed jobs*.

**Reports hold no secret values.** gitleaks runs with `--redact`. Semgrep's text output, which prints each matched
line, is discarded. Every SARIF file has its `snippet` / `contextRegion` / `fixes` removed before upload, and the
job fails if any snippet is left.

## Workflows

| File | Trigger | Purpose |
|---|---|---|
| `ci.yml` | PR / push to dev, staging, main; manual | Orchestrator: the jobs above and `ci-gate` |
| `reusable-python-tests.yml` | `workflow_call` | uv + Python, lock check, install, blocking lint, no-new-findings lint, tests, optional PostgreSQL |
| `reusable-frontend.yml` | `workflow_call` | npm ci, tsc, ESLint (diff / blocking / off), every `*.test.ts` via tsx, next build |
| `reusable-security.yml` | `workflow_call` | gitleaks, ggshield, Semgrep, OSV-Scanner, Trivy fs, Checkov, Hadolint, ShellCheck, actionlint |
| `reusable-codeql.yml` | `workflow_call` | CodeQL for python and javascript-typescript (licence-gated) |
| `reusable-image-build.yml` | `workflow_call` | Pre-build check, buildx build without push, Trivy image scan, matrix over images |
| `reusable-pr-checks.yml` | `workflow_call` | branch-flow and pr-hygiene |
| `security-scheduled.yml` | weekly (Mon 03:17 UTC), manual | Full-history gitleaks and a full scanner report |
| `pr-labels.yml` | PR; also `workflow_call` | Area labels (actions/labeler) and size labels |
| `aibom-nightly.yml` | nightly 07:00 UTC, manual | Live AI-BOM benchmark against the Trusera and Cisco oracles (Bedrock spend) |
| `cbom-nightly.yml` | nightly 07:30 UTC, manual | Live CBOM benchmark against IBM cbomkit-theia |
| `deploy-staging.yml` | manual | Build the production images, optionally deploy them to staging |
| `scan-node-image.yml` | manual | Release the CBOM scan-node image as a file |

### What each `ci.yml` suite runs

| Job | Directory | Commands |
|---|---|---|
| backend | `backend/` | `uv lock --check`; `uv sync --frozen` plus the aibom venv (the posture-PDF tests call `aibom/.venv/bin/python`); `pytest tests` on Python 3.12 against PostgreSQL 15 with four databases (`CANCEL_RACE_PG_URL`, `AUTH_TEST_PG_URL`, `CBOM_TEST_PG_URL`, `P1_PG_URL`); ruff, no new findings |
| aibom | `aibom/` | `uv lock --check`; `uv sync --frozen --all-extras --dev`; `pytest tests` (covers the old AI-BOM gates A-E, the CBOM gates A-B and the posture suite); `bench/ci_repos.sh` (AI-BOM true-miss gate on pinned real repositories); `bench/cbom/ci_repos.sh` (CBOM true-miss gate on pyjwt and pyopenssl); ruff and mypy, no new findings |
| cbom-action | `.github/actions/cbom-scan` | The composite action passes on `code-supply/clean` and returns exit code 1 on `code-supply/vulnerable` |
| scan-node | `scan_node/` | Hash-pinned `requirements.lock` install, `pytest tests` |
| frontend | `frontend/` | `npm ci`, `tsc --noEmit`, ESLint (no new errors), 47 `*.test.ts` files run with `npx tsx`, `next build` |
| images | repository root | `scripts/deploy/check_image_contexts.sh`, then a buildx build and a Trivy scan of each changed image |

### "gitbot": the PR bot

The request named "gitbot", which is not a specific product. A PR bot here means automation that comments on or
labels pull requests. `pr-labels.yml` does this with **actions/labeler**: area labels from the changed paths
(`.github/labeler.yml`) and a **size label** (`size/XS` under 10 changed lines, `S` under 50, `M` under 250, `L`
under 1,000, `XL` above). It needs no app, no external service and no token beyond `GITHUB_TOKEN`.

- **Danger** was not chosen. It needs a Dangerfile in Ruby or JS plus its own runtime. Its typical checks (title
  format, description sections, forbidden files) already live in `pr-hygiene`.
- **Mergify** was not chosen. It is a hosted GitHub App with write access, and merging here is a release-manager
  decision.
- **CodeRabbit** provides AI review comments. **GitGuardian** provides secret alerts.
- Dependabot opens the dependency PRs.

## Reusing the workflows in another repository

Call a reusable workflow by path and ref. Pin the ref to a tag or a commit SHA, not a branch:

```yaml
name: CI
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  tests:
    uses: AnshSinghal-CyberUltron/devsecshield/.github/workflows/reusable-python-tests.yml@<sha-or-tag>
    with:
      suite-name: api
      working-directory: api
      python-version: "3.12"
      install-command: uv sync --frozen
      test-command: uv run --frozen pytest -q
      lint-diff-command: uvx ruff@0.15.18 check --output-format concise .
      postgres: true
      postgres-databases: test
  web:
    uses: AnshSinghal-CyberUltron/devsecshield/.github/workflows/reusable-frontend.yml@<sha-or-tag>
    with:
      working-directory: web
  security:
    uses: AnshSinghal-CyberUltron/devsecshield/.github/workflows/reusable-security.yml@<sha-or-tag>
    secrets:
      GITGUARDIAN_API_KEY: ${{ secrets.GITGUARDIAN_API_KEY }}
  pr:
    if: github.event_name == 'pull_request'
    permissions: { contents: read, pull-requests: read }
    uses: AnshSinghal-CyberUltron/devsecshield/.github/workflows/reusable-pr-checks.yml@<sha-or-tag>
    with:
      flows: "main:release"        # only `release` may open PRs into `main`
```

**Access.** This repository is private. Another repository can call its workflows only when (a) it belongs to the
same owner and (b) this repository allows it: *Settings → Actions → General → Access → "Accessible from
repositories owned by the user"*. For repositories under other owners, copy the workflow files into a separate
public repository that holds only them, and call them from there.

**Do not make this repository public** until every credential in the debt table below is rotated and the history
is purged. Today's tree holds 81 live-looking secrets, including 12 `.env` files and `cu-devsecshield-key.pem`, and
the history holds 328. Making it public would publish all of them.

Each workflow reads only the caller's checkout. Repo-specific files are optional and used when present:
`.gitleaks.toml`, `.semgrepignore`, `.trivyignore`, `.hadolint.yaml`, `.github/labeler.yml`.

### `workflow_call` interfaces

**reusable-python-tests.yml**

| Input | Default | Meaning |
|---|---|---|
| `suite-name` | `python` | Job title and summary name |
| `working-directory` | `.` | Project directory |
| `python-version` | `3.12` | Sets `UV_PYTHON` (overrides `.python-version`) |
| `uv-version` | `0.13.6` | uv to install |
| `lock-check` | `true` | `uv lock --check` |
| `install-command` | `uv sync --frozen` | Install |
| `lint-command` | empty | Blocking lint |
| `lint-diff-command` | empty | Lint whose `path:line[:col]: message` output is compared with the base commit (PRs fail on new lines) |
| `test-command` | `uv run --frozen pytest -q` | Tests |
| `env` | empty | Non-secret `KEY=VALUE` lines |
| `apt-packages` | empty | Ubuntu packages the tests need (backend: `poppler-utils` for `pdftotext`) |
| `setup-command` | empty | System setup before the install (backend: allow `nginx -t` to bind :80 as the runner user) |
| `postgres` | `false` | Start PostgreSQL |
| `postgres-image` | `postgres:15-alpine` | Image |
| `postgres-databases` | `test` | Databases to create; each is exported as `PG_URL_<NAME>`, the first also as `DATABASE_URL` |
| `fetch-depth`, `timeout-minutes`, `runs-on`, `artifact-paths` | `1`, `30`, `ubuntu-latest`, empty | |

| Secret | Meaning |
|---|---|
| `extra-env` | Optional secret `KEY=VALUE` lines (masked in logs) |

**reusable-frontend.yml**

| Input | Default |
|---|---|
| `working-directory` | `frontend` |
| `node-version` | `20` |
| `install-command` | `npm ci --no-audit --no-fund` |
| `typecheck-command` | `npx tsc --noEmit` (empty skips) |
| `eslint-mode` | `diff` (or `blocking`, `off`) |
| `eslint-args` | `.` |
| `test-pattern` | `*.test.ts` |
| `test-runner` | `npx --yes tsx@4.23.15` |
| `build-command` | `npx next build` (empty skips) |
| `build-env` | `NEXT_TELEMETRY_DISABLED=1`, `NEXT_PUBLIC_BACKEND_URL=http://localhost:8000` |

**reusable-security.yml**

| Input | Default |
|---|---|
| `mode` | `auto`: PRs and pushes use diff, everything else full |
| `exclude-regex` | `node_modules`, `.venv`, `venv`, `.next`, `dist` (does not apply to gitleaks). `ci.yml` adds this repo's fixture roots, anchored (`^aibom/tests/fixtures/`, ...), so a future product directory named `fixtures` or `examples` is still scanned |
| `gitleaks-config`, `gitleaks-fail-full` | `.gitleaks.toml` (taken from the base commit in diff mode), `false` |
| `secret-fixture-label`, `secret-fixture-regex` | `secret-fixtures-reviewed`, `(^\|/)tests?/fixtures/` |
| `semgrep-configs` | `p/ci p/python p/typescript p/secrets p/dockerfile` |
| `semgrep-min-level`, `hadolint-min-level`, `shellcheck-severity` | `warning` |
| `trivy-scanners`, `trivy-severity` | `vuln,misconfig`, `HIGH,CRITICAL` (secrets are left to gitleaks) |
| `checkov-frameworks` | `kubernetes terraform` |
| `helm-charts` | One chart per line, `<dir> [helm template args]`. Each is rendered for head and base and scanned as Kubernetes manifests. A chart that fails to render, input Checkov cannot process, or a rendered chart with zero evaluated checks fails the step. `ci.yml` passes `deploy/helm/cbom-scan-node` with CI placeholder values and the DaemonSet switched on |
| `*-version`, `*-sha256` | Pinned tool versions and checksums. Change both together. |
| `upload-sarif` | `false`. Set `true` only where code scanning exists, and grant `security-events: write` |

| Secret | Meaning |
|---|---|
| `GITGUARDIAN_API_KEY` | Optional. Without it, ggshield is skipped with a notice |

**reusable-codeql.yml**: `enabled` (`true`), `languages` (`["python","javascript-typescript"]`), `queries`
(`security-extended`), `paths-ignore`, `upload` (`false`). The caller grants `contents: read`, `actions: read`, plus
`security-events: write` when `upload: true`.

**reusable-image-build.yml**: `images` (required; a JSON array of `{name, context, dockerfile, build-args?,
build-contexts?}`), `pre-build-command`, `trivy-severity` (`HIGH,CRITICAL`), `trivy-fail-on` (empty, which means
report only), `cache` (`true`; the final image layers go to the Actions cache, so re-runs reuse them),
`free-disk-space` (`true`; deletes the runner's preinstalled Android, .NET, GHC and CodeQL. Without it the scan-worker
image, which pulls torch through garak, fails with "No space left on device").

**reusable-pr-checks.yml**: `flows` (`staging:dev main:staging`), `title-regex`, `title-max-length` (100),
`require-acceptance-criteria` (`true`; bots are exempt), `acceptance-heading-regex`, `forbidden-files-regex`
(case-insensitive: `.env` and `*.env` files, `.envrc`, `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `kubeconfig`,
`credentials`, `*.pem` / `.key` / `.p12` / `.pfx` / `.p8` / `.jks` / `.keystore` / `.ppk` / `.kdbx` / `.tfvars` / `.tfstate` / `.der`,
`id_rsa*`-style keys, service-account JSON), `allowed-files-regex` (`*.pub`, `.env.example` / `.sample` /
`.template` / `.dist`), `secret-fixture-label` / `secret-fixture-regex`, `security-config-regex` /
`security-config-label`. The caller grants `pull-requests: read`.

**pr-labels.yml**: `configuration-path` (`.github/labeler.yml`), `size-thresholds` (`10 50 250 1000`). The caller
grants `pull-requests: write`.

## Secrets, variables and apps

| Name | Kind | Needed by | Without it |
|---|---|---|---|
| `GITGUARDIAN_API_KEY` | repository secret | security / ggshield | Step skipped with a notice |
| `CODEQL_ENABLED` | repository variable (`true`) | codeql | CodeQL prints a notice (see [Known limits](#known-limits)) |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | repository secrets | aibom-nightly (Bedrock) | Nightly cannot call Bedrock |
| `STAGING_SSH_KEY`, `STAGING_SSH_KNOWN_HOSTS`, `STAGING_SSH_TARGET`; `STAGING_DIR` | `staging` environment secrets / variable | deploy-staging | Deploy step unavailable (the build still works) |

No other workflow needs a secret. CI tests use dummy values that are marked as such.

### CodeRabbit (AI code review)

`.coderabbit.yaml` is committed (validated against CodeRabbit's schema v2). It sets an assertive profile, reviews
PRs into dev, staging and main, uses the team's severity tags, adds security-risk instructions specific to
DevSecShield, has per-path instructions, and enables the ruff, ESLint, ShellCheck, Hadolint, actionlint, zizmor,
gitleaks, Checkov, Semgrep, OSV-Scanner and Trivy integrations. **It does nothing until the CodeRabbit GitHub App
is installed:**

1. Sign in at <https://app.coderabbit.ai> with the GitHub account that owns this repository.
2. Choose *Add repositories* (or GitHub → Settings → Applications → CodeRabbit → Configure) and grant access to
   `devsecshield` only.
3. Open or update a PR. CodeRabbit posts a walkthrough and line comments. It only comments; the required check
   stays `ci-gate`.

The free tier covers open-source repositories. A private repository needs a paid seat for the PR author.

### GitGuardian (secret detection, second engine)

1. Create an account at <https://dashboard.gitguardian.com> (the free plan covers small teams).
2. *API → Personal access tokens* (or *Service accounts*): create a token with the `scan` scope.
3. GitHub → this repository → *Settings → Secrets and variables → Actions → New repository secret*: name
   `GITGUARDIAN_API_KEY`, value the token.
4. The next PR runs `ggshield secret scan ci` on the PR's commits, which blocks on any secret.

Optionally, also install the GitGuardian GitHub App for real-time alerts on every push to every branch.

## Branch protection (release manager)

Require **one** status check on `dev`, `staging` and `main`:

| Check name (exactly) | Branches |
|---|---|
| `ci-gate` | dev, staging, main |

`ci-gate` already depends on every other job, including `pr-checks / branch-flow` and `pr-checks / pr-hygiene`
on PRs. Requiring the individual jobs as well would break: path filtering skips them on many PRs, and a skipped
required check blocks the merge. Also recommended: *Require branches to be up to date* on `staging` and `main`,
and *Do not allow bypassing*. Do **not** turn on *Require review from Code Owners* while all authors and reviewers
post through one account (see `.github/CODEOWNERS`).

## Audit of the workflows this replaced

The table records the state at `dev` 8314739, checked against 579 runs from the Actions API and their job logs.

| Workflow | Before | Root cause | Decision |
|---|---|---|---|
| `aibom-gates.yml` | green on `ansh` | Branch filter main/develop/module_1/ansh, so it never ran on `dev` | Folded into `ci.yml` → `aibom` |
| `cbom-gates.yml` | red, 59/59 | Gate C ruff: 1,640 E501 (pyproject line-length 88, code written to about 120) and 17 other findings. Gate D would also have failed (see below) | Folded into `aibom`; ruff and mypy now block only new findings |
| `cbom-deliverables.yml` | startup failure, 72/72 | Path filter `frontend/app/[[]team_id]/...` is not a valid glob, so no job ever ran | Folded into `backend` and `frontend` |
| `cbom-posture-gates.yml` | startup failure, 71/71 | Same invalid glob | Folded into `aibom` and `backend` |
| `cbom-code-scan.yml` | red | The composite action ran `uv` without installing it. Every scan exited 127, so "vulnerable tree is blocked" passed for the wrong reason | Action fixed (installs uv, exposes `exit-code`); folded into `cbom-action`, which asserts exit code 1 |
| `pdf-smoke.yml` | green | Subset of the backend suite | Folded into `backend` |
| `aibom-nightly.yml` | red or cancelled (runs from `main`) | Genuine benchmark result: 34 true misses; on other nights the 71-minute run hit the 90-minute timeout | Kept, actions pinned. Product follow-up |
| `cbom-nightly.yml` | red (runs from `main`) | Genuine result: 3 true misses on mitmproxy (`ecdsa-sha384` and two certificates) | Kept, actions pinned. Product follow-up |
| `deploy-staging.yml` | manual, never run | n/a | Kept, actions pinned |
| `scan-node-image.yml` | manual | n/a | Kept, actions pinned |
| `build-agents.yml` | never triggered | Builds `agent/`, which is not in this repository (AISecShield agent). Also had `contents: write` and pushed binaries | Retired |
| `build-offline.yml` | manual | Needs `scripts/build_offline_package.py` and `scripts/build_agent.py` (absent) | Retired |
| `build-uninstaller.yml` | red | Needs `endpoint_agent/` (absent) | Retired |
| `docker-ci.yml` | red, 20/20 | Builds `gateway/` and `agent/`, runs `tests/unit` and `make lock-check`; none exist | Retired; replaced by `images` and `uv lock --check` |
| `lint.yml` | red | No `.pre-commit-config.yaml`; runs a Django check on a FastAPI app | Retired; replaced by the ruff and ESLint diff gates |
| `module1-e2e.yml` | red, 19/19 | `scripts/module1_e2e_smoke.sh` absent | Retired |
| `security-validation.yml` | red, 19/19 | No root compose file and no `scripts/run_security_validation.sh` | Retired; replaced by `security` |

Restore any retired file with `git show 8314739:.github/workflows/<file>`.

**Stray gitlinks removed.** `dev` carried 15 gitlinks (mode 160000) with no `.gitmodules`: three under
`.worktrees/`, which were accidentally committed git worktrees, and twelve benchmark clones under `bench/repos/` and
`bench/cbom/repos/`. With actions/checkout v4 they only printed "No url found for submodule path" at clean-up.
With the current checkout they fail the checkout itself (git exit 128). That was the first CI run on this PR, run
42984085692. They are removed from the index, and `.worktrees/` is now ignored. The bench directories were already
ignored by `bench/.gitignore` and `bench/cbom/.gitignore`, and the bench scripts clone on demand.

They also hid a gate failure. A checkout had the bench gitlinks as empty directories, so `bench/cbom/ci_repos.sh`
took "directory exists" to mean "already cloned", scanned an empty directory, and reported 6 + 1 true misses on
pyjwt and pyopenssl. It now clones when the directory is missing or empty. After the fix, both repositories pass
with 0 true misses. `bench/ci_repos.sh` got the same guard.

## Current debt the pipelines report

Measured on `dev` 8314739. These findings do not block a PR (only new ones do), but they are real.

| Area | Count | Notes |
|---|---:|---|
| **Secrets in git history** (gitleaks, excluding the fabricated detector fixtures) | 328 | 81 in today's tree across 42 tracked files, 12 of them `.env` files. They include OpenAI, AWS, GitHub fine-grained PATs, Atlassian, Azure AD and GCP keys, and `cu-devsecshield-key.pem` at the root. Main places: `backend/.env`, `backend/utilities/ai/` (`.env`, `llm.py`, `chatbot.py`, `testing.py`), `RabbitMQ/.env`, `RabbitMQ/{worker,dast_worker,guardrail_worker}/.env`, `RabbitMQ/worker/helpers/context/.env`, `RabbitMQ/worker/helpers/tests/*`, `RabbitMQ/worker/celery_test.py`, `RabbitMQ/worker/Dockerfile`, `RabbitMQ/dast_worker/Dockerfile`, `RabbitMQ/guardrail_worker/ticketing/jira.py`, `docs/Docs.md`, `.playwright-mcp/scan367_api.json`. **Rotate every credential first.** Then remove the files, and decide whether to rewrite history. |
| Dependency vulnerabilities (OSV-Scanner) | 2,608 | Across 12 lockfiles (benchmark fixtures excluded) |
| ESLint errors (frontend) | 208 | 113 `no-explicit-any`, 77 react-hooks |
| ruff (aibom `src` + `tests`) | about 2,600 | Mostly E501 at 88 columns. Either set line-length to 120 or reformat |
| mypy (aibom CBOM lane) | 68 | |
| ruff defaults (backend) | 547 | |
| ShellCheck (warning and above) | 4,186 | |
| Hadolint (warning and above) | 14 | |

The secret values were never printed or stored. Every scan above ran with `--redact`, and the reports list only
the file and the rule.

## Running the checks locally

```bash
# workflows
pipx run actionlint-py==1.7.12.25                                 # or: uvx --from actionlint-py actionlint
# secrets (gitleaks 8.30.1), as CI runs them: the PR's commits, or the whole history
gitleaks git --redact --ignore-gitleaks-allow --log-opts="--text --diff-merges=remerge origin/dev..HEAD" .
gitleaks git --redact --ignore-gitleaks-allow --log-opts="--full-history --all --text --diff-merges=remerge" .
# Semgrep, the same rulesets as CI
uvx --from semgrep==1.181.1 semgrep scan --metrics=off --config p/ci --config p/python --config p/typescript \
  --config p/secrets --config p/dockerfile
# backend tests as CI runs them (PostgreSQL optional: without the *_PG_URL variables those tests skip)
(cd aibom && uv sync --frozen --all-extras --dev)
cd backend && UV_PYTHON=3.12 uv sync --frozen && PYTHONPATH=.. JWT_SECRET_KEY=x JWT_REFRESH_SECRET_KEY=x \
  uv run --frozen --with pytest==9.2.0 --with moto==5.2.5 python -m pytest tests -q
# frontend
cd frontend && npm ci && npx tsc --noEmit && npx eslint . && \
  for t in $(find . -name '*.test.ts' -not -path './node_modules/*'); do npx --yes tsx@4.23.15 "$t" || break; done
```

## Known limits

- **CodeQL and code scanning are unavailable on this repository today.** It is a private repository owned by a user
  account. GitHub's terms allow CodeQL only on public repositories and on organisation repositories with GitHub
  Code Security. SARIF upload is refused the same way: the code-scanning API returns 403, "Code scanning is not
  enabled". The `codeql` job therefore prints a notice, and every SARIF report is kept as a workflow artifact
  (14 days). Semgrep provides SAST in the meantime. To enable CodeQL, move the repository to an organisation with
  GitHub Code Security, then set the variable `CODEQL_ENABLED=true` and, if wanted, `upload-sarif: true`. Making it
  public is **not** an option until the credentials are rotated and the history is purged (see above).
- **Schedules run from the default branch only.** `security-scheduled.yml` and the nightlies fire from `main`.
  Until this PR reaches `main`, run them by hand, or keep the old copies on `main`.
- **Dependabot and `ARG`-based base images.** Dependabot's docker updater rewrites `FROM image:tag` lines. The
  backend and worker Dockerfiles take their base image from an `ARG` default, so those bumps may need a manual
  edit.
- **The images job builds without pushing.** Publishing images stays with `deploy-staging.yml` and
  `scan-node-image.yml`.
