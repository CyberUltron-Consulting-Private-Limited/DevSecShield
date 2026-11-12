# DevSecShield CI/CD and review pipelines

This folder documents the GitHub Actions pipelines in `.github/workflows/`. Every pull request depends on them, and
they are written so that other repositories can reuse them.

- [How a change is checked](#how-a-change-is-checked)
- [The gating rule: no new findings](#the-gating-rule-no-new-findings)
- [The secret gate](#the-secret-gate)
- [Branch flow and hotfixes](#branch-flow-and-hotfixes)
- [Workflows](#workflows)
- [Reusing the workflows in another repository](#reusing-the-workflows-in-another-repository)
- [Secrets, variables, labels and apps](#secrets-variables-labels-and-apps)
- [Branch protection (release manager)](#branch-protection-release-manager)
- [Audit of the workflows this replaced](#audit-of-the-workflows-this-replaced)
- [Current debt the pipelines report](#current-debt-the-pipelines-report)
- [Running the checks locally](#running-the-checks-locally)
- [Known limits](#known-limits)

## How a change is checked

```
pull_request into dev / staging / main, merge_group, push to dev / staging / main, workflow_dispatch
        │
        ▼
   ci.yml ── changes (dorny/paths-filter) ──┬────────────┬────────────┬────────────┬────────────┐
        │                                   ▼            ▼            ▼            ▼            ▼
        ├── ci-selftest (pipeline changes)  backend      aibom        worker       scan-node    frontend
        ├── pr-checks (PRs only)            (pytest +    (pytest +    dast-worker  (pytest)     (tsc, eslint,
        │     ├── branch-flow               PostgreSQL,  ruff/mypy,   (pytest)     cbom-action   tests, build)
        │     └── pr-hygiene                ruff)        true-miss)   worker-locks  cbom-d1      codeql
        ├── security                          images (backend, frontend, scan-node, scan-worker, dast-worker)
        │     ├── secrets  (gitleaks, ggshield)
        │     └── scanners (semgrep, osv, trivy, checkov, hadolint, shellcheck, actionlint)
        ▼
     ci-gate  ← the one required status check: passes when every job passed, or was skipped because `changes`
                said it was not affected (a job skipped although its paths changed fails the gate)
```

| Event | What runs |
|---|---|
| Pull request into dev, staging or main | pr-checks, security, and the suites and images whose paths changed |
| `merge_group` (a merge queue entry) | security, and the suites and images whose paths changed between the queue's base commit and its merge commit. The suites' tests and the image builds run as on a PR. Their lint-diff steps (ruff, mypy, ESLint "no new findings") run in report mode only, as on a push, and the security jobs scan in report mode (see [Known limits](#known-limits), #70). There are no pr-checks: there is no PR event, and the PR's own run checked them. `ci-gate` reports on the queue commit, so a queue can require it |
| Push to `dev` (a merge) | security, and the suites and images whose paths changed since the commit before the push |
| Push to `staging` or `main` (a promotion) | security and the changed images only. The commit arrived through a PR whose run already tested the merged tree (branch protection requires branches to be up to date), so the suites are not run a second time |
| `workflow_dispatch` | everything; scanners in report mode |

- **Path filters.** A suite runs when a file **its tests read** changes, not only its own directory (table
  below). The backend rule is inverted, because its tests read deploy/, scripts/, e2e/, compose/, RabbitMQ/,
  scan_node/, aibom/, bench/ and migrations: it runs on any change except `docs/`, `*.md`, `.github/` and frontend
  files outside `frontend/{app,components,utils}` (which its tests do read). A change to `ci.yml` or any
  `reusable-*.yml` runs every suite, so a pipeline change is tested end to end. On pushes, the filter compares with
  the commit before the push (`base: <pushed branch>`), not with the default branch. `.github/tests/test_ci.py`
  checks the map: each tested file must select the suites whose tests read it, and docs must select none.
- **The scan-worker image** (torch through garak, about 20 minutes) is built on a PR only when `RabbitMQ/worker/`
  or `reusable-image-build.yml` changes, and on a push to `dev` also when `aibom/` (copied into the image) changes.
  Its runner gets the `free-disk-space` clean-up; the other images do not need it. Build layers go to the Actions
  cache from `dev` only, and PRs read them. The cache is `mode=min` (final-image layers only), so a PR that changes
  worker code re-installs every dependency: plan for a full build.
- **Runner disk.** Every image job logs the lowest free disk space it reached, and warns under 10 GB. See
  [Runner disk](#runner-disk).
- **Concurrency.** A new push to a PR cancels that PR's older run. On `dev`, `staging` and `main` a running run is
  not cancelled. But GitHub keeps only one *pending* run per group, so after several quick merges the middle commits
  may get no result of their own. Merge-queue runs are never cancelled by this workflow, because each queue entry
  has its own ref. GitHub does not cancel them either when it rebuilds or drops a queue group: those runs finish and
  use runner minutes. Keep the queue's *Maximum pull requests to build* small (a cancel job is #71).
- **Permissions.** The workflow defaults to `contents: read`, and each job asks only for what it needs. Only two jobs
  get a write token, `pull-requests: write`, and neither checks out PR code: the label job, and
  `pr-checks / review labels`, which removes review labels that new commits outdate. Every checkout uses
  `persist-credentials: false`.
- **Pinned actions.** Every action is pinned to a full commit SHA with the version in a comment. Tool binaries
  (gitleaks, Trivy, OSV-Scanner, Hadolint, ShellCheck, actionlint) are pinned by version and SHA-256. Dependabot
  updates the action SHAs only. It cannot see the `*-version` / `*-sha256` inputs, or the PyPI and npm tools
  (Semgrep, Checkov, ggshield, tsx), which are pinned by top-level version only, so bump those by hand
  (hash-locking them is #20). The PostgreSQL service image is pinned by digest. Bump it by hand too: Dependabot does
  not update workflow service images.

### Runner disk

The hosted runner has about 15 GB free. A full build of the scan-worker image (torch with the CUDA wheels, through
garak) needs about 40 GB at its peak (#50). How the image job keeps that within the disk:

- **One copy of the image.** Images are built with Buildx's `docker` driver, straight into the runner's Docker
  image store. The default `docker-container` driver kept a second copy in its own BuildKit store, and `load`
  streamed it into Docker as a tarball that Docker stored and unpacked again. That filled the 44 GB left after the
  clean-up.
- **Clean-up.** Images with `"free-disk-space": true` first delete preinstalled toolchains the job never uses:
  15 GB free becomes 54 GB. `/mnt` is on the same disk on these runners, so it adds nothing.
- **Build cache pruned before Trivy.** Intermediate stages and uv's wheel cache (34 GB on scan-worker) are deleted
  before Trivy writes its temporary copy of the image.
- **Disk headroom.** A background monitor samples the free space on `/` every 5 s. The last step prints the lowest
  value in the log and the job summary, for example `Disk (scan-worker): lowest free space 13.5 GB at 06:46:27 UTC`.

**When it warns** (lowest free space under 10 GB):

1. If the image has no `"free-disk-space": true` in the `Decide` step of `ci.yml`, add it. The clean-up adds about
   39 GB and about 3 minutes.
2. If it already has it, the image or its build must get smaller. For scan-worker the open options are in #50:
   - CPU-only torch wheels, if the worker never uses a GPU (about 3 GB compressed, in every copy);
   - avoid the second copy of the venv that the uv cache mount makes with `UV_LINK_MODE=copy`.

Small images built without the clean-up (dast-worker) sit near 10 GB on a fully cached build. A warning there is
not yet a risk; a per-image threshold is #71.

## The gating rule: no new findings

The repository carries a lot of existing findings (see [Current debt](#current-debt-the-pipelines-report)). A gate
that failed on all of them would block every pull request, so people would learn to ignore it. That is exactly
what happened to the old `cbom-gates.yml`, which was red on 59 of 59 runs. The rule instead is:

- **Pull requests ("diff" mode; the scanners also on pushes):** each linter and scanner also runs on the base
  commit (PR: the base branch; push: the commit before the push). The job **fails only on findings the change
  adds.** A finding is keyed on (rule, file, message). The message is normalised to its first line, with checkout
  paths, `line 123` references, ruff's `(130 > 88)` measurement and OSV's `@<version>` removed, and a file the
  change renamed is compared under its new name (`git diff -M`). So identical code at another path, moved or
  renamed code, a shortened line that is still too long, and a dependency bump that leaves a CVE open are never
  "new". Several occurrences of one rule in one file are counted. Semgrep uses its own `--baseline-commit`, and
  runs with `--disable-nosem`, so a `# nosemgrep` comment a change adds does not hide its own finding (pr-hygiene
  also asks for the security label when a PR adds any inline scanner suppression). The secret gate is stricter;
  see the next section.
- **A gate that could not run never passes.** A linter that exits with anything but 0 or 1 (crashed, missing,
  rejected its config), or exits 1 without a finding the gate can read, fails the step, on every event. The Python
  lint runs each line of `lint-diff-command` as its own command, so aibom's ruff and mypy each keep their exit
  code. On a pull request, a base commit that cannot be checked out fails the step. If the linter fails on the
  base commit (for example an upgrade whose new version cannot load the base's config), every finding in a file
  the PR adds or modifies counts as new, never every finding in the repository.
- **`workflow_dispatch` and the weekly scan ("full" mode):** everything is scanned and **reported**: SARIF and JSON
  in the artifacts, counts in the run summary. Nothing is gated, gitleaks included (`gitleaks-fail-full: false`).
  New secrets are already blocked by the diff-mode scan of every pull request and push.
- **Tests, type checks and builds always block.** pytest, `tsc --noEmit`, the tsx tests, `next build`, `uv lock
  --check` and the image builds have no "existing debt" mode. They must pass.

The comparators are Python embedded in the workflows, so callers in other repositories need no extra files. All
their decisions (tool exit codes, missing base, renames) are inside that Python. `.github/tests/` extracts it from
the YAML and tests it: 104 tests, run by the `ci-selftest` job whenever a workflow, a test or this file changes.
They check that the same findings from two checkouts at different paths give 0 new, that an added finding is new,
that each failure mode above fails, that ci-gate, the path map, the image list (`Decide`, run for each event),
pr-hygiene and the image job's disk steps behave as documented, and that every reusable-workflow input is documented
here.

Each new finding is annotated on a line the change added (`git diff -U0`), with the tool's own message, because
several findings of one rule in one file share a key: a new long line in a file that already has some is shown on
the new line, "(102 > 88)", not on the file's first long line. Known limit: a change that fixes one occurrence of a
rule in a file and adds another nets to zero (#19).

Every run's summary page shows a table per tool: findings now, on the base commit, new, and the result.

## The secret gate

gitleaks scans **commits**, not the tree. A PR is scanned commit by commit from base to head; a push from the
commit before the push to the pushed one. Anything found there blocks, except what the base already knew about.

**A change cannot exempt its own secret.** A pull request runs its own workflows and configs, so gitleaks is set up
as follows. Each row was reproduced with fabricated tokens (security review on PR #16) and is caught:

| A change that... | is still caught because |
|---|---|
| adds a `[[allowlists]]` entry to `.gitleaks.toml` | diff mode reads `.gitleaks.toml` from the **base** commit |
| adds its own fingerprint to `.gitleaksignore` | diff mode reads `.gitleaksignore` from the base commit and deletes the checkout's copy |
| adds a 3-field line (`file:rule:line`) to `.gitleaksignore`, which gitleaks would apply to every commit | only 4-field fingerprints that start with a full commit SHA are kept; any other line is dropped with a warning |
| ends the line with `# gitleaks:allow` | `--ignore-gitleaks-allow` |
| marks the file `-diff` in `.gitattributes` | `git log --text` |
| hides the secret in a merge's conflict resolution | `git log --diff-merges=remerge` shows what a merge adds beyond the automatic merge |
| puts a real `.env` under `tests/fixtures/` | there is no path allowlist; fixtures need a label (below) |

GitGuardian gets the same treatment: `.gitguardian.yaml` is taken from the base commit.

**Promotion PRs** (`dev → staging`, `staging → main`) re-scan every commit since the last release. gitleaks reads
the config and `.gitleaksignore` from the promotion head only when all three hold: the head is listed in
`trusted-heads` (default `dev staging`), the PR comes from this repository, and the GitHub API reports the head
branch as **protected**. Only then is it certain that every change to those files arrived through a reviewed PR
with the `security-config-reviewed` label. On an unprotected branch a direct push could allowlist its own secret, so
the base commit's files are used and a notice says why. Today `dev`, `staging` and `main` are not protected (see
[Branch protection](#branch-protection-release-manager)), so promotions use the base's files. `dev → staging`
works, because the range holds only new commits. The first `staging → main` promotion also needs `main` to carry the
baseline first, through a labelled `hotfix/*` PR that adds `.gitleaksignore` (or branch protection turned on).

**Secret baseline (`.gitleaksignore`).** This file lists the fingerprints (`commit:file:rule:line`, no values) of
all 829 findings, 396 fingerprints, that gitleaks reports on the full history of every branch as of 2026-11-11. A
fingerprint names one finding in one commit, so it can never cover a new secret (and lines without a commit SHA
are dropped before the scan, see the table above). These findings are **known, not
accepted**: most are live credentials that must be rotated. The baseline only stops them from blocking every
promotion. To regenerate it, run on a full (not shallow) clone:

```bash
gitleaks git --redact --ignore-gitleaks-allow --log-opts="--full-history --all --text --diff-merges=remerge" \
  --report-format json --report-path baseline.json .
jq -r '.[].Fingerprint' baseline.json | sort -u     # append to .gitleaksignore, below the header
```

**Fabricated secrets for detector tests.** A gitleaks finding whose file is under a `tests/fixtures/` directory
passes only when the PR carries the **`secret-fixtures-reviewed`** label. A reviewer adds it after checking that
every value is fabricated, then re-runs the failed jobs. A finding anywhere else can never be waived by a label.
pr-hygiene applies the same rule to key files (`*.pem`, `*.key`, ...) under fixture directories. A push run has no
PR and no label, so **after merging a labelled fixture PR, the push run on `dev` is red by design**: follow it with
a PR that adds the fixture's fingerprints to `.gitleaksignore` (with the `security-config-reviewed` label). Making
push runs apply the merged PR's label is #24.

**Reports hold no secret values.** gitleaks runs with `--redact`. Semgrep's text output, which prints each matched
line, is discarded. Every SARIF file has its `snippet` / `contextRegion` / `fixes` removed before upload, and the
job fails if any snippet is left. Secrets inside binary and archive files (.docx, .zip) are not seen (#21).

**The first `staging → main` promotion is blocked until #18 lands.** `main` (15 July) is 347 commits behind
`dev`, and those commits modify tracked `.env` files (`backend/.env`, `backend/utilities/ai/.env`,
`RabbitMQ/worker/.env`, `RabbitMQ/worker/helpers/context/.env`). pr-hygiene refuses a PR that adds or modifies
secret-bearing files, and it is deliberately **not** relaxed for promotion PRs. #18 removes the tracked `.env`
files from `dev` (replacing them with `.env.example`) without breaking the staging deploy. Once it is merged, the
promotion diff shows them as removed, which is allowed. gitleaks findings in those commits are covered by the
baseline.

## Branch flow and hotfixes

| PR into | allowed from | checked by |
|---|---|---|
| `dev` | any branch (`feature/*`, `fix/*`, a `main → dev` back-merge, Dependabot) | |
| `staging` | `dev` only | `pr-checks / branch-flow` |
| `main` | `staging`, or `hotfix/*` | `pr-checks / branch-flow` |

**Hotfix route.** For an urgent production fix that must not ship everything unreleased on `dev`:

1. Branch from `main` as `hotfix/<name>` and open a PR into `main`. The full CI runs, and the release manager merges.
2. Back-merge right away: open a PR `main → dev` (allowed, since `dev` is not a promotion base), so the fix is not
   lost at the next `dev → staging → main` promotion.

`flows` takes `base:head1|head2` pairs with globs, e.g. `staging:dev main:staging|hotfix/*`.

**pr-hygiene** checks, on every PR:

- The title follows `type(scope): summary` (feat, fix, docs, ci, build, chore, refactor, perf, test, security,
  release, revert), or is the `Revert "<title>"` that GitHub's Revert button writes (which may be 9 characters
  over the limit). A revert still needs the table: one row, "the reverted behaviour is back", with the ci-gate run.
- The template's *Acceptance criteria → evidence* table has filled rows only: any row with an *italic
  placeholder*, an empty cell, evidence that says `pending`, `TBD`, `TODO` or `WIP`, or starts with `N/A`, fails. Bots
  (Dependabot) are exempt.
- **Promotion PRs** (into `staging` or `main`) use the promotion template: add `?template=promotion.md` to the
  compare URL (`.github/PULL_REQUEST_TEMPLATE/promotion.md`). Its table asks for the promotion's own evidence: every
  change merged through a green `ci-gate`, `ci-gate` green on the promoted commit, the target checked, migrations
  and secrets in place, and a rollback plan.
- No secret-bearing file is added or modified. This is case-insensitive and covers `.env` and `*.env`, `.envrc`,
  `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `.pgpass`, `.htpasswd`, `.s3cfg`, `kubeconfig`,
  `credentials` (also `.json`, `.csv`), `accessKeys.csv`, `.docker/config.json`, private keys and keystores,
  `*.ovpn`, `*.keytab`, `.tfvars` / `.tfstate` / `.tfstate.backup`, `id_rsa*` and service-account JSON. Deleting
  one is allowed.
- Changes to the gates themselves (`.github/**`, `.gitleaks.toml`, `.gitleaksignore`, `.gitattributes`,
  `CODEOWNERS`, `.coderabbit.yaml`, `.semgrepignore`, `.trivyignore`, `trivy.yaml`, `osv-scanner.toml`,
  `.hadolint.yaml`, `.shellcheckrc`, `.checkov.yaml`, `.gitguardian.yaml`) need the `security-config-reviewed`
  label, whether the file is added, modified, renamed (either name) or **deleted**. So does an added line with an
  inline scanner suppression (`nosemgrep`, `checkov:skip`, `hadolint ignore`, `shellcheck disable`,
  `trivy:ignore`; `suppression-regex`). The files are listed in the job summary. (A file whose patch the API omits,
  binary or very large, is listed as unchecked for suppressions.)
- **Review labels cover the commits they were given for.** On every new push, `pr-checks / review labels` runs
  before pr-hygiene. It removes `security-config-reviewed` when the new commits touch gate files or add a
  suppression, and `secret-fixtures-reviewed` when they touch a fixture path (both, if the change cannot be read).
  The reviewer checks the new commits and adds the label again. This runs inside `pr-checks`, not in
  `pr-labels.yml`, so the same push can never be judged with the old label.

It reads the title, body and labels from the API when it runs, so after editing the PR or adding a label, use
*Re-run failed jobs* (no new commit needed).

**Dependabot's github-actions PRs** change `.github/workflows/`, so they fail pr-hygiene until a person checks the
bump (the action's release notes and the new commit SHA) and adds the `security-config-reviewed` label, then
re-runs the failed jobs. That is deliberate: an action update runs new third-party code with the workflow's token.
Every promotion that carries a `.github/` change needs the label too.

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
| `pr-labels.yml` | PR; also `workflow_call` | Area labels (actions/labeler) and a size label, in one job |
| `aibom-nightly.yml` | **weekly** (Mon 07:00 UTC), manual | Live AI-BOM benchmark against the Trusera and Cisco oracles (Bedrock spend). Was nightly, 86 min a night on July code |
| `cbom-nightly.yml` | **weekly** (Mon 07:30 UTC), manual | Live CBOM benchmark against IBM cbomkit-theia |
| `deploy-staging.yml` | manual | Build the production images, optionally deploy them to staging |
| `scan-node-image.yml` | manual | Release the CBOM scan-node image as a file |

### What each `ci.yml` suite runs

| Job | Directory | Commands |
|---|---|---|
| backend | `backend/` | `uv lock --check`; `uv sync --frozen` plus the aibom venv (the posture-PDF tests call `aibom/.venv/bin/python`); poppler-utils; `pytest tests` on Python 3.12 against PostgreSQL 15 with four databases (`CANCEL_RACE_PG_URL`, `AUTH_TEST_PG_URL`, `CBOM_TEST_PG_URL`, `P1_PG_URL`); ruff, no new findings |
| aibom | `aibom/` | `uv lock --check`; `uv sync --frozen --all-extras --dev`; `pytest tests` (covers the old AI-BOM gates A-E, the CBOM gates A-B and the posture suite); `bench/ci_repos.sh` (AI-BOM true-miss gate on pinned real repositories); `bench/cbom/ci_repos.sh` (CBOM true-miss gate on pyjwt and pyopenssl at the commits the oracle snapshots were made from; a repository that cannot be fetched, or nothing scanned, fails); ruff and mypy, no new findings |
| worker | `RabbitMQ/worker/` | `uv lock --check`; `uv sync --frozen` (torch + CUDA wheels, so the disk is freed first and nothing is cached); `pytest tests helpers/tests/test_*.py helpers/tools/sca_sbom_agent/test_*.py` (14 files; the older `*_test.py` scripts call live LLMs). Tests that fail today are listed, with their reason, in `.github/ci/pytest-deselect-worker.txt` |
| dast-worker | `RabbitMQ/dast_worker/` | `uv lock --check`; `uv sync --frozen`; `pytest helpers/tests/test_*.py` (6 files, including test_egress_pinning). Deselect list: `.github/ci/pytest-deselect-dast-worker.txt` |
| worker-locks | `RabbitMQ/guardrail_worker/` | `uv lock --check` (it has no pytest suite) |
| cbom-action | `.github/actions/cbom-scan` | The composite action passes on `code-supply/clean` and returns exit code 1 on `code-supply/vulnerable` |
| cbom-d1 | `aibom/` (runs `bench/cbom/d1/ci.sh`) | `uv sync --frozen --all-extras --dev`; fetches CryptoAPI-Bench and the OWASP Benchmark Java crypto/hash/weakrand subset at pinned commits, runs the CBOM code engine as the scan-worker does, scores it against the benchmarks' own labels, the labelled corpus in `e2e/fixtures/cbom-d1-corpus/` and OSV; fails on a non-regression floor or on a target floor that starts passing (`bench/cbom/d1/README.md`). `report.md` goes to the job summary, the report and work files to the `cbom-d1-artifacts` artifact. Needs network to github.com and api.osv.dev |
| scan-node | `scan_node/` | Hash-pinned `requirements.lock` install, `pytest tests` |
| frontend | `frontend/` | `npm ci`, `tsc --noEmit`, ESLint (no new errors), 47 `*.test.ts` files run with `npx tsx`, `next build` |
| images | repository root | `scripts/deploy/check_image_contexts.sh`, then a buildx build and a Trivy scan of each changed image |
| ci-selftest | `.github/tests/` | Unit tests of the comparators, branch-flow and the pr-hygiene regexes |

### Which suite a change runs

| Suite | Runs when these change (plus `ci.yml` / `reusable-*.yml`) | Why the extra paths |
|---|---|---|
| backend | everything except `docs/`, `*.md`, `.github/`, root CI configs and `frontend/` outside `app/`, `components/`, `utils/` | its tests read deploy/staging compose and nginx, scripts/deploy and scripts/crypto_kb, e2e/, compose/, RabbitMQ Dockerfiles and helpers, scan_node collectors, aibom, bench/certin, migrations, and search the frontend sources for banned words |
| aibom | `aibom/`, `bench/`, every `.py` under `backend/`, `RabbitMQ/`, `e2e/`; `backend/utilities/cbom_sources/data/crypto_kb.json`; the CBOM, CERT-In and SEBI ledgers under `docs/` | test_only_cbom_code_imports_posture reads all that Python; other tests compare the KB and the ledgers |
| cbom-action | the action, the aibom CLI and CBOM code, its fixtures, `aibom/pyproject.toml`, `aibom/uv.lock` | |
| cbom-d1 | `bench/cbom/d1/`, `e2e/fixtures/cbom-d1-corpus/`, `aibom/src/aibom/cbom/`, `aibom/src/aibom/integrations/cbom_devsecshield.py`, `RabbitMQ/worker/helpers/tools/cbom_agent/`, `aibom/pyproject.toml`, `aibom/uv.lock` | the engine, the scan-worker's call into it, and the lane (round 7 wave W-D1) |
| scan-node | `scan_node/`, `deploy/node-images/`, `backend/utilities/cbom_sources/{node_auth,templates}.py`, `aibom/src/aibom/cbom/pkgdb.py`, `frontend/components/cbom/sources/logic.ts` | the node tests pin those server and wizard files |
| worker | `RabbitMQ/worker/`, `aibom/src/`, its deselect list | the SBOM agent tests import aibom from source |
| dast-worker | `RabbitMQ/dast_worker/`, `compose/worker-compose/docker-compose.yml`, its deselect list | test_nuclei_process_cleanup reads the compose file |
| worker-locks | `RabbitMQ/guardrail_worker/` | |
| frontend | `frontend/` | |

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

**Target (#22):** a dedicated `<org>/ci-workflows` repository that holds only these workflows, the cbom-scan
action and `.github/tests`. It has no product code and no secrets, so it can be public. Releases get semver tags
(`v1`, `v1.2.0`), and callers pin `@v1`. Until it exists, this repository calls its workflows locally (`uses:
./.github/workflows/...`). Other repositories of the same owner can call them here, if *Settings → Actions →
General → Access* is set to "Accessible from repositories owned by the user". Repositories under another owner
must copy the files.

**Do not make this repository public** until every credential in the debt table is rotated and the history is
purged. Today's tree holds 81 live-looking secrets, including 12 `.env` files and `cu-devsecshield-key.pem`, and
the history holds 328. Making it public would publish all of them.

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
    permissions: { contents: read, pull-requests: read }
    uses: AnshSinghal-CyberUltron/devsecshield/.github/workflows/reusable-security.yml@<sha-or-tag>
    secrets:
      GITGUARDIAN_API_KEY: ${{ secrets.GITGUARDIAN_API_KEY }}
  pr:
    if: github.event_name == 'pull_request'
    permissions: { contents: read, pull-requests: read }
    uses: AnshSinghal-CyberUltron/devsecshield/.github/workflows/reusable-pr-checks.yml@<sha-or-tag>
    with:
      flows: "main:release|hotfix/*"     # only `release` or a hotfix branch may open PRs into `main`
```

The composite action works from any repository too. It runs the scanner from its own copy of this repository and
scans `path` in the caller's workspace:

```yaml
      - uses: AnshSinghal-CyberUltron/devsecshield/.github/actions/cbom-scan@<sha-or-tag>
        with:
          path: .
```

Each workflow reads only the caller's checkout. Repo-specific files are used when present: `.gitleaks.toml`,
`.gitleaksignore`, `.semgrepignore`, `.trivyignore`, `.hadolint.yaml`, `.github/labeler.yml`. The workflows declare
no `outputs:` yet; results are in the job summaries and artifacts (#22). Notices that point to `docs/ci/README.md`
refer to this file.

### `workflow_call` interfaces

Every input of every reusable workflow is listed below. `ci-selftest` fails when one is missing from this file.

**reusable-python-tests.yml**

| Input | Default | Meaning |
|---|---|---|
| `deselect-file` | empty | Repository-relative file of pytest node ids to deselect (`# reason` per line), for tests that fail today for a tracked reason. Listed in the job summary. Keep it under `.github/`, so a change needs the `security-config-reviewed` label |
| `suite-name` | `python` | Job title and summary name |
| `working-directory` | `.` | Project directory |
| `python-version` | `3.12` | Sets `UV_PYTHON` (overrides `.python-version`) |
| `uv-version` | `0.13.6` | uv to install |
| `uv-cache` | `true` | Cache uv downloads in the Actions cache (off for multi-GB dependency sets) |
| `free-disk-space` | `false` | Delete the runner's preinstalled Android, .NET, GHC and CodeQL first (about 25 GB) |
| `lock-check` | `true` | `uv lock --check` |
| `install-command` | `uv sync --frozen` | Install |
| `lint-command` | empty | Blocking lint |
| `lint-diff-command` | empty | Linters whose `path:line[:col]: message` output is compared with the base commit, one command per line (PRs fail on new findings; exit codes other than 0/1 always fail) |
| `test-command` | `uv run --frozen pytest -q` | Tests |
| `env` | empty | Non-secret `KEY=VALUE` lines |
| `apt-packages` | empty | Ubuntu packages the tests need (backend: `poppler-utils` for `pdftotext`) |
| `setup-command` | empty | System setup before the install (backend: allow `nginx -t` to bind :80 as the runner user) |
| `postgres` | `false` | Start PostgreSQL |
| `postgres-image` | `postgres:15-alpine` | Image (ci.yml pins it by digest) |
| `postgres-databases` | `test` | Databases to create; each is exported as `PG_URL_<NAME>`, the first also as `DATABASE_URL` |
| `pg-url-scheme` | `postgresql+psycopg2` | Scheme of those URLs (SQLAlchemy + psycopg2; use `postgresql` for psycopg 3, asyncpg, Prisma, Django) |
| `fetch-depth` | `1` | Commits to fetch (the lint diff fetches its base commit itself) |
| `timeout-minutes` | `30` | |
| `runs-on` | `ubuntu-latest` | |
| `artifact-paths` | empty | Paths uploaded after the run |

| Secret | Meaning |
|---|---|
| `extra-env` | Optional secret `KEY=VALUE` lines (masked in logs) |

**reusable-frontend.yml**

| Input | Default |
|---|---|
| `suite-name` | `frontend` |
| `working-directory` | `frontend` |
| `node-version` | `20` |
| `install-command` | `npm ci --no-audit --no-fund` |
| `typecheck-command` | `npx tsc --noEmit` (empty skips) |
| `eslint-mode` | `diff` (PRs fail on new errors; a missing base fails; ESLint failing on the base gates the changed files), `blocking`, or `off` |
| `eslint-args` | `.` |
| `test-pattern` | `*.test.ts` |
| `test-runner` | `npx --yes tsx@4.23.15` |
| `build-command` | `npx next build` (empty skips) |
| `build-env` | `NEXT_TELEMETRY_DISABLED=1`, `NEXT_PUBLIC_BACKEND_URL=http://localhost:8000` (this repo's dev backend; override it) |
| `timeout-minutes` | `30` |
| `runs-on` | `ubuntu-latest` |

**reusable-security.yml**

| Input | Default |
|---|---|
| `mode` | `auto`: PRs and pushes use diff, everything else full |
| `exclude-regex` | `node_modules`, `.venv`, `venv`, `.next`, `dist` (not applied to gitleaks). `ci.yml` adds this repo's fixture roots, anchored (`^aibom/tests/fixtures/`, ...), so a future product directory named `fixtures` or `examples` is still scanned |
| `gitleaks-version`, `gitleaks-sha256` | `8.30.1`, pinned |
| `gitleaks-config`, `gitleaks-fail-full` | `.gitleaks.toml` (taken from the base commit in diff mode), `false` |
| `trusted-heads` | `dev staging`: promotion heads whose gitleaks files are trusted |
| `secret-fixture-label`, `secret-fixture-regex` | `secret-fixtures-reviewed`, `(^\|/)tests?/fixtures/` |
| `ggshield-version` | `1.56.1` |
| `semgrep-version`, `semgrep-configs` | `1.181.1`, `p/ci p/python p/typescript p/secrets p/dockerfile` |
| `semgrep-exclude` | `node_modules .venv` (`ci.yml` adds the fixture roots) |
| `semgrep-min-level`, `hadolint-min-level`, `shellcheck-severity` | `warning` |
| `osv-version`, `osv-sha256` | `2.7.0`, pinned |
| `trivy-version`, `trivy-sha256` | `0.76.1`, pinned |
| `trivy-scanners`, `trivy-severity` | `vuln,misconfig`, `HIGH,CRITICAL` (secrets are left to gitleaks) |
| `trivy-skip-dirs` | `**/node_modules,**/.venv` (`ci.yml` adds the fixture roots) |
| `checkov-version`, `checkov-frameworks` | `3.3.30`, `kubernetes terraform` |
| `helm-charts` | One chart per line, `<dir> [helm template args]`. Each is rendered for head and base and scanned as Kubernetes manifests. A chart that fails to render, input Checkov cannot process, or a rendered chart with zero evaluated checks fails the step. `ci.yml` passes `deploy/helm/cbom-scan-node` with CI placeholder values and the DaemonSet switched on |
| `hadolint-version`, `hadolint-sha256` | `2.15.1`, pinned |
| `shellcheck-version`, `shellcheck-sha256` | `0.11.0`, pinned |
| `actionlint-version`, `actionlint-sha256` | `1.7.12`, pinned |
| `uv-version` | `0.13.6` |
| `upload-sarif` | `false`. Set `true` only where code scanning exists, and grant `security-events: write` |

| Secret | Meaning |
|---|---|
| `GITGUARDIAN_API_KEY` | Optional. Without it, ggshield is skipped with a notice |

The caller grants `contents: read` and `pull-requests: read` (the fixture label).

**reusable-codeql.yml**: `enabled` (`true`), `languages` (`["python","javascript-typescript"]`), `queries`
(`security-extended`), `paths-ignore`, `upload` (`false`). The caller grants `contents: read`, `actions: read`, plus
`security-events: write` when `upload: true`.

**reusable-image-build.yml**: `images` (required; a JSON array of `{name, context, dockerfile, build-args?,
build-contexts?, free-disk-space?}`), `pre-build-command` (run once, in its own job, before the builds),
`trivy-version` / `trivy-sha256` (`0.76.1`, pinned), `trivy-severity` (`HIGH,CRITICAL`), `trivy-fail-on` (empty,
which means report only), `cache` (`true`), `cache-write` (`true`; `ci.yml` writes from `dev` only),
`free-disk-space` (`false` for all images; per image with `"free-disk-space": true`), `timeout-minutes` (`45`).
Builds use Buildx's `docker` driver; with `cache: true` the runner's Docker must use the containerd image store
(GitHub's Ubuntu runners do), and the job fails early with the reason if it does not.

**reusable-pr-checks.yml**: `flows` (`staging:dev main:staging|hotfix/*`), `title-regex`, `title-max-length` (100),
`require-acceptance-criteria` (`true`; bots are exempt), `acceptance-heading-regex`, `forbidden-files-regex`,
`allowed-files-regex` (`*.pub`, `.env.example` / `.sample` / `.template` / `.dist`), `secret-fixture-label`,
`secret-fixture-regex`, `security-config-regex`, `security-config-label`, `suppression-regex`
(`nosemgrep|checkov:skip|hadolint ignore|shellcheck disable|trivy:ignore`). The caller grants `contents: read` and
`pull-requests: write` (the review-labels job removes outdated labels; it checks out nothing).

**pr-labels.yml**: `configuration-path` (`.github/labeler.yml`), `size-thresholds` (`10 50 250 1000`). The caller
grants `pull-requests: write`.

## Secrets, variables, labels and apps

| Name | Kind | Needed by | Without it |
|---|---|---|---|
| `GITGUARDIAN_API_KEY` | repository secret | security / ggshield | Step skipped with a notice |
| `CODEQL_ENABLED` | repository variable (`true`) | codeql | CodeQL job skipped (see [Known limits](#known-limits)) |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | repository secrets | aibom-nightly (Bedrock) | Weekly benchmark cannot call Bedrock |
| `STAGING_SSH_KEY`, `STAGING_SSH_KNOWN_HOSTS`, `STAGING_SSH_TARGET`; `STAGING_DIR` | `staging` environment secrets / variable | deploy-staging | Deploy step unavailable (the build still works). Give the environment deployment-branch rules (`staging` only) |
| `security-config-reviewed` | PR label | pr-hygiene | A PR that changes CI or scanner configs fails |
| `secret-fixtures-reviewed` | PR label | gitleaks, pr-hygiene | Fabricated secrets and key files under `tests/fixtures/` fail |

No other workflow needs a secret. CI tests use dummy values that are marked as such.

### CodeRabbit (AI code review)

`.coderabbit.yaml` is committed (validated against CodeRabbit's schema v2). It uses the `chill` profile, reviews
feature PRs into `dev` only (promotions carry already-reviewed changes), skips Dependabot, uses the team's severity
tags, adds security-risk instructions specific to DevSecShield and per-path instructions, and enables only the tools
CI does not already run (zizmor, yamllint, markdownlint). **It does nothing until the CodeRabbit GitHub App is
installed:**

1. **Rotate the leaked credentials first** (debt table): the app gets read access to a tree that still holds them.
2. Sign in at <https://app.coderabbit.ai> with the GitHub account that owns this repository.
3. Choose *Add repositories* (or GitHub → Settings → Applications → CodeRabbit → Configure) and grant access to
   `devsecshield` only.
4. Open or update a PR. CodeRabbit posts a walkthrough and line comments. It only comments; the required check
   stays `ci-gate`.

The free tier covers open-source repositories. A private repository needs a paid seat for the PR author.

### GitGuardian (secret detection, second engine)

1. Create an account at <https://dashboard.gitguardian.com> (the free plan covers small teams).
2. *API → Personal access tokens* (or *Service accounts*): create a token with the `scan` scope.
3. GitHub → this repository → *Settings → Secrets and variables → Actions → New repository secret*: name
   `GITGUARDIAN_API_KEY`, value the token.
4. The next PR runs `ggshield secret scan ci` on the PR's commits, which blocks on any secret.

Optionally, also install the GitGuardian GitHub App for real-time alerts on every push to every branch (after the
credentials are rotated).

## Branch protection (release manager)

**This needs GitHub Pro (user-owned repository) or GitHub Team (organisation) on a private repository.** Today the
rulesets API answers "Upgrade to GitHub Pro or make this repository public", and `dev`, `staging` and `main` report
`"protected": false`. Until protection is on, nothing stops a direct push or the merge of a PR with a red `ci-gate`,
and the secret gate does not trust promotion heads (see [The secret gate](#the-secret-gate)).

Settings → Branches (or Rules → Rulesets), for each of `dev`, `staging` and `main`:

| Setting | Value |
|---|---|
| Require a pull request before merging | on (required approvals: 0 while one account authors and reviews) |
| Require status checks to pass | on, with the one check `ci-gate` (exact name) |
| Require branches to be up to date before merging | on for `staging` and `main` (pushes there do not re-run the suites) |
| Do not allow bypassing the above settings | **on**: the one shared account is the owner, so without it the rules bind nobody |
| Allow force pushes | off |
| Allow deletions | off |

`ci-gate` already depends on every other job, including `pr-checks / branch-flow`, `pr-checks / review labels` and
`pr-checks / pr-hygiene` on PRs. Requiring the individual jobs as well would break: path filtering skips them on
many PRs, and a skipped required check blocks the merge. Do **not** turn on *Require review from Code Owners* while
all authors and reviewers post through one account (see `.github/CODEOWNERS`). Once `dev` and `staging` are
protected, the secret gate trusts them as promotion heads automatically (it reads the API's `protected` flag).

**Merge queue (optional).** In the same ruleset, *Require merge queue* tests each PR merged onto the latest base
before it lands, so two PRs that pass alone cannot break `dev` together. `ci.yml` already runs on `merge_group` and
`ci-gate` reports there; keep `ci-gate` as the one required check. Make `dev` the default branch first: a queue run
can restore Actions caches only from its own ref and the default branch, so with `main` as default it builds
images without the layer cache written from `dev`. That is inferred from GitHub's caching docs; check the first
queue run for `CACHED` steps (#71). Keep *Maximum pull requests to build* small: invalidated queue runs are not
cancelled.

**Until #70 lands, a queue commit is not security-gated.** On `merge_group` the security jobs run in report mode,
and the suites' lint-diff steps report without blocking (see [Known limits](#known-limits)). A new finding that exists only in the
merged tree therefore passes the queue, and the push run reports it only after the merge. The merged tree differs
from the tree the PR's own run gated when:
- the base moved after the PR's last run, or PRs ahead in the queue add commits;
- the base changed the Semgrep, Checkov or gitleaks rules or configuration;
- the OSV or Trivy advisory data changed.

So keep *Require branches to be up to date* on `staging` and `main` even with a queue: it makes the PR run's
diff-mode security run on the exact tree that lands. On `dev`, the push run after each merge reports such findings.

**Make `dev` the default branch** (Settings → General). Schedules run only from the default branch, so today
`security-scheduled.yml` and the weekly benchmarks would run July code from `main`. Dependabot security updates also
always target the default branch. Promotions to `main` are unaffected.

## Audit of the workflows this replaced

The table records the state at `dev` 8314739, checked against 579 runs from the Actions API and their job logs.

| Workflow | Before | Root cause | Decision |
|---|---|---|---|
| `aibom-gates.yml` | green on `ansh` | Branch filter main/develop/module_1/ansh, so it never ran on `dev` | Folded into `ci.yml` → `aibom` |
| `cbom-gates.yml` | red, 59/59 | Gate C ruff: 1,640 E501 (pyproject line-length 88, code written to about 120) and 17 other findings. Gate D would also have failed (see below) | Folded into `aibom`; ruff and mypy now block only new findings |
| `cbom-deliverables.yml` | startup failure, 72/72 | Path filter `frontend/app/[[]team_id]/...` is not a valid glob, so no job ever ran | Folded into `backend` and `frontend` |
| `cbom-posture-gates.yml` | startup failure, 71/71 | Same invalid glob | Folded into `aibom` and `backend` |
| `cbom-code-scan.yml` | red | The composite action ran `uv` without installing it. Every scan exited 127, so "vulnerable tree is blocked" passed for the wrong reason | Action fixed (installs uv, exposes `exit-code`, portable); folded into `cbom-action`, which asserts exit code 1 |
| `pdf-smoke.yml` | green | Subset of the backend suite | Folded into `backend` |
| `aibom-nightly.yml` | red or cancelled (runs from `main`) | Genuine benchmark result: 34 true misses; 8 of the last 10 nights hit the 90-minute timeout (about 2,600 minutes a month) | Kept, now **weekly**, actions pinned. Product follow-up |
| `cbom-nightly.yml` | red (runs from `main`) | Genuine result: 3 true misses on mitmproxy (`ecdsa-sha384` and two certificates) | Kept, now **weekly**, actions pinned. Product follow-up |
| `deploy-staging.yml` | manual, never run | n/a | Kept, actions pinned, no persisted checkout credentials |
| `scan-node-image.yml` | manual | n/a | Kept, actions pinned, no persisted checkout credentials |
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
With the current checkout they fail the checkout itself (git exit 128): that was the first CI run on this PR,
42984085692. They are removed from the index, and `.worktrees/` is now ignored. The bench directories were already
ignored, and the bench scripts clone on demand.

They also hid a gate failure. A checkout had the bench gitlinks as empty directories, so `bench/cbom/ci_repos.sh`
took "directory exists" to mean "already cloned", scanned an empty directory, and reported 6 + 1 true misses on
pyjwt and pyopenssl. It now clones when the directory is missing or empty. After the fix, both repositories pass
with 0 true misses. `bench/ci_repos.sh` got the same guard.

## Current debt the pipelines report

Measured on `dev` 8314739. These findings do not block a PR (only new ones do), but they are real.

| Area | Count | Notes |
|---|---:|---|
| **Secrets** (gitleaks) | 829 in the history of all branches (396 fingerprints, baselined in `.gitleaksignore`); 81 in today's tree across 42 tracked files | 12 of the tracked files are `.env` files. The secrets include OpenAI, AWS, GitHub classic and fine-grained PATs, Atlassian, Azure AD and GCP keys, and `cu-devsecshield-key.pem` at the root. Main places: `backend/.env`, `backend/utilities/ai/` (`.env`, `llm.py`, `chatbot.py`, `testing.py`), `RabbitMQ/.env`, `RabbitMQ/{worker,dast_worker,guardrail_worker}/.env`, `RabbitMQ/worker/helpers/context/.env`, `RabbitMQ/worker/helpers/tests/*`, `RabbitMQ/worker/celery_test.py`, `RabbitMQ/worker/Dockerfile`, `RabbitMQ/dast_worker/Dockerfile`, `RabbitMQ/guardrail_worker/ticketing/jira.py`, `docs/Docs.md`, `.playwright-mcp/scan367_api.json`, `backend/*.db`. **Rotate every credential first.** Then remove the files (#18), and decide whether to rewrite history. |
| Dependency vulnerabilities (OSV-Scanner) | 1,547 | Distinct (advisory, lockfile, package) findings across 12 lockfiles, benchmark fixtures excluded. OSV-Scanner writes many results twice; the gate counts each once (it reported 2,608 before) |
| ESLint errors (frontend) | 208 | 113 `no-explicit-any`, 77 react-hooks |
| ruff (aibom `src` + `tests`) | about 2,690 | Mostly E501 at 88 columns. Either set line-length to 120 or reformat |
| mypy (aibom CBOM lane) | 68 | |
| ruff defaults (backend) | 547 | |
| ShellCheck (warning and above) | 4,186 | |
| Hadolint (warning and above) | 14 | |

The secret values were never printed or stored. Every scan above ran with `--redact`, and the reports list only
the file and the rule.

## Running the checks locally

```bash
# workflows, and the CI self-tests
pipx run actionlint-py==1.7.12.25                                 # or: uvx --from actionlint-py actionlint
python3 -m unittest discover -s .github/tests -v
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
  enabled". The `codeql` job is therefore skipped, and every SARIF report is kept as a workflow artifact (14 days).
  Semgrep provides SAST in the meantime. To enable CodeQL, move the repository to an organisation with GitHub Code
  Security, then set the variable `CODEQL_ENABLED=true` and, if wanted, `upload-sarif: true`. Making it public is
  **not** an option until the credentials are rotated and the history is purged.
- **Schedules run from the default branch only.** Make `dev` the default branch (see Branch protection).
- **Dependabot and `ARG`-based base images.** Dependabot's docker updater rewrites `FROM image:tag` lines. The
  backend and worker Dockerfiles take their base image from an `ARG` default, so those bumps may need a manual
  edit.
- **The images job builds without pushing.** Publishing images stays with `deploy-staging.yml` and
  `scan-node-image.yml`.
- **Image Trivy scans are report-only** (`trivy-fail-on` is empty). The base images are pinned by tag, not digest,
  so they gain CVEs every day whatever the PR changes, and a gate there would be noise. The plan is to pin the base
  images by digest first, then gate on new image CVEs (tracked as a follow-up). Dependency CVEs are already gated:
  OSV-Scanner and Trivy fs block new ones in the lockfiles.
- **Checkov** renders Helm charts into `ci-rendered-charts/` (not a dot directory: Checkov skips those) and fails
  when a rendered chart produced no evaluated check.
- **Merge-queue runs scan security in report mode.** The secret and scanner gates compare with a base commit taken
  from the pull request or push event; a `merge_group` event has neither, so they scan in full mode and report
  without blocking. The suites' lint-diff steps run in report mode only too, as on a push. The PR's own run already gated
  its diff, but a finding that exists only in the merged tree passes the queue (see Branch protection). Gating the
  queue commit against `merge_group.base_sha` is #70.
- **The pull-request files API lists at most 3,000 files**, so pr-hygiene does not see files beyond that in a huge
  PR. gitleaks still scans those commits.
