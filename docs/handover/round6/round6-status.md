# Round 6 — enterprise scale: status (2026-11-11)

Plan doc (Claude Docs): https://claude.ai/artifact/Y24pBT85c29VD1Nr9hXHNZ. It covers the market, how to reach thousands of targets, the roadmap, the Feature 1 spec, and decisions.

## Branches (GitHub AnshSinghal-CyberUltron/devsecshield)
- **`dev`** is the integration branch, now at 3399452 (merge of PR #16). Feature PRs target it.
- **`staging`** is at fdf9bb4, promoted from dev through PR #26.
- **`main`** is old (July). The first `staging` → `main` promotion is blocked by design until #18 (tracked .env files) is done and `main` carries the secret baseline.
- **`ansh`** is legacy.
- **Who merges:** agents review and merge; the owner does not merge.
- **Branch protection is not possible on the current plan** (user-owned private repo on GitHub Free). The rulesets API answers "Upgrade to GitHub Pro". Until then, the gates are process: every change goes through a PR, and the release manager merges only after confirming `ci-gate` is green on the head.

## Feature 0: CI/CD pipelines. DONE (PR #16 → dev, PR #26 → staging)
- **Reusable workflows** (`on: workflow_call`):
  - Python tests;
  - frontend (tsc, ESLint, unit tests, next build);
  - security: gitleaks/ggshield, Semgrep, OSV, Trivy, Checkov, Hadolint, ShellCheck, actionlint;
  - CodeQL;
  - image build with Trivy;
  - PR checks: branch flow, hygiene, review labels.
- **`ci-gate`:** the one required check.
- **Scanners fail only on findings the change adds.** The base is scanned too. Findings are matched ignoring paths, line numbers, renames, ruff lengths and OSV versions. A scanner that cannot run fails.
- **Secret gate:** the config and ignore file come from the base. A head is trusted only when its branch is protected. Inline allow comments are ignored, and merge commits are scanned. The baseline has 396 commit-pinned fingerprints and no values.
- **Path filters:** worked out from what each suite's tests read. The worker and dast-worker suites now run (81 + 59 tests).
- **CI and security config changes need a security reviewer's label.** This covers workflows, scanner configs, inline suppressions and deletions. The label is removed when later commits touch those files.
- **Proof:**
  - the canary PR #23 caught one planted ruff error, one ESLint error, a vulnerable jinja2, and two fake tokens (one with `gitleaks:allow`). Each was reported once and nothing else was reported.
  - 76 self-tests in CI.
- **Reviews:** security, QA and architecture, plus two security re-reviews: 57 threads, all resolved. Deferred items are #19–#22, #24 and #25.
- **Run time:** about 6 minutes per PR (backend is the longest job). Nightly benchmarks now run weekly.

## Earlier gap fixes (on dev/staging)
- Cancel a running scan with a refund (C1).
- DAST egress pinning (D1).
- Invitations without passwords (S2).
- Fresh-customer fixes and the Account page (X1/P1).
- Sources counted as results (M1x).
- nginx WebSocket upgrade.
- The R2 browser regression: 22 pass, 0 fail, 1 blocked.

## Next
1. **First real PR through the pipeline:** the R2 bugs #12–#15, then #17. #17 is a scope bug: never-scan is applied per address, so a host excluded by IPv4 is still scanned over IPv6.
2. **Feature 1, fleet onboarding,** in four parts:
   - lean node API;
   - inventory and tag policies (AWS discovery through the read-only scanner role);
   - agentless transports through the customer's tools (Ansible AWX, AWS SSM, Salt via salt-api) plus `zs-collect`;
   - SSH CA.
3. **Feature 2:** (i) info tooltips. **Feature 3:** repos at scale. **Feature 4:** SSO/SCIM/RBAC.

## Owner actions outstanding
- **Default branch:** make `dev` the default (Settings → General). The proxy refuses repo-settings writes. Until then, schedules run July code from `main`.
- **Branch protection:** upgrade to GitHub Pro, or move the repo to an organisation on Team. Then enable on dev, staging and main: require a PR, require `ci-gate`, do not allow bypassing, no force pushes, no deletions. Land #25 item 1 before turning it on.
- **Delete branch `canary/ci-gates`** (fake tokens only). The proxy refuses branch deletion.
- **Rotate:**
  - the pasted AWS access key and console password;
  - the live secrets in tracked `.env` files and in git history. The CI scan counts 81 in the tree and 328 in history.
- **AWS:**
  - attach the proposed SSM policy (in the session scratchpad, round6/aws);
  - delete the old-lab stack `u1-zs-cbom-reader` and the 5 secrets named `zscbom/*`.
- **CI:**
  - install the CodeRabbit app;
  - optionally add `GITGUARDIAN_API_KEY`;
  - add deployment-branch rules to the staging environment.
- **Sandbox disk:** clearing the 6 GB uv cache was refused by the permission check. Owner's call.
