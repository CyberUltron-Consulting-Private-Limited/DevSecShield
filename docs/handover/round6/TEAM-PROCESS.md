# DevSecShield engineering process (round 6) — every agent reads this first

The owner wants us to work like a professional engineering org: specs with acceptance criteria, feature branches,
pull requests, independent reviewers who comment, QA as a customer, and promotion dev -> staging -> main. Agents
review AND merge (the owner does not merge). Plan doc (the source of truth for scope and acceptance criteria):
https://claude.ai/artifact/Y24pBT85c29VD1Nr9hXHNZ (Feature 1 spec, Decisions). Research:
$R6/research/enterprise-scale.md (R6=/tmp/claude-0/-home-claude/976896a4-2e24-5405-8100-31f07ced9160/scratchpad/round6).

## Repository and branches
* GitHub: AnshSinghal-CyberUltron/devsecshield (private). Default branch `main` (old, July). `dev` = integration
  (cut from `ansh` at b59869f + 8314739). `staging` is cut from `dev` after QA sign-off. `ansh` is legacy; do not
  target it any more.
* Feature work: `feature/<short-name>` from `dev`; one PR per reviewable unit into `dev`.
* Promotion PRs: `dev` -> `staging`, `staging` -> `main` (release manager only).
* Local clone: /home/claude/devsecshield. Agents work in their own git worktree (isolation) and push their branch.

## GitHub access (important)
* `gh` works for REST only. GraphQL is blocked: `gh pr create`, `gh pr view` etc. FAIL. Use `gh api`:
  - create PR: `gh api repos/AnshSinghal-CyberUltron/devsecshield/pulls -f title=... -f head=feature/x -f base=dev -F body=@file.md`
  - review with comments: `gh api repos/.../pulls/<n>/reviews --input review.json` where review.json =
    {"commit_id":"<head sha>","event":"COMMENT","body":"...","comments":[{"path":"a/b.py","line":42,"side":"RIGHT","body":"..."}]}
    (event APPROVE/REQUEST_CHANGES is not possible on our own PRs: everyone posts under the same account; use
    COMMENT and start the body with your role, e.g. "**Security review (agent)** — verdict: changes needed").
  - reply to a review comment: `gh api repos/.../pulls/<n>/comments/<comment_id>/replies -f body=...`
  - resolve threads: `gh api -X POST repos/.../pulls/<n>/ccr/comments/<comment_id>/resolve`; list threads:
    `gh api repos/.../pulls/<n>/ccr/review_threads`
  - CI status: `gh api repos/.../commits/<sha>/check-runs` and `gh api "repos/.../actions/runs?branch=<b>"`;
    job logs: `gh api repos/.../actions/jobs/<id>/logs`
  - merge: `gh api -X PUT repos/.../pulls/<n>/merge -f merge_method=merge` (release manager only)
* Never write a bare `@name` in PR text or comments (GitHub notifies real users); put such text in backticks.
* PR bodies end with:
  🤖 Generated with [Claude Code](https://claude.com/claude-code)

  https://claude.ai/code/session_01SDCVQSqoacevwbyX9VGquR
* Commits: explicit pathspecs, never `git add -A`, no stash, no `--no-verify`, no force-push to shared branches;
  every message ends with
      Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
      Claude-Session: https://claude.ai/code/session_01SDCVQSqoacevwbyX9VGquR

## Branch protection is NOT available (verified Nov 11)
The repo is user-owned, private, on GitHub Free: `branches/<b>.protected` is false for dev/staging/main and the rulesets
API answers "Upgrade to GitHub Pro". Nothing technically stops a direct push or a merge with red checks. Until the
owner upgrades (GitHub Pro, or an organisation on Team), the gate is PROCESS: nobody pushes directly to dev/staging/main;
every change lands through a PR; the release manager merges only with `ci-gate` green on the current head, checks it
via the API right before merging, and records the run link in the merge commit message.

## Roles
* Builder (feature lead): spec -> tests first -> code -> PR with "Acceptance criteria -> evidence" table and scale
  numbers. Addresses every review comment (fix, or reply with evidence) and resolves the thread.
* Reviewers (independent, fresh context, each one PR review with line comments): Architecture/Platform,
  Security, QA/Test, and for UI work UX. Severity in each comment: [blocker] [major] [minor] [nit].
* QA (customer behaviour): browser-only testing on a stack built from the branch; signs off with evidence.
* Release manager: merges only when (1) required CI checks are green, (2) no unresolved [blocker]/[major] thread,
  (3) acceptance-criteria table complete with evidence, (4) QA sign-off for user-facing changes. Then promotion PRs.

## Hard rules
* Read CLAUDE.md. Evidence over assumption. Root cause fixes.
* Secrets: never read .env, *.pem or key files; never print secrets. AWS test credentials are in
  $R6/secrets/aws-dev.env (0600; source it, never echo it). The AWS account also runs PRODUCTION servers: touch
  only resources you created, tagged zs-lab=sandbox, inside vpc-0b4f6fef4233d8a43 (devsecshield-sandbox-vpc).
  Never run commands on, change, or stop any other instance or resource. Read-only scans of the account go through
  DevSecShieldScannerReadOnlyRole; never enable the Lambda/Glue decrypt opt-ins against this account.
* Shared machine: 2 CPUs, 7 GB RAM, ~11 GB free disk. One browser at a time; keep >= 3 GB disk free; do not
  prune or stop Docker resources you did not create; dockerd is owned by the integrator.
* The container restarts sometimes: commit and push often; keep $R6/<your-name>/progress.txt (one line per step).
* GitHub Actions minutes cost money on a private repo: use path filters, `concurrency: cancel-in-progress`, and do
  not re-run workflows in loops.

## AWS sandbox guardrails (owner, Nov 11) — these override anything above
* EVERY resource you create (EC2, volumes, RDS, EKS, KMS keys, S3, security groups, secrets, ACM certs) MUST carry
  the tag `Project=DevSecShield` (IAM rejects creation without it). Also add `zs-lab=sandbox` and `zs-owner=<agent>`.
* Network: EC2, EKS nodes and RDS only in the sandbox private subnets (app: subnet-0a933715183eeedc8,
  subnet-0dd252df2cad964fe; db subnet group devsecshield-rds-subnet-group); security groups sg-0c617f55ec5ff0bbd
  (internal) / sg-0640198d7e52a6b61 (remote access). Instance profile devsecshield-ec2-instance-profile; EKS roles
  devsecshield-eks-cluster-role / devsecshield-eks-node-role. The VPC has a NAT gateway.
* Names: S3 buckets start `devsecshield-`; Secrets Manager canaries start `devsecshield-`.
* Budget: $50/month for the whole sandbox with alerts at 80%/100%. Use the smallest sizes (t3.micro/t4g.small,
  db.t4g.micro), stop or terminate everything when a test ends, EKS only for the hours a test needs, never leave
  anything running overnight. Record every resource you create in $R6/aws/ledger.txt (id, type, created, owner)
  and delete it when done.
* Permissions: EC2 launch works with the Project tag; KMS/ACM/Secrets (prefix) and eksctl are allowed. SSM
  (SendCommand/DescribeInstanceInformation) is NOT allowed yet — the owner has a proposed policy at
  $R6/aws/devsecshield-developer-sandbox-policy.json.

## AWS sandbox guardrails (from the owner, Nov 11) — IAM enforces these
* Every resource you create (EC2, volumes, RDS, EKS, KMS, S3, security groups, secrets) MUST carry the tag
  Project=DevSecShield (creation is refused without it). Also add zs-lab=sandbox so we can find our test resources.
* Launch only into the sandbox subnets: app subnet-0a933715183eeedc8 / subnet-0dd252df2cad964fe; RDS via subnet group
  devsecshield-rds-subnet-group; SGs sg-0c617f55ec5ff0bbd (internal), sg-0640198d7e52a6b61 (remote access).
  Instance profile devsecshield-ec2-instance-profile (role devsecshield-ec2-test-role). Verified Nov 11: the private subnets reach the internet through NAT gateway nat-08c2305b3e2e6feb1 (public subnets use igw-060f88ec01ca34a5d). There are no VPC endpoints, so SSM agents use the NAT.
* S3 buckets must start with `devsecshield-`; Secrets Manager names must start with `devsecshield-`.
* Budget: USD 50/month for the whole sandbox. EKS costs ~USD 0.10/h for the control plane alone: create a cluster
  only for a test window and delete it the same day; stop or terminate EC2/RDS when a test ends; prefer t3.micro /
  t4g and db.t3.micro. Record every resource you create (id, type, time) in $R6/aws/ledger.txt and delete it before
  you finish (or state why it must stay).
* Permitted today: EC2 launch with the tag, KMS keys, ACM import/request, Secrets Manager (prefix), eksctl's
  CloudFormation/AutoScaling/launch templates, read of the account, assume DevSecShieldScannerReadOnlyRole.
  NOT permitted today: Systems Manager (SSM) — the SSM transport cannot be proven live until the owner adds it.

## Re-running CI on a labelled PR
After a reviewer adds `security-config-reviewed`, re-run with `POST .../actions/runs/<id>/rerun-failed-jobs` only.
"Re-run all jobs" replays `pr-checks / review labels` for the original push and removes the label again.
Review-label caveats (force push to an older head, reopen, cancelled run, labeler race) are tracked in #25.

## Parallel tracks: shared-machine rules (from Nov 11, many agents at once)
The machine has 2 CPUs, 7 GB RAM and only a few GB of free disk, so heavy local work is serialised with `flock`.
L=/tmp/claude-0/-home-claude/976896a4-2e24-5405-8100-31f07ced9160/scratchpad/round6/locks
* **Full backend pytest** (or any suite over ~2 min): `flock $L/heavy-tests.lock <command>`. Prefer targeted tests
  locally (`pytest tests/test_x.py -q`) and leave full suites to CI, which runs them on GitHub runners.
* **Docker builds and the local stack** (rebuild, browser QA): `flock $L/stack.lock ...` for the whole QA session.
  Only one stack runs at a time (RAM). Rebuild from your branch, test, and when you finish leave the stack running on
  the latest `dev` or tell the coordinator. dockerd is owned by the coordinator; if `docker info` fails, ask the coordinator.
* **Frontend node_modules:** never `npm ci` in a worktree. Symlink the shared install:
  `ln -s /home/claude/devsecshield/frontend/node_modules frontend/node_modules` (dev's package-lock matches it).
  If your PR changes package.json, ask the coordinator first.
* **Python venvs:** use uv's default link mode (hardlink; never `UV_LINK_MODE=symlink`, the coordinator clears the uv cache when disk is low). Do not create torch/garak (scan worker) venvs locally.
* **Disk:** check `df -h /` before anything big. Stop and tell the coordinator if free space is under 1.5 GB.
  Delete your build outputs (.next, dist, coverage, downloaded tools) when you finish.
* **Alembic migrations:** several PRs may add migrations. Before your PR is merged, merge the latest `dev` into your
  branch and re-chain your migration's `down_revision` to dev's current head. `alembic heads` must show exactly ONE head.
  The release manager checks this.
* **Shared files** (backend/routes/__init__ or app router registration, frontend sidebar/nav, shared types): keep
  your changes small and additive to make merges easy. Resolve conflicts with merge commits only, never by rebasing
  a pushed branch.
* **AWS:** source the credentials only from $R6/secrets/aws-dev.env (`env -u AWS_SESSION_TOKEN`). Tag every resource
  `Project=DevSecShield`, `zs-lab=sandbox`, `zs-owner=<track>`. Append every resource you create to $R6/aws/ledger.txt
  using `flock $L/aws-ledger.lock`, and delete it the same day. Use the smallest sizes. EKS only with the coordinator's OK.
  If `aws` is not installed, install it with `pip install --break-system-packages awscli` (inside `flock $L/install.lock`).

## AWS update (Nov 11, about 11:30): SSM is now permitted
The owner attached the SSM policy. `ssm:DescribeInstanceInformation` works. SendCommand is allowed ONLY for documents
named `devsecshield-*` and ONLY on instances tagged `Project=DevSecShield`. Other SSM-managed instances in this account
are PRODUCTION: never target them; always pass explicit `--instance-ids` of instances you created. CloudFormation
DeleteStack on the old `u1-zs-cbom-reader` stack is still refused (left for the owner).

## Docker locks, refined (Nov 11, 11:40)
* `stack.lock` covers ONLY the shared dss-staging stack: rebuilding or recreating its containers, and browser QA against it.
  Hold it for one QA session and release it as soon as you are done. Never hold it waiting for something else.
* Other docker work does NOT take stack.lock: building your own images, small test containers (sshd, salt, keycloak,
  postgres for a bench). It uses `flock $L/docker-build.lock` for image builds only, and before starting containers checks
  `free -m`. Keep available memory above 1.5 GB; if it would drop below, stop and ask the coordinator. Name your containers
  `<track>-...` and remove them when done.
* Large environments (AWX, hundreds of targets) run on a sandbox EC2 with the coordinator's OK, not locally.

## Container restart (Nov 11, ~12:14 UTC) and CI blocked by GitHub billing
* The container restarted. Every background process died: local PG servers under /var/tmp/zs-*, `next dev` servers,
  Playwright servers, benches, pollers. The coordinator restarted dockerd (12:18) and re-added /etc/hosts
  (`127.0.0.1 devsec.dss.test api.dss.test devsec2.dss.test api2.dss.test`). The dss-staging stack is up again (UI/API 200).
  Containers f1-4-bench-pg and f1test-pg exited: start them again if you own them. Disk: ~7 GB free after cache clears.
* Relaunched builders work in their EXISTING worktree (path given in the brief). First run `git status` and
  `git log --oneline -5`, read your $R6/<track>/progress.txt, and continue from the last step. Do not redo committed work.
  Uncommitted files in the worktree are your own earlier work: review them, keep what is right.
* **GitHub Actions is not running jobs**: since ~12:13 UTC jobs fail with "The job was not started because recent account
  payments have failed or your spending limit needs to be increased". This is an owner billing action. Until it is fixed:
  - Do not merge anything (ci-gate cannot pass). Reviews, QA and building continue as normal.
  - Before you push, run the local equivalent of the CI jobs your diff touches and keep the logs under $R6/<track>/:
    backend: `ruff` diff vs base + targeted pytest (heavy runs under heavy-tests.lock); frontend: `tsc --noEmit`, eslint
    on changed files, vitest; semgrep diff on changed files with the repo config (`--disable-nosem`); gitleaks if available.
    Put "CI blocked by GitHub billing; local gate evidence: <paths>" in the PR body until CI runs.
  - Push in coherent batches, not after every small edit: each full CI run costs ~30 runner-minutes once billing returns.
