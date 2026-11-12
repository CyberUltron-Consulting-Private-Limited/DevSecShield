# DevSecShield — coordinator session memory (rounds 1–6, as of 2026-11-12)

This is the working memory of the coordinator session that ran rounds 1–6. It is for the next session, which starts in a fresh container on the new repo. Read it together with:
- `claude/round6-handover.md` (Project doc): PR-by-PR state and the ordered next steps;
- the notes branch `handover/round6-notes`, folder `docs/handover/`:
  - `round6/`: process, plan, contract, specs, logs, bench results;
  - `earlier-rounds/`: CBOM rounds 3–5 plans, scan-node design, test catalogues, local-stack guide;
  - this file.

Secrets are deliberately absent. The owner gives AWS credentials to the new session directly. Never write them into a file, doc, PR, issue or commit.

---

## 1. The product and the repo
- **DevSecShield** is ZeroShield's ASPM platform. Products in the UI: SAST, SCA + SBOM, IaC, DAST, AI BOM, MCP scan, LLM scan, and CBOM (cryptography bill of materials), with CBOM Sources (servers, network, cloud, Kubernetes, databases, appliances, Windows/AD CS, HSM/KMIP, scan nodes).
- **Repo:**
  - `CyberUltron-Consulting-Private-Limited/DevSecShield`, private, on GitHub Enterprise since Nov 12;
  - transferred from `AnshSinghal-CyberUltron/devsecshield`, whose old URL is only a redirect;
  - **never delete "the old repo"**: it is the same repository.
- **Code map:**
  - `backend/` (FastAPI: `routers/`, `utilities/`, `new_models.py`, `access_models.py`);
  - `frontend/` (Next.js app router: `app/[team_id]/...`, `components/`, `content/infotips.ts`);
  - `scan_worker`, `cicd` worker, `dast-worker` + `dast-scheduler`, `cbom-cloud-worker`;
  - `scan_node/` (`zs_scan_node`, the on-prem collector agent: collectors for linux_ssh, windows_winrm, kubernetes, database, network, appliance, ca, kmip, container_images and others; `netutil.py` has the never-scan guard);
  - `prod_database_migrations/migrations/versions` (alembic; keep exactly ONE head);
  - `bench/`, `e2e/`, `.github/workflows/` (CI from Feature 0).
- **Runtime:** Postgres, Mongo, RabbitMQ, MinIO, nginx (TLS). Local compose project `dss-staging` serves https://devsec.dss.test (UI) and https://api.dss.test (API). See `earlier-rounds/round5/local/STACK.md`.
- **Branches:**
  - `dev` (integration, 3399452);
  - `staging` (fdf9bb4);
  - `main` (old, July; promotion waits for #18, the tracked `.env` files, and the secret baseline);
  - `ansh` (legacy).
  - The default branch should become `dev`.

## 2. What the owner asked for (standing)
- **Nov 11 enterprise request.** Scale DevSecShield to enterprises: thousands of servers, clusters, repos and databases, scanned without connecting each one by hand.
  - Be brutally honest about the approach; Salt minions were only the owner's guess.
  - Add access management.
  - Add small (i) info buttons everywhere: hover, focus or tap shows what the thing is, plus a concrete example.
  - Build incrementally, test end to end, and meet exit/acceptance criteria and scaling proof before calling a feature done.
  - Work like a team of specialised CTOs: dev → staging → main, PRs, reviewer agents leaving comments, full QA as a customer.
- **Feature order:**
  1. R2 bugs #12–#15, then #17 (never-scan per address: a host excluded by IPv4 was still scanned over IPv6).
  2. Feature 1, fleet onboarding:
     - lean node API;
     - inventory and tag policies (AWS discovery through `DevSecShieldScannerReadOnlyRole`);
     - agentless transports through the customer's own tools (Ansible AWX/AAP, AWS SSM, Salt via salt-api) plus `zs-collect`;
     - SSH CA.
  3. Feature 2: (i) tooltips. Feature 3: repos at scale. Feature 4: SSO/SCIM/RBAC.
- **"Ship all features in parallel with many specialised agents, but never skip a step"** (spec, tests first, review, QA, evidence, exit criteria, scaling, live tests). Use maximum usage.

## 3. Owner decisions (with dates)
- Nov 11: agentless through the customer's tools (AWX, SSM, Salt via salt-api) rather than our own resident agent.
- Nov 11: typed credentials.
- Nov 11: credits are charged per run.
- Nov 11: SSO/SCIM/RBAC come after the fleet work.
- Nov 11: fully autonomous; "everything else is your call".
- Nov 11: clear caches whenever needed without asking.
- Nov 11: the SSM policy is attached in AWS.
- Nov 11: agents review and merge; the owner does not merge.
- Nov 12: GitHub Enterprise. Use its benefits: rulesets, environments, CODEOWNERS, merge queue, Copilot code review, 50k Actions minutes.
- Nov 12, approvals:
  - **checks-only gate**: rulesets require a PR, `ci-gate` and resolved threads, with 0 required approvals (all agents post as one GitHub account);
  - **independent reviewer subagents must review every PR before merge**: security, code/QA and architecture, plus UX/browser QA for UI.
- Nov 12, Advanced Security: "try once, I think yes". Enable secret scanning, push protection, CodeQL default setup and dependency review once; if not licensed, keep our CI scanners.
- Earlier rounds (see the Project docs `cbom-round4-results.md` and `cbom-round5-status.md`): CBOM without an LLM, an offline knowledge base, an air-gap edition, the scan-node design with 5 reviews plus a devil's-advocate pass (`earlier-rounds/scan-node-contract.md`).

## 4. The engineering process (summary of `round6/TEAM-PROCESS.md`)
- **Roles.**
  - Coordinator (main session): plans, launches agents, relays reviews, keeps the registry.
  - Builders, one per track: explore → `SPEC.md` → tests first (see them fail) → code → PR with an acceptance-criteria evidence table → never merge.
  - Reviewers, independent and never the builder: they post ONE review each, with `[blocker|major|minor|nit]` comments carrying evidence and a fix.
  - Browser QA: acts as a customer in Playwright.
  - Release manager: merges one PR at a time after re-checking `ci-gate` on the head.
- **Each PR's acceptance-criteria table** has one row per criterion, with real evidence: test names, run links, numbers, screenshots. pr-hygiene fails on rows marked pending/TBD/TODO/WIP/placeholder, and on titles of 100 characters or more.
- **CI (Feature 0).**
  - `ci-gate` is the one required check.
  - Scanners fail only on findings the change adds.
  - Changes to CI or security config, or new inline suppressions, need the `security-config-reviewed` label.
  - Re-run ONLY failed jobs on a labelled PR; "re-run all" strips the label.
  - Semgrep runs with `--disable-nosem`.
- **Git hygiene.**
  - Explicit pathspecs only; no `git add -A`, no `git stash`, no `--no-verify`, no amend or force-push of pushed commits.
  - Update branches by merging dev into them (merge commits), never by rebasing.
  - Identity `Claude <noreply@anthropic.com>`.
  - Commits end with the `Co-Authored-By` and `Claude-Session` lines. PR bodies end with "Generated with Claude Code" and the session link.
  - Never write a bare `@` mention in GitHub text.
- **Migrations.** One alembic head. Per-track prefixes:
  - r6f11node, r6f12inv, r6f12pol, r6f13trn, r6f14sshca;
  - r6f3repo;
  - r6f4rbac, r6f4sso, r6f4scim;
  - r6t2ledger.
- **Feature 1 contract** (`round6/f1/CONTRACT.md`).
  - F1.1 owns the extension points: `secret_refs.py`, `capabilities.py`, `limits.py`, `node_segment`, `authenticate_node()`, `jobs.leased_job()`.
  - Flags `CBOM_FLEET_INVENTORY/_POLICIES/_MATERIALIZE/_TRANSPORTS` and `CBOM_SSH_CA` default to off (the route answers 404).
  - Every route declares `x-zs-permission`, so F4 RBAC can enforce it.
  - Fleet auth uses the `require_member` dependency, with `ctx: Member` after the limiter and no router-level guard.
  - SSM runs in the cloud worker under a separate role; output over 24,000 chars goes via S3.
  - zs-collect ships an Ed25519-signed manifest.
  - The SSH CA key is server-side and wrapped by KMS. It signs the node's own key and issues 5-minute certificates.
  - Salt: salt-ssh for 200 targets plus 20 minions. AWX output is gzip-chunked at 512 KB or less.

## 5. Environment facts and gotchas (learned the hard way)
- **GitHub access goes through a proxy.**
  - REST only; GraphQL is blocked.
  - `gh api --paginate` fails; page by hand with `?per_page=100&page=N`.
  - Repo-settings writes and branch deletion were refused on the old repo. Try once on the new one, and if refused, hand the owner exact JSON or a click-path.
  - `repositories/{id}` paths are refused.
  - A session can only use repos attached at its start, and two repos with the same name cannot share a session.
- **Permission classifier.** It sometimes refuses issue creation by subagents and trigger deletion. Never work around a refusal; report it.
- **Machine.** 2 CPUs and 8 GB RAM; load averages of 40–100 were seen with about 20 agents. Disk is tight (~4–7 GB free).
  - Clear the uv cache and the docker build cache (`docker builder prune -af`) whenever needed.
  - Locks (`flock` in `round6/locks/`):
    - `heavy-tests.lock` for heavy runs;
    - `stack.lock` only while driving the shared dss-staging stack;
    - `docker-build.lock` for image builds;
    - `aws-ledger.lock`.
  - Name containers `<track>-...` and keep free RAM above 1.5 GB.
- **At most 20 concurrent subagents.**
- **Container restarts and session interruptions kill every background agent and process,** including dockerd (a background task can run at most 2 h). After any restart:
  1. check AWS for running instances;
  2. restart dockerd;
  3. re-add `/etc/hosts`: `127.0.0.1 devsec.dss.test api.dss.test devsec2.dss.test api2.dss.test`;
  4. relaunch agents from their `progress.txt`.
  - Keep a `progress.txt` per track, and push early.
- **Local stack.** The `*.dss.test` names are not in NO_PROXY, so curl needs `--noproxy '*'`. Playwright: run node with the proxy env vars unset and launch Chromium with `--no-proxy-server`. Sign-in codes go to the mail catcher at http://127.0.0.1:8025. The VM kernel has IPv6 disabled.
- **The shared frontend node_modules** is a symlink. Turbopack refuses it, so use `next dev --webpack`. For venvs, use uv's default hardlink mode.
- **Time zones.** QA runs in UTC, which hid #48. Run one QA pass with `timezoneId: 'Asia/Kolkata'`.

## 6. AWS sandbox facts (no secrets here)
- **Account and region:** account 935951870001, region ap-south-1, VPC vpc-0b4f6fef4233d8a43 (10.50.0.0/16).
- **Network:**
  - private app subnets subnet-0a933715183eeedc8 and subnet-0dd252df2cad964fe;
  - DB subnets subnet-0c7db1e608aa37ce4 and subnet-05fd97b04d1b8c4f8, subnet group `devsecshield-rds-subnet-group`;
  - public subnets subnet-050130edaba957b44 and subnet-0744f8711179fa898;
  - security groups: sg-0c617f55ec5ff0bbd (internal) and sg-0640198d7e52a6b61 (remote access);
  - there is a NAT gateway, so the VPC is NOT air-gapped.
- **IAM:**
  - instance profile `devsecshield-ec2-instance-profile`;
  - roles `devsecshield-eks-cluster-role`, `devsecshield-eks-node-role` and `DevSecShieldScannerReadOnlyRole`.
- **Rules:**
  - tag every resource `Project=DevSecShield` (IAM enforces it) plus `zs-lab=sandbox` and `zs-owner=<track>`;
  - sandbox subnets only;
  - S3 bucket names start `devsecshield-` and Secrets Manager names start `devsecshield-`;
  - $50/month budget;
  - record everything in the ledger and tear it down the same day.
- **Permissions learned:**
  - SSM is allowed only for `devsecshield-*` documents on instances tagged Project=DevSecShield. Always pass explicit instance ids: the account has production SSM-managed instances.
  - S3 PutBucketTagging and PutBucketPublicAccessBlock are denied. Ship code to EC2 as base64 chunks over SSM with a sha256 check.
  - KMS: create works, but GenerateDataKey, Encrypt and ScheduleKeyDeletion are denied. Key 59416634-… is left over for the owner.
  - CloudFormation DeleteStack on `u1-zs-cbom-reader` is denied (owner action).
- **Not ours; never touch:** the RDS `proxy-platform-postgres` and any untagged or production resource. Never enable the Lambda/Glue decrypt opt-ins.
- **Infrastructure as code:** `tofu plan -out`, review, then apply the saved plan. Never run downloaded Helm or Packer binaries.
- **Incident:** the F1.1 bench c6i.xlarge ran about 16 h past its 2 h cap after an interruption. It is now terminated, after its results were fetched. Lesson: schedule a teardown check that survives the session, and check AWS first after any restart.

## 7. Feature 1 research conclusions (detail in `round6/research/enterprise-scale.md` and the plan doc https://claude.ai/artifact/Y24pBT85c29VD1Nr9hXHNZ)
- **Don't build our own resident agent fleet.** Enterprises already run AWX/AAP, SSM, Salt, Intune and the like. Reach targets through those, under the customer's change control, with a signed, read-only, no-listener collector (`zs-collect`) whose output matches the SSH path's.
- **Where no tool exists:** the scan node with SSH and short-lived certificates from a built-in SSH CA (5 min, principals per target group, every certificate audited), with Vault's SSH engine as an option.
- **Inventory first:** AWS discovery through the read-only role across regions, CSV/JSON import and an API. Tag policies (e.g. `env=prod` → schedule, transport, never-scan) are deterministic, and the UI shows which policy won.
- **Lean node API for 10,000 nodes:**
  - no per-request INSERT;
  - nonces kept in a time window plus an LRU;
  - claims via `FOR UPDATE SKIP LOCKED`;
  - leases re-queue a dead node's job;
  - configurable limits.
- **Repos at scale:** org-level import (GitHub App / GitLab / Bitbucket), filters, bounded and fair queues, webhook-triggered scans.
- **USP vs the market:** one platform from code to crypto to infrastructure, agentless through existing tools, short-lived access, honest evidence and CBOM depth. Feature 4 adds enterprise SSO/SCIM/RBAC with an audit log.

## 8. Where things stand (details in `claude/round6-handover.md`)
- **Feature 0 (CI/CD):** merged to dev and staging.
- **Open PRs into dev:**
  - #30 (T0): approved with minors; browser QA findings logged; needs a fixer.
  - #32 (T1): security asked for changes; fixes on `wip/t1-never-scan-review-fixes`.
  - #34 (F1.2 scaffold): approved; 2 small minors.
  - #38 (F2 part 1): content review asked for changes, which produced bugs #45–#49.
  - #40 (F3 backend): reviews to redo; scan-worker image build runs out of runner disk.
  - #41 (F1.1): steady heartbeat passes (p99 45 ms at 10k nodes), but the **10k-job run fails** (21% errors, ~31 s timeouts). Root-cause it.
  - #42 (F4 RBAC): reviews to redo; browser QA of the role matrix still to run.
- **Unopened work:** on `wip/*` and `feat/*` branches (T2, F1.2 UI, F1.3 zs-collect, F1.4 SSH CA, F2 part 2, F3 UI, F4 SSO).
- **Open issues:**
  - #12–#15 and #17 (in PRs);
  - #18 (tracked .env files);
  - #19–#22, #24, #25 (CI follow-ups);
  - #27–#29;
  - #31 (console logs passwords);
  - #33 (reinitialize credit bypass);
  - #35–#37 (tooltip-found bugs);
  - #39 (tracked key file);
  - #45–#49 (Ruby SAST analyses nothing, SBOM inventory counted as vulnerabilities, `last_updated` noise, timestamps without a timezone, zip source shown as "—").
  - Not filed yet: CI scan-worker runner-disk exhaustion, and the T1 draft about pinned HTTP clients (`round6/t1/issue-pinned-clients.md`).

## 9. Lessons for the next coordinator
1. Real bugs surface when a reviewer *executes* the claim (the content review found 5 product bugs). Keep reviewers adversarial and evidence-based.
2. Post reviews as soon as they are done. Three full reviews were lost because the agents died before posting.
3. With about 20 agents on 2 CPUs, heavy work must go through the locks, and big benches go to EC2 with a hard teardown deadline that a separate scheduled check enforces.
4. CI minutes ran out on GitHub Free (about 30 runner-minutes per run). Enterprise has 50k, but still push in coherent batches.
5. Merge order: #34 → #30 → #32 → #41 → the rest, one at a time, merging dev into the next branch after each merge. Run a browser regression on dev, then promote to staging.
