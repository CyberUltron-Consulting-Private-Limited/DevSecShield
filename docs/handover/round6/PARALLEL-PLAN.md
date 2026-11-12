# Parallel delivery plan (from Nov 11, about 10:50 UTC)

The owner asked to ship every feature in parallel with many specialised agents, without skipping any step: spec, then
tests first, then code, then PR, then 3 independent reviews, then browser QA as a customer, then proof and evidence
against the acceptance criteria and scale targets, then live tests, then the release manager merges into dev, then
promotion to staging.

Every builder reads TEAM-PROCESS.md (including "Parallel tracks: shared-machine rules") and /home/claude/devsecshield/CLAUDE.md.
Research: $R6/research/enterprise-scale.md. Plan doc: https://claude.ai/artifact/Y24pBT85c29VD1Nr9hXHNZ.

## Tracks
| Track | Branch | Depends on | PRs |
|---|---|---|---|
| T0 R2 polish #12–#15 | fix/r2-polish | none | 1 |
| T1 never-scan dual stack #17 | fix/never-scan-dual-stack | none | 1 |
| F1.1 lean node API | feat/f1-node-api | none (hot-path internals; the API stays compatible) | 1–2 |
| F1-ARCH contract | (doc only) | none | none: it writes $R6/f1/CONTRACT.md, which F1.2–F1.4 follow |
| F1.2 inventory and tag policies | feat/f1-inventory | F1-ARCH | 1–2 |
| F1.3 transports and zs-collect | feat/f1-transports | F1-ARCH (rebases onto F1.2 when it merges) | 2–3 |
| F1.4 SSH CA | feat/f1-ssh-ca | F1-ARCH | 1 |
| F2 (i) info tooltips | feat/f2-info-tips | none | 1–2 |
| F3 repos at scale | feat/f3-repos-at-scale | none | 2 |
| F4 SSO/SCIM/RBAC | feat/f4-rbac, feat/f4-sso, feat/f4-scim | none (RBAC first) | 3 |

## Acceptance criteria
Each PR's AC table quotes the rows it covers, with evidence.

### T1: never-scan (#17)
- If any address a name resolves to is on the never-scan list, the whole name is skipped as `skipped_never_scan`. This holds for the registry and for redirect targets.
- The test is restored to `127.0.0.1` only, and a new unit test covers a name whose excluded IPv4 sits alongside a non-excluded IPv6.

### F1.1: lean node API
- 10,000 simulated nodes with a 60 s heartbeat: p99 < 300 ms and no errors, sustained for 10 minutes.
  - There is no per-request INSERT on the hot path, and nonce/replay protection is kept by another means, such as a time window plus an LRU or a single upsert.
- A 10,000-job run: scheduling overhead under 5 min, with no O(N²) `recompute_run`.
  - Jobs are claimed with Postgres `FOR UPDATE SKIP LOCKED` and are not pinned to one node. A node that dies mid-job has its job re-queued after a lease timeout.
- The 500-sources and 50-agentless-node caps become configurable limits, with defaults sized for enterprise use.
- The existing scan-node suite and backend suite stay green. An old scan node, running the current image, still works.
- Proof: a load-test script committed under bench/ and its report (p50/p95/p99, error rate, CPU and DB QPS), run where results are trustworthy, under `flock heavy-tests.lock`.

### F1.2: inventory and tag policies
- Inventory sources:
  - AWS discovery through DevSecShieldScannerReadOnlyRole (EC2, RDS, EKS, ELB/ACM, KMS, Secrets Manager), across regions;
  - CSV/JSON import;
  - an API.
- 1,000 targets imported in < 2 min. Re-import is idempotent and updates targets rather than duplicating them.
- Tag policies, for example `env=prod` → schedule, transport and never-scan.
  - Evaluation is deterministic.
  - When several policies match a target, the UI shows which one won.
- Live proof in the sandbox: create 3–5 tagged t3.micro / db.t4g.micro resources, discover them, then tear them down. Scale proof with recorded or moto responses for 1,000.

### F1.3: transports and zs-collect
- `zs-collect`: a signed, read-only collector (no network listener, no writes outside its temp dir) that emits the scan-node inventory format. Its output is identical to the SSH path's on the same host.
- Transports:
  - Ansible AWX/AAP (a job template that runs zs-collect);
  - customer Salt through salt-api (cmd/state);
  - AWS SSM (SendCommand with a `devsecshield-*` document). SSM permission is not granted yet: build it, test it against recorded responses, and mark it for a live test.
- 200 real targets (containers) collected through each of AWX and Salt, with results matching the SSH path.
- Typed credentials, as today. Credits are charged per run, as today.

### F1.4: SSH CA
- A built-in SSH CA issues short-lived user certificates (default 5 min) for scan sessions, with principals per target group.
- Rotation and revocation; host-key trust; an audit log entry for every issued certificate.
- HashiCorp Vault SSH engine as an option.
- Proof: a real sshd that trusts the CA. An expired certificate is refused, and a principal mismatch is refused.

### F2: (i) info tooltips
- A reusable `<InfoTip>` with hover, focus and tap. It is keyboard accessible (it opens on focus and closes on Esc), works on mobile, and is screen-reader labelled.
- Each tip has "what it is" plus a concrete example. The content lives in one registry.
- Every form field, metric, badge and setting across the eight products, CBOM Sources, Settings and Admin has a tip. A unit test fails when a field has no registry entry.
- The content is accurate: a reviewer checks every tip against the backend's real behaviour.
- Browser QA on desktop and a 390×844 phone, plus axe with 0 serious violations on the pages changed.

### F3: repos at scale
- Org-level import from GitHub, GitLab and Bitbucket: an app installation or token, auto-discovery of every repo, and include/exclude filters.
- 1,000 repos imported in < 5 min. Scheduled and webhook-triggered (push) scans have bounded concurrency and per-team fairness.
- Dedup and rollup across repos. Credits per run.
- Proof: a live GitHub org or user with several repos, if reachable through the proxy, otherwise recorded responses; plus a scale test with 1,000 mocked repos.

### F4: SSO/SCIM/RBAC
- RBAC first: roles owner, admin, member and viewer, scoped per team, enforced server-side on every route. There is a route-coverage test that fails if a route has no permission declared. An audit log records every privileged action.
- SSO: OIDC and SAML per organisation, with JIT provisioning, domain capture and enforced SSO. Tested against a local Keycloak.
- SCIM 2.0: Users and Groups, with create, update, deactivate and group-to-role mapping. Tested with a SCIM client against Keycloak or a test harness.
- Browser QA of login, the role matrix and deprovisioning.

## Merge order
1. T0 and T1 (small).
2. F1.1.
3. Then whichever is green first; the release manager handles one merge at a time.
4. Each merge re-runs CI for the remaining PRs, which merge dev into their branch.
5. Promote dev → staging after each batch has integration QA on dev: one browser regression, run as a customer.
