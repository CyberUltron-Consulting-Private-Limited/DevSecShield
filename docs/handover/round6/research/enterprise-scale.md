# DevSecShield CBOM at enterprise scale: architecture, market and roadmap

Prepared 2026-11-11 for the CTO. Code facts come from `/home/claude/devsecshield` as read on 2026-11-11. Market facts come from the web sources listed at the end, each with its date. Where a source did not say something, this report says so. "Inference" marks a conclusion of mine rather than a sourced fact.

---

## Executive summary

1. **Collection is already the strong, secure part.** The read-only collectors, network gate, signed node requests, pool-token enrolment and evidence model are not what blocks 10,000 targets. The blockers are **onboarding** (every target typed into a source by hand), **credentials** (one set per source), **SCM** (no org-level integration), **enterprise identity** (no SSO, SCIM or scoped RBAC) and a **backend hot path** sized for tens of nodes.
2. **Do not bundle Salt, or any general remote-execution fabric.** A Salt master is root on every minion by design. Its CVE history (an unauthenticated RCE exploited in the wild in 2020, and 11 more CVEs fixed in 3006.12 in 2025) and its Broadcom-run distribution make it a liability inside a bank. The market pattern is different. Vendors ship **one signed, read-only scanner binary** and let the customer's existing control plane run it: Tanium, CrowdStrike, Cortex XDR, AWS SSM, Intune or Ansible. TYCHON, SandboxAQ and Keyfactor all do this.
3. **The market consolidated in 2025-26, and incumbents now bundle PQC inventory.** Keyfactor bought InfoSec Global and CipherInsights (May 2025); Palo Alto closed CyberArk/Venafi (Feb 2026) and uses its firewalls as crypto sensors; Wiz includes PQC readiness in Wiz Cloud (May 2026); IBM's Quantum Safe suite is commercial (Oct 2026). AQtive Guard lists at **USD 250k a year**. ZeroShield cannot win on breadth.
4. **ZeroShield can win on four things together:** air-gapped, small-footprint deployment with an offline KB and no AI; provably read-only collection; code plus infrastructure in one CycloneDX 1.6 CBOM with evidence and drift; and India mapping at a price Indian BFSI will pay. **RBI's Q-SAFE committee (May 2026) is to evaluate the sector's crypto inventory "through a CBOM".** That is the wedge.
5. **Scale is a backend and onboarding problem, not a broker problem.** 10,000 agents at a 60 s heartbeat is about 170 req/s, easy for Postgres if each request is one cheap UPDATE. Today's code would generate about 2,300 req/s, with roughly twice that in write statements. Kafka is unnecessary.

Recommended order (Part D): 0) the hot-path and data-model fix, then 1) SSO, SCIM and scoped RBAC, then 2) SCM apps and incremental scans, then 3) inventory-driven auto-onboarding with credential profiles and an SSH CA, then 4) reach through customer control planes, then 5) a packaged host agent with self-update and cloud attestation.

---

## Part A: what the product has today

**What exists**

- **Enrolment.** A scan node is a container, Helm chart, AMI or OVA (`scan_node/README.md`, `deploy/`). It exchanges a single-use `zsr_` token for a node token, then signs every request with Ed25519 (timestamp, nonce, body hash). It optionally uses mTLS with certificate pinning (`node_auth.py:170-251`). Agent mode (`ZS_MODE=agent`) runs as a DaemonSet, a `docker run` or the AMI. It enrols with expiring, capped and revocable `zsp_` pool tokens, and each pod becomes its own node with an auto-created `host_agent` source (`agents.py:1-42`). There is no approval queue and no cloud instance attestation.
- **Fleet and jobs.** All job state lives in one Postgres table, claimed with `FOR UPDATE SKIP LOCKED`. Leases are 15 minutes, there are 3 attempts, and runtime is capped at 8 hours (`jobs.py:36-49, 497-580`). Nodes poll for a claim every 5 s (`agent.py:48`) and heartbeat every 30 s, or every 5 s while busy (`cbom_node.py:53-54`). A node runs 2 jobs by default and at most 8 (`agent.py:88`). The cloud worker uses the same table (`cbom_cloud_worker.py`). Self-update and staged rollout do not exist.
- **Credentials.** Secrets are encrypted per source; the decision allows raw credentials. On the node, vault references are opt-in and cover only HashiCorp Vault KV v2 and AWS Secrets Manager (`vault.py`, README). The default Linux login is the node's own SSH key, which someone must add to `authorized_keys` on every server. There is no SSH CA, CyberArk or Azure Key Vault support.
- **Discovery and onboarding.** Discovery is a network sweep. CMDB import from a CSV or a ServiceNow pull is capped at 5,000 rows and 500 sources, makes groups of at most 1,000 targets, and creates Linux sources only (`cmdb.py:1-37`). The AWS collector can walk an organisation (first 200 accounts, serially; `aws_collect.py:1169-1216`). It reads EC2, RDS and EKS for crypto facts but never turns them into scan targets. Schedules run daily, weekly or monthly, with at most 20 per team (`schedules.py:42`). `waves.py` holds **remediation** waves, not staged scan rollout.
- **Code repos.** Each scan goes create → estimate → start, and only its owner can start it, with a PAT per repo (`scans.py:516-690`). Celery queues `scan_worker_queue` and `cicd_worker_queue` run with prefetch 1 (`scan_worker.py:103-112`). The CI/CD API-key upload path (`cicd.py`) is the only route that scales. There is **no GitHub App, no GitLab group integration, no inbound webhook and no org repo listing** (grep found only outbound webhooks in `integrations/`).
- **Tenancy and identity.** Rows are scoped by `team_id`. Roles are `admin` or `member` only (`new_models.py:37`). Sign-in is email and password with JWT (`routers/auth.py`). There is no SSO or SCIM, and no business-unit or asset-group scope. A CBOM audit table exists, plus SIEM, ServiceNow and webhook push (WP11).

**Bottlenecks at 1,000-10,000 targets**

| # | Bottleneck | Evidence | Effect at 10k |
|---|---|---|---|
| 1 | Polling cadence | claim every 5 s plus heartbeat every 30 s (`agent.py:48`, `cbom_node.py:53`) | about 2,333 req/s while idle |
| 2 | A nonce INSERT and commit on every request | `node_auth.py:192-199`; sweep once a minute | about 2,300 inserts/s, or 8.4M rows/h of churn |
| 3 | Heartbeat does reap, settings load and pending count | `cbom_node.py:303-350` | several queries per beat |
| 4 | `recompute_run` loads **every** job of the run on each claim and finish | `jobs.py:111-143` | a 10k-job run means about 2×10⁸ row loads, O(N²) |
| 5 | One source is one job, pinned to one node | `runs.py:94-98` | no load-balancing or failover; 1,000 hosts run on one node at ≤64 SSH sessions under the 8 h cap (`linux_ssh.py:741`) |
| 6 | Hard caps | 50 agentless nodes, 500 sources (`cbom_sources.py:107-108`); 1,000 agents and 50 pools (`agents.py:39-42`); 1,000 lines per source (`targets.py:13`); 50k assets per job (`jobs.py:49`) | DBs and clusters are one per source (`kinds.py:249-330`), so at most 500 per team |
| 7 | Kubernetes needs a static-token kubeconfig per cluster; exec plugins are refused | `kinds.py:294-295` | EKS, AKS and GKE need a long-lived SA token pasted in for every cluster |
| 8 | Assets are re-stored in full on every run; no retention and no partitioning | `new_models.py:449-473`; `cleanup.py` deletes only when the team is deleted | about 1.5M rows per weekly run (assuming ~150 assets per host), roughly 80M a year |
| 9 | The rate limiter keeps counts in memory per worker | `ratelimit.py:4` | limits are N× too loose behind N workers |
| 10 | Code scans are per-repo, manual and owner-only | `scans.py:559` | 5,000 repos cannot be onboarded by hand |

---

## Part B: the market

### B.1 What changed in 2025-26 (dated)

- **Keyfactor** bought InfoSec Global (AgileSec) and Quantum Xchange's CipherInsights network sensor on **2025-05-14**.
- **Palo Alto Networks** made Quantum-Safe Security GA on **2026-01-30**, using its firewalls as sensors. Its CyberArk acquisition, including Venafi, closed on **2026-02-11**.
- **Wiz for PQC Readiness** [**2026-05-18**] is included in Wiz Cloud for all customers.
- **RBI** set up the **Q-SAFE** expert committee on **2026-05-25**. Its terms include evaluating the financial sector's "cryptographic inventory through a CBOM", assessing vendor-tool maturity, and a roadmap. The report is due within 6 months of the first meeting.
- **Entrust** added CBOM import and export on **2026-09-15**. **AppViewX** made Quantum Trust Hub standalone on **2026-10-29**. **IBM**'s Quantum Safe suite was reported commercially available on **2026-10-31**.
- **CERT-In** published version 2 of its BOM guidelines on **2025-07-09**. They cover SBOM, QBOM, CBOM, AIBOM and HBOM, and are advisory, not mandatory.

### B.2 Comparison table

| Vendor | Deployment model and how it reaches scale | Integrations | Packaging and pricing signal | Known weaknesses (honest) |
|---|---|---|---|---|
| **IBM** Quantum Safe Explorer, Guardium Cryptography Manager | Explorer scans source code into a CBOM inside DevSecOps pipelines. IBM's CIO office scanned **5,815 repos and 47M lines**. GCM *ingests* network scanners, Kubernetes, Vault, Qualys, Nessus and CBOMs, plus CSV or JSON bulk import. It installs on K8s or OpenShift via Helm. | Pipelines, Qualys/Nessus, Vault; the datasheet does not mention CMDB or SIEM. | Commercial with trials; no public price. The minimum cluster is 3 control-plane plus 3 worker nodes, each worker 8 vCPU / 16 GB. | Heavy footprint and services-led. Host reach depends on third-party scanners; the datasheet names no host agent. |
| **SandboxAQ AQtive Guard** (incl. Cryptosense) | A filesystem and image scanner, a Java tracer and a network analyzer produce trace files (up to 4 GB). Scale comes from the customer's EDR: **CrowdStrike** (needs Falcon Prevent plus Discover or Insight) or **Tanium** (packages; traces pulled through Threat Response File Evidence). An on-prem server option exists. | CrowdStrike, Tanium, SentinelOne, Qualys, Venafi. | **AWS Marketplace Enterprise: USD 250,000 for 12 months**, non-refundable. | Expensive; the trace-upload model is clunky; docs are split between the original and SaaS releases. |
| **Keyfactor AgileSec** (ex-InfoSec Global) plus CipherInsights | A unified sensor binary run remotely or by CLI, with sensors for Git hosts, cloud KMS, PKCS#11 and HSMs, containers, Artifactory and SQL Server; it ingests Qualys, Tenable and CipherInsights. Host sensors are pushed **via Tanium** and **CrowdStrike** "across your existing Falcon footprint". Back end: Kafka, OpenSearch, ephemeral K8s pods per scan, incremental scans, dedup. CipherInsights is a passive network listener. | ServiceNow, CMDB/SIEM/SOAR APIs, Tanium, CrowdStrike. | Not public. | Assembled from acquisitions, so complex. CipherInsights sees only traffic past the sensor. |
| **Venafi / CyberArk, now Palo Alto Networks** | Certificate discovery through customer-hosted **VSatellites** and Kubernetes discovery. Quantum-Safe Security uses **NGFW and Prisma Access telemetry** as sensors (nothing new deployed), plus CMDB and EDR ingestion and a cipher-translation proxy. | PAN-OS, Prisma, CMDB, EDR. | Not public; assessment entry point. | Certificate-centric, not a code CBOM; best with a Palo Alto estate. |
| **Entrust** Cryptographic Security Platform | Discovery mechanics not disclosed. SaaS or on-prem; CBOM import/export and correlation; Ansible certificate automation. | Ansible, SPIRE, Qualys CertView plugin. | Not public. | Strongest where Entrust PKI or HSMs exist; discovery depth unclear. |
| **DigiCert** Trust Lifecycle Manager | A hosted control plane with customer-side **sensors** (network discovery, connectors) and host **agents** (IIS/Apache certificates). | Tenable, Qualys VMDR, AWS Private CA, Microsoft CA. | Not public. | Mostly certificates and TLS. |
| **AppViewX** Quantum Trust Hub | "Agentless-first" through the customer's Qualys and Tenable, plus CBOM/SBOM uploads. | ServiceNow, Qualys, Tenable. | 30-day assessment offer. | Only as good as the third-party scanners. |
| **QuSecure** QuProtect R3 | "Agentless" Recon; CycloneDX CBOM mapped to NIST, FIPS, CNSA 2.0; in-line PQC remediation. | Not named. | AWS Marketplace listing; price not checked. | Mechanics undisclosed; transport-focused. |
| **Quantum Xchange CipherInsights** | A passive network sensor. Now Keyfactor (see above). | CMDB, SIEM, SOAR APIs; CBOM. | n/a | Blind to keys at rest, code and anything encrypted off the sensor's path. |
| **TYCHON** Quantum Readiness / ACDI | **One binary per OS** pushed through Cortex XDR (script or agent profile with SHA-256 checks, 6-hour schedule), writing NDJSON that XSIAM ingests. An **Army deployment covered more than 180,000 endpoints and 100M+ certificate files** (Jan 2026). | Palo Alto XDR/XSIAM; US federal contract vehicles. | Quote only. | US-federal focus; little presence in India. |
| **Thales** | "An agreed discovery platform, consultant-led assessment or a combination". CipherTrust is key management, not a CBOM scanner. | n/a | Services. | A channel or partner more than a competitor. |
| **PQShield** | PQC IP and libraries (UltraPQ); no discovery product found. | n/a | n/a | Not a competitor; possibly a remediation partner. |
| **Wiz** (new entrant) | Agentless cloud plus code, optional runtime sensor; "can help create a CBOM". | The Wiz platform. | **Included in Wiz Cloud.** | Cloud-only; no air-gap; CBOM format not described. |
| **Qualys** (adjacent) | CertView shows PQC key-exchange support per certificate from network scans (QID 38994). | Feeds AppViewX, Entrust. | In existing subscriptions. | TLS endpoints only. |
| **Open source**: PQCA CBOMkit, sonar-cryptography, CBOMkit-theia | sonar-cryptography covers Java (JCA, BouncyCastle), Python (pyca) and Go stdlib, with C# in development, and writes CycloneDX 1.6 `cbom.json`. CBOMkit-theia scans images and directories (certificates, java.security, openssl.cnf, gitleaks secrets). | Sonar, GitHub Action. | Free (Apache-2.0, with Sonar source-available parts). | Code and images only; no fleet, no hosts, no policy, no reporting. It sets the floor that a paid code CBOM must beat. |

**Pattern across the leaders (inference):** nobody reaches 100k hosts with their own transport. They **ride a control plane the customer already trusts** (EDR, Tanium, NGFW, cloud APIs, VM scanners) and **ingest** other tools' output. Their agents are thin scanners, not remote-execution fabrics.

### B.3 USPs ZeroShield can realistically own

1. **"Sovereign CBOM": a full air-gapped edition at a small footprint.** IBM needs a 6-node K8s or OpenShift cluster; Wiz, AppViewX and DigiCert are SaaS-first. An offline, AI-free KB on one or two VMs suits Indian banks, PSUs and defence. **Caveat:** IBM, Entrust, AQG and Keyfactor all have on-prem options, so air-gap *alone* is not unique; the footprint, price and India focus are.
2. **Read-only you can audit.** Publish the exact command list (rendered from `commands.py`), the sudoers file, ClusterRoles and DB grants, and keep the network gate and the never-read-private-keys rule. Competitors run as root or SYSTEM through the EDR. Add a per-job command-transcript hash to the evidence so the CISO and auditor can prove what ran.
3. **One CBOM across code, hosts, K8s, DBs, cloud and network, with stable identities and drift.** IBM and Keyfactor cover both, but at enterprise price and complexity. Keep CycloneDX 1.6 *with evidence* first-class, and **import** other vendors' CBOMs (Entrust and AppViewX do).
4. **Indian regulatory mapping as product, not slides.** Map to CERT-In BOM v2 (CBOM/QBOM fields), RBI Q-SAFE outcomes when published, RBI IT/cyber directions, and SEBI CSCRF. Ship board-ready "crypto-agility" evidence packs. **Do not claim CERT-In empanelment**: per company records, ZeroShield is not empanelled.
5. **Price and packaging for India.** Against a USD 250k list price (AQG), a per-asset annual licence that a mid-size bank or NBFC can approve locally is a real wedge (inference).

### B.4 Gaps to close to compete

- Org-level SCM apps and webhooks, incremental scans, and a per-repo subscription model in place of per-scan estimates.
- Inventory-driven onboarding from cloud APIs, CMDB sync, AD and K8s self-registration, plus tag-based collection policies.
- Credentials without per-target secrets: an SSH CA, more vaults (CyberArk, Azure Key Vault), cloud-native IAM for DBs.
- Reach through customer control planes (SSM, Azure Run Command, Intune, Ansible, and later Tanium or XDR), which the competitors already have.
- SSO, SCIM, scoped RBAC and audit export: table stakes in BFSI RFPs.
- A backend hot path and data model for 10k nodes and 100M+ observations.
- Ingesting Qualys, Tenable and CBOM data to fill coverage gaps cheaply.

---

## Part C: fleet-scale technology, compared honestly

### C.1 Configuration-management agents

| Option | Model | For a read-only security product | Verdict |
|---|---|---|---|
| **Salt** (minion and master) | A persistent minion with a ZeroMQ pub/sub master and fast fan-out | The master **is designed to execute arbitrary commands as root on every minion**, the opposite of least privilege. **CVE-2020-11651/11652** gave unauthenticated master RCE and root on all minions. It was exploited from 2-3 May 2020 against LineageOS and Ghost, with more than 6,000 masters exposed. **3006.12 fixed 11 CVEs** (CVE-2024-38822 to 38825, CVE-2025-22236 to 22242): minion impersonation, event-bus auth bypass, command execution via git pillar URL, path traversal, and auto-accept of minion keys. Distribution moved to Broadcom Artifactory in Oct 2024 and dropped packages older than 3006; the change was described as "disruptive". | **Do not bundle.** Shipping a root RCE fabric into a bank turns ZeroShield into the highest-value target in the estate and fails security review. **Do** offer a "run via your Salt" recipe (a state that runs our read-only binary) for customers who already run Salt. |
| **Puppet / Chef** | A pull agent with its own PKI, running as root | Same root concern. **Perforce moved Puppet binaries to a private, EULA-gated channel** (Nov 2024; free use is limited to 25 nodes), and the community forked it as **OpenVox** (Jan 2025). | Do not bundle. Integration recipes only. |
| **Ansible** (agentless push) and **AWX/AAP** | SSH or WinRM from a controller | Same model as our scan node, so no new reach. AWX is mid-refactor, and Red Hat says it "isn't to offer an exact replica of our commercial product" (Jan 2026). | Ship an **Ansible collection** (`zeroshield.cbom`) that runs our binary and posts results. That is useful for customers with AAP, but it is not our core transport. |

### C.2 Purpose-built security agents: how vendors do it

These are the common patterns, each sourced:

- **Enrolment secret, scoped and revocable.** Qualys uses an activation key plus a customer ID, with separate keys per business unit or module. osquery uses an enroll secret that returns a `node_key` and optionally an approval step; the server can force re-enrolment with `node_invalid`. Wazuh uses an `authd` password, and also supports manager and agent certificate verification. ZeroShield's `zsp_` pool tokens already match this. **Missing: an approval queue and per-token default tags or groups.**
- **Zero-touch cloud identity.** All three clouds publish signed identity that the server can verify:
  - **AWS:** the instance identity document carries PKCS7, RSA and RSA-2048 signatures, with per-region public certificates. It is *not secret* and can be replayed, so bind it to a server nonce and check `instanceId` and `accountId` against the customer's linked accounts.
  - **Azure:** IMDS `attested/document` is PKCS7-signed with `vmId`, `subscriptionId`, a caller nonce and `expiresOn`; the SAN is `*.metadata.azure.com`.
  - **GCP:** an RS256 JWT for an audience the caller chooses, verified against Google certificates.
  - **SPIRE** wraps these as node attestors (`aws_iid`, `gcp_iit`, `azure_msi`, `k8s_psat`, `join_token`, `x509pop`) and rotates SVIDs automatically.

  **Recommendation:** add cloud attestation as an enrolment method; a pool token becomes optional when the account is linked. Do **not** adopt full SPIRE yet. That is another server for air-gapped sites to run; borrow the pattern instead (inference).
- **Outbound-only pull with resource caps.** Qualys advises a 900 s status check-in (under 1 KB), delta uploads every 10-20 s, a CPU limit of at least 10% and a throttle of at most 20 ms. The AQG Tanium guide says to stagger installs and cap parallel uploads. ZeroShield is outbound-only already, but its Helm chart caps memory only.
- **Self-update and signing.** Qualys auto-updates by default (retries every 18 h); TYCHON's XDR profile checks SHA-256 before running. ZeroShield has no self-update; the image tarball has only a `.sha256`.
- **mTLS rotation.** Agents should hold a short-lived client certificate renewed automatically. Today mTLS is optional and comes from customer-supplied files, and pinning forces a node reset when the certificate changes (`node_auth.py:247-250`).
- **Teleport / Fleet / osquery as references.** Teleport Machine ID issues short-lived certificates to bots; Fleet and osquery show central config with distributed queries. Borrow the patterns; do not bundle them.

### C.3 Agentless at scale: ride the customer's control plane

**The key architectural move (inference, backed by TYCHON, AQG and Keyfactor):** separate the **collector** (a signed, read-only, single binary that writes one JSON document) from the **transport** that runs it. The collector logic already exists (`hostfs.py`, `pkgdb.py`, `linux_parsers.py`). Each transport is then a thin adapter:

| Transport | How it works | Pros | Cons / risks |
|---|---|---|---|
| **AWS SSM Run Command / State Manager** | An SSM document targeted by tags (max 5 keys × 5 values); `max-concurrency` default 50 (or %), `max-errors` default 0; output to the customer's S3, read by our existing cross-account role. | No SSH keys or inbound ports; whole accounts. | Runs as root, so the script must be signed and auditable; needs SSM coverage. |
| **Azure Run Command** (VMs; Arc servers) | Managed Run Command for VMs; Arc Run Command runs as LocalSystem over the Arc agent. | Covers on-prem through Arc. | Arc Run Command was **public preview** per an Aug-2025 doc; status unverified. |
| **GCP OS Config** | OS policies and inventory. | Native. | Not researched; verify first. |
| **Intune** (Windows) | A remediation script or Win32 app runs the binary on a schedule. | Reaches off-LAN machines. | Output upload needs our endpoint or a share. |
| **Tanium, CrowdStrike, Cortex XDR** | The competitors' route: a package, RTR, or an XDR script. | Reach to 100k endpoints. | Needs partnerships; do later, with demand. |
| **Ansible AWX/AAP, Salt** | A collection or state that runs the binary. | Low effort. | Customer-operated. |
| **SSH via CA** | **Vault SSH** signed certificates or **Teleport Machine ID** short-lived certificates; targets trust one `TrustedUserCAKeys`; the node gets a certificate per job. | No `authorized_keys` distribution, no static keys. | Needs Vault or Teleport; fallback is a small SSH CA built into the node. |
| **Vaults** | Today: Vault KV v2, AWS Secrets Manager. Add CyberArk, Azure Key Vault, GCP Secret Manager. | Secrets never reach SaaS. | One integration per vault. |
| **Cloud-native DB auth** | RDS, Azure and Cloud SQL IAM tokens in place of passwords (verify per engine). | No DB passwords. | Not every engine supports it. |

**"No per-target secrets" in practice** means a **credential profile** (an SSH CA role, a vault path template such as `secret/cbom/{{env}}/{{os}}`, or "use SSM") attached by **policy**, not typed per source. This is the single biggest usability change.

### C.4 Discovery and auto-onboarding

- **Target inventory as a first-class table**, separate from "sources", with normalised tags (env, BU, owner, criticality, exposure, OS, account, cluster). Populated by:
  - **Cloud APIs**, using the role we already hold (EC2/VMs, EKS/AKS/GKE, RDS/Azure SQL/Cloud SQL). The AWS collector already calls `describe_instances`, `describe_db_instances` and EKS APIs (`aws_collect.py:467, 726, 884`), but only for crypto facts.
  - **K8s operator self-registration** with its own read-only ServiceAccount, so no kubeconfig leaves the cluster (also fixes the exec-plugin problem).
  - **CMDB scheduled sync** (turn the ServiceNow pull into a periodic reconcile), **AD/LDAP computer objects** for Windows, plus the existing network discovery and agents.
- **Collection policies** replace manual sources. Each is selector → method → tier → schedule and window → credential profile → node group. Example: `env=prod AND os=linux` → SSM if available, else scan-node SSH with the CA → Tier 2 → weekly in the Sunday window → node group `dc-mumbai`. Jobs are created **per target batch** (for example 50-200 targets) and claimed by **any node in the group**, which removes bottleneck 5 and gives failover.
- **Coverage report**: known targets vs. collected vs. failed, per BU. That is what auditors and RBI-style reviews ask for.

### C.5 Repositories at scale

- **GitHub App** (github.com and GHES), installed per org:
  - It lists repos 100 per page, so 5,000 repos take about 50 calls.
  - Installation tokens have a **5,000 requests/hour baseline**, scaling to **12,500**, or **15,000 on Enterprise Cloud**. Secondary limits are 100 concurrent requests and 900 REST points per minute.
  - Webhooks: `push`, `pull_request`, `installation_repositories`, `repository`.
- **GitLab:** group access tokens (Premium or Ultimate on GitLab.com; any tier self-managed; 365-day default maximum lifetime) plus group webhooks. **Bitbucket** workspace and Data Center, and **Azure DevOps** org service hooks, follow the same pattern (not researched in depth).
- **How others do it:**
  - **Semgrep Managed Scans:** a private GitHub App or a GitLab token; a full scan weekly (first scan at a random time up to 6 days later, one retry); a diff-aware scan on every PR in "seconds"; ephemeral, network-isolated containers that are destroyed after the scan.
  - **GitHub code scanning default setup:** enabled for all eligible repos from org security configurations.
  - **Snyk:** a bulk import tool with batches, controlled pace, retries and restartability.
- **For a CBOM** (inference):
  - Diff scans can miss cross-file facts (a key size in a constants file), so pair **PR/push diff scans** with a **weekly full scan**, as Semgrep does.
  - Cache per-file results by blob SHA, so monorepos cost only their changed paths; shard large repos by top-level path.
  - Queue priority: PR > default-branch push > scheduled full > backfill, with per-tenant fair share so one 5,000-repo backfill cannot starve another tenant.
- **Air-gapped GitLab or GHES with no inbound webhooks:** poll `git ls-remote` per repo (one cheap call) every N minutes and scan on a SHA change.

### C.6 Backend for ingestion

**Arithmetic for 10,000 agents:**

| | Today's code | Target |
|---|---|---|
| Heartbeat | every 30 s → 333 req/s | every 60 s with ±20% jitter → 167 req/s |
| Claim polling | every 5 s → 2,000 req/s | piggy-backed on the heartbeat, or a long-poll held 25-55 s → ~0 extra |
| DB writes per request | nonce INSERT + commit, node UPDATE, reap, settings, counts | 1 UPDATE (last_seen); nonce checked in memory or Redis, or a per-node monotonic counter in the node row |
| Weekly run of 10k jobs over an 8 h window | ≈ (1 claim + 2 asset batches + 1 result) × 10k ≈ 1.4 req/s, **but** `recompute_run` is O(N²) | the same 1.4 req/s, with incremental run counters |

So the queue technology is **not** the problem. Postgres `SKIP LOCKED` handles this volume when the hot path is lean.

- **Brokers.** Kafka is wrong here: it is an operational burden for air-gapped sites and buys nothing at about 200 req/s. Use the RabbitMQ you already run for **code-scan fan-out**, with per-tenant queues or a dispatcher-side token bucket. For node wakeups, use Postgres `LISTEN/NOTIFY` or Redis pub/sub to end a long-poll early. Consider **NATS** (a single binary with leaf nodes) only if you later move nodes to persistent push connections.
- **Data model.** Move from "a full copy per run" (`cbomcollectedasset`) to three layers:
  - **current asset state** keyed by `identity.stable_key`, which already exists, with first_seen and last_seen;
  - **observations** partitioned by month (Postgres declarative partitioning) with a retention policy, for example 13 months online;
  - **drift events**, which already exist.

  The CycloneDX export then reads current state plus evidence. A time-series database is not needed.
- **Dedup across sources.**
  - Certificates by DER SHA-256, which is global.
  - Keys by SPKI hash.
  - Hosts by cloud instance ID, then FQDN, then IP with a time window.
  - A network-observed certificate and the host file holding it merge on the fingerprint.

  Show "seen by: network, host agent, K8s" as evidence. Keyfactor also advertises dedup and auto-resolve.
- **Multi-tenant isolation.** Keep the `team_id` filters and add **Postgres RLS** as defence in depth; per-tenant envelope encryption for secrets (KMS in SaaS, customer HSM on-prem); dedicated single-tenant SaaS for large banks (inference: often demanded by Indian BFSI).
- **Enterprise identity.**
  - **SAML 2.0 and OIDC SSO**; **SCIM 2.0** with deprovisioning that kills sessions.
  - **RBAC** roles: Owner, Security Admin, Collector Operator (nodes, credentials, policies), Analyst, Auditor (read plus audit export), Developer (repos only).
  - **ABAC** scope by asset group or BU tag, enforced in the query layer and in every export path, including CBOM, PDF and SIEM.
  - An **immutable audit log** exported to SIEM; the WP11 syslog and HEC connectors already exist.

---

## Part D: recommendation

### Target architecture (one picture)

```
   Customer estate                                          ZeroShield (SaaS or on-prem edition)
 ┌───────────────────────────────────────────┐          ┌─────────────────────────────────────────┐
 │ Targets: servers, K8s, DBs, HSM, network  │          │ Inventory (targets + tags)  ◄── cloud APIs, CMDB sync, AD,
 │                                           │          │                                 K8s operator, agents, SCM apps
 │ Transports (customer-trusted):            │          │ Collection policies (selector→method→tier→window→cred profile)
 │  SSM / Azure RunCmd / Intune / Ansible ───┼─ S3/HTTPS┤ Scheduler → jobs per target batch → node group (any node)
 │  zs-collect (signed single binary)        │          │ Node API: heartbeat+claim (long-poll), signed, mTLS rotate
 │  Scan node group (agentless; SSH CA/vault)┼─ HTTPS ─►│ Ingest → classify (offline KB) → asset state + observations
 │  K8s operator (own read-only SA)          │ outbound │ Dedup/identity → drift → CBOM 1.6 / reports / RBI-CERT-In map
 │  Host agent (pkg, self-update, attested)  │  only    │ SSO/SCIM, RBAC+ABAC, audit → SIEM; ServiceNow/Jira
 └───────────────────────────────────────────┘          │ SCM: GitHub App / GitLab group / BB / ADO → fair repo queue
                                                        └─────────────────────────────────────────┘
```

### Increments

Each increment is about 3-6 weeks for a small team (inference). The scale targets are **targets to prove with `load_testing/` and `bench/`**, not current facts.

**Increment 0: make the hot path cheap (do first; low risk, unblocks everything)**
- **Scope:**
  - Merge claim into heartbeat or add a long-poll, with jitter.
  - Replace the per-request nonce INSERT with an in-memory, Redis or monotonic-counter check.
  - Move reap to the background worker; it already runs in the cloud worker.
  - Make `recompute_run` incremental.
  - Run jobs per target batch on node groups.
  - Partition observations and add retention.
  - Move the rate limiter to a shared store.
  - Raise caps only after tests pass.
- **Acceptance:**
  - A synthetic fleet of **10,000 agents at a 60 s heartbeat** has p99 API latency under 300 ms and DB CPU under 50%.
  - A **10,000-job run** spends under 5 minutes in scheduling overhead.
  - No job is lost or double-run under random node kills and restarts, and leases recover in 15 minutes or less.
  - Nonce replay is still refused.
- **Risks:** a protocol change for deployed nodes. Keep the old endpoints until nodes upgrade, gated by `X-ZS-Deployment` and version.

**Increment 1: enterprise identity and scoping (deal-blocker for BFSI)**
- **Scope:** OIDC and SAML SSO (Azure AD/Entra, Okta, Keycloak for on-prem), SCIM 2.0, the roles above, asset-group or BU scoping, and audit export.
- **Acceptance:**
  - A SCIM deprovision revokes access within 5 minutes.
  - A BU-scoped analyst gets 403 or empty results on other BUs' assets in the API, UI, CBOM export, PDF and SIEM feed. This is automated in tests.
  - Every write is audited with who, what and before/after values.
- **Risks:** scope leaks through export paths; test every path.

**Increment 2: repositories at scale**
- **Scope:**
  - GitHub App (cloud and GHES), GitLab group, Bitbucket and Azure DevOps.
  - Webhooks with a polling fallback.
  - The repo registry, a fair-share priority queue, per-file blob caching and diff scans plus a weekly full scan.
  - A per-repo annual credit or licence model in place of per-scan estimates.
- **Acceptance:**
  - **5,000 repos discovered and registered in under 1 hour**, which is about 50 list calls and so well within limits.
  - **First baseline of all 5,000 within 24 hours** with a stated worker count. Example: at about 2 worker-minutes per repo, that is 10,000 worker-minutes, so about 7 workers for 24 h or 50 workers for 3.3 h.
  - **Incremental results within 2 minutes p90 per push** for diffs under 500 files.
  - API use stays under 50% of the installation quota.
  - A new repo created in the org is scanned within 15 minutes.
- **Risks:**
  - Diff scans miss cross-file context; mitigate with the weekly full scan.
  - Large monorepos; mitigate with sharding and size caps.
  - The customer's GitHub plan limits.

**Increment 3: inventory-driven auto-onboarding and credentials without per-target secrets**
- **Scope:**
  - A target inventory from cloud APIs (including all org accounts in parallel, past the 200-account cap), CMDB sync, AD, the K8s operator and agents.
  - Collection policies and credential profiles.
  - A built-in SSH CA, plus Vault SSH and Teleport adapters.
  - CyberArk and Azure Key Vault.
  - IAM DB auth where supported.
- **Acceptance:**
  - A new EC2 instance tagged `env=prod` appears in inventory within 15 minutes and is collected in its next window with **no human action**.
  - **Zero per-target secrets typed** for a 2,000-server lab.
  - K8s clusters self-register with no kubeconfig upload.
  - The coverage report balances: known = collected + failed + excluded.
- **Risks:**
  - Policy mistakes scanning the wrong things; mitigate with a dry-run "would collect" preview, never-scan lists (existing) and change windows.
  - The SSH CA becomes a high-value key; keep it on the node, in an HSM if available, with short TTLs.

**Increment 4: reach through customer control planes**
- **Scope:**
  - `zs-collect`, a signed single binary or bundle with a JSON output contract.
  - An SSM document and State Manager association.
  - Azure Run Command for VMs and Arc.
  - An Intune remediation package.
  - An Ansible collection.
  - Ingest from the customer's S3 or blob storage, or through the scan node.
- **Acceptance:**
  - **2,000 EC2 instances collected via SSM** at `max-concurrency 10%`, with no SSH keys, and results identical to the SSH path (a parity test on the same hosts).
  - The binary's hash is verified before it runs.
  - A collection run stays under one core-minute on a typical host (target).
- **Risks:**
  - Running as root or LocalSystem through the customer tool; mitigate with a published, reviewable read-only command set and signatures.
  - Azure Arc Run Command maturity.

**Increment 5: packaged host agent v2 (only after 0-4)**
- **Scope:**
  - deb, rpm and msi packages.
  - Signed self-update with a manifest, rollout rings and auto-halt.
  - Cloud-attested enrolment (AWS IID, Azure attested data, GCP token) and an approval queue.
  - Automatic mTLS certificate rotation.
  - CPU and IO caps (cgroup or nice on Linux, job objects on Windows).
- **Acceptance:**
  - **10,000 agents, 60 s heartbeat**, with an upgrade going 1% → 10% → 100% that halts automatically above a 2% failure rate.
  - Agent average CPU under 1%, with a collection capped at 10% of one core (target).
  - A replayed IID is refused.
- **Risks:**
  - Windows and legacy Unix support costs.
  - Python packaging size and AV false positives. Start with PyInstaller for Linux and decide on a Go rewrite only with evidence.

**Increment 6 (in parallel, cheap): ingest others.** Import CycloneDX CBOMs for infra (code upload exists), Qualys and Tenable TLS findings, and later CrowdStrike, Tanium or XDR results. Acceptance: an imported asset dedups against a native one on fingerprint, and its evidence shows both sources.

### Build vs. integrate

| Build (core, differentiating) | Integrate (do not own) |
|---|---|
| Read-only collectors and `zs-collect`, offline KB and classifier, evidence and drift, CBOM 1.6 | Remote execution: SSM, Azure Run Command, Intune, Ansible, Tanium, XDR |
| Inventory, policies, credential profiles, node groups, lean node API | Secrets: Vault, CyberArk, AWS, Azure and GCP secret stores; SSH CA through Vault or Teleport where present |
| SCM apps, repo queue, incremental and caching layer | Identity: customer IdP over SAML, OIDC and SCIM |
| RBAC/ABAC, audit, India regulatory mappings and reports | CMDB (ServiceNow), SIEM, ITSM (WP11 exists); Qualys and Tenable TLS data; other vendors' CBOMs |

### What NOT to build (brutally honest)

- **No bundled Salt, Puppet, Chef or any general remote-execution fabric.** It is the opposite of read-only, a CVE magnet, and a procurement blocker.
- **No Kafka or microservice rewrite.** About 200 req/s does not need it, and air-gapped customers would have to run it. No custom time-series database.
- **No passive network DPI sensor** (taps or SPAN). CipherInsights (Keyfactor) and Palo Alto's NGFW own this; import their data instead.
- **No certificate lifecycle or renewal automation.** That is Venafi (now Palo Alto), Keyfactor and DigiCert territory. Integrate and hand over findings.
- **No kernel or eBPF runtime tracer and no EDR-like always-on agent** for now (like AQG's Java tracer). The cost and support burden are high for the buyer's question, "what crypto do I have and where".
- **No home-grown IdP, vault or PKI product.** Use the customer's.
- **No chasing Wiz on cloud breadth.** Be the sovereign, on-prem and India-regulated option, and read the cloud through the roles you already have.
- **No AI in the classification path.** "Deterministic, offline, explainable" is a selling point.
- **No more per-scan credit estimates for fleets.** Enterprise buyers need predictable annual per-asset pricing (inference; see open decision 1).

### Open decisions for the owner

1. **Pricing model:** keep per-run credits, or move to an annual per-asset or per-repo licence for fleets?
2. **Credentials:** keep accepting raw credentials into SaaS, or make SaaS vault-reference-only with raw credentials allowed only in the on-prem edition?
3. **Agent language:** a PyInstaller bundle of the existing Python, or a Go rewrite of the host collector?
4. **Which control plane first:** AWS SSM or Intune/Azure, based on the first three target customers' estates?
5. **Tenancy:** offer a dedicated single-tenant SaaS for banks, and at what price floor?
6. **Partnerships:** pursue CrowdStrike, Tanium or Palo Alto marketplaces now, or after Increment 4?

---

## Sources (accessed 2026-11-11 unless noted; publication date in brackets where the source gave one)

**Market**
- IBM Quantum Safe suite launch, Quantum Computing Report [2026-10-31]: https://quantumcomputingreport.com/ibm-launches-unified-quantum-safe-software-suite-to-automate-enterprise-pqc-migration/amp/
- IBM Guardium Cryptography Manager data sheet (CDW): https://webobjects2.cdw.com/is/content/CDW/cdw/on-domain-cdw/brands/ibm/ibm-guardium-cryptography-manager-data-sheet.pdf
- AQtive Guard sensors: https://docs.aqtiveguard.com/aqtive-guard-sensors
- AQtive Guard CrowdStrike integration (original release): https://aqtiveguard.sandboxaq.com/docs/integrations/crowdstrike/
- AQtive Guard Tanium integration: https://aqtiveguard.sandboxaq.com/docs/integrations/tanium/getting-started/
- AQtive Guard for Falcon (CrowdStrike Marketplace): https://marketplace.crowdstrike.com/listings/sandboxaq-aqtive-guard-for-falcon/
- AQtive Guard on AWS Marketplace (USD 250k / 12 months): https://aws.amazon.com/marketplace/pp/prodview-ccwrhqfeekqwk
- Keyfactor AgileSec sensors architecture (3.5): https://docs.keyfactor.com/agilesec/3.5/sensors-architecture-and-overview
- Keyfactor AgileSec Tanium module: https://docs.keyfactor.com/agilesec/latest/isg-tanium
- AgileSec Analytics on CrowdStrike Marketplace: https://marketplace.crowdstrike.com/listings/infosec-global-agilesec-analytics/
- Keyfactor acquires InfoSec Global and CipherInsights [2025-05-14]: https://thequantuminsider.com/2025/05/14/keyfactor-acquires-infosec-global-and-cipherinsights-for-quantum-safe-security-expansion/
- CipherInsights 11.0 [2024-07-10]: https://www.helpnetsecurity.com/2024/07/10/quantum-xchange-cipherinsights-11-0/
- CyberArk discovery announcements [2025-10-07]: https://www.businesswire.com/news/home/20251007133485/en/cyberark-expands-machine-identity-security-portfolio-with-advanced-discovery-and-context-capabilities-enabling-enhanced-visibility-and-control
- Palo Alto Networks completes CyberArk acquisition [2026-02-11]: https://paloaltonetworks.com/company/press/2026/palo-alto-networks-completes-acquisition-of-cyberark-to-secure-the-ai-era
- Venafi VSatellites in Palo Alto Networks docs: https://docs.paloaltonetworks.com/content/techdocs/en_US/next-gen-trust-security/next-gen-trust-security/about-vaas/c-VSatellite-Management-about.html
- Palo Alto Networks Quantum-Safe Security [2026-01-27; GA 2026-01-30]: https://www.paloaltonetworks.com/blog/?p=351472
- Entrust CBOM capabilities [2026-09-15]: https://thequantuminsider.com/2026/09/15/entrust-adds-cbom-capabilities-cryptographic-security-platform/
- DigiCert TLM discovery architecture: https://docs.digicert.com/en/trust-lifecycle-manager/get-started/trust-architecture-playbook/baseline-pillar/discovery-overview-and-architecture.html
- DigiCert Crypto Discovery data sheet: https://www.digicert.com/content/dam/digicert/pdfs/datasheet/digicert-crypto-discovery-datasheet-en.pdf
- AppViewX Quantum Trust Hub [2026-10-29]: https://cybersecuritynews.com/appviewx-expands-quantum-trust-hub-with-cryptographic-discovery-posture-management-and-remediation/amp/
- QuSecure discovery and inventory: https://www.qusecure.com/quprotect/cryptographic-discovery-and-inventory/
- TYCHON / ECS Army case study [2026-01-08]: https://ecstech.com/ecs-insight/case-study/modernizing-army-cyber-defense-for-the-post-quantum-era
- TYCHON Cortex XDR deployment docs: https://tychonpqcdocs.pages.dev/palo-alto-xdr-deployment
- TYCHON on Carahsoft: https://www.carahsoft.com/tychon
- Thales PQC discovery solution brief: https://cpl.thalesgroup.com/sites/default/files/content/solution_briefs/post-quantum-cryptography-discovery-sb.pdf
- PQShield UltraPQ: https://pqshield.com/ultrapq-suite-from-a-leading-quantum-security-company/
- Wiz for PQC Readiness [2026-05-18]: https://wiz.io/blog/wiz-for-pqc-readiness
- Qualys CertView PQC details: https://docs.qualys.com/en/certview/latest/assets_certificates/pqc_details.htm
- IBM donates CBOM toolset to the Linux Foundation (undated page): https://researcher.ibm.com/blog/cryptographic-cbom-linux-foundation
- sonar-cryptography: https://github.com/PQCA/sonar-cryptography
- CBOMkit-theia: https://github.com/cbomkit/cbomkit-theia

**India regulation**
- RBI Q-SAFE committee press release [2026-05-25]: https://www.rbi.org.in/scripts/BS_PressReleaseDisplay.aspx?prid=62803
- CERT-In BOM guidelines v2, AZB & Partners [2025-09-30; guidelines dated 2025-07-09]: https://www.azbpartners.com/bank/cert-ins-technical-guidelines-on-sbom-qbom-and-cbom-aibom-and-hbom/

**Fleet technology**
- Salt 3006.12 release notes (CVE list): https://docs.saltproject.io/en/3006/topics/releases/3006.12.html
- SUSE on CVE-2025-22240: https://www.suse.com/security/cve/CVE-2025-22240
- Tenable on CVE-2020-11651/11652 [2020-05]: https://www.tenable.com/blog/cve-2020-11651-cve-2020-11652-critical-salt-framework-vulnerabilities-exploited-in-the-wild
- Salt package repository migration [2024-10-28]: https://saltproject.io/blog/salt-project-package-repo-migration-and-guidance/
- Puppet to OpenVox transition, NC State [2025-07]: https://linux.ncsu.edu/news/2025/07/puppet-to-openvox-transition/
- AWX modernization thread [2026-01-20 to 2026-04-01]: https://forum.ansible.com/t/awx-modernization-moving-forward/45134
- osquery remote enrollment: https://osquery.readthedocs.io/en/stable/deployment/remote/
- Wazuh password enrollment: https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/using-password-authentication.html
- Qualys Cloud Agent tuning [2023-07-06]: https://blog.qualys.com/product-tech/2023/07/06/qualys-performance-tuning-series-qualys-cloud-agent-configuration-best-practice
- SPIRE configuration (node attestors): https://spiffe.io/docs/latest/deploying/configuring/
- AWS: verify the instance identity document: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-iid.html
- Azure IMDS attested data: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
- GCP: verify VM identity: https://docs.cloud.google.com/compute/docs/instances/verifying-instance-identity
- AWS SSM: run commands at scale: https://docs.aws.amazon.com/systems-manager/latest/userguide/send-commands-multiple.html
- Azure Arc Run Command (doc updated 2025-08-20): https://learn.microsoft.com/en-us/azure/azure-arc/servers/cloud-native/scripting-task-automation
- HashiCorp Vault SSH secrets engine API: https://developer.hashicorp.com/vault/api-docs/v1.16.x/secret/ssh
- Teleport Machine ID SSH guide (full text not retrievable; cited for the pattern only): https://goteleport.com/docs/machine-workload-identity/machine-id/access-guides/ssh

**Repositories**
- GitHub REST rate limits: https://docs.github.com/en/enterprise-cloud@latest/rest/overview/rate-limits-for-the-rest-api
- GitHub default setup at scale (GHES 3.17): https://docs.github.com/en/enterprise-server@3.17/code-security/how-tos/secure-at-scale/configure-organization-security/configure-specific-tools/configuring-default-setup-for-code-scanning-at-scale
- GitLab group access tokens: https://docs.gitlab.com/user/group/settings/group_access_tokens/
- Semgrep Managed Scans: https://docs.semgrep.dev/deployment/managed-scanning/overview
- Snyk API import tool: https://docs.snyk.io/scan-with-snyk/snyk-tools/tool-snyk-api-import

**Not verified (flagged in text)**
- Current GA status of Azure Arc Run Command.
- GCP OS Config details.
- Bitbucket and Azure DevOps org-integration specifics.
- Entrust discovery mechanics.
- QuSecure pricing.
- Per-engine IAM database authentication support.
