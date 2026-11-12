# Round 5 plan: close every gap in the CBOM guide (rev 38)

Repo `/home/claude/devsecshield`, branch `ansh`, base `d91205a`. Scope chosen by the user: everything in the guide
(the 7 open items, the known issues and smaller open points, the air-gap limits, and the 21 partial/not-built
architecture capabilities). Decisions already taken: Lambda/Glue reading is an opt-in in the reader template and is
proven in a small AWS lab (destroyed after); passwords move to Argon2id with a 128-character limit; staging gets a
production deploy in the repo that the user runs.

Evidence references are file:line at `d91205a` from five read-only maps (backend auth/API, collectors + scan node,
engine + outputs, code-scan engine + corpus, frontend + deploy).

Confidence: H = proven by reading code/logs, M = strong inference, L = needs a test to confirm.

---------------------------------------------------------------------------------------------------------------------
## A. Fixes (open items, known issues, smaller points)

### A1. Sign-in codes (Critical) — H
Evidence: `backend/utilities/auth/auth_utils.py:360-365` maps two emails to one fixed code that never expires; it is
accepted by login (`routers/auth.py:130`), signup (`:60`) and **reset_password (`:292`), where it is the only factor**:
account takeover for anyone who reads the source. Five tracked `.skill-workspace/prod_loadtest_30*.py` hold the
prod host + one of those emails + its password + the code. `LOCAL_DEV_VERIFICATION_EMAIL/CODE` (`:357-377`) has no
production guard; the e2e suite depends on it.
Fix: delete the fixed-code dict and every branch using it. Keep the env dev code only when `DSS_DEV_MODE=1` is also
set, never for `/reset_password`, and log a warning at startup when active. Remove the five scripts from the index.
Tell the user to change the passwords of the two accounts (the code was public to anyone with repo access).
Risk: demos that relied on the fixed code now need the real email code (decision D1).

### A2. Passwords (High) — H
Evidence: `auth_schema.py:19,27,32` 5..24 chars; `auth_utils.py:29` bcrypt only (72-byte limit; bcrypt 4.3.0 truncates
silently); no rehash anywhere; admin create has no bounds (`routers/admin.py:16-27`) so an admin-made password > 24 can
never log in; invites use `random.choices` (`utilities/team/membership.py:15-16`); frontend has no length checks and a
422 shows "Validation error".
Fix: add `argon2-cffi` to `backend/pyproject.toml` + `uv.lock`; `CryptContext(schemes=["argon2","bcrypt"],
deprecated=["bcrypt"], argon2__type="ID", argon2__memory_cost=19456, argon2__time_cost=2, argon2__parallelism=1)`
(OWASP minimum; passlib's default 100 MiB × 9 workers × concurrent logins would exhaust RAM). Login uses
`verify_and_update` and stores the new hash. Limits: 8..128 characters and ≤ 512 UTF-8 bytes on signup/reset/admin;
login accepts 1..128 so every existing password still logs in. Invites use `secrets`. Frontend: same limits with clear
messages, `autocomplete`, `type="button"` on Send code. Hash work stays in the threadpool (admin path is on the event
loop today; move it).
Risk: Argon2 cost on the 2-vCPU box under load (bench it: 19 MiB, t=2 ≈ 30-60 ms).

### A3. Rate limits (High) — H
Evidence: 48 routes in scans/team/cicd/certin/dast_profiles/guardrails pass `dependencies=[Depends(limiter)]` as a
parameter (no-op). `fastapi-throttle` keeps counts in a per-process dict; gunicorn runs 9 workers, so real limits vary up
to 9×; key is `request.client.host`, which behind the proxy is the proxy for every user (`cbom_deliverables.py:17-21`
says so). Frontend polls scan status every 6 s and stops polling silently on 429. `cbom_sources/http.py:79-83` trusts
any `X-Forwarded-For` (enroll limiter bypass). CI calls use `cicd-api-key`.
Fix: one shared limiter module: fixed-window counters in Postgres (`INSERT … ON CONFLICT DO UPDATE … RETURNING count`,
old windows pruned) so limits are exact across workers and replicas; key = SHA-256 of the bearer token for user routes,
of `cicd-api-key` for CI routes, trusted client IP for anonymous routes. Trusted IP = peer address, and
`X-Forwarded-For` only when the peer is in `TRUSTED_PROXY_CIDRS` (also set gunicorn `forwarded_allow_ips` from it).
Move all 48 into decorators; set limits from measured client behaviour (status polling allowed at 1/s per user).
Frontend: 429 → back off and keep polling; single-flight token refresh. Tests: decorator presence for every route
(AST test), 429 path, limiter shared across two processes.
Risk: DB write per request (indexed upsert, ~1 ms); fallback to in-memory if DB is unavailable is NOT added (fail open
would hide outages; fail closed would block everything) — limiter errors are logged and the request proceeds.

### A4. Secrets in git (High) — H
Evidence: 15 tracked `.env` files, tracked `cu-devsecshield-key.pem`, no `.env`/`*.pem` rule in root `.gitignore`,
backend/worker `.dockerignore` don't exclude `.env` (baked into images), Mongo password inline in two compose files.
Fix: `.gitignore` + `.dockerignore` rules; `.env.example` per service generated from the code's `os.getenv` names (no
`.env` is opened); compose files read the Mongo URL from the environment. Untracking depends on decision D2.

### A5. The three unregistered scanners (Medium) — H
Evidence: `jvm_go/native/web_native_crypto_scan.py` are decorated but never imported; `AGENTS.md:62-90` and the kiro
spec say C2/C3 must extend `detect.py` tables and that `web_native` is the rejected branch; native and web_native
contradict each other (`AES-256-GCM` vs `AES-GCM`+keySize); 41 tests fail because they filter on properties only the
unregistered modules emit. Real product bug shown by one of them: JS `AES-256-GCM` and `AES-GCM` both emitted for one
call (also 8 of the lab's spurious duplicates).
Fix (root cause, follows the repo's own design rule): port what only these modules have into the registered path —
Go `aes.NewCipher`→`cipher.NewGCM/NewCBCEncrypter` mode binding, `KeyPairGenerator.initialize(n)` size binding, call-site
provenance properties, and sized/coarse de-duplication — then delete the three modules and rewrite their tests to assert
the same behaviour through `scan_crypto` on the same fixtures; update `baseline_counts.json`, `e2e/fixtures/expected.json`
(`unwired_scanner_modules`), AGENTS.md.

### A6. Lambda environments and Glue (opt-in) — H
Evidence: `templates.py:12-24, 260-330` (inline CFN, no Conditions; deny on `kms:Decrypt` blocks Lambda decrypting for
the caller); `aws_collect.py:341-366` reads env via ListFunctions; Glue not read; validator requires the deny
(`aws_validate.py:139-154`); UI text hard-coded (`CloudIdentityTab.tsx:965-985`).
Fix: CFN parameters `ReadLambdaEnvironment` and `ReadGlueConnections` (default `false`) with Conditions. When on:
the `kms:Decrypt` deny gains `Condition: StringNotEquals kms:ViaService lambda.<region>.amazonaws.com` (an explicit
deny cannot be overridden by an allow, so the deny is carved, not paired); Glue adds
`glue:GetConnections, glue:GetConnection` (+ `GetDataCatalogEncryptionSettings`, `GetSecurityConfigurations` if not in
SecurityAudit — check the managed policy). Collector: Glue always called with `HidePassword=True`; reports JDBC
`JDBC_ENFORCE_SSL`, inline password vs `SECRET_ID`, catalog/job encryption. Validator accepts the conditional deny.
Template endpoint/UI get the two switches and explain the trade-off. AWS lab proves: off → coverage rows, on → findings,
CloudTrail shows `Decrypt` only via Lambda and no password in any response.

### A7. PostgreSQL md5 roles — H/L
Evidence: node `database.py:172-174` reads `pg_authid` (superuser only) → coverage "denied" on every least-privilege
install, not only RDS; shipped grants (`templates.py:135-142`) don't help; AWS collector never reads RDS parameter groups.
Fix: collector tries, in order: `pg_authid` → a DBA-installed `zs_role_password_types()` SECURITY DEFINER function
(template provided; returns role + hash type only) → RDS `rds_tools.role_password_encryption_type()` (AWS-documented) →
coverage gap naming the exact one-line grant. AWS collector adds `describe_db_parameters` (`password_encryption`,
`rds.force_ssl`, `rds.accepted_password_auth_method`) and `PubliclyAccessible`. Lab proves which privileges the rds_tools
call needs (L).

### A8. Staging and deployment (High for usability) — H
Evidence: staging serves Turbopack dev chunks; nothing in the repo builds/deploys images; frontend image built without
`--build-arg` points at 127.0.0.1:9001; `frontend/.dockerignore` doesn't exclude `.env*`; backend image needs
`_migrations` populated; no TLS proxy config; scan-node image never published; Helm/AMI/OVA offered with nothing behind.
Fix: `deploy/staging/` (compose of production images incl. workers, Caddy or nginx TLS proxy for both hostnames,
`.env.example`), `scripts/deploy/staging.sh` (build → save → copy → load → up → health checks → hydration check),
GitHub workflow `deploy-staging.yml` (manual dispatch), scan-node `docker save` archive script, Helm chart for the node
(proven on k3s), AMI cloud-init path (agent reads `/etc/zs-node/env`), Packer files for AMI/OVA; UI only offers the
deployment modes that are proven, others marked "build it yourself".

### A9. Smaller open points — H
- Import notes: return `cbom_input` from `scan_metadata.py:238-256`; show it on the results page.
- Library end of life: `posture.py:173` passes the run date; the panel shows "as of this run" and, if different, "now".
- Clean inventory rows counted as Low: `normalize._impact_for` returns no impact for unflagged rows; dashboard
  (`scan.py:1220-1345`), PDF (`cbom_pdf.py:78-168`), list item, multi-scan dashboard, Mongo findings and Jira
  auto-tickets count only rows with finding codes.
- Mosca: merge with `exclude_unset` (`cbom_sources.py:881-882`); UI hides "Change" for non-admins.
- Node "unauthorized": server stamps a stable deployment id on every node response (incl. 401); node clears its token
  only when the 401 comes from the deployment it enrolled with; otherwise it backs off and reports "wrong server".
  401 during asset flush handled the same way.
- Self-signed SHA-1: keep not raising SIG_SHA1 for self-signed leaves, state why in the finding text; self-signed CA/IdP
  certs with SHA-1 get the same informational text.
- `evidence.occurrences` (and `cryptoProperties` where meaningful) for posture facts and library rows in the code-scan
  CycloneDX; fact line = attribute line, not block start. (Also lifts 12 lab items the scorer could not see.)
- Credits: a stored estimate is charged at start without checking what was estimated: record a digest of the estimated
  input + formula version; re-estimate at start when they differ. Minimum charge per D3.
- Pre-existing failing tests: fix test bugs (stale manifest literal, haproxy/tomcat endpoint labels, page-break-tolerant
  appendix regex, Mongo monkeypatch), make live tests skip cleanly (JWT secret from env, DB reachability before seeding),
  aibom weights pin, AIBOM goldens drift (investigate), optional-package tests skip when packages missing.
- Air gap: self-hosted Git hosts via `GIT_ALLOWED_HOSTS` in both the backend schema (`utilities/db/schemas.py:60-85`) and
  the worker (`scan_context.py:45-133`), clone URL rebuilt from the parsed host, `https` required unless the host is
  listed with `http://`; delete `RabbitMQ/worker/utils/repo_utils.py`. Private IdP metadata via operator-level
  `CBOM_IDP_ALLOWED_PRIVATE` (CIDRs/hosts) in API and cloud worker; loopback, link-local, metadata and CGNAT always blocked.
- Kubernetes: `mtls_mode` vs `mode` mismatch (classify never fires), DestinationRule in the wrong API group, ClusterRole
  over-grants.

---------------------------------------------------------------------------------------------------------------------
## B. Code-scan detection gaps (50 lab misses, 11 trap hits, 14 spurious)

Measured by the lab scorer on the crypto-zoo corpus (165 items without binaries) and the public-CBOM benchmark.
- Export visibility (12): solved by A9 occurrences/cryptoProperties.
- Cross-file constants (4): project-wide constant table pre-pass on `CbomScanContext`, fed to `detect_crypto`,
  `_JavaContext` (class-qualified `Algs.CIPHER`), `ast_crypto_scan._collect_consts`, misuse binding.
- Keys split or read from config (4): implicit bytes concatenation, `P1 + P2` constants, `.properties`/`.yaml` lookups.
- Encoded/derived key literals (4): `b64decode`, `bytes.fromhex`, key-length hex constants, hash-of-constant as key.
- Notebook (1): `.ipynb` virtual source with a cell→line map shared by all lanes.
- Nested zip (1): in-engine recursion with the same limits as upload extraction; paths `outer.zip!inner`.
- Custom XOR/Feistel (2): structural detectors (XOR loop over key bytes; Feistel swap round).
- Fernet (1), PowerShell `ConvertTo-SecureString -Key` (1), `.txt` sources with a code double extension (1).
- IaC: ELB policy catalogue complete (1), Helm `values.yaml` (1), Dockerfile EOL base images + pinned libs (1),
  Kubernetes Secret base64 keys parsed in memory (1), Ansible `validate_certs` (1), S3 provider-managed vs customer key
  (1), fact line attribution (2).
- Dependencies (3): advisories for pycrypto and cryptography 3.x, all `requirements*.txt`, Go pseudo-versions.
- MSSQL `EncryptByKey` resolves the key's `CREATE SYMMETRIC KEY … ALGORITHM` (1).
- Excluded directories (4): scan `vendor/`, `dist/`, `build/` and loose files at the top of `node_modules/`, labelled
  third-party/build output (packages under `node_modules/<pkg>/` stay skipped).
- Git history (1): when a `.git` directory is present (zip) or history depth is opted in (clone), scan blobs that look
  like key files across history.
- Submodule/LFS (2, not planted): report them as coverage rows.
- Trap hits (11): these are clean inventory rows (AES-GCM, Ed25519, scrypt…), which a CBOM must list; after A9 they
  carry no impact. The scorer must count a trap as hit only when the row is flagged (check how it decides today
  before changing anything; changing the measure needs a written justification in the evidence).
- Spurious (14): sized/coarse duplicates (A5), duplicate lines; inner hashes of composites become derived components
  (the public benchmark expects them: 23 SHA-2 pairs) without their own finding.
- Benchmark extras: binary OpenPGP keyrings (24 pairs), SecretKeySpec field defaults (8), interprocedural enum (4),
  SecureRandom (3).
Target: recall ≥ 0.95 on non-manual items, precision ≥ 0.95, every EVA technique ≥ 0.6, benchmark ≥ 0.80 raw.

---------------------------------------------------------------------------------------------------------------------
## C. Architecture capabilities (21)

| # | Capability | Build | Proof |
|---|---|---|---|
| C1 | CycloneDX XML | Serializer from the JSON model for code scans and node runs; `?format=xml`; UI choice | Validate against the official bom-1.6.xsd offline (lxml) |
| C2 | Versioned inventory, diff, drift, continuous re-scan, proof fixes landed | Diff endpoint by `(source_id, asset_key)` and finding codes; drift events; schedules executed by the cloud-worker tick with a system actor within scan windows; finding resolved-in-run tracking; code scans diff by repo/branch | Two runs with a change in between; scheduled run fires in window; UI compare |
| C3 | Internet exposure | Collectors emit `internet_facing` (ELB scheme, RDS public, EC2 public IP, CloudFront, API GW, EKS endpoint, global network IPs, DMZ segment), per-source override; risk multiplier | Unit + AWS lab |
| C4 | Owners, applications, data classification, SBOM link | Fields on sources (like business_criticality), `cbom-mapping.yaml` applied to crypto rows, purl on library rows linked to SBOM scans | API + UI |
| C5 | Remediation waves with owners | Assignment table, API, UI, rule-suggested wave, roadmap PDF fills Wave/Owner/Target | PDF text check |
| C6 | Heat-map and certificate calendar | Posture endpoint matrix + certificate list; hand-built components (no new libraries) | Browser |
| C7 | ServiceNow, SIEM/SOAR, GRC | ServiceNow Table API, syslog RFC 5424 + CEF (TCP/TLS/UDP), Splunk HEC, signed webhook, OSCAL assessment-results export | Local receivers on the internal network |
| C8 | CMDB import | CSV import + ServiceNow CMDB pull (`cmdb_ci_server`) seeding sources and metadata | Mock Table API |
| C9 | Signed payloads and mTLS | Ed25519 signature over every node body (key sent at enroll), mTLS at the proxy with verified header trusted only from the proxy, optional pinned client cert | nginx mTLS + node |
| C10 | Container image layers | Unpack `docker save`/OCI tars (upload) and registry v2 pulls (node) safely; dpkg/rpm/apk, Python, Java, Node, Go buildinfo, libssl versions | Image with old OpenSSL |
| C11 | Binaries and firmware | Constant signatures (AES/DES/SHA/MD5/Blowfish/ChaCha), ELF/PE imports, embedded keys/certs, version strings; firmware unpack (gzip/xz/lzma/tar/cpio/squashfs/uImage) with limits | Compiled samples + built firmware image |
| C12 | HSM PKCS#11 and KMIP | Node collectors: PKCS#11 object attributes (never values), KMIP Locate/GetAttributes over TLS | SoftHSM2; KMIP server container |
| C13 | Vault PKI/transit, internal CA | Vault mounts/issuers/roles/transit keys; ADCS over WinRM; EJBCA REST | Vault dev; ADCS in AWS lab; EJBCA if disk allows |
| C14 | IKE/VPN | UDP IKEv2 SA_INIT and IKEv1 main-mode proposal probing | strongSwan container |
| C15 | Appliance configs | Read-only SSH/API pull + parsers for Cisco IOS/ASA, FortiOS, PAN-OS, F5 | Vendor-format fixtures + simulated SSH appliance (labelled as simulated) |
| C16 | Service mesh mTLS | Istio PeerAuthentication/DestinationRule, Linkerd policy + trust roots | k3s with CRDs |
| C17 | Host agent / DaemonSet | Agent mode (collects its own host) + pool enrollment token; Helm DaemonSet | k3s |
| C18 | OT | OPC UA GetEndpoints security policies + cert, Modbus 502/802, forced fragile | asyncua/pymodbus servers |
| C19 | SQL Server, Oracle | python-tds / oracledb thin (pure Python): TLS, TDE, keys and certificates, password versions | Containers |
| C20 | Azure Key Vault, GCP KMS | Verify collectors | Real tenants or recorded responses (decision D4) |
| C21 | Posture dashboard roll-ups | (covered by C6, C2) | |

---------------------------------------------------------------------------------------------------------------------
## Execution
Work packages run as agents in separate worktrees (2 vCPU / 7 GB / 11 GB disk: at most 3 at once), each with its own
tests; I integrate one branch at a time, rebuild the knowledge base once per integration, run the suites, commit to
`ansh` with explicit pathspecs. Order: A1-A3 (security) → A5+B (engine) → A6/A7 → A8/A9 → C1-C6 → C9-C19 → C7/C8/C20.
Validation after integration: backend suites + extreme cases with logs; Playwright customer walkthrough (desktop, tablet,
mobile; Chromium and Firefox if installable offline) on a connected and an air-gapped stack with zero egress; small AWS
lab (RDS PostgreSQL, Lambda, Glue, optionally Windows ADCS) destroyed after; five adversarial reviews of the finished
work; independent verifier; guide + evidence.

## Decisions still needed from the user
D1 the two fixed-code accounts; D2 untracking secrets (teammates' `git pull` deletes their local copies);
D3 minimum charge for code scans; D4 Azure/GCP proof.

## Known limits that will remain
Live appliance devices, real HSM vendors, DigiCert/Sectigo/Venafi SaaS CA APIs and real OT devices cannot be proven
without the hardware/accounts; proofs use the open-source equivalents listed above and say so.
