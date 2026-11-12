# CBOM scan node and collectors: design (Phase 2 plan)

Repo: /home/claude/devsecshield, branch `ansh`. Existing platform (built and tested this session):
backend/routers/cbom_sources.py, backend/routers/cbom_node.py, backend/utilities/cbom_sources/*,
frontend/components/cbom/sources/*. Collect jobs are created by `POST /{team}/cbom/sources/runs`;
a node claims them via `/cbom/node/jobs/claim` (payload: job, scope, source{kind,config,secrets}) and
posts `/cbom/node/jobs/{id}/result` (256 KB cap). Today only a fake node exists (results are dummy).

## Current behaviour (evidence)
- kinds.py: aws_account/azure/gcp/idp: needs_node=never, collectable=never -> plan says "not available yet".
  ca_connector: only provider=adcs is collectable (via node). network_range, servers, kubernetes, database collectable via node.
- jobs.finish_job stores the node's `result` JSON on the job (scrubbed of known secrets and PEM private keys).
  Nothing turns results into an inventory; the UI shows only job counts.
- Test jobs: `_test_result_from_job` reads `result.samples[]` (status ready|ok|passed counts as ready).
  UI BAD statuses: failed, failure, error, no_route, unreachable, host_key_changed, login_failed, auth_failed, timeout, refused.
- Node contract from the UI install command: env ZS_API_URL, ZS_REGISTRATION_TOKEN, HTTPS_PROXY; volume /var/lib/zs-node.
- templates.py shows customers the exact Tier 1 / Tier 2 commands and a sudoers file (exact command lines).
  Tier 2 includes `find /proc -maxdepth 2 -name exe -exec readlink {} +` which prints targets WITHOUT pids
  (misaligned when a readlink fails) -> must change to `-printf`.

## New components
1. `scan_node/` (repo root): Python 3.12 package `zs_scan_node` + Dockerfile + README.
   - Loop: enroll once (persist node token + generated ed25519 SSH key in /var/lib/zs-node, 0600), heartbeat every
     30 s in a thread (honours cancel_job_ids and stop_all_network), claim -> run job in a worker thread with
     a per-job deadline, post assets in batches, post final result. Exponential backoff on API errors.
   - Never logs secrets; secrets live only in memory for the job.
   - Collectors:
     * linux_ssh (paramiko): Tier 1 commands as the login user; Tier 2 via `sudo -n` exact allowlisted lines.
       Facts: OS, FIPS, crypto-policy, packages of crypto libs (+EOL flags), openssl version, sshd effective config,
       SSH host keys (ssh-keygen -l), listening sockets -> processes -> crypto libs (maps) and exe, dm-crypt and LUKS,
       key/cert/keystore files (paths; cert metadata via `openssl x509 -noout -text`; public half of readable keys via
       `openssl pkey -pubout`; keystores via `keytool -list` when a JRE exists). Host key: TOFU per source in the volume,
       or pinned known_hosts; mismatch => host_key_changed, target skipped.
       Credential types: node_key (node's own key), ssh_cert (private_key + certificate), password, vault
       (HashiCorp KV v2 via node env VAULT_ADDR/VAULT_TOKEN; AWS Secrets Manager via the node's IAM role).
     * windows_winrm (pywinrm, HTTPS 5986): read-only PowerShell: cert stores, SCHANNEL protocol registry, TLS cipher
       suites, BitLocker status, RDP security layer. Not testable locally (validated in the AWS lab).
     * kubernetes (httpx to the API server, token or client cert from kubeconfig, CA pinned): version, nodes,
       API-server TLS, ingress TLS, cert-manager Certificates, Istio mTLS mode, configmap CA bundles; Tier 2 adds
       kubernetes.io/tls Secrets: only tls.crt is parsed, tls.key is discarded in memory and never sent.
     * database: postgres (psycopg), mysql (PyMySQL), redis, mongodb: TLS settings, auth/hash methods, live connection
       TLS, at-rest encryption hints, plus a TLS probe of the port (STARTTLS for postgres/mysql). mssql/oracle: not
       collectable yet (plan says so).
     * network (own prober, no sslyze): per endpoint a prioritised list of handshakes capped by
       handshakes_per_endpoint: raw ClientHello per version (SSL3, TLS1.0, 1.1, 1.2, 1.3), full handshake via
       `openssl s_client -brief` (cipher, group, peer signature type, certificate), PQ group probe (TLS1.3 HRR with
       X25519MLKEM768 only), TLS_FALLBACK_SCSV downgrade probe, weak-cipher-class probes (RC4/3DES/NULL/EXPORT,
       static-RSA, CBC). Fragile mode: versions + one full handshake only. STARTTLS: smtp, imap, ldap, postgres,
       mysql. SSH: banner + KEXINIT algorithm lists. RDP: negotiation (selected protocol) + TLS. TDS: prelogin
       encryption flag. IKE: not supported yet (reported, not silent).
       Rate limits: global token bucket (connections_per_second), per-IP semaphore (parallel_per_server),
       never_scan re-checked on the node before each connection, stop_all_network checked between endpoints.
     * discovery: TCP connect sweep over ranges x ports with the same limits; returns open endpoints (capped 5,000).
2. Backend
   - New table `cbomcollectedasset` (team_id, run_id, job_id, source_id, asset_type, asset_key unique per job,
     location, name, algorithm, key_size, protocol, quantum_vulnerable, severity, finding, data JSON, created_at)
     + Alembic migration.
   - `POST /cbom/node/jobs/{id}/assets` {lease_id, assets[<=500]} (body cap 1 MB, per-job cap 50,000 assets),
     lease-checked like /result; assets validated, scrubbed (PEM private keys, known secrets), classified server-side
     (`classify.py`: quantum-vulnerable public-key algorithms, weak protocols/ciphers/hashes/key sizes, expiry,
     EOL libraries) so rules are central.
   - Node-less collection (aws_account, idp) by a server-side worker `python -m backend.workers.cbom_cloud_worker`:
     claims `collect` jobs with node_id NULL using the same guarded UPDATE + lease, renews its own lease, writes assets
     directly. AWS: AssumeRole with the team's external ID (supports CBOM_AWS_SESSION_TOKEN), per-region reads of KMS,
     ACM, ACM PCA, Secrets Manager (metadata), S3 encryption + TLS-only policy, EBS defaults/volumes, RDS, ELBv2
     listeners + SSL policies, CloudFront, API Gateway domain TLS policy, IAM server certs + SAML/OIDC providers,
     EKS secrets encryption. Hard caps and deadline. IdP: OIDC discovery/JWKS and SAML metadata (defusedxml), with
     an SSRF guard (https only, public IPs only unless CBOM_ALLOW_PRIVATE_FETCH=1, no redirects to private, 1 MB cap).
   - kinds.py: aws_account collectable; idp collectable (node-less); ca_connector not collectable (AWS Private CA comes
     through the AWS account); database collectable only for postgres/mysql/redis/mongodb.
   - Reaper/claim: node-less jobs must not be claimable by nodes and must be reaped like others.
   - Team routes: `GET /{team}/cbom/sources/runs/{run_id}/assets` (filters, paging, facets) and
     `GET /{team}/cbom/sources/runs/{run_id}/cbom` (CycloneDX 1.6 cryptographic-asset export).
   - templates.py: Tier 1 list = exactly what the node runs; sudoers exe line uses `-printf`. A test asserts the
     node's command constants equal the backend's displayed lists.
3. Frontend: Review & Run gets "View results" per run: summary by source, per-target errors, asset table with
   filters (type, severity, quantum-vulnerable), and "Download CBOM". Sidebar run card links to it.
   Cloud & Identity text "Cloud collection is not available yet" removed for AWS; still shown for Azure/GCP.

## Local lab (Docker in the workspace) with ground truth
Linux SSH hosts (ubuntu 22.04 with zs-cbom user, sudoers, planted certs/keys/keystores, nginx with libssl, LUKS-like
dm table not possible in containers -> recorded as not present), legacy sshd, TLS zoo (nginx variants incl. TLS1.0,
weak ciphers, RSA-1024, expired, self-signed, PQ hybrid if available), STARTTLS SMTP, Postgres 16 with TLS + md5 HBA
rule, MySQL 8 with TLS, Redis TLS, MongoDB TLS, k3s with cert-manager-like TLS secrets and RBAC tier1/tier2,
OIDC/SAML metadata over HTTPS, HashiCorp Vault dev. AWS: live with short-lived keys from the user.

## Risks
- Scope: Windows/AD untestable locally; IKE not supported; mssql/oracle not collected.
- sudoers escaping of `-printf` and `-regex` args must be proven with real sudo.
- Raw TLS ClientHello parsing must tolerate hostile servers (length checks, timeouts, size caps).
- SSRF from server-side IdP fetches.
- Secrets: kubeconfig/DB passwords in node memory; tls.key in K8s secret responses.
- Credits: AWS now charged 4/account; must match plan text and estimate.
