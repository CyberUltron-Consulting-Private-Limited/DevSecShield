# Accepted design after 5 reviews + devil's advocate (binding contract)

Owners: backend + UI = main session. `scan_node/` package = fork A. Lab targets = fork B.
Repo /home/claude/devsecshield (branch ansh). Never `git add -A`; main session commits.

## Node <-> server protocol (all JSON, header X-ZS-Node-Token; node also sends X-ZS-Job: <job>/<attempt> on job calls)
Enroll/heartbeat/claim/result exist (backend/routers/cbom_node.py). Changes:

Heartbeat request adds `running: [{"job_id": int, "lease_id": str}]` (jobs the node is executing right now).
  Server renews ONLY those leases. A claimed job of this node not reported for >120 s after claim is released
  (attempts<3 -> pending, else failure+refund). If `running` is absent (old node) the old renew-all behaviour stays.
Heartbeat response adds: `cancel_job_ids` (stop-all network, run cancelled, source changed/disabled/moved/deleted,
  window closed), `never_scan` (team list, apply live), `stop_all_network`.

Claim payload: unchanged keys plus `scope.window_ends_at` (ISO-8601 Z or null) and `scope.max_runtime_s`.
  Servers scope: `targets` (normalized lines) + `never_scan`. The node expands CIDRs/ranges, de-duplicates by IP,
  resolves hostnames and skips any whose resolved IP is in never_scan, connects to the checked IP.

NEW `POST /cbom/node/jobs/{job_id}/assets` body (<=1 MB, <=500 assets):
  {"lease_id": str, "batch_id": str<=64, "assets": [Asset]}
  Response: {"accepted": n, "duplicate": n, "rejected": n, "total_for_attempt": n, "cap_reached": bool}
  409 if the job is no longer leased to this node or the source became invalid (node must abort the job).
Asset (node sends facts only; the server classifies):
  {"type": str, "target": str<=255, "location": str<=512, "name": str<=255,
   "algorithm": str<=64|null, "key_size": int|null, "protocol": str<=32|null, "facts": object (<=16 KB JSON)}
  Types: certificate, private_key, public_key, keystore, ssh_host_key, ssh_server_config, ssh_endpoint,
  tls_endpoint, crypto_library, process_library, disk_encryption, os_crypto_policy, database_tls,
  database_config, database_user_auth, k8s_cluster, k8s_tls_secret, k8s_certificate, k8s_ingress_tls,
  k8s_mesh_policy, kms_key, cloud_secret, storage_encryption, load_balancer_tls, cdn_tls, api_tls,
  cloud_ca, iam_certificate, identity_provider, signing_key, open_port, coverage.
  `coverage` assets record what could NOT be read (facts: {"check": "...", "status": "denied|not_installed|
  not_supported|error|truncated", "detail": "..."}), so gaps are visible, never silent.
  Certificates: facts {subject, issuer, serial, not_before, not_after (ISO Z), sig_alg, key_alg, key_size|curve,
  san:[...], is_ca, self_signed, fingerprint_sha256, source:"file|tls|k8s|aws|idp"}. Never send private key bytes,
  secret values, passwords or tokens. The node scrubs the secrets it holds from every string before sending.
Result body: {"lease_id", "status": "success|failure|cancelled", "error": str|null,
  "result": {"summary": str, "counts": {"total","ok","failed","skipped"}, "asset_count": int,
             "targets": [{"target","status","error","duration_ms","assets"}] (<=1000; rest summarised),
             "truncated": bool, "duration_s": int, "node_version": str}}
  Target status enum (shared): ok | unreachable | refused | timeout | no_route | auth_failed | mfa_required |
  host_key_changed | sudoers_missing | sudo_denied | tls_unavailable | not_supported | error |
  skipped_never_scan | skipped_window | skipped_stop | skipped_deadline | skipped_cancelled.
  Test jobs keep `result.samples: [{target, status ("ready" when ok), reachable, login, privilege, note}]`.
Server computes job outcome ok/partial/failed from counts and asset_count vs stored count.

## Refund policy (one rule, every path)
A collect job that ends failure, cancelled or expired is refunded in full. success (incl. partial) is charged.

## Linux commands (exact; shown to customers; equality test against ServersTab.tsx list and SUDOERS)
Tier 1 (login user, no sudo, stdin </dev/null, per-command timeout, output cap 4 MB):
  cat /etc/os-release ; uname -r ; (dpkg-query -W -f '${Package}\t${Version}\n' | rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n') ;
  cat /etc/crypto-policies/config ; cat /proc/sys/crypto/fips_enabled ; openssl version -a ; cat /etc/ssh/sshd_config ;
  ssh-keygen -l -f /etc/ssh/ssh_host_<type>_key.pub ; ps -eo pid=,comm= ;
  openssl storeutl -noout -text -certs <file> ; openssl pkey -pubout -passin pass: -in <file> ;
  grep -c 'PRIVATE KEY-----' <file> ; keytool -list -v -keystore <file> -storepass:env ZS_EMPTY (empty) .
  Every <file> is shlex-quoted, must be an absolute path without control characters, and comes only from the Tier 2 find.
Tier 2 (sudo -n, exact lines; sudoers ships /usr/bin and /bin variants): ss -H -tlnp ;
  find /proc -maxdepth 2 -name maps -exec grep -HE <libs> {} + ;
  find /proc -maxdepth 2 -name exe -printf %h\t%l\n   (replaces the readlink line) ;
  sshd -T ; dmsetup table --target crypt ; lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT ;
  find /etc /opt /srv /home /root /usr/local -xdev -type f -size -1024k -regextype posix-extended -regex <escaped dots>
  If sudo -n refuses a line: coverage asset {check, status: denied}; target status ok if Tier 1 worked (Tier 1 source)
  or sudo_denied if tier 2 was required and nothing ran.

## Kubernetes
Static token / client-cert kubeconfig only; CA from ca_pem else certificate-authority-data; insecure-skip-tls-verify
refused. Secrets read ONLY with fieldSelector=type=kubernetes.io/tls and paging; tls.key discarded unread; 403 ->
coverage denied (Tier 1 result kept); CRD 404 -> coverage not_installed.

## Databases
postgres, mysql, redis, mongodb collectable; mssql, oracle not collectable (plan reason). If require_tls and the
server has no TLS: finding + do not send credentials. Redis: CONFIG GET only explicit tls-* names (never
tls-key-file-pass / requirepass). MySQL: SELECT user, host, plugin, ssl_type FROM mysql.user only.

## AWS (server-side worker, node-less jobs)
`python -m backend.workers.cbom_cloud_worker`. Requires CBOM_AWS_ACCESS_KEY_ID/SECRET(/SESSION_TOKEN) (no ambient
creds). Collect only if last_test_status == passed. Before collecting: AssumeRole WITHOUT ExternalId must fail;
GetCallerIdentity account == role ARN account. Re-assume before expiry. Coverage asset per service/region on
AccessDenied/opt-in disabled/throttle. Global services once.

## IdP (server-side worker, node-less)
OIDC discovery/JWKS, SAML metadata (defusedxml). Fetch: https only, resolve + reject non-public IPs (incl. mapped,
CGNAT, link-local, ULA) unless CBOM_LAB_ALLOW_PRIVATE_FETCH=1 (lab only, warns), connect to the checked IP, no
proxy, <=3 redirects each re-checked, 1 MB cap, 10 s.

## Not collectable (honest plan reasons): active_directory, ca_connector (AWS Private CA comes via AWS), azure, gcp,
mssql, oracle. Open jobs for them are cancelled + refunded at claim.
