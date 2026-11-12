# F1.4 SSH certificate authority: spec (builder, Nov 11)

Branch `feat/f1-ssh-ca` from `origin/dev` 3399452. Binding design: `$R6/f1/CONTRACT.md` (sections 2, 3, 5, 6, 7, 9).
Flag `CBOM_SSH_CA` (default off). Migration prefix `r6f14sshca`.

## Evidence gathered before the design (dev 3399452)
* Node identity: `cbomscannode.ssh_public_key` (Ed25519, `new_models.py:291`), `source_ips` (`local_ips()`,
  `scan_node/zs_scan_node/netutil.py:317`: interface addresses, so a node in Docker bridge mode reports 172.17.x.x,
  not the address its targets see). `mode` agent nodes never get credentials (`jobs.py:578`).
* SSH auth on the node: `linux_ssh._credentials` (:124) and `open_session` (:212-322) use paramiko 3.5.1
  `auth_publickey`; `PKey.load_certificate` already powers `ssh_cert`.
* Job checks: `jobs.connection_version` hashes the config **as the kind's model dumps it** (`jobs.py:258-277`), so any
  new ServersConfig field with a default would change the version of every existing Linux/Windows source and cancel
  their open jobs at deploy. New fields are therefore omitted from the dump unless `credential_type == "ssh_ca"`
  (a wrap serializer); a test pins the old dump.
* Source save validates with `KINDS[kind].model.model_validate` (`routers/cbom_sources.py:450`) and stored configs are
  re-validated by jobs/planning (`jobs.py:443`, `planning.py:182`).
* F1.1 (`feat/f1-node-api`, not merged yet) publishes `secret_refs.source_secrets(session, source, node, now)` which
  calls `sshca.claim.claim_extras(session, source, node, now, acc)` with no job argument, `authenticate_node`
  (alias `_authenticate` kept) and `jobs.leased_job`. F1.2-a0 (`feat/f1-inventory-scaffold`) creates
  `routers/cbom_fleet.py` with a `# F1.4 routers` marker and `fleet/flags.flagged_route`.

## Spike: paramiko host certificates (contract open question 5, section 9)
`$R6/f1-4/spike/spike_paramiko_hostcert.py` against a real OpenSSH 9.6 sshd with `HostCertificate`:
* default client order: paramiko negotiates the plain `ssh-ed25519` host key (cert types are listed after plain ones);
* with `key_types = ("ssh-ed25519-cert-v01@openssh.com", ...)` it negotiates the certificate and keeps the blob in
  `public_blob`, but **paramiko verifies only the kex signature; it does not check the CA signature, the type, the
  principals or the validity** (`PKey.load_certificate`: "very little effort is made to validate the certificate").
* `cryptography.load_ssh_public_identity` + `verify_cert_signature()` can verify it (the spike verifies CA, type HOST,
  principals and that the certified key is the kex key).
Decision (coordinator rule): paramiko cannot verify host certificates by itself, so F1.4 ships known_hosts pinning
(`pinned`/`tofu`, unchanged) plus the user certificate, and files an issue with this spike for a `host_ca` policy
verified with `cryptography`.

## Design
### Data model (`backend/utilities/cbom_sources/sshca/models.py`, migration `r6f14sshca001`)
`cbomsshca`: contract columns + `fingerprint` (SHA256:…), `lineage_id` (root CA id: a source points at a lineage, the
signing CA is the lineage's `active` row, so rotation never edits sources), `retired_at` (bounds the overlap),
`secret_fields`, `owner_user_id`, `updated_by_user_id`, `row_version`, timestamps.
`cbomsshcertissued`: contract columns + `source_addresses`, `via` (`claim`|`refresh`), `revoked_reason`,
`row_version`, timestamps. `ca_id` is a plain int (no FK): the audit outlives anything. Unique `(ca_id, serial)`,
index `(team_id, issued_at)`, index `(team_id, job_id)`.

### Keys and wrapping (`sshca/keywrap.py`)
* Builtin CA keys: Ed25519 (default) or ECDSA P-256 generated with `cryptography`; stored only wrapped.
* `fernet`: `ENCRYPTION_KEY` (existing `encrypt_value`), plaintext bound to `{team, fingerprint}`, checked on unwrap.
* `aws_kms`: envelope encryption. `GenerateDataKey(AES_256)` with EncryptionContext
  `{zs:purpose: devsecshield-sshca, zs:team, zs:ca_fp}`; the CA key is sealed with AES-GCM (AAD = the context). The
  key ARN must be in the deployment allow-list `CBOM_SSHCA_KMS_KEY_ARNS` (first = default); a team admin cannot name
  an arbitrary ARN (confused deputy). "KMS when configured, otherwise the deployment key": a new CA defaults to
  `aws_kms` when the allow-list is set.
* Unwrapped keys cached per worker for at most 10 minutes, keyed by (ca id, fingerprint).

### Issuing (`sshca/ca.py`, `sshca/issue.py`)
`issue_for_job(session, node, job, source, now, via)`: flag on; agentless node; job is this node's and claimed;
source of the job, same team, `linux_servers`, `credential_type == "ssh_ca"`; the source was last saved by a team
admin (like vault credentials: the CA is a team-wide login credential); principals `zs-<team_id>-<group>` only
(1-16, so a certificate can never name `root` or another team); the lineage's active CA in this team (not revoked);
the node's own `ssh_public_key` (the private key never leaves the node); `source-address` = the source's
`ssh_source_addresses` when set, else the node's `source_ips` (refused when neither is known); TTL = CA
`default_ttl_s` clamped 60-3600; `valid_after = now - 60 s`; no extensions; `key_id = zs:<team>:<node>:<job>:<serial>`;
serial from `UPDATE cbomsshca SET serial_next = serial_next + 1 WHERE id = … AND state = 'active' AND revoked_at IS NULL
RETURNING serial_next`; one `cbomsshcertissued` row in the caller's transaction. Refresh through the node route only when
the job's newest certificate has less than `min(120 s, ttl / 2)` left. Vault provider: `POST /v1/<mount>/sign/<role>`
(`cert_type=user`, `extensions={}`, `critical_options.source-address`), through an SSRF-checked client, and the
returned certificate is verified (CA = the stored Vault CA key, our key, principals, validity inside the request,
source-address present, no extensions) before it is recorded.

### Claim plugin (`sshca/claim.py`)
`claim_extras` mints at claim: it finds the job just claimed (`node_id`, `source_id`, `status=claimed`,
`claimed_at=now`), issues inside a SAVEPOINT and sets `secrets.ssh_certificate` + `config.ssh_ca {serial, expires_in_s,
refresh_before_s}`. It never raises: a CA problem becomes `config.ssh_ca.error` (the node fails the job with that
message) so one broken CA cannot wedge a node's queue. `version_input` returns None (rotation must not cancel jobs;
CA state is checked at mint). `known_secrets` returns [] (a certificate is public).

### Revocation (`sshca/krl.py`)
OpenSSH KRL (PROTOCOL.krl) writer: revoked CA keys as explicit-key sections, revoked certificates as serial lists
under their CA key. Served by `GET …/ssh-ca/revoked` (binary, for `RevokedKeys`); `?format=keys` gives the plain list.
Per-certificate revocation: `POST …/ssh-ca/certificates/{id}/revoke` (additive to the contract's route list).

### Rotation
`rotate` creates a `next` CA in the lineage (one at a time, 409 otherwise); `trusted-keys` lists next + active +
retired-within-overlap (`retired_at` + 3600 s + 300 s, the longest certificate an old CA could still have live);
`promote` makes `next` active and the old active `retired`. A revoked key is never listed.

### API (prefix `/{team_id}/cbom/sources/fleet/ssh-ca`, 404 while `CBOM_SSH_CA` is off)
Contract routes plus `POST /certificates/{id}/revoke`. Reads `cbom.fleet.read` (member), writes `cbom.sshca.admin`
(admin, else 400). Node route `POST /cbom/node/jobs/{job_id}/ssh-cert` `{lease_id}` → `{certificate, serial,
valid_after, valid_before, expires_in_s, principals}` (node auth + lease, `node_limiter`, 404 when off).
Templates: `sshd-config` scopes `TrustedUserCAKeys`, `RevokedKeys` and `AuthorizedPrincipalsFile` to
`Match User zs-cbom` (verified with `sshd -t` on OpenSSH 9.6), `principals` lists the principals for the file.

### Scan node
`CAPABILITIES += ["ssh_ca"]`; `Api.ssh_cert()`; `JobContext.cert_refresher`; `agent.py` one line;
`zs_scan_node/sshca.py` `CertSource` (current cert + paramiko key, refresh under a lock when less than
`refresh_before_s` is left, checks the certificate is a user certificate for the node's own key);
`linux_ssh._credentials` (`ssh_ca`) and the auth line of `open_session`.

### Frontend
`utils/api/cbom_ssh_ca.ts`, `components/cbom/sources/fleet/SshCaSection.tsx` (CAs, create, rotate/promote/revoke,
downloads, issued certificates), `ServersTab.tsx` (`ssh_ca` credential: CA, principals, source addresses).

## Risks
* SaaS holds a login-capable key (contract 9: same trust as stored passwords; mitigated by 5-minute TTL, principals
  `zs-<team>-*` only, `source-address`, `Match User zs-cbom` template, audit per certificate, KRL).
* Docker-bridge nodes report container addresses: the form asks for the addresses the servers see; until set,
  logins fail closed (auth_failed) rather than issuing unbound certificates.
* Flag turned off after use: stored `ssh_ca` configs no longer validate, their jobs are refused ("configuration is
  no longer valid"), and the source must be deleted or the flag turned back on to edit it.
* F1.1 / F1.2-a0 not merged: optional-import seams (`authenticate_node`/`_authenticate`, `leased_job`, `flagged_route`)
  until they land; the aggregator line and the claim-path test are added when dev has them.

## Acceptance criteria → proof
| Criterion | Proof |
|---|---|
| Built-in CA, short-lived user certs (default 5 min), principals per target group | unit tests on cert fields; sshd proof (valid cert logs in) |
| Rotation and revocation | unit tests; sshd proof: rotated CA during overlap, revoked cert refused via KRL |
| Host-key trust | spike evidence + pinned/tofu kept + issue filed |
| Audit entry for every cert | unit test (rows == certs, 10,000 bench) |
| Vault SSH engine option | unit tests (fake transport) + live Vault dev container test |
| Real sshd: expired refused, principal mismatch refused (+ source-address, revoked, rotation) | `bench/f1_sshca/sshd_proof.py` under `flock stack.lock`, report in PR |
| KMS wrap | moto tests + live KMS key (tagged, wrap/unwrap, deletion scheduled 7 days, ledger) |
| Security: key material never logged; TTL bounds; issue-route authorisation | dedicated tests |
| Scale | 10,000 issues timed (`bench/f1_sshca/issue_bench.py`) |
