# ZeroShield CBOM scan node

The scan node is a small container the customer runs inside their own network. It reaches servers, clusters,
databases and network ranges that ZeroShield cannot reach from the internet. It is **agentless**: nothing is
installed on the servers it scans; it logs in with a read-only account (SSH, WinRM, Kubernetes API, database
login) or only performs TLS/SSH handshakes. It calls **out** to ZeroShield over HTTPS; nothing calls in.

## Install

Create a node in ZeroShield (**CBOM Sources → Scan nodes → Add scan node**) and run the command it shows:

```sh
docker run -d --name zs-scan-node --restart unless-stopped \
  -e ZS_API_URL='https://api.zeroshield.ai' \
  -e ZS_REGISTRATION_TOKEN='zsr_…' \
  -v zs-node:/var/lib/zs-node \
  registry.zeroshield.ai/cbom/scan-node:1.0
```

On first start the node creates an ed25519 SSH key in the volume and exchanges the single-use registration
token for its own node token. The public key is shown in ZeroShield: add it to the `zs-cbom` user's
`authorized_keys` on the Linux servers you want collected (the default "node key" credential).

| Variable | Meaning |
|---|---|
| `ZS_API_URL` | ZeroShield API URL over `https://` (required) |
| `ZS_ALLOW_INSECURE_HTTP` | `1` allows an `http://` API URL; local test labs only, since job credentials would travel unencrypted |
| `ZS_REGISTRATION_TOKEN` | single-use token, needed only until the node has enrolled |
| `ZS_STATE_DIR` | state directory (default `/var/lib/zs-node`; keep it on a volume) |
| `ZS_MAX_JOBS` | jobs run in parallel (default 2, max 8) |
| `HTTPS_PROXY` / `NO_PROXY` | outbound proxy to ZeroShield |
| `ZS_VAULT_PATH_PREFIX` | allow vault credentials under this path only (vault use is **off** without it) |
| `VAULT_ADDR`, `VAULT_TOKEN` | HashiCorp Vault (KV v2) for vault credentials |
| AWS role of the host | used for AWS Secrets Manager credentials |
| `ZS_CLIENT_CERT`, `ZS_CLIENT_KEY` | PEM client certificate and key the node presents to the ZeroShield proxy (mTLS; optional) |
| `ZS_CA_FILE` | CA bundle trusted for the ZeroShield API instead of the default (private CA, TLS-inspecting proxy) |

### How the node authenticates

* **Signed requests.** On every enrollment the node makes a new Ed25519 signing key (`$ZS_STATE_DIR/signing_ed25519`,
  0600, written before the key is sent) and registers its public half. Every request then carries
  `X-ZS-Timestamp`, `X-ZS-Nonce` and `X-ZS-Signature` over `METHOD\nPATH\nTIMESTAMP\nNONCE\nsha256(body)`, and the
  body is sent as exactly the signed bytes. ZeroShield refuses unsigned requests from a node that has a key (a
  copied node token alone is useless), replays (nonce seen) and timestamps more than 5 minutes off; a node whose
  clock is off re-signs once with the time from the server's `Date` header (fix NTP anyway). Nodes enrolled
  before signing existed show as "Legacy" until they are reset and registered again; a team can refuse them.
* **Deployment id.** Every ZeroShield node answer carries `X-ZS-Deployment`; the node stores the id at enrollment
  (older state adopts it from the first successful answer). A 401 clears the node token only when it carries that
  id. A 401 without it or with another id (a wrong `ZS_API_URL`, a proxy) keeps the token: the node backs off,
  logs "wrong server or proxy" and reports it in its next successful heartbeat; an enrollment refused that way
  does not use up the registration token. With `ZS_ALLOW_INSECURE_HTTP` a man in the middle can forge this
  header like everything else.
* **mTLS.** With `ZS_CLIENT_CERT`/`ZS_CLIENT_KEY` the node presents a client certificate; the proxy checks it and
  ZeroShield can require it and pin each node to the certificate it enrolled with (`deploy/staging/README.md`).

The node runs as uid 10001, needs no capabilities, and only needs outbound TCP to the targets and HTTPS to
ZeroShield. The container is healthy while its heartbeat loop turns: it touches `$ZS_STATE_DIR/alive` on every
pass (at most 60 s apart) and the image health check fails when that file is older than 180 s or missing (a node
that has not enrolled yet is therefore unhealthy).

### Without registry access

Each release is also published as a file (`scripts/release/scan_node_image.sh build <version>`, or the
**Scan node image** workflow): copy `scan-node-<version>.tar.gz` and its `.sha256` to the host, then

```sh
sha256sum -c scan-node-<version>.tar.gz.sha256
docker load -i scan-node-<version>.tar.gz     # registry.zeroshield.ai/cbom/scan-node:<version>
```

The image installs `requirements.lock`: every Python package pinned with sha256 hashes. After editing
`requirements.txt`, run `scripts/release/scan_node_image.sh lock`; the image build refuses a lock that does not
match `requirements.txt`.

## What it runs

**Linux (SSH).** Tier 1 runs as the login user without sudo; Tier 2 adds the exact `/usr/bin/sudo -n` lines of the
`zs-cbom` sudoers file. The command list is in `zs_scan_node/commands.py` (the same list the UI shows), and
`commands.sudoers_file()` produces the sudoers file. File paths only ever come from the Tier 2 `find`, are
shell-quoted, and are read with commands that print **public** material only (`openssl storeutl -certs`,
`openssl pkey -pubout`, `ssh-keygen -l`, `keytool -list`). Host keys: pinned `known_hosts`, or trust on first
use per (address, port, key type); a changed key stops the target before any credential is sent.

**Windows (WinRM HTTPS 5986).** Read-only PowerShell: certificate stores, SCHANNEL protocol keys, TLS cipher
suite order, BitLocker, RDP security layer.

**Kubernetes.** Static token or client-certificate kubeconfig only (exec plugins and
`insecure-skip-tls-verify` are refused). Tier 1: version, nodes, ingress TLS, cert-manager Certificates, Istio
mTLS, ConfigMap CA bundles and private keys pasted into ConfigMaps (type and size only). Tier 2 adds TLS
secrets, listed with `fieldSelector=type=kubernetes.io/tls`; only `tls.crt` is parsed, `tls.key` is dropped.

**Databases.** PostgreSQL, MySQL, Redis, MongoDB. TLS is checked before the password is sent; with
`require_tls` and no TLS the password is never sent. Only fixed queries and fixed setting names are read.
PostgreSQL password hash *types* of login roles (never the hashes) come from `pg_authid` (superuser), else the
DBA-installed `public.zs_role_password_types()` SECURITY DEFINER function (in the grant template), else
`rds_tools.role_password_encryption_type()` on Amazon RDS/Aurora; otherwise one coverage row names the exact fix
for that kind of server. Errors are classified by SQLSTATE (42501, 42883, 3F000), not by message text.

**Network gate.** Every connection a collector makes to a target goes through `netutil`: `resolve_checked()`
resolves once and applies the never-scan list, `checked_ip()` re-checks right before a driver connects,
`connect()` opens the socket to the checked address and `http_client()` pins an HTTP client to it (Host, SNI and
the certificate name stay the host name). `tests/test_network_gate.py` fails when a collector module opens
sockets or HTTP clients any other way, so new collectors must use it.

**Network.** Per open endpoint a capped list of handshakes (`handshakes_per_endpoint`): one full handshake
(`openssl s_client`), raw ClientHello per protocol version, a TLS 1.3 post-quantum group probe (ML-KEM hybrid
via HelloRetryRequest), TLS_FALLBACK_SCSV, and weak cipher classes. STARTTLS for SMTP, IMAP, LDAP, PostgreSQL,
MySQL; SSH algorithm lists; RDP negotiation; SQL Server PRELOGIN encryption flag. IKE is reported as not
supported. Connections are rate-limited (connections per second, parallel per server), the never-scan list and
the stop-all switch apply live, and work stops at the end of the scan window.

## Develop and test

```sh
pip install -r requirements.txt pytest
python -m pytest -q
sh tests/pg_matrix.sh            # PostgreSQL 16 role hash-type matrix in Docker (needs a Docker daemon)
# run one collector without a server
python -m zs_scan_node.collect --kind network_range --scope scope.json
python -m zs_scan_node.collect --kind linux_servers --job-kind test_connection \
    --config cfg.json --secrets sec.json --scope scope.json --state-dir ./state
```
