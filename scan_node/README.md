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

The node runs as uid 10001, needs no capabilities, and only needs outbound TCP to the targets and HTTPS to
ZeroShield.

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
# run one collector without a server
python -m zs_scan_node.collect --kind network_range --scope scope.json
python -m zs_scan_node.collect --kind linux_servers --job-kind test_connection \
    --config cfg.json --secrets sec.json --scope scope.json --state-dir ./state
```
