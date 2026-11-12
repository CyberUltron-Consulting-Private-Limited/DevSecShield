# ZeroShield CBOM scan node

The scan node is a small container the customer runs inside their own network. It reaches servers, clusters,
databases and network ranges that ZeroShield cannot reach from the internet. It is **agentless**: nothing is
installed on the servers it scans; it logs in with a read-only account (SSH, WinRM, Kubernetes API, database
login) or only performs TLS/SSH handshakes. It calls **out** to ZeroShield over HTTPS; nothing calls in.

## Install

Create a node in ZeroShield (**CBOM Sources → Scan nodes → Add scan node**) and run the command it shows:

```sh
docker run -d --name zs-scan-node-dc-mumbai-01 --restart unless-stopped \
  -e ZS_API_URL='https://api.zeroshield.ai' \
  -e ZS_REGISTRATION_TOKEN='zsr_…' \
  -v zs-node-dc-mumbai-01:/var/lib/zs-node \
  registry.zeroshield.ai/cbom/scan-node:1.0
```

The container, its volume (and the Helm release) are named after the node (`dc-mumbai-01` here), so two nodes can
run on one host: the volume holds the node's credential and SSH key, and a node started on another node's volume
would run as that node.

A host that cannot pull from `registry.zeroshield.ai` (an air-gapped site, or before the image is published there)
loads the image from a file first: see [Without registry access](#without-registry-access).

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
| `ZS_PKCS11_MODULES` | PKCS#11 libraries the node may load, as `name=/path` pairs separated by `;` (for example `luna=/usr/safenet/lunaclient/lib/libCryptoki2_64.so`). An HSM source names a module; the path never comes from ZeroShield. Mount the vendor client read-only into the container. |

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
  id AND ZeroShield says explicitly that the token is revoked (`X-ZS-Refused: node_token_revoked`: the node was
  reset or deleted). Any other 401 (another id, no id, or `node_token_missing` because a proxy dropped the token
  header) and a 403 without that id keep the token: the node backs off, logs "server at <ZS_API_URL> did not accept
  this node (...); not the ZeroShield this node enrolled with?" and reports it in its next successful heartbeat; an
  enrollment refused that way does not use up the registration token. A copy of the same deployment's database
  (same id) that does not know the node can still revoke it. With `ZS_ALLOW_INSECURE_HTTP` a man in the middle can
  forge these headers like everything else.
* **mTLS.** With `ZS_CLIENT_CERT`/`ZS_CLIENT_KEY` the node presents a client certificate; the proxy checks it and
  ZeroShield can require it and pin each node to the certificate it enrolled with (`deploy/staging/README.md`).

The node runs as uid 10001, needs no capabilities, and only needs outbound TCP to the targets and HTTPS to
ZeroShield. The container is healthy while its heartbeat loop turns: it touches `$ZS_STATE_DIR/alive` on every
pass (at most 60 s apart) and the image health check fails when that file is older than 180 s or missing (a node
that has not enrolled yet is therefore unhealthy).

### Kubernetes (Helm) and agent mode

`deploy/helm/cbom-scan-node` runs the same image as a Deployment (one replica, `Recreate`, state on a PVC, uid
10001, read-only root file system, no capabilities, no service-account token): the **Helm chart** command of the
wizard. With `agent.enabled=true` it adds a DaemonSet of **agent-mode** nodes, one per Kubernetes node:

| Variable | Meaning |
|---|---|
| `ZS_MODE` | `agent`: collect only this node's own host; never run another kind of job; never take a credential (vault use is off) |
| `ZS_NODE_NAME` | the name to enroll under (the chart passes the Kubernetes node name) |
| `ZS_HOST_ROOT` | where the host's `/` is mounted read-only (default `/host`) |
| `ZS_HOST_PROC` | the host's `/proc` (chart value `agent.hostPID`): crypto libraries mapped by running processes |

A DaemonSet enrolls with an **agent pool token** (`zsp_...`, Scan nodes > *Create agent pool token*): it expires,
caps how many nodes enroll and can be revoked; each pod becomes its own node with its own `host_agent` source. A pod
whose node is reset or deleted gets a 401 and enrolls again with the same pool token (a reset node is taken back
without using an enrollment) while the token is active; a pool token ZeroShield refused is not tried again until the
pod restarts with another one (`helm upgrade --set agent.poolToken=...` restarts the pods).
ZeroShield enforces the rest: a source that holds credentials cannot be given to an agent node, a claim never hands
an agent node another job or decrypts a secret for it, and the node refuses such a job too. The host is read
through `hostfs.py` (paths resolved on descriptors inside the host root, so a directory swapped for a symlink cannot
lead outside it; the host's `/proc`, `/sys` and `/dev` are not read; regular files only, size caps; the walk holds
one open directory per level, stays on one device, caps entries and depth and stops at the job's deadline):
os-release, the package databases (`pkgdb.py`, byte-identical to the engine's), crypto policy, FIPS flag,
`sshd_config`, SSH host keys and the key and certificate files under the Tier 2 search roots. As uid 10001 it
reads world-readable files only (unreadable ones are coverage rows); `agent.runAsRoot=true` adds root with
`CAP_DAC_READ_SEARCH` only, and `agent.sysPtrace=true` adds `CAP_SYS_PTRACE`, which reading another user's
`/proc/<pid>/maps` needs. A `docker run` or VM node becomes a single host agent with `ZS_MODE=agent` and `/`
mounted read-only at `/host` (`deploy/node-images/files/zs-node-run` does this on the AMI/OVA).

### Container images from a registry

A *Container images* source (`container_images`) lists images (`registry/repository:tag` or `@sha256:...`). The
node fetches each manifest (Distribution API v2 / OCI; an index is followed to linux/amd64), streams every layer
once without writing it to disk, checks it against its digest and size, applies the layers with OCI whiteouts and
parses the package databases with `pkgdb.py`: crypto packages become library rows with a package URL. HTTPS only;
every host (registry, token service, blob redirect) passes the network gate, and a token service or redirect the
registry names is never a loopback (unless the registry is), link-local or metadata address; credentials
(anonymous, or a vault reference with `username`/`password` or `token`) go only to the registry's own origin or to
the token service of Docker Hub (`auth.docker.io`) or GitLab.com (`gitlab.com`) (`TOKEN_SERVICES`), never to another
token service or a redirect on another host. Caps: 50 images per source, 128 layers, `max_image_mb` (default 2048)
of compressed layers, each blob stops at its descriptor's size, inflated size per layer (8 GB at most), 1 MB of tar
headers per member, 128 MB of package databases and 1,000 dpkg `status.d` entries per image; zstd and foreign layers
are reported, not read.

### Without registry access

Each release is also published as a file. Build it from the repository with `make node-image VERSION=<version>`
(the same as `scripts/release/scan_node_image.sh build <version>`, or the **Scan node image** workflow): it writes
`dist/scan-node/scan-node-<version>.tar.gz` and its `.sha256`. Copy both files to the host, check the file, and load
it; then run the install command unchanged (Docker uses the loaded image and does not pull):

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
Service mesh (Tier 1): Istio PeerAuthentications with the root namespace read from the `istio` mesh ConfigMap
(`rootNamespace`); when Istio is installed and no mesh-wide policy exists, a "(mesh default)" row records that
Istio applies PERMISSIVE. DestinationRules (`networking.istio.io`): `trafficPolicy.tls.mode` for the host, each
port and each subset (certificate paths are not kept). Linkerd (`policy.linkerd.io`, versions found by API
discovery): Servers with their `accessPolicy`, ServerAuthorizations, AuthorizationPolicies, MeshTLS- and
NetworkAuthentications, giving one row per Server that says whether clients without a mesh identity are allowed
and why; the `linkerd-identity-trust-roots` certificates are tagged `linkerd-trust-root`.

**Databases.** PostgreSQL, MySQL, Redis, MongoDB, SQL Server, Oracle. TLS is checked before the password is sent; with
`require_tls` and no TLS the password is never sent. Only fixed queries and fixed setting names are read.
PostgreSQL password hash *types* of login roles (never the hashes) come from `pg_authid` (superuser), else the
DBA-installed `public.zs_role_password_types()` SECURITY DEFINER function (in the grant template), else
`rds_tools.role_password_encryption_type()` on Amazon RDS/Aurora; otherwise one coverage row names the exact fix
for that kind of server. Errors are classified by SQLSTATE (42501, 42883, 3F000), not by message text.
SQL Server (python-tds): PRELOGIN encryption policy, TLS versions and certificate are read before any login; the
login only obfuscates the password (MS-TDS 2.2.6.4), so it is sent only inside TLS to a server proven by the
uploaded CA (or its own certificate). Then TDE per database, symmetric/asymmetric keys, certificates and Always
Encrypted keys per database (metadata), live connection encryption, login policy and hash *version*. A server
with TDS 8.0 strict encryption is reported (transport facts only). Oracle (python-oracledb thin): TCPS when
offered, TDE keystore and encrypted tablespaces/columns, password verifier versions, native network encryption
in use; thin-mode refusals (NNE required DPY-3001, 10G verifier DPY-3015, release before 12.1 DPY-3010) are
findings. Both drivers open their own sockets and can be redirected by the server, so they run inside
`drivergate.scope()`, which routes every lookup and connection through the network gate.

**HSMs and key managers.** PKCS#11 (python-pkcs11): read-only sessions; token information and per object the
class, key type, size or curve, label, id, extractable/sensitive/local and usage flags and dates; a key's value
attribute is never requested (certificates are read, they are public). KMIP 1.0-2.0 (own TTLV client over TLS
with a client certificate): Discover Versions, Query, Locate and Get Attributes only, never Get or Export.

**Certificate authorities.** HashiCorp Vault (PKI issuers, roles, CRL/URL configuration; transit key settings,
never `export` or `backup`; read-only policy template), EJBCA REST (CAs, CA certificates, built-in certificate
profiles where the endpoint exists; client-certificate authentication) and AD CS over WinRM HTTPS (signing hash,
CA certificate, EditFlags and DisableExtensionList, published templates and their permissions (DACL as SDDL) from
the CA server's own template cache).

**Network gate.** Every connection a collector makes to a target goes through `netutil`: `resolve_checked()`
resolves once and applies the never-scan list, `checked_ip()` re-checks right before a driver connects,
`checked_target()` re-checks a target against its name and every address it resolved to, `connect()` opens the
socket to the checked address, and `http_client()` (httpx) and `requests_adapter()` (requests, for WinRM and AD CS)
pin an HTTP client to it: Host, SNI and the certificate name stay the host name, the name is not resolved again, and
no proxy is used, not even one from the environment. `tests/test_network_gate.py` fails when a collector module opens
sockets or HTTP clients any other way, so new collectors must use it.

**Never-scan rule.**
- *Entries* may be addresses, CIDRs, `a-b` ranges (IPv4 or IPv6) or host names. An IPv4-mapped entry
  (`::ffff:10.0.0.5`) counts as its IPv4 address. A zone on an IPv6 entry (`fe80::1%br-ab12`) names an interface,
  not a host: the entry covers that address on every interface.
- *A host name entry* covers the name and every address it resolves to from the scan node. One resolver per node
  process looks the listed names up on its own threads (at most 8 lookups at once, never on a job's claim or watcher
  thread): when a job starts listing a name (jobs starting within 5 s of each other share one lookup), so a job's
  first target is checked against a current answer; again whenever the list changes; then every 5 minutes (every
  minute while a name does not resolve). A host listed by name is therefore not reached by its short name, a CNAME,
  a target written as its address, or a range sweep either. Host name entries belong in a source's own never-scan
  list: the team-level list takes addresses and ranges only (the API refuses a host name there with a 422).
- *Fail closed:* while a listed host name has no known address (its lookup is pending, hangs, fails, answers that
  the name does not exist, or answers only addresses no host has: `0.0.0.0/8`, `::`, their IPv4-mapped and NAT64
  forms, multicast or broadcast, which is what DNS sinkholes and RPZ policies return), the node cannot tell which
  address is that host, so it scans no target at all:
  each one is skipped as `skipped_never_scan` with a reason that names the host name, and the job's summary (and
  `never_scan_unresolved` in its result) lists the names. A newly listed name is waited for, on the job's own
  threads, for at most 15 s first, so a normal lookup costs nothing. The fix is to correct the name (or the node's
  DNS), or to list that host by address instead. A mixed answer keeps its real addresses and drops the others; an
  answer with no usable address keeps the addresses learned before. A loopback answer (`127.0.0.0/8`, `::1`) counts
  as an address: the node's own host name commonly resolves there (Debian maps it to 127.0.1.1).
- *A target name* (a server, database, registry, token service, blob redirect, database redirect, CA, KMIP or
  Kubernetes API host) is skipped as `skipped_never_scan` when the name is listed or when ANY address it resolves to
  is listed, so a dual-stack host listed by its IPv4 address is not scanned over IPv6 and the other way round. The
  outcome, and in a connection test the sample, names the address and the entry that matched.
- *An IP address target* is checked as itself.
- *CIDR and `a-b` target ranges* are checked address by address: the listed addresses inside a range are skipped
  (one outcome each) and the rest are scanned. A range carries no names, so when one address of a dual-stack host is
  listed by address and its other address lies inside a scanned range, that other address is scanned unless it is
  listed too (listing the host by name covers both).
- *Never scanned, whatever the list says:* `0.0.0.0/8` and `::`, which reach the node itself (DNS sinkholes answer
  `0.0.0.0`), also in their IPv4-mapped and NAT64 forms. A registry that sends the node to one of them (token
  service, redirect) is refused as an error, not reported as a never-scan skip.
- *IPv4 in IPv6:* an IPv4-mapped (`::ffff:a.b.c.d`) or NAT64 (`64:ff9b::/96`, RFC 6052 well-known prefix) answer is
  checked as the IPv4 address it reaches as well. A network-specific NAT64 prefix is not recognised.
- *Changes during a job:* the list can change while a job runs. Every new connection, and every request of an HTTP
  client that is already open (registry pulls, the Kubernetes API, CA and appliance REST APIs, WinRM), re-checks the
  address it goes to. Server and database targets are also re-checked against the name and every address it
  resolved to. WinRM and AD CS resolve the name again for each session and stay pinned to the answer they checked.
  A name that resolves to no address is `unreachable`.

**Network.** Per open endpoint a capped list of handshakes (`handshakes_per_endpoint`): one full handshake
(`openssl s_client`), raw ClientHello per protocol version, a TLS 1.3 post-quantum group probe (ML-KEM hybrid
via HelloRetryRequest), TLS_FALLBACK_SCSV, and weak cipher classes. STARTTLS for SMTP, IMAP, LDAP, PostgreSQL,
MySQL; SSH algorithm lists; RDP negotiation; SQL Server PRELOGIN encryption flag. Connections are rate-limited
(connections per second, parallel per server), the never-scan list and the stop-all switch apply live, and work
stops at the end of the scan window.

**IKE / VPN (UDP 500, 4500).** `ikeprobe.py` sends only the first message of an exchange: IKEv2 IKE_SA_INIT
(RFC 7296) and IKEv1 Main/Aggressive Mode message 1 (RFC 2409); no SA is ever completed and no credential is used.
One proposal set per packet finds what the gateway accepts: an IKEv2 baseline, the weak classes (DH groups
1/2/5/22-25, DES/3DES/Blowfish, MD5/SHA-1 integrity and PRF), an ML-KEM additional key exchange (RFC 9370, ids
35-37) and IKEv1 (all-weak set, weak classes, Aggressive Mode). Weak classes are read from INVALID_KE_PAYLOAD
answers, which leave no half-open SA on the gateway (strongSwan stops answering a peer with 5 half-open SAs; one
32 s pause is made if a gateway that answered goes silent). Every packet passes the network gate and the rate
limiter, packets to one endpoint are at least 200 ms apart, and the budget is `2 x handshakes_per_endpoint`
(12-40) packets, 6 in fragile mode (one strong and one all-weak IKEv2 proposal, one IKEv1 message). Port 4500
uses the RFC 3948 non-ESP marker and gets the baseline only. The node sends from an unprivileged source port:
IKEv1 gateways that answer only to source port 500 look silent. An Aggressive Mode answer's hash is never kept.

**OT.** OPC UA (`opcua`, 4840): `otprobe.py` opens one connection and sends HEL, OpenSecureChannel with
SecurityPolicy None, GetEndpoints and CloseSecureChannel (OPC UA Part 6): security policies and modes, user token
policies and the server certificate; no session, no read, write or call. Modbus/TCP (`modbus`, 502): the TCP
connect of the port sweep only; no Modbus request is sent (the protocol has no security to read). Modbus/TCP
Security (`modbus-tls`, 802) goes through the TLS probe; a requested client certificate is reported, not a
failure. An address with an open OT port is scanned in fragile mode, one connection at a time. OT protocols are
not in the default port list: add them for OT ranges.

**Appliances (source kind `appliance`).** Read-only configuration of Cisco IOS/IOS XE, Cisco ASA and FortiOS over
SSH (the Linux login code: pinned host key for passwords, one authentication attempt) and of PAN-OS (XML API,
`type=config&action=show`) and F5 BIG-IP (iControl REST GET) over verified HTTPS. Only the commands in
`collectors/appliance.py` `COMMANDS` are sent (all `show ...`, plus the ASA's session-only `terminal pager 0`);
the ASA has no exec channel, so its commands are typed into one shell. The output is parsed on the node
(`appliance_parsers.py`): SSH versions and algorithms, management TLS versions and ciphers, IKE and IPsec
proposals, key sizes; nothing else (pre-shared keys, passwords) leaves it. Only configured values are judged;
vendor defaults that the configuration does not print are not assumed. `tests/sim_appliance.py` is a SIMULATED
appliance (paramiko) used by the tests and the lab proof; no real device was available.

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
