/**
 * (i) tip text of the "cbsrc-workloads" area (ids: cbsrc.k8s.*, cbsrc.k8sdb.*, cbsrc.db.*, cbsrc.km.*, cbsrc.img.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── CBOM Sources: Kubernetes, databases, HSMs and key managers (components/cbom/sources/ClustersDatabasesTab.tsx)
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:374 — read through a scan node
  "cbsrc.k8sdb.intro": {
    what: "Kubernetes clusters, databases, HSMs and key managers, each read through a scan node inside your network.",
    why: "Clusters and databases terminate much of your TLS and store keys and certificates that servers alone do not show.",
    example: "prod-payments cluster and pg-core-01 database, both through node-dc1.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:426-472 — clusters, databases, HSMs and key managers of the team
  "cbsrc.k8sdb.list": {
    what: "The cluster, database, HSM and key manager sources of this team with their endpoint, access level or login, scan node and last connection test.",
    why: "These sources are what a run collects from on the Review & Run tab.",
    example: "pg-core-01 · PostgreSQL · pg-core-01.bank.local:5432 · zs_cbom · Passed.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:909-915 — read through the Kubernetes API with a read-only ClusterRole
  "cbsrc.k8s.form": {
    what: "A Kubernetes cluster read through its API with a read-only ClusterRole: versions, API server and ingress TLS, cert-manager certificates, keys in ConfigMaps and service mesh mTLS policy.",
    why: "Clusters hold many certificates that rotate on their own and are easy to lose track of.",
    example: "prod-payments, https://10.30.0.5:6443, Tier 1, through node-dc1.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:918-919 — 1-64 characters
  "cbsrc.k8s.name": {
    what: "A name for this cluster, 1 to 64 letters, digits, spaces, dots, dashes or underscores, shown in lists, run results and reports.",
    why: "Each asset found records it as its source.",
    example: "prod-payments.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:921-932 — the Kubernetes API endpoint
  "cbsrc.k8s.api_url": {
    what: "The HTTPS address of the cluster's Kubernetes API server, as in the server field of your kubeconfig.",
    why: "The scan node talks only to this URL; it must be reachable from the node.",
    example: "https://10.30.0.5:6443.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:934-941, backend/utilities/cbom_sources/kinds.py:21 — PEM up to 64 KB; optional with certificate-authority-data
  "cbsrc.k8s.ca": {
    what: "The PEM certificate of the cluster's CA, used to verify the API server before the token is sent. Optional when the kubeconfig embeds certificate-authority-data.",
    why: "Without verification a spoofed API server could capture the service account token.",
    example: "The ca.crt from /etc/kubernetes/pki on a control plane node.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:988-997 — kubeconfig or token from vault
  "cbsrc.k8s.credential": {
    what: "Upload kubeconfig: encrypted at rest and sent only to the scan node. Token from vault: the node fetches it when the job runs (team admins only).",
    why: "A token kept in your vault never rests on ZeroShield.",
    example: "A kubeconfig for the service account zs-cbom bound to the ClusterRole below.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:890-894,1006, frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1005-1017 — exec and auth-provider plugins refused
  "cbsrc.k8s.kubeconfig": {
    what: "The kubeconfig of the zs-cbom service account. It is sent once, encrypted at rest and sent only to the scan node that runs the job. Configs that use exec or auth-provider plugins are refused.",
    why: "Plugins would run commands on the scan node; a static token keeps the node's footprint read-only.",
    example: "zs-cbom.kubeconfig with a token for the zs-cbom service account.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1052-1053 — up to 128 characters; blank uses current-context
  "cbsrc.k8s.context": {
    what: "Which context of the kubeconfig to use, up to 128 characters. Blank uses its current-context.",
    why: "A kubeconfig with several clusters would otherwise read whichever was last selected.",
    example: "prod-payments-admin.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1072-1093 — Tier 1 without Secrets; Tier 2 reads TLS Secrets, private keys dropped unparsed
  "cbsrc.k8s.tier": {
    what: "Tier 1 reads versions, API server and ingress TLS, Secret names, cert-manager Certificates, certificates in ConfigMaps and mesh mTLS policy. Tier 2 also reads the certificates of TLS Secrets; their private keys are dropped unparsed and never stored or sent.",
    why: "Tier 2 covers certificates kept only in Secrets, but its token can read Secret values.",
    example: "Tier 2 finds the expiring ingress certificate stored in secret payments-tls.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1095-1103 — Kubernetes cannot grant Secret names without values
  "cbsrc.k8s.tier2_warning": {
    what: "Kubernetes cannot grant access to Secret names without their values, so a Tier 2 token can read them. Only metadata such as fingerprints is sent to ZeroShield.",
    why: "The token is as sensitive as the Secrets it can read; protect it accordingly.",
    example: "Try Tier 2 on a staging cluster before production.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1136-1138 — link the cloud account that runs it
  "cbsrc.k8s.managed": {
    what: "Tick for EKS, AKS, GKE or OKE clusters to link the cloud account source that runs the cluster.",
    why: "The cloud account holds the encryption-at-rest settings of the cluster's Secrets.",
    example: "EKS cluster prod-payments, linked to the AWS account aws-prod.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1141-1147 — stored as a link until cloud collection reads it
  "cbsrc.k8s.cloud": {
    what: "The cloud account source that runs this managed cluster. Secret encryption at rest is read from this account once cloud collection is available; until then it is stored as a link.",
    why: "Ties the cluster's findings to the account where the fix is made.",
    example: "aws-prod · AWS account.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1387-1392, backend/utilities/cbom_sources/kinds.py:382-391 — read-only login
  "cbsrc.db.form": {
    what: "A database server read with a read-only login: its TLS setup, certificates and encryption settings. Run the grant shown below once as an admin.",
    why: "Databases hold the most sensitive data; weak TLS or unencrypted storage there is a top finding.",
    example: "pg-core-01.bank.local:5432, login zs_cbom, Require TLS with the bank CA.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1396-1397 — 1-64 characters
  "cbsrc.db.name": {
    what: "A name for this database source, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each asset found records it as its source.",
    example: "pg-core-01.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:62-69, backend/utilities/cbom_sources/kinds.py:379 — PostgreSQL, MySQL/MariaDB, SQL Server, Oracle, MongoDB, Redis
  "cbsrc.db.engine": {
    what: "The database engine: PostgreSQL, MySQL / MariaDB, SQL Server, Oracle, MongoDB or Redis. It sets the default port, the grant to run and how the login is protected.",
    why: "Each engine exposes its crypto settings differently, so the wrong engine reads nothing.",
    example: "SQL Server, default port 1433.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:384 — up to 253 characters
  "cbsrc.db.host": {
    what: "The database server's hostname or IP address, up to 253 characters, as the scan node reaches it.",
    why: "Use the name in the server's certificate so the TLS check passes.",
    example: "pg-core-01.bank.local.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:379, backend/utilities/cbom_sources/kinds.py:385 — 1-65535; engine default when blank
  "cbsrc.db.port": {
    what: "The database port, 1 to 65535. Blank uses the engine's default: PostgreSQL 5432, MySQL 3306, SQL Server 1433, Oracle 1521, MongoDB 27017, Redis 6379.",
    why: "A wrong port fails the connection test before the login is tried.",
    example: "6432 when PostgreSQL sits behind PgBouncer.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:386, backend/utilities/cbom_sources/kinds.py:27 — up to 64 characters; optional for engines that run without authentication
  "cbsrc.db.login": {
    what: "The read-only login the node connects with, up to 64 characters. Optional for MongoDB and Redis servers that run without authentication.",
    why: "A dedicated login with only the grants below limits what a leaked password can do.",
    example: "zs_cbom.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:391 — up to 128 characters; required for Oracle
  "cbsrc.db.database": {
    what: "For Oracle, the service (PDB) the login and grants belong to (required). For other engines, the database to connect to first (optional); server-wide settings are read from there.",
    why: "Oracle logins exist per service, so a wrong name fails the login.",
    example: "ORCLPDB1 for Oracle; postgres for PostgreSQL.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1455-1463 — password or password from vault
  "cbsrc.db.credential": {
    what: "Password: encrypted at rest and sent only to the scan node. Password from vault: the node fetches it when the job runs (team admins only).",
    why: "A vault reference keeps the password out of ZeroShield entirely.",
    example: "Password from vault at secret/zs-cbom/db/pg-core-01.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:20, backend/utilities/cbom_sources/kinds.py:262-271 — encrypted at rest; MySQL, Redis and SQL Server need TLS with a CA
  "cbsrc.db.password": {
    what: "The password of the login. Encrypted at rest, never shown again, sent only to the scan node. MySQL, Redis and SQL Server logins also need Require TLS and the CA certificate, so the password only goes to the real server.",
    why: "Those engines would otherwise send the password in a form an impostor can read.",
    example: "The password of zs_cbom, with the bank CA uploaded below.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:389 — on by default
  "cbsrc.db.require_tls": {
    what: "On (the default): the node connects only over TLS. Off: it may connect without TLS and records that the server allows plaintext.",
    why: "TLS keeps the login and the data in transit away from anyone on the network path.",
    example: "Leave on; turn off only for a legacy server you are documenting as plaintext.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1501-1518, backend/utilities/cbom_sources/kinds.py:390 — PEM up to 64 KB; required with a password for MySQL, Redis, SQL Server
  "cbsrc.db.ca": {
    what: "The PEM certificate of the CA that signed the database server's certificate. The node checks the server against it before sending a password. Required with a password for MySQL, Redis and SQL Server; optional otherwise.",
    why: "It proves the node is talking to the real database, not an impostor collecting credentials.",
    example: "bank-root-ca.pem.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1788-1793, frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1628-1639,1789 — attributes only, never key values
  "cbsrc.km.form": {
    what: "An HSM or token read through PKCS#11, or a KMIP key manager. Keys are inventoried by their attributes only: type, size, flags, state and dates. No key value ever leaves the device.",
    why: "Keys in HSMs sign payments and certificates; their algorithms and sizes decide the post-quantum migration work.",
    example: "hsm-payments-01, a Luna HSM read through module luna.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1796-1797 — 1-64 characters
  "cbsrc.km.name": {
    what: "A name for this HSM or key manager source, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each key found records it as its source.",
    example: "hsm-payments-01.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1800-1809 — PKCS#11 or KMIP
  "cbsrc.km.provider": {
    what: "HSM or token (PKCS#11): read through the vendor library on the scan node. KMIP server: read over TLS with a client certificate.",
    why: "It decides how the node connects and which credential it needs.",
    example: "KMIP for a Thales CipherTrust Manager.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1815-1823 — mapped in ZS_PKCS11_MODULES on the node
  "cbsrc.km.module": {
    what: "The name the scan node's operator maps to a PKCS#11 library in ZS_PKCS11_MODULES on the node. ZeroShield never sends a library path.",
    why: "Only libraries the node's operator approved can be loaded.",
    example: "luna, mapped to /usr/safenet/lunaclient/lib/libCryptoki2_64.so.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1825-1826 — up to 32 characters; blank reads every initialised token
  "cbsrc.km.token": {
    what: "The label of the token or partition to read, up to 32 characters. Required when the module shows more than one token; blank works for a module with one token.",
    why: "The PIN is only ever tried on this token, so a wrong PIN cannot count toward locking other partitions of a shared HSM.",
    example: "payments-partition.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1831-1837 — PIN, PIN from vault; optional
  "cbsrc.km.pin_source": {
    what: "The crypto user PIN, typed here (encrypted at rest) or fetched from your vault when the job runs. Optional: without it only public objects are read.",
    why: "Private and secret keys are only listed after a login with the PIN.",
    example: "PIN from vault for the crypto user of payments-partition.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1842, backend/utilities/cbom_sources/kinds.py:20 — encrypted at rest
  "cbsrc.km.pin": {
    what: "The PIN of the crypto user or partition role. Encrypted at rest, never shown again, sent only to the scan node; the session it opens is read-only.",
    why: "Without it the inventory misses the private keys, which matter most.",
    example: "The crypto user PIN of payments-partition.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:26 — up to 253 characters
  "cbsrc.km.host": {
    what: "The KMIP server's hostname or IP address as the scan node reaches it.",
    why: "Use the name in the server's certificate so the TLS check passes.",
    example: "kms01.bank.local.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1862 — default 5696
  "cbsrc.km.port": {
    what: "The KMIP port, default 5696.",
    why: "A wrong port fails the connection test before TLS starts.",
    example: "5696.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1866-1873 — optional PEM; verifies the KMIP server
  "cbsrc.km.ca": {
    what: "Optional PEM certificate of the CA that issued the KMIP server's certificate. With it the node verifies the server; TLS client authentication never reveals the client key either way.",
    why: "Verifying the server proves the inventory comes from your real key manager.",
    example: "The CipherTrust root CA certificate.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1876, backend/utilities/cbom_sources/kinds.py:20 — PEM, encrypted at rest
  "cbsrc.km.client_cert": {
    what: "The PEM client certificate the node presents to the KMIP server. Encrypted at rest and sent only to the scan node.",
    why: "KMIP servers admit only clients with a certificate they trust.",
    example: "zs-cbom-client.crt issued by the KMIP server's CA.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1877, backend/utilities/cbom_sources/kinds.py:20 — PEM, unencrypted; encrypted at rest
  "cbsrc.km.client_key": {
    what: "The unencrypted PEM private key of the client certificate. Encrypted at rest by ZeroShield, never shown again, sent only to the scan node.",
    why: "Give the KMIP client read-only rights so this key can list objects but not export them.",
    example: "-----BEGIN PRIVATE KEY----- ....",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:1-5, frontend/components/cbom/sources/ContainerImagesSection.tsx:55-58 — pulled over HTTPS, 1 credit per image per run
  "cbsrc.img.card": {
    what: "The scan node pulls images from your registry over HTTPS (verified by digest, never written to disk) and lists the crypto packages inside with package URLs. 1 credit per image per run.",
    why: "Images ship their own OpenSSL and crypto libraries, often older than the host's.",
    example: "registry.bank.in/payments/api:2.4.1 contains openssl 1.1.1k.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:776, backend/utilities/cbom_sources/kinds.py:782 — up to 50 per source
  "cbsrc.img.col.images": {
    what: "How many images this source pulls, up to 50.",
    why: "Each image costs 1 credit per run.",
    example: "12 images: 12 credits per run.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:1-5 — anonymous or a vault reference
  "cbsrc.img.col.credentials": {
    what: "How the registry is accessed: anonymous, or a credential read from your vault on the node. ZeroShield never stores a registry password.",
    why: "Private registries need a credential; keeping it in your vault keeps it off ZeroShield.",
    example: "Vault: secret/zs-cbom/registry.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:181-182 — up to 64 characters
  "cbsrc.img.name": {
    what: "A name for this image source, up to 64 characters, shown in lists, run results and reports.",
    why: "Each package found records it as its source.",
    example: "payments-images.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:184-185 — an agentless node that reaches the registry
  "cbsrc.img.node": {
    what: "An agentless scan node that reaches the registry over HTTPS.",
    why: "Host-agent nodes never pull images.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:187-189, backend/utilities/cbom_sources/kinds.py:776 — up to 50; registry/repository:tag or @sha256
  "cbsrc.img.refs": {
    what: "Up to 50 images, one per line: registry/repository:tag or @sha256:digest. Docker Hub is used when no registry is named.",
    why: "A digest pins exactly what was scanned; a tag may move.",
    example: "registry.bank.in/payments/api@sha256:4f1c...",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:192-202 — anonymous or from a vault (admins)
  "cbsrc.img.cred": {
    what: "Anonymous for public pulls, or From a vault (team admins): the node reads the credential from your vault and sends it only to the registry's own host or its token service.",
    why: "The credential never passes through ZeroShield.",
    example: "From a vault for the private registry.bank.in.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:215-216 — up to 512 characters; under ZS_VAULT_PATH_PREFIX on the node
  "cbsrc.img.vault_path": {
    what: "Where the registry credential lives in your vault, up to 512 characters, under the prefix the node's operator allows (ZS_VAULT_PATH_PREFIX).",
    why: "The prefix keeps a source from reading arbitrary secrets through the node.",
    example: "secret/zs-cbom/registry/bank.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:786 — 1 to 8,192 MB, default 2,048
  "cbsrc.img.max": {
    what: "The largest image to pull, compressed, 1 to 8,192 MB (default 2,048). Bigger images are reported as not read.",
    why: "Caps the node's bandwidth and time on one huge image.",
    example: "4096 for ML images with large CUDA layers.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:224-225 — only for a private CA
  "cbsrc.img.ca": {
    what: "Optional PEM certificate of the CA that issued the registry's certificate. The registry's certificate is always verified.",
    why: "Needed for an internal registry with a private CA.",
    example: "bank-root-ca.pem.",
  },
} as const satisfies TipAreaText;

export default TEXT;
