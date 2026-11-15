/**
 * (i) tip text of the "cbsrc-nodes" area (ids: cbsrc.nodes.*, cbsrc.pool.*, cbsrc.sched.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── CBOM Sources: Scan nodes (components/cbom/sources/ScanNodesTab.tsx)
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:297 — nodes of the team
  "cbsrc.nodes.count": {
    what: "How many scan nodes this team has registered or is registering.",
    why: "Each network segment you want to scan needs a node inside it.",
    example: "3: one per data centre and one in the DMZ.",
  },
  // src: backend/utilities/cbom_sources/planning.py:22, backend/utilities/cbom_sources/planning.py:69-78 — heartbeat within the last 120 s
  "cbsrc.nodes.online": {
    what: "Nodes that sent a heartbeat in the last 2 minutes and can take jobs now.",
    why: "Jobs for sources behind an offline node wait and expire.",
    example: "2 of 3 online.",
  },
  // src: backend/utilities/cbom_sources/planning.py:22, backend/utilities/cbom_sources/planning.py:69-78 — registered, no heartbeat for 120 s
  "cbsrc.nodes.offline": {
    what: "Registered nodes with no heartbeat for more than 2 minutes: stopped, unable to reach ZeroShield, or their host is down.",
    why: "An offline node silently removes its whole segment from the next run.",
    example: "node-dr1 offline since the DR site's proxy changed.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:300 — servers and addresses routed through these nodes
  "cbsrc.nodes.assigned": {
    what: "Servers and addresses routed through these nodes by your sources and network ranges.",
    why: "Shows how much depends on each node staying online.",
    example: "4,612 targets across 3 nodes.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:303-306 — one per segment; outbound only
  "cbsrc.nodes.list": {
    what: "Your scan nodes: small read-only collectors inside your network, one per network segment. Each connects out to ZeroShield on one HTTPS port, to the targets of its jobs and to your DNS resolver (port 53), and opens no inbound ports.",
    why: "Nodes are how ZeroShield reads systems that are not reachable from the internet.",
    example: "node-dc1 · DC1-core · Online · Docker container.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:345 — node name
  "cbsrc.nodes.col.node": {
    what: "The node's name, as chosen when it was added.",
    why: "Sources and ranges pick their node by this name.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:346, frontend/components/cbom/sources/ScanNodesTab.tsx:464-467 — the network segment it sits in
  "cbsrc.nodes.col.segment": {
    what: "The network segment the node sits in.",
    why: "A source must use a node in a segment that reaches its targets.",
    example: "DC1-core.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:64-69 — online, offline, waiting to register, token expired
  "cbsrc.nodes.col.status": {
    what: "Online (heartbeat in the last 2 minutes), Offline, Waiting to register (installed with a token that was not used yet) or Token expired (create a new registration token).",
    why: "Only online nodes take jobs.",
    example: "Token expired: the install command was not run within 24 hours.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:73-79,348, frontend/components/cbom/sources/ScanNodesTab.tsx:370-378,348 — Docker, OVA, AMI or Helm; host agent mode
  "cbsrc.nodes.col.runs_as": {
    what: "How the node runs: Docker container, OVA appliance, AWS AMI or Helm chart. Host agent means it collects only its own host from read-only mounts and is never given a credential.",
    why: "It tells you where to look when a node needs restarting or upgrading.",
    example: "Helm chart in the prod-payments cluster.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:349 — node_version reported by the node
  "cbsrc.nodes.col.version": {
    what: "The software version the node reported.",
    why: "Old versions may miss newer collectors; upgrade them with the install command.",
    example: "1.8.2.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:350, frontend/components/cbom/sources/ScanNodesTab.tsx:852-855,350 — signed or legacy unsigned
  "cbsrc.nodes.col.requests": {
    what: "Whether the node signs every request with a key made at enrollment (Signed), or is a legacy node that does not.",
    why: "With signing, a copied node token alone cannot act as the node.",
    example: "Legacy: unsigned. Reset the node and register it again to sign.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:351 — last heartbeat
  "cbsrc.nodes.col.last_seen": {
    what: "How long ago the node's last heartbeat arrived.",
    why: "More than 2 minutes means it is offline.",
    example: "12 seconds ago.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:352 — targets routed through the node
  "cbsrc.nodes.col.targets": {
    what: "How many servers and addresses are routed through this node.",
    why: "A heavily loaded node may need the parallel limits lowered or a second node.",
    example: "2,304.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:438-443 — run on any VM or cluster inside the segment
  "cbsrc.nodes.add": {
    what: "Register a new scan node: name it, choose how to run it, allow its outbound traffic, then run the install command on a VM or cluster inside the segment you want to scan.",
    why: "Without a node, servers, clusters, databases and network ranges cannot be collected.",
    example: "node-dc1 as a Docker container on a Linux VM in DC1-core.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:460-461 — up to 64 characters
  "cbsrc.nodes.name": {
    what: "A name for the node, up to 64 characters, shown wherever a source picks its node.",
    why: "Name it after its location so the right node is picked for each source.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:464-467 — pick one or type your own
  "cbsrc.nodes.segment": {
    what: "The network segment the node sits in; pick an existing one or type your own, up to 64 characters.",
    why: "Segments group nodes and appear in run results, so findings can be traced to a network.",
    example: "DC1-core.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:469-471 — the node's time zone
  "cbsrc.nodes.tz": {
    what: "The time zone of the node's location, used in its install settings.",
    why: "Makes the node's own logs line up with your local time.",
    example: "Asia/Kolkata.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:73-79,482 — Docker, OVA, AMI, Helm
  "cbsrc.nodes.deploy": {
    what: "How to run the node: a Docker container on any Linux VM, an OVA appliance for VMware, an AWS AMI in your VPC, or a Helm chart in your Kubernetes cluster. Docker and Helm are the proven ways; the others you build from the published template.",
    why: "It decides the install command you get.",
    example: "Docker container on an existing RHEL 9 VM.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:563-568 — ZeroShield API and your targets
  "cbsrc.nodes.col.destination": {
    what: "Where the node connects to: ZeroShield's API host, and the targets it reads.",
    why: "Firewalls must allow these connections from the node, and nothing inbound.",
    example: "api.zeroshield.ai.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:563-568 — HTTPS to ZeroShield; 22, 5986, 6443, database and TLS ports to targets
  "cbsrc.nodes.col.port": {
    what: "The destination port: HTTPS to ZeroShield, and 22, 5986, 6443 and your database and TLS ports to targets.",
    why: "A blocked port shows up as unreachable targets in the connection test.",
    example: "443 to api.zeroshield.ai.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:563-568 — jobs in, results out; read-only collection
  "cbsrc.nodes.col.used_for": {
    what: "What the connection is for: jobs in and results out (HTTPS to ZeroShield), or read-only collection from your targets.",
    why: "Lets your firewall team approve each rule for a stated purpose.",
    example: "Jobs in, results out (HTTPS).",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:572-573, frontend/components/cbom/sources/ScanNodesTab.tsx:789-790 — an http proxy URL
  "cbsrc.nodes.proxy": {
    what: "Optional: the HTTP proxy the node uses to reach ZeroShield.",
    why: "Nodes in locked-down segments often reach the internet only through a proxy.",
    example: "http://proxy.bank.local:8080.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:633, frontend/components/cbom/sources/logic.ts:376 (apiCa, #196) — PEM up to 64 KB
  "cbsrc.nodes.proxy_ca": {
    what: "Only if your proxy inspects TLS: the PEM certificate of the proxy's CA, up to 64 KB. With \"My proxy inspects TLS\" ticked, the install command gives it to the node (ZS_CA_FILE) from the file in the directory where you run it.",
    why: "Without it the node refuses the proxy's re-signed certificate and cannot connect.",
    example: "bank-proxy-ca.pem.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:629, frontend/components/cbom/sources/logic.ts:387 (proxyAuthCreate, #199)
  "cbsrc.nodes.proxy_user": {
    what: "Optional: the user name, when your proxy needs a login. The install command asks for the password on the host where you run it and keeps it there in a read-only file the node reads (ZS_PROXY_AUTH_FILE); ZeroShield never sees it.",
    why: "Corporate proxies that need a login refuse a node without one (HTTP 407).",
    example: "svc-zs, or CORP\\svc-zs.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:624, deploy/helm/cbom-scan-node/values.yaml — CB-15 section
  "cbsrc.nodes.trust": {
    what: "Only for an on-prem ZeroShield or a gateway with its own CA or mTLS: point the node at a private CA bundle and, if the gateway asks for one, a client certificate and key. The command then mounts these files read-only into the node.",
    why: "The node must trust the API's certificate to enroll, and an mTLS gateway refuses a node without its client certificate. The files never leave your host.",
    example: "An on-prem ZeroShield behind an internal CA and an mTLS ingress.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:629, scan_node/zs_scan_node/api.py:91-97 — CB-15: ZS_CA_FILE
  "cbsrc.nodes.private_ca": {
    what: "Tick if the ZeroShield API's certificate is signed by your own CA (an on-prem deployment, an internal gateway). Give the PEM file's path on the host; the node trusts it for the ZeroShield API only.",
    why: "Without it the node refuses the API's certificate and cannot enroll. The file stays on the host and your targets are not affected.",
    example: "/etc/pki/zeroshield-ca.pem, the CA that signed the ZeroShield API certificate.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:639, scan_node/zs_scan_node/api.py:93-99 — CB-15: ZS_CLIENT_CERT / KEY
  "cbsrc.nodes.mtls": {
    what: "Tick if the gateway in front of the ZeroShield API asks every node for a client certificate. Give the certificate and key paths on the host; the node presents them when it connects.",
    why: "An mTLS gateway refuses a node without one. The key never leaves the host: the command mounts it read-only.",
    example: "/etc/pki/zs-node.crt and /etc/pki/zs-node.key, the key readable by uid 10001.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:532-534 — trust the proxy CA only for ZeroShield hostnames
  "cbsrc.nodes.tls_inspect": {
    what: "Tick if your proxy decrypts TLS: it needs the proxy and its CA certificate. The node then trusts that CA only for ZeroShield's hostnames. The proxy can read the node's credential and its jobs, logins included.",
    why: "A TLS-inspection bypass for the ZeroShield API host keeps credentials out of the proxy; ask for one instead where you can.",
    example: "Tick for a Zscaler or Blue Coat proxy with SSL inspection on.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:632-646 — outbound only, read-only, metadata only
  "cbsrc.nodes.does": {
    what: "The node opens no inbound ports, uses each credential only on its targets, reads with read-only accounts, and sends metadata only: algorithms, key sizes, versions and locations, never private keys.",
    why: "These are the guarantees your security team reviews before approving a node.",
    example: "For a private key file, only its public half and type are sent.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:765-771 — the node's own SSH key
  "cbsrc.nodes.ssh_key": {
    what: "The public half of the SSH key this node generated. Install it for the login user on servers that use the node-generated key.",
    why: "The private key never leaves the node, so nothing secret is stored by ZeroShield.",
    example: "ssh-ed25519 AAAAC3Nza... zs-node-7.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:852-864 — require signed scan nodes
  "cbsrc.nodes.signing": {
    what: "Scan nodes sign every request with a key made at enrollment. A team admin can require it, so nodes that do not sign are refused.",
    why: "A copied node token alone is then not enough to act as the node.",
    example: "Turn on once every node shows Signed.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:859-861 — refuse unsigned nodes
  "cbsrc.nodes.require_signed": {
    what: "Refuse requests from nodes that do not sign them. Legacy unsigned nodes stop working until reset and registered again.",
    why: "Closes the gap of a stolen node token being replayed from another machine.",
    example: "On, after resetting the one legacy node.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: agent pools, schedules, run comparison, scan sidebar, remediation waves
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:105, frontend/components/cbom/sources/AgentPoolsCard.tsx:104-108 — one token for a Helm DaemonSet
  "cbsrc.pool.card": {
    what: "One token for a Helm DaemonSet: every pod enrolls as its own agent-mode scan node named after its Kubernetes node, reads only that node's files through a read-only mount, and is never given a credential.",
    why: "Covers every worker node's crypto (keys, certificates, libraries) without SSH access to each one.",
    example: "A pool token for prod-cluster enrolls 24 host agents, one per worker node.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:125-126 — up to 64 characters
  "cbsrc.pool.name": {
    what: "A name for the pool, up to 64 characters; its agents are named after their Kubernetes nodes.",
    why: "Identifies which cluster the agents belong to.",
    example: "prod-cluster.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:129-130 — up to 64 characters
  "cbsrc.pool.segment": {
    what: "The network segment recorded for every agent of the pool, up to 64 characters.",
    why: "Findings from the agents are grouped by segment in run results.",
    example: "DC1-k8s.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:132-139 — enrolled nodes keep working
  "cbsrc.pool.expiry": {
    what: "How long the pool token can enroll new agents. Agents that already enrolled keep working after it expires.",
    why: "A short expiry limits the damage if the token leaks from the Helm values.",
    example: "24 hours: long enough to roll out the DaemonSet.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:140-141 — 1 to 1,000; at least the number of Kubernetes nodes
  "cbsrc.pool.max": {
    what: "The most agents the token may enroll, 1 to 1,000. Set at least the number of Kubernetes nodes.",
    why: "A cap stops a leaked token from enrolling unlimited fake nodes.",
    example: "30 for a 24-node cluster that may grow.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:176 — the pool token's name
  "cbsrc.pool.col.token": {
    what: "The pool token, by name. The token value itself is shown once, when it is created.",
    why: "Revoke a token here if it may have leaked.",
    example: "prod-cluster.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:177 — active, expired or revoked
  "cbsrc.pool.col.status": {
    what: "Whether the token can still enroll agents: Active, All enrollments used, Expired or Revoked.",
    why: "Only active tokens accept new agents; enrolled agents keep working either way.",
    example: "Expired.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:178 — agents enrolled out of the maximum
  "cbsrc.pool.col.enrolled": {
    what: "How many agents enrolled with this token, out of the maximum allowed.",
    why: "Fewer than your node count means some pods did not start or could not reach ZeroShield.",
    example: "22 of 30.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:179 — when the token stops enrolling
  "cbsrc.pool.col.expires": {
    what: "When the token stops enrolling new agents.",
    why: "Create a new token before scaling the cluster after this time.",
    example: "15 Nov 2026, 11:00 am IST.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:180 — agent nodes of the pool
  "cbsrc.pool.col.nodes": {
    what: "The agent scan nodes this token enrolled, as listed under Registered scan nodes.",
    why: "Each agent appears as its own node with its own status.",
    example: "prod-cluster-ip-10-30-1-12, prod-cluster-ip-10-30-1-13, ...",
  },
  // src: frontend/components/cbom/sources/SchedulesCard.tsx:166, frontend/components/cbom/sources/SchedulesCard.tsx:166 — daily, weekly or monthly; charged like Start scan
  "cbsrc.sched.card": {
    what: "Collection runs that start on their own, daily, weekly or monthly, at a time in the team's time zone. Each run charges credits like Start a scan and is skipped, with the reason, when the team has too few.",
    why: "Regular runs show what changed and prove fixes landed.",
    example: "Weekly, Sunday 02:00 Asia/Kolkata: servers, databases and cloud.",
  },
  // src: frontend/components/cbom/sources/SchedulesCard.tsx:68-69 — up to 64 characters
  "cbsrc.sched.name": {
    what: "A name for the schedule, up to 64 characters.",
    why: "Runs started by a schedule are labelled with it.",
    example: "Weekly full collection.",
  },
  // src: frontend/components/cbom/sources/SchedulesCard.tsx:71-80 — daily, weekly, monthly
  "cbsrc.sched.repeat": {
    what: "How often the schedule starts a run: daily, weekly or monthly.",
    why: "More frequent runs catch drift sooner but cost more credits.",
    example: "Weekly.",
  },
  // src: frontend/components/cbom/sources/SchedulesCard.tsx:82-90 — day of the week
  "cbsrc.sched.day": {
    what: "The day of the week a weekly schedule runs.",
    why: "Pick a day inside your scan window.",
    example: "Sunday.",
  },
  // src: frontend/components/cbom/sources/SchedulesCard.tsx:92-95 — 1 to 28
  "cbsrc.sched.monthday": {
    what: "The day of the month a monthly schedule runs, 1 to 28 so it exists in every month.",
    why: "Align it with your monthly patch cycle to prove fixes.",
    example: "5: the run after the monthly patch weekend.",
  },
  // src: frontend/components/cbom/sources/SchedulesCard.tsx:98-101 — team time zone; the scan window still applies
  "cbsrc.sched.time": {
    what: "The time the run starts, in the team's time zone (set with the scan window on Network TLS). The scan window still applies: work outside it waits.",
    why: "A start time outside the window only queues jobs that wait.",
    example: "02:00.",
  },
  // src: frontend/components/cbom/sources/scheduleForm.ts:9, frontend/components/cbom/sources/scheduleForm.ts:27 — servers, Kubernetes, databases, cloud, network
  "cbsrc.sched.groups": {
    what: "Which groups of sources each scheduled run collects. Network is off by default and needs the SOC agreement.",
    why: "Leave out groups that should only run on demand.",
    example: "Servers, Kubernetes, databases and cloud.",
  },
  // src: frontend/components/cbom/sources/scheduleForm.ts:19 — any, or at least low, medium, high, critical
  "cbsrc.sched.min_crit": {
    what: "Limit the schedule to sources whose business criticality is at least this level, or Any.",
    why: "Scan critical systems more often without paying for every source each time.",
    example: "High: a daily run of only high and critical sources.",
  },
  // src: frontend/components/cbom/sources/SchedulesCard.tsx:125, frontend/components/cbom/sources/SchedulesCard.tsx:125-127 — kept with the schedule
  "cbsrc.sched.soc": {
    what: "Confirm that your SOC has agreed the network ranges and scan windows for every scheduled run. It is kept with the schedule.",
    why: "Unattended network scans need standing SOC approval.",
    example: "Tick after the SOC approved weekly scans of 10.20.0.0/16.",
  },
  // src: frontend/components/cbom/sources/NodeInstall.tsx:41, frontend/components/cbom/sources/NodeInstall.tsx:37-43 — ZS_ALLOW_INSECURE_HTTP
  "cbsrc.nodes.lab_only": {
    what: "This install command sets ZS_ALLOW_INSECURE_HTTP=1 because the API is plain HTTP: the node's credentials and the decrypted secrets of every job travel unencrypted.",
    why: "Anyone on the network path could read them; serve the API over HTTPS for anything but a closed test lab.",
    example: "A lab on 192.168.56.0/24 with no other users; never a production network.",
  },
  // src: frontend/components/cbom/sources/logic.ts:612-634, frontend/components/cbom/sources/ScanNodesTab.tsx:488-498 — docker pull or helm from the public registry
  "cbsrc.nodes.registry_pull": {
    what: "When ZeroShield publishes the node image in a public registry, one command pulls the pinned release and starts the node (Docker), or installs the Helm chart from that registry. No registry login is needed. Hosts without access to the registry use the downloaded files below instead.",
    why: "The quickest install on a host with internet access; the pinned version matches this ZeroShield.",
    example: "docker pull ghcr.io/… && docker run … on the scan host.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: node install without the public registry (#233)
  // src: backend/routers/cbom_node_artifacts.py:26-33, frontend/components/cbom/sources/ScanNodesTab.tsx:312-322,501 — one paste with curl or wget, or the downloaded files
  "cbsrc.nodes.files_install": {
    what: "For a host that cannot reach the public registry: one paste that downloads this node's files from ZeroShield, checks their SHA-256 and installs them (curl, or wget), or the same install from files you downloaded in the browser. The download links work only for this node and only until it registers or its token is replaced or expires.",
    why: "Installs the same pinned release on a host with no internet access.",
    example: "Copy the files to the host, then run the install command shown below them.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: scan node network requirements (#243)
  // src: frontend/components/cbom/sources/logic.ts:543-549 — outbound HTTPS to the API; registry, build kits and cloud APIs
  "cbsrc.nodes.network_req": {
    what: "What needs network access: the scan node needs outbound HTTPS to the ZeroShield API, DNS (port 53) to your resolver and direct reach to your targets. Pulling the image from a public registry needs that registry; building the OVA or AMI kits needs internet; cloud and identity sources are read from ZeroShield's servers.",
    why: "Tells your network team which firewall rules to open, and that nothing calls in.",
    example: "Allow node-dc1 out to the ZeroShield API on 443; no inbound rule.",
  },
} as const satisfies TipAreaText;

export default TEXT;
