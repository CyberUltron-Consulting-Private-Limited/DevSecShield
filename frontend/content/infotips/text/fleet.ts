/**
 * (i) tip text of the "fleet" area (ids: fleet.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── CBOM Sources: Fleet > Credentials (F1.2, PR #81)
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:3-6, backend/utilities/cbom_sources/fleet/credentials.py:1-7 — logins policies hand to managed sources; secrets write-only
  "fleet.cred.section": {
    what: "Logins that fleet policies give to the managed sources they create: how to sign in to a Linux host over SSH, and the secret if the type stores one. Secrets are encrypted and never shown again.",
    why: "One credential serves every host a policy matches, so a fleet of thousands needs no per-host setup.",
    example: "linux-fleet: SSH certificate and key, login zs-cbom on port 22, used by 14 managed sources.",
  },
  // src: backend/utilities/cbom_sources/fleet/credentials.py:73 — 1 to 64 characters
  "fleet.cred.name": {
    what: "A name for this credential, 1 to 64 characters, shown when you choose one in a policy.",
    why: "Policies pick credentials by name.",
    example: "linux-fleet.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:36-43, backend/utilities/cbom_sources/fleet/credentials.py:3-7 — node key, password, SSH certificate, vault, SSH CA
  "fleet.cred.type": {
    what: "How the scan node signs in: its own node key (nothing stored here), a password (host keys must be pinned), an SSH certificate and key, or a secret read from a vault. SSH CA credentials are made in the SSH CA section. The type cannot change once added.",
    why: "Decides which secret is stored and where it may be used.",
    example: "SSH certificate and key.",
  },
  // src: backend/utilities/cbom_sources/fleet/credentials.py:27 — login_user, up to 64 characters
  "fleet.cred.login": {
    what: "The account the scan node signs in with on each host, up to 64 characters.",
    why: "Use a dedicated read-only account so the scan can be audited and limited.",
    example: "zs-cbom.",
  },
  // src: backend/utilities/cbom_sources/fleet/credentials.py:28 — 1 to 65535, default 22
  "fleet.cred.port": {
    what: "The SSH port on the hosts, 1 to 65535.",
    why: "Hosts that run SSH on another port are unreachable on 22.",
    example: "22, or 2222 where SSH was moved.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:156-164, backend/utilities/cbom_sources/fleet/credentials.py:29-30 — pinned or trust on first use
  "fleet.cred.pinned": {
    what: "Pinned: the node only accepts the host keys listed below. Off: it trusts each host's key the first time and then expects the same key (trust on first use). A password credential is always pinned.",
    why: "Pinning stops a password or session from going to a host that impersonates the real one.",
    example: "On for the PCI segment, with its known_hosts lines pasted.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:165-169, backend/utilities/cbom_sources/fleet/credentials.py:30 — pinned host keys
  "fleet.cred.known_hosts": {
    what: "The hosts' public keys in OpenSSH known_hosts format, one per line. Required when host keys are pinned.",
    why: "Only hosts whose key is listed are accepted.",
    example: "web-01.bank.local ssh-ed25519 AAAAC3Nza… (one line per host).",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:170-174, backend/utilities/cbom_sources/fleet/credentials.py:21 — encrypted, write-only; re-entered when the login changes
  "fleet.cred.password": {
    what: "The account's password. Encrypted at rest and never shown again; leave it blank on edit to keep it. Changing the login, port, host keys or vault asks for it again.",
    why: "A password for one login never follows the credential to another one.",
    example: "The password of zs-cbom.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:175-183, backend/utilities/cbom_sources/fleet/credentials.py:21 — ssh_certificate with private_key
  "fleet.cred.cert": {
    what: "The OpenSSH user certificate signed by your SSH CA for the login account. Stored encrypted with the private key below; never shown again.",
    why: "Short-lived certificates avoid copying a long-lived key to every host.",
    example: "ssh-ed25519-cert-v01@openssh.com AAAA… zs-cbom.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:180-182, backend/utilities/cbom_sources/fleet/credentials.py:21 — encrypted, write-only
  "fleet.cred.key": {
    what: "The private key that belongs to the SSH certificate. Encrypted at rest and sent only to the scan node that runs the job; never shown again.",
    why: "The certificate is useless without it, so keep it read-only on the hosts' side.",
    example: "The OpenSSH private key that matches zs-cbom-cert.pub.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:185-197, backend/utilities/cbom_sources/kinds.py:81-83 — VaultRef provider
  "fleet.cred.vault": {
    what: "Where the scan node reads the secret at run time: HashiCorp Vault or AWS Secrets Manager (CyberArk and Azure Key Vault: not available yet). Nothing secret is stored in ZeroShield.",
    why: "Keeps the secret in the vault your team already rotates and audits.",
    example: "HashiCorp.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:83 — 1 to 512 characters
  "fleet.cred.vault_path": {
    what: "The path of the secret in the vault, 1 to 512 characters.",
    why: "The node reads exactly this secret and nothing else.",
    example: "secret/data/cbom/zs-cbom.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:278 — credential_type
  "fleet.cred.col.type": {
    what: "The credential's type: node_key, password, ssh_cert, vault or ssh_ca.",
    why: "Tells you at a glance which secret, if any, is stored.",
    example: "ssh_cert.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:279 — login_user:port
  "fleet.cred.col.login": {
    what: "The login account and SSH port the credential uses.",
    why: "Shows which account the hosts must allow.",
    example: "zs-cbom:22.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:264, backend/utilities/cbom_sources/fleet/credentials.py:5-7 — secrets_set, names only
  "fleet.cred.col.secrets": {
    what: "Which secrets are stored for this credential, by name only; the values are never shown.",
    why: "Confirms the secret is in place without exposing it.",
    example: "ssh_certificate, private_key.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:265 — managed_sources
  "fleet.cred.col.managed": {
    what: "How many managed sources, created by policies, use this credential now.",
    why: "Deleting or changing a credential affects every one of them.",
    example: "14 managed sources.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Fleet > Inventory (F1.2, PR #81)
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:3-4, backend/utilities/cbom_sources/fleet/policy.py:1-14 — targets from inventory sources, each with its policy decision
  "fleet.inv.section": {
    what: "Every host, database, cluster, certificate, key and secret your inventory sources list (a CSV or JSON import, an AWS account, the API), each with the policy decision on it: collect, never scan or not collected, which policy won and why.",
    why: "Shows which part of the estate the fleet policies cover and which part nothing collects.",
    example: "4,210 targets: 3,980 collect, 120 never scan, 110 not collected (no policy matches).",
  },
  // src: backend/utilities/cbom_sources/fleet/inventory_sources.py:7-12 — CSV with a header row, or JSON
  "fleet.inv.import_format": {
    what: "CSV with a header row (external_id, kind, address, addresses, hostname, account_id, region, platform, tags, tag:<key> and handle: or attr: columns) or JSON (a list of objects, or {\"targets\": [...]}). Unknown CSV columns are refused. Picked from the file name when you choose a file.",
    why: "A typo in a column name must not silently drop a tag a policy depends on.",
    example: "CSV exported from your CMDB.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:82-87, backend/utilities/cbom_sources/fleet/inventory_sources.py:29 — up to 10,000 rows
  "fleet.inv.import_file": {
    what: "A .csv or .json file of up to 10,000 targets; its content is loaded into the box below. Importing the same file again changes nothing; targets it no longer lists are marked missing.",
    why: "Keeps the inventory in step with your CMDB export.",
    example: "cmdb-linux-2026-11.csv.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:113-125, backend/utilities/cbom_sources/fleet/inventory_sources.py:13 — external_id defaults to hostname, else address
  "fleet.inv.import_content": {
    what: "The rows to import, pasted or loaded from the file. external_id defaults to the hostname, else the address; kind defaults to linux_host. Preview shows what would change without saving.",
    why: "Check the preview before an import marks hosts missing.",
    example: "A header external_id,kind,address,tag:env and a row web-01,linux_host,10.0.1.5,prod.",
  },
  // src: backend/utilities/cbom_sources/fleet/schemas.py:43 — 1 to 64 characters
  "fleet.inv.aws_name": {
    what: "A name for this AWS inventory source, 1 to 64 characters.",
    why: "Each target shows the source that lists it.",
    example: "aws-payments-prod.",
  },
  // src: backend/utilities/cbom_sources/fleet/aws_inventory.py:1-8 — the validated read-only role; list and describe calls only
  "fleet.inv.aws_account": {
    what: "The AWS account, added and validated on Cloud & Identity, whose read-only role lists the resources. Only list and describe calls are made: no secret value or key material is read.",
    why: "Discovery reuses the role you already approved; no new credential is needed.",
    example: "payments-prod · 111122223333.",
  },
  // src: backend/utilities/cbom_sources/fleet/aws_inventory.py:32,40 — 1 to 20 regions
  "fleet.inv.aws_regions": {
    what: "The regions to list, comma-separated, 1 to 20.",
    why: "Resources in a region not listed here are not discovered.",
    example: "ap-south-1, ap-south-2.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:48,217-232, backend/utilities/cbom_sources/fleet/aws_inventory.py:10-14 — names and tags only; a status per region and service
  "fleet.inv.aws_services": {
    what: "Which AWS services to list: EC2, RDS, EKS, load balancers, ACM certificates, KMS keys and Secrets Manager secrets (names and tags only). Each region and service gets a status; only a fully read one can mark vanished targets missing.",
    why: "Leave out services your role may not list, so they do not show as denied.",
    example: "ec2, rds and acm only.",
  },
  // src: backend/utilities/cbom_sources/fleet/schemas.py:45 — 15 minutes to 7 days
  "fleet.inv.aws_every": {
    what: "How often the account is listed again, from 15 minutes to 7 days (10,080 minutes).",
    why: "New and removed hosts reach the policies at the next sync.",
    example: "60 minutes.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:325 — CSV, JSON, API or AWS with its regions
  "fleet.inv.col.kind": {
    what: "Where the source's targets come from: an import (CSV or JSON), the API, or an AWS account with its regions.",
    why: "AWS sources sync themselves; imports change only when you import again.",
    example: "AWS · ap-south-1, us-east-1.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:311 — target_count
  "fleet.inv.col.targets": {
    what: "How many targets this source lists now.",
    why: "A sudden drop usually means a sync could not read part of the account.",
    example: "1,240.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:327-332,312, backend/utilities/cbom_sources/fleet/aws_inventory.py:10-14 — status, time, error, scopes not read
  "fleet.inv.col.last_sync": {
    what: "The result and time of the last sync or import, its error if any, and the regions and services it could not read (access denied, region not enabled and so on).",
    why: "Targets in a scope that was not read are not marked missing, and may be out of date.",
    example: "partial · 14 Nov 2026, 09:00 · Not read: us-east-1 rds (access denied).",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:462-475 — name, address or ID; applied when typing pauses
  "fleet.inv.search": {
    what: "Finds targets by name, address or external ID; the list updates when you pause typing.",
    why: "Jump to one host in an inventory of thousands.",
    example: "web-01.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:462-464 — a key may contain colons
  "fleet.inv.tag_key": {
    what: "Shows only targets that have this tag key. A key may contain colons.",
    why: "Check what a tag policy will match before you write it.",
    example: "env, or aws:cloudformation:stack-name.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:486-489 — with a tag key; any value when empty
  "fleet.inv.tag_value": {
    what: "With a tag key: shows only targets whose tag has this value. Empty means any value.",
    why: "Narrows the list to one environment or owner.",
    example: "prod.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:43-47 — target kinds
  "fleet.inv.kind": {
    what: "Shows only one kind of target: Linux or Windows host, database, Kubernetes, load balancer, certificate, KMS key, secret or other. Policies collect Linux hosts; the other kinds are listed for the inventory.",
    why: "See how much of each kind the inventory holds.",
    example: "Linux host.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:3-12 — collect, never scan, unmanaged
  "fleet.inv.decision": {
    what: "Shows only targets with one decision: Collect (a policy collects it), Never scan (a never-scan policy or the team's never-scan list), or Not collected (no policy matches, or something the policy needs is not usable).",
    why: "Not collected is the list of hosts nothing reads yet.",
    example: "Not collected: 110 targets.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:508-517, backend/utilities/cbom_sources/fleet/policy.py:9-11 — missing for more than 7 days is not collected
  "fleet.inv.missing": {
    what: "Present: targets the last sync or import listed. Missing: targets a fully read sync or a re-import no longer lists. A target missing for more than 7 days is not collected.",
    why: "Missing hosts were often decommissioned; check before you chase them.",
    example: "Missing: 6 targets since 2 Nov.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:546-551 — name, address and external ID; click for the detail
  "fleet.inv.col.target": {
    what: "The target's host name or address and its external ID. Click a row for its decision, every matching policy, addresses and tags.",
    why: "The detail shows why a policy did or did not win.",
    example: "web-01 · 10.0.1.5 · i-0abc123.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:552 — KIND_LABEL
  "fleet.inv.col.kind_t": {
    what: "What the target is: Linux host, Windows host, database, Kubernetes, load balancer, certificate, KMS key, secret or other.",
    why: "Policies collect Linux hosts over SSH; other kinds are inventory only.",
    example: "Linux host.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:553-560, backend/utilities/cbom_sources/fleet/policy.py:19 — keys compared lower-cased, values exactly
  "fleet.inv.col.tags": {
    what: "The target's tags as key=value (the first four). Policies match tag keys lower-cased and values exactly.",
    why: "Tags are what policies select on.",
    example: "env=prod, owner=payments.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:538 — region and account
  "fleet.inv.col.where": {
    what: "The cloud region and account of the target, when it came from a cloud source.",
    why: "Policies can select on region and account_id too.",
    example: "ap-south-1 · 111122223333.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:562-571,539, backend/utilities/cbom_sources/fleet/policy.py:3-14 — the first matching policy wins
  "fleet.inv.col.decision": {
    what: "Collect, Never scan or Not collected, the policy that won (highest priority, then the older one) and the reason. Waiting for a running job means its managed source changes when that job ends.",
    why: "Shows exactly which rule decides each host, so overlaps are easy to spot.",
    example: "Collect · prod-weekly won (priority 200) over linux-default.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Fleet > Policies (F1.2, PR #81)
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:3-5, backend/utilities/cbom_sources/fleet/policy.py:1-14 — first match by priority wins; never-scan list overrides
  "fleet.pol.section": {
    what: "Rules that decide how each inventory target is collected: a selector over tags and fields, and an action (collect over SSH with a credential, scan node and schedule, or never scan). The highest-priority match wins, then the older policy; the team's never-scan list overrides every policy. Apply policies creates and updates the managed sources and schedules.",
    why: "Thousands of hosts are covered by a few rules instead of one source per host.",
    example: "pci (priority 500): never scan; prod-weekly (200): collect weekly; linux-default (0): collect monthly.",
  },
  // src: backend/utilities/cbom_sources/fleet/schemas.py:69 — 1 to 64 characters
  "fleet.pol.name": {
    what: "A name for the policy, 1 to 64 characters, shown on each target it wins.",
    why: "The targets table names the policy that decided each host.",
    example: "prod-weekly.",
  },
  // src: backend/utilities/cbom_sources/fleet/schemas.py:71, backend/utilities/cbom_sources/fleet/policy.py:6-7 — 0 to 1,000,000; higher wins, then the older policy
  "fleet.pol.priority": {
    what: "0 to 1,000,000. When several policies match a target, the highest priority wins; on a tie the older policy wins.",
    why: "Put exceptions, such as never scan for PCI hosts, above the broad rules.",
    example: "500 for pci, 100 for the default.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:17-19 — all / any / not, leaves on tags and fields, at most 20
  "fleet.pol.selector": {
    what: "The conditions a target must meet: on a tag (any key) or a field (kind, account_id, region, platform). No condition matches every target. At most 20 conditions; no regular expressions.",
    why: "Decides which hosts this policy governs.",
    example: "env is prod and region starts with ap-.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:129-151, backend/utilities/cbom_sources/fleet/policy.py:17-19 — tag or field; keys lower-cased, values exact
  "fleet.pol.condition": {
    what: "What the condition tests: a tag, by key (compared lower-cased), or a field: kind, account_id, region or platform.",
    why: "Tags carry your own grouping; fields come from the inventory source.",
    example: "Tag env, or Field region.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:153-162, frontend/components/cbom/sources/fleet/fleetLogic.ts:81-87 — is, is not, is one of, is set, starts with
  "fleet.pol.operator": {
    what: "How the value is compared: is, is not, is one of (comma-separated, up to 50 values), is set (any value), or starts with. Values are compared exactly.",
    why: "Pick the narrowest test that matches what you mean.",
    example: "env is one of prod, dr.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:250-261, backend/utilities/cbom_sources/fleet/policy.py:17 — all or any
  "fleet.pol.combine": {
    what: "All conditions must hold, or any one is enough.",
    why: "Changes how many targets the policy matches; preview it before saving.",
    example: "All: env is prod and platform is ubuntu.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:277-281, backend/utilities/cbom_sources/fleet/policy.py:17-19 — the selector grammar
  "fleet.pol.selector_json": {
    what: "A selector that uses not or nesting is edited as JSON: {\"all\": [...]}, {\"any\": [...]}, {\"not\": {...}} and leaves {\"tag\": k, \"op\": op, \"value\": v} or {\"field\": f, \"op\": op, \"value\": v}. At most 20 leaves, 6 levels deep.",
    why: "Expresses exclusions the simple form cannot.",
    example: "env is prod but not tagged pci: {\"all\": [{\"tag\": \"env\", \"op\": \"eq\", \"value\": \"prod\"}, {\"not\": {\"tag\": \"pci\", \"op\": \"exists\"}}]}.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:8-12 — collect, never scan, or not collected with the reason
  "fleet.pol.action": {
    what: "Collect the matched targets over SSH with the credential, scan node, tier, batch size and schedule below, or never scan them. A target that cannot be collected (not a Linux host, no address, a deleted credential or node, missing for over 7 days) is listed as not collected with the reason.",
    why: "Decides what a run does with every host this policy wins.",
    example: "Collect weekly on Sunday 02:00 through node-dc1.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:8 — a never-scan winner gives never_scan
  "fleet.pol.never_scan": {
    what: "Targets this policy wins are never collected, whatever lower-priority policies say.",
    why: "Keeps sensitive systems out of every scan by rule, not by hand.",
    example: "tag pci is set: never scan.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Fleet > Transports (F1.3, #318)
  // src: frontend/components/cbom/sources/fleet/TransportsSection.tsx:1-7, backend/routers/cbom_transports.py:1-7 — AWX/AAP, Salt and SSM transports; secrets write-only
  "fleet.tr.section": {
    what: "Your own configuration management runs the ZeroShield collector on the hosts instead of an SSH login from a scan node: Ansible (AWX or Automation Platform), Salt, or AWS Systems Manager. A fleet policy chooses one in Collect through.",
    why: "Hosts your automation already reaches need no SSH key, firewall rule or login for ZeroShield.",
    example: "awx-prod: job template 42 on https://awx.example.com, used by 3 managed sources.",
  },
  // src: backend/routers/cbom_transports.py:133-140 — kind awx, salt or ssm
  "fleet.tr.kind": {
    what: "Which automation runs the collector: an AWX or Ansible Automation Platform job template, the salt-api, or AWS Systems Manager Run Command. AWX and Salt are called from a scan node inside your network; SSM is called from ZeroShield through a read-only role.",
    why: "Decides what is asked for below and what you install on your side.",
    example: "Salt, for hosts that are already minions.",
  },
  // src: backend/routers/cbom_transports.py:138 — 1 to 64 characters, unique in the team
  "fleet.tr.name": {
    what: "A name for this transport, 1 to 64 characters, unique in the team; policies list transports by name.",
    why: "Policies pick the transport by name in Collect through.",
    example: "awx-prod.",
  },
  // src: backend/routers/cbom_transports.py:46-52,55,77 — https only, no user, query or fragment
  "fleet.tr.base_url": {
    what: "The https:// address of your AWX or Automation Platform, or of your salt-api, as a scan node inside your network reaches it. No user name, query or fragment.",
    why: "The scan node calls this address to start the collection; plain HTTP would expose the token.",
    example: "https://awx.example.com.",
  },
  // src: backend/routers/cbom_transports.py:56 — job_template_id, a number from 1
  "fleet.tr.job_template": {
    what: "The ID of the AWX or Automation Platform job template that runs the ZeroShield Ansible collection (the ansible-collection file below) on the hosts it is given.",
    why: "ZeroShield launches this template with the hosts of each batch, nothing else.",
    example: "42 (the ID in the template's URL).",
  },
  // src: backend/routers/cbom_transports.py:133 — secrets awx: token, write-only
  "fleet.tr.token": {
    what: "An AWX or Automation Platform token that may launch the job template. It is encrypted, sent only to the scan node that runs the job, and never shown again.",
    why: "Without it the job template cannot be launched; keep its scope to that template.",
    example: "An application token with execute on job template 42.",
  },
  // src: backend/routers/cbom_transports.py:133 — secrets salt: username and password
  "fleet.tr.salt_user": {
    what: "The salt-api user ZeroShield signs in as, with the external authentication set below (pam by default). Stored encrypted and never shown again.",
    why: "Give it only the publisher rights the ZeroShield state needs.",
    example: "zs-collect.",
  },
  // src: backend/routers/cbom_transports.py:133 — secrets salt: username and password
  "fleet.tr.salt_password": {
    what: "The password of the salt-api user. It is encrypted, sent only to the scan node that runs the job, and never shown again.",
    why: "salt-api refuses the batch without it.",
    example: "The password of zs-collect.",
  },
  // src: backend/routers/cbom_transports.py:79 — client local, local_async or ssh
  "fleet.tr.salt_client": {
    what: "How Salt reaches the hosts: minions asynchronously (default), minions while the call waits, or salt-ssh for hosts without a minion.",
    why: "salt-ssh needs a bigger master and smaller batches.",
    example: "Minions (async).",
  },
  // src: backend/routers/cbom_transports.py:80 — mode state or cmd
  "fleet.tr.salt_mode": {
    what: "Whether Salt runs the collector as a command (default) or applies the ZeroShield state from the salt-state file below.",
    why: "A state fits teams that keep everything in states.",
    example: "A command.",
  },
  // src: backend/routers/cbom_transports.py:73,81,97-104 — 1 to 500; at most 100 with salt-ssh
  "fleet.tr.salt_batch": {
    what: "How many hosts one salt-api call covers, 1 to 500 (default 50). With salt-ssh at most 100, as one batch is one salt-api request.",
    why: "Too large a salt-ssh batch outruns the request timeout and the master's memory.",
    example: "50 hosts per call.",
  },
  // src: backend/routers/cbom_transports.py:57,83 — verify_tls, default on
  "fleet.tr.verify_tls": {
    what: "Check the control plane's TLS certificate before the token or password is sent. On by default; turn it off only in a lab.",
    why: "Off, anyone on the path could read the secret.",
    example: "On, with the CA below for an internal certificate.",
  },
  // src: backend/routers/cbom_transports.py:58,84 — ca_pem, PEM certificates
  "fleet.tr.ca_pem": {
    what: "The PEM certificate of the CA that issued the control plane's certificate, when it is your own CA rather than a public one.",
    why: "Lets TLS verification stay on with an internal CA.",
    example: "-----BEGIN CERTIFICATE----- of your internal root.",
  },
  // src: backend/routers/cbom_transports.py:108,112-117 — an IAM role ARN; assumed with the team's external id
  "fleet.tr.role_arn": {
    what: "The IAM role ZeroShield assumes with your external ID to send the SSM command. The ssm-role-cfn file below creates it with only the permissions it needs.",
    why: "No access key is exchanged; you can revoke the role at any time.",
    example: "arn:aws:iam::123456789012:role/zeroshield-cbom-run.",
  },
  // src: backend/routers/cbom_transports.py:109,119-125 — 1 to 16 regions
  "fleet.tr.regions": {
    what: "The AWS regions whose managed instances are collected, 1 to 16, comma or space separated.",
    why: "Run Command is regional: a region not listed is not reached.",
    example: "ap-south-1, eu-west-1.",
  },
  // src: backend/routers/cbom_transports.py:110 — devsecshield- prefix
  "fleet.tr.document": {
    what: "The name of the SSM document that runs the collector, created from the ssm-document file below. It starts with devsecshield-.",
    why: "Test checks the document exists in every listed region.",
    example: "devsecshield-collect.",
  },
  // src: backend/routers/cbom_transports.py:111 — output_s3_bucket, optional
  "fleet.tr.bucket": {
    what: "An S3 bucket in your account where Run Command also writes its output, for your own audit.",
    why: "Keeps a copy of every run on your side.",
    example: "zs-cbom-runs.",
  },
  // src: frontend/components/cbom/sources/fleet/TransportsSection.tsx:1-7 — the transport's kind
  "fleet.tr.col.kind": {
    what: "Ansible (AWX / AAP), Salt or AWS Systems Manager: the automation that runs the collector.",
    why: "Tells you where to look when a run fails.",
    example: "Salt.",
  },
  // src: backend/routers/cbom_transports.py:191-196 — config, never a secret
  "fleet.tr.col.where": {
    what: "Where the transport points: the control plane URL and job template or Salt client, or the role and regions for SSM. Never a secret.",
    why: "Confirms which automation a policy will call.",
    example: "https://awx.example.com · job template 42.",
  },
  // src: backend/routers/cbom_transports.py:191-196 — secrets_set, names only
  "fleet.tr.col.secrets": {
    what: "Which secrets are stored for this transport, by name only. Secrets are write-only: they are never shown again.",
    why: "You can tell a transport is complete without the secret ever leaving ZeroShield.",
    example: "token.",
  },
  // src: backend/routers/cbom_transports.py:349-368 — validate is SSM only
  "fleet.tr.col.status": {
    what: "For SSM, the last Test: role assumed with the external ID and the document found in each region. AWX and Salt are reached from a scan node in your network, so a source that uses them is what tests them.",
    why: "Shows whether ZeroShield can use the transport before a policy depends on it.",
    example: "Failed · The run-command role could not be used: AccessDenied.",
  },
  // src: backend/routers/cbom_transports.py:324-336 — a transport in use cannot be deleted
  "fleet.tr.col.used_by": {
    what: "The managed sources that collect through this transport. A transport in use cannot be deleted.",
    why: "Shows what stops collecting if you change it.",
    example: "fleet-4-1, fleet-4-2.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:1-5, backend/utilities/cbom_sources/fleet/policy.py:247-273 — ssh or a transport; SSM needs no scan node
  "fleet.pol.transport": {
    what: "How the matched targets are collected: SSH from a scan node with a credential, or one of your transports. AWX and Salt still need the scan node that reaches their control plane; SSM runs from ZeroShield.",
    why: "Hosts your automation already manages need no SSH login.",
    example: "awx-prod (Ansible), through scan node dc1.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:294-303 — from Fleet > Credentials
  "fleet.pol.credential": {
    what: "The credential the managed sources sign in with. Add one in Credentials below.",
    why: "Without a usable credential the targets are not collected.",
    example: "linux-fleet · ssh_cert.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:180-182,304-306 — agentless nodes only
  "fleet.pol.node": {
    what: "The agentless scan node, in a segment that reaches these hosts, that runs the collection.",
    why: "The node must reach every matched host on the SSH port.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:307-315, backend/utilities/cbom_sources/fleet/policy.py:275-278 — 1 or 2
  "fleet.pol.tier": {
    what: "Tier 1 reads without sudo. Tier 2 also runs the read-only sudo lines published on the Servers tab, for files only root can read.",
    why: "Tier 2 finds more (private key files, service configs) but needs the sudoers lines on each host.",
    example: "Tier 2 on hosts where the sudoers file is rolled out.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:279-282, backend/utilities/cbom_sources/fleet/materialize.py:7-9 — 25 to 1,000 targets per managed source
  "fleet.pol.batch": {
    what: "How many targets go into one managed source, 25 to 1,000. A target keeps its managed source while its policy, credential and node stay the same.",
    why: "Smaller batches spread the work over more jobs; larger ones mean fewer sources to watch.",
    example: "100 targets per managed source.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:287-297, backend/utilities/cbom_sources/fleet/materialize.py:322,373 — daily, weekly or monthly in the team's scan window time zone
  "fleet.pol.schedule": {
    what: "When the policy's managed sources are collected: on demand, daily, weekly or monthly, at a time in the team's scan window time zone. One managed schedule per policy.",
    why: "Keeps the inventory current without starting runs by hand.",
    example: "Weekly, Sunday at 02:00.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:298-304 — HH:MM, 24 hour
  "fleet.pol.time": {
    what: "The time of day the scheduled run starts, 24-hour HH:MM.",
    why: "Pick a quiet hour for the hosts and the network.",
    example: "02:00.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:305-310 — Monday to Sunday
  "fleet.pol.weekday": {
    what: "The day of the week a weekly schedule runs.",
    why: "Avoid your change-window days.",
    example: "Sunday.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:312-314 — 1 to 28
  "fleet.pol.monthday": {
    what: "The day of the month a monthly schedule runs, 1 to 28, so every month has it.",
    why: "Line the run up with your monthly reporting.",
    example: "1, the first of each month.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:485-493 — name, priority, disabled
  "fleet.pol.col.policy": {
    what: "The policy's name and priority, in the order the policies apply; Disabled when it is switched off.",
    why: "The first matching policy in this order wins.",
    example: "1. pci · priority 500.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:475, frontend/components/cbom/sources/fleet/fleetLogic.ts:153-155 — the selector in words
  "fleet.pol.col.matches": {
    what: "The policy's selector in words.",
    why: "Read what the policy covers without opening it.",
    example: "env is prod and region starts with ap-.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:476 — actionText
  "fleet.pol.col.does": {
    what: "The policy's action in words: never scan, or collect with which credential, node, tier and schedule.",
    why: "Shows what happens to the targets it wins.",
    example: "Collect over SSH with linux-fleet on node-dc1, tier 1, weekly.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:477, backend/utilities/cbom_sources/fleet/policy.py:6-7 — won by this policy / matched by its selector
  "fleet.pol.col.targets": {
    what: "Targets this policy decides (won) over targets its selector matches. Matched but not won means a higher-priority policy or the never-scan list decided them.",
    why: "A big gap between the two shows policies overlapping.",
    example: "1,180 / 1,240.",
  },
} as const satisfies TipAreaText;

export default TEXT;
