/**
 * (i) tip text of the "cbsrc-common" area (ids: cbsrc.col.*, cbsrc.common.*, cbsrc.sources.*, cbsrc.sidebar.*, cbsrc.meta.*, cbsrc.compare.*, cbsrc.waves.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── CBOM Sources: shared by the tabs, and Servers (components/cbom/sources/ServersTab.tsx)
  // src: frontend/components/cbom/sources/ServersTab.tsx:967, backend/utilities/cbom_sources/kinds.py:26 — 1-64 letters, digits, spaces, dots, dashes, underscores
  "cbsrc.common.name": {
    what: "A name for this source, 1 to 64 letters, digits, spaces, dots, dashes or underscores. It labels the source in lists, run results, the CBOM and reports.",
    why: "Every asset a run finds records the source it came from, so a clear name tells an auditor where a weak key or certificate lives.",
    example: "dc-mumbai-linux for the Linux servers of the Mumbai data centre.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:977-987, backend/utilities/cbom_sources/jobs.py:323 — jobs of the source run on this node
  "cbsrc.common.node": {
    what: "The scan node, inside your network, that connects to these targets and collects their crypto. Every job of this source (connection tests and collection) runs on it.",
    why: "Only a node that can reach the targets on the right port can read them; a node in the wrong network segment makes every target unreachable.",
    example: "node-dc1 in the 10.20.0.0/16 segment for servers in 10.20.5.0/24.",
  },
  // src: frontend/components/cbom/sources/teamNeverScan.ts:93-94 — per-source exclusions; never-scan always wins
  "cbsrc.common.never_scan": {
    what: "Addresses, ranges or hostnames this source must never touch, one per line or comma-separated. A hostname also covers every address it resolves to from the scan node. The team never-scan list on the Network tab applies as well. Never-scan always wins over targets.",
    why: "Keeps fragile or out-of-scope systems (a core banking host, a partner's range) out of every job.",
    example: "10.20.0.1, 10.20.0.254 keeps the two gateways out of 10.20.0.0/24.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:136-141 — HashiCorp Vault, CyberArk, AWS Secrets Manager, Azure Key Vault
  "cbsrc.common.vault_provider": {
    what: "The secrets manager the scan node reads the credential from when a job runs: HashiCorp Vault, CyberArk, AWS Secrets Manager or Azure Key Vault.",
    why: "The password stays in your vault and is never stored by ZeroShield.",
    example: "CyberArk, where the svc-zscbom password is already rotated daily.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1373-1381 — only the reference is stored
  "cbsrc.common.vault_path": {
    what: "Where the secret lives in your vault. The scan node reads it when the job runs; ZeroShield stores only this reference. Only a team admin can add or change it.",
    why: "A wrong path fails every job of the source at the login step.",
    example: "secret/data/cbom/linux-prod for HashiCorp Vault KV v2.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1397-1407, backend/utilities/cbom_sources/kinds.py:20 — encrypted at rest; blank on edit keeps the saved one
  "cbsrc.common.password": {
    what: "The account's password. Encrypted at rest by ZeroShield, sent only to the scan node that runs the job and never shown again. When editing, leave it blank to keep the saved one.",
    why: "Changing the targets, port, login or node clears a stored password, so it is never sent to a host it was not meant for.",
    example: "The password of svc-zscbom, rotated every 90 days.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1546-1578 — team network window, any time, or a custom copy
  "cbsrc.common.window": {
    what: "When collection may run: the team scan window set on the Network tab, any time, or a custom copy of the weekly hours for this source. Connection tests always run straight away.",
    why: "Keeps scans out of business hours or change freezes on production systems.",
    example: "Network window (team): weekdays 22:00 to 06:00 IST.",
  },
  // src: backend/routers/cbom_sources.py:624-648 — #225: server-side search
  "cbsrc.sources.search": {
    what: "Finds sources by name or by anything in their settings: a target host or IP address, owner, application, API URL. Searched on the server, so it covers every source, not only the rows loaded.",
    why: "With thousands of sources, scrolling is not a way to find one.",
    example: "10.20.0.11 finds the server source that lists it.",
  },
  // src: backend/routers/cbom_sources.py:624-648 — #225: kind filter
  "cbsrc.sources.filter_kind": {
    what: "Shows only sources of one kind, such as Windows servers or databases.",
    why: "Narrows a long list to the sources you are working on.",
    example: "Windows servers.",
  },
  // src: backend/routers/cbom_sources.py:624-648, backend/utilities/cbom_sources/serialize.py:111 — #225: segment of the source's scan node
  "cbsrc.sources.filter_segment": {
    what: "Shows only sources whose scan node is in this segment (the segment set on the scan node).",
    why: "Per data centre or network zone, you can check what each node covers.",
    example: "dc-chennai.",
  },
  // src: backend/routers/cbom_sources.py:615-648 — #225: enabled, disabled or the last test result
  "cbsrc.sources.filter_status": {
    what: "Shows enabled or disabled sources, or sources by their last connection test: passed, partly passed, failed, error, running or never tested.",
    why: "Failed and untested sources are the ones to fix before a run.",
    example: "Test failed.",
  },
  // src: frontend/components/cbom/sources/SourceTableControls.tsx:163-217 — #225: every source, searchable and paged
  "cbsrc.sources.all": {
    what: "Every source of the team across all tabs, searched and filtered on the server and loaded 100 at a time.",
    why: "One place to check what a run covers, however many sources the team has.",
    example: "Showing 100 of 4,512 sources.",
  },
  // src: backend/utilities/cbom_sources/serialize.py:111 — #225: the scan node's segment
  "cbsrc.col.segment": {
    what: "The segment of the scan node that runs this source, as set on the scan node.",
    why: "Shows which network zone or data centre the source is reached from.",
    example: "dc-mumbai.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:117-124 — the source kind
  "cbsrc.col.type": {
    what: "The kind of source: what it reads and how.",
    why: "Each type uses a different protocol, port and credential.",
    example: "Linux servers over SSH; Active Directory over LDAPS.",
  },
  // src: backend/utilities/cbom_sources/jobs.py:323 — targets after exclusions
  "cbsrc.col.targets": {
    what: "How many addresses or names this source covers after its never-scan list and the team never-scan list are removed.",
    why: "Collection credits and run time grow with the number of targets.",
    example: "254 for 10.20.0.0/24 minus the two gateways.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:977-987 — the scan node that runs the source's jobs
  "cbsrc.col.node": {
    what: "The scan node that runs this source's jobs.",
    why: "An offline node means the source cannot be tested or collected.",
    example: "node-dc1 · Online.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1415-1429 — Tier 1 or Tier 2
  "cbsrc.col.tier": {
    what: "The privilege tier of a Linux source: Tier 1 without sudo, Tier 2 with the exact sudo allowlist.",
    why: "Tier 2 sees runtime crypto use that Tier 1 cannot.",
    example: "Tier 2 on the application servers, Tier 1 elsewhere.",
  },
  // src: backend/utilities/cbom_sources/jobs.py:716-736 — passed, partial, failed, could not test
  "cbsrc.col.last_test": {
    what: "The result of the latest connection test: Not tested, Testing, Passed (every sample ready), Partly ready, Failed or Could not test, with its summary below.",
    why: "A source that has not passed a test is likely to fail its collection jobs.",
    example: "Partly ready · 3 of 5 samples ready.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: source metadata (components/cbom/sources/SourceMetadata.tsx)
  // src: backend/utilities/cbom_sources/kinds.py:55-56, backend/utilities/cbom_sources/kinds.py:67, backend/utilities/cbom_sources/waves.py:121 — up to 128 characters; the default remediation owner
  "cbsrc.meta.owner": {
    what: "The team or person who answers for this source, up to 128 characters. Remediation waves use it as the owner of this source's findings.",
    why: "A finding without an owner is rarely fixed; this routes it to the right people.",
    example: "Payments platform team.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:55-56, backend/utilities/cbom_sources/kinds.py:68 — up to 128 characters
  "cbsrc.meta.application": {
    what: "The business application this source serves, up to 128 characters, shown with its findings in reports and the roadmap.",
    why: "Migration is planned per application, so findings grouped by it are easier to schedule.",
    example: "UPI switch.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:55-56, backend/utilities/cbom_sources/kinds.py:69 — public, internal, confidential or restricted
  "cbsrc.meta.classification": {
    what: "How sensitive the data this source handles is: Public, Internal, Confidential or Restricted.",
    why: "Sensitive data protected by quantum-vulnerable crypto is the first thing to migrate.",
    example: "Restricted for systems holding card or Aadhaar data.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:70, backend/utilities/cbom_sources/posture.py:10-11 — 0 to 100 years; Mosca's X
  "cbsrc.meta.lifetime": {
    what: "How many years this source's data must stay confidential, 0 to 100: Mosca's X. With the team's migration time (Y) and quantum timeline (Z), X + Y > Z means the data is already at risk.",
    why: "Long-lived data encrypted with RSA or ECDH today can be recorded now and decrypted later (harvest now, decrypt later).",
    example: "10 for loan records kept a decade: with Y = 3 and Z = 10, 13 > 10, so it is at risk now.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:57, backend/utilities/cbom_sources/kinds.py:71 — up to 32 characters, as the CMDB names it
  "cbsrc.meta.environment": {
    what: "The environment of this source as your CMDB names it, up to 32 characters. A CMDB import fills it in.",
    why: "Lets you plan production fixes separately from test systems.",
    example: "production.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:54, backend/utilities/cbom_sources/posture.py:47, backend/utilities/cbom_sources/posture.py:398 — overrides the derived exposure; internet x1.5
  "cbsrc.meta.exposure": {
    what: "Overrides the internet exposure worked out from the collected facts: From collected facts (no override), Internet-facing, Internal or Unknown. Internet-facing multiplies the risk score of this source's findings by 1.5.",
    why: "Systems reachable from the internet are attacked first, so their weak crypto ranks higher.",
    example: "Internet-facing for the API gateway servers behind the public load balancer.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:53, backend/utilities/cbom_sources/posture.py:44, backend/utilities/cbom_sources/posture.py:496-497 — low 0.5, medium 1, high 1.5, critical 2
  "cbsrc.meta.criticality": {
    what: "How critical the systems of the selected sources are to the business. It scales the risk score of their findings: Low x0.5, Medium x1 (the default), High x1.5, Critical x2.",
    why: "The same weak cipher matters more on a payment switch than on a test box.",
    example: "Critical: a High finding (7) on an internet-facing source scores 7 x 2 x 1.5 = 21.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:59-62 — metadata never cancels a job or resets the test
  "cbsrc.meta.bulk": {
    what: "Set the owner, application, data classification, data lifetime, environment and criticality of several sources at once. These describe the source, so saving them never cancels a job or resets its connection test.",
    why: "Ownership and sensitivity drive risk scores and remediation waves for every run that follows.",
    example: "Select the 4 Mumbai sources and set Owner to Payments platform team.",
  },
  // src: frontend/components/cbom/sources/SourceMetadata.tsx:240-250 — which sources the bulk edit changes
  "cbsrc.meta.select": {
    what: "Choose the sources the values below are written to; the first box selects every source.",
    why: "Only selected sources change; the others keep their values.",
    example: "Tick dc-mumbai-linux and dc-mumbai-windows, then Apply.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:468 — API server URL, host and port, module or KMIP host
  "cbsrc.col.endpoint": {
    what: "Where the source is reached: the cluster's API server URL, the database host and port, the PKCS#11 module, or the KMIP server.",
    why: "The scan node must reach this endpoint for the source's jobs to succeed.",
    example: "https://10.30.0.5:6443 for a cluster.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:469 — tier for clusters, login for databases
  "cbsrc.col.access": {
    what: "How the source is read: the access tier of a cluster (Tier 1 without Secrets, Tier 2 with) or the login of a database.",
    why: "It shows how much each source's credential can see.",
    example: "Tier 1 for prod-payments; zs_cbom for pg-core-01.",
  },
  // src: frontend/components/cbom/sources/ChangesPanel.tsx:242, frontend/components/cbom/sources/ChangesPanel.tsx:242-246 — the previous complete run or a chosen one
  "cbsrc.compare.with": {
    what: "The run to compare this one with: by default each source's previous complete collection, or a run you choose. Partial or failed jobs show as not compared, never as everything removed.",
    why: "Comparing shows exactly what changed between two points in time.",
    example: "Run #38, before the TLS hardening change.",
  },
  // src: frontend/components/cbom/sources/SidebarSources.tsx:44 — off by default; adds the group's run and credits to the estimate
  "cbsrc.sidebar.include": {
    what: "Also run a collection of this group of CBOM Sources with this scan. Off by default; turning it on adds that group's collection run and its credits to the estimate. Sources are managed on the CBOM Sources page.",
    why: "One action then covers the code and the infrastructure that runs it.",
    example: "Include servers: 3 sources with 31 targets add 6.20 credits (0.2 per target).",
  },
  // src: frontend/components/cbom/sources/SidebarSources.tsx:162-170 — required with network TLS
  "cbsrc.sidebar.soc": {
    what: "Confirm that your SOC has agreed the network ranges and scan windows. Required when network TLS is included.",
    why: "Active network probing without SOC agreement is often treated as an incident.",
    example: "Tick after the SOC acknowledged the ranges.",
  },
  // src: backend/utilities/cbom_sources/waves.py:44-60 — suggested_wave: 1 weakness Critical/High and exposed or HNDL, or any HNDL quantum-vulnerable asset; 2 other Critical/High weakness; 3 other weakness; 4 quantum-vulnerable only
  "cbsrc.waves.card": {
    what: "Each asset's suggested wave: 1 for a Critical or High weakness that is internet-exposed or harvest-now-decrypt-later, and for any harvest-now-decrypt-later quantum-vulnerable asset; 2 other Critical or High weaknesses; 3 other weaknesses; 4 post-quantum migration. Assign a wave, owner, target date and status; plans follow the asset to later runs and scans.",
    why: "Waves turn a long findings list into an ordered plan with owners and dates.",
    example: "Wave 1: RSA-2048 key exchange on api.bank.in:443, owner Payments, due 31 Dec.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:151-155 — hides assets without a wave
  "cbsrc.waves.only_planned": {
    what: "Show only assets that have a wave, hiding those that need no action.",
    why: "Keeps the list to what someone has to fix.",
    example: "On: 1,284 assets narrow to 96.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:164-168 — selection for the bulk bar
  "cbsrc.waves.select": {
    what: "Select assets to assign together with the bar above.",
    why: "Assign a whole group to one owner and date in one step.",
    example: "Tick the 12 wave-1 certificates of api.bank.in.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:98-104 — set or keep the wave
  "cbsrc.waves.bulk_wave": {
    what: "The wave to give the selected assets: 1 to 4, Use suggested (the wave worked out from impact and exposure), or Keep wave.",
    why: "Override the suggestion when you know better, for example a system due to be retired.",
    example: "Wave 2.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:106-107 — up to 128 characters
  "cbsrc.waves.bulk_owner": {
    what: "Who fixes the selected assets, up to 128 characters. Blank keeps each one's owner.",
    why: "Each fix needs a named owner to happen.",
    example: "Payments platform team.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:109-110 — date
  "cbsrc.waves.bulk_date": {
    what: "When the selected assets should be fixed by. Blank keeps each one's date.",
    why: "Dates let you track the plan against regulator deadlines.",
    example: "31 Mar 2027.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:29, frontend/components/cbom/sources/WavesControls.tsx:113-120 — open, in progress, done, risk accepted
  "cbsrc.waves.bulk_status": {
    what: "The status to set: Open, In progress, Done or Risk accepted; or Keep status.",
    why: "Done items should disappear from the next run; Risk accepted records a decision.",
    example: "In progress.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:78-88 — last connection test
  "cbsrc.col.test": {
    what: "The result of the last connection test: Not tested, Testing, Passed, Partly ready, Failed or Could not test.",
    why: "A source that has not passed a test is likely to fail its collection jobs.",
    example: "Passed.",
  },
} as const satisfies TipAreaText;

export default TEXT;
