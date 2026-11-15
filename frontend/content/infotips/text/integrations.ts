/**
 * (i) tip text of the "integrations" area (ids: int.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── Settings > Integrations (components/integrations/IntegrationsPage.tsx)
  // src: frontend/components/integrations/IntegrationsPage.tsx:139-140 — one record per finding; resolved when a later complete run no longer finds it
  "int.card.servicenow": {
    what: "Opens one ServiceNow record per new finding (de-duplicated by a correlation id) and resolves it when a later complete run no longer finds it. Also the source for the CMDB import on CBOM Sources.",
    why: "Findings land in the queue your teams already work from, and close themselves when fixed.",
    example: "INC0012345: RSA-1024 certificate on api.bank.in:443, assigned to Payments.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:133 — RFC 5424 with CEF or JSON
  "int.card.syslog": {
    what: "Sends every event as an RFC 5424 syslog message with a CEF or JSON payload to your SIEM or SOAR.",
    why: "Your SOC sees crypto findings next to other security alerts.",
    example: "A CEF event Finding opened, severity High, to ArcSight on 6514.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:134 — batched JSON events
  "int.card.splunk_hec": {
    what: "Sends every event to a Splunk HTTP Event Collector, batched as JSON events.",
    why: "Lets you build Splunk dashboards and alerts on crypto findings.",
    example: "sourcetype zeroshield:cbom in index security.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:135 — HMAC-SHA256 over timestamp and body
  "int.card.webhook": {
    what: "POSTs every event as JSON to your receiver, signed with HMAC-SHA256 over the timestamp and the body.",
    why: "Any SOAR or in-house tool can act on events and prove they came from ZeroShield.",
    example: "A Certificate expiring event POSTed to https://soar.bank.in/hooks/zeroshield.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:136 — OSCAL 1.2.3 assessment results, schema-validated, signed
  "int.card.oscal": {
    what: "When a Sources run or a CBOM code scan finishes, pushes its OSCAL 1.2.3 assessment results (schema-validated) to your GRC tool, signed like the webhook.",
    why: "Auditors get machine-readable evidence without exports by hand.",
    example: "Run #42's assessment results pushed to https://grc.bank.in/api/oscal.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:289-291 — on or off per integration
  "int.enabled": {
    what: "On: events are queued and delivered to this destination. Off: nothing is sent; the settings are kept.",
    why: "Turn it off during a destination's maintenance instead of deleting the integration.",
    example: "Off while the SIEM is being migrated.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:55-58,73 — PEM; certificates are always verified
  "int.common.ca_pem": {
    what: "Optional PEM certificate of the CA that signed the destination's certificate, when it is not publicly trusted. The destination's certificate is always verified.",
    why: "Without it, a destination with an internal CA fails every delivery on the TLS check.",
    example: "bank-root-ca.pem for siem.bank.local.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:79 — https://<instance>.service-now.com
  "int.sn.instance_url": {
    what: "Your ServiceNow instance's address.",
    why: "Records are created only on this instance.",
    example: "https://bank.service-now.com.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:80 — incident or sn_vul_vulnerable_item
  "int.sn.table": {
    what: "The table records are created in: incident, or sn_vul_vulnerable_item with Vulnerability Response.",
    why: "Use the table your remediation teams work from.",
    example: "sn_vul_vulnerable_item.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:81 — user and password or OAuth client credentials
  "int.sn.auth": {
    what: "How ZeroShield signs in to ServiceNow: a user and password, or OAuth client credentials.",
    why: "OAuth credentials can be scoped and rotated without a user account.",
    example: "OAuth client credentials for the zeroshield-integration app.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:82 — basic authentication user
  "int.sn.username": {
    what: "The ServiceNow user for basic authentication, with rights to create and update records in the table.",
    why: "A dedicated integration user makes the records' origin clear in audit history.",
    example: "svc_zeroshield.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:83 — OAuth client credentials
  "int.sn.client_id": {
    what: "The client ID of the OAuth application registered in ServiceNow.",
    why: "Pairs with the client secret below.",
    example: "3f9c1e2a7b...",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:84 — optional
  "int.sn.assignment_group": {
    what: "Optional: the group new records are assigned to.",
    why: "Records without a group may sit unassigned.",
    example: "PKI Operations.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:85 — optional
  "int.sn.category": {
    what: "Optional: the category set on new records.",
    why: "Lets you filter and report crypto findings in ServiceNow.",
    example: "Security.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:86 — incident: 6 (Resolved)
  "int.sn.resolve_state": {
    what: "The state value set when a finding is no longer found by a later complete run.",
    why: "A wrong value leaves fixed findings open in ServiceNow.",
    example: "6 (Resolved) for incident.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:87 — close code on resolve
  "int.sn.close_code": {
    what: "The resolution (close) code set when a record is resolved.",
    why: "Some instances refuse to resolve a record without a close code.",
    example: "Solution provided.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:88 — resolving always goes through
  "int.sn.min_severity": {
    what: "The lowest severity that opens a new record. Resolving a record always goes through.",
    why: "Keeps low findings out of the ticket queue while still closing records that exist.",
    example: "High and above.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:91 — one record per finding
  "int.sn.correlation_field": {
    what: "The field that stores ZeroShield's finding id. Before creating a record, ZeroShield looks it up by this field, so each finding has one record.",
    why: "Prevents duplicates when a finding is seen in every run.",
    example: "correlation_id.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:93 — the table the CMDB import reads
  "int.sn.cmdb_table": {
    what: "The CMDB table the CMDB import on CBOM Sources reads.",
    why: "Point it at the class that holds your servers.",
    example: "cmdb_ci_server.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:94 — encoded query, optional
  "int.sn.cmdb_query": {
    what: "Optional: a ServiceNow encoded query that limits which CMDB records are imported.",
    why: "Leaves decommissioned or non-production CIs out.",
    example: "operational_status=1.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:95 — fields tried in order
  "int.sn.cmdb_host": {
    what: "The CMDB fields that hold the host, tried in order.",
    why: "The first non-empty field becomes the target the import matches or adds.",
    example: "fqdn, ip_address, host_name, name.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:96 — maps to the source owner
  "int.sn.cmdb_owner": {
    what: "The CMDB field mapped to the source owner.",
    why: "Owners from the CMDB become the remediation owners.",
    example: "owned_by.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:97 — maps to the source application
  "int.sn.cmdb_application": {
    what: "The CMDB field mapped to the source application.",
    why: "Groups findings by the application they affect.",
    example: "u_application.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:98 — maps to the source environment
  "int.sn.cmdb_environment": {
    what: "The CMDB field mapped to the source environment.",
    why: "Separates production from test in plans and reports.",
    example: "used_for.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:99 — optional; maps to business criticality
  "int.sn.cmdb_criticality": {
    what: "Optional: the CMDB field mapped to business criticality (low, medium, high or critical).",
    why: "Criticality scales the risk score of every finding of the source.",
    example: "busines_criticality.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:100 — optional; maps to internet exposure
  "int.sn.cmdb_exposure": {
    what: "Optional: the CMDB field mapped to internet exposure.",
    why: "Internet-facing multiplies the risk score by 1.5.",
    example: "u_internet_facing.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:101 — optional
  "int.sn.cmdb_classification": {
    what: "Optional: the CMDB field mapped to the data classification (public, internal, confidential, restricted).",
    why: "Sensitive data under weak crypto is migrated first.",
    example: "u_data_classification.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:104, backend/utilities/integrations/servicenow.py:56-60 — #225: optional import column
  "int.sn.cmdb_segment": {
    what: "The CMDB field holding each CI's network segment or site. A row goes to the scan node whose segment matches (or the one chosen for it in the import).",
    why: "Hosts in two data centres each reach the scan node that can see them.",
    example: "location.name for dc-mumbai and dc-chennai.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:105, backend/utilities/integrations/servicenow.py:56-60 — #225: optional import column
  "int.sn.cmdb_scan_node": {
    what: "The CMDB field naming the scan node (by its name in ZeroShield) that reaches the CI. It wins over the segment.",
    why: "Pins CIs that only one node can reach.",
    example: "u_scan_node = mum-01.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:106, backend/utilities/integrations/servicenow.py:56-60 — #225: optional import column
  "int.sn.cmdb_kind": {
    what: "The CMDB field saying what a CI is for the import: linux, windows, database (or an engine name), kubernetes, hsm or kmip. Without it the CI class decides (cmdb_ci_db_*, *kubernetes*, Windows or Linux).",
    why: "A CI read as the wrong kind is imported as the wrong source, or skipped.",
    example: "u_cbom_kind = hsm.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:107, backend/utilities/integrations/servicenow.py:56-60 — #225: optional import column
  "int.sn.cmdb_engine": {
    what: "The CMDB field with a database CI's engine: postgres, mysql, mssql, oracle, mongodb or redis (PostgreSQL and SQL Server spellings are understood).",
    why: "A database row without its engine is skipped with the reason.",
    example: "u_db_engine = PostgreSQL.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:108, backend/utilities/integrations/servicenow.py:56-60 — #225: optional import column
  "int.sn.cmdb_port": {
    what: "The CMDB field with a database CI's port. Blank: the engine's default port.",
    why: "A wrong port makes the source fail its connection test.",
    example: "tcp_port = 5433.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:109, backend/utilities/integrations/servicenow.py:56-60 — #225: optional import column
  "int.sn.cmdb_login": {
    what: "The CMDB field with the read-only login of a database, or the WinRM login of a Windows server. The password is read from the vault, never from ServiceNow.",
    why: "Database rows with a login need it to collect.",
    example: "u_db_login = cbom_ro.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:110, backend/utilities/integrations/servicenow.py:56-60 — #225: optional import column
  "int.sn.cmdb_database_name": {
    what: "The CMDB field with a database name; required for Oracle (the service name).",
    why: "An Oracle row without its service name is skipped.",
    example: "u_db_name = ORCLPDB1.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:111, backend/utilities/integrations/servicenow.py:56-60 — #225: optional import column
  "int.sn.cmdb_vault_path": {
    what: "The CMDB field with the vault secret path of the CI's login: a database password, a cluster kubeconfig, an HSM PIN or a Windows login. Read from the vault chosen in the import.",
    why: "Credentials stay in your vault; rows that need one and have none are skipped.",
    example: "u_vault_path = secret/data/db/pg1.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:112, backend/utilities/integrations/servicenow.py:56-60 — #225: optional import column
  "int.sn.cmdb_vault_provider": {
    what: "The CMDB field naming the vault of a CI's vault path when it is not the one chosen in the import: hashicorp or aws_secrets_manager (cyberark and azure_key_vault rows are skipped: not available yet).",
    why: "Lets one import read logins from more than one vault.",
    example: "u_vault_provider = aws_secrets_manager.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:113, backend/utilities/integrations/servicenow.py:56-60 — #225: optional import column
  "int.sn.cmdb_api_url": {
    what: "The CMDB field with a Kubernetes cluster's API server URL (https://...).",
    why: "A cluster row without its API URL is skipped with the reason.",
    example: "u_api_url = https://k8s-prod.bank.local:6443.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:114, backend/utilities/integrations/servicenow.py:56-60 — #225: optional import column
  "int.sn.cmdb_context": {
    what: "The CMDB field with the kubeconfig context to use for a cluster. Blank: the kubeconfig's current context.",
    why: "The wrong context reads the wrong cluster.",
    example: "u_kube_context = prod.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:115, backend/utilities/integrations/servicenow.py:56-60 — #225: optional import column
  "int.sn.cmdb_module": {
    what: "The CMDB field with an HSM's PKCS#11 module name, as the scan node lists it in ZS_PKCS11_MODULES.",
    why: "An HSM row without its module is skipped.",
    example: "u_pkcs11_module = luna.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:116, backend/utilities/integrations/servicenow.py:56-60 — #225: optional import column
  "int.sn.cmdb_token_label": {
    what: "The CMDB field with the HSM token (slot) label to read. Blank: the module's first token.",
    why: "Each token is its own source.",
    example: "u_token_label = payments-01.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:120 — syslog collector
  "int.sys.host": {
    what: "The hostname or address of your syslog collector.",
    why: "Every event is sent here.",
    example: "siem.bank.local.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:106 — TLS, TCP, UDP
  "int.sys.transport": {
    what: "TLS (RFC 5425, port 6514), TCP with octet counting, or UDP (RFC 5426, no delivery confirmation).",
    why: "Only TLS protects the events in transit; UDP may lose them silently.",
    example: "TLS to siem.bank.local on 6514.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:91 — default 6514 for TLS, 514 for TCP and UDP
  "int.sys.port": {
    what: "Optional: the collector's port. Default 6514 for TLS, 514 for TCP and UDP.",
    why: "A wrong port fails the test event.",
    example: "6514.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:109 — CEF or JSON
  "int.sys.format": {
    what: "The payload format: CEF (ArcSight) or JSON.",
    why: "Pick the one your SIEM parses without a custom parser.",
    example: "CEF for ArcSight; JSON for Elastic.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:110 — syslog facility number
  "int.sys.facility": {
    what: "The syslog facility number set on each message; 16 is local0.",
    why: "Lets the collector route ZeroShield events to their own file or index.",
    example: "16 (local0).",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:111 — the HOSTNAME field
  "int.sys.sender": {
    what: "The name put in the HOSTNAME field of each message.",
    why: "Identifies the events as ZeroShield's in the SIEM.",
    example: "zeroshield.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:115 — https
  "int.hec.url": {
    what: "The address of your Splunk HTTP Event Collector.",
    why: "Events are posted only here.",
    example: "https://splunk.bank.local:8088.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:116 — optional
  "int.hec.index": {
    what: "Optional: the Splunk index to write to. Blank uses the token's default index.",
    why: "Keeps crypto events in the index your SOC searches.",
    example: "security.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:117 — sourcetype of each event
  "int.hec.sourcetype": {
    what: "The sourcetype set on each event.",
    why: "Splunk searches and field extraction key off the sourcetype.",
    example: "zeroshield:cbom.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:118 — source of each event
  "int.hec.source": {
    what: "The source set on each event.",
    why: "Tells events from different ZeroShield teams or deployments apart.",
    example: "zeroshield-prod.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:119 — HEC data channel (#126)
  "int.hec.channel": {
    what: "Optional: a GUID sent as X-Splunk-Request-Channel with every request.",
    why: "A HEC token with indexer acknowledgement on refuses requests without a channel (\"Data channel is missing\").",
    example: "0aeeac95-ac74-4aa9-b30d-6c4c0ac581ba.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:100 — https
  "int.webhook.url": {
    what: "The HTTPS address that receives the signed JSON events.",
    why: "Events are posted only here.",
    example: "https://soar.bank.local/hooks/zeroshield.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:126 — https
  "int.oscal.url": {
    what: "The HTTPS address of your GRC tool's OSCAL endpoint.",
    why: "Assessment results are pushed only here.",
    example: "https://grc.bank.local/api/oscal.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:148, frontend/components/integrations/IntegrationsPage.tsx:325-328 — write-only
  "int.secret.password": {
    what: "The ServiceNow user's password. Encrypted at rest and never shown again; changing the URL or user clears it unless you enter it again.",
    why: "Clearing it on change keeps it from going to a host it was not meant for.",
    example: "The svc_zeroshield password.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:148, frontend/components/integrations/IntegrationsPage.tsx:325-328,150 — write-only
  "int.secret.client_secret": {
    what: "The OAuth application's client secret. Encrypted at rest and never shown again.",
    why: "With the client ID it obtains tokens to create records.",
    example: "The secret shown when the OAuth app was created.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:153, frontend/components/integrations/IntegrationsPage.tsx:325-328,153 — write-only
  "int.secret.hec_token": {
    what: "The Splunk HEC token. Encrypted at rest and never shown again.",
    why: "Anyone with it can write events to your Splunk; scope it to one index.",
    example: "A token created under Data inputs > HTTP Event Collector.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:154, frontend/components/integrations/IntegrationsPage.tsx:325-328,154 — 16 or more characters; write-only
  "int.secret.signing": {
    what: "The shared secret, 16 characters or more, used to sign each request (HMAC-SHA256). Generate creates one; copy it to your receiver before saving, as it is never shown again.",
    why: "Your receiver uses it to reject requests not sent by ZeroShield.",
    example: "A 43-character random value from Generate.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:31-40,354, frontend/components/integrations/IntegrationsPage.tsx:351-364 — which events are sent
  "int.events": {
    what: "Which events this destination receives: finding opened or resolved, asset added or removed, certificate renewed or expiring in 30 days, scheduled run skipped, run or code scan finished.",
    why: "Send only what the destination acts on, to keep noise down.",
    example: "Finding opened and Certificate expiring for the SOC.",
  },
  // src: backend/utilities/integrations/dispatch.py:1-11 — at least once, in order, back-off, dead-letter
  "int.log": {
    what: "Every event is delivered at least once, in order per destination, with the same event id on each retry. A failing destination is retried with back-off (30 s doubling to 30 min); events it refuses for good go to the dead-letter list, from where you can retry them.",
    why: "Shows whether your SIEM or ServiceNow actually received each event.",
    example: "Dead-lettered: HTTP 400 from ServiceNow, field u_category not found.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:432-439 — one integration or all
  "int.log.filter_kind": {
    what: "Show deliveries of one integration, or of all.",
    why: "Retry all needs one integration chosen.",
    example: "ServiceNow.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:440-446 — pending, delivered, dead-lettered
  "int.log.filter_status": {
    what: "Show deliveries by status: pending, delivered or dead-lettered.",
    why: "Dead-lettered events were not received and may need a retry.",
    example: "Dead-lettered.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:464 — when the event was queued
  "int.log.col.queued": {
    what: "When the event was queued for this destination.",
    why: "Events are delivered oldest first.",
    example: "14 Nov 2026, 02:31 am IST.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:465 — destination
  "int.log.col.integration": {
    what: "The destination the event is for.",
    why: "Each destination has its own queue.",
    example: "Splunk HEC.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:31-40, frontend/components/integrations/IntegrationsPage.tsx:466 — event type
  "int.log.col.event": {
    what: "What happened: finding opened or resolved, asset added or removed, certificate renewed or expiring, scheduled run skipped, run or scan finished.",
    why: "Lets you check a specific finding reached the destination.",
    example: "Finding resolved.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:467 — pending, delivered, dead
  "int.log.col.status": {
    what: "Pending (queued or backing off), delivered, or dead-lettered (refused for good, or still undelivered after the maximum age).",
    why: "Dead-lettered events need fixing at the destination, then a retry.",
    example: "Pending: next attempt in 4 minutes.",
  },
  // src: backend/utilities/integrations/dispatch.py:46, frontend/components/integrations/IntegrationsPage.tsx:468 — delivery attempts
  "int.log.col.attempts": {
    what: "How many times delivery was tried.",
    why: "Many attempts point at a destination that is down or refusing the credentials.",
    example: "3: two timeouts, then delivered.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:469 — last response or error
  "int.log.col.result": {
    what: "The destination's last answer or the error.",
    why: "Names the exact cause to fix at the destination.",
    example: "HTTP 401: the HEC token is disabled.",
  },
} as const satisfies TipAreaText;

export default TEXT;
