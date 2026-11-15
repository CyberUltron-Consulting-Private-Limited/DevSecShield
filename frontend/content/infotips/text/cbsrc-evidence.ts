/**
 * (i) tip text of the "cbsrc-evidence" area (ids: cbsrc.ev.*, cbsrc.cmdb.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── CBOM Sources: Evidence (components/cbom/sources/EvidenceTab.tsx)
  // src: backend/utilities/cbom_sources/evidence.py:16-17, frontend/components/cbom/sources/EvidenceTab.tsx:283-292,55 — areas at E0
  "cbsrc.ev.e0": {
    what: "Areas with no usable answer: never answered, answered without evidence where evidence is needed, or with evidence older than 12 months.",
    why: "Each E0 area is a Q0 gap in the risk register, listed on Review & Run and never treated as safe.",
    example: "3 areas: the payment HSM vendor has not answered.",
  },
  // src: backend/utilities/cbom_sources/evidence.py:16-17, frontend/components/cbom/sources/EvidenceTab.tsx:283-292,55 — areas at E1
  "cbsrc.ev.e1": {
    what: "Areas answered by their owner or vendor without supporting evidence.",
    why: "A self-attested answer is better than nothing but would not satisfy an auditor.",
    example: "The card vendor says its terminals use AES-256, with no document.",
  },
  // src: backend/utilities/cbom_sources/evidence.py:16-17, frontend/components/cbom/sources/EvidenceTab.tsx:283-292,55 — areas at E2
  "cbsrc.ev.e2": {
    what: "Areas answered with a dated evidence document, such as a policy, certificate or report.",
    why: "Documented answers can be shown to an auditor and re-checked when the document is renewed.",
    example: "Key management policy v3 (PDF), dated March 2026.",
  },
  // src: backend/utilities/cbom_sources/evidence.py:16-17, frontend/components/cbom/sources/EvidenceTab.tsx:283-292,55 — areas at E3
  "cbsrc.ev.e3": {
    what: "Areas whose evidence your team has checked and confirmed.",
    why: "Verified evidence carries the same weight as a scan result.",
    example: "The HSM's FIPS 140-3 certificate checked against the NIST CMVP list.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:280-284,300, frontend/components/cbom/sources/EvidenceTab.tsx:299-325 — owner questionnaires with a confidence level
  "cbsrc.ev.areas": {
    what: "Parts of your crypto estate no scan can read, such as vendor services and offline key ceremonies. Each has an owner questionnaire, a confidence level and an optional evidence link; a missing answer stays a visible gap.",
    why: "A CBOM that only lists what scans can see overstates your readiness.",
    example: "Card personalisation bureau: owner Cards ops, E1, due 30 Nov.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:320 — the evidence area
  "cbsrc.ev.col.area": {
    what: "The part of the estate the questionnaire covers.",
    why: "Each area is one gap until it is answered.",
    example: "Offline root CA key ceremony.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:321, frontend/components/cbom/sources/EvidenceTab.tsx:794 — who answers
  "cbsrc.ev.col.owner": {
    what: "The person or team asked to answer for this area.",
    why: "An area without an owner is never answered.",
    example: "PKI team.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:136-149 — E0 Unknown to E3 Verified
  "cbsrc.ev.col.confidence": {
    what: "How much the answer can be trusted: E0 Unknown, E1 Self-attested, E2 Documented (evidence document), E3 Verified (evidence checked by your team).",
    why: "Reports and the run's coverage weigh answers by this level.",
    example: "E2 Documented.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:323, frontend/components/cbom/sources/EvidenceTab.tsx:876-902 — the evidence document and its date
  "cbsrc.ev.col.evidence": {
    what: "The supporting document's title and link, and its date. Evidence older than 12 months drops back to E0 until renewed.",
    why: "Dated evidence shows the answer was true recently, not years ago.",
    example: "HSM FIPS certificate (PDF), 4 Feb 2026.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:324, frontend/components/cbom/sources/EvidenceTab.tsx:910 — when the owner should answer by
  "cbsrc.ev.col.due": {
    what: "When the owner should answer by.",
    why: "Overdue areas are the gaps to chase before an audit.",
    example: "30 Nov 2026.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:414-418 — single-use links, no login, 14 days
  "cbsrc.ev.vendors": {
    what: "Vendors asked to answer a questionnaire through a single-use link, with no login; the link expires in 14 days. A vendor who does not answer stays E0 Unknown, a Q0 gap.",
    why: "Third-party services use crypto you cannot scan but still answer for in an audit.",
    example: "Acme Payments, link sent 2 Nov, answered 6 Nov, E2.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:442 — vendor name
  "cbsrc.ev.col.vendor": {
    what: "The vendor asked to answer.",
    why: "Each vendor is one evidence area of its own.",
    example: "Acme Payments.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:443 — the single-use link
  "cbsrc.ev.col.link": {
    what: "The state of the vendor's single-use link: not sent, sent and waiting, answered, or expired (after 14 days).",
    why: "An expired link needs a new one before the vendor can answer.",
    example: "Expired: press New link and send the vendor the fresh link.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:531, frontend/components/cbom/sources/EvidenceTab.tsx:663-696,531 — read-only preview
  "cbsrc.ev.preview": {
    what: "Read-only view of exactly what an owner or vendor is asked for the chosen area.",
    why: "Check the questions before sending a link to a vendor.",
    example: "Preview Card personalisation bureau: 5 questions and an evidence link.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:534-536 — which area to preview
  "cbsrc.ev.preview_area": {
    what: "The evidence area whose questionnaire is shown below.",
    why: "Each area asks different questions.",
    example: "Offline root CA key ceremony.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:809-843, frontend/components/cbom/sources/EvidenceTab.tsx:667-686 — yes/no/unknown or a free-text answer
  "cbsrc.ev.question": {
    what: "One question of the area's questionnaire, answered with a choice or in free text.",
    why: "Each answer feeds the area's confidence; an unanswered question keeps it a gap.",
    example: "Are keys generated inside a FIPS 140-3 Level 3 HSM? Yes.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:688 — E2 and E3 need one
  "cbsrc.ev.preview_link": {
    what: "Where the person answering links a policy, certificate or report. Documented (E2) and Verified (E3) need one.",
    why: "Without evidence an answer stays Self-attested at best.",
    example: "https://intranet.bank.in/pki/ceremony-2026.pdf.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:794-796 — the person or team who answers
  "cbsrc.ev.owner": {
    what: "Who answers for this area: a person or team. The area may suggest a usual owner.",
    why: "Named owners are who auditors ask, and who remediation is routed to.",
    example: "PKI team (usually: Information security).",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:849-857 — Documented and Verified need a document and date
  "cbsrc.ev.confidence": {
    what: "The confidence of this area's answer: E0 Unknown, E1 Self-attested, E2 Documented or E3 Verified. Documented and Verified need an evidence document and its date.",
    why: "It decides how the area counts in coverage and reports.",
    example: "E3 after you checked the vendor's certificate yourself.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:876-877 — up to 200 characters
  "cbsrc.ev.title": {
    what: "A short title for the evidence document, up to 200 characters.",
    why: "Auditors find the document by its title in the evidence pack.",
    example: "Key management policy v3 (PDF).",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:879-886 — http or https, up to 1,000 characters
  "cbsrc.ev.url": {
    what: "An http:// or https:// link to the document, up to 1,000 characters.",
    why: "The link lets a reviewer open the evidence in one click.",
    example: "https://intranet.bank.in/policies/kms-v3.pdf.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:876-888 — evidence older than 12 months drops to E0
  "cbsrc.ev.date": {
    what: "The date of the document, not later than today. Evidence older than 12 months drops back to E0 until renewed.",
    why: "Crypto policies change; old evidence may describe a setup that no longer exists.",
    example: "14 Mar 2026.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:910-911 — when the owner should answer by
  "cbsrc.ev.due": {
    what: "When the owner should answer by.",
    why: "A due date turns an open gap into a tracked task.",
    example: "30 Nov 2026.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:983-984 — required
  "cbsrc.ev.vendor_name": {
    what: "The vendor's name, as shown in lists and reports.",
    why: "Each vendor becomes an evidence area of its own.",
    example: "Acme Payments Pvt Ltd.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:993-994 — for your records only
  "cbsrc.ev.vendor_email": {
    what: "Optional: the vendor contact's email, for your records only. ZeroShield does not email the vendor; you send the link yourself.",
    why: "Keeps who was asked next to the answer.",
    example: "security@acmepayments.in.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:1069-1075,1084 — E1 when answered, E2 with a link, E3 once verified
  "cbsrc.ev.vendor_confidence": {
    what: "The confidence of the vendor's answer. Set E1 when answered, E2 when the vendor gave an evidence link, E3 once you have verified the evidence.",
    why: "It decides how much the vendor's answer counts.",
    example: "E2: the vendor linked its PCI PIN attestation.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:1-4,45, frontend/components/cbom/sources/CmdbImportDialog.tsx:45-56 — existing sources keep how they connect
  "cbsrc.cmdb.updates": {
    what: "Existing sources whose owner, application, criticality, exposure, data classification or environment would change. How they connect is untouched, so running and queued jobs are kept.",
    why: "Keeps CBOM ownership in line with your CMDB without re-testing sources.",
    example: "dc-mumbai-linux: owner none → Payments platform team.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:1-4,58, frontend/components/cbom/sources/CmdbImportDialog.tsx:58-69 — new Linux server sources or network ranges
  "cbsrc.cmdb.creates": {
    what: "Sources the import would create, each on its scan node: new Linux hosts become Linux server sources, Windows hosts WinRM sources (login from your vault), database, cluster and HSM rows sources of those kinds; CIDRs become network ranges. Nothing past the team's source limit is created.",
    why: "New sources still need a credential and a passing test before they are collected.",
    example: "cmdb-import-1 (14 Linux hosts) · owner: Cards ops.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:71-81 — left unchanged
  "cbsrc.cmdb.conflicts": {
    what: "Rows that disagree with what is already set, for example a host in two sources with different owners. They are left unchanged.",
    why: "Resolve them in the CMDB or by hand so the right owner gets the findings.",
    example: "10.20.5.17: owner Payments in one source, Cards in another.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:83, backend/utilities/integrations/cmdb.py:654-670 — new sources past the team's source cap
  "cbsrc.cmdb.over_limit": {
    what: "New sources this import would create beyond the team's source limit. They are listed here and are not created when you apply; the rest of the import still goes ahead.",
    why: "The team's source cap is checked in the preview and again when you apply, so nothing past it is created by surprise.",
    example: "Limit 500, 495 used: 5 of 12 new Linux server sources are created and 7 are listed here. Raise the limit or delete unused sources, then import again.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:82-92 — rows that could not be used
  "cbsrc.cmdb.skipped": {
    what: "CSV or CMDB rows that could not be used, or were only partly read, with the reason.",
    why: "Fix them at the source so the next import covers them.",
    example: "Row 37: criticality \"P1\" is not low, medium, high or critical.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:143-153 — CSV or ServiceNow CMDB
  "cbsrc.cmdb.source": {
    what: "CSV file: host / fqdn / ip / cidr, owner, application, criticality, exposure, data_classification, environment, os, segment or scan_node; for databases, clusters and HSMs also kind, engine, port, login, api_url, module, vault_path. ServiceNow CMDB: the table set in Settings > Integrations.",
    why: "Importing keeps owners and criticality in one place instead of typing them per source.",
    example: "ServiceNow CMDB, table cmdb_ci_server.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:155-171 — up to 5,000 rows and 2 MB, header row required
  "cbsrc.cmdb.csv": {
    what: "The CSV to import, pasted or uploaded: up to 5,000 rows and 2 MB, with a header row.",
    why: "The header names the columns, so their order does not matter.",
    example: "host,owner,criticality\\napp-01.bank.local,Payments,high.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:1-4,174, frontend/components/cbom/sources/CmdbImportDialog.tsx:171-173 — new hosts become Linux server sources
  "cbsrc.cmdb.create": {
    what: "Also create sources for hosts and CIDRs that are not in any source yet. Off: only existing sources are updated.",
    why: "Bringing every CMDB host into scope closes blind spots.",
    example: "On: 14 new hosts become a Linux server source on node-dc1.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:178-179 — the node that can reach the new hosts
  "cbsrc.cmdb.node": {
    what: "The scan node for rows with no segment or scan_node column. A row's segment picks the scan node of that segment instead.",
    why: "A node that cannot reach them makes every new source fail its test.",
    example: "node-dc1.",
  },
  // src: backend/utilities/integrations/cmdb.py:378-400, backend/routers/integrations.py:114 — #225: one choice per shared segment
  "cbsrc.cmdb.segment_node": {
    what: "Several scan nodes serve this segment, so the import needs to know which one takes its rows. Without a choice those rows are skipped with the reason. A row's scan_node column still wins.",
    why: "A node that cannot reach a segment's hosts makes every source there fail its test.",
    example: "dc-mumbai: mum-01.",
  },
  // src: backend/utilities/integrations/cmdb.py:403-476, backend/routers/integrations.py:116 — #225: credentials only from a vault
  "cbsrc.cmdb.vault": {
    what: "The vault that holds the logins named in a vault_path column (databases, cluster kubeconfigs, HSM PINs) and the Windows login below. Passwords, kubeconfigs and certificates are never read from the file; rows that need one are skipped.",
    why: "Credentials stay in your vault, read by the scan node at run time.",
    example: "HashiCorp Vault.",
  },
  // src: backend/utilities/integrations/cmdb.py:576-588, backend/routers/integrations.py:117 — #225: Windows rows become WinRM sources
  "cbsrc.cmdb.windows_vault": {
    what: "The vault secret path of the WinRM login for Windows rows. They become Windows sources over WinRM HTTPS (port 5986) that read it; a row's vault_path overrides it. Without either, Windows rows are skipped.",
    why: "Windows hosts can then be onboarded in bulk instead of one by one in the Servers tab.",
    example: "secret/data/cbom/winrm.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:1-4, frontend/components/cbom/sources/CmdbImportDialog.tsx:134 — admins only; preview, then confirm
  "cbsrc.cmdb.dialog": {
    what: "Upload a CSV or pull the ServiceNow CMDB, preview what changes, then confirm. Team admins only.",
    why: "Nothing changes until you confirm the preview.",
    example: "Preview: 12 metadata updates, 1 new source, 2 conflicts.",
  },
} as const satisfies TipAreaText;

export default TEXT;
