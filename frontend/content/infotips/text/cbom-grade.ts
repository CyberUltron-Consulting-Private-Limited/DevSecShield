/**
 * (i) tip text of the "cbom-grade" area (ids: cbom.agility.*, cbom.qgrade.*, cbom.source.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── crypto-agility and quantum-risk grade (components/cbom/grade, moved from grade/tips.ts, #126)
  // src: backend/utilities/cbom_sources/agility.py:76-82 (CLASS_TEXT["configurable"])
  "cbom.agility.configurable": {
    what: "The owner fixes it by changing a setting, policy, key or certificate with the software, hardware and services already deployed. No code change, no new release.",
    why: "The quickest kind of fix: no code change or new release needed.",
    example: "nginx accepts TLS 1.0: set `ssl_protocols TLSv1.2 TLSv1.3;` and reload. Windows SCHANNEL: set the `TLS 1.0\\Server\\Enabled` registry value to 0.",
  },
  // src: backend/utilities/cbom_sources/agility.py:83-88 (CLASS_TEXT["code-fixed"])
  "cbom.agility.code_fixed": {
    what: "The team's own source code or build must change, then be rebuilt, tested and released (includes a dependency or base-image bump in the team's own build).",
    why: "Needs a development cycle, so plan it into a release.",
    example: "Java code calls `KeyPairGenerator.initialize(1024)`: change it to 3072 (or a post-quantum signature algorithm when the platform has it) and ship a release.",
  },
  // src: backend/utilities/cbom_sources/agility.py:89-95 (CLASS_TEXT["vendor-fixed"])
  "cbom.agility.vendor_fixed": {
    what: "The cryptography lives in a third party's product or service (OS distribution, commercial software, SaaS, cloud service, CA ecosystem). Only the vendor can change it; the owner installs the update when it exists, or asks for it.",
    why: "You depend on the vendor's roadmap; ask early and track it.",
    example: "A SaaS provider's API still accepts TLS 1.0; or an OpenSSL 3.0 server cannot offer a post-quantum key exchange until the distribution ships OpenSSL 3.5.",
  },
  // src: backend/utilities/cbom_sources/agility.py:96-101 (CLASS_TEXT["hardware-fixed"])
  "cbom.agility.hardware_fixed": {
    what: "The cryptography is bound to a device: HSM, TPM, smart card, network appliance or OT device. It needs a firmware update or a hardware replacement.",
    why: "Firmware or hardware changes take budget and long lead times.",
    example: "An HSM whose firmware has no post-quantum signature algorithm keeps RSA root keys until the firmware is upgraded or the HSM replaced.",
  },
  // src: backend/utilities/cbom_sources/agility.py:102-106 (CLASS_TEXT["unknown"]), :392-407 (asset_class: floor)
  "cbom.agility.unknown": {
    what: "A fact that decides the class was not read (key provider of a Windows certificate, type of a PKCS#11 token, a code with no row). Never treated as the easiest class; shows the class it is at least.",
    why: "Until the missing fact is read, plan for the class it is at least.",
    example: "A Windows certificate with a private key, read by a node that does not report the key provider yet.",
  },
  // src: backend/utilities/cbom_sources/agility.py:112-113 (INFERRED_TEXT), :406-407 (confidence observed | inferred)
  "cbom.agility.inferred": {
    what: "Likely: no fact the product read decides this class; it is the table's default for a capability code (the platform must implement the algorithm), never easier than the evidence allows.",
    why: "An inferred class may change once more evidence is collected.",
    example: "NO_PQ_KEX on a TLS endpoint: the TLS library version is not visible from the network, so the class is vendor-fixed (inferred) until host evidence says otherwise.",
  },
  // src: backend/utilities/cbom_sources/agility.py:47 (SELF_FIXABLE), :562-566 (self_fixable_pct), :621-640 (RunAgility.result)
  "cbom.agility.self_fixable": {
    what: "Assets whose hardest finding is configurable or code-fixed, out of the assets with one of the four fix classes. Unknown and none are left out of both numbers. Computed from this run's stored findings when the page is read.",
    why: "Shows how much of the work your own team can do without waiting on others.",
    example: "30 configurable, 10 code-fixed, 50 vendor-fixed, 10 hardware-fixed: 40 of 100, 40% self-fixable.",
  },
  // src: backend/utilities/cbom_sources/agility.py:50 (PQ_CODES), :483-485 (excluding_pq), posture fix_classes_excl_pq
  "cbom.agility.excl_pq": {
    what: "The same assets, classed without the four post-quantum migration codes (QUANTUM_VULNERABLE, NO_PQ_KEX, SSH_NO_PQ_KEX, IKE_NO_PQ): what is hard to fix among today's weaknesses only.",
    why: "Separates today's fixes from the longer post-quantum migration.",
    example: "An RSA-2048 certificate whose only code is QUANTUM_VULNERABLE counts as none here.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:59-60,73 (operated_by us | vendor | null), backend/utilities/cbom_sources/agility.py:230-235 (R-VENDOR)
  "cbom.source.operated_by": {
    what: "Who runs what this source reaches: your team (the default when not set) or a vendor (a SaaS or managed service). Every finding of a vendor-operated source is at least vendor-fixed. A run keeps the value the source had when the run started.",
    why: "Vendor-operated systems need the vendor to fix them, which changes how you plan.",
    example: "A managed database whose TLS settings only the provider can change: set Vendor.",
  },
  // src: backend/utilities/cbom_sources/qgrade.py:46-99 (FORMULA_TEXT), :768-814 (RunGrades: counts and items)
  "cbom.qgrade.distribution": {
    what: "Each asset of the run graded by the signed model shown under \"How grades are computed\": the PQC class, internet exposure, trust-anchor status and the Mosca inequality X + Y > Z. No grade means nothing to grade (no public-key cryptography). The grade uses the team's Mosca settings as they are now.",
    why: "Ranks assets by quantum risk so migration starts where data is most exposed.",
    example: "A quantum-vulnerable internet-facing TLS endpoint with X 10 + Y 5 > Z 12 grades Critical.",
  },
  // src: backend/utilities/cbom_sources/agility.py:76-113, frontend/components/cbom/grade/Agility.tsx:150-160 — the hardest fix class of each asset
  "cbom.agility.section": {
    what: "Crypto-agility: each asset by the hardest fix class among its findings, Configurable, Code-fixed, Vendor-fixed, Hardware-fixed or Unknown, and the share your own team can fix.",
    why: "Separates what you can change this sprint from what waits on a vendor or new hardware.",
    example: "40 of 100 assets self-fixable: 30 configurable, 10 code-fixed.",
  },
  // ────────────────────────────────────────────────────────────── CBOM: crypto-agility baseline of the team (CB-25)
  // src: backend/utilities/cbom_sources/agility_rollup.py:1-21, frontend/components/cbom/grade/AgilityBaseline.tsx:3-6 — current estate, one asset per cross-source identity
  "cbom.agility.baseline": {
    what: "How hard the team's current estate is to fix, by fix class: every asset of each source's latest collection and each repository's latest code scan, plus the evidence items with a class. An asset several sources see counts once, at its hardest class.",
    why: "The enterprise number to track over time: how much of the crypto your own team can change.",
    example: "1,200 assets, 46% self-fixable; Core banking is mostly vendor-fixed.",
  },
  // src: backend/utilities/cbom_sources/agility_rollup.py:16-21 — application, else source; repository; evidence groups
  "cbom.agility.system": {
    what: "Where an asset belongs: the source's application when it has one, else the source itself; a code scan's repository; or the evidence groups Third parties and Key management. An asset counts in the system of its latest observation, so the systems add up to the team's counts.",
    why: "Owners plan by system, not by source.",
    example: "Netbanking (application).",
  },
  // src: backend/utilities/cbom_sources/agility_rollup.py:16-17 — the hardest class across the system's assets
  "cbom.agility.hardest": {
    what: "The hardest fix class among the system's assets.",
    why: "One hardware-fixed asset can hold a whole system's migration back.",
    example: "Vendor-fixed.",
  },
  // src: backend/utilities/cbom_sources/agility_rollup.py:19-20 — configurable + code-fixed over the four classes
  "cbom.agility.system_self_fixable": {
    what: "The system's configurable and code-fixed assets out of those with one of the four fix classes; Unknown and none are left out.",
    why: "Shows which systems your team can migrate without a vendor or new hardware.",
    example: "80%: 16 of 20 assets.",
  },
  // src: frontend/components/cbom/grade/AgilityBaseline.tsx:213-220 — drill-down by class and system
  "cbom.agility.drill": {
    what: "Lists the assets of one fix class, or every class, for the whole team or the system you opened.",
    why: "Gives the concrete asset list behind each count.",
    example: "Hardware-fixed assets of Card switch.",
  },
  // src: frontend/components/cbom/grade/AgilityBaseline.tsx:104, backend/utilities/cbom_sources/agility_rollup.py:83-89 — the codes that decided the class
  "cbom.agility.why_codes": {
    what: "The finding codes that decided the asset's fix class. An asset seen several times is classed on all its observations' codes together.",
    why: "Tells the owner what to change, not just how hard it is.",
    example: "WEAK_PROTOCOL, NO_PQ_KEX.",
  },
  // src: backend/utilities/cbom_sources/agility_rollup.py:12-17, frontend/components/cbom/grade/AgilityBaseline.tsx:106 — observations merged into one asset
  "cbom.agility.seen_by": {
    what: "How many observations, from Sources collections and code scans, were merged into this one asset. Hover for their names.",
    why: "An asset several sources see is counted once, not once per source.",
    example: "3 (Network TLS DC1, Servers DC1, repo payments@main).",
  },
} as const satisfies TipAreaText;

export default TEXT;
