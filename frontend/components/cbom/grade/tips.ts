/**
 * (i) info tips of the crypto-agility and quantum-risk components, in the shape of F2's registry
 * (`frontend/content/infotips.ts`, PR #38, not merged yet): id `<surface>.<area>.<item>`, `label`, `what`, `example`,
 * and a `// src:` comment naming the code each text was checked against. When #38 merges, these entries move into
 * INFO_TIPS unchanged and the components switch to <InfoTip id="…" /> (follow-up recorded on issue #126).
 *
 * The six fix-class texts are the backend's own (`agility.CLASS_TEXT`, `agility.INFERRED_TEXT`):
 * gradeContract.test.ts checks them against contracts/cbom/grade_keys.json, which a backend test keeps equal to
 * agility.py. A reworded class in the backend fails CI until the tip says the same: the backend job fails while the
 * JSON is stale, and once it is rewritten the frontend job (which runs on `contracts/**`, ci.yml) fails on the tip.
 */
export interface TipEntry {
  /** What the (i) button is about; the button is named "About <label>". */
  label: string;
  what: string;
  example: string;
}

export const GRADE_TIPS = {
  // src: backend/utilities/cbom_sources/agility.py:76-82 (CLASS_TEXT["configurable"])
  "cbom.agility.configurable": {
    label: "Configurable",
    what: "The owner fixes it by changing a setting, policy, key or certificate with the software, hardware and services already deployed. No code change, no new release.",
    example: "nginx accepts TLS 1.0: set `ssl_protocols TLSv1.2 TLSv1.3;` and reload. Windows SCHANNEL: set the `TLS 1.0\\Server\\Enabled` registry value to 0.",
  },
  // src: backend/utilities/cbom_sources/agility.py:83-88 (CLASS_TEXT["code-fixed"])
  "cbom.agility.code_fixed": {
    label: "Code-fixed",
    what: "The team's own source code or build must change, then be rebuilt, tested and released (includes a dependency or base-image bump in the team's own build).",
    example: "Java code calls `KeyPairGenerator.initialize(1024)`: change it to 3072 (or a post-quantum signature algorithm when the platform has it) and ship a release.",
  },
  // src: backend/utilities/cbom_sources/agility.py:89-95 (CLASS_TEXT["vendor-fixed"])
  "cbom.agility.vendor_fixed": {
    label: "Vendor-fixed",
    what: "The cryptography lives in a third party's product or service (OS distribution, commercial software, SaaS, cloud service, CA ecosystem). Only the vendor can change it; the owner installs the update when it exists, or asks for it.",
    example: "A SaaS provider's API still accepts TLS 1.0; or an OpenSSL 3.0 server cannot offer a post-quantum key exchange until the distribution ships OpenSSL 3.5.",
  },
  // src: backend/utilities/cbom_sources/agility.py:96-101 (CLASS_TEXT["hardware-fixed"])
  "cbom.agility.hardware_fixed": {
    label: "Hardware-fixed",
    what: "The cryptography is bound to a device: HSM, TPM, smart card, network appliance or OT device. It needs a firmware update or a hardware replacement.",
    example: "An HSM whose firmware has no post-quantum signature algorithm keeps RSA root keys until the firmware is upgraded or the HSM replaced.",
  },
  // src: backend/utilities/cbom_sources/agility.py:102-106 (CLASS_TEXT["unknown"]), :392-407 (asset_class: floor)
  "cbom.agility.unknown": {
    label: "Unknown",
    what: "A fact that decides the class was not read (key provider of a Windows certificate, type of a PKCS#11 token, a code with no row). Never treated as the easiest class; shows the class it is at least.",
    example: "A Windows certificate with a private key, read by a node that does not report the key provider yet.",
  },
  // src: backend/utilities/cbom_sources/agility.py:112-113 (INFERRED_TEXT), :406-407 (confidence observed | inferred)
  "cbom.agility.inferred": {
    label: "Likely (inferred)",
    what: "Likely: no fact the product read decides this class; it is the table's default for a capability code (the platform must implement the algorithm), never easier than the evidence allows.",
    example: "NO_PQ_KEX on a TLS endpoint: the TLS library version is not visible from the network, so the class is vendor-fixed (inferred) until host evidence says otherwise.",
  },
  // src: backend/utilities/cbom_sources/agility.py:47 (SELF_FIXABLE), :562-566 (self_fixable_pct), :621-640 (RunAgility.result)
  "cbom.agility.self_fixable": {
    label: "Self-fixable share",
    what: "Assets whose hardest finding is configurable or code-fixed, out of the assets with one of the four fix classes. Unknown and none are left out of both numbers. Computed from this run's stored findings when the page is read.",
    example: "30 configurable, 10 code-fixed, 50 vendor-fixed, 10 hardware-fixed: 40 of 100, 40% self-fixable.",
  },
  // src: backend/utilities/cbom_sources/agility.py:50 (PQ_CODES), :483-485 (excluding_pq), posture fix_classes_excl_pq
  "cbom.agility.excl_pq": {
    label: "Excluding post-quantum",
    what: "The same assets, classed without the four post-quantum migration codes (QUANTUM_VULNERABLE, NO_PQ_KEX, SSH_NO_PQ_KEX, IKE_NO_PQ): what is hard to fix among today's weaknesses only.",
    example: "An RSA-2048 certificate whose only code is QUANTUM_VULNERABLE counts as none here.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:59-60,73 (operated_by us | vendor | null), agility.py:230-235 (R-VENDOR)
  "cbom.source.operated_by": {
    label: "Operated by",
    what: "Who runs what this source reaches: your team (the default when not set) or a vendor (a SaaS or managed service). Every finding of a vendor-operated source is at least vendor-fixed. A run keeps the value the source had when the run started.",
    example: "A managed database whose TLS settings only the provider can change: set Vendor.",
  },
  // src: backend/utilities/cbom_sources/qgrade.py:46-99 (FORMULA_TEXT), :768-814 (RunGrades: counts and items)
  "cbom.qgrade.distribution": {
    label: "Quantum risk grade",
    what: "Each asset of the run graded by the signed model shown under \"How grades are computed\": the PQC class, internet exposure, trust-anchor status and the Mosca inequality X + Y > Z. No grade means nothing to grade (no public-key cryptography). The grade uses the team's Mosca settings as they are now.",
    example: "A quantum-vulnerable internet-facing TLS endpoint with X 10 + Y 5 > Z 12 grades Critical.",
  },
} satisfies Record<string, TipEntry>;

export type GradeTipId = keyof typeof GRADE_TIPS;

/** The tip of a fix-class value (none has no tip). */
export function fixClassTipId(value: string): GradeTipId | null {
  const id = `cbom.agility.${value.replace(/-/g, "_")}`;
  return id in GRADE_TIPS ? (id as GradeTipId) : null;
}
