// Test fixtures for the compliance mapping (#270): the shapes of /runs/{id}/results `compliance` (KB clauses with
// their findings) and of scan_metadata.cbom_compliance (the tri-state report). Used by complianceSummary.test.ts and
// complianceSummaryRender.test.ts.
import type { Compliance } from "@/components/compliance/types";

import type { ComplianceRow } from "./model";

export const RBI_TEXT = "The key length, algorithms, cipher suites and applicable protocols used in transmission channels, processing of data and authentication purpose shall be strong.";
export const MAPPING: ComplianceRow[] = [
  { framework: "NIST", assets: 3, clauses: [
    { clause: "SP 800-131A Rev. 2, Sec. 9 Table 8 (SHA-1)", title: "Digital signature generation: Disallowed ...", assets: 3,
      codes: ["SSH_DH_SHA1", "WEAK_CIPHER"], source: "https://nvlpubs.nist.gov/x.pdf",
      findings: [{ code: "SSH_DH_SHA1", title: "SHA-1 based SSH key exchange", fix: "Use curve25519-sha256 / diffie-hellman-group16-sha512 or a hybrid PQ method." },
                 { code: "WEAK_CIPHER", title: "Weak cipher suites accepted", fix: "Offer only ECDHE key exchange with AEAD ciphers (AES-GCM, ChaCha20-Poly1305)." }] },
  ] },
  { framework: "RBI", assets: 2, clauses: [
    { clause: "Master Direction on IT Governance (2023), para 16", title: RBI_TEXT, assets: 2, codes: ["WEAK_CIPHER"],
      note: "Applies to REs other than commercial banks", findings: [{ code: "WEAK_CIPHER", title: "Weak cipher suites accepted", fix: "Offer only ECDHE key exchange with AEAD ciphers (AES-GCM, ChaCha20-Poly1305)." }] },
    { clause: "Commercial Banks Cybersecurity Directions 2026, para 140", title: RBI_TEXT, assets: 2, codes: ["WEAK_CIPHER"],
      findings: [{ code: "WEAK_CIPHER", title: "Weak cipher suites accepted", fix: "Offer only ECDHE key exchange with AEAD ciphers (AES-GCM, ChaCha20-Poly1305)." }] },
  ] },
  { framework: "CERT-In", assets: 4, clauses: [
    { clause: "BOM Guidelines v2.0, 8.4.2.2", title: "Enforce strict TLS configurations ...", assets: 2, codes: ["WEAK_CIPHER"],
      findings: [{ code: "WEAK_CIPHER", title: "Weak cipher suites accepted", fix: "Offer only ECDHE key exchange with AEAD ciphers (AES-GCM, ChaCha20-Poly1305)." }] },
    { clause: "BOM Guidelines v2.0, 8.6", title: "Plan the migration to post-quantum cryptography ...", assets: 3, codes: ["NO_PQ_KEX", "QUANTUM_VULNERABLE"],
      findings: [{ code: "NO_PQ_KEX", title: "No post-quantum key exchange", fix: "Offer a hybrid post-quantum key-exchange group first where the TLS stack supports it." },
                 { code: "QUANTUM_VULNERABLE", title: "Quantum-vulnerable algorithm", fix: "Add it to the PQC migration plan; prioritise by the Mosca score." }] },
  ] },
];

const req = (id: string, verdict: string, refs: string[] = [], evidence = "") => ({ id, title: `Requirement ${id}`, verdict, refs, evidence, source: `https://src/${id}` });
export const ENGINE = {
  nist_800_57: { pass: 2, pass_with_evidence: 0, fail: 1, out_of_scope: 0, not_bom_evidenceable: 1, na: 0, coverage: 0.66,
                 requirements: [req("57-1", "pass"), req("57-2", "pass"), req("57-3", "fail", ["zs-asset-11", "zs-asset-12"], "RSA-1024 in use"), req("57-4", "not_bom_evidenceable")] },
  fips_140_3: { pass: 1, pass_with_evidence: 0, fail: 0, out_of_scope: 0, not_bom_evidenceable: 0, na: 1, coverage: 1, requirements: [req("F-1", "pass"), req("F-2", "na")] },
  cert_in_cbom: { pass: 3, pass_with_evidence: 0, fail: 0, out_of_scope: 0, not_bom_evidenceable: 0, na: 0, coverage: 1, requirements: [] },
  cnsa_2_0: { pass: 0, pass_with_evidence: 0, fail: 2, out_of_scope: 0, not_bom_evidenceable: 0, na: 0, coverage: 0,
              requirements: [req("CNSA-1", "fail", ["zs-asset-11", "crypto-algo-rsa"], "RSA is not CNSA 2.0"), req("CNSA-2", "fail", ["zs-asset-13"], "no post-quantum key exchange")] },
  sebi_cscrf_cbom: { pass: 0, pass_with_evidence: 0, fail: 0, out_of_scope: 4, not_bom_evidenceable: 0, na: 0, coverage: null, requirements: [] },
  eu_cra: { pass: 1, pass_with_evidence: 0, fail: 5, out_of_scope: 0, not_bom_evidenceable: 0, na: 0, coverage: 0.16, requirements: [] },
  disclaimer: "Advisory.",
} as unknown as Compliance;

