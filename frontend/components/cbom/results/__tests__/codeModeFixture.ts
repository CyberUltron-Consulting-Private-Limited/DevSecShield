// A code scan's results props (no `source`), rich enough to reach every code-mode section of CbomResults: the header
// and its download row, import and coverage notes, the metadata cards, the crypto charts, the dashboard, the findings
// table and its filters, and the top risks. codeModeUnchanged.test.ts renders it and compares the markup with the
// snapshot taken on the base commit (fbf79f7e) before the run-mode redesign: code mode must render exactly as before.
// Nothing here depends on today's date.

import type { CbomFinding, CbomScanDashboardData } from "@/utils/backend_api";

export const CODE_FINDINGS: CbomFinding[] = [
  {
    id: "f-1", bom_ref: "crypto-rsa-1", title: "RSA-1024", description: "RSA with a 1024-bit key", impact: "High", risk_score: 8.2,
    status: "not_started", compliance_controls: { "nist-800-131a": "NIST SP 800-131A" }, owasp_top_10: { A02: "Cryptographic Failures" },
    suggested_fix: "Use RSA-3072 or ML-DSA", algorithm_name: "RSA", algorithm_type: "asymmetric", crypto_strength: "weak", key_size: 1024,
    quantum_safe: false, location: "src/keys.py", line: 12, language: "python", finding_codes: ["RSA_LT_2048"],
  },
  {
    id: "f-2", bom_ref: "crypto-md5-2", title: "MD5", description: "MD5 digest", impact: "Medium", risk_score: 5.5,
    status: "fixed", compliance_controls: {}, owasp_top_10: {}, suggested_fix: "Use SHA-256", algorithm_name: "MD5",
    algorithm_type: "hash", crypto_strength: "weak", quantum_safe: true, location: "src/hash.py", finding_codes: ["MD5"],
  },
];

export const CODE_DASHBOARD = {
  card_data: {
    total_crypto_assets: 5, total_crypto_vulnerabilities: 2, total_informational: 3, quantum_readiness_judged: true,
    total_weak_algorithms: 2, total_quantum_vulnerable: 1, total_certificates: 0, total_keys: 1, quantum_readiness_score: 40,
    average_risk_score: 6.8,
    // the API's D3 risk score of these findings (1 High, 1 Medium): the engine's posture_risk(0, 1, 1, 0)
    risk_score: 28, risk_grade: "B", risk_label: "Moderate risk",
  },
  remediation_metrics: { mean_time_to_remediate: [1, 2, 3], critical_issues_fixed: 0, remediation_velocity: 1, high_priority_backlog: 1 },
  remediation_actions_required: { total_findings: 2, total_fixed: 1, total_in_progress: 0, total_not_started: 1, total_ignored: 0 },
  severity_distribution: { critical: 0, high: 1, medium: 1, low: 0 },
  algorithm_type_distribution: { asymmetric: 1, hash: 1 },
  strength_distribution: { weak: 2, strong: 3 },
  quantum_readiness: { quantum_safe: 4, quantum_vulnerable: 1 },
  owasp_top_10_issues: { A02: 2 },
  compliance_controls: { "nist-800-131a": 1 },
  top_risks: [{ algorithm_name: "RSA", algorithm_type: "asymmetric", crypto_strength: "weak", quantum_safe: false, impact: "High" }],
} as unknown as CbomScanDashboardData;

export const CODE_DATA = {
  cbom_distributions: {
    algorithms: { RSA: 1, MD5: 1, "AES-256-GCM": 3 },
    weakness: { "RSA-1024": 1, MD5: 1 },
    certificates: [],
    protocols: { "TLS 1.2": 1 },
    pqc: {
      quantum_vulnerable: 1, quantum_safe: 4, readiness_pct: 80,
      migration: [{ name: "RSA", primitive: "pke", key_size: "1024", curve: null, nist_quantum_security_level: 0,
        migration_target: "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)", migration_roadmap: "ML-DSA-65", impact: "High",
        location: "src/keys.py", bom_ref: "crypto-rsa-1" }],
    },
  },
};

export const CODE_METADATA = {
  repo_url: "https://example.test/repo.git",
  branch: "main",
  zip_file_used: false,
  cbom_coverage: { notes: [{ key: "archives", text: "2 archives were skipped", kind: "skipped" }], skipped: 1 },
  cbom_input: { crypto_assets: 4, imported: 3, skipped_not_crypto: 1, truncated: false, spec_version: "1.6", notes: ["One component had no name"] },
};
