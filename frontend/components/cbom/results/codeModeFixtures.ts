// Fixtures for codeModeSnapshot.test.ts: the props a code scan (and, before the redesign, a Sources run) passes to the
// shared results components. The snapshot of their output was taken on dev fbf79f7e, before the run-only redesign
// props existed; with those props left out every component must render exactly that output.
import type { CbomFinding, CbomGraph, CbomScanDashboardData } from "@/utils/backend_api";
import type { CbomCompliance, CbomDistributions } from "@/components/cbom/CbomCryptoCharts";
import type { HeatData } from "@/components/cbom/heatmapLogic";
import type { AgilityPosture, QPosture } from "@/components/cbom/grade";

export const DISTRIBUTIONS: CbomDistributions = {
  algorithms: { pke: 4, "block-cipher": 3, hash: 2, signature: 1, kem: 0 },
  weakness: { WEAK_ALGORITHM: 2, QUANTUM_VULNERABLE: 4, SELF_SIGNED_LEAF: 1 },
  pqc: {
    quantum_vulnerable: 4, quantum_safe: 3, readiness_pct: 42.9, hybrid: 1,
    nist_level_distribution: { "0": 4, "3": 2, "5": 1 },
    migration: [
      { name: "RSA-2048", primitive: "pke", key_size: "2048", curve: null, nist_quantum_security_level: 0,
        migration_target: "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)", migration_roadmap: "ML-KEM-768", impact: "High",
        location: "src/crypto/rsa.py", bom_ref: "ref-rsa-1", description: "RSA key transport", suggested_fix: "Move to ML-KEM-768",
        finding_codes: ["QUANTUM_VULNERABLE"] },
      { name: "RSA-2048", primitive: "pke", key_size: "2048", curve: null, nist_quantum_security_level: 0,
        migration_target: "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)", migration_roadmap: "ML-KEM-768", impact: "High",
        location: "src/crypto/rsa2.py", bom_ref: "ref-rsa-2", description: "RSA key transport", suggested_fix: "Move to ML-KEM-768",
        finding_codes: ["QUANTUM_VULNERABLE"] },
      { name: "ECDSA-P256", primitive: "signature", key_size: "256", curve: "P-256", nist_quantum_security_level: 0,
        migration_target: "ML-DSA (FIPS 204)", migration_roadmap: "ML-DSA-65", impact: "Medium",
        location: "src/sign.go", bom_ref: "ref-ec-1", description: null, suggested_fix: "Move to ML-DSA-65",
        finding_codes: ["QUANTUM_VULNERABLE"] },
    ],
  },
  certificates: [
    { name: "CN=api.example", not_valid_after: "2027-03-01T00:00:00Z", self_signed: false, expired: false, location: "certs/api.pem", bom_ref: "c1" },
    { name: "CN=old.example", not_valid_after: "2024-01-01T00:00:00Z", self_signed: true, expired: true, location: "certs/old.pem", bom_ref: "c2" },
    { name: "CN=soon.example", not_valid_after: "2026-12-01T00:00:00Z", self_signed: false, expired: false, near_expiry: true, location: "certs/soon.pem", bom_ref: "c3" },
  ],
  key_material: [
    { name: "server.key", material_kind: "private-key", container_format: "PEM", parse_status: "ok", location: "certs/server.key", bom_ref: "k1" },
    { name: "store.p12", material_kind: "credential", container_format: "PKCS12", parse_status: "opaque", location: "certs/store.p12", bom_ref: "k2" },
  ],
  protocols: { "TLS 1.2": 3, "TLS 1.0": 1, "SSL 3.0": 1 },
};

export const GRAPH: CbomGraph = {
  nodes: [
    { id: "n1", label: "RSA-2048", kind: "asset", asset_type: "algorithm", primitive: "pke", quantum_vulnerable: true },
    { id: "n2", label: "CN=api.example", kind: "asset", asset_type: "certificate" },
    { id: "n3", label: "TLS 1.2", kind: "asset", asset_type: "protocol" },
    { id: "n4", label: "server.key", kind: "asset", asset_type: "related-crypto-material" },
    { id: "n5", label: "openssl", kind: "framework" },
  ],
  edges: [{ source: "n2", target: "n1", rel: "uses" }, { source: "n5", target: "n1", rel: "provides" }],
};

export const COMPLIANCE: CbomCompliance = {
  cnsa_2_0: { pass: 1, fail: 1, na: 0, pass_with_evidence: 0, out_of_scope: 0, not_bom_evidenceable: 0, coverage: 0.5,
    requirements: [
      { id: "CNSA-1", title: "Symmetric ciphers and hashes are AES-256 / SHA-384/512", verdict: "fail", source: "NSA CNSA 2.0" },
      { id: "CNSA-2", title: "Post-quantum algorithms are a CNSA 2.0 parameter set", verdict: "pass", source: "NSA CNSA 2.0" },
    ] },
  fips_140_3: { pass: 2, fail: 0, na: 1, coverage: 1,
    requirements: [
      { id: "FIPS-1", title: "Only approved security functions", verdict: "pass" },
      { id: "FIPS-2", title: "Keys of at least 2048 bits", verdict: "pass" },
      { id: "FIPS-4", title: "CMVP certificate", verdict: "not_bom_evidenceable", attestable: true },
    ] },
  disclaimer: "Advisory.",
};

export const FINDINGS: CbomFinding[] = [
  { id: "f1", bom_ref: "ref-rsa-1", title: "RSA-2048", description: "RSA key transport", impact: "High", risk_score: 7.5, status: "open",
    compliance_controls: {}, owasp_top_10: {}, algorithm_name: "RSA-2048", algorithm_type: "asymmetric", crypto_strength: "moderate",
    quantum_safe: false, location: "src/crypto/rsa.py", asset_type: "algorithm" },
  { id: "f2", bom_ref: "c2", title: "Expired certificate", description: "", impact: "Medium", risk_score: 5, status: "open",
    compliance_controls: {}, owasp_top_10: {}, algorithm_name: "CN=old.example", location: "certs/old.pem", asset_type: "certificate",
    not_valid_after: "2024-01-01T00:00:00Z", self_signed: true, expired: true },
  { id: "f3", bom_ref: "ref-ec-1", title: "ECDSA-P256", description: "", impact: "Low", risk_score: 3, status: "fixed",
    compliance_controls: {}, owasp_top_10: {}, algorithm_name: "ECDSA-P256", algorithm_type: "signature", quantum_safe: false,
    location: "src/sign.go", asset_type: "algorithm" },
];

export const DASHBOARD: CbomScanDashboardData = {
  card_data: {
    total_crypto_assets: 12, total_weak_algorithms: 2, total_quantum_vulnerable: 4, total_certificates: 3, total_keys: 2,
    quantum_readiness_score: 42.9, quantum_readiness_judged: true, average_risk_score: 5.2,
  },
  remediation_metrics: { mean_time_to_remediate: [2, 4, 0], critical_issues_fixed: 1, remediation_velocity: 6, high_priority_backlog: 12 },
  remediation_actions_required: { total_findings: 10, total_fixed: 3, total_in_progress: 2, total_not_started: 4, total_ignored: 1 },
  severity_distribution: { critical: 2, high: 3, medium: 4, low: 1 },
  algorithm_type_distribution: { asymmetric: 5, symmetric_cipher: 3, hash: 2 },
  strength_distribution: { weak: 2, moderate: 5, strong: 3, quantum_safe: 2 },
  quantum_readiness: { quantum_safe: 3, quantum_vulnerable: 4, unknown: 1 },
  owasp_top_10_issues: { A02_2021: 4, A05_2021: 2 },
  compliance_controls: { "NIST-800-53-SC-13": 4, "ISO-27001-A.10.1": 2 },
  top_risks: [],
} as unknown as CbomScanDashboardData;

export const HEAT: HeatData = {
  rows: ["RSA", "Elliptic curve"],
  columns: ["src/crypto", "src/sign.go"],
  cells: [
    { row: "RSA", column: "src/crypto", count: 2, worst: "High", by_impact: { High: 2 } },
    { row: "Elliptic curve", column: "src/sign.go", count: 1, worst: "Low", by_impact: { Low: 1 } },
  ],
};

export const Q_POSTURE: QPosture = {
  assets: 20,
  q_grades: { Q0: 3, Q1: 2, Q2: 4, Q3: 1, Q4: 0, none: 10 },
  q0_reasons: { coverage_gap: 1, mosca_missing: 1, unknown_verdict: 1 },
  q0_items: [
    { key: "inputs:mosca", kind: "inputs", reason: "mosca_missing", q_grade: "Q0", source_id: null, source_name: null, count: 2, missing: ["z"] },
    { key: "asset:node:abc", kind: "asset", reason: "unknown_verdict", q_grade: "Q0", source_id: 1, source_name: "DMZ range",
      count: 1, asset_id: 77, location: "10.0.0.9:443" },
  ],
  q0_items_total: 2,
  q0_counts: { assets: 3, scope_items: 1, scope_rows: 7 },
  grade_model: "qg-1", grade_model_version: "qg-1+abcdef012345",
  grade_inputs: { source: "current", mosca: { x: 10, y: 5, z: null }, digest: "0123456789abcdef" },
} as unknown as QPosture;

export const AGILITY: AgilityPosture = {
  assets: 150,
  fix_classes: { configurable: 30, "code-fixed": 10, "vendor-fixed": 50, "hardware-fixed": 10, unknown: 7, none: 43 },
  fix_classes_excl_pq: { configurable: 30, "code-fixed": 5, "vendor-fixed": 20, "hardware-fixed": 5, unknown: 2, none: 88 },
  fix_class_self_fixable_pct: 40,
  unknown_reasons: { key_provider_not_read: 5, no_fix_class: 2 },
  fix_class_systems: [{ key: "application:payments", label: "Payments", kind: "application", assets: 100, hardest: "hardware-fixed",
    counts: { configurable: 20, "vendor-fixed": 50, "hardware-fixed": 10, unknown: 5, none: 15 }, self_fixable_pct: 25 }],
  fix_class_systems_truncated: false,
  agility_version: "fx-1+0123",
} as unknown as AgilityPosture;
