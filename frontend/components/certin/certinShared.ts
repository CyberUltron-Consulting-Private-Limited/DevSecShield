/** Shared CERT-In posture types + dimension labels (rollup + lane charts). */

export const CERTIN_DIM_LABELS: Record<string, string> = {
  sbom_minimum_elements: "Software component inventory",
  sbom_recommendations: "SBOM process controls",
  cbom_crypto_assets: "Cryptographic asset inventory",
  cbom_recommendations: "Crypto process controls",
  aibom_ai_assets: "AI model & dataset inventory",
  aibom_recommendations: "AI process controls",
};

export const CERTIN_LANE_DIMS = {
  sbom: ["sbom_minimum_elements", "sbom_recommendations"] as const,
  cbom: ["cbom_crypto_assets", "cbom_recommendations"] as const,
  aibom: ["aibom_ai_assets", "aibom_recommendations"] as const,
};

export type CertInLane = keyof typeof CERTIN_LANE_DIMS;

export const CERTIN_LANE_META: Record<
  CertInLane,
  { title: string; description: string; empty: string }
> = {
  sbom: {
    title: "CERT-In SBOM posture (advisory)",
    description:
      "Software component inventory and SBOM process controls for this scan. Does not constitute certification.",
    empty: "No CERT-In SBOM verdicts in this scan",
  },
  cbom: {
    title: "CERT-In CBOM posture (advisory)",
    description:
      "Cryptographic asset inventory and crypto process controls for this scan. Does not constitute certification.",
    empty: "No CERT-In CBOM verdicts in this scan",
  },
  aibom: {
    title: "CERT-In AIBOM posture (advisory)",
    description:
      "AI model and dataset inventory and AI process controls for this scan. Does not constitute certification.",
    empty: "No CERT-In AIBOM verdicts in this scan",
  },
};

export type CertInRequirement = {
  id: string;
  framework: string;
  verdict: string;
  title: string;
  source?: string;
  evidence?: string;
  refs?: string[];
  attestable?: boolean;
  resolve_hint?: string;
  _scanner?: string;
};

export type CertInDimRollup = {
  pass?: number;
  pass_with_evidence?: number;
  fail?: number;
  out_of_scope?: number;
  not_bom_evidenceable?: number;
  na?: number;
  coverage?: number | null;
  requirements?: CertInRequirement[];
};

export type CertInRollupData = {
  certin_posture?: Record<string, CertInDimRollup>;
  disclaimer?: string;
  hbom_note?: string;
};

export const CERTIN_VERDICT_COLORS = {
  pass: "#10b981",
  pass_with_evidence: "#14b8a6",
  fail: "#dc2626",
  out_of_scope: "#64748b",
  not_bom_evidenceable: "#8b5cf6",
  na: "#a1a1aa",
} as const;
