import type { FrameworkGroup } from "./types";

/** Merged AIBOM + CBOM + CERT-In + SEBI framework display labels. */
export const FRAMEWORK_LABELS: Record<string, string> = {
  // AIBOM
  fda_524b: "FDA §524B",
  eu_ai_act_annexIV: "EU AI Act (Annex IV)",
  gmlp: "GMLP (IMDRF)",
  hipaa: "HIPAA",
  nist_rmf: "NIST AI RMF",
  rbi_free_ai: "RBI FREE-AI",
  rbi_free_ai_supply: "RBI FREE-AI (Supply Chain)",
  ntia_minimum_elements: "NTIA Minimum Elements",
  nist_ssdf: "NIST SSDF (SP 800-218)",
  // CBOM
  nist_1800_38b: "NIST SP 1800-38B",
  nist_800_57: "NIST SP 800-57",
  omb_m_23_02: "OMB M-23-02",
  eu_cra: "EU CRA",
  eu_dora: "EU DORA",
  pci_dss_4: "PCI-DSS 4.0",
  fips_140_3: "FIPS 140-3",
  bsi_tr_02102: "BSI TR-02102",
  nist_1800_38c: "NIST SP 1800-38C",
  cnsa_2_0: "CNSA 2.0",
  rbi_free_ai_protection: "RBI FREE-AI (Protection)",
  // CERT-In
  cert_in_cbom: "CERT-In CBOM (Guidelines v2.0)",
  cert_in_aibom: "CERT-In AIBOM (Guidelines v2.0)",
  cert_in_sbom: "CERT-In SBOM (Guidelines v2.0)",
  // SEBI CSCRF
  sebi_cscrf_cbom: "SEBI CSCRF (CBOM)",
  sebi_cscrf_aibom: "SEBI CSCRF (AIBOM)",
  sebi_cscrf_sbom: "SEBI CSCRF (SBOM)",
};

/** CBOM framework-filter groups (default remains All — never auto-India). */
export const FRAMEWORK_GROUPS_CBOM: FrameworkGroup[] = [
  { id: "all", label: "All", keys: [] },
  {
    id: "quantum",
    label: "Quantum-safe",
    keys: ["nist_1800_38b", "nist_1800_38c", "cnsa_2_0"],
  },
  {
    id: "baseline",
    label: "Baseline crypto",
    keys: ["nist_800_57", "fips_140_3", "bsi_tr_02102"],
  },
  {
    id: "regulatory",
    label: "Regulatory",
    keys: [
      "pci_dss_4",
      "eu_cra",
      "eu_dora",
      "omb_m_23_02",
      "rbi_free_ai_protection",
    ],
  },
];

/**
 * CBOM groups plus India / CERT-In / SEBI chip.
 * Default filter remains All — never auto-select India.
 */
export const FRAMEWORK_GROUPS_CBOM_WITH_INDIA: FrameworkGroup[] = [
  ...FRAMEWORK_GROUPS_CBOM,
  {
    id: "india",
    label: "India / CERT-In / SEBI",
    keys: ["cert_in_cbom", "sebi_cscrf_cbom"],
  },
];

/**
 * AIBOM groups plus India / CERT-In / SEBI chip.
 * Default filter remains All — never auto-select India.
 */
export const FRAMEWORK_GROUPS_AIBOM_WITH_INDIA: FrameworkGroup[] = [
  { id: "all", label: "All", keys: [] },
  {
    id: "india",
    label: "India / CERT-In / SEBI",
    keys: ["cert_in_aibom", "sebi_cscrf_aibom"],
  },
];

/**
 * SBOM groups: Supply chain (RBI/NTIA/SSDF) + India / CERT-In / SEBI.
 * Default filter remains All — never auto-select India.
 */
export const FRAMEWORK_GROUPS_SBOM_WITH_INDIA: FrameworkGroup[] = [
  { id: "all", label: "All", keys: [] },
  {
    id: "supply",
    label: "Supply chain",
    keys: ["rbi_free_ai_supply", "ntia_minimum_elements", "nist_ssdf"],
  },
  {
    id: "india",
    label: "India / CERT-In / SEBI",
    keys: ["cert_in_sbom", "sebi_cscrf_sbom"],
  },
];

/**
 * India / CERT-In / SEBI group — available for later Phase wiring.
 * Must NOT change the default filter to this group.
 */
export const FRAMEWORK_GROUPS_INDIA_CERTIN: FrameworkGroup[] = [
  { id: "all", label: "All", keys: [] },
  {
    id: "india",
    label: "India / CERT-In / SEBI",
    keys: [
      "cert_in_cbom",
      "cert_in_aibom",
      "cert_in_sbom",
      "sebi_cscrf_cbom",
      "sebi_cscrf_aibom",
      "sebi_cscrf_sbom",
    ],
  },
];

export const labelFramework = (k: string) => FRAMEWORK_LABELS[k] ?? k;
