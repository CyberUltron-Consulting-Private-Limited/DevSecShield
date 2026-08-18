/** Shared compliance matrix types (AIBOM / CBOM / SBOM). */

export type ComplianceVerdict =
  | "pass"
  | "pass_with_evidence"
  | "fail"
  | "out_of_scope"
  | "not_bom_evidenceable"
  | "na";

export interface ComplianceRequirement {
  id: string;
  title: string;
  verdict: ComplianceVerdict;
  evidence?: string;
  source?: string;
  attestable?: boolean;
}

export interface FrameworkCoverage {
  pass: number;
  pass_with_evidence?: number;
  fail: number;
  out_of_scope?: number;
  not_bom_evidenceable?: number;
  na: number;
  coverage: number | null;
  requirements?: ComplianceRequirement[];
}

/** Framework coverage map; a `disclaimer` string may ride alongside objects. */
export type Compliance = Record<string, FrameworkCoverage | string>;

export interface FrameworkGroup {
  id: string;
  label: string;
  /** Empty keys = show all frameworks. */
  keys: string[];
}
