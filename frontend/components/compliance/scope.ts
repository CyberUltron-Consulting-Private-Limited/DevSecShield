/** Whether a compliance framework applies to the scanned system at all. */

import type { FrameworkCoverage } from "./types";

/**
 * False when every requirement of the framework is `out_of_scope` (HIPAA, FDA §524B or GMLP for a bank's AI BOM):
 * nothing passed, failed, needs evidence or is n/a. A framework with any requirement in scope, or with no counts at
 * all, applies. Counts are read first; without counts the requirements decide.
 */
export function appliesAtAll(f: FrameworkCoverage): boolean {
  const inScope =
    (f.pass ?? 0) + (f.pass_with_evidence ?? 0) + (f.fail ?? 0) + (f.not_bom_evidenceable ?? 0) + (f.na ?? 0);
  if (inScope > 0) return true;
  if ((f.out_of_scope ?? 0) > 0) return false;
  const reqs = f.requirements ?? [];
  return reqs.length === 0 || reqs.some((r) => r.verdict !== "out_of_scope");
}
