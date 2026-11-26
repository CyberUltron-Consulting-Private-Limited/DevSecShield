import { createContext } from "react";

import type { FrameworkGroup } from "./types";

/**
 * The CBOM and SBOM compliance matrices show the frameworks that bind the team (backend
 * utilities/compliance/bom_applicability.py, `scan_metadata.compliance_applicability`), and the preset chips are named
 * after what is shown: a bank SEBI does not regulate reads "India / CERT-In", never "India / CERT-In / SEBI". The AI BOM
 * page does the same with its own view (PR #498: `groupsForFrameworks` in frameworkLabels.ts and `bindingCompliance` /
 * `applicabilityNote` in ai-bom/aibomDisplay.ts); this module is the one place for the CBOM and SBOM pages, and #498's
 * helpers can be re-exported from here once both are on dev.
 *
 * Without a view (an older backend, a Sources run, the pinned code-mode snapshot) every framework and the pinned chips
 * show, as before.
 */
export interface ComplianceApplicability {
  regulatory_profile?: { entity?: string; jurisdiction?: string; flags?: string[] } | null;
  basis?: string;
  binding?: string[];
  not_applicable?: { framework: string; label: string }[];
}

// TODO(#498): #498 adds the same `groupsForFrameworks` to frameworkLabels.ts for the AI BOM page. Once both PRs are on
// dev, frameworkLabels.ts should re-export this one (`export { groupsForFrameworks } from "./teamApplicability"`) so
// there is a single copy (review 6064315680 of #505, finding 7).

/** Indian regulators in chip order, by the framework keys that belong to them. */
const INDIA_REGULATORS: [string, RegExp][] = [
  ["CERT-In", /^cert_in_/],
  ["RBI", /^rbi_/],
  ["SEBI", /^sebi_cscrf_/],
];

/**
 * The preset chips for the frameworks a page shows (the semantics of #498's `groupsForFrameworks`): the "india" chip
 * keeps only its keys that are present and is named after their regulators; with none left it is dropped. Other chips
 * are unchanged. `present` = the framework keys of the compliance object the matrix receives.
 */
export function groupsForFrameworks(groups: FrameworkGroup[], present: Iterable<string>): FrameworkGroup[] {
  const have = new Set(present);
  const out: FrameworkGroup[] = [];
  for (const g of groups) {
    if (g.id !== "india") {
      out.push(g);
      continue;
    }
    const keys = g.keys.filter((k) => have.has(k));
    if (keys.length === 0) continue;
    const names = INDIA_REGULATORS.filter(([, re]) => keys.some((k) => re.test(k))).map(([name]) => name);
    out.push({ ...g, keys, label: ["India", ...names].join(" / ") });
  }
  return out;
}

/** The compliance object without the frameworks the view leaves out (the disclaimer stays); unchanged without one. */
export function bindingCompliance<T extends object>(
  compliance: T | null | undefined,
  view: ComplianceApplicability | null | undefined,
): T | null | undefined {
  if (!compliance || !view || !Array.isArray(view.binding)) return compliance;
  const keep = new Set([...view.binding, "disclaimer"]);
  return Object.fromEntries(Object.entries(compliance).filter(([k]) => keep.has(k))) as T;
}

/** The sentence under the matrix: which profile chose the frameworks, and which it leaves out. */
export function applicabilityNote(view: ComplianceApplicability | null | undefined): string | null {
  if (!view) return null;
  if (!view.regulatory_profile) {
    return "Team regulatory profile: regulated entity not set. Every framework is shown.";
  }
  const names = (view.not_applicable ?? []).map((n) => n.label);
  if (names.length === 0) return null;
  return `Frameworks shown for this team's regulatory profile (${view.basis}). Not applicable to it: ${names.join(", ")}.`;
}

/** What a CBOM / SBOM matrix renders: the binding frameworks, chips named after them, and the note; with no view,
 * the compliance and the groups as given (no note). */
export function teamCompliance<T extends object>(
  compliance: T,
  groups: FrameworkGroup[],
  view: ComplianceApplicability | null | undefined,
): { compliance: T; groups: FrameworkGroup[]; note: string | null } {
  if (!view || !Array.isArray(view.binding)) return { compliance, groups, note: null };
  const shown = (bindingCompliance(compliance, view) ?? compliance) as T;
  const keys = Object.keys(shown).filter((k) => k !== "disclaimer");
  return { compliance: shown, groups: groupsForFrameworks(groups, keys), note: applicabilityNote(view) };
}

/** The view a CBOM page passes down to its compliance matrix (CbomCryptoCharts' CbomComplianceMatrix); null: none. */
export const ComplianceApplicabilityContext = createContext<ComplianceApplicability | null>(null);
