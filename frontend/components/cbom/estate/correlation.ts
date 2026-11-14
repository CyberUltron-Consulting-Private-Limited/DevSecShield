// Engine step 3 (correlate): an estate asset's owners, applications and data classification (its sources' current
// metadata) and the code / SBOM scan components that use it. Served on the run asset drawer (`asset.correlation`),
// the estate asset (`correlation`) and the register rows (`owners`, `data_classification`). Pure; tested with tsx.

export interface CorrelationLink {
  kind: "sbom" | "code" | string;
  scan_id: number;
  scan_title: string | null;
  component: string;
  purl: string | null;
  match: string;
}

export interface Correlation {
  estate_key?: string;
  owners: string[];
  applications: string[];
  data_classification: string | null;
  data_classifications?: string[];
  environments?: string[];
  criticality?: string[];
  conflicts?: string[];
  unknown?: string[];
  links: CorrelationLink[];
  links_state?: string;
}

export const CLASSIFICATION_LABEL: Record<string, string> = {
  public: "Public", internal: "Internal", confidential: "Confidential", restricted: "Restricted",
};

export const MATCH_LABEL: Record<string, string> = {
  purl: "same package URL", name_version: "same name and version", name: "same name, another version",
  cert_key: "same certificate",
};

export function classificationText(c: Pick<Correlation, "data_classification" | "data_classifications">): string {
  if (!c.data_classification) return "Not set";
  const label = CLASSIFICATION_LABEL[c.data_classification] ?? c.data_classification;
  const others = (c.data_classifications ?? []).filter((v) => v !== c.data_classification);
  return others.length ? `${label} (highest of ${c.data_classifications!.length} systems)` : label;
}

/** "SBOM scan #501 (payments sbom): openssl@1.1.1k, same name and version". */
export function linkText(l: CorrelationLink): string {
  const where = `${l.kind === "sbom" ? "SBOM scan" : "Code scan"} #${l.scan_id}${l.scan_title ? ` (${l.scan_title})` : ""}`;
  return `${where}: ${l.component}, ${MATCH_LABEL[l.match] ?? l.match}`;
}

export function scanHref(teamId: number | string, l: CorrelationLink): string {
  return l.kind === "sbom" ? `/${teamId}/sbom_sca/${l.scan_id}/results` : `/${teamId}/cbom/${l.scan_id}/results`;
}

/** Sentences for what is missing or disputed (a CMDB import or the source form fills them). */
export function gaps(c: Pick<Correlation, "unknown" | "conflicts">): string[] {
  const out: string[] = [];
  const names: Record<string, string> = { owner: "owner", application: "application", data_classification: "data classification",
    environment: "environment", business_criticality: "business criticality" };
  if (c.unknown?.length) out.push(`No source names its ${c.unknown.map((f) => names[f] ?? f).join(", ")}.`);
  if (c.conflicts?.length) out.push(`Its sources disagree on the ${c.conflicts.map((f) => names[f] ?? f).join(", ")}.`);
  return out;
}
