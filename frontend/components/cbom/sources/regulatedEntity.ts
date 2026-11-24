import type { InfoTipId } from "@/content/infotips/labels";

// The team's regulatory profile (CBOM settings, backend cbom_sources/regulated_entity.py): the regulated-entity type
// picks the RBI instrument the regulatory mapping cites (NBFC when not set), and three facts decide whether PCI DSS,
// SEBI CSCRF and the CERT-In Guidelines for Government Entities bind the team (all false when not set).
export type RegulatedEntity =
  | "nbfc" | "bank" | "sfb" | "payments_bank" | "ucb" | "aifi" | "credit_info_company" | "other";

const DIRECTIONS = "Cybersecurity, Technology: Risk, Resilience and Assurance Framework Directions 2026";

export const REGULATED_ENTITY_CHOICES: { value: RegulatedEntity; label: string; instrument: string | null }[] = [
  { value: "nbfc", label: "NBFC", instrument: `RBI NBFC ${DIRECTIONS}, para 118 (Middle Layer and above)` },
  { value: "bank", label: "Commercial bank", instrument: `RBI Commercial Banks ${DIRECTIONS}, para 140` },
  { value: "sfb", label: "Small finance bank", instrument: `RBI Small Finance Banks ${DIRECTIONS}, para 139` },
  { value: "payments_bank", label: "Payments bank", instrument: `RBI Payments Banks ${DIRECTIONS}, para 139` },
  { value: "ucb", label: "Urban co-operative bank", instrument: `RBI Urban Co-operative Banks ${DIRECTIONS}, para 25` },
  { value: "aifi", label: "All India Financial Institution",
    instrument: `RBI All India Financial Institutions ${DIRECTIONS}, para 135` },
  { value: "credit_info_company", label: "Credit information company",
    instrument: `RBI Credit Information Companies ${DIRECTIONS}, para 135` },
  { value: "other", label: "Other entity", instrument: null },
];

export const DEFAULT_REGULATED_ENTITY: RegulatedEntity = "nbfc";

export function regulatedEntityOf(value: unknown): RegulatedEntity {
  return REGULATED_ENTITY_CHOICES.some((c) => c.value === value) ? (value as RegulatedEntity) : DEFAULT_REGULATED_ENTITY;
}

export type RegulatoryFlag = "processes_card_data" | "sebi_regulated" | "government_entity";

export const REGULATORY_FLAGS: { value: RegulatoryFlag; label: string; tip: InfoTipId }[] = [
  { value: "processes_card_data", label: "Processes payment-card data (PCI DSS applies)",
    tip: "cbsrc.rr.flag.processes_card_data" },
  { value: "sebi_regulated", label: "SEBI-regulated entity (SEBI CSCRF applies)", tip: "cbsrc.rr.flag.sebi_regulated" },
  { value: "government_entity", label: "Government entity (CERT-In Guidelines for Government Entities apply)",
    tip: "cbsrc.rr.flag.government_entity" },
];

/** Deploy skew (review m7): a backend older than this setting sends no `regulated_entity`; the control is hidden then,
 * so the page never shows a value the server does not hold and never sends a field the server rejects (422). */
export function hasRegulatoryProfile(settings: { regulated_entity?: unknown } | null | undefined): boolean {
  return typeof settings?.regulated_entity === "string";
}

/** The flags the server holds; a flag the server does not send is not offered (an older backend). */
export function regulatoryFlagsOf(settings: Partial<Record<RegulatoryFlag, unknown>> | null | undefined
): Partial<Record<RegulatoryFlag, boolean>> {
  const out: Partial<Record<RegulatoryFlag, boolean>> = {};
  for (const f of REGULATORY_FLAGS) {
    const value = settings?.[f.value];
    if (typeof value === "boolean") out[f.value] = value;
  }
  return out;
}
