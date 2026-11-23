// The team's regulated-entity type (CBOM settings `regulated_entity`, backend cbom_sources/regulated_entity.py): it
// picks the RBI instrument the deliverables' regulatory mapping cites. NBFC when not set.
export type RegulatedEntity = "nbfc" | "bank" | "other";

export const REGULATED_ENTITY_CHOICES: { value: RegulatedEntity; label: string; instrument: string }[] = [
  { value: "nbfc", label: "NBFC",
    instrument: "RBI NBFC Cybersecurity, Technology: Risk, Resilience and Assurance Framework Directions 2026" },
  { value: "bank", label: "Commercial bank",
    instrument: "RBI Commercial Banks Cybersecurity, Technology: Risk, Resilience and Assurance Framework Directions 2026" },
  { value: "other", label: "Other regulated entity",
    instrument: "RBI Master Direction on IT Governance, Risk, Controls and Assurance Practices (2023)" },
];

export const DEFAULT_REGULATED_ENTITY: RegulatedEntity = "nbfc";

export function regulatedEntityOf(value: unknown): RegulatedEntity {
  return REGULATED_ENTITY_CHOICES.some((c) => c.value === value) ? (value as RegulatedEntity) : DEFAULT_REGULATED_ENTITY;
}
