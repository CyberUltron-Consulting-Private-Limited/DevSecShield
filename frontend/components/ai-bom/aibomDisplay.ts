/**
 * AI BOM results-page wording and labels (staging QA round 2, D5).
 *
 * - The AI Governance subtitle follows the team's regulatory profile (CBOM settings ``regulated_entity``, the same
 *   profile the PDF report and the evidence pack's compliance.json use): a bank or an NBFC never reads "Healthcare".
 *   The healthcare wording is kept only for an "other" entity whose AI BOM itself carries the healthcare disclaimer
 *   (the engine's ``regulatory:disclaimer`` names FDA / HIPAA only for a BOM with clinical metadata).
 * - Licence ids can be long (``LicenseRef-Mistral-AI-Non-Production-License``): the chart axis shows a short label
 *   and the tooltip keeps the full id.
 */
import { REGULATED_ENTITY_CHOICES } from "@/components/cbom/sources/regulatedEntity";

type Json = Record<string, unknown>;

const SUBTITLE_TAIL = "compliance readiness, supply-chain lineage, deployment drift and model provenance.";

/** Whether the AI BOM carries the engine's healthcare disclaimer (a BOM with clinical / regulatory metadata). */
export function isHealthcareBom(aiBomJson: Json | null | undefined): boolean {
  const meta = aiBomJson?.metadata as Json | undefined;
  const props = Array.isArray(meta?.properties) ? (meta?.properties as Json[]) : [];
  const disclaimer = props.find((p) => p?.name === "regulatory:disclaimer")?.value;
  return typeof disclaimer === "string" && /\b(?:HIPAA|FDA)\b/.test(disclaimer);
}

/** The AI Governance section subtitle for a team's regulated-entity type (undefined: not loaded / not readable). */
export function governanceSubtitle(entity: string | null | undefined, aiBomJson: Json | null | undefined): string {
  const choice = REGULATED_ENTITY_CHOICES.find((c) => c.value === entity);
  if (choice && choice.value !== "other") return `${choice.label} AI BOM: ${SUBTITLE_TAIL}`;
  if (choice?.value === "other" && isHealthcareBom(aiBomJson)) return `Healthcare AI BOM: ${SUBTITLE_TAIL}`;
  return `AI BOM: ${SUBTITLE_TAIL}`;
}

const MAX_LABEL = 24;

/** A short label for a licence id (at most ``max`` characters); the full id belongs in the tooltip / title. */
export function licenceLabel(id: string, max: number = MAX_LABEL): string {
  if (id === "NOASSERTION") return max >= 22 ? "unknown (not resolved)" : "unknown";
  const text = id.startsWith("LicenseRef-") ? id.slice("LicenseRef-".length).replace(/-/g, " ") : id;
  return text.length <= max ? text : `${text.slice(0, max - 1).trimEnd()}…`;
}
