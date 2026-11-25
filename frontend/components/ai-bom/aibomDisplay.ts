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

/** The AI Governance section subtitle for a team's regulated-entity type. ``null`` / undefined: the team declared no
 * regulated entity, so nothing is filtered and a clinical BOM keeps the healthcare wording (review 6037909737 M4). */
export function governanceSubtitle(entity: string | null | undefined, aiBomJson: Json | null | undefined): string {
  const choice = REGULATED_ENTITY_CHOICES.find((c) => c.value === entity);
  if (choice && choice.value !== "other") return `${choice.label} AI BOM: ${SUBTITLE_TAIL}`;
  if (isHealthcareBom(aiBomJson)) return `Healthcare AI BOM: ${SUBTITLE_TAIL}`;
  return `AI BOM: ${SUBTITLE_TAIL}`;
}

/** The server's ``ai_bom_applicability`` (backend aibom_applicability.page_view): the frameworks that bind the team. */
export type AiBomApplicability = {
  regulatory_profile?: { entity?: string; flags?: string[] } | null;
  basis?: string;
  binding?: string[];
  not_applicable?: { framework: string; label: string }[];
};

/** The engine's compliance report keeping only the frameworks that bind the team (and its disclaimer), so the
 * results page shows what the PDF and the evidence pack show (review 6037909737 of #498, M3). No applicability (an
 * older backend): unchanged. */
export function bindingCompliance<T extends Record<string, unknown>>(
  compliance: T | null | undefined,
  applicability: AiBomApplicability | null | undefined,
): T | null | undefined {
  if (!compliance || !applicability || !Array.isArray(applicability.binding)) return compliance;
  const keep = new Set([...applicability.binding, "disclaimer"]);
  return Object.fromEntries(Object.entries(compliance).filter(([k]) => keep.has(k))) as T;
}

/** The sentence under the framework charts: which profile chose them, and which frameworks it leaves out. */
export function applicabilityNote(applicability: AiBomApplicability | null | undefined): string | null {
  if (!applicability) return null;
  if (!applicability.regulatory_profile) {
    return "Team regulatory profile: regulated entity not set. Every framework this AI BOM is in the scope of is shown.";
  }
  const names = (applicability.not_applicable ?? []).map((n) => n.label);
  if (names.length === 0) return null;
  return `Frameworks shown for this team's regulatory profile (${applicability.basis}). Not applicable to it: ${names.join(", ")}.`;
}

/** The Models tile's note for model calls that name no model (engine ``aibom:model_unnamed_*``, #498 round 3):
 * ``ChatOpenAI()`` runs the library's default model, which depends on the installed release, so the page says so
 * instead of silently showing fewer models. ``null`` when every call names its model. */
export function unnamedModelHint(aiBomJson: Json | null | undefined): string | null {
  const meta = aiBomJson?.metadata as Json | undefined;
  const props = Array.isArray(meta?.properties) ? (meta?.properties as Json[]) : [];
  const value = (name: string) => {
    const v = props.find((p) => p?.name === name)?.value;
    return typeof v === "string" ? v : "";
  };
  const n = Number.parseInt(value("aibom:model_unnamed_calls"), 10);
  if (!Number.isFinite(n) || n <= 0) return null;
  const library = value("aibom:model_unnamed_library");
  const calls = n === 1 ? "1 call names no model" : `${n} calls name no model`;
  return `${calls}: library default${library ? ` (${library})` : ""}`;
}

const MAX_LABEL = 24;

/** A short label for a licence id (at most ``max`` characters); the full id belongs in the tooltip / title. */
export function licenceLabel(id: string, max: number = MAX_LABEL): string {
  if (id === "NOASSERTION") return max >= 22 ? "unknown (not resolved)" : "unknown";
  const text = id.startsWith("LicenseRef-") ? id.slice("LicenseRef-".length).replace(/-/g, " ") : id;
  return text.length <= max ? text : `${text.slice(0, max - 1).trimEnd()}…`;
}
