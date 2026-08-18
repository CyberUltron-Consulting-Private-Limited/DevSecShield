/**
 * Pure helpers for the AI-BOM Model Card panel — candidate ranking, default
 * pick + reason, and never-blank field fill. No React deps so hermetic tests
 * can import this module without a component harness.
 */

export type Json = Record<string, unknown>;

export type ModelCandidate = {
  id: string;
  name: string;
  version?: string;
  component: Json;
  hasCard: boolean;
  richness: number;
  inInventory: boolean;
};

export type ModelCardRows = {
  name: string;
  version: string;
  approach: string;
  task: string;
  architectureFamily: string;
  modelArchitecture: string;
  cardSource: "BOM modelCard" | "Inferred from model identity";
};

export type DefaultPick = {
  candidate: ModelCandidate;
  reason: string;
};

const INVENTORY_TYPES = new Set([
  "local_model_file",
  "huggingface_model",
  "embedding_model",
]);

const NOT_DECLARED = "Not declared in BOM";
const UNSPECIFIED = "Unspecified";

function asObj(v: unknown): Json {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Json) : {};
}

function nonEmptyStr(v: unknown): string | undefined {
  if (v == null) return undefined;
  if (typeof v === "object") return undefined;
  const s = String(v).trim();
  if (!s || s === "—" || s === "-" || s.toLowerCase() === "unknown") return undefined;
  if (s === "[object Object]") return undefined;
  return s;
}

function modelParameters(comp: Json): Json {
  const mc = asObj(comp.modelCard ?? comp.model_card);
  return asObj(mc.modelParameters);
}

function cardRichness(comp: Json): number {
  const mp = modelParameters(comp);
  let n = 0;
  for (const k of ["task", "architectureFamily", "modelArchitecture", "approach"]) {
    const v = mp[k];
    if (k === "approach") {
      if (typeof v === "object" && v && nonEmptyStr((v as Json).type)) n += 1;
      else if (nonEmptyStr(v)) n += 1;
    } else if (nonEmptyStr(v)) {
      n += 1;
    }
  }
  return n;
}

function hasModelCard(comp: Json): boolean {
  const mc = comp.modelCard ?? comp.model_card;
  if (!mc || typeof mc !== "object") return false;
  return cardRichness(comp) > 0 || Object.keys(asObj(mc)).length > 0;
}

function componentId(comp: Json, index: number): string {
  return (
    nonEmptyStr(comp["bom-ref"]) ||
    nonEmptyStr(comp.bom_ref) ||
    nonEmptyStr(comp.name) ||
    `model-${index}`
  );
}

/** Inventory model names from findings rows. */
export function inventoryModelNames(findings?: Json[] | null): Set<string> {
  const out = new Set<string>();
  for (const f of findings ?? []) {
    const t = String(f.asset_type ?? f.component_type ?? "").toLowerCase();
    if (!INVENTORY_TYPES.has(t)) continue;
    const name = nonEmptyStr(f.asset_name) || nonEmptyStr(f.component_name) || nonEmptyStr(f.title);
    if (name) out.add(name);
  }
  return out;
}

/** Build ranked candidate list for the selector. */
export function buildModelCandidates(
  aiBomJson?: Json | null,
  findings?: Json[] | null,
): ModelCandidate[] {
  const comps = (aiBomJson?.components as Json[] | undefined) ?? [];
  const inventory = inventoryModelNames(findings);
  const allModels: ModelCandidate[] = [];
  comps.forEach((c, i) => {
    if (String(c.type ?? "") !== "machine-learning-model") return;
    const name = nonEmptyStr(c.name) || `model-${i}`;
    allModels.push({
      id: componentId(c, i),
      name,
      version: nonEmptyStr(c.version),
      component: c,
      hasCard: hasModelCard(c),
      richness: cardRichness(c),
      inInventory: inventory.has(name),
    });
  });

  if (allModels.length === 0) return [];

  const inventoryHits = allModels.filter((m) => m.inInventory);
  let pool: ModelCandidate[];
  if (inventoryHits.length > 0) {
    pool = inventoryHits;
  } else {
    const withCards = allModels.filter((m) => m.hasCard);
    pool = withCards.length > 0 ? withCards : allModels;
  }

  // Stable sort: richer cards first, then name.
  return [...pool].sort((a, b) => {
    if (b.richness !== a.richness) return b.richness - a.richness;
    if (a.hasCard !== b.hasCard) return a.hasCard ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
}

/** Default pick + human-readable why string. */
export function pickDefaultModel(candidates: ModelCandidate[]): DefaultPick | null {
  if (candidates.length === 0) return null;
  const richest = candidates.reduce((best, c) =>
    c.richness > best.richness ? c : best,
  );
  if (richest.richness > 0) {
    return {
      candidate: richest,
      reason: richest.inInventory
        ? "selected because it has the richest BOM model card among inventoried models"
        : "selected because it has the richest BOM model card in this scan",
    };
  }
  const withCard = candidates.find((c) => c.hasCard);
  if (withCard) {
    return {
      candidate: withCard,
      reason: withCard.inInventory
        ? "selected because it carries a BOM model card among inventoried models"
        : "selected because it carries a BOM model card",
    };
  }
  const first = candidates[0];
  return {
    candidate: first,
    reason: first.inInventory
      ? "selected as the first inventoried model (no BOM model card present)"
      : "selected as the first available model (no BOM model card present)",
  };
}

function approachFromCard(mp: Json): string | undefined {
  const approach = mp.approach;
  if (approach && typeof approach === "object") {
    return nonEmptyStr((approach as Json).type);
  }
  return nonEmptyStr(approach);
}

function inferTask(name: string): string | undefined {
  const n = name.toLowerCase();
  if (n.includes("embedding")) return "embedding";
  if (n.includes("whisper")) return "speech-to-text";
  if (n.includes("tts")) return "text-to-speech";
  if (n.includes("dall-e") || n.includes("image") || n.includes("gpt-image")) {
    return "image-generation";
  }
  if (n.includes("moderation")) return "moderation";
  if (n.includes("realtime")) return "realtime-audio";
  if (
    n.includes("gpt") ||
    n.includes("claude") ||
    n.includes("chat") ||
    n.includes("o1") ||
    n.includes("o3")
  ) {
    return "chat/completion";
  }
  return undefined;
}

function inferFamily(name: string): string | undefined {
  const n = name.toLowerCase();
  if (
    n.includes("gpt") ||
    n.includes("claude") ||
    n.includes("llama") ||
    n.includes("mistral") ||
    n.includes("gemini")
  ) {
    return "transformer";
  }
  return undefined;
}

function inferArchitecture(name: string): string | undefined {
  const n = name.toLowerCase();
  if (n.includes("gpt") || n.startsWith("o1") || n.startsWith("o3")) {
    return "GPT (proprietary)";
  }
  if (n.includes("claude")) return "Claude (proprietary)";
  if (n.includes("llama")) return "LLaMA";
  if (n.includes("whisper")) return "Whisper";
  if (n.includes("dall-e") || n.includes("gpt-image")) return "Diffusion / image (proprietary)";
  if (n.includes("embedding")) return "Embedding model";
  return undefined;
}

function isHostedApiName(name: string): boolean {
  const n = name.toLowerCase();
  return (
    n.includes("gpt") ||
    n.includes("claude") ||
    n.includes("dall-e") ||
    n.includes("whisper") ||
    n.includes("o1") ||
    n.includes("o3") ||
    n.includes("gemini") ||
    n.includes("bedrock")
  );
}

/** Never-blank display rows for a selected CycloneDX model component. */
export function fillModelCardRows(comp: Json): ModelCardRows {
  const name = nonEmptyStr(comp.name) || "Unnamed model";
  const mp = modelParameters(comp);
  const fromBom = hasModelCard(comp);

  const approach =
    approachFromCard(mp) ||
    (isHostedApiName(name) ? "Proprietary API model" : undefined) ||
    NOT_DECLARED;
  const task = nonEmptyStr(mp.task) || inferTask(name) || NOT_DECLARED;
  const architectureFamily =
    nonEmptyStr(mp.architectureFamily) || inferFamily(name) || NOT_DECLARED;
  const modelArchitecture =
    nonEmptyStr(mp.modelArchitecture) || inferArchitecture(name) || NOT_DECLARED;
  const version = nonEmptyStr(comp.version) || UNSPECIFIED;

  return {
    name,
    version,
    approach,
    task,
    architectureFamily,
    modelArchitecture,
    cardSource: fromBom ? "BOM modelCard" : "Inferred from model identity",
  };
}

/** Assert helper for tests: no blank / em-dash / object-string values. */
export function rowsHaveNoBlanks(rows: ModelCardRows): boolean {
  const vals = [
    rows.name,
    rows.version,
    rows.approach,
    rows.task,
    rows.architectureFamily,
    rows.modelArchitecture,
    rows.cardSource,
  ];
  return vals.every((v) => {
    const s = String(v ?? "").trim();
    return s.length > 0 && s !== "—" && s !== "-" && s !== "[object Object]";
  });
}
