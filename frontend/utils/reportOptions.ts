/**
 * PDF report options in the browser: what the export dialog (components/reports/ExportPdfDialog.tsx) may leave out,
 * filter or add, and how it says so to the PDF routes (`toQuery`: the JSON body of a POST, or nothing at all).
 *
 * The constants block mirrors backend/utilities/pdf/report_options.py (the single source; utils/reportOptions.test.ts
 * reads that file and fails when the two differ). Leaving every option at its default sends no parameter at all, so
 * the server renders today's report unchanged.
 */

// --- constants (backend parity: backend/utilities/pdf/report_options.py) -------------------------------------------
export const FAMILIES = ["scan", "run", "deliverable", "pack"] as const;
export const PRESETS = ["executive", "technical", "full"] as const;
export const SEVERITIES = ["critical", "high", "medium", "low", "other"] as const;
export const STATUSES = ["not_started", "in_progress", "fixed", "ignored"] as const;
export const LABELS = ["confidential", "internal", "restricted", "public"] as const;
export const LABEL_TEXT = { confidential: "Confidential", internal: "Internal", restricted: "Restricted", public: "" } as const;
export const SCAN_SECTIONS = ["summary", "catalog", "details", "remediation", "mappings", "compliance", "inventory", "notes"] as const;
export const RUN_SECTIONS = ["summary", "posture", "catalog", "provenance"] as const;
export const PRESET_SECTIONS = {
  scan: {
    executive: ["summary", "compliance"],
    technical: ["summary", "catalog", "details", "remediation", "mappings", "notes"],
    full: SCAN_SECTIONS,
  },
  run: {
    executive: ["summary", "posture"],
    technical: ["summary", "catalog"],
    full: RUN_SECTIONS,
  },
} as const;
/** Sections each scan type actually has (the dialog shows only these; the server ignores the rest). */
export const TYPE_SECTIONS = {
  sast: ["summary", "catalog", "details", "remediation", "mappings", "notes"],
  iac: ["summary", "catalog", "details", "remediation", "mappings"],
  dast: ["summary", "catalog", "details", "remediation", "mappings"],
  mcp: ["summary", "catalog", "details", "remediation", "mappings", "notes"],
  llm: ["summary", "catalog", "details", "remediation", "mappings"],
  sbom_sca: ["summary", "catalog", "details", "remediation", "mappings", "compliance", "inventory"],
  ai_bom: ["summary", "catalog", "details", "remediation", "mappings", "compliance"],
  cbom: ["summary", "catalog", "details", "remediation", "mappings", "compliance", "notes"],
} as const;
export const FAMILY_KEYS = {
  scan: ["preset", "sections", "severities", "statuses", "prepared_for", "title", "label", "hide_evidence"],
  run: ["preset", "sections", "severities", "prepared_for", "title", "label"],
  deliverable: ["prepared_for", "label"],
  pack: [],
} as const;
export const PREPARED_FOR_MAX = 120;
export const TITLE_MAX = 140;
/** Beyond Windows-1252, the code points free text may use (inclusive ranges): Latin Extended, combining marks, Greek,
 * Cyrillic, Devanagari, the zero-width (non-)joiner, the rupee sign. The server draws them with Noto fonts. */
export const TEXT_RANGES = [
  [0x0100, 0x024f],
  [0x0300, 0x036f],
  [0x0370, 0x0377],
  [0x037a, 0x037f],
  [0x0384, 0x038a],
  [0x038c, 0x038c],
  [0x038e, 0x03a1],
  [0x03a3, 0x03e1],
  [0x03f0, 0x03ff],
  [0x0400, 0x052f],
  [0x0900, 0x097f],
  [0x1e00, 0x1eff],
  [0x200c, 0x200d],
  [0x20b9, 0x20b9],
  [0xa8e0, 0xa8ff],
] as const;
// --- end constants -------------------------------------------------------------------------------------------------

export type ReportFamily = (typeof FAMILIES)[number];
/** The families the export dialog builds (the evidence packs take no options). */
export type DialogFamily = "scan" | "run" | "deliverable";
export type Preset = (typeof PRESETS)[number];
export type Severity = (typeof SEVERITIES)[number];
export type FindingStatus = (typeof STATUSES)[number];
export type ReportLabel = (typeof LABELS)[number];
export type ScanSection = (typeof SCAN_SECTIONS)[number];
export type RunSection = (typeof RUN_SECTIONS)[number];
export type ReportSection = ScanSection | RunSection;
export type ReportScanType = keyof typeof TYPE_SECTIONS;
export type ReportKey = (typeof FAMILY_KEYS.scan)[number];

export const REPORT_SCAN_TYPES = Object.keys(TYPE_SECTIONS) as ReportScanType[];

/** What the dialog holds. Null sets mean "all" (no filter); empty strings mean "not set". */
export interface ReportOptions {
  /** null: a custom choice of sections (no preset) */
  preset: Preset | null;
  sections: ReportSection[] | null;
  severities: Severity[] | null;
  statuses: FindingStatus[] | null;
  prepared_for: string;
  title: string;
  label: ReportLabel;
  hide_evidence: boolean;
}

export const DEFAULT_OPTIONS: ReportOptions = {
  preset: "full",
  sections: null,
  severities: null,
  statuses: null,
  prepared_for: "",
  title: "",
  label: "confidential",
  hide_evidence: false,
};

const has = <T extends string>(list: readonly T[], value: unknown): value is T =>
  typeof value === "string" && (list as readonly string[]).includes(value);

/** The values of `chosen` that are in `order`, in `order`'s order (canonical, no duplicates). */
function inOrder<T extends string>(order: readonly T[], chosen: readonly string[]): T[] {
  const set = new Set(chosen);
  return order.filter((v) => set.has(v));
}

const sameSet = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((v) => b.includes(v));

/** The sections a report of this family (and scan type) has. */
export function availableSections(family: DialogFamily, scanType?: ReportScanType | null): readonly ReportSection[] {
  if (family === "run") return RUN_SECTIONS;
  if (family === "scan") return scanType ? TYPE_SECTIONS[scanType] : SCAN_SECTIONS;
  return [];
}

/** What a preset keeps of this report's sections (the server intersects the same way). */
export function presetSections(family: DialogFamily, preset: Preset, scanType?: ReportScanType | null): ReportSection[] {
  const available = availableSections(family, scanType);
  if (family !== "scan" && family !== "run") return [];
  const chosen = PRESET_SECTIONS[family][preset] as readonly string[];
  return inOrder(available, chosen);
}

/** The preset whose sections are exactly `sections`, else null (a custom choice). Full wins a tie (it is the default). */
export function presetFor(family: DialogFamily, sections: readonly string[], scanType?: ReportScanType | null): Preset | null {
  for (const preset of ["full", "executive", "technical"] as const) {
    if (sameSet(presetSections(family, preset, scanType), inOrder(availableSections(family, scanType), sections))) return preset;
  }
  return null;
}

export type TextField = "prepared_for" | "title";
export const TEXT_MAX: Record<TextField, number> = { prepared_for: PREPARED_FOR_MAX, title: TITLE_MAX };

// Windows-1252: Latin-1 (U+0000-U+007F, U+00A0-U+00FF) plus the 27 characters it puts at 0x80-0x9F.
const CP1252_EXTRA = new Set("€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ");
const isCp1252 = (ch: string) => {
  const code = ch.codePointAt(0) ?? 0;
  return code <= 0x7f || (code >= 0xa0 && code <= 0xff) || CP1252_EXTRA.has(ch);
};
const inTextRanges = (ch: string) => {
  const code = ch.codePointAt(0) ?? 0;
  return TEXT_RANGES.some(([low, high]) => code >= low && code <= high);
};
/** Every character is Windows-1252 or in TEXT_RANGES (the server's `text_supported`). */
export const textSupported = (text: string) => [...text].every((ch) => isCp1252(ch) || inTextRanges(ch));
// Python's unicodedata categories Cc (controls), Cf (format), Zl and Zp (line and paragraph separators), except the
// zero-width non-joiner and joiner (U+200C, U+200D), which are part of Devanagari spelling
const NOT_ONE_LINE = /(?![\u200C\u200D])[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

/** The text the server will print (NFC, trimmed; "" for nothing) and the problem with it, if any: the same checks, in
 * the same order and words, as `_text` in backend/utilities/pdf/report_options.py. */
export function validateText(field: TextField, raw: string): { value: string; error: string | null } {
  const value = raw.normalize("NFC").trim();
  if (!value) return { value: "", error: null };
  const limit = TEXT_MAX[field];
  if ([...value].length > limit) return { value, error: `must be ${limit} characters or fewer` };
  if (NOT_ONE_LINE.test(value)) return { value, error: "must be one line of plain text" };
  if (!textSupported(value)) return { value, error: "can only use Latin, Greek, Cyrillic or Devanagari characters" };
  return { value, error: null };
}

/** Length as the server counts it (code points after NFC and trimming), for the live counter. */
export function textLength(raw: string): number {
  return [...raw.normalize("NFC").trim()].length;
}

export interface OptionProblems {
  sections?: string;
  severities?: string;
  statuses?: string;
  prepared_for?: string;
  title?: string;
}

/** Why these options cannot be sent (empty: they can). Download stays disabled while any is set. */
export function optionProblems(options: ReportOptions, family: DialogFamily, scanType?: ReportScanType | null): OptionProblems {
  const keys = FAMILY_KEYS[family] as readonly string[];
  const out: OptionProblems = {};
  if (keys.includes("sections") && options.sections && inOrder(availableSections(family, scanType), options.sections).length === 0) {
    out.sections = "Choose at least one section";
  }
  if (keys.includes("severities") && options.severities && options.severities.length === 0) out.severities = "Choose at least one severity";
  if (keys.includes("statuses") && options.statuses && options.statuses.length === 0) out.statuses = "Choose at least one status";
  for (const field of ["prepared_for", "title"] as const) {
    if (!keys.includes(field)) continue;
    const { error } = validateText(field, options[field]);
    if (error) out[field] = error;
  }
  return out;
}

/** The report options to send to a route of `family`: only the keys the family takes, and only those that differ from
 * the default (all defaults: nothing, so a plain GET and today's report). Sent as the JSON body of a POST, never in the
 * URL, so a client name stays out of access logs (backend/utilities/pdf/report_http.py). The values are the ones the
 * GET query string takes. */
export function toQuery(options: ReportOptions, family: DialogFamily, scanType?: ReportScanType | null): Record<string, string> {
  const keys = FAMILY_KEYS[family] as readonly string[];
  const q: Record<string, string> = {};
  if (keys.includes("sections")) {
    const available = availableSections(family, scanType);
    const preset = options.preset && options.preset !== "full" ? options.preset : null;
    const expected = preset ? presetSections(family, preset, scanType) : [...available];
    const chosen = options.sections ? inOrder(available, options.sections) : expected;
    if (preset) q.preset = preset;
    // explicit sections win over a preset on the server: sent only when they differ from what the preset gives
    if (!sameSet(chosen, expected)) q.sections = chosen.join(",");
  }
  if (keys.includes("severities") && options.severities && !sameSet(inOrder(SEVERITIES, options.severities), SEVERITIES)) {
    q.severities = inOrder(SEVERITIES, options.severities).join(",");
  }
  if (keys.includes("statuses") && options.statuses && !sameSet(inOrder(STATUSES, options.statuses), STATUSES)) {
    q.statuses = inOrder(STATUSES, options.statuses).join(",");
  }
  for (const field of ["prepared_for", "title"] as const) {
    if (!keys.includes(field)) continue;
    const { value } = validateText(field, options[field]);
    if (value) q[field] = value;
  }
  if (keys.includes("label") && options.label !== "confidential") q.label = options.label;
  if (keys.includes("hide_evidence") && options.hide_evidence) q.hide_evidence = "true";
  return q;
}

// ------------------------------------------------------------------------------------------- remembered options
/** Only these are remembered between visits: never names, titles or filters (they can name a client or hide findings). */
export const REMEMBERED_KEYS = ["preset", "sections", "label", "hide_evidence"] as const;
type Remembered = Partial<Pick<ReportOptions, (typeof REMEMBERED_KEYS)[number]>>;

export const rememberedKey = (teamId: number | string, family: DialogFamily) => `zs.export.v1.${teamId}.${family}`;

function storage(): Storage | null {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null; // access denied (e.g. storage disabled for the site)
  }
}

/** What was remembered for this team and family, each field checked; anything unknown or malformed is dropped. */
export function loadRemembered(teamId: number | string, family: DialogFamily): Remembered {
  let raw: unknown = null;
  try {
    const text = storage()?.getItem(rememberedKey(teamId, family));
    raw = text ? JSON.parse(text) : null;
  } catch {
    return {};
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const r = raw as Record<string, unknown>;
  const keys = FAMILY_KEYS[family] as readonly string[];
  const out: Remembered = {};
  if (keys.includes("preset") && (r.preset === null || has(PRESETS, r.preset))) out.preset = r.preset as Preset | null;
  if (keys.includes("sections") && Array.isArray(r.sections)) {
    const all: readonly string[] = family === "run" ? RUN_SECTIONS : SCAN_SECTIONS;
    const sections = inOrder(all as readonly ReportSection[], r.sections.filter((s): s is string => typeof s === "string"));
    if (sections.length > 0 && sections.length === new Set(r.sections).size) out.sections = sections;
  }
  if (keys.includes("label") && has(LABELS, r.label)) out.label = r.label;
  if (keys.includes("hide_evidence") && typeof r.hide_evidence === "boolean") out.hide_evidence = r.hide_evidence;
  return out;
}

/** Remembers the dialog's preset, sections, label and snippet switch (only those the family takes). */
export function saveRemembered(teamId: number | string, family: DialogFamily, options: ReportOptions): void {
  const keys = FAMILY_KEYS[family] as readonly string[];
  const out: Record<string, unknown> = {};
  for (const key of REMEMBERED_KEYS) if (keys.includes(key)) out[key] = options[key];
  try {
    storage()?.setItem(rememberedKey(teamId, family), JSON.stringify(out));
  } catch {
    // full or denied: the next dialog starts from the defaults
  }
}

/** The dialog's starting options: the defaults, then what was remembered, fitted to this report's sections. */
export function initialOptions(teamId: number | string, family: DialogFamily, scanType?: ReportScanType | null): ReportOptions {
  const remembered = loadRemembered(teamId, family);
  const options: ReportOptions = { ...DEFAULT_OPTIONS, ...remembered };
  if (family === "scan" || family === "run") {
    const available = availableSections(family, scanType);
    if (options.preset) {
      options.sections = presetSections(family, options.preset, scanType);
    } else {
      const kept = inOrder(available, options.sections ?? []);
      options.sections = kept.length ? kept : [...available];
      options.preset = presetFor(family, options.sections, scanType);
    }
  }
  return options;
}

// ------------------------------------------------------------------------------------------- deliverable cover
// "Prepared for" is never stored; the deliverables menu keeps the one typed in the Cover options dialog for this page
// session only (until a reload), so its items stay one click.
const sessionPreparedFor = new Map<string, string>();

export function getSessionPreparedFor(teamId: number | string): string {
  return sessionPreparedFor.get(String(teamId)) ?? "";
}

export function setSessionPreparedFor(teamId: number | string, value: string): void {
  if (value) sessionPreparedFor.set(String(teamId), value);
  else sessionPreparedFor.delete(String(teamId));
}

/** The cover options the deliverables menu's one-click items use: the remembered label and this session's name. */
export function deliverableCover(teamId: number | string): ReportOptions {
  return { ...initialOptions(teamId, "deliverable"), prepared_for: getSessionPreparedFor(teamId) };
}

// ------------------------------------------------------------------------------------------- words
export const PRESET_TEXT: Record<Preset, string> = { executive: "Executive", technical: "Technical", full: "Full" };
export const SEVERITY_TEXT: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", other: "Other" };
export const STATUS_TEXT: Record<FindingStatus, string> = { not_started: "Not started", in_progress: "In progress", fixed: "Fixed", ignored: "Ignored" };
export const LABEL_CHOICE_TEXT: Record<ReportLabel, string> = { confidential: "Confidential", internal: "Internal", restricted: "Restricted", public: "Public (no label)" };

/** One line, in words (no counts), of what the PDF will hold. */
export function summaryText(options: ReportOptions, family: DialogFamily, scanType?: ReportScanType | null): string {
  if (family === "deliverable") {
    const parts = [options.prepared_for.trim() ? "A cover naming the client" : "The usual cover"];
    parts.push(options.label === "public" ? "no classification label" : `marked ${LABEL_TEXT[options.label]}`);
    return `${parts.join(", ")}, for each deliverable you download from this menu.`;
  }
  const available = availableSections(family, scanType);
  const chosen = inOrder(available, options.sections ?? available);
  const parts: string[] = [];
  if (chosen.length === available.length) parts.push("The full report");
  else if (options.preset) parts.push(`The ${PRESET_TEXT[options.preset].toLowerCase()} report`);
  else parts.push("A report with the sections you chose");
  const sev = options.severities ? inOrder(SEVERITIES, options.severities) : null;
  if (sev && sev.length < SEVERITIES.length) {
    parts.push(sev.length ? `${sev.map((s) => SEVERITY_TEXT[s].toLowerCase()).join(", ")} findings only` : "no severity chosen");
  } else parts.push("every severity");
  if (family === "scan") {
    const st = options.statuses ? inOrder(STATUSES, options.statuses) : null;
    if (st && st.length < STATUSES.length) parts.push(st.length ? `status ${st.map((s) => STATUS_TEXT[s].toLowerCase()).join(" or ")}` : "no status chosen");
    if (options.hide_evidence) parts.push("without code snippets");
  }
  if (options.prepared_for.trim()) parts.push("a cover naming the client");
  if (options.label !== "confidential") parts.push(options.label === "public" ? "no classification label" : `marked ${LABEL_TEXT[options.label]}`);
  return parts.join(", ") + ".";
}
