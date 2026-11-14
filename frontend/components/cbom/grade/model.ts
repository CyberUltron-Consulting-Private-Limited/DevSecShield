// Quantum risk grade (CB-19, model qg-1) and crypto-agility fix class (CB-24, model fx-1): the API shapes, the label
// and palette maps, and the pure helpers the components render with. Every value comes from the API: the run asset
// list (q_grade, fix_class ...), the asset detail (q_explain, agility), the run posture (q_grades, q0_items,
// fix_classes ...) and the two model routes (GET …/sources/grade-model, …/sources/agility-model). Nothing here
// derives a grade or a class; it only says how one is shown.
//
// Vocabulary (CB-18 / CB-19 §2.7): a grade is printed only with its risk word, "Q1 Critical", never alone; the
// grade keys are read from GRADE_TEXT so this file names each one only next to its word. The grade keys, reason
// codes and fix-class values must equal the backend's: contracts/cbom/grade_keys.json (written from qgrade.py and
// agility.py by backend/tests/test_cbom_cb19_cb24_ui_contract.py, read by gradeContract.test.ts).

// ---------------------------------------------------------------------------------------------- quantum risk grade
/** The five grades, worst first after the unknown, each with its risk word: the only place a grade key is spelled. */
export const GRADE_TEXT = ["Q0 Unknown", "Q1 Critical", "Q2 High", "Q3 Medium", "Q4 Low"] as const;
export type GradeText = (typeof GRADE_TEXT)[number];
type KeyOf<T extends string> = T extends `${infer K} ${string}` ? K : never;
export type QGrade = KeyOf<GradeText>;
/** Grade keys in the API's order. */
export const GRADE_KEYS = GRADE_TEXT.map((t) => t.split(" ")[0]) as QGrade[];
/** Risk word per grade key ("Critical" ...). */
export const GRADE_WORD = Object.fromEntries(GRADE_TEXT.map((t) => [t.split(" ")[0], t.slice(t.indexOf(" ") + 1)])) as Record<QGrade, string>;
/** The distribution's buckets: the five grades and "none" (no grade: nothing to grade). */
export const GRADE_BUCKETS = [...GRADE_KEYS, "none"] as const;
export type GradeBucket = QGrade | "none";

/** Risk palette (CB-19 §2.7), in GRADE_TEXT's order: grey, red, orange, amber, green; text always next to the colour. */
const PALETTE: { chip: string; bar: string }[] = [
  { chip: "border-zinc-400/60 bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300", bar: "bg-zinc-400" },
  { chip: "border-red-500/60 bg-red-50 text-red-700 dark:bg-red-950/40 dark:text-red-300", bar: "bg-red-600" },
  { chip: "border-orange-500/60 bg-orange-50 text-orange-700 dark:bg-orange-950/40 dark:text-orange-300", bar: "bg-orange-500" },
  { chip: "border-amber-500/60 bg-amber-50 text-amber-800 dark:bg-amber-950/40 dark:text-amber-300", bar: "bg-amber-400" },
  { chip: "border-green-500/60 bg-green-50 text-green-700 dark:bg-green-950/40 dark:text-green-300", bar: "bg-green-600" },
];
export const GRADE_STYLE = Object.fromEntries(GRADE_KEYS.map((k, i) => [k, PALETTE[i]])) as Record<QGrade, { chip: string; bar: string }>;
export const NONE_STYLE = { chip: "border-zinc-300/60 text-zinc-500 dark:text-zinc-400", bar: "bg-zinc-200 dark:bg-zinc-700" };

export function isGrade(value: unknown): value is QGrade {
  return typeof value === "string" && (GRADE_KEYS as string[]).includes(value);
}

/** Run asset list item / asset detail fields (CB-19 PR-1). */
export interface QGradeFields {
  q_grade?: string | null;
  q_label?: string | null;
  q_reason?: string | null;
  q_item_key?: string | null;
}

/** `q_explain` of the asset detail: the inputs the grade read. */
export interface QExplain {
  class: string | null;
  class_basis: string | null;
  graded_class: string | null;
  fallback: boolean;
  fallback_basis: string | null;
  exposure: string | null;
  exposure_basis: string | null;
  anchor: boolean;
  anchor_basis: string | null;
  x: number | null;
  x_basis: "source" | "team" | null;
  y: number | null;
  z: number | null;
  missing: string[];
  inequality: string | null;
  provenance: string;
  item_kind: "asset" | "scope" | string;
  coverage: string | null;
  check: string | null;
  status: string | null;
  model: string;
  model_version: string;
  inputs_source: string;
  inputs_digest: string;
  classifier_version?: string | null;
  run_classifier_version?: string | null;
}

/** One entry of the run posture's `q0_items` (unread scope, an asset the product could not grade, a missing input). */
export interface Q0Item {
  key: string;
  kind: string;
  reason: string;
  q_grade: string | null;
  source_id: number | null;
  source_name: string | null;
  count: number;
  target?: string | null;
  check?: string | null;
  status?: string | null;
  detail?: string | Record<string, unknown> | null;
  refs?: number[];
  addresses?: string[];
  asset_id?: number;
  type?: string;
  location?: string;
  missing?: string[];
}

/** The quantum-risk part of GET …/runs/{id}/posture. Optional: an older backend sends none of it. */
export interface QPosture {
  assets?: number;
  q_grades?: Partial<Record<string, number>>;
  q0_reasons?: Record<string, number>;
  q0_items?: Q0Item[];
  q0_items_total?: number;
  q0_counts?: { assets: number; scope_items: number; scope_rows: number };
  q_not_items?: { no_answer: number; not_present: number };
  grade_model?: string;
  grade_model_version?: string;
  grade_inputs?: { source: string; mosca: { x: number | null; y: number | null; z: number | null }; digest: string };
}

/** GET …/sources/grade-model. */
export interface GradeModel {
  model: string;
  model_version: string;
  text: string;
  text_sha256: string;
  grades: { grade: string; label: string }[];
  reasons: { code: string; grade: string | null; label: string | null; kind: string; text: string }[];
}

/** "Q1 Critical"; null for "no grade"; an unseen value is printed as it came, marked, never crashing. */
export function gradeText(grade: string | null | undefined): string | null {
  if (grade == null || grade === "") return null;
  return isGrade(grade) ? `${grade} ${GRADE_WORD[grade]}` : `${grade} (unrecognised grade)`;
}

export function gradeChipClass(grade: string | null | undefined): string {
  return isGrade(grade) ? GRADE_STYLE[grade].chip : NONE_STYLE.chip;
}

/** Whether the server sent grade fields at all (an older backend sends neither key). */
export function gradeAvailable(item: QGradeFields): boolean {
  return item.q_grade !== undefined || item.q_reason !== undefined;
}

/** The chip's hover text: the reason (served text when the model is loaded, else the code) or why there is no grade. */
export function gradeTitle(item: QGradeFields, reasons?: Map<string, string>): string {
  if (!gradeAvailable(item)) return "Not graded: this server does not send a quantum risk grade";
  const reason = item.q_reason ? reasons?.get(item.q_reason) ?? humanize(item.q_reason) : null;
  if (item.q_grade == null || item.q_grade === "") {
    if (item.q_reason === "not_applicable" || !item.q_reason) return "No grade: no public-key cryptography";
    return `No grade: ${reason}`;
  }
  return reason ? `${gradeText(item.q_grade)}: ${reason}` : gradeText(item.q_grade) ?? "";
}

export function humanize(code: string): string {
  const s = code.replace(/[_-]+/g, " ").trim();
  return s ? s[0].toUpperCase() + s.slice(1) : code;
}

/** reason code -> served sentence. */
export function reasonTexts(model: GradeModel | null | undefined): Map<string, string> {
  return new Map((model?.reasons ?? []).map((r) => [r.code, r.text]));
}

export interface DistributionSegment {
  bucket: GradeBucket;
  text: string;
  count: number;
  /** share of the total, 0-100, one decimal */
  pct: number;
  bar: string;
}

/** The posture's grade distribution in order (Q0 Unknown .. Q4 Low, then "No grade"), every bucket present (0 too),
 * and whether its total equals the posture's asset count (both count the run's assets without coverage rows). */
export function qDistribution(p: QPosture): { segments: DistributionSegment[]; total: number; consistent: boolean } {
  const counts = p.q_grades ?? {};
  const total = GRADE_BUCKETS.reduce((n, b) => n + (Number(counts[b]) || 0), 0);
  const segments = GRADE_BUCKETS.map((bucket) => {
    const count = Number(counts[bucket]) || 0;
    return {
      bucket,
      text: bucket === "none" ? "No grade" : `${bucket} ${GRADE_WORD[bucket]}`,
      count,
      pct: total ? Math.round((1000 * count) / total) / 10 : 0,
      bar: bucket === "none" ? NONE_STYLE.bar : GRADE_STYLE[bucket].bar,
    };
  });
  return { segments, total, consistent: p.assets == null || p.assets === total };
}

/** Whether the posture carries grades at all (an older backend: no). */
export function hasGrades(p: QPosture | null | undefined): boolean {
  return !!p && !!p.q_grades;
}

/** Q0 Unknown reasons with their item counts, most items first, then by code. */
export function q0Reasons(p: QPosture): { code: string; count: number }[] {
  return Object.entries(p.q0_reasons ?? {})
    .map(([code, count]) => ({ code, count: Number(count) || 0 }))
    .sort((a, b) => b.count - a.count || a.code.localeCompare(b.code));
}

/** One line per Q0 Unknown item: what is unread or ungraded, where, and how many rows it stands for. */
export function q0ItemLine(item: Q0Item): string {
  const parts: string[] = [];
  if (item.kind === "inputs") {
    const missing = (item.missing ?? []).map((m) => m.toUpperCase()).join(", ");
    parts.push(`Mosca ${missing || "X, Y or Z"} not set`);
  } else if (item.location) {
    parts.push(item.location);
  } else if (item.target && item.target !== "*") {
    parts.push(item.target);
  } else if (item.target === "*") {
    parts.push("addresses");
  }
  if (item.check && item.check !== "target") parts.push(item.check);
  if (item.status) parts.push(item.status.replace(/_/g, " "));
  return parts.join(" · ");
}

export function q0ItemCountText(item: Q0Item): string | null {
  if (item.kind === "inputs") return `${item.count} asset${item.count === 1 ? "" : "s"} ungraded`;
  if (item.count > 1) return `${item.count} rows`;
  return null;
}

export function detailText(detail: Q0Item["detail"]): string | null {
  if (detail == null || detail === "") return null;
  if (typeof detail === "string") return detail;
  if (typeof detail !== "object") return String(detail);
  // e.g. {"reported": 9, "stored": 4} (assets lost) or {"truncated": true, "stored": 0}
  const parts = Object.entries(detail).map(([k, v]) =>
    v === true ? humanize(k).toLowerCase() : `${humanize(k).toLowerCase()} ${typeof v === "object" ? JSON.stringify(v) : String(v)}`);
  return parts.length ? parts.join(", ") : null;
}

/** The drawer's inputs table: label, value and where the value came from (empty rows are left out). */
export function explainRows(e: QExplain): { label: string; value: string; basis: string | null }[] {
  const rows: { label: string; value: string; basis: string | null }[] = [];
  const add = (label: string, value: string | number | null | undefined, basis?: string | null) => {
    if (value === null || value === undefined || value === "") return;
    rows.push({ label, value: String(value), basis: basis ?? null });
  };
  if (e.item_kind === "scope") {
    add("Item", "Unread scope");
    add("Check", e.check);
    add("Status", e.status ? e.status.replace(/_/g, " ") : null);
    add("Coverage", e.coverage ? humanize(e.coverage) : null);
  } else {
    add("PQC class", e.class, e.class_basis);
    if (e.graded_class && e.graded_class !== e.class) add("Graded as", e.graded_class, "weakest configuration it accepts");
    if (e.fallback) add("Classical fallback", "Yes", e.fallback_basis);
    add("Exposure", e.exposure, e.exposure_basis);
    add("Trust anchor", e.anchor ? "Yes" : "No", e.anchor_basis);
    rows.push({ label: "X: years data must stay secret", value: e.x == null ? "Not set" : String(e.x),
                basis: e.x_basis === "source" ? "set on the source" : e.x_basis === "team" ? "team setting" : null });
    rows.push({ label: "Y: years to migrate", value: e.y == null ? "Not set" : String(e.y), basis: "team setting" });
    rows.push({ label: "Z: years until a quantum computer", value: e.z == null ? "Not set" : String(e.z), basis: "team setting" });
    add("Mosca", e.inequality);
    if (e.missing?.length) add("Missing", e.missing.map((m) => m.toUpperCase()).join(", "));
    add("Provenance", e.provenance);
  }
  add("Grade model", e.model_version);
  add("Inputs", e.inputs_source === "current" ? "The team's settings as they are now" : e.inputs_source, e.inputs_digest);
  return rows;
}

/** sha256 of a text as lower-case hex, with Web Crypto (browsers in a secure context, Node 20); null when unavailable. */
export type ShaCheck = "checking" | "match" | "mismatch" | "insecure" | "unavailable";
/** What the dialog says about the served sha: computed here (`sha`, null when Web Crypto is missing) against the
 * served value; browsers offer Web Crypto only on secure pages (https:// or localhost). */
export function shaCheck(sha: string | null, served: string, secureContext: boolean): ShaCheck {
  if (sha == null) return secureContext ? "unavailable" : "insecure";
  return sha === served ? "match" : "mismatch";
}
export const SHA_CHECK_TEXT: Record<ShaCheck, string> = {
  checking: "",
  match: "checked in this browser",
  mismatch: "does not match the text shown",
  insecure: "not checked: this page is not served over HTTPS (browsers offer Web Crypto only on secure pages)",
  unavailable: "this browser cannot check it",
};

export async function sha256Hex(text: string): Promise<string | null> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return null;
  const digest = await subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------------------------- crypto-agility
export const FIX_CLASSES = ["configurable", "code-fixed", "vendor-fixed", "hardware-fixed"] as const;
export type FixClass = (typeof FIX_CLASSES)[number];
/** The six values an asset can have: the four classes, `unknown` (with the class it is at least) and `none`. */
export const FIX_VALUES = [...FIX_CLASSES, "unknown", "none"] as const;
export type FixValue = (typeof FIX_VALUES)[number];
export const SELF_FIXABLE: readonly FixClass[] = ["configurable", "code-fixed"];

export const FIX_LABEL: Record<FixValue, string> = {
  configurable: "Configurable",
  "code-fixed": "Code-fixed",
  "vendor-fixed": "Vendor-fixed",
  "hardware-fixed": "Hardware-fixed",
  unknown: "Unknown",
  none: "None",
};

/** Palette distinct from the risk grades and the E-levels (CB-24 §10). */
export const FIX_STYLE: Record<FixValue, { chip: string; bar: string }> = {
  configurable: { chip: "border-teal-500/60 bg-teal-50 text-teal-700 dark:bg-teal-950/40 dark:text-teal-300", bar: "bg-teal-500" },
  "code-fixed": { chip: "border-blue-500/60 bg-blue-50 text-blue-700 dark:bg-blue-950/40 dark:text-blue-300", bar: "bg-blue-600" },
  "vendor-fixed": { chip: "border-violet-500/60 bg-violet-50 text-violet-700 dark:bg-violet-950/40 dark:text-violet-300", bar: "bg-violet-600" },
  "hardware-fixed": { chip: "border-slate-500/60 bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300", bar: "bg-slate-600" },
  unknown: { chip: "border-dashed border-zinc-400 text-zinc-600 dark:text-zinc-400", bar: "bg-zinc-300 dark:bg-zinc-600" },
  none: { chip: "border-transparent text-zinc-500 dark:text-zinc-400", bar: "bg-zinc-200 dark:bg-zinc-700" },
};

export function isFixValue(value: unknown): value is FixValue {
  return typeof value === "string" && (FIX_VALUES as readonly string[]).includes(value);
}

export interface FixClassFields {
  fix_class?: string | null;
  fix_class_floor?: string | null;
  fix_class_confidence?: string | null;
}

/** The asset detail's `agility` block. */
export interface AgilityDetail {
  fix_class: string;
  floor: string | null;
  confidence: string | null;
  fix_class_excl_pq?: string;
  by_code: { code: string; class: string; floor: string | null; capability: boolean; rule: string; basis: string;
             fact: string | null; confidence: string | null }[];
  model: string;
  model_version: string;
  source?: string;
}

export interface AgilitySystem {
  key: string;
  label: string;
  kind: string;
  assets: number;
  hardest: string | null;
  counts: Partial<Record<string, number>>;
  self_fixable_pct: number | null;
}

/** The crypto-agility part of the run posture. */
export interface AgilityPosture {
  assets?: number;
  fix_classes?: Partial<Record<string, number>>;
  fix_classes_excl_pq?: Partial<Record<string, number>>;
  fix_class_self_fixable_pct?: number | null;
  unknown_reasons?: Record<string, number>;
  fix_class_systems?: AgilitySystem[];
  fix_class_systems_truncated?: boolean;
  agility_version?: string;
}

/** GET …/sources/agility-model. */
export interface AgilityModel {
  model: string;
  model_version: string;
  kb_version: string;
  classes: { key: string; rank: number | null; label: string; what: string; example: string }[];
  inferred: string;
  pq_codes: string[];
  self_fixable: string[];
  rules: { id: string; applies_to: string; condition: string; result: string }[];
  unknown_reasons: Record<string, string>;
}

/** The chip's text: "Vendor-fixed", "At least vendor-fixed" for an unknown with a floor, "Unknown", "—" for none;
 * an unseen value is printed as it came, marked. */
export function fixClassText(f: FixClassFields): string {
  const v = f.fix_class;
  if (v == null || v === "" || v === "none") return "—";
  if (v === "unknown") {
    return isFixValue(f.fix_class_floor) && f.fix_class_floor !== "unknown" && f.fix_class_floor !== "none"
      ? `At least ${FIX_LABEL[f.fix_class_floor].toLowerCase()}` : "Unknown";
  }
  return isFixValue(v) ? FIX_LABEL[v] : `${v} (unrecognised class)`;
}

export function fixClassChipClass(value: string | null | undefined): string {
  return isFixValue(value) ? FIX_STYLE[value].chip : FIX_STYLE.unknown.chip;
}

/** Whether the server sent a fix class at all (an older backend does not). */
export function fixClassAvailable(f: FixClassFields): boolean {
  return f.fix_class !== undefined;
}

export function fixClassTitle(f: FixClassFields): string {
  if (!fixClassAvailable(f)) return "No fix class: this server does not send one";
  const v = f.fix_class;
  if (v == null || v === "" || v === "none") return "No finding code: nothing to change today";
  if (v === "unknown") return "Unknown: a fact that decides the class was not read" +
    (isFixValue(f.fix_class_floor) ? `; it is at least ${FIX_LABEL[f.fix_class_floor].toLowerCase()}` : "");
  return `${isFixValue(v) ? FIX_LABEL[v] : v}${f.fix_class_confidence === "inferred" ? " (likely: inferred, no deciding fact read)" : ""}`;
}

/** (configurable + code-fixed) over the assets with one of the four classes, one decimal; null when there are none
 * (agility.self_fixable_pct). */
export function selfFixablePct(counts: Partial<Record<string, number>>): number | null {
  const classified = FIX_CLASSES.reduce((n, c) => n + (Number(counts[c]) || 0), 0);
  if (!classified) return null;
  const self = SELF_FIXABLE.reduce((n, c) => n + (Number(counts[c]) || 0), 0);
  return Math.round((1000 * self) / classified) / 10;
}

export interface FixSegment { value: FixValue; text: string; count: number; pct: number; bar: string }

/** The six counts in order, every value present (0 too), and whether the total equals the posture's asset count. */
export function fixDistribution(counts: Partial<Record<string, number>> | undefined, assets?: number):
    { segments: FixSegment[]; total: number; classified: number; selfFixable: number; consistent: boolean } {
  const c = counts ?? {};
  const total = FIX_VALUES.reduce((n, v) => n + (Number(c[v]) || 0), 0);
  const segments = FIX_VALUES.map((value) => {
    const count = Number(c[value]) || 0;
    return { value, text: FIX_LABEL[value], count, pct: total ? Math.round((1000 * count) / total) / 10 : 0,
             bar: FIX_STYLE[value].bar };
  });
  const classified = FIX_CLASSES.reduce((n, v) => n + (Number(c[v]) || 0), 0);
  const selfFixable = SELF_FIXABLE.reduce((n, v) => n + (Number(c[v]) || 0), 0);
  return { segments, total, classified, selfFixable, consistent: assets == null || assets === total };
}

export function hasAgility(p: AgilityPosture | null | undefined): boolean {
  return !!p && !!p.fix_classes;
}

/** Rule id -> its condition sentence (served by the agility model). */
export function ruleTexts(model: AgilityModel | null | undefined): Map<string, string> {
  return new Map((model?.rules ?? []).map((r) => [r.id, `${r.applies_to}: ${r.condition} → ${r.result}`]));
}
