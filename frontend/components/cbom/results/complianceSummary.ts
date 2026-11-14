// Compliance mapping view-model (#270). Pure: no React, no fetching, so the rules are tested without a browser
// (complianceSummary.test.ts). One results template, two inputs:
//   - `engine`: the tri-state compliance report (scan_metadata.cbom_compliance; a run's comes from /runs/{id}/parity),
//     present on code scans and runs. Its six verdict types give each framework's verdict and chart.
//   - `mapping`: the knowledge-base clauses the run's findings touch (/runs/{id}/results compliance; runs only). Each
//     clause carries its finding codes with their KB title and remediation summary.
// Nothing here counts table rows: clause and framework asset counts are the API's (Rule P); the drill-down hands the
// table a filter (finding codes or asset ids) and the table's total comes from the server.

import type { Compliance, ComplianceRequirement, ComplianceVerdict, FrameworkCoverage } from "@/components/compliance/types";
import { labelFramework } from "@/components/compliance/frameworkLabels";
import { VERDICT_ORDER } from "@/components/compliance/verdictTokens";
import { filterFindingsByRelatedRefs, type RelatedFindingFields } from "@/utils/relatedFindingMatch";
import type { CbomClauseFinding } from "@/utils/backend_api";

import { FRAMEWORK_ORDER, type ComplianceRow } from "./model";

/** A framework's overall verdict, from the six requirement verdict types. */
export type FrameworkVerdict = "pass" | "fail" | "partial" | "not_assessed";

export const FRAMEWORK_VERDICT_LABEL: Record<FrameworkVerdict, string> = {
  pass: "Pass",
  fail: "Fail",
  partial: "Partial",
  not_assessed: "Not assessed",
};

export const FRAMEWORK_VERDICT_BADGE: Record<FrameworkVerdict, string> = {
  pass: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200",
  fail: "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200",
  partial: "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200",
  not_assessed: "bg-zinc-100 text-zinc-700 dark:bg-zinc-700/50 dark:text-zinc-200",
};

/** The tri-state engine's framework keys behind each mapping framework (frameworkLabels.ts names them). */
export const ENGINE_KEYS: Record<string, string[]> = {
  "CERT-In": ["cert_in_cbom"],
  RBI: ["rbi_free_ai_protection"],
  "SEBI CSCRF": ["sebi_cscrf_cbom"],
  NIST: ["nist_1800_38b", "nist_800_57", "nist_1800_38c", "fips_140_3"],
  "CNSA 2.0": ["cnsa_2_0"],
};

/** A count's drill-down: the findings table filtered to a clause's codes or a requirement's assets (bom-refs). */
export type DrillTarget =
  | { kind: "codes"; codes: string[]; label: string }
  | { kind: "refs"; refs: string[]; label: string };

export interface ClauseFix { label: string; fix: string }

export interface ClauseView {
  key: string;
  /** clause or requirement id ("SP 800-131A Rev. 2, Sec. 9 Table 8 (SHA-1)", "CNSA-2") */
  id: string;
  /** one plain-language line: the readable names of the findings behind it */
  summary: string;
  /** the regulation's text (collapsed by default), or the requirement's evidence line */
  quote: string | null;
  source: string | null;
  note: string | null;
  verdict: ComplianceVerdict;
  assets: number;
  drill: DrillTarget | null;
  fixes: ClauseFix[];
  origin: "kb" | "engine";
}

export type VerdictCounts = Record<ComplianceVerdict, number>;

export interface FrameworkSummary {
  framework: string;
  verdict: FrameworkVerdict;
  /** requirement verdicts of the engine frameworks behind it (all zero without engine data) */
  counts: VerdictCounts;
  requirements: number;
  /** the engine frameworks used, by label ("NIST SP 800-57", ...) */
  engineFrameworks: string[];
  /** KB clauses the findings touch */
  clausesTouched: number;
  /** distinct assets affected (null when the API cannot say) */
  assets: number | null;
  drill: DrillTarget | null;
  clauses: ClauseView[];
}

// ---------------------------------------------------------------------------- labels

/** Readable name of a finding code: the KB title when known, else the code in words ("SSH_DH_SHA1" -> "SSH DH SHA1").
 * The one label helper of the section: clause summaries, fixes and drill-down chips all go through it. */
export function codeLabel(code: string, titles?: Record<string, string> | null): string {
  const title = titles?.[code]?.trim();
  if (title && title !== code) return title;
  return code.replace(/_/g, " ").trim() || code;
}

/** code -> KB title from every place the page has one (clause findings, the posture's top codes). */
export function codeTitles(
  mapping: ComplianceRow[] | null | undefined,
  extra?: { code: string; title: string }[] | null,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const item of extra ?? []) if (item?.code && item.title) out[item.code] = item.title;
  for (const fw of mapping ?? []) {
    for (const c of fw.clauses) for (const f of c.findings ?? []) if (f.code && f.title) out[f.code] = f.title;
  }
  return out;
}

function joinLabels(labels: string[], max = 3): string {
  const uniq = [...new Set(labels.filter(Boolean))];
  if (uniq.length <= max) return uniq.join(", ");
  return `${uniq.slice(0, max).join(", ")} and ${uniq.length - max} more`;
}

// ---------------------------------------------------------------------------- verdicts

export function emptyCounts(): VerdictCounts {
  return Object.fromEntries(VERDICT_ORDER.map((v) => [v, 0])) as VerdictCounts;
}

function engineFrameworks(engine: Compliance | null | undefined, keys: string[]): { key: string; fw: FrameworkCoverage }[] {
  if (!engine) return [];
  return keys
    .map((key) => ({ key, fw: engine[key] }))
    .filter((x): x is { key: string; fw: FrameworkCoverage } => typeof x.fw === "object" && x.fw !== null);
}

/** The framework verdict: Pass = every assessed requirement passes and nothing is open; Fail = requirements fail and
 * none passes; Partial = some pass while others fail, need evidence, or findings touch its clauses; Not assessed =
 * nothing could be judged from the BOM (out of scope, N/A or no data). Without engine data, clauses touched by
 * findings are a Fail (the knowledge base says the findings breach them). */
export function frameworkVerdict(counts: VerdictCounts, opts: { hasEngine: boolean; clausesTouched: number }): FrameworkVerdict {
  const passed = counts.pass + counts.pass_with_evidence;
  const touched = opts.clausesTouched > 0;
  if (!opts.hasEngine || passed + counts.fail === 0) return touched ? "fail" : "not_assessed";
  if (counts.fail > 0 && passed === 0) return "fail";
  if (counts.fail > 0 || touched || counts.not_bom_evidenceable > 0) return "partial";
  return "pass";
}

// ---------------------------------------------------------------------------- build

const SAMPLE_FIXES = 3;

function kbClause(framework: string, c: ComplianceRow["clauses"][number], titles: Record<string, string>): ClauseView {
  const findings: CbomClauseFinding[] = c.findings?.length ? c.findings : c.codes.map((code) => ({ code, title: code, fix: null }));
  const labels = findings.map((f) => codeLabel(f.code, { ...titles, [f.code]: f.title }));
  const fixes: ClauseFix[] = [];
  for (const [i, f] of findings.entries()) if (f.fix && !fixes.some((x) => x.fix === f.fix)) fixes.push({ label: labels[i], fix: f.fix });
  return {
    key: `${framework}::${c.clause}`,
    id: c.clause,
    summary: joinLabels(labels),
    quote: c.title?.trim() || null,
    source: c.source ?? null,
    note: c.note ?? null,
    verdict: "fail",
    assets: c.assets,
    drill: c.codes.length && c.assets > 0 ? { kind: "codes", codes: [...c.codes], label: `${framework} · ${c.clause}` } : null,
    fixes,
    origin: "kb",
  };
}

type FixFinding = RelatedFindingFields & { suggested_fix?: string | null; algorithm_name?: string | null };

function engineClause(framework: string, key: string, r: ComplianceRequirement & { refs?: string[] },
                      findings: FixFinding[] | null | undefined, refAliases?: Record<string, string>): ClauseView {
  const refs = [...new Set(r.refs ?? [])];
  const matched = findings && refs.length ? filterFindingsByRelatedRefs(findings, refs, { aliases: refAliases }) : [];
  const fixes: ClauseFix[] = [];
  for (const f of matched) {
    const fix = (f.suggested_fix ?? "").trim();
    if (fix && !fixes.some((x) => x.fix === fix)) fixes.push({ label: (f.algorithm_name || f.title || "").trim() || "Finding", fix });
    if (fixes.length >= SAMPLE_FIXES) break;
  }
  return {
    key: `${framework}::${key}::${r.id}`,
    id: r.id,
    summary: r.title,
    quote: r.evidence?.trim() || null,
    source: r.source ?? null,
    note: null,
    verdict: r.verdict,
    assets: refs.length,
    drill: refs.length ? { kind: "refs", refs, label: `${framework} · ${r.id}` } : null,
    fixes,
    origin: "engine",
  };
}

const isOpen = (v: ComplianceVerdict) => v === "fail" || v === "not_bom_evidenceable";

/**
 * Per-framework summary rows, in the mapping's order (CERT-In, RBI, SEBI CSCRF, NIST, CNSA 2.0, then any other the
 * KB adds). A framework shows when the engine judged it or findings touch its clauses. Clause rows: the KB clauses
 * when the mapping has some for the framework; otherwise the engine's failing / needs-evidence requirements.
 */
export function buildComplianceSummary(input: {
  engine?: Compliance | null;
  mapping?: ComplianceRow[] | null;
  /** the code page's findings (fixes for engine requirements); a run passes none */
  findings?: FixFinding[] | null;
  refAliases?: Record<string, string>;
  titles?: Record<string, string>;
}): FrameworkSummary[] {
  const mapping = input.mapping ?? [];
  const titles = { ...codeTitles(mapping), ...(input.titles ?? {}) };
  const names = [...FRAMEWORK_ORDER, ...mapping.map((m) => m.framework).filter((n) => !FRAMEWORK_ORDER.includes(n)).sort()];
  const out: FrameworkSummary[] = [];
  for (const name of [...new Set(names)]) {
    const row = mapping.find((m) => m.framework === name);
    const kbClauses = (row?.clauses ?? []).map((c) => kbClause(name, c, titles));
    const engine = engineFrameworks(input.engine, ENGINE_KEYS[name] ?? []);
    if (!engine.length && !kbClauses.length) continue;
    const counts = emptyCounts();
    for (const { fw } of engine) {
      for (const v of VERDICT_ORDER) counts[v] += Number((fw as unknown as Record<string, number | undefined>)[v] ?? 0) || 0;
    }
    const requirements = VERDICT_ORDER.reduce((n, v) => n + counts[v], 0);
    const engineRows = kbClauses.length ? [] : engine.flatMap(({ key, fw }) =>
      (fw.requirements ?? []).filter((r) => isOpen(r.verdict))
        .map((r) => engineClause(name, key, r as ComplianceRequirement & { refs?: string[] }, input.findings, input.refAliases)));
    const clauses = kbClauses.length ? kbClauses : engineRows;
    let assets: number | null;
    let drill: DrillTarget | null = null;
    if (kbClauses.length) {
      const codes = [...new Set(row!.clauses.flatMap((c) => c.codes))].sort();
      assets = typeof row?.assets === "number" ? row.assets : null;
      if (codes.length && assets !== 0) drill = { kind: "codes", codes, label: `${name} · every clause` };
    } else {
      const refs = [...new Set(engineRows.filter((c) => c.verdict === "fail").flatMap((c) => (c.drill?.kind === "refs" ? c.drill.refs : [])))];
      assets = refs.length;
      if (refs.length) drill = { kind: "refs", refs, label: `${name} · failing requirements` };
    }
    out.push({
      framework: name,
      verdict: frameworkVerdict(counts, { hasEngine: engine.length > 0, clausesTouched: kbClauses.length }),
      counts,
      requirements,
      engineFrameworks: engine.map((e) => labelFramework(e.key)),
      clausesTouched: kbClauses.length,
      assets,
      drill,
      clauses,
    });
  }
  return out;
}

/** Stacked-bar segments (verdict, count, percent of the framework's requirements), zero counts left out. */
export function verdictSegments(counts: VerdictCounts): { verdict: ComplianceVerdict; count: number; pct: number }[] {
  const total = VERDICT_ORDER.reduce((n, v) => n + counts[v], 0);
  if (!total) return [];
  return VERDICT_ORDER.filter((v) => counts[v] > 0).map((v) => ({ verdict: v, count: counts[v], pct: (counts[v] / total) * 100 }));
}

// ---------------------------------------------------------------------------- drill-down

/** The run's asset id from a bom-ref (`zs-asset-<id>`, PARITY.md S7), else null. */
export function runAssetId(ref: string): number | null {
  const m = /^zs-asset-(\d{1,10})$/.exec(ref.trim());
  if (!m) return null;
  const id = Number(m[1]);
  return id > 0 && id <= 2_147_483_647 ? id : null;
}

export const MAX_DRILL_IDS = 500; // backend run_assets.MAX_IDS
export const MAX_DRILL_CODES = 50; // backend run_assets.MAX_CODES

/** The run findings table filter a drill-down sets (all other filters cleared, the All view so the total equals the
 * clause count: the posture counts every collected asset with the code). `truncated` when a requirement names more
 * assets than one request may carry. */
export function runDrillFilters(target: DrillTarget): {
  patch: { codes?: string[]; asset_ids?: number[]; drill_label: string; view: "all"; page: 1;
           type: undefined; impact: undefined; quantum: undefined; q: undefined; source_id: undefined; status: undefined;
           pqc_group: undefined };
  truncated: boolean;
} {
  const cleared = { type: undefined, impact: undefined, quantum: undefined, q: undefined, source_id: undefined, status: undefined,
                    pqc_group: undefined } as const;
  if (target.kind === "codes") {
    const codes = target.codes.slice(0, MAX_DRILL_CODES);
    return { patch: { ...cleared, codes, asset_ids: undefined, drill_label: target.label, view: "all", page: 1 }, truncated: codes.length < target.codes.length };
  }
  const ids = [...new Set(target.refs.map(runAssetId).filter((x): x is number => x != null))];
  const kept = ids.slice(0, MAX_DRILL_IDS);
  return { patch: { ...cleared, codes: undefined, asset_ids: kept, drill_label: target.label, view: "all", page: 1 }, truncated: kept.length < ids.length };
}
