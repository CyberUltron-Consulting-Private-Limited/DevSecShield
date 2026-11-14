// Crypto-agility baseline of the team's current estate (CB-25 PR-A): GET /{team}/cbom/agility (enterprise counts and
// the per-system table) and GET /{team}/cbom/agility/subjects (drill-down), both keyset-paged with an opaque `next`.
// Pure: types, the mapping onto the run posture card's shape (AgilityPostureCard is reused as is) and the sum check.
import { FIX_VALUES, type AgilityPosture, type AgilitySystem } from "./model";

export interface BaselineSystem extends AgilitySystem {
  counts_excl_pq?: Partial<Record<string, number>>;
  self_fixable_pct_excl_pq?: number | null;
  unknown?: number;
}

export interface AgilityBaseline {
  as_of: string;
  scope: string;
  model?: string;
  agility_version?: string;
  assets: number;
  counts: Partial<Record<string, number>>;
  counts_excl_pq: Partial<Record<string, number>>;
  self_fixable_pct: number | null;
  self_fixable_pct_excl_pq?: number | null;
  hardest?: string | null;
  unknown_reasons?: Record<string, number>;
  not_assessed?: number;
  dedupe?: { method: string; key_version?: string; observations: number; merged: number; not_correlated: number };
  inputs?: { collections?: number; code_scans?: number; evidence_items?: number };
  systems_total: number;
  systems: { items: BaselineSystem[]; next: string | null; matched: number };
}

export interface AgilitySubject {
  key: string;
  name: string;
  type: string;
  location: string;
  origin: string;
  fix_class: string;
  fix_class_floor: string | null;
  fix_class_excl_pq: string;
  deciding_codes: string[];
  unknown_reasons?: string[];
  observations: number;
  sources: string[];
  system: { key: string; label: string; kind: string };
}

export interface AgilitySubjectsPage {
  as_of: string;
  view: "all" | "excl_pq";
  fix_class: string | null;
  system: string | null;
  total: number;
  next: string | null;
  items: AgilitySubject[];
}

export const SYSTEM_KIND_LABEL: Record<string, string> = {
  application: "application",
  source: "source",
  repository: "repository",
  evidence: "evidence",
};

/** The enterprise baseline in the run posture's shape, so `AgilityPostureCard` renders it (its own systems table is
 * left empty: the baseline section lists the systems with a drill-down). */
export function baselinePosture(b: AgilityBaseline): AgilityPosture {
  return {
    assets: b.assets,
    fix_classes: b.counts,
    fix_classes_excl_pq: b.counts_excl_pq,
    fix_class_self_fixable_pct: b.self_fixable_pct,
    unknown_reasons: b.unknown_reasons ?? {},
    fix_class_systems: [],
    fix_class_systems_truncated: false,
    agility_version: b.agility_version,
  };
}

/** The dedupe sentence: how many observations became how many assets. */
export function dedupeText(b: AgilityBaseline): string | null {
  const d = b.dedupe;
  if (!d || !d.observations) return null;
  const parts = [`${d.observations} observation${d.observations === 1 ? "" : "s"} counted as ${b.assets} asset${b.assets === 1 ? "" : "s"}`];
  if (d.merged > 0) parts.push(`${d.merged} seen again by another source or a code scan (one certificate, endpoint or cloud resource counts once, with its hardest class)`);
  if (d.not_correlated > 0) parts.push(`${d.not_correlated} certificate${d.not_correlated === 1 ? "" : "s"} with nothing identifying counted within their own source`);
  return parts.join("; ") + ".";
}

/** True when the listed systems add up to the enterprise counts (only checkable when every system is listed). */
export function systemsAddUp(b: AgilityBaseline): boolean | null {
  if (b.systems.next || b.systems.items.length !== b.systems_total) return null;
  return FIX_VALUES.every((v) => b.systems.items.reduce((n, s) => n + (Number(s.counts[v]) || 0), 0) === (Number(b.counts[v]) || 0));
}

export const baselineKeys = {
  baseline: (teamId: number) => ["cbom-sources", teamId, "agility-baseline"] as const,
  subjects: (teamId: number, params: { fixClass: string | null; system: string | null; view: string }) =>
    ["cbom-sources", teamId, "agility-subjects", params.fixClass ?? "", params.system ?? "", params.view] as const,
};
