// Issue #271: plain-words explanations for the run results page: what "PQC readiness N%" rests on and what would raise
// it, what a NIST quantum security level means, and what each remediation wave holds.
//
// Rule P (CB-38 PLAN 2.5): every number here is read from the API (posture.readiness_basis, posture.pqc_classes,
// posture.readiness_actions / readiness_excluded, the wave plan's by_wave). Nothing is recounted and no readiness is
// computed in the browser; the text only names and arranges those figures.

import type { CbomReadinessAction, CbomReadinessBasis, CbomReadinessExcluded } from "@/utils/backend_api";

import type { RunTableFilters } from "./model";

export interface ReadinessPostureLike {
  pqc_readiness_pct: number | null;
  pqc_classes?: Partial<Record<string, number>>;
  readiness_basis?: CbomReadinessBasis;
  readiness_actions?: CbomReadinessAction[];
  readiness_excluded?: CbomReadinessExcluded[];
}

export interface ReadinessAction {
  key: string;
  /** "Fix 12 TLS endpoints: No post-quantum key exchange" */
  text: string;
  fix: string | null;
  assets: number;
  assetType: string;
  /** the group's key for the findings table's ``pqc_group`` filter: its quantum finding code, "none" without one */
  pqcGroup: string;
  /** "Readiness 0% -> 26.1%" when the API gave the readiness after the fix */
  effect: string | null;
}

export interface ReadinessExplanation {
  /** false: the run judged nothing (or the API is older and sent no basis): only the definition is shown */
  hasBasis: boolean;
  value: string;
  /** "Ready judged assets ÷ judged assets = 0 ÷ 46 = 0%" */
  formula: string;
  judged: string;
  counts: string[];
  excluded: string[];
  symmetric: string;
  target: string;
  actions: ReadinessAction[];
  /** the number of quantum-vulnerable assets the "show them" link filters the table to (posture's class count) */
  vulnerable: number;
}

const n = (v: number | undefined | null) => (typeof v === "number" && Number.isFinite(v) ? v : 0);

export function plural(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}

/** "TLS endpoint" -> "TLS endpoints"; labels ending in "s" or "y" read naturally enough with a plain "s" rule tweak. */
export function pluralLabel(count: number, label: string): string {
  if (count === 1) return `1 ${label}`;
  if (/[^aeiou]y$/i.test(label)) return `${count} ${label.slice(0, -1)}ies`;
  if (/(s|x|sh|ch)$/i.test(label)) return `${count} ${label}es`;
  return `${count} ${label}s`;
}

const pct = (v: number | null | undefined) => (v == null ? "n/a" : `${v}%`);

/** What the PQC readiness figure means for this run, in plain words. */
export function readinessExplanation(p: ReadinessPostureLike | null | undefined): ReadinessExplanation {
  const b = p?.readiness_basis;
  const classes = p?.pqc_classes ?? {};
  const vulnerable = n(classes["quantum-vulnerable"]);
  const symmetric =
    "Symmetric cryptography (AES-256, ChaCha20) and hashes are not broken by a quantum computer, so an asset whose verdict is " +
    "symmetric counts as quantum-safe and raises the score; a 128-bit key (AES-128) counts too, as Grover-weakened. " +
    "A TLS or SSH endpoint is judged on its key exchange, not on its AES bulk cipher: an endpoint that encrypts with " +
    "AES-256 but agrees its keys with RSA, elliptic curves or Diffie-Hellman is quantum-vulnerable. " +
    "Settings with no algorithm to judge (e.g. a password-hash setting) are left out of both numbers.";
  const target =
    "Higher is better: 100% means every judged asset already resists a quantum computer. NIST plans to deprecate " +
    "quantum-vulnerable public-key cryptography after 2030 and disallow it after 2035.";
  const actions = (p?.readiness_actions ?? []).map((a, i) => ({
    key: `${a.asset_type}|${a.code ?? ""}|${i}`,
    text: `Fix ${pluralLabel(a.assets, a.type_label)}: ${a.title}`,
    fix: a.fix,
    assets: a.assets,
    assetType: a.asset_type,
    pqcGroup: a.code ?? "none",
    effect: a.readiness_after == null || p?.pqc_readiness_pct == null
      ? null
      : `Readiness ${pct(p.pqc_readiness_pct)} → ${pct(a.readiness_after)}`,
  }));
  if (!b) {
    return {
      hasBasis: false, value: pct(p?.pqc_readiness_pct), formula: "Ready judged assets ÷ judged assets",
      judged: "", counts: [], excluded: [], symmetric, target, actions, vulnerable,
    };
  }
  const value = b.status === "not_enough_identified" ? "Not enough identified" : pct(p?.pqc_readiness_pct);
  const formula = b.status === "ok"
    ? `Ready judged assets ÷ judged assets = ${b.ready} ÷ ${b.judged} = ${pct(p?.pqc_readiness_pct)}`
    : "Ready judged assets ÷ judged assets";
  const judged =
    `"Judged" means the scan identified the asset's cryptography and gave it a quantum verdict: quantum-vulnerable, ` +
    `hybrid (a post-quantum key exchange next to the classical one), quantum-safe (post-quantum or symmetric) or ` +
    `Grover-weakened (128-bit symmetric). This run judged ${plural(b.judged, "asset")}.`;
  const counts = [
    `${b.ready} quantum-safe, hybrid or Grover-weakened (count as ready)`,
    `${vulnerable} quantum-vulnerable (count against)`,
  ];
  const excluded = (p?.readiness_excluded ?? []).map((e) =>
    `${plural(e.assets, "asset")} left out, ${e.class === "unknown" ? "not identified" : "no quantum verdict"}: ${e.text}`);
  if (excluded.length === 0 && b.unknown + b.not_applicable > 0) {
    excluded.push(`${plural(b.unknown + b.not_applicable, "asset")} left out: ${b.unknown} not identified, ${b.not_applicable} with no public-key algorithm`);
  }
  if (b.status === "not_enough_identified") {
    excluded.unshift(`The percentage is withheld: more assets are unidentified (${b.unknown}) than judged (${b.judged}).`);
  }
  if (b.status === "nothing_judged") {
    excluded.unshift("No asset of this run has a quantum verdict, so there is no percentage (not 0%, not 100%).");
  }
  return { hasBasis: true, value, formula, judged, counts, excluded, symmetric, target, actions, vulnerable };
}

/** The findings-table filter behind "Show these N" (one readiness group: its asset type and quantum finding code) or,
 * without an action, "Show the N quantum-vulnerable assets". The server judges the group with posture's own class and
 * group functions (``pqc_group``), so the table lists exactly the N rows the card counts; every other filter is
 * cleared so it cannot narrow the list. ``quantum: true`` keeps an older server (no ``pqc_group``) on the vulnerable
 * assets. */
export function readinessDrillFilters(action?: Pick<ReadinessAction, "assetType" | "pqcGroup" | "text"> | null): Partial<RunTableFilters> {
  return {
    view: "all", quantum: true, type: action?.assetType, pqc_group: action?.pqcGroup ?? "any",
    drill_label: action ? action.text : "every quantum-vulnerable asset",
    impact: undefined, q: undefined, source_id: undefined, status: undefined, codes: undefined, asset_ids: undefined,
    page: 1,
  };
}

// ------------------------------------------------------------------------------------------------- NIST levels

export interface NistLevelInfo {
  /** "Level 0: no quantum resistance" */
  name: string;
  /** one line: what the level means */
  meaning: string;
  /** what the next level needs ("" at the top level) */
  next: string;
}

const LEVELS: Record<number, [string, string]> = {
  0: ["no quantum resistance", "A large quantum computer running Shor's algorithm breaks it, whatever the key size (RSA, elliptic curves, Diffie-Hellman)."],
  1: ["as hard as AES-128 key search", "Breaking it takes at least the effort of an exhaustive AES-128 key search."],
  2: ["as hard as a SHA-256 collision", "Breaking it takes at least the effort of finding a SHA-256 collision."],
  3: ["as hard as AES-192 key search", "Breaking it takes at least the effort of an exhaustive AES-192 key search."],
  4: ["as hard as a SHA-384 collision", "Breaking it takes at least the effort of finding a SHA-384 collision."],
  5: ["as hard as AES-256 key search", "Breaking it takes at least the effort of an exhaustive AES-256 key search (the highest NIST category)."],
};

/** The NIST post-quantum security category (FIPS 203/204/205 "security category") behind a "Level N" badge. */
export function nistLevelInfo(level: number | null | undefined): NistLevelInfo {
  const l = typeof level === "number" && Number.isInteger(level) && level >= 0 && level <= 5 ? level : 0;
  const [short, meaning] = LEVELS[l];
  const next = l === 0
    ? "Level 1 needs a NIST post-quantum algorithm (FIPS 203 key exchange, FIPS 204 or 205 signature) at least as hard to break as AES-128; a hybrid key exchange counts as ready."
    : l < 5 ? `Level ${l + 1}: ${LEVELS[l + 1][0]} (a larger parameter set).` : "";
  return { name: `Level ${l}: ${short}`, meaning, next };
}

// ------------------------------------------------------------------------------------------- remediation waves

export interface WaveLegendRow {
  key: string;
  label: string;
  rule: string;
  count: number;
  /** why the wave has no asset in this run ("" when it has some) */
  empty: string;
}

// An older backend sends no ``rules``: the same words as waves.py WAVE_RULE (test_cbom_readiness_explained.py
// test_frontend_fallback_wave_text_is_the_backend_rules keeps the two equal).
const WAVE_FALLBACK: Record<string, string> = {
  "1": "Urgent: a Critical or High weakness on an internet-facing or in-transit (HNDL) asset, or any quantum-vulnerable key exchange in transit (harvest now, decrypt later: traffic recorded today can be decrypted later)",
  "2": "Any other Critical or High weakness",
  "3": "Any other weakness, whatever its impact (Medium, Low, Info or none recorded)",
  "4": "A quantum-vulnerable asset with no other weakness: plan its post-quantum migration",
  none: "No weakness and not quantum-vulnerable: nothing to remediate",
};

/** One legend row per wave (1-4, then "No action"), with this run's count from the wave plan and why a wave is empty.
 * The rule text is the backend's (``rules``, the suggested_wave rule set); an older backend gets the same words. */
export function waveLegend(byWave: Record<string, number> | null | undefined,
                           rules?: Record<string, string> | null): WaveLegendRow[] {
  return ["1", "2", "3", "4", "none"].map((key) => {
    const count = n(byWave?.[key]);
    const rule = rules?.[key] ?? WAVE_FALLBACK[key];
    return {
      key, count, rule,
      label: key === "none" ? "No action" : `Wave ${key}`,
      empty: count > 0 ? "" : key === "none"
        ? "Every asset of this run needs some remediation."
        : "No asset of this run matches this rule (and none was moved here by hand), so the wave is empty.",
    };
  });
}
