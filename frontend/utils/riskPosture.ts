/**
 * One risk score for every product (SBOM, DAST, SAST, LLM, AI BOM, CBOM): the 0-100 posture score, its grade and
 * words, as the backend sends it (`risk_posture`, backend/utilities/dashboard/risk_scale.py `posture`, which runs the
 * engine's aibom/src/aibom/score/posture.py). Lists, tiles, filters and the results pages read it from here, so a scan
 * reads the same "56 · D" everywhere, and in its PDF headline.
 *
 * score = min(100, 4 x (10 critical + 5 high + 2 medium + 1 low)), capped by the worst severity present.
 * Grades: A < 15 "Low risk", B 15-29 "Moderate risk", C 30-49 "Elevated risk", D 50-69 "High risk",
 * F 70 or more "Critical risk" (riskPosture.test.ts reads the engine's table and checks these).
 */

export type RiskGrade = "A" | "B" | "C" | "D" | "F";

export interface RiskPosture {
  score: number;
  grade: string;
  label: string;
  band?: string;
}

/** The engine's POSTURE_GRADES, highest first: (lowest score of the grade, grade, band word). */
export const RISK_GRADES: readonly { floor: number; grade: RiskGrade; band: string; label: string }[] = [
  { floor: 70, grade: "F", band: "critical", label: "Critical risk" },
  { floor: 50, grade: "D", band: "high", label: "High risk" },
  { floor: 30, grade: "C", band: "elevated", label: "Elevated risk" },
  { floor: 15, grade: "B", band: "moderate", label: "Moderate risk" },
  { floor: 0, grade: "A", band: "low", label: "Low risk" },
];

/** The grade, band and words of a 0-100 score. */
export function gradeOf(score: number): { grade: RiskGrade; band: string; label: string } {
  const g = RISK_GRADES.find((r) => score >= r.floor) ?? RISK_GRADES[RISK_GRADES.length - 1];
  return { grade: g.grade, band: g.band, label: g.label };
}

/** The Risk score filter of the scan lists. Tiers sit on the grade bands. */
export type RiskTier = "all" | "critical" | "high" | "medium" | "low";

export const RISK_TIER_LABELS: Record<Exclude<RiskTier, "all">, string> = {
  critical: "Critical (F, ≥70)",
  high: "High (D, 50–69)",
  medium: "Medium (B–C, 15–49)",
  low: "Low (A, <15)",
};

/** Critical = F (>= 70), High = D (50-69), Medium = C and B (15-49), Low = A (< 15); no score matches only "all". */
export function matchesRiskTier(score: number | null, tier: RiskTier): boolean {
  if (tier === "all") return true;
  if (score == null) return false;
  if (tier === "critical") return score >= 70;
  if (tier === "high") return score >= 50 && score < 70;
  if (tier === "medium") return score >= 15 && score < 50;
  return score < 15;
}

type MaybePosture = {
  risk_posture?: RiskPosture | null;
  risk_score?: unknown;
  risk_grade?: unknown;
  risk_label?: unknown;
} | null | undefined;

const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

/**
 * The posture of a list row, a dashboard card or a results card: its `risk_posture`, else the flat `risk_score` +
 * `risk_grade` the CBOM rows carry (PR #500). A `risk_score` without a grade is some older number (the SAST list's
 * weighted sum, the LLM card's 0-10 average) and is never read as the posture. null: no score (an older backend, a
 * scan that did not succeed); the page shows "—".
 */
export function postureOf(item: MaybePosture): RiskPosture | null {
  if (!item) return null;
  const p = item.risk_posture;
  if (p && isNum(p.score)) {
    const score = Math.round(Math.min(100, Math.max(0, p.score)));
    const g = gradeOf(score);
    return { score, grade: p.grade || g.grade, label: p.label || g.label, band: p.band || g.band };
  }
  if (isNum(item.risk_score) && typeof item.risk_grade === "string" && item.risk_grade) {
    const score = Math.round(Math.min(100, Math.max(0, item.risk_score)));
    const g = gradeOf(score);
    return { score, grade: item.risk_grade, label: typeof item.risk_label === "string" && item.risk_label ? item.risk_label : g.label, band: g.band };
  }
  return null;
}

/** The 0-100 score the lists filter and sort by; null without one. */
export function postureScore(item: MaybePosture): number | null {
  return postureOf(item)?.score ?? null;
}

/** "56 · D" for a table cell or a tile; "—" without a score. */
export function riskScoreText(p: RiskPosture | null): string {
  return p ? `${p.score} · ${p.grade}` : "—";
}

/** "of 100 · High risk" under a tile's number; null without a score. */
export function riskScoreHint(p: RiskPosture | null): string | null {
  return p ? `of 100 · ${p.label}` : null;
}

/** Tile tones: red from D (50), amber from C (30), green below (the CBOM tile's tones). */
export function riskTone(score: number | null | undefined): { box: string; icon: string; fill: string } {
  const s = score ?? 0;
  if (s >= 50) return { box: "bg-red-500/15 dark:bg-red-500/10", icon: "text-red-500", fill: "#dc2626" };
  if (s >= 30) return { box: "bg-amber-500/15 dark:bg-amber-500/10", icon: "text-amber-500", fill: "#ea580c" };
  return { box: "bg-green-500/15 dark:bg-green-500/10", icon: "text-green-500", fill: "#22c55e" };
}
