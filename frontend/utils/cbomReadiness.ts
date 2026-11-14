/**
 * The "Quantum readiness" card of the CBOM scan page and the CBOM scan list.
 *
 * The backend sends ``quantum_readiness_score: 0`` with ``quantum_readiness_judged: false`` when no asset has a quantum
 * verdict (only hashes, certificates, protocols ...): no verdict is not 0 %, so the card says "n/a" in a neutral colour,
 * as the scan PDF and the team roll-up print it. A response without the flag (older API) keeps the score.
 */
export interface ReadinessCard {
  quantum_readiness_score?: number | null
  quantum_readiness_judged?: boolean
}

export type ReadinessTone = "good" | "fair" | "poor" | "none"

export function readinessJudged(card: ReadinessCard): boolean {
  return card.quantum_readiness_judged !== false && typeof card.quantum_readiness_score === "number"
}

export function readinessText(card: ReadinessCard): string {
  return readinessJudged(card) ? `${card.quantum_readiness_score}%` : "n/a"
}

/** good >= 70 %, fair >= 40 %, poor below; none when nothing was judged. */
export function readinessTone(card: ReadinessCard): ReadinessTone {
  if (!readinessJudged(card)) return "none"
  const score = card.quantum_readiness_score as number
  return score >= 70 ? "good" : score >= 40 ? "fair" : "poor"
}

/** The bars of a "Quantum readiness" chart (CBOM scan list, code results and run results): the three verdicts the
 * backend counts (cbom_metrics.CodeRowSummary.quantum), so the chart, its (i) tip and the "Quantum ready" card agree.
 * Broken today (weak even without a quantum computer, e.g. MD5, DES) counts against readiness and gets its own bar.
 * It only formats counts the backend sent and never recounts rows, so the run page may use it (Rule P). */
export interface QuantumReadinessCounts {
  quantum_safe?: number | null;
  quantum_vulnerable?: number | null;
  broken_today?: number | null;
}

export function quantumReadinessBars(q: QuantumReadinessCounts | null | undefined): { name: string; count: number; fill: string }[] {
  if (!q) return [];
  return [
    { name: "Safe", count: Number(q.quantum_safe ?? 0), fill: "hsl(142 71% 45%)" },
    { name: "Vulnerable", count: Number(q.quantum_vulnerable ?? 0), fill: "hsl(0 72% 51%)" },
    { name: "Broken today", count: Number(q.broken_today ?? 0), fill: "hsl(25 95% 53%)" },
  ].filter((d) => d.count > 0);
}
