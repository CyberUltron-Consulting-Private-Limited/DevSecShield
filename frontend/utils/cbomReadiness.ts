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
