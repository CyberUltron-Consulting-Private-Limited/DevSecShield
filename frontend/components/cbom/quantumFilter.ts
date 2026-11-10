/** The Quantum column and its filter on the CBOM results page, from one rule. */

export type QuantumFilter = "all" | "safe" | "broken" | "vulnerable";

interface QuantumFields {
  quantum_safe?: boolean | null;
  crypto_strength?: string | null;
}

/** Not broken by a quantum computer but already broken without one (MD5, SHA-1, DES, RC4, ECB ...): the column says
 * "Broken today", never "Safe". */
export function isBrokenToday(f: QuantumFields): boolean {
  return f.quantum_safe === true && String(f.crypto_strength ?? "").toLowerCase() === "weak";
}

/** "Quantum-Safe" lists only the rows the column calls Safe; the rows it calls "Broken today" have their own option
 * (they were listed under Quantum-Safe: lab UI run u2, round 5). */
export function matchesQuantumFilter(f: QuantumFields, filter: string): boolean {
  if (filter === "safe") return f.quantum_safe === true && !isBrokenToday(f);
  if (filter === "broken") return isBrokenToday(f);
  if (filter === "vulnerable") return f.quantum_safe === false;
  return true;
}

export interface QuantumCounts {
  safe: number;
  broken: number;
  vulnerable: number;
  /** rows with a quantum verdict: safe + broken + vulnerable */
  judged: number;
  /** quantum-safe share of the judged rows (one decimal); null when nothing was judged */
  readinessPct: number | null;
}

/** The PQC readiness gauge and its legend count the rows by the Quantum column's rule: a row that is broken today
 * is judged and is NOT quantum-safe (MD5 and DES used to count as safe: a lab scan showed 77 %). Same rule as the
 * backend's cbom_metrics.CodeRowSummary (scan card and PDF). */
export function quantumCounts(rows: QuantumFields[]): QuantumCounts {
  let safe = 0;
  let broken = 0;
  let vulnerable = 0;
  for (const r of rows) {
    if (isBrokenToday(r)) broken += 1;
    else if (r.quantum_safe === true) safe += 1;
    else if (r.quantum_safe === false) vulnerable += 1;
  }
  const judged = safe + broken + vulnerable;
  const readinessPct = judged ? Math.round((1000 * safe) / judged) / 10 : null;
  return { safe, broken, vulnerable, judged, readinessPct };
}
