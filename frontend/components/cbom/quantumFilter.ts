/** The Quantum column and its filter on the CBOM results page, from one rule. */

export type QuantumFilter = "all" | "safe" | "broken" | "vulnerable";

export interface QuantumFields {
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

/** One decimal as Python's round(x, 1) (the backend's quantum_readiness_pct): nearest, an exact tie to even. A tie
 * needs x to end in .25 or .75 exactly (x = odd / 4); Math.round would give 6.3 for 1 of 16 where the PDF says 6.2. */
export function round1(x: number): number {
  if (Number.isInteger(x * 4) && !Number.isInteger(x * 2)) {
    const whole = Math.floor(x);
    return Number((whole + (x - whole === 0.25 ? 0.2 : 0.8)).toFixed(1));
  }
  return Number(x.toFixed(1)); // the exact value of x, rounded to nearest (no tie left)
}

/** The PQC readiness gauge and its legend count the rows by the Quantum column's rule: a row that is broken today
 * is judged and is NOT quantum-safe (MD5 and DES used to count as safe: a lab scan showed 77 %). Same rule and the
 * same rounding as the backend's cbom_metrics.CodeRowSummary (scan dashboard, scan list and PDF). */
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
  const readinessPct = judged ? round1((100 * safe) / judged) : null;
  return { safe, broken, vulnerable, judged, readinessPct };
}

/** The rows the readiness gauge counts: EVERY cryptographic asset of the scan, findings and clean inventory (an
 * ML-KEM-768 row with no finding is a quantum-safe asset), as the PDF and the scan list do (cbom_metrics over
 * scan_data.results). The GET scan's ``data`` is that row list; the findings table lists findings only, so passing
 * it made the page say 0 % where the PDF and the scan list said 10 % (lab UI r1 F3, scan #51). Falls back to the
 * findings when the scan carries no row list. */
export function inventoryRows(data: unknown, findings: QuantumFields[]): QuantumFields[] {
  if (Array.isArray(data)) {
    const rows = data.filter((r): r is QuantumFields => !!r && typeof r === "object" && !Array.isArray(r));
    if (rows.length > 0) return rows;
  }
  return findings;
}

/** The bars of a "Quantum readiness" chart (CBOM scan list and code results): the three verdicts the backend counts
 * (cbom_metrics.CodeRowSummary.quantum), so the chart, its (i) tip and the "Quantum ready" card agree. Broken today
 * (weak even without a quantum computer, e.g. MD5, DES) counts against readiness and gets its own bar. */
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
