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
