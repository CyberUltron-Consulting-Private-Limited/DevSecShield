/** "Critical issues fixed": fixed Critical findings as a whole percent of all Critical findings (fixed ones included). */
export function criticalFixedPct(fixed: number, allCritical: number): number {
  if (!(allCritical > 0)) return 0;
  return Math.max(0, Math.min(100, Math.round((fixed / allCritical) * 100)));
}
