/**
 * The balance an admin types in Admin > Teams > Update Credits, as POST /admin/update takes it: any finite number of 0
 * or more. Credits are fractional (prices are to the cent, a server is 0.2 credits, a scan chat message 0.006), so
 * "4984.79" is 4984.79, not 4984. Plain decimal notation only ("1e3", "1,000" and ".5" are refused, not guessed).
 * Returns null when the text is not such a balance.
 */
export function parseCreditBalance(text: string): number | null {
  const trimmed = text.trim();
  if (!/^\d+(\.\d+)?$/.test(trimmed)) return null;
  const value = Number(trimmed);
  return Number.isFinite(value) ? value : null;
}
