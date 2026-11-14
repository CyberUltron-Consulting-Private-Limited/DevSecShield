/** The highest balance an admin sets: POST /admin/update refuses more (backend/routers/admin.py MAX_CREDIT_BALANCE). */
export const MAX_CREDIT_BALANCE = 1_000_000_000;

/**
 * The balance an admin types in Admin > Teams > Update Credits, as POST /admin/update takes it: a number from 0 to
 * MAX_CREDIT_BALANCE. Credits are fractional (prices are to the cent, a server is 0.2 credits, a scan chat message
 * 0.006), so "4984.79" is 4984.79, not 4984. Plain decimal notation only ("1e3", "1,000" and ".5" are refused, not
 * guessed). Returns null when the text is not such a balance.
 */
export function parseCreditBalance(text: string): number | null {
  const trimmed = text.trim();
  if (!/^\d+(\.\d+)?$/.test(trimmed)) return null;
  const value = Number(trimmed);
  return Number.isFinite(value) && value <= MAX_CREDIT_BALANCE ? value : null;
}

/**
 * A balance in plain decimals, for the Update Credits field and the Teams table: exactly the stored number (the text
 * reads back as itself), never with an exponent. String() writes 1e-7 and 1e+21, which parseCreditBalance refuses, so
 * Save without an edit failed on the team's own balance; toFixed would round it instead (PR #67 review).
 */
export function formatCreditBalance(value: number): string {
  const text = String(value); // the shortest decimals that read back as this number
  const match = /^(-?)(\d)(?:\.(\d+))?e([+-]\d+)$/.exec(text);
  if (!match) return text;
  const [, sign, lead, rest = "", exponent] = match;
  const digits = lead + rest;
  const point = 1 + Number(exponent); // where the decimal point goes in `digits`
  if (point <= 0) return `${sign}0.${"0".repeat(-point)}${digits}`;
  if (point >= digits.length) return sign + digits + "0".repeat(point - digits.length);
  return `${sign}${digits.slice(0, point)}.${digits.slice(point)}`;
}
