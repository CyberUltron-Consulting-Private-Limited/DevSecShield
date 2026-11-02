// Pure helpers for the crypto heat-map and the certificate-expiry calendar (no React). The family table mirrors
// backend/utilities/cbom_sources/heatmap.py (FAMILY_RULES) so node runs and code scans bucket algorithms alike.

export type HeatImpact = "Critical" | "High" | "Medium" | "Low" | "none";
export const IMPACT_ORDER: HeatImpact[] = ["Critical", "High", "Medium", "Low", "none"];

export interface HeatCell {
  row: string;
  column: string;
  count: number;
  worst: HeatImpact;
  by_impact: Record<string, number>;
}

export interface HeatData {
  rows: string[];
  columns: string[];
  cells: HeatCell[];
}

export const FAMILY_RULES: [string, string[]][] = [
  ["Post-quantum", ["mlkem", "ml-kem", "kyber", "mldsa", "ml-dsa", "dilithium", "slhdsa", "slh-dsa", "sphincs", "falcon",
    "frodo", "ntru", "hqc"]],
  ["EdDSA", ["ed25519", "ed448", "eddsa"]],
  ["RSA", ["rsa"]],
  ["Elliptic curve", ["ecdsa", "ecdh", "ecdhe", "ec", "secp", "prime256", "p256", "p384", "p521", "nistp", "x25519", "x448",
    "curve25519", "brainpool"]],
  ["Diffie-Hellman", ["dh", "dhe", "ffdhe", "modp", "diffie"]],
  ["DSA", ["dsa", "dss"]],
  ["AES", ["aes"]],
  ["ChaCha20", ["chacha", "chacha20"]],
  ["DES / 3DES", ["des", "3des", "tripledes", "desede", "cbc3"]],
  ["RC4", ["rc4", "arcfour"]],
  ["Blowfish", ["blowfish", "bf"]],
  ["MD5", ["md5"]],
  ["SHA-1", ["sha1"]],
  ["SHA-2 / SHA-3", ["sha2", "sha224", "sha256", "sha384", "sha512", "sha3"]],
  ["HMAC", ["hmac"]],
];
export const FAMILIES = [...FAMILY_RULES.map(([f]) => f), "Protocol (no key data)", "Library", "Other"];

function tokens(text: string): string[] {
  const raw = text.toLowerCase().replace(/[^a-z0-9-]+/g, " ").split(/\s+/).filter(Boolean);
  const out: string[] = [];
  for (const tok of raw) {
    out.push(tok, tok.replace(/-/g, ""), ...tok.split("-").filter(Boolean));
  }
  return out;
}

function match(text: string): string | null {
  const toks = tokens(text);
  for (const [family, words] of FAMILY_RULES) {
    for (const word of words) {
      const w = word.replace(/-/g, "");
      if (toks.some((t) => (w.length <= 3 ? t === w : t.includes(w)) || (w === "rsa" && t.includes("rsa")))) return family;
    }
  }
  return null;
}

/** First text that names a family wins; otherwise libraries and protocols get their own bucket. */
export function algorithmFamily(texts: (string | null | undefined)[], assetType?: string | null): string {
  for (const text of texts) {
    if (text) {
      const found = match(String(text));
      if (found) return found;
    }
  }
  const t = (assetType || "").toLowerCase();
  if (t.includes("library")) return "Library";
  if (t === "protocol" || t.endsWith("_tls") || t.includes("endpoint") || t.includes("ssh")) return "Protocol (no key data)";
  return "Other";
}

export function worse(a: HeatImpact, b: HeatImpact): HeatImpact {
  return IMPACT_ORDER.indexOf(a) <= IMPACT_ORDER.indexOf(b) ? a : b;
}

export interface CodeHeatRow {
  title?: string | null;
  algorithm_name?: string | null;
  asset_type?: string | null;
  algorithm_type?: string | null;
  impact?: string | null;
  finding_codes?: string[] | null;
  weak?: boolean | null;
  quantum_vulnerable?: boolean | null;
}

/** Mirrors cbom_rows.is_finding: legacy rows (no finding_codes) are findings; clean inventory is not. */
export function isFindingRow(row: CodeHeatRow): boolean {
  if (!("finding_codes" in row) || row.finding_codes === undefined) return true;
  if ((row.finding_codes || []).some((c) => !!c)) return true;
  return row.weak === true || row.quantum_vulnerable === true;
}

/** Algorithm family x asset type for a code scan, counted by worst impact (inventory counts as "none"). */
export function codeHeatmap(rows: CodeHeatRow[]): HeatData {
  const cells = new Map<string, HeatCell>();
  const colCount = new Map<string, number>();
  for (const row of rows) {
    const column = String(row.asset_type || row.algorithm_type || "other");
    const family = algorithmFamily([row.algorithm_name, row.title], column);
    const impact = (isFindingRow(row) ? (IMPACT_ORDER.includes(row.impact as HeatImpact) ? row.impact : "Low") : "none") as HeatImpact;
    const key = `${family}\u0000${column}`;
    const cell = cells.get(key) ?? { row: family, column, count: 0, worst: "none" as HeatImpact,
      by_impact: { Critical: 0, High: 0, Medium: 0, Low: 0, none: 0 } };
    cell.count += 1;
    cell.by_impact[impact] = (cell.by_impact[impact] ?? 0) + 1;
    cell.worst = worse(cell.worst, impact);
    cells.set(key, cell);
    colCount.set(column, (colCount.get(column) ?? 0) + 1);
  }
  const used = new Set([...cells.values()].map((c) => c.row));
  return {
    rows: FAMILIES.filter((f) => used.has(f)),
    columns: [...colCount.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([c]) => c),
    cells: [...cells.values()],
  };
}

// ----------------------------------------------------------------------------- calendar
export type ExpiryBand = "expired" | "30" | "60" | "90" | "later";

export function expiryBand(daysLeft: number): ExpiryBand {
  if (daysLeft < 0) return "expired";
  if (daysLeft <= 30) return "30";
  if (daysLeft <= 60) return "60";
  if (daysLeft <= 90) return "90";
  return "later";
}

/** "YYYY-MM-DD" of a date in UTC (certificate dates are UTC). */
export function dayKey(d: Date): string {
  return d.toISOString().slice(0, 10);
}

export function parseExpiry(value: string | null | undefined): Date | null {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function daysLeft(expiry: Date, now: Date): number {
  return Math.floor((expiry.getTime() - now.getTime()) / 86_400_000);
}

/** Monday-first weeks of a month (UTC): 4 to 6 rows of 7 cells, null outside the month. */
export function monthGrid(year: number, month: number): (Date | null)[][] {
  const first = new Date(Date.UTC(year, month, 1));
  const days = new Date(Date.UTC(year, month + 1, 0)).getUTCDate();
  const lead = (first.getUTCDay() + 6) % 7;
  const cells: (Date | null)[] = Array.from({ length: lead }, () => null);
  for (let d = 1; d <= days; d++) cells.push(new Date(Date.UTC(year, month, d)));
  while (cells.length % 7) cells.push(null);
  const weeks: (Date | null)[][] = [];
  for (let i = 0; i < cells.length; i += 7) weeks.push(cells.slice(i, i + 7));
  return weeks;
}

export function groupByDay<T extends { not_after: string | null }>(certs: T[]): Map<string, T[]> {
  const out = new Map<string, T[]>();
  for (const cert of certs) {
    const d = parseExpiry(cert.not_after);
    if (!d) continue;
    const key = dayKey(d);
    out.set(key, [...(out.get(key) ?? []), cert]);
  }
  return out;
}
