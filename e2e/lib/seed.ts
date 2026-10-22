/**
 * Typed view of seed.json (written by e2e/seed/seed_team.py) and helpers over it.
 *
 * seed.json is an INPUT of the specs, not a product output: it records which scans were stored, with
 * which ids and dates, and the throw-away credentials of the three personas. The specs derive every
 * date-relative expectation (first/last seen, ages, data window) from the `created_at` values in here.
 */
import * as fs from 'node:fs';

import { SEED_JSON } from './paths';

export type Persona = 'admin' | 'other' | 'empty';

export interface SeedUser {
  id: number;
  email: string;
  password: string;
  otp: string;
  otp_permanent: boolean;
  default_team_id: number;
  team_ids: number[];
}

export interface SeedScan {
  id: number;
  team_id: number;
  scan_type: string;
  title: string;
  status: string;
  age_days: number;
  created_at: string;
  last_updated: string;
  repo_url: string | null;
  findings: number;
}

export interface SeedJson {
  schema: number;
  seeded_at: string;
  as_of: string;
  teams: Record<'demo' | 'other' | 'empty' | 'perf', { id: number; name: string } | undefined>;
  users: Record<Persona, SeedUser>;
  scans: Record<string, SeedScan>;
  demo_scan_ids: number[];
  trees: Record<string, { rows: number; certificates: number; libraries: number; sha256: string }>;
  oracle: { checked: boolean; cert_unique: number };
  perf: {
    team_id: number;
    scans: number;
    sources: number;
    versions: number;
    first_scan_id: number;
    last_scan_id: number;
    unique_certs_total: number;
    current_unique_certs: number;
  } | null;
}

let cached: SeedJson | undefined;

export function loadSeed(file: string = SEED_JSON): SeedJson {
  if (file === SEED_JSON && cached) return cached;
  if (!fs.existsSync(file)) {
    throw new Error(`seed.json not found at ${file}: run e2e/scripts/seed.sh first`);
  }
  const seed = JSON.parse(fs.readFileSync(file, 'utf8')) as SeedJson;
  if (seed.schema !== 1) throw new Error(`unsupported seed.json schema ${seed.schema}`);
  if (file === SEED_JSON) cached = seed;
  return seed;
}

/** `YYYY-MM-DD` (UTC) of the moment a scan was created. */
export function scanDate(seed: SeedJson, id: number): string {
  const scan = seed.scans[String(id)];
  if (!scan) throw new Error(`scan #${id} is not in seed.json`);
  return scan.created_at.slice(0, 10);
}

/** Whole days between two `YYYY-MM-DD` dates (later minus earlier). */
export function daysBetween(earlier: string, later: string): number {
  const a = Date.UTC(+earlier.slice(0, 4), +earlier.slice(5, 7) - 1, +earlier.slice(8, 10));
  const b = Date.UTC(+later.slice(0, 4), +later.slice(5, 7) - 1, +later.slice(8, 10));
  return Math.round((b - a) / 86_400_000);
}
