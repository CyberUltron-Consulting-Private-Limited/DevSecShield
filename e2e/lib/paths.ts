/**
 * Paths and endpoints shared by the fixtures, the evidence helpers and the specs.
 *
 * Everything is environment driven so one set of specs serves the real stack (scripts/run-specs.sh
 * exports all of these) and the offline selftest (selftest/oracle.spec.ts):
 *
 *   E2E_EVIDENCE_DIR  where videos / screenshots / downloads / logs / pdf-pages go
 *   E2E_WORK_DIR      e2e/.work (trees, scan outputs, seed.json, token cache)
 *   E2E_SEED_JSON     seed.json written by seed_team.py
 *   E2E_BASE_URL      frontend  (default http://127.0.0.1:43000)
 *   E2E_API_URL       backend   (default http://127.0.0.1:43080)
 */
import * as fs from 'node:fs';
import * as path from 'node:path';

export const E2E_ROOT = path.resolve(__dirname, '..');
export const WORK_DIR = process.env.E2E_WORK_DIR ?? path.join(E2E_ROOT, '.work');
export const EVIDENCE_DIR = process.env.E2E_EVIDENCE_DIR ?? path.join(WORK_DIR, 'evidence');
export const SEED_JSON = process.env.E2E_SEED_JSON ?? path.join(WORK_DIR, 'seed.json');
export const EXPECTED_JSON = path.join(E2E_ROOT, 'fixtures', 'expected.json');
export const TREES_DIR = path.join(WORK_DIR, 'trees');

export const BASE_URL = (process.env.E2E_BASE_URL ?? 'http://127.0.0.1:43000').replace(/\/$/, '');
export const API_URL = (process.env.E2E_API_URL ?? 'http://127.0.0.1:43080').replace(/\/$/, '');

/** The only two origins a browser in these specs may talk to. */
export const ALLOWED_ORIGINS: readonly string[] = [new URL(BASE_URL).origin, new URL(API_URL).origin];

export type EvidenceKind = 'videos' | 'screenshots' | 'downloads' | 'pdf-pages' | 'logs' | 'reports';

export function evidencePath(kind: EvidenceKind, name: string): string {
  const dir = path.join(EVIDENCE_DIR, kind);
  fs.mkdirSync(dir, { recursive: true });
  return path.join(dir, name);
}

/** `07-certificate-estate-register` for specs/07-certificate-estate-register.spec.ts. */
export function specBaseName(specFile: string): string {
  return path.basename(specFile).replace(/\.spec\.[cm]?[jt]sx?$/, '');
}

/** `YYYY-MM-DD` of a Date in UTC. */
export function ymd(date: Date): string {
  return date.toISOString().slice(0, 10);
}
