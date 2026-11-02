/**
 * Offline selftest of the PDF oracle - no browser, no stack.
 *
 * Judges the PDFs of a rehearsal (seed/dryrun_world.py: the real seed code against SQLite, the same
 * renderers the router calls) with the very functions the stack specs use, then proves the oracle can
 * FAIL: each mutation below corrupts one fact in the PDF text and the oracle must notice.
 *
 *   E2E_SELFTEST_DIR=/tmp/dss-dryrun E2E_SEED_JSON=/tmp/dss-dryrun/seed.json \
 *   E2E_EVIDENCE_DIR=/tmp/dss-selftest E2E_TEST_DIR=$PWD/selftest npx playwright test
 *
 * (see seed/dryrun_world.py for how the directory is produced.)
 */
import * as fs from 'node:fs';
import * as path from 'node:path';

import { expect, test } from '@playwright/test';

import { loadExpected } from '../lib/expected';
import { checkDocument, checkEmptyDocument } from '../lib/oracle';
import type { DocInput } from '../lib/oracle-core';
import { loadSeed } from '../lib/seed';
import { loadDoc, makeWorld, SLUGS } from '../lib/world';

const DIR = process.env.E2E_SELFTEST_DIR ?? '';
const exp = loadExpected();
const number = (slug: string): string => String(exp.documents[slug].number).padStart(2, '0');

test.beforeAll(() => {
  expect(DIR, 'set E2E_SELFTEST_DIR to the dryrun_world.py output directory').not.toBe('');
  expect(fs.existsSync(path.join(DIR, 'team1')), `${DIR}/team1 exists`).toBe(true);
});

const seedTime = (): Date => new Date(Date.parse(loadSeed().seeded_at) + 2 * 60_000);

function pdf(sub: string, slug: string): DocInput {
  return loadDoc(slug, path.join(DIR, sub, `${number(slug)}-${slug}.pdf`));
}

function report(failures: string[]): string {
  return failures.length ? `\n${failures.map((x) => `  - ${x}`).join('\n')}` : '';
}

test.describe('oracle accepts the rehearsal PDFs', () => {
  for (const slug of SLUGS) {
    test(`#${number(slug)} ${slug} (demo team)`, () => {
      const world = makeWorld({ reference: seedTime() });
      const result = checkDocument(pdf('team1', slug), world);
      test.info().annotations.push({ type: 'checks', description: `${result.passed.length} passed` });
      expect(result.failures, `oracle failures${report(result.failures)}`).toEqual([]);
      expect(result.passed.length, 'the oracle really ran').toBeGreaterThan(20);
    });
  }

  for (const slug of SLUGS) {
    test(`#${number(slug)} ${slug} (empty team)`, () => {
      const world = makeWorld({ reference: seedTime() });
      const result = checkEmptyDocument(pdf('team3', slug), world);
      expect(result.failures, `oracle failures${report(result.failures)}`).toEqual([]);
    });
  }

  test('#10 after the attestation upload: Attested 1/5, evidence, 0.5%', () => {
    const dry = JSON.parse(fs.readFileSync(path.join(DIR, 'dryrun.json'), 'utf8')) as { attestation: { uploaded_at: string } };
    const world = makeWorld({ reference: seedTime(), attested: true, attestedDate: dry.attestation.uploaded_at.slice(0, 10) });
    for (const slug of ['third-party-assurance-register', 'methodology-evidence-plan', 'board-executive-report'] as const) {
      const result = checkDocument(pdf('team1-attested', slug), world);
      expect(result.failures, `${slug} after attestation${report(result.failures)}`).toEqual([]);
    }
  });

  test('before the upload the attested-world checks fail (the oracle can tell the two states apart)', () => {
    const world = makeWorld({ reference: seedTime(), attested: true, attestedDate: '2000-01-01' });
    const result = checkDocument(pdf('team1', 'third-party-assurance-register'), world);
    expect(result.failures.length).toBeGreaterThan(0);
  });
});

// Each entry corrupts ONE fact in the text of an otherwise valid PDF; the oracle must report a failure.
const MUTATIONS: Array<{ slug: (typeof SLUGS)[number]; name: string; change: (raw: string) => string }> = [
  { slug: 'board-executive-report', name: 'readiness 86.5% -> 86.4%', change: (t) => t.replace(/86\.5%/g, '86.4%') },
  { slug: 'board-executive-report', name: 'a canary leaks into the text', change: (t) => `${t}\nFAILED-SCAN-CANARY` },
  { slug: 'board-executive-report', name: 'foreign identity (clinithread)', change: (t) => `${t}\nclinithread-aibom` },
  { slug: 'board-executive-report', name: 'grade F -> A', change: (t) => t.replace('Posture grade\nF\n', 'Posture grade\nA\n') },
  { slug: 'certificate-estate-register', name: 'expired by 36 days instead of 35', change: (t) => t.replace(/(\d+) days ago/, (_m, n) => `${Number(n) + 1} days ago`) },
  { slug: 'certificate-estate-register', name: 'owner cell filled in', change: (t) => t.replace(/(1 scan \(#6\))/, '$1\nACME Corp') },
  { slug: 'certificate-estate-register', name: 'a certificate row disappears', change: (t) => t.replace('strong-control.test', 'x') },
  { slug: 'scope-baseline-register', name: 'per-source assets 8/0/0/9/2 -> 8/0/0/9/3', change: (t) => t.replace('8/0/0/9/2', '8/0/0/9/3') },
  { slug: 'scope-baseline-register', name: 'repository URL keeps its credentials', change: (t) => t.replace('https://github.com/e2e-d', 'https://x-access-token@github.com/e2e-d') },
  { slug: 'methodology-evidence-plan', name: 'scanner order 25 -> 26', change: (t) => t.replace('crypto_misuse 25', 'crypto_misuse 26') },
  { slug: 'methodology-evidence-plan', name: 'a removed scanner module is described', change: (t) => `${t}\nnative_crypto_scan` },
  { slug: 'third-party-assurance-register', name: 'a control shows as attested', change: (t) => t.replace('Attested 0/5', 'Attested 1/5') },
  { slug: 'third-party-assurance-register', name: 'a library disappears', change: (t) => t.replace('libsodium', 'libsodiumX') },
  { slug: 'pqc-migration-roadmap', name: 'sized target changes', change: (t) => t.replace(/ML-KEM-768/g, 'ML-KEM-512') },
  { slug: 'pqc-migration-roadmap', name: 'IR 8547 loses its draft status', change: (t) => t.replace(/DRAFT/g, 'FINAL') },
];

test.describe('oracle rejects corrupted PDFs', () => {
  for (const mutation of MUTATIONS) {
    test(`#${number(mutation.slug)} ${mutation.name}`, () => {
      const world = makeWorld({ reference: seedTime() });
      const good = pdf('team1', mutation.slug);
      const raw = mutation.change(good.raw);
      expect(raw, 'the mutation changed something').not.toBe(good.raw);
      const pages = good.pages.map(mutation.change);
      const bad = checkDocument({ ...good, raw, pages }, world);
      expect(bad.failures.length, `the oracle must notice: ${mutation.name}`).toBeGreaterThan(0);
    });
  }
});
