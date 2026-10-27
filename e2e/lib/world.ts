/**
 * Builds the `World` the oracle judges against, and loads a PDF into the shape `checkDocument` expects.
 */
import { pdfFonts, pdfInfo, pdfPageTexts, pdfText } from './evidence';
import { loadExpected } from './expected';
import type { DocInput, World } from './oracle-core';
import { WORK_DIR } from './paths';
import { loadSeed } from './seed';

export function makeWorld(extra: Partial<World> = {}): World {
  return { seed: loadSeed(), exp: loadExpected(), workDir: WORK_DIR, ...extra };
}

export function loadDoc(slug: string, file: string): DocInput {
  return {
    slug,
    raw: pdfText(file, 'raw'),
    pages: pdfPageTexts(file),
    info: pdfInfo(file),
    fonts: pdfFonts(file).fonts,
  };
}

export const POSTURE_SLUGS = [
  'infrastructure-cloud-encryption-posture',
  'network-tls-protocol-assessment',
  'data-at-rest-encryption-assessment',
] as const;

export const SLUGS = [
  'scope-baseline-register',
  'methodology-evidence-plan',
  'certificate-estate-register',
  'third-party-assurance-register',
  'pqc-migration-roadmap',
  'board-executive-report',
] as const;

export type Slug = (typeof SLUGS)[number];
