/**
 * Shared types and text helpers of the PDF oracle (see oracle.ts for the overview).
 *
 * Kept free of imports from oracle.ts / oracle-docs.ts so the three modules form a tree, not a cycle.
 */
import type { PdfFont, PdfInfo } from './evidence';
import { Findings, norm, textLines, type Expected } from './expected';
import type { SeedJson } from './seed';

export interface DocInput {
  slug: string;
  /** `pdftotext -raw` of the whole file. */
  raw: string;
  /** `raw` split per page. */
  pages: string[];
  info: PdfInfo;
  fonts: PdfFont[];
}

export interface World {
  seed: SeedJson;
  exp: Expected;
  /** e2e/.work (trees for openssl). */
  workDir: string;
  /** Moment the PDF is expected to have been generated (default: now). */
  reference?: Date;
  /** How far `reference` may be after the generation time, in minutes (default from expected.json). */
  clockToleranceMinutes?: number;
  /** After the spec 91 attestation upload: expect `Attested 1/n` and the evidence in the ledger. */
  attested?: boolean;
  /** `YYYY-MM-DD` the backend stamped on the attestation (`uploaded_at` of the upload response). */
  attestedDate?: string;
}

export interface DocMeta {
  asOf: string;
  generated: string; // `YYYY-MM-DDTHH:MM` UTC
  docId: string;
  number: string;
  team: string;
  idDate: string;
  fp8: string;
  fp12: string;
  windowFrom: string | null;
  windowTo: string | null;
}

const CHROME_END = /· Confidential Page \d+$/;
export const isChromeFooter = (line: string): boolean => CHROME_END.test(line);

/** Lines of one page without the brand header / footer block that opens every page. */
export function pageBody(pageText: string): string[] {
  const lines = textLines(pageText);
  const end = lines.findIndex((line) => CHROME_END.test(line));
  return end >= 0 ? lines.slice(end + 1) : lines;
}

/** Body lines of the whole document: page chrome removed, pages in order. */
export function bodyLines(doc: DocInput): string[] {
  return doc.pages.flatMap(pageBody);
}

export function docMeta(raw: string): DocMeta | null {
  const text = norm(raw);
  const id = /Document ID (CBOM-D(\d{2})-T(\d+)-(\d{8})-([0-9a-f]{8}))/.exec(text);
  const generated = /\(UTC\+IST\) (\d{4}-\d{2}-\d{2}) (\d{2}):(\d{2}) UTC \((\d{2}):(\d{2}) IST\)/.exec(text);
  const fp = /Data fingerprint ([0-9a-f]{12})/.exec(text);
  if (!id || !generated || !fp) return null;
  const window = /Data window (\d{4}-\d{2}-\d{2}) to (\d{4}-\d{2}-\d{2}) \(UTC\)/.exec(text);
  return {
    asOf: generated[1],
    generated: `${generated[1]}T${generated[2]}:${generated[3]}`,
    docId: id[1],
    number: id[2],
    team: id[3],
    idDate: id[4],
    fp8: id[5],
    fp12: fp[1],
    windowFrom: window?.[1] ?? null,
    windowTo: window?.[2] ?? null,
  };
}

/** The IST `HH:MM` that follows from a UTC `HH:MM` (UTC+05:30). */
export function istOf(utcHm: string): string {
  const [h, m] = utcHm.split(':').map(Number);
  const total = (h * 60 + m + 330) % 1440;
  return `${String(Math.floor(total / 60)).padStart(2, '0')}:${String(total % 60).padStart(2, '0')}`;
}

/** Headings, each of which must START a line, appear in this order. */
export function headingsInOrder(lines: string[], headings: string[], f: Findings, label: string): void {
  let from = 0;
  for (const heading of headings) {
    const at = lines.findIndex((line, index) => index >= from && line.startsWith(heading));
    if (at < 0) {
      f.check(false, `${label}: heading "${heading}"`, `not found after line ${from}`);
      return;
    }
    from = at + 1;
  }
  f.check(true, `${label}: ${headings.length} headings in order`);
}

/** Every string must occur, whitespace-insensitively. */
export function allPresent(f: Findings, haystack: string, needles: string[], label: string): void {
  for (const needle of needles) f.contains(haystack, needle, `${label}: ${needle.slice(0, 70)}`);
}

export const MANUAL_BANNER = 'To be completed by assessor';

export function worldDocs(exp: Expected): Record<string, Expected> {
  return exp.documents as Record<string, Expected>;
}

/** True when two strings are equal ignoring case and every non-alphanumeric character. */
export function sameAlnum(a: string, b: string): boolean {
  const key = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '');
  return key(a) === key(b);
}
