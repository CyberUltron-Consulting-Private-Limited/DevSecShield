/**
 * fixtures/expected.json (the hand-/openssl-derived oracle) and the text helpers every check uses.
 *
 * Matching rule: PDF text comes from `pdftotext -raw`, where a table cell that wrapped inside a narrow
 * column is split over several lines ("(WEAK_" / "CERTIFICATE_" / "KEY)"). All string checks therefore
 * compare with every whitespace character removed on BOTH sides (`squash`). Row checks slice the raw text
 * into rows first (see oracle.ts) so a value must appear in the right row, not merely somewhere.
 */
import * as fs from 'node:fs';

import { EXPECTED_JSON } from './paths';

// The JSON is large and only partly typed on purpose: the checks that read a section know its shape.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Expected = Record<string, any>;

let cached: Expected | undefined;

export function loadExpected(): Expected {
  if (!cached) cached = JSON.parse(fs.readFileSync(EXPECTED_JSON, 'utf8')) as Expected;
  return cached;
}

export const squash = (text: string): string => text.replace(/\s+/g, '');
export const norm = (text: string): string => text.replace(/\s+/g, ' ').trim();

/** True when `needle` occurs in `haystack`, ignoring all whitespace on both sides. */
export function has(haystack: string, needle: string): boolean {
  return squash(haystack).includes(squash(needle));
}

/** Non-empty trimmed lines of a raw text. */
export function textLines(raw: string): string[] {
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

/** `0.867` -> `86.7%` (one decimal, as every PDF prints coverage). */
export function pct(fraction: number): string {
  return `${(fraction * 100).toFixed(1)}%`;
}

/** JSON with object keys sorted, so two equal values always print the same. */
export function stable(value: unknown): string {
  return JSON.stringify(value, (_key, v) =>
    v && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)))
      : v,
  );
}

/** Collects failures so one run reports everything that is wrong, not just the first mismatch. */
export class Findings {
  readonly failures: string[] = [];
  readonly passed: string[] = [];

  check(ok: boolean, label: string, detail = ''): boolean {
    if (ok) this.passed.push(label);
    else this.failures.push(detail ? `${label} -- ${detail}` : label);
    return ok;
  }

  /** Needle must occur (whitespace-insensitive) in `haystack`. */
  contains(haystack: string, needle: string, label: string): boolean {
    return this.check(has(haystack, needle), label, `missing ${JSON.stringify(needle)}`);
  }

  /** Needle must NOT occur. */
  absent(haystack: string, needle: string, label: string): boolean {
    return this.check(!has(haystack, needle), label, `unexpected ${JSON.stringify(needle)}`);
  }

  /** Deep equality; object key order does not matter. */
  equal<T>(actual: T, wanted: T, label: string): boolean {
    return this.check(
      stable(actual) === stable(wanted),
      label,
      `got ${stable(actual)}, expected ${stable(wanted)}`,
    );
  }

  /** Needles must occur in `haystack` in this order. */
  inOrder(haystack: string, needles: string[], label: string): boolean {
    const text = squash(haystack);
    let from = 0;
    for (const needle of needles) {
      const at = text.indexOf(squash(needle), from);
      if (at < 0) return this.check(false, label, `${JSON.stringify(needle)} not found after position ${from}`);
      from = at + squash(needle).length;
    }
    return this.check(true, label);
  }

  merge(other: Findings): void {
    this.failures.push(...other.failures);
    this.passed.push(...other.passed);
  }
}
