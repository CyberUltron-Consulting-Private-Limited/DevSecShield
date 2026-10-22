/**
 * One check per deliverable (see oracle.ts). Each function receives the PDF text and the world
 * (expected.json + seed.json + the trees on disk) and records every mismatch in `Findings`.
 *
 * Conventions:
 *   - a "chain" is the expected text of several adjacent cells/lines joined with spaces; `Findings.contains`
 *     compares it with all whitespace removed, so wrapping inside a narrow column does not matter but the
 *     ORDER of the cells does (that is how a value is tied to its row);
 *   - date-relative values come from seed.json (scan dates), from the document's own "Generated" date and
 *     from `openssl` on the files in e2e/.work/trees, never from the product.
 */
import * as path from 'node:path';

import { run } from './exec';
import { Findings, norm, pct, squash } from './expected';
import {
  allPresent, bodyLines, headingsInOrder, MANUAL_BANNER,
  type DocInput, type DocMeta, type World,
} from './oracle-core'; // fmt: skip
import { daysBetween, scanDate } from './seed';

/* eslint-disable @typescript-eslint/no-explicit-any */

// ---------------------------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------------------------
interface SourceInfo {
  label: string;
  kind: string;
  url: string | null;
  branch: string | null;
  scans: number[];
  current: number;
  fidelity: string;
  last_attempt: { status: string; scan: number };
  first: string;
  last: string;
}

function sourcesOf(w: World): SourceInfo[] {
  return (w.exp.sources as any[]).map((s) => {
    const dates = (s.scans as number[]).map((id) => scanDate(w.seed, id)).sort();
    return { ...s, first: dates[0], last: dates[dates.length - 1] } as SourceInfo;
  });
}

/** Cells joined by single spaces; empty parts are dropped. */
const join = (...parts: Array<string | number | null | undefined | false>): string =>
  parts.filter((p) => p !== null && p !== undefined && p !== false && p !== '').join(' ');

function assetsCell(w: World, label: string): string {
  const p = w.exp.per_source[label];
  return `${p.alg}/${p.cert}/${p.proto}/${p.mat}/${p.libs}`;
}

/** `YYYY-MM-DD` from the `Mon  D HH:MM:SS YYYY GMT` form openssl prints. */
function opensslDate(text: string): string {
  const m = /([A-Z][a-z]{2})\s+(\d{1,2})\s+\d{2}:\d{2}:\d{2}\s+(\d{4})\s+GMT/.exec(text);
  if (!m) throw new Error(`cannot parse openssl date: ${text}`);
  const month = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'].indexOf(m[1]) + 1;
  return `${m[3]}-${String(month).padStart(2, '0')}-${m[2].padStart(2, '0')}`;
}

/** Validity dates of a certificate file, read by openssl (an independent oracle). */
export function opensslValidity(file: string): { from: string; to: string } {
  const out = run('openssl', ['x509', '-in', file, '-noout', '-startdate', '-enddate']).stdout;
  const from = /notBefore=(.*)/.exec(out)?.[1];
  const to = /notAfter=(.*)/.exec(out)?.[1];
  if (!from || !to) throw new Error(`openssl gave no validity for ${file}`);
  return { from: opensslDate(from), to: opensslDate(to) };
}

function bandOf(days: number): 'EXPIRED' | 'LE_30' | 'LE_90' | 'VALID' {
  if (days < 0) return 'EXPIRED';
  if (days <= 30) return 'LE_30';
  if (days <= 90) return 'LE_90';
  return 'VALID';
}

const daysText = (days: number): string => (days < 0 ? `${-days} days ago` : `${days} days left`);

/** Rows that are a label followed by a number (or text) on one line. */
function labelValueRows(f: Findings, raw: string, rows: Array<[string, string | number]>, label: string): void {
  for (const [name, value] of rows) f.contains(raw, `${name} ${value}`, `${label}: ${name} = ${value}`);
}

/** Sign-off tables are manual: the last body line of the document is the last role, nothing after it. */
function lastLineIs(f: Findings, doc: DocInput, role: string, label: string): void {
  const lines = bodyLines(doc);
  f.check(lines[lines.length - 1] === role, `${label}: sign-off rows are blank (nothing after "${role}")`, `last line: ${lines[lines.length - 1]}`);
}

// ---------------------------------------------------------------------------------------------
// #1 Scope Baseline & Asset Population Register
// ---------------------------------------------------------------------------------------------
export function checkScope(doc: DocInput, w: World, meta: DocMeta, f: Findings): void {
  const exp = w.exp;
  const s = exp.scope;
  const ab = exp.appendix_b;
  const L = '#1';
  const raw = doc.raw;
  headingsInOrder(bodyLines(doc), s.sections, f, `${L} sections`);
  f.contains(raw, s.intro, `${L}: intro sentence`);
  f.contains(raw, MANUAL_BANNER, `${L}: manual forms are marked`);
  allPresent(f, raw, s.boundary_items, `${L} boundary item`);

  // B. Sources assessed
  f.contains(raw, `Sources assessed: ${ab.sources}. Completed scans included: ${ab.included}.`, `${L}: B summary line`);
  f.contains(raw, `# ${(s.source_columns as string[]).join(' ')}`, `${L}: B column headers incl. the two manual columns`);
  const sources = sourcesOf(w);
  sources.forEach((src, index) => {
    const attempt =
      src.last_attempt.status === 'SUCCESS'
        ? `SUCCESS scan #${src.last_attempt.scan}`
        : `${src.last_attempt.status} most recent attempt failed on ${scanDate(w.seed, src.last_attempt.scan)} ` +
          `(scan #${src.last_attempt.scan}); figures reflect scan #${src.current} of ${scanDate(w.seed, src.current)}`;
    const row = join(
      index + 1, src.label, src.kind, src.url ?? '—', src.branch ? `branch: ${src.branch}` : '',
      src.scans.length, src.first, src.last, `${daysBetween(src.last, meta.asOf)} days ago`,
      attempt, src.fidelity, assetsCell(w, src.label),
    ); // fmt: skip
    f.contains(raw, row, `${L}: B row ${index + 1} ${src.label}`);
  });
  allPresent(f, raw, s.limits_lines, `${L} B limits`);
  f.contains(raw, 'Legacy: the scan predates the current CBOM engine (reduced fidelity).', `${L}: B legacy note`);

  // C. Asset population
  const types = ab.by_type_impact;
  f.contains(
    raw,
    join(
      'Sources', ab.sources, 'with a completed scan', 'Asset occurrences', ab.occurrences, 'current state',
      'Algorithms', types.alg.total, 'occurrences', 'Certificates', types.cert.total, `${ab.cert_unique} unique`,
      'Protocols', types.proto.total, 'occurrences', 'Key material', types.mat.total, 'occurrences',
    ),
    `${L}: C KPI cards`,
  ); // fmt: skip
  f.contains(raw, 'Asset type Critical High Medium Low Total', `${L}: C type/impact header`);
  for (const row of s.type_rows as Array<{ label: string; klass: string }>) {
    const t = types[row.klass];
    f.contains(raw, join(row.label, t.Critical, t.High, t.Medium, t.Low, t.total), `${L}: C ${row.label} row`);
  }
  const imp = ab.impact;
  f.contains(raw, join('All asset types', imp.Critical, imp.High, imp.Medium, imp.Low, ab.occurrences), `${L}: C total row`);
  f.contains(raw, '# Source Algorithms Certificates Protocols Key material Total Libraries Critical High Medium Low', `${L}: C by-source header`);
  sources.forEach((src, index) => {
    const p = exp.per_source[src.label];
    f.contains(
      raw,
      join(index + 1, src.label, p.alg, p.cert, p.proto, p.mat, p.total, p.libs, p.impact.Critical, p.impact.High, p.impact.Medium, p.impact.Low),
      `${L}: C by-source row ${index + 1} ${src.label}`,
    );
  });
  f.contains(
    raw,
    join('All sources', types.alg.total, types.cert.total, types.proto.total, types.mat.total, ab.occurrences, `${ab.libs} unique`, imp.Critical, imp.High, imp.Medium, imp.Low),
    `${L}: C all-sources row`,
  );
  f.contains(raw, `Crypto libraries: ${ab.libs} unique across sources (${ab.libs_source_level} source-level occurrences).`, `${L}: C libraries line`);

  // D. Exclusions and data quality
  const t = s.treatment_labels;
  const ex = ab.excluded;
  labelValueRows(
    f, raw,
    [
      [t.total, ab.scans_total], [t.eligible, ab.eligible], [t.included, ab.included], [t.failed, ex.failure],
      [t.not_completed, ex.not_completed], [t.no_data, ex.no_data], [t.history, 0],
    ],
    `${L} D treatment`,
  ); // fmt: skip
  const excluded = s.not_included as Array<{ id: number; status: string; reason: string }>;
  for (const item of excluded) {
    f.contains(
      raw,
      join(`#${item.id}`, exp.scan_titles[String(item.id)], exp.scan_sources[String(item.id)], scanDate(w.seed, item.id), item.status, item.reason),
      `${L}: D excluded scan #${item.id}`,
    );
  }
  f.inOrder(raw, excluded.map((x) => `#${x.id} ${exp.scan_titles[String(x.id)]}`), `${L}: D excluded scans listed newest first`);
  for (const row of s.data_quality as Array<{ label: string; value: string }>) {
    f.contains(raw, `${row.label} ${row.value}`, `${L}: D check "${row.label}"`);
  }

  // E. Outside static visibility, F. Sign-off: manual and blank
  allPresent(f, raw, s.outside_visibility, `${L} E item`);
  f.contains(raw, 'Sign-off Name Role Date Signature', `${L}: F sign-off header`);
  f.inOrder(raw.slice(raw.indexOf('F. Sign-off')), s.sign_off_rows, `${L}: F sign-off roles`);
  lastLineIs(f, doc, s.sign_off_rows[s.sign_off_rows.length - 1], `${L} F`);
}

// ---------------------------------------------------------------------------------------------
// #3 Cryptographic Discovery Methodology & Evidence Plan
// ---------------------------------------------------------------------------------------------
export function checkMethodology(doc: DocInput, w: World, meta: DocMeta, f: Findings): void {
  const exp = w.exp;
  const m = exp.methodology;
  const ab = exp.appendix_b;
  const L = '#3';
  const raw = doc.raw;
  headingsInOrder(bodyLines(doc), m.sections, f, `${L} sections`);

  // 1. Purpose and scope: live numbers
  const k = m.kpi_labels as string[];
  f.contains(
    raw,
    join(
      k[0], ab.sources, 'assessed in this edition', k[1], ab.included, `of ${ab.eligible} successful scans`, k[2], ab.occurrences, 'current occurrences',
      k[3], ab.cert_unique, 'de-duplicated across sources', k[4], m.kpis.frameworks, `pooled over ${ab.pooled} sources`, k[5], m.kpis.requirements, 'tracked across frameworks',
    ),
    `${L}: 1 KPI cards`,
  ); // fmt: skip
  const ex = ab.excluded;
  f.contains(
    raw,
    `This edition reflects ${ab.included} completed scans of ${ab.sources} sources as of ${meta.asOf}: ${ab.included - ab.legacy} full-fidelity and ${ab.legacy} legacy-format. ` +
      `Of ${ab.scans_total} CBOM scans recorded for this team, ${ab.eligible} completed successfully and ${ab.included} are included; ` +
      `left out: ${ex.failure} failed, ${ex.not_completed} not completed and ${ex.no_data} completed without data.`,
    `${L}: 1 edition sentence`,
  );
  const types = ab.by_type_impact;
  f.contains(raw, 'Asset type Occurrences', `${L}: 1 type table header`);
  for (const row of m.type_rows as Array<{ label: string; klass: string }>) {
    f.contains(raw, `${row.label} ${types[row.klass].total}`, `${L}: 1 ${row.label} = ${types[row.klass].total}`);
  }
  f.contains(raw, `Total ${ab.occurrences}`, `${L}: 1 total occurrences`);

  // 2. Automated discovery: the nine registered scanners, in order, none of the unwired modules
  const scanners = m.scanners as Array<{ name: string; order: number }>;
  f.contains(raw, 'Scanner Order Discovers Evidence recorded', `${L}: 2 scanner table header`);
  for (const sc of scanners) f.contains(raw, `${sc.name} ${sc.order}`, `${L}: 2 scanner ${sc.name} order ${sc.order}`);
  f.inOrder(raw, scanners.map((sc) => `${sc.name} ${sc.order}`), `${L}: 2 scanners listed in registry order`);
  for (const dead of m.unwired_scanner_modules as string[]) f.absent(raw, dead, `${L}: 2 does not describe the unwired module ${dead}`);

  // 3. Manual discovery checklist (blank)
  f.contains(raw, MANUAL_BANNER, `${L}: 3 manual checklist marked`);
  allPresent(f, raw, m.manual_items, `${L} 3 manual item`);

  // 4. Evidence sources
  f.contains(raw, `Evidence is drawn from ${ab.sources} sources: ${ab.sources - 1} repositories and 1 zip upload.`, `${L}: 4 sources sentence`);
  for (const row of m.evidence_rows as Array<{ label: string; present: number; out_of: number; share: string }>) {
    f.contains(raw, join(row.label, row.present, row.out_of, row.share), `${L}: 4 ${row.label}`);
  }

  // 5-7
  f.contains(raw, m.validation_sentence, `${L}: 5 no ML / LLM statement`);
  f.contains(raw, m.coverage_formula, `${L}: 6 coverage formula`);
  f.contains(raw, m.pooled_line, `${L}: 6 pooled line`);
  f.contains(raw, 'Framework Pass Pass with evidence Fail Not evidenceable Out of scope Coverage Sources pooled', `${L}: 6 framework table header`);
  const labels: Record<string, string> = Object.fromEntries((exp.frameworks as any[]).map((x) => [x.key, x.label]));
  for (const [key, c] of Object.entries(ab.compliance as Record<string, any>)) {
    const target = key === exp.attestation.framework && w.attested;
    const pwe = target ? c.pass_with_evidence + 1 : c.pass_with_evidence;
    const nbe = target ? c.nbe - 1 : c.nbe;
    const coverage = Math.round(((c.pass + pwe) / (c.pass + pwe + c.fail)) * 1000) / 1000;
    f.contains(raw, join(labels[key], c.pass, pwe, c.fail, nbe, c.oos, pct(coverage), ab.pooled), `${L}: 6 ${labels[key]} pooled row`);
  }
  const total = m.totals_row;
  f.contains(
    raw,
    join(total.label, total.pass, total.pass_with_evidence + (w.attested ? 1 : 0), total.fail, total.nbe - (w.attested ? 1 : 0), total.oos, '—', '—'),
    `${L}: 6 all-frameworks row`,
  );
  allPresent(f, raw, m.confidence_rows, `${L} 7 confidence class`);
  f.contains(raw, m.confidence_note, `${L}: 7 honest limit on per-asset confidence`);

  // 8-9
  allPresent(f, raw, m.raci_rows, `${L} 8 RACI row`);
  f.contains(
    raw,
    `Versioning: this edition is Document ID ${meta.docId} with data fingerprint ${meta.fp12} and template version 1.0.`,
    `${L}: 9 versioning sentence ties to the document-control block`,
  );
  allPresent(f, raw, m.retention_rows, `${L} 9 retention row`);

  // 10-11
  allPresent(f, raw, m.limits, `${L} 10 limit`);
  f.inOrder(raw.slice(raw.indexOf('11. Sign-off')), m.sign_off_rows, `${L}: 11 sign-off roles`);

  // Appendix A. Scans considered: every CBOM scan of the team, newest first
  f.contains(raw, 'Scan Title Source Created (UTC) Disposition Fidelity Assets', `${L}: Appendix A header`);
  const list = exp.scan_list as Array<{ id: number; disposition: string; fidelity: string | null; assets: number | null }>;
  for (const row of list) {
    f.contains(
      raw,
      join(`#${row.id}`, exp.scan_titles[String(row.id)], exp.scan_sources[String(row.id)], scanDate(w.seed, row.id), row.disposition, row.fidelity ?? '—', row.assets ?? '—'),
      `${L}: Appendix A scan #${row.id}`,
    );
  }
  f.inOrder(raw, list.map((row) => `#${row.id} ${exp.scan_titles[String(row.id)]} `), `${L}: Appendix A newest first`);
}

// ---------------------------------------------------------------------------------------------
// #7 Certificate Estate Register
// ---------------------------------------------------------------------------------------------
interface CertTruth {
  subject: string;
  row: any;
  from: string;
  to: string;
  days: number;
  band: string;
}

/** The 14 certificates with validity from openssl for the two authored ones and expected.json for the frozen ones. */
export function certTruth(w: World, asOf: string): CertTruth[] {
  const c = w.exp.certificates;
  return (c.register_order as string[]).map((subject) => {
    const row = c.rows[subject];
    let from = row.valid_from as string | undefined;
    let to = row.valid_to as string | undefined;
    if (row.authored) {
      const validity = opensslValidity(path.join(w.workDir, 'trees', row.authored.tree, row.authored.file));
      from = validity.from;
      to = validity.to;
    }
    const days = daysBetween(asOf, to as string);
    return { subject, row, from: from as string, to: to as string, days, band: bandOf(days) };
  });
}

/** Lines the repeated column header of a continuation page starts with. */
const REGISTER_HEADER_START = '# Certificate';

/** Start line of each expected row, found in order: `N <subject...>` (the subject may wrap onto the next lines). */
function findCertRowStarts(lines: string[], subjects: string[]): number[] | string {
  const starts: number[] = [];
  let cursor = 0;
  for (let n = 1; n <= subjects.length; n++) {
    const want = squash(subjects[n - 1]);
    let found = -1;
    for (let i = cursor; i < lines.length; i++) {
      const m = /^(\d+)\s+(.+)$/.exec(lines[i]);
      if (!m || Number(m[1]) !== n) continue;
      if (squash(`${m[2]}${lines[i + 1] ?? ''}${lines[i + 2] ?? ''}`).startsWith(want)) {
        found = i;
        break;
      }
    }
    if (found < 0) return `row ${n} (${subjects[n - 1]}) not found after line ${cursor}`;
    starts.push(found);
    cursor = found + 1;
  }
  return starts;
}

export function checkCertificates(doc: DocInput, w: World, meta: DocMeta, f: Findings): void {
  const exp = w.exp;
  const c = exp.certificates;
  const ab = exp.appendix_b;
  const L = '#7';
  const raw = doc.raw;
  const truth = certTruth(w, meta.asOf);
  const chip = c.band_labels as Record<string, string>;

  // The oracle must still be valid for today's date (the frozen fixture certificates age).
  const bands: Record<string, number> = { EXPIRED: 0, LE_30: 0, LE_90: 0, VALID: 0 };
  for (const t of truth) bands[t.band] += 1;
  f.equal(bands, ab.bands, `${L}: validity bands recomputed from the certificate FILES (openssl) as of ${meta.asOf} equal Appendix B`);
  for (const t of truth) f.equal(t.band, t.row.band, `${L}: band of ${t.subject} unchanged since expected.json was derived`);

  headingsInOrder(bodyLines(doc), c.sections, f, `${L} sections`);
  const k = c.kpis;
  f.contains(
    raw,
    join(
      'Certificates', k.unique, 'Unique, all sources', 'Expired', k.expired, 'Past notAfter date', chip.LE_30, k.le30, 'Due in 0 to 30 days',
      chip.LE_90, k.le90, 'Due in 31 to 90 days', 'Weak crypto', k.weak, 'Weak key or signature', 'Self-signed leaf', k.self_signed_leaf,
      'Self-signed, not a CA', 'Issuer not found', k.issuer_not_found, 'Issuer not in estate',
    ),
    `${L}: 1 KPI strip`,
  ); // fmt: skip
  f.equal(k.unique, ab.cert_unique, `${L}: KPI unique equals Appendix B`);
  f.equal(k.weak, truth.filter((t) => t.row.findings.some((x: string) => x.startsWith('WEAK_CERTIFICATE'))).length, `${L}: weak-crypto KPI = certificates with a weak key or signature finding`);
  f.equal(k.self_signed_leaf, truth.filter((t) => t.row.findings.includes('SELF_SIGNED_LEAF')).length, `${L}: self-signed-leaf KPI`);

  f.contains(raw, 'Validity band Definition Certificates', `${L}: 2 band table header`);
  f.contains(raw, `EXPIRED notAfter date is before ${meta.asOf} ${bands.EXPIRED}`, `${L}: 2 EXPIRED row`);
  f.contains(raw, `${chip.LE_30} Expires in 0 to 30 days ${bands.LE_30}`, `${L}: 2 <=30 DAYS row`);
  f.contains(raw, `${chip.LE_90} Expires in 31 to 90 days ${bands.LE_90}`, `${L}: 2 <=90 DAYS row`);
  f.contains(raw, `VALID Expires in more than 90 days ${bands.VALID}`, `${L}: 2 VALID row`);

  f.contains(raw, `Showing all ${ab.cert_unique} unique certificates.`, `${L}: 3 register shows every unique certificate`);
  f.contains(
    raw,
    `# Certificate Issuer CN Public key Signature algorithm Valid from Valid to Expiry as of ${meta.asOf} CA / self-signed / chain Findings Where found Seen (first -> last) Owner (assessor) Business system (assessor)`,
    `${L}: 3 register column headers incl. the two manual columns`,
  );

  // --- the register rows ---
  const lines = bodyLines(doc);
  const starts = findCertRowStarts(lines, truth.map((t) => t.subject));
  if (!f.check(Array.isArray(starts), `${L}: 14 rows in the documented sort order (expired, <=30, impact, valid-to, subject)`, String(starts))) return;
  const rowStarts = starts as number[];
  const limitsAt = lines.findIndex((line, index) => index > rowStarts[rowStarts.length - 1] && /^4\. Discovery limits/.test(line));
  const labelsByCode = exp.finding_labels as Record<string, string>;
  const sourceLabel = (scan: number): string => exp.scan_sources[String(scan)];

  truth.forEach((t, index) => {
    const end = index + 1 < rowStarts.length ? rowStarts[index + 1] : limitsAt < 0 ? lines.length : limitsAt;
    const segLines = lines.slice(rowStarts[index], end);
    const seg = squash(segLines.join(''));
    const r = t.row;
    const tag = `${L} row ${index + 1} ${t.subject}`;
    const locations: Array<{ scan: number; path: string }> = r.locations;
    const multi = Array.isArray(r.scans) && r.scans.length > 1;
    const findings: string[] = r.findings;
    // Cells in the order the register prints them; elements of one cell may come in any order.
    const groups: string[][] = [
      [`${index + 1}${t.subject}`, ...(r.files as string[])],
      [r.issuer],
      [r.public_key],
      [r.signature],
      [`${t.from}${t.to}`],
      [`${chip[t.band]}${daysText(t.days)}`],
      [r.chain],
      [r.impact],
      findings.length ? findings.map((code) => `${labelsByCode[code]}(${code})`) : ['No findings'],
      [...(multi ? [`${locations.length} locations`] : []), ...locations.map((loc) => `${sourceLabel(loc.scan)}: ${loc.path}`)],
    ];
    let pos = 0;
    for (const group of groups) {
      let groupEnd = pos;
      for (const element of group) {
        const at = seg.indexOf(squash(element), pos);
        if (at < 0) {
          f.check(false, `${tag}: "${element.slice(0, 60)}" in the expected cell order`);
          return;
        }
        groupEnd = Math.max(groupEnd, at + squash(element).length);
      }
      pos = groupEnd;
    }
    // Seen (first -> last): one scan, or a range with the count and the latest scan. Then nothing.
    const dates = (multi ? (r.scans as number[]) : [locations[0].scan]).map((id) => scanDate(w.seed, id)).sort();
    const seen = multi
      ? `${dates[0]} -> ${dates[dates.length - 1]} ${(r.scans as number[]).length} scans latest #${r.latest_scan}`
      : `${dates[0]} 1 scan (#${locations[0].scan})`;
    const seenAt = seg.indexOf(squash(seen), pos);
    f.check(seenAt >= 0, `${tag}: seen "${seen}"`);
    if (seenAt < 0) return;
    const lastWords = squash(seen.split(' ').slice(-2).join(' '));
    const lastLine = segLines.findIndex((line) => squash(line).endsWith(lastWords));
    const tail = lastLine >= 0 ? segLines.slice(lastLine + 1) : [];
    const header = tail.findIndex((line) => line.startsWith(REGISTER_HEADER_START));
    const stray = header >= 0 ? tail.slice(0, header) : tail;
    f.check(stray.length === 0, `${tag}: Owner and Business system cells are blank`, stray.slice(0, 3).join(' | '));
  });

  allPresent(f, raw, [
    'The engine records subject and issuer common names, validity dates, signature algorithm, public-key algorithm, key size or curve, and the self-signed and CA flags.',
    'Owner and Business system are intentionally blank.',
  ], `${L} 4 limits`);
  f.inOrder(raw.slice(raw.indexOf('5. Reviewer sign-off')), c.sign_off_rows, `${L}: 5 sign-off roles`);
  lastLineIs(f, doc, c.sign_off_rows[c.sign_off_rows.length - 1], `${L} 5`);
}

// ---------------------------------------------------------------------------------------------
// #10 Third-Party Cryptographic Assurance & Attestation Register
// ---------------------------------------------------------------------------------------------
export function checkAssurance(doc: DocInput, w: World, _meta: DocMeta, f: Findings): void {
  const exp = w.exp;
  const a = exp.assurance;
  const ab = exp.appendix_b;
  const att = exp.attestation;
  const L = '#10';
  const raw = doc.raw;
  headingsInOrder(bodyLines(doc), a.sections, f, `${L} sections`);
  f.contains(raw, a.libraries_line, `${L}: A libraries summary`);
  f.contains(raw, (a.library_columns as string[]).join(' '), `${L}: A column headers incl. the manual columns`);

  // A. every library with its sources and first / last seen
  const byLabel = new Map(sourcesOf(w).map((s) => [s.label, s]));
  const libs = a.libraries as Array<{ name: string; sources: string[] }>;
  f.equal(libs.length, ab.libs, `${L}: library table lists ${ab.libs} libraries`);
  for (const lib of libs) {
    const dates = lib.sources.flatMap((label) => (byLabel.get(label) as SourceInfo).scans.map((id) => scanDate(w.seed, id))).sort();
    f.contains(raw, join(lib.name, lib.sources.length, ...[...lib.sources].sort(), dates[0], dates[dates.length - 1]), `${L}: A ${lib.name}`);
  }
  f.inOrder(raw, libs.map((lib) => lib.name), `${L}: A libraries sorted by name`);
  f.equal(libs.filter((lib) => lib.sources.length > 1).map((lib) => lib.name.toLowerCase()).sort(), ab.libs_multi, `${L}: libraries used by more than one source`);

  // B. attestation ledger: one row per control the BOM cannot evidence
  f.contains(raw, a.ledger_intro, `${L}: B pooled-sources line`);
  f.contains(raw, (a.ledger_columns as string[]).join(' '), `${L}: B column headers`);
  const attested = [...norm(raw).matchAll(/Attested (\d+)\/(\d+)/g)].map((m) => ({ k: Number(m[1]), n: Number(m[2]) }));
  f.equal(attested.length, ab.ledger.pairs, `${L}: B ${ab.ledger.pairs} ledger rows`);
  f.equal(attested.reduce((sum, x) => sum + x.n, 0), ab.ledger.source_level, `${L}: B "sources in scope" add up to ${ab.ledger.source_level}`);
  f.equal(attested.reduce((sum, x) => sum + x.k, 0), w.attested ? 1 : 0, `${L}: B attested source-level count`);
  for (const row of a.ledger_rows_spot as Array<{ framework: string; req: string; title: string; citation: string; in_scope: number; n: number }>) {
    const target = w.attested && row.framework === att.framework_label && row.req === att.requirement_id;
    const status = `Attested ${target ? 1 : 0}/${row.n}`;
    const tail = target ? join(att.filename, att.note, w.attestedDate) : '—';
    f.contains(raw, join(row.framework, row.req, row.title, row.citation, row.in_scope, status, tail), `${L}: B ledger row ${row.req}${target ? ' (attested)' : ''}`);
  }

  // C. summary
  const d = w.attested ? att.after : a.summary_before;
  f.contains(
    raw,
    join(
      'Controls needing attestation', ab.ledger.pairs, 'framework/requirement pairs the BOM cannot evidence',
      'Fully attested', d.fully, 'attested in every source that needs the control',
      'Partly attested', d.partly, 'attested in some, but not all, sources',
      'Attested (source level)', d.percent, `${d.source_level} of ${d.of} source-level attestations`,
    ),
    `${L}: C attestation summary (${w.attested ? 'after' : 'before'} the upload)`,
  ); // fmt: skip

  // D-E manual
  f.contains(raw, (a.vendor_columns as string[]).join(' '), `${L}: D vendor register columns`);
  f.contains(raw, MANUAL_BANNER, `${L}: D / E marked as manual`);
  f.inOrder(raw.slice(raw.indexOf('E. Sign-off')), a.sign_off_rows, `${L}: E sign-off roles`);
  lastLineIs(f, doc, a.sign_off_rows[a.sign_off_rows.length - 1], `${L} E`);
}

// ---------------------------------------------------------------------------------------------
// #15 PQC Migration Roadmap
// ---------------------------------------------------------------------------------------------
export function checkPqc(doc: DocInput, w: World, _meta: DocMeta, f: Findings): void {
  const exp = w.exp;
  const p = exp.pqc;
  const ab = exp.appendix_b;
  const L = '#15';
  const raw = doc.raw;
  headingsInOrder(bodyLines(doc), p.sections, f, `${L} sections`);
  const k = p.kpi_labels as string[];
  f.contains(
    raw,
    join(
      k[0], ab.qv, 'current occurrences', k[1], p.kpis.distinct_kinds, 'algorithm with key size or curve', k[2], `${ab.readiness}%`,
      'quantum-safe / (safe + vulnerable)', k[3], ab.safe, 'current occurrences', k[4], p.kpis.hybrid, 'subset of quantum-safe', k[5], ab.not_gradeable,
      'no quantum status recorded',
    ),
    `${L}: 1 KPI cards`,
  ); // fmt: skip

  // 2. Regulatory timeline: public sources and URLs (plan Appendix C)
  f.contains(raw, 'When Milestone Status Source Source URL', `${L}: 2 timeline header`);
  const timeline = p.timeline as Array<{ when: string; status: string; source: string; url: string; text: string }>;
  for (const row of timeline) {
    f.contains(raw, row.when, `${L}: 2 ${row.when}`);
    f.contains(raw, row.text, `${L}: 2 ${row.when}: ${row.text.slice(0, 40)}`);
    f.contains(raw, join(row.status, row.source, row.url), `${L}: 2 ${row.when} cites ${row.url.slice(0, 50)}`);
  }
  f.inOrder(raw, timeline.map((row) => `${row.when} `), `${L}: 2 timeline in date order`);
  f.contains(raw, p.timeline_note, `${L}: 2 draft qualifier`);

  // 3. Target families
  const tf = p.target_family;
  f.contains(raw, 'Target family Primitive Occurrences Sources', `${L}: 3 header`);
  f.contains(raw, join(tf.family, tf.primitive, tf.occurrences, tf.sources), `${L}: 3 ML-KEM / ML-DSA family row`);

  // 4. Per-asset roadmap
  f.contains(raw, p.roadmap_group, `${L}: 4 group "${p.roadmap_group}"`);
  f.contains(raw, `# ${(p.roadmap_columns as string[]).join(' ')}`, `${L}: 4 column headers incl. Wave / Target date / Owner (assessor)`);
  for (const row of p.rows as any[]) {
    const scans: number[] = row.scans ?? [row.scan];
    const dates = scans.map((id) => scanDate(w.seed, id)).sort();
    const seen = scans.length > 1 ? `${dates[0]} to ${dates[dates.length - 1]} ${scans.length} scans` : `${dates[0]} 1 scan`;
    f.contains(
      raw,
      join(
        row.n, row.algorithm, row.key, row.strength, row.qsl, tf.family, row.legacy ? p.legacy_target : p.sized_target, row.impact,
        exp.scan_sources[String(row.scan)], row.path, seen,
      ),
      `${L}: 4 row ${row.n} ${row.algorithm} (${row.legacy ? 'legacy' : 'current'} scan #${row.scan})`,
    ); // fmt: skip
  }
  f.contains(raw, p.note_order, `${L}: 4 "not a migration sequence" note`);
  f.contains(raw, p.note_manual, `${L}: 6 manual columns note`);

  // 5. Already quantum-safe and hybrid
  f.contains(raw, 'NIST quantum security level Occurrences Of which hybrid', `${L}: 5 header`);
  let safe = 0;
  let hybrid = 0;
  for (const [level, v] of Object.entries(ab.qsl as Record<string, { occurrences: number; hybrid: number }>)) {
    const name = level === 'none' ? 'Not recorded' : `Level ${level}`;
    f.contains(raw, join(name, v.occurrences, v.hybrid), `${L}: 5 ${name} = ${v.occurrences} (hybrid ${v.hybrid})`);
    safe += v.occurrences;
    hybrid += v.hybrid;
  }
  f.contains(raw, join(p.qsl_total_row, safe, hybrid), `${L}: 5 total quantum-safe = ${safe}`);
  f.equal(safe, ab.safe, `${L}: 5 QSL table adds up to the quantum-safe count`);
}

// ---------------------------------------------------------------------------------------------
// #16 Board / IT Strategy Committee Regulatory & Executive Report
// ---------------------------------------------------------------------------------------------
export function checkBoard(doc: DocInput, w: World, meta: DocMeta, f: Findings): void {
  const exp = w.exp;
  const b = exp.board;
  const ab = exp.appendix_b;
  const L = '#16';
  const raw = doc.raw;
  headingsInOrder(bodyLines(doc), b.sections, f, `${L} sections`);

  // 1. Executive summary
  const issues = ab.issue.Critical + ab.issue.High + ab.issue.Medium;
  f.contains(
    raw,
    join(
      'Posture grade', ab.risk.grade, 'Risk score', ab.risk.score, b.grade_label, 'Crypto assets', ab.occurrences,
      'current occurrences across all sources', 'Issue assets', issues, `Critical ${ab.issue.Critical} · High ${ab.issue.High} · Medium ${ab.issue.Medium} · Low 0`,
      'Sources', ab.sources, 'repositories and uploads assessed', 'Scans included', ab.included, `of ${ab.eligible} eligible completed scans`,
      'Unique certificates', ab.cert_unique, 'de-duplicated across sources', 'Quantum readiness', `${ab.readiness}%`,
      `${ab.qv} of ${ab.qv + ab.safe} algorithm occurrences quantum-vulnerable`,
    ),
    `${L}: 1 KPI cards`,
  ); // fmt: skip
  f.contains(
    raw,
    `Across ${ab.sources} sources and ${ab.included} completed scans, the platform inventoried ${ab.occurrences} cryptographic asset occurrences. ` +
      `Findings were raised on ${issues} of them: Critical ${ab.issue.Critical}, High ${ab.issue.High}, Medium ${ab.issue.Medium}, Low 0.`,
    `${L}: 1 summary sentence`,
  );
  f.contains(raw, `Posture grade ${ab.risk.grade} (${b.grade_label}, score ${ab.risk.score} of 100) is computed from the issue assets only. ${b.grade_note}`, `${L}: 1 grade sentence`);
  f.contains(
    raw,
    `Quantum readiness is ${ab.readiness}%: ${ab.qv} of ${ab.qv + ab.safe} gradeable algorithm occurrences use quantum-vulnerable public-key cryptography. ` +
      `${ab.bands.EXPIRED} certificate has expired and ${ab.bands.LE_30 + ab.bands.LE_90} expires within 90 days.`,
    `${L}: 1 quantum / expiry sentence`,
  );

  // 2. Material risks (top 10)
  const top = b.top_risk_first;
  f.contains(raw, '# Asset Source / location Impact Finding First seen', `${L}: 2 table header`);
  f.contains(
    raw,
    join(1, top.asset, 'Certificate', exp.scan_sources['3'], top.asset, top.impact, ...top.findings, scanDate(w.seed, 3)),
    `${L}: 2 row 1 is the only Critical asset (${top.asset}), first seen ${scanDate(w.seed, 3)}`,
  );
  f.contains(
    raw,
    join('expired.crt', 'Certificate', exp.scan_sources['6'], 'expired.crt', 'High', 'Expired certificate', 'Self-signed leaf certificate', scanDate(w.seed, 6)),
    `${L}: 2 expired.crt is in the top 10 with both findings`,
  );
  f.contains(raw, b.top_risk_count_line, `${L}: 2 "Top 10 of ${issues} issue assets" line`);
  const topText = raw.slice(raw.indexOf('2. Material risks'), raw.indexOf('3. Quantum readiness'));
  const rowNumbers = [...topText.matchAll(/^(\d+) \S/gm)].map((m) => Number(m[1])).filter((n) => n >= 1 && n <= 10);
  f.equal(rowNumbers, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], `${L}: 2 exactly ten numbered rows`);
  const rank: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  const impacts = [...topText.matchAll(/^(Critical|High|Medium|Low) [A-Z]/gm)].map((m) => m[1]);
  f.check(impacts.length === 10 && impacts.every((v, i) => i === 0 || rank[v] >= rank[impacts[i - 1]]), `${L}: 2 ten impact cells, never increasing down the table`, impacts.join(','));

  // 3. Quantum readiness
  f.contains(
    raw,
    join('Readiness', `${ab.readiness}%`, 'share of gradeable algorithm occurrences', 'Quantum-vulnerable', ab.qv, 'public-key occurrences to migrate', 'Quantum-safe', ab.safe, `of which ${exp.pqc.kpis.hybrid} hybrid`, 'Not gradeable', ab.not_gradeable, 'excluded from readiness'),
    `${L}: 3 readiness cards`,
  ); // fmt: skip

  // 4. Certificate and key-material posture
  f.contains(raw, 'Measure Count', `${L}: 4 header`);
  for (const row of b.certificate_posture_rows as Array<{ label: string; count: number }>) {
    f.contains(raw, `${row.label} ${row.count}`, `${L}: 4 ${row.label} = ${row.count}`);
  }
  f.contains(raw, `Validity is computed as of ${meta.asOf} (the report date) from each certificate's notAfter date`, `${L}: 4 validity as-of sentence`);

  // 5. Regulatory exposure
  f.contains(raw, b.regulatory_pooled_line, `${L}: 5 pooled line`);
  f.contains(raw, 'Framework Coverage Pass Fail Not evidenceable Out of scope Sources pooled', `${L}: 5 header`);
  const labels: Record<string, string> = Object.fromEntries((exp.frameworks as any[]).map((x) => [x.key, x.label]));
  for (const [key, c] of Object.entries(ab.compliance as Record<string, any>)) {
    const target = key === exp.attestation.framework && w.attested;
    const pwe = target ? c.pass_with_evidence + 1 : c.pass_with_evidence;
    const nbe = target ? c.nbe - 1 : c.nbe;
    const passed = c.pass + pwe;
    const coverage = Math.round((passed / (passed + c.fail)) * 1000) / 1000;
    f.contains(raw, join(labels[key], pct(coverage), passed, c.fail, nbe, c.oos, ab.pooled), `${L}: 5 ${labels[key]} row`);
  }
  f.inOrder(raw, (exp.frameworks as any[]).map((x) => `${x.label} `), `${L}: 5 frameworks in registry order`);
  f.contains(raw, b.regulatory_note, `${L}: 5 RBI mapping note`);
  f.absent(raw, 'RBI Q-SAFE is', `${L}: 5 no RBI Q-SAFE claim`);

  // 6. Remediation priorities
  f.contains(raw, 'Finding Assets Highest impact Recommended action', `${L}: 6 header`);
  const remediation = b.remediation as Array<{ finding: string; assets: number; impact: string }>;
  for (const row of remediation) f.contains(raw, join(row.finding, row.assets, row.impact), `${L}: 6 ${row.finding} x${row.assets}`);
  f.inOrder(raw, remediation.map((row) => join(row.finding, row.assets, row.impact)), `${L}: 6 ordered by impact, then number of assets`);

  // 7. PQC roadmap summary
  const pr = b.pqc_summary_row;
  f.contains(raw, join('Target family Occurrences Sources', pr.family, pr.occurrences, pr.sources), `${L}: 7 target family row`);
  f.contains(raw, exp.pqc.timeline_note, `${L}: 7 draft qualifier`);

  // 8. Governance actions: live metrics, blank owner / due / decision
  f.contains(raw, 'Action Live metric Owner (assessor) Due (assessor) Decision (assessor)', `${L}: 8 header with the three manual columns`);
  for (const row of b.governance as Array<{ action: string; metric: string }>) f.contains(raw, join(row.action, row.metric), `${L}: 8 ${row.metric}`);

  // 9. Sign-off and appendices
  f.inOrder(raw.slice(raw.indexOf('9. Sign-off')), b.sign_off_rows, `${L}: 9 sign-off roles`);
  f.contains(raw, b.grade_formula, `${L}: App. A formula`);
  f.contains(
    raw,
    join('Critical', ab.issue.Critical, 10, ab.issue.Critical * 10, 'High', ab.issue.High, 5, ab.issue.High * 5, 'Medium', ab.issue.Medium, 2, ab.issue.Medium * 2, 'Low 0 1 0'),
    `${L}: App. A points table`,
  );
  f.contains(raw, b.grade_result, `${L}: App. A result`);
  f.contains(raw, 'Scan Source Scanned (UTC) Fidelity Role', `${L}: App. B header`);
  for (const src of sourcesOf(w)) {
    for (const id of src.scans) {
      f.contains(
        raw,
        join(`#${id}`, src.label, scanDate(w.seed, id), src.fidelity === 'LEGACY' ? 'Legacy format' : 'Full', id === src.current ? 'Current' : 'History'),
        `${L}: App. B scan #${id}`,
      );
    }
  }
}
