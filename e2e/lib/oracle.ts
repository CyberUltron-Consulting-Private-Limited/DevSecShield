/**
 * The PDF oracle: what every team-wide CBOM deliverable must contain, checked against the TEXT of the
 * downloaded PDF (poppler), never against the DOM and never by recomputing with product code.
 *
 * Sources of truth (all independent of the aggregator and the renderers):
 *   - fixtures/expected.json   hand-/openssl-derived literals (plan Appendix B, openssl, public sources)
 *   - seed.json                the scans the seed stored: ids and created_at dates (a test INPUT)
 *   - openssl                  run on the certificate files in e2e/.work/trees for date-relative values
 *
 * `checkDocument` returns a `Findings` (all failures, not only the first). The same functions judge the
 * downloads of the real stack (specs/*.spec.ts) and the PDFs of the offline rehearsal
 * (selftest/oracle.spec.ts), so the oracle itself is exercised before the stack ever runs.
 *
 * Layout: oracle-core.ts (types, text helpers) <- oracle-docs.ts (one check per deliverable) <- this file
 * (checks every document has, dispatcher, empty-team variant).
 */
import { Findings, norm, textLines } from './expected';
import {
  allPresent, docMeta, isChromeFooter, istOf, worldDocs,
  type DocInput, type DocMeta, type World,
} from './oracle-core'; // fmt: skip
import { checkAssurance, checkBoard, checkCertificates, checkMethodology, checkPqc, checkScope } from './oracle-docs';

export type { DocInput, DocMeta, World } from './oracle-core';
export { docMeta } from './oracle-core';

const escapeRegExp = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Checks every document must satisfy: PDF metadata, the document-control block, the Basis box,
 * disclaimers, footer pagination, no foreign identity and no canary. Returns the parsed metadata.
 */
export function checkCommon(doc: DocInput, w: World, f: Findings): DocMeta | null {
  const exp = w.exp;
  const spec = worldDocs(exp)[doc.slug];
  const common = exp.common;
  const ab = exp.appendix_b;
  const label = `#${spec.number} common`;

  // --- PDF file level ---
  f.check(doc.info.magicOk, `${label}: %PDF- magic`);
  f.check(doc.info.fileSize > 3 * 1024, `${label}: size > 3 KB`, `${doc.info.fileSize} bytes`);
  f.check(
    doc.info.pages >= spec.min_pages && doc.info.pages <= spec.max_pages,
    `${label}: page count in [${spec.min_pages}, ${spec.max_pages}]`,
    `${doc.info.pages} pages`,
  );
  f.equal(doc.info.orientation, spec.orientation, `${label}: orientation`);
  f.equal(doc.info.title, `${spec.title} - ${common.team.name}`, `${label}: PDF Title`);
  f.equal(doc.info.author, common.tool, `${label}: PDF Author`);
  f.check(new RegExp(common.creator_re).test(doc.info.creator), `${label}: PDF Creator`, doc.info.creator);
  f.check(doc.info.keywords.includes('CBOM'), `${label}: PDF Keywords mention CBOM`, doc.info.keywords);
  const fontNames = [...new Set(doc.fonts.map((font) => font.name))];
  f.check(
    fontNames.every((name) => (common.fonts_allowed as string[]).includes(name)),
    `${label}: fonts are the built-in Helvetica/Courier set`,
    fontNames.join(', '),
  );

  // --- document-control block ---
  const meta = docMeta(doc.raw);
  if (!f.check(meta !== null, `${label}: document-control block parses (Document ID, Generated, fingerprint)`)) return null;
  const m = meta as DocMeta;
  f.equal(m.number, String(spec.number).padStart(2, '0'), `${label}: Document ID number`);
  f.equal(m.team, String(common.team.id), `${label}: Document ID team`);
  f.equal(m.idDate, m.asOf.replace(/-/g, ''), `${label}: Document ID date equals the Generated date`);
  f.equal(m.fp12.slice(0, 8), m.fp8, `${label}: Document ID suffix is the data fingerprint`);
  f.check(doc.info.subject.includes(m.docId), `${label}: PDF Subject carries the Document ID`, doc.info.subject);
  const hm = /(\d{2}:\d{2}) UTC \((\d{2}:\d{2}) IST\)/.exec(norm(doc.raw));
  if (hm) f.equal(hm[2], istOf(hm[1]), `${label}: IST is UTC+05:30`);
  const reference = w.reference ?? new Date();
  const skew = w.clockToleranceMinutes ?? (common.max_clock_skew_minutes as number);
  const delta = (reference.getTime() - Date.parse(`${m.generated}:00Z`)) / 60000;
  f.check(delta > -3 && delta < skew, `${label}: generated within ${skew} min of the download`, `${delta.toFixed(1)} min`);
  f.contains(doc.raw, `Team ${common.team.name} (ID ${common.team.id})`, `${label}: team line`);
  f.contains(doc.raw, `Template version ${common.template_line}`, `${label}: template version`);

  // --- data window: first to last folded scan (created_at values are a seed input) ---
  const dates = Object.keys(exp.rows_per_scan as Record<string, number>)
    .map((id) => w.seed.scans[id].created_at.slice(0, 10))
    .sort();
  f.contains(
    doc.raw,
    `Data window ${dates[0]} to ${dates[dates.length - 1]} (UTC)`,
    `${label}: data window = first to last folded scan`,
  );

  // --- Basis box (template of plan 5.4 filled with the Appendix-B numbers) ---
  const ex = ab.excluded;
  f.contains(
    doc.raw,
    `Scans: ${ab.included} included of ${ab.eligible} eligible · excluded: ${ex.failure} failed, ${ex.not_completed} not completed, ${ex.no_data} without data`,
    `${label}: Basis - scans line`,
  );
  f.contains(
    doc.raw,
    `Sources: ${ab.sources} · Fidelity: ${ab.included - ab.legacy} full / ${ab.legacy} legacy-format · History: ${ab.included} scans folded`,
    `${label}: Basis - sources / fidelity line`,
  );
  f.contains(doc.raw, common.basis_rule, `${label}: Basis - rule line`);
  const postureMethod =
    'Method: analysis of declared configuration in repositories and uploaded artefacts (infrastructure-as-code, container and cluster definitions, server and database configuration) and offline import of result files that the customer\'s own tools produced. The platform does not probe any endpoint, call any cloud API, inspect a KMS or HSM, or inspect stored data. A declared setting is not proof that it is in operation.';
  const postureSlug =
    doc.slug === 'infrastructure-cloud-encryption-posture' ||
    doc.slug === 'network-tls-protocol-assessment' ||
    doc.slug === 'data-at-rest-encryption-assessment';
  const disclaimers = postureSlug
    ? [...(common.disclaimers as string[]).slice(0, 2), postureMethod]
    : (common.disclaimers as string[]);
  for (const sentence of disclaimers) f.contains(doc.raw, sentence, `${label}: disclaimer sentence`);
  f.contains(doc.raw, common.manual_legend, `${label}: manual-cell legend`);

  // --- brand footer with page number on every page ---
  const footers = doc.pages.map((page) => textLines(page).find(isChromeFooter) ?? '');
  f.check(
    footers.every((line, index) => line === `${spec.header_label} · Confidential Page ${index + 1}`),
    `${label}: every page carries "${spec.header_label} · Confidential Page N"`,
    JSON.stringify(footers.slice(0, 3)),
  );

  // --- nothing from other scans, nothing foreign ---
  for (const token of exp.forbidden.canaries as string[]) f.absent(doc.raw, token, `${label}: canary absent: ${token}`);
  // Exact phrases, not squashed: the disclaimer legitimately says "AIBOM".
  const text = norm(doc.raw);
  for (const token of exp.forbidden.foreign_identity as string[]) {
    const pattern = new RegExp(escapeRegExp(token), token === 'clinithread' ? 'i' : '');
    f.check(!pattern.test(text), `${label}: no "${token}"`);
  }
  for (const word of exp.forbidden.bare_words as string[]) {
    f.check(!new RegExp(`\\b${word}\\b`).test(text), `${label}: no bare "${word}"`);
  }
  return m;
}

/** The document-specific checks on top of the common ones. */
export function checkDocument(doc: DocInput, w: World): Findings {
  const f = new Findings();
  const meta = checkCommon(doc, w, f);
  if (!meta) return f;
  switch (doc.slug) {
    case 'scope-baseline-register':
      checkScope(doc, w, meta, f);
      break;
    case 'methodology-evidence-plan':
      checkMethodology(doc, w, meta, f);
      break;
    case 'certificate-estate-register':
      checkCertificates(doc, w, meta, f);
      break;
    case 'third-party-assurance-register':
      checkAssurance(doc, w, meta, f);
      break;
    case 'pqc-migration-roadmap':
      checkPqc(doc, w, meta, f);
      break;
    case 'board-executive-report':
      checkBoard(doc, w, meta, f);
      break;
    case 'infrastructure-cloud-encryption-posture':
      f.contains(doc.raw, 'declared configuration is not proof of operation', '#5 limit sentence');
      break;
    case 'network-tls-protocol-assessment':
      f.contains(doc.raw, 'The platform did not probe any endpoint', '#6 no live probe');
      break;
    case 'data-at-rest-encryption-assessment':
      f.contains(doc.raw, 'stored data was not inspected', '#9 stored data not inspected');
      break;
    default:
      f.check(false, `unknown deliverable slug ${doc.slug}`);
  }
  return f;
}

/** The empty-team variant: banner, zero counts, no grade, nothing from any other team. */
export function checkEmptyDocument(doc: DocInput, w: World): Findings {
  const f = new Findings();
  const exp = w.exp;
  const empty = exp.empty_team;
  const spec = worldDocs(exp)[doc.slug];
  const label = `#${spec.number} empty team`;
  f.contains(doc.raw, empty.banner, `${label}: banner "${empty.banner}"`);
  f.contains(doc.raw, empty.banner_text, `${label}: banner explanation`);
  f.contains(doc.raw, empty.basis_line, `${label}: Basis shows zero scans`);
  f.contains(doc.raw, empty.data_window, `${label}: no data window`);
  f.contains(doc.raw, `Team ${empty.team.name} (ID ${empty.team.id})`, `${label}: team line`);
  allPresent(f, doc.raw, empty.per_document[doc.slug] as string[], label);
  f.check(doc.info.magicOk && doc.info.pages >= 2, `${label}: a real PDF with pages`, `${doc.info.pages} pages`);
  f.equal(doc.info.orientation, spec.orientation, `${label}: orientation`);
  for (const token of exp.forbidden.canaries as string[]) f.absent(doc.raw, token, `${label}: canary absent: ${token}`);
  for (const token of ['E2E Demo Team', 'payments-service', 'identity-gateway', 'rsa1024_sha1.pem']) {
    f.absent(doc.raw, token, `${label}: nothing from team 1: ${token}`);
  }
  if (doc.slug === 'board-executive-report') {
    for (const token of empty.board_forbidden as string[]) f.absent(doc.raw, token, `${label}: no ${token}`);
  }
  const fontNames = [...new Set(doc.fonts.map((font) => font.name))];
  f.check(
    fontNames.every((name) => (exp.common.fonts_allowed as string[]).includes(name)),
    `${label}: fonts`,
    fontNames.join(', '),
  );
  return f;
}
