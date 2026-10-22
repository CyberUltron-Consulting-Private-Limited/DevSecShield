/**
 * 91 - an uploaded attestation moves the #10 ledger from "Attested 0/5" to "Attested 1/5".
 *
 *   npx playwright test specs/91-attestation-before-after.spec.ts
 *
 * Before: the Third-Party Assurance Register is downloaded through the UI; every one of its 48 ledger rows
 * reads "Attested 0/n" and the summary box says 0 of 207 source-level attestations.
 * Action: the evidence for OMB-3 ("Agency PQC migration plan submitted to OMB") is uploaded to scan #2, the
 *         current scan of payments-service, through the CERT-In attestation endpoint the results page uses.
 * After:  the register is downloaded again: OMB-3 reads "Attested 1/5" followed by the file name, the note and
 *         the upload date; "Partly attested" is 1; the summary says 1 of 207 (0.5%). The pooled compliance of
 *         the methodology (#3) and the board report (#16) moves with it: OMB M-23-02 coverage 80.0% -> 81.8%,
 *         one requirement from "not evidenceable" to "pass with evidence".
 * Identity: the upload route rewrites scan_data but never touches Scan.last_updated, so the data fingerprint also
 *         hashes the attestation records of the included scans (addendum A-2). The X-Cbom-Fingerprint header and
 *         the Document ID suffix of #10 (CBOM-D10-T<team>-<date>-<fingerprint[:8]>) therefore CHANGE with the
 *         upload, as the methodology (#3, section 9) says; the deliverable number and the team stay the same.
 *
 * THIS SPEC CHANGES THE SEEDED DATA of scan #2 (the product stores the flipped verdict and offers no way
 * back: DELETE .../attestations removes the record but leaves the verdict at "pass with evidence").
 * It therefore runs after every content check (files sort 00 .. 91) and refuses to run twice on the same seed:
 * reseed (scripts/teardown.sh, up.sh, seed.sh) to repeat it.
 */
import { expect, test } from '../fixtures';
import { apiGet, bodyJson } from '../lib/api';
import { pdfFonts, pdfInfo, pdfPageTexts, pdfText, recordPdfEvidence, saveDownload } from '../lib/evidence';
import { loadExpected } from '../lib/expected';
import { checkDocument, docMeta } from '../lib/oracle';
import { API_URL, WORK_DIR, evidencePath } from '../lib/paths';
import { closeMenu, downloadViaMenu, openLanding, openMenu } from '../lib/ui';
import { showPdf, writeViewer } from '../lib/viewer';
import { makeWorld } from '../lib/world';
import { expectNoFindings } from '../lib/flow';
import * as fs from 'node:fs';

test('91 attestation before / after for #10 (and the pooled compliance of #3 and #16)', async ({
  authedPage: page,
  kit,
  seed,
  request,
  personaTokens,
}) => {
  test.setTimeout(420_000);
  const exp = loadExpected();
  const spec = exp.attestation;
  const team = seed.teams.demo!.id;
  const slug = 'third-party-assurance-register';
  const tokens = await personaTokens('admin');
  const auth = { Authorization: `Bearer ${tokens.access}` };

  await test.step('precondition: scan #2 carries no attestation yet (reseed to repeat this spec)', async () => {
    const res = await apiGet(request, `/${team}/cbom/scan/${spec.scan}/attestations`, { token: tokens.access });
    expect(res.status).toBe(200);
    expect(bodyJson(res), 'scan #2 already has attestations: this spec changes the data once per seed. Run teardown.sh, up.sh and seed.sh again.').toEqual({ attestations: {} });
  });

  async function downloadLedger(label: 'before' | 'after') {
    await openLanding(page, team);
    await openMenu(page);
    const { download, api } = await downloadViaMenu(page, team, slug);
    expect(api.status).toBe(200);
    await expect(page.getByText(`Downloaded ${exp.documents[slug].title}`).first()).toBeVisible();
    await kit.shot(page, `ledger-${label}-downloaded`);
    const saved = await saveDownload(download, `91-ledger-${label}.pdf`);
    const evidence = recordPdfEvidence(saved.path, `91-${label}`, 'ledger');
    await closeMenu(page).catch(() => undefined);
    return { saved, evidence, fingerprint: api.headers['x-cbom-fingerprint'], doc: { slug, raw: evidence.raw, pages: evidence.pages, info: evidence.info, fonts: evidence.fonts } };
  }

  const before = await test.step('BEFORE: download #10 and judge it (all 48 rows "Attested 0/n")', async () => {
    const result = await downloadLedger('before');
    expectNoFindings(checkDocument(result.doc, makeWorld({ seed, workDir: WORK_DIR })), '#10 before the upload');
    return result;
  });

  const uploaded = await test.step(`UPLOAD the evidence for ${spec.framework_label} ${spec.requirement_id} to scan #${spec.scan}`, async () => {
    const response = await request.post(`${API_URL}/${team}/cbom/scan/${spec.scan}/attestations`, {
      headers: auth,
      multipart: {
        framework: spec.framework,
        requirement_id: spec.requirement_id,
        note: spec.note,
        file: { name: spec.filename, mimeType: 'text/plain', buffer: Buffer.from(`${spec.note}\nexported by the dss-e2e harness\n`) },
      },
    });
    expect(response.status(), await response.text()).toBe(200);
    const body = (await response.json()) as { attestations: Record<string, Record<string, { filename: string; note: string; uploaded_at: string }>>; compliance: Record<string, { pass_with_evidence: number; not_bom_evidenceable: number }> };
    const record = body.attestations[spec.framework][spec.requirement_id];
    expect(record).toMatchObject({ filename: spec.filename, note: spec.note });
    expect(record.uploaded_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(body.compliance[spec.framework].pass_with_evidence, 'the verdict flipped to pass-with-evidence').toBe(1);
    kit.log('attestation-upload.json', { framework: spec.framework, requirement_id: spec.requirement_id, scan: spec.scan, record, compliance_after: body.compliance[spec.framework] });
    return record;
  });

  const world = makeWorld({ seed, workDir: WORK_DIR, attested: true, attestedDate: uploaded.uploaded_at.slice(0, 10) });
  const after = await test.step('AFTER: download #10 again and judge it (OMB-3 "Attested 1/5" with file, note, date)', async () => {
    const result = await downloadLedger('after');
    expectNoFindings(checkDocument(result.doc, world), '#10 after the upload');
    return result;
  });

  // The upload route never touches Scan.last_updated; the fingerprint hashes the attestation records themselves
  // (addendum A-2), so the identity of the document moves with its content.
  const idBefore = docMeta(before.doc.raw);
  const idAfter = docMeta(after.doc.raw);
  const fingerprintChanged = before.fingerprint !== after.fingerprint;

  await test.step('the data fingerprint moved with the upload: the Document ID suffix of #10 changed', async () => {
    // soft: a failure here must not cost the recorded ledger pages or the pooled-compliance checks below
    expect.soft(fingerprintChanged, `X-Cbom-Fingerprint before ${before.fingerprint}, after ${after.fingerprint}`).toBe(true);
    expect.soft(idBefore, 'the Document ID block of the BEFORE pdf parses').not.toBeNull();
    expect.soft(idAfter, 'the Document ID block of the AFTER pdf parses').not.toBeNull();
    // each PDF prints the fingerprint its response header announced ...
    expect.soft(idBefore?.fp12, 'fingerprint printed in the BEFORE pdf equals its X-Cbom-Fingerprint').toBe(before.fingerprint);
    expect.soft(idAfter?.fp12, 'fingerprint printed in the AFTER pdf equals its X-Cbom-Fingerprint').toBe(after.fingerprint);
    // ... so the Document ID suffix changed, while the deliverable number and the team did not
    expect.soft(idAfter?.docId, `Document ID ${idBefore?.docId} -> ${idAfter?.docId}`).not.toBe(idBefore?.docId);
    expect.soft(idAfter?.fp8, 'Document ID suffix (first 8 hex of the data fingerprint)').not.toBe(idBefore?.fp8);
    expect.soft(idAfter?.number, 'deliverable number in the Document ID').toBe(idBefore?.number);
    expect.soft(idAfter?.team, 'team in the Document ID').toBe(idBefore?.team);
  });

  await test.step('the pooled compliance of #3 and #16 moved with it (OMB M-23-02 80.0% -> 81.8%)', async () => {
    for (const other of ['methodology-evidence-plan', 'board-executive-report']) {
      const res = await apiGet(request, `/${team}/cbom/deliverables/${other}`, { token: tokens.access });
      expect(res.status).toBe(200);
      const file = evidencePath('downloads', `91-${other}-after.pdf`);
      fs.writeFileSync(file, res.body);
      const doc = { slug: other, raw: pdfText(file), pages: pdfPageTexts(file), info: pdfInfo(file), fonts: pdfFonts(file).fonts };
      expectNoFindings(checkDocument(doc, world), `${other} after the upload`);
      await page.waitForTimeout(1500);
    }
  });

  await test.step('show the ledger page of both PDFs in the recorded page', async () => {
    for (const [label, run] of [['before', before], ['after', after]] as const) {
      const at = run.doc.pages.findIndex((text) => text.replace(/\s+/g, '').includes('OMB-3'));
      const viewer = writeViewer({
        number: `91-${label}`,
        title: `#10 ledger ${label.toUpperCase()} the attestation upload`,
        subtitle: `${run.saved.suggestedFilename} · sha256 ${run.saved.sha256.slice(0, 16)}… · OMB-3 on page ${at + 1}`,
        pages: run.evidence.png,
      });
      await showPdf(page, viewer, { stops: [at + 1, run.evidence.info.pages], onStop: async (n) => void (await kit.shot(page, `ledger-${label}-pdf-p${n}`)), goBack: false });
    }
  });

  kit.log('attestation-summary.json', {
    scan: spec.scan,
    requirement: `${spec.framework}/${spec.requirement_id}`,
    uploaded,
    fingerprint_before: before.fingerprint,
    fingerprint_after: after.fingerprint,
    fingerprint_changed: fingerprintChanged,
    document_id_before: idBefore?.docId ?? null,
    document_id_after: idAfter?.docId ?? null,
  });
  test.info().annotations.push({
    type: 'observation',
    description: `data fingerprint ${before.fingerprint} -> ${after.fingerprint}; #10 Document ID ${idBefore?.docId} -> ${idAfter?.docId}`,
  });
});
