/**
 * What the import of an uploaded CBOM file left out (scan metadata ``cbom_input``), as the sentences the results page
 * card and the scan sidebar show. An upload that imported nothing (for example a CycloneDX 1.5 file, which has no
 * cryptographic-asset type) finished with "Scan has run successfully" and zero findings in the sidebar, the engine's
 * explanation only on the results page; a re-uploaded CBOM silently lost its library components because the card
 * stayed hidden without a note (lab UI run u2, round 5).
 */
import type { CbomImportReport } from "@/utils/api/cbom_outputs";

export function notCryptoNote(n: number): string {
  return `${n} component(s) of the file are not cryptographic assets (for example libraries or applications) and were ` +
    "not judged here: a library's known vulnerabilities come from a code scan or the dependency scan.";
}

/** The card shows whenever the import left something out, not only when the engine wrote a note. */
export function importReportHasNews(r: CbomImportReport | null | undefined): boolean {
  if (!r) return false;
  return (r.notes ?? []).length > 0 || (r.skipped_not_crypto ?? 0) > 0 || (r.skipped_invalid ?? 0) > 0 ||
    (r.duplicates ?? 0) > 0 || r.truncated === true || (r.imported ?? 0) === 0;
}

/** The engine's notes, then the sentence about components that are not cryptographic assets. */
export function importNoteLines(r: CbomImportReport | null | undefined): string[] {
  if (!r) return [];
  const lines = [...(r.notes ?? [])];
  if ((r.skipped_not_crypto ?? 0) > 0) lines.push(notCryptoNote(r.skipped_not_crypto ?? 0));
  return lines;
}

/** One line for the sidebar after the run: how many cryptographic assets the file gave. */
export function importHeadline(r: CbomImportReport): string {
  const imported = r.imported ?? 0;
  if (imported === 0) return "No cryptographic assets were imported from the uploaded file, so there are no findings.";
  return `${imported} of ${r.crypto_assets ?? imported} cryptographic assets were imported from the uploaded file.`;
}
