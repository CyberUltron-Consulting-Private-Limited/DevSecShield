/** The certificates one code scan found (staging QA N1): the scan's own rows, never the team's estate. */

export interface ScanCertificateRow {
  title?: string | null;
  algorithm_name?: string | null;
  algorithm_type?: string | null;
  asset_type?: string | null;
  location?: string | null;
  line?: number | null;
  not_valid_after?: string | null;
  expired?: boolean | null;
  self_signed?: boolean | null;
}

/** The rows of a code scan that are certificates (the dashboard's "Certificates" count reads the same type). */
export function scanCertificates(rows: unknown[]): ScanCertificateRow[] {
  return rows.filter((r): r is ScanCertificateRow => {
    if (!r || typeof r !== "object" || Array.isArray(r)) return false;
    const row = r as ScanCertificateRow;
    return row.algorithm_type === "certificate" || row.asset_type === "certificate";
  });
}

/** Where the team's whole certificate estate (orphaned and unmanaged) is shown: the CBOM dashboard. */
export function teamCertificatesHref(teamId: number): string {
  return `/${teamId}/cbom`;
}
