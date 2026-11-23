/**
 * FIX-C1 (SOW D4, audit G-D4-5): which rows the "Software bill of materials" table shows.
 * The table used to open on "Vulnerable only", so an SBOM with no known vulnerability looked empty ("No components
 * match this search" for a 5-component BOM). It now opens on every component, with the filter visible next to it.
 */
import type { SbomInventoryRow } from "@/utils/sbomInventory";

export type BomView = "all" | "vulnerable";
export const DEFAULT_BOM_VIEW: BomView = "all";

const NO_VULN = new Set(["None", "N/A", "—"]);

export function isVulnerableRow(row: Pick<SbomInventoryRow, "cves">): boolean {
  return !NO_VULN.has(row.cves);
}

export function filterBomRows<T extends SbomInventoryRow>(rows: T[], query: string, view: BomView): T[] {
  const q = query.trim().toLowerCase();
  return rows.filter((row) => {
    if (view === "vulnerable" && !isVulnerableRow(row)) return false;
    if (!q) return true;
    return [row.name, row.supplier, row.version, row.uniqueId, row.cves, row.relationship, row.author]
      .join(" ")
      .toLowerCase()
      .includes(q);
  });
}

/** The empty-table message says why nothing shows, instead of a bare "No components match". */
export function emptyBomMessage(view: BomView, query: string, total: number): string {
  if (query.trim()) return "No components match this search";
  if (view === "vulnerable" && total > 0) return `None of the ${total} components has a known vulnerability`;
  return "No components";
}
