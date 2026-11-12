"use client";

import { useMemo, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Download, Search } from "lucide-react";
import {
  inventoryRowsFromCycloneDx,
  overallComplianceFromBom,
  type SbomComplianceStatus,
  type SbomInventoryRow,
} from "@/utils/sbomInventory";

const COLUMNS: { key: keyof SbomInventoryRow; label: string; className: string }[] = [
  { key: "name", label: "Component name", className: "min-w-[180px] font-medium" },
  { key: "supplier", label: "Supplier", className: "min-w-[110px]" },
  { key: "version", label: "Version", className: "min-w-[110px]" },
  { key: "uniqueId", label: "License", className: "min-w-[120px]" },
  { key: "relationship", label: "Relationship", className: "min-w-[220px]" },
  { key: "subDependencies", label: "Sub dependencies", className: "min-w-[160px]" },
  { key: "subSubDependencies", label: "Sub-subdependencies", className: "min-w-[140px]" },
  { key: "author", label: "Author", className: "min-w-[100px]" },
  { key: "hash", label: "Hash", className: "min-w-[140px] font-mono" },
  { key: "cves", label: "Known vulnerabilities", className: "min-w-[160px]" },
  { key: "dateAdded", label: "Date added", className: "min-w-[90px]" },
];

function StatusBadge({ status }: { status: SbomComplianceStatus }) {
  if (status === "pass") {
    return (
      <Badge className="border-transparent bg-emerald-100 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300">
        Pass
      </Badge>
    );
  }
  if (status === "fail") {
    return (
      <Badge className="border-transparent bg-red-100 text-red-800 dark:bg-red-950/50 dark:text-red-300">
        Fail
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="text-zinc-600 dark:text-zinc-400">
      —
    </Badge>
  );
}

export default function SbomBillOfMaterialsTable({
  bom,
  onDownload,
}: {
  bom: unknown;
  onDownload?: () => void;
}) {
  const [query, setQuery] = useState("");
  const rows = useMemo(() => inventoryRowsFromCycloneDx(bom), [bom]);
  const overall = useMemo(() => overallComplianceFromBom(bom), [bom]);
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter((row) =>
      [row.name, row.supplier, row.version, row.uniqueId, row.cves, row.relationship, row.author]
        .join(" ")
        .toLowerCase()
        .includes(q),
    );
  }, [rows, query]);

  if (!rows.length) return null;

  return (
    <Card data-testid="sbom-bill-of-materials">
      <CardHeader className="gap-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle>Software bill of materials</CardTitle>
            <CardDescription className="mt-1 max-w-3xl">
              One row per unique component and version. GitHub Actions that pin a tag
              and a commit appear as two rows. Document status is a single Pass/Fail
              verdict. RBI, SEBI, and CERT-In detail stays in the dashboard and PDF.
            </CardDescription>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={overall} />
            {onDownload ? (
              <Button
                type="button"
                variant="outline"
                className="cursor-pointer"
                onClick={onDownload}
                data-testid="sbom-download-cyclonedx"
              >
                <Download className="mr-2 h-4 w-4" />
                Download CycloneDX
              </Button>
            ) : null}
          </div>
        </div>
        <div className="relative max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400" />
          <Input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search components, licenses, CVEs..."
            className="h-9 cursor-text pl-9"
            aria-label="Search software bill of materials"
          />
        </div>
      </CardHeader>
      <CardContent>
        <ScrollArea className="w-full rounded-md border border-zinc-200 dark:border-zinc-800">
          <Table>
            <TableHeader>
              <TableRow className="bg-blue-50 hover:bg-blue-50 dark:bg-blue-950/40 dark:hover:bg-blue-950/40">
                {COLUMNS.map((col) => (
                  <TableHead
                    key={col.key}
                    className={`${col.className} text-[11px] font-semibold uppercase tracking-wide text-blue-800 dark:text-blue-200`}
                  >
                    {col.label}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={COLUMNS.length} className="py-8 text-center text-zinc-500">
                    No components match this search
                  </TableCell>
                </TableRow>
              ) : (
                filtered.map((row) => (
                  <TableRow
                    key={`${row.name}@${row.version}`}
                    className="odd:bg-transparent even:bg-blue-50/40 dark:even:bg-blue-950/20"
                  >
                    {COLUMNS.map((col) => (
                      <TableCell
                        key={col.key}
                        className={`align-top text-xs text-zinc-800 dark:text-zinc-200 ${col.className}`}
                      >
                        {col.key === "cves" && row.cves !== "N/A" ? (
                          <span className="text-red-700 dark:text-red-300">{row.cves}</span>
                        ) : (
                          <span className="break-words">{row[col.key]}</span>
                        )}
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
          <ScrollBar orientation="horizontal" />
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
