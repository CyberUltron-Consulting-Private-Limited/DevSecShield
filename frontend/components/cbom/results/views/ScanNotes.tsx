"use client";

// "About the uploaded CBOM file" and "What this scan covered": the notes a code scan shows under its header and a run
// shows in its run status area (from /parity's scan_metadata). One component each, so both modes render the same
// markup (code mode is pinned by codeModeUnchanged.test.ts).

import { AlertTriangle } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { InfoTip } from "@/components/ui/info-tip";
import type { CbomCoverageReport, CbomImportReport } from "@/utils/api/cbom_outputs";
import { importNoteLines, importReportHasNews } from "@/components/cbom/importNotes";

export function ImportNotesCard({ report }: { report: CbomImportReport | null }) {
  if (!report || !importReportHasNews(report)) return null;
  return (
    <Card className="mb-6 border-amber-300 dark:border-amber-700 bg-amber-50/60 dark:bg-amber-950/20" role="alert" data-testid="cbom-import-notes">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center gap-2 text-amber-800 dark:text-amber-300">
          <AlertTriangle className="h-4 w-4 shrink-0" /> About the uploaded CBOM file
        <InfoTip id="cbom.res.import_notes" />
        </CardTitle>
        <CardDescription className="text-amber-900/80 dark:text-amber-200/80">
          {report.imported ?? 0} of {report.crypto_assets ?? 0} cryptographic assets imported
          {report.spec_version ? ` · CycloneDX ${report.spec_version}` : ""}
          {report.skipped_not_crypto ? ` · ${report.skipped_not_crypto} non-crypto components skipped` : ""}
          {report.skipped_invalid ? ` · ${report.skipped_invalid} unreadable` : ""}
          {report.duplicates ? ` · ${report.duplicates} duplicates` : ""}
          {report.truncated ? " · truncated" : ""}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="list-disc pl-5 space-y-1 text-sm text-amber-900 dark:text-amber-200 break-words">
          {importNoteLines(report).map((note, i) => <li key={i}>{note}</li>)}
        </ul>
      </CardContent>
    </Card>
  );
}

export function CoverageNotesCard({ report }: { report: CbomCoverageReport | null }) {
  if (!report || report.notes.length === 0) return null;
  return (
    <Card className={`mb-6 ${report.skipped > 0 ? "border-amber-300 dark:border-amber-700 bg-amber-50/60 dark:bg-amber-950/20" : "border-zinc-200 dark:border-zinc-800"}`}
      role={report.skipped > 0 ? "alert" : undefined} data-testid="cbom-coverage-notes">
      <CardHeader className="pb-2">
        <CardTitle className={`text-sm flex items-center gap-2 ${report.skipped > 0 ? "text-amber-800 dark:text-amber-300" : "text-zinc-800 dark:text-zinc-200"}`}>
          <AlertTriangle className="h-4 w-4 shrink-0" /> What this scan covered
        <InfoTip id="cbom.res.coverage" />
        </CardTitle>
        <CardDescription className={report.skipped > 0 ? "text-amber-900/80 dark:text-amber-200/80" : undefined}>
          {report.skipped > 0
            ? `${report.skipped} kind(s) of input were skipped or only partly read; the CycloneDX file lists the same counts (crypto:coverage:*).`
            : "Nothing was skipped; these notes say what was read and are also in the CycloneDX file (crypto:coverage:*)."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="list-disc pl-5 space-y-1 text-sm break-words">
          {report.notes.map((note) => (
            <li key={note.key} className={note.kind === "skipped" ? "text-amber-900 dark:text-amber-200" : "text-zinc-700 dark:text-zinc-300"}>
              {note.text}
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
