"use client";

// S0 of the Sources run results page: the same header as the code-scan page (back button, large title, origin line,
// export buttons) for a run: "Sources run #N", status, started / finished, credits, sources, linked scan, the run's
// CycloneDX JSON / XML and OSCAL downloads, Compare… and Open in CBOM Sources. Below 1024 px the downloads collapse
// into one "Downloads" menu (PLAN §4.5); only one of the two variants is in the DOM, so the test ids stay unique.

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowLeft, ChevronDown, Download, GitCompare, Loader2, Network, ShieldCheck, SlidersHorizontal } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { downloadCbomRunCbom, type CbomRun } from "@/utils/backend_api";
import { downloadCbomRunBom } from "@/utils/api/cbom_outputs";
import { downloadOscal } from "@/utils/api/integrations";

import { credits, formatDateTime } from "@/components/cbom/sources/logic";
import { RunStatusBadge } from "@/components/cbom/sources/shared";

import { isActiveRunStatus, runTitle } from "./model";

const LG = 1024;

/** true at ≥ 1024 px; true before the first measurement (server render) so the desktop row renders first. */
function useWideHeader(): boolean {
  const [wide, setWide] = useState(true);
  useEffect(() => {
    const mql = window.matchMedia(`(min-width: ${LG}px)`);
    const onChange = () => setWide(mql.matches);
    onChange();
    mql.addEventListener("change", onChange);
    return () => mql.removeEventListener("change", onChange);
  }, []);
  return wide;
}

export function RunHeader({ teamId, run, sources, assetTotal, canCompare, onCompare }: {
  teamId: number;
  run: CbomRun;
  sources: { id: number | null; name: string }[];
  /** every asset of the run (the API's all_total); null while unknown */
  assetTotal: number | null;
  canCompare: boolean;
  onCompare: () => void;
}) {
  const router = useRouter();
  const wide = useWideHeader();
  const [downloading, setDownloading] = useState(false);
  const active = isActiveRunStatus(run.status);
  const empty = assetTotal === 0;

  const run_ = async (fn: () => Promise<unknown>) => {
    setDownloading(true);
    try {
      await fn();
    } catch {
      // the download helpers already showed the error
    } finally {
      setDownloading(false);
    }
  };
  const downloads = [
    {
      testId: "run-results-download",
      label: `CycloneDX JSON${assetTotal != null ? ` (${assetTotal})` : ""}${active ? " so far" : ""}`,
      title: "The run's CycloneDX 1.6 CBOM as JSON",
      disabled: empty || downloading,
      onClick: () => run_(() => downloadCbomRunCbom(teamId, run.id)),
    },
    {
      testId: "run-results-download-xml",
      label: "CycloneDX XML",
      title: "The same CycloneDX 1.6 CBOM as XML, valid against the official schema",
      disabled: empty || downloading,
      onClick: () => run_(() => downloadCbomRunBom(teamId, run.id, "xml")),
    },
    {
      testId: "run-results-download-oscal",
      label: "OSCAL",
      title: active ? "Available when the run has finished" : "OSCAL 1.2.3 assessment results for a GRC tool (validated against the official schema)",
      disabled: active || downloading,
      onClick: () => run_(() => downloadOscal(teamId, { runId: run.id })),
    },
  ];

  return (
    <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between" data-testid="run-results-header">
      <div className="flex items-start gap-4 min-w-0">
        <Button variant="outline" size="icon" aria-label="Back" className="cursor-pointer shrink-0"
                onClick={() => router.push(`/${teamId}/cbom`)}>
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div className="min-w-0">
          <h1 className="text-2xl sm:text-3xl font-bold text-zinc-900 dark:text-white flex flex-wrap items-center gap-2">
            <ShieldCheck className="h-7 w-7 text-blue-600 dark:text-blue-400 shrink-0" />
            <span data-testid="run-results-title">{runTitle(run.id)}</span>
            <Badge variant="outline" className="border-violet-500/50 text-violet-600 dark:text-violet-400 text-xs font-medium">
              <Network className="h-3 w-3 mr-1" /> Sources run
            </Badge>
          </h1>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-1 text-sm text-zinc-600 dark:text-zinc-400" data-testid="run-results-meta">
            <span data-testid="run-results-status"><RunStatusBadge status={run.status} /></span>
            <span>Started {formatDateTime(run.created_at)}</span>
            {run.finished_at ? <span>Finished {formatDateTime(run.finished_at)}</span> : active ? <span>Running</span> : null}
            <span data-testid="run-results-credits">
              {credits(run.credits?.charged)} credits charged, {credits(run.credits?.refunded)} refunded
            </span>
            {run.scan_id != null && (
              <Link href={`/${teamId}/cbom/${run.scan_id}/results`} className="text-blue-600 dark:text-blue-400 hover:underline"
                    data-testid="run-results-linked-scan">
                Linked scan #{run.scan_id}
              </Link>
            )}
          </div>
          {sources.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mt-2" data-testid="run-results-sources">
              {sources.map((s) => (
                <Badge key={`${s.id ?? "x"}-${s.name}`} variant="outline" className="border-zinc-300 text-zinc-600 dark:border-zinc-700 dark:text-zinc-400 max-w-[260px] truncate">
                  {s.name}
                </Badge>
              ))}
            </div>
          )}
          {active && (
            <p className="mt-2 text-xs text-zinc-500" data-testid="run-results-live">
              The run is still collecting: this page updates every few seconds and the downloads hold what was collected so far.
            </p>
          )}
        </div>
      </div>
      <div className="flex items-center gap-2 flex-wrap lg:justify-end">
        {wide ? (
          downloads.map((d) => (
            <Button key={d.testId} variant="outline" className="cursor-pointer" title={d.title} disabled={d.disabled}
                    data-testid={d.testId} onClick={() => void d.onClick()}>
              {downloading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Download className="h-4 w-4 mr-2" />}
              {d.label}
            </Button>
          ))
        ) : (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" className="cursor-pointer" data-testid="run-results-downloads-menu">
                <Download className="h-4 w-4 mr-2" /> Downloads <ChevronDown className="h-4 w-4 ml-1" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start">
              {downloads.map((d) => (
                <DropdownMenuItem key={d.testId} className="cursor-pointer" disabled={d.disabled} title={d.title}
                                  data-testid={d.testId} onClick={() => void d.onClick()}>
                  <Download className="h-4 w-4" /> {d.label}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        )}
        {canCompare && (
          <Button variant="outline" className="cursor-pointer" onClick={onCompare} data-testid="run-results-compare">
            <GitCompare className="h-4 w-4 mr-2" /> Compare…
          </Button>
        )}
        <Button variant="default" className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white"
                onClick={() => router.push(`/${teamId}/cbom/sources?tab=review`)} data-testid="run-results-open-sources">
          <SlidersHorizontal className="h-4 w-4 mr-2" /> Open in CBOM Sources
        </Button>
      </div>
    </div>
  );
}
