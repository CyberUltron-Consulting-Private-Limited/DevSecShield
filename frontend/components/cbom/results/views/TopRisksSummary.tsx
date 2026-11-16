"use client";

// Top cryptographic risks (results redesign 07, C + B): the run posture's ranked risks once, not twice (the former
// posture card's "Highest risk" list and the RunTopRisks table showed the same top_risks): the first three as cards
// with their issues, the rest as a table. Both headings, their tips, the scoring footnote, and (when there are risks)
// the regulatory clauses toggle and the Z note are here.

import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { InfoTip } from "@/components/ui/info-tip";
import { EXPOSURE_LABEL, type CbomPostureWithExposure, type CbomTopRisk } from "@/utils/api/cbom_outputs";
import { EXPOSURE_TONE } from "@/components/cbom/sources/RunPosture";
import { StatusBadge } from "@/components/cbom/sources/shared";

import { ChevronRight } from "lucide-react";

import { getImpactBadgeClass } from "../badgeClasses";
import { CARD_ARROW, CLICKABLE_CARD, cardOpenProps } from "../findingTable";
import { PostureClauses, ZNote } from "./PostureSummary";

/** The issues behind a risk: the stored finding text is one sentence per issue, joined with "; " by the classifier. */
export function riskIssues(finding: string | null | undefined): string[] {
  return (finding ?? "").split("; ").map((s) => s.trim()).filter(Boolean);
}

/** Cards for the first three, the table for the rest (each risk once). */
export function splitTopRisks<T>(risks: T[], cards = 3): { cards: T[]; rest: T[] } {
  return { cards: risks.slice(0, cards), rest: risks.slice(cards) };
}

function Exposure({ r, factors }: { r: CbomTopRisk; factors: CbomPostureWithExposure["exposure_factors"] }) {
  if (!r.exposure) return <span className="text-zinc-500">—</span>;
  return (
    <span title={r.exposure_basis}>
      <StatusBadge tone={EXPOSURE_TONE[r.exposure]}>
        {EXPOSURE_LABEL[r.exposure]}{factors && r.exposure === "internet" ? ` ×${factors.internet}` : ""}
      </StatusBadge>
    </span>
  );
}

function PriorityBar({ score, max }: { score: number; max: number }) {
  const pct = max > 0 ? Math.max(4, Math.round((score / max) * 100)) : 0;
  return (
    <span className="mt-1 block h-1.5 w-20 rounded-full bg-zinc-200 dark:bg-zinc-800 overflow-hidden" aria-hidden>
      <span className="block h-full bg-orange-500" style={{ width: `${pct}%` }} />
    </span>
  );
}

export function TopRisksSummary({ posture, onOpenAsset }: { posture: CbomPostureWithExposure; onOpenAsset: (id: number) => void }) {
  const risks = posture.top_risks ?? [];
  if (risks.length === 0) return null;
  const { cards, rest } = splitTopRisks(risks);
  const max = Math.max(...risks.map((r) => r.score));
  return (
    <section className="space-y-3 min-w-0" data-testid="run-top-risks">
      <div className="space-y-1">
        <h2 className="text-base font-semibold text-zinc-900 dark:text-white">Top cryptographic risks <InfoTip id="cbom.run.top_risks" /></h2>
        <p className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
          Highest risk (impact × business criticality × internet exposure)
        </p>
        <p className="text-sm text-zinc-500 dark:text-zinc-400">Priority = impact × business criticality × internet exposure, from the run posture</p>
      </div>
      <ol className="grid grid-cols-1 md:grid-cols-3 gap-3" data-testid="run-top-risk-cards">
        {cards.map((r) => (
          // the whole card opens the asset's finding popup (the asset name stays the keyboard stop)
          <li key={r.id} className={`flex flex-col rounded-xl border border-zinc-200 dark:border-zinc-800 p-4 min-w-0 space-y-2 ${CLICKABLE_CARD}`}
              data-testid={`run-top-risk-${r.id}`} {...cardOpenProps(() => onOpenAsset(r.id))}>
            <div className="flex items-center justify-between gap-2" data-testid={`top-risk-${r.id}`}>
              <span className="text-xs text-zinc-500">Priority <InfoTip id="cbom.run.col.priority" /></span>
              <span className="text-xs text-zinc-500">Impact <InfoTip id="results.table.impact" /></span>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-2xl font-bold tabular-nums text-zinc-900 dark:text-white">{r.score}</span>
              <Badge variant="outline" className={getImpactBadgeClass(r.impact)}>{r.impact}</Badge>
            </div>
            <PriorityBar score={r.score} max={max} />
            <div className="text-xs text-zinc-500">Asset <InfoTip id="cbom.run.col.asset" /></div>
            <button type="button" className="text-left text-blue-600 dark:text-blue-400 hover:underline cursor-pointer font-medium break-all rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                    title={r.location} onClick={() => onOpenAsset(r.id)}>
              {r.name}
            </button>
            <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs" data-testid={`run-top-risk-fields-${r.id}`}>
              <dt className="text-zinc-500">Source <InfoTip id="cbom.run.col.source" /></dt>
              <dd className="text-zinc-700 dark:text-zinc-300 min-w-0 break-words">{r.source_name ?? "—"}</dd>
              <dt className="text-zinc-500">Criticality <InfoTip id="cbom.run.col.criticality" /></dt>
              <dd className="text-zinc-700 dark:text-zinc-300 capitalize">{r.criticality}</dd>
              <dt className="text-zinc-500">Exposure <InfoTip id="cbom.run.col.exposure" /></dt>
              <dd><Exposure r={r} factors={posture.exposure_factors} /></dd>
              <dt className="text-zinc-500">HNDL <InfoTip id="cbom.run.col.hndl" /></dt>
              <dd className="text-zinc-700 dark:text-zinc-300">{r.hndl ? <StatusBadge tone="red">HNDL</StatusBadge> : "—"}</dd>
            </dl>
            {riskIssues(r.finding).length > 0 && (
              <ul className="list-disc pl-5 space-y-0.5 text-xs text-zinc-700 dark:text-zinc-300 [overflow-wrap:anywhere]">
                {riskIssues(r.finding).map((t) => <li key={t}>{t}</li>)}
              </ul>
            )}
            {/* the cue that the card opens more (the asset name above is the real control) */}
            <span aria-hidden="true" className="mt-auto inline-flex items-center gap-0.5 pt-1 text-xs font-medium text-blue-600 dark:text-blue-400 group-hover:underline"
                  data-testid={`run-top-risk-open-${r.id}`}>
              View details <ChevronRight className={`h-3.5 w-3.5 ${CARD_ARROW}`} />
            </span>
          </li>
        ))}
      </ol>
      {rest.length > 0 && (
        <ScrollArea className="h-[320px] w-full rounded-md border border-zinc-200 dark:border-zinc-800" data-testid="run-top-risk-table">
          <Table className="min-w-max">
            <TableHeader>
              <TableRow>
                <TableHead className="min-w-[110px]">Priority <InfoTip id="cbom.run.col.priority" /></TableHead>
                <TableHead className="min-w-[260px]">Asset <InfoTip id="cbom.run.col.asset" /></TableHead>
                <TableHead className="min-w-[90px]">Impact <InfoTip id="results.table.impact" /></TableHead>
                <TableHead className="min-w-[140px]">Source <InfoTip id="cbom.run.col.source" /></TableHead>
                <TableHead className="min-w-[100px]">Criticality <InfoTip id="cbom.run.col.criticality" /></TableHead>
                <TableHead className="min-w-[130px]">Exposure <InfoTip id="cbom.run.col.exposure" /></TableHead>
                <TableHead className="min-w-[70px]">HNDL <InfoTip id="cbom.run.col.hndl" /></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rest.map((r) => (
                <TableRow key={r.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800/50" data-testid={`run-top-risk-${r.id}`}>
                  <TableCell className="font-mono tabular-nums" data-testid={`top-risk-${r.id}`}>
                    {r.score}
                    <PriorityBar score={r.score} max={max} />
                  </TableCell>
                  <TableCell className="max-w-[360px]">
                    <button type="button" className="text-left text-blue-600 dark:text-blue-400 hover:underline cursor-pointer max-w-[340px] truncate block font-mono text-xs"
                            title={r.location} onClick={() => onOpenAsset(r.id)}>
                      {r.name}
                    </button>
                    {riskIssues(r.finding).length > 0 && (
                      <ul className="list-disc pl-4 text-xs text-zinc-500 max-w-[340px]">
                        {riskIssues(r.finding).map((t) => <li key={t} className="truncate" title={t}>{t}</li>)}
                      </ul>
                    )}
                  </TableCell>
                  <TableCell><Badge variant="outline" className={getImpactBadgeClass(r.impact)}>{r.impact}</Badge></TableCell>
                  <TableCell className="text-sm text-zinc-600 dark:text-zinc-400">{r.source_name ?? "—"}</TableCell>
                  <TableCell className="text-sm text-zinc-600 dark:text-zinc-400 capitalize">{r.criticality}</TableCell>
                  <TableCell className="text-sm text-zinc-600 dark:text-zinc-400"><Exposure r={r} factors={posture.exposure_factors} /></TableCell>
                  <TableCell className="text-sm">{r.hndl ? <StatusBadge tone="red">HNDL</StatusBadge> : "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <ScrollBar orientation="horizontal" />
        </ScrollArea>
      )}
      <p className="text-xs text-zinc-500">Scored with the criticality and exposure the sources had when this run started.</p>
      <PostureClauses posture={posture} />
      <ZNote posture={posture} />
    </section>
  );
}
