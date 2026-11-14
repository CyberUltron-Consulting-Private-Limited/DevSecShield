"use client";

// Compliance mapping (#270) on the one CBOM results template (code scans and Sources runs): a per-framework summary
// first (verdict, requirement verdicts as a compact stacked bar in the matrix's verdict colours, clauses touched, assets
// affected), then each framework's failing clauses with readable finding names, a clickable asset count that filters
// the findings table, "How to fix" from the knowledge base, and the regulation's text collapsed behind "Show text".
// The view-model is complianceSummary.ts; this file only renders it.

import type { ReactNode } from "react";
import { ExternalLink, Info, Wrench } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { InfoTip } from "@/components/ui/info-tip";
import { VERDICT_BADGE, VERDICT_COLOR, VERDICT_LABEL, VERDICT_ORDER } from "@/components/compliance/verdictTokens";

import {
  FRAMEWORK_VERDICT_BADGE,
  FRAMEWORK_VERDICT_LABEL,
  verdictSegments,
  type ClauseView,
  type DrillTarget,
  type FrameworkSummary,
} from "./complianceSummary";

const slug = (s: string) => s.replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "");
const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;

function Note({ children, testId }: { children: ReactNode; testId?: string }) {
  return (
    <p className="text-sm text-zinc-500 dark:text-zinc-400 flex items-start gap-1.5" data-testid={testId}>
      <Info className="h-4 w-4 shrink-0 mt-0.5" /> <span>{children}</span>
    </p>
  );
}

/** "N assets": a button that filters the findings table when the count has a drill-down, plain text otherwise. */
export function AssetCount({ count, drill, onDrill, testId }: {
  count: number | null; drill: DrillTarget | null; onDrill?: (t: DrillTarget) => void; testId: string;
}) {
  if (count == null) return <span className="text-zinc-500" data-testid={testId}>—</span>;
  const text = plural(count, "asset");
  if (!drill || !onDrill || count === 0) return <span className="tabular-nums" data-testid={testId}>{text}</span>;
  return (
    <button type="button" className="tabular-nums text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
            title={`Show these assets in the findings table (${drill.label})`}
            aria-label={`${text}: ${drill.label}, show in the findings table`} data-testid={testId}
            onClick={() => onDrill(drill)}>
      {text}
    </button>
  );
}

/** Requirement verdicts as one stacked bar (the readiness matrix's colours), with the counts in its tooltip. */
export function VerdictBar({ fw }: { fw: FrameworkSummary }) {
  const segments = verdictSegments(fw.counts);
  if (!segments.length) return <span className="text-xs text-zinc-500" data-testid={`compliance-bar-${slug(fw.framework)}`}>No requirement judged</span>;
  const title = segments.map((s) => `${VERDICT_LABEL[s.verdict]} ${s.count}`).join(" · ");
  return (
    <div className="flex items-center gap-2 min-w-[140px]" data-testid={`compliance-bar-${slug(fw.framework)}`}>
      <div className="flex h-2.5 w-full min-w-[96px] overflow-hidden rounded-sm bg-zinc-100 dark:bg-zinc-800" title={title} role="img"
           aria-label={`${fw.framework} requirements: ${title}`}>
        {segments.map((s) => (
          <span key={s.verdict} className="h-full" style={{ width: `${s.pct}%`, background: VERDICT_COLOR[s.verdict] }}
                data-verdict={s.verdict} data-count={s.count} />
        ))}
      </div>
      <span className="text-xs tabular-nums text-zinc-500 whitespace-nowrap">{fw.counts.pass + fw.counts.pass_with_evidence}/{fw.requirements}</span>
    </div>
  );
}

function ClauseRow({ clause, onDrill }: { clause: ClauseView; onDrill?: (t: DrillTarget) => void }) {
  const tid = `compliance-clause-${slug(clause.key)}`;
  return (
    <li className="py-2.5 border-t border-zinc-100 dark:border-zinc-800 first:border-t-0 space-y-1 min-w-0" data-testid={tid}>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
        <Badge className={VERDICT_BADGE[clause.verdict] ?? VERDICT_BADGE.na}>{VERDICT_LABEL[clause.verdict] ?? clause.verdict}</Badge>
        {clause.source ? (
          <a href={clause.source} target="_blank" rel="noreferrer noopener"
             className="font-medium text-blue-600 dark:text-blue-400 inline-flex items-center gap-1 [overflow-wrap:anywhere]">
            {clause.id} <ExternalLink className="h-3 w-3 shrink-0" />
          </a>
        ) : (
          <span className="font-medium text-zinc-800 dark:text-zinc-200 [overflow-wrap:anywhere]">{clause.id}</span>
        )}
        <span className="text-zinc-400">·</span>
        <AssetCount count={clause.assets} drill={clause.drill} onDrill={onDrill} testId={`${tid}-assets`} />
      </div>
      <p className="text-sm text-zinc-700 dark:text-zinc-300 [overflow-wrap:anywhere]" data-testid={`${tid}-summary`}>{clause.summary}</p>
      {clause.fixes.length > 0 && (
        <div className="rounded-md bg-emerald-50 dark:bg-emerald-950/30 px-2.5 py-1.5 text-xs text-zinc-700 dark:text-zinc-300" data-testid={`${tid}-fix`}>
          <p className="font-medium text-emerald-800 dark:text-emerald-300 flex items-center gap-1"><Wrench className="h-3 w-3" /> How to fix{/* infotip-shared: the Compliance mapping (i) explains it */}</p>
          <ul className="mt-0.5 space-y-0.5">
            {clause.fixes.map((f) => (
              <li key={`${f.label}-${f.fix}`} className="[overflow-wrap:anywhere]">
                {clause.fixes.length > 1 || clause.origin === "engine" ? <span className="font-medium">{f.label}: </span> : null}{f.fix}
              </li>
            ))}
          </ul>
        </div>
      )}
      {(clause.quote || clause.note) && (
        <details className="text-xs text-zinc-600 dark:text-zinc-400" data-testid={`${tid}-text`}>
          <summary className="cursor-pointer text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 select-none">
            {clause.origin === "kb" ? "Show text" : "Show evidence"}
          </summary>
          {clause.quote && <blockquote className="mt-1 border-l-2 border-zinc-200 dark:border-zinc-700 pl-2 [overflow-wrap:anywhere]">{clause.quote}</blockquote>}
          {clause.note && <p className="mt-1 italic">{clause.note}</p>}
        </details>
      )}
    </li>
  );
}

export function ComplianceMappingSection({ frameworks, onDrill, note, footnote, scope }: {
  frameworks: FrameworkSummary[];
  /** filters the findings table to a count's assets */
  onDrill?: (target: DrillTarget) => void;
  /** one line when there is nothing to show (an older backend, a run still collecting) */
  note?: string | null;
  footnote?: string | null;
  scope: "run" | "scan";
}) {
  if (frameworks.length === 0 && !note) return null;
  return (
    <Card className="border-zinc-200 dark:border-zinc-800 min-w-0" data-testid="run-section-compliance">
      <CardHeader>
        <CardTitle className="text-base">Compliance mapping <InfoTip id="cbom.run.compliance" /></CardTitle>
        <CardDescription>
          {`Per framework: verdict, requirement results and the assets behind each failing clause or requirement. Click an asset count to filter the findings table; the regulation's text is behind "Show text". Advisory, from the knowledge base and the compliance checks of this ${scope} (no AI).`}
        </CardDescription>
      </CardHeader>
      <CardContent className="min-w-0 space-y-4">
        {note && <Note testId="run-compliance-note">{note}</Note>}
        {frameworks.length > 0 && (
          <>
            <div className="overflow-x-auto rounded-lg border border-zinc-200 dark:border-zinc-800">
              <table className="w-full text-sm" data-testid="compliance-summary">
                <thead className="bg-zinc-50 dark:bg-zinc-900/50 text-xs text-zinc-500">
                  <tr>
                    <th className="text-left font-medium px-3 py-2">Framework</th>
                    <th className="text-left font-medium px-3 py-2">Verdict</th>
                    <th className="text-left font-medium px-3 py-2">Requirements passed</th>
                    <th className="text-right font-medium px-3 py-2">Clauses touched</th>
                    <th className="text-right font-medium px-3 py-2">Assets affected</th>
                  </tr>
                </thead>
                <tbody>
                  {frameworks.map((fw) => {
                    const tid = `compliance-summary-${slug(fw.framework)}`;
                    return (
                      <tr key={fw.framework} className="border-t border-zinc-100 dark:border-zinc-800" data-testid={tid}>
                        <td className="px-3 py-2 align-top">
                          <a href={`#compliance-fw-${slug(fw.framework)}`} className="font-medium text-zinc-900 dark:text-white hover:underline">{fw.framework}</a>
                          {fw.engineFrameworks.length > 0 && (
                            <span className="block text-xs text-zinc-500" title="Compliance checks behind the verdict">{fw.engineFrameworks.join(", ")}</span>
                          )}
                        </td>
                        <td className="px-3 py-2 align-top">
                          <Badge className={FRAMEWORK_VERDICT_BADGE[fw.verdict]} data-testid={`${tid}-verdict`}>{FRAMEWORK_VERDICT_LABEL[fw.verdict]}</Badge>
                        </td>
                        <td className="px-3 py-2 align-top"><VerdictBar fw={fw} /></td>
                        <td className="px-3 py-2 align-top text-right tabular-nums" data-testid={`${tid}-clauses`}>{fw.clausesTouched}</td>
                        <td className="px-3 py-2 align-top text-right">
                          <AssetCount count={fw.assets} drill={fw.drill} onDrill={onDrill} testId={`${tid}-assets`} />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-zinc-600 dark:text-zinc-400" data-testid="compliance-summary-legend">
              {VERDICT_ORDER.map((v) => (
                <span key={v} className="flex items-center gap-1.5">
                  <span className="size-2.5 rounded-sm" style={{ background: VERDICT_COLOR[v] }} /> {VERDICT_LABEL[v]}
                </span>
              ))}
            </div>
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
              {frameworks.filter((fw) => fw.clauses.length > 0).map((fw) => (
                <details key={fw.framework} id={`compliance-fw-${slug(fw.framework)}`} open={fw.verdict === "fail" || fw.verdict === "partial"}
                         className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3 min-w-0" data-testid={`run-compliance-${slug(fw.framework)}`}>
                  <summary className="cursor-pointer text-sm font-semibold text-zinc-900 dark:text-white">
                    {fw.framework}{" "}
                    <span className="text-xs font-normal text-zinc-500">
                      · {fw.clausesTouched > 0 ? plural(fw.clausesTouched, "clause") : plural(fw.clauses.length, "open requirement")}
                    </span>
                  </summary>
                  <ul className="mt-2">
                    {fw.clauses.map((c) => <ClauseRow key={c.key} clause={c} onDrill={onDrill} />)}
                  </ul>
                </details>
              ))}
            </div>
          </>
        )}
        {footnote && <p className="text-xs text-zinc-500">{footnote}</p>}
      </CardContent>
    </Card>
  );
}

export default ComplianceMappingSection;
