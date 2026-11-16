"use client";

// Post-quantum and risk posture, summary (results redesign 04-B): the summary part of the run's former posture card
// (components/cbom/sources/RunPosture.tsx), with every stat, the Mosca test and its admin editor, the PQC class badges,
// the knowledge base line, and a donut of the run's classes. The quantum-risk distribution and the crypto-agility card
// are in the Quantum grades view. The highest risks are in TopRisksSummary (one list, not two); the regulatory clauses
// toggle and the Z note stay here when the run has no top risk, else they follow the risks.

import { ExternalLink, Info } from "lucide-react";
import { useState } from "react";

import { InfoTip } from "@/components/ui/info-tip";
import type { CbomPqcClass } from "@/utils/backend_api";
import type { CbomPostureWithExposure } from "@/utils/api/cbom_outputs";
import { pluralize } from "@/components/cbom/sources/logic";
import {
  CLASS_LABEL,
  MoscaEditor,
  Stat,
  readinessText as postureReadinessText,
  useIsTeamAdmin,
  useRunPostureQuery,
} from "@/components/cbom/sources/RunPosture";
import { ErrorBlock, LoadingBlock, StatusBadge } from "@/components/cbom/sources/shared";

import { READY_CLASSES } from "../model";
import { readinessExplanation, readinessDrillFilters } from "../readinessExplain";
import type { RunTableFilters } from "../model";

/** The donut's slices: posture's class counts (Rule P), never rows of the table. */
export function postureSlices(p: Pick<CbomPostureWithExposure, "pqc_classes">): { key: string; label: string; count: number; stroke: string; dot: string }[] {
  const c = p.pqc_classes ?? ({} as Record<CbomPqcClass, number>);
  const ready = READY_CLASSES.reduce((n, k) => n + (c[k] ?? 0), 0);
  return [
    { key: "vulnerable", label: "Vulnerable", count: c["quantum-vulnerable"] ?? 0, stroke: "stroke-orange-500", dot: "bg-orange-500" },
    { key: "safe", label: "Safe", count: ready, stroke: "stroke-teal-500", dot: "bg-teal-500" },
    { key: "unknown", label: "Unknown", count: c.unknown ?? 0, stroke: "stroke-zinc-400 dark:stroke-zinc-500", dot: "bg-zinc-400 dark:bg-zinc-500" },
    { key: "na", label: "Not applicable", count: c["not-applicable"] ?? 0, stroke: "stroke-zinc-300 dark:stroke-zinc-700", dot: "bg-zinc-300 dark:bg-zinc-700" },
  ].filter((s) => s.count > 0);
}

function PostureDonut({ p }: { p: CbomPostureWithExposure }) {
  const slices = postureSlices(p);
  const total = slices.reduce((n, s) => n + s.count, 0);
  const C = 100; // r = 15.9155 makes the circumference 100
  let offset = 25;
  const label = slices.map((s) => `${s.count} ${s.label.toLowerCase()}`).join(", ") || "No asset with a class";
  return (
    <div className="flex items-center gap-4 min-w-0" data-testid="posture-donut">
      <svg viewBox="0 0 42 42" className="h-32 w-32 shrink-0" role="img" aria-label={`Post-quantum classes: ${label}`}>
        <circle cx="21" cy="21" r="15.9155" fill="none" strokeWidth="6" className="stroke-zinc-200 dark:stroke-zinc-800" />
        {total > 0 && slices.map((s) => {
          const len = (s.count / total) * C;
          const el = (
            <circle key={s.key} cx="21" cy="21" r="15.9155" fill="none" strokeWidth="6" className={s.stroke}
                    strokeDasharray={`${len} ${C - len}`} strokeDashoffset={offset} />
          );
          offset -= len;
          return el;
        })}
        <text x="21" y="22.5" textAnchor="middle" className="fill-zinc-900 dark:fill-white" fontSize="6.5" fontWeight="700">
          {postureReadinessText(p).value === "Not enough identified" ? "—" : postureReadinessText(p).value}
        </text>
        <text x="21" y="28" textAnchor="middle" className="fill-zinc-500 dark:fill-zinc-400" fontSize="2.8">ready</text>
      </svg>
      <ul className="space-y-1.5 text-sm min-w-0">
        {slices.map((s) => (
          <li key={s.key} className="flex items-center gap-2 text-zinc-700 dark:text-zinc-300" data-testid={`posture-slice-${s.key}`}>
            <span className={`h-2.5 w-2.5 rounded-full shrink-0 ${s.dot}`} aria-hidden /> {s.label} <span className="tabular-nums font-semibold">{s.count}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** "Show / Hide regulatory clauses these findings touch": in the posture card, or under the top risks when there are. */
export function PostureClauses({ posture: p }: { posture: Pick<CbomPostureWithExposure, "compliance"> }) {
  const [show, setShow] = useState(false);
  if (p.compliance.length === 0) return null;
  return (
    <div>
      <button type="button" className="text-xs text-blue-600 dark:text-blue-400 cursor-pointer" onClick={() => setShow(!show)}
              aria-expanded={show} aria-controls="posture-compliance" data-testid="posture-compliance-toggle">
        {show ? "Hide" : "Show"} regulatory clauses these findings touch ({p.compliance.map((f) => f.framework).join(", ")})
      </button>
      {show && (
        <div className="mt-2 space-y-2" id="posture-compliance" data-testid="posture-compliance">
          {p.compliance.map((fw) => (
            <div key={fw.framework}>
              <p className="text-xs font-semibold text-zinc-800 dark:text-zinc-200">{fw.framework}</p>
              <ul className="space-y-1">
                {fw.clauses.map((c) => (
                  <li key={c.id} className="text-xs text-zinc-600 dark:text-zinc-400">
                    <a href={c.source} target="_blank" rel="noreferrer noopener" className="text-blue-600 dark:text-blue-400 inline-flex items-center gap-1">
                      {c.id} <ExternalLink className="h-3 w-3" />
                    </a>{" "}
                    · {pluralize(c.assets, "asset")} · {c.codes.join(", ")}
                    {c.note && <span className="block italic text-zinc-500">{c.note}</span>}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function ZNote({ posture: p }: { posture: Pick<CbomPostureWithExposure, "pqc_context"> }) {
  if (!p.pqc_context?.z_note) return null;
  return <p className="text-xs text-zinc-500 flex gap-1" data-testid="posture-z-note"><Info className="h-3.5 w-3.5 shrink-0 mt-0.5" />{p.pqc_context.z_note}</p>;
}

/** The top readiness actions as rows: what each fix would bring the readiness to, and "Show these N". */
function RaiseList({ p, onDrill }: { p: CbomPostureWithExposure; onDrill: (patch: Partial<RunTableFilters>) => void }) {
  const e = readinessExplanation(p);
  if (e.actions.length === 0 && e.vulnerable === 0) return null;
  const now = typeof p.pqc_readiness_pct === "number" ? p.pqc_readiness_pct : null;
  // readinessExplanation keeps the API's order: action i is readiness_actions[i]
  const after = (i: number) => p.readiness_actions?.[i]?.readiness_after ?? null;
  return (
    <div className="space-y-2 min-w-0" data-testid="posture-raise">
      {e.actions.length > 0 && (
        <>
          <p className="text-sm font-medium text-zinc-900 dark:text-white">What would raise it <InfoTip id="cbom.run.readiness_actions" /></p>
          <ul className="space-y-2">
            {e.actions.map((a, i) => {
              const to = after(i);
              return (
                <li key={a.key} className="grid grid-cols-1 sm:grid-cols-[minmax(0,1fr)_8rem_auto] gap-x-3 gap-y-1 items-center text-sm" data-testid="posture-raise-action">
                  <span className="text-zinc-800 dark:text-zinc-200 [overflow-wrap:anywhere]">{a.text}</span>
                  <span className="h-2 rounded-full bg-zinc-200 dark:bg-zinc-800 overflow-hidden flex" aria-hidden>
                    {now != null && <span className="h-full bg-teal-500" style={{ width: `${Math.min(100, now)}%` }} />}
                    {now != null && to != null && to > now && <span className="h-full bg-teal-500/40" style={{ width: `${Math.min(100, to) - Math.min(100, now)}%` }} />}
                  </span>
                  <span className="flex items-center gap-2 text-xs whitespace-nowrap">
                    {to != null && <b className="text-teal-700 dark:text-teal-400">→ {to}%</b>}
                    <button type="button" className="cursor-pointer text-blue-600 hover:underline dark:text-blue-400"
                            onClick={() => onDrill(readinessDrillFilters(a))} data-testid="posture-raise-show">
                      Show these {a.assets}
                    </button>
                  </span>
                </li>
              );
            })}
          </ul>
        </>
      )}
      {e.vulnerable > 0 && (
        <button type="button" className="text-sm cursor-pointer text-blue-600 hover:underline dark:text-blue-400"
                onClick={() => onDrill(readinessDrillFilters())} data-testid="posture-show-vulnerable">
          Show the {e.vulnerable} quantum-vulnerable assets
        </button>
      )}
    </div>
  );
}

export function PostureSummary({ teamId, runId, active, onDrill, onOpenQuantum }: {
  teamId: number; runId: number; active: boolean;
  /** a readiness action's "Show these N": filters the findings table */
  onDrill: (patch: Partial<RunTableFilters>) => void;
  /** a run that read no asset: its unread items are listed in the Quantum grades view */
  onOpenQuantum: () => void;
}) {
  const [editMosca, setEditMosca] = useState(false);
  const isAdmin = useIsTeamAdmin(teamId);
  const query = useRunPostureQuery(teamId, runId, active);
  if (query.isLoading) return <LoadingBlock />;
  if (query.isError || !query.data) return <ErrorBlock error={query.error} onRetry={() => query.refetch()} />;
  const p = query.data;
  // a run that read no asset can still have Q0 Unknown items (sources or targets not read): they are in the Quantum view
  if (p.assets === 0) {
    if ((p.q0_items_total ?? 0) === 0) return null;
    return (
      <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 p-4 space-y-2" data-testid="run-posture-empty">
        <p className="text-sm font-medium text-zinc-900 dark:text-white">Post-quantum and risk posture <InfoTip id="cbom.run.posture" /></p>
        <p className="text-sm text-zinc-600 dark:text-zinc-400">
          This run read no asset; {pluralize(p.q0_items_total ?? 0, "item")} could not be read and {(p.q0_items_total ?? 0) === 1 ? "is" : "are"} graded Q0 Unknown.
        </p>
        <button type="button" className="text-sm cursor-pointer text-blue-600 hover:underline dark:text-blue-400" onClick={onOpenQuantum}
                data-testid="posture-open-quantum">
          See what was not read in Quantum grades ›
        </button>
      </div>
    );
  }
  const m = p.mosca; // the Mosca this run recorded at Start (the team's now: mosca_now, and the editor)
  const risksElsewhere = p.top_risks.length > 0; // the clauses toggle and the Z note follow the top risks
  return (
    <section className="space-y-4 rounded-xl border border-zinc-200 dark:border-zinc-800 p-4 sm:p-5 min-w-0" data-testid="run-posture">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-base font-semibold text-zinc-900 dark:text-white">Post-quantum and risk posture <InfoTip id="cbom.run.posture" /></h2>
        <span className="text-xs text-zinc-500">Knowledge base {p.kb_version} · no AI</span>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)] gap-6 items-start">
        <div className="space-y-3 min-w-0">
          <PostureDonut p={p} />
          <div className="flex flex-wrap gap-2">
            {(Object.keys(CLASS_LABEL) as CbomPqcClass[]).map((c) =>
              p.pqc_classes[c] ? (
                <span key={c} title={CLASS_LABEL[c][2]} data-testid={`posture-class-${c}`} data-count={p.pqc_classes[c]}>
                  <StatusBadge tone={CLASS_LABEL[c][1]}>{CLASS_LABEL[c][0]} {p.pqc_classes[c]}</StatusBadge>
                </span>
              ) : null,
            )}
          </div>
        </div>
        <div className="space-y-4 min-w-0">
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
            <Stat label="PQC readiness" value={postureReadinessText(p).value} hint={postureReadinessText(p).hint} testId="posture-readiness" />
            <Stat label="Harvest now, decrypt later" value={String(p.hndl_assets)}
                  hint="Endpoints whose key exchange a quantum computer breaks later" testId="posture-hndl" />
            <Stat label="Critical / High" value={`${p.impacts.Critical ?? 0} / ${p.impacts.High ?? 0}`} hint={`${p.impacts.Medium ?? 0} medium, ${p.impacts.Low ?? 0} low`} testId="posture-impacts" />
            <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3 min-w-0" data-testid="posture-mosca">
              <p className="text-xs text-zinc-500">Mosca (X + Y &gt; Z)</p>
              {m.configured ? (
                <>
                  <p className={`text-xl font-semibold ${m.at_risk ? "text-red-600 dark:text-red-400" : "text-green-600 dark:text-green-400"}`}>
                    {m.at_risk ? "At risk" : "Inside window"}
                  </p>
                  <p className="text-xs text-zinc-500 mt-0.5">X {m.x} + Y {m.y} vs Z {m.z} years</p>
                </>
              ) : (
                <p className="text-xs text-zinc-500 mt-1">Not set</p>
              )}
              {p.mosca_now && (
                <p className="text-xs text-zinc-500 mt-0.5" data-testid="posture-mosca-now">
                  Team now: {p.mosca_now.configured ? `X ${p.mosca_now.x} + Y ${p.mosca_now.y} vs Z ${p.mosca_now.z}` : "not set"} (applies to new runs)
                </p>
              )}
              {isAdmin ? (
                <button type="button" className="text-xs text-blue-600 dark:text-blue-400 cursor-pointer mt-1" data-testid="mosca-edit"
                        title="Team setting: new runs record it at Start; this run keeps the values it started with"
                        aria-expanded={editMosca} onClick={() => setEditMosca(!editMosca)}>
                  {m.configured || p.mosca_now ? "Change X, Y, Z" : "Set X, Y, Z"}
                </button>
              ) : (
                <p className="text-xs text-zinc-500 mt-1" data-testid="mosca-admin-only">A team admin sets X, Y and Z</p>
              )}
            </div>
          </div>
          {editMosca && isAdmin && <MoscaEditor teamId={teamId} onDone={() => setEditMosca(false)} />}
          {!m.configured && !editMosca && m.note && <p className="text-xs text-zinc-500">{m.note}</p>}
          {m.configured && m.verdict && <p className="text-xs text-zinc-600 dark:text-zinc-400" data-testid="posture-mosca-verdict">{m.verdict}</p>}
          <RaiseList p={p} onDrill={onDrill} />
        </div>
      </div>
      {!risksElsewhere && <PostureClauses posture={p} />}
      {!risksElsewhere && <ZNote posture={p} />}
    </section>
  );
}
