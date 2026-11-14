"use client";

// "Agility baseline" on the CBOM team page (CB-25 PR-A; diagram output 03 "Asset, system and enterprise agility by
// fix class"): the enterprise distribution (the run posture's AgilityPostureCard, fed the team baseline), the systems
// table and a drill-down to the assets of one class and/or one system. Data: GET /{team}/cbom/agility and
// /{team}/cbom/agility/subjects (keyset pages, "Load more").
import { useInfiniteQuery } from "@tanstack/react-query";
import { useState } from "react";

import { AgilityPostureCard, FixClassChip } from "./Agility";
import { getCbomAgilityBaseline, getCbomAgilitySubjects } from "./api";
import {
  baselineKeys,
  baselinePosture,
  dedupeText,
  systemsAddUp,
  SYSTEM_KIND_LABEL,
  type AgilityBaseline,
  type AgilitySubject,
  type BaselineSystem,
} from "./baseline";
import { FIX_LABEL, FIX_VALUES, type AgilityModel, type FixValue } from "./model";

export interface DrillDown {
  fixClass: string | null;
  system: { key: string; label: string } | null;
  view: "all" | "excl_pq";
}

const BTN = "rounded border px-2 py-0.5 text-xs cursor-pointer border-zinc-300 text-zinc-700 hover:border-blue-500 dark:border-zinc-700 dark:text-zinc-300";

/** The systems table: one row per system (application, source, repository or evidence), its hardest class, the
 * self-fixable share and its count per class; a class count or "Assets" opens the drill-down. */
export function AgilitySystemsTable({ systems, onOpen }: {
  systems: BaselineSystem[];
  onOpen?: (d: DrillDown) => void;
}) {
  if (systems.length === 0) return null;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs" data-testid="agility-baseline-systems">
        <thead>
          <tr className="text-left text-zinc-500 dark:text-zinc-400">
            <th className="py-1 pr-3 font-normal">System</th>
            <th className="py-1 pr-3 font-normal text-right">Assets</th>
            <th className="py-1 pr-3 font-normal">Hardest</th>
            <th className="py-1 pr-3 font-normal text-right">Self-fixable</th>
            {FIX_VALUES.map((v) => (
              <th key={v} className="py-1 pr-3 font-normal text-right whitespace-nowrap">{FIX_LABEL[v]}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {systems.map((s) => (
            <tr key={s.key} className="border-t border-zinc-100 dark:border-zinc-800" data-testid={`agility-baseline-system-${s.key}`}
                data-assets={s.assets} data-kind={s.kind}>
              <td className="py-1 pr-3 text-zinc-800 dark:text-zinc-200 break-all min-w-[10rem]">
                {s.label} <span className="text-zinc-500 dark:text-zinc-400">({SYSTEM_KIND_LABEL[s.kind] ?? s.kind})</span>
              </td>
              <td className="py-1 pr-3 text-right tabular-nums">
                <button type="button" className="text-blue-600 dark:text-blue-400 cursor-pointer tabular-nums"
                        onClick={() => onOpen?.({ fixClass: null, system: { key: s.key, label: s.label }, view: "all" })}
                        aria-label={`Show the ${s.assets} assets of ${s.label}`}>
                  {s.assets}
                </button>
              </td>
              <td className="py-1 pr-3"><FixClassChip item={{ fix_class: s.hardest ?? "none" }} /></td>
              <td className="py-1 pr-3 text-right tabular-nums">{s.self_fixable_pct == null ? "—" : `${s.self_fixable_pct}%`}</td>
              {FIX_VALUES.map((v) => {
                const n = Number(s.counts[v]) || 0;
                return (
                  <td key={v} className="py-1 pr-3 text-right tabular-nums" data-testid={`agility-baseline-system-${s.key}-${v}`} data-count={n}>
                    {n === 0 ? <span className="text-zinc-400">0</span> : (
                      <button type="button" className="text-blue-600 dark:text-blue-400 cursor-pointer"
                              onClick={() => onOpen?.({ fixClass: v, system: { key: s.key, label: s.label }, view: "all" })}
                              aria-label={`Show the ${n} ${FIX_LABEL[v]} assets of ${s.label}`}>
                        {n}
                      </button>
                    )}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** The drill-down list: name, where, class (with the class it is at least), the codes that decided it, system and how
 * many observations (sources and code scans) the asset was merged from. */
export function AgilitySubjectsTable({ items }: { items: AgilitySubject[] }) {
  if (items.length === 0) return <p className="text-xs text-zinc-500 dark:text-zinc-400">No asset matches.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs" data-testid="agility-baseline-subjects">
        <thead>
          <tr className="text-left text-zinc-500 dark:text-zinc-400">
            <th className="py-1 pr-3 font-normal">Asset</th>
            <th className="py-1 pr-3 font-normal">Fix class</th>
            <th className="py-1 pr-3 font-normal">Why</th>
            <th className="py-1 pr-3 font-normal">System</th>
            <th className="py-1 font-normal text-right">Seen by</th>
          </tr>
        </thead>
        <tbody>
          {items.map((i) => (
            <tr key={i.key} className="border-t border-zinc-100 dark:border-zinc-800 align-top" data-testid="agility-baseline-subject"
                data-fix-class={i.fix_class} data-key={i.key}>
              <td className="py-1 pr-3 min-w-[12rem]">
                <p className="text-zinc-800 dark:text-zinc-200 break-all">{i.name || "(unnamed)"}</p>
                <p className="text-zinc-500 dark:text-zinc-400 break-all">{i.type}{i.location ? ` · ${i.location}` : ""}</p>
              </td>
              <td className="py-1 pr-3"><FixClassChip item={{ fix_class: i.fix_class, fix_class_floor: i.fix_class_floor }} /></td>
              <td className="py-1 pr-3 font-mono text-zinc-600 dark:text-zinc-400 break-all">{i.deciding_codes.join(", ") || "—"}</td>
              <td className="py-1 pr-3 text-zinc-700 dark:text-zinc-300 break-all">{i.system.label}</td>
              <td className="py-1 text-right text-zinc-700 dark:text-zinc-300" title={i.sources.join(", ")}>
                <span className="tabular-nums">{i.observations}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Everything but the fetching: the enterprise card, the dedupe note, the systems table and its "Load more". */
export function AgilityBaselineView({ teamId, baseline, systems, model, onOpen, onMoreSystems, loadingMore }: {
  teamId?: number;
  baseline: AgilityBaseline;
  systems: BaselineSystem[];
  model?: AgilityModel | null;
  onOpen?: (d: DrillDown) => void;
  onMoreSystems?: () => void;
  loadingMore?: boolean;
}) {
  const dedupe = dedupeText(baseline);
  const addsUp = systemsAddUp({ ...baseline, systems: { ...baseline.systems, items: systems, next: onMoreSystems ? "more" : null } });
  return (
    <div className="space-y-3" data-testid="agility-baseline" data-assets={baseline.assets} data-systems={baseline.systems_total}>
      {baseline.assets === 0 ? (
        <p className="text-sm text-zinc-500 dark:text-zinc-400" data-testid="agility-baseline-empty">
          No asset yet: run a CBOM Sources collection or a code scan to see how hard the estate is to fix.
        </p>
      ) : (
        <>
          <AgilityPostureCard teamId={teamId} posture={baselinePosture(baseline)} model={model} />
          <div className="flex flex-wrap items-center gap-2 text-xs" role="group" aria-label="Show the assets of a fix class">
            <span className="text-zinc-500 dark:text-zinc-400">Show assets:</span>
            {FIX_VALUES.filter((v) => Number(baseline.counts[v]) > 0).map((v: FixValue) => (
              <button key={v} type="button" className={BTN} data-testid={`agility-baseline-open-${v}`}
                      onClick={() => onOpen?.({ fixClass: v, system: null, view: "all" })}>
                {FIX_LABEL[v]} ({baseline.counts[v]})
              </button>
            ))}
          </div>
          {dedupe && <p className="text-xs text-zinc-500 dark:text-zinc-400" data-testid="agility-baseline-dedupe">{dedupe}</p>}
          {!!baseline.not_assessed && (
            <p className="text-xs text-zinc-500 dark:text-zinc-400" data-testid="agility-baseline-not-assessed">
              {baseline.not_assessed} evidence area{baseline.not_assessed === 1 ? "" : "s"} not answered yet: not assessed, not counted.
            </p>
          )}
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">
              Systems ({baseline.systems_total})
            </p>
            <AgilitySystemsTable systems={systems} onOpen={onOpen} />
            {addsUp === false && (
              <p className="text-xs text-red-600 dark:text-red-400" role="alert" data-testid="agility-baseline-mismatch">
                The systems do not add up to the team&apos;s counts: please report this.
              </p>
            )}
            {onMoreSystems && (
              <button type="button" className={`${BTN} mt-2`} onClick={onMoreSystems} disabled={loadingMore}
                      data-testid="agility-baseline-more-systems">
                {loadingMore ? "Loading…" : "Load more systems"}
              </button>
            )}
          </div>
        </>
      )}
      <p className="text-xs text-zinc-500 dark:text-zinc-400">
        Current estate as of {baseline.as_of.replace("T", " ").replace("Z", " UTC")}: each source&apos;s latest collection and
        each repository&apos;s latest code scan. A system is the source&apos;s application, else the source itself.
      </p>
    </div>
  );
}

function DrillDownPanel({ teamId, drill, onChange, onClose }: {
  teamId: number;
  drill: DrillDown;
  onChange: (d: DrillDown) => void;
  onClose: () => void;
}) {
  const query = useInfiniteQuery({
    queryKey: baselineKeys.subjects(teamId, { fixClass: drill.fixClass, system: drill.system?.key ?? null, view: drill.view }),
    queryFn: ({ pageParam }) => getCbomAgilitySubjects(teamId, {
      fixClass: drill.fixClass, system: drill.system?.key ?? null, view: drill.view, after: pageParam, limit: 50,
    }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next,
  });
  const items = query.data?.pages.flatMap((p) => p.items) ?? [];
  const total = query.data?.pages[0]?.total;
  return (
    <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3 space-y-2 min-w-0" data-testid="agility-baseline-drill"
         data-fix-class={drill.fixClass ?? ""} data-system={drill.system?.key ?? ""} data-total={total ?? ""}>
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <p className="font-medium text-zinc-900 dark:text-white">
          {drill.fixClass ? FIX_LABEL[drill.fixClass as FixValue] ?? drill.fixClass : "All"} assets
          {drill.system ? ` of ${drill.system.label}` : ""}{total != null ? ` (${total})` : ""}
        </p>
        <select className="rounded border border-zinc-300 dark:border-zinc-700 bg-transparent px-1 py-0.5" aria-label="Fix class"
                value={drill.fixClass ?? ""} onChange={(e) => onChange({ ...drill, fixClass: e.target.value || null })}>
          <option value="">Every class</option>
          {FIX_VALUES.map((v) => <option key={v} value={v}>{FIX_LABEL[v]}</option>)}
        </select>
        <label className="inline-flex items-center gap-1">
          <input type="checkbox" checked={drill.view === "excl_pq"}
                 onChange={(e) => onChange({ ...drill, view: e.target.checked ? "excl_pq" : "all" })} />
          Excluding post-quantum
        </label>
        {drill.system && <button type="button" className={BTN} onClick={() => onChange({ ...drill, system: null })}>All systems</button>}
        <button type="button" className={BTN} onClick={onClose} data-testid="agility-baseline-drill-close">Close</button>
      </div>
      {query.isError ? (
        <p className="text-xs text-red-600 dark:text-red-400" role="alert">Couldn&apos;t load the assets. Try again.</p>
      ) : query.isPending ? (
        <p className="text-xs text-zinc-500">Loading…</p>
      ) : (
        <AgilitySubjectsTable items={items} />
      )}
      {query.hasNextPage && (
        <button type="button" className={BTN} disabled={query.isFetchingNextPage} onClick={() => query.fetchNextPage()}
                data-testid="agility-baseline-drill-more">
          {query.isFetchingNextPage ? "Loading…" : `Load more (${items.length} of ${total ?? "?"})`}
        </button>
      )}
    </div>
  );
}

/** The "Agility baseline" section of the CBOM team page. */
export function AgilityBaselineSection({ teamId }: { teamId: number }) {
  const [drill, setDrill] = useState<DrillDown | null>(null);
  const query = useInfiniteQuery({
    queryKey: baselineKeys.baseline(teamId),
    queryFn: ({ pageParam }) => getCbomAgilityBaseline(teamId, pageParam, 50),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.systems.next,
    enabled: Number.isFinite(teamId),
    staleTime: 60_000,
  });
  const first = query.data?.pages[0];
  const systems = query.data?.pages.flatMap((p) => p.systems.items) ?? [];
  return (
    <section className="space-y-3 rounded-lg border border-zinc-200 dark:border-zinc-800 p-4 min-w-0" aria-labelledby="agility-baseline-title">
      <div>
        <h2 id="agility-baseline-title" className="text-base font-semibold text-zinc-900 dark:text-white">Agility baseline</h2>
        <p className="text-xs text-zinc-500 dark:text-zinc-400">Asset, system and enterprise agility by fix class: how much of the estate the team can fix itself.</p>
      </div>
      {query.isError ? (
        <p className="text-sm text-red-600 dark:text-red-400" role="alert" data-testid="agility-baseline-error">
          Couldn&apos;t load the agility baseline. Try again later.
        </p>
      ) : !first ? (
        <p className="text-sm text-zinc-500">Loading…</p>
      ) : (
        <AgilityBaselineView teamId={teamId} baseline={first} systems={systems} onOpen={setDrill}
                             onMoreSystems={query.hasNextPage ? () => query.fetchNextPage() : undefined}
                             loadingMore={query.isFetchingNextPage} />
      )}
      {drill && <DrillDownPanel teamId={teamId} drill={drill} onChange={setDrill} onClose={() => setDrill(null)} />}
    </section>
  );
}
