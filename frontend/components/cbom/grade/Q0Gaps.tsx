"use client";

// Quantum risk -> Q0 gaps (CB-23 PR-A): the team's Q0 Unknown items with their lifecycle, grouped by reason, with
// age, opened, closed and the closing cause. Fed only by GET /{team}/cbom/register/q0 (Q0GapList takes the rows as
// props; Q0GapRegister fetches them). Hooks: q0-gap-<id> (data-reason, data-status), q0-gap-group-<reason>
// (data-count), q0-gaps-status-<open|closed>.
import { useMemo, useState } from "react";

import { formatDateTime } from "@/components/cbom/sources/logic";

import { useGradeModel } from "./api";
import { QGradeChip } from "./QGrade";
import { humanize, reasonTexts, type GradeModel } from "./model";
import {
  KIND_TEXT,
  ageText,
  causeText,
  flattenPages,
  groupByReason,
  subReasonText,
  useQ0Gaps,
  type Q0Gap,
  type Q0GapStatus,
} from "./q0gaps";

function GapRow({ gap }: { gap: Q0Gap }) {
  const sub = subReasonText(gap.sub_reason);
  return (
    <tr className="border-t border-zinc-100 align-top dark:border-zinc-800" data-testid={`q0-gap-${gap.id}`}
        data-reason={gap.reason} data-status={gap.status} data-item-key={gap.item_key}>
      <td className="py-1.5 pr-3">
        <div className="font-medium text-zinc-900 dark:text-zinc-100">{gap.title}</div>
        <div className="text-xs text-zinc-500 dark:text-zinc-400">
          {KIND_TEXT[gap.item_kind] ?? gap.item_kind}
          {gap.source_name ? ` · ${gap.source_name}` : ""}
          {sub ? ` · ${sub}` : ""}
        </div>
      </td>
      <td className="py-1.5 pr-3 whitespace-nowrap text-xs tabular-nums">{ageText(gap.age_days)}</td>
      <td className="py-1.5 pr-3 whitespace-nowrap text-xs">{formatDateTime(gap.opened_at)}</td>
      <td className="py-1.5 pr-3 whitespace-nowrap text-xs">{gap.closed_at ? formatDateTime(gap.closed_at) : "—"}</td>
      <td className="py-1.5 text-xs">
        {gap.status === "closed" ? (
          <span className="inline-flex flex-wrap items-center gap-1.5">
            <span>{causeText(gap.close_cause)}</span>
            {gap.closed_grade && <QGradeChip item={{ q_grade: gap.closed_grade, q_reason: null }} />}
          </span>
        ) : "—"}
      </td>
    </tr>
  );
}

/** The rows of one status grouped by reason (reason sentence from the grade model when given). */
export function Q0GapList({ items, byReason, model, status }: {
  items: Q0Gap[];
  byReason?: Record<string, number>;
  model?: GradeModel | null;
  status: Q0GapStatus;
}) {
  const reasons = useMemo(() => reasonTexts(model), [model]);
  const groups = useMemo(() => groupByReason(items, byReason), [items, byReason]);
  if (!groups.length) {
    return (
      <p className="text-sm text-zinc-500 dark:text-zinc-400" data-testid={`q0-gaps-empty-${status}`}>
        {status === "open" ? "No open Q0 gaps: every evidence area, scope and asset has a grade." : "No closed Q0 gaps yet."}
      </p>
    );
  }
  return (
    <div className="space-y-4">
      {groups.map((group) => {
        const text = reasons.get(group.reason) ?? items.find((i) => i.reason === group.reason)?.reason_text;
        return (
          <section key={group.reason} data-testid={`q0-gap-group-${group.reason}`} data-count={group.total}>
            <h4 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
              {humanize(group.reason)} <span className="font-normal text-zinc-500">({group.total})</span>
            </h4>
            {text && <p className="mb-1 text-xs text-zinc-500 dark:text-zinc-400">{text}</p>}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-zinc-500 dark:text-zinc-400">
                    <th className="py-1 pr-3 font-medium">Item</th>
                    <th className="py-1 pr-3 font-medium">Age</th>
                    <th className="py-1 pr-3 font-medium">Opened</th>
                    <th className="py-1 pr-3 font-medium">Closed</th>
                    <th className="py-1 font-medium">Cause</th>
                  </tr>
                </thead>
                <tbody>{group.items.map((gap) => <GapRow key={gap.id} gap={gap} />)}</tbody>
              </table>
            </div>
          </section>
        );
      })}
    </div>
  );
}

/** Quantum risk -> Q0 gaps: open / closed toggle, the grouped list, "Load more" (keyset pages of 200). */
export function Q0GapRegister({ teamId }: { teamId: number }) {
  const [status, setStatus] = useState<Q0GapStatus>("open");
  const query = useQ0Gaps(teamId, status);
  const model = useGradeModel(teamId).data ?? null;
  const pages = query.data?.pages;
  const items = useMemo(() => flattenPages(pages), [pages]);
  const first = pages?.[0];
  return (
    <div className="space-y-3" data-testid="q0-gap-register">
      <div className="flex flex-wrap items-center gap-2">
        {(["open", "closed"] as Q0GapStatus[]).map((s) => (
          <button key={s} type="button" onClick={() => setStatus(s)} data-testid={`q0-gaps-status-${s}`}
                  aria-pressed={status === s}
                  className={`rounded-md border px-2.5 py-1 text-xs font-medium ${status === s
                    ? "border-blue-600 bg-blue-600 text-white" : "border-zinc-300 text-zinc-700 dark:border-zinc-700 dark:text-zinc-300"}`}>
            {s === "open" ? "Open" : "Closed"}{first ? ` (${first.counts[s] ?? 0})` : ""}
          </button>
        ))}
      </div>
      {query.isLoading && <p className="text-sm text-zinc-500">Loading Q0 gaps…</p>}
      {query.isError && (
        <p className="text-sm text-red-600" role="alert">
          Could not load the Q0 gaps. <button type="button" className="underline" onClick={() => query.refetch()}>Retry</button>
        </p>
      )}
      {query.data && <Q0GapList items={items} byReason={first?.by_reason} model={model} status={status} />}
      {query.hasNextPage && (
        <button type="button" className="text-xs underline" disabled={query.isFetchingNextPage}
                onClick={() => query.fetchNextPage()}>
          {query.isFetchingNextPage ? "Loading…" : "Load more"}
        </button>
      )}
      <p className="text-xs text-zinc-500 dark:text-zinc-400">
        Scope and asset items come from each source&apos;s latest collection run; evidence items from the Evidence tab.
      </p>
    </div>
  );
}
