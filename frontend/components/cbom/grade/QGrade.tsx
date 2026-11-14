"use client";

// Quantum risk grade components (CB-19 PR-1u). Standalone and fed only by the API: give them the run asset list item,
// the asset detail or the run posture as the API returned it; the model text and reason sentences come from
// GET …/sources/grade-model (fetched here, or passed as `model`).
import { ChevronDown, ChevronRight } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";

import { useGradeModel } from "./api";
import {
  detailText,
  explainRows,
  gradeAvailable,
  gradeChipClass,
  gradeText,
  gradeTitle,
  humanize,
  q0ItemCountText,
  q0ItemLine,
  q0Reasons,
  qDistribution,
  reasonTexts,
  SHA_CHECK_TEXT,
  sha256Hex,
  shaCheck,
  type GradeModel,
  type ShaCheck,
  type Q0Item,
  type QExplain,
  type QGradeFields,
  type QPosture,
} from "./model";
import { Tip } from "./Tip";

/** `model` given (also null): use it and fetch nothing; undefined: fetch the grade model with `teamId`. */
function useModel(teamId: number | undefined, model: GradeModel | null | undefined): GradeModel | null {
  const query = useGradeModel(teamId, model === undefined);
  return model === undefined ? query.data ?? null : model;
}

/** "Q1 Critical" as a coloured chip with the text inside; "—" (no grade) with the reason as its title.
 * `assetId` adds the gate hook `data-testid="run-asset-q-<id>"`; `data-q` is the grade key or "none". */
export function QGradeChip({ item, assetId, reasons, testId }: {
  item: QGradeFields;
  assetId?: number;
  reasons?: Map<string, string>;
  testId?: string;
}) {
  const text = gradeText(item.q_grade);
  const hook = testId ?? (assetId != null ? `run-asset-q-${assetId}` : undefined);
  const title = gradeTitle(item, reasons);
  if (!text) {
    // "none": graded, no grade (e.g. no public-key cryptography); "unavailable": the server sent no grade fields
    return (
      <span className="text-xs text-zinc-500 dark:text-zinc-400" title={title} data-testid={hook}
            data-q={gradeAvailable(item) ? "none" : "unavailable"} data-q-reason={item.q_reason ?? undefined}>
        —<span className="sr-only"> {title}</span>
      </span>
    );
  }
  return (
    <span
      className={`inline-flex items-center whitespace-nowrap rounded-md border px-1.5 py-0.5 text-xs font-medium ${gradeChipClass(item.q_grade)}`}
      title={title}
      data-testid={hook}
      data-q={item.q_grade ?? undefined}
      data-q-reason={item.q_reason ?? undefined}
    >
      {text}
    </span>
  );
}

/** The distribution bar with the number of each grade next to its colour; every grade is listed, 0 included. */
export function QDistributionBar({ posture }: { posture: QPosture }) {
  const { segments, total, consistent } = qDistribution(posture);
  return (
    <div className="space-y-2" data-testid="posture-q-distribution" data-total={total}>
      <div className="flex h-3 w-full overflow-hidden rounded bg-zinc-100 dark:bg-zinc-800" aria-hidden="true">
        {segments.filter((s) => s.count > 0).map((s) => (
          <div key={s.bucket} className={s.bar} style={{ width: `${(100 * s.count) / (total || 1)}%` }} />
        ))}
      </div>
      <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
        {segments.map((s) => (
          <li key={s.bucket} className="inline-flex items-center gap-1.5 text-zinc-700 dark:text-zinc-300"
              data-testid={`posture-q-${s.bucket}`} data-count={s.count}>
            <span className={`inline-block h-2.5 w-2.5 rounded-sm ${s.bar}`} aria-hidden="true" />
            <span>{s.text}</span>
            <span className="font-semibold tabular-nums">{s.count}</span>
            {total > 0 && <span className="text-zinc-500 dark:text-zinc-400 tabular-nums">({s.pct}%)</span>}
          </li>
        ))}
      </ul>
      {!consistent && (
        <p className="text-xs text-red-600 dark:text-red-400" role="alert" data-testid="posture-q-mismatch">
          The grade counts ({total}) do not add up to the run&apos;s {posture.assets} assets: please report this.
        </p>
      )}
    </div>
  );
}

/** The run's Q0 Unknown items (unread scope, assets the product could not grade, a missing Mosca input). Hooks:
 * `data-testid="q0-item-<key>"` with `data-reason`. `onOpenAsset` makes asset items open the asset. */
export function Q0ItemList({ items, total, reasons, onOpenAsset, limit }: {
  items: Q0Item[];
  total?: number;
  reasons?: Map<string, string>;
  onOpenAsset?: (assetId: number) => void;
  /** show this many first, with a "Show all" button (default: all) */
  limit?: number;
}) {
  const [all, setAll] = useState(false);
  const shown = limit && !all ? items.slice(0, limit) : items;
  const count = total ?? items.length;
  if (items.length === 0) return <p className="text-xs text-zinc-500 dark:text-zinc-400" data-testid="q0-items-empty">No Q0 Unknown items in this run.</p>;
  return (
    <div className="space-y-1" data-testid="q0-items" data-total={count}>
      <ul className="space-y-1">
        {shown.map((item) => {
          const line = q0ItemLine(item);
          const n = q0ItemCountText(item);
          const detail = detailText(item.detail);
          const addresses = item.addresses ?? [];
          return (
            <li key={item.key} className="rounded-md border border-zinc-200 dark:border-zinc-800 px-2 py-1.5 text-xs min-w-0"
                data-testid={`q0-item-${item.key}`} data-reason={item.reason} data-kind={item.kind}>
              <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                <span className="font-medium text-zinc-900 dark:text-white">{reasons?.get(item.reason) ?? humanize(item.reason)}</span>
                {item.source_name && <span className="text-zinc-500 dark:text-zinc-400">{item.source_name}</span>}
                {n && <span className="text-zinc-500 dark:text-zinc-400 tabular-nums">· {n}</span>}
              </div>
              {line && (
                item.asset_id != null && onOpenAsset ? (
                  <button type="button" className="font-mono text-blue-600 dark:text-blue-400 break-all text-left cursor-pointer"
                          onClick={() => onOpenAsset(item.asset_id as number)} data-testid={`q0-item-open-${item.asset_id}`}>
                    {line}
                  </button>
                ) : (
                  <p className="font-mono text-zinc-700 dark:text-zinc-300 break-all">{line}</p>
                )
              )}
              {detail && <p className="text-zinc-500 dark:text-zinc-400 break-words">{detail}</p>}
              {addresses.length > 0 && (
                <p className="text-zinc-500 dark:text-zinc-400 font-mono break-all">
                  {addresses.slice(0, 5).join(", ")}{addresses.length > 5 ? ` and ${addresses.length - 5} more` : ""}
                </p>
              )}
            </li>
          );
        })}
      </ul>
      {limit && items.length > limit && (
        <button type="button" className="text-xs text-blue-600 dark:text-blue-400 cursor-pointer" onClick={() => setAll(!all)}
                data-testid="q0-items-more">
          {all ? "Show fewer" : `Show all ${items.length}`}
        </button>
      )}
      {count > items.length && (
        <p className="text-xs text-zinc-500 dark:text-zinc-400" data-testid="q0-items-capped">
          Showing the first {items.length} of {count} items (missing inputs and unread sources first).
        </p>
      )}
    </div>
  );
}

/** The served model text, verbatim, with its sha256 as the API gave it and whether this browser computes the same. */
export function QGradeModelBody({ model }: { model: GradeModel }) {
  const [check, setCheck] = useState<ShaCheck>("checking");
  useEffect(() => {
    let live = true;
    const secure = typeof window === "undefined" || window.isSecureContext !== false;
    sha256Hex(model.text).then(
      (sha) => live && setCheck(shaCheck(sha, model.text_sha256, secure)),
      () => live && setCheck(shaCheck(null, model.text_sha256, secure)),
    );
    return () => { live = false; };
  }, [model.text, model.text_sha256]);
  return (
    <div className="space-y-2 min-w-0" data-testid="grade-model-body">
      <pre className="max-h-[60vh] overflow-auto whitespace-pre-wrap break-words rounded-md bg-zinc-50 dark:bg-zinc-900 p-3 text-xs text-zinc-800 dark:text-zinc-200"
           data-testid="grade-model-text">{model.text}</pre>
      <p className="text-xs text-zinc-500 dark:text-zinc-400 break-all">
        Model {model.model} · version <span className="font-mono">{model.model_version}</span>
      </p>
      <p className="text-xs text-zinc-500 dark:text-zinc-400 break-all" data-testid="grade-model-sha" data-sha={model.text_sha256} data-check={check}>
        sha256 of this text: <span className="font-mono">{model.text_sha256}</span>
        {check !== "checking" && (
          <span className={check === "match" ? "text-green-700 dark:text-green-400" : check === "mismatch" ? "text-red-600 dark:text-red-400" : ""}>
            {" · "}{SHA_CHECK_TEXT[check]}
          </span>
        )}
      </p>
    </div>
  );
}

export function QGradeModelDialog({ teamId, open, onOpenChange, model }: {
  teamId?: number;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  model?: GradeModel | null;
}) {
  const query = useGradeModel(teamId, open && model === undefined);
  const m = model === undefined ? query.data : model;
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-3xl" data-testid="grade-model-dialog">
        <DialogHeader>
          <DialogTitle>How grades are computed</DialogTitle>
          <DialogDescription>The signed grade model, as the product serves and applies it.</DialogDescription>
        </DialogHeader>
        {m ? <QGradeModelBody model={m} />
          : query.isError ? <p className="text-sm text-red-600 dark:text-red-400" role="alert">Could not load the grade model.</p>
            : <p className="text-sm text-zinc-500 dark:text-zinc-400">Loading…</p>}
      </DialogContent>
    </Dialog>
  );
}

/** The posture card "Quantum risk": distribution, Q0 Unknown reasons with counts, the Q0 Unknown item list and the model dialog.
 * Renders nothing when the posture has no grades (an older backend). */
export function QDistributionCard({ teamId, posture, onOpenAsset, model }: {
  teamId?: number;
  posture: QPosture;
  onOpenAsset?: (assetId: number) => void;
  model?: GradeModel | null;
}) {
  const [showItems, setShowItems] = useState(false);
  const [dialog, setDialog] = useState(false);
  const m = useModel(teamId, model);
  const reasons = useMemo(() => reasonTexts(m), [m]);
  if (!posture.q_grades) return null;
  const q0 = q0Reasons(posture);
  const items = posture.q0_items ?? [];
  const total = posture.q0_items_total ?? items.length;
  const counts = posture.q0_counts;
  const inputs = posture.grade_inputs;
  return (
    <div className="space-y-3 rounded-lg border border-zinc-200 dark:border-zinc-800 p-3 min-w-0" data-testid="posture-q"
         data-model-version={posture.grade_model_version} data-inputs-digest={inputs?.digest}>
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-sm font-medium text-zinc-900 dark:text-white">Quantum risk</p>
        <Tip id="cbom.qgrade.distribution" />
        <button type="button" className="text-xs text-blue-600 dark:text-blue-400 cursor-pointer" onClick={() => setDialog(true)}
                data-testid="grade-model-open">
          How grades are computed
        </button>
      </div>
      <QDistributionBar posture={posture} />
      {q0.length > 0 && (
        <div className="space-y-1" data-testid="posture-q0-reasons">
          <p className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">Q0 Unknown: why</p>
          <ul className="space-y-0.5">
            {q0.map((r) => (
              <li key={r.code} className="text-xs text-zinc-700 dark:text-zinc-300 flex gap-2" data-testid={`posture-q0-reason-${r.code}`}
                  data-count={r.count}>
                <span className="font-semibold tabular-nums w-8 shrink-0 text-right">{r.count}</span>
                <span className="min-w-0">{reasons.get(r.code) ?? humanize(r.code)}</span>
              </li>
            ))}
          </ul>
          {counts && (
            <p className="text-xs text-zinc-500 dark:text-zinc-400" data-testid="posture-q0-counts">
              {counts.assets} asset{counts.assets === 1 ? "" : "s"} graded Q0 Unknown; {counts.scope_items} unread scope
              item{counts.scope_items === 1 ? "" : "s"} ({counts.scope_rows} row{counts.scope_rows === 1 ? "" : "s"}). Counts are items: a
              missing Mosca setting is one item for every asset it leaves ungraded.
            </p>
          )}
        </div>
      )}
      {total > 0 && (
        <div>
          <button type="button" className="inline-flex items-center gap-1 text-xs text-blue-600 dark:text-blue-400 cursor-pointer"
                  onClick={() => setShowItems(!showItems)} aria-expanded={showItems} data-testid="posture-q0-items-toggle">
            {showItems ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
            {showItems ? "Hide" : "Show"} the {total} Q0 Unknown item{total === 1 ? "" : "s"}
          </button>
          {showItems && <div className="mt-2"><Q0ItemList items={items} total={total} reasons={reasons} onOpenAsset={onOpenAsset} limit={25} /></div>}
        </div>
      )}
      <p className="text-xs text-zinc-500 dark:text-zinc-400 break-all" data-testid="posture-q-inputs">
        Graded with model {posture.grade_model_version ?? posture.grade_model ?? "—"}
        {inputs ? ` · Mosca X ${inputs.mosca.x ?? "not set"}, Y ${inputs.mosca.y ?? "not set"}, Z ${inputs.mosca.z ?? "not set"}` : ""}
        {inputs?.source === "current" ? " (the team's settings now, not when the run started)" : ""}
      </p>
      <QGradeModelDialog teamId={teamId} open={dialog} onOpenChange={setDialog} model={m ?? undefined} />
    </div>
  );
}

/** The asset drawer's grade: chip, the reason sentence and the inputs table (from `q_explain`). */
export function QGradeDrawerSection({ teamId, asset, model }: {
  teamId?: number;
  asset: QGradeFields & { q_explain?: QExplain | null };
  model?: GradeModel | null;
}) {
  const m = useModel(teamId, model);
  const reasons = useMemo(() => reasonTexts(m), [m]);
  if (asset.q_grade === undefined && asset.q_reason === undefined) return null;  // an older backend
  const e = asset.q_explain;
  const reason = asset.q_reason ? reasons.get(asset.q_reason) ?? humanize(asset.q_reason) : null;
  const rows = e ? explainRows(e) : [];
  return (
    <div className="rounded-md border border-zinc-200 dark:border-zinc-700 p-3 space-y-2 min-w-0" data-testid="asset-q-grade"
         data-q={asset.q_grade ?? "none"} data-q-reason={asset.q_reason ?? undefined}>
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs font-semibold text-zinc-800 dark:text-zinc-200">Quantum risk</p>
        <QGradeChip item={asset} reasons={reasons} testId="asset-q-chip" />
        {!asset.q_grade && <span className="text-xs text-zinc-500 dark:text-zinc-400">No grade</span>}
      </div>
      {reason && (
        <p className="text-xs text-zinc-700 dark:text-zinc-300" data-testid="asset-q-reason">
          {reason}{e?.inequality ? ` (X + Y vs Z: ${e.inequality})` : ""}.
        </p>
      )}
      {rows.length > 0 && (
        <dl className="grid grid-cols-1 sm:grid-cols-[minmax(0,16rem)_minmax(0,1fr)] gap-x-4 text-xs" data-testid="asset-q-inputs">
          {rows.map((r) => (
            <div key={r.label} className="contents">
              <dt className="pt-1 sm:py-1 text-zinc-500 dark:text-zinc-400 sm:border-t border-zinc-100 dark:border-zinc-800">{r.label}</dt>
              <dd className="pb-1 sm:py-1 min-w-0 break-words border-b sm:border-b-0 sm:border-t border-zinc-100 dark:border-zinc-800"
                  data-testid={`asset-q-input-${r.label.split(":")[0].toLowerCase().replace(/[^a-z]+/g, "-")}`}>
                <span className="text-zinc-800 dark:text-zinc-200">{r.value}</span>
                {r.basis && <span className="text-zinc-500 dark:text-zinc-400"> · {r.basis}</span>}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}
