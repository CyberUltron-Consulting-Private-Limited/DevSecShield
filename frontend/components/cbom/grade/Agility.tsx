"use client";

// Crypto-agility components (CB-24 PR-1u). Standalone and fed only by the API: the run asset list item (fix_class,
// fix_class_floor, fix_class_confidence), the asset detail's `agility` block, the run posture's fix-class counts, and
// GET …/sources/agility-model for the rule and unknown-reason sentences (fetched here, or passed as `model`).
import { useMemo, useState } from "react";

import { useAgilityModel } from "./api";
import {
  FIX_CLASSES,
  FIX_LABEL,
  fixClassAvailable,
  fixClassChipClass,
  fixClassText,
  fixClassTitle,
  fixDistribution,
  humanize,
  isFixValue,
  ruleTexts,
  selfFixablePct,
  type AgilityDetail,
  type AgilityModel,
  type AgilityPosture,
  type FixClassFields,
} from "./model";
import { InfoTip } from "@/components/ui/info-tip";
import { fixClassTipId } from "./tips";

function useModel(teamId: number | undefined, model: AgilityModel | null | undefined): AgilityModel | null {
  const query = useAgilityModel(teamId, model === undefined);
  return model === undefined ? query.data ?? null : model;
}

/** The fix class as a chip with its text ("Vendor-fixed", "At least vendor-fixed", "—"); "likely" when inferred.
 * `assetId` adds the gate hook `data-testid="run-asset-fixclass-<id>"`; `data-fix-class` is the API value or "none". */
export function FixClassChip({ item, assetId, testId }: { item: FixClassFields; assetId?: number; testId?: string }) {
  const v = item.fix_class;
  const hook = testId ?? (assetId != null ? `run-asset-fixclass-${assetId}` : undefined);
  const text = fixClassText(item);
  const title = fixClassTitle(item);
  if (v == null || v === "" || v === "none") {
    // "none": no finding code; "unavailable": the server sent no fix class
    return (
      <span className="text-xs text-zinc-500 dark:text-zinc-400" title={title} data-testid={hook}
            data-fix-class={fixClassAvailable(item) ? "none" : "unavailable"}>
        —<span className="sr-only"> {title}</span>
      </span>
    );
  }
  return (
    <span
      className={`inline-flex items-center gap-1 whitespace-nowrap rounded-md border px-1.5 py-0.5 text-xs font-medium ${fixClassChipClass(v)}`}
      title={title}
      data-testid={hook}
      data-fix-class={v}
      data-fix-floor={item.fix_class_floor ?? undefined}
      data-fix-confidence={item.fix_class_confidence ?? undefined}
    >
      {text}
      {item.fix_class_confidence === "inferred" && <span className="font-normal opacity-80">· likely</span>}
    </span>
  );
}

/** An evidence area or vendor as an agility subject (GET …/sources/evidence, CB-24): the HSM firmware area
 * (hardware-fixed) and the third-party area (vendor-fixed) once answered, each vendor (vendor-fixed); an unanswered one
 * of those two areas is "not assessed"; the process areas carry no class and show nothing. */
export function EvidenceFixClass({ item, testId }: {
  item: { fix_class?: string | null; not_assessed?: boolean };
  testId?: string;
}) {
  if (item.fix_class) {
    return <span className="inline-flex"><FixClassChip item={{ fix_class: item.fix_class, fix_class_confidence: "observed" }} testId={testId} /></span>;
  }
  if (item.not_assessed) {
    return (
      <span className="text-xs text-zinc-500 dark:text-zinc-400" data-testid={testId} data-fix-class="not_assessed"
            title="Fix class: answer this area to classify it">
        Fix class: not assessed
      </span>
    );
  }
  return null;
}

/** Bar and the six counts (every value listed, 0 included), with the "all / excluding post-quantum" toggle. */
export function AgilityDistribution({ posture }: { posture: AgilityPosture }) {
  const [exclPq, setExclPq] = useState(false);
  const counts = exclPq ? posture.fix_classes_excl_pq : posture.fix_classes;
  const d = fixDistribution(counts, posture.assets);
  const pct = exclPq ? selfFixablePct(counts ?? {}) : posture.fix_class_self_fixable_pct ?? selfFixablePct(counts ?? {});
  return (
    <div className="space-y-2" data-testid="posture-fix-distribution" data-view={exclPq ? "excl_pq" : "all"} data-total={d.total}>
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <p className="text-xl font-semibold text-zinc-900 dark:text-white" data-testid="posture-fix-self-fixable" data-pct={pct ?? ""}>
          {pct == null ? "—" : `${pct}%`}
        </p>
        <p className="text-xs text-zinc-600 dark:text-zinc-400">
          {pct == null
            ? "self-fixable: no asset has one of the four fix classes"
            : `self-fixable: ${d.selfFixable} of ${d.classified} assets with a fix class are configurable or code-fixed`}
        </p>
        <InfoTip id="cbom.agility.self_fixable" />
      </div>
      <div className="flex flex-wrap items-center gap-2 text-xs" role="group" aria-label="Codes counted">
        <button type="button" aria-pressed={!exclPq} onClick={() => setExclPq(false)} data-testid="posture-fix-view-all"
                className={`rounded border px-2 py-0.5 cursor-pointer ${!exclPq ? "border-blue-500 text-blue-700 dark:text-blue-300" : "border-zinc-300 text-zinc-600 dark:text-zinc-400"}`}>
          All findings
        </button>
        <button type="button" aria-pressed={exclPq} onClick={() => setExclPq(true)} data-testid="posture-fix-view-excl-pq"
                disabled={!posture.fix_classes_excl_pq}
                className={`rounded border px-2 py-0.5 cursor-pointer disabled:opacity-50 ${exclPq ? "border-blue-500 text-blue-700 dark:text-blue-300" : "border-zinc-300 text-zinc-600 dark:text-zinc-400"}`}>
          Excluding post-quantum
        </button>
        <InfoTip id="cbom.agility.excl_pq" />
      </div>
      <div className="flex h-3 w-full overflow-hidden rounded bg-zinc-100 dark:bg-zinc-800" aria-hidden="true">
        {d.segments.filter((s) => s.count > 0).map((s) => (
          <div key={s.value} className={s.bar} style={{ width: `${(100 * s.count) / (d.total || 1)}%` }} />
        ))}
      </div>
      <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
        {d.segments.map((s) => (
          <li key={s.value} className="inline-flex items-center gap-1.5 text-zinc-700 dark:text-zinc-300"
              data-testid={`posture-fix-${s.value}`} data-count={s.count}>
            <span className={`inline-block h-2.5 w-2.5 rounded-sm ${s.bar}`} aria-hidden="true" />
            <span>{s.text}</span>
            <span className="font-semibold tabular-nums">{s.count}</span>
            {d.total > 0 && <span className="text-zinc-500 dark:text-zinc-400 tabular-nums">({s.pct}%)</span>}
          </li>
        ))}
      </ul>
      {!d.consistent && (
        <p className="text-xs text-red-600 dark:text-red-400" role="alert" data-testid="posture-fix-mismatch">
          The fix-class counts ({d.total}) do not add up to the run&apos;s {posture.assets} assets: please report this.
        </p>
      )}
    </div>
  );
}

/** The run posture card "How hard is this to fix?": self-fixable headline, six counts (all / excluding post-quantum),
 * unknown reasons and the per-system table. Renders nothing when the posture has no fix classes (an older backend). */
export function AgilityPostureCard({ teamId, posture, model }: {
  teamId?: number;
  posture: AgilityPosture;
  model?: AgilityModel | null;
}) {
  const m = useModel(teamId, model);
  const [showSystems, setShowSystems] = useState(false);
  if (!posture.fix_classes) return null;
  const unknown = Object.entries(posture.unknown_reasons ?? {}).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const systems = posture.fix_class_systems ?? [];
  return (
    <div className="space-y-3 rounded-lg border border-zinc-200 dark:border-zinc-800 p-3 min-w-0" data-testid="posture-fix"
         data-agility-version={posture.agility_version}>
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-sm font-medium text-zinc-900 dark:text-white">How hard is this to fix?</p>
        <span className="text-xs text-zinc-500 dark:text-zinc-400">Crypto-agility: the hardest fix class of each asset</span>
      </div>
      <AgilityDistribution posture={posture} />
      <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-zinc-500 dark:text-zinc-400">
        {FIX_CLASSES.map((c) => {
          const id = fixClassTipId(c);
          return id ? <span key={c} className="inline-flex flex-wrap items-center gap-1">{FIX_LABEL[c]} <InfoTip id={id} /></span> : null;
        })}
        <span className="inline-flex flex-wrap items-center gap-1">Unknown <InfoTip id="cbom.agility.unknown" /></span>
        <span className="inline-flex flex-wrap items-center gap-1">Likely <InfoTip id="cbom.agility.inferred" /></span>
      </div>
      {unknown.length > 0 && (
        <div data-testid="posture-fix-unknown-reasons">
          <p className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">Unknown: what was not read</p>
          <ul className="space-y-0.5">
            {unknown.map(([code, n]) => (
              <li key={code} className="text-xs text-zinc-700 dark:text-zinc-300 flex gap-2" data-testid={`posture-fix-unknown-${code}`} data-count={n}>
                <span className="font-semibold tabular-nums w-8 shrink-0 text-right">{n}</span>
                <span className="min-w-0">{m?.unknown_reasons?.[code] ?? humanize(code)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {systems.length > 0 && (
        <div>
          <button type="button" className="text-xs text-blue-600 dark:text-blue-400 cursor-pointer" aria-expanded={showSystems}
                  onClick={() => setShowSystems(!showSystems)} data-testid="posture-fix-systems-toggle">
            {showSystems ? "Hide" : "Show"} per system ({systems.length}{posture.fix_class_systems_truncated ? "+" : ""})
          </button>
          {showSystems && (
            <div className="mt-2 overflow-x-auto">
              <table className="w-full text-xs" data-testid="posture-fix-systems">
                <thead>
                  <tr className="text-left text-zinc-500 dark:text-zinc-400">
                    <th className="py-1 pr-3 font-normal">System</th>
                    <th className="py-1 pr-3 font-normal text-right">Assets</th>
                    <th className="py-1 pr-3 font-normal">Hardest</th>
                    <th className="py-1 pr-3 font-normal text-right">Self-fixable</th>
                    <th className="py-1 font-normal text-right">Unknown</th>
                  </tr>
                </thead>
                <tbody>
                  {systems.map((s) => (
                    <tr key={s.key} className="border-t border-zinc-100 dark:border-zinc-800" data-testid={`posture-fix-system-${s.key}`}>
                      <td className="py-1 pr-3 text-zinc-800 dark:text-zinc-200 break-all">
                        {s.label} <span className="text-zinc-500 dark:text-zinc-400">({s.kind === "application" ? "application" : "source"})</span>
                      </td>
                      <td className="py-1 pr-3 text-right tabular-nums">{s.assets}</td>
                      <td className="py-1 pr-3"><FixClassChip item={{ fix_class: s.hardest ?? "none" }} /></td>
                      <td className="py-1 pr-3 text-right tabular-nums">{s.self_fixable_pct == null ? "—" : `${s.self_fixable_pct}%`}</td>
                      <td className="py-1 text-right tabular-nums">{s.counts.unknown ?? 0}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {posture.fix_class_systems_truncated && (
                <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">The largest {systems.length} systems are listed.</p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** The asset drawer's "How hard is this to fix?": the asset's class (floor, confidence) and one row per finding code
 * with its class, the rule that decided it and the fact it read. */
export function AgilityDrawerSection({ teamId, agility, model }: {
  teamId?: number;
  agility: AgilityDetail | null | undefined;
  model?: AgilityModel | null;
}) {
  const m = useModel(teamId, model);
  const rules = useMemo(() => ruleTexts(m), [m]);
  if (!agility) return null;  // an older backend
  const asset: FixClassFields = { fix_class: agility.fix_class, fix_class_floor: agility.floor, fix_class_confidence: agility.confidence };
  const inferred = agility.by_code.some((p) => p.confidence === "inferred");
  return (
    <div className="rounded-md border border-zinc-200 dark:border-zinc-700 p-3 space-y-2 min-w-0" data-testid="asset-fix-class"
         data-fix-class={agility.fix_class} data-fix-floor={agility.floor ?? undefined} data-fix-confidence={agility.confidence ?? undefined}>
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs font-semibold text-zinc-800 dark:text-zinc-200">How hard is this to fix?</p>
        <FixClassChip item={asset} testId="asset-fix-chip" />
        {isFixValue(agility.fix_class) && fixClassTipId(agility.fix_class) && <InfoTip id={fixClassTipId(agility.fix_class)!} />}
        {agility.confidence && (
          <span className="text-xs text-zinc-500 dark:text-zinc-400">{agility.confidence === "inferred" ? "Likely (inferred)" : "Observed"}</span>
        )}
      </div>
      {agility.fix_class === "unknown" && (
        <p className="text-xs text-zinc-600 dark:text-zinc-400">
          A fact that decides the class was not read
          {isFixValue(agility.floor) ? `: it is at least ${fixClassText({ fix_class: agility.floor }).toLowerCase()}` : ""}.
        </p>
      )}
      {agility.fix_class_excl_pq && agility.fix_class_excl_pq !== agility.fix_class && (
        <p className="text-xs text-zinc-500 dark:text-zinc-400" data-testid="asset-fix-excl-pq" data-fix-class={agility.fix_class_excl_pq}>
          Without the post-quantum migration codes: {agility.fix_class_excl_pq === "none"
            ? "nothing to change today" : fixClassText({ fix_class: agility.fix_class_excl_pq })}.
        </p>
      )}
      {agility.by_code.length === 0 ? (
        <p className="text-xs text-zinc-500 dark:text-zinc-400">No finding code: nothing to change today.</p>
      ) : (
        <ul className="text-xs divide-y divide-zinc-100 dark:divide-zinc-800" data-testid="asset-fix-codes">
          {agility.by_code.map((p) => (
            <li key={p.code} className="py-1.5 space-y-0.5 min-w-0" data-testid={`asset-fix-code-${p.code}`}
                data-fix-class={p.class} data-rule={p.rule}>
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <span className="font-mono text-zinc-800 dark:text-zinc-200 break-all">{p.code}</span>
                <FixClassChip item={{ fix_class: p.class, fix_class_floor: p.floor, fix_class_confidence: p.confidence }} />
                <span className="font-mono text-zinc-500 dark:text-zinc-400" title={rules.get(p.rule)}>rule {p.rule}</span>
              </div>
              <p className="text-zinc-600 dark:text-zinc-400 break-words">{p.basis}</p>
              {p.fact && <p className="text-zinc-500 dark:text-zinc-400 break-words">Read: {p.fact}</p>}
            </li>
          ))}
        </ul>
      )}
      {inferred && (
        <p className="text-xs text-zinc-500 dark:text-zinc-400 flex flex-wrap items-center gap-1">
          &quot;Likely&quot;: no fact the product read decides that class; it is the table&apos;s default. <InfoTip id="cbom.agility.inferred" />
        </p>
      )}
      <p className="text-xs text-zinc-500 dark:text-zinc-400 break-all">Model {agility.model} · {agility.model_version}</p>
    </div>
  );
}
