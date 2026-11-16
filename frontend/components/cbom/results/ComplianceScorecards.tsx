"use client";

// 12-A (run results redesign): the crypto compliance readiness of a run (the code page's ComplianceMatrix data, from
// GET /runs/{id}/parity cbom_compliance) as one scorecard per framework: a ring of requirements passed out of all its
// requirements, a verdict chip, the failing requirements and the assets the worst of them fails. A click on a card opens
// that framework's requirements inline (every requirement with its verdict, evidence, source and failing assets; the
// same "Failures only" filter and attestation upload as the matrix). The framework groups are the matrix's.

import { useId, useState } from "react";
import { Scale } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { InfoTip } from "@/components/ui/info-tip";
import { labelFramework } from "@/components/compliance/frameworkLabels";
import type { AttestHandler, Compliance, ComplianceRequirement, FrameworkCoverage, FrameworkGroup } from "@/components/compliance/ComplianceMatrix";
import { VERDICT_BADGE, VERDICT_COLOR, VERDICT_LABEL, isFailingVerdict } from "@/components/compliance/verdictTokens";

type Verdict = "pass" | "partial" | "fail" | "not_assessed";
const VERDICT_CHIP: Record<Verdict, [string, string]> = {
  pass: ["Pass", "border-emerald-500/50 bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300"],
  partial: ["Partial", "border-amber-500/50 bg-amber-50 text-amber-800 dark:bg-amber-950/40 dark:text-amber-300"],
  fail: ["Fail", "border-red-500/50 bg-red-50 text-red-700 dark:bg-red-950/40 dark:text-red-300"],
  not_assessed: ["Not assessed", "border-zinc-400/50 bg-zinc-50 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300"],
};
const RING: Record<Verdict, string> = { pass: "#10b981", partial: "#eab308", fail: "#dc2626", not_assessed: "#a1a1aa" };

export interface FrameworkScore {
  key: string;
  passed: number;
  total: number;
  failing: number;
  /** the assets the worst failing requirement fails (null: the requirements do not say) */
  assets: number | null;
  verdict: Verdict;
  coverage: number | null;
}

/** A framework's scorecard figures, from its verdict counts as the server sent them (nothing recounted from rows). */
export function frameworkScore(key: string, f: FrameworkCoverage): FrameworkScore {
  const passed = (f.pass ?? 0) + (f.pass_with_evidence ?? 0);
  const failing = f.fail ?? 0;
  const total = passed + failing + (f.out_of_scope ?? 0) + (f.not_bom_evidenceable ?? 0) + (f.na ?? 0);
  const counts = (f.requirements ?? []).filter((r) => r.verdict === "fail")
    .map((r) => (r as ComplianceRequirement & { failing?: number }).failing)
    .filter((n): n is number => typeof n === "number");
  const verdict: Verdict = failing > 0 ? (passed > 0 ? "partial" : "fail") : passed > 0 ? "pass" : "not_assessed";
  return { key, passed, total, failing, assets: counts.length ? Math.max(...counts) : null, verdict, coverage: f.coverage ?? null };
}

function Ring({ score }: { score: FrameworkScore }) {
  const share = score.total ? (100 * score.passed) / score.total : 0;
  return (
    <svg viewBox="0 0 42 42" className="h-20 w-20 shrink-0" role="img" aria-label={`${score.passed} of ${score.total} requirements passed`}>
      <circle cx="21" cy="21" r="15.9" fill="none" strokeWidth="5" className="stroke-zinc-200 dark:stroke-zinc-800" />
      {share > 0 && (
        <circle cx="21" cy="21" r="15.9" fill="none" strokeWidth="5" stroke={RING[score.verdict]}
                strokeDasharray={`${share} ${100 - share}`} strokeDashoffset="25" />
      )}
      <text x="21" y="23.5" textAnchor="middle" fontSize="7" fontWeight="700" className="fill-zinc-900 dark:fill-zinc-100">
        {score.passed}/{score.total}
      </text>
    </svg>
  );
}

const plural = (n: number, one: string) => `${n} ${one}${n === 1 ? "" : "s"}`;

export function ComplianceScorecards({ compliance, groups, enableFailingOnly = true, enableAttestation = true, onAttest,
  title = "Crypto compliance readiness" }: {
  compliance: Compliance;
  groups?: FrameworkGroup[];
  enableFailingOnly?: boolean;
  enableAttestation?: boolean;
  onAttest?: AttestHandler;
  title?: string;
}) {
  const frameworks = Object.entries(compliance ?? {})
    .filter(([k, v]) => k !== "disclaimer" && typeof v === "object" && v !== null)
    .map(([k, v]) => ({ key: k, ...(v as FrameworkCoverage) }));
  const [group, setGroup] = useState("all");
  const [active, setActive] = useState<string | null>(null);
  const [failingOnly, setFailingOnly] = useState(false);
  const [pending, setPending] = useState<Record<string, string>>({});
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const detailId = useId();
  if (frameworks.length === 0) return null;
  const keys = groups?.find((g) => g.id === group)?.keys ?? [];
  const shown = keys.length === 0 ? frameworks : frameworks.filter((f) => keys.includes(f.key));
  const activeFw = active ? shown.find((f) => f.key === active) ?? null : null;
  const reqsAll = activeFw?.requirements ?? [];
  const reqs = enableFailingOnly && failingOnly ? reqsAll.filter((r) => isFailingVerdict(r.verdict)) : reqsAll;
  const chipCls = (on: boolean) =>
    `rounded-full border px-3 py-1 text-xs font-medium transition-colors cursor-pointer ${
      on ? "border-blue-500/60 bg-blue-500/10 text-blue-600 dark:text-blue-300"
        : "border-zinc-200 dark:border-zinc-700 text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200"}`;

  const handleFile = async (fwKey: string, rid: string, file: File) => {
    const key = `${fwKey}:${rid}`;
    setPending((s) => ({ ...s, [key]: file.name }));
    if (!onAttest) return;  // no API wired: keep the pending label only (never a fake pass)
    setBusyKey(key);
    try {
      await onAttest(fwKey, rid, file);
      setPending((s) => {
        const next = { ...s };
        delete next[key];
        return next;
      });
    } catch {
      // keep the pending file name so the user can retry; the parent toasts the error
    } finally {
      setBusyKey(null);
    }
  };

  return (
    <Card className="border-zinc-200 dark:border-zinc-800 col-span-full" data-testid="compliance-scorecards">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Scale className="w-4 h-4 text-emerald-600" />
          {title}
          <InfoTip id="cbom.run.compliance_readiness" />
        </CardTitle>
        <CardDescription>
          Per-framework verdicts (advisory). Coverage = pass / (pass + fail). Out of scope (framework doesn&apos;t apply) and Not
          BOM-evidenceable (process evidence) are reported separately — never folded into pass or fail. Click a card for
          per-requirement detail.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {(groups?.length || enableFailingOnly) && (
          <div className="flex flex-wrap items-center gap-2">
            {!!groups?.length && (
              <>
                <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400 mr-1">Frameworks</span>
                {groups.map((g) => (
                  <button key={g.id} type="button" className={chipCls(group === g.id)} aria-pressed={group === g.id}
                          onClick={() => { setGroup(g.id); setActive(null); }}>
                    {g.label}
                  </button>
                ))}
              </>
            )}
            {enableFailingOnly && (
              <>
                {!!groups?.length && <span className="mx-1 h-4 w-px bg-zinc-200 dark:bg-zinc-700" aria-hidden />}
                <button type="button" className={chipCls(failingOnly)} aria-pressed={failingOnly} onClick={() => setFailingOnly((v) => !v)}>
                  Failures only
                </button>
              </>
            )}
          </div>
        )}
        {shown.length === 0 ? (
          <div className="flex h-[120px] items-center justify-center text-sm text-zinc-500 dark:text-zinc-400">No frameworks in this group</div>
        ) : (
          <ul className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-5 gap-3">
            {shown.map((f) => {
              const s = frameworkScore(f.key, f);
              const [chip, chipClass] = VERDICT_CHIP[s.verdict];
              const on = active === f.key;
              return (
                <li key={f.key} className="min-w-0">
                  <button type="button" aria-expanded={on} aria-controls={detailId} onClick={() => setActive(on ? null : f.key)}
                          data-testid={`compliance-card-${f.key}`} data-verdict={s.verdict} data-passed={s.passed} data-total={s.total}
                          className={`flex h-full w-full flex-col gap-2 rounded-xl border p-3 text-left cursor-pointer transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                            on ? "border-blue-500 bg-blue-50/60 dark:bg-blue-950/30" : "border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:border-zinc-300 dark:hover:border-zinc-700"}`}>
                    <span className="flex items-start justify-between gap-2">
                      <span className="text-sm font-semibold text-zinc-900 dark:text-white break-words">{labelFramework(f.key)}</span>
                      <Badge variant="outline" className={chipClass}>{chip}</Badge>
                    </span>
                    <span className="flex items-center gap-3">
                      <Ring score={s} />
                      <span className="space-y-0.5 text-xs text-zinc-600 dark:text-zinc-400">
                        <span className="block" data-testid={`compliance-card-${f.key}-failing`}>
                          {s.failing > 0 ? `${plural(s.failing, "requirement")} failing` : "No requirement failing"}
                        </span>
                        {s.assets != null && s.assets > 0 && (
                          <span className="block" data-testid={`compliance-card-${f.key}-assets`}>{plural(s.assets, "asset")} fail the worst one</span>
                        )}
                        {s.coverage != null && <span className="block">coverage {Math.round(s.coverage * 100)}%</span>}
                      </span>
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
        <div id={detailId} hidden={!activeFw} data-testid="compliance-detail">
          {activeFw && (
            <div className="rounded-lg border border-zinc-200 dark:border-zinc-800">
              <div className="px-3 py-2 text-sm font-medium border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between gap-2">
                <span>
                  {labelFramework(activeFw.key)} — requirements
                  {activeFw.coverage != null && (
                    <span className="ml-2 text-xs font-normal text-zinc-500 dark:text-zinc-400">coverage {Math.round(activeFw.coverage * 100)}%</span>
                  )}
                </span>
                <button type="button" className="text-xs text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-300 cursor-pointer"
                        onClick={() => setActive(null)}>
                  Close
                </button>
              </div>
              {reqs.length === 0 ? (
                <div className="px-3 py-4 text-sm text-zinc-500 dark:text-zinc-400">No {failingOnly ? "failing " : ""}requirements.</div>
              ) : (
                <ul className="divide-y divide-zinc-200 dark:divide-zinc-800">
                  {reqs.map((r) => {
                    const pKey = `${activeFw.key}:${r.id}`;
                    const pendingName = pending[pKey];
                    const failingAssets = (r as ComplianceRequirement & { failing?: number }).failing;
                    const showAttach = enableAttestation && (r.verdict === "not_bom_evidenceable" || r.attestable)
                      && r.verdict !== "pass_with_evidence" && !pendingName;
                    return (
                      <li key={r.id} className="flex flex-col gap-1 px-3 py-2 sm:flex-row sm:items-start sm:gap-3" data-testid={`compliance-req-${r.id}`}
                          data-verdict={r.verdict}>
                        <span className="flex shrink-0 items-center gap-2 sm:w-56">
                          <Badge className={VERDICT_BADGE[r.verdict] ?? VERDICT_BADGE.na}>
                            <span className="mr-1 inline-block h-2 w-2 rounded-sm" style={{ background: VERDICT_COLOR[r.verdict] ?? VERDICT_COLOR.na }} aria-hidden />
                            {VERDICT_LABEL[r.verdict] ?? r.verdict}
                          </Badge>
                          <span className="font-mono text-xs text-zinc-600 dark:text-zinc-400">{r.id}</span>
                        </span>
                        <span className="min-w-0 text-sm">
                          {r.title}
                          {r.evidence && <span className="block text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">{r.evidence}</span>}
                          {r.source && <span className="block text-xs text-zinc-500 dark:text-zinc-400">{r.source}</span>}
                          {typeof failingAssets === "number" && failingAssets > 0 && (
                            <span className="block text-xs text-red-600 dark:text-red-400" data-testid={`compliance-req-${r.id}-failing`}>
                              {plural(failingAssets, "asset")} fail it
                            </span>
                          )}
                          {pendingName && (
                            <span className="block text-xs text-teal-600 dark:text-teal-400">
                              attested: {pendingName}{busyKey === pKey ? " (uploading…)" : " (pending re-evaluation)"}
                            </span>
                          )}
                          {showAttach && (
                            <label className="mt-1 inline-flex cursor-pointer items-center gap-1 text-xs text-violet-600 dark:text-violet-400 hover:underline">
                              {/* infotip-shared: the attestation upload belongs to the requirement above; the card's tip explains it */}
                              <input type="file" className="hidden" disabled={busyKey != null}
                                     onChange={(e) => {
                                       const file = e.target.files?.[0];
                                       if (file) void handleFile(activeFw.key, r.id, file);
                                       e.target.value = "";
                                     }} />
                              + Attach attestation
                            </label>
                          )}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
