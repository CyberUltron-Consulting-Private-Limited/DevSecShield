// The figures the summary's run status banner and drill tiles show (results redesign §2.2, §2.7). Each reads the same
// payload as the view it opens (Rule P: totals from /posture or /results, never counted from table rows), and says "—"
// with the view's own note when that view has no data. Pure, so unit tested.

import type { CbomJob, CbomJobTargets, CbomRun } from "@/utils/backend_api";
import type { CbomPostureWithExposure } from "@/utils/api/cbom_outputs";
import type { CbomDistributions } from "../../CbomCryptoCharts";
import { GRADE_KEYS, GRADE_WORD } from "../../grade/model";
import type { FrameworkSummary } from "../complianceSummary";
import { FRAMEWORK_VERDICT_LABEL } from "../complianceSummary";
import { waveChips, type RunDashboardModel, type SectionView } from "../model";
import type { DetailSection } from "./url";

export interface TileFigure {
  /** the count line; "—" when the view has no data (yet) */
  value: string;
  /** why there is no count (the view's own note), or what the view holds */
  note: string | null;
  loading: boolean;
}

const JOB_WORD: Record<string, string> = {
  success: "done", failure: "failed", expired: "expired", cancelled: "cancelled", pending: "waiting", claimed: "running",
};

const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;

/** "6 jobs: 5 done, 1 failed" from the run's jobs (the collection view's jobs table). */
export function jobsLine(jobs: Pick<CbomJob, "status">[] | undefined): string | null {
  if (!jobs || jobs.length === 0) return null;
  const by = new Map<string, number>();
  for (const j of jobs) by.set(j.status, (by.get(j.status) ?? 0) + 1);
  const parts = [...by.entries()].map(([s, n]) => `${n} ${JOB_WORD[s] ?? s}`);
  return `${plural(jobs.length, "job")}: ${parts.join(", ")}`;
}

/** Jobs that ended with an error (failed, expired, an error message, or nothing read). */
export function jobsWithErrors(jobs: Pick<CbomJob, "status" | "error" | "outcome">[] | undefined): number {
  return (jobs ?? []).filter((j) => j.status === "failure" || j.status === "expired" || !!j.error || j.outcome === "failed").length;
}

export interface RunProblem {
  /** one line per reason, in order */
  lines: string[];
}

/** The summary's run status banner: shown when the run failed, was cancelled or is partial, read no asset, skipped a
 * source at the start, or a job or target ended with an error. null when the run read everything it was asked to. */
export function runProblem(run: Pick<CbomRun, "status" | "jobs" | "breakdown">, opts: {
  assets: number | null; targets: Pick<CbomJobTargets, "error" | "targets">[] | null;
}): RunProblem | null {
  const lines: string[] = [];
  if (run.status === "failed") lines.push("The run failed.");
  else if (run.status === "cancelled") lines.push("The run was cancelled.");
  else if (run.status === "partial") lines.push("The run finished partly: some jobs or targets were not read.");
  const errors = jobsWithErrors(run.jobs);
  if (errors > 0) lines.push(`${plural(errors, "job")} of ${(run.jobs ?? []).length} ended with an error.`);
  const skipped = run.breakdown?.skipped?.length ?? 0;
  if (skipped > 0) lines.push(`${plural(skipped, "source")} skipped at the start.`);
  const notRead = (opts.targets ?? []).reduce((n, j) => n + j.targets.filter((t) => t.status !== "ok").length, 0);
  if (notRead > 0) lines.push(`${plural(notRead, "target")} not fully read.`);
  if (opts.assets === 0 && (run.status === "done" || run.status === "partial" || run.status === "failed")) lines.push("No asset was read.");
  return lines.length ? { lines } : null;
}

export interface TileInputs {
  run: Pick<CbomRun, "jobs"> | undefined;
  posture: CbomPostureWithExposure | null;
  plan: { cryptoCharts: SectionView; dashboard: SectionView; compliance: SectionView };
  resultsPending: boolean;
  dashboardModel: RunDashboardModel;
  distributions: CbomDistributions | null;
  frameworks: FrameworkSummary[];
  waves: { byWave: Record<string, number> | null | undefined; loading: boolean; deferred: boolean };
}

const none = (note: string | null, loading = false): TileFigure => ({ value: "—", note, loading });

/** Each tile's figure, from the payload its view renders. */
export function tileFigures(i: TileInputs): Record<DetailSection, TileFigure> {
  const p = i.posture;
  const collection: TileFigure = (() => {
    const line = jobsLine(i.run?.jobs);
    if (!line) return none("No jobs in this run");
    return { value: p ? `${line} · ${plural(p.assets, "asset")}` : line, note: null, loading: false };
  })();

  const quantum: TileFigure = (() => {
    if (!p) return none(null, true);
    const q = p.q_grades;
    if (!q) return none(null);
    // a grade is printed with its risk word ("Q0 Unknown 25"), never bare (confidenceVocabulary.test.ts)
    const parts = GRADE_KEYS.filter((k) => (q[k] ?? 0) > 0).map((k) => `${k} ${GRADE_WORD[k]} ${q[k]}`);
    if ((q.none ?? 0) > 0) parts.push(`No grade ${q.none}`);
    if (typeof p.fix_class_self_fixable_pct === "number") parts.push(`self-fixable ${p.fix_class_self_fixable_pct}%`);
    return parts.length ? { value: parts.join(" · "), note: null, loading: false } : none(null);
  })();

  const inventory: TileFigure = (() => {
    const c = i.dashboardModel.dashboard?.card_data;
    if (c) return { value: `${plural(c.total_crypto_assets, "crypto asset")} · ${plural(c.total_certificates, "certificate")} · ${plural(c.total_keys, "key")}`, note: null, loading: false };
    if (i.resultsPending) return none(null, true);
    return none(i.plan.dashboard.note ?? i.plan.cryptoCharts.note ?? null);
  })();

  const migration: TileFigure = (() => {
    const pqc = i.distributions?.pqc;
    if (pqc) {
      const groups = new Set((pqc.migration ?? []).map((m) => m.migration_code ?? m.name)).size;
      return { value: `${plural(pqc.quantum_vulnerable ?? 0, "quantum-vulnerable asset")}${groups ? ` · ${plural(groups, "fix", "fixes")}` : ""}`, note: null, loading: false };
    }
    if (i.resultsPending) return none(null, true);
    return none(i.plan.cryptoCharts.note ?? null);
  })();

  const compliance: TileFigure = (() => {
    if (i.frameworks.length) {
      return { value: i.frameworks.map((f) => `${f.framework} ${FRAMEWORK_VERDICT_LABEL[f.verdict]}`).join(" · "), note: null, loading: false };
    }
    if (!i.plan.compliance.show) return none(null, true);
    return none(i.plan.compliance.note ?? null);
  })();

  const remediation: TileFigure = (() => {
    if (i.waves.deferred) return none("Wave counts appear when the run has finished");
    if (i.waves.loading) return none(null, true);
    const chips = waveChips(i.waves.byWave);
    if (!chips.length) return none(null);
    return { value: chips.map((c) => `${c.label}: ${c.count}`).join(" · "), note: null, loading: false };
  })();

  return { collection, quantum, inventory, migration, compliance, remediation };
}
