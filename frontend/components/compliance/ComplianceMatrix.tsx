"use client";

/**
 * Shared stacked-bar compliance matrix used by AIBOM / CBOM / SBOM results.
 * Verdict tokens live in verdictTokens.ts; framework labels in frameworkLabels.ts.
 */

import { useMemo, useState } from "react";
import { Bar, BarChart, XAxis, YAxis } from "recharts";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { Scale, ShieldCheck } from "lucide-react";
import type {
  Compliance,
  ComplianceRequirement,
  ComplianceVerdict,
  FrameworkCoverage,
  FrameworkGroup,
} from "./types";
import { labelFramework } from "./frameworkLabels";
import {
  VERDICT_BADGE,
  VERDICT_COLOR,
  VERDICT_LABEL,
  VERDICT_ORDER,
  isFailingVerdict,
} from "./verdictTokens";

export type {
  Compliance,
  ComplianceRequirement,
  ComplianceVerdict,
  FrameworkCoverage,
  FrameworkGroup,
} from "./types";

export type AttestHandler = (
  frameworkKey: string,
  requirementId: string,
  file: File,
) => Promise<void>;

export interface ComplianceMatrixProps {
  compliance?: Compliance | null;
  title?: string;
  description?: string;
  /** Framework-group chips; omit to hide the filter row (AIBOM default). */
  groups?: FrameworkGroup[];
  /** Default group id when groups are provided (must stay "all" for Phase 0). */
  defaultGroup?: string;
  enableFailingOnly?: boolean;
  enableAttestation?: boolean;
  /**
   * When set, file picks POST via this handler; on success the parent refreshes
   * compliance (server flips NBE → pass_with_evidence). Until then show pending.
   */
  onAttest?: AttestHandler;
  /** Prefer Scale (CBOM) vs ShieldCheck (AIBOM). */
  icon?: "scale" | "shield";
  className?: string;
}

export function ComplianceMatrix({
  compliance,
  title = "Regulatory Compliance Readiness",
  description,
  groups,
  defaultGroup = "all",
  enableFailingOnly = false,
  enableAttestation = false,
  onAttest,
  icon = "shield",
  className,
}: ComplianceMatrixProps) {
  const frameworks = useMemo(
    () =>
      Object.entries(compliance ?? {})
        .filter(
          ([k, v]) => k !== "disclaimer" && typeof v === "object" && v !== null,
        )
        .map(([k, v]) => ({ key: k, ...(v as FrameworkCoverage) })),
    [compliance],
  );

  const [group, setGroup] = useState<string>(defaultGroup);
  const [active, setActive] = useState<string | null>(null);
  const [failingOnly, setFailingOnly] = useState(false);
  /** Local pending filenames while upload in flight (keyed `${fw}:${rid}`). */
  const [pending, setPending] = useState<Record<string, string>>({});
  const [busyKey, setBusyKey] = useState<string | null>(null);

  const shown = useMemo(() => {
    if (!groups?.length) return frameworks;
    const keys = groups.find((g) => g.id === group)?.keys ?? [];
    return keys.length === 0
      ? frameworks
      : frameworks.filter((f) => keys.includes(f.key));
  }, [frameworks, group, groups]);

  if (frameworks.length === 0) return null;

  const data = shown.map((f) => ({
    key: f.key,
    name: labelFramework(f.key),
    pass: f.pass,
    pass_with_evidence: f.pass_with_evidence ?? 0,
    fail: f.fail,
    out_of_scope: f.out_of_scope ?? 0,
    not_bom_evidenceable: f.not_bom_evidenceable ?? 0,
    na: f.na,
  }));

  const cfg: ChartConfig = Object.fromEntries(
    VERDICT_ORDER.map((v) => [
      v,
      { label: VERDICT_LABEL[v], color: VERDICT_COLOR[v] },
    ]),
  );

  const activeFw =
    active && shown.some((f) => f.key === active)
      ? shown.find((f) => f.key === active)!
      : null;
  const reqsAll: ComplianceRequirement[] = activeFw?.requirements ?? [];
  const reqs =
    enableFailingOnly && failingOnly
      ? reqsAll.filter((r) => isFailingVerdict(r.verdict))
      : reqsAll;

  const chipCls = (on: boolean) =>
    `rounded-full border px-3 py-1 text-xs font-medium transition-colors cursor-pointer ${
      on
        ? "border-blue-500/60 bg-blue-500/10 text-blue-600 dark:text-blue-300"
        : "border-zinc-200 dark:border-zinc-700 text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200"
    }`;

  const Icon = icon === "scale" ? Scale : ShieldCheck;
  const desc =
    description ??
    "Per-framework verdicts (advisory). Coverage = pass / (pass + fail). Out of scope (framework doesn't apply) and Not BOM-evidenceable (process evidence) are reported separately — never folded into pass or fail. Click a bar for per-requirement detail.";

  const handleFile = async (fwKey: string, rid: string, file: File) => {
    const key = `${fwKey}:${rid}`;
    setPending((s) => ({ ...s, [key]: file.name }));
    if (!onAttest) {
      // No API wired — keep pending label only (do not fake pass_with_evidence).
      return;
    }
    setBusyKey(key);
    try {
      await onAttest(fwKey, rid, file);
      setPending((s) => {
        const next = { ...s };
        delete next[key];
        return next;
      });
    } catch {
      // keep pending filename so user can retry; parent toasts error
    } finally {
      setBusyKey(null);
    }
  };

  return (
    <Card
      className={
        className ??
        "border-zinc-200 dark:border-zinc-800 col-span-full"
      }
    >
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Icon className="w-4 h-4 text-emerald-600" />
          {title}
        </CardTitle>
        <CardDescription>{desc}</CardDescription>
      </CardHeader>
      <CardContent>
        {(groups?.length || enableFailingOnly) && (
          <div className="mb-4 flex flex-wrap items-center gap-2">
            {!!groups?.length && (
              <>
                <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400 mr-1">
                  Frameworks
                </span>
                {groups.map((g) => (
                  <button
                    key={g.id}
                    type="button"
                    className={chipCls(group === g.id)}
                    onClick={() => {
                      setGroup(g.id);
                      setActive(null);
                    }}
                  >
                    {g.label}
                  </button>
                ))}
              </>
            )}
            {enableFailingOnly && (
              <>
                {!!groups?.length && (
                  <span
                    className="mx-1 h-4 w-px bg-zinc-200 dark:bg-zinc-700"
                    aria-hidden
                  />
                )}
                <button
                  type="button"
                  className={chipCls(failingOnly)}
                  onClick={() => setFailingOnly((v) => !v)}
                >
                  Failures only
                </button>
              </>
            )}
          </div>
        )}

        {data.length === 0 ? (
          <div className="flex h-[160px] items-center justify-center text-sm text-zinc-500 dark:text-zinc-400">
            No frameworks in this group
          </div>
        ) : (
          <div
            style={{
              height: Math.max(
                groups?.length ? 160 : 260,
                data.length * 34 + 40,
              ),
            }}
          >
            <ChartContainer config={cfg} className="aspect-auto h-full w-full">
              <BarChart
                data={data}
                layout="vertical"
                margin={{ top: 4, right: 16, bottom: 4, left: 8 }}
              >
                <XAxis type="number" hide />
                <YAxis
                  dataKey="name"
                  type="category"
                  width={groups?.length ? 140 : 150}
                  tickLine={false}
                  axisLine={false}
                  className="text-xs"
                />
                <ChartTooltip content={<ChartTooltipContent />} />
                {VERDICT_ORDER.map((v, i) => (
                  <Bar
                    key={v}
                    dataKey={v}
                    stackId="a"
                    fill={VERDICT_COLOR[v]}
                    cursor="pointer"
                    radius={
                      i === 0
                        ? [3, 0, 0, 3]
                        : i === VERDICT_ORDER.length - 1
                          ? [0, 3, 3, 0]
                          : undefined
                    }
                    onClick={(_, idx) => setActive(data[idx].key)}
                  />
                ))}
              </BarChart>
            </ChartContainer>
          </div>
        )}

        <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-zinc-600 dark:text-zinc-400">
          {VERDICT_ORDER.map((v) => (
            <span key={v} className="flex items-center gap-1.5">
              <span
                className="size-2.5 rounded-sm"
                style={{ background: VERDICT_COLOR[v] }}
              />
              {VERDICT_LABEL[v]}
            </span>
          ))}
        </div>

        {activeFw && (
          <div className="mt-4 rounded-lg border border-zinc-200 dark:border-zinc-800">
            <div className="px-3 py-2 text-sm font-medium border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between">
              <span>
                {labelFramework(activeFw.key)} — requirements
                {activeFw.coverage != null && (
                  <span className="ml-2 text-xs font-normal text-zinc-500">
                    coverage {Math.round(activeFw.coverage * 100)}%
                  </span>
                )}
              </span>
              <button
                type="button"
                className="text-xs text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 cursor-pointer"
                onClick={() => setActive(null)}
              >
                Close
              </button>
            </div>
            {reqs.length === 0 ? (
              <div className="px-3 py-4 text-sm text-zinc-500">
                No {failingOnly ? "failing " : ""}requirements.
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-36">Verdict</TableHead>
                    <TableHead className="w-28">ID</TableHead>
                    <TableHead>Requirement</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {reqs.map((r) => {
                    const pKey = `${activeFw.key}:${r.id}`;
                    const pendingName = pending[pKey];
                    const v: ComplianceVerdict = r.verdict;
                    const showAttach =
                      enableAttestation &&
                      (r.verdict === "not_bom_evidenceable" || r.attestable) &&
                      r.verdict !== "pass_with_evidence" &&
                      !pendingName;
                    return (
                      <TableRow key={r.id}>
                        <TableCell>
                          <Badge
                            className={VERDICT_BADGE[v] ?? VERDICT_BADGE.na}
                          >
                            {VERDICT_LABEL[v] ?? v}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs text-zinc-600 dark:text-zinc-400">
                          {r.id}
                        </TableCell>
                        <TableCell className="text-sm">
                          {r.title}
                          {r.evidence && (
                            <div className="text-xs text-zinc-500 mt-0.5">
                              {r.evidence}
                            </div>
                          )}
                          {pendingName && (
                            <div className="text-xs text-teal-600 dark:text-teal-400">
                              attested: {pendingName}
                              {busyKey === pKey
                                ? " (uploading…)"
                                : onAttest
                                  ? " (pending re-evaluation)"
                                  : " (pending re-evaluation)"}
                            </div>
                          )}
                          {showAttach && (
                            <label className="mt-1 inline-flex cursor-pointer items-center gap-1 text-xs text-violet-600 dark:text-violet-400 hover:underline">
                              <input
                                type="file"
                                className="hidden"
                                disabled={busyKey != null}
                                onChange={(e) => {
                                  const f = e.target.files?.[0];
                                  if (f) void handleFile(activeFw.key, r.id, f);
                                  e.target.value = "";
                                }}
                              />
                              + Attach attestation
                            </label>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default ComplianceMatrix;
