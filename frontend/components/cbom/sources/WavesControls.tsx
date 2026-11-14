"use client";

// Remediation waves: the suggested wave per asset (1 exposed or harvest-now-decrypt-later critical/high, 2 other
// critical/high, 3 medium/low, 4 post-quantum migration), the team's assignment (wave, owner, target date, status),
// and a bulk-assign bar. Assignments follow the asset's stable identity, so they carry over to later runs and scans.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { toast } from "@/utils/toast";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  cbomOpsKeys,
  getCbomCodeRemediation,
  getCbomRunRemediation,
  putCbomRemediation,
  type CbomAssignmentPatch,
  type CbomRemediationItem,
  type CbomWaveStatus,
} from "@/utils/api/cbom_ops";

import { ErrorBlock, LoadingBlock, SectionCard, StatusBadge, Truncate, type Tone } from "./shared";
import { InfoTip } from "@/components/ui/info-tip";

const WAVE_TONE: Record<number, Tone> = { 1: "red", 2: "amber", 3: "blue", 4: "zinc" };
const STATUS_LABEL: Record<CbomWaveStatus, string> = { open: "Open", in_progress: "In progress", done: "Done", accepted_risk: "Risk accepted" };

export function WaveBadge({ item }: { item: CbomRemediationItem | undefined }) {
  if (!item || item.wave == null) return <span className="text-xs text-zinc-400">—</span>;
  const a = item.assignment;
  return (
    <span className="inline-flex flex-col gap-0.5" data-testid={`wave-${item.asset_key}`}>
      <StatusBadge tone={WAVE_TONE[item.wave] ?? "zinc"} title={item.wave_source === "suggested" ? "Suggested by the rules" : "Assigned"}>
        Wave {item.wave}{item.wave_source === "suggested" ? " (suggested)" : ""}
      </StatusBadge>
      {(a?.owner || a?.target_date) && (
        <span className="text-[11px] text-zinc-500">{[a?.owner, a?.target_date, a?.status ? STATUS_LABEL[a.status] : null].filter(Boolean).join(" · ")}</span>
      )}
    </span>
  );
}

export function useRunRemediation(teamId: number, runId: number, active: boolean) {
  const q = useQuery({
    queryKey: cbomOpsKeys.runRemediation(teamId, runId),
    queryFn: () => getCbomRunRemediation(teamId, runId),
    retry: 1,
    refetchInterval: active ? 15000 : false,
  });
  const byAsset = useMemo(() => new Map((q.data?.items ?? []).map((i) => [i.asset_id ?? -1, i])), [q.data]);
  return { query: q, byAsset };
}

function errorText(err: unknown): string {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  return typeof detail === "string" ? detail : "Could not save the assignment";
}

export function BulkAssignBar({ teamId, target, keys, onDone }: {
  teamId: number;
  target: { run_id: number } | { scan_id: number };
  keys: string[];
  onDone: () => void;
}) {
  const queryClient = useQueryClient();
  const [wave, setWave] = useState("keep");
  const [owner, setOwner] = useState("");
  const [date, setDate] = useState("");
  const [status, setStatus] = useState("keep");
  const save = useMutation({
    mutationFn: () => {
      const fields: Omit<CbomAssignmentPatch, "asset_key"> = {};
      if (wave !== "keep") fields.wave = wave === "suggested" ? null : Number(wave);
      if (owner.trim()) fields.owner = owner.trim();
      if (date) fields.target_date = date;
      if (status !== "keep") fields.status = status as CbomWaveStatus;
      return putCbomRemediation(teamId, { ...target, items: keys.map((asset_key) => ({ asset_key, ...fields })) });
    },
    onSuccess: (out) => {
      toast.success(`Updated ${out.updated} asset${out.updated === 1 ? "" : "s"}`);
      queryClient.invalidateQueries({ queryKey: ["cbom-sources", teamId] });
      onDone();
    },
    onError: (err) => toast.error(errorText(err)),
  });
  if (keys.length === 0) return null;
  return (
    <div className="flex flex-wrap items-end gap-2 rounded-md border border-blue-200 dark:border-blue-900 bg-blue-50/60 dark:bg-blue-950/30 p-2"
         data-testid="bulk-assign">
      <span className="text-sm text-zinc-800 dark:text-zinc-200 self-center">{keys.length} selected</span>
      <Select value={wave} onValueChange={setWave}>
        <SelectTrigger className="w-[150px] cursor-pointer" aria-label="Wave" data-testid="bulk-wave"><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectItem value="keep" className="cursor-pointer">Keep wave</SelectItem>
          {[1, 2, 3, 4].map((w) => <SelectItem key={w} value={String(w)} className="cursor-pointer">Wave {w}</SelectItem>)}
          <SelectItem value="suggested" className="cursor-pointer">Use suggested</SelectItem>
        </SelectContent>
      </Select>
      <InfoTip id="cbsrc.waves.bulk_wave" className="self-center" />
      <Input className="w-[160px]" placeholder="Owner" aria-label="Owner" value={owner} maxLength={128}
             onChange={(e) => setOwner(e.target.value)} data-testid="bulk-owner" />
      <InfoTip id="cbsrc.waves.bulk_owner" className="self-center" />
      <Input className="w-[150px]" type="date" aria-label="Target date" value={date} onChange={(e) => setDate(e.target.value)}
             data-testid="bulk-date" />
      <InfoTip id="cbsrc.waves.bulk_date" className="self-center" />
      <Select value={status} onValueChange={setStatus}>
        <SelectTrigger className="w-[150px] cursor-pointer" aria-label="Status"><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectItem value="keep" className="cursor-pointer">Keep status</SelectItem>
          {(Object.keys(STATUS_LABEL) as CbomWaveStatus[]).map((s) => (
            <SelectItem key={s} value={s} className="cursor-pointer">{STATUS_LABEL[s]}</SelectItem>
          ))}
        </SelectContent>
      </Select>
      <InfoTip id="cbsrc.waves.bulk_status" className="self-center" />
      <Button size="sm" className="cursor-pointer" disabled={save.isPending} onClick={() => save.mutate()} data-testid="bulk-apply">
        Apply
      </Button>
      <Button size="sm" variant="ghost" className="cursor-pointer" onClick={onDone}>Clear</Button>
    </div>
  );
}

/** Code-scan remediation plan: one row per asset (line-independent), suggested and assigned waves, bulk assign. */
export function CodeWavesPanel({ teamId, scanId }: { teamId: number; scanId: number }) {
  const q = useQuery({
    queryKey: cbomOpsKeys.codeRemediation(teamId, scanId),
    queryFn: () => getCbomCodeRemediation(teamId, scanId),
    retry: 1,
  });
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [onlyPlanned, setOnlyPlanned] = useState(true);
  if (q.isLoading) return <LoadingBlock />;
  if (q.isError || !q.data) return <ErrorBlock error={q.error} onRetry={() => q.refetch()} />;
  const items = q.data.items.filter((i) => !onlyPlanned || i.wave != null);
  const toggle = (key: string) => setSelected((s) => { const n = new Set(s); if (n.has(key)) n.delete(key); else n.add(key); return n; });
  return (
    <SectionCard infoId="cbsrc.waves.card" title="Remediation waves" description="Who fixes what, by when; plans carry over to later scans of this repository and branch">
      <div className="space-y-2" data-testid="code-waves">
        <div className="flex flex-wrap gap-2 text-xs">
          {Object.entries(q.data.by_wave).sort().map(([w, n]) => (
            <StatusBadge key={w} tone={WAVE_TONE[Number(w)] ?? "zinc"}>{w === "none" ? "No action" : `Wave ${w}`}: {n}</StatusBadge>
          ))}
          <label className="inline-flex items-center gap-1 cursor-pointer">
            <input type="checkbox" checked={onlyPlanned} onChange={(e) => setOnlyPlanned(e.target.checked)} />
            Only assets that need action
          </label>
          <InfoTip id="cbsrc.waves.only_planned" />
        </div>
        <BulkAssignBar teamId={teamId} target={{ scan_id: scanId }} keys={[...selected]} onDone={() => setSelected(new Set())} />
        <div className="overflow-x-auto max-h-96 border rounded-md">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-white dark:bg-zinc-950">
              <tr className="text-left text-zinc-500">
                <th className="p-2 w-6"><span className="sr-only">Select</span><InfoTip id="cbsrc.waves.select" /></th>
                <th className="p-2">Asset</th>
                <th className="p-2">Impact</th>
                <th className="p-2">Wave</th>
                <th className="p-2">Owner hint</th>
              </tr>
            </thead>
            <tbody>
              {items.map((i) => (
                <tr key={i.asset_key} className="border-t border-zinc-100 dark:border-zinc-800">
                  <td className="p-2">
                    {/* infotip-shared: one row of the selection; the Select column's tip explains it */}
                    <input type="checkbox" aria-label={`Select ${i.label}`} checked={selected.has(i.asset_key)} onChange={() => toggle(i.asset_key)} />
                  </td>
                  <td className="p-2 max-w-[360px]"><Truncate text={i.label} className="font-mono" /></td>
                  <td className="p-2">{i.impact ?? "—"}</td>
                  <td className="p-2"><WaveBadge item={i} /></td>
                  <td className="p-2 text-zinc-500">{i.owner_hint ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </SectionCard>
  );
}
