"use client";

// CBOM Sources inside the per-scan "CBOM Configuration" sidebar (dark-only, like the rest of it).
// Each group has an include switch, off by default: turning one on adds that group's collection run
// (and its credits) to this scan's estimate.  Sources are managed on the CBOM Sources page.

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { ClipboardCheck, Cloud, Network, Server } from "lucide-react";
import type { ReactNode } from "react";

import { AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  getCbomSourcesOverview,
  listCbomRuns,
  type CbomEstimate,
  type CbomInclude,
  type CbomIncludeKey,
  type CbomSourcesOverview,
} from "@/utils/backend_api";

import { cbomSourcesKeys, TERMINAL_RUN } from "./keys";
import { credits, pluralize } from "./logic";
import { RunStatusBadge } from "./shared";

const ITEM = "border-zinc-700 border rounded-lg px-3 mt-2 data-[state=open]:border-blue-500/50";
const TRIGGER = "text-zinc-300 hover:text-white cursor-pointer py-4 hover:no-underline [&[data-state=open]>svg]:rotate-180";

export function useSourcesOverview(teamId: number) {
  return useQuery<CbomSourcesOverview>({
    queryKey: cbomSourcesKeys.overview(teamId),
    queryFn: () => getCbomSourcesOverview(teamId),
    enabled: Number.isFinite(teamId),
    retry: 1,
    staleTime: 30_000,
  });
}

function IncludeRow({ id, checked, disabled, onChange, label }: { id: string; checked: boolean; disabled?: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <div className="flex items-center justify-between gap-3 mt-3">
      <Label htmlFor={id} className="text-zinc-300 text-sm">{label}</Label>
      <Switch id={id} checked={checked} disabled={disabled} onCheckedChange={onChange} className="cursor-pointer" />
    </div>
  );
}

function Line({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex items-center justify-between text-sm py-1">
      <span className="text-zinc-400">{label}</span>
      <span className="text-zinc-200">{value}</span>
    </div>
  );
}

function Manage({ teamId, tab }: { teamId: number; tab: string }) {
  return (
    <Link href={`/${teamId}/cbom/sources?tab=${tab}`} className="inline-block mt-3 text-sm text-blue-400 hover:text-blue-300">
      Manage in CBOM Sources
    </Link>
  );
}

export function SourcesAccordionItems({
  teamId,
  overview,
  include,
  onToggle,
  socAck,
  setSocAck,
}: {
  teamId: number;
  overview: CbomSourcesOverview | undefined;
  include: CbomInclude;
  onToggle: (key: CbomIncludeKey, on: boolean) => void;
  socAck: boolean;
  setSocAck: (v: boolean) => void;
}) {
  const g = overview?.groups ?? {};
  const kinds = g.servers?.by_kind ?? {};
  const serverCount = g.servers?.units ?? 0;
  const clusters = g.kubernetes?.sources ?? 0;
  const databases = g.databases?.sources ?? 0;
  const cloudAccounts = g.cloud?.sources ?? 0;
  const ranges = g.network?.sources ?? 0;
  const nodes = overview?.nodes;
  const ev = overview?.evidence;
  const hasServers = (g.servers?.sources ?? 0) + clusters + databases > 0;

  return (
    <>
      <AccordionItem value="servers" className={ITEM}>
        <AccordionTrigger className={TRIGGER}>
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-zinc-400 shrink-0" />
            <span>Analyze Servers &amp; Clusters</span>
          </div>
        </AccordionTrigger>
        <AccordionContent className="pb-5 pt-0">
          <p className="text-xs text-zinc-500 mb-2">Reached through a scan node inside your network; nothing is installed on the servers it reads unless you deploy host agents.</p>
          <Line label="Scan nodes" value={nodes ? `${nodes.online} online of ${nodes.total}` : "—"} />
          <Line label="Linux servers" value={kinds.linux_servers ? pluralize(kinds.linux_servers, "group") : "Not added"} />
          <Line label="Windows / AD" value={(kinds.windows_servers ?? 0) + (kinds.active_directory ?? 0) || "Not added"} />
          <Line label="Server targets" value={serverCount.toLocaleString()} />
          <Line label="Kubernetes" value={clusters ? pluralize(clusters, "cluster") : "Not added"} />
          <Line label="Databases" value={databases ? pluralize(databases, "instance") : "Not added"} />
          {hasServers && (
            <>
              <IncludeRow id="inc-servers" label="Include servers" checked={!!include.servers} onChange={(v) => onToggle("servers", v)} />
              <IncludeRow id="inc-k8s" label="Include Kubernetes" checked={!!include.kubernetes} disabled={!clusters} onChange={(v) => onToggle("kubernetes", v)} />
              <IncludeRow id="inc-db" label="Include databases" checked={!!include.databases} disabled={!databases} onChange={(v) => onToggle("databases", v)} />
            </>
          )}
          <Manage teamId={teamId} tab="servers" />
        </AccordionContent>
      </AccordionItem>

      <AccordionItem value="cloud" className={ITEM}>
        <AccordionTrigger className={TRIGGER}>
          <div className="flex items-center gap-2 text-left">
            <Cloud className="h-4 w-4 text-zinc-400 shrink-0" />
            <span>
              Analyze Cloud, Keys &amp; Identity
              {cloudAccounts > 0 && <span className="ml-1.5 text-xs text-zinc-500 font-normal whitespace-nowrap">({pluralize(cloudAccounts, "account")})</span>}
            </span>
          </div>
        </AccordionTrigger>
        <AccordionContent className="pb-5 pt-0">
          <Line label="Cloud accounts" value={cloudAccounts || "Not added"} />
          <Line label="CAs and identity providers" value={g.identity?.sources || "Not added"} />
          <p className="text-xs text-zinc-500 mt-2">
            AWS, Azure and Google Cloud accounts are read from ZeroShield&apos;s cloud (4 credits each; an AWS role must pass validation first,
            and an account whose last validation failed is skipped). Identity-provider signing keys are free.
          </p>
          {cloudAccounts + (g.identity?.sources ?? 0) > 0 && (
            <IncludeRow id="inc-cloud" label="Include cloud and identity" checked={!!include.cloud} onChange={(v) => onToggle("cloud", v)} />
          )}
          <Manage teamId={teamId} tab="cloud" />
        </AccordionContent>
      </AccordionItem>

      <AccordionItem value="network" className={ITEM}>
        <AccordionTrigger className={TRIGGER}>
          <div className="flex items-center gap-2">
            <Network className="h-4 w-4 text-zinc-400 shrink-0" />
            <span>Analyze Network TLS</span>
            {ranges > 0 && <span className="text-xs text-zinc-500 font-normal">({pluralize(ranges, "range")})</span>}
          </div>
        </AccordionTrigger>
        <AccordionContent className="pb-5 pt-0">
          <Line label="Allowed ranges" value={ranges || "Not added"} />
          <Line label="Addresses" value={(g.network?.units ?? 0).toLocaleString()} />
          <Line label="Ports" value={overview?.settings.ports ?? "—"} />
          {overview?.settings.stop_all_network && <p className="text-xs text-red-400 mt-2">Network scanning is stopped.</p>}
          {ranges > 0 && (
            <>
              <IncludeRow id="inc-network" label="Include network TLS" checked={!!include.network} onChange={(v) => onToggle("network", v)} />
              {include.network && (
                <label className="flex items-start gap-2 text-xs text-zinc-300 mt-3 cursor-pointer">
                  <input type="checkbox" className="mt-0.5 h-4 w-4 accent-blue-600" checked={socAck} onChange={(e) => setSocAck(e.target.checked)} />
                  Our SOC has agreed the network ranges and scan windows
                </label>
              )}
            </>
          )}
          <Manage teamId={teamId} tab="network" />
        </AccordionContent>
      </AccordionItem>

      <AccordionItem value="evidence" className={ITEM}>
        <AccordionTrigger className={TRIGGER}>
          <div className="flex items-center gap-2">
            <ClipboardCheck className="h-4 w-4 text-zinc-400 shrink-0" />
            <span>Evidence &amp; Attestation</span>
            {ev && <span className="text-xs text-zinc-500 font-normal">({ev.answered} of {ev.areas})</span>}
          </div>
        </AccordionTrigger>
        <AccordionContent className="pb-5 pt-0">
          <p className="text-xs text-zinc-500">Areas that cannot be scanned are answered by owners and vendors. Unanswered areas stay E0 Unknown and visible as Q0 gaps. No charge.</p>
          <Manage teamId={teamId} tab="evidence" />
        </AccordionContent>
      </AccordionItem>
    </>
  );
}

export function SourcesBreakdown({ estimate, codeCredits }: { estimate: CbomEstimate | null; codeCredits: number | null }) {
  if (!estimate) return null;
  const g = estimate.groups;
  const parts = [
    `Code ${codeCredits != null && codeCredits >= 0 ? credits(codeCredits) : "—"}`,
    g.servers ? `Servers ${credits(g.servers.credits)}` : null,
    g.kubernetes ? `Kubernetes ${credits(g.kubernetes.credits)}` : null,
    g.databases ? `Databases ${credits(g.databases.credits)}` : null,
    g.network ? `Network ${credits(g.network.credits)}` : null,
    g.cloud ? `Cloud ${credits(g.cloud.credits)}` : null,
    "Evidence free",
  ].filter(Boolean);
  return <p className="text-xs text-zinc-500 mt-1">{parts.join(" · ")}</p>;
}

export function LinkedSourcesRun({ teamId, scanId }: { teamId: number; scanId: number }) {
  const runs = useQuery({
    queryKey: cbomSourcesKeys.runs(teamId, scanId),
    queryFn: () => listCbomRuns(teamId, scanId),
    enabled: Number.isFinite(teamId) && Number.isFinite(scanId),
    retry: 1,
    refetchInterval: (q) => {
      const latest = q.state.data?.runs?.[0];
      return latest && !TERMINAL_RUN.has(latest.status) ? 15000 : false;
    },
  });
  const latest = runs.data?.runs?.[0];
  if (!latest) return null;
  return (
    <div className="mt-4 rounded-lg border border-zinc-700 p-3 text-sm">
      <div className="flex items-center justify-between gap-2">
        <span className="text-zinc-300">Sources run #{latest.id}</span>
        <RunStatusBadge status={latest.status} />
      </div>
      <p className="text-xs text-zinc-500 mt-1">
        {Object.entries(latest.job_counts ?? {}).map(([k, v]) => `${v} ${k}`).join(" · ") || "No jobs"} · {credits(latest.credits.net)} credits
      </p>
      <Link href={`/${teamId}/cbom/sources?tab=review`} className="inline-block mt-2 text-xs text-blue-400 hover:text-blue-300">
        View in CBOM Sources
      </Link>
    </div>
  );
}
