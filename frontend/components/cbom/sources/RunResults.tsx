"use client";

// What a collection run found: every target's outcome (nothing skipped silently), the asset table with
// filters, and the CycloneDX download.  All numbers come from /runs/{id}/assets, the same query the
// export uses, so the table, the chips and the file always agree.

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, Download, Loader2, ShieldAlert } from "lucide-react";
import { Fragment, useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  downloadCbomRunCbom,
  getCbomRunAssets,
  type CbomAsset,
  type CbomAssetFilters,
  type CbomImpact,
  type CbomJobTargets,
} from "@/utils/backend_api";

import { downloadCbomRunBom } from "@/utils/api/cbom_outputs";

import { cbomSourcesKeys } from "./keys";
import { pluralize } from "./logic";
import { RunInsights } from "./ChangesPanel";
import { AssetDetailPanel, RunPostureCard } from "./RunPosture";
import { BulkAssignBar, useRunRemediation, WaveBadge } from "./WavesControls";
import { ErrorBlock, LoadingBlock, StatusBadge, Truncate, type Tone } from "./shared";

export const ASSET_TYPE_LABEL: Record<string, string> = {
  certificate: "Certificate",
  private_key: "Private key",
  public_key: "Public key",
  keystore: "Keystore",
  ssh_host_key: "SSH host key",
  ssh_server_config: "SSH server config",
  ssh_endpoint: "SSH endpoint",
  tls_endpoint: "TLS endpoint",
  crypto_library: "Crypto library",
  process_library: "Process library",
  disk_encryption: "Disk encryption",
  os_crypto_policy: "OS crypto policy",
  database_tls: "Database TLS",
  database_config: "Database settings",
  database_user_auth: "Database authentication",
  k8s_cluster: "Kubernetes cluster",
  k8s_tls_secret: "Kubernetes TLS secret",
  k8s_certificate: "cert-manager certificate",
  k8s_ingress_tls: "Ingress TLS",
  k8s_mesh_policy: "Mesh mTLS policy",
  kms_key: "KMS key",
  cloud_secret: "Cloud secret",
  host_secret: "Secret in a service or script",
  crypto_config: "Crypto configuration",
  storage_encryption: "Storage encryption",
  load_balancer_tls: "Load balancer TLS",
  cdn_tls: "CDN TLS",
  api_tls: "API TLS",
  cloud_ca: "Certificate authority",
  iam_certificate: "IAM certificate",
  identity_provider: "Identity provider",
  signing_key: "Signing key",
  open_port: "Open port",
  glue_catalog: "Glue Data Catalog",
  glue_connection: "Glue connection",
  key_vault: "Key vault",
  coverage: "Not collected",
};

const IMPACTS: CbomImpact[] = ["Critical", "High", "Medium", "Low"];
const IMPACT_TONE: Record<CbomImpact, Tone> = { Critical: "red", High: "red", Medium: "amber", Low: "blue" };
const OUTCOME: Record<string, [Tone, string]> = { ok: ["green", "All targets read"], partial: ["amber", "Partly read"], failed: ["red", "Nothing read"] };
const TARGET_TONE: Record<string, Tone> = { ok: "green", skipped_never_scan: "zinc", skipped_window: "amber", skipped_stop: "amber",
  skipped_deadline: "amber", skipped_cancelled: "zinc", not_supported: "zinc" };
const TARGET_LABEL: Record<string, string> = {
  ok: "Read", unreachable: "Unreachable", refused: "Connection refused", timeout: "Timed out", no_route: "No route",
  auth_failed: "Login failed", mfa_required: "MFA required", host_key_changed: "Host key changed", identity_unverified: "Server not verified", sudoers_missing: "Sudoers missing", rbac_denied: "Kubernetes RBAC denied",
  sudo_denied: "Sudo refused", winrm_denied: "WinRM shell refused", tls_unavailable: "No TLS", not_supported: "Not supported", error: "Error",
  skipped_never_scan: "Skipped: never-scan list", skipped_window: "Skipped: scan window closed", skipped_stop: "Skipped: scanning stopped",
  skipped_deadline: "Skipped: time limit", skipped_cancelled: "Skipped: cancelled",
};

function ImpactBadge({ impact }: { impact: CbomImpact | null }) {
  if (!impact) return <span className="text-xs text-zinc-500">Info</span>;
  return <StatusBadge tone={IMPACT_TONE[impact]}>{impact}</StatusBadge>;
}

function factsRows(asset: CbomAsset): [string, string][] {
  const out: [string, string][] = [];
  for (const [key, value] of Object.entries(asset.facts ?? {})) {
    if (value === null || value === undefined || value === "" || (Array.isArray(value) && value.length === 0)) continue;
    const text = typeof value === "string" ? value : JSON.stringify(value);
    out.push([key.replace(/_/g, " "), text.length > 400 ? `${text.slice(0, 400)}…` : text]);
  }
  return out.slice(0, 30);
}

function TargetsBlock({ jobs }: { jobs: CbomJobTargets[] }) {
  const [open, setOpen] = useState<number | null>(null);
  if (jobs.length === 0) return null;
  return (
    <div className="space-y-2" data-testid="run-results-targets">
      <p className="text-sm font-medium text-zinc-900 dark:text-white">Targets</p>
      <ul className="space-y-2">
        {jobs.map((job) => {
          const problems = job.targets.filter((t) => t.status !== "ok");
          const [tone, label] =
            job.outcome === "ok" && problems.length > 0
              ? ["amber", "Read, with errors"]
              : job.outcome
                ? OUTCOME[job.outcome] ?? ["zinc", job.outcome]
                : ["blue", job.status === "pending" ? "Waiting" : "Running"];
          const counts = job.counts;
          return (
            <li key={job.job_id} className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3 text-sm" data-testid={`run-results-job-${job.job_id}`}>
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium text-zinc-900 dark:text-white break-all">{job.source_name ?? `Source ${job.source_id ?? "—"}`}</span>
                <StatusBadge tone={tone as Tone}>{label}</StatusBadge>
                {job.truncated && <StatusBadge tone="amber">Truncated</StatusBadge>}
                {job.asset_mismatch && (
                  <StatusBadge tone="amber" title={`Node reported ${job.asset_mismatch.reported}, stored ${job.asset_mismatch.stored}`}>
                    Asset count mismatch
                  </StatusBadge>
                )}
              </div>
              <p className="mt-1 text-xs text-zinc-500">
                {counts
                  ? `${counts.ok ?? 0} read · ${counts.failed ?? 0} failed · ${counts.skipped ?? 0} skipped of ${counts.total ?? 0}`
                  : job.summary ?? "No result yet"}
                {" · "}
                {pluralize(job.asset_count, "asset")}
                {job.duration_s != null ? ` · ${job.duration_s}s` : ""}
              </p>
              {job.error && <p className="mt-1 text-xs text-red-600 dark:text-red-400 break-words">{job.error}</p>}
              {problems.length > 0 && (
                <div className="mt-2">
                  <button
                    type="button"
                    className="inline-flex items-center gap-1 text-xs text-blue-600 dark:text-blue-400 cursor-pointer"
                    onClick={() => setOpen(open === job.job_id ? null : job.job_id)}
                    data-testid={`run-results-problems-${job.job_id}`}
                  >
                    {open === job.job_id ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                    {pluralize(problems.length, problems.every((t) => /:\d+$/.test(t.target)) ? "endpoint" : "target")} not fully read
                  </button>
                  {open === job.job_id && (
                    <ul className="mt-2 space-y-1">
                      {problems.slice(0, 200).map((t, i) => (
                        <li key={`${t.target}-${i}`} className="flex flex-wrap items-start gap-2 text-xs">
                          <span className="font-mono text-zinc-700 dark:text-zinc-300 break-all">{t.target}</span>
                          <StatusBadge tone={TARGET_TONE[t.status] ?? "red"}>{TARGET_LABEL[t.status] ?? t.status}</StatusBadge>
                          {t.error && <span className="text-zinc-500 break-words min-w-0">{t.error}</span>}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export default function RunResults({ teamId, runId, active }: { teamId: number; runId: number; active: boolean }) {
  const [filters, setFilters] = useState<CbomAssetFilters>({ page: 1, page_size: 50 });
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<number | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const waves = useRunRemediation(teamId, runId, active);
  const query = useQuery({
    queryKey: cbomSourcesKeys.runAssets(teamId, runId, JSON.stringify(filters)),
    queryFn: () => getCbomRunAssets(teamId, runId, filters),
    enabled: Number.isFinite(teamId),
    retry: 1,
    placeholderData: keepPreviousData,
    refetchInterval: active ? 8000 : false,
  });
  const data = query.data;
  const set = (patch: Partial<CbomAssetFilters>) => setFilters((f) => ({ ...f, ...patch, page: patch.page ?? 1 }));
  const pages = data ? Math.max(1, Math.ceil(data.total / (data.page_size || 50))) : 1;
  const types = Object.entries(data?.facets.type ?? {}).sort((a, b) => b[1] - a[1]);

  if (query.isLoading) return <LoadingBlock />;
  if (query.isError && !data) return <ErrorBlock onRetry={() => query.refetch()} />;
  if (!data) return null;

  return (
    <div className="space-y-4 min-w-0" data-testid="run-results">
      <TargetsBlock jobs={data.targets} />
      <RunPostureCard teamId={teamId} runId={runId} active={active} />
      <RunInsights teamId={teamId} runId={runId} active={active} />

      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <p className="text-sm font-medium text-zinc-900 dark:text-white" data-testid="run-results-total">
            {pluralize(data.all_total, "asset")} found
          </p>
          {IMPACTS.map((impact) =>
            data.facets.impact[impact] ? (
              <button
                key={impact}
                type="button"
                className="cursor-pointer"
                onClick={() => set({ impact: filters.impact === impact ? undefined : impact })}
                data-testid={`run-results-impact-${impact}`}
              >
                <StatusBadge tone={filters.impact === impact ? "blue" : IMPACT_TONE[impact]}>
                  {impact} {data.facets.impact[impact]}
                </StatusBadge>
              </button>
            ) : null,
          )}
          {data.facets.quantum_vulnerable > 0 && (
            <button type="button" className="cursor-pointer" onClick={() => set({ quantum: filters.quantum ? undefined : true })}>
              <StatusBadge tone={filters.quantum ? "blue" : "zinc"}>
                <ShieldAlert className="h-3 w-3" />
                Quantum-vulnerable {data.facets.quantum_vulnerable}
              </StatusBadge>
            </button>
          )}
        </div>
        <Button
          size="sm"
          variant="outline"
          className="cursor-pointer"
          disabled={data.all_total === 0 || downloading}
          data-testid="run-results-download"
          onClick={async () => {
            setDownloading(true);
            try {
              await downloadCbomRunCbom(teamId, runId);
            } finally {
              setDownloading(false);
            }
          }}
        >
          {downloading ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <Download className="h-4 w-4 mr-1.5" />}
          Download CBOM ({data.all_total}){active ? " so far" : ""}
        </Button>
        <Button
          size="sm"
          variant="outline"
          className="cursor-pointer"
          disabled={data.all_total === 0 || downloading}
          data-testid="run-results-download-xml"
          title="The same CycloneDX 1.6 CBOM as XML, valid against the official schema"
          onClick={async () => {
            setDownloading(true);
            try {
              await downloadCbomRunBom(teamId, runId, "xml");
            } catch {
              // the helper already showed the error
            } finally {
              setDownloading(false);
            }
          }}
        >
          <Download className="h-4 w-4 mr-1.5" />
          XML
        </Button>
      </div>

      <div className="flex flex-wrap gap-2">
        <Select value={filters.type ?? "all"} onValueChange={(v) => set({ type: v === "all" ? undefined : v })}>
          <SelectTrigger className="w-[220px] cursor-pointer" data-testid="run-results-type">
            <SelectValue placeholder="All types" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all" className="cursor-pointer">All types</SelectItem>
            {types.map(([type, count]) => (
              <SelectItem key={type} value={type} className="cursor-pointer">
                {ASSET_TYPE_LABEL[type] ?? type} ({count})
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          className="w-full sm:w-[260px]"
          placeholder="Search location, algorithm or finding"
          value={search}
          data-testid="run-results-search"
          onChange={(e) => setSearch(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && set({ q: search.trim() || undefined })}
          onBlur={() => set({ q: search.trim() || undefined })}
        />
        {(filters.type || filters.impact || filters.quantum || filters.q) && (
          <Button variant="ghost" size="sm" className="cursor-pointer" onClick={() => { setSearch(""); setFilters({ page: 1, page_size: 50 }); }}>
            Clear filters
          </Button>
        )}
      </div>

      <BulkAssignBar teamId={teamId} target={{ run_id: runId }} keys={[...selected]} onDone={() => setSelected(new Set())} />
      {data.items.length === 0 ? (
        <p className="text-sm text-zinc-500" data-testid="run-results-empty">
          {data.all_total === 0 ? (active ? "Nothing collected yet." : "This run collected no assets.") : "No assets match these filters."}
        </p>
      ) : (
        <ScrollArea className="w-full border rounded-lg">
          <div className="min-w-max">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-6"><span className="sr-only">Expand</span></TableHead>
                  <TableHead className="w-6"><span className="sr-only">Select for wave assignment</span></TableHead>
                  <TableHead>Impact</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Where</TableHead>
                  <TableHead>Algorithm</TableHead>
                  <TableHead>Finding</TableHead>
                  <TableHead>Quantum</TableHead>
                  <TableHead>Wave</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((asset) => (
                  <Fragment key={asset.id}>
                    <TableRow
                      className="cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800"
                      onClick={() => setExpanded(expanded === asset.id ? null : asset.id)}
                      data-testid={`run-asset-${asset.id}`}
                    >
                      <TableCell>{expanded === asset.id ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}</TableCell>
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        {waves.byAsset.get(asset.id) && (
                          <input
                            type="checkbox"
                            className="cursor-pointer"
                            aria-label={`Select ${asset.location} for wave assignment`}
                            data-testid={`run-asset-select-${asset.id}`}
                            checked={selected.has(waves.byAsset.get(asset.id)!.asset_key)}
                            onChange={() => {
                              const key = waves.byAsset.get(asset.id)!.asset_key;
                              setSelected((cur) => { const next = new Set(cur); if (next.has(key)) next.delete(key); else next.add(key); return next; });
                            }}
                          />
                        )}
                      </TableCell>
                      <TableCell><ImpactBadge impact={asset.impact} /></TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">{ASSET_TYPE_LABEL[asset.type] ?? asset.type}</TableCell>
                      <TableCell className="max-w-[280px]">
                        <Truncate text={asset.location} className="font-mono text-xs text-zinc-900 dark:text-white" />
                        {asset.target && asset.target !== asset.location && <Truncate text={asset.target} className="text-xs text-zinc-500" />}
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400 whitespace-nowrap">
                        {asset.algorithm ?? asset.protocol ?? "—"}
                        {asset.key_size ? ` ${asset.key_size}` : ""}
                      </TableCell>
                      <TableCell className="max-w-[320px]"><Truncate text={asset.finding} className="text-zinc-600 dark:text-zinc-400" /></TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">
                        {asset.quantum_vulnerable === true ? "Vulnerable" : asset.quantum_vulnerable === false ? "Safe" : "—"}
                      </TableCell>
                      <TableCell><WaveBadge item={waves.byAsset.get(asset.id)} /></TableCell>
                    </TableRow>
                    {expanded === asset.id && (
                      <TableRow>
                        <TableCell colSpan={9} className="bg-zinc-50 dark:bg-zinc-800/50">
                          <div className="max-w-[900px] space-y-2 whitespace-normal">
                            {asset.finding && <p className="text-sm text-zinc-900 dark:text-white">{asset.finding}</p>}
                            <p className="text-xs text-zinc-500">
                              Source: {asset.source_name ?? "—"}
                              {asset.finding_codes.length > 0 ? ` · ${asset.finding_codes.join(", ")}` : ""}
                            </p>
                            <AssetDetailPanel teamId={teamId} assetId={asset.id} />
                            <details className="text-xs">
                              <summary className="cursor-pointer text-zinc-500">Collected facts</summary>
                              <dl className="mt-2 grid grid-cols-1 sm:grid-cols-[180px_1fr] gap-x-4 gap-y-1 text-xs">
                                {factsRows(asset).map(([key, value]) => (
                                  <Fragment key={key}>
                                    <dt className="text-zinc-500">{key}</dt>
                                    <dd className="text-zinc-800 dark:text-zinc-200 break-all font-mono">{value}</dd>
                                  </Fragment>
                                ))}
                              </dl>
                            </details>
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                ))}
              </TableBody>
            </Table>
          </div>
          <ScrollBar orientation="horizontal" />
        </ScrollArea>
      )}

      {pages > 1 && (
        <div className="flex items-center justify-end gap-2 text-sm text-zinc-600 dark:text-zinc-400">
          <Button size="sm" variant="outline" className="cursor-pointer" disabled={(filters.page ?? 1) <= 1} onClick={() => set({ page: (filters.page ?? 1) - 1 })}>
            Previous
          </Button>
          <span data-testid="run-results-page">
            Page {filters.page ?? 1} of {pages}
          </span>
          <Button size="sm" variant="outline" className="cursor-pointer" disabled={(filters.page ?? 1) >= pages} onClick={() => set({ page: (filters.page ?? 1) + 1 })}>
            Next
          </Button>
        </div>
      )}
    </div>
  );
}
