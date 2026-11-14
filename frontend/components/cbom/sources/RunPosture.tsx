"use client";

// Post-quantum and risk posture of a collection run, and the per-asset explanation (CWE / OWASP / CVE, fix and
// read-only proof commands). Everything comes from the API's offline knowledge base: no AI, no internet.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Info } from "lucide-react";
import { Fragment, useState } from "react";

import KbFindingDetails from "@/components/cbom/KbFindingDetails";
import {
  AgilityDrawerSection,
  AgilityPostureCard,
  QDistributionCard,
  QGradeDrawerSection,
} from "@/components/cbom/grade";
import { cbomOpsKeys, getCbomAssetSbom } from "@/utils/api/cbom_ops";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  getCbomAssetDetail,
  getCbomRunPosture,
  getCbomSourcesOverview,
  getCbomSourcesSettings,
  listCbomSources,
  updateCbomSource,
  updateCbomSourcesSettings,
  type CbomPqcClass,
  type CbomRiskModel,
  type CbomSource,
} from "@/utils/backend_api";
import {
  EXPOSURE_LABEL,
  type CbomAssetDetailWithExposure,
  type CbomExposure,
  type CbomPostureWithExposure,
} from "@/utils/api/cbom_outputs";

import { handleApiError } from "@/utils/error-handler";

import { cbomSourcesKeys } from "./keys";
import { EXPOSURE_CHOICES, pluralize } from "./logic";
import { ErrorBlock, LoadingBlock, SectionCard, StatusBadge, Truncate, type Tone } from "./shared";

const CLASS_LABEL: Record<CbomPqcClass, [string, Tone, string]> = {
  "quantum-vulnerable": ["Quantum-vulnerable", "red", "RSA, elliptic-curve or Diffie-Hellman: a large quantum computer breaks it"],
  hybrid: ["Hybrid PQC", "green", "A post-quantum key exchange (ML-KEM) is accepted next to the classical one"],
  "quantum-safe": ["Quantum-safe", "green", "Symmetric, hash or post-quantum cryptography"],
  "grover-weakened": ["Grover-weakened", "amber", "128-bit symmetric keys: still secure, smaller margin against quantum search"],
  "not-applicable": ["Not applicable", "zinc", "Settings and inventory with no public-key algorithm"],
};

const EXPOSURE_TONE: Record<CbomExposure, Tone> = { internet: "red", internal: "zinc", unknown: "zinc" };

/** Team admins may change team settings (the API enforces it); others do not see the controls. */
function useIsTeamAdmin(teamId: number): boolean {
  const q = useQuery({
    queryKey: cbomSourcesKeys.overview(teamId),
    queryFn: () => getCbomSourcesOverview(teamId),
    enabled: Number.isFinite(teamId),
    retry: 1,
    staleTime: 60_000,
  });
  return !!q.data?.viewer?.is_admin;
}

function Stat({ label, value, hint, testId }: { label: string; value: string; hint?: string; testId?: string }) {
  return (
    <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3 min-w-0" data-testid={testId}>
      <p className="text-xs text-zinc-500">{label}</p>
      <p className="text-xl font-semibold text-zinc-900 dark:text-white">{value}</p>
      {hint && <p className="text-xs text-zinc-500 mt-0.5">{hint}</p>}
    </div>
  );
}

const MOSCA_FIELDS: { key: keyof CbomRiskModel; label: string; hint: string }[] = [
  { key: "data_shelf_life_years", label: "X: years data must stay secret", hint: "e.g. 10 for account records" },
  { key: "migration_years", label: "Y: years to migrate", hint: "inventory, testing and roll-out" },
  { key: "threat_years", label: "Z: years until a quantum computer", hint: "your organisation's assumption" },
];

function MoscaEditor({ teamId, onDone }: { teamId: number; onDone: () => void }) {
  const queryClient = useQueryClient();
  const settings = useQuery({ queryKey: cbomSourcesKeys.settings(teamId), queryFn: () => getCbomSourcesSettings(teamId) });
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: (risk_model: CbomRiskModel) =>
      updateCbomSourcesSettings(teamId, { risk_model, expected_version: settings.data?.row_version }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });
      onDone();
    },
    // say why the values were not saved (a 409 means someone else saved first: reload so the next try sends the
    // current version)
    onError: (err) => {
      setError(handleApiError(err).message);
      queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });
    },
  });
  if (!settings.data) return <LoadingBlock />;
  const current = settings.data.risk_model ?? { data_shelf_life_years: null, migration_years: null, threat_years: null };
  const value = (k: keyof CbomRiskModel) => draft[k] ?? (current[k] == null ? "" : String(current[k]));
  return (
    <form
      className="space-y-2 rounded-md border border-zinc-200 dark:border-zinc-700 p-3"
      data-testid="mosca-editor"
      onSubmit={(e) => {
        e.preventDefault();
        const out = {} as CbomRiskModel;
        for (const f of MOSCA_FIELDS) {
          const raw = value(f.key).trim();
          const n = Number(raw);
          if (raw !== "" && (!Number.isInteger(n) || n < 0 || n > 100)) {
            setError(`${f.label}: enter a whole number of years from 0 to 100`);
            return;
          }
          out[f.key] = raw === "" ? null : n;
        }
        setError(null);
        save.mutate(out);
      }}
    >
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
        {MOSCA_FIELDS.map((f) => (
          <label key={f.key} className="text-xs text-zinc-600 dark:text-zinc-400 space-y-1">
            <span>{f.label}</span>
            <Input inputMode="numeric" value={value(f.key)} placeholder={f.hint} data-testid={`mosca-${f.key}`}
                   onChange={(e) => setDraft((d) => ({ ...d, [f.key]: e.target.value }))} />
          </label>
        ))}
      </div>
      {error && <p className="text-xs text-red-600 dark:text-red-400" role="alert">{error}</p>}
      <div className="flex gap-2">
        <Button type="submit" size="sm" className="cursor-pointer" disabled={save.isPending} data-testid="mosca-save">Save</Button>
        <Button type="button" size="sm" variant="ghost" className="cursor-pointer" onClick={onDone}>Cancel</Button>
      </div>
      <p className="text-xs text-zinc-500">Team admins only. Leave a field empty to clear it.</p>
    </form>
  );
}

/** `onOpenAsset`: what a Q0 Unknown asset item in the quantum-risk card opens (optional; without it the item is text). */
export function RunPostureCard({ teamId, runId, active, onOpenAsset }: {
  teamId: number; runId: number; active: boolean; onOpenAsset?: (assetId: number) => void;
}) {
  const [showCompliance, setShowCompliance] = useState(false);
  const [editMosca, setEditMosca] = useState(false);
  const isAdmin = useIsTeamAdmin(teamId);
  const query = useQuery({
    queryKey: cbomSourcesKeys.runPosture(teamId, runId),
    queryFn: async () => (await getCbomRunPosture(teamId, runId)) as unknown as CbomPostureWithExposure,
    enabled: Number.isFinite(teamId),
    retry: 1,
    refetchInterval: active ? 15000 : false,
  });
  if (query.isLoading) return <LoadingBlock />;
  if (query.isError || !query.data) return <ErrorBlock error={query.error} onRetry={() => query.refetch()} />;
  const p = query.data;
  // a run that read no asset can still have Q0 Unknown items (sources or targets not read): show only those
  if (p.assets === 0) {
    return (p.q0_items_total ?? 0) > 0 ? <QDistributionCard teamId={teamId} posture={p} onOpenAsset={onOpenAsset} /> : null;
  }
  const m = p.mosca;
  return (
    <div className="space-y-3 rounded-lg border border-zinc-200 dark:border-zinc-800 p-4" data-testid="run-posture">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-sm font-medium text-zinc-900 dark:text-white">Post-quantum and risk posture</p>
        <span className="text-xs text-zinc-500">Knowledge base {p.kb_version} · no AI</span>
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Stat label="PQC readiness" value={p.pqc_readiness_pct == null ? "—" : `${p.pqc_readiness_pct}%`}
              hint="Assets with a quantum verdict that are not quantum-vulnerable" testId="posture-readiness" />
        <Stat label="Harvest now, decrypt later" value={String(p.hndl_assets)}
              hint="Endpoints whose key exchange a quantum computer breaks later" testId="posture-hndl" />
        <Stat label="Critical / High" value={`${p.impacts.Critical ?? 0} / ${p.impacts.High ?? 0}`} hint={`${p.impacts.Medium ?? 0} medium, ${p.impacts.Low ?? 0} low`} />
        <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3 min-w-0" data-testid="posture-mosca">
          <p className="text-xs text-zinc-500">Mosca (X + Y &gt; Z)</p>
          {m.configured ? (
            <>
              <p className={`text-xl font-semibold ${m.at_risk ? "text-red-600 dark:text-red-400" : "text-green-600 dark:text-green-400"}`}>
                {m.at_risk ? "At risk" : "Inside window"}
              </p>
              <p className="text-xs text-zinc-500 mt-0.5">X {m.x} + Y {m.y} vs Z {m.z} years</p>
            </>
          ) : (
            <p className="text-xs text-zinc-500 mt-1">Not set</p>
          )}
          {isAdmin ? (
            <button type="button" className="text-xs text-blue-600 dark:text-blue-400 cursor-pointer mt-1" data-testid="mosca-edit"
                    onClick={() => setEditMosca(!editMosca)}>
              {m.configured ? "Change X, Y, Z" : "Set X, Y, Z"}
            </button>
          ) : (
            <p className="text-xs text-zinc-500 mt-1" data-testid="mosca-admin-only">A team admin sets X, Y and Z</p>
          )}
        </div>
      </div>
      {editMosca && isAdmin && <MoscaEditor teamId={teamId} onDone={() => setEditMosca(false)} />}
      {!m.configured && !editMosca && m.note && <p className="text-xs text-zinc-500">{m.note}</p>}
      <div className="flex flex-wrap gap-2">
        {(Object.keys(CLASS_LABEL) as CbomPqcClass[]).map((c) =>
          p.pqc_classes[c] ? (
            <span key={c} title={CLASS_LABEL[c][2]}>
              <StatusBadge tone={CLASS_LABEL[c][1]}>{CLASS_LABEL[c][0]} {p.pqc_classes[c]}</StatusBadge>
            </span>
          ) : null,
        )}
      </div>
      {m.configured && m.verdict && <p className="text-xs text-zinc-600 dark:text-zinc-400">{m.verdict}</p>}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-3 items-start">
        <QDistributionCard teamId={teamId} posture={p} onOpenAsset={onOpenAsset} />
        <AgilityPostureCard teamId={teamId} posture={p} />
      </div>
      {p.top_risks.length > 0 && (
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-zinc-500 mb-1">
            Highest risk (impact × business criticality × internet exposure)
          </p>
          <ul className="space-y-1">
            {p.top_risks.slice(0, 5).map((r) => (
              <li key={r.id} className="text-xs text-zinc-700 dark:text-zinc-300 flex flex-wrap gap-2" data-testid={`top-risk-${r.id}`}>
                <span className="font-mono">{r.score}</span>
                <span className="font-mono break-all">{r.name}</span>
                <span className="text-zinc-500">{r.source_name ?? ""} · {r.criticality}{r.hndl ? " · HNDL" : ""}</span>
                {r.exposure && (
                  <span title={r.exposure_basis}>
                    <StatusBadge tone={EXPOSURE_TONE[r.exposure]}>
                      {EXPOSURE_LABEL[r.exposure]}{p.exposure_factors && r.exposure === "internet" ? ` ×${p.exposure_factors.internet}` : ""}
                    </StatusBadge>
                  </span>
                )}
              </li>
            ))}
          </ul>
          <p className="text-xs text-zinc-500 mt-1">Scored with the criticality and exposure the sources had when this run started.</p>
        </div>
      )}
      {p.compliance.length > 0 && (
        <div>
          <button type="button" className="text-xs text-blue-600 dark:text-blue-400 cursor-pointer" onClick={() => setShowCompliance(!showCompliance)}
                  data-testid="posture-compliance-toggle">
            {showCompliance ? "Hide" : "Show"} regulatory clauses these findings touch ({p.compliance.map((f) => f.framework).join(", ")})
          </button>
          {showCompliance && (
            <div className="mt-2 space-y-2" data-testid="posture-compliance">
              {p.compliance.map((fw) => (
                <div key={fw.framework}>
                  <p className="text-xs font-semibold text-zinc-800 dark:text-zinc-200">{fw.framework}</p>
                  <ul className="space-y-1">
                    {fw.clauses.map((c) => (
                      <li key={c.id} className="text-xs text-zinc-600 dark:text-zinc-400">
                        <a href={c.source} target="_blank" rel="noreferrer noopener" className="text-blue-600 dark:text-blue-400 inline-flex items-center gap-1">
                          {c.id} <ExternalLink className="h-3 w-3" />
                        </a>{" "}
                        · {pluralize(c.assets, "asset")} · {c.codes.join(", ")}
                        {c.note && <span className="block italic text-zinc-500">{c.note}</span>}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      {p.pqc_context?.z_note && (
        <p className="text-xs text-zinc-500 flex gap-1"><Info className="h-3.5 w-3.5 shrink-0 mt-0.5" />{p.pqc_context.z_note}</p>
      )}
    </div>
  );
}

export function AssetDetailPanel({ teamId, assetId }: { teamId: number; assetId: number }) {
  const query = useQuery({
    queryKey: cbomSourcesKeys.asset(teamId, assetId),
    queryFn: async () => (await getCbomAssetDetail(teamId, assetId)) as unknown as CbomAssetDetailWithExposure,
    retry: 1,
    staleTime: 60_000,
  });
  if (query.isLoading) return <LoadingBlock />;
  if (query.isError || !query.data) return <ErrorBlock error={query.error} onRetry={() => query.refetch()} />;
  const a = query.data;
  const cls = CLASS_LABEL[a.pqc_class];
  return (
    <div className="space-y-3" data-testid={`asset-detail-${a.id}`}>
      <div className="flex flex-wrap gap-2 items-center">
        <StatusBadge tone={cls[1]}>{cls[0]}</StatusBadge>
        {a.hndl && <StatusBadge tone="red">Harvest now, decrypt later</StatusBadge>}
        <span className="text-xs text-zinc-500">Business criticality: {a.criticality}</span>
        {a.exposure && (
          <span title={a.exposure_basis} data-testid="asset-exposure">
            <StatusBadge tone={EXPOSURE_TONE[a.exposure]}>
              {EXPOSURE_LABEL[a.exposure]}{a.exposure_factor && a.exposure_factor !== 1 ? ` (risk ×${a.exposure_factor})` : ""}
            </StatusBadge>
          </span>
        )}
        {a.exposure_basis && <span className="text-xs text-zinc-500">{a.exposure_basis}</span>}
      </div>
      <QGradeDrawerSection teamId={teamId} asset={a} />
      <AgilityDrawerSection teamId={teamId} agility={a.agility} />
      {a.library && (
        <div className="rounded-md border border-zinc-200 dark:border-zinc-700 p-3 space-y-1" data-testid="asset-library">
          <p className="text-xs font-semibold text-zinc-800 dark:text-zinc-200">
            {a.library.package} {a.library.package_version} (upstream {a.library.library} {a.library.upstream_version})
          </p>
          {a.library.eol && (
            <p className={`text-xs ${a.library.eol.passed ? "text-red-600 dark:text-red-400" : "text-zinc-600 dark:text-zinc-400"}`}
               data-testid="asset-library-eol">
              {a.library.eol_as_of ? `As of this run (${a.library.eol_as_of}): ` : ""}
              upstream {a.library.eol.branch} {a.library.eol.passed ? "had reached end of life" : "was supported until"} {a.library.eol.date}
            </p>
          )}
          {a.library.eol_today && (
            <p className={`text-xs ${a.library.eol_today.passed ? "text-red-600 dark:text-red-400" : "text-zinc-600 dark:text-zinc-400"}`}
               data-testid="asset-library-eol-today">
              Today: upstream {a.library.eol_today.branch} {a.library.eol_today.passed ? "has reached end of life" : "is supported until"} {a.library.eol_today.date}
            </p>
          )}
          {a.library.cves.length > 0 && (
            <p className="text-xs text-zinc-600 dark:text-zinc-400">
              In the published affected range of {pluralize(a.library.cves.length, "CVE")} (in triage: confirm your vendor&apos;s back-ported fixes):{" "}
              {a.library.cve_details.map((c, i) => c && (
                <Fragment key={c.id}>
                  {i > 0 && ", "}
                  <a href={c.url} target="_blank" rel="noreferrer noopener" className="font-mono text-blue-600 dark:text-blue-400">{c.id}</a>
                  {c.cvss?.score != null && <span className="text-zinc-500"> ({c.cvss.score})</span>}
                </Fragment>
              ))}
            </p>
          )}
        </div>
      )}
      {(a.type === "crypto_library" || a.type === "process_library") && <SbomLinks teamId={teamId} assetId={a.id} />}
      <KbFindingDetails details={a.details} />
    </div>
  );
}

/** "Also in SBOM scan X (component Y)": the team's SBOM scans that list this library (purl, else name and version). */
function SbomLinks({ teamId, assetId }: { teamId: number; assetId: number }) {
  const q = useQuery({ queryKey: cbomOpsKeys.assetSbom(teamId, assetId), queryFn: () => getCbomAssetSbom(teamId, assetId),
                       retry: 1, staleTime: 60_000 });
  if (!q.data) return null;
  return (
    <div className="text-xs text-zinc-600 dark:text-zinc-400 space-y-0.5" data-testid="asset-sbom-links">
      {q.data.purl && <p>Package URL: <span className="font-mono break-all">{q.data.purl}</span></p>}
      {q.data.matches.length === 0 ? <p>Not listed in the team&apos;s recent SBOM scans.</p> : q.data.matches.map((m) => (
        <p key={m.scan_id}>
          Also in SBOM scan <span className="font-medium text-zinc-800 dark:text-zinc-200">{m.scan_title} (#{m.scan_id})</span>
          {" "}as {m.component}{m.match === "name" ? " (another version)" : ""}
        </p>
      ))}
    </div>
  );
}

const CRITICALITY = ["low", "medium", "high", "critical"] as const;

function CriticalitySelect({ teamId, source }: { teamId: number; source: CbomSource }) {
  const queryClient = useQueryClient();
  const current = (source.config?.business_criticality as string | undefined) ?? "medium";
  const save = useMutation({
    mutationFn: (value: string) =>
      updateCbomSource(teamId, source.id, { config: { ...source.config, business_criticality: value }, expected_version: source.row_version }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) }),
    onError: () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) }),
  });
  return (
    <Select value={current} onValueChange={(v) => v !== current && save.mutate(v)} disabled={save.isPending}>
      <SelectTrigger className="w-[140px] cursor-pointer" data-testid={`criticality-${source.id}`} aria-label={`Business criticality of ${source.name}`}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {CRITICALITY.map((c) => (
          <SelectItem key={c} value={c} className="cursor-pointer capitalize">{c}</SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function ExposureSelect({ teamId, source }: { teamId: number; source: CbomSource }) {
  const queryClient = useQueryClient();
  const current = ((source.config?.exposure as CbomExposure | null | undefined) ?? "auto") as CbomExposure | "auto";
  const save = useMutation({
    mutationFn: (value: CbomExposure | "auto") =>
      updateCbomSource(teamId, source.id, {
        config: { ...source.config, exposure: value === "auto" ? null : value },
        expected_version: source.row_version,
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) }),
    onError: () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) }),
  });
  return (
    <Select value={current} onValueChange={(v) => v !== current && save.mutate(v as CbomExposure | "auto")} disabled={save.isPending}>
      <SelectTrigger className="w-[170px] cursor-pointer" data-testid={`exposure-${source.id}`} aria-label={`Internet exposure of ${source.name}`}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {EXPOSURE_CHOICES.map((c) => (
          <SelectItem key={c.value} value={c.value} className="cursor-pointer">{c.label}</SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

/** Business criticality and internet exposure per source: they multiply the impact of what the source finds in the
 * risk ranking (internet-facing x1.5). Changing them does not reset the source's connection test or stop its jobs. */
export function CriticalityCard({ teamId }: { teamId: number }) {
  const query = useQuery({ queryKey: cbomSourcesKeys.sources(teamId, "all"), queryFn: () => listCbomSources(teamId), retry: 1 });
  const sources = query.data?.sources ?? [];
  if (query.isLoading || sources.length === 0) return null;
  return (
    <SectionCard title="Business criticality and exposure"
                 description="Weights each source's findings in the risk ranking of the next run (default: medium; exposure from the collected facts, internet-facing x1.5)">
      <ul className="divide-y divide-zinc-200 dark:divide-zinc-800" data-testid="criticality-card">
        {sources.map((src) => (
          <li key={src.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
            <div className="min-w-0">
              <Truncate text={src.name} className="text-sm font-medium text-zinc-900 dark:text-white" />
              <span className="text-xs text-zinc-500">{src.kind_label}</span>
            </div>
            <div className="flex flex-wrap gap-2">
              <CriticalitySelect teamId={teamId} source={src} />
              <ExposureSelect teamId={teamId} source={src} />
            </div>
          </li>
        ))}
      </ul>
    </SectionCard>
  );
}
