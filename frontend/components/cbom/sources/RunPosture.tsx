"use client";

// Post-quantum and risk posture of a collection run, and the per-asset explanation (CWE / OWASP / CVE, fix and
// read-only proof commands). Everything comes from the API's offline knowledge base: no AI, no internet.

import { CorrelationSection } from "@/components/cbom/estate/Correlation";
import type { Correlation } from "@/components/cbom/estate/correlation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment, useState } from "react";

import KbFindingDetails from "@/components/cbom/KbFindingDetails";
import { StandardsDrawerSection } from "@/components/cbom/standards/Standards";
import { AgilityDrawerSection, QGradeDrawerSection } from "@/components/cbom/grade";
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
  type CbomReadinessBasis,
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
import { refreshCreditBalance } from "@/utils/creditBalance";
import { InfoTip } from "@/components/ui/info-tip";

export const CLASS_LABEL: Record<CbomPqcClass, [string, Tone, string]> = {
  "quantum-vulnerable": ["Quantum-vulnerable", "red", "RSA, elliptic-curve or Diffie-Hellman: a large quantum computer breaks it"],
  hybrid: ["Hybrid PQC", "green", "An identified post-quantum component (such as ML-KEM) next to classical public-key cryptography, inside one construction or offered beside it"],
  "quantum-safe": ["Quantum-safe", "green", "Symmetric, hash or post-quantum cryptography"],
  "grover-weakened": ["Grover-weakened", "amber", "128-bit symmetric keys: still secure, smaller margin against quantum search"],
  unknown: ["Unknown", "zinc", "Public-key cryptography the scan could not identify, or a key exchange it could not read: not judged, never counted as ready"],
  "not-applicable": ["Not applicable", "zinc", "Settings and inventory with no public-key algorithm"],
};

/** The readiness headline (CB-18): withheld when more assets are unknown than judged, and always "of N judged". */
export function readinessText(p: { pqc_readiness_pct: number | null; readiness_basis?: CbomReadinessBasis }):
  { value: string; hint: string } {
  const b = p.readiness_basis;
  const unknown = b && b.unknown ? `; ${b.unknown} unknown not included` : "";
  if (b && b.status === "not_enough_identified") {
    return { value: "Not enough identified", hint: `${b.judged} of ${b.judged + b.unknown} public-key assets judged${unknown}` };
  }
  if (p.pqc_readiness_pct == null) return { value: "—", hint: "No asset with a quantum verdict" };
  return { value: `${p.pqc_readiness_pct}%`, hint: `Of ${b ? b.judged : "the"} judged assets, the share not quantum-vulnerable${unknown}` };
}

export const EXPOSURE_TONE: Record<CbomExposure, Tone> = { internet: "red", internal: "zinc", unknown: "zinc" };

/** Team admins may change team settings (the API enforces it); others do not see the controls. */
export function useIsTeamAdmin(teamId: number): boolean {
  const q = useQuery({
    queryKey: cbomSourcesKeys.overview(teamId),
    queryFn: () => getCbomSourcesOverview(teamId),
    enabled: Number.isFinite(teamId),
    retry: 1,
    staleTime: 60_000,
  });
  return !!q.data?.viewer?.is_admin;
}

export function Stat({ label, value, hint, testId }: { label: string; value: string; hint?: string; testId?: string }) {
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

export function MoscaEditor({ teamId, onDone }: { teamId: number; onDone: () => void }) {
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
            <span className="flex items-center gap-0.5">{f.label} <InfoTip id="cbom.run.mosca" /></span>
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

/** GET /runs/{id}/posture: one cache entry for the run page (the adapter's posture, the posture summary and the quantum
 * view read the same key and fetcher); polled every 15 s while the run collects. */
export function useRunPostureQuery(teamId: number, runId: number, active: boolean) {
  return useQuery({
    queryKey: cbomSourcesKeys.runPosture(teamId, runId),
    queryFn: async () => (await getCbomRunPosture(teamId, runId)) as unknown as CbomPostureWithExposure,
    enabled: Number.isFinite(teamId),
    retry: 1,
    // a finished run's posture does not change: no refetch on each view switch (invalidations still refetch)
    staleTime: active ? 0 : Infinity,
    refetchInterval: active ? 15000 : false,
  });
}

// The run's posture card is split by the results redesign: its summary (stats, Mosca, classes, the highest risks and
// the regulatory clauses) is components/cbom/results/views/PostureSummary.tsx; the quantum-risk distribution and the
// crypto-agility card are in the Quantum grades view (views/QuantumView.tsx).

/** GET /sources/assets/{id}: the one asset-detail query (the run finding dialog and AssetDetailPanel both use it, so one
 * definition and one request). */
export function useAssetDetail(teamId: number, assetId: number | null, enabled = true) {
  return useQuery({
    queryKey: cbomSourcesKeys.asset(teamId, assetId ?? 0),
    queryFn: async () => (await getCbomAssetDetail(teamId, assetId as number)) as unknown as CbomAssetDetailWithExposure,
    enabled: enabled && assetId != null,
    retry: 1,
    staleTime: 60_000,
  });
}

/** PQC class, HNDL, business criticality and internet exposure chips of an asset, then the class basis line. */
export function AssetClassChips({ a }: { a: CbomAssetDetailWithExposure }) {
  // a class this bundle does not know (a newer backend) reads as Unknown, never as "Not applicable" or a crash
  const cls = CLASS_LABEL[a.pqc_class] ?? CLASS_LABEL.unknown;
  return (
    <>
      <div className="flex flex-wrap gap-2 items-center">
        <span title={a.pqc_class_basis_text ?? cls[2]} data-testid="asset-pqc-class" data-class={a.pqc_class}
              data-basis={a.pqc_class_basis}>
          <StatusBadge tone={cls[1]}>{cls[0]}</StatusBadge>
        </span>
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
      {a.pqc_class_basis_text && (
        <p className="text-xs text-zinc-500" data-testid="asset-pqc-basis">
          {a.pqc_class_basis_text}
          {a.pqc_class_read_elsewhere ? ` (asset #${a.pqc_class_read_elsewhere})` : ""}
        </p>
      )}
    </>
  );
}

/** The library an asset belongs to: package and upstream versions, end of life as of the run and today, CVEs. */
export function AssetLibraryBlock({ a }: { a: CbomAssetDetailWithExposure }) {
  if (!a.library) return null;
  return (
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
  );
}

/** The asset's quantum and effort explanation: Q grade, crypto agility, standards, correlation, library, SBOM links.
 * AssetDetailPanel renders it between the class chips and the KB details; the run finding dialog in its Quantum &
 * effort tab. */
export function AssetQuantumParts({ teamId, a }: { teamId: number; a: CbomAssetDetailWithExposure }) {
  return (
    <>
      <QGradeDrawerSection teamId={teamId} asset={a} />
      <AgilityDrawerSection teamId={teamId} agility={a.agility} />
      <StandardsDrawerSection standards={a.standards} />
      <CorrelationSection teamId={teamId} correlation={(a as { correlation?: Correlation | null }).correlation} />
      <AssetLibraryBlock a={a} />
      {(a.type === "crypto_library" || a.type === "process_library") && <SbomLinks teamId={teamId} assetId={a.id} />}
    </>
  );
}

/** The asset explanation (Sources asset drawer and anywhere else): one column, every part. The run finding dialog
 * places the same parts (AssetClassChips, AssetQuantumParts, KbFindingDetails) into its tabs instead. */
export function AssetDetailPanel({ teamId, assetId, mergedStandards = false }: { teamId: number; assetId: number; mergedStandards?: boolean }) {
  const query = useAssetDetail(teamId, assetId);
  if (query.isLoading) return <LoadingBlock />;
  if (query.isError || !query.data) return <ErrorBlock error={query.error} onRetry={() => query.refetch()} />;
  const a = query.data;
  return (
    <div className="space-y-3" data-testid={`asset-detail-${a.id}`}>
      <AssetClassChips a={a} />
      <AssetQuantumParts teamId={teamId} a={a} />
      <KbFindingDetails details={a.details} mergedStandards={mergedStandards} />
    </div>
  );
}

/** "Also in SBOM scan X (component Y)": the team's SBOM scans that list this library (purl, else name and version). */
export function SbomLinks({ teamId, assetId }: { teamId: number; assetId: number }) {
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
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });
      refreshCreditBalance(queryClient); // every source edit (only a changed connection refunds; utils/creditBalance.ts)
    },
  });
  return (
    <Select value={current} onValueChange={(v) => v !== current && save.mutate(v)} disabled={save.isPending}>
      {/* infotip-shared: the Business criticality and exposure card's tip explains it */}
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
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });
      refreshCreditBalance(queryClient); // every source edit (only a changed connection refunds; utils/creditBalance.ts)
    },
  });
  return (
    <Select value={current} onValueChange={(v) => v !== current && save.mutate(v as CbomExposure | "auto")} disabled={save.isPending}>
      {/* infotip-shared: the Business criticality and exposure card's tip explains it */}
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
    <SectionCard infoId="cbsrc.rr.criticality" title="Business criticality and exposure"
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
