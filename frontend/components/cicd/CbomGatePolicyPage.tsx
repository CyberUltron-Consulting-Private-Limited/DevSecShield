"use client";

// Settings > CBOM policy gate (SOW S1): the policy POST /cicd/cbom/scan applies to every CBOM CI/CD integration of the
// team (banned algorithms, minimum key sizes per family, quantum-vulnerable and SP 800-131A deprecated algorithms as
// off / warn / fail, blocked finding codes, allow-list exceptions with a reason and an expiry), an optional override per
// integration, and the same policy as a file for the offline `aibom cbom --policy` gate. Admins change it; members read.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Download, Loader2, Plus, RotateCcw, Save, Trash2 } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { Checkbox2, ErrorBlock, Field, LoadingBlock, SectionCard, StatusBadge } from "@/components/cbom/sources/shared";
import { Button } from "@/components/ui/button";
import { InfoTip } from "@/components/ui/info-tip";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import {
  KEY_FAMILIES,
  RULE_LABEL,
  boundedLocation,
  cleanException,
  gatePolicyKey,
  getGatePolicy,
  matchingPreset,
  policyFileText,
  resetGatePolicy,
  saveGatePolicy,
  splitList,
  type GateException,
  type GateMode,
  type GatePolicy,
  type GatePolicyView,
  type GateRule,
  type KeyFamily,
  type StoredGatePolicy,
} from "@/utils/api/cbomGatePolicy";
import { formatDateIst } from "@/utils/datetime";
import { saveBlob } from "@/utils/download";
import { showErrorToast } from "@/utils/error-handler";
import { toast } from "@/utils/toast";
import type { InfoTipId } from "@/content/infotips";

const FAMILY: Record<KeyFamily, { label: string; infoId: InfoTipId }> = {
  rsa: { label: "RSA minimum (bits)", infoId: "cbom.gate.min_rsa" },
  dsa: { label: "DSA minimum (bits)", infoId: "cbom.gate.min_dsa" },
  dh: { label: "Finite-field DH minimum (bits)", infoId: "cbom.gate.min_dh" },
  ec: { label: "Elliptic-curve minimum (bits)", infoId: "cbom.gate.min_ec" },
  symmetric: { label: "Symmetric key minimum (bits)", infoId: "cbom.gate.min_symmetric" },
};

const MODE_LABEL: Record<GateMode, string> = {
  off: "Off (not reported)",
  warn: "Warn (reported, the build passes)",
  fail: "Fail the build",
};

const CUSTOM_PRESET = "custom";
const PRESET_LABEL: Record<string, string> = {
  "sp800-131a": "NIST SP 800-131A Rev. 2 (default)",
  "sp800-131a-2031": "SP 800-131A from 2031 (128-bit floor)",
  "cnsa-2.0": "CNSA 2.0 (strict)",
};

type Draft = Omit<GatePolicy, "banned_algorithms" | "min_key_bits"> & {
  banned: string;
  sizes: Record<KeyFamily, string>;
};

function toDraft(p: GatePolicy): Draft {
  return {
    ...p,
    banned: p.banned_algorithms.join(", "),
    sizes: Object.fromEntries(KEY_FAMILIES.map((f) => [f, String(p.min_key_bits[f])])) as Record<KeyFamily, string>,
    exceptions: p.exceptions.map((e) => ({ ...e })),
  };
}

export function fromDraft(d: Draft): GatePolicy {
  return {
    version: 1,
    name: d.name.trim(),
    block_codes: [...d.block_codes].sort(),
    banned_algorithms: splitList(d.banned),
    min_key_bits: Object.fromEntries(KEY_FAMILIES.map((f) => [f, Number(d.sizes[f])])) as Record<KeyFamily, number>,
    quantum_vulnerable: d.quantum_vulnerable,
    deprecated: d.deprecated,
    exceptions: d.exceptions.map(cleanException),
  };
}

function inDays(days: number): string {
  const d = new Date(Date.now() + days * 86400000);
  return d.toISOString().slice(0, 10);
}

function PolicyEditor({ teamId, view, stored, integrationId, onDone }: {
  teamId: number;
  view: GatePolicyView;
  stored: StoredGatePolicy | null;
  /** an integration override; undefined for the team policy */
  integrationId?: number;
  onDone?: () => void;
}) {
  const queryClient = useQueryClient();
  const start = stored?.policy ?? (integrationId ? view.team?.policy : undefined) ?? view.default;
  const [draft, setDraft] = useState<Draft>(() => toDraft(start));
  // the preset the saved rules equal ("custom" when edited): a save remounts the editor, which used to reset it to the
  // default (staging QA2 m9)
  const [preset, setPreset] = useState(() => matchingPreset(start, view.presets) ?? CUSTOM_PRESET);
  const isAdmin = view.is_admin;
  const prefix = integrationId ? `gate-int-${integrationId}` : "gate-team";
  const set = <K extends keyof Draft>(key: K, value: Draft[K]) => setDraft((d) => ({ ...d, [key]: value }));
  const refresh = () => queryClient.invalidateQueries({ queryKey: gatePolicyKey(teamId) });
  const codes = Array.from(new Set([...view.default.block_codes, ...draft.block_codes])).sort();

  const save = useMutation({
    mutationFn: () => saveGatePolicy(teamId, fromDraft(draft), stored?.row_version ?? null, integrationId),
    onSuccess: (r) => {
      toast.success(r.saved ? `Policy saved (version ${r.row_version})` : "No change to save");
      refresh();
      onDone?.();
    },
    onError: (e) => showErrorToast(e),
  });
  const reset = useMutation({
    mutationFn: () => resetGatePolicy(teamId, integrationId),
    onSuccess: () => {
      toast.success(integrationId ? "This integration follows the team policy again" : "The team uses the default policy again");
      refresh();
      onDone?.();
    },
    onError: (e) => showErrorToast(e),
  });
  const updateException = (i: number, patch: Partial<GateException>) =>
    set("exceptions", draft.exceptions.map((e, j) => (j === i ? { ...e, ...patch } : e)));
  const download = () => {
    const name = integrationId ? `cbom-gate-policy-integration-${integrationId}.json` : `cbom-gate-policy-team-${teamId}.json`;
    saveBlob(new Blob([policyFileText(fromDraft(draft), view.file_kind)], { type: "application/json" }), name);
  };
  const disabled = !isAdmin || save.isPending;

  return (
    <div className="space-y-5" data-testid={prefix}>
      {isAdmin && (
        <div className="flex flex-wrap items-end gap-2">
          <Field infoId="cbom.gate.preset" label="Start from a preset" htmlFor={`${prefix}-preset`} className="w-full sm:w-80">
            <Select value={preset} onValueChange={setPreset}>
              <SelectTrigger id={`${prefix}-preset`} className="w-full cursor-pointer"><SelectValue /></SelectTrigger>
              <SelectContent>
                {Object.keys(view.presets).map((k) => (
                  <SelectItem key={k} value={k} className="cursor-pointer">{PRESET_LABEL[k] ?? k}</SelectItem>
                ))}
                <SelectItem value={CUSTOM_PRESET} disabled>Custom (edited rules)</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Button variant="outline" className="cursor-pointer" disabled={!view.presets[preset]}
                  onClick={() => setDraft(toDraft({ ...view.presets[preset], exceptions: draft.exceptions }))}>
            Apply preset
          </Button>
        </div>
      )}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Field infoId="cbom.gate.name" label="Policy name" htmlFor={`${prefix}-name`} required>
          <Input id={`${prefix}-name`} value={draft.name} maxLength={80} disabled={disabled}
                 onChange={(e) => set("name", e.target.value)} />
        </Field>
        <Field infoId="cbom.gate.quantum" label="Quantum-vulnerable algorithms" htmlFor={`${prefix}-qv`}>
          <Select value={draft.quantum_vulnerable} onValueChange={(v) => set("quantum_vulnerable", v as GateMode)} disabled={disabled}>
            <SelectTrigger id={`${prefix}-qv`} className="w-full cursor-pointer"><SelectValue /></SelectTrigger>
            <SelectContent>
              {(Object.keys(MODE_LABEL) as GateMode[]).map((m) => <SelectItem key={m} value={m} className="cursor-pointer">{MODE_LABEL[m]}</SelectItem>)}
            </SelectContent>
          </Select>
        </Field>
        <Field infoId="cbom.gate.deprecated" label="Deprecated by SP 800-131A" htmlFor={`${prefix}-dep`}>
          <Select value={draft.deprecated} onValueChange={(v) => set("deprecated", v as GateMode)} disabled={disabled}>
            <SelectTrigger id={`${prefix}-dep`} className="w-full cursor-pointer"><SelectValue /></SelectTrigger>
            <SelectContent>
              {(Object.keys(MODE_LABEL) as GateMode[]).map((m) => <SelectItem key={m} value={m} className="cursor-pointer">{MODE_LABEL[m]}</SelectItem>)}
            </SelectContent>
          </Select>
        </Field>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {KEY_FAMILIES.map((f) => {
          const [low, high] = view.key_limits[f];
          return (
            <Field key={f} infoId={FAMILY[f].infoId} label={FAMILY[f].label} htmlFor={`${prefix}-min-${f}`} hint={`${low} to ${high}`}>
              <Input id={`${prefix}-min-${f}`} inputMode="numeric" value={draft.sizes[f]} disabled={disabled}
                     onChange={(e) => set("sizes", { ...draft.sizes, [f]: e.target.value.replace(/[^0-9]/g, "") })} />
            </Field>
          );
        })}
      </div>
      <Field infoId="cbom.gate.banned" label="Banned algorithms" htmlFor={`${prefix}-banned`}
             hint="Comma-separated. 3DES also matches TDEA, DESede and TripleDES; a name such as RSA-1024 bans that size only.">
        <Textarea id={`${prefix}-banned`} value={draft.banned} disabled={disabled} spellCheck={false}
                  className="font-mono text-xs min-h-[56px]" onChange={(e) => set("banned", e.target.value)} />
      </Field>
      <fieldset className="space-y-2">
        <legend className="text-sm font-medium text-zinc-800 dark:text-zinc-200">
          Blocked finding codes <InfoTip id="cbom.gate.block_codes" />
        </legend>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {codes.map((code) => (
            /* infotip-shared: one code of the list; the Blocked finding codes tip above explains them */
            <Checkbox2 key={code} id={`${prefix}-code-${code}`} checked={draft.block_codes.includes(code)} disabled={!isAdmin}
                       onChange={(v) => isAdmin && set("block_codes", v ? [...draft.block_codes, code] : draft.block_codes.filter((c) => c !== code))}>
              <span className="font-mono text-xs">{code}</span>
            </Checkbox2>
          ))}
        </div>
      </fieldset>
      <div className="space-y-2">
        <h3 className="text-sm font-medium text-zinc-800 dark:text-zinc-200">
          Exceptions (allow-list) <InfoTip id="cbom.gate.exceptions" />
        </h3>
        {draft.exceptions.length === 0 ? (
          <p className="text-xs text-zinc-500">No exceptions: every finding is judged by the rules above.</p>
        ) : (
          <div className="overflow-x-auto">
            <Table data-testid={`${prefix}-exceptions`}>
              <TableHeader>
                <TableRow>
                  <TableHead>Rule <InfoTip id="cbom.gate.exc.rule" /></TableHead>
                  <TableHead>Finding code or algorithm <InfoTip id="cbom.gate.exc.algorithm" /> <InfoTip id="cbom.gate.exc.code" /></TableHead>
                  <TableHead>Location <InfoTip id="cbom.gate.exc.location" /></TableHead>
                  <TableHead>Reason <InfoTip id="cbom.gate.exc.reason" /></TableHead>
                  <TableHead>Expires <InfoTip id="cbom.gate.exc.expires" /></TableHead>
                  {isAdmin && <TableHead />}
                </TableRow>
              </TableHeader>
              <TableBody>
                {draft.exceptions.map((e, i) => (
                  <TableRow key={i}>
                    <TableCell className="min-w-[180px]">
                      {/* infotip-shared: the Rule column's tip explains this cell */}
                      <Select value={e.rule} onValueChange={(v) => updateException(i, { rule: v as GateRule })} disabled={disabled}>
                        <SelectTrigger aria-label={`Exception ${i + 1} rule`} className="w-full cursor-pointer"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          {view.rules.map((r) => <SelectItem key={r} value={r} className="cursor-pointer">{RULE_LABEL[r]}</SelectItem>)}
                        </SelectContent>
                      </Select>
                    </TableCell>
                    <TableCell className="min-w-[150px]">
                      {e.rule === "finding_code" ? (
                        <>
                          {/* infotip-shared: the Finding code or algorithm column's tips explain this cell */}
                          <Input aria-label={`Exception ${i + 1} finding code`} value={e.code ?? ""} placeholder="HARDCODED_KEY" disabled={disabled}
                                 className="font-mono text-xs" onChange={(ev) => updateException(i, { code: ev.target.value })} />
                        </>
                      ) : (
                        <>
                          {/* infotip-shared: the Finding code or algorithm column's tips explain this cell */}
                          <Input aria-label={`Exception ${i + 1} algorithm`} value={e.algorithm ?? ""} placeholder="RSA-1024" disabled={disabled}
                                 onChange={(ev) => updateException(i, { algorithm: ev.target.value })} />
                        </>
                      )}
                    </TableCell>
                    <TableCell className="min-w-[160px]">
                      {/* infotip-shared: the Location column's tip explains this cell */}
                      <Input aria-label={`Exception ${i + 1} location`} value={e.location ?? ""} placeholder="vendor/hsm/*" disabled={disabled}
                             aria-invalid={Boolean(e.location) && !boundedLocation(e.location ?? "")}
                             onChange={(ev) => updateException(i, { location: ev.target.value })} />
                      {e.location && !boundedLocation(e.location) && (
                        <p className="text-xs text-red-500 mt-1" role="alert">Name a folder or file: a glob that matches everything is refused.</p>
                      )}
                    </TableCell>
                    <TableCell className="min-w-[200px]">
                      {/* infotip-shared: the Reason column's tip explains this cell */}
                      <Input aria-label={`Exception ${i + 1} reason`} value={e.reason} maxLength={300} disabled={disabled}
                             onChange={(ev) => updateException(i, { reason: ev.target.value })} />
                    </TableCell>
                    <TableCell className="min-w-[150px]">
                      {/* infotip-shared: the Expires column's tip explains this cell */}
                      <Input aria-label={`Exception ${i + 1} expires`} type="date" value={e.expires} disabled={disabled}
                             min={inDays(0)} max={inDays(view.max_exception_days)}
                             onChange={(ev) => updateException(i, { expires: ev.target.value })} />
                    </TableCell>
                    {isAdmin && (
                      <TableCell>
                        <Button size="sm" variant="outline" className="cursor-pointer text-red-500" aria-label={`Remove exception ${i + 1}`}
                                onClick={() => set("exceptions", draft.exceptions.filter((_, j) => j !== i))}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        {isAdmin && (
          <Button variant="outline" size="sm" className="cursor-pointer"
                  onClick={() => set("exceptions", [...draft.exceptions, { rule: "min_key_size", code: null, algorithm: "", location: "", reason: "", expires: inDays(90) }])}>
            <Plus className="h-4 w-4 mr-1.5" />Add exception
          </Button>
        )}
      </div>
      {stored && (
        <p className="text-xs text-zinc-500">
          Saved version {stored.row_version}{stored.updated_at ? ` (${formatDateIst(stored.updated_at)})` : ""} · digest{" "}
          <span className="font-mono">{stored.digest}</span>: the CI verdict shows the same digest.
        </p>
      )}
      <div className="flex flex-wrap gap-2">
        {isAdmin && (
          <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={save.isPending}
                  onClick={() => save.mutate()} data-testid={`${prefix}-save`}>
            {save.isPending ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <Save className="h-4 w-4 mr-1.5" />}
            Save policy
          </Button>
        )}
        <Button variant="outline" className="cursor-pointer" onClick={download} data-testid={`${prefix}-download`}>
          <Download className="h-4 w-4 mr-1.5" />Download policy file
        </Button>
        {isAdmin && (stored || integrationId) && (
          <Button variant="outline" className="cursor-pointer" disabled={reset.isPending}
                  onClick={() => {
                    if (!stored) { onDone?.(); return; }
                    if (window.confirm(integrationId ? "Make this integration follow the team policy again?" : "Go back to the default policy?")) reset.mutate();
                  }}>
            <RotateCcw className="h-4 w-4 mr-1.5" />{integrationId ? (stored ? "Use the team policy" : "Cancel") : "Reset to default"}
          </Button>
        )}
      </div>
    </div>
  );
}

function IntegrationRow({ teamId, view, item }: { teamId: number; view: GatePolicyView; item: GatePolicyView["integrations"][number] }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border border-zinc-200 dark:border-zinc-800 rounded-md p-4 space-y-3" data-testid={`gate-int-row-${item.id}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <Link href={`/${teamId}/ci_cd/${item.id}`} className="font-medium text-blue-600 dark:text-blue-400 hover:underline">{item.title}</Link>
          {item.override
            ? <StatusBadge tone="blue">Own policy: {item.override.policy.name}</StatusBadge>
            : <StatusBadge tone="zinc">Follows the team policy</StatusBadge>}
        </div>
        {!open && (
          <Button size="sm" variant="outline" className="cursor-pointer" onClick={() => setOpen(true)}>
            {item.override ? (view.is_admin ? "Edit its policy" : "View its policy") : view.is_admin ? "Give it its own policy" : "View"}
          </Button>
        )}
      </div>
      {open && (
        <PolicyEditor key={`${item.id}-${item.override?.row_version ?? 0}`} teamId={teamId} view={view} stored={item.override}
                      integrationId={item.id} onDone={() => setOpen(false)} />
      )}
    </div>
  );
}

export default function CbomGatePolicyPage({ teamId }: { teamId: number }) {
  const q = useQuery({ queryKey: gatePolicyKey(teamId), queryFn: () => getGatePolicy(teamId) });
  const view = q.data;
  return (
    <div className="flex min-h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 min-w-0 p-4 sm:p-8 overflow-auto">
        <div className="max-w-6xl mx-auto space-y-6">
          <div>
            <Link href={`/${teamId}/settings`} className="inline-flex items-center gap-1.5 text-sm text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white mb-2">
              <ArrowLeft className="h-4 w-4" />Team settings
            </Link>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">CBOM policy gate</h1>
            <p className="text-zinc-600 dark:text-zinc-400 max-w-3xl">
              What fails a pipeline that runs the DevSecShield CBOM scan (GitHub Actions, GitLab CI, Jenkins, Bamboo): banned
              algorithms, key sizes below your minimum, quantum-vulnerable and deprecated algorithms, and blocked finding codes,
              with time-limited exceptions. Every failing finding in the CI answer names the rule it broke.
              {view && !view.is_admin ? " Only team admins can change the policy." : ""}
            </p>
            <p className="text-xs text-zinc-500 mt-2 max-w-3xl">
              Offline (air-gapped) pipelines: download the policy file and run <span className="font-mono">aibom cbom --policy policy.json &lt;path&gt;</span>;
              it judges the tree with the same rules.
            </p>
          </div>
          {q.isLoading ? <LoadingBlock /> : q.isError || !view ? <ErrorBlock error={q.error} onRetry={() => q.refetch()} /> : (
            <>
              <SectionCard
                infoId="cbom.gate.team"
                title={
                  <span className="flex flex-wrap items-center gap-2">
                    Team policy
                    {view.team ? <StatusBadge tone="blue">{view.team.policy.name}</StatusBadge> : <StatusBadge tone="zinc">Default</StatusBadge>}
                    {view.team && !view.team.valid && <StatusBadge tone="red">Unreadable: the strict preset applies</StatusBadge>}
                  </span>
                }
                description="Applies to every CBOM CI/CD integration of the team that has no policy of its own."
              >
                <PolicyEditor key={`team-${view.team?.row_version ?? 0}`} teamId={teamId} view={view} stored={view.team} />
              </SectionCard>
              <SectionCard
                infoId="cbom.gate.integrations"
                title="CBOM CI/CD integrations"
                description="An integration with its own policy uses it instead of the team policy (for example a legacy application with a dated exception list)."
              >
                {view.integrations.length === 0 ? (
                  <p className="text-sm text-zinc-500">
                    No CBOM CI/CD integration yet. Create one on the <Link href={`/${teamId}/ci_cd`} className="text-blue-600 dark:text-blue-400 hover:underline">CI/CD page</Link>.
                  </p>
                ) : (
                  <div className="space-y-3">
                    {view.integrations.map((item) => (
                      <IntegrationRow key={`${item.id}-${item.override?.row_version ?? 0}`} teamId={teamId} view={view} item={item} />
                    ))}
                  </div>
                )}
              </SectionCard>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
