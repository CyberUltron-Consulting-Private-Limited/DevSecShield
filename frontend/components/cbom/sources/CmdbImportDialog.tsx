"use client";

// CMDB import wizard (CBOM Sources): upload a CSV or pull the ServiceNow CMDB, preview what changes, then confirm.
// Hosts already in a server source get its metadata updated (owner, application, criticality, exposure, data
// classification, environment) without touching how it connects, so running and queued jobs are kept. New hosts become
// Linux server sources, Windows hosts WinRM sources whose login is read from a vault, and database / Kubernetes / HSM
// rows sources of those kinds (#225); CIDRs become network ranges. A segment or scan_node column picks each row's scan
// node; the chosen node takes rows that name none. Admins only.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { DatabaseZap, Loader2, Upload } from "lucide-react";
import { useState } from "react";
import { toast } from "@/utils/toast";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { listCbomScanNodes } from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
import {
  applyCmdbImport, previewCmdbImport, type CmdbPlan, type CmdbRequest, type CmdbVaultProvider,
} from "@/utils/api/integrations";

import { CA_ENGINES, DIALOG_LAYOUT, createLine, importNodes, leftOutLine, segmentPickers } from "./cmdbLogic";
import { VAULT_PROVIDERS } from "./vaultProviders";
import { VaultNodeSettings } from "./VaultNodeSettings";

import { cbomSourcesKeys } from "./keys";
import { ChoiceCards, Checkbox2, Field, NodeSelect, StatusBadge } from "./shared";
import { InfoTip } from "@/components/ui/info-tip";

const MAX_CSV = 2 * 1024 * 1024;
const SAMPLE = "hostname,ip_address,owner,application,criticality,exposure,data_classification,environment,os,segment\n" +
  "app-01.bank.local,10.20.0.11,Payments Team,Payments,critical,internet,restricted,production,linux,dc-mumbai\n" +
  "win-01.bank.local,10.20.0.12,Payments Team,Payments,high,internal,restricted,production,windows,dc-chennai\n";
const NONE = "__none";

function fmt(value: unknown): string {
  return value === null || value === undefined || value === "" ? "—" : String(value);
}

export function PlanView({ plan }: { plan: CmdbPlan }) {
  return (
    <div className={`space-y-3 text-sm ${DIALOG_LAYOUT.text}`} data-testid="cmdb-plan">
      <div className="flex flex-wrap gap-2">
        <StatusBadge tone="blue">{plan.rows} rows read</StatusBadge>
        <StatusBadge tone="green">{plan.counts.create} sources to create ({plan.counts.new_targets} targets)</StatusBadge>
        <StatusBadge tone="green">{plan.counts.update} sources to update</StatusBadge>
        <StatusBadge tone="zinc">{plan.unchanged} unchanged</StatusBadge>
        {(plan.counts.merged ?? 0) > 0 && <StatusBadge tone="blue">{plan.counts.merged} hosts on several rows (merged)</StatusBadge>}
        {plan.counts.conflict > 0 && <StatusBadge tone="amber">{plan.counts.conflict} conflicts</StatusBadge>}
        {plan.counts.skipped > 0 && <StatusBadge tone="red">{plan.counts.skipped} rows skipped</StatusBadge>}
        {(plan.counts.over_limit ?? 0) > 0 && (
          <StatusBadge tone="red">{plan.counts.over_limit} over the source limit (not created)</StatusBadge>
        )}
      </div>
      {plan.limit && (
        <p className="text-xs text-zinc-600 dark:text-zinc-400" data-testid="cmdb-limit">
          Source limit: this team has {plan.limit.used.toLocaleString("en-US")} of {plan.limit.max.toLocaleString("en-US")} sources
          ({plan.limit.remaining.toLocaleString("en-US")} more allowed, set by {plan.limit.setting}).
        </p>
      )}
      {(plan.warnings ?? []).map((w) => (
        <p key={w} className="text-sm text-amber-700 dark:text-amber-400" role="alert">{w}</p>
      ))}
      {plan.updates.length > 0 && (
        <div>
          <p className="font-medium mb-1">Metadata updates <InfoTip id="cbsrc.cmdb.updates" /></p>
          <ul className="space-y-1 text-xs">
            {plan.updates.map((u) => (
              <li key={u.source_id}>
                <span className="font-medium">{u.source}</span>:{" "}
                {Object.entries(u.changes).map(([k, [a, b]]) => `${k.replace(/_/g, " ")} ${fmt(a)} → ${fmt(b)}`).join("; ")}
              </li>
            ))}
          </ul>
        </div>
      )}
      {plan.creates.length > 0 && (
        <div>
          <p className="font-medium mb-1">New sources <InfoTip id="cbsrc.cmdb.creates" /></p>
          <ul className="space-y-1 text-xs">
            {plan.creates.map((c) => (
              <li key={c.name}>
                <span className="font-medium">{c.name}</span> ({createLine(c)})
                {Object.keys(c.metadata).length > 0 && <span className="text-zinc-500"> · {Object.entries(c.metadata).map(([k, v]) => `${k.replace(/_/g, " ")}: ${v}`).join(", ")}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {(plan.over_limit ?? []).length > 0 && (
        <div data-testid="cmdb-over-limit">
          <p className="font-medium mb-1 text-red-600 dark:text-red-400">Over the source limit (will not be created) <InfoTip id="cbsrc.cmdb.over_limit" /></p>
          <p className="text-xs text-zinc-500 mb-1">{plan.over_limit![0].reason}</p>
          <ul className="space-y-1 text-xs max-h-40 overflow-y-auto">
            {plan.over_limit!.map((c) => (
              <li key={c.name}>
                <span className="font-medium">{c.name}</span> ({createLine(c)})
              </li>
            ))}
          </ul>
        </div>
      )}
      {plan.conflicts.length > 0 && (
        <div>
          <p className="font-medium mb-1 text-amber-600 dark:text-amber-400">Conflicts (left unchanged) <InfoTip id="cbsrc.cmdb.conflicts" /></p>
          <ul className="space-y-1 text-xs">
            {plan.conflicts.map((c) => (
              <li key={`${c.source_id ?? c.host}-${c.field}`}>
                {c.source ?? `${c.host} (new)`}: rows disagree on {c.field.replace(/_/g, " ")} ({Object.entries(c.values).map(([v, lines]) => `${v} on line ${lines.join(", ")}`).join("; ")})
              </li>
            ))}
          </ul>
        </div>
      )}
      {(plan.merged ?? []).length > 0 && (
        <div data-testid="cmdb-merged">
          <p className="font-medium mb-1">Rows merged into one source <InfoTip id="cbsrc.cmdb.merged" /></p>
          <ul className="space-y-1 text-xs max-h-40 overflow-y-auto">
            {plan.merged!.map((m, i) => (
              <li key={`${m.label}-${i}`}>
                <span className="font-medium">{m.label}</span>: lines {m.lines.join(", ")}{m.notes.length ? ` (${m.notes.join("; ")})` : ""}
              </li>
            ))}
          </ul>
        </div>
      )}
      {(plan.unchanged_items ?? []).length > 0 && (
        <div data-testid="cmdb-unchanged">
          <p className="font-medium mb-1">Already up to date <InfoTip id="cbsrc.cmdb.unchanged" /></p>
          <ul className="space-y-1 text-xs max-h-40 overflow-y-auto">
            {plan.unchanged_items!.map((u) => (
              <li key={u.source_id}>
                <span className="font-medium">{u.source}</span>: {u.lines.length ? `line${u.lines.length === 1 ? "" : "s"} ${u.lines.join(", ")}` : "matched"}, nothing to change
              </li>
            ))}
          </ul>
        </div>
      )}
      {plan.skipped.length > 0 && (
        <div>
          <p className="font-medium mb-1 text-red-600 dark:text-red-400">Skipped or partly read rows <InfoTip id="cbsrc.cmdb.skipped" /></p>
          <ul className="space-y-1 text-xs max-h-40 overflow-y-auto">
            {plan.skipped.map((s, i) => (
              <li key={i}>{s.line ? `Line ${s.line}` : s.label ?? "Row"}: {s.reason}</li>
            ))}
          </ul>
        </div>
      )}
      {plan.truncated && <p className="text-xs text-zinc-500">Only the first 500 items of each list are shown.</p>}
    </div>
  );
}

export default function CmdbImportDialog({ teamId }: { teamId: number }) {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [source, setSource] = useState<"csv" | "servicenow">("csv");
  const [csv, setCsv] = useState("");
  const [nodeId, setNodeId] = useState<number | null>(null);
  const [createMissing, setCreateMissing] = useState(true);
  const [segmentNodes, setSegmentNodes] = useState<Record<string, number>>({});
  const [vaultProvider, setVaultProvider] = useState<CmdbVaultProvider | null>(null);
  const [winPath, setWinPath] = useState("");
  const [databaseCa, setDatabaseCa] = useState<Record<string, { pem: string; file: string }>>({});
  const [caEngine, setCaEngine] = useState("*");
  const [plan, setPlan] = useState<CmdbPlan | null>(null);
  const nodes = useQuery({ queryKey: cbomSourcesKeys.nodes(teamId), queryFn: () => listCbomScanNodes(teamId), enabled: open });
  const request = (digest?: string): CmdbRequest => ({
    source, csv: source === "csv" ? csv : undefined, node_id: nodeId, create_missing: createMissing, digest,
    segment_nodes: Object.keys(segmentNodes).length ? segmentNodes : undefined,
    vault_provider: vaultProvider,
    windows_vault: vaultProvider && winPath.trim() ? { provider: vaultProvider, path: winPath.trim() } : null,
    database_ca: Object.keys(databaseCa).length ? Object.fromEntries(Object.entries(databaseCa).map(([k, v]) => [k, v.pem])) : undefined,
  });
  // #367: registered agentless nodes only; segment pickers only for the file's segments that need a choice
  const offered = importNodes(nodes.data?.nodes ?? []);
  const leftOut = leftOutLine(offered);
  const shared = segmentPickers(plan, offered.usable);
  const preview = useMutation({
    mutationFn: () => previewCmdbImport(teamId, request()),
    onSuccess: (r) => setPlan(r.plan),
    onError: (e) => showErrorToast(e),
  });
  const apply = useMutation({
    mutationFn: () => applyCmdbImport(teamId, request(plan?.digest)),
    onSuccess: (r) => {
      const over = r.result.over_limit ? `; ${r.result.over_limit} over the source limit were not created` : "";
      toast.success(`CMDB import: ${r.result.created} sources created, ${r.result.updated} updated${over}`);
      queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });
      setOpen(false);
      setPlan(null);
    },
    onError: (e) => showErrorToast(e),
  });
  const reset = () => setPlan(null);
  // rows with no segment or scan_node column go to the chosen node
  const needsNode = (plan?.creates ?? []).some((c) => c.node_id == null) && !nodeId;

  return (
    <>
      <Button variant="outline" className="cursor-pointer" onClick={() => setOpen(true)} data-testid="cmdb-import-open">
        <DatabaseZap className="h-4 w-4 mr-2" />
        Import from CMDB
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className={DIALOG_LAYOUT.content} data-testid="cmdb-dialog">
          <DialogHeader>
            <DialogTitle className={DIALOG_LAYOUT.text}>Import sources and metadata from a CMDB <InfoTip id="cbsrc.cmdb.dialog" /></DialogTitle>
            <DialogDescription className={DIALOG_LAYOUT.text}>
              Preview first: nothing changes until you confirm. Hosts already in a server source get its owner, application,
              criticality, exposure, data classification and environment updated; running and queued collections are not
              interrupted. A blank cell keeps the stored value. Only team admins can import.
            </DialogDescription>
          </DialogHeader>
          <div className={DIALOG_LAYOUT.body}>
            <ChoiceCards
              infoId="cbsrc.cmdb.source"
              name="cmdb-source"
              label="Import from"
              value={source}
              onChange={(v) => { setSource(v); reset(); }}
              options={[
                { value: "csv", title: "CSV file", description: "Columns: host / fqdn / ip / cidr, owner, application, criticality, exposure, data_classification, environment, os, segment or scan_node; for databases, clusters and HSMs: kind, engine, port, login, database_name, api_url, context, module, token_label, vault_path" },
                { value: "servicenow", title: "ServiceNow CMDB", description: "Reads the CMDB table set in Settings > Integrations (default cmdb_ci_server)" },
              ]}
            />
            {source === "csv" && (
              <Field infoId="cbsrc.cmdb.csv" label="CSV" htmlFor="cmdb-csv" hint="Up to 5,000 rows and 2 MB. A header row is required.">
                <div className="space-y-2">
                  <label className="inline-flex items-center gap-2 text-sm text-blue-600 dark:text-blue-400 cursor-pointer">
                    <Upload className="h-4 w-4" />
                    Choose a file
                    {/* infotip-shared: file picker behind Choose a file; the CSV field's tip covers it */}
                    <input type="file" accept=".csv,text/csv" className="sr-only" data-testid="cmdb-file" onChange={async (e) => {
                      const file = e.target.files?.[0];
                      if (!file) return;
                      if (file.size > MAX_CSV) { toast.error("The CSV is larger than 2 MB"); return; }
                      setCsv(await file.text());
                      reset();
                    }} />
                  </label>
                  <Textarea id="cmdb-csv" value={csv} onChange={(e) => { setCsv(e.target.value); reset(); }} placeholder={SAMPLE}
                            spellCheck={false} wrap="off" className={DIALOG_LAYOUT.csv} data-testid="cmdb-csv" />
                </div>
              </Field>
            )}
            <Checkbox2 infoId="cbsrc.cmdb.create" id="cmdb-create" checked={createMissing} onChange={(v) => { setCreateMissing(v); reset(); }}>
              Create sources for hosts that are not in any source yet (Linux servers, scan-node key login; CIDRs as network ranges)
            </Checkbox2>
            {createMissing && (
              <Field infoId="cbsrc.cmdb.node" label="Scan node for new sources" htmlFor="cmdb-node"
                     hint={"For rows with no segment or scan_node column. A row's segment picks the scan node of that segment." + (leftOut ? ` ${leftOut}` : "")}>
                <NodeSelect id="cmdb-node" nodes={offered.usable} value={nodeId} onChange={(v) => { setNodeId(v); reset(); }} />
              </Field>
            )}
            {createMissing && shared.map(({ segment, rows, nodes: choices }) => (
              <Field key={segment} infoId="cbsrc.cmdb.segment_node" label={`Scan node for segment ${segment}`} htmlFor={`cmdb-seg-${segment}`}
                     hint={`${choices.length} registered scan nodes serve this segment; its ${rows} row${rows === 1 ? "" : "s"} go to the one you choose`}>
                <NodeSelect id={`cmdb-seg-${segment}`} nodes={choices} value={segmentNodes[segment] ?? null}
                            onChange={(v) => {
                              setSegmentNodes((m) => {
                                const next = { ...m };
                                if (v) next[segment] = v; else delete next[segment];
                                return next;
                              });
                              reset();
                            }} />
              </Field>
            ))}
            {createMissing && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3" data-testid="cmdb-vault">
                <Field infoId="cbsrc.cmdb.vault" label="Vault for credentials" htmlFor="cmdb-vault-provider"
                       hint="Logins are read from your vault, never imported from the file (vault_path column, and Windows below)">
                  <Select value={vaultProvider ?? NONE} onValueChange={(v) => { setVaultProvider(v === NONE ? null : v as CmdbVaultProvider); reset(); }}>
                    <SelectTrigger id="cmdb-vault-provider" className="w-full cursor-pointer"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value={NONE} className="cursor-pointer">No vault</SelectItem>
                      {VAULT_PROVIDERS.map((p) => (
                        <SelectItem key={p.value} value={p.value} disabled={!p.available} className="cursor-pointer">{p.optionLabel}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>
                <Field infoId="cbsrc.cmdb.windows_vault" label="Windows WinRM login (vault secret path)" htmlFor="cmdb-win-path"
                       hint="Windows rows become WinRM (HTTPS 5986) sources that read this login; without it they are skipped">
                  <Input id="cmdb-win-path" value={winPath} disabled={!vaultProvider} placeholder="secret/data/cbom/winrm"
                         onChange={(e) => { setWinPath(e.target.value); reset(); }} data-testid="cmdb-win-path" />
                </Field>
                {/* #364: what the node's operator sets; the import's node is checked here, every row's node in the preview */}
                <VaultNodeSettings provider={vaultProvider} path={winPath} testId="cmdb-vault-node-settings"
                  node={(nodes.data?.nodes ?? []).find((n) => n.id === nodeId) ?? null} className="sm:col-span-2" />
              </div>
            )}
            {createMissing && (
              <div className="space-y-2 min-w-0" data-testid="cmdb-db-ca">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <Field infoId="cbsrc.cmdb.db_ca_engine" label="Database CA certificates" htmlFor="cmdb-ca-engine"
                         hint="MySQL, SQL Server, Oracle, MongoDB and Redis logins need TLS with the server's CA: give it once here">
                    <Select value={caEngine} onValueChange={setCaEngine}>
                      <SelectTrigger id="cmdb-ca-engine" className="w-full cursor-pointer"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {CA_ENGINES.map((e) => <SelectItem key={e.value} value={e.value} className="cursor-pointer">{e.label}</SelectItem>)}
                      </SelectContent>
                    </Select>
                  </Field>
                  <Field infoId="cbsrc.cmdb.db_ca_file" label="CA certificate file (PEM)" htmlFor="cmdb-ca-file" hint="A bundle of several CA certificates is fine">
                    <Input id="cmdb-ca-file" type="file" accept=".pem,.crt,.cer" className="cursor-pointer" data-testid="cmdb-ca-file"
                           onChange={async (e) => {
                             const input = e.currentTarget;
                             const file = input.files?.[0];
                             if (!file) return;
                             if (file.size > 64 * 1024) { toast.error("The CA file is larger than 64 KB"); return; }
                             const pem = await file.text();
                             setDatabaseCa((m) => ({ ...m, [caEngine]: { pem, file: file.name } }));
                             input.value = "";
                             reset();
                           }} />
                  </Field>
                </div>
                {Object.keys(databaseCa).length > 0 && (
                  <ul className="text-xs space-y-1" data-testid="cmdb-ca-list">
                    {Object.entries(databaseCa).map(([engine, v]) => (
                      <li key={engine} className="flex flex-wrap items-center gap-2 min-w-0">
                        <span className={DIALOG_LAYOUT.text}>{CA_ENGINES.find((e) => e.value === engine)?.label ?? engine}: {v.file}</span>
                        <Button type="button" variant="ghost" size="sm" className="cursor-pointer h-6 px-2"
                                onClick={() => { setDatabaseCa((m) => { const next = { ...m }; delete next[engine]; return next; }); reset(); }}>
                          Remove
                        </Button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
            {plan && <PlanView plan={plan} />}
          </div>
          <DialogFooter className="gap-2 flex-wrap">
            <Button variant="outline" className="cursor-pointer" onClick={() => setOpen(false)}>Cancel</Button>
            {!plan ? (
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" data-testid="cmdb-preview"
                      disabled={preview.isPending || (source === "csv" && !csv.trim())} onClick={() => preview.mutate()}>
                {preview.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Preview
              </Button>
            ) : (
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" data-testid="cmdb-apply"
                      disabled={apply.isPending || needsNode || (plan.counts.create === 0 && plan.counts.update === 0)}
                      title={needsNode ? "Choose the scan node for the new sources" : undefined}
                      onClick={() => apply.mutate()}>
                {apply.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Confirm import
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
