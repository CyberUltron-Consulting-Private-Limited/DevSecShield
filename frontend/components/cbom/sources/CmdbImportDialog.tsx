"use client";

// CMDB import wizard (CBOM Sources): upload a CSV or pull the ServiceNow CMDB, preview what changes, then confirm.
// Hosts already in a server source get its metadata updated (owner, application, criticality, exposure, data
// classification, environment) without touching how it connects, so running and queued jobs are kept. New hosts become
// Linux server sources on the chosen scan node; CIDRs become network ranges. Admins only.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { DatabaseZap, Loader2, Upload } from "lucide-react";
import { useState } from "react";
import { toast } from "@/utils/toast";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { listCbomScanNodes } from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
import { applyCmdbImport, previewCmdbImport, type CmdbPlan, type CmdbRequest } from "@/utils/api/integrations";

import { cbomSourcesKeys } from "./keys";
import { ChoiceCards, Checkbox2, Field, NodeSelect, StatusBadge } from "./shared";

const MAX_CSV = 2 * 1024 * 1024;
const SAMPLE = "hostname,ip_address,owner,application,criticality,exposure,data_classification,environment,os\n" +
  "app-01.bank.local,10.20.0.11,Payments Team,Payments,critical,internet,restricted,production,linux\n";

function fmt(value: unknown): string {
  return value === null || value === undefined || value === "" ? "—" : String(value);
}

function PlanView({ plan }: { plan: CmdbPlan }) {
  return (
    <div className="space-y-3 text-sm" data-testid="cmdb-plan">
      <div className="flex flex-wrap gap-2">
        <StatusBadge tone="blue">{plan.rows} rows read</StatusBadge>
        <StatusBadge tone="green">{plan.counts.create} sources to create ({plan.counts.new_targets} targets)</StatusBadge>
        <StatusBadge tone="green">{plan.counts.update} sources to update</StatusBadge>
        <StatusBadge tone="zinc">{plan.unchanged} unchanged</StatusBadge>
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
          <p className="font-medium mb-1">Metadata updates</p>
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
          <p className="font-medium mb-1">New sources</p>
          <ul className="space-y-1 text-xs">
            {plan.creates.map((c) => (
              <li key={c.name}>
                <span className="font-medium">{c.name}</span> ({c.kind === "network_range" ? `network range ${c.cidr}` : `${c.targets?.length} Linux hosts`})
                {Object.keys(c.metadata).length > 0 && <span className="text-zinc-500"> · {Object.entries(c.metadata).map(([k, v]) => `${k.replace(/_/g, " ")}: ${v}`).join(", ")}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {(plan.over_limit ?? []).length > 0 && (
        <div data-testid="cmdb-over-limit">
          <p className="font-medium mb-1 text-red-600 dark:text-red-400">Over the source limit (will not be created)</p>
          <p className="text-xs text-zinc-500 mb-1">{plan.over_limit![0].reason}</p>
          <ul className="space-y-1 text-xs max-h-40 overflow-y-auto">
            {plan.over_limit!.map((c) => (
              <li key={c.name}>
                <span className="font-medium">{c.name}</span> ({c.kind === "network_range" ? `network range ${c.cidr}` : `${c.targets?.length} hosts`})
              </li>
            ))}
          </ul>
        </div>
      )}
      {plan.conflicts.length > 0 && (
        <div>
          <p className="font-medium mb-1 text-amber-600 dark:text-amber-400">Conflicts (left unchanged)</p>
          <ul className="space-y-1 text-xs">
            {plan.conflicts.map((c) => (
              <li key={`${c.source_id}-${c.field}`}>
                {c.source}: rows disagree on {c.field.replace(/_/g, " ")} ({Object.entries(c.values).map(([v, lines]) => `${v} on line ${lines.join(", ")}`).join("; ")})
              </li>
            ))}
          </ul>
        </div>
      )}
      {plan.skipped.length > 0 && (
        <div>
          <p className="font-medium mb-1 text-red-600 dark:text-red-400">Skipped or partly read rows</p>
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
  const [plan, setPlan] = useState<CmdbPlan | null>(null);
  const nodes = useQuery({ queryKey: cbomSourcesKeys.nodes(teamId), queryFn: () => listCbomScanNodes(teamId), enabled: open });
  const request = (digest?: string): CmdbRequest => ({
    source, csv: source === "csv" ? csv : undefined, node_id: nodeId, create_missing: createMissing, digest,
  });
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
  const needsNode = (plan?.counts.create ?? 0) > 0 && !nodeId;

  return (
    <>
      <Button variant="outline" className="cursor-pointer" onClick={() => setOpen(true)} data-testid="cmdb-import-open">
        <DatabaseZap className="h-4 w-4 mr-2" />
        Import from CMDB
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-3xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Import sources and metadata from a CMDB</DialogTitle>
            <DialogDescription>
              Preview first: nothing changes until you confirm. Hosts already in a server source get its owner, application,
              criticality, exposure, data classification and environment updated; running and queued collections are not
              interrupted. A blank cell keeps the stored value. Only team admins can import.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <ChoiceCards
              name="cmdb-source"
              label="Import from"
              value={source}
              onChange={(v) => { setSource(v); reset(); }}
              options={[
                { value: "csv", title: "CSV file", description: "Columns: host / fqdn / ip / cidr, owner, application, criticality, exposure, data_classification, environment, os" },
                { value: "servicenow", title: "ServiceNow CMDB", description: "Reads the CMDB table set in Settings > Integrations (default cmdb_ci_server)" },
              ]}
            />
            {source === "csv" && (
              <Field label="CSV" htmlFor="cmdb-csv" hint="Up to 5,000 rows and 2 MB. A header row is required.">
                <div className="space-y-2">
                  <label className="inline-flex items-center gap-2 text-sm text-blue-600 dark:text-blue-400 cursor-pointer">
                    <Upload className="h-4 w-4" />
                    Choose a file
                    <input type="file" accept=".csv,text/csv" className="sr-only" data-testid="cmdb-file" onChange={async (e) => {
                      const file = e.target.files?.[0];
                      if (!file) return;
                      if (file.size > MAX_CSV) { toast.error("The CSV is larger than 2 MB"); return; }
                      setCsv(await file.text());
                      reset();
                    }} />
                  </label>
                  <Textarea id="cmdb-csv" value={csv} onChange={(e) => { setCsv(e.target.value); reset(); }} placeholder={SAMPLE}
                            spellCheck={false} className="font-mono text-xs min-h-[140px]" />
                </div>
              </Field>
            )}
            <Checkbox2 id="cmdb-create" checked={createMissing} onChange={(v) => { setCreateMissing(v); reset(); }}>
              Create sources for hosts that are not in any source yet (Linux servers, scan-node key login; CIDRs as network ranges)
            </Checkbox2>
            {createMissing && (
              <Field label="Scan node for new sources" htmlFor="cmdb-node" hint="The node that can reach the new hosts">
                <NodeSelect id="cmdb-node" nodes={nodes.data?.nodes ?? []} value={nodeId} onChange={(v) => { setNodeId(v); reset(); }} />
              </Field>
            )}
            {plan && <PlanView plan={plan} />}
          </div>
          <DialogFooter className="gap-2">
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
