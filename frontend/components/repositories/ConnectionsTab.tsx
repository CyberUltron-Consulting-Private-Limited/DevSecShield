"use client";

// Connections: each organisation / group / workspace with its last discovery, test, sync now, filters, a new webhook
// secret (shown once), disable and delete (queued scans are cancelled and refunded).

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { FlaskConical, KeyRound, Loader2, RefreshCcw, SlidersHorizontal, Trash2 } from "lucide-react";
import { useState } from "react";

import { refusalReason } from "@/components/cbom/sources/logic";
import { ConfirmDialog, CopyButton, SectionCard, StatusBadge } from "@/components/cbom/sources/shared";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  deleteScmConnection,
  rotateScmWebhookSecret,
  syncScmConnection,
  testScmConnection,
  updateScmConnection,
  type ScmConnection,
  type ScmWebhookOnce,
} from "@/utils/api/scm";
import { apiBaseURL } from "@/utils/interceptors";
import { toast } from "@/utils/toast";

import ImportWizard from "./ImportWizard";
import { scmKeys } from "./keys";
import { formatCredits, PROVIDER_LABEL, SCOPES, webhookHelp, webhookUrl } from "./logic";

const SYNC_TONE: Record<string, "green" | "amber" | "red" | "blue" | "zinc"> = {
  ok: "green", partial: "amber", failed: "red", running: "blue", queued: "blue", never: "zinc",
};

function when(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleString() : "never";
}

function ConnectionCard({ teamId, c, isAdmin }: { teamId: number; c: ScmConnection; isAdmin: boolean }) {
  const qc = useQueryClient();
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [secret, setSecret] = useState<ScmWebhookOnce | null>(null);
  const done = () => qc.invalidateQueries({ queryKey: scmKeys.all(teamId) });
  const fail = (what: string) => (err: unknown) => toast.error(refusalReason(err) ?? `Could not ${what}`);
  const sync = useMutation({ mutationFn: () => syncScmConnection(teamId, c.id), onSuccess: () => { toast.success("Discovery started"); done(); }, onError: fail("start discovery") });
  const test = useMutation({
    mutationFn: () => testScmConnection(teamId, c.id),
    onSuccess: (r) => { (r.ok ? toast.success : toast.error)(r.message); done(); },
    onError: fail("test the connection"),
  });
  const rotate = useMutation({ mutationFn: () => rotateScmWebhookSecret(teamId, c.id), onSuccess: (r) => { setSecret(r.webhook); done(); }, onError: fail("make a new secret") });
  const toggle = useMutation({ mutationFn: () => updateScmConnection(teamId, c.id, { enabled: !c.enabled, expected_version: c.row_version }), onSuccess: done, onError: fail("change the connection") });
  const remove = useMutation({
    mutationFn: () => deleteScmConnection(teamId, c.id),
    onSuccess: (r) => { toast.success(`Deleted; ${formatCredits(r.refunded)} refunded for queued scans`); setConfirmDelete(false); done(); },
    onError: fail("delete the connection"),
  });
  const s = c.sync.summary;
  const label = SCOPES[c.provider].find((x) => x.scope === c.scope_kind)?.label ?? c.scope_kind;
  const running = c.sync.status === "running" || c.sync.status === "queued";
  return (
    <SectionCard
      title={<span className="flex flex-wrap items-center gap-2">{c.name}<StatusBadge tone="zinc">{PROVIDER_LABEL[c.provider]}</StatusBadge>{!c.enabled && <StatusBadge tone="amber">Disabled</StatusBadge>}</span>}
      description={`${label}${c.scope_name ? `: ${c.scope_name}` : ""} · ${c.api_base}`}
      actions={isAdmin && (
        <>
          <Button size="sm" variant="outline" className="cursor-pointer" disabled={sync.isPending || running} onClick={() => sync.mutate()}>
            {running ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <RefreshCcw className="h-4 w-4 mr-1.5" />}Sync now
          </Button>
          <Button size="sm" variant="outline" className="cursor-pointer" disabled={test.isPending} onClick={() => test.mutate()}>
            <FlaskConical className="h-4 w-4 mr-1.5" />Test
          </Button>
          <Button size="sm" variant="outline" className="cursor-pointer" onClick={() => setFiltersOpen(true)}>
            <SlidersHorizontal className="h-4 w-4 mr-1.5" />Filters
          </Button>
          <Button size="sm" variant="outline" className="cursor-pointer" disabled={rotate.isPending} onClick={() => rotate.mutate()}>
            <KeyRound className="h-4 w-4 mr-1.5" />New webhook secret
          </Button>
          <Button size="sm" variant="outline" className="cursor-pointer" disabled={toggle.isPending} onClick={() => toggle.mutate()}>
            {c.enabled ? "Disable" : "Enable"}
          </Button>
          <Button size="icon" variant="outline" className="cursor-pointer h-8 w-8" aria-label={`Delete ${c.name}`} onClick={() => setConfirmDelete(true)}>
            <Trash2 className="h-4 w-4" />
          </Button>
        </>
      )}
    >
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm">
        <div><p className="text-zinc-500 text-xs">Repositories</p><p className="font-semibold">{(c.repos ?? 0).toLocaleString("en-US")}</p></div>
        <div><p className="text-zinc-500 text-xs">In scope</p><p className="font-semibold">{(c.repos_in_scope ?? 0).toLocaleString("en-US")}</p></div>
        <div>
          <p className="text-zinc-500 text-xs">Last discovery</p>
          <StatusBadge tone={SYNC_TONE[c.sync.status] ?? "zinc"}>{c.sync.status}</StatusBadge>
          <p className="text-xs text-zinc-500 mt-1">{when(c.sync.last_at)}</p>
        </div>
        <div><p className="text-zinc-500 text-xs">Next discovery</p><p className="text-xs">{when(c.sync.next_at)}</p></div>
      </div>
      {s.discovered !== undefined && (
        <p className="text-xs text-zinc-500 mt-3">
          {s.discovered} found, {s.added ?? 0} new, {s.updated ?? 0} changed, {s.removed ?? 0} removed · {s.api_calls ?? 0} API calls,
          {" "}{s.waits ?? 0} rate-limit waits ({Math.round(s.waited_s ?? 0)} s){s.rate_remaining !== null && s.rate_remaining !== undefined ? ` · ${s.rate_remaining} calls left in the window` : ""}
        </p>
      )}
      {c.sync.error && <p className="text-sm text-amber-600 dark:text-amber-400 mt-2" role="status">{c.sync.error}</p>}
      {c.last_test.message && <p className="text-xs text-zinc-500 mt-1">Last test: {c.last_test.message}</p>}
      <p className="text-xs text-zinc-500 mt-2 break-all">Webhook URL: {webhookUrl(apiBaseURL, c.webhook_path)}</p>

      {filtersOpen && <ImportWizard teamId={teamId} open={filtersOpen} onOpenChange={setFiltersOpen} existing={c} />}
      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title={`Delete ${c.name}?`}
        description="Its repositories leave the inventory and the roll-up, and scans still queued for them are cancelled and refunded. Finished scans stay on their product pages."
        confirmLabel="Delete"
        destructive
        pending={remove.isPending}
        onConfirm={() => remove.mutate()}
      />
      <Dialog open={Boolean(secret)} onOpenChange={(v) => !v && setSecret(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New webhook secret</DialogTitle>
            <DialogDescription>Shown only now. The old secret stops working immediately. {webhookHelp(c.provider)}</DialogDescription>
          </DialogHeader>
          {secret && (
            <div className="space-y-2">
              <code className="block text-xs break-all bg-zinc-100 dark:bg-zinc-800 rounded px-2 py-1">{secret.secret}</code>
              <CopyButton text={secret.secret} label="Copy secret" />
            </div>
          )}
          <DialogFooter><Button className="cursor-pointer" onClick={() => setSecret(null)}>Done</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </SectionCard>
  );
}

export default function ConnectionsTab({ teamId, isAdmin, connections }: { teamId: number; isAdmin: boolean; connections: ScmConnection[] }) {
  return (
    <div className="space-y-4">
      {/* keyed by id only: a new webhook secret bumps row_version, and a remount would drop the secret's dialog */}
      {connections.map((c) => <ConnectionCard key={c.id} teamId={teamId} c={c} isAdmin={isAdmin} />)}
    </div>
  );
}
