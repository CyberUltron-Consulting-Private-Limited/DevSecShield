"use client";

// Agent pool tokens (WP8b): one token for a Helm DaemonSet whose pods each enroll as their own agent-mode scan node,
// named after their Kubernetes node. Agent nodes read only their own host and are never given a credential.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban, KeyRound, Loader2, Plus } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  createCbomNodePool,
  listCbomNodePools,
  revokeCbomNodePool,
  type CbomNodePool,
  type CbomPoolStatus,
} from "@/utils/api/cbom_agents";

import { cbomSourcesKeys } from "./keys";
import { formatDateTime, helmAgentCommand } from "./logic";
import { CodeSnippet, ConfirmDialog, Field, SectionCard, StatusBadge, type Tone } from "./shared";

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;
const EXPIRY = [
  { hours: 24, label: "24 hours" },
  { hours: 24 * 7, label: "7 days" },
  { hours: 24 * 30, label: "30 days" },
  { hours: 24 * 90, label: "90 days" },
];
const POOL_STATUS: Record<CbomPoolStatus, [Tone, string]> = {
  active: ["green", "Active"],
  full: ["amber", "All enrollments used"],
  expired: ["zinc", "Expired"],
  revoked: ["red", "Revoked"],
};

export function AgentPoolsCard({ teamId, image, apiUrl }: { teamId: number; image: string; apiUrl: string }) {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [segment, setSegment] = useState("Kubernetes");
  const [hours, setHours] = useState(24 * 7);
  const [max, setMax] = useState("50");
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<{ pool: CbomNodePool; token: string } | null>(null);
  const [revoking, setRevoking] = useState<CbomNodePool | null>(null);

  const key = [...cbomSourcesKeys.all(teamId), "node-pools"] as const;
  const pools = useQuery({
    queryKey: key,
    queryFn: () => listCbomNodePools(teamId),
    enabled: Number.isFinite(teamId),
    retry: 1,
    refetchInterval: created ? 10000 : 60000,
  });
  const invalidate = () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });

  const create = useMutation({
    mutationFn: () =>
      createCbomNodePool(teamId, { name: name.trim(), segment: segment.trim(), expires_in_hours: hours, max_enrollments: Number(max) }),
    onSuccess: (data) => setCreated({ pool: data.pool, token: data.registration_token }),
    onError: (err) => setError((err as Error)?.message || "The token was not created"),
    onSettled: invalidate,
  });
  const revoke = useMutation({
    mutationFn: (pool: CbomNodePool) => revokeCbomNodePool(teamId, pool.id),
    onSuccess: () => setRevoking(null),
    onSettled: invalidate,
  });

  const submit = () => {
    const n = Number(max);
    if (!NAME_RE.test(name.trim())) {
      setError("Use 1-64 letters, digits, spaces, dots, dashes or underscores, starting with a letter or digit.");
      return;
    }
    if (!Number.isInteger(n) || n < 1 || n > 1000) {
      setError("Allow between 1 and 1000 nodes to enroll.");
      return;
    }
    setError(null);
    create.mutate();
  };

  const rows = pools.data?.pools ?? [];
  return (
    <SectionCard
      title="Host agents on Kubernetes (agent pool tokens)"
      description="One token for a Helm DaemonSet: every pod enrolls as its own scan node named after its Kubernetes node, reads only that node's files through a read-only mount, and is never given a credential."
      actions={
        <Button variant="outline" className="cursor-pointer" onClick={() => { setOpen(true); setCreated(null); setName(""); setError(null); }}
          data-testid="create-agent-pool">
          <Plus className="h-4 w-4 mr-2" />
          Create agent pool token
        </Button>
      }
    >
      {open && (
        <div className="mb-6 space-y-4 rounded-lg border border-zinc-200 dark:border-zinc-800 p-4" data-testid="agent-pool-form">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Field label="Name" htmlFor="pool-name" required error={error}>
              <Input id="pool-name" value={name} maxLength={64} disabled={!!created} placeholder="prod-cluster"
                onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label="Network segment" htmlFor="pool-segment">
              <Input id="pool-segment" value={segment} maxLength={64} disabled={!!created} onChange={(e) => setSegment(e.target.value)} />
            </Field>
            <Field label="Token expires in" htmlFor="pool-expiry" hint="Nodes that enrolled keep working after it expires">
              <Select value={String(hours)} disabled={!!created} onValueChange={(v) => setHours(Number(v))}>
                <SelectTrigger id="pool-expiry" className="w-full cursor-pointer"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {EXPIRY.map((e) => <SelectItem key={e.hours} value={String(e.hours)} className="cursor-pointer">{e.label}</SelectItem>)}
                </SelectContent>
              </Select>
            </Field>
            <Field label="Nodes that may enroll" htmlFor="pool-max" hint="At least the number of Kubernetes nodes">
              <Input id="pool-max" type="number" min={1} max={1000} value={max} disabled={!!created} onChange={(e) => setMax(e.target.value)} />
            </Field>
          </div>
          {!created ? (
            <div className="flex gap-2">
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={create.isPending} onClick={submit}>
                {create.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <KeyRound className="h-4 w-4 mr-2" />}
                Create token and show the Helm command
              </Button>
              <Button variant="outline" className="cursor-pointer" onClick={() => setOpen(false)}>Cancel</Button>
            </div>
          ) : (
            <div className="space-y-2" data-testid="agent-pool-command">
              <CodeSnippet code={helmAgentCommand({ poolToken: created.token, apiUrl, image })} language="bash" />
              <p className="text-xs text-zinc-500">
                The token is shown only here. It enrolls at most {created.pool.max_enrollments} nodes until{" "}
                {formatDateTime(created.pool.expires_at)}. Each pod keeps its node credential on its Kubernetes node
                (<span className="font-mono">/var/lib/zs-node-agent</span>), so a restarted pod does not enroll again. Add
                {" "}<span className="font-mono">--set agent.runAsRoot=true</span> to read root-only files, and
                {" "}<span className="font-mono">--set agent.hostPID=true</span> to see the crypto libraries running processes load.
              </p>
              <Button variant="outline" size="sm" className="cursor-pointer" onClick={() => { setOpen(false); setCreated(null); }}>Done</Button>
            </div>
          )}
        </div>
      )}
      {rows.length === 0 ? (
        <p className="text-sm text-zinc-500">No agent pool tokens yet. Host agents show up in the node list above once they enroll.</p>
      ) : (
        <div className="border rounded-lg overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Token</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Enrolled</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead>Nodes</TableHead>
                <TableHead className="w-12"><span className="sr-only">Actions</span></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((pool) => {
                const [tone, label] = POOL_STATUS[pool.status];
                return (
                  <TableRow key={pool.id}>
                    <TableCell className="font-medium">{pool.name}<span className="block text-xs text-zinc-500">{pool.segment}</span></TableCell>
                    <TableCell><StatusBadge tone={tone}>{label}</StatusBadge></TableCell>
                    <TableCell>{pool.enrollments} of {pool.max_enrollments}</TableCell>
                    <TableCell className="text-zinc-600 dark:text-zinc-400">{formatDateTime(pool.expires_at)}</TableCell>
                    <TableCell className="text-zinc-600 dark:text-zinc-400 max-w-[260px] truncate" title={pool.nodes.map((n) => n.name).join(", ")}>
                      {pool.nodes.map((n) => n.name).join(", ") || "—"}
                    </TableCell>
                    <TableCell>
                      {pool.status !== "revoked" && (
                        <Button variant="ghost" size="icon" className="cursor-pointer" aria-label={`Revoke ${pool.name}`} onClick={() => setRevoking(pool)}>
                          <Ban className="h-4 w-4" />
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
      <ConfirmDialog
        open={!!revoking}
        onOpenChange={(v) => !v && setRevoking(null)}
        title="Revoke this agent pool token?"
        description={revoking ? `No new node can enroll with ${revoking.name}. The ${revoking.enrollments} node(s) that enrolled keep working; delete them in the node list to stop them.` : ""}
        confirmLabel="Revoke"
        destructive
        pending={revoke.isPending}
        onConfirm={() => revoking && revoke.mutate(revoking)}
      />
    </SectionCard>
  );
}
