"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Circle, KeyRound, Loader2, MoreVertical, Pencil, Plus, RotateCcw, Server, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  createCbomScanNode,
  deleteCbomScanNode,
  listCbomScanNodes,
  newCbomNodeRegistration,
  updateCbomScanNode,
  type CbomScanNode,
} from "@/utils/backend_api";
import { apiBaseURL } from "@/utils/interceptors";

import { cbomSourcesKeys } from "./keys";
import { ago, installCommand, readTextFile, type DeployMethod } from "./logic";
import {
  Checkbox2,
  ChoiceCards,
  CodeSnippet,
  ConfirmDialog,
  CopyButton,
  EmptyState,
  ErrorBlock,
  Field,
  LoadingBlock,
  NodeStatusBadge,
  SectionCard,
  StatCard,
  Truncate,
} from "./shared";

const NODE_IMAGE = process.env.NEXT_PUBLIC_CBOM_NODE_IMAGE || "registry.zeroshield.ai/cbom/scan-node:1.0";
const SEGMENTS = ["Data centre", "DMZ", "Branch office", "OT / plant", "Cloud VPC"];
const TIMEZONES = ["Asia/Kolkata", "UTC", "Asia/Dubai", "Asia/Singapore", "Europe/London", "America/New_York"];
const DEPLOY_OPTIONS: { value: DeployMethod; title: string; description: string }[] = [
  { value: "docker", title: "Docker container", description: "Any Linux VM with Docker" },
  { value: "ova", title: "OVA appliance", description: "VMware or Hyper-V" },
  { value: "ami", title: "AWS AMI", description: "Launch in your VPC" },
  { value: "helm", title: "Helm chart", description: "Runs in your Kubernetes cluster" },
];
const DEPLOY_LABEL: Record<string, string> = { docker: "Docker", ova: "OVA appliance", ami: "AWS AMI", helm: "Helm chart" };
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;

interface WizardState {
  name: string;
  segment: string;
  timezone: string;
  deployment: DeployMethod;
  proxyUrl: string;
  proxyCa: string;
  proxyCaName: string;
  tlsInspect: boolean;
}
const EMPTY_WIZARD: WizardState = {
  name: "",
  segment: "Data centre",
  timezone: "Asia/Kolkata",
  deployment: "docker",
  proxyUrl: "",
  proxyCa: "",
  proxyCaName: "",
  tlsInspect: false,
};

function apiHost(): string {
  try {
    return new URL(apiBaseURL).hostname;
  } catch {
    return apiBaseURL;
  }
}

function apiPort(): string {
  try {
    const url = new URL(apiBaseURL);
    return url.port || (url.protocol === "http:" ? "80" : "443");
  } catch {
    return "443";
  }
}

function expiresIn(iso: string | null, serverNow: string | null | undefined): string {
  if (!iso) return "";
  const ms = Date.parse(iso) - (serverNow ? Date.parse(serverNow) : Date.now());
  if (ms <= 0) return "expired";
  const h = Math.floor(ms / 3_600_000);
  const m = Math.floor((ms % 3_600_000) / 60_000);
  return `${h} h ${m} min`;
}

export default function ScanNodesTab({ teamId, onNavigate }: { teamId: number; onNavigate: (tab: string) => void }) {
  const queryClient = useQueryClient();
  const [wizardOpen, setWizardOpen] = useState(false);
  const [wizard, setWizard] = useState<WizardState>(EMPTY_WIZARD);
  const [wizardError, setWizardError] = useState<string | null>(null);
  const [created, setCreated] = useState<{ nodeId: number; token: string } | null>(null);
  const [editing, setEditing] = useState<CbomScanNode | null>(null);
  const [deleting, setDeleting] = useState<CbomScanNode | null>(null);
  const [resetting, setResetting] = useState<CbomScanNode | null>(null);

  const nodesQuery = useQuery({
    queryKey: cbomSourcesKeys.nodes(teamId),
    queryFn: () => listCbomScanNodes(teamId),
    enabled: Number.isFinite(teamId),
    retry: 1,
    // Faster while a new node is waiting to register, so the checklist ticks itself off.
    refetchInterval: (query) => {
      if (!created) return 30000;
      const fresh = query.state.data?.nodes.find((n) => n.id === created.nodeId);
      return fresh?.status === "online" && fresh.clock_in_sync !== null ? 30000 : 5000;
    },
  });
  const nodes = useMemo(() => nodesQuery.data?.nodes ?? [], [nodesQuery.data]);
  const serverNow = nodesQuery.data?.server_time;
  const createdNode = created ? nodes.find((n) => n.id === created.nodeId) ?? null : null;

  const invalidate = () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });

  const createMutation = useMutation({
    mutationFn: () =>
      createCbomScanNode(teamId, {
        name: wizard.name.trim(),
        segment: wizard.segment.trim(),
        timezone: wizard.timezone,
        deployment: wizard.deployment,
        proxy_url: wizard.proxyUrl.trim() || null,
        proxy_ca_pem: wizard.proxyCa || null,
        proxy_tls_inspect: wizard.tlsInspect,
      }),
    onSuccess: (data) => setCreated({ nodeId: data.node.id, token: data.registration_token }),
    onSettled: invalidate,
  });

  const tokenMutation = useMutation({
    mutationFn: ({ node, reset }: { node: CbomScanNode; reset: boolean }) => newCbomNodeRegistration(teamId, node.id, reset),
    onSuccess: (data) => {
      setCreated({ nodeId: data.node.id, token: data.registration_token });
      setWizard((w) => ({ ...w, deployment: data.node.deployment, proxyUrl: data.node.proxy_url ?? "" }));
      setWizardOpen(true);
      setResetting(null);
    },
    onSettled: invalidate,
  });

  const deleteMutation = useMutation({
    mutationFn: (node: CbomScanNode) => deleteCbomScanNode(teamId, node.id),
    onSuccess: () => setDeleting(null),
    onSettled: invalidate,
  });

  const startWizard = () => {
    setWizard(EMPTY_WIZARD);
    setWizardError(null);
    setCreated(null);
    setWizardOpen(true);
  };

  const submitWizard = () => {
    if (!NAME_RE.test(wizard.name.trim())) {
      setWizardError("Use 1-64 letters, digits, spaces, dots, dashes or underscores, starting with a letter or digit.");
      return;
    }
    setWizardError(null);
    createMutation.mutate();
  };

  const online = nodes.filter((n) => n.status === "online").length;
  const offline = nodes.filter((n) => n.status === "offline").length;
  const assigned = nodes.reduce((sum, n) => sum + (n.assigned_targets || 0), 0);

  if (nodesQuery.isLoading) return <LoadingBlock />;
  if (nodesQuery.isError && !nodesQuery.data) return <ErrorBlock onRetry={() => nodesQuery.refetch()} />;

  const command = created
    ? installCommand(createdNode?.deployment ?? wizard.deployment, {
        token: created.token,
        apiUrl: apiBaseURL,
        proxyUrl: createdNode?.proxy_url ?? (wizard.proxyUrl.trim() || null),
        image: NODE_IMAGE,
        name: createdNode?.name ?? wizard.name,
      })
    : "";

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Scan nodes" value={nodes.length} />
        <StatCard label="Online" value={online} tone={online ? "green" : undefined} />
        <StatCard label="Offline" value={offline} tone={offline ? "red" : undefined} />
        <StatCard label="Targets assigned" value={assigned.toLocaleString()} hint="Servers and addresses routed through these nodes" />
      </div>

      <SectionCard
        title="Registered scan nodes"
        description={`One node per network segment. Each connects out to ZeroShield on port ${apiPort()} only.`}
        actions={
          <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={startWizard}>
            <Plus className="h-4 w-4 mr-2" />
            Add scan node
          </Button>
        }
      >
        {nodes.length === 0 ? (
          <EmptyState
            title="No scan nodes yet"
            body="A scan node is a small appliance you run inside the network segment you want scanned. It reaches your servers, clusters and TLS endpoints and only ever connects out to ZeroShield."
            action={
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={startWizard}>
                <Plus className="h-4 w-4 mr-2" />
                Add your first scan node
              </Button>
            }
          />
        ) : (
          <ScrollArea className="w-full border rounded-lg">
            <div className="min-w-max">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Node</TableHead>
                    <TableHead>Segment</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Runs as</TableHead>
                    <TableHead>Version</TableHead>
                    <TableHead>Last seen</TableHead>
                    <TableHead className="text-right">Targets</TableHead>
                    <TableHead className="w-12">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {nodes.map((node) => (
                    <TableRow key={node.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800">
                      <TableCell className="font-medium text-zinc-900 dark:text-white max-w-[220px]">
                        <Truncate text={node.name} />
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400 max-w-[160px]">
                        <Truncate text={node.segment || "—"} />
                      </TableCell>
                      <TableCell>
                        <NodeStatusBadge status={node.status} />
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">{DEPLOY_LABEL[node.deployment] ?? node.deployment}</TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">{node.node_version ?? "—"}</TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">{ago(node.last_heartbeat_at, serverNow)}</TableCell>
                      <TableCell className="text-right text-zinc-600 dark:text-zinc-400">{node.assigned_targets.toLocaleString()}</TableCell>
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" className="cursor-pointer" aria-label={`Actions for ${node.name}`}>
                              <MoreVertical className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem className="cursor-pointer" onSelect={() => setEditing(node)}>
                              <Pencil className="h-4 w-4" />
                              Details and edit
                            </DropdownMenuItem>
                            {node.status === "pending_registration" || node.status === "registration_expired" ? (
                              <DropdownMenuItem className="cursor-pointer" onSelect={() => tokenMutation.mutate({ node, reset: false })}>
                                <KeyRound className="h-4 w-4" />
                                New registration token
                              </DropdownMenuItem>
                            ) : (
                              <DropdownMenuItem className="cursor-pointer" onSelect={() => setResetting(node)}>
                                <RotateCcw className="h-4 w-4" />
                                Reset and register again
                              </DropdownMenuItem>
                            )}
                            <DropdownMenuSeparator />
                            <DropdownMenuItem variant="destructive" className="cursor-pointer" onSelect={() => setDeleting(node)}>
                              <Trash2 className="h-4 w-4" />
                              Delete
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <ScrollBar orientation="horizontal" />
          </ScrollArea>
        )}
      </SectionCard>

      {wizardOpen && (
        <SectionCard
          title="Add a scan node"
          description="Run it on any VM or cluster inside the segment you want to scan."
          actions={
            <Button variant="outline" className="cursor-pointer" onClick={() => { setWizardOpen(false); setCreated(null); }}>
              {created ? "Done" : "Cancel"}
            </Button>
          }
        >
          <ol className="space-y-8">
            <li>
              <StepTitle n={1} title="Name and segment" />
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Field label="Node name" htmlFor="node-name" required error={wizardError}>
                  <Input id="node-name" value={wizard.name} disabled={!!created} maxLength={64} placeholder="dc-mumbai-01"
                    onChange={(e) => setWizard({ ...wizard, name: e.target.value })} />
                </Field>
                <Field label="Network segment" htmlFor="node-segment" hint="Pick one or type your own">
                  <Input id="node-segment" list="cbom-segments" value={wizard.segment} disabled={!!created} maxLength={64}
                    onChange={(e) => setWizard({ ...wizard, segment: e.target.value })} />
                  <datalist id="cbom-segments">{SEGMENTS.map((s) => <option key={s} value={s} />)}</datalist>
                </Field>
                <Field label="Time zone" htmlFor="node-tz">
                  <Select value={wizard.timezone} disabled={!!created} onValueChange={(v) => setWizard({ ...wizard, timezone: v })}>
                    <SelectTrigger id="node-tz" className="w-full cursor-pointer"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {TIMEZONES.map((tz) => <SelectItem key={tz} value={tz} className="cursor-pointer">{tz}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </Field>
              </div>
            </li>

            <li>
              <StepTitle n={2} title="Choose how to run it" />
              <ChoiceCards name="node-deploy" label="Deployment" columns={4} value={wizard.deployment}
                onChange={(v) => setWizard({ ...wizard, deployment: v })}
                options={DEPLOY_OPTIONS.map((o) => ({ ...o, disabled: !!created && o.value !== wizard.deployment }))} />
              {created && (
                <div className="mt-4 space-y-2">
                  <CodeSnippet code={command} language={wizard.deployment === "ami" ? "yaml" : "bash"} />
                  <p className="text-xs text-zinc-500">
                    The registration token works once and expires in {expiresIn(createdNode?.registration_expires_at ?? null, serverNow) || "24 h"}.
                    It is shown only here; if you refresh this page, use <span className="font-medium">New registration token</span>.
                  </p>
                  {createdNode && createdNode.status !== "online" && createdNode.status !== "offline" && (
                    <Button variant="outline" size="sm" className="cursor-pointer" disabled={tokenMutation.isPending}
                      onClick={() => tokenMutation.mutate({ node: createdNode, reset: false })}>
                      {tokenMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <KeyRound className="h-4 w-4 mr-2" />}
                      Regenerate token
                    </Button>
                  )}
                </div>
              )}
            </li>

            <li>
              <StepTitle n={3} title="Allow outbound traffic from the node" />
              <div className="border rounded-lg overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow><TableHead>Destination</TableHead><TableHead>Port</TableHead><TableHead>Used for</TableHead></TableRow>
                  </TableHeader>
                  <TableBody>
                    <TableRow><TableCell className="font-mono text-xs">{apiHost()}</TableCell><TableCell>{apiPort()}</TableCell><TableCell className="text-zinc-600 dark:text-zinc-400">Jobs in, results out (HTTPS)</TableCell></TableRow>
                    <TableRow><TableCell>Your targets</TableCell><TableCell>22, 5986, 6443, database and TLS ports</TableCell><TableCell className="text-zinc-600 dark:text-zinc-400">Read-only collection</TableCell></TableRow>
                  </TableBody>
                </Table>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                <Field label="Proxy (optional)" htmlFor="node-proxy" hint="http://proxy.example.local:8080">
                  <Input id="node-proxy" value={wizard.proxyUrl} disabled={!!created} placeholder="http://proxy.bank.local:8080"
                    onChange={(e) => setWizard({ ...wizard, proxyUrl: e.target.value })} />
                </Field>
                <Field label="Proxy CA certificate" htmlFor="node-proxy-ca" hint={wizard.proxyCaName || "PEM file, only if your proxy inspects TLS"}>
                  <Input id="node-proxy-ca" type="file" accept=".pem,.crt,.cer" disabled={!!created} className="cursor-pointer"
                    onChange={async (e) => {
                      const file = e.target.files?.[0];
                      if (!file) return;
                      try {
                        const text = await readTextFile(file, 64 * 1024);
                        setWizard((w) => ({ ...w, proxyCa: text, proxyCaName: file.name }));
                        setWizardError(null);
                      } catch (err) {
                        setWizardError((err as Error).message);
                      }
                    }} />
                </Field>
              </div>
              <div className="mt-3">
                <Checkbox2 id="node-tls-inspect" checked={wizard.tlsInspect} onChange={(v) => !created && setWizard({ ...wizard, tlsInspect: v })}>
                  My proxy inspects TLS; trust its CA only for ZeroShield hostnames
                </Checkbox2>
              </div>
              {!created && (
                <div className="mt-6">
                  <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={createMutation.isPending} onClick={submitWizard}>
                    {createMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Server className="h-4 w-4 mr-2" />}
                    Create node and show install command
                  </Button>
                </div>
              )}
            </li>

            <li>
              <StepTitle n={4} title="Wait for the node to register" />
              {!created ? (
                <p className="text-sm text-zinc-500">Steps appear here after you create the node and start it.</p>
              ) : (
                <ul className="space-y-2 text-sm">
                  <CheckRow done={!!createdNode?.enrolled_at} label="Token accepted, node bound to this team" />
                  <CheckRow done={!!createdNode?.enrolled_at} label="Node credential issued" />
                  <CheckRow done={createdNode?.clock_in_sync === true} warn={createdNode?.clock_in_sync === false}
                    label={createdNode?.clock_in_sync === false ? `Clock is ${Math.abs(createdNode.clock_skew_s ?? 0)} s out of sync; fix NTP on the node` : "Clock in sync with ZeroShield"} />
                  <CheckRow done={false} pending={!!createdNode?.enrolled_at}
                    label="Reachability is checked on the first connection test of each source" />
                  {createdNode?.enrolled_at && (
                    <li className="pt-2">
                      <Button variant="outline" size="sm" className="cursor-pointer" onClick={() => onNavigate("servers")}>
                        Add servers to this node
                      </Button>
                    </li>
                  )}
                </ul>
              )}
            </li>
          </ol>
        </SectionCard>
      )}

      <SectionCard title="What the node does, and never does">
        <ul className="list-disc pl-5 space-y-1.5 text-sm text-zinc-700 dark:text-zinc-300">
          <li>Opens no inbound ports. It only connects out to {apiHost()} on port {apiPort()}.</li>
          <li>Secrets you enter are encrypted at rest by ZeroShield and sent only to the scan node that runs the job.</li>
          <li>Uses each credential only on the targets it was entered with; your never-scan list always wins.</li>
          <li>Reads with read-only accounts and the published command list shown on the Servers tab.</li>
          <li>Sends metadata only: algorithms, key sizes, versions and locations. For private keys, only the public half is read.</li>
        </ul>
        <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-4">
          Fully air-gapped network? Use the on-prem edition: the whole platform runs inside your data centre.
        </p>
      </SectionCard>

      {editing && (
        <NodeDialog key={editing.id} teamId={teamId} node={editing} serverNow={serverNow} onClose={() => setEditing(null)} onSaved={invalidate} />
      )}

      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(v) => !v && setDeleting(null)}
        title="Delete scan node?"
        description={deleting ? `${deleting.name} will stop receiving jobs. Sources that use it must be moved or deleted first.` : ""}
        confirmLabel="Delete"
        destructive
        pending={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting)}
      />
      <ConfirmDialog
        open={!!resetting}
        onOpenChange={(v) => !v && setResetting(null)}
        title="Reset this scan node?"
        description={resetting ? `${resetting.name} loses its credential immediately and stops receiving jobs until you register it again with a new token. Use this if the node was reinstalled or its credential may have leaked.` : ""}
        confirmLabel="Reset node"
        destructive
        pending={tokenMutation.isPending}
        onConfirm={() => resetting && tokenMutation.mutate({ node: resetting, reset: true })}
      />
    </div>
  );
}

function StepTitle({ n, title }: { n: number; title: string }) {
  return (
    <div className="flex items-center gap-3 mb-3">
      <span className="flex h-6 w-6 items-center justify-center rounded-full bg-blue-600 text-xs font-semibold text-white">{n}</span>
      <h3 className="font-medium text-zinc-900 dark:text-white">{title}</h3>
    </div>
  );
}

function CheckRow({ done, warn, pending, label }: { done: boolean; warn?: boolean; pending?: boolean; label: string }) {
  return (
    <li className="flex items-center gap-2">
      {done ? (
        <CheckCircle2 className="h-4 w-4 text-green-500" />
      ) : warn ? (
        <Circle className="h-4 w-4 text-amber-500" />
      ) : pending ? (
        <Circle className="h-4 w-4 text-zinc-400" />
      ) : (
        <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />
      )}
      <span className={done ? "text-zinc-900 dark:text-white" : "text-zinc-600 dark:text-zinc-400"}>{label}</span>
    </li>
  );
}

function NodeDialog({
  teamId,
  node,
  serverNow,
  onClose,
  onSaved,
}: {
  teamId: number;
  node: CbomScanNode;
  serverNow?: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  // Mounted with key={node.id}, so the form starts from the node's values without a sync effect.
  const [name, setName] = useState(node.name);
  const [segment, setSegment] = useState(node.segment);
  const [timezone, setTimezone] = useState(node.timezone);
  const [proxy, setProxy] = useState(node.proxy_url ?? "");
  const [error, setError] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: () =>
      updateCbomScanNode(teamId, node.id, {
        name: name.trim(),
        segment: segment.trim(),
        timezone,
        proxy_url: proxy.trim() || null,
        expected_version: node.row_version,
      }),
    onSuccess: onClose,
    onSettled: onSaved,
  });

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Scan node {node?.name}</DialogTitle>
          <DialogDescription>
            {node ? <>Status: <NodeStatusBadge status={node.status} /> · last seen {ago(node.last_heartbeat_at, serverNow)}</> : null}
          </DialogDescription>
        </DialogHeader>
        {node && (
          <div className="space-y-5 py-2">
            <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-sm">
              <Detail label="Host name" value={node.hostname} />
              <Detail label="Version" value={node.node_version} />
              <Detail label="Source IPs (tell your SOC)" value={node.source_ips.join(", ") || null} />
              <Detail label="Registered" value={node.enrolled_at ? ago(node.enrolled_at, serverNow) : "Not yet"} />
              <Detail label="Clock" value={node.clock_skew_s == null ? null : `${node.clock_skew_s > 0 ? "+" : ""}${node.clock_skew_s} s vs ZeroShield`} />
              <Detail label="Last job claimed" value={node.last_claim_at ? ago(node.last_claim_at, serverNow) : "Never"} />
              {node.last_node_error && <Detail label="Last error reported" value={node.last_node_error} wide />}
            </dl>
            {node.ssh_public_key && (
              <div className="space-y-2">
                <p className="text-sm font-medium">Node SSH public key</p>
                <div className="flex items-start gap-2">
                  <code className="flex-1 min-w-0 break-all rounded-md border bg-zinc-50 dark:bg-zinc-950 p-2 text-xs">{node.ssh_public_key}</code>
                  <CopyButton text={node.ssh_public_key} />
                </div>
              </div>
            )}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Field label="Node name" htmlFor="edit-node-name" required error={error}>
                <Input id="edit-node-name" value={name} maxLength={64} onChange={(e) => setName(e.target.value)} />
              </Field>
              <Field label="Network segment" htmlFor="edit-node-segment">
                <Input id="edit-node-segment" value={segment} maxLength={64} list="cbom-segments" onChange={(e) => setSegment(e.target.value)} />
              </Field>
              <Field label="Time zone" htmlFor="edit-node-tz">
                <Select value={timezone} onValueChange={setTimezone}>
                  <SelectTrigger id="edit-node-tz" className="w-full cursor-pointer"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {Array.from(new Set([timezone, ...TIMEZONES])).map((tz) => <SelectItem key={tz} value={tz} className="cursor-pointer">{tz}</SelectItem>)}
                  </SelectContent>
                </Select>
              </Field>
              <Field label="Proxy" htmlFor="edit-node-proxy">
                <Input id="edit-node-proxy" value={proxy} onChange={(e) => setProxy(e.target.value)} placeholder="http://proxy:8080" />
              </Field>
            </div>
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" className="cursor-pointer" onClick={onClose}>Cancel</Button>
          <Button
            className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            disabled={save.isPending}
            onClick={() => {
              if (!NAME_RE.test(name.trim())) {
                setError("Use 1-64 letters, digits, spaces, dots, dashes or underscores.");
                return;
              }
              save.mutate();
            }}
          >
            {save.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Detail({ label, value, wide }: { label: string; value: string | null | undefined; wide?: boolean }) {
  return (
    <div className={wide ? "sm:col-span-2" : undefined}>
      <dt className="text-zinc-500">{label}</dt>
      <dd className="text-zinc-900 dark:text-white break-words">{value || "—"}</dd>
    </div>
  );
}
