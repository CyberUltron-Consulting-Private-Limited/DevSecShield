"use client";

// Container images (CBOM Sources > Clusters & databases): the scan node pulls images from a registry (Distribution
// API v2, HTTPS only) and inventories the crypto packages in their package databases, with package URLs. Kind
// "container_images" in backend/utilities/cbom_sources/kinds.py; collector
// scan_node/zs_scan_node/collectors/container_images.py. Registry credentials are anonymous or a vault reference
// resolved on the node: ZeroShield never stores a registry password. Charged 1 credit per image per run.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CirclePlay, Loader2, Plus, Trash2 } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import {
  createCbomSource,
  deleteCbomSource,
  listCbomSources,
  testCbomSource,
  type CbomScanNode,
  type CbomSource,
} from "@/utils/backend_api";

import { cbomSourcesKeys } from "./keys";
import { ConfirmDialog, EmptyState, Field, NodeSelect, SectionCard, TestStatusBadge, Truncate } from "./shared";

// registry/repository:tag or @sha256:digest (same grammar as the API and the node)
const IMAGE_RE = /^(?:(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?::\d{1,5})?|localhost(?::\d{1,5})?|[A-Za-z0-9-]+:\d{1,5})\/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:\/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[0-9a-f]{64})?$/;

function lines(text: string): string[] {
  return text.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
}

export default function ContainerImagesSection({ teamId, nodes, isAdmin }: { teamId: number; nodes: CbomScanNode[]; isAdmin: boolean }) {
  const queryClient = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [deleting, setDeleting] = useState<CbomSource | null>(null);
  const query = useQuery({
    queryKey: cbomSourcesKeys.sources(teamId, "kubernetes"),
    queryFn: () => listCbomSources(teamId, "kubernetes"),
    retry: 1,
    refetchInterval: (q) => (q.state.data?.sources.some((s) => s.last_test_status === "pending") ? 6000 : 30000),
  });
  const rows = (query.data?.sources ?? []).filter((s) => s.kind === "container_images");
  const agentless = nodes.filter((n) => n.mode !== "agent");
  const invalidate = () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });
  const test = useMutation({ mutationFn: (id: number) => testCbomSource(teamId, id), onSettled: invalidate });
  const remove = useMutation({ mutationFn: (id: number) => deleteCbomSource(teamId, id), onSettled: invalidate, onSuccess: () => setDeleting(null) });

  return (
    <SectionCard
      title="Container images"
      description="The scan node pulls images from your registry over HTTPS (manifests and layers, verified by digest, never written to disk) and lists the crypto packages in them with package URLs. 1 credit per image per run."
      actions={
        !adding && (
          <Button variant="outline" size="sm" className="cursor-pointer" onClick={() => setAdding(true)} data-testid="images-add">
            <Plus className="h-4 w-4 mr-2" />
            Add images
          </Button>
        )
      }
    >
      <div className="space-y-4">
        {adding && <ImagesForm teamId={teamId} nodes={agentless} isAdmin={isAdmin} onDone={() => setAdding(false)} onSaved={invalidate} />}
        {rows.length === 0 && !adding ? (
          <EmptyState title="No container images yet" body="Add the images your clusters run (registry/repository:tag) to inventory OpenSSL, GnuTLS and other crypto packages inside them." />
        ) : (
          rows.length > 0 && (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Images</TableHead>
                    <TableHead>Credentials</TableHead>
                    <TableHead>Node</TableHead>
                    <TableHead>Test</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((s) => (
                    <TableRow key={s.id} data-testid={`images-row-${s.id}`}>
                      <TableCell className="font-medium">{s.name}</TableCell>
                      <TableCell className="font-mono text-xs max-w-[300px]"><Truncate text={(s.config?.images ?? []).join(", ")} /></TableCell>
                      <TableCell>{s.config?.credential_type === "vault" ? `Vault: ${s.config?.vault?.path ?? ""}` : "Anonymous"}</TableCell>
                      <TableCell>{s.node_name ?? "—"}</TableCell>
                      <TableCell><TestStatusBadge status={s.last_test_status} title={s.last_test_summary} /></TableCell>
                      <TableCell className="text-right whitespace-nowrap">
                        <Button variant="ghost" size="sm" className="cursor-pointer" title="Read the manifests from the scan node"
                          disabled={test.isPending} onClick={() => test.mutate(s.id)}>
                          <CirclePlay className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="sm" className="cursor-pointer text-red-600" title="Delete" onClick={() => setDeleting(s)}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )
        )}
      </div>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Delete these images?"
        description={`${deleting?.name ?? ""} is removed. Collected results stay in past runs.`}
        confirmLabel="Delete"
        destructive
        pending={remove.isPending}
        onConfirm={() => deleting && remove.mutate(deleting.id)}
      />
    </SectionCard>
  );
}

function ImagesForm({ teamId, nodes, isAdmin, onDone, onSaved }: {
  teamId: number;
  nodes: CbomScanNode[];
  isAdmin: boolean;
  onDone: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState("");
  const [images, setImages] = useState("");
  const [cred, setCred] = useState<"anonymous" | "vault">("anonymous");
  const [vaultProvider, setVaultProvider] = useState<"hashicorp" | "aws_secrets_manager">("hashicorp");
  const [vaultPath, setVaultPath] = useState("");
  const [caPem, setCaPem] = useState("");
  const [maxMb, setMaxMb] = useState("2048");
  const [nodeId, setNodeId] = useState<number | null>(nodes.length === 1 ? nodes[0].id : null);
  const [errors, setErrors] = useState<Record<string, string | null>>({});

  const save = useMutation({
    mutationFn: ({ test }: { test: boolean }) =>
      createCbomSource(teamId, {
        kind: "container_images",
        name: name.trim(),
        node_id: nodeId ?? undefined,
        config: {
          images: lines(images),
          credential_type: cred,
          vault: cred === "vault" ? { provider: vaultProvider, path: vaultPath.trim() } : null,
          ca_pem: caPem.trim() || null,
          max_image_mb: Number(maxMb),
        },
        secrets: {},
        test_after_save: test,
      }),
    onSuccess: onDone,
    onSettled: onSaved,
  });

  const submit = (test: boolean) => {
    const refs = lines(images);
    const mb = Number(maxMb);
    const next: Record<string, string | null> = {
      name: /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/.test(name.trim()) ? null : "Use letters, digits, spaces, . _ - (64 at most)",
      images: refs.length === 0 ? "Enter at least one image" : refs.length > 50 ? "At most 50 images per source"
        : refs.find((r) => !IMAGE_RE.test(r)) ? `Not an image reference: ${refs.find((r) => !IMAGE_RE.test(r))}` : null,
      vault: cred === "vault" && !vaultPath.trim() ? "Enter the secret path (keys username and password, or token)" : null,
      maxMb: Number.isInteger(mb) && mb >= 1 && mb <= 8192 ? null : "1 to 8192 MB",
      node: nodeId ? null : "Choose the scan node that reaches the registry",
    };
    setErrors(next);
    if (Object.values(next).some(Boolean)) return;
    save.mutate({ test });
  };

  return (
    <div className="space-y-4 rounded-lg border border-zinc-200 dark:border-zinc-800 p-4" data-testid="images-form">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Field label="Name" htmlFor="images-name" required error={errors.name}>
          <Input id="images-name" value={name} maxLength={64} onChange={(e) => setName(e.target.value)} placeholder="Payments images" />
        </Field>
        <Field label="Scan node" htmlFor="images-node" required error={errors.node} hint="An agentless node that reaches the registry">
          <NodeSelect id="images-node" nodes={nodes} value={nodeId} onChange={setNodeId} />
        </Field>
        <Field label="Images" htmlFor="images-refs" required error={errors.images} hint="One per line: registry/repository:tag or @sha256:digest (Docker Hub when no registry is named)">
          <Textarea id="images-refs" className="font-mono text-sm min-h-[88px]" value={images} spellCheck={false}
            onChange={(e) => setImages(e.target.value)} placeholder={"harbor.corp.example/payments/api:2.4.1\nghcr.io/org/worker@sha256:..."} />
        </Field>
        <div className="space-y-4">
          <Field label="Registry credentials" htmlFor="images-cred"
            hint={cred === "vault"
              ? "Read on the scan node (ZS_VAULT_PATH_PREFIX). Sent only to the registry's own host, or to the token service of Docker Hub (auth.docker.io) or GitLab.com (gitlab.com). A token service on any other host gets an anonymous request, so a private image there is not read (for example a self-managed GitLab whose registry has its own host name)"
              : "Public or anonymous pulls"}>
            <Select value={cred} onValueChange={(v) => setCred(v as "anonymous" | "vault")}>
              <SelectTrigger id="images-cred" className="w-full cursor-pointer"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="anonymous" className="cursor-pointer">Anonymous</SelectItem>
                <SelectItem value="vault" className="cursor-pointer" disabled={!isAdmin}>From a vault (team admins)</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          {cred === "vault" && (
            <div className="grid grid-cols-2 gap-4">
              <Field label="Vault" htmlFor="images-vault-provider">
                <Select value={vaultProvider} onValueChange={(v) => setVaultProvider(v as "hashicorp" | "aws_secrets_manager")}>
                  <SelectTrigger id="images-vault-provider" className="w-full cursor-pointer"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="hashicorp" className="cursor-pointer">HashiCorp Vault</SelectItem>
                    <SelectItem value="aws_secrets_manager" className="cursor-pointer">AWS Secrets Manager</SelectItem>
                  </SelectContent>
                </Select>
              </Field>
              <Field label="Secret path" htmlFor="images-vault-path" error={errors.vault}>
                <Input id="images-vault-path" value={vaultPath} maxLength={512} onChange={(e) => setVaultPath(e.target.value)} placeholder="secret/zs/registry" />
              </Field>
            </div>
          )}
          <Field label="Largest image (MB, compressed)" htmlFor="images-max" error={errors.maxMb} hint="Bigger images are reported as not read">
            <Input id="images-max" inputMode="numeric" value={maxMb} onChange={(e) => setMaxMb(e.target.value.replace(/\D/g, "").slice(0, 4))} />
          </Field>
        </div>
        <Field label="Registry CA certificate (PEM)" htmlFor="images-ca" hint="Only for a registry with a private CA; the registry's certificate is always verified">
          <Textarea id="images-ca" className="font-mono text-xs min-h-[72px]" value={caPem} spellCheck={false} onChange={(e) => setCaPem(e.target.value)} />
        </Field>
      </div>
      <div className="flex flex-wrap justify-end gap-2">
        <Button variant="outline" className="cursor-pointer" onClick={onDone} disabled={save.isPending}>Cancel</Button>
        <Button variant="outline" className="cursor-pointer" disabled={save.isPending} onClick={() => submit(false)}>
          {save.isPending && save.variables?.test === false && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
          Save
        </Button>
        <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={save.isPending} onClick={() => submit(true)}>
          {save.isPending && save.variables?.test === true && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
          Save and test
        </Button>
      </div>
      {save.isError && <p className="text-sm text-red-600">Not saved: {(save.error as Error)?.message || "try again"}</p>}
    </div>
  );
}
