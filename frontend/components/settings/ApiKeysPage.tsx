"use client";

// Settings > API keys (issue #226): team-scoped CBOM API keys for scripted onboarding. Admins create a named key with
// scopes and an optional expiry (the secret is shown once, in a dialog, and never again) and revoke keys; members
// see the list. The list never holds a secret or a hash: the key's prefix and last four characters only.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, KeyRound, Loader2, Plus } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import {
  Checkbox2,
  ConfirmDialog,
  CopyButton,
  EmptyState,
  ErrorBlock,
  Field,
  LoadingBlock,
  SectionCard,
  StatusBadge,
  type Tone,
} from "@/components/cbom/sources/shared";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  cbomApiKeyKeys,
  createCbomApiKey,
  createFormProblem,
  EXPIRY_CHOICES,
  listCbomApiKeys,
  maskedKey,
  revokeCbomApiKey,
  statusLabel,
  type CbomApiKey,
  type CbomApiKeyScope,
} from "@/utils/api/cbom_api_keys";
import { formatDateIst } from "@/utils/datetime";
import { showErrorToast } from "@/utils/error-handler";
import { toast } from "@/utils/toast";

const TONE: Record<CbomApiKey["status"], Tone> = { active: "green", expired: "amber", revoked: "zinc" };

function when(value: string | null): string {
  return value ? formatDateIst(value) : "—";
}

function CreateKeyForm({ teamId, scopes, onCreated }: {
  teamId: number;
  scopes: { name: CbomApiKeyScope; description: string }[];
  onCreated: (secret: string, key: CbomApiKey) => void;
}) {
  const [name, setName] = useState("");
  const [chosen, setChosen] = useState<CbomApiKeyScope[]>([]);
  const [expiry, setExpiry] = useState("90");
  const [touched, setTouched] = useState(false);
  const problem = createFormProblem(name, chosen);
  const create = useMutation({
    mutationFn: () => createCbomApiKey(teamId, {
      name: name.trim(),
      scopes: chosen,
      expires_in_days: EXPIRY_CHOICES.find((c) => c.value === expiry)?.days ?? null,
    }),
    onSuccess: (data) => {
      setName("");
      setChosen([]);
      setTouched(false);
      onCreated(data.secret, data.api_key);
    },
    onError: (error) => showErrorToast(error, "Could not create the API key"),
  });

  return (
    <form
      className="grid gap-4 md:grid-cols-2"
      onSubmit={(e) => {
        e.preventDefault();
        setTouched(true);
        if (!problem) create.mutate();
      }}
      data-testid="api-key-create-form"
    >
      <Field label="Name" htmlFor="api-key-name" required hint="What uses it, e.g. cmdb-nightly or terraform-prod"
             error={touched && problem && !name.trim() ? problem : null}>
        <Input id="api-key-name" value={name} maxLength={64} onChange={(e) => setName(e.target.value)}
               placeholder="cmdb-nightly" autoComplete="off" />
      </Field>
      <Field label="Expires" htmlFor="api-key-expiry" hint="Rotate keys regularly; a key can also be revoked at any time">
        <Select value={expiry} onValueChange={setExpiry}>
          <SelectTrigger id="api-key-expiry" className="w-full cursor-pointer"><SelectValue /></SelectTrigger>
          <SelectContent>
            {EXPIRY_CHOICES.map((c) => (
              <SelectItem key={c.value} value={c.value} className="cursor-pointer">{c.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </Field>
      <fieldset className="md:col-span-2 space-y-2">
        <legend className="text-sm font-medium mb-1">Scopes<span className="text-red-500">*</span></legend>
        {scopes.map((s) => (
          <Checkbox2 key={s.name} id={`api-key-scope-${s.name}`} checked={chosen.includes(s.name)}
                     onChange={(v) => setChosen((cur) => (v ? [...cur, s.name] : cur.filter((x) => x !== s.name)))}>
            <span className="font-mono text-xs">{s.name}</span>
            <span className="block text-xs text-zinc-500">{s.description}</span>
          </Checkbox2>
        ))}
      </fieldset>
      {touched && problem && name.trim() && (
        <p className="md:col-span-2 text-sm text-red-500" role="alert">{problem}</p>
      )}
      <div className="md:col-span-2">
        <Button type="submit" className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white" disabled={create.isPending}
                data-testid="api-key-create">
          {create.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
          Create API key
        </Button>
      </div>
    </form>
  );
}

function SecretDialog({ secret, keyName, onClose }: { secret: string | null; keyName: string; onClose: () => void }) {
  return (
    <Dialog open={secret !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent onInteractOutside={(e) => e.preventDefault()}>
        <DialogHeader>
          <DialogTitle>Copy the key &ldquo;{keyName}&rdquo; now</DialogTitle>
          <DialogDescription>
            This is the only time the key is shown. Only its hash is stored, so it cannot be shown again. Put it in
            your secret store; if you lose it, revoke it and create a new one.
          </DialogDescription>
        </DialogHeader>
        <div className="flex items-center gap-2">
          <code className="flex-1 break-all rounded bg-zinc-100 dark:bg-zinc-900 px-3 py-2 text-xs" data-testid="api-key-secret">
            {secret}
          </code>
          {secret && <CopyButton text={secret} />}
        </div>
        <p className="text-xs text-zinc-500">
          Use it as <span className="font-mono">Authorization: Bearer &lt;key&gt;</span> on the CBOM Sources, runs and
          export routes. See the guide <span className="font-mono">docs/cbom/api-keys.md</span>.
        </p>
        <DialogFooter>
          <Button className="cursor-pointer" onClick={onClose} data-testid="api-key-secret-done">I have copied the key</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function ApiKeysPage({ teamId }: { teamId: number }) {
  const queryClient = useQueryClient();
  const keys = useQuery({ queryKey: cbomApiKeyKeys.list(teamId), queryFn: () => listCbomApiKeys(teamId) });
  const [secret, setSecret] = useState<{ value: string; name: string } | null>(null);
  const [revoking, setRevoking] = useState<CbomApiKey | null>(null);
  const revoke = useMutation({
    mutationFn: (key: CbomApiKey) => revokeCbomApiKey(teamId, key.id),
    onSuccess: (key) => {
      toast.success(`Revoked ${key.name}`);
      setRevoking(null);
      queryClient.invalidateQueries({ queryKey: cbomApiKeyKeys.list(teamId) });
    },
    onError: (error) => showErrorToast(error, "Could not revoke the API key"),
  });

  const data = keys.data;
  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-6" data-testid="api-keys-page">
      <div className="flex items-center gap-3">
        <Link href={`/${teamId}/settings`} className="inline-flex items-center text-sm text-blue-600 hover:underline">
          <ArrowLeft className="h-4 w-4 mr-1" /> Settings
        </Link>
      </div>
      <div>
        <h1 className="text-2xl font-semibold flex items-center gap-2"><KeyRound className="h-6 w-6" /> API keys</h1>
        <p className="text-sm text-muted-foreground mt-1 max-w-3xl">
          Keys let scripts (Terraform, a CMDB sync, CI) add CBOM sources, start runs and download CBOMs without
          signing in. A key works only for this team, only within its scopes, and never for account, team, billing or
          key settings. A key acts as the admin who created it and stops working if they stop being an admin. Every
          use is rate-limited and recorded in the CBOM audit log.
        </p>
      </div>

      {keys.isLoading && <LoadingBlock />}
      {keys.isError && <ErrorBlock error={keys.error} onRetry={() => keys.refetch()} />}
      {data && (
        <>
          {data.can_manage ? (
            <SectionCard title="Create a key" description="The key is shown once, right after you create it.">
              <CreateKeyForm teamId={teamId} scopes={data.scopes} onCreated={(value, key) => {
                setSecret({ value, name: key.name });
                queryClient.invalidateQueries({ queryKey: cbomApiKeyKeys.list(teamId) });
              }} />
            </SectionCard>
          ) : (
            <p className="text-sm text-amber-600 dark:text-amber-400" role="status">
              Only a team admin can create or revoke API keys.
            </p>
          )}

          <SectionCard title="Keys" description={`${data.api_keys.filter((k) => k.status === "active").length} active`}>
            {data.api_keys.length === 0 ? (
              <EmptyState title="No API keys yet" body="Create one to script CBOM onboarding." />
            ) : (
              <div className="overflow-x-auto">
                <Table data-testid="api-keys-table">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Key</TableHead>
                      <TableHead>Scopes</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead>Expires</TableHead>
                      <TableHead>Last used</TableHead>
                      {data.can_manage && <TableHead className="text-right">Actions</TableHead>}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.api_keys.map((k) => (
                      <TableRow key={k.id} data-testid={`api-key-row-${k.id}`}>
                        <TableCell className="font-medium">{k.name}</TableCell>
                        <TableCell className="font-mono text-xs">{maskedKey(data.prefix, k.hint)}</TableCell>
                        <TableCell className="font-mono text-xs">{k.scopes.join(", ")}</TableCell>
                        <TableCell><StatusBadge tone={TONE[k.status]}>{statusLabel(k)}</StatusBadge></TableCell>
                        <TableCell className="text-xs">
                          {when(k.created_at)}
                          {k.created_by && <span className="block text-zinc-500">{k.created_by}</span>}
                        </TableCell>
                        <TableCell className="text-xs">{k.status === "revoked" ? `Revoked ${when(k.revoked_at)}` : when(k.expires_at)}</TableCell>
                        <TableCell className="text-xs">{k.last_used_at ? when(k.last_used_at) : "Never"}</TableCell>
                        {data.can_manage && (
                          <TableCell className="text-right">
                            {k.status !== "revoked" && (
                              <Button variant="outline" size="sm" className="cursor-pointer text-red-600"
                                      onClick={() => setRevoking(k)} data-testid={`api-key-revoke-${k.id}`}>
                                Revoke
                              </Button>
                            )}
                          </TableCell>
                        )}
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </SectionCard>
        </>
      )}

      <SecretDialog secret={secret?.value ?? null} keyName={secret?.name ?? ""} onClose={() => setSecret(null)} />
      <ConfirmDialog
        open={revoking !== null}
        onOpenChange={(open) => !open && setRevoking(null)}
        title={`Revoke ${revoking?.name ?? "this key"}?`}
        description="Scripts using this key are refused from their next request. This cannot be undone."
        confirmLabel="Revoke key"
        destructive
        pending={revoke.isPending}
        onConfirm={() => revoking && revoke.mutate(revoking)}
      />
    </div>
  );
}
