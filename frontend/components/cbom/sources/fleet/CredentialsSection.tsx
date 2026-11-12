"use client";

// Typed credentials that policies hand to the managed sources they create: the same login settings a Linux servers
// source has. Secrets are write-only: they are never shown again, and a blank field keeps the stored one.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "@/utils/toast";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import {
  createCbomCredential,
  deleteCbomCredential,
  listCbomCredentials,
  type CbomCredential,
  type CbomCredentialType,
} from "@/utils/api/cbom_fleet";

import { refusalReason } from "../logic";
import { ConfirmDialog, EmptyState, ErrorBlock, Field, LoadingBlock, SectionCard } from "../shared";
import { cbomFleetKeys } from "./keys";
import type { FleetSectionProps } from "./sections";

const TYPES: { value: CbomCredentialType; label: string }[] = [
  { value: "node_key", label: "Scan node key (no stored secret)" },
  { value: "password", label: "Password (needs pinned host keys)" },
  { value: "ssh_cert", label: "SSH certificate and key" },
  { value: "vault", label: "From a vault" },
];

function CredentialForm({ teamId, onDone }: { teamId: number; onDone: () => void }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [type, setType] = useState<CbomCredentialType>("node_key");
  const [login, setLogin] = useState("zs-cbom");
  const [port, setPort] = useState(22);
  const [pinned, setPinned] = useState(false);
  const [knownHosts, setKnownHosts] = useState("");
  const [password, setPassword] = useState("");
  const [cert, setCert] = useState("");
  const [key, setKey] = useState("");
  const [vaultProvider, setVaultProvider] = useState("hashicorp");
  const [vaultPath, setVaultPath] = useState("");
  const [error, setError] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: () => {
      const config: Record<string, unknown> = { login_user: login, port, host_key_policy: pinned || type === "password" ? "pinned" : "tofu" };
      if (pinned || type === "password") config.known_hosts = knownHosts;
      if (type === "vault") config.vault = { provider: vaultProvider, path: vaultPath };
      const secrets = type === "password" ? { password } : type === "ssh_cert" ? { ssh_certificate: cert, private_key: key } : undefined;
      return createCbomCredential(teamId, { name: name.trim(), credential_type: type, config, secrets });
    },
    onSuccess: () => {
      toast.success("Credential added");
      queryClient.invalidateQueries({ queryKey: cbomFleetKeys.credentials(teamId) });
      onDone();
    },
    onError: (err) => setError(refusalReason(err) ?? "Could not add the credential"),
  });
  return (
    <Dialog open onOpenChange={(v) => !v && onDone()}>
      <DialogContent className="sm:max-w-xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Add a credential</DialogTitle>
          <DialogDescription>Policies use it to log in to the hosts they collect. Secrets are encrypted and never shown again.</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <Field label="Name" htmlFor="cred-name" required>
            <Input id="cred-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="linux-fleet" />
          </Field>
          <Field label="Type" htmlFor="cred-type">
            <Select value={type} onValueChange={(v) => setType(v as CbomCredentialType)}>
              <SelectTrigger id="cred-type" className="cursor-pointer"><SelectValue /></SelectTrigger>
              <SelectContent>
                {TYPES.map((t) => <SelectItem key={t.value} value={t.value} className="cursor-pointer">{t.label}</SelectItem>)}
              </SelectContent>
            </Select>
          </Field>
          <div className="grid grid-cols-[1fr_100px] gap-3">
            <Field label="Login" htmlFor="cred-login"><Input id="cred-login" value={login} onChange={(e) => setLogin(e.target.value)} /></Field>
            <Field label="Port" htmlFor="cred-port"><Input id="cred-port" type="number" value={port} onChange={(e) => setPort(Number(e.target.value))} /></Field>
          </div>
          {type !== "password" && (
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={pinned} onChange={(e) => setPinned(e.target.checked)} />
              Pin host keys (otherwise trust on first use)
            </label>
          )}
          {(pinned || type === "password") && (
            <Field label="known_hosts lines" htmlFor="cred-known-hosts" required>
              <Textarea id="cred-known-hosts" rows={4} className="font-mono text-xs" value={knownHosts} onChange={(e) => setKnownHosts(e.target.value)} />
            </Field>
          )}
          {type === "password" && (
            <Field label="Password" htmlFor="cred-password" required>
              <Input id="cred-password" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </Field>
          )}
          {type === "ssh_cert" && (
            <>
              <Field label="SSH certificate" htmlFor="cred-cert" required>
                <Textarea id="cred-cert" rows={3} className="font-mono text-xs" value={cert} onChange={(e) => setCert(e.target.value)} />
              </Field>
              <Field label="Private key" htmlFor="cred-key" required>
                <Textarea id="cred-key" rows={4} className="font-mono text-xs" value={key} onChange={(e) => setKey(e.target.value)} />
              </Field>
            </>
          )}
          {type === "vault" && (
            <div className="grid grid-cols-[160px_1fr] gap-3">
              <Field label="Vault" htmlFor="cred-vault">
                <Select value={vaultProvider} onValueChange={setVaultProvider}>
                  <SelectTrigger id="cred-vault" className="cursor-pointer"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="hashicorp" className="cursor-pointer">HashiCorp</SelectItem>
                    <SelectItem value="cyberark" className="cursor-pointer">CyberArk</SelectItem>
                    <SelectItem value="aws_secrets_manager" className="cursor-pointer">AWS Secrets Manager</SelectItem>
                    <SelectItem value="azure_key_vault" className="cursor-pointer">Azure Key Vault</SelectItem>
                  </SelectContent>
                </Select>
              </Field>
              <Field label="Secret path" htmlFor="cred-vault-path"><Input id="cred-vault-path" value={vaultPath} onChange={(e) => setVaultPath(e.target.value)} /></Field>
            </div>
          )}
          {error && <p className="text-sm text-red-600 dark:text-red-400" role="alert">{error}</p>}
        </div>
        <DialogFooter>
          <Button className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white" disabled={!name.trim() || save.isPending} onClick={() => save.mutate()}>
            Add credential
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function CredentialsSection({ teamId }: FleetSectionProps) {
  const queryClient = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<CbomCredential | null>(null);
  const creds = useQuery({ queryKey: cbomFleetKeys.credentials(teamId), queryFn: () => listCbomCredentials(teamId) });
  const remove = useMutation({
    mutationFn: (id: number) => deleteCbomCredential(teamId, id),
    onSuccess: () => { setRemoving(null); queryClient.invalidateQueries({ queryKey: cbomFleetKeys.all(teamId) }); },
    onError: (err) => toast.error(refusalReason(err) ?? "Could not delete the credential"),
  });
  return (
    <SectionCard
      id="fleet-credentials"
      title="Credentials"
      description="Logins that policies give to the sources they manage. Secrets are write-only."
      actions={
        <Button size="sm" variant="outline" className="cursor-pointer" onClick={() => setAdding(true)} data-testid="fleet-add-credential">
          <KeyRound className="h-4 w-4 mr-1.5" /> Add credential
        </Button>
      }
    >
      {creds.isLoading && <LoadingBlock />}
      {!creds.data && creds.isError && <ErrorBlock error={creds.error} onRetry={() => creds.refetch()} />}
      {creds.data && creds.data.credentials.length === 0 && <EmptyState title="No credential yet" body="A policy that collects over SSH needs one." />}
      {creds.data && creds.data.credentials.length > 0 && (
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Login</TableHead>
                <TableHead>Secrets stored</TableHead>
                <TableHead className="text-right">Managed sources</TableHead>
                <TableHead><span className="sr-only">Actions</span></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {creds.data.credentials.map((c) => (
                <TableRow key={c.id}>
                  <TableCell className="font-medium">{c.name}</TableCell>
                  <TableCell>{c.credential_type}</TableCell>
                  <TableCell className="text-sm">{String(c.config.login_user ?? "")}:{String(c.config.port ?? 22)}</TableCell>
                  <TableCell className="text-sm">{c.secrets_set.length ? c.secrets_set.join(", ") : "none"}</TableCell>
                  <TableCell className="text-right">{c.managed_sources ?? 0}</TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="icon" className="cursor-pointer" aria-label={`Delete ${c.name}`} onClick={() => setRemoving(c)}>
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {adding && <CredentialForm teamId={teamId} onDone={() => setAdding(false)} />}
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(v) => !v && setRemoving(null)}
        title={`Delete ${removing?.name ?? "this credential"}?`}
        description="Its secrets are erased. Policies that use it stop collecting their targets until they get another credential."
        confirmLabel="Delete"
        destructive
        pending={remove.isPending}
        onConfirm={() => removing && remove.mutate(removing.id)}
      />
    </SectionCard>
  );
}
