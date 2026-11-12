"use client";

// Typed credentials that policies hand to the managed sources they create: the same login settings a Linux servers
// source has. Secrets are write-only: they are never shown again. Edit changes the name and the login settings; a
// blank secret field keeps the stored secret, except that changing where it is used (login, port, host keys, vault)
// makes the server ask for it again.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Pencil, Trash2 } from "lucide-react";
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
  updateCbomCredential,
  type CbomCredential,
  type CbomCredentialType,
} from "@/utils/api/cbom_fleet";

import { refusalReason } from "../logic";
import { ConfirmDialog, EmptyState, ErrorBlock, Field, LoadingBlock, SectionCard } from "../shared";
import { isConflict } from "./fleetLogic";
import { cbomFleetKeys, refreshFleet } from "./keys";
import type { FleetSectionProps } from "./sections";
import { useOpener } from "./useOpener";

const TYPES: { value: CbomCredentialType; label: string }[] = [
  { value: "node_key", label: "Scan node key (no stored secret)" },
  { value: "password", label: "Password (needs pinned host keys)" },
  { value: "ssh_cert", label: "SSH certificate and key" },
  { value: "vault", label: "From a vault" },
];
// the secrets each type stores, and the settings that say where they are used: changing one of those makes the
// server ask for the secrets again (a password for one host must not follow the credential to another login)
const SECRET_LABEL: Record<string, string> = { password: "password", ssh_certificate: "certificate and key", private_key: "certificate and key" };
const SECRETS_OF: Partial<Record<CbomCredentialType, string[]>> = { password: ["password"], ssh_cert: ["ssh_certificate", "private_key"] };
const WHERE = ["login_user", "port", "host_key_policy", "known_hosts", "vault"];

function vaultOf(c: CbomCredential | null): { provider?: string; path?: string } {
  const v = c?.config.vault;
  return v && typeof v === "object" ? (v as { provider?: string; path?: string }) : {};
}

function CredentialForm({ teamId, editing, onDone, onCloseAutoFocus }: {
  teamId: number; editing: CbomCredential | null; onDone: () => void; onCloseAutoFocus: (e: Event) => void;
}) {
  const queryClient = useQueryClient();
  const [base, setBase] = useState<CbomCredential | null>(editing); // the version being edited (reloaded after a 409)
  const [name, setName] = useState(editing?.name ?? "");
  const [type, setType] = useState<CbomCredentialType>(editing?.credential_type ?? "node_key");
  const [login, setLogin] = useState(String(editing?.config.login_user ?? "zs-cbom"));
  const [port, setPort] = useState(Number(editing?.config.port ?? 22));
  const [pinned, setPinned] = useState(editing?.config.host_key_policy === "pinned");
  const [knownHosts, setKnownHosts] = useState(String(editing?.config.known_hosts ?? ""));
  const [password, setPassword] = useState("");
  const [cert, setCert] = useState("");
  const [key, setKey] = useState("");
  const [vaultProvider, setVaultProvider] = useState(vaultOf(editing).provider ?? "hashicorp");
  const [vaultPath, setVaultPath] = useState(vaultOf(editing).path ?? "");
  const [error, setError] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);
  const config = (): Record<string, unknown> => {
    const out: Record<string, unknown> = { login_user: login, port, host_key_policy: pinned || type === "password" ? "pinned" : "tofu" };
    if (pinned || type === "password") out.known_hosts = knownHosts;
    if (type === "vault") out.vault = { provider: vaultProvider, path: vaultPath };
    return out;
  };
  // only the secret fields a person filled are sent: a blank one keeps the stored secret
  const secrets = (): Record<string, string> | undefined => {
    const typed = type === "password" ? { password } : type === "ssh_cert" ? { ssh_certificate: cert, private_key: key } : {};
    const filled = Object.fromEntries(Object.entries(typed).filter(([, v]) => v !== ""));
    return Object.keys(filled).length ? filled : undefined;
  };
  const stored = new Set(base?.secrets_set ?? []);
  const keepHint = (field: string) => (base && stored.has(field) ? "Stored; leave blank to keep it" : undefined);
  const next = config();
  const whereChanged = !!base && WHERE.some((k) => JSON.stringify(base.config[k] ?? null) !== JSON.stringify(next[k] ?? null));
  const reentry = whereChanged ? (SECRETS_OF[type] ?? []).filter((f) => stored.has(f)) : [];
  const save = useMutation({
    mutationFn: () => (base
      ? updateCbomCredential(teamId, base.id, { name: name.trim(), config: config(), secrets: secrets(), expected_version: base.row_version })
      : createCbomCredential(teamId, { name: name.trim(), credential_type: type, config: config(), secrets: secrets() })),
    onSuccess: () => {
      toast.success(base ? "Credential saved" : "Credential added");
      // a new credential changes no decision; an edited one can (policies that use it)
      refreshFleet(queryClient, teamId, base ? ["credentials", "policies", "targets"] : ["credentials"]);
      onDone();
    },
    onError: (err) => {
      if (base && isConflict(err)) {
        setConflict(true);
        setError("This credential was changed elsewhere (another tab or person) since you opened it.");
        refreshFleet(queryClient, teamId, ["credentials"]);
      } else setError(refusalReason(err) ?? (base ? "Could not save the credential" : "Could not add the credential"));
    },
  });
  // after a 409: the latest saved settings replace the form (secret fields stay blank: they are never shown)
  const reload = useMutation({
    mutationFn: () => queryClient.fetchQuery({ queryKey: cbomFleetKeys.credentials(teamId), queryFn: () => listCbomCredentials(teamId), staleTime: 0 }),
    onSuccess: (data) => {
      const fresh = data.credentials.find((c) => c.id === base?.id);
      if (!fresh) {
        setError("This credential was deleted elsewhere.");
        return;
      }
      setBase(fresh);
      setName(fresh.name);
      setLogin(String(fresh.config.login_user ?? "zs-cbom"));
      setPort(Number(fresh.config.port ?? 22));
      setPinned(fresh.config.host_key_policy === "pinned");
      setKnownHosts(String(fresh.config.known_hosts ?? ""));
      setVaultProvider(vaultOf(fresh).provider ?? "hashicorp");
      setVaultPath(vaultOf(fresh).path ?? "");
      setConflict(false);
      setError(null);
    },
    onError: (err) => setError(refusalReason(err) ?? "Could not load the latest version"),
  });
  return (
    <Dialog open onOpenChange={(v) => !v && onDone()}>
      <DialogContent className="sm:max-w-xl max-h-[90vh] overflow-y-auto" onCloseAutoFocus={onCloseAutoFocus}>
        <DialogHeader>
          <DialogTitle>{base ? `Edit ${base.name}` : "Add a credential"}</DialogTitle>
          <DialogDescription>Policies use it to log in to the hosts they collect. Secrets are encrypted and never shown again.</DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <Field label="Name" htmlFor="cred-name" required>
            <Input id="cred-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="linux-fleet" />
          </Field>
          <Field label="Type" htmlFor="cred-type">
            <Select value={type} onValueChange={(v) => setType(v as CbomCredentialType)} disabled={!!base}>
              <SelectTrigger id="cred-type" className="cursor-pointer" title={base ? "The type of a credential cannot change: add another one" : undefined}><SelectValue /></SelectTrigger>
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
              <Input id="cred-password" type="password" autoComplete="new-password" value={password} placeholder={keepHint("password")} onChange={(e) => setPassword(e.target.value)} />
            </Field>
          )}
          {type === "ssh_cert" && (
            <>
              <Field label="SSH certificate" htmlFor="cred-cert" required>
                <Textarea id="cred-cert" rows={3} className="font-mono text-xs" value={cert} placeholder={keepHint("ssh_certificate")} onChange={(e) => setCert(e.target.value)} />
              </Field>
              <Field label="Private key" htmlFor="cred-key" required>
                <Textarea id="cred-key" rows={4} className="font-mono text-xs" value={key} placeholder={keepHint("private_key")} onChange={(e) => setKey(e.target.value)} />
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
          {reentry.length > 0 && (
            <p className="text-sm text-amber-700 dark:text-amber-400" role="status">
              The login settings changed: enter the {SECRET_LABEL[reentry[0]]} again (the stored one is not used for another login).
            </p>
          )}
          {error && (
            <div className="flex flex-wrap items-center gap-2" role="alert">
              <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
              {conflict && (
                <Button variant="outline" size="sm" className="cursor-pointer" disabled={reload.isPending} onClick={() => reload.mutate()}>
                  Load the latest version
                </Button>
              )}
            </div>
          )}
        </div>
        <DialogFooter>
          <Button className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white" disabled={!name.trim() || save.isPending || conflict} onClick={() => save.mutate()}>
            {base ? "Save" : "Add credential"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function CredentialsSection({ teamId }: FleetSectionProps) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<CbomCredential | null | "new">(null);
  const [removing, setRemoving] = useState<CbomCredential | null>(null);
  const opener = useOpener();
  const creds = useQuery({ queryKey: cbomFleetKeys.credentials(teamId), queryFn: () => listCbomCredentials(teamId) });
  const remove = useMutation({
    mutationFn: (id: number) => deleteCbomCredential(teamId, id),
    onSuccess: () => { setRemoving(null); refreshFleet(queryClient, teamId, ["credentials", "policies", "targets"]); },
    onError: (err) => toast.error(refusalReason(err) ?? "Could not delete the credential"),
  });
  return (
    <SectionCard
      id="fleet-credentials"
      title="Credentials"
      description="Logins that policies give to the sources they manage. Secrets are write-only."
      actions={
        <Button size="sm" variant="outline" className="cursor-pointer" onClick={(e) => { opener.remember(e); setEditing("new"); }} data-testid="fleet-add-credential">
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
                  <TableCell className="text-right whitespace-nowrap">
                    <Button variant="ghost" size="icon" className="cursor-pointer" aria-label={`Edit ${c.name}`} onClick={(e) => { opener.remember(e); setEditing(c); }}>
                      <Pencil className="h-4 w-4" />
                    </Button>
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
      {editing !== null && (
        <CredentialForm teamId={teamId} editing={editing === "new" ? null : editing} onDone={() => setEditing(null)} onCloseAutoFocus={opener.onCloseAutoFocus} />
      )}
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
