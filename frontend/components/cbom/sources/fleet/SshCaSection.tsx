"use client";

// Fleet > SSH CA (F1.4): the team's SSH certificate authority. ZeroShield signs each scan node's own public key into a
// 5-minute user certificate per job (principals zs-<team>-<group>, bound to the node's address, no extensions), so the
// Linux servers trust one CA for the zs-cbom login instead of every node key. Admins create, rotate, promote and
// revoke, and issue trust tokens with which the servers fetch their trust files themselves (trust-fetch script);
// everyone in the team can download what the servers need and read the certificate audit.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Ban, Download, KeyRound, Loader2, Plus, RefreshCw, ShieldCheck } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  createSshCa,
  createSshCaTrustToken,
  getSshCaKrl,
  getSshCaText,
  listSshCas,
  listSshCaTrustTokens,
  listSshCertificates,
  promoteSshCa,
  revokeSshCa,
  revokeSshCaTrustToken,
  revokeSshCertificate,
  rotateSshCa,
  type SshCa,
  type SshCaKeyWrap,
  type SshCaState,
  type SshCaTrustToken,
  type SshCertIssued,
} from "@/utils/api/cbom_ssh_ca";
import { getCbomSourcesOverview } from "@/utils/backend_api";

import { cbomSourcesKeys } from "../keys";
import { readinessText } from "./sshCaLogic";
import { formatDateTime } from "../logic";
import { CodeSnippet, ConfirmDialog, EmptyState, ErrorBlock, Field, LoadingBlock, SectionCard, StatusBadge, type Tone } from "../shared";
import type { FleetSectionProps } from "./sections";
import { InfoTip } from "@/components/ui/info-tip";

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;
const GROUP_RE = /^[a-z0-9][a-z0-9._-]{0,47}$/;
const STATE: Record<SshCaState, [Tone, string]> = {
  active: ["green", "Active (signs)"],
  next: ["blue", "Rotation: trusted, not signing yet"],
  retired: ["amber", "Retired (trusted during the overlap)"],
  revoked: ["red", "Revoked"],
};
const CERT_STATUS: Record<SshCertIssued["status"], Tone> = { valid: "green", expired: "zinc", revoked: "red" };

export const sshCaKeys = {
  list: (teamId: number) => [...cbomSourcesKeys.all(teamId), "ssh-ca"] as const,
  tokens: (teamId: number) => [...cbomSourcesKeys.all(teamId), "ssh-ca", "trust-tokens"] as const,
  certs: (teamId: number, caId: number | null) => [...cbomSourcesKeys.all(teamId), "ssh-ca", "certs", caId ?? "all"] as const,
};

function errorText(err: unknown, fallback: string): string {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  return typeof detail === "string" ? detail : (err as Error)?.message || fallback;
}

function saveText(name: string, text: string | Blob) {
  const blob = text instanceof Blob ? text : new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

type Pending =
  | { kind: "rotate" | "promote" | "revoke"; ca: SshCa }
  | { kind: "revoke-cert"; cert: SshCertIssued }
  | { kind: "revoke-token"; token: SshCaTrustToken }
  | null;

function readinessOf(ca: SshCa) {
  return readinessText(ca.readiness, formatDateTime);
}

export function SshCaSection({ teamId, isAdmin }: { teamId: number; isAdmin: boolean }) {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [provider, setProvider] = useState<"builtin" | "vault">("builtin");
  const [alg, setAlg] = useState<"ed25519" | "ecdsa-p256">("ed25519");
  const [wrap, setWrap] = useState<SshCaKeyWrap | "">("");
  const [kmsKey, setKmsKey] = useState("");
  const [ttl, setTtl] = useState("300");
  const [vaultAddr, setVaultAddr] = useState("");
  const [vaultMount, setVaultMount] = useState("ssh-client-signer");
  const [vaultRole, setVaultRole] = useState("");
  const [vaultToken, setVaultToken] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [pending, setPending] = useState<Pending>(null);
  const [reason, setReason] = useState("");
  const [group, setGroup] = useState("");
  const [shown, setShown] = useState<{ title: string; text: string } | null>(null);
  const [certCa, setCertCa] = useState<number | null>(null);
  const [force, setForce] = useState(false);
  const [tokenName, setTokenName] = useState("");
  const [newToken, setNewToken] = useState<string | null>(null);

  const cas = useQuery({ queryKey: sshCaKeys.list(teamId), queryFn: () => listSshCas(teamId), enabled: Number.isFinite(teamId), retry: 1 });
  const certs = useQuery({
    queryKey: sshCaKeys.certs(teamId, certCa),
    queryFn: () => listSshCertificates(teamId, { ca_id: certCa ?? undefined, limit: 50 }),
    enabled: Number.isFinite(teamId),
    refetchInterval: 30000,
    retry: 1,
  });
  const tokens = useQuery({ queryKey: sshCaKeys.tokens(teamId), queryFn: () => listSshCaTrustTokens(teamId), enabled: Number.isFinite(teamId), retry: 1 });
  const invalidate = () => queryClient.invalidateQueries({ queryKey: sshCaKeys.list(teamId) });
  const makeToken = useMutation({
    mutationFn: () => createSshCaTrustToken(teamId, tokenName.trim()),
    onSuccess: (out) => { setNewToken(out.token); setTokenName(""); },
    onSettled: () => queryClient.invalidateQueries({ queryKey: sshCaKeys.tokens(teamId) }),
  });

  const create = useMutation({
    mutationFn: () =>
      createSshCa(teamId, provider === "builtin"
        ? { name: name.trim(), provider, key_alg: alg, key_wrap: wrap || undefined, kms_key: kmsKey || undefined, default_ttl_s: Number(ttl) }
        : { name: name.trim(), provider, vault_config: { addr: vaultAddr.trim(), mount: vaultMount.trim(), role: vaultRole.trim() }, secrets: { token: vaultToken }, default_ttl_s: Number(ttl) }),
    onSuccess: () => { setOpen(false); setVaultToken(""); setName(""); },
    onError: (err) => setFormError(errorText(err, "The CA was not created")),
    onSettled: invalidate,
  });
  const act = useMutation({
    mutationFn: async (p: NonNullable<Pending>) => {
      if (p.kind === "revoke-cert") return revokeSshCertificate(teamId, p.cert.id, reason.trim());
      if (p.kind === "revoke-token") return revokeSshCaTrustToken(teamId, p.token.id);
      if (p.kind === "rotate") return rotateSshCa(teamId, p.ca.id, p.ca.row_version);
      if (p.kind === "promote") return promoteSshCa(teamId, p.ca.id, p.ca.row_version, force);
      return revokeSshCa(teamId, p.ca.id, reason.trim(), p.ca.row_version);
    },
    onSuccess: () => { setPending(null); setReason(""); setForce(false); },
    onSettled: () => {
      invalidate();
      queryClient.invalidateQueries({ queryKey: sshCaKeys.certs(teamId, certCa) });
      queryClient.invalidateQueries({ queryKey: sshCaKeys.tokens(teamId) });
    },
  });

  const submit = () => {
    const t = Number(ttl);
    if (!NAME_RE.test(name.trim())) return setFormError("Use 1-64 letters, digits, spaces, dots, dashes or underscores.");
    if (!Number.isInteger(t) || t < 60 || t > 3600) return setFormError("Certificate lifetime: between 60 and 3600 seconds.");
    if (provider === "vault" && (!vaultAddr.startsWith("https://") || !vaultRole.trim() || !vaultToken))
      return setFormError("Vault needs its https:// address, the SSH engine role and a token.");
    setFormError(null);
    create.mutate();
  };

  const show = async (title: string, what: Parameters<typeof getSshCaText>[1]) => {
    try {
      setShown({ title, text: await getSshCaText(teamId, what, what === "templates/principals" && group ? group : undefined) });
    } catch (err) {
      setShown({ title, text: `# ${errorText(err, "could not be loaded")}` });
    }
  };

  const list = cas.data?.cas ?? [];
  const kmsKeys = cas.data?.kms_keys ?? [];
  const needSave = cas.data?.attention?.sources_needing_admin_save ?? [];
  const needSaveTotal = cas.data?.attention?.sources_needing_admin_save_total ?? needSave.length;
  const pendingReady = pending?.kind === "promote" ? readinessOf(pending.ca) : null;
  const lineageHasNext = (ca: SshCa) => list.some((c) => c.lineage_id === ca.lineage_id && c.state === "next");
  const reasonNeeded = pending?.kind === "revoke" || pending?.kind === "revoke-cert";
  const confirmBlocked = (reasonNeeded && !reason.trim()) || (pendingReady?.early === true && !force);

  return (
    <SectionCard
      infoId="cbsrc.sshca.card"
      id="fleet-ssh-ca"
      title="SSH certificate authority"
      description="ZeroShield signs each scan node's own key into a short-lived certificate for every job (5 minutes by default, principals zs-<team>-<group>, bound to the node's address, no forwarding or terminal). Your servers trust the CA for the zs-cbom login only; every certificate is listed below."
      actions={isAdmin && (
        <Button variant="outline" className="cursor-pointer" data-testid="ssh-ca-create" onClick={() => { setOpen(true); setFormError(null); }}>
          <Plus className="h-4 w-4 mr-2" />Create SSH CA
        </Button>
      )}
    >
      {open && (
        <div className="mb-6 space-y-4 rounded-lg border border-zinc-200 dark:border-zinc-800 p-4" data-testid="ssh-ca-form">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Field infoId="cbsrc.sshca.name" label="Name" htmlFor="ssh-ca-name" required error={formError}>
              <Input id="ssh-ca-name" value={name} maxLength={64} placeholder="prod-servers-ca" onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field infoId="cbsrc.sshca.provider" label="Where the CA key lives" htmlFor="ssh-ca-provider" hint="Built in: ZeroShield holds the key, encrypted (AWS KMS when this deployment has a key). Vault: your HashiCorp Vault SSH engine signs.">
              <Select value={provider} onValueChange={(v) => setProvider(v as "builtin" | "vault")}>
                <SelectTrigger id="ssh-ca-provider" className="w-full cursor-pointer"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="builtin" className="cursor-pointer">Built in (ZeroShield)</SelectItem>
                  <SelectItem value="vault" className="cursor-pointer">HashiCorp Vault SSH engine</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field infoId="cbsrc.sshca.ttl" label="Certificate lifetime (seconds)" htmlFor="ssh-ca-ttl" hint="60 to 3600. A job renews its certificate before it runs out.">
              <Input id="ssh-ca-ttl" type="number" min={60} max={3600} value={ttl} onChange={(e) => setTtl(e.target.value)} />
            </Field>
            {provider === "builtin" ? (
              <>
                <Field infoId="cbsrc.sshca.alg" label="Key type" htmlFor="ssh-ca-alg">
                  <Select value={alg} onValueChange={(v) => setAlg(v as "ed25519" | "ecdsa-p256")}>
                    <SelectTrigger id="ssh-ca-alg" className="w-full cursor-pointer"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ed25519" className="cursor-pointer">Ed25519 (recommended)</SelectItem>
                      <SelectItem value="ecdsa-p256" className="cursor-pointer">ECDSA P-256</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
                <Field infoId="cbsrc.sshca.wrap" label="Key encryption" htmlFor="ssh-ca-wrap" hint={kmsKeys.length ? "This deployment wraps CA keys with AWS KMS" : "This deployment has no AWS KMS key configured"}>
                  <Select value={kmsKeys.length ? "aws_kms" : (wrap || "fernet")} onValueChange={(v) => setWrap(v as SshCaKeyWrap)} disabled={kmsKeys.length > 0}>
                    <SelectTrigger id="ssh-ca-wrap" className="w-full cursor-pointer"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {kmsKeys.length > 0
                        ? <SelectItem value="aws_kms" className="cursor-pointer">AWS KMS</SelectItem>
                        : <SelectItem value="fernet" className="cursor-pointer">Deployment key (ENCRYPTION_KEY)</SelectItem>}
                    </SelectContent>
                  </Select>
                </Field>
                {kmsKeys.length > 1 && (
                  <Field infoId="cbsrc.sshca.kms" label="KMS key" htmlFor="ssh-ca-kms" hint="Labels of the KMS keys this deployment allows">
                    <Select value={kmsKey || (kmsKeys.find((k) => k.default) ?? kmsKeys[0]).label} onValueChange={setKmsKey}>
                      <SelectTrigger id="ssh-ca-kms" className="w-full cursor-pointer"><SelectValue /></SelectTrigger>
                      <SelectContent>{kmsKeys.map((k) => <SelectItem key={k.label} value={k.label} className="cursor-pointer font-mono text-xs">{k.label}{k.default ? " (default)" : ""}</SelectItem>)}</SelectContent>
                    </Select>
                  </Field>
                )}
              </>
            ) : (
              <>
                <Field infoId="cbsrc.sshca.vault_addr" label="Vault address" htmlFor="ssh-ca-vault-addr" required hint="https://vault.example:8200 (the active node)">
                  <Input id="ssh-ca-vault-addr" value={vaultAddr} onChange={(e) => setVaultAddr(e.target.value)} />
                </Field>
                <Field infoId="cbsrc.sshca.vault_mount" label="SSH engine mount" htmlFor="ssh-ca-vault-mount">
                  <Input id="ssh-ca-vault-mount" value={vaultMount} onChange={(e) => setVaultMount(e.target.value)} />
                </Field>
                <Field infoId="cbsrc.sshca.vault_role" label="Signing role" htmlFor="ssh-ca-vault-role" required hint="allowed_critical_options must include source-address; default_extensions {}">
                  <Input id="ssh-ca-vault-role" value={vaultRole} onChange={(e) => setVaultRole(e.target.value)} />
                </Field>
                <Field infoId="cbsrc.sshca.vault_token" label="Vault token" htmlFor="ssh-ca-vault-token" required hint="Write-only; may only call <mount>/sign/<role>">
                  <Input id="ssh-ca-vault-token" type="password" autoComplete="off" value={vaultToken} onChange={(e) => setVaultToken(e.target.value)} />
                </Field>
              </>
            )}
          </div>
          <div className="flex gap-2">
            <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={create.isPending} onClick={submit}>
              {create.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <KeyRound className="h-4 w-4 mr-2" />}Create CA
            </Button>
            <Button variant="outline" className="cursor-pointer" onClick={() => setOpen(false)}>Cancel</Button>
          </div>
        </div>
      )}

      {needSave.length > 0 && (
        <div className="mb-4 rounded-lg border border-amber-300 bg-amber-50 dark:bg-amber-950/30 p-3 text-sm" role="status" data-testid="ssh-ca-attention">
          <div className="flex items-center gap-2 font-medium"><AlertTriangle className="h-4 w-4 text-amber-600" />
            {needSaveTotal} source{needSaveTotal === 1 ? "" : "s"} saved by someone who is no longer a team admin
          </div>
          <p className="text-xs mt-1">They get no SSH certificate until a team admin opens each one and clicks Save (no change is needed): {needSave.map((s) => s.name).join(", ")}{needSaveTotal > needSave.length ? " and more" : ""}.</p>
        </div>
      )}
      {cas.isLoading ? <LoadingBlock /> : cas.isError ? <ErrorBlock error={cas.error} onRetry={() => cas.refetch()} /> : list.length === 0 ? (
        <EmptyState title="No SSH CA yet" body="Create one, install its public key on your servers, then choose “SSH CA certificate” as the credential of a Linux server group." />
      ) : (
        <div className="overflow-x-auto">
          <Table data-testid="ssh-ca-table">
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead><TableHead>State <InfoTip id="cbsrc.sshca.col.state" /></TableHead><TableHead>Key <InfoTip id="cbsrc.sshca.col.key" /></TableHead>
                <TableHead>Lifetime <InfoTip id="cbsrc.sshca.col.lifetime" /></TableHead><TableHead>Certificates <InfoTip id="cbsrc.sshca.col.certs" /></TableHead><TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.map((ca) => (
                <TableRow key={ca.id} data-testid={`ssh-ca-row-${ca.id}`}>
                  <TableCell className="font-medium">{ca.name}<div className="text-xs text-zinc-500">#{ca.id}{ca.rotated_from_id ? ` · rotated from #${ca.rotated_from_id}` : ""} · {ca.provider === "vault" ? "Vault" : ca.key_wrap === "aws_kms" ? `AWS KMS ${ca.kms_key ?? ""}` : "deployment key"}</div>
                    {ca.wrap_warning && <div className="text-xs text-amber-700 mt-1" role="note">{ca.wrap_warning}</div>}
                  </TableCell>
                  <TableCell><StatusBadge tone={STATE[ca.state][0]} title={ca.revoked_reason ?? undefined}>{STATE[ca.state][1]}</StatusBadge>
                    {ca.state === "next" && <div className="text-xs text-zinc-500 mt-1 max-w-[16rem]" data-testid={`ssh-ca-readiness-${ca.id}`}>{readinessOf(ca)?.text}</div>}
                  </TableCell>
                  <TableCell className="font-mono text-xs break-all max-w-[18rem]">{ca.key_alg} {ca.fingerprint}</TableCell>
                  <TableCell>{ca.default_ttl_s} s</TableCell>
                  <TableCell>
                    <button type="button" className="underline cursor-pointer" onClick={() => setCertCa(ca.id)}>Show</button>
                  </TableCell>
                  <TableCell className="text-right space-x-2 whitespace-nowrap">
                    {isAdmin && ca.state === "active" && !lineageHasNext(ca) && (
                      <Button size="sm" variant="outline" className="cursor-pointer" onClick={() => setPending({ kind: "rotate", ca })}><RefreshCw className="h-3.5 w-3.5 mr-1" />Rotate</Button>
                    )}
                    {isAdmin && ca.state === "next" && (
                      <Button size="sm" variant="outline" className="cursor-pointer" onClick={() => { setForce(false); setPending({ kind: "promote", ca }); }}><ShieldCheck className="h-3.5 w-3.5 mr-1" />Promote</Button>
                    )}
                    {isAdmin && ca.state !== "revoked" && (
                      <Button size="sm" variant="outline" className="cursor-pointer text-red-600" onClick={() => setPending({ kind: "revoke", ca })}><Ban className="h-3.5 w-3.5 mr-1" />Revoke</Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <div className="mt-6 space-y-3" data-testid="ssh-ca-downloads">
        <h4 className="text-sm font-semibold">For your servers</h4>
        <p className="text-xs text-zinc-500">
          Install the sshd snippet once. The fetch script keeps the trusted keys, the revocation list and the principals file current with a trust token
          (run it from a timer every few minutes); rotate, promote and revoke reach the servers on its next run. sshd refuses every key for zs-cbom while
          the revocation list file is missing, so run the script once before reloading sshd.
        </p>
        <div className="flex flex-wrap items-end gap-2">
          <Button size="sm" variant="outline" className="cursor-pointer" onClick={() => show("sshd_config.d/50-zs-cbom-ca.conf", "templates/sshd-config")}>sshd snippet</Button>
          <Button size="sm" variant="outline" className="cursor-pointer" onClick={() => show("zs-trust-fetch.sh", "templates/trust-fetch")}>Fetch script</Button>
          <Button size="sm" variant="outline" className="cursor-pointer" onClick={() => show("trusted_user_ca_keys", "trusted-keys")}>Trusted keys</Button>
          <Button size="sm" variant="outline" className="cursor-pointer"
            onClick={async () => saveText(`zs-team${teamId}-revoked.krl`, await getSshCaKrl(teamId))}><Download className="h-3.5 w-3.5 mr-1" />Revocation list (KRL)</Button>
          <Field infoId="cbsrc.sshca.group" label="Server group" htmlFor="ssh-ca-group" className="w-40" error={group && !GROUP_RE.test(group) ? "lowercase letters, digits, . _ -" : null}>
            <Input id="ssh-ca-group" value={group} placeholder="prod" onChange={(e) => setGroup(e.target.value.trim())} />
          </Field>
          <Button size="sm" variant="outline" className="cursor-pointer" disabled={!!group && !GROUP_RE.test(group)}
            onClick={() => show("principals/zs-cbom", "templates/principals")}>Principals file</Button>
        </div>
        {shown && (
          <div className="space-y-2" data-testid="ssh-ca-text">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs">{shown.title}</span>
              <Button size="sm" variant="ghost" className="cursor-pointer" onClick={() => saveText(shown.title.split("/").pop() || "file", shown.text)}><Download className="h-3.5 w-3.5 mr-1" />Save</Button>
            </div>
            <CodeSnippet code={shown.text} language="bash" />
          </div>
        )}
      </div>

      <div className="mt-6 space-y-2" data-testid="ssh-ca-trust-tokens">
        <h4 className="text-sm font-semibold">Trust tokens <InfoTip id="cbsrc.sshca.trust_tokens" /></h4>
        <p className="text-xs text-zinc-500">
          A trust token lets your servers (or your configuration management) read this team&apos;s trusted keys, revocation list and principals, and nothing else.
          It is shown once. Each server sends its name, so a rotation shows how many servers already have the new key.
        </p>
        {isAdmin && (
          <div className="flex flex-wrap items-end gap-2">
            <Field infoId="cbsrc.sshca.token_name" label="Token name" htmlFor="ssh-ca-token-name" className="w-56">
              <Input id="ssh-ca-token-name" value={tokenName} maxLength={64} placeholder="prod-servers" onChange={(e) => setTokenName(e.target.value)} />
            </Field>
            <Button size="sm" variant="outline" className="cursor-pointer" disabled={!NAME_RE.test(tokenName.trim()) || makeToken.isPending}
              onClick={() => { setNewToken(null); makeToken.mutate(); }}>
              {makeToken.isPending ? <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" /> : <Plus className="h-3.5 w-3.5 mr-1" />}Create trust token
            </Button>
          </div>
        )}
        {makeToken.isError && <p className="text-sm text-red-600" role="alert">{errorText(makeToken.error, "The token was not created")}</p>}
        {newToken && (
          <div className="space-y-1" data-testid="ssh-ca-new-token">
            <p className="text-xs font-medium">Copy it now: it is not shown again. Keep it in a file only root can read (ZS_TRUST_TOKEN). <InfoTip id="cbsrc.sshca.new_token" /></p>
            <CodeSnippet code={newToken} language="bash" />
          </div>
        )}
        {(tokens.data?.tokens ?? []).length > 0 && (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow><TableHead>Name</TableHead><TableHead>Token <InfoTip id="cbsrc.sshca.col.token" /></TableHead><TableHead>Servers (24 h) <InfoTip id="cbsrc.sshca.col.servers" /></TableHead><TableHead>Last used <InfoTip id="cbsrc.sshca.col.last_used" /></TableHead><TableHead>Status <InfoTip id="cbsrc.sshca.col.token_status" /></TableHead><TableHead /></TableRow>
              </TableHeader>
              <TableBody>
                {(tokens.data?.tokens ?? []).map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="text-sm">{t.name}</TableCell>
                    <TableCell className="font-mono text-xs">{t.prefix}…</TableCell>
                    <TableCell className="text-xs">{t.fetchers}</TableCell>
                    <TableCell className="text-xs">{formatDateTime(t.last_used_at)}</TableCell>
                    <TableCell><StatusBadge tone={t.revoked_at ? "red" : "green"}>{t.revoked_at ? "revoked" : "active"}</StatusBadge></TableCell>
                    <TableCell className="text-right">
                      {isAdmin && !t.revoked_at && (
                        <Button size="sm" variant="ghost" className="cursor-pointer text-red-600" onClick={() => setPending({ kind: "revoke-token", token: t })}>Revoke</Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>

      <div className="mt-6 space-y-2" data-testid="ssh-ca-certificates">
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-semibold">Issued certificates{certCa ? ` (CA #${certCa})` : ""}</h4>
          {certCa && <Button size="sm" variant="ghost" className="cursor-pointer" onClick={() => setCertCa(null)}>Show all</Button>}
        </div>
        {certs.isLoading ? <LoadingBlock /> : (certs.data?.certificates ?? []).length === 0 ? (
          <p className="text-xs text-zinc-500">No certificate issued yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Issued <InfoTip id="cbsrc.sshca.col.issued" /></TableHead><TableHead>Serial <InfoTip id="cbsrc.sshca.col.serial" /></TableHead><TableHead>Principals <InfoTip id="cbsrc.sshca.col.principals" /></TableHead>
                  <TableHead>From <InfoTip id="cbsrc.sshca.col.from" /></TableHead><TableHead>Node / job <InfoTip id="cbsrc.sshca.col.node_job" /></TableHead><TableHead>Valid until <InfoTip id="cbsrc.sshca.col.valid_until" /></TableHead><TableHead>Status <InfoTip id="cbsrc.sshca.col.cert_status" /></TableHead><TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {(certs.data?.certificates ?? []).map((c) => (
                  <TableRow key={c.id}>
                    <TableCell className="text-xs">{formatDateTime(c.issued_at)}</TableCell>
                    <TableCell className="font-mono text-xs">{c.serial}<div className="text-zinc-500">CA #{c.ca_id}</div></TableCell>
                    <TableCell className="font-mono text-xs">{c.principals.join(", ")}</TableCell>
                    <TableCell className="font-mono text-xs break-all">{c.source_addresses.join(", ") || "—"}</TableCell>
                    <TableCell className="text-xs">node #{c.node_id ?? "—"} · job #{c.job_id ?? "—"}<div className="text-zinc-500">{c.via === "claim" ? "at claim" : "renewal"}</div></TableCell>
                    <TableCell className="text-xs">{formatDateTime(c.valid_before)}</TableCell>
                    <TableCell><StatusBadge tone={CERT_STATUS[c.status]} title={c.revoked_reason ?? undefined}>{c.status}</StatusBadge></TableCell>
                    <TableCell className="text-right">
                      {isAdmin && c.status === "valid" && (
                        <Button size="sm" variant="ghost" className="cursor-pointer text-red-600" onClick={() => setPending({ kind: "revoke-cert", cert: c })}>Revoke</Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>

      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(v) => { if (!v) { setPending(null); setReason(""); setForce(false); act.reset(); } }}
        title={pending?.kind === "rotate" ? "Start a CA rotation?" : pending?.kind === "promote" ? "Promote the new CA?"
          : pending?.kind === "revoke" ? "Revoke this CA?" : pending?.kind === "revoke-token" ? "Revoke this trust token?" : "Revoke this certificate?"}
        description={
          <span className="space-y-3 block">
            {pending?.kind === "rotate" && "A new CA key is created and listed in the trusted keys at once; it signs only after you promote it. Promote it once every server has the new trusted keys (the fetch script picks them up on its next run)."}
            {pending?.kind === "promote" && (
              <span className="block space-y-2">
                <span className="block">The new key signs from now on. Servers that do not trust it yet refuse every scan login. The old key stays trusted for an hour (the longest certificate it may still have issued), then leaves the trusted keys.</span>
                {pendingReady && <span className="block font-medium" data-testid="ssh-ca-promote-readiness">{pendingReady.text}</span>}
                {pendingReady?.early && (
                  <label className="flex items-center gap-2 cursor-pointer">
                    <Checkbox checked={force} onCheckedChange={(v) => setForce(v === true)} aria-label="Promote now" />
                    <span>Every server already has the new trusted keys: promote now</span>
                  </label>
                )}
                {pendingReady?.early && (
                  <InfoTip id="cbsrc.sshca.promote_now" />
                )}
              </span>
            )}
            {pending?.kind === "revoke" && "It signs nothing more and goes into the revocation list; servers refuse its certificates once they have the new list. Sources using this CA stop until a new CA in the lineage is promoted."}
            {pending?.kind === "revoke-cert" && `Serial ${pending.cert.serial} goes into the revocation list; servers refuse it once they have the new list. This run of job #${pending.cert.job_id ?? "?"} stops and gets no new certificate. The scan node's other jobs still get certificates: to stop the node itself, reset or delete it on the Scan nodes tab.`}
            {pending?.kind === "revoke-token" && `Servers using ${pending.token.name} (${pending.token.prefix}…) get 401 from now on and keep their current files until they get a new token.`}
            {reasonNeeded && (
              <span className="mt-2 flex items-center gap-1">
                <Input aria-label="Reason" placeholder="Reason (recorded in the audit)" value={reason} maxLength={512} onChange={(e) => setReason(e.target.value)} />
                <InfoTip id="cbsrc.sshca.reason" />
              </span>
            )}
            {act.isError && <span className="block text-red-600 text-sm" role="alert">{errorText(act.error, "That did not work")}</span>}
          </span>
        }
        confirmLabel={pending?.kind === "rotate" ? "Rotate" : pending?.kind === "promote" ? "Promote" : "Revoke"}
        destructive={reasonNeeded || pending?.kind === "revoke-token"}
        pending={act.isPending}
        onConfirm={() => { if (pending && !confirmBlocked) act.mutate(pending); }}
      />
    </SectionCard>
  );
}

/** The Fleet tab's SSH CA section (``sections.tsx``): the viewer's admin flag comes from the CBOM Sources overview
 * (the server enforces it as well; a member's write gets a 400). */
export function SshCaFleetSection({ teamId }: FleetSectionProps) {
  const overview = useQuery({
    queryKey: cbomSourcesKeys.overview(teamId),
    queryFn: () => getCbomSourcesOverview(teamId),
    enabled: Number.isFinite(teamId) && teamId > 0,
    retry: 1,
    staleTime: 60_000,
  });
  return <SshCaSection teamId={teamId} isAdmin={!!overview.data?.viewer?.is_admin} />;
}

export default SshCaSection;
