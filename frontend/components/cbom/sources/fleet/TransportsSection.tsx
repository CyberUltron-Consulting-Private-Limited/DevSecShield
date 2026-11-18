"use client";

// Transports (F1.3, #318): run the collection through the customer's own configuration management, Ansible (AWX /
// AAP), Salt or AWS Systems Manager, instead of SSH from a scan node. Policies choose one in "Collect through".
// Secrets (the AWX token, the salt-api user and password) are entered once and never shown back: the list names the
// secrets stored. Test runs from ZeroShield for SSM only; AWX and Salt are reached from a scan node inside the
// customer's network, so a source that uses them is what tests them. The files to install come from the API.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileText, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { useRef, useState } from "react";
import { toast } from "@/utils/toast";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { InfoTip } from "@/components/ui/info-tip";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import {
  createCbomTransport,
  deleteCbomTransport,
  getCbomTransportArtifact,
  listCbomTransports,
  validateCbomTransport,
  type CbomTransport,
  type CbomTransportKind,
} from "@/utils/api/cbom_fleet";

import { refusalReason } from "../logic";
import { ChoiceCards, CodeSnippet, ConfirmDialog, EmptyState, ErrorBlock, Field, LoadingBlock, SectionCard, StatusBadge, type Tone } from "../shared";
import { cbomFleetKeys, refreshFleet } from "./keys";
import type { FleetSectionProps } from "./sections";
import {
  ARTIFACTS_OF,
  NEEDS_RELEASE,
  TEST_ELSEWHERE,
  TRANSPORT_LABEL,
  canTest,
  emptyTransportDraft,
  endpointText,
  transportBody,
  transportProblems,
  type TransportDraft,
} from "./transportsLogic";
import { useOpener } from "./useOpener";

const KIND_DESCRIPTION: Record<CbomTransportKind, string> = {
  awx: "A job template in your AWX or Ansible Automation Platform runs the collector on the hosts. A scan node calls it.",
  salt: "Your salt-api runs the collector on minions or over salt-ssh. A scan node calls it.",
  ssm: "AWS Systems Manager Run Command runs the collector on managed instances, through a read-only role. No scan node.",
};
const FILES = [...new Set([...ARTIFACTS_OF.awx, ...ARTIFACTS_OF.salt, ...ARTIFACTS_OF.ssm, "zs-collect-manifest", "zs-collect-pubkey"])];
const STATUS_TONE: Record<string, Tone> = { passed: "green", failed: "red", never: "zinc" };

function TransportForm({ teamId, onDone, onCloseAutoFocus }: { teamId: number; onDone: () => void; onCloseAutoFocus: (e: Event) => void }) {
  const queryClient = useQueryClient();
  const [d, setD] = useState<TransportDraft>(() => emptyTransportDraft("awx"));
  const [tried, setTried] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const set = <K extends keyof TransportDraft>(k: K, v: TransportDraft[K]) => setD((cur) => ({ ...cur, [k]: v }));
  const problems = transportProblems(d);
  const shown = (k: keyof TransportDraft) => (tried ? problems[k] ?? null : null);
  const save = useMutation({
    mutationFn: () => createCbomTransport(teamId, transportBody(d)),
    onSuccess: (res) => {
      toast.success(`Transport added: ${res.transport.name}`);
      refreshFleet(queryClient, teamId, ["transports"]);
      onDone();
    },
    onError: (err) => setError(refusalReason(err) ?? "Could not add the transport"),
  });
  const submit = () => {
    setTried(true);
    setError(null);
    if (Object.keys(problems).length === 0) save.mutate();
  };
  const web = d.kind === "awx" || d.kind === "salt";
  return (
    <Dialog open onOpenChange={(v) => !v && onDone()}>
      <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto" onCloseAutoFocus={onCloseAutoFocus}>
        <DialogHeader>
          <DialogTitle>Add a transport</DialogTitle>
          <DialogDescription>Secrets are encrypted and never shown again; the list names the ones stored.</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <ChoiceCards<CbomTransportKind>
            name="transport-kind"
            label="Kind"
            infoId="fleet.tr.kind"
            columns={3}
            value={d.kind}
            onChange={(k) => setD((cur) => ({ ...emptyTransportDraft(k), name: cur.name }))}
            options={(Object.keys(TRANSPORT_LABEL) as CbomTransportKind[]).map((k) => ({ value: k, title: TRANSPORT_LABEL[k], description: KIND_DESCRIPTION[k] }))}
          />
          <Field infoId="fleet.tr.name" label="Name" htmlFor="transport-name" required error={shown("name")}>
            <Input id="transport-name" maxLength={64} value={d.name} placeholder={d.kind === "ssm" ? "ssm-prod" : `${d.kind}-dc1`} onChange={(e) => set("name", e.target.value)} />
          </Field>
          {web && (
            <Field infoId="fleet.tr.base_url" label={d.kind === "awx" ? "AWX / AAP URL" : "salt-api URL"} htmlFor="transport-base-url" required error={shown("baseUrl")}>
              <Input id="transport-base-url" value={d.baseUrl} placeholder={d.kind === "awx" ? "https://awx.example.com" : "https://salt.example.com:8000"}
                onChange={(e) => set("baseUrl", e.target.value)} />
            </Field>
          )}
          {d.kind === "awx" && (
            <div className="grid sm:grid-cols-2 gap-3">
              <Field infoId="fleet.tr.job_template" label="Job template ID" htmlFor="transport-job-template" required error={shown("jobTemplateId")}>
                <Input id="transport-job-template" inputMode="numeric" value={d.jobTemplateId} placeholder="42" onChange={(e) => set("jobTemplateId", e.target.value)} />
              </Field>
              <Field infoId="fleet.tr.token" label="Token" htmlFor="transport-token" required error={shown("token")}>
                <Input id="transport-token" type="password" autoComplete="new-password" value={d.token} onChange={(e) => set("token", e.target.value)} />
              </Field>
            </div>
          )}
          {d.kind === "salt" && (
            <>
              <div className="grid sm:grid-cols-2 gap-3">
                <Field infoId="fleet.tr.salt_user" label="salt-api user" htmlFor="transport-salt-username" required error={shown("username")}>
                  <Input id="transport-salt-username" autoComplete="off" value={d.username} onChange={(e) => set("username", e.target.value)} />
                </Field>
                <Field infoId="fleet.tr.salt_password" label="salt-api password" htmlFor="transport-salt-password" required error={shown("password")}>
                  <Input id="transport-salt-password" type="password" autoComplete="new-password" value={d.password} onChange={(e) => set("password", e.target.value)} />
                </Field>
              </div>
              <div className="grid sm:grid-cols-3 gap-3">
                <Field infoId="fleet.tr.salt_client" label="Client" htmlFor="transport-salt-client">
                  <Select value={d.client} onValueChange={(v) => set("client", v as TransportDraft["client"])}>
                    <SelectTrigger id="transport-salt-client" className="cursor-pointer"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="local_async" className="cursor-pointer">Minions (async)</SelectItem>
                      <SelectItem value="local" className="cursor-pointer">Minions (wait)</SelectItem>
                      <SelectItem value="ssh" className="cursor-pointer">salt-ssh</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
                <Field infoId="fleet.tr.salt_mode" label="Runs as" htmlFor="transport-salt-mode">
                  <Select value={d.mode} onValueChange={(v) => set("mode", v as TransportDraft["mode"])}>
                    <SelectTrigger id="transport-salt-mode" className="cursor-pointer"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="cmd" className="cursor-pointer">A command</SelectItem>
                      <SelectItem value="state" className="cursor-pointer">A state</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
                <Field infoId="fleet.tr.salt_batch" label="Hosts per batch" htmlFor="transport-salt-batch" error={shown("batchSize")}>
                  <Input id="transport-salt-batch" inputMode="numeric" value={d.batchSize} onChange={(e) => set("batchSize", e.target.value)} />
                </Field>
              </div>
            </>
          )}
          {web && (
            <>
              <div className="flex items-center gap-1">
                <label className="flex items-center gap-2 text-sm cursor-pointer">
                  <input type="checkbox" id="transport-verify-tls" checked={d.verifyTls} onChange={(e) => set("verifyTls", e.target.checked)} />
                  Verify its TLS certificate
                </label>
                <InfoTip id="fleet.tr.verify_tls" />
              </div>
              <Field infoId="fleet.tr.ca_pem" label="CA certificate (optional)" htmlFor="transport-ca-pem" hint="PEM, when the control plane's certificate is issued by your own CA">
                <Textarea id="transport-ca-pem" rows={3} className="font-mono text-xs" value={d.caPem} onChange={(e) => set("caPem", e.target.value)} />
              </Field>
            </>
          )}
          {d.kind === "ssm" && (
            <>
              <Field infoId="fleet.tr.role_arn" label="Run-command role ARN" htmlFor="transport-role-arn" required error={shown("roleArn")}
                hint="Assumed with this team's external ID; the ssm-role-cfn file below creates it">
                <Input id="transport-role-arn" value={d.roleArn} placeholder="arn:aws:iam::123456789012:role/zeroshield-cbom-run" onChange={(e) => set("roleArn", e.target.value)} />
              </Field>
              <div className="grid sm:grid-cols-2 gap-3">
                <Field infoId="fleet.tr.regions" label="Regions" htmlFor="transport-regions" required error={shown("regions")} hint="Comma or space separated, up to 16">
                  <Input id="transport-regions" value={d.regions} placeholder="ap-south-1, eu-west-1" onChange={(e) => set("regions", e.target.value)} />
                </Field>
                <Field infoId="fleet.tr.document" label="SSM document" htmlFor="transport-document" required error={shown("documentName")}>
                  <Input id="transport-document" value={d.documentName} onChange={(e) => set("documentName", e.target.value)} />
                </Field>
              </div>
              <Field infoId="fleet.tr.bucket" label="Output S3 bucket (optional)" htmlFor="transport-bucket" error={shown("bucket")}>
                <Input id="transport-bucket" value={d.bucket} onChange={(e) => set("bucket", e.target.value)} />
              </Field>
            </>
          )}
          {error && <p className="text-sm text-red-600 dark:text-red-400" role="alert">{error}</p>}
        </div>
        <DialogFooter>
          <Button className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white" disabled={save.isPending} onClick={submit}>
            Add transport
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function TransportsSection({ teamId }: FleetSectionProps) {
  const queryClient = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<CbomTransport | null>(null);
  const [file, setFile] = useState<{ name: string; text: string } | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const addButton = useRef<HTMLButtonElement>(null);
  const opener = useOpener(addButton);
  const list = useQuery({ queryKey: cbomFleetKeys.transports(teamId), queryFn: () => listCbomTransports(teamId) });
  const test = useMutation({
    mutationFn: (t: CbomTransport) => validateCbomTransport(teamId, t.id),
    onSuccess: (r) => {
      if (r.status === "passed") toast.success(`${r.transport.name}: ${r.summary}`);
      else toast.error(`${r.transport.name}: ${r.summary}`);
      refreshFleet(queryClient, teamId, ["transports"]);
    },
    onError: (err) => toast.error(refusalReason(err) ?? "Could not test the transport"),
  });
  const remove = useMutation({
    mutationFn: (id: number) => deleteCbomTransport(teamId, id),
    onSuccess: () => { setRemoving(null); toast.success("Transport deleted; its secrets are erased"); refreshFleet(queryClient, teamId, ["transports", "policies", "targets"]); },
    onError: (err) => { setRemoving(null); toast.error(refusalReason(err) ?? "Could not delete the transport"); },
  });
  const fetchFile = useMutation({
    mutationFn: (name: string) => getCbomTransportArtifact(teamId, name),
    onMutate: () => setFileError(null),
    onSuccess: (text, name) => setFile({ name, text }),
    onError: (err) => { setFile(null); setFileError(refusalReason(err) ?? "Could not load the file"); },
  });
  const data = list.data;
  return (
    <SectionCard
      infoId="fleet.tr.section"
      id="fleet-transports"
      title="Transports"
      description="Collect through your configuration management (Ansible AWX / AAP, Salt or AWS Systems Manager) instead of SSH. Policies choose one in Collect through."
      actions={
        <Button size="sm" variant="outline" className="cursor-pointer" ref={addButton} id="fleet-add-transport" data-testid="fleet-add-transport"
          onClick={(e) => { opener.remember(e); setAdding(true); }}>
          <Plus className="h-4 w-4 mr-1.5" /> Add transport
        </Button>
      }
    >
      {list.isLoading && <LoadingBlock />}
      {!data && list.isError && <ErrorBlock error={list.error} onRetry={() => list.refetch()} />}
      {data && data.transports.length === 0 && (
        <EmptyState title="No transport yet" body="Add one to collect hosts your Ansible, Salt or SSM already manages, with no SSH login from a scan node." />
      )}
      {data && data.transports.length > 0 && (
        // below 672 px the kind, endpoint, secrets and status fold under the name, so Test and Delete stay on screen
        <div className="@container">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead className="hidden @2xl:table-cell">Kind <InfoTip id="fleet.tr.col.kind" /></TableHead>
                  <TableHead className="hidden @2xl:table-cell">Where <InfoTip id="fleet.tr.col.where" /></TableHead>
                  <TableHead className="hidden @2xl:table-cell">Secrets stored <InfoTip id="fleet.tr.col.secrets" /></TableHead>
                  <TableHead>Status <InfoTip id="fleet.tr.col.status" /></TableHead>
                  <TableHead className="hidden @2xl:table-cell">Used by <InfoTip id="fleet.tr.col.used_by" /></TableHead>
                  <TableHead><span className="sr-only">Actions</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.transports.map((t) => {
                  const secrets = t.secrets_set.length ? t.secrets_set.join(", ") : "none";
                  const used = t.used_by.length ? t.used_by.map((s) => s.name).join(", ") : "nothing yet";
                  return (
                    <TableRow key={t.id} data-testid={`fleet-transport-${t.id}`}>
                      <TableCell className="font-medium wrap-anywhere">
                        {t.name}
                        {!t.enabled && <StatusBadge tone="zinc" className="ml-2">Disabled</StatusBadge>}
                        <span className="block @2xl:hidden text-xs font-normal text-zinc-600 dark:text-zinc-400 wrap-anywhere">
                          {TRANSPORT_LABEL[t.kind]} · {endpointText(t)} · secrets: {secrets} · used by {used}
                        </span>
                      </TableCell>
                      <TableCell className="hidden @2xl:table-cell">{TRANSPORT_LABEL[t.kind]}</TableCell>
                      <TableCell className="hidden @2xl:table-cell text-sm wrap-anywhere max-w-[320px]">{endpointText(t)}</TableCell>
                      <TableCell className="hidden @2xl:table-cell text-sm">{secrets}</TableCell>
                      <TableCell className="text-sm max-w-[280px]">
                        {canTest(t.kind) ? (
                          <>
                            <StatusBadge tone={STATUS_TONE[t.last_validation_status] ?? "amber"}>
                              {t.last_validation_status === "never" ? "Not tested" : t.last_validation_status === "passed" ? "Passed" : "Failed"}
                            </StatusBadge>
                            {t.last_validation_summary && <span className="block text-xs text-zinc-600 dark:text-zinc-400 mt-1 wrap-anywhere">{t.last_validation_summary}</span>}
                          </>
                        ) : (
                          <span className="text-xs text-zinc-600 dark:text-zinc-400">{TEST_ELSEWHERE}</span>
                        )}
                      </TableCell>
                      <TableCell className="hidden @2xl:table-cell text-sm wrap-anywhere">{used}</TableCell>
                      <TableCell className="text-right whitespace-nowrap">
                        {canTest(t.kind) && (
                          <Button variant="ghost" size="icon" className="cursor-pointer" aria-label={`Test ${t.name}`} disabled={test.isPending} onClick={() => test.mutate(t)}>
                            <ShieldCheck className="h-4 w-4" />
                          </Button>
                        )}
                        <Button variant="ghost" size="icon" className="cursor-pointer" aria-label={`Delete ${t.name}`} onClick={(e) => { opener.remember(e); setRemoving(t); }}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </div>
      )}
      {data && (
        <div className="mt-6 space-y-2" data-testid="fleet-transport-files">
          <h4 className="text-sm font-semibold">Files to install on your side</h4>
          <p className="text-xs text-zinc-600 dark:text-zinc-400">
            {data.release
              ? `zs-collect ${data.release.version} · signed with key ${data.release.fingerprint}. AWX: the Ansible collection and the SSH CA trust role; Salt: the state and the SSH CA trust state; SSM: the document, the role template and the SSH CA trust document.`
              : "No verified zs-collect release is active in this deployment yet: the role template, the signing key and the SSH CA trust installers can be made. The collector files wait for a release."}
          </p>
          <div className="flex flex-wrap gap-2">
            {FILES.map((name) => {
              // made from the zs-collect release: without one the API can only refuse it, so it is not offered
              const waiting = !data.release && NEEDS_RELEASE.has(name);
              return (
                <Button key={name} size="sm" variant="outline" className="cursor-pointer" disabled={fetchFile.isPending || waiting}
                  title={waiting ? "Available once a verified zs-collect release is active in this deployment" : undefined}
                  onClick={() => fetchFile.mutate(name)}>
                  <FileText className="h-3.5 w-3.5 mr-1" />{name}
                </Button>
              );
            })}
          </div>
          {fileError && <p className="text-sm text-red-600 dark:text-red-400" role="alert">{fileError}</p>}
          {file && (
            <div className="space-y-1" data-testid="fleet-transport-file">
              <span className="font-mono text-xs">{file.name}</span>
              <CodeSnippet code={file.text} language={file.name === "ssm-role-cfn" ? "yaml" : "json"} />
            </div>
          )}
        </div>
      )}
      {adding && <TransportForm teamId={teamId} onDone={() => setAdding(false)} onCloseAutoFocus={opener.onCloseAutoFocus} />}
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(v) => !v && setRemoving(null)}
        title={`Delete ${removing?.name ?? "this transport"}?`}
        onCloseAutoFocus={opener.onCloseAutoFocus}
        description="Its secrets are erased. A transport that a source still uses cannot be deleted: change or delete the policy that uses it first."
        confirmLabel="Delete"
        destructive
        pending={remove.isPending}
        onConfirm={() => removing && remove.mutate(removing.id)}
      />
    </SectionCard>
  );
}
