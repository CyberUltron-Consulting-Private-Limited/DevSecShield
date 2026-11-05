"use client";

// Settings > Integrations: ServiceNow, syslog (SIEM), Splunk HEC, signed webhook and OSCAL push. One card per
// integration (form, test button, queue state), the webhook signature check to copy, and the delivery log with the
// dead-letter list. Secrets are write-only; a blank secret field keeps the stored one. Admins change, members read.

import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, FlaskConical, KeyRound, Loader2, RotateCw, Save, Trash2 } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import {
  Checkbox2,
  CodeSnippet,
  ErrorBlock,
  Field,
  LoadingBlock,
  SectionCard,
  StatusBadge,
  type Tone,
} from "@/components/cbom/sources/shared";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { getTeam } from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
import {
  deleteIntegration,
  integrationKeys,
  listDeliveries,
  listIntegrations,
  retryDeliveries,
  saveIntegration,
  testIntegration,
  type Delivery,
  type Integration,
  type IntegrationEventKind,
  type IntegrationKind,
} from "@/utils/api/integrations";

type Form = Record<string, string>;
type FieldDef = {
  key: string;
  label: string;
  type?: "text" | "number" | "select" | "textarea";
  options?: [string, string][];
  hint?: string;
  placeholder?: string;
  show?: (f: Form) => boolean;
  required?: boolean;
};

const EVENT_LABEL: Record<IntegrationEventKind, string> = {
  opened: "Finding opened",
  resolved: "Finding resolved",
  new_asset: "New asset",
  removed_asset: "Asset removed",
  cert_renewed: "Certificate renewed",
  cert_expiring: "Certificate expiring (30 days)",
  schedule_skipped: "Scheduled run skipped",
  scan_finished: "Run or code scan finished",
};

const CA_FIELD: FieldDef = {
  key: "ca_pem", label: "CA certificate (optional)", type: "textarea",
  hint: "PEM of the CA that signed the destination's certificate, when it is not publicly trusted. Certificates are always verified.",
};

const FIELDS: Record<IntegrationKind, FieldDef[]> = {
  servicenow: [
    { key: "instance_url", label: "Instance URL", placeholder: "https://acme.service-now.com", required: true },
    { key: "table", label: "Table", placeholder: "incident", hint: "incident, or sn_vul_vulnerable_item with Vulnerability Response" },
    { key: "auth", label: "Authentication", type: "select", options: [["basic", "User and password"], ["oauth", "OAuth client credentials"]] },
    { key: "username", label: "User", show: (f) => (f.auth || "basic") === "basic", required: true },
    { key: "client_id", label: "OAuth client ID", show: (f) => f.auth === "oauth", required: true },
    { key: "assignment_group", label: "Assignment group (optional)" },
    { key: "category", label: "Category (optional)" },
    { key: "resolve_state", label: "Resolved state value", placeholder: "6", hint: "incident: 6 (Resolved)" },
    { key: "close_code", label: "Resolution code", placeholder: "Solution provided" },
    { key: "min_severity", label: "Open records from severity", type: "select",
      options: [["Low", "Low and above"], ["Medium", "Medium and above"], ["High", "High and above"], ["Critical", "Critical only"]],
      hint: "Resolving a record always goes through" },
    { key: "correlation_field", label: "Correlation field", placeholder: "correlation_id",
      hint: "One record per finding: looked up by this field before a record is created" },
    { key: "cmdb_table", label: "CMDB table (import)", placeholder: "cmdb_ci_server" },
    { key: "cmdb_query", label: "CMDB filter (encoded query, optional)", placeholder: "operational_status=1" },
    { key: "cmdb_mapping.host", label: "CMDB host fields", placeholder: "fqdn, ip_address, host_name, name" },
    { key: "cmdb_mapping.owner", label: "CMDB owner field", placeholder: "owned_by" },
    { key: "cmdb_mapping.application", label: "CMDB application field", placeholder: "u_application" },
    { key: "cmdb_mapping.environment", label: "CMDB environment field", placeholder: "used_for" },
    { key: "cmdb_mapping.criticality", label: "CMDB criticality field (optional)" },
    { key: "cmdb_mapping.exposure", label: "CMDB exposure field (optional)" },
    { key: "cmdb_mapping.data_classification", label: "CMDB data classification field (optional)" },
    CA_FIELD,
  ],
  syslog: [
    { key: "host", label: "Collector host", placeholder: "siem.corp.local", required: true },
    { key: "transport", label: "Transport", type: "select",
      options: [["tls", "TLS (RFC 5425, port 6514)"], ["tcp", "TCP (octet counting)"], ["udp", "UDP (RFC 5426, no confirmation)"]] },
    { key: "port", label: "Port (optional)", type: "number", hint: "Default 6514 for TLS, 514 for TCP and UDP" },
    { key: "format", label: "Message format", type: "select", options: [["cef", "CEF (ArcSight)"], ["json", "JSON"]] },
    { key: "facility", label: "Facility", type: "number", placeholder: "16", hint: "16 = local0" },
    { key: "sender_name", label: "Sender name (HOSTNAME field)", placeholder: "zeroshield" },
    { ...CA_FIELD, show: (f) => (f.transport || "tls") === "tls" },
  ],
  splunk_hec: [
    { key: "url", label: "HEC URL", placeholder: "https://splunk.corp.local:8088", required: true },
    { key: "index", label: "Index (optional)" },
    { key: "sourcetype", label: "Sourcetype", placeholder: "zeroshield:cbom" },
    { key: "source", label: "Source", placeholder: "zeroshield" },
    CA_FIELD,
  ],
  webhook: [
    { key: "url", label: "Receiver URL", placeholder: "https://soar.corp.local/hooks/zeroshield", required: true },
    CA_FIELD,
  ],
  oscal: [
    { key: "url", label: "GRC endpoint URL", placeholder: "https://grc.corp.local/api/oscal", required: true },
    CA_FIELD,
  ],
};

const DESCRIPTION: Record<IntegrationKind, string> = {
  servicenow: "Opens one record per new finding (de-duplicated by correlation id) and resolves it when a later complete run no longer finds it. Also the source for the CMDB import on CBOM Sources.",
  syslog: "Sends every event as an RFC 5424 syslog message with a CEF or JSON payload to your SIEM or SOAR.",
  splunk_hec: "Sends every event to a Splunk HTTP Event Collector (batched JSON events).",
  webhook: "POSTs every event as JSON, signed with HMAC-SHA256 over the timestamp and the body.",
  oscal: "When a run or a CBOM code scan finishes, pushes its OSCAL 1.2.3 assessment results (schema-validated), signed like the webhook.",
};

function secretsFor(kind: IntegrationKind, f: Form): { key: string; label: string }[] {
  if (kind === "servicenow") return f.auth === "oauth" ? [{ key: "client_secret", label: "OAuth client secret" }] : [{ key: "password", label: "Password" }];
  if (kind === "splunk_hec") return [{ key: "token", label: "HEC token" }];
  if (kind === "webhook" || kind === "oscal") return [{ key: "signing_secret", label: "Signing secret (16+ characters)" }];
  return [];
}

function formFrom(integration: Integration): Form {
  const out: Form = {};
  for (const [k, v] of Object.entries(integration.config ?? {})) {
    if (k === "cmdb_mapping" && v && typeof v === "object") {
      for (const [mk, mv] of Object.entries(v as Record<string, unknown>)) {
        out[`cmdb_mapping.${mk}`] = Array.isArray(mv) ? mv.join(", ") : mv == null ? "" : String(mv);
      }
    } else if (k !== "events" && v != null && typeof v !== "object") {
      out[k] = String(v);
    }
  }
  return out;
}

export function configFrom(kind: IntegrationKind, f: Form, events: IntegrationEventKind[] | null): Record<string, unknown> {
  const config: Record<string, unknown> = {};
  const mapping: Record<string, unknown> = {};
  for (const def of FIELDS[kind]) {
    if (def.show && !def.show(f)) continue;
    const raw = (f[def.key] ?? "").trim();
    if (raw === "") continue;
    const value = def.type === "number" ? Number(raw) : raw;
    if (def.key.startsWith("cmdb_mapping.")) {
      const sub = def.key.slice("cmdb_mapping.".length);
      mapping[sub] = sub === "host" ? raw.split(",").map((x) => x.trim()).filter(Boolean) : value;
    } else {
      config[def.key] = value;
    }
  }
  if (kind === "servicenow" && Object.keys(mapping).length) config.cmdb_mapping = mapping;
  if (kind !== "oscal" && events) config.events = events;
  return config;
}

function randomSecret(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function ago(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleString() : "—";
}

function IntegrationCard({ teamId, integration, isAdmin, snippet }: {
  teamId: number;
  integration: Integration;
  isAdmin: boolean;
  snippet: string;
}) {
  const queryClient = useQueryClient();
  const kind = integration.kind;
  const [form, setForm] = useState<Form>(() => formFrom(integration));
  const [enabled, setEnabled] = useState(integration.enabled);
  const [events, setEvents] = useState<IntegrationEventKind[]>(
    (integration.config?.events as IntegrationEventKind[] | undefined) ?? integration.default_events);
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [shownSecret, setShownSecret] = useState<string | null>(null);
  const set = (key: string, value: string) => setForm((f) => ({ ...f, [key]: value }));
  const refresh = () => queryClient.invalidateQueries({ queryKey: integrationKeys.all(teamId) });

  const save = useMutation({
    mutationFn: () => saveIntegration(teamId, kind, {
      enabled, config: configFrom(kind, form, kind === "oscal" ? null : events),
      secrets: Object.fromEntries(Object.entries(secrets).filter(([, v]) => v !== "")),
      expected_version: integration.row_version,
    }),
    onSuccess: () => {
      toast.success(`${integration.label} saved`);
      setSecrets({});
      setShownSecret(null);
      refresh();
    },
    onError: (e) => showErrorToast(e),
  });
  const test = useMutation({
    mutationFn: () => testIntegration(teamId, kind),
    onSuccess: (r) => {
      // syslog over UDP: sent, but nothing can confirm it arrived (a port with no listener looks the same)
      if (r.ok && r.confirmed === false) toast.warning(`Test sent (unconfirmed): ${r.message}`);
      else if (r.ok) toast.success(`Test passed: ${r.message}`);
      else toast.error(`Test failed: ${r.message}`);
      refresh();
    },
    onError: (e) => showErrorToast(e),
  });
  const remove = useMutation({
    mutationFn: () => deleteIntegration(teamId, kind),
    onSuccess: () => {
      toast.success(`${integration.label} removed`);
      refresh();
    },
    onError: (e) => showErrorToast(e),
  });

  const lastTest = integration.last_test;
  const testTone: Tone = lastTest?.status === "ok" ? "green" : lastTest?.status === "failed" ? "red"
    : lastTest?.status === "unconfirmed" ? "amber" : "zinc";
  const testLabel = lastTest?.status === "ok" ? "passed" : lastTest?.status === "unconfirmed" ? "sent (unconfirmed)" : "failed";
  const disabled = !isAdmin || save.isPending;
  const prefix = `int-${kind}`;
  return (
    <SectionCard
      id={prefix}
      title={
        <span className="flex flex-wrap items-center gap-2">
          {integration.label}
          <StatusBadge tone={integration.enabled ? "green" : "zinc"}>{integration.enabled ? "On" : integration.configured ? "Off" : "Not set up"}</StatusBadge>
          {lastTest && lastTest.status !== "never" && (
            <StatusBadge tone={testTone} title={lastTest.message ?? undefined}>Test {testLabel}</StatusBadge>
          )}
          {(integration.queue.pending ?? 0) > 0 && <StatusBadge tone="blue">{integration.queue.pending} queued</StatusBadge>}
          {(integration.queue.dead ?? 0) > 0 && <StatusBadge tone="red">{integration.queue.dead} dead-lettered</StatusBadge>}
        </span>
      }
      description={DESCRIPTION[kind]}
    >
      <div className="space-y-4" data-testid={prefix}>
        {integration.last_error && (
          <p className="text-sm text-amber-600 dark:text-amber-400" role="status">
            {/* no next attempt: the destination answered but refused every event of the last batch (dead-lettered) */}
            {integration.next_attempt_at ? "Delivery is backing off" : "Last delivery problem"}: {integration.last_error}
            {integration.next_attempt_at ? ` (next attempt ${ago(integration.next_attempt_at)})` : ""}
          </p>
        )}
        {lastTest?.message && lastTest.status !== "never" && (
          <p className="text-xs text-zinc-500">Last test {ago(lastTest.at)}: {lastTest.message}</p>
        )}
        <Checkbox2 id={`${prefix}-enabled`} checked={enabled} onChange={(v) => isAdmin && setEnabled(v)}>
          Forward events to {integration.label}
        </Checkbox2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {FIELDS[kind].filter((d) => !d.show || d.show(form)).map((def) => {
            const id = `${prefix}-${def.key.replace(".", "-")}`;
            const value = form[def.key] ?? "";
            if (def.type === "select") {
              return (
                <Field key={def.key} label={def.label} htmlFor={id} hint={def.hint}>
                  <Select value={value || def.options![0][0]} onValueChange={(v) => set(def.key, v)} disabled={disabled}>
                    <SelectTrigger id={id} className="w-full cursor-pointer"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {def.options!.map(([v, l]) => <SelectItem key={v} value={v} className="cursor-pointer">{l}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </Field>
              );
            }
            if (def.type === "textarea") {
              return (
                <Field key={def.key} label={def.label} htmlFor={id} hint={def.hint} className="md:col-span-2">
                  <Textarea id={id} value={value} onChange={(e) => set(def.key, e.target.value)} disabled={disabled}
                            spellCheck={false} className="font-mono text-xs min-h-[72px]" placeholder="-----BEGIN CERTIFICATE-----" />
                </Field>
              );
            }
            return (
              <Field key={def.key} label={def.label} htmlFor={id} hint={def.hint} required={def.required}>
                <Input id={id} value={value} inputMode={def.type === "number" ? "numeric" : undefined}
                       placeholder={def.placeholder} onChange={(e) => set(def.key, e.target.value)} disabled={disabled} />
              </Field>
            );
          })}
          {secretsFor(kind, form).map((s) => {
            const isSet = integration.secrets_set.includes(s.key);
            const id = `${prefix}-secret-${s.key}`;
            return (
              <Field key={s.key} label={s.label} htmlFor={id} required={!isSet}
                     hint="Encrypted at rest; never shown again. Changing the URL, host or user clears it unless you enter it again.">
                <div className="flex gap-2">
                  <Input id={id} type="password" autoComplete="new-password" value={secrets[s.key] ?? ""} disabled={disabled}
                         placeholder={isSet ? "Saved. Leave blank to keep it" : ""}
                         onChange={(e) => setSecrets((x) => ({ ...x, [s.key]: e.target.value }))} />
                  {s.key === "signing_secret" && isAdmin && (
                    <Button type="button" variant="outline" className="cursor-pointer shrink-0" onClick={() => {
                      const value = randomSecret();
                      setSecrets((x) => ({ ...x, signing_secret: value }));
                      setShownSecret(value);
                    }}>
                      <KeyRound className="h-4 w-4 mr-1.5" />Generate
                    </Button>
                  )}
                </div>
              </Field>
            );
          })}
        </div>
        {shownSecret && (
          <div className="space-y-1">
            <p className="text-xs text-amber-600 dark:text-amber-400">Copy this secret to your receiver now: after saving it is never shown again.</p>
            <CodeSnippet code={shownSecret} language="text" />
          </div>
        )}
        {kind !== "oscal" && (
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium text-zinc-800 dark:text-zinc-200">Events</legend>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
              {integration.allowed_events.map((e) => (
                <Checkbox2 key={e} id={`${prefix}-event-${e}`} checked={events.includes(e)}
                           onChange={(v) => isAdmin && setEvents((cur) => (v ? [...cur, e] : cur.filter((x) => x !== e)))}>
                  {EVENT_LABEL[e]}
                </Checkbox2>
              ))}
            </div>
          </fieldset>
        )}
        {(kind === "webhook" || kind === "oscal") && (
          <details className="text-sm">
            <summary className="cursor-pointer text-blue-600 dark:text-blue-400">Verify the signature on your receiver</summary>
            <p className="text-xs text-zinc-500 my-2">
              Headers: X-ZS-Event-Id (same on every retry: drop duplicates by it), X-ZS-Event-Type, X-ZS-Timestamp and
              X-ZS-Signature (v1=HMAC-SHA256 of &quot;timestamp.body&quot;). Reject signatures that do not match or are older than five minutes.
            </p>
            <CodeSnippet code={snippet} language="python" />
          </details>
        )}
        {isAdmin && (
          <div className="flex flex-wrap gap-2">
            <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={save.isPending}
                    onClick={() => save.mutate()} data-testid={`${prefix}-save`}>
              {save.isPending ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <Save className="h-4 w-4 mr-1.5" />}
              Save
            </Button>
            <Button variant="outline" className="cursor-pointer" disabled={!integration.configured || test.isPending}
                    onClick={() => test.mutate()} data-testid={`${prefix}-test`}
                    title={kind === "servicenow" ? "Reads one record of the table; creates nothing" : "Sends a test event"}>
              {test.isPending ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <FlaskConical className="h-4 w-4 mr-1.5" />}
              Send test
            </Button>
            {integration.configured && (
              <Button variant="outline" className="cursor-pointer text-red-500" disabled={remove.isPending}
                      onClick={() => { if (window.confirm(`Remove ${integration.label} and its delivery log?`)) remove.mutate(); }}>
                <Trash2 className="h-4 w-4 mr-1.5" />Remove
              </Button>
            )}
          </div>
        )}
      </div>
    </SectionCard>
  );
}

const STATUS_TONE: Record<Delivery["status"], Tone> = { pending: "blue", delivered: "green", dead: "red" };

function DeliveryLog({ teamId, isAdmin, labels }: { teamId: number; isAdmin: boolean; labels: Record<string, string> }) {
  const queryClient = useQueryClient();
  const [kind, setKind] = useState("all");
  const [status, setStatus] = useState("all");
  const q = useQuery({
    queryKey: integrationKeys.deliveries(teamId, kind, status),
    queryFn: () => listDeliveries(teamId, { kind: kind === "all" ? undefined : kind, status: status === "all" ? undefined : status, limit: 100 }),
    placeholderData: keepPreviousData,
    refetchInterval: 15000,
  });
  const retry = useMutation({
    mutationFn: (body: { ids?: number[]; kind?: string; all_dead?: boolean }) => retryDeliveries(teamId, body),
    onSuccess: (r) => {
      toast.success(`${r.requeued} queued again`);
      queryClient.invalidateQueries({ queryKey: integrationKeys.all(teamId) });
    },
    onError: (e) => showErrorToast(e),
  });
  const rows = q.data?.deliveries ?? [];
  return (
    <SectionCard
      title="Delivery log"
      description="Every event is delivered at least once, in order per destination, with the same event id on each retry. A failing destination is retried with back-off for 24 hours; events it refused, or that could not be delivered in time, are dead-lettered here."
      actions={
        <div className="flex flex-wrap gap-2">
          <Select value={kind} onValueChange={setKind}>
            <SelectTrigger className="w-[180px] cursor-pointer" aria-label="Integration"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all" className="cursor-pointer">All integrations</SelectItem>
              {Object.entries(labels).map(([k, l]) => <SelectItem key={k} value={k} className="cursor-pointer">{l}</SelectItem>)}
            </SelectContent>
          </Select>
          <Select value={status} onValueChange={setStatus}>
            <SelectTrigger className="w-[150px] cursor-pointer" aria-label="Status"><SelectValue /></SelectTrigger>
            <SelectContent>
              {["all", "pending", "delivered", "dead"].map((s) => (
                <SelectItem key={s} value={s} className="cursor-pointer">{s === "all" ? "Any status" : s === "dead" ? "Dead-lettered" : s[0].toUpperCase() + s.slice(1)}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          {isAdmin && status === "dead" && kind !== "all" && rows.length > 0 && (
            <Button variant="outline" className="cursor-pointer" disabled={retry.isPending}
                    onClick={() => retry.mutate({ kind, all_dead: true })}>
              <RotateCw className="h-4 w-4 mr-1.5" />Retry all
            </Button>
          )}
        </div>
      }
    >
      {q.isLoading ? <LoadingBlock /> : q.isError ? <ErrorBlock onRetry={() => q.refetch()} /> : rows.length === 0 ? (
        <p className="text-sm text-zinc-500">No deliveries yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <Table data-testid="delivery-log">
            <TableHeader>
              <TableRow>
                <TableHead>Queued</TableHead>
                <TableHead>Integration</TableHead>
                <TableHead>Event</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Attempts</TableHead>
                <TableHead>Result</TableHead>
                {isAdmin && <TableHead />}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((d) => (
                <TableRow key={d.id}>
                  <TableCell className="whitespace-nowrap text-xs">{ago(d.queued_at)}</TableCell>
                  <TableCell className="text-xs">{labels[d.kind] ?? d.kind}</TableCell>
                  <TableCell className="text-xs max-w-[280px]">
                    <span className="font-mono">{d.event_type}</span>
                    {d.code && <span className="font-mono"> · {d.code}</span>}
                    {(d.asset || d.source) && <span className="block text-zinc-500 truncate">{d.asset ?? d.source}</span>}
                  </TableCell>
                  <TableCell><StatusBadge tone={STATUS_TONE[d.status]}>{d.status === "dead" ? "dead-lettered" : d.status}</StatusBadge></TableCell>
                  <TableCell className="text-xs">{d.attempts}</TableCell>
                  <TableCell className="text-xs max-w-[320px] break-words">
                    {d.result ?? "—"}{d.external_ref ? ` (${d.external_ref})` : ""}
                  </TableCell>
                  {isAdmin && (
                    <TableCell>
                      {d.status === "dead" && (
                        <Button size="sm" variant="outline" className="cursor-pointer" disabled={retry.isPending}
                                onClick={() => retry.mutate({ ids: [d.id] })}>Retry</Button>
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
  );
}

export default function IntegrationsPage({ teamId }: { teamId: number }) {
  const team = useQuery({ queryKey: ["team-details", String(teamId)], queryFn: () => getTeam(teamId) });
  const q = useQuery({ queryKey: integrationKeys.list(teamId), queryFn: () => listIntegrations(teamId), refetchInterval: 30000 });
  const labels = useMemo(() => Object.fromEntries((q.data?.integrations ?? []).map((i) => [i.kind, i.label])), [q.data]);
  const isAdmin = Boolean(team.data?.is_team_admin);
  return (
    <div className="flex min-h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 min-w-0 p-4 sm:p-8 overflow-auto">
        <div className="max-w-6xl mx-auto space-y-6">
          <div>
            <Link href={`/${teamId}/settings`} className="inline-flex items-center gap-1.5 text-sm text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white mb-2">
              <ArrowLeft className="h-4 w-4" />Team settings
            </Link>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">Integrations</h1>
            <p className="text-zinc-600 dark:text-zinc-400 max-w-3xl">
              Forward CBOM findings, drift, certificate expiry and finished scans to ServiceNow, your SIEM, a signed webhook or a
              GRC tool (OSCAL). {isAdmin ? "" : "Only team admins can change integrations."}
            </p>
            {q.data && (
              <p className="text-xs text-zinc-500 mt-2 max-w-3xl">
                Destinations on private networks (an on-premises Splunk or syslog collector) must be allowed by the ZeroShield
                operator in {q.data.private_destinations.env}{q.data.private_destinations.configured ? " (some are allowed on this server)" : " (none are allowed on this server)"}.
                Loopback, link-local and cloud metadata addresses are never contacted.
              </p>
            )}
          </div>
          {q.isLoading ? <LoadingBlock /> : q.isError || !q.data ? <ErrorBlock onRetry={() => q.refetch()} /> : (
            <>
              {q.data.integrations.map((integration) => (
                // keyed by the saved version: a save (here or elsewhere) reloads the form; a background refetch does not
                <IntegrationCard key={`${integration.kind}-${integration.row_version ?? 0}-${integration.configured}`}
                                 teamId={teamId} integration={integration} isAdmin={isAdmin}
                                 snippet={q.data.webhook_verify_snippet} />
              ))}
              <DeliveryLog teamId={teamId} isAdmin={isAdmin} labels={labels} />
            </>
          )}
        </div>
      </div>
    </div>
  );
}
