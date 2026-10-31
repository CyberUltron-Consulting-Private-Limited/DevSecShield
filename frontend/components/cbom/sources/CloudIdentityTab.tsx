"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, ExternalLink, Loader2, MoreVertical, Pencil, Plus, ShieldCheck, Trash2, X } from "lucide-react";
import { Fragment, useState, type ReactNode } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import {
  createCbomSource,
  deleteCbomSource,
  getCbomAwsTemplate,
  getCbomSourcesSettings,
  listCbomScanNodes,
  listCbomSources,
  testCbomSource,
  updateCbomSource,
  updateCbomSourcesSettings,
  type CbomAwsCheck,
  type CbomScanNode,
  type CbomSource,
  type CbomSourcesSettings,
  type CbomSourceSaveResponse,
  type CbomTestResponse,
} from "@/utils/backend_api";

import { cbomSourcesKeys } from "./keys";
import { formatDateTime, pluralize, readTextFile, splitLines } from "./logic";
import {
  ChoiceCards,
  CodeSnippet,
  ConfirmDialog,
  CopyButton,
  EmptyState,
  ErrorBlock,
  Field,
  JobStatusBadge,
  LoadingBlock,
  NodeSelect,
  SecretField,
  SectionCard,
  StatusBadge,
  TestStatusBadge,
  Truncate,
  usePolledJob,
  type Tone,
} from "./shared";

// ---------------------------------------------------------------------------- constants
type Provider = "aws" | "azure" | "gcp";
type AwsScope = "account" | "organization";
type CaProvider = "adcs" | "aws_private_ca" | "venafi" | "keyfactor" | "digicert" | "ejbca" | "sectigo" | "other";
type IdpProvider = "entra_id" | "okta" | "keycloak";
type MetadataProvider = "saml_metadata" | "oidc_discovery";

const PROVIDERS: { value: Provider; label: string; description: string }[] = [
  { value: "aws", label: "AWS", description: "About five minutes; no keys are exchanged." },
  { value: "azure", label: "Azure", description: "Uses an app registration and its client secret." },
  { value: "gcp", label: "Google Cloud", description: "Uses a service account and its JSON key." },
];
const PROVIDER_OF_KIND: Record<string, Provider> = { aws_account: "aws", azure_subscription: "azure", gcp_project: "gcp" };

interface CaRow {
  key: string;
  providers: CaProvider[];
  label: string;
  detail?: string;
}
const CA_ROWS: CaRow[] = [
  { key: "adcs", providers: ["adcs"], label: "Microsoft AD CS", detail: "through a scan node" },
  { key: "aws_private_ca", providers: ["aws_private_ca"], label: "AWS Private CA", detail: "through a connected AWS account" },
  { key: "venafi", providers: ["venafi"], label: "Venafi / CyberArk Certificate Manager" },
  { key: "keyfactor", providers: ["keyfactor"], label: "Keyfactor" },
  { key: "digicert", providers: ["digicert"], label: "DigiCert CertCentral" },
  { key: "other", providers: ["ejbca", "sectigo", "other"], label: "EJBCA, Sectigo or other" },
];
const CA_DEFAULT_NAME: Record<CaProvider, string> = {
  adcs: "AD CS",
  aws_private_ca: "AWS Private CA",
  venafi: "Venafi",
  keyfactor: "Keyfactor",
  digicert: "DigiCert",
  ejbca: "EJBCA",
  sectigo: "Sectigo",
  other: "Other CA",
};
const CA_OTHER_LABEL: Record<string, string> = { ejbca: "EJBCA", sectigo: "Sectigo", other: "Other CA or CLM" };

interface IdpRow {
  provider: IdpProvider;
  label: string;
  detail?: string;
  defaultName: string;
}
const IDP_ROWS: IdpRow[] = [
  { provider: "entra_id", label: "Microsoft Entra ID", detail: "Application.Read.All, read-only", defaultName: "Entra ID" },
  { provider: "okta", label: "Okta", defaultName: "Okta" },
  { provider: "keycloak", label: "Keycloak", defaultName: "Keycloak" },
];
const METADATA_LABEL: Record<MetadataProvider, string> = { saml_metadata: "SAML metadata", oidc_discovery: "OIDC discovery" };

const CHECK_BADGE: Record<CbomAwsCheck["status"], [Tone, string]> = {
  pass: ["green", "Pass"],
  fail: ["red", "Fail"],
  skipped: ["zinc", "Skipped"],
  error: ["amber", "Error"],
};

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;
const NAME_ERROR = "Use 1-64 letters, digits, spaces, dots, dashes or underscores, starting with a letter or digit.";
const ROLE_ARN_RE = /^arn:aws(-cn|-us-gov)?:iam::(\d{12}):role\/[A-Za-z0-9+=,.@_/-]{1,512}$/;
const REGION_RE = /^[a-z]{2}(-gov|-iso[a-z]?)?-[a-z]+-\d$/; // same as the server's AWS_REGION_RE
const GUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const GCP_PROJECT_RE = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const GCP_SA_RE = /^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/;
const LOGIN_RE = /^[A-Za-z0-9._@$\\-]{1,64}$/;
const DOMAIN_LABEL_RE = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/;
const MAX_DOMAINS = 200;
const CLOUDFORMATION_CONSOLE = "https://console.aws.amazon.com/cloudformation/home";
const NOT_AVAILABLE = "Validation is not available yet; collection is not available yet.";
// Cloud, CLM and IdP secrets never go to a scan node, so the node wording of the default hint would be wrong here.
const STORED_HINT = "Encrypted at rest by ZeroShield. Never shown again.";

// ---------------------------------------------------------------------------- helpers
function httpStatus(error: unknown): number | undefined {
  return (error as { response?: { status?: number } } | null)?.response?.status;
}

function cfgString(source: CbomSource | null | undefined, key: string): string {
  const value = source?.config?.[key];
  return typeof value === "string" ? value : "";
}

function cfgList(source: CbomSource | null | undefined, key: string): string[] {
  const value = source?.config?.[key];
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

function cfgNumber(source: CbomSource | null | undefined, key: string): number | null {
  const value = source?.config?.[key];
  return typeof value === "number" ? value : null;
}

function nameError(name: string): string | null {
  return NAME_RE.test(name.trim()) ? null : NAME_ERROR;
}

function awsAccountId(roleArn: string): string | null {
  return ROLE_ARN_RE.exec(roleArn.trim())?.[2] ?? null;
}

function httpsUrlError(value: string, label: string, maxLength = 512): string | null {
  const text = value.trim();
  if (!text) return `Enter the ${label}`;
  if (text.length > maxLength) return `The ${label} is longer than ${maxLength} characters`;
  if (/[\s'"`<>\\]/.test(text)) return `The ${label} contains characters that are not allowed`;
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return `Enter the full ${label}, starting with https://`;
  }
  if (url.protocol !== "https:" || !url.hostname) return `The ${label} must start with https://`;
  if (url.username || url.password) return `The ${label} must not contain a user name or password`;
  return null;
}

function normalizeDomain(raw: string): { value: string; error: string | null } {
  const value = raw.trim().toLowerCase().replace(/\.$/, "");
  if (!value) return { value, error: "Enter a domain such as example.com" };
  if (/[^\x00-\x7f]/.test(value)) return { value, error: null }; // internationalised names: the server converts and checks them
  const labels = value.split(".");
  if (value.length > 253 || labels.length < 2 || !labels.every((l) => DOMAIN_LABEL_RE.test(l)) || /^\d+$/.test(labels[labels.length - 1])) {
    return { value, error: `${raw.trim()} is not a domain name such as example.com` };
  }
  return { value, error: null };
}

/** A unique source name (the server enforces unique names per kind) that matches the name rule. */
function uniqueName(base: string, taken: string[]): string {
  const clean = base.replace(/[^A-Za-z0-9 ._-]/g, "-").replace(/^[^A-Za-z0-9]+/, "").slice(0, 60) || "source";
  const lower = new Set(taken.map((t) => t.toLowerCase()));
  if (!lower.has(clean.toLowerCase())) return clean;
  for (let i = 2; i < 100; i++) {
    const candidate = `${clean.slice(0, 60)}-${i}`;
    if (!lower.has(candidate.toLowerCase())) return candidate;
  }
  return `${clean.slice(0, 50)}-${Date.now().toString(36)}`;
}

function saveTextFile(text: string, filename: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

interface AwsConfig {
  scope: AwsScope;
  role_arn: string;
  regions: string[];
}

function sameAwsConfig(source: CbomSource, config: AwsConfig): boolean {
  const saved = { scope: cfgString(source, "scope") || "account", role_arn: cfgString(source, "role_arn"), regions: cfgList(source, "regions") };
  return JSON.stringify(saved) === JSON.stringify({ scope: config.scope, role_arn: config.role_arn, regions: config.regions });
}

interface ValidationView {
  sourceId: number;
  name: string;
  status: string;
  checks: CbomAwsCheck[];
  memberAccounts: number | null;
  at: string | null;
}

function isAwsResult(test: CbomSourceSaveResponse["test"] | CbomTestResponse | null | undefined): test is CbomTestResponse {
  return !!test && "checks" in test && Array.isArray(test.checks);
}

function viewFromTest(source: CbomSource, test: CbomTestResponse): ValidationView {
  return {
    sourceId: source.id,
    name: source.name,
    status: test.status,
    checks: test.checks ?? [],
    memberAccounts: typeof test.member_accounts === "number" ? test.member_accounts : null,
    at: test.validated_at ?? null,
  };
}

function viewFromSource(source: CbomSource | null | undefined): ValidationView | null {
  const checks = source?.last_test_result?.checks;
  if (!source || !Array.isArray(checks) || checks.length === 0) return null;
  const members = source.last_test_result.member_accounts;
  return {
    sourceId: source.id,
    name: source.name,
    status: source.last_test_status,
    checks,
    memberAccounts: typeof members === "number" ? members : null,
    at: source.last_test_at,
  };
}

function toastValidation(test: CbomTestResponse) {
  if (test.status === "passed") toast.success("All AWS checks passed");
  else if (test.status === "failed") toast.error("Some AWS checks did not pass; see Validation");
  else toast.warning("ZeroShield could not run every AWS check; see Validation");
}

function useInvalidate(teamId: number) {
  const queryClient = useQueryClient();
  return () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });
}

// ---------------------------------------------------------------------------- tab
export default function CloudIdentityTab({ teamId, onNavigate }: { teamId: number; onNavigate: (tab: string) => void }) {
  const invalidate = useInvalidate(teamId);
  const enabled = Number.isFinite(teamId);
  const [form, setForm] = useState<{ provider: Provider; source: CbomSource | null; nonce: number }>({ provider: "aws", source: null, nonce: 0 });
  const [validation, setValidation] = useState<ValidationView | null>(null);
  const [deleting, setDeleting] = useState<CbomSource | null>(null);
  const [caDialog, setCaDialog] = useState<{ row: CaRow; source: CbomSource | null; nonce: number } | null>(null);
  const [idpDialog, setIdpDialog] = useState<{ row: IdpRow; source: CbomSource | null; nonce: number } | null>(null);

  const settingsQuery = useQuery({
    queryKey: cbomSourcesKeys.settings(teamId),
    queryFn: () => getCbomSourcesSettings(teamId),
    enabled,
    retry: 1,
  });
  const cloudQuery = useQuery({
    queryKey: cbomSourcesKeys.sources(teamId, "cloud"),
    queryFn: () => listCbomSources(teamId, "cloud"),
    enabled,
    retry: 1,
    refetchInterval: 30000,
  });
  const identityQuery = useQuery({
    queryKey: cbomSourcesKeys.sources(teamId, "identity"),
    queryFn: () => listCbomSources(teamId, "identity"),
    enabled,
    retry: 1,
    // Faster while an AD CS connection test waits for its scan node.
    refetchInterval: (query) => (query.state.data?.sources.some((s) => s.last_test_status === "pending") ? 6000 : 30000),
  });
  const nodesQuery = useQuery({
    queryKey: cbomSourcesKeys.nodes(teamId),
    queryFn: () => listCbomScanNodes(teamId),
    enabled,
    retry: 1,
    refetchInterval: 30000,
  });

  const resetForm = (provider?: Provider) =>
    setForm((f) => ({ provider: provider ?? f.provider, source: null, nonce: f.nonce + 1 }));

  const awsMutation = useMutation({
    mutationFn: async (v: { source: CbomSource | null; name: string; config: AwsConfig }): Promise<{ source: CbomSource; test: CbomSourceSaveResponse["test"]; toasted: boolean }> => {
      if (v.source && v.name === v.source.name && sameAwsConfig(v.source, v.config)) {
        // Nothing changed: validate the saved account (testCbomSource toasts the outcome itself).
        return { source: v.source, test: await testCbomSource(teamId, v.source.id), toasted: true };
      }
      const data = v.source
        ? await updateCbomSource(teamId, v.source.id, { name: v.name, config: v.config, expected_version: v.source.row_version, test_after_save: true })
        : await createCbomSource(teamId, { kind: "aws_account", name: v.name, config: v.config, test_after_save: true });
      return { ...data, toasted: false };
    },
    onSuccess: (data) => {
      // Keep editing the saved account, so fixing the role and validating again updates it instead of adding a copy.
      setForm((f) => ({ provider: "aws", source: data.source, nonce: f.nonce }));
      if (isAwsResult(data.test)) {
        setValidation(viewFromTest(data.source, data.test));
        if (!data.toasted) toastValidation(data.test);
      }
    },
    onError: (err, v) => {
      if (v.source && (httpStatus(err) === 409 || httpStatus(err) === 404)) resetForm("aws");
    },
    onSettled: invalidate,
  });

  const testMutation = useMutation({
    mutationFn: (source: CbomSource) => testCbomSource(teamId, source.id),
    onSuccess: (data, source) => {
      if (isAwsResult(data)) setValidation(viewFromTest(source, data));
    },
    onSettled: invalidate,
  });

  const deleteMutation = useMutation({
    mutationFn: (source: CbomSource) => deleteCbomSource(teamId, source.id),
    onSuccess: (_data, source) => {
      setDeleting(null);
      if (form.source?.id === source.id) resetForm();
      if (validation?.sourceId === source.id) setValidation(null);
    },
    onSettled: invalidate,
  });

  if (settingsQuery.isLoading || cloudQuery.isLoading || identityQuery.isLoading) return <LoadingBlock />;
  const settings = settingsQuery.data;
  if (!settings || (cloudQuery.isError && !cloudQuery.data) || (identityQuery.isError && !identityQuery.data)) {
    return (
      <ErrorBlock
        onRetry={() => {
          settingsQuery.refetch();
          cloudQuery.refetch();
          identityQuery.refetch();
        }}
      />
    );
  }

  const cloudSources = cloudQuery.data?.sources ?? [];
  const identitySources = identityQuery.data?.sources ?? [];
  const nodes = nodesQuery.data?.nodes ?? [];
  const awsSources = cloudSources.filter((s) => s.kind === "aws_account");
  const caSources = identitySources.filter((s) => s.kind === "ca_connector");
  const idpSources = identitySources.filter((s) => s.kind === "idp");
  const metadataSources = idpSources.filter((s) => s.config?.provider === "saml_metadata" || s.config?.provider === "oidc_discovery");
  const identityNames = idpSources.map((s) => s.name);

  // A validation result stays shown while its account exists (or is the one being edited, right after it was created).
  const liveValidation =
    validation && (form.source?.id === validation.sourceId || cloudSources.some((s) => s.id === validation.sourceId)) ? validation : null;
  const editingAws = form.source && form.source.kind === "aws_account" ? awsSources.find((s) => s.id === form.source?.id) : undefined;
  const latestValidated = [...awsSources]
    .filter((s) => viewFromSource(s))
    .sort((a, b) => (b.last_test_at ?? "").localeCompare(a.last_test_at ?? ""))[0];
  const shownValidation = liveValidation ?? viewFromSource(editingAws) ?? viewFromSource(latestValidated);
  const validating = awsMutation.isPending || (testMutation.isPending && testMutation.variables?.kind === "aws_account");

  const startEdit = (source: CbomSource) => {
    setValidation(null);
    setForm((f) => ({ provider: PROVIDER_OF_KIND[source.kind] ?? "aws", source, nonce: f.nonce + 1 }));
    document.getElementById("cbom-cloud-connect")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const formKey = `${form.provider}-${form.source?.id ?? "new"}-${form.nonce}`;
  const provider = PROVIDERS.find((p) => p.value === form.provider) ?? PROVIDERS[0];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 items-start">
        <SectionCard
          id="cbom-cloud-connect"
          className="xl:col-span-2"
          title="Connect a cloud account"
          description={provider.description}
          actions={
            <div role="group" aria-label="Cloud provider" className="inline-flex flex-wrap gap-1 rounded-lg bg-zinc-100 dark:bg-zinc-800/60 p-1">
              {PROVIDERS.map((p) => {
                const on = form.provider === p.value;
                return (
                  <button
                    key={p.value}
                    type="button"
                    aria-pressed={on}
                    data-testid={`cloud-provider-${p.value}`}
                    onClick={() => !on && resetForm(p.value)}
                    className={cn(
                      "h-7 rounded-md px-3 text-sm font-medium cursor-pointer transition-colors",
                      on ? "bg-blue-600 text-white shadow-sm" : "text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white",
                    )}
                  >
                    {p.label}
                  </button>
                );
              })}
            </div>
          }
        >
          {form.provider === "aws" && (
            <AwsForm
              key={formKey}
              teamId={teamId}
              externalId={settings.aws_external_id}
              source={form.source}
              pending={awsMutation.isPending}
              onSubmit={(v) => awsMutation.mutate({ source: form.source, ...v })}
              onCancel={() => resetForm()}
            />
          )}
          {form.provider === "azure" && (
            <AzureForm key={formKey} teamId={teamId} source={form.source} onDone={() => resetForm()} onCancel={() => resetForm()} />
          )}
          {form.provider === "gcp" && (
            <GcpForm key={formKey} teamId={teamId} source={form.source} onDone={() => resetForm()} onCancel={() => resetForm()} />
          )}
        </SectionCard>

        <SectionCard
          title="Validation"
          description={
            shownValidation
              ? `${shownValidation.name}${shownValidation.at ? ` · last run ${formatDateTime(shownValidation.at)}` : ""}`
              : form.provider !== "aws"
                ? "Not available yet for this provider"
                : "Results appear after Validate connection"
          }
        >
          <ValidationPanel view={shownValidation} pending={validating} provider={form.provider} />
        </SectionCard>
      </div>

      <SectionCard title="Connected cloud accounts" description={pluralize(cloudSources.length, "account")}>
        {cloudSources.length === 0 ? (
          <EmptyState
            title="No cloud accounts yet"
            body="Connect an AWS account: ZeroShield assumes a read-only role in it with your external ID, so no keys are exchanged."
            action={
              <Button
                className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                onClick={() => {
                  resetForm("aws");
                  document.getElementById("cbom-cloud-connect")?.scrollIntoView({ behavior: "smooth", block: "start" });
                }}
              >
                <Plus className="h-4 w-4 mr-2" />
                Connect an AWS account
              </Button>
            }
          />
        ) : (
          <ScrollArea className="w-full border rounded-lg">
            <div className="min-w-max">
              <Table data-testid="cloud-accounts-table">
                <TableHeader>
                  <TableRow>
                    <TableHead>Account</TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Scope</TableHead>
                    <TableHead className="text-right">Regions</TableHead>
                    <TableHead>Last validated</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="w-12">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {cloudSources.map((s) => {
                    const busy = (testMutation.isPending && testMutation.variables?.id === s.id) || (awsMutation.isPending && form.source?.id === s.id);
                    return (
                      <TableRow key={s.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800">
                        <TableCell className="max-w-[260px]">
                          <AccountCell source={s} />
                        </TableCell>
                        <TableCell className="font-medium text-zinc-900 dark:text-white max-w-[200px]">
                          <Truncate text={s.name} />
                        </TableCell>
                        <TableCell className="text-zinc-600 dark:text-zinc-400">{scopeLabel(s)}</TableCell>
                        <TableCell className="text-right text-zinc-600 dark:text-zinc-400">
                          {s.kind === "aws_account" ? cfgList(s, "regions").length : "—"}
                        </TableCell>
                        <TableCell className="text-zinc-600 dark:text-zinc-400">{s.last_test_at ? formatDateTime(s.last_test_at) : "Never"}</TableCell>
                        <TableCell>
                          {busy ? <TestStatusBadge status="pending" /> : <TestStatusBadge status={s.last_test_status} title={s.last_test_summary} />}
                        </TableCell>
                        <TableCell>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon" className="cursor-pointer" aria-label={`Actions for ${s.name}`} data-testid={`cloud-account-actions-${s.id}`}>
                                <MoreVertical className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              {s.kind === "aws_account" ? (
                                <DropdownMenuItem className="cursor-pointer" disabled={busy} onSelect={() => testMutation.mutate(s)}>
                                  <ShieldCheck className="h-4 w-4" />
                                  Validate connection
                                </DropdownMenuItem>
                              ) : (
                                <DropdownMenuItem disabled>
                                  <ShieldCheck className="h-4 w-4" />
                                  Validation not available yet
                                </DropdownMenuItem>
                              )}
                              <DropdownMenuItem className="cursor-pointer" onSelect={() => startEdit(s)}>
                                <Pencil className="h-4 w-4" />
                                Edit
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem variant="destructive" className="cursor-pointer" onSelect={() => setDeleting(s)}>
                                <Trash2 className="h-4 w-4" />
                                Delete
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
            <ScrollBar orientation="horizontal" />
          </ScrollArea>
        )}
      </SectionCard>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 items-start">
        <SectionCard title="Certificates" description="Certificate authorities, CLM tools and the domains you own.">
          <div className="space-y-6">
            <CertDomains teamId={teamId} settings={settings} />
            <div className="space-y-2">
              <p className="text-sm font-medium text-zinc-900 dark:text-white">Certificate authorities and CLM</p>
              {CA_ROWS.map((row) => {
                const rowSources = caSources.filter((s) => row.providers.includes(s.config?.provider as CaProvider));
                const isAdcs = row.key === "adcs";
                return (
                  <ConnectorRow
                    key={row.key}
                    testId={`cloud-ca-${row.key}`}
                    label={row.label}
                    detail={row.detail}
                    sources={rowSources}
                    canTest={isAdcs}
                    testing={testMutation.isPending ? testMutation.variables?.id ?? null : null}
                    onConnect={() => setCaDialog({ row, source: null, nonce: Date.now() })}
                    onEdit={(s) => setCaDialog({ row, source: s, nonce: Date.now() })}
                    onTest={(s) => testMutation.mutate(s)}
                    onDelete={(s) => setDeleting(s)}
                    renderDetail={(s) =>
                      isAdcs ? (
                        <NodeTestLine teamId={teamId} source={s} />
                      ) : row.key === "aws_private_ca" ? (
                        <span className="text-xs text-zinc-500">
                          through {awsSources.find((a) => a.id === cfgNumber(s, "aws_source_id"))?.name ?? "an AWS account that was removed"} ·{" "}
                          {NOT_AVAILABLE}
                        </span>
                      ) : (
                        <span className="text-xs text-zinc-500">
                          {row.key === "other" ? `${CA_OTHER_LABEL[cfgString(s, "provider")] ?? "Other"} · ` : ""}
                          {NOT_AVAILABLE}
                        </span>
                      )
                    }
                  />
                );
              })}
            </div>
          </div>
        </SectionCard>

        <SectionCard title="Identity providers" description="Signing keys, their sizes and how often they rotate, once identity collection is available.">
          <div className="space-y-6">
            <div className="space-y-2">
              {IDP_ROWS.map((row) => (
                <ConnectorRow
                  key={row.provider}
                  testId={`cloud-idp-${row.provider}`}
                  label={row.label}
                  detail={row.detail}
                  sources={idpSources.filter((s) => s.config?.provider === row.provider)}
                  canTest={false}
                  testing={null}
                  onConnect={() => setIdpDialog({ row, source: null, nonce: Date.now() })}
                  onEdit={(s) => setIdpDialog({ row, source: s, nonce: Date.now() })}
                  onTest={() => undefined}
                  onDelete={(s) => setDeleting(s)}
                  renderDetail={() => <span className="text-xs text-zinc-500">{NOT_AVAILABLE}</span>}
                />
              ))}
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-zinc-200 dark:border-zinc-800 px-4 py-3">
                <div className="min-w-0">
                  <span className="text-sm font-medium text-zinc-900 dark:text-white">ADFS</span>
                  <span className="ml-1.5 text-xs text-zinc-500">read from the Windows servers you add on the Servers tab</span>
                </div>
                <div className="flex items-center gap-2">
                  <StatusBadge tone="zinc">Via servers</StatusBadge>
                  <Button variant="outline" size="sm" className="cursor-pointer" onClick={() => onNavigate("servers")}>
                    Servers
                  </Button>
                </div>
              </div>
            </div>
            <MetadataUrls teamId={teamId} sources={metadataSources} takenNames={identityNames} onDelete={(s) => setDeleting(s)} />
          </div>
        </SectionCard>
      </div>

      {caDialog && (
        <CaDialog
          key={`${caDialog.row.key}-${caDialog.source?.id ?? "new"}-${caDialog.nonce}`}
          teamId={teamId}
          row={caDialog.row}
          source={caDialog.source}
          nodes={nodes}
          awsSources={awsSources}
          takenNames={caSources.map((s) => s.name)}
          onClose={() => setCaDialog(null)}
          onNavigate={onNavigate}
        />
      )}
      {idpDialog && (
        <IdpDialog
          key={`${idpDialog.row.provider}-${idpDialog.source?.id ?? "new"}-${idpDialog.nonce}`}
          teamId={teamId}
          row={idpDialog.row}
          source={idpDialog.source}
          takenNames={identityNames}
          onClose={() => setIdpDialog(null)}
        />
      )}

      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(v) => !v && setDeleting(null)}
        title={deleting?.group === "cloud" ? "Delete cloud account?" : "Delete connector?"}
        description={
          deleting
            ? deleting.kind === "aws_account"
              ? `${deleting.name} is removed from ZeroShield. The read-only role stays in your AWS account until you delete its stack.`
              : `${deleting.name} and any secret stored for it are removed from ZeroShield.`
            : ""
        }
        confirmLabel="Delete"
        destructive
        pending={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting)}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------- small pieces
function StepTitle({ n, title }: { n: number; title: string }) {
  return (
    <div className="flex items-center gap-3 mb-3">
      <span className="flex h-6 w-6 items-center justify-center rounded-full bg-blue-600 text-xs font-semibold text-white">{n}</span>
      <h3 className="font-medium text-zinc-900 dark:text-white">{title}</h3>
    </div>
  );
}

function Chip({ children, onRemove, removeLabel, tone = "zinc" }: { children: ReactNode; onRemove?: () => void; removeLabel: string; tone?: "blue" | "zinc" }) {
  return (
    <span
      className={cn(
        "inline-flex max-w-full items-center gap-1 rounded-full border py-0.5 pl-2.5 pr-1 text-xs font-medium",
        tone === "blue" ? "border-blue-500/50 text-blue-600 dark:text-blue-400" : "border-zinc-400/50 text-zinc-700 dark:text-zinc-300",
      )}
    >
      <span className="truncate">{children}</span>
      {onRemove && (
        <button type="button" aria-label={removeLabel} onClick={onRemove} className="rounded-full p-0.5 hover:bg-zinc-500/15 cursor-pointer">
          <X className="h-3 w-3" />
        </button>
      )}
    </span>
  );
}

function EditingBanner({ name, onCancel }: { name: string; onCancel: () => void }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-blue-500/40 bg-blue-500/5 px-3 py-2 text-sm">
      <span className="min-w-0 text-zinc-700 dark:text-zinc-300">
        Editing <span className="font-medium text-zinc-900 dark:text-white">{name}</span>
      </span>
      <Button variant="outline" size="sm" className="cursor-pointer" onClick={onCancel}>
        Cancel editing
      </Button>
    </div>
  );
}

function AccountCell({ source }: { source: CbomSource }) {
  if (source.kind === "aws_account") {
    return (
      <div>
        <span className="font-mono text-xs text-zinc-900 dark:text-white">{awsAccountId(cfgString(source, "role_arn")) ?? "—"}</span>
        <span className="block text-xs text-zinc-500">AWS</span>
      </div>
    );
  }
  if (source.kind === "azure_subscription") {
    return (
      <div className="min-w-0">
        <Truncate className="font-mono text-xs text-zinc-900 dark:text-white" text={cfgString(source, "tenant_id") || "—"} />
        <span className="block text-xs text-zinc-500">Azure tenant</span>
      </div>
    );
  }
  const org = cfgString(source, "organization_id");
  const projects = cfgList(source, "project_ids");
  return (
    <div className="min-w-0">
      <Truncate
        className="font-mono text-xs text-zinc-900 dark:text-white"
        text={org ? `organizations/${org}` : projects.length ? `${projects[0]}${projects.length > 1 ? ` +${projects.length - 1}` : ""}` : "—"}
      />
      <span className="block text-xs text-zinc-500">Google Cloud</span>
    </div>
  );
}

function scopeLabel(source: CbomSource): string {
  if (source.kind === "aws_account") return cfgString(source, "scope") === "organization" ? "Organization" : "One account";
  if (source.kind === "azure_subscription") {
    const subs = cfgList(source, "subscription_ids").length;
    return subs ? pluralize(subs, "subscription") : "Tenant";
  }
  if (cfgString(source, "organization_id")) return "Organization";
  return pluralize(cfgList(source, "project_ids").length, "project");
}

// ---------------------------------------------------------------------------- validation panel
function ValidationPanel({ view, pending, provider }: { view: ValidationView | null; pending: boolean; provider: Provider }) {
  const isAws = provider === "aws";
  return (
    <div data-testid="cloud-validation" aria-live="polite" className="space-y-3">
      {!isAws && (
        <p className="text-sm text-zinc-600 dark:text-zinc-400">
          {provider === "azure" ? "Azure" : "Google Cloud"} accounts are saved and listed below. {NOT_AVAILABLE}
        </p>
      )}
      {pending && (
        <p className="flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-400">
          <Loader2 className="h-4 w-4 animate-spin text-blue-600" />
          ZeroShield is assuming the role and running read-only checks. This takes up to 20 seconds.
        </p>
      )}
      {isAws && !pending && !view && (
        <p className="text-sm text-zinc-600 dark:text-zinc-400">
          Fill in the role ARN and regions, then choose Validate connection. Each check AWS answers is listed here.
        </p>
      )}
      {view && !isAws && <p className="text-xs font-medium text-zinc-500">Last AWS validation: {view.name}</p>}
      {view && (
        <ul className={cn("divide-y divide-zinc-200 dark:divide-zinc-800", pending && "opacity-50")}>
          {view.checks.map((check) => {
            const [tone, label] = CHECK_BADGE[check.status] ?? CHECK_BADGE.error;
            return (
              <li key={check.check} className="flex items-start gap-2 py-2.5">
                <span className="w-16 shrink-0">
                  <StatusBadge tone={tone}>{label}</StatusBadge>
                </span>
                <span className="min-w-0">
                  <span className="block text-sm text-zinc-900 dark:text-white">{check.check}</span>
                  {check.detail && <span className="block text-xs text-zinc-500 break-words">{check.detail}</span>}
                </span>
              </li>
            );
          })}
          {view.memberAccounts !== null && (
            <li className="flex items-center gap-2 py-2.5">
              <span className="w-16 shrink-0">
                <StatusBadge tone="blue">Found</StatusBadge>
              </span>
              <span className="text-sm text-zinc-900 dark:text-white">{pluralize(view.memberAccounts, "member account")}</span>
            </li>
          )}
        </ul>
      )}
      {(isAws || view) && <p className="text-xs text-zinc-500">Every call the role makes lands in your CloudTrail.</p>}
    </div>
  );
}

// ---------------------------------------------------------------------------- AWS
function AwsForm({
  teamId,
  externalId,
  source,
  pending,
  onSubmit,
  onCancel,
}: {
  teamId: number;
  externalId: string;
  source: CbomSource | null;
  pending: boolean;
  onSubmit: (v: { name: string; config: AwsConfig }) => void;
  onCancel: () => void;
}) {
  const queryClient = useQueryClient();
  // Mounted with a key per record, so the form starts from the source's values without a sync effect.
  const [scope, setScope] = useState<AwsScope>(cfgString(source, "scope") === "organization" ? "organization" : "account");
  const [roleArn, setRoleArn] = useState(cfgString(source, "role_arn"));
  const [regions, setRegions] = useState<string[]>(() => {
    const saved = cfgList(source, "regions");
    return saved.length ? saved : ["ap-south-1"];
  });
  const [regionInput, setRegionInput] = useState("");
  const [name, setName] = useState(source?.name ?? "");
  const [errors, setErrors] = useState<{ name?: string | null; arn?: string | null; region?: string | null }>({});
  const [downloading, setDownloading] = useState(false);
  const [policyOpen, setPolicyOpen] = useState(false);
  const accountId = awsAccountId(roleArn);

  const addRegion = () => {
    const value = regionInput.trim().toLowerCase();
    if (!value) return;
    if (!REGION_RE.test(value)) {
      setErrors((e) => ({ ...e, region: `${value} is not an AWS region code such as ap-south-1` }));
      return;
    }
    if (!regions.includes(value)) {
      if (regions.length >= 32) {
        setErrors((e) => ({ ...e, region: "At most 32 regions" }));
        return;
      }
      setRegions([...regions, value]);
    }
    setRegionInput("");
    setErrors((e) => ({ ...e, region: null }));
  };

  const download = async () => {
    setDownloading(true);
    try {
      const text = await queryClient.fetchQuery({
        queryKey: cbomSourcesKeys.template(teamId, `aws-${scope}`),
        queryFn: () => getCbomAwsTemplate(teamId, scope),
        staleTime: 60_000,
      });
      saveTextFile(text, `zeroshield-cbom-reader-${scope}.yaml`, "application/yaml");
    } catch {
      toast.error("Could not download the template. Please try again.");
    } finally {
      setDownloading(false);
    }
  };

  const submit = () => {
    const arn = roleArn.trim();
    const finalName = name.trim() || (accountId ? `aws-${accountId}` : "");
    const next = {
      arn: ROLE_ARN_RE.test(arn) ? null : "Enter an IAM role ARN like arn:aws:iam::111122223333:role/ZeroShieldCBOMReader",
      region: regions.length ? null : "Add at least one region",
      name: nameError(finalName),
    };
    setErrors(next);
    if (next.arn || next.region || next.name) return;
    onSubmit({ name: finalName, config: { scope, role_arn: arn, regions } });
  };

  return (
    <div className="space-y-6">
      {source && <EditingBanner name={source.name} onCancel={onCancel} />}
      <ol className="space-y-8">
        <li>
          <StepTitle n={1} title="Scope" />
          <div data-testid="cloud-aws-scope">
            <ChoiceCards
              name="aws-scope"
              label="Scope"
              value={scope}
              onChange={setScope}
              options={[
                { value: "account", title: "One account", description: "CloudFormation stack" },
                { value: "organization", title: "Whole AWS Organization", description: "StackSet to every member account" },
              ]}
            />
          </div>
        </li>

        <li>
          <StepTitle n={2} title="Your external ID" />
          <div className="flex flex-wrap items-center gap-2">
            <code
              data-testid="cloud-external-id"
              className="flex-1 min-w-[200px] break-all rounded-md border bg-zinc-50 dark:bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-900 dark:text-zinc-100"
            >
              {externalId}
            </code>
            <CopyButton text={externalId} />
          </div>
          <p className="text-xs text-zinc-500 mt-2">Unique to your team. Without it the role cannot be assumed, even by ZeroShield.</p>
        </li>

        <li>
          <StepTitle n={3} title="Create the read-only role" />
          <p className="text-sm text-zinc-600 dark:text-zinc-400 mb-3">
            {scope === "organization"
              ? "Download the template and deploy it from the management account as a StackSet with service-managed permissions."
              : "Download the template and create a stack from it in the account you want inventoried."}{" "}
            Then paste the RoleArn output in step 4.
          </p>
          <div className="flex flex-wrap gap-2">
            <Button
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
              disabled={downloading}
              onClick={download}
              data-testid="cloud-aws-download"
            >
              {downloading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Download className="h-4 w-4 mr-2" />}
              Download template
            </Button>
            <Button variant="outline" className="cursor-pointer" asChild>
              <a href={CLOUDFORMATION_CONSOLE} target="_blank" rel="noopener noreferrer" data-testid="cloud-aws-console">
                <ExternalLink className="h-4 w-4 mr-2" />
                Open CloudFormation console
              </a>
            </Button>
          </div>
          <div className="mt-3 space-y-2 rounded-lg border border-zinc-200 dark:border-zinc-800 p-4 text-sm">
            <p>
              <span className="font-medium text-zinc-900 dark:text-white">Allows: </span>
              <span className="text-zinc-600 dark:text-zinc-400">AWS managed SecurityAudit (describe and list only)</span>
            </p>
            <p className="break-words">
              <span className="font-medium text-zinc-900 dark:text-white">Explicitly denies: </span>
              <span className="font-mono text-xs text-zinc-600 dark:text-zinc-400">
                kms:Decrypt, kms:Sign, kms:GenerateDataKey*, secretsmanager:GetSecretValue, ssm:GetParameter*, s3:GetObject, acm:ExportCertificate,
                ec2:GetPasswordData
              </span>
              <span className="text-zinc-600 dark:text-zinc-400"> and the other data-plane actions</span>
            </p>
            <button
              type="button"
              className="text-sm font-medium text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
              onClick={() => setPolicyOpen(true)}
              data-testid="cloud-aws-policy"
            >
              View the full policy
            </button>
          </div>
        </li>

        <li>
          <StepTitle n={4} title="Connect the role" />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Field
              className="md:col-span-2"
              label={scope === "organization" ? "Role ARN in the management account" : "Role ARN"}
              htmlFor="aws-role-arn"
              required
              error={errors.arn}
            >
              <Input
                id="aws-role-arn"
                data-testid="cloud-aws-role-arn"
                className="font-mono text-sm"
                value={roleArn}
                maxLength={600}
                spellCheck={false}
                autoComplete="off"
                placeholder="arn:aws:iam::111122223333:role/ZeroShieldCBOMReader"
                onChange={(e) => setRoleArn(e.target.value)}
              />
            </Field>
            <Field className="md:col-span-2" label="Regions" htmlFor="aws-region-input" required error={errors.region} hint="The first region is used for the test read.">
              <div className="space-y-2">
                {regions.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5" data-testid="cloud-aws-regions">
                    {regions.map((r) => (
                      <Chip key={r} tone="blue" removeLabel={`Remove region ${r}`} onRemove={() => setRegions(regions.filter((x) => x !== r))}>
                        {r}
                      </Chip>
                    ))}
                  </div>
                )}
                <div className="flex flex-wrap gap-2">
                  <Input
                    id="aws-region-input"
                    data-testid="cloud-aws-region-input"
                    className="flex-1 min-w-[160px]"
                    value={regionInput}
                    maxLength={32}
                    placeholder="eu-west-1"
                    onChange={(e) => setRegionInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        addRegion();
                      }
                    }}
                  />
                  <Button variant="outline" className="cursor-pointer" onClick={addRegion} data-testid="cloud-aws-region-add">
                    <Plus className="h-4 w-4 mr-2" />
                    Add region
                  </Button>
                </div>
              </div>
            </Field>
            <Field
              label="Name"
              htmlFor="aws-name"
              error={errors.name}
              hint={accountId ? `Leave blank to use aws-${accountId}` : "A short name such as payments-prod"}
            >
              <Input id="aws-name" data-testid="cloud-aws-name" value={name} maxLength={64} placeholder="payments-prod" onChange={(e) => setName(e.target.value)} />
            </Field>
          </div>
          <div className="mt-6 flex flex-wrap items-center justify-end gap-3">
            <p className="text-xs text-zinc-500 mr-auto">Saves the account, then ZeroShield assumes the role and runs read-only checks.</p>
            <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={pending} onClick={submit} data-testid="cloud-aws-validate">
              {pending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <ShieldCheck className="h-4 w-4 mr-2" />}
              Validate connection
            </Button>
          </div>
        </li>
      </ol>
      <PolicyDialog teamId={teamId} scope={scope} open={policyOpen} onOpenChange={setPolicyOpen} />
    </div>
  );
}

function PolicyDialog({ teamId, scope, open, onOpenChange }: { teamId: number; scope: AwsScope; open: boolean; onOpenChange: (v: boolean) => void }) {
  const query = useQuery({
    queryKey: cbomSourcesKeys.template(teamId, `aws-${scope}`),
    queryFn: () => getCbomAwsTemplate(teamId, scope),
    enabled: open && Number.isFinite(teamId),
    retry: 1,
    staleTime: 60_000,
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Read-only role template</DialogTitle>
          <DialogDescription>
            {scope === "organization" ? "For a StackSet across your Organization." : "For a stack in one account."} This is the file Download template
            saves, with your external ID filled in.
          </DialogDescription>
        </DialogHeader>
        <div className="min-w-0" data-testid="cloud-aws-policy-text">
          {query.isLoading ? (
            <LoadingBlock />
          ) : query.isError || !query.data ? (
            <ErrorBlock message="Could not load the template." onRetry={() => query.refetch()} />
          ) : (
            <CodeSnippet code={query.data} language="yaml" />
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" className="cursor-pointer" onClick={() => onOpenChange(false)}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------- Azure
function AzureForm({ teamId, source, onDone, onCancel }: { teamId: number; source: CbomSource | null; onDone: () => void; onCancel: () => void }) {
  const invalidate = useInvalidate(teamId);
  const [name, setName] = useState(source?.name ?? "");
  const [tenantId, setTenantId] = useState(cfgString(source, "tenant_id"));
  const [clientId, setClientId] = useState(cfgString(source, "client_id"));
  const [subscriptions, setSubscriptions] = useState(cfgList(source, "subscription_ids").join("\n"));
  const [secret, setSecret] = useState("");
  const [errors, setErrors] = useState<Record<string, string | null>>({});
  const secretSet = !!source?.secrets_set.includes("client_secret");

  const save = useMutation({
    mutationFn: (body: { name: string; config: Record<string, unknown>; secrets: Record<string, string> }) =>
      source
        ? updateCbomSource(teamId, source.id, { ...body, expected_version: source.row_version })
        : createCbomSource(teamId, { kind: "azure_subscription", ...body }),
    onSuccess: onDone,
    onError: (err) => {
      if (source && (httpStatus(err) === 409 || httpStatus(err) === 404)) onCancel();
    },
    onSettled: invalidate,
  });

  const submit = () => {
    const tenant = tenantId.trim().toLowerCase();
    const client = clientId.trim().toLowerCase();
    const subs = splitLines(subscriptions).map((s) => s.toLowerCase());
    const badSub = subs.find((s) => !GUID_RE.test(s));
    const whereChanged = !!source && (tenant !== cfgString(source, "tenant_id").toLowerCase() || client !== cfgString(source, "client_id").toLowerCase());
    const next: Record<string, string | null> = {
      name: nameError(name),
      tenant: GUID_RE.test(tenant) ? null : "Enter the directory (tenant) ID, a GUID like 00000000-0000-0000-0000-000000000000",
      client: GUID_RE.test(client) ? null : "Enter the application (client) ID, a GUID",
      subs: badSub ? `${badSub} is not a subscription GUID` : subs.length > 200 ? "At most 200 subscriptions" : null,
      secret:
        secret || (secretSet && !whereChanged)
          ? null
          : secretSet
            ? "Re-enter the client secret: it is cleared when the tenant or client ID changes"
            : "Enter the client secret",
    };
    setErrors(next);
    if (Object.values(next).some(Boolean)) return;
    save.mutate({
      name: name.trim(),
      config: { tenant_id: tenant, client_id: client, subscription_ids: Array.from(new Set(subs)) },
      secrets: secret ? { client_secret: secret } : {},
    });
  };

  return (
    <div className="space-y-5">
      {source && <EditingBanner name={source.name} onCancel={onCancel} />}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Field label="Name" htmlFor="azure-name" required error={errors.name}>
          <Input id="azure-name" data-testid="cloud-azure-name" value={name} maxLength={64} placeholder="azure-prod" onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Directory (tenant) ID" htmlFor="azure-tenant" required error={errors.tenant}>
          <Input
            id="azure-tenant"
            data-testid="cloud-azure-tenant"
            className="font-mono text-sm"
            value={tenantId}
            maxLength={36}
            spellCheck={false}
            placeholder="00000000-0000-0000-0000-000000000000"
            onChange={(e) => setTenantId(e.target.value)}
          />
        </Field>
        <Field label="Application (client) ID" htmlFor="azure-client" required error={errors.client}>
          <Input
            id="azure-client"
            data-testid="cloud-azure-client"
            className="font-mono text-sm"
            value={clientId}
            maxLength={36}
            spellCheck={false}
            placeholder="00000000-0000-0000-0000-000000000000"
            onChange={(e) => setClientId(e.target.value)}
          />
        </Field>
        <SecretField
          id="azure-secret"
          label="Client secret"
          value={secret}
          onChange={setSecret}
          isSet={secretSet}
          required
          error={errors.secret}
          hint={secretSet ? "Saved. Leave blank to keep it; changing the tenant or client ID clears it." : STORED_HINT}
        />
        <Field
          className="md:col-span-2"
          label="Subscription IDs"
          htmlFor="azure-subs"
          error={errors.subs}
          hint="One GUID per line. Optional."
        >
          <Textarea
            id="azure-subs"
            data-testid="cloud-azure-subscriptions"
            className="font-mono text-xs min-h-[88px]"
            value={subscriptions}
            spellCheck={false}
            placeholder={"11111111-2222-3333-4444-555555555555\n66666666-7777-8888-9999-000000000000"}
            onChange={(e) => setSubscriptions(e.target.value)}
          />
        </Field>
      </div>
      <FormFooter pending={save.isPending} onSave={submit} testId="cloud-azure-save" />
    </div>
  );
}

// ---------------------------------------------------------------------------- Google Cloud
function GcpForm({ teamId, source, onDone, onCancel }: { teamId: number; source: CbomSource | null; onDone: () => void; onCancel: () => void }) {
  const invalidate = useInvalidate(teamId);
  const [name, setName] = useState(source?.name ?? "");
  const [orgId, setOrgId] = useState(cfgString(source, "organization_id"));
  const [projects, setProjects] = useState(cfgList(source, "project_ids").join("\n"));
  const [email, setEmail] = useState(cfgString(source, "service_account_email"));
  const [key, setKey] = useState("");
  const [keyFile, setKeyFile] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string | null>>({});
  const keySet = !!source?.secrets_set.includes("service_account_key");

  const save = useMutation({
    mutationFn: (body: { name: string; config: Record<string, unknown>; secrets: Record<string, string> }) =>
      source
        ? updateCbomSource(teamId, source.id, { ...body, expected_version: source.row_version })
        : createCbomSource(teamId, { kind: "gcp_project", ...body }),
    onSuccess: onDone,
    onError: (err) => {
      if (source && (httpStatus(err) === 409 || httpStatus(err) === 404)) onCancel();
    },
    onSettled: invalidate,
  });

  const keyError = (text: string): string | null => {
    try {
      const parsed: unknown = JSON.parse(text);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return "The key must be the JSON key file of the service account";
      const type = (parsed as { type?: unknown }).type;
      if (type !== undefined && type !== "service_account") return "This JSON is not a service account key";
      return null;
    } catch {
      return "The key is not valid JSON; upload the .json key file";
    }
  };

  const submit = () => {
    const org = orgId.trim();
    const projectList = Array.from(new Set(splitLines(projects)));
    const badProject = projectList.find((p) => !GCP_PROJECT_RE.test(p));
    const mail = email.trim();
    const whereChanged = !!source && mail !== cfgString(source, "service_account_email");
    const next: Record<string, string | null> = {
      name: nameError(name),
      org: org && !/^\d{1,32}$/.test(org) ? "The organization ID is numeric" : null,
      projects: badProject
        ? `${badProject} is not a project ID (6-30 lowercase letters, digits and dashes)`
        : projectList.length > 200
          ? "At most 200 projects"
          : !org && projectList.length === 0
            ? "Enter an organization ID or at least one project ID"
            : null,
      email: GCP_SA_RE.test(mail) ? null : "Enter a service account such as zs-cbom@project.iam.gserviceaccount.com",
      key: key
        ? keyError(key)
        : keySet && !whereChanged
          ? null
          : keySet
            ? "Re-enter the key: it is cleared when the service account changes"
            : "Upload or paste the service account key",
    };
    setErrors(next);
    if (Object.values(next).some(Boolean)) return;
    save.mutate({
      name: name.trim(),
      config: { organization_id: org || null, project_ids: projectList, service_account_email: mail },
      secrets: key ? { service_account_key: key } : {},
    });
  };

  return (
    <div className="space-y-5">
      {source && <EditingBanner name={source.name} onCancel={onCancel} />}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Field label="Name" htmlFor="gcp-name" required error={errors.name}>
          <Input id="gcp-name" data-testid="cloud-gcp-name" value={name} maxLength={64} placeholder="gcp-prod" onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Organization ID" htmlFor="gcp-org" error={errors.org} hint="Numeric. Leave blank to list projects instead.">
          <Input
            id="gcp-org"
            data-testid="cloud-gcp-org"
            className="font-mono text-sm"
            inputMode="numeric"
            value={orgId}
            maxLength={32}
            placeholder="123456789012"
            onChange={(e) => setOrgId(e.target.value)}
          />
        </Field>
        <Field className="md:col-span-2" label="Project IDs" htmlFor="gcp-projects" error={errors.projects} hint="One per line. Needed when there is no organization ID.">
          <Textarea
            id="gcp-projects"
            data-testid="cloud-gcp-projects"
            className="font-mono text-xs min-h-[88px]"
            value={projects}
            spellCheck={false}
            placeholder={"payments-prod\ncore-banking-dr"}
            onChange={(e) => setProjects(e.target.value)}
          />
        </Field>
        <Field className="md:col-span-2" label="Service account" htmlFor="gcp-email" required error={errors.email}>
          <Input
            id="gcp-email"
            data-testid="cloud-gcp-email"
            className="font-mono text-sm"
            value={email}
            maxLength={254}
            spellCheck={false}
            placeholder="zs-cbom@project.iam.gserviceaccount.com"
            onChange={(e) => setEmail(e.target.value)}
          />
        </Field>
        <SecretField
          id="gcp-key"
          label="Service account key (JSON)"
          value={key}
          onChange={(v) => {
            setKey(v);
            setKeyFile(null);
          }}
          isSet={keySet}
          required
          error={errors.key}
          placeholder="Paste the key, or upload the file"
          hint={keyFile ? `Loaded ${keyFile}` : keySet ? "Saved. Leave blank to keep it; changing the service account clears it." : STORED_HINT}
        />
        <Field label="Upload the key file" htmlFor="gcp-key-file" error={errors.keyFile} hint="The .json file from IAM > Service accounts > Keys">
          <Input
            id="gcp-key-file"
            data-testid="cloud-gcp-key-file"
            type="file"
            accept=".json,application/json"
            className="cursor-pointer"
            onChange={async (e) => {
              const file = e.target.files?.[0];
              if (!file) return;
              try {
                const text = await readTextFile(file, 64 * 1024);
                setKey(text);
                setKeyFile(file.name);
                setErrors((x) => ({ ...x, keyFile: null, key: null }));
              } catch (err) {
                setErrors((x) => ({ ...x, keyFile: (err as Error).message }));
              }
            }}
          />
        </Field>
      </div>
      <FormFooter pending={save.isPending} onSave={submit} testId="cloud-gcp-save" />
    </div>
  );
}

function FormFooter({ pending, onSave, testId }: { pending: boolean; onSave: () => void; testId: string }) {
  return (
    <div className="flex flex-wrap items-center justify-end gap-3">
      <p className="text-xs text-zinc-500 mr-auto">{NOT_AVAILABLE}</p>
      <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={pending} onClick={onSave} data-testid={testId}>
        {pending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
        Save
      </Button>
    </div>
  );
}

// ---------------------------------------------------------------------------- certificate domains
function CertDomains({ teamId, settings }: { teamId: number; settings: CbomSourcesSettings }) {
  const queryClient = useQueryClient();
  const [input, setInput] = useState("");
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: (next: string[]) => updateCbomSourcesSettings(teamId, { cert_domains: next, expected_version: settings.row_version }),
    onSuccess: (data) => queryClient.setQueryData(cbomSourcesKeys.settings(teamId), data),
    onError: (err) => {
      if (httpStatus(err) === 409) toast.info("Settings were changed elsewhere and have been reloaded. Re-apply your change.");
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) }),
  });

  const add = () => {
    const { value, error: err } = normalizeDomain(input);
    if (err) {
      setError(err);
      return;
    }
    if (settings.cert_domains.includes(value)) {
      setError(`${value} is already in the list`);
      return;
    }
    if (settings.cert_domains.length >= MAX_DOMAINS) {
      setError(`At most ${MAX_DOMAINS} domains`);
      return;
    }
    setError(null);
    mutation.mutate([...settings.cert_domains, value], { onSuccess: () => setInput("") });
  };

  return (
    <Field
      label="Domains to search in Certificate Transparency logs"
      htmlFor="cert-domain-input"
      error={error}
      hint="Saved for the certificate collector. ZeroShield does not query Certificate Transparency logs yet."
    >
      <div className="space-y-2">
        {settings.cert_domains.length > 0 ? (
          <div className="flex flex-wrap gap-1.5" data-testid="cloud-cert-domains">
            {settings.cert_domains.map((d) => (
              <Chip
                key={d}
                removeLabel={`Remove ${d}`}
                onRemove={mutation.isPending ? undefined : () => mutation.mutate(settings.cert_domains.filter((x) => x !== d))}
              >
                {d}
              </Chip>
            ))}
          </div>
        ) : (
          <p className="text-xs text-zinc-500">No domains yet.</p>
        )}
        <div className="flex flex-wrap gap-2">
          <Input
            id="cert-domain-input"
            data-testid="cloud-cert-domain-input"
            className="flex-1 min-w-[180px]"
            value={input}
            maxLength={253}
            placeholder="Add a domain, e.g. example.com"
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                add();
              }
            }}
          />
          <Button variant="outline" className="cursor-pointer" disabled={mutation.isPending} onClick={add} data-testid="cloud-cert-domain-add">
            {mutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
            Add
          </Button>
        </div>
      </div>
    </Field>
  );
}

// ---------------------------------------------------------------------------- connector rows
function ConnectorRow({
  testId,
  label,
  detail,
  sources,
  canTest,
  testing,
  onConnect,
  onEdit,
  onTest,
  onDelete,
  renderDetail,
}: {
  testId: string;
  label: string;
  detail?: string;
  sources: CbomSource[];
  canTest: boolean;
  testing: number | null;
  onConnect: () => void;
  onEdit: (s: CbomSource) => void;
  onTest: (s: CbomSource) => void;
  onDelete: (s: CbomSource) => void;
  renderDetail: (s: CbomSource) => ReactNode;
}) {
  const connected = sources.length > 0;
  return (
    <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 px-4 py-3" data-testid={testId}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <span className="text-sm font-medium text-zinc-900 dark:text-white">{label}</span>
          {detail && <span className="ml-1.5 text-xs text-zinc-500">{detail}</span>}
        </div>
        <div className="flex items-center gap-2">
          {connected ? (
            <>
              <StatusBadge tone="green">Connected</StatusBadge>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon" className="cursor-pointer" aria-label={`Manage ${label}`} data-testid={`${testId}-manage`}>
                    <MoreVertical className="h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  {sources.map((s) => (
                    <Fragment key={s.id}>
                      <DropdownMenuItem className="cursor-pointer" onSelect={() => onEdit(s)}>
                        <Pencil className="h-4 w-4" />
                        Edit {s.name}
                      </DropdownMenuItem>
                      {canTest && (
                        <DropdownMenuItem className="cursor-pointer" disabled={testing === s.id} onSelect={() => onTest(s)}>
                          <ShieldCheck className="h-4 w-4" />
                          Test {s.name}
                        </DropdownMenuItem>
                      )}
                      <DropdownMenuItem variant="destructive" className="cursor-pointer" onSelect={() => onDelete(s)}>
                        <Trash2 className="h-4 w-4" />
                        Delete {s.name}
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                    </Fragment>
                  ))}
                  <DropdownMenuItem className="cursor-pointer" onSelect={onConnect}>
                    <Plus className="h-4 w-4" />
                    Connect another
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </>
          ) : (
            <Button variant="outline" size="sm" className="cursor-pointer" onClick={onConnect} data-testid={`${testId}-connect`}>
              Connect
            </Button>
          )}
        </div>
      </div>
      {connected && (
        <ul className="mt-2 space-y-2">
          {sources.map((s) => (
            <li key={s.id} className="min-w-0 space-y-1">
              <span className="block text-sm text-zinc-700 dark:text-zinc-300 truncate" title={s.name}>
                {s.name}
              </span>
              {renderDetail(s)}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** AD CS is tested by its scan node: show the queued job and why it waits, then the result. */
function NodeTestLine({ teamId, source }: { teamId: number; source: CbomSource }) {
  const pendingJobId = source.last_test_status === "pending" ? source.last_test_job_id : null;
  const job = usePolledJob(teamId, pendingJobId);
  const samples = source.last_test_result?.samples ?? [];
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-500">
        <span>through {source.node_name ?? "a scan node that was removed"}</span>
        {pendingJobId && job.data ? <JobStatusBadge status={job.data.status} /> : <TestStatusBadge status={source.last_test_status} title={source.last_test_summary} />}
      </div>
      {pendingJobId ? (
        <p className="text-xs text-zinc-500">{job.data?.waiting_reason ?? source.last_test_summary ?? "Waiting for the scan node"}</p>
      ) : (
        source.last_test_summary && <p className="text-xs text-zinc-500">{source.last_test_summary}</p>
      )}
      {!pendingJobId && samples.length > 0 && (
        <ul className="text-xs text-zinc-600 dark:text-zinc-400">
          {samples.map((sample) => (
            <li key={sample.target} className="break-words">
              <span className="font-mono">{sample.target}</span>: {sample.status}
              {sample.note ? ` (${sample.note})` : ""}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------- CA dialog
function CaDialog({
  teamId,
  row,
  source,
  nodes,
  awsSources,
  takenNames,
  onClose,
  onNavigate,
}: {
  teamId: number;
  row: CaRow;
  source: CbomSource | null;
  nodes: CbomScanNode[];
  awsSources: CbomSource[];
  takenNames: string[];
  onClose: () => void;
  onNavigate: (tab: string) => void;
}) {
  const invalidate = useInvalidate(teamId);
  const savedProvider = cfgString(source, "provider") as CaProvider;
  const initialProvider: CaProvider = row.providers.includes(savedProvider) ? savedProvider : row.providers[0];
  const [provider, setProvider] = useState<CaProvider>(initialProvider);
  const [name, setName] = useState(source?.name ?? uniqueName(CA_DEFAULT_NAME[initialProvider], takenNames));
  const [nodeId, setNodeId] = useState<number | null>(source?.node_id ?? (nodes.length === 1 ? nodes[0].id : null));
  const [login, setLogin] = useState(cfgString(source, "login"));
  const [password, setPassword] = useState("");
  const [awsSourceId, setAwsSourceId] = useState<number | null>(cfgNumber(source, "aws_source_id") ?? (awsSources.length === 1 ? awsSources[0].id : null));
  const [apiUrl, setApiUrl] = useState(cfgString(source, "api_url"));
  const [apiKey, setApiKey] = useState("");
  const [errors, setErrors] = useState<Record<string, string | null>>({});
  const isAdcs = provider === "adcs";
  const isAwsCa = provider === "aws_private_ca";
  const passwordSet = !!source?.secrets_set.includes("password");
  const apiKeySet = !!source?.secrets_set.includes("api_key");

  const save = useMutation({
    mutationFn: ({ test }: { test: boolean }) => {
      const config: Record<string, unknown> = { provider };
      const secrets: Record<string, string> = {};
      if (isAdcs) {
        config.login = login.trim();
        if (password) secrets.password = password;
      } else if (isAwsCa) {
        config.aws_source_id = awsSourceId;
      } else {
        config.api_url = apiUrl.trim();
        if (apiKey) secrets.api_key = apiKey;
      }
      const body = { name: name.trim(), config, secrets, test_after_save: test, ...(isAdcs && nodeId ? { node_id: nodeId } : {}) };
      return source
        ? updateCbomSource(teamId, source.id, { ...body, expected_version: source.row_version })
        : createCbomSource(teamId, { kind: "ca_connector", ...body });
    },
    onSuccess: onClose,
    onError: (err) => {
      if (source && (httpStatus(err) === 409 || httpStatus(err) === 404)) onClose();
    },
    onSettled: invalidate,
  });

  const submit = (test: boolean) => {
    const providerChanged = !!source && savedProvider !== provider;
    const next: Record<string, string | null> = { name: nameError(name) };
    if (isAdcs) {
      const whereChanged = !!source && (providerChanged || login.trim() !== cfgString(source, "login") || nodeId !== source.node_id);
      next.node = nodeId ? null : "Choose the scan node that can reach your certificate authority";
      next.login = LOGIN_RE.test(login.trim()) ? null : "Enter the read-only Windows account, e.g. CORP\\svc-zscbom";
      next.password =
        password || (passwordSet && !whereChanged) ? null : passwordSet ? "Re-enter the password: it is cleared when the account or node changes" : "Enter the password";
    } else if (isAwsCa) {
      next.aws = awsSourceId ? null : "Pick the AWS account that holds the private CA";
    } else {
      const whereChanged = !!source && (providerChanged || apiUrl.trim() !== cfgString(source, "api_url"));
      next.apiUrl = httpsUrlError(apiUrl, "API address");
      next.apiKey = apiKey || (apiKeySet && !whereChanged) ? null : apiKeySet ? "Re-enter the API key: it is cleared when the address changes" : "Enter the API key";
    }
    setErrors(next);
    if (Object.values(next).some(Boolean)) return;
    save.mutate({ test });
  };

  const pendingTest = save.isPending && save.variables?.test === true;
  const pendingSave = save.isPending && save.variables?.test === false;

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{source ? `Edit ${source.name}` : `Connect ${row.label}`}</DialogTitle>
          <DialogDescription>
            {isAdcs
              ? "A scan node reads the certificate authority with a read-only Windows account."
              : isAwsCa
                ? "Read through the read-only role of a connected AWS account. No new credential is needed."
                : "ZeroShield keeps the API address and key for the certificate collector."}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          {row.providers.length > 1 && (
            <Field label="Product" htmlFor="ca-provider">
              <Select
                value={provider}
                onValueChange={(v) => {
                  const next = v as CaProvider;
                  if (!source && name === uniqueName(CA_DEFAULT_NAME[provider], takenNames)) setName(uniqueName(CA_DEFAULT_NAME[next], takenNames));
                  setProvider(next);
                }}
              >
                <SelectTrigger id="ca-provider" className="w-full cursor-pointer" data-testid="cloud-ca-provider">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {row.providers.map((p) => (
                    <SelectItem key={p} value={p} className="cursor-pointer">
                      {CA_OTHER_LABEL[p] ?? p}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
          )}
          <Field label="Name" htmlFor="ca-name" required error={errors.name}>
            <Input id="ca-name" data-testid="cloud-ca-name" value={name} maxLength={64} onChange={(e) => setName(e.target.value)} />
          </Field>

          {isAdcs && (
            <>
              <Field label="Scan node" htmlFor="ca-node" required error={errors.node} hint="A node in a segment that reaches your domain controllers and CA">
                <NodeSelect id="ca-node" nodes={nodes} value={nodeId} onChange={setNodeId} />
              </Field>
              {nodes.length === 0 && (
                <Button
                  variant="outline"
                  size="sm"
                  className="cursor-pointer"
                  onClick={() => {
                    onClose();
                    onNavigate("scan-nodes");
                  }}
                >
                  Add a scan node first
                </Button>
              )}
              <Field label="Read-only Windows account" htmlFor="ca-login" required error={errors.login}>
                <Input id="ca-login" data-testid="cloud-ca-login" value={login} maxLength={64} placeholder="svc-zscbom" autoComplete="off" onChange={(e) => setLogin(e.target.value)} />
              </Field>
              <SecretField
                id="ca-password"
                label="Password"
                value={password}
                onChange={setPassword}
                isSet={passwordSet}
                required
                error={errors.password}
                hint={passwordSet ? "Saved. Leave blank to keep it; changing the account or node clears it." : undefined}
              />
            </>
          )}

          {isAwsCa && (
            <Field label="AWS account" htmlFor="ca-aws" required error={errors.aws}>
              {awsSources.length === 0 ? (
                <p className="text-sm text-zinc-600 dark:text-zinc-400">Connect an AWS account at the top of this tab first.</p>
              ) : (
                <Select value={awsSourceId ? String(awsSourceId) : ""} onValueChange={(v) => setAwsSourceId(v ? Number(v) : null)}>
                  <SelectTrigger id="ca-aws" className="w-full cursor-pointer" data-testid="cloud-ca-aws">
                    <SelectValue placeholder="Choose an AWS account" />
                  </SelectTrigger>
                  <SelectContent>
                    {awsSources.map((a) => (
                      <SelectItem key={a.id} value={String(a.id)} className="cursor-pointer">
                        {a.name} · {awsAccountId(cfgString(a, "role_arn")) ?? "AWS"}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </Field>
          )}

          {!isAdcs && !isAwsCa && (
            <>
              <Field label="API address" htmlFor="ca-api-url" required error={errors.apiUrl}>
                <Input
                  id="ca-api-url"
                  data-testid="cloud-ca-api-url"
                  value={apiUrl}
                  maxLength={512}
                  spellCheck={false}
                  placeholder="https://tpp.example.com/vedsdk"
                  onChange={(e) => setApiUrl(e.target.value)}
                />
              </Field>
              <SecretField
                id="ca-api-key"
                label="API key"
                value={apiKey}
                onChange={setApiKey}
                isSet={apiKeySet}
                required
                error={errors.apiKey}
                hint={apiKeySet ? "Saved. Leave blank to keep it; changing the address clears it." : STORED_HINT}
              />
            </>
          )}
          {!isAdcs && <p className="text-xs text-zinc-500">{NOT_AVAILABLE}</p>}
        </div>
        <DialogFooter>
          <Button variant="outline" className="cursor-pointer" onClick={onClose}>
            Cancel
          </Button>
          {isAdcs ? (
            <>
              <Button variant="outline" className="cursor-pointer" disabled={save.isPending} onClick={() => submit(false)} data-testid="cloud-ca-save">
                {pendingSave && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Save
              </Button>
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={save.isPending} onClick={() => submit(true)} data-testid="cloud-ca-save-test">
                {pendingTest && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Save and test
              </Button>
            </>
          ) : (
            <Button
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
              disabled={save.isPending || (isAwsCa && awsSources.length === 0)}
              onClick={() => submit(false)}
              data-testid="cloud-ca-save"
            >
              {save.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Save
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------- IdP dialog
function IdpDialog({
  teamId,
  row,
  source,
  takenNames,
  onClose,
}: {
  teamId: number;
  row: IdpRow;
  source: CbomSource | null;
  takenNames: string[];
  onClose: () => void;
}) {
  const invalidate = useInvalidate(teamId);
  const provider = row.provider;
  const [name, setName] = useState(source?.name ?? uniqueName(row.defaultName, takenNames));
  const [tenantId, setTenantId] = useState(cfgString(source, "tenant_id"));
  const [clientId, setClientId] = useState(cfgString(source, "client_id"));
  const [baseUrl, setBaseUrl] = useState(cfgString(source, "base_url"));
  const [realm, setRealm] = useState(cfgString(source, "realm"));
  const [secret, setSecret] = useState("");
  const [errors, setErrors] = useState<Record<string, string | null>>({});
  const secretName = provider === "okta" ? "api_token" : "client_secret";
  const secretLabel = provider === "okta" ? "API token" : "Client secret";
  const secretSet = !!source?.secrets_set.includes(secretName);

  const save = useMutation({
    mutationFn: () => {
      const config: Record<string, unknown> = { provider };
      if (provider === "entra_id") Object.assign(config, { tenant_id: tenantId.trim().toLowerCase(), client_id: clientId.trim() });
      if (provider === "okta") Object.assign(config, { base_url: baseUrl.trim() });
      if (provider === "keycloak") Object.assign(config, { base_url: baseUrl.trim(), realm: realm.trim(), client_id: clientId.trim() });
      const body = { name: name.trim(), config, secrets: secret ? { [secretName]: secret } : {} };
      return source
        ? updateCbomSource(teamId, source.id, { ...body, expected_version: source.row_version })
        : createCbomSource(teamId, { kind: "idp", ...body });
    },
    onSuccess: onClose,
    onError: (err) => {
      if (source && (httpStatus(err) === 409 || httpStatus(err) === 404)) onClose();
    },
    onSettled: invalidate,
  });

  const submit = () => {
    const next: Record<string, string | null> = { name: nameError(name) };
    let whereChanged = false;
    if (provider === "entra_id") {
      next.tenant = GUID_RE.test(tenantId.trim()) ? null : "Enter the directory (tenant) ID, a GUID";
      next.client = clientId.trim() ? null : "Enter the application (client) ID";
      whereChanged = !!source && (tenantId.trim().toLowerCase() !== cfgString(source, "tenant_id").toLowerCase() || clientId.trim() !== cfgString(source, "client_id"));
    } else if (provider === "okta") {
      next.baseUrl = httpsUrlError(baseUrl, "Okta domain");
      whereChanged = !!source && baseUrl.trim() !== cfgString(source, "base_url");
    } else {
      next.baseUrl = httpsUrlError(baseUrl, "Keycloak base URL");
      next.realm = realm.trim() ? null : "Enter the realm";
      next.client = clientId.trim() ? null : "Enter the client ID";
      whereChanged = !!source && (baseUrl.trim() !== cfgString(source, "base_url") || clientId.trim() !== cfgString(source, "client_id"));
    }
    next.secret =
      secret || (secretSet && !whereChanged)
        ? null
        : secretSet
          ? `Re-enter the ${secretLabel.toLowerCase()}: it is cleared when the address or IDs change`
          : `Enter the ${secretLabel.toLowerCase()}`;
    setErrors(next);
    if (Object.values(next).some(Boolean)) return;
    save.mutate();
  };

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{source ? `Edit ${source.name}` : `Connect ${row.label}`}</DialogTitle>
          <DialogDescription>
            {provider === "entra_id"
              ? "An app registration with the Application.Read.All application permission (read-only)."
              : provider === "okta"
                ? "A read-only API token from your Okta admin console."
                : "A confidential client in the realm with read-only access to clients and keys."}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <Field label="Name" htmlFor="idp-name" required error={errors.name}>
            <Input id="idp-name" data-testid="cloud-idp-name" value={name} maxLength={64} onChange={(e) => setName(e.target.value)} />
          </Field>
          {provider === "entra_id" && (
            <Field label="Directory (tenant) ID" htmlFor="idp-tenant" required error={errors.tenant}>
              <Input
                id="idp-tenant"
                className="font-mono text-sm"
                value={tenantId}
                maxLength={36}
                spellCheck={false}
                placeholder="00000000-0000-0000-0000-000000000000"
                onChange={(e) => setTenantId(e.target.value)}
              />
            </Field>
          )}
          {(provider === "okta" || provider === "keycloak") && (
            <Field label={provider === "okta" ? "Okta domain" : "Base URL"} htmlFor="idp-base" required error={errors.baseUrl}>
              <Input
                id="idp-base"
                value={baseUrl}
                maxLength={512}
                spellCheck={false}
                placeholder={provider === "okta" ? "https://example.okta.com" : "https://sso.example.com"}
                onChange={(e) => setBaseUrl(e.target.value)}
              />
            </Field>
          )}
          {provider === "keycloak" && (
            <Field label="Realm" htmlFor="idp-realm" required error={errors.realm}>
              <Input id="idp-realm" value={realm} maxLength={128} placeholder="corp" onChange={(e) => setRealm(e.target.value)} />
            </Field>
          )}
          {(provider === "entra_id" || provider === "keycloak") && (
            <Field label={provider === "entra_id" ? "Application (client) ID" : "Client ID"} htmlFor="idp-client" required error={errors.client}>
              <Input id="idp-client" className="font-mono text-sm" value={clientId} maxLength={128} spellCheck={false} onChange={(e) => setClientId(e.target.value)} />
            </Field>
          )}
          <SecretField
            id="idp-secret"
            label={secretLabel}
            value={secret}
            onChange={setSecret}
            isSet={secretSet}
            required
            error={errors.secret}
            hint={secretSet ? "Saved. Leave blank to keep it; changing the address or IDs clears it." : STORED_HINT}
          />
          <p className="text-xs text-zinc-500">{NOT_AVAILABLE}</p>
        </div>
        <DialogFooter>
          <Button variant="outline" className="cursor-pointer" onClick={onClose}>
            Cancel
          </Button>
          <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={save.isPending} onClick={submit} data-testid="cloud-idp-save">
            {save.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------- SAML / OIDC metadata URLs
function MetadataUrls({
  teamId,
  sources,
  takenNames,
  onDelete,
}: {
  teamId: number;
  sources: CbomSource[];
  takenNames: string[];
  onDelete: (s: CbomSource) => void;
}) {
  const invalidate = useInvalidate(teamId);
  const [urls, setUrls] = useState<Record<MetadataProvider, string>>({ saml_metadata: "", oidc_discovery: "" });
  const [errors, setErrors] = useState<Partial<Record<MetadataProvider, string | null>>>({});

  const save = useMutation({
    mutationFn: ({ provider, url }: { provider: MetadataProvider; url: string }) => {
      let host = "idp";
      try {
        host = new URL(url).hostname;
      } catch {
        /* validated before; keep the fallback */
      }
      const name = uniqueName(`${provider === "saml_metadata" ? "saml" : "oidc"}-${host}`, takenNames);
      return createCbomSource(teamId, { kind: "idp", name, config: { provider, metadata_url: url } });
    },
    onSuccess: (_data, v) => setUrls((u) => ({ ...u, [v.provider]: "" })),
    onSettled: invalidate,
  });

  const submit = (provider: MetadataProvider) => {
    const url = urls[provider].trim();
    const error = httpsUrlError(url, "URL", 1000);
    const duplicate = sources.some((s) => s.config?.provider === provider && cfgString(s, "metadata_url") === url);
    setErrors((e) => ({ ...e, [provider]: error ?? (duplicate ? "This URL is already saved" : null) }));
    if (error || duplicate) return;
    save.mutate({ provider, url });
  };

  const input = (provider: MetadataProvider, label: string, placeholder: string, testId: string) => (
    <Field label={label} htmlFor={`idp-${provider}`} error={errors[provider]}>
      <div className="flex flex-wrap gap-2">
        <Input
          id={`idp-${provider}`}
          data-testid={`${testId}-url`}
          className="flex-1 min-w-[200px]"
          value={urls[provider]}
          maxLength={1000}
          spellCheck={false}
          placeholder={placeholder}
          onChange={(e) => setUrls((u) => ({ ...u, [provider]: e.target.value }))}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              submit(provider);
            }
          }}
        />
        <Button variant="outline" className="cursor-pointer" disabled={save.isPending} onClick={() => submit(provider)} data-testid={`${testId}-save`}>
          {save.isPending && save.variables?.provider === provider && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
          Save
        </Button>
      </div>
    </Field>
  );

  return (
    <div className="space-y-4">
      <p className="text-xs text-zinc-500">
        No admin access? Public metadata is enough to read signing keys and their rotation. The URLs are saved for ZeroShield&apos;s identity
        collector to fetch later; nothing is fetched now.
      </p>
      {input("saml_metadata", "SAML metadata URL", "https://login.example.com/saml/metadata", "cloud-saml")}
      {input("oidc_discovery", "OIDC discovery URL", "https://login.example.com/.well-known/openid-configuration", "cloud-oidc")}
      {sources.length > 0 && (
        <ul className="space-y-1.5" data-testid="cloud-metadata-list">
          {sources.map((s) => (
            <li key={s.id} className="flex items-center gap-2 rounded-md border border-zinc-200 dark:border-zinc-800 px-3 py-2">
              <StatusBadge tone="zinc">{METADATA_LABEL[s.config?.provider as MetadataProvider] ?? "Metadata"}</StatusBadge>
              <Truncate className="flex-1 min-w-0 font-mono text-xs text-zinc-700 dark:text-zinc-300" text={cfgString(s, "metadata_url")} />
              <Button variant="ghost" size="icon-sm" className="cursor-pointer shrink-0" aria-label={`Delete ${s.name}`} onClick={() => onDelete(s)}>
                <Trash2 className="h-4 w-4" />
              </Button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
