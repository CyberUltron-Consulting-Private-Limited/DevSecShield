"use client";

import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ChevronDown,
  ChevronUp,
  Download,
  FlaskConical,
  Loader2,
  MoreVertical,
  Pencil,
  Plus,
  Power,
  RotateCw,
  Save,
  Server,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { toast } from "@/utils/toast";

import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import {
  countCbomTargets,
  createCbomSource,
  deleteCbomSource,
  getCbomSourcesOverview,
  getCbomSourcesSettings,
  getCbomTemplate,
  listCbomScanNodes,
  listCbomSources,
  testCbomSource,
  updateCbomSource,
  type CbomJob,
  type CbomScanNode,
  type CbomSource,
  type CbomSourceSaveResponse,
  type CbomSourcesSettings,
  type CbomSourceWrite,
  type CbomTestSample,
} from "@/utils/backend_api";

import { listSshCas } from "@/utils/api/cbom_ssh_ca";

import { cbomSourcesKeys, TERMINAL_JOB } from "./keys";
import { principalOk } from "./fleet/sshCaLogic";
import { MetadataFields, metadataConfig, metadataFrom, type SourceMetadata } from "./SourceMetadata";
import {
  ago,
  blankSecretError,
  ansibleSnippet,
  countHours,
  csvFirstColumn,
  defaultWindow,
  formatDateTime,
  normalizeGrid,
  pluralize,
  readTextFile,
  SUDOERS_DOWNLOAD,
  splitLines,
  type WindowGrid,
} from "./logic";
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
  NodeStatusBadge,
  SecretField,
  SectionCard,
  StatusBadge,
  TestStatusBadge,
  Truncate,
  nodeStatusLabel,
  useMenuReveal,
  usePolledJob,
  type Tone,
} from "./shared";

// ---------------------------------------------------------------------------- constants (mirror backend kinds.py / templates.py)
type ServerKind = "linux_servers" | "windows_servers" | "active_directory";
type CredType = "node_key" | "ssh_cert" | "vault" | "password" | "ssh_ca";
type HostKeyPolicy = "tofu" | "pinned";
type WindowMode = "network" | "any" | "custom";

interface KindInfo {
  value: ServerKind;
  short: string;
  label: string;
  port: number;
  login: string;
  portLabel: string;
  defaultCred: CredType;
  creds: CredType[];
}

const KINDS: KindInfo[] = [
  { value: "linux_servers", short: "linux", label: "Linux", port: 22, login: "zs-cbom", portLabel: "SSH port", defaultCred: "node_key", creds: ["node_key", "ssh_ca", "ssh_cert", "vault", "password"] },
  { value: "windows_servers", short: "windows", label: "Windows", port: 5986, login: "svc-zscbom", portLabel: "WinRM port (HTTPS)", defaultCred: "password", creds: ["vault", "password"] },
  { value: "active_directory", short: "ad", label: "Active Directory", port: 636, login: "svc-zscbom", portLabel: "LDAPS port", defaultCred: "password", creds: ["vault", "password"] },
];
const KIND_INFO = Object.fromEntries(KINDS.map((k) => [k.value, k])) as Record<ServerKind, KindInfo>;

const CRED_TEXT: Record<CredType, { title: string; description: string }> = {
  node_key: { title: "Node-generated SSH key", description: "Recommended. The private key never leaves the node." },
  ssh_cert: { title: "SSH certificate", description: "Short-lived, signed by your SSH CA" },
  ssh_ca: { title: "SSH CA certificate", description: "ZeroShield's SSH CA signs the node's own key for each job (minutes)" },
  vault: { title: "Vault reference", description: "CyberArk, HashiCorp Vault, AWS Secrets Manager, Azure Key Vault" },
  password: { title: "Password", description: "Encrypted at rest by ZeroShield; sent only to the scan node that runs the job" },
};

const VAULT_PROVIDERS = [
  { value: "hashicorp", label: "HashiCorp Vault" },
  { value: "cyberark", label: "CyberArk" },
  { value: "aws_secrets_manager", label: "AWS Secrets Manager" },
  { value: "azure_key_vault", label: "Azure Key Vault" },
];

// Must equal backend/utilities/cbom_sources/templates.py TIER1_COMMANDS / TIER2_COMMANDS (a backend test checks this).
const TIER1_COMMANDS = [
  "cat /etc/os-release",
  "uname -r",
  "dpkg-query -W -f '${Package}\\t${Version}\\n'  (or: rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n')",
  "cat /etc/crypto-policies/config",
  "cat /proc/sys/crypto/fips_enabled",
  "openssl version -a",
  "cat /etc/ssh/sshd_config",
  "ssh-keygen -l -f /etc/ssh/ssh_host_<type>_key.pub",
  "ps -eo pid=,comm=",
  "openssl storeutl -noout -text -certs <file>",
  "openssl pkey -pubout -passin pass: -in <file>",
  "grep -c 'PRIVATE KEY-----' <file>",
  "ssh-keygen -l -f <file>",
  "keytool -J-XX:-UsePerfData -list -v -keystore <file>",
  "stat -c %a <file>",
  "lsblk -nr -o MAJ:MIN,FSTYPE,FSVER",
  "systemctl show --type=service --state=running -p Id -p FragmentPath -p Environment -p ExecStart '*'",
  "grep -rnIEs 'openssl[[:space:]]+(enc|des|des3|des-ede3|aes-[0-9]+-[a-z]+|bf|rc4|rc2|cast)([[:space:]]|$)' /etc/cron.d /etc/crontab /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /usr/local/bin /usr/local/sbin",
  "grep -rnIEs '^[[:space:]]*(ssl_protocols|ssl_ciphers|SSLProtocol|SSLCipherSuite)[[:space:]]' /etc/nginx /etc/httpd /etc/apache2",
  "grep -nEi '^[[:space:]]*(MinProtocol|MaxProtocol|CipherString|Ciphersuites|jdk[.]tls[.]disabledAlgorithms|jdk[.]certpath[.]disabledAlgorithms)[[:space:]]*=' <file>",
];
const TIER2_COMMANDS = [
  "/usr/bin/ss -H -tlnp",
  "/usr/bin/find /proc -maxdepth 2 -name maps -exec /usr/bin/grep -HE libssl|libcrypto|libgnutls|libnss3|libgcrypt|libsodium|libwolfssl|libmbedcrypto|libbotan|libnettle {} +",
  "/usr/bin/find /proc -maxdepth 2 -name exe -printf %h\\t%l\\n",
  "/usr/sbin/sshd -T",
  "/usr/sbin/dmsetup table --target crypt",
  "/usr/bin/lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT",
  "/usr/bin/find /etc /opt /srv /home /root /usr/local -xdev -type f -size -1024k -regextype posix-extended -regex .+(\\.pem|\\.crt|\\.cer|\\.der|\\.key|\\.p8|\\.pk8|\\.p12|\\.pfx|\\.jks|\\.jceks|\\.bks|\\.keystore|\\.truststore|/id_rsa|/id_dsa|/id_ecdsa|/id_ed25519|/authorized_keys|/ssh_host_.+_key) -print0",
];

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;
const NAME_ERROR = "Use 1-64 letters, digits, spaces, dots, dashes or underscores, starting with a letter or digit.";
const LOGIN_RE = /^[A-Za-z0-9._@$\\-]{1,64}$/;
const SSH_PRINCIPAL_RE = /^zs-(0|[1-9]\d{0,9})-[a-z0-9][a-z0-9._-]{0,47}$/; // F1.4: mirrors sshca/certs.py (one spelling)
const MAX_TARGET_LINES = 1000;
const MAX_EXCLUSIONS = 2000;
const READY = new Set(["ready", "ok", "passed"]);
const WAITING = new Set(["pending", "running", "queued", "claimed"]);
const BAD = new Set(["failed", "failure", "error", "no_route", "unreachable", "host_key_changed", "identity_unverified", "login_failed", "auth_failed", "timeout", "refused"]);

// ---------------------------------------------------------------------------- helpers
/** Never-scan accepts one per line or comma separated (the design shows "10.20.0.1, 10.20.0.254"). */
function splitList(text: string): string[] {
  return splitLines(text.replace(/[,;]/g, "\n"));
}

function intIn(value: string, min: number, max: number): number | null {
  const text = value.trim();
  if (!/^\d{1,6}$/.test(text)) return null;
  const n = Number(text);
  return n >= min && n <= max ? n : null;
}

function httpStatus(err: unknown): number | undefined {
  return (err as { response?: { status?: number } } | null)?.response?.status;
}

function testJobId(test: CbomSourceSaveResponse["test"]): number | null {
  return test && "job_id" in test && typeof test.job_id === "number" ? test.job_id : null;
}

function downloadText(text: string, filename: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function scrollToId(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function sampleTone(status: string): Tone {
  if (READY.has(status)) return "green";
  if (WAITING.has(status)) return "blue";
  if (BAD.has(status)) return "red";
  return "amber";
}

function sampleLabel(status: string): string {
  if (READY.has(status)) return "Ready";
  const text = status.replace(/[_-]+/g, " ").trim();
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : "Unknown";
}

function yesNo(value: boolean | undefined, pending: boolean, notNeeded = false): string {
  if (value === true) return "Yes";
  if (value === false) return "No";
  if (pending) return "Waiting";
  return notNeeded ? "Not needed" : "Not run";
}

function minutes(seconds: number | null): string {
  if (seconds == null) return "";
  if (seconds < 60) return `${seconds} s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return s ? `${m} min ${s} s` : `${m} min`;
}

// ---------------------------------------------------------------------------- form state
interface FormState {
  kind: ServerKind;
  name: string;
  targets: string;
  exclusions: string;
  nodeId: number | null;
  port: string;
  loginUser: string;
  hostKeyPolicy: HostKeyPolicy;
  knownHosts: string;
  caPem: string;
  credentialType: CredType;
  vaultProvider: string;
  vaultPath: string;
  password: string;
  sshCertificate: string;
  privateKey: string;
  // F1.4 ssh_ca: the CA lineage, principals (zs-<team>-<group>) and the addresses the servers see the node as
  sshCaId: number | null;
  sshPrincipals: string;
  sshSourceAddresses: string;
  tier: 1 | 2;
  parallel: string;
  timeoutS: string;
  window: WindowMode;
  customWindow: WindowGrid | null;
}
type ErrorKey = keyof FormState | "csv" | "knownHostsFile" | "caFile";
type Errors = Partial<Record<ErrorKey, string>>;

function initialForm(source: CbomSource | null, nodes: CbomScanNode[]): FormState {
  if (!source) {
    const info = KIND_INFO.linux_servers;
    return {
      kind: info.value,
      name: "",
      targets: "",
      exclusions: "",
      nodeId: nodes.length === 1 ? nodes[0].id : null,
      port: String(info.port),
      loginUser: info.login,
      hostKeyPolicy: "tofu",
      knownHosts: "",
      caPem: "",
      credentialType: info.defaultCred,
      vaultProvider: "hashicorp",
      vaultPath: "",
      password: "",
      sshCertificate: "",
      privateKey: "",
      sshCaId: null,
      sshPrincipals: "",
      sshSourceAddresses: "",
      tier: 1,
      parallel: "8",
      timeoutS: "300",
      window: "network",
      customWindow: null,
    };
  }
  const cfg = source.config ?? {};
  const kind = (KIND_INFO[source.kind as ServerKind] ? source.kind : "linux_servers") as ServerKind;
  const info = KIND_INFO[kind];
  const cred = (info.creds.includes(cfg.credential_type) ? cfg.credential_type : info.defaultCred) as CredType;
  return {
    kind,
    name: source.name,
    targets: Array.isArray(cfg.targets) ? cfg.targets.join("\n") : "",
    exclusions: Array.isArray(cfg.exclusions) ? cfg.exclusions.join("\n") : "",
    nodeId: source.node_id,
    port: String(cfg.port ?? info.port),
    loginUser: String(cfg.login_user ?? info.login),
    hostKeyPolicy: cfg.host_key_policy === "pinned" ? "pinned" : "tofu",
    knownHosts: typeof cfg.known_hosts === "string" ? cfg.known_hosts : "",
    caPem: typeof cfg.ca_pem === "string" ? cfg.ca_pem : "",
    credentialType: cred,
    vaultProvider: cfg.vault?.provider ?? "hashicorp",
    vaultPath: cfg.vault?.path ?? "",
    password: "",
    sshCertificate: "",
    privateKey: "",
    sshCaId: typeof cfg.ssh_ca_id === "number" ? cfg.ssh_ca_id : null,
    sshPrincipals: Array.isArray(cfg.ssh_principals) ? cfg.ssh_principals.join("\n") : "",
    sshSourceAddresses: Array.isArray(cfg.ssh_source_addresses) ? cfg.ssh_source_addresses.join("\n") : "",
    tier: cfg.tier === 2 ? 2 : 1,
    parallel: String(cfg.parallel ?? 8),
    timeoutS: String(cfg.timeout_s ?? 300),
    window: cfg.window === "any" || cfg.window === "custom" ? cfg.window : "network",
    customWindow: cfg.window === "custom" && Array.isArray(cfg.custom_window) ? normalizeGrid(cfg.custom_window) : null,
  };
}

/** Same list as the server would store, so we can tell when a stored secret is about to be cleared. */
function whereChanged(form: FormState, source: CbomSource | null): boolean {
  if (!source) return false;
  const cfg = source.config ?? {};
  const stored = Array.isArray(cfg.targets) ? (cfg.targets as string[]).join("\n") : "";
  // How the node checks the server's identity also counts: a weaker check must not reuse a stored password.
  const linux = source.kind === "linux_servers";
  const policy = linux ? form.hostKeyPolicy : "tofu";
  const knownHosts = linux && form.hostKeyPolicy === "pinned" ? form.knownHosts.trim() : null;
  const vault = form.credentialType === "vault" ? `${form.vaultProvider}|${form.vaultPath.trim()}` : null;
  const storedVault = cfg.vault ? `${cfg.vault.provider}|${cfg.vault.path}` : null;
  return (
    splitLines(form.targets).join("\n") !== stored ||
    Number(form.port) !== Number(cfg.port) ||
    form.loginUser.trim() !== String(cfg.login_user ?? "") ||
    form.nodeId !== source.node_id ||
    policy !== (cfg.host_key_policy ?? "tofu") ||
    (!linux && (form.caPem.trim() || null) !== ((typeof cfg.ca_pem === "string" && cfg.ca_pem.trim()) || null)) ||
    (knownHosts || null) !== ((typeof cfg.known_hosts === "string" && cfg.known_hosts.trim()) || null) ||
    vault !== storedVault
  );
}

// ---------------------------------------------------------------------------- tab
export default function ServersTab({ teamId, onNavigate }: { teamId: number; onNavigate: (tab: string) => void }) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<CbomSource | null>(null);
  const [formNonce, setFormNonce] = useState(0);
  const [testView, setTestView] = useState<{ sourceId: number; jobId: number | null } | null>(null);
  const [deleting, setDeleting] = useState<CbomSource | null>(null);
  const rowMenu = useMenuReveal();

  const nodesQuery = useQuery({
    queryKey: cbomSourcesKeys.nodes(teamId),
    queryFn: () => listCbomScanNodes(teamId),
    enabled: Number.isFinite(teamId),
    retry: 1,
    refetchInterval: 30000,
  });
  const sourcesQuery = useQuery({
    queryKey: cbomSourcesKeys.sources(teamId, "servers"),
    queryFn: () => listCbomSources(teamId, "servers"),
    enabled: Number.isFinite(teamId),
    retry: 1,
    // Faster while a connection test is waiting, so the badge and samples update on their own.
    refetchInterval: (query) => (query.state.data?.sources.some((s) => s.last_test_status === "pending") ? 6000 : 30000),
  });
  const settingsQuery = useQuery({
    queryKey: cbomSourcesKeys.settings(teamId),
    queryFn: () => getCbomSourcesSettings(teamId),
    enabled: Number.isFinite(teamId),
    retry: 1,
  });
  const nodes = useMemo(() => nodesQuery.data?.nodes ?? [], [nodesQuery.data]);
  // host agents (agent-mode nodes, one source each) are listed on the Scan nodes tab, not here
  const sources = useMemo(() => (sourcesQuery.data?.sources ?? []).filter((s) => s.kind !== "host_agent"), [sourcesQuery.data]);
  const serverNow = sourcesQuery.data?.server_time;
  const jobQuery = usePolledJob(teamId, testView?.jobId ?? null);
  const testedSource = testView ? sources.find((s) => s.id === testView.sourceId) ?? null : null;

  const invalidate = () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });

  const testMutation = useMutation({
    mutationFn: (source: CbomSource) => testCbomSource(teamId, source.id),
    onSuccess: (data, source) => {
      if (data.job) setTestView({ sourceId: source.id, jobId: data.job.id });
    },
    onSettled: invalidate,
  });
  const toggleMutation = useMutation({
    mutationFn: (source: CbomSource) => updateCbomSource(teamId, source.id, { enabled: !source.enabled, expected_version: source.row_version }),
    // Keep an open edit form on the new version so its next save does not hit a 409.
    onSuccess: (data) => setEditing((cur) => (cur && cur.id === data.source.id ? data.source : cur)),
    onSettled: invalidate,
  });
  const deleteMutation = useMutation({
    mutationFn: (source: CbomSource) => deleteCbomSource(teamId, source.id),
    onSuccess: (_data, source) => {
      setDeleting(null);
      setEditing((cur) => (cur && cur.id === source.id ? null : cur));
      setTestView((cur) => (cur && cur.sourceId === source.id ? null : cur));
    },
    onSettled: invalidate,
  });

  // Scroll after the re-render: the form is remounted (new key) and the test panel opens, so a scroll started before
  // them lands below the form (lab UI round 5: Edit from the table left the page at the table, scrolled further down).
  const startNew = () => {
    setEditing(null);
    setFormNonce((n) => n + 1);
    window.setTimeout(() => scrollToId("servers-form"), 0);
  };
  // From the row menu: the form is revealed when the menu has closed (reveal.ts), not here.
  const startEdit = (source: CbomSource) => {
    setEditing(source);
    setTestView(source.last_test_status === "never" ? null : { sourceId: source.id, jobId: source.last_test_job_id });
    rowMenu.request("servers-form");
  };
  const showResults = (source: CbomSource, fromMenu = false) => {
    setTestView({ sourceId: source.id, jobId: source.last_test_job_id });
    if (fromMenu) rowMenu.request("servers-test");
    else window.setTimeout(() => scrollToId("servers-test"), 0);
  };
  const onSaved = (source: CbomSource, jobId: number | null, tested: boolean) => {
    if (tested) {
      // "Save and test" keeps the form on this source so it can be fixed and tested again. The nonce
      // remounts the form even when nothing changed, so typed secrets never stay in memory.
      setEditing(source);
      setFormNonce((n) => n + 1);
      setTestView({ sourceId: source.id, jobId });
      window.setTimeout(() => scrollToId("servers-test"), 0);
    } else {
      setEditing(null);
      setFormNonce((n) => n + 1);
      setTestView((cur) => (cur && cur.sourceId === source.id ? null : cur));
    }
  };
  const onStale = () => {
    setEditing(null);
    setFormNonce((n) => n + 1);
  };

  if (nodesQuery.isLoading || sourcesQuery.isLoading) return <LoadingBlock />;
  if ((nodesQuery.isError && !nodesQuery.data) || (sourcesQuery.isError && !sourcesQuery.data)) {
    return (
      <ErrorBlock
        error={nodesQuery.error ?? sourcesQuery.error}
        onRetry={() => {
          nodesQuery.refetch();
          sourcesQuery.refetch();
        }}
      />
    );
  }

  return (
    <div className="space-y-6">
      {nodes.length === 0 ? (
        <SectionCard title="Add servers" description="Servers are read over SSH or WinRM by your scan node, with a read-only account.">
          <EmptyState
            title="Add a scan node first"
            body="Servers are reached through a scan node that runs inside your network. Add one on the Scan nodes tab, then come back to add servers."
            action={
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => onNavigate("scan-nodes")} data-testid="servers-go-scan-nodes">
                <Server className="h-4 w-4 mr-2" />
                Go to Scan nodes
              </Button>
            }
          />
        </SectionCard>
      ) : (
        <ServerForm
          key={editing ? `edit-${editing.id}-${editing.row_version}-${formNonce}` : `new-${formNonce}`}
          teamId={teamId}
          source={editing}
          nodes={nodes}
          settings={settingsQuery.data}
          onSaved={onSaved}
          onCancelEdit={startNew}
          onStale={onStale}
          onNavigate={onNavigate}
        />
      )}

      {testView && testedSource && (
        <TestResultsCard
          source={testedSource}
          job={jobQuery.data && jobQuery.data.id === testView.jobId ? jobQuery.data : undefined}
          jobLoading={!!testView.jobId && jobQuery.isLoading}
          serverNow={serverNow}
          retesting={testMutation.isPending}
          onRetest={() => testMutation.mutate(testedSource)}
          onClose={() => setTestView(null)}
        />
      )}

      <SectionCard
        title="Configured server sources"
        description={sources.length ? `${pluralize(sources.length, "source")}, ${pluralize(sources.reduce((sum, s) => sum + s.target_count, 0), "target")} after exclusions` : "Server sources you add appear here."}
      >
        {sources.length === 0 ? (
          <EmptyState
            title="No servers added yet"
            body="Add Linux servers, Windows servers or Active Directory with the form above. Each source is one list of targets reached through one scan node."
            action={
              nodes.length ? (
                <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={startNew}>
                  <Plus className="h-4 w-4 mr-2" />
                  Add servers
                </Button>
              ) : (
                <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => onNavigate("scan-nodes")}>
                  <Server className="h-4 w-4 mr-2" />
                  Add a scan node
                </Button>
              )
            }
          />
        ) : (
          <ScrollArea className="w-full border rounded-lg">
            <div className="min-w-max">
              <Table data-testid="servers-table">
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead className="text-right">Targets</TableHead>
                    <TableHead>Node</TableHead>
                    <TableHead>Tier</TableHead>
                    <TableHead>Last test</TableHead>
                    <TableHead className="w-12">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sources.map((source) => (
                    <TableRow key={source.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800" data-testid={`servers-row-${source.id}`}>
                      <TableCell className="font-medium text-zinc-900 dark:text-white max-w-[240px]">
                        <div className="flex items-center gap-2 min-w-0">
                          <Truncate text={source.name} className="min-w-0" />
                          {!source.enabled && <StatusBadge tone="zinc">Disabled</StatusBadge>}
                        </div>
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">{source.kind_label}</TableCell>
                      <TableCell className="text-right text-zinc-600 dark:text-zinc-400">{source.target_count.toLocaleString()}</TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400 max-w-[200px]">
                        <div className="flex items-center gap-2 min-w-0">
                          <Truncate text={source.node_name ?? "—"} className="min-w-0" />
                          {source.node_status && source.node_status !== "online" && <NodeStatusBadge status={source.node_status} />}
                        </div>
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">
                        {source.kind === "linux_servers" ? `Tier ${source.config?.tier === 2 ? 2 : 1}` : "—"}
                      </TableCell>
                      <TableCell className="max-w-[260px]">
                        <button
                          type="button"
                          className="cursor-pointer text-left"
                          onClick={() => showResults(source)}
                          aria-label={`Show connection test results for ${source.name}`}
                          disabled={source.last_test_status === "never"}
                        >
                          <TestStatusBadge status={source.last_test_status} title={source.last_test_summary} />
                        </button>
                        {(source.last_test_summary || source.last_test_at) && (
                          <p className="text-xs text-zinc-500 mt-1 truncate" title={source.last_test_summary ?? undefined}>
                            {source.last_test_summary ?? ""}
                            {source.last_test_at ? `${source.last_test_summary ? " · " : ""}${ago(source.last_test_at, serverNow)}` : ""}
                          </p>
                        )}
                      </TableCell>
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" className="cursor-pointer" aria-label={`Actions for ${source.name}`} data-testid={`servers-actions-${source.id}`}>
                              <MoreVertical className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end" onCloseAutoFocus={rowMenu.onCloseAutoFocus}>
                            <DropdownMenuItem className="cursor-pointer" onSelect={() => startEdit(source)} data-testid={`servers-edit-${source.id}`}>
                              <Pencil className="h-4 w-4" />
                              Edit
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              className="cursor-pointer"
                              disabled={testMutation.isPending}
                              onSelect={() => testMutation.mutate(source)}
                              data-testid={`servers-test-${source.id}`}
                            >
                              <FlaskConical className="h-4 w-4" />
                              Run connection test
                            </DropdownMenuItem>
                            {source.last_test_status !== "never" && (
                              <DropdownMenuItem className="cursor-pointer" onSelect={() => showResults(source, true)}>
                                <Server className="h-4 w-4" />
                                Test results
                              </DropdownMenuItem>
                            )}
                            <DropdownMenuItem
                              className="cursor-pointer"
                              disabled={toggleMutation.isPending}
                              onSelect={() => toggleMutation.mutate(source)}
                              data-testid={`servers-toggle-${source.id}`}
                            >
                              <Power className="h-4 w-4" />
                              {source.enabled ? "Disable" : "Enable"}
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              variant="destructive"
                              className="cursor-pointer"
                              onSelect={() => setDeleting(source)}
                              data-testid={`servers-delete-${source.id}`}
                            >
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

      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(v) => !v && setDeleting(null)}
        title="Delete this server source?"
        description={
          deleting
            ? `${deleting.name} and its stored credentials are deleted. Pending tests and collection jobs for it are cancelled; results already collected stay in past scans.`
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

// ---------------------------------------------------------------------------- form
function ServerForm({
  teamId,
  source,
  nodes,
  settings,
  onSaved,
  onCancelEdit,
  onStale,
  onNavigate,
}: {
  teamId: number;
  source: CbomSource | null;
  nodes: CbomScanNode[];
  settings: CbomSourcesSettings | undefined;
  onSaved: (source: CbomSource, jobId: number | null, tested: boolean) => void;
  onCancelEdit: () => void;
  onStale: () => void;
  onNavigate: (tab: string) => void;
}) {
  const queryClient = useQueryClient();
  // Mounted with a key per source (and per version), so the form starts from the record without a sync effect.
  const [form, setForm] = useState<FormState>(() => initialForm(source, nodes));
  const [meta, setMeta] = useState<SourceMetadata>(() => metadataFrom(source?.config));
  const [errors, setErrors] = useState<Errors>({});
  const [showAnsible, setShowAnsible] = useState(false);
  const [showCommands, setShowCommands] = useState(false);
  const [debouncedTargets, setDebouncedTargets] = useState(form.targets);
  const [debouncedExclusions, setDebouncedExclusions] = useState(form.exclusions);
  const csvRef = useRef<HTMLInputElement>(null);
  const knownHostsRef = useRef<HTMLInputElement>(null);

  const info = KIND_INFO[form.kind];
  const isLinux = form.kind === "linux_servers";
  const overviewQuery = useQuery({
    queryKey: cbomSourcesKeys.overview(teamId),
    queryFn: () => getCbomSourcesOverview(teamId),
    enabled: Number.isFinite(teamId),
    retry: 1,
    staleTime: 60_000,
  });
  // Vault references fetch a secret on the node: only team admins may add or change them (server enforces too).
  const isAdmin = !!overviewQuery.data?.viewer?.is_admin;
  const caRef = useRef<HTMLInputElement>(null);
  // F1.4: the SSH CA option exists only while the deployment turns the CA on (its routes answer 404 otherwise)
  const sshCas = useQuery({
    queryKey: [...cbomSourcesKeys.all(teamId), "ssh-ca"],
    queryFn: () => listSshCas(teamId),
    enabled: Number.isFinite(teamId) && isLinux,
    retry: false,
    staleTime: 60_000,
  });
  const sshCaOn = sshCas.isSuccess;
  const signingCas = (sshCas.data?.cas ?? []).filter((c) => c.state === "active");
  const selectedNode = nodes.find((n) => n.id === form.nodeId) ?? null;
  const login = form.loginUser.trim() || info.login;
  const editingWhereChanged = whereChanged(form, source);
  const sameCredential = !!source && source.config?.credential_type === form.credentialType;
  const stored = (name: string) => sameCredential && !!source?.secrets_set.includes(name);

  const set = (patch: Partial<FormState>) => {
    setForm((f) => ({ ...f, ...patch }));
    setErrors((e) => {
      const next = { ...e };
      for (const key of Object.keys(patch)) delete next[key as ErrorKey];
      return next;
    });
  };

  // Debounce the live count (about 400 ms after the last keystroke).
  useEffect(() => {
    const timer = window.setTimeout(() => {
      setDebouncedTargets(form.targets);
      setDebouncedExclusions(form.exclusions);
    }, 400);
    return () => window.clearTimeout(timer);
  }, [form.targets, form.exclusions]);

  const teamExclusions = useMemo(() => (settings?.network_exclusions ?? []).map((e) => e.cidr).filter(Boolean), [settings]);
  const targetLines = useMemo(() => splitLines(debouncedTargets), [debouncedTargets]);
  const exclusionLines = useMemo(() => [...splitList(debouncedExclusions), ...teamExclusions], [debouncedExclusions, teamExclusions]);
  const countQuery = useQuery({
    queryKey: [...cbomSourcesKeys.all(teamId), "target-count", targetLines.join("\n"), exclusionLines.join("\n")],
    queryFn: () => countCbomTargets(teamId, targetLines, exclusionLines),
    enabled: Number.isFinite(teamId) && targetLines.length > 0,
    retry: 1,
    staleTime: 60_000,
    placeholderData: keepPreviousData,
  });
  const count = targetLines.length === 0 ? null : countQuery.data;
  const countError = count && !count.valid ? count.error : null;
  const countErrorOnExclusions = !!countError && /^never-scan/i.test(countError);

  const sudoers = useMutation({
    mutationFn: () => getCbomTemplate(teamId, "sudoers"),
    onSuccess: (text) => downloadText(text, SUDOERS_DOWNLOAD.filename, SUDOERS_DOWNLOAD.type),
    onError: () => toast.error("Could not download the sudoers file. Please try again."),
  });
  const windowsSetup = useMutation({
    mutationFn: () => getCbomTemplate(teamId, "windows-setup"),
    onSuccess: (text) => downloadText(text, "zs-cbom-windows-setup.ps1", "text/plain"),
    onError: () => toast.error("Could not download the Windows setup script. Please try again."),
  });

  const save = useMutation({
    mutationFn: ({ body, test }: { body: CbomSourceWrite; test: boolean }) =>
      source ? updateCbomSource(teamId, source.id, { ...body, test_after_save: test }) : createCbomSource(teamId, { ...body, test_after_save: test }),
    onSuccess: (data, vars) => onSaved(data.source, testJobId(data.test), vars.test),
    onError: (err) => {
      // 409: changed elsewhere; 404: deleted elsewhere. The API already toasted; reload from the list.
      const status = httpStatus(err);
      if (source && (status === 409 || status === 404)) onStale();
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) }),
  });

  const changeKind = (kind: ServerKind) => {
    if (kind === form.kind || source) return;
    const prev = KIND_INFO[form.kind];
    const next = KIND_INFO[kind];
    set({
      kind,
      port: !form.port.trim() || form.port.trim() === String(prev.port) ? String(next.port) : form.port,
      loginUser: !form.loginUser.trim() || form.loginUser.trim() === prev.login ? next.login : form.loginUser,
      credentialType: form.credentialType === prev.defaultCred || !next.creds.includes(form.credentialType) ? next.defaultCred : form.credentialType,
    });
  };

  const copyNetworkWindow = (): WindowGrid => {
    const grid = normalizeGrid(settings?.scan_window);
    return countHours(grid) > 0 ? grid : defaultWindow();
  };

  const validate = (): Errors => {
    const e: Errors = {};
    if (!NAME_RE.test(form.name.trim())) e.name = NAME_ERROR;
    const lines = splitLines(form.targets);
    if (lines.length === 0) e.targets = "Add at least one IP address, CIDR range or hostname";
    else if (lines.length > MAX_TARGET_LINES) e.targets = `${lines.length.toLocaleString()} lines; the limit is ${MAX_TARGET_LINES.toLocaleString()} per source`;
    else if (countError && !countErrorOnExclusions && debouncedTargets === form.targets) e.targets = countError;
    if (splitList(form.exclusions).length > MAX_EXCLUSIONS) e.exclusions = `The never-scan list is limited to ${MAX_EXCLUSIONS.toLocaleString()} entries`;
    else if (countErrorOnExclusions && countError && debouncedExclusions === form.exclusions) e.exclusions = countError;
    if (!form.nodeId) e.nodeId = "Choose the scan node that reaches these servers";
    if (intIn(form.port, 1, 65535) == null) e.port = "Enter a port from 1 to 65535";
    if (!LOGIN_RE.test(form.loginUser.trim())) e.loginUser = "Use up to 64 letters, digits and . _ @ $ \\ -";
    if (isLinux && form.hostKeyPolicy === "pinned" && !form.knownHosts.trim()) e.knownHosts = "Paste the known_hosts lines to pin, or choose trust on first use";
    if (isLinux && form.credentialType === "password" && form.hostKeyPolicy !== "pinned")
      e.hostKeyPolicy = "Password logins need pinned host keys, so the password only goes to the real servers";
    if (!isLinux && Number(form.port) === 5985) e.port = "WinRM over HTTP (5985) cannot prove the server; use HTTPS (5986)";
    if (form.credentialType === "vault" && !isAdmin) e.credentialType = "Only a team admin can add or change a vault reference";
    if (form.credentialType === "vault" && !form.vaultPath.trim()) e.vaultPath = "Enter the secret path in your vault";
    if (form.credentialType === "ssh_ca") {
      // certificates are issued only for sources a team admin saved (the server enforces it at issue time too)
      if (!isAdmin) e.credentialType = "Only a team admin can save a source that uses the SSH CA";
      if (!form.sshCaId) e.sshCaId = "Choose the SSH CA that signs the scan node's certificates";
      const principals = splitList(form.sshPrincipals);
      if (principals.length === 0 || principals.length > 16
        || principals.some((p) => !SSH_PRINCIPAL_RE.test(p) || !principalOk(p, teamId)))
        e.sshPrincipals = `One to 16 principals of this team like zs-${teamId}-prod, as listed in the servers' principals file`;
      if (splitList(form.sshSourceAddresses).length > 32) e.sshSourceAddresses = "At most 32 addresses";
    }
    // A stored secret survives only while the targets and their identity check stay the same: ask for it here
    // instead of letting the server refuse the save with a short toast.
    // (Set a key only for a real error: submit() counts the keys of the error object.)
    const blank = (key: "password" | "sshCertificate" | "privateKey", what: string, missing: string) => {
      const message = blankSecretError(stored(what), editingWhereChanged, missing);
      if (message) e[key] = message;
    };
    if (form.credentialType === "password" && !form.password) blank("password", "password", "Enter the password for this login");
    if (form.credentialType === "ssh_cert") {
      if (!form.sshCertificate.trim()) blank("sshCertificate", "ssh_certificate", "Paste the signed SSH certificate");
      if (!form.privateKey.trim()) blank("privateKey", "private_key", "Paste the private key the certificate was issued for");
    }
    if (intIn(form.parallel, 1, 64) == null) e.parallel = "Enter 1 to 64";
    if (intIn(form.timeoutS, 10, 3600) == null) e.timeoutS = "Enter 10 to 3600 seconds";
    if (form.window === "custom" && (!form.customWindow || countHours(form.customWindow) === 0)) e.window = "The custom window has no allowed hours";
    return e;
  };

  const submit = (test: boolean) => {
    const found = validate();
    setErrors(found);
    const metaConfig = metadataConfig(meta);
    if (Object.keys(found).length || typeof metaConfig === "string") {
      toast.error(typeof metaConfig === "string" ? metaConfig : "Check the highlighted fields");
      return;
    }
    const secrets: Record<string, string> = {};
    if (form.credentialType === "password" && form.password) secrets.password = form.password;
    if (form.credentialType === "ssh_cert") {
      if (form.sshCertificate.trim()) secrets.ssh_certificate = form.sshCertificate;
      if (form.privateKey.trim()) secrets.private_key = form.privateKey;
    }
    const body: CbomSourceWrite = {
      name: form.name.trim(),
      node_id: form.nodeId,
      config: {
        targets: splitLines(form.targets),
        exclusions: splitList(form.exclusions),
        port: Number(form.port.trim()),
        login_user: form.loginUser.trim(),
        host_key_policy: isLinux ? form.hostKeyPolicy : "tofu",
        known_hosts: isLinux && form.hostKeyPolicy === "pinned" ? form.knownHosts : null,
        ...(isLinux ? {} : { ca_pem: form.caPem.trim() ? form.caPem : null }),
        credential_type: form.credentialType,
        vault: form.credentialType === "vault" ? { provider: form.vaultProvider, path: form.vaultPath.trim() } : null,
        ...(form.credentialType === "ssh_ca"
          ? { ssh_ca_id: form.sshCaId, ssh_principals: splitList(form.sshPrincipals), ssh_source_addresses: splitList(form.sshSourceAddresses) }
          : {}),
        tier: isLinux ? form.tier : source?.config?.tier === 2 ? 2 : 1,
        parallel: Number(form.parallel.trim()),
        timeout_s: Number(form.timeoutS.trim()),
        window: form.window,
        custom_window: form.window === "custom" ? form.customWindow : null,
        ...metaConfig,
      },
      secrets,
      ...(source ? { expected_version: source.row_version } : { kind: form.kind }),
    };
    save.mutate({ body, test });
  };

  const readFileInto = async (file: File | undefined, apply: (text: string) => void, errorKey: ErrorKey) => {
    if (!file) return;
    try {
      const text = await readTextFile(file);
      // Clear first: apply() may set its own error for this key (e.g. an empty CSV).
      setErrors((e) => ({ ...e, [errorKey]: undefined }));
      apply(text);
    } catch (err) {
      setErrors((e) => ({ ...e, [errorKey]: (err as Error).message }));
    }
  };

  const secretHint = (what: string) =>
    source && editingWhereChanged && stored(what) ? (
      <span className="text-amber-600 dark:text-amber-400">
        The targets, port, login, host key check, vault path or scan node changed: enter it again, or the server refuses the save because
        stored credentials are cleared when the target or the way its identity is checked changes.
      </span>
    ) : source ? (
      "Encrypted at rest by ZeroShield; sent only to the scan node that runs the job. Changing the targets, port, login, host key check, vault path or scan node clears it unless you enter it again."
    ) : undefined;

  const hours = form.customWindow ? countHours(form.customWindow) : 0;
  const pendingTest = save.isPending && save.variables?.test;
  const pendingSave = save.isPending && !save.variables?.test;

  return (
    <div id="servers-form" className="grid grid-cols-1 xl:grid-cols-3 gap-6 items-start scroll-mt-4">
      <SectionCard
        className="xl:col-span-2"
        title={source ? `Edit ${source.name}` : "Add servers"}
        description={source ? `${source.kind_label} · blank secret fields keep the saved ones` : "Pick the server type, then where they are and how to log in."}
        actions={
          <div role="group" aria-label="Server type" className="inline-flex flex-wrap gap-1 rounded-lg bg-zinc-100 dark:bg-zinc-800/60 p-1">
            {KINDS.map((k) => {
              const on = k.value === form.kind;
              const locked = !!source && !on;
              return (
                <button
                  key={k.value}
                  type="button"
                  aria-pressed={on}
                  disabled={locked}
                  title={locked ? "A source's type cannot be changed; add a new source instead" : undefined}
                  onClick={() => changeKind(k.value)}
                  data-testid={`servers-kind-${k.short}`}
                  className={cn(
                    "h-7 px-3 rounded-md text-sm font-medium transition-colors",
                    on ? "bg-blue-600 text-white shadow-sm" : "text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white",
                    locked ? "cursor-not-allowed opacity-50" : "cursor-pointer",
                  )}
                >
                  {k.label}
                </button>
              );
            })}
          </div>
        }
      >
        <div className="space-y-6">
          <FormSection title="Targets">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Field label="Source name" htmlFor="servers-name" required error={errors.name} hint="Shown in lists and reports, e.g. dc-mumbai-linux">
                <Input
                  id="servers-name"
                  data-testid="servers-name"
                  value={form.name}
                  maxLength={64}
                  placeholder="dc-mumbai-linux"
                  onChange={(e) => set({ name: e.target.value })}
                />
              </Field>
              <Field
                label="Reached through scan node"
                htmlFor="servers-node"
                required
                error={errors.nodeId}
                hint={`The node must be able to reach port ${form.port || info.port} on these servers.`}
              >
                <div data-testid="servers-node">
                  <NodeSelect id="servers-node" nodes={nodes} value={form.nodeId} onChange={(v) => set({ nodeId: v })} />
                </div>
              </Field>
            </div>

            <Field
              label="IP addresses, CIDR ranges or hostnames, one per line"
              htmlFor="servers-targets"
              required
              error={errors.targets ?? (countErrorOnExclusions ? null : countError) ?? errors.csv}
              hint="Up to 1,000 lines. Each range may be at most a /16; a source may cover up to 262,144 addresses."
            >
              <Textarea
                id="servers-targets"
                data-testid="servers-targets"
                value={form.targets}
                rows={5}
                spellCheck={false}
                placeholder={"10.20.0.0/24\n10.20.5.17\napp-01.bank.local"}
                className="font-mono text-xs min-h-[112px] max-h-72 overflow-y-auto resize-y"
                onChange={(e) => set({ targets: e.target.value })}
              />
            </Field>
            <div className="flex flex-wrap items-center gap-2">
              <input
                ref={csvRef}
                type="file"
                accept=".csv,.txt,text/csv,text/plain"
                className="hidden"
                data-testid="servers-csv-input"
                onChange={async (e) => {
                  const input = e.currentTarget;
                  await readFileInto(
                    input.files?.[0],
                    (text) => {
                      const rows = csvFirstColumn(text);
                      if (!rows.length) {
                        setErrors((er) => ({ ...er, csv: "No addresses found in the first column of that file" }));
                        return;
                      }
                      setForm((f) => ({ ...f, targets: [...splitLines(f.targets), ...rows].filter((v, i, all) => all.indexOf(v) === i).join("\n") }));
                      setErrors((er) => ({ ...er, targets: undefined }));
                      toast.success(`Imported ${pluralize(rows.length, "line")}`);
                    },
                    "csv",
                  );
                  input.value = "";
                }}
              />
              <Button type="button" variant="outline" size="sm" className="cursor-pointer" onClick={() => csvRef.current?.click()} data-testid="servers-import-csv">
                <Upload className="h-4 w-4 mr-1.5" />
                Import CSV
              </Button>
              <span className="text-xs text-zinc-500">First column of each row; a header row is skipped.</span>
              <span className="flex-1" />
              <span data-testid="servers-target-count" aria-live="polite">
                <StatusBadge tone={countError ? "red" : "blue"}>
                  {countQuery.isFetching && targetLines.length > 0 && <Loader2 className="animate-spin" />}
                  {countError
                    ? "Check the targets"
                    : `${(count?.count ?? 0).toLocaleString()} ${count?.count === 1 ? "target" : "targets"} after exclusions`}
                </StatusBadge>
              </span>
            </div>
            {teamExclusions.length > 0 && (
              <p className="text-xs text-zinc-500 -mt-2">
                The count also removes the team never-scan list ({pluralize(teamExclusions.length, "entry", "entries")}) from the Network tab.
              </p>
            )}

            <Field
              label="Never scan"
              htmlFor="servers-exclusions"
              error={errors.exclusions ?? (countErrorOnExclusions ? countError : null)}
              hint="IP addresses, ranges or hostnames, one per line or separated by commas. A listed hostname also covers every address it resolves to from the scan node; until it resolves there, none of these targets is scanned. A target name is skipped if any address it resolves to is listed; ranges are checked one address at a time. Never-scan always wins."
            >
              <Textarea
                id="servers-exclusions"
                data-testid="servers-exclusions"
                value={form.exclusions}
                rows={2}
                spellCheck={false}
                placeholder="10.20.0.1, 10.20.0.254"
                className="font-mono text-xs min-h-[64px] max-h-48 overflow-y-auto resize-y"
                onChange={(e) => set({ exclusions: e.target.value })}
              />
            </Field>
          </FormSection>

          <FormSection title="Connection">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Field label={info.portLabel} htmlFor="servers-port" required error={errors.port}>
                <Input
                  id="servers-port"
                  data-testid="servers-port"
                  inputMode="numeric"
                  value={form.port}
                  maxLength={5}
                  onChange={(e) => set({ port: e.target.value.replace(/[^\d]/g, "") })}
                />
              </Field>
              <Field
                label="Login user"
                htmlFor="servers-login"
                required
                error={errors.loginUser}
                hint={isLinux ? "A read-only account on each server" : "A local or domain account; DOMAIN\\user is accepted"}
              >
                <Input
                  id="servers-login"
                  data-testid="servers-login"
                  value={form.loginUser}
                  maxLength={64}
                  autoComplete="off"
                  onChange={(e) => set({ loginUser: e.target.value })}
                />
              </Field>
            </div>
            {isLinux && (
              <div className="space-y-3">
                <p className="text-sm font-medium">Host key policy</p>
                <div data-testid="servers-host-key-policy">
                  <ChoiceCards<HostKeyPolicy>
                    name="servers-host-key"
                    label="Host key policy"
                    value={form.hostKeyPolicy}
                    onChange={(v) => set({ hostKeyPolicy: v })}
                    options={[
                      {
                        value: "tofu",
                        title: "Trust on first use",
                        description:
                          form.credentialType === "password"
                            ? "Not with a password: a key seen for the first time proves nothing"
                            : "Remember each key on first contact; refuse and alert if it changes",
                        disabled: form.credentialType === "password",
                      },
                      { value: "pinned", title: "Pin fingerprints", description: "Paste or upload a known_hosts file" },
                    ]}
                  />
                </div>
                {errors.hostKeyPolicy && <p className="text-xs text-red-600 dark:text-red-400">{errors.hostKeyPolicy}</p>}
                {form.hostKeyPolicy === "pinned" && (
                  <Field
                    label="known_hosts lines"
                    htmlFor="servers-known-hosts"
                    required
                    error={errors.knownHosts ?? errors.knownHostsFile}
                    hint="Output of ssh-keyscan or your existing known_hosts file. Public keys only."
                  >
                    <Textarea
                      id="servers-known-hosts"
                      data-testid="servers-known-hosts"
                      value={form.knownHosts}
                      rows={4}
                      spellCheck={false}
                      placeholder="10.20.0.11 ssh-ed25519 AAAAC3Nza..."
                      className="font-mono text-xs min-h-[96px] max-h-72 overflow-y-auto resize-y"
                      onChange={(e) => set({ knownHosts: e.target.value })}
                    />
                    <input
                      ref={knownHostsRef}
                      type="file"
                      className="hidden"
                      data-testid="servers-known-hosts-file"
                      onChange={async (e) => {
                        const input = e.currentTarget;
                        await readFileInto(input.files?.[0], (text) => set({ knownHosts: text }), "knownHostsFile");
                        input.value = "";
                      }}
                    />
                    <div>
                      <Button type="button" variant="outline" size="sm" className="cursor-pointer" onClick={() => knownHostsRef.current?.click()}>
                        <Upload className="h-4 w-4 mr-1.5" />
                        Upload known_hosts
                      </Button>
                    </div>
                  </Field>
                )}
              </div>
            )}
            {!isLinux && (
              <Field
                label="CA certificate (optional)"
                htmlFor="servers-ca"
                error={errors.caPem ?? errors.caFile}
                hint={form.kind === "active_directory"
                  ? "LDAPS is checked against the domain controller's certificate before the login is sent. Add the CA that issued it when it is an internal CA."
                  : "WinRM runs over HTTPS and the server's certificate is checked before the login is sent. Add the CA that issued it when it is an internal CA."}
              >
                <Textarea
                  id="servers-ca"
                  data-testid="servers-ca"
                  value={form.caPem}
                  rows={3}
                  spellCheck={false}
                  placeholder="-----BEGIN CERTIFICATE-----"
                  className="font-mono text-xs min-h-[72px] max-h-60 overflow-y-auto resize-y"
                  onChange={(e) => set({ caPem: e.target.value })}
                />
                <input
                  ref={caRef}
                  type="file"
                  accept=".pem,.crt,.cer"
                  className="hidden"
                  data-testid="servers-ca-file"
                  onChange={async (e) => {
                    const input = e.currentTarget;
                    await readFileInto(input.files?.[0], (text) => set({ caPem: text }), "caFile");
                    input.value = "";
                  }}
                />
                <div className="flex gap-2">
                  <Button type="button" variant="outline" size="sm" className="cursor-pointer" onClick={() => caRef.current?.click()}>
                    <Upload className="h-4 w-4 mr-1.5" />
                    Upload PEM file
                  </Button>
                  {form.caPem && (
                    <Button type="button" variant="ghost" size="sm" className="cursor-pointer" onClick={() => set({ caPem: "" })}>
                      Remove
                    </Button>
                  )}
                </div>
              </Field>
            )}
          </FormSection>

          <FormSection title="Credential">
            <div data-testid="servers-credential">
              <ChoiceCards<CredType>
                name="servers-credential"
                label="Credential"
                value={form.credentialType}
                onChange={(v) =>
                  // a password goes only to pinned host keys, so choosing one pins them
                  set({ credentialType: v, ...(isLinux && v === "password" ? { hostKeyPolicy: "pinned" as HostKeyPolicy } : {}) })
                }
                options={info.creds
                  .filter((c) => c !== "ssh_ca" || sshCaOn || form.credentialType === "ssh_ca")
                  .map((c) => ({ value: c, ...CRED_TEXT[c], disabled: (c === "vault" || c === "ssh_ca") && !isAdmin }))}
              />
            </div>
            {!isAdmin && info.creds.includes("vault") && (
              <p className="text-xs text-zinc-600 dark:text-zinc-400">Only a team admin can add or change a vault reference.</p>
            )}
            {errors.credentialType && <p className="text-xs text-red-600 dark:text-red-400">{errors.credentialType}</p>}
            {source && !sameCredential && (
              <p className="text-xs text-amber-600 dark:text-amber-400">Changing the credential type replaces the stored credential when you save.</p>
            )}

            {form.credentialType === "node_key" && (
              <div className="space-y-2" data-testid="servers-node-key-panel">
                {!selectedNode ? (
                  <p className="text-sm text-zinc-600 dark:text-zinc-400">Choose a scan node above to see the public key to install.</p>
                ) : !selectedNode.ssh_public_key ? (
                  <p className="text-sm text-zinc-600 dark:text-zinc-400" data-testid="servers-node-key-missing">
                    {selectedNode.enrolled_at
                      ? `${selectedNode.name} registered without reporting an SSH key, so this option cannot be used with it yet. Choose another credential.`
                      : `Appears after the node registers. ${selectedNode.name} is ${nodeStatusLabel(selectedNode.status).toLowerCase()}.`}
                  </p>
                ) : (
                  <>
                    <p className="text-sm font-medium">
                      Install this public key for user <code className="font-mono">{login}</code> on each server
                    </p>
                    <code
                      className="block break-all rounded-md border bg-zinc-50 dark:bg-zinc-950 p-2 font-mono text-xs text-zinc-800 dark:text-zinc-200"
                      data-testid="servers-node-key"
                    >
                      {selectedNode.ssh_public_key}
                    </code>
                    <div className="flex flex-wrap gap-2">
                      <CopyButton text={selectedNode.ssh_public_key} label="Copy key" />
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="cursor-pointer"
                        aria-expanded={showAnsible}
                        onClick={() => setShowAnsible((v) => !v)}
                        data-testid="servers-ansible"
                      >
                        {showAnsible ? <ChevronUp className="h-4 w-4 mr-1.5" /> : <ChevronDown className="h-4 w-4 mr-1.5" />}
                        Ansible snippet
                      </Button>
                    </div>
                    {showAnsible && <CodeSnippet code={ansibleSnippet(selectedNode.ssh_public_key, login)} language="yaml" />}
                  </>
                )}
                <p className="text-xs text-zinc-500">Nothing is stored for this option: the node signs in with its own key.</p>
              </div>
            )}

            {form.credentialType === "ssh_cert" && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4" data-testid="servers-ssh-cert-panel">
                <SecretField
                  id="servers-ssh-certificate"
                  label="SSH certificate"
                  multiline
                  required
                  value={form.sshCertificate}
                  onChange={(v) => set({ sshCertificate: v })}
                  isSet={stored("ssh_certificate")}
                  error={errors.sshCertificate}
                  placeholder="ssh-ed25519-cert-v01@openssh.com AAAA..."
                  hint={secretHint("ssh_certificate")}
                />
                <SecretField
                  id="servers-private-key"
                  label="Private key"
                  multiline
                  required
                  value={form.privateKey}
                  onChange={(v) => set({ privateKey: v })}
                  isSet={stored("private_key")}
                  error={errors.privateKey}
                  placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                  hint={secretHint("private_key")}
                />
              </div>
            )}

            {form.credentialType === "ssh_ca" && (
              <div className="space-y-4" data-testid="servers-ssh-ca-panel">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <Field label="SSH CA" htmlFor="servers-ssh-ca" required error={errors.sshCaId}
                    hint={sshCaOn && signingCas.length === 0 ? "Create an SSH CA first (Fleet > SSH CA)" : "Its active key signs; rotation needs no change here"}>
                    <Select value={form.sshCaId ? String(form.sshCaId) : ""} onValueChange={(v) => set({ sshCaId: Number(v) })}>
                      <SelectTrigger id="servers-ssh-ca" className="w-full cursor-pointer" data-testid="servers-ssh-ca">
                        <SelectValue placeholder="Choose a CA" />
                      </SelectTrigger>
                      <SelectContent>
                        {signingCas.map((c) => (
                          <SelectItem key={c.id} value={String(c.lineage_id)} className="cursor-pointer">{c.name} ({c.fingerprint.slice(0, 19)}…)</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </Field>
                  <Field label="Principals" htmlFor="servers-ssh-principals" required error={errors.sshPrincipals}
                    hint={`One per line, e.g. zs-${teamId}-prod; the servers list them in /etc/ssh/zs-cbom/principals/${login}`}>
                    <Textarea id="servers-ssh-principals" rows={2} className="font-mono text-xs" value={form.sshPrincipals}
                      placeholder={`zs-${teamId}-prod`} onChange={(e) => set({ sshPrincipals: e.target.value })} />
                  </Field>
                  <Field label="Addresses the servers see the node as" htmlFor="servers-ssh-source-addresses" error={errors.sshSourceAddresses}
                    hint={`Each certificate only works from these (source-address): addresses or networks of /16 or narrower (IPv6 /48). Blank: the node's own addresses${selectedNode?.source_ips?.length ? ` (${selectedNode.source_ips.join(", ")})` : ""}; a node in Docker without host networking needs the Docker host's address here.`}>
                    <Textarea id="servers-ssh-source-addresses" rows={2} className="font-mono text-xs" value={form.sshSourceAddresses}
                      placeholder="10.20.1.15 or 10.20.1.0/28" onChange={(e) => set({ sshSourceAddresses: e.target.value })} />
                  </Field>
                </div>
                <p className="text-xs text-zinc-500">
                  Nothing is stored: for every job ZeroShield signs the scan node&apos;s own key for a few minutes (no terminal, forwarding or
                  agent), and lists each certificate under Fleet &gt; SSH CA. Install the CA&apos;s sshd snippet and its fetch script on the servers.
                  Only a team admin can save a source that uses the SSH CA (it decides which servers and groups the team&apos;s CA signs for).
                </p>
              </div>
            )}

            {form.credentialType === "vault" && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4" data-testid="servers-vault-panel">
                <Field label="Vault" htmlFor="servers-vault-provider">
                  <Select value={form.vaultProvider} onValueChange={(v) => set({ vaultProvider: v })}>
                    <SelectTrigger id="servers-vault-provider" className="w-full cursor-pointer" data-testid="servers-vault-provider">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {VAULT_PROVIDERS.map((p) => (
                        <SelectItem key={p.value} value={p.value} className="cursor-pointer">
                          {p.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>
                <Field
                  label="Secret path"
                  htmlFor="servers-vault-path"
                  required
                  error={errors.vaultPath}
                  className="md:col-span-2"
                  hint="The scan node reads the secret from your vault when the job runs; ZeroShield stores only this reference."
                >
                  <Input
                    id="servers-vault-path"
                    data-testid="servers-vault-path"
                    value={form.vaultPath}
                    maxLength={512}
                    placeholder="secret/zs-cbom/linux"
                    className="font-mono text-xs"
                    onChange={(e) => set({ vaultPath: e.target.value })}
                  />
                </Field>
              </div>
            )}

            {form.credentialType === "password" && (
              <div className="max-w-md" data-testid="servers-password-panel">
                <SecretField
                  id="servers-password"
                  label={`Password for ${login}`}
                  required
                  value={form.password}
                  onChange={(v) => set({ password: v })}
                  isSet={stored("password")}
                  error={errors.password}
                  hint={secretHint("password")}
                />
              </div>
            )}
          </FormSection>

          {isLinux && (
            <FormSection title="Privilege">
              <div data-testid="servers-tier">
                <ChoiceCards<1 | 2>
                  name="servers-tier"
                  label="Privilege tier"
                  value={form.tier}
                  onChange={(v) => set({ tier: v })}
                  options={[
                    { value: 1, title: "Tier 1 · no sudo", description: "Packages, configs, readable keys and certificates, keystores" },
                    {
                      value: 2,
                      title: "Tier 2 · sudo allowlist",
                      description: "Adds which process loads which crypto library, socket owners, effective SSH config, disk encryption",
                    },
                  ]}
                />
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {form.tier === 2 && (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="cursor-pointer"
                    disabled={sudoers.isPending}
                    onClick={() => sudoers.mutate()}
                    data-testid="servers-download-sudoers"
                  >
                    {sudoers.isPending ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <Download className="h-4 w-4 mr-1.5" />}
                    Download sudoers file
                  </Button>
                )}
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="cursor-pointer text-blue-600 dark:text-blue-400"
                  aria-expanded={showCommands}
                  aria-controls="servers-commands"
                  onClick={() => setShowCommands((v) => !v)}
                  data-testid="servers-view-commands"
                >
                  {showCommands ? <ChevronUp className="h-4 w-4 mr-1.5" /> : <ChevronDown className="h-4 w-4 mr-1.5" />}
                  View the exact commands
                </Button>
              </div>
              {form.tier === 2 && (
                <div className="space-y-1 text-xs text-zinc-500">
                  <p>
                    The sudoers file lists exact command lines only. A wildcard in a sudoers argument can be abused to read any file, so it never
                    uses one. Install it as <code className="font-mono">/etc/sudoers.d/zs-cbom</code> and check it with{" "}
                    <code className="font-mono">visudo -cf</code>.
                  </p>
                  {login !== "zs-cbom" && (
                    <p className="text-amber-600 dark:text-amber-400">
                      The file is written for the user zs-cbom. Replace zs-cbom with {login} in it before installing.
                    </p>
                  )}
                </div>
              )}
              {showCommands && (
                <div id="servers-commands" className="grid grid-cols-1 md:grid-cols-2 gap-3" data-testid="servers-commands">
                  <CommandList title={`Tier 1, as ${login}`} commands={TIER1_COMMANDS} />
                  <CommandList title="Tier 2 adds, through sudo" commands={TIER2_COMMANDS} />
                </div>
              )}
            </FormSection>
          )}

          {form.kind === "windows_servers" && (
            <FormSection title="Privilege">
              <div className="space-y-2 text-sm text-zinc-700 dark:text-zinc-300" data-testid="servers-windows-privilege">
                <p>
                  {login} does not need to be an administrator. It needs to be in Remote Management Users, and that group needs Read and
                  Execute on the WinRM service: Windows only gives a WinRM shell to administrators unless this is granted.
                </p>
                <p className="text-xs text-zinc-500">
                  Run the setup script once on each server in an elevated PowerShell. It adds the account to Remote Management Users, grants the
                  group Read and Execute on WinRM, and checks for an HTTPS listener. It changes nothing else and is safe to run again.
                </p>
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="cursor-pointer"
                disabled={windowsSetup.isPending}
                onClick={() => windowsSetup.mutate()}
                data-testid="servers-download-windows-setup"
              >
                {windowsSetup.isPending ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <Download className="h-4 w-4 mr-1.5" />}
                Download Windows setup script
              </Button>
            </FormSection>
          )}

          <FormSection title="Ownership and data">
            <MetadataFields value={meta} onChange={setMeta} idPrefix="servers" />
          </FormSection>

          <FormSection title="Limits" last>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Field label="Servers in parallel" htmlFor="servers-parallel" required error={errors.parallel} hint="1 to 64">
                <Input
                  id="servers-parallel"
                  data-testid="servers-parallel"
                  type="number"
                  min={1}
                  max={64}
                  inputMode="numeric"
                  value={form.parallel}
                  onChange={(e) => set({ parallel: e.target.value })}
                />
              </Field>
              <Field
                label="Timeout per server (seconds)"
                htmlFor="servers-timeout"
                required
                error={errors.timeoutS}
                hint={`10 to 3,600 s${intIn(form.timeoutS, 10, 3600) != null ? ` · ${minutes(Number(form.timeoutS))}` : ""}`}
              >
                <Input
                  id="servers-timeout"
                  data-testid="servers-timeout"
                  type="number"
                  min={10}
                  max={3600}
                  inputMode="numeric"
                  value={form.timeoutS}
                  onChange={(e) => set({ timeoutS: e.target.value })}
                />
              </Field>
              <Field
                label="Scan window"
                htmlFor="servers-window"
                error={errors.window}
                hint={
                  form.window === "network"
                    ? settings?.next_window_start
                      ? `Team window (${settings.window_timezone}); next starts ${formatDateTime(settings.next_window_start)}`
                      : "The team scan window set on the Network tab"
                    : form.window === "any"
                      ? "Collection may run at any hour. Connection tests always run straight away."
                      : undefined
                }
              >
                <Select
                  value={form.window}
                  onValueChange={(v) => {
                    const mode = v as WindowMode;
                    set(mode === "custom" && !form.customWindow ? { window: mode, customWindow: copyNetworkWindow() } : { window: mode });
                  }}
                >
                  <SelectTrigger id="servers-window" className="w-full cursor-pointer" data-testid="servers-window">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="network" className="cursor-pointer">
                      Network window (team)
                    </SelectItem>
                    <SelectItem value="any" className="cursor-pointer">
                      Any time
                    </SelectItem>
                    <SelectItem value="custom" className="cursor-pointer">
                      Custom
                    </SelectItem>
                  </SelectContent>
                </Select>
              </Field>
            </div>
            {form.window === "custom" && (
              <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3 text-sm space-y-2" data-testid="servers-custom-window">
                <p className="text-zinc-700 dark:text-zinc-300">
                  This source keeps its own copy of the weekly hours: {pluralize(hours, "hour")} a week. It starts as a copy of the team scan
                  window, and the hour grid is edited on the Network tab. To pick up changes made there, copy the window again and save.
                </p>
                <div className="flex flex-wrap gap-2">
                  <Button type="button" variant="outline" size="sm" className="cursor-pointer" onClick={() => set({ customWindow: copyNetworkWindow() })}>
                    Copy the current network window
                  </Button>
                  <Button type="button" variant="ghost" size="sm" className="cursor-pointer text-blue-600 dark:text-blue-400" onClick={() => onNavigate("network")}>
                    Open the Network tab
                  </Button>
                </div>
              </div>
            )}
          </FormSection>

          <div className="flex flex-wrap justify-end gap-2 pt-2">
            {source && (
              <Button variant="outline" className="cursor-pointer" onClick={onCancelEdit} disabled={save.isPending} data-testid="servers-cancel-edit">
                Cancel
              </Button>
            )}
            <Button variant="outline" className="cursor-pointer" disabled={save.isPending} onClick={() => submit(false)} data-testid="servers-save">
              {pendingSave ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Save className="h-4 w-4 mr-2" />}
              Save
            </Button>
            <Button
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
              disabled={save.isPending}
              onClick={() => submit(true)}
              data-testid="servers-save-test"
            >
              {pendingTest ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <FlaskConical className="h-4 w-4 mr-2" />}
              Save and test
            </Button>
          </div>
          <p className="text-xs text-zinc-500 text-right">The connection test is run by the scan node on up to 5 sample servers.</p>
        </div>
      </SectionCard>

      <SectionCard
        title="Exactly what runs on each server"
        description={isLinux ? "Nothing is installed. Output is parsed on the node." : "Nothing is installed. Results are parsed on the node."}
      >
        <WhatRuns kind={form.kind} login={login} tier={form.tier} />
      </SectionCard>
    </div>
  );
}

function FormSection({ title, last, children }: { title: string; last?: boolean; children: ReactNode }) {
  return (
    <section className={cn("space-y-4", !last && "pb-6 border-b border-zinc-200 dark:border-zinc-800")}>
      <h3 className="text-sm font-semibold text-zinc-900 dark:text-white">{title}</h3>
      {children}
    </section>
  );
}

function CommandList({ title, commands }: { title: string; commands: string[] }) {
  return (
    <div className="min-w-0">
      <p className="text-xs font-medium text-zinc-500 mb-1">{title}</p>
      <pre className="rounded-md border bg-zinc-50 dark:bg-zinc-950 p-3 font-mono text-xs leading-relaxed text-zinc-800 dark:text-zinc-200 whitespace-pre-wrap break-all">
        {commands.join("\n")}
      </pre>
    </div>
  );
}

function WhatRuns({ kind, login, tier }: { kind: ServerKind; login: string; tier: 1 | 2 }) {
  const bullets =
    kind === "linux_servers"
      ? [
          `Tier 1 runs ${TIER1_COMMANDS.length} read-only commands as ${login}, with no sudo.`,
          `Tier 2 adds ${TIER2_COMMANDS.length} commands through sudo, each allowed by an exact command line in the sudoers file.${tier === 2 ? "" : " Not used by this source."}`,
          "For private keys, only the public half is read off the server.",
          "Only the targets in this source are touched, and the never-scan lists always win.",
          "Credentials are encrypted at rest by ZeroShield and sent only to the scan node that runs the job.",
        ]
      : kind === "windows_servers"
        ? [
            `Read over WinRM on HTTPS with the account ${login}.`,
            "No agent or script is left on the server.",
            "For private keys, only the public half is read.",
            "Only the targets in this source are touched, and the never-scan lists always win.",
            "Credentials are encrypted at rest by ZeroShield and sent only to the scan node that runs the job.",
          ]
        : [
            `Read over LDAPS with the read-only directory account ${login}.`,
            "Nothing is changed in the directory.",
            "Only the domain controllers in this source are contacted, and the never-scan lists always win.",
            "Credentials are encrypted at rest by ZeroShield and sent only to the scan node that runs the job.",
          ];
  return (
    <div className="space-y-4">
      <ul className="list-disc pl-5 space-y-1.5 text-sm text-zinc-700 dark:text-zinc-300">
        {bullets.map((b) => (
          <li key={b}>{b}</li>
        ))}
      </ul>
      {kind === "linux_servers" && (
        <p className="text-xs text-zinc-500">Use “View the exact commands” in the Privilege section for the full list.</p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------- test results
function TestResultsCard({
  source,
  job,
  jobLoading,
  serverNow,
  retesting,
  onRetest,
  onClose,
}: {
  source: CbomSource;
  job: CbomJob | undefined;
  jobLoading: boolean;
  serverNow?: string;
  retesting: boolean;
  onRetest: () => void;
  onClose: () => void;
}) {
  // A polled job is the freshest view while it runs; once the source has a newer test, the source wins.
  const jobIsCurrent = !!job && (source.last_test_job_id == null || source.last_test_job_id === job.id);
  const open = jobIsCurrent && !!job && !TERMINAL_JOB.has(job.status);
  const jobSamples = jobIsCurrent && job && Array.isArray(job.result?.samples) ? (job.result.samples as CbomTestSample[]) : null;
  const sourceSamples = source.last_test_result?.samples ?? [];
  // Just after the job ends the list may still hold the "pending" placeholders for a few seconds.
  const placeholdersOnly = jobIsCurrent && !open && source.last_test_status === "pending";
  const rows: CbomTestSample[] = open
    ? sourceSamples.length
      ? sourceSamples
      : (job?.samples ?? []).map((target) => ({ target, status: "pending" }))
    : jobSamples && jobSamples.length
      ? jobSamples
      : placeholdersOnly
        ? []
        : sourceSamples;
  const isLinux = source.kind === "linux_servers";
  const tier1 = isLinux && source.config?.tier !== 2;

  return (
    <SectionCard
      id="servers-test"
      className="scroll-mt-4"
      title={`Connection test · ${source.name}`}
      description={`Run by ${source.node_name ?? "the scan node"} on up to 5 sample servers.`}
      actions={
        <>
          <Button variant="outline" className="cursor-pointer" disabled={retesting || open} onClick={onRetest} data-testid="servers-retest">
            {retesting ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <RotateCw className="h-4 w-4 mr-2" />}
            Run test again
          </Button>
          <Button variant="ghost" size="icon" className="cursor-pointer" onClick={onClose} aria-label="Close the test results">
            <X className="h-4 w-4" />
          </Button>
        </>
      }
    >
      <div className="space-y-4" data-testid="servers-test-results">
        <div className="flex flex-wrap items-center gap-2 text-sm" aria-live="polite">
          {jobIsCurrent && job ? (
            <>
              <JobStatusBadge status={job.status} />
              {open && job.waiting_reason && <span className="text-zinc-600 dark:text-zinc-400">{job.waiting_reason}</span>}
              {!open && (job.error || source.last_test_summary) && (
                <span className="text-zinc-600 dark:text-zinc-400">{job.error || source.last_test_summary}</span>
              )}
              {!open && job.finished_at && <span className="text-xs text-zinc-500">{ago(job.finished_at, job.server_time)}</span>}
            </>
          ) : jobLoading ? (
            <span className="inline-flex items-center gap-2 text-zinc-600 dark:text-zinc-400">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading the test
            </span>
          ) : (
            <>
              <TestStatusBadge status={source.last_test_status} />
              {source.last_test_summary && <span className="text-zinc-600 dark:text-zinc-400">{source.last_test_summary}</span>}
              {source.last_test_at && <span className="text-xs text-zinc-500">{ago(source.last_test_at, serverNow)}</span>}
            </>
          )}
        </div>

        {rows.length === 0 ? (
          <p className="text-sm text-zinc-600 dark:text-zinc-400">
            {open ? "The scan node has not picked up the test yet." : "No per-server results were reported for this test."}
          </p>
        ) : (
          <ScrollArea className="w-full border rounded-lg">
            <div className="min-w-max">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Server</TableHead>
                    <TableHead>Reachable</TableHead>
                    <TableHead>Login</TableHead>
                    <TableHead>{isLinux ? "Sudo allowlist" : "Privilege"}</TableHead>
                    <TableHead>Result</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((sample, index) => {
                    const pending = WAITING.has(sample.status);
                    return (
                      <TableRow key={`${sample.target}-${index}`} className="hover:bg-zinc-50 dark:hover:bg-zinc-800">
                        <TableCell className="font-mono text-xs text-zinc-900 dark:text-white max-w-[260px]">
                          <Truncate text={sample.target} />
                        </TableCell>
                        <TableCell className="text-zinc-600 dark:text-zinc-400">{yesNo(sample.reachable, pending)}</TableCell>
                        <TableCell className="text-zinc-600 dark:text-zinc-400">{yesNo(sample.login, pending)}</TableCell>
                        <TableCell className="text-zinc-600 dark:text-zinc-400">{yesNo(sample.privilege, pending, tier1)}</TableCell>
                        <TableCell className="max-w-[360px]">
                          <StatusBadge tone={sampleTone(sample.status)}>
                            {pending && <Loader2 className="animate-spin" />}
                            {sampleLabel(sample.status)}
                          </StatusBadge>
                          {sample.note && <p className="text-xs text-zinc-500 mt-1 whitespace-normal break-words">{sample.note}</p>}
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
      </div>
    </SectionCard>
  );
}
