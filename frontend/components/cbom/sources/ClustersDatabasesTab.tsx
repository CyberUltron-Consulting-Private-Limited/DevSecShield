"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Database, Download, FlaskConical, Loader2, MoreVertical, Pencil, Plus, Save, Server, Trash2, Upload, X } from "lucide-react";
import { useMemo, useRef, useState, type ReactNode } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import {
  createCbomSource,
  deleteCbomSource,
  getCbomSourcesOverview,
  getCbomTemplate,
  listCbomScanNodes,
  listCbomSources,
  testCbomSource,
  updateCbomSource,
  type CbomJob,
  type CbomScanNode,
  type CbomSource,
  type CbomSourceSaveResponse,
  type CbomSourceWrite,
} from "@/utils/backend_api";

import ContainerImagesSection from "./ContainerImagesSection";
import { cbomSourcesKeys, TERMINAL_JOB } from "./keys";
import { MetadataFields, metadataConfig, metadataFrom, type SourceMetadata } from "./SourceMetadata";
import { ago, pluralize, readTextFile } from "./logic";
import {
  Checkbox2,
  ChoiceCards,
  CodeSnippet,
  ConfirmDialog,
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
  useMenuReveal,
  usePolledJob,
} from "./shared";

// ---------------------------------------------------------------------------- constants (mirror backend kinds.py / templates.py)
type Engine = "postgres" | "mysql" | "mssql" | "oracle" | "mongodb" | "redis";
type ClusterCred = "kubeconfig" | "vault";
type DbCred = "password" | "vault";

const ENGINES: { value: Engine; label: string; short: string }[] = [
  { value: "postgres", label: "PostgreSQL", short: "PostgreSQL" },
  { value: "mysql", label: "MySQL / MariaDB", short: "MySQL" },
  { value: "mssql", label: "SQL Server", short: "SQL Server" },
  { value: "oracle", label: "Oracle", short: "Oracle" },
  { value: "mongodb", label: "MongoDB", short: "MongoDB" },
  { value: "redis", label: "Redis", short: "Redis" },
];
const ENGINE_SHORT = Object.fromEntries(ENGINES.map((e) => [e.value, e.short])) as Record<Engine, string>;

// kinds.py DB_DEFAULT_PORTS
const DB_DEFAULT_PORTS: Record<Engine, number> = { postgres: 5432, mysql: 3306, mssql: 1433, oracle: 1521, mongodb: 27017, redis: 6379 };
// The login names the grant templates create.
const DB_DEFAULT_LOGIN: Record<Engine, string> = { postgres: "zs_cbom", mysql: "zs_cbom", mssql: "svc_zscbom", oracle: "zs_cbom", mongodb: "zs_cbom", redis: "zs_cbom" };
const LOGIN_OPTIONAL: ReadonlySet<Engine> = new Set(["mongodb", "redis"]);
// kinds.credential_target_problem: logins a fake server could read need TLS with the server's CA
const CA_REQUIRED_ENGINES: ReadonlySet<Engine> = new Set(["mysql", "redis", "mssql"]);
const GRANT_LANGUAGE: Record<Engine, string> = { postgres: "sql", mysql: "sql", mssql: "sql", oracle: "sql", mongodb: "javascript", redis: "bash" };

// templates.py DB_READS (kept equal by test_command_lists_shown_to_customers_match_the_server_and_sudoers)
const DB_READS: Record<Engine, string[]> = {
  postgres: [
    "TLS on or off, minimum TLS version and ciphers",
    "Password hashing setting and the method of each HBA rule",
    "Password hash type of each login role (md5 or SCRAM; never the hash itself)",
    "TLS used by live client connections",
    "pgcrypto use",
  ],
  mysql: [
    "require_secure_transport and TLS versions",
    "Authentication plugin per user",
    "TLS used by live client connections",
    "Table encryption (InnoDB) and keyring",
  ],
  mssql: [
    "Force encryption, TLS versions and the server certificate (read before logging in)",
    "Transparent Data Encryption per database (algorithm, key length, state)",
    "Symmetric and asymmetric keys, certificates and Always Encrypted keys per database (metadata only)",
    "Encryption of live connections",
    "Password policy and hash version of each SQL login (never the hash)",
  ],
  oracle: [
    "TLS on the listener and native network encryption in use",
    "TDE keystore state, encrypted tablespaces and columns (algorithms)",
    "Password verifier versions per user (10G, 11G, 12C; never the verifier)",
  ],
  mongodb: [
    "TLS mode and allowed protocols",
    "OpenSSL version and whether authorization is on",
    "Encryption at rest setting",
  ],
  redis: [
    "TLS port, protocols and ciphers (named tls-* settings only; never passwords)",
    "Whether AUTH is required",
    "Note: Redis ACLs cannot limit CONFIG GET to tls-* names, so this login could read any setting, including requirepass; the scan node never asks for those",
  ],
};

const VAULT_PROVIDERS = [
  { value: "hashicorp", label: "HashiCorp Vault" },
  { value: "cyberark", label: "CyberArk" },
  { value: "aws_secrets_manager", label: "AWS Secrets Manager" },
  { value: "azure_key_vault", label: "Azure Key Vault" },
];

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;
const NAME_ERROR = "Use 1-64 letters, digits, spaces, dots, dashes or underscores, starting with a letter or digit.";
const LOGIN_RE = /^[A-Za-z0-9._@$\\-]{1,64}$/;
const HOST_RE = /^[A-Za-z0-9._:-]{1,253}$/;
const MAX_PEM = 64 * 1024;
const CLOUD_KINDS = new Set(["aws_account", "azure_subscription", "gcp_project"]);

// ---------------------------------------------------------------------------- helpers
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

function byteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

function checkHttpsUrl(value: string): string | null {
  const text = value.trim();
  if (!text) return "Enter the API server URL";
  if (/[\s'"`<>\\]/.test(text)) return "The URL contains characters that are not allowed";
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return "Enter a URL like https://10.30.0.10:6443";
  }
  if (url.protocol !== "https:" || !url.hostname) return "The URL must start with https://";
  if (url.username || url.password) return "The URL must not contain a user name or password";
  return null;
}

function checkPem(value: string): string | null {
  const text = value.trim();
  if (!text) return null;
  if (byteLength(text) > MAX_PEM) return "The certificate is larger than 64 KB";
  if (text.includes("PRIVATE KEY")) return "Paste the CA certificate, not a private key";
  if (!text.includes("-----BEGIN CERTIFICATE-----")) return "Not a PEM certificate (expected -----BEGIN CERTIFICATE-----)";
  return null;
}

/** The same rules the server applies (kinds.check_kubeconfig), checked early so the user sees them inline. */
function kubeconfigProblem(text: string): string | null {
  const key = (name: string) => new RegExp(`(^|[\\s{,])["']?${name}["']?\\s*:`, "m");
  if (!key("clusters").test(text) || !key("users").test(text)) return "This does not look like a kubeconfig: it needs clusters, users and contexts";
  if (key("exec").test(text) || key("auth-provider").test(text)) {
    return "This kubeconfig uses an exec or auth-provider plugin; use a static token or client certificate";
  }
  for (const name of ["client-certificate", "client-key", "tokenFile"]) {
    if (key(name).test(text)) return `This kubeconfig points at a file (${name}); embed the data instead`;
  }
  if (key("certificate-authority").test(text)) return "This kubeconfig points at a CA file; embed certificate-authority-data instead";
  return null;
}

function endpointOf(source: CbomSource): string {
  const cfg = source.config ?? {};
  if (source.kind === "key_manager") {
    return cfg.provider === "kmip" ? `${cfg.host ?? "—"}:${cfg.port ?? 5696}` : `module ${cfg.module ?? "—"}${cfg.token_label ? ` / ${cfg.token_label}` : ""}`;
  }
  if (source.kind === "kubernetes") {
    try {
      return new URL(String(cfg.api_url ?? "")).host || String(cfg.api_url ?? "—");
    } catch {
      return String(cfg.api_url ?? "—");
    }
  }
  const engine = cfg.engine as Engine;
  return `${cfg.host ?? "—"}:${cfg.port ?? DB_DEFAULT_PORTS[engine] ?? ""}`;
}

function typeOf(source: CbomSource): string {
  if (source.kind === "kubernetes") return "Kubernetes";
  if (source.kind === "key_manager") return source.config?.provider === "kmip" ? "KMIP server" : "HSM (PKCS#11)";
  return ENGINE_SHORT[source.config?.engine as Engine] ?? source.kind_label;
}

function accessOf(source: CbomSource): string {
  if (source.kind === "kubernetes") return `Tier ${source.config?.tier === 2 ? 2 : 1}${source.config?.managed ? " · managed" : ""}`;
  if (source.kind === "key_manager") {
    if (source.config?.provider === "kmip") return "client certificate";
    return source.config?.credential_type === "vault" ? "PIN from vault" : source.secrets_set.includes("pin") ? "PIN" : "public objects only";
  }
  return source.config?.login || "—";
}

// ---------------------------------------------------------------------------- tab
export default function ClustersDatabasesTab({ teamId, onNavigate }: { teamId: number; onNavigate: (tab: string) => void }) {
  const queryClient = useQueryClient();
  const [editingCluster, setEditingCluster] = useState<CbomSource | null>(null);
  const [editingDb, setEditingDb] = useState<CbomSource | null>(null);
  const [editingKm, setEditingKm] = useState<CbomSource | null>(null);
  const [clusterNonce, setClusterNonce] = useState(0);
  const [dbNonce, setDbNonce] = useState(0);
  const [kmNonce, setKmNonce] = useState(0);
  const [activeTest, setActiveTest] = useState<{ sourceId: number; jobId: number } | null>(null);
  const [deleting, setDeleting] = useState<CbomSource | null>(null);
  const rowMenu = useMenuReveal();

  const pendingInterval = (data: { sources: CbomSource[] } | undefined) => (data?.sources.some((s) => s.last_test_status === "pending") ? 6000 : 30000);
  const nodesQuery = useQuery({
    queryKey: cbomSourcesKeys.nodes(teamId),
    queryFn: () => listCbomScanNodes(teamId),
    enabled: Number.isFinite(teamId),
    retry: 1,
    refetchInterval: 30000,
  });
  const clustersQuery = useQuery({
    queryKey: cbomSourcesKeys.sources(teamId, "kubernetes"),
    queryFn: () => listCbomSources(teamId, "kubernetes"),
    enabled: Number.isFinite(teamId),
    retry: 1,
    refetchInterval: (query) => pendingInterval(query.state.data),
  });
  const databasesQuery = useQuery({
    queryKey: cbomSourcesKeys.sources(teamId, "databases"),
    queryFn: () => listCbomSources(teamId, "databases"),
    enabled: Number.isFinite(teamId),
    retry: 1,
    refetchInterval: (query) => pendingInterval(query.state.data),
  });
  const cloudQuery = useQuery({
    queryKey: cbomSourcesKeys.sources(teamId, "cloud"),
    queryFn: () => listCbomSources(teamId, "cloud"),
    enabled: Number.isFinite(teamId),
    retry: 1,
  });

  const nodes = useMemo(() => nodesQuery.data?.nodes ?? [], [nodesQuery.data]);
  // the kubernetes group also holds registry image sources (kind container_images, own section below)
  const clusters = useMemo(() => (clustersQuery.data?.sources ?? []).filter((s) => s.kind === "kubernetes"), [clustersQuery.data]);
  const isAdminForImages = useIsTeamAdmin(teamId);
  // the databases group also holds HSMs and KMIP servers (kind key_manager)
  const databases = useMemo(() => databasesQuery.data?.sources ?? [], [databasesQuery.data]);
  const keyManagerCount = databases.filter((s) => s.kind === "key_manager").length;
  const cloudSources = useMemo(() => (cloudQuery.data?.sources ?? []).filter((s) => CLOUD_KINDS.has(s.kind)), [cloudQuery.data]);
  const rows = useMemo(() => [...clusters, ...databases], [clusters, databases]);
  const serverNow = clustersQuery.data?.server_time ?? databasesQuery.data?.server_time;
  const jobQuery = usePolledJob(teamId, activeTest?.jobId ?? null);
  const activeJob = activeTest && jobQuery.data && jobQuery.data.id === activeTest.jobId ? jobQuery.data : undefined;
  const jobFor = (sourceId: number | undefined) => (activeTest && activeTest.sourceId === sourceId ? activeJob : undefined);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });

  const testMutation = useMutation({
    mutationFn: (source: CbomSource) => testCbomSource(teamId, source.id),
    onSuccess: (data, source) => {
      if (data.job) setActiveTest({ sourceId: source.id, jobId: data.job.id });
    },
    onSettled: invalidate,
  });
  const deleteMutation = useMutation({
    mutationFn: (source: CbomSource) => deleteCbomSource(teamId, source.id),
    onSuccess: (_data, source) => {
      setDeleting(null);
      setEditingCluster((cur) => (cur && cur.id === source.id ? null : cur));
      setEditingDb((cur) => (cur && cur.id === source.id ? null : cur));
      setEditingKm((cur) => (cur && cur.id === source.id ? null : cur));
      setActiveTest((cur) => (cur && cur.sourceId === source.id ? null : cur));
    },
    onSettled: invalidate,
  });

  const newCluster = () => {
    setEditingCluster(null);
    setClusterNonce((n) => n + 1);
  };
  const newDb = () => {
    setEditingDb(null);
    setDbNonce((n) => n + 1);
  };
  const newKm = () => {
    setEditingKm(null);
    setKmNonce((n) => n + 1);
  };
  // From the row menu: the form is revealed when the menu has closed (reveal.ts), not here.
  const startEdit = (source: CbomSource) => {
    if (source.kind === "kubernetes") {
      setEditingCluster(source);
      rowMenu.request("k8s-form");
    } else if (source.kind === "key_manager") {
      setEditingKm(source);
      rowMenu.request("km-form");
    } else {
      setEditingDb(source);
      rowMenu.request("db-form");
    }
  };
  // "Test" keeps the form on the saved source (so it can be fixed and tested again); "Save" returns to a blank form.
  const savedCluster = (source: CbomSource, jobId: number | null, tested: boolean) => {
    setEditingCluster(tested ? source : null);
    setClusterNonce((n) => n + 1);
    if (tested && jobId) setActiveTest({ sourceId: source.id, jobId });
  };
  const savedDb = (source: CbomSource, jobId: number | null, tested: boolean) => {
    setEditingDb(tested ? source : null);
    setDbNonce((n) => n + 1);
    if (tested && jobId) setActiveTest({ sourceId: source.id, jobId });
  };
  const savedKm = (source: CbomSource, jobId: number | null, tested: boolean) => {
    setEditingKm(tested ? source : null);
    setKmNonce((n) => n + 1);
    if (tested && jobId) setActiveTest({ sourceId: source.id, jobId });
  };

  const loading = nodesQuery.isLoading || clustersQuery.isLoading || databasesQuery.isLoading;
  const failed =
    (nodesQuery.isError && !nodesQuery.data) || (clustersQuery.isError && !clustersQuery.data) || (databasesQuery.isError && !databasesQuery.data);
  if (loading) return <LoadingBlock />;
  if (failed) {
    return (
      <ErrorBlock
        error={nodesQuery.error ?? clustersQuery.error ?? databasesQuery.error}
        onRetry={() => {
          nodesQuery.refetch();
          clustersQuery.refetch();
          databasesQuery.refetch();
        }}
      />
    );
  }

  const liveCluster = editingCluster ? clusters.find((s) => s.id === editingCluster.id) ?? null : null;
  const liveDb = editingDb ? databases.find((s) => s.id === editingDb.id) ?? null : null;
  const liveKm = editingKm ? databases.find((s) => s.id === editingKm.id) ?? null : null;

  return (
    <div className="space-y-6">
      {nodes.length === 0 ? (
        <SectionCard title="Add Kubernetes clusters and databases" description="Both are read through a scan node inside your network.">
          <EmptyState
            title="Add a scan node first"
            body="Clusters and databases are reached through a scan node that runs inside your network, with accounts that can only read. Add a node on the Scan nodes tab, then come back here."
            action={
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => onNavigate("scan-nodes")} data-testid="k8sdb-go-scan-nodes">
                <Server className="h-4 w-4 mr-2" />
                Go to Scan nodes
              </Button>
            }
          />
        </SectionCard>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
          <ClusterForm
            // sibling keys must differ from the database form's, or React keeps a ghost form after a remount
            key={editingCluster ? `cluster-edit-${editingCluster.id}-${editingCluster.row_version}-${clusterNonce}` : `cluster-new-${clusterNonce}`}
            teamId={teamId}
            source={editingCluster}
            nodes={nodes}
            cloudSources={cloudSources}
            testStatus={liveCluster ? <TestLine source={liveCluster} job={jobFor(liveCluster.id)} serverNow={serverNow} /> : null}
            onSaved={savedCluster}
            onCancelEdit={newCluster}
            onStale={newCluster}
            onNavigate={onNavigate}
          />
          <DatabaseForm
            key={editingDb ? `db-edit-${editingDb.id}-${editingDb.row_version}-${dbNonce}` : `db-new-${dbNonce}`}
            teamId={teamId}
            source={editingDb}
            nodes={nodes}
            testStatus={liveDb ? <TestLine source={liveDb} job={jobFor(liveDb.id)} serverNow={serverNow} /> : null}
            onSaved={savedDb}
            onCancelEdit={newDb}
            onStale={newDb}
          />
          <KeyManagerForm
            key={editingKm ? `km-edit-${editingKm.id}-${editingKm.row_version}-${kmNonce}` : `km-new-${kmNonce}`}
            teamId={teamId}
            source={editingKm}
            nodes={nodes}
            testStatus={liveKm ? <TestLine source={liveKm} job={jobFor(liveKm.id)} serverNow={serverNow} /> : null}
            onSaved={savedKm}
            onCancelEdit={newKm}
            onStale={newKm}
          />
        </div>
      )}

      <ContainerImagesSection teamId={teamId} nodes={nodes} isAdmin={isAdminForImages} />

      <SectionCard
        title="Configured clusters and databases"
        description={
          rows.length
            ? `${pluralize(clusters.length, "cluster")} and ${pluralize(databases.length - keyManagerCount, "database")}` +
              (keyManagerCount ? `, ${pluralize(keyManagerCount, "HSM or key manager", "HSMs or key managers")}` : "")
            : "Clusters and databases you add appear here."
        }
      >
        {rows.length === 0 ? (
          <EmptyState
            title="No clusters or databases yet"
            body="Add a Kubernetes cluster or a database with the forms above. Each one is read through the scan node you pick."
            action={
              nodes.length ? (
                <div className="flex flex-wrap justify-center gap-2">
                  <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => scrollToId("k8s-form")}>
                    <Plus className="h-4 w-4 mr-2" />
                    Add a cluster
                  </Button>
                  <Button variant="outline" className="cursor-pointer" onClick={() => scrollToId("db-form")}>
                    <Database className="h-4 w-4 mr-2" />
                    Add a database
                  </Button>
                </div>
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
              <Table data-testid="k8sdb-table">
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Endpoint</TableHead>
                    <TableHead>Access / login</TableHead>
                    <TableHead>Node</TableHead>
                    <TableHead>Last test</TableHead>
                    <TableHead className="w-12">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((source) => {
                    const job = jobFor(source.id);
                    const jobOpen = !!job && !TERMINAL_JOB.has(job.status) && (source.last_test_job_id == null || source.last_test_job_id === job.id);
                    return (
                      <TableRow key={source.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800" data-testid={`k8sdb-row-${source.id}`}>
                        <TableCell className="font-medium text-zinc-900 dark:text-white max-w-[220px]">
                          <div className="flex items-center gap-2 min-w-0">
                            <Truncate text={source.name} className="min-w-0" />
                            {!source.enabled && <StatusBadge tone="zinc">Disabled</StatusBadge>}
                          </div>
                        </TableCell>
                        <TableCell className="text-zinc-600 dark:text-zinc-400">{typeOf(source)}</TableCell>
                        <TableCell className="font-mono text-xs text-zinc-600 dark:text-zinc-400 max-w-[240px]">
                          <Truncate text={endpointOf(source)} />
                        </TableCell>
                        <TableCell className="text-zinc-600 dark:text-zinc-400 max-w-[160px]">
                          <Truncate text={accessOf(source)} />
                        </TableCell>
                        <TableCell className="text-zinc-600 dark:text-zinc-400 max-w-[200px]">
                          <div className="flex items-center gap-2 min-w-0">
                            <Truncate text={source.node_name ?? "—"} className="min-w-0" />
                            {source.node_status && source.node_status !== "online" && <NodeStatusBadge status={source.node_status} />}
                          </div>
                        </TableCell>
                        <TableCell className="max-w-[300px]">
                          {jobOpen && job ? (
                            <>
                              <JobStatusBadge status={job.status} />
                              {job.waiting_reason && <p className="text-xs text-zinc-500 mt-1 whitespace-normal">{job.waiting_reason}</p>}
                            </>
                          ) : (
                            <>
                              <TestStatusBadge status={source.last_test_status} title={source.last_test_summary} />
                              {(source.last_test_summary || source.last_test_at) && (
                                <p className="text-xs text-zinc-500 mt-1 whitespace-normal break-words">
                                  {source.last_test_summary ?? ""}
                                  {source.last_test_at ? `${source.last_test_summary ? " · " : ""}${ago(source.last_test_at, serverNow)}` : ""}
                                </p>
                              )}
                            </>
                          )}
                        </TableCell>
                        <TableCell>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon" className="cursor-pointer" aria-label={`Actions for ${source.name}`} data-testid={`k8sdb-actions-${source.id}`}>
                                <MoreVertical className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" onCloseAutoFocus={rowMenu.onCloseAutoFocus}>
                              <DropdownMenuItem className="cursor-pointer" onSelect={() => startEdit(source)} data-testid={`k8sdb-edit-${source.id}`}>
                                <Pencil className="h-4 w-4" />
                                Edit
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                className="cursor-pointer"
                                disabled={testMutation.isPending}
                                onSelect={() => testMutation.mutate(source)}
                                data-testid={`k8sdb-test-${source.id}`}
                              >
                                <FlaskConical className="h-4 w-4" />
                                Run connection test
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem
                                variant="destructive"
                                className="cursor-pointer"
                                onSelect={() => setDeleting(source)}
                                data-testid={`k8sdb-delete-${source.id}`}
                              >
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

      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(v) => !v && setDeleting(null)}
        title={deleting?.kind === "kubernetes" ? "Delete this cluster?" : deleting?.kind === "key_manager" ? "Delete this key manager?" : "Delete this database?"}
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

// ---------------------------------------------------------------------------- shared bits
function TestLine({ source, job, serverNow }: { source: CbomSource; job: CbomJob | undefined; serverNow?: string }) {
  const current = !!job && (source.last_test_job_id == null || source.last_test_job_id === job.id);
  const open = current && !!job && !TERMINAL_JOB.has(job.status);
  // Just after the job ends, the list can still say "pending" for a few seconds; show the job's outcome meanwhile.
  const justEnded = current && !!job && !open && source.last_test_status === "pending";
  return (
    <div className="flex flex-wrap items-center gap-2 text-sm" aria-live="polite" data-testid={`test-line-${source.id}`}>
      <span className="font-medium text-zinc-900 dark:text-white">Connection test</span>
      {(open || justEnded) && job ? (
        <>
          <JobStatusBadge status={job.status} />
          <span className="text-zinc-600 dark:text-zinc-400">
            {open ? job.waiting_reason ?? "" : job.error ?? (typeof job.result?.summary === "string" ? job.result.summary : "")}
          </span>
        </>
      ) : (
        <>
          <TestStatusBadge status={source.last_test_status} />
          {source.last_test_summary && <span className="text-zinc-600 dark:text-zinc-400">{source.last_test_summary}</span>}
          {source.last_test_at && <span className="text-xs text-zinc-500">{ago(source.last_test_at, serverNow)}</span>}
        </>
      )}
    </div>
  );
}

function VaultFields({
  idPrefix,
  provider,
  path,
  error,
  onProvider,
  onPath,
  placeholder,
}: {
  idPrefix: string;
  provider: string;
  path: string;
  error?: string | null;
  onProvider: (v: string) => void;
  onPath: (v: string) => void;
  placeholder: string;
}) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
      <Field label="Vault" htmlFor={`${idPrefix}-vault-provider`}>
        <Select value={provider} onValueChange={onProvider}>
          <SelectTrigger id={`${idPrefix}-vault-provider`} className="w-full cursor-pointer" data-testid={`${idPrefix}-vault-provider`}>
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
        htmlFor={`${idPrefix}-vault-path`}
        required
        error={error}
        className="sm:col-span-2"
        hint="The scan node reads the secret from your vault when the job runs; ZeroShield stores only this reference."
      >
        <Input
          id={`${idPrefix}-vault-path`}
          data-testid={`${idPrefix}-vault-path`}
          value={path}
          maxLength={512}
          placeholder={placeholder}
          className="font-mono text-xs"
          onChange={(e) => onPath(e.target.value)}
        />
      </Field>
    </div>
  );
}

function FormButtons({
  prefix,
  editing,
  pending,
  testing,
  saveLabel,
  onCancel,
  onTest,
  onSave,
}: {
  prefix: string;
  editing: boolean;
  pending: boolean;
  testing: boolean;
  saveLabel: string;
  onCancel: () => void;
  onTest: () => void;
  onSave: () => void;
}) {
  return (
    <div className="flex flex-wrap justify-end gap-2 pt-2">
      {editing && (
        <Button variant="ghost" className="cursor-pointer" disabled={pending} onClick={onCancel} data-testid={`${prefix}-cancel-edit`}>
          <X className="h-4 w-4 mr-2" />
          Cancel
        </Button>
      )}
      <Button variant="outline" className="cursor-pointer" disabled={pending} onClick={onTest} data-testid={`${prefix}-test`} title="Save, then ask the scan node to test the connection">
        {pending && testing ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <FlaskConical className="h-4 w-4 mr-2" />}
        Test
      </Button>
      <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={pending} onClick={onSave} data-testid={`${prefix}-save`}>
        {pending && !testing ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Save className="h-4 w-4 mr-2" />}
        {saveLabel}
      </Button>
    </div>
  );
}

function SubLabel({ children }: { children: ReactNode }) {
  return <p className="text-sm font-medium">{children}</p>;
}

// ---------------------------------------------------------------------------- Kubernetes
interface ClusterState {
  name: string;
  apiUrl: string;
  caPem: string;
  credentialType: ClusterCred;
  kubeconfig: string;
  kubeconfigName: string;
  context: string;
  vaultProvider: string;
  vaultPath: string;
  tier: 1 | 2;
  managed: boolean;
  cloudSourceId: number | null;
  nodeId: number | null;
}
type ClusterErrors = Partial<Record<keyof ClusterState | "caFile", string>>;

function initialCluster(source: CbomSource | null, nodes: CbomScanNode[]): ClusterState {
  const cfg = source?.config ?? {};
  return {
    name: source?.name ?? "",
    apiUrl: String(cfg.api_url ?? ""),
    caPem: typeof cfg.ca_pem === "string" ? cfg.ca_pem : "",
    credentialType: cfg.credential_type === "vault" ? "vault" : "kubeconfig",
    kubeconfig: "",
    kubeconfigName: "",
    context: typeof cfg.context === "string" ? cfg.context : "",
    vaultProvider: cfg.vault?.provider ?? "hashicorp",
    vaultPath: cfg.vault?.path ?? "",
    tier: cfg.tier === 2 ? 2 : 1,
    managed: !!cfg.managed,
    cloudSourceId: typeof cfg.cloud_source_id === "number" ? cfg.cloud_source_id : null,
    nodeId: source ? source.node_id : nodes.length === 1 ? nodes[0].id : null,
  };
}

/** Vault references fetch a secret on the scan node, so only team admins may add or change them (the API enforces it). */
function useIsTeamAdmin(teamId: number): boolean {
  const q = useQuery({
    queryKey: cbomSourcesKeys.overview(teamId),
    queryFn: () => getCbomSourcesOverview(teamId),
    enabled: Number.isFinite(teamId),
    retry: 1,
    staleTime: 60_000,
  });
  return !!q.data?.viewer?.is_admin;
}

function ClusterForm({
  teamId,
  source,
  nodes,
  cloudSources,
  testStatus,
  onSaved,
  onCancelEdit,
  onStale,
  onNavigate,
}: {
  teamId: number;
  source: CbomSource | null;
  nodes: CbomScanNode[];
  cloudSources: CbomSource[];
  testStatus: ReactNode;
  onSaved: (source: CbomSource, jobId: number | null, tested: boolean) => void;
  onCancelEdit: () => void;
  onStale: () => void;
  onNavigate: (tab: string) => void;
}) {
  const queryClient = useQueryClient();
  const isAdmin = useIsTeamAdmin(teamId);
  // Mounted with a key per source and save, so it starts from the record without a sync effect.
  const [form, setForm] = useState<ClusterState>(() => initialCluster(source, nodes));
  const [meta, setMeta] = useState<SourceMetadata>(() => metadataFrom(source?.config));
  const [errors, setErrors] = useState<ClusterErrors>({});
  const caRef = useRef<HTMLInputElement>(null);
  const kubeRef = useRef<HTMLInputElement>(null);

  const cfg = source?.config ?? {};
  const sameCredential = !!source && cfg.credential_type === form.credentialType;
  const kubeconfigStored = sameCredential && !!source?.secrets_set.includes("kubeconfig");
  const whereChanged =
    !!source &&
    (form.apiUrl.trim() !== String(cfg.api_url ?? "") ||
      (form.context.trim() || null) !== (cfg.context ?? null) ||
      form.nodeId !== source.node_id ||
      (form.caPem.trim() || null) !== ((typeof cfg.ca_pem === "string" && cfg.ca_pem.trim()) || null) ||
      (form.credentialType === "vault" ? `${form.vaultProvider}|${form.vaultPath.trim()}` : null) !==
        (cfg.vault ? `${cfg.vault.provider}|${cfg.vault.path}` : null));
  const templateName = form.tier === 2 ? "k8s-tier2" : "k8s-tier1";
  const roleQuery = useQuery({
    queryKey: cbomSourcesKeys.template(teamId, templateName),
    queryFn: () => getCbomTemplate(teamId, templateName),
    enabled: Number.isFinite(teamId),
    retry: 1,
    staleTime: Infinity,
  });

  const set = (patch: Partial<ClusterState>) => {
    setForm((f) => ({ ...f, ...patch }));
    setErrors((e) => {
      const next = { ...e };
      for (const key of Object.keys(patch)) delete next[key as keyof ClusterErrors];
      return next;
    });
  };

  const save = useMutation({
    mutationFn: ({ body, test }: { body: CbomSourceWrite; test: boolean }) =>
      source ? updateCbomSource(teamId, source.id, { ...body, test_after_save: test }) : createCbomSource(teamId, { ...body, test_after_save: test }),
    onSuccess: (data, vars) => onSaved(data.source, testJobId(data.test), vars.test),
    onError: (err) => {
      const status = httpStatus(err);
      if (source && (status === 409 || status === 404)) onStale();
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) }),
  });

  const validate = (): ClusterErrors => {
    const e: ClusterErrors = {};
    if (!NAME_RE.test(form.name.trim())) e.name = NAME_ERROR;
    const urlError = checkHttpsUrl(form.apiUrl);
    if (urlError) e.apiUrl = urlError;
    const pemError = checkPem(form.caPem);
    if (pemError) e.caPem = pemError;
    if (form.credentialType === "kubeconfig") {
      if (!form.kubeconfig && !kubeconfigStored) e.kubeconfig = "Upload a kubeconfig file";
      else if (form.kubeconfig) {
        const problem = kubeconfigProblem(form.kubeconfig);
        if (problem) e.kubeconfig = problem;
      }
    }
    if (form.context.trim().length > 128) e.context = "128 characters at most";
    if (form.credentialType === "vault" && !form.vaultPath.trim()) e.vaultPath = "Enter the secret path in your vault";
    if (form.credentialType === "vault" && !isAdmin) e.vaultPath = "Only a team admin can add or change a vault reference";
    if (!form.nodeId) e.nodeId = "Choose the scan node that reaches this cluster";
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
    const body: CbomSourceWrite = {
      name: form.name.trim(),
      node_id: form.nodeId,
      config: {
        api_url: form.apiUrl.trim(),
        ca_pem: form.caPem.trim() ? form.caPem : null,
        credential_type: form.credentialType,
        vault: form.credentialType === "vault" ? { provider: form.vaultProvider, path: form.vaultPath.trim() } : null,
        context: form.credentialType === "kubeconfig" && form.context.trim() ? form.context.trim() : null,
        tier: form.tier,
        managed: form.managed,
        cloud_source_id: form.managed ? form.cloudSourceId : null,
        ...metaConfig,
      },
      secrets: form.credentialType === "kubeconfig" && form.kubeconfig ? { kubeconfig: form.kubeconfig } : {},
      ...(source ? { expected_version: source.row_version } : { kind: "kubernetes" }),
    };
    save.mutate({ body, test });
  };

  const downloadRole = async () => {
    try {
      const text = await queryClient.fetchQuery({
        queryKey: cbomSourcesKeys.template(teamId, templateName),
        queryFn: () => getCbomTemplate(teamId, templateName),
        staleTime: Infinity,
      });
      downloadText(text, `zs-cbom-tier${form.tier}.yaml`, "application/yaml");
    } catch {
      toast.error("Could not download the ClusterRole. Please try again.");
    }
  };

  const kubeconfigHint = form.kubeconfig ? (
    <span>
      Loaded {form.kubeconfigName || "kubeconfig"} ({Math.max(1, Math.round(byteLength(form.kubeconfig) / 1024))} KB). It is sent once, encrypted at rest by
      ZeroShield and sent only to the scan node that runs the job. The server refuses exec and auth-provider plugins.
    </span>
  ) : source && kubeconfigStored && whereChanged ? (
    <span className="text-amber-600 dark:text-amber-400">
      The API server URL, context, CA certificate, vault path or scan node changed: upload the kubeconfig again, or the server refuses the save
      because stored credentials are cleared when the target or the way its identity is checked changes.
    </span>
  ) : kubeconfigStored ? (
    "Saved. Upload a new file to replace it. Changing the API server URL, context or scan node clears it unless you upload it again."
  ) : (
    "Static token or client certificate only; the server refuses exec and auth-provider plugins. Encrypted at rest by ZeroShield; sent only to the scan node that runs the job."
  );

  const linkedCloud = cloudSources.find((c) => c.id === form.cloudSourceId) ?? null;

  return (
    <SectionCard
      id="k8s-form"
      className="scroll-mt-4"
      title={source ? `Edit cluster ${source.name}` : "Add a Kubernetes cluster"}
      description="Read through the Kubernetes API with a read-only ClusterRole."
    >
      <div className="space-y-5">
        <div className="grid grid-cols-1 sm:grid-cols-5 gap-4">
          <Field label="Cluster name" htmlFor="k8s-name" required error={errors.name} className="sm:col-span-2">
            <Input id="k8s-name" data-testid="k8s-name" value={form.name} maxLength={64} placeholder="prod-payments" onChange={(e) => set({ name: e.target.value })} />
          </Field>
          <Field label="API server URL" htmlFor="k8s-api-url" required error={errors.apiUrl} className="sm:col-span-3">
            <Input
              id="k8s-api-url"
              data-testid="k8s-api-url"
              value={form.apiUrl}
              maxLength={512}
              placeholder="https://10.30.0.10:6443"
              className="font-mono text-xs"
              onChange={(e) => set({ apiUrl: e.target.value })}
            />
          </Field>
        </div>

        <Field
          label="Cluster CA certificate"
          htmlFor="k8s-ca"
          error={errors.caPem ?? errors.caFile}
          hint="PEM. Optional when the kubeconfig embeds certificate-authority-data."
        >
          <Textarea
            id="k8s-ca"
            data-testid="k8s-ca"
            value={form.caPem}
            rows={3}
            spellCheck={false}
            placeholder="-----BEGIN CERTIFICATE-----"
            className="font-mono text-xs min-h-[72px] max-h-48 overflow-y-auto resize-y"
            onChange={(e) => set({ caPem: e.target.value })}
          />
          <input
            ref={caRef}
            type="file"
            accept=".pem,.crt,.cer"
            className="hidden"
            data-testid="k8s-ca-file"
            onChange={async (e) => {
              const input = e.currentTarget;
              const file = input.files?.[0];
              input.value = "";
              if (!file) return;
              try {
                const text = await readTextFile(file, MAX_PEM);
                set({ caPem: text });
                setErrors((er) => ({ ...er, caFile: undefined }));
              } catch (err) {
                setErrors((er) => ({ ...er, caFile: (err as Error).message }));
              }
            }}
          />
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" size="sm" className="cursor-pointer" onClick={() => caRef.current?.click()}>
              <Upload className="h-4 w-4 mr-1.5" />
              Upload PEM file
            </Button>
            {form.caPem && (
              <Button type="button" variant="ghost" size="sm" className="cursor-pointer" onClick={() => set({ caPem: "" })}>
                Clear
              </Button>
            )}
          </div>
        </Field>

        <div className="space-y-3">
          <SubLabel>Credential</SubLabel>
          <div data-testid="k8s-credential">
            <ChoiceCards<ClusterCred>
              name="k8s-credential"
              label="Cluster credential"
              value={form.credentialType}
              onChange={(v) => set({ credentialType: v })}
              options={[
                { value: "kubeconfig", title: "Upload kubeconfig", description: "Encrypted at rest; sent only to the scan node" },
                { value: "vault", title: "Token from vault", description: "Fetched by the scan node when the job runs", disabled: !isAdmin },
              ]}
            />
          </div>
          {!isAdmin && <p className="text-xs text-zinc-600 dark:text-zinc-400">Only a team admin can add or change a vault reference.</p>}
          {source && !sameCredential && (
            <p className="text-xs text-amber-600 dark:text-amber-400">Changing the credential type replaces the stored credential when you save.</p>
          )}
          {form.credentialType === "kubeconfig" ? (
            <div className="grid grid-cols-1 sm:grid-cols-5 gap-4">
              <Field
                label="Kubeconfig file"
                htmlFor="k8s-kubeconfig"
                required={!kubeconfigStored}
                error={errors.kubeconfig}
                hint={kubeconfigHint}
                className="sm:col-span-3"
              >
                <input
                  ref={kubeRef}
                  id="k8s-kubeconfig"
                  type="file"
                  accept=".yaml,.yml,.conf,.config,.json,text/plain"
                  className="hidden"
                  data-testid="k8s-kubeconfig"
                  onChange={async (e) => {
                    const input = e.currentTarget;
                    const file = input.files?.[0];
                    input.value = "";
                    if (!file) return;
                    try {
                      const text = await readTextFile(file);
                      const problem = kubeconfigProblem(text);
                      if (problem) {
                        set({ kubeconfig: "", kubeconfigName: "" });
                        setErrors((er) => ({ ...er, kubeconfig: problem }));
                        return;
                      }
                      set({ kubeconfig: text, kubeconfigName: file.name });
                    } catch (err) {
                      setErrors((er) => ({ ...er, kubeconfig: (err as Error).message }));
                    }
                  }}
                />
                <div className="flex flex-wrap items-center gap-2">
                  <Button type="button" variant="outline" size="sm" className="cursor-pointer" onClick={() => kubeRef.current?.click()} data-testid="k8s-kubeconfig-button">
                    <Upload className="h-4 w-4 mr-1.5" />
                    {form.kubeconfig || kubeconfigStored ? "Replace kubeconfig" : "Choose kubeconfig"}
                  </Button>
                  {form.kubeconfig && (
                    <Button type="button" variant="ghost" size="sm" className="cursor-pointer" onClick={() => set({ kubeconfig: "", kubeconfigName: "" })}>
                      Remove
                    </Button>
                  )}
                </div>
              </Field>
              <Field label="Context" htmlFor="k8s-context" error={errors.context} hint="Optional. Blank uses current-context." className="sm:col-span-2">
                <Input id="k8s-context" data-testid="k8s-context" value={form.context} maxLength={128} onChange={(e) => set({ context: e.target.value })} />
              </Field>
            </div>
          ) : (
            <VaultFields
              idPrefix="k8s"
              provider={form.vaultProvider}
              path={form.vaultPath}
              error={errors.vaultPath}
              onProvider={(v) => set({ vaultProvider: v })}
              onPath={(v) => set({ vaultPath: v })}
              placeholder="secret/zs-cbom/k8s/prod-payments"
            />
          )}
        </div>

        <div className="space-y-3">
          <SubLabel>Access tier</SubLabel>
          <div data-testid="k8s-tier">
            <ChoiceCards<1 | 2>
              name="k8s-tier"
              label="Access tier"
              value={form.tier}
              onChange={(v) => set({ tier: v })}
              options={[
                { value: 1, title: "Tier 1 · no Secrets", description: "Certificates and issuers, ingress TLS, mesh mTLS mode, images in use" },
                { value: 2, title: "Tier 2 · reads Secrets", description: "Adds TLS secrets and private keys left in Secrets or ConfigMaps" },
              ]}
            />
          </div>
          {form.tier === 2 && (
            <div role="note" className="flex items-start gap-3 rounded-lg border border-amber-500/50 px-4 py-3" data-testid="k8s-tier2-warning">
              <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0 text-amber-600 dark:text-amber-400" />
              <div className="text-sm">
                <p className="font-medium text-amber-600 dark:text-amber-400">Tier 2 can read Secret values</p>
                <p className="text-zinc-700 dark:text-zinc-300">
                  Kubernetes cannot grant access to Secret names without their values, so this token can read them. Only metadata such as
                  fingerprints is sent to ZeroShield. Start with non-production clusters.
                </p>
              </div>
            </div>
          )}
          <div className="space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-xs font-medium text-zinc-500">
                Apply this ClusterRole and binding for the service account zs-cbom (Tier {form.tier})
              </p>
              <Button type="button" variant="outline" size="sm" className="cursor-pointer" onClick={downloadRole} data-testid="k8s-download-role">
                <Download className="h-4 w-4 mr-1.5" />
                ClusterRole · Tier {form.tier}
              </Button>
            </div>
            {roleQuery.isLoading ? (
              <div className="flex items-center gap-2 text-sm text-zinc-500">
                <Loader2 className="h-4 w-4 animate-spin" />
                Loading the ClusterRole
              </div>
            ) : roleQuery.isError || !roleQuery.data ? (
              <div className="flex flex-wrap items-center gap-2 text-sm text-zinc-600 dark:text-zinc-400">
                Could not load the ClusterRole.
                <Button type="button" variant="outline" size="sm" className="cursor-pointer" onClick={() => roleQuery.refetch()}>
                  Try again
                </Button>
              </div>
            ) : (
              <div className="max-h-72 overflow-y-auto rounded-md" data-testid="k8s-role-preview">
                <CodeSnippet code={roleQuery.data} language="yaml" />
              </div>
            )}
          </div>
        </div>

        <div className="space-y-2">
          <Checkbox2 id="k8s-managed" checked={form.managed} onChange={(v) => set({ managed: v })}>
            Managed cluster (EKS, AKS, GKE): link the cloud account that runs it
          </Checkbox2>
          {form.managed &&
            (cloudSources.length ? (
              <Field
                label="Cloud account"
                htmlFor="k8s-cloud"
                hint="Secret encryption at rest is read from this account once cloud collection is available; until then it is stored as a link."
              >
                <Select value={form.cloudSourceId ? String(form.cloudSourceId) : ""} onValueChange={(v) => set({ cloudSourceId: v ? Number(v) : null })}>
                  <SelectTrigger id="k8s-cloud" className="w-full cursor-pointer" data-testid="k8s-cloud">
                    <SelectValue placeholder="Choose the cloud account (optional)" />
                  </SelectTrigger>
                  <SelectContent>
                    {cloudSources.map((c) => (
                      <SelectItem key={c.id} value={String(c.id)} className="cursor-pointer">
                        {c.name} · {c.kind_label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {form.cloudSourceId && !linkedCloud && <p className="text-xs text-amber-600 dark:text-amber-400">The linked cloud account no longer exists; choose another.</p>}
              </Field>
            ) : (
              <div className="flex flex-wrap items-center gap-2 text-sm text-zinc-600 dark:text-zinc-400">
                No cloud accounts yet.
                <Button type="button" variant="outline" size="sm" className="cursor-pointer" onClick={() => onNavigate("cloud")}>
                  Add a cloud account
                </Button>
              </div>
            ))}
        </div>

        <Field label="Reached through scan node" htmlFor="k8s-node" required error={errors.nodeId} hint="The node must reach the API server URL above.">
          <div data-testid="k8s-node">
            <NodeSelect id="k8s-node" nodes={nodes} value={form.nodeId} onChange={(v) => set({ nodeId: v })} />
          </div>
        </Field>

        <details className="rounded-md border border-zinc-200 dark:border-zinc-800 p-3">
          <summary className="cursor-pointer text-sm font-medium text-zinc-900 dark:text-white">Ownership and data</summary>
          <div className="mt-3"><MetadataFields value={meta} onChange={setMeta} idPrefix="k8s" /></div>
        </details>

        <FormButtons
          prefix="k8s"
          editing={!!source}
          pending={save.isPending}
          testing={!!save.variables?.test}
          saveLabel="Save cluster"
          onCancel={onCancelEdit}
          onTest={() => submit(true)}
          onSave={() => submit(false)}
        />
        {testStatus}
      </div>
    </SectionCard>
  );
}

// ---------------------------------------------------------------------------- databases
interface DbState {
  name: string;
  engine: Engine;
  host: string;
  port: string;
  login: string;
  databaseName: string;
  credentialType: DbCred;
  password: string;
  vaultProvider: string;
  vaultPath: string;
  requireTls: boolean;
  caPem: string;
  caName: string;
  nodeId: number | null;
}
type DbErrors = Partial<Record<keyof DbState, string>>;

function initialDb(source: CbomSource | null, nodes: CbomScanNode[]): DbState {
  const cfg = source?.config ?? {};
  const engine = (ENGINES.some((e) => e.value === cfg.engine) ? cfg.engine : "postgres") as Engine;
  return {
    name: source?.name ?? "",
    engine,
    host: String(cfg.host ?? ""),
    port: String(cfg.port ?? DB_DEFAULT_PORTS[engine]),
    login: source ? String(cfg.login ?? "") : DB_DEFAULT_LOGIN[engine],
    databaseName: typeof cfg.database_name === "string" ? cfg.database_name : "",
    credentialType: cfg.credential_type === "vault" ? "vault" : "password",
    password: "",
    vaultProvider: cfg.vault?.provider ?? "hashicorp",
    vaultPath: cfg.vault?.path ?? "",
    requireTls: source ? cfg.require_tls !== false : true,
    caPem: typeof cfg.ca_pem === "string" ? cfg.ca_pem : "",
    caName: typeof cfg.ca_pem === "string" && cfg.ca_pem ? "Saved certificate" : "",
    nodeId: source ? source.node_id : nodes.length === 1 ? nodes[0].id : null,
  };
}

function DatabaseForm({
  teamId,
  source,
  nodes,
  testStatus,
  onSaved,
  onCancelEdit,
  onStale,
}: {
  teamId: number;
  source: CbomSource | null;
  nodes: CbomScanNode[];
  testStatus: ReactNode;
  onSaved: (source: CbomSource, jobId: number | null, tested: boolean) => void;
  onCancelEdit: () => void;
  onStale: () => void;
}) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState<DbState>(() => initialDb(source, nodes));
  const [meta, setMeta] = useState<SourceMetadata>(() => metadataFrom(source?.config));
  const [errors, setErrors] = useState<DbErrors>({});
  const caRef = useRef<HTMLInputElement>(null);

  const cfg = source?.config ?? {};
  const sameCredential = !!source && cfg.credential_type === form.credentialType;
  const passwordStored = sameCredential && !!source?.secrets_set.includes("password");
  const loginOptional = LOGIN_OPTIONAL.has(form.engine);
  const passwordRequired = form.credentialType === "password" && form.engine !== "redis" && !!form.login.trim();
  const isAdmin = useIsTeamAdmin(teamId);
  // MySQL, Redis and SQL Server logins can be read by whatever answers, so a password needs TLS with the server's CA
  const usesPassword = form.credentialType === "vault" || !!form.password || passwordStored;
  const caRequired = CA_REQUIRED_ENGINES.has(form.engine) && usesPassword;
  const whereChanged =
    !!source &&
    (form.engine !== cfg.engine ||
      form.host.trim() !== String(cfg.host ?? "") ||
      Number(form.port.trim() || DB_DEFAULT_PORTS[form.engine]) !== Number(cfg.port) ||
      (form.login.trim() || null) !== (cfg.login ?? null) ||
      form.nodeId !== source.node_id ||
      form.requireTls !== (cfg.require_tls !== false) ||
      (form.caPem.trim() || null) !== ((typeof cfg.ca_pem === "string" && cfg.ca_pem.trim()) || null) ||
      (form.credentialType === "vault" ? `${form.vaultProvider}|${form.vaultPath.trim()}` : null) !==
        (cfg.vault ? `${cfg.vault.provider}|${cfg.vault.path}` : null));
  const grantName = `grant-${form.engine}`;
  const grantQuery = useQuery({
    queryKey: cbomSourcesKeys.template(teamId, grantName),
    queryFn: () => getCbomTemplate(teamId, grantName),
    enabled: Number.isFinite(teamId),
    retry: 1,
    staleTime: Infinity,
  });

  const set = (patch: Partial<DbState>) => {
    setForm((f) => ({ ...f, ...patch }));
    setErrors((e) => {
      const next = { ...e };
      for (const key of Object.keys(patch)) delete next[key as keyof DbState];
      return next;
    });
  };

  const changeEngine = (engine: Engine) => {
    const prev = form.engine;
    set({
      engine,
      port: !form.port.trim() || form.port.trim() === String(DB_DEFAULT_PORTS[prev]) ? String(DB_DEFAULT_PORTS[engine]) : form.port,
      login: !form.login.trim() || form.login.trim() === DB_DEFAULT_LOGIN[prev] ? DB_DEFAULT_LOGIN[engine] : form.login,
    });
  };

  const save = useMutation({
    mutationFn: ({ body, test }: { body: CbomSourceWrite; test: boolean }) =>
      source ? updateCbomSource(teamId, source.id, { ...body, test_after_save: test }) : createCbomSource(teamId, { ...body, test_after_save: test }),
    onSuccess: (data, vars) => onSaved(data.source, testJobId(data.test), vars.test),
    onError: (err) => {
      const status = httpStatus(err);
      if (source && (status === 409 || status === 404)) onStale();
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) }),
  });

  const validate = (): DbErrors => {
    const e: DbErrors = {};
    if (!NAME_RE.test(form.name.trim())) e.name = NAME_ERROR;
    if (!HOST_RE.test(form.host.trim())) e.host = "Enter a host name or IP address";
    if (form.port.trim()) {
      const port = Number(form.port.trim());
      if (!/^\d{1,5}$/.test(form.port.trim()) || port < 1 || port > 65535) e.port = "1 to 65535";
    }
    if (!form.login.trim()) {
      if (!loginOptional) e.login = "Enter the read-only database login";
    } else if (!LOGIN_RE.test(form.login.trim())) {
      e.login = "Use up to 64 letters, digits and . _ @ $ \\ -";
    }
    if (form.databaseName.trim().length > 128) e.databaseName = "128 characters at most";
    else if (form.engine === "oracle" && !form.databaseName.trim()) e.databaseName = "Enter the Oracle service name (for example ORCLPDB1)";
    if (passwordRequired && !form.password && !passwordStored) e.password = "Enter the password for this login";
    if (form.credentialType === "vault" && !form.vaultPath.trim()) e.vaultPath = "Enter the secret path in your vault";
    if (form.credentialType === "vault" && !isAdmin) e.vaultPath = "Only a team admin can add or change a vault reference";
    const pemError = checkPem(form.caPem);
    if (pemError) e.caPem = pemError;
    else if (caRequired && !(form.requireTls && form.caPem.trim()))
      e.caPem = `${ENGINE_SHORT[form.engine]} logins need TLS and the CA that signed the server's certificate, so the password only goes to the real server`;
    if (!form.nodeId) e.nodeId = "Choose the scan node that reaches this database";
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
    const body: CbomSourceWrite = {
      name: form.name.trim(),
      node_id: form.nodeId,
      config: {
        engine: form.engine,
        host: form.host.trim(),
        port: form.port.trim() ? Number(form.port.trim()) : null,
        login: form.login.trim() || null,
        credential_type: form.credentialType,
        vault: form.credentialType === "vault" ? { provider: form.vaultProvider, path: form.vaultPath.trim() } : null,
        require_tls: form.requireTls,
        ca_pem: form.caPem.trim() ? form.caPem : null,
        database_name: form.databaseName.trim() || null,
        ...metaConfig,
      },
      secrets: form.credentialType === "password" && form.password ? { password: form.password } : {},
      ...(source ? { expected_version: source.row_version } : { kind: "database" }),
    };
    save.mutate({ body, test });
  };

  const passwordHint =
    source && passwordStored && whereChanged ? (
      <span className="text-amber-600 dark:text-amber-400">
        The engine, host, port, login, TLS requirement, CA certificate, vault path or scan node changed: enter the password again, or the
        server refuses the save because stored credentials are cleared when the target or the way its identity is checked changes.
      </span>
    ) : source ? (
      "Encrypted at rest by ZeroShield; sent only to the scan node that runs the job. Changing the engine, host, port, login or scan node clears it unless you enter it again."
    ) : form.engine === "redis" ? (
      "Optional for Redis without AUTH. Encrypted at rest by ZeroShield; sent only to the scan node that runs the job."
    ) : undefined;

  return (
    <SectionCard
      id="db-form"
      className="scroll-mt-4"
      title={source ? `Edit database ${source.name}` : "Add a database"}
      description="Read-only: the login needs only the grants shown below."
    >
      <div className="space-y-5">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <Field label="Name" htmlFor="db-name" required error={errors.name}>
            <Input id="db-name" data-testid="db-name" value={form.name} maxLength={64} placeholder="pg-core-01" onChange={(e) => set({ name: e.target.value })} />
          </Field>
          <Field label="Engine" htmlFor="db-engine">
            <Select value={form.engine} onValueChange={(v) => changeEngine(v as Engine)}>
              <SelectTrigger id="db-engine" className="w-full cursor-pointer" data-testid="db-engine">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ENGINES.map((e) => (
                  <SelectItem key={e.value} value={e.value} className="cursor-pointer">
                    {e.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          <Field label="Host" htmlFor="db-host" required error={errors.host} className="sm:col-span-3">
            <Input id="db-host" data-testid="db-host" value={form.host} maxLength={253} placeholder="pg-core-01.bank.local" onChange={(e) => set({ host: e.target.value })} />
          </Field>
          <Field label="Port" htmlFor="db-port" error={errors.port} hint={`Default ${DB_DEFAULT_PORTS[form.engine]}`}>
            <Input
              id="db-port"
              data-testid="db-port"
              inputMode="numeric"
              value={form.port}
              maxLength={5}
              onChange={(e) => set({ port: e.target.value.replace(/[^\d]/g, "") })}
            />
          </Field>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <Field
            label={loginOptional ? "Login (optional)" : "Login"}
            htmlFor="db-login"
            required={!loginOptional}
            error={errors.login}
            hint={loginOptional ? "Leave blank if the server runs without authentication" : undefined}
          >
            <Input id="db-login" data-testid="db-login" value={form.login} maxLength={64} autoComplete="off" onChange={(e) => set({ login: e.target.value })} />
          </Field>
          <Field
            label={form.engine === "oracle" ? "Service name" : "Database (optional)"}
            htmlFor="db-database"
            required={form.engine === "oracle"}
            error={errors.databaseName}
            hint={form.engine === "oracle" ? "The service (PDB) the login and grants belong to" : "Where to connect first; server-wide settings are read from there"}
          >
            <Input id="db-database" data-testid="db-database" value={form.databaseName} maxLength={128} onChange={(e) => set({ databaseName: e.target.value })} />
          </Field>
        </div>

        <div className="space-y-3">
          <SubLabel>Credential</SubLabel>
          <div data-testid="db-credential">
            <ChoiceCards<DbCred>
              name="db-credential"
              label="Database credential"
              value={form.credentialType}
              onChange={(v) => set({ credentialType: v })}
              options={[
                { value: "password", title: "Password", description: "Encrypted at rest; sent only to the scan node" },
                { value: "vault", title: "Password from vault", description: "Fetched by the scan node when the job runs", disabled: !isAdmin },
              ]}
            />
          </div>
          {!isAdmin && <p className="text-xs text-zinc-600 dark:text-zinc-400">Only a team admin can add or change a vault reference.</p>}
          {source && !sameCredential && (
            <p className="text-xs text-amber-600 dark:text-amber-400">Changing the credential type replaces the stored credential when you save.</p>
          )}
          {form.credentialType === "password" ? (
            <SecretField
              id="db-password"
              label={form.login.trim() ? `Password for ${form.login.trim()}` : "Password"}
              required={passwordRequired}
              value={form.password}
              onChange={(v) => set({ password: v })}
              isSet={passwordStored}
              error={errors.password}
              hint={passwordHint}
            />
          ) : (
            <VaultFields
              idPrefix="db"
              provider={form.vaultProvider}
              path={form.vaultPath}
              error={errors.vaultPath}
              onProvider={(v) => set({ vaultProvider: v })}
              onPath={(v) => set({ vaultPath: v })}
              placeholder="secret/zs-cbom/db/pg-core-01"
            />
          )}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 items-start">
          <div className="sm:pt-7">
            <Checkbox2 id="db-require-tls" checked={form.requireTls} onChange={(v) => set({ requireTls: v })}>
              Require TLS to the database
            </Checkbox2>
          </div>
          <Field
            label="Database CA certificate"
            htmlFor="db-ca"
            error={errors.caPem}
            required={caRequired}
            hint={
              form.caName
                ? form.caName
                : caRequired
                  ? "Required with a password: the node checks the server against this CA before sending it"
                  : form.engine === "postgres"
                    ? "Optional. Without it, the node allows only SCRAM logins, which never reveal the password"
                    : form.engine === "mssql"
                      ? "Needed to log in: SQL Server only obfuscates the password, so it goes only to a server proven by this CA (or its own certificate). Without it the node reads the TLS setup only"
                      : form.engine === "oracle"
                        ? "Optional (TCPS). The Oracle login never sends the password itself"
                        : "Optional PEM file, for a private CA"
            }
          >
            <input
              ref={caRef}
              id="db-ca"
              type="file"
              accept=".pem,.crt,.cer"
              className="hidden"
              data-testid="db-ca"
              onChange={async (e) => {
                const input = e.currentTarget;
                const file = input.files?.[0];
                input.value = "";
                if (!file) return;
                try {
                  const text = await readTextFile(file, MAX_PEM);
                  const problem = checkPem(text);
                  if (problem) {
                    setErrors((er) => ({ ...er, caPem: problem }));
                    return;
                  }
                  set({ caPem: text, caName: file.name });
                } catch (err) {
                  setErrors((er) => ({ ...er, caPem: (err as Error).message }));
                }
              }}
            />
            <div className="flex flex-wrap gap-2">
              <Button type="button" variant="outline" size="sm" className="cursor-pointer" onClick={() => caRef.current?.click()} data-testid="db-ca-button">
                <Upload className="h-4 w-4 mr-1.5" />
                {form.caPem ? "Replace PEM file" : "Upload PEM file"}
              </Button>
              {form.caPem && (
                <Button type="button" variant="ghost" size="sm" className="cursor-pointer" onClick={() => set({ caPem: "", caName: "" })}>
                  Remove
                </Button>
              )}
            </div>
          </Field>
        </div>

        <div className="space-y-2">
          <SubLabel>Run this once as an admin</SubLabel>
          {grantQuery.isLoading ? (
            <div className="flex items-center gap-2 text-sm text-zinc-500">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading the grant
            </div>
          ) : grantQuery.isError || !grantQuery.data ? (
            <div className="flex flex-wrap items-center gap-2 text-sm text-zinc-600 dark:text-zinc-400">
              Could not load the grant.
              <Button type="button" variant="outline" size="sm" className="cursor-pointer" onClick={() => grantQuery.refetch()}>
                Try again
              </Button>
            </div>
          ) : (
            <div data-testid="db-grant">
              <CodeSnippet code={grantQuery.data} language={GRANT_LANGUAGE[form.engine]} />
            </div>
          )}
          {form.login.trim() && form.login.trim() !== DB_DEFAULT_LOGIN[form.engine] && (
            <p className="text-xs text-amber-600 dark:text-amber-400">
              The grant creates the login {DB_DEFAULT_LOGIN[form.engine]}; change it to {form.login.trim()} before running it.
            </p>
          )}
        </div>

        <div className="space-y-2">
          <SubLabel>What we read</SubLabel>
          <ul className="list-disc pl-5 space-y-1 text-sm text-zinc-700 dark:text-zinc-300" data-testid="db-reads">
            {DB_READS[form.engine].map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
          <p className="text-xs text-zinc-500">Turn on statement logging during the first scan to see for yourself that nothing else is sent.</p>
        </div>

        <Field label="Reached through scan node" htmlFor="db-node" required error={errors.nodeId} hint="The node must reach the host and port above.">
          <div data-testid="db-node">
            <NodeSelect id="db-node" nodes={nodes} value={form.nodeId} onChange={(v) => set({ nodeId: v })} />
          </div>
        </Field>

        <details className="rounded-md border border-zinc-200 dark:border-zinc-800 p-3">
          <summary className="cursor-pointer text-sm font-medium text-zinc-900 dark:text-white">Ownership and data</summary>
          <div className="mt-3"><MetadataFields value={meta} onChange={setMeta} idPrefix="db" /></div>
        </details>

        <FormButtons
          prefix="db"
          editing={!!source}
          pending={save.isPending}
          testing={!!save.variables?.test}
          saveLabel="Save database"
          onCancel={onCancelEdit}
          onTest={() => submit(true)}
          onSave={() => submit(false)}
        />
        {testStatus}
      </div>
    </SectionCard>
  );
}

// ---------------------------------------------------------------------------- HSMs and key managers (key_manager)
type KmProvider = "pkcs11" | "kmip";
type KmCred = "password" | "vault";
const MODULE_RE = /^[A-Za-z0-9_.-]{1,64}$/;
// kinds.KeyManagerConfig: what the scan node reads (attributes only, never key values)
const KM_READS: Record<KmProvider, string[]> = {
  pkcs11: [
    "Token label, manufacturer, model, serial and firmware",
    "Per key: class, type, size or curve, label, id, extractable / sensitive / local flags, usage flags and dates",
    "Certificates stored on the token (public)",
    "Never key values: the session is read-only and no value attribute of a key is requested",
  ],
  kmip: [
    "Protocol versions, vendor and server information (Discover Versions, Query)",
    "Per object: type, algorithm, length, state, usage mask and dates (Locate, Get Attributes)",
    "Never key material: Get and Export are not sent",
  ],
};

interface KmState {
  name: string;
  provider: KmProvider;
  module: string;
  tokenLabel: string;
  credentialType: KmCred;
  pin: string;
  vaultProvider: string;
  vaultPath: string;
  host: string;
  port: string;
  caPem: string;
  clientCert: string;
  clientKey: string;
  nodeId: number | null;
}
type KmErrors = Partial<Record<keyof KmState, string>>;

function initialKm(source: CbomSource | null, nodes: CbomScanNode[]): KmState {
  const cfg = source?.config ?? {};
  return {
    name: source?.name ?? "",
    provider: cfg.provider === "kmip" ? "kmip" : "pkcs11",
    module: typeof cfg.module === "string" ? cfg.module : "",
    tokenLabel: typeof cfg.token_label === "string" ? cfg.token_label : "",
    credentialType: cfg.credential_type === "vault" ? "vault" : "password",
    pin: "",
    vaultProvider: cfg.vault?.provider ?? "hashicorp",
    vaultPath: cfg.vault?.path ?? "",
    host: typeof cfg.host === "string" ? cfg.host : "",
    port: String(cfg.port ?? 5696),
    caPem: typeof cfg.ca_pem === "string" ? cfg.ca_pem : "",
    clientCert: "",
    clientKey: "",
    nodeId: source ? source.node_id : nodes.length === 1 ? nodes[0].id : null,
  };
}

function KeyManagerForm({
  teamId,
  source,
  nodes,
  testStatus,
  onSaved,
  onCancelEdit,
  onStale,
}: {
  teamId: number;
  source: CbomSource | null;
  nodes: CbomScanNode[];
  testStatus: ReactNode;
  onSaved: (source: CbomSource, jobId: number | null, tested: boolean) => void;
  onCancelEdit: () => void;
  onStale: () => void;
}) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState<KmState>(() => initialKm(source, nodes));
  const [errors, setErrors] = useState<KmErrors>({});
  const isAdmin = useIsTeamAdmin(teamId);
  const cfg = source?.config ?? {};
  const pinStored = !!source?.secrets_set.includes("pin") && cfg.credential_type !== "vault";
  const certStored = !!source?.secrets_set.includes("client_cert") && !!source?.secrets_set.includes("client_key");
  const kmipWhereChanged =
    !!source &&
    (cfg.provider !== "kmip" ||
      form.host.trim() !== String(cfg.host ?? "") ||
      Number(form.port.trim() || 5696) !== Number(cfg.port ?? 5696) ||
      (form.caPem.trim() || null) !== ((typeof cfg.ca_pem === "string" && cfg.ca_pem.trim()) || null) ||
      form.nodeId !== source.node_id);

  const set = (patch: Partial<KmState>) => {
    setForm((f) => ({ ...f, ...patch }));
    setErrors((e) => {
      const next = { ...e };
      for (const key of Object.keys(patch)) delete next[key as keyof KmState];
      return next;
    });
  };

  const save = useMutation({
    mutationFn: ({ body, test }: { body: CbomSourceWrite; test: boolean }) =>
      source ? updateCbomSource(teamId, source.id, { ...body, test_after_save: test }) : createCbomSource(teamId, { ...body, test_after_save: test }),
    onSuccess: (data, vars) => onSaved(data.source, testJobId(data.test), vars.test),
    onError: (err) => {
      const status = httpStatus(err);
      if (source && (status === 409 || status === 404)) onStale();
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) }),
  });

  const validate = (): KmErrors => {
    const e: KmErrors = {};
    if (!NAME_RE.test(form.name.trim())) e.name = NAME_ERROR;
    if (form.provider === "pkcs11") {
      if (!MODULE_RE.test(form.module.trim())) e.module = "Enter the module name listed in the node's ZS_PKCS11_MODULES (letters, digits, . _ -)";
      if (form.tokenLabel.length > 32) e.tokenLabel = "32 characters at most (a PKCS#11 token label)";
      if (form.credentialType === "vault" && !form.vaultPath.trim()) e.vaultPath = "Enter the secret path of the PIN in your vault";
      if (form.credentialType === "vault" && !isAdmin) e.vaultPath = "Only a team admin can add or change a vault reference";
    } else {
      if (!HOST_RE.test(form.host.trim())) e.host = "Enter the KMIP server's host name or IP address";
      const port = Number(form.port.trim() || 5696);
      if (!/^\d{0,5}$/.test(form.port.trim()) || port < 1 || port > 65535) e.port = "1 to 65535";
      const pemError = checkPem(form.caPem);
      if (pemError) e.caPem = pemError;
      const needCert = !certStored || kmipWhereChanged;
      if (form.clientCert.trim() && !form.clientCert.includes("-----BEGIN CERTIFICATE-----")) e.clientCert = "Paste the PEM client certificate";
      else if (needCert && !form.clientCert.trim()) e.clientCert = certStored ? "Re-enter it: it is cleared when the server, CA or node changes" : "Paste the PEM client certificate";
      if (form.clientKey.trim() && (!form.clientKey.includes("PRIVATE KEY-----") || form.clientKey.includes("ENCRYPTED PRIVATE KEY")))
        e.clientKey = "Paste the unencrypted PEM private key of the client certificate";
      else if (needCert && !form.clientKey.trim()) e.clientKey = "Paste the PEM private key of the client certificate";
    }
    if (!form.nodeId) e.nodeId = "Choose the scan node that reaches this HSM or key manager";
    return e;
  };

  const submit = (test: boolean) => {
    const found = validate();
    setErrors(found);
    if (Object.keys(found).length) {
      toast.error("Check the highlighted fields");
      return;
    }
    const pkcs11 = form.provider === "pkcs11";
    const secrets: Record<string, string> = {};
    if (pkcs11 && form.credentialType === "password" && form.pin) secrets.pin = form.pin;
    if (!pkcs11 && form.clientCert.trim()) secrets.client_cert = form.clientCert.trim() + "\n";
    if (!pkcs11 && form.clientKey.trim()) secrets.client_key = form.clientKey.trim() + "\n";
    const body: CbomSourceWrite = {
      name: form.name.trim(),
      node_id: form.nodeId,
      config: pkcs11
        ? {
            provider: "pkcs11",
            module: form.module.trim(),
            token_label: form.tokenLabel.trim() || null,
            credential_type: form.credentialType,
            vault: form.credentialType === "vault" ? { provider: form.vaultProvider, path: form.vaultPath.trim() } : null,
          }
        : { provider: "kmip", host: form.host.trim(), port: form.port.trim() ? Number(form.port.trim()) : null, ca_pem: form.caPem.trim() ? form.caPem : null },
      secrets,
      ...(source ? { expected_version: source.row_version } : { kind: "key_manager" }),
    };
    save.mutate({ body, test });
  };

  return (
    <SectionCard
      id="km-form"
      className="scroll-mt-4"
      title={source ? `Edit ${source.name}` : "Add an HSM or key manager"}
      description="Keys are inventoried by their attributes only; no key value ever leaves the HSM or key manager."
    >
      <div className="space-y-5">
        <Field label="Name" htmlFor="km-name" required error={errors.name}>
          <Input id="km-name" data-testid="km-name" value={form.name} maxLength={64} placeholder="hsm-payments-01" onChange={(e) => set({ name: e.target.value })} />
        </Field>
        <div data-testid="km-provider">
          <ChoiceCards<KmProvider>
            name="km-provider"
            label="Kind of key manager"
            value={form.provider}
            onChange={(v) => set({ provider: v })}
            options={[
              { value: "pkcs11", title: "HSM or token (PKCS#11)", description: "Read through the vendor library on the scan node" },
              { value: "kmip", title: "KMIP server", description: "Read over TLS with a client certificate" },
            ]}
          />
        </div>

        {form.provider === "pkcs11" ? (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Field
                label="Module name"
                htmlFor="km-module"
                required
                error={errors.module}
                hint="The name the scan node's operator maps to a library in ZS_PKCS11_MODULES, e.g. luna=/usr/safenet/lunaclient/lib/libCryptoki2_64.so. ZeroShield never sends a library path."
              >
                <Input id="km-module" data-testid="km-module" value={form.module} maxLength={64} placeholder="luna" onChange={(e) => set({ module: e.target.value })} />
              </Field>
              <Field label="Token label (optional)" htmlFor="km-token" error={errors.tokenLabel} hint="Blank reads every initialised token the module shows">
                <Input id="km-token" data-testid="km-token" value={form.tokenLabel} maxLength={32} onChange={(e) => set({ tokenLabel: e.target.value })} />
              </Field>
            </div>
            <div className="space-y-3">
              <SubLabel>User PIN</SubLabel>
              <ChoiceCards<KmCred>
                name="km-credential"
                label="PIN source"
                value={form.credentialType}
                onChange={(v) => set({ credentialType: v })}
                options={[
                  { value: "password", title: "PIN", description: "Optional: without it only public objects are read" },
                  { value: "vault", title: "PIN from vault", description: "Fetched by the scan node when the job runs", disabled: !isAdmin },
                ]}
              />
              {form.credentialType === "password" ? (
                <SecretField id="km-pin" label="User PIN (crypto user / partition role)" value={form.pin} onChange={(v) => set({ pin: v })} isSet={pinStored} error={errors.pin} />
              ) : (
                <VaultFields
                  idPrefix="km"
                  provider={form.vaultProvider}
                  path={form.vaultPath}
                  error={errors.vaultPath}
                  onProvider={(v) => set({ vaultProvider: v })}
                  onPath={(v) => set({ vaultPath: v })}
                  placeholder="secret/zs-cbom/hsm/payments"
                />
              )}
            </div>
          </>
        ) : (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
              <Field label="Host" htmlFor="km-host" required error={errors.host} className="sm:col-span-3">
                <Input id="km-host" data-testid="km-host" value={form.host} maxLength={253} placeholder="kms01.bank.local" onChange={(e) => set({ host: e.target.value })} />
              </Field>
              <Field label="Port" htmlFor="km-port" error={errors.port} hint="Default 5696">
                <Input id="km-port" data-testid="km-port" inputMode="numeric" value={form.port} maxLength={5} onChange={(e) => set({ port: e.target.value.replace(/[^\d]/g, "") })} />
              </Field>
            </div>
            <Field
              label="Server CA certificate (optional)"
              htmlFor="km-ca"
              error={errors.caPem}
              hint="PEM. With it the node verifies the KMIP server; TLS client authentication never reveals the client key either way."
            >
              <Textarea id="km-ca" data-testid="km-ca" value={form.caPem} spellCheck={false} className="font-mono text-xs min-h-[72px]" placeholder="-----BEGIN CERTIFICATE-----" onChange={(e) => set({ caPem: e.target.value })} />
            </Field>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <SecretField id="km-client-cert" label="Client certificate (PEM)" multiline value={form.clientCert} onChange={(v) => set({ clientCert: v })} isSet={certStored && !kmipWhereChanged} required error={errors.clientCert} />
              <SecretField id="km-client-key" label="Client private key (PEM, unencrypted)" multiline value={form.clientKey} onChange={(v) => set({ clientKey: v })} isSet={certStored && !kmipWhereChanged} required error={errors.clientKey} />
            </div>
          </>
        )}

        <div className="space-y-2">
          <SubLabel>What we read</SubLabel>
          <ul className="list-disc pl-5 space-y-1 text-sm text-zinc-700 dark:text-zinc-300" data-testid="km-reads">
            {KM_READS[form.provider].map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>

        <Field label="Reached through scan node" htmlFor="km-node" required error={errors.nodeId} hint={form.provider === "pkcs11" ? "The node that has the vendor's PKCS#11 client installed." : "The node must reach the host and port above."}>
          <div data-testid="km-node">
            <NodeSelect id="km-node" nodes={nodes} value={form.nodeId} onChange={(v) => set({ nodeId: v })} />
          </div>
        </Field>

        <FormButtons
          prefix="km"
          editing={!!source}
          pending={save.isPending}
          testing={!!save.variables?.test}
          saveLabel="Save key manager"
          onCancel={onCancelEdit}
          onTest={() => submit(true)}
          onSave={() => submit(false)}
        />
        {testStatus}
      </div>
    </SectionCard>
  );
}
