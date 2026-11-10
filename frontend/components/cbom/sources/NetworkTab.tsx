"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CirclePlay, CircleX, Loader2, OctagonX, Pencil, Plus, Radar, ShieldCheck, Trash2, X } from "lucide-react";
import { useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import {
  createCbomSource,
  deleteCbomSource,
  getCbomJobAssets,
  getCbomSourcesSettings,
  listCbomScanNodes,
  listCbomSources,
  setCbomNetworkStop,
  startCbomDiscovery,
  testCbomSource,
  updateCbomSourcesSettings,
  type CbomExclusionItem,
  type CbomJob,
  type CbomPortItem,
  type CbomScanNode,
  type CbomSettingsWrite,
  type CbomSource,
  type CbomSourcesSettings,
} from "@/utils/backend_api";

import AppliancesSection from "./AppliancesSection";
import { cbomSourcesKeys } from "./keys";
import { MetadataFields, metadataConfig, metadataFrom, type SourceMetadata } from "./SourceMetadata";
import {
  addressProgress,
  ago,
  countHours,
  csvFirstColumn,
  DAYS,
  defaultWindow,
  emptyGrid,
  formatDateTime,
  normalizeGrid,
  pluralize,
  readTextFile,
  setCell,
  splitLines,
  zoneFileHostnames,
  type WindowGrid,
} from "./logic";
import {
  Checkbox2,
  ConfirmDialog,
  EmptyState,
  ErrorBlock,
  Field,
  JobStatusBadge,
  LoadingBlock,
  NodeSelect,
  NodeStatusBadge,
  SectionCard,
  StatusBadge,
  TestStatusBadge,
  Truncate,
  usePolledJob,
} from "./shared";

// ---------------------------------------------------------------------------- constants
// Values from backend/utilities/cbom_sources/schemas.py PortItem.protocol.
const PROTOCOLS: { value: string; label: string }[] = [
  { value: "tls", label: "TLS" },
  { value: "starttls-ldap", label: "LDAP StartTLS" },
  { value: "starttls-smtp", label: "SMTP StartTLS" },
  { value: "starttls-imap", label: "IMAP StartTLS" },
  { value: "starttls-postgres", label: "PostgreSQL TLS" },
  { value: "starttls-mysql", label: "MySQL TLS" },
  { value: "tds", label: "SQL Server (TDS)" },
  { value: "ssh", label: "SSH" },
  { value: "rdp", label: "RDP" },
  { value: "ike", label: "IKE (IPsec)" },
  // OT: an address with one of these open is scanned in fragile mode, one connection at a time
  { value: "opcua", label: "OPC UA (OT)" },
  { value: "modbus", label: "Modbus/TCP (OT, port check only)" },
  { value: "modbus-tls", label: "Modbus/TCP Security (OT, TLS)" },
];
const PROTOCOL_LABEL: Record<string, string> = Object.fromEntries(PROTOCOLS.map((p) => [p.value, p.label]));
const TIMEZONES = [
  "Asia/Kolkata",
  "UTC",
  "Asia/Dubai",
  "Asia/Singapore",
  "Asia/Hong_Kong",
  "Asia/Tokyo",
  "Australia/Sydney",
  "Europe/London",
  "Europe/Berlin",
  "America/New_York",
  "America/Chicago",
  "America/Los_Angeles",
];
type RateKey = "rate_conn_per_s" | "rate_parallel_per_server" | "rate_handshakes_per_endpoint";
const RATES: { key: RateKey; label: string; min: number; max: number; testId: string }[] = [
  { key: "rate_conn_per_s", label: "Connections/s per node", min: 1, max: 500, testId: "network-rate-conn" },
  { key: "rate_parallel_per_server", label: "Parallel per server", min: 1, max: 32, testId: "network-rate-parallel" },
  { key: "rate_handshakes_per_endpoint", label: "Handshakes per endpoint", min: 1, max: 200, testId: "network-rate-handshakes" },
];
const MAX_PORTS = 64;
const MAX_SNI = 10_000;
const MAX_EXCLUSIONS = 500;
const MAX_ZONE_FILE = 8 * 1024 * 1024;
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;
const EMAIL_RE = /^[^@\s'"<>]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$/;
const PHONE_RE = /^[0-9+()\- ]{3,64}$/;
const HOST_LABEL_RE = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/;

type Mode = "full" | "fragile";
const SECTION_LABEL: Record<string, string> = {
  network_exclusions: "Never scan",
  ports: "Ports and protocols",
  zeek_span: "Zeek",
  scan_window: "Scan window",
  rates: "Rate limits",
  soc: "SOC contacts",
};

/** Unsaved edits to the shared settings row; only touched sections are present. */
interface Draft {
  network_exclusions?: CbomExclusionItem[];
  ports?: CbomPortItem[];
  zeek_span?: boolean;
  scan_window?: WindowGrid;
  window_timezone?: string;
  rate_conn_per_s?: string;
  rate_parallel_per_server?: string;
  rate_handshakes_per_endpoint?: string;
  soc_email?: string;
  emergency_contact?: string;
}

// ---------------------------------------------------------------------------- helpers
function httpStatus(error: unknown): number | undefined {
  return (error as { response?: { status?: number } } | null)?.response?.status;
}

function useInvalidate(teamId: number) {
  const queryClient = useQueryClient();
  return () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });
}

function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function pad(hour: number): string {
  return String(hour).padStart(2, "0");
}

function ipv4ToInt(text: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return parts[0] * 16777216 + parts[1] * 65536 + parts[2] * 256 + parts[3];
}

function intToIpv4(n: number): string {
  return [Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256, Math.floor(n / 256) % 256, n % 256].join(".");
}

/** Light check of an IP, CIDR or a-b range (the server is the authority). Allowed ranges are capped at a /16. */
function rangeError(raw: string, capped: boolean): string | null {
  const text = raw.trim();
  if (!text) return "Enter an IP address, CIDR range or a-b range, e.g. 10.20.0.0/16";
  if (text.length > 64) return "Use at most 64 characters";
  if (text.includes(":")) {
    return /^[0-9a-fA-F:.]+(\/\d{1,3})?$|^[0-9a-fA-F:.]+\s*-\s*[0-9a-fA-F:.]+$/.test(text) ? null : `${text} is not an IP address or range`;
  }
  const dash = /^([\d.]+)\s*-\s*([\d.]+)$/.exec(text);
  if (dash) {
    const first = ipv4ToInt(dash[1]);
    const last = ipv4ToInt(dash[2]);
    if (first === null || last === null) return `${text} is not a valid address range`;
    if (last < first) return `${text}: the range ends before it starts`;
    if (capped && last - first + 1 > 65536) return `${text} has more than 65,536 addresses; split it into smaller ranges`;
    return null;
  }
  const cidr = /^([\d.]+)(?:\/(\d{1,2}))?$/.exec(text);
  const ip = cidr ? ipv4ToInt(cidr[1]) : null;
  const prefix = cidr?.[2] === undefined ? 32 : Number(cidr[2]);
  if (!cidr || ip === null || prefix > 32) return `${text} is not a valid IP address or CIDR range`;
  const size = 2 ** (32 - prefix);
  const network = ip - (ip % size);
  if (network !== ip) return `${text} has host bits set; did you mean ${intToIpv4(network)}/${prefix}?`;
  if (capped && prefix < 16) return `${text} is larger than a /16; split it into /16 ranges`;
  return null;
}

/** Hostname check mirroring the server (lower-case labels, no wildcards, not an IP). */
function hostnameError(name: string): string | null {
  if (/[^\x00-\x7f]/.test(name)) return null; // internationalised names: the server converts and checks them
  const labels = name.split(".");
  if (name.length > 253 || !labels.every((l) => HOST_LABEL_RE.test(l)) || /^\d+$/.test(labels[labels.length - 1])) return `${name} is not a hostname`;
  return null;
}

function cleanHostnames(lines: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const line of lines) {
    const name = line.trim().toLowerCase().replace(/\.$/, "");
    if (name && !seen.has(name)) {
      seen.add(name);
      out.push(name);
    }
  }
  return out;
}

/** Source names must be unique per kind and match the name rule; "range-10.20.0.0-16" style. */
function rangeName(cidr: string, taken: string[]): string {
  const base = `range-${cidr
    .trim()
    .replace(/\s+/g, "")
    .replace(/\//g, "-")
    .replace(/:/g, "_")
    .replace(/[^A-Za-z0-9._-]/g, "-")}`.slice(0, 58);
  const lower = new Set(taken.map((t) => t.toLowerCase()));
  if (!lower.has(base.toLowerCase())) return base;
  for (let i = 2; i < 100; i++) {
    const candidate = `${base}-${i}`;
    if (!lower.has(candidate.toLowerCase())) return candidate;
  }
  return NAME_RE.test(base) ? base : "range";
}

/** Which settings sections differ from the saved row, the PATCH body for them, and client-side errors. */
function planSave(draft: Draft, s: CbomSourcesSettings) {
  const body: CbomSettingsWrite = {};
  const changed = new Set<string>();
  const errors: Record<string, string | null> = {};
  if (draft.network_exclusions && !same(draft.network_exclusions, s.network_exclusions)) {
    body.network_exclusions = draft.network_exclusions;
    changed.add("network_exclusions");
  }
  if (draft.ports && !same(draft.ports, s.ports)) {
    body.ports = draft.ports;
    changed.add("ports");
  }
  if (draft.zeek_span !== undefined && draft.zeek_span !== s.zeek_span) {
    body.zeek_span = draft.zeek_span;
    changed.add("zeek_span");
  }
  const savedGrid = normalizeGrid(s.scan_window);
  const grid = draft.scan_window ?? savedGrid;
  const tz = draft.window_timezone ?? s.window_timezone;
  if (!same(grid, savedGrid) || tz !== s.window_timezone) {
    changed.add("scan_window");
    if (countHours(grid) === 0) errors.scan_window = "Allow at least one hour; an empty window would never scan";
    body.scan_window = grid;
    body.window_timezone = tz;
  }
  for (const rate of RATES) {
    const raw = draft[rate.key];
    if (raw === undefined) continue;
    const value = Number(raw.trim());
    if (!raw.trim() || !Number.isInteger(value) || value < rate.min || value > rate.max) {
      errors[rate.key] = `Enter a whole number from ${rate.min} to ${rate.max}`;
      changed.add("rates");
    } else if (value !== s[rate.key]) {
      body[rate.key] = value;
      changed.add("rates");
    }
  }
  if (draft.soc_email !== undefined) {
    const value = draft.soc_email.trim();
    if (value !== (s.soc_email ?? "")) {
      changed.add("soc");
      if (value && !EMAIL_RE.test(value)) errors.soc_email = "Enter a valid email address";
      else body.soc_email = value || null;
    }
  }
  if (draft.emergency_contact !== undefined) {
    const value = draft.emergency_contact.trim();
    if (value !== (s.emergency_contact ?? "")) {
      changed.add("soc");
      if (value && !PHONE_RE.test(value)) errors.emergency_contact = "Enter a phone number (digits, spaces, + - ( ))";
      else body.emergency_contact = value || null;
    }
  }
  return { body, changed, errors };
}

const REAPPLY = "The network scope was changed elsewhere and has been reloaded. Re-apply your changes and save again.";

// ---------------------------------------------------------------------------- tab
export default function NetworkTab({ teamId, onNavigate }: { teamId: number; onNavigate: (tab: string) => void }) {
  const queryClient = useQueryClient();
  const invalidate = useInvalidate(teamId);
  const enabled = Number.isFinite(teamId);
  const [draft, setDraft] = useState<Draft>({});
  const [showErrors, setShowErrors] = useState(false);
  const [addingRange, setAddingRange] = useState(false);
  const [deletingRange, setDeletingRange] = useState<CbomSource | null>(null);
  const [sniOpen, setSniOpen] = useState(false);
  const [discoveryJobs, setDiscoveryJobs] = useState<CbomJob[]>([]);
  const [exclusion, setExclusion] = useState({ cidr: "", reason: "" });
  const [exclusionError, setExclusionError] = useState<string | null>(null);
  const [port, setPort] = useState({ port: "", protocol: "tls", label: "" });
  const [portError, setPortError] = useState<string | null>(null);

  const settingsQuery = useQuery({
    queryKey: cbomSourcesKeys.settings(teamId),
    queryFn: () => getCbomSourcesSettings(teamId),
    enabled,
    retry: 1,
    refetchInterval: 30000, // a stop-all set by someone else shows up without a manual refresh
  });
  const nodesQuery = useQuery({
    queryKey: cbomSourcesKeys.nodes(teamId),
    queryFn: () => listCbomScanNodes(teamId),
    enabled,
    retry: 1,
    refetchInterval: 30000,
  });
  const rangesQuery = useQuery({
    queryKey: cbomSourcesKeys.sources(teamId, "network"),
    queryFn: () => listCbomSources(teamId, "network"),
    enabled,
    retry: 1,
    // Faster while a range's connection test waits for its scan node.
    refetchInterval: (query) => (query.state.data?.sources.some((s) => s.last_test_status === "pending") ? 6000 : 30000),
  });

  const putSettings = (data: CbomSourcesSettings) => queryClient.setQueryData(cbomSourcesKeys.settings(teamId), data);

  const saveMutation = useMutation({
    mutationFn: (body: CbomSettingsWrite) => updateCbomSourcesSettings(teamId, body),
    onSuccess: (data) => {
      putSettings(data);
      setDraft({});
      setShowErrors(false);
    },
    onError: (err) => {
      if (httpStatus(err) === 409) {
        setDraft({});
        setShowErrors(false);
        toast.info(REAPPLY);
      }
    },
    onSettled: invalidate,
  });

  const stopMutation = useMutation({
    mutationFn: (on: boolean) => setCbomNetworkStop(teamId, on),
    onSuccess: putSettings,
    onSettled: invalidate,
  });

  const discoveryMutation = useMutation({
    mutationFn: () => startCbomDiscovery(teamId),
    onSuccess: (data) => setDiscoveryJobs(data.jobs),
    onSettled: invalidate,
  });

  const testMutation = useMutation({
    mutationFn: (source: CbomSource) => testCbomSource(teamId, source.id),
    onSettled: invalidate,
  });

  const deleteMutation = useMutation({
    mutationFn: (source: CbomSource) => deleteCbomSource(teamId, source.id),
    onSuccess: () => setDeletingRange(null),
    onSettled: invalidate,
  });

  if (settingsQuery.isLoading || rangesQuery.isLoading) return <LoadingBlock />;
  const settings = settingsQuery.data;
  if (!settings || (rangesQuery.isError && !rangesQuery.data)) {
    return (
      <ErrorBlock
        onRetry={() => {
          settingsQuery.refetch();
          rangesQuery.refetch();
        }}
      />
    );
  }

  const ranges = rangesQuery.data?.sources.filter((s) => s.kind === "network_range") ?? [];
  const serverNow = rangesQuery.data?.server_time;
  const nodes = nodesQuery.data?.nodes ?? [];
  const stopped = settings.stop_all_network;

  // Effective values: the unsaved draft over the saved row.
  const exclusions = draft.network_exclusions ?? settings.network_exclusions;
  const ports = draft.ports ?? settings.ports;
  const zeek = draft.zeek_span ?? settings.zeek_span;
  const savedGrid = normalizeGrid(settings.scan_window);
  const grid = draft.scan_window ?? savedGrid;
  const timezone = draft.window_timezone ?? settings.window_timezone;
  const socEmail = draft.soc_email ?? settings.soc_email ?? "";
  const emergency = draft.emergency_contact ?? settings.emergency_contact ?? "";
  const plan = planSave(draft, settings);
  const dirty = plan.changed.size > 0;
  const errorFor = (key: string) => (showErrors ? plan.errors[key] ?? null : null);
  const unsaved = (section: string) => plan.changed.has(section) && <StatusBadge tone="amber">Not saved</StatusBadge>;

  const addresses = ranges.reduce((sum, r) => sum + (r.target_count || 0), 0);

  const updateGrid = (update: (g: WindowGrid) => WindowGrid) =>
    setDraft((d) => ({ ...d, scan_window: update(d.scan_window ?? savedGrid) }));

  const addExclusion = () => {
    const cidr = exclusion.cidr.trim();
    const reason = exclusion.reason.trim();
    const error =
      rangeError(cidr, false) ??
      (exclusions.some((e) => e.cidr === cidr) ? `${cidr} is already in the list` : null) ??
      (exclusions.length >= MAX_EXCLUSIONS ? `At most ${MAX_EXCLUSIONS} entries` : null) ??
      (reason.length > 120 ? "Keep the reason under 120 characters" : null);
    setExclusionError(error);
    if (error) return;
    setDraft((d) => ({ ...d, network_exclusions: [...(d.network_exclusions ?? settings.network_exclusions), { cidr, reason }] }));
    setExclusion({ cidr: "", reason: "" });
  };

  const addPort = () => {
    const value = Number(port.port.trim());
    const label = port.label.trim();
    const error =
      !/^\d{1,5}$/.test(port.port.trim()) || value < 1 || value > 65535
        ? "Enter a port from 1 to 65535"
        : ports.some((p) => p.port === value && p.protocol === port.protocol)
          ? `${value} ${PROTOCOL_LABEL[port.protocol] ?? port.protocol} is already in the list`
          : ports.length >= MAX_PORTS
            ? `At most ${MAX_PORTS} ports`
            : label.length > 40
              ? "Keep the label under 40 characters"
              : null;
    setPortError(error);
    if (error) return;
    setDraft((d) => ({ ...d, ports: [...(d.ports ?? settings.ports), { port: value, protocol: port.protocol, label }] }));
    setPort({ port: "", protocol: port.protocol, label: "" });
  };

  const save = () => {
    setShowErrors(true);
    if (Object.values(plan.errors).some(Boolean)) {
      toast.error("Fix the highlighted fields before saving");
      return;
    }
    if (Object.keys(plan.body).length === 0) return;
    saveMutation.mutate({ ...plan.body, expected_version: settings.row_version });
  };

  const windowChanged = plan.changed.has("scan_window");

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <p className="text-sm text-zinc-600 dark:text-zinc-400 max-w-3xl">
          The scan node handshakes with TLS and SSH services in the ranges you allow and records what each server offers. It never logs in or sends
          application data.
        </p>
        {stopped ? (
          <Button
            className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            disabled={stopMutation.isPending}
            onClick={() => stopMutation.mutate(false)}
            data-testid="network-resume"
          >
            {stopMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <CirclePlay className="h-4 w-4 mr-2" />}
            Resume network scanning
          </Button>
        ) : (
          <Button variant="destructive" className="cursor-pointer" disabled={stopMutation.isPending} onClick={() => stopMutation.mutate(true)} data-testid="network-stop">
            {stopMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <CircleX className="h-4 w-4 mr-2" />}
            Stop all network scanning
          </Button>
        )}
      </div>

      {stopped && (
        <div
          role="alert"
          data-testid="network-stopped-banner"
          className="flex items-start gap-3 rounded-lg border border-red-500/50 bg-red-500/10 p-4 text-sm text-red-700 dark:text-red-300"
        >
          <OctagonX className="h-5 w-5 shrink-0" />
          <div>
            <p className="font-medium">All network scanning is stopped</p>
            <p className="mt-0.5">
              Scan nodes skip network ranges and discovery sweeps until a team admin resumes scanning.
              {settings.stop_all_changed_at ? ` Stopped ${ago(settings.stop_all_changed_at, serverNow)}.` : ""}
            </p>
          </div>
        </div>
      )}

      {dirty && (
        <div className="rounded-lg border border-amber-500/50 bg-amber-500/10 px-4 py-3 text-sm text-amber-800 dark:text-amber-200" role="status">
          Unsaved changes: {Array.from(plan.changed).map((k) => SECTION_LABEL[k] ?? k).join(", ")}. Use Save network scope at the end of Safety to apply them.
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 items-start">
        {/* ------------------------------------------------------------------ Scope */}
        <SectionCard title="Scope" description="What may be scanned, and through which node.">
          <div className="space-y-6">
            <Section
              title="Allowed ranges"
              actions={
                !addingRange && (
                  <Button variant="outline" size="sm" className="cursor-pointer" onClick={() => setAddingRange(true)} data-testid="network-add-range">
                    <Plus className="h-4 w-4" />
                    Add range
                  </Button>
                )
              }
            >
              {ranges.length === 0 && !addingRange ? (
                <EmptyState
                  title="No allowed ranges yet"
                  body="Nothing is scanned until you allow a range and pick the scan node that reaches it."
                  action={
                    nodes.length === 0 ? (
                      <Button variant="outline" className="cursor-pointer" onClick={() => onNavigate("scan-nodes")}>
                        Add a scan node first
                      </Button>
                    ) : (
                      <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => setAddingRange(true)}>
                        <Plus className="h-4 w-4 mr-2" />
                        Add range
                      </Button>
                    )
                  }
                />
              ) : (
                ranges.length > 0 && (
                  <ScrollArea className="w-full border rounded-lg">
                    <div className="min-w-max">
                      <Table data-testid="network-ranges-table">
                        <TableHeader>
                          <TableRow>
                            <TableHead>Range</TableHead>
                            <TableHead>Scan node</TableHead>
                            <TableHead>Mode</TableHead>
                            <TableHead>Last test</TableHead>
                            <TableHead className="w-24">
                              <span className="sr-only">Actions</span>
                            </TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {ranges.map((r) => {
                            const cidr = typeof r.config?.cidr === "string" ? r.config.cidr : r.name;
                            const testing = testMutation.isPending && testMutation.variables?.id === r.id;
                            return (
                              <TableRow key={r.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800">
                                <TableCell>
                                  <span className="font-mono text-xs text-zinc-900 dark:text-white">{cidr}</span>
                                  <span className="block text-xs text-zinc-500">{pluralize(r.target_count, "address", "addresses")}</span>
                                </TableCell>
                                <TableCell className="max-w-[180px]">
                                  <Truncate className="text-zinc-700 dark:text-zinc-300" text={r.node_name ?? "No node"} />
                                  {r.node_status && r.node_status !== "online" && <NodeStatusBadge status={r.node_status} />}
                                </TableCell>
                                <TableCell className="text-zinc-600 dark:text-zinc-400">
                                  {r.config?.mode === "fragile" ? <StatusBadge tone="amber">Fragile: version check only</StatusBadge> : "Full"}
                                </TableCell>
                                <TableCell className="whitespace-normal max-w-[220px]">
                                  <RangeTestCell teamId={teamId} source={r} serverNow={serverNow} />
                                </TableCell>
                                <TableCell>
                                  <div className="flex items-center justify-end gap-1">
                                    <Button
                                      variant="ghost"
                                      size="icon-sm"
                                      className="cursor-pointer"
                                      aria-label={`Test ${cidr}`}
                                      title="Test the connection from the scan node"
                                      disabled={testing || r.last_test_status === "pending"}
                                      onClick={() => testMutation.mutate(r)}
                                    >
                                      {testing ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                                    </Button>
                                    <Button
                                      variant="ghost"
                                      size="icon-sm"
                                      className="cursor-pointer text-red-600 dark:text-red-400"
                                      aria-label={`Delete ${cidr}`}
                                      onClick={() => setDeletingRange(r)}
                                    >
                                      <Trash2 className="h-4 w-4" />
                                    </Button>
                                  </div>
                                </TableCell>
                              </TableRow>
                            );
                          })}
                        </TableBody>
                      </Table>
                    </div>
                    <ScrollBar orientation="horizontal" />
                  </ScrollArea>
                )
              )}
              {addingRange && (
                <AddRangeForm
                  teamId={teamId}
                  nodes={nodes}
                  takenNames={ranges.map((r) => r.name)}
                  onDone={() => setAddingRange(false)}
                  onNavigate={onNavigate}
                />
              )}
            </Section>

            <Section title="Never scan" badge={unsaved("network_exclusions")}>
              {exclusions.length === 0 ? (
                <EmptyState title="Nothing is excluded" body="Add OT networks, core routers and anything else that must never be touched." />
              ) : (
                <ScrollArea className="w-full border rounded-lg">
                  <div className="min-w-max">
                    <Table data-testid="network-exclusions-table">
                      <TableHeader>
                        <TableRow>
                          <TableHead>Range</TableHead>
                          <TableHead>Reason</TableHead>
                          <TableHead className="w-12">
                            <span className="sr-only">Remove</span>
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {exclusions.map((e) => (
                          <TableRow key={e.cidr} className="hover:bg-zinc-50 dark:hover:bg-zinc-800">
                            <TableCell className="font-mono text-xs text-zinc-900 dark:text-white">{e.cidr}</TableCell>
                            <TableCell className="max-w-[240px] text-zinc-600 dark:text-zinc-400">
                              <Truncate text={e.reason || "—"} />
                            </TableCell>
                            <TableCell>
                              <Button
                                variant="ghost"
                                size="icon-sm"
                                className="cursor-pointer"
                                aria-label={`Remove ${e.cidr} from never scan`}
                                onClick={() => setDraft((d) => ({ ...d, network_exclusions: exclusions.filter((x) => x.cidr !== e.cidr) }))}
                              >
                                <X className="h-4 w-4" />
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                  <ScrollBar orientation="horizontal" />
                </ScrollArea>
              )}
              <div className="grid grid-cols-1 sm:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)_auto] gap-2 items-start">
                <Input
                  aria-label="Range to never scan"
                  data-testid="network-exclusion-cidr"
                  className="font-mono text-sm"
                  value={exclusion.cidr}
                  maxLength={64}
                  placeholder="10.20.99.0/24"
                  onChange={(e) => setExclusion({ ...exclusion, cidr: e.target.value })}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      addExclusion();
                    }
                  }}
                />
                <Input
                  aria-label="Reason"
                  data-testid="network-exclusion-reason"
                  value={exclusion.reason}
                  maxLength={120}
                  placeholder="Reason, e.g. OT plant network"
                  onChange={(e) => setExclusion({ ...exclusion, reason: e.target.value })}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      addExclusion();
                    }
                  }}
                />
                <Button variant="outline" className="cursor-pointer" onClick={addExclusion} data-testid="network-exclusion-add">
                  <Plus className="h-4 w-4 mr-2" />
                  Add
                </Button>
              </div>
              {exclusionError && <InlineError>{exclusionError}</InlineError>}
              <p className="text-xs text-zinc-500">This list always wins. The node refuses these addresses even if a job asks for them.</p>
            </Section>

            <Section title="Hostnames for SNI">
              <p className="text-xs text-zinc-500">One IP often serves many sites, each with its own certificate. Add the names so each one is checked.</p>
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge tone="blue">{pluralize(settings.sni_hostnames.length, "hostname")}</StatusBadge>
                <Button variant="outline" size="sm" className="cursor-pointer" onClick={() => setSniOpen(true)} data-testid="network-sni-edit">
                  <Pencil className="h-4 w-4" />
                  {settings.sni_hostnames.length ? "Edit hostnames" : "Add hostnames"}
                </Button>
              </div>
            </Section>

            <Section title="Ports and protocols" badge={unsaved("ports") || unsaved("zeek_span")} last>
              {ports.length === 0 ? (
                <p className="text-sm text-zinc-600 dark:text-zinc-400">No ports. Add at least one port for the network scan to check.</p>
              ) : (
                <div className="flex flex-wrap gap-1.5" data-testid="network-ports">
                  {ports.map((p) => {
                    const text = `${p.port} ${p.label || PROTOCOL_LABEL[p.protocol] || p.protocol}`;
                    return (
                      <span
                        key={`${p.port}-${p.protocol}`}
                        title={PROTOCOL_LABEL[p.protocol] ?? p.protocol}
                        className="inline-flex items-center gap-1 rounded-full border border-zinc-400/50 py-0.5 pl-2.5 pr-1 text-xs font-medium text-zinc-700 dark:text-zinc-300"
                      >
                        {text}
                        <button
                          type="button"
                          aria-label={`Remove port ${text}`}
                          className="rounded-full p-0.5 hover:bg-zinc-500/15 cursor-pointer"
                          onClick={() => setDraft((d) => ({ ...d, ports: ports.filter((x) => !(x.port === p.port && x.protocol === p.protocol)) }))}
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </span>
                    );
                  })}
                </div>
              )}
              <div className="grid grid-cols-2 sm:grid-cols-[110px_minmax(0,1fr)_minmax(0,1fr)_auto] gap-2 items-start">
                <Input
                  aria-label="Port"
                  data-testid="network-port-input"
                  inputMode="numeric"
                  value={port.port}
                  maxLength={5}
                  placeholder="7443"
                  onChange={(e) => setPort({ ...port, port: e.target.value })}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      addPort();
                    }
                  }}
                />
                <Select value={port.protocol} onValueChange={(v) => setPort({ ...port, protocol: v })}>
                  <SelectTrigger aria-label="Protocol" className="w-full cursor-pointer" data-testid="network-port-protocol">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {PROTOCOLS.map((p) => (
                      <SelectItem key={p.value} value={p.value} className="cursor-pointer">
                        {p.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input
                  aria-label="Label (optional)"
                  data-testid="network-port-label"
                  value={port.label}
                  maxLength={40}
                  placeholder="Label (optional)"
                  onChange={(e) => setPort({ ...port, label: e.target.value })}
                />
                <Button variant="outline" className="cursor-pointer" onClick={addPort} data-testid="network-port-add">
                  <Plus className="h-4 w-4 mr-2" />
                  Add
                </Button>
              </div>
              {portError && <InlineError>{portError}</InlineError>}
              <div data-testid="network-zeek">
                <Checkbox2 id="network-zeek" checked={zeek} onChange={(v) => setDraft((d) => ({ ...d, zeek_span: v }))}>
                  Also read Zeek ssl.log from a SPAN port, to see what clients actually negotiate
                </Checkbox2>
              </div>
            </Section>
          </div>
        </SectionCard>

        <AppliancesSection teamId={teamId} nodes={nodes} onNavigate={onNavigate} />

        {/* ------------------------------------------------------------------ Safety */}
        <SectionCard title="Safety" description="When, how fast, and who to tell.">
          <div className="space-y-6">
            <Section
              title="Scan window"
              badge={unsaved("scan_window")}
              actions={
                <Select value={timezone} onValueChange={(v) => setDraft((d) => ({ ...d, window_timezone: v }))}>
                  <SelectTrigger aria-label="Time zone" className="w-[200px] cursor-pointer" data-testid="network-timezone">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {Array.from(new Set([timezone, ...TIMEZONES])).map((tz) => (
                      <SelectItem key={tz} value={tz} className="cursor-pointer">
                        {tz}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              }
            >
              <WindowGridEditor grid={grid} onChange={updateGrid} />
              <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-zinc-500">
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-3 w-3 rounded-[3px] bg-blue-600" aria-hidden="true" />
                  Allowed
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-3 w-3 rounded-[3px] bg-zinc-200 dark:bg-zinc-800" aria-hidden="true" />
                  Paused
                </span>
                <span>{pluralize(countHours(grid), "hour")} a week</span>
                <span className="ml-auto flex flex-wrap gap-2">
                  <Button variant="outline" size="sm" className="cursor-pointer" onClick={() => updateGrid(() => defaultWindow())}>
                    Weekday nights
                  </Button>
                  <Button variant="outline" size="sm" className="cursor-pointer" onClick={() => updateGrid(() => emptyGrid().map((row) => row.map(() => true)))}>
                    Every hour
                  </Button>
                  <Button variant="outline" size="sm" className="cursor-pointer" onClick={() => updateGrid(() => emptyGrid())}>
                    Clear
                  </Button>
                </span>
              </div>
              {countHours(grid) === 0 ? (
                <InlineError>Allow at least one hour; an empty window would never scan.</InlineError>
              ) : (
                <p className="text-xs text-zinc-500" data-testid="network-next-window">
                  {windowChanged
                    ? "Save to see when the next window starts."
                    : settings.in_window_now
                      ? "Inside the scan window now."
                      : settings.next_window_start
                        ? `Next window starts ${formatDateTime(settings.next_window_start)} (your time).`
                        : "No allowed hours."}{" "}
                  Work pauses at the end of the window and resumes in the next one. Click or drag across hours; arrow keys and Space work too.
                </p>
              )}
            </Section>

            <Section title="Rate limits" badge={unsaved("rates")}>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {RATES.map((rate) => (
                  <Field key={rate.key} label={rate.label} htmlFor={rate.testId} error={errorFor(rate.key)} hint={`${rate.min}-${rate.max}`}>
                    <Input
                      id={rate.testId}
                      data-testid={rate.testId}
                      type="number"
                      inputMode="numeric"
                      min={rate.min}
                      max={rate.max}
                      step={1}
                      value={draft[rate.key] ?? String(settings[rate.key])}
                      onChange={(e) => setDraft((d) => ({ ...d, [rate.key]: e.target.value }))}
                    />
                  </Field>
                ))}
              </div>
              <p className="text-xs text-zinc-500">Lower them for fragile or busy networks.</p>
            </Section>

            <Section title="Tell your SOC" badge={unsaved("soc")}>
              {nodes.length === 0 ? (
                <EmptyState
                  title="No scan nodes yet"
                  body="Each scan node's source IPs appear here once it registers, ready to share with your SOC."
                  action={
                    <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => onNavigate("scan-nodes")}>
                      <Plus className="h-4 w-4 mr-2" />
                      Add a scan node
                    </Button>
                  }
                />
              ) : (
                <ScrollArea className="w-full border rounded-lg">
                  <div className="min-w-max">
                    <Table data-testid="network-soc-table">
                      <TableHeader>
                        <TableRow>
                          <TableHead>Scan node</TableHead>
                          <TableHead>Source IPs</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {nodes.map((n) => (
                          <SocRow key={n.id} node={n} />
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                  <ScrollBar orientation="horizontal" />
                </ScrollArea>
              )}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <Field label="SOC email" htmlFor="network-soc-email" error={errorFor("soc_email")}>
                  <Input
                    id="network-soc-email"
                    data-testid="network-soc-email"
                    type="email"
                    value={socEmail}
                    maxLength={254}
                    placeholder="soc@example.com"
                    onChange={(e) => setDraft((d) => ({ ...d, soc_email: e.target.value }))}
                  />
                </Field>
                <Field label="Emergency stop contact" htmlFor="network-emergency" error={errorFor("emergency_contact")}>
                  <Input
                    id="network-emergency"
                    data-testid="network-emergency"
                    type="tel"
                    value={emergency}
                    maxLength={64}
                    placeholder="Phone number"
                    onChange={(e) => setDraft((d) => ({ ...d, emergency_contact: e.target.value }))}
                  />
                </Field>
              </div>
              <p className="text-xs text-zinc-500">Share the source IPs, allowed ranges and scan window with your SOC before the first run.</p>
            </Section>

            <Section title="Before the first run" last>
              <p className="text-sm text-zinc-900 dark:text-white" data-testid="network-totals">
                {pluralize(addresses, "address", "addresses")} after the never-scan list, {pluralize(settings.ports.length, "port")}.
              </p>
              <p className="text-xs text-zinc-500">
                A discovery sweep asks each scan node that has ranges to find open ports first.
                {stopped ? " Resume network scanning to run one." : ranges.length === 0 ? " Add an allowed range to run one." : ""}
              </p>
              {discoveryJobs.length > 0 && (
                <ul className="space-y-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 p-3" data-testid="network-discovery-jobs">
                  {discoveryJobs.map((job) => (
                    <DiscoveryJobRow key={job.id} teamId={teamId} job={job} />
                  ))}
                </ul>
              )}
              <div className="flex flex-wrap justify-end gap-2 pt-2">
                {dirty && (
                  <Button
                    variant="outline"
                    className="cursor-pointer"
                    disabled={saveMutation.isPending}
                    onClick={() => {
                      setDraft({});
                      setShowErrors(false);
                    }}
                  >
                    Discard changes
                  </Button>
                )}
                <Button
                  variant="outline"
                  className="cursor-pointer"
                  disabled={discoveryMutation.isPending || stopped || ranges.length === 0}
                  onClick={() => discoveryMutation.mutate()}
                  data-testid="network-discovery"
                >
                  {discoveryMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Radar className="h-4 w-4 mr-2" />}
                  Run discovery sweep
                </Button>
                <Button
                  className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                  disabled={saveMutation.isPending || !dirty}
                  onClick={save}
                  data-testid="network-save"
                >
                  {saveMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  Save network scope
                </Button>
              </div>
            </Section>
          </div>
        </SectionCard>
      </div>

      {sniOpen && <SniDialog teamId={teamId} settings={settings} onClose={() => setSniOpen(false)} />}

      <ConfirmDialog
        open={!!deletingRange}
        onOpenChange={(v) => !v && setDeletingRange(null)}
        title="Delete allowed range?"
        description={
          deletingRange ? `${typeof deletingRange.config?.cidr === "string" ? deletingRange.config.cidr : deletingRange.name} will no longer be scanned. Queued jobs for it are cancelled.` : ""
        }
        confirmLabel="Delete"
        destructive
        pending={deleteMutation.isPending}
        onConfirm={() => deletingRange && deleteMutation.mutate(deletingRange)}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------- small pieces
function Section({
  title,
  badge,
  actions,
  last,
  children,
}: {
  title: string;
  badge?: ReactNode;
  actions?: ReactNode;
  last?: boolean;
  children: ReactNode;
}) {
  return (
    <section className={cn("space-y-3", !last && "border-b border-zinc-200 dark:border-zinc-800 pb-6")}>
      <div className="flex flex-wrap items-center gap-3">
        <h3 className="flex-1 text-sm font-semibold text-zinc-900 dark:text-white">
          {title}
          {badge && <span className="ml-2 align-middle">{badge}</span>}
        </h3>
        {actions}
      </div>
      {children}
    </section>
  );
}

function InlineError({ children }: { children: ReactNode }) {
  return (
    <p className="text-sm text-red-500 dark:text-red-400" role="alert">
      {children}
    </p>
  );
}

function SocRow({ node }: { node: CbomScanNode }) {
  return (
    <TableRow className="hover:bg-zinc-50 dark:hover:bg-zinc-800">
      <TableCell className="max-w-[200px]">
        <Truncate className="font-medium text-zinc-900 dark:text-white" text={node.name} />
      </TableCell>
      <TableCell className="font-mono text-xs text-zinc-600 dark:text-zinc-400">
        {node.source_ips.length ? node.source_ips.join(", ") : <span className="font-sans">Reported when the node registers</span>}
      </TableCell>
    </TableRow>
  );
}

/** A range's connection test is run by its scan node: show why it waits, then the result. */
function RangeTestCell({ teamId, source, serverNow }: { teamId: number; source: CbomSource; serverNow?: string }) {
  const pendingJobId = source.last_test_status === "pending" ? source.last_test_job_id : null;
  const job = usePolledJob(teamId, pendingJobId);
  const detail = pendingJobId
    ? job.data?.waiting_reason ?? source.last_test_summary ?? "Waiting for the scan node"
    : source.last_test_at
      ? `${ago(source.last_test_at, serverNow)}${source.last_test_summary ? ` · ${source.last_test_summary}` : ""}`
      : null;
  return (
    <div className="space-y-1">
      {pendingJobId && job.data ? <JobStatusBadge status={job.data.status} /> : <TestStatusBadge status={source.last_test_status} title={source.last_test_summary} />}
      {detail && <span className="block text-xs text-zinc-500">{detail}</span>}
    </div>
  );
}

function DiscoveryJobRow({ teamId, job }: { teamId: number; job: CbomJob }) {
  const polled = usePolledJob(teamId, job.id);
  const live = polled.data ?? job;
  const note = live.error ?? live.waiting_reason;
  const [open, setOpen] = useState(false);
  const found = useQuery({
    queryKey: cbomSourcesKeys.jobAssets(teamId, job.id),
    queryFn: () => getCbomJobAssets(teamId, job.id),
    enabled: open && Number.isFinite(teamId),
    retry: 1,
  });
  const count = live.asset_count ?? 0;
  const progress = addressProgress(live);
  return (
    <li className="text-sm space-y-1" data-testid={`network-discovery-job-${job.id}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium text-zinc-900 dark:text-white">{live.node_name ?? "Scan node"}</span>
        <JobStatusBadge status={live.status} />
        {live.status === "success" && (
          <button type="button" className="text-xs text-blue-600 dark:text-blue-400 cursor-pointer" onClick={() => setOpen(!open)}>
            {pluralize(count, "open endpoint")} {open ? "(hide)" : "(show)"}
          </button>
        )}
        {note && <span className="text-xs text-zinc-500">{note}</span>}
        {progress && (
          <span className="text-xs text-zinc-700 dark:text-zinc-300" data-testid={`network-discovery-progress-${job.id}`}>
            {progress}
          </span>
        )}
      </div>
      {open && (
        <ul className="max-h-48 overflow-y-auto rounded border border-zinc-200 dark:border-zinc-800 p-2 font-mono text-xs text-zinc-700 dark:text-zinc-300">
          {found.isLoading ? (
            <li>Loading</li>
          ) : (
            (found.data?.items ?? []).map((a) => (
              <li key={a.id}>
                {a.location}
                {typeof a.facts?.service === "string" ? ` · ${a.facts.service}` : ""}
              </li>
            ))
          )}
          {found.data && found.data.total > found.data.items.length && <li>… and {found.data.total - found.data.items.length} more</li>}
        </ul>
      )}
    </li>
  );
}

// ---------------------------------------------------------------------------- add range
function AddRangeForm({
  teamId,
  nodes,
  takenNames,
  onDone,
  onNavigate,
}: {
  teamId: number;
  nodes: CbomScanNode[];
  takenNames: string[];
  onDone: () => void;
  onNavigate: (tab: string) => void;
}) {
  const invalidate = useInvalidate(teamId);
  const [cidr, setCidr] = useState("");
  const [nodeId, setNodeId] = useState<number | null>(nodes.length === 1 ? nodes[0].id : null);
  const [mode, setMode] = useState<Mode>("full");
  const [meta, setMeta] = useState<SourceMetadata>(() => metadataFrom(null));
  const [errors, setErrors] = useState<{ cidr?: string | null; node?: string | null; meta?: string | null }>({});

  const save = useMutation({
    mutationFn: ({ test, metaConfig }: { test: boolean; metaConfig: Record<string, unknown> }) =>
      createCbomSource(teamId, {
        kind: "network_range",
        name: rangeName(cidr, takenNames),
        node_id: nodeId ?? undefined,
        config: { cidr: cidr.trim(), mode, ...metaConfig },
        test_after_save: test,
      }),
    onSuccess: onDone,
    onSettled: invalidate,
  });

  const submit = (test: boolean) => {
    const metaConfig = metadataConfig(meta);
    const next = { cidr: rangeError(cidr, true), node: nodeId ? null : "Choose the scan node that reaches this range",
                   meta: typeof metaConfig === "string" ? metaConfig : null };
    setErrors(next);
    if (next.cidr || next.node || typeof metaConfig === "string") return;
    save.mutate({ test, metaConfig });
  };

  return (
    <div className="space-y-4 rounded-lg border border-zinc-200 dark:border-zinc-800 p-4" data-testid="network-range-form">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Field label="Range" htmlFor="range-cidr" required error={errors.cidr} hint="A /16 or smaller, one IP, or a-b">
          <Input
            id="range-cidr"
            data-testid="network-range-cidr"
            className="font-mono text-sm"
            value={cidr}
            maxLength={64}
            spellCheck={false}
            placeholder="10.20.0.0/16"
            onChange={(e) => setCidr(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                submit(false);
              }
            }}
          />
        </Field>
        <Field label="Scan node" htmlFor="range-node" required error={errors.node}>
          <div data-testid="network-range-node">
            <NodeSelect id="range-node" nodes={nodes} value={nodeId} onChange={setNodeId} />
          </div>
        </Field>
        <Field label="Mode" htmlFor="range-mode" hint={mode === "fragile" ? "For OT or devices that may not cope with many handshakes" : undefined}>
          <Select value={mode} onValueChange={(v) => setMode(v === "fragile" ? "fragile" : "full")}>
            <SelectTrigger id="range-mode" className="w-full cursor-pointer" data-testid="network-range-mode">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="full" className="cursor-pointer">
                Full
              </SelectItem>
              <SelectItem value="fragile" className="cursor-pointer">
                Fragile: version check only
              </SelectItem>
            </SelectContent>
          </Select>
        </Field>
      </div>
      {nodes.length === 0 && (
        <Button variant="outline" size="sm" className="cursor-pointer" onClick={() => onNavigate("scan-nodes")}>
          Add a scan node first
        </Button>
      )}
      <details className="rounded-md border border-zinc-200 dark:border-zinc-800 p-3">
        <summary className="cursor-pointer text-sm font-medium text-zinc-900 dark:text-white">Ownership and data</summary>
        <div className="mt-3"><MetadataFields value={meta} onChange={setMeta} idPrefix="range" /></div>
        {errors.meta && <p className="text-xs text-red-600 dark:text-red-400 mt-2" role="alert">{errors.meta}</p>}
      </details>
      <div className="flex flex-wrap justify-end gap-2">
        <Button variant="outline" className="cursor-pointer" onClick={onDone} disabled={save.isPending}>
          Cancel
        </Button>
        <Button variant="outline" className="cursor-pointer" disabled={save.isPending} onClick={() => submit(false)} data-testid="network-range-save">
          {save.isPending && save.variables?.test === false && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
          Save
        </Button>
        <Button
          className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
          disabled={save.isPending}
          onClick={() => submit(true)}
          data-testid="network-range-save-test"
        >
          {save.isPending && save.variables?.test === true && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
          Save and test
        </Button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------- scan window grid
/**
 * 7 x 24 toggle grid.  Mouse: click toggles, click-and-drag paints the first cell's new value.  Touch: tap toggles
 * (dragging scrolls the grid on small screens).  Keyboard: one tab stop, arrow keys move, Space or Enter toggles.
 */
function WindowGridEditor({ grid, onChange }: { grid: WindowGrid; onChange: (update: (g: WindowGrid) => WindowGrid) => void }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const paintRef = useRef<boolean | null>(null);
  const pointerRef = useRef<string>("mouse");
  const [focus, setFocus] = useState<[number, number]>([0, 0]);

  const paint = (day: number, hour: number, value: boolean) => onChange((g) => (g[day][hour] === value ? g : setCell(g, day, hour, value)));
  const toggle = (day: number, hour: number) => onChange((g) => setCell(g, day, hour, !g[day][hour]));

  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>, day: number, hour: number) => {
    if (e.key === " " || e.key === "Enter") {
      e.preventDefault();
      toggle(day, hour);
      return;
    }
    const moves: Record<string, [number, number]> = {
      ArrowLeft: [day, Math.max(0, hour - 1)],
      ArrowRight: [day, Math.min(23, hour + 1)],
      ArrowUp: [Math.max(0, day - 1), hour],
      ArrowDown: [Math.min(6, day + 1), hour],
      Home: [day, 0],
      End: [day, 23],
    };
    const next = moves[e.key];
    if (!next) return;
    e.preventDefault();
    setFocus(next);
    containerRef.current?.querySelector<HTMLButtonElement>(`[data-cell="${next[0]}-${next[1]}"]`)?.focus();
  };

  return (
    <div className="overflow-x-auto pb-1" data-testid="network-window-grid">
      <div ref={containerRef} role="group" aria-label="Scan window: hours when network scanning is allowed" className="min-w-[560px] select-none space-y-1">
        {grid.map((row, day) => (
          <div key={DAYS[day]} className="flex items-center gap-2">
            <span className="w-9 shrink-0 text-xs text-zinc-500">{DAYS[day]}</span>
            <div className="flex flex-1 gap-[2px]">
              {row.map((on, hour) => (
                <button
                  key={hour}
                  type="button"
                  data-cell={`${day}-${hour}`}
                  aria-pressed={on}
                  aria-label={`${DAYS[day]} ${pad(hour)}:00 to ${pad(hour + 1)}:00`}
                  tabIndex={focus[0] === day && focus[1] === hour ? 0 : -1}
                  className={cn(
                    "h-6 min-w-0 flex-1 rounded-[3px] cursor-pointer outline-none transition-colors focus-visible:ring-2 focus-visible:ring-blue-400 focus-visible:ring-offset-1 focus-visible:ring-offset-white dark:focus-visible:ring-offset-zinc-900",
                    on ? "bg-blue-600 hover:bg-blue-500" : "bg-zinc-200 hover:bg-zinc-300 dark:bg-zinc-800 dark:hover:bg-zinc-700",
                  )}
                  onPointerDown={(e) => {
                    pointerRef.current = e.pointerType;
                    if (e.pointerType === "touch" || e.button !== 0) return;
                    const value = !on;
                    paintRef.current = value;
                    paint(day, hour, value);
                    setFocus([day, hour]);
                    window.addEventListener(
                      "pointerup",
                      () => {
                        paintRef.current = null;
                      },
                      { once: true },
                    );
                  }}
                  onPointerEnter={(e) => {
                    if (paintRef.current === null) return;
                    // The button was released outside the window: stop painting.
                    if ((e.buttons & 1) === 0) {
                      paintRef.current = null;
                      return;
                    }
                    paint(day, hour, paintRef.current);
                  }}
                  onClick={(e) => {
                    // Mouse and pen toggled on pointer down; keyboard clicks (detail 0) are handled in onKeyDown.
                    if (pointerRef.current === "touch" && e.detail > 0) toggle(day, hour);
                  }}
                  onKeyDown={(e) => onKeyDown(e, day, hour)}
                  onFocus={() => setFocus([day, hour])}
                />
              ))}
            </div>
          </div>
        ))}
        <div className="relative ml-11 h-4 text-xs text-zinc-500" aria-hidden="true">
          {[0, 6, 12, 18, 24].map((hour) => (
            <span
              key={hour}
              className="absolute top-0"
              style={{ left: `${(hour / 24) * 100}%`, transform: hour === 0 ? "none" : hour === 24 ? "translateX(-100%)" : "translateX(-50%)" }}
            >
              {pad(hour)}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------- SNI hostnames
function SniDialog({ teamId, settings, onClose }: { teamId: number; settings: CbomSourcesSettings; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [text, setText] = useState(settings.sni_hostnames.join("\n"));
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const names = cleanHostnames(splitLines(text));

  const save = useMutation({
    mutationFn: (list: string[]) => updateCbomSourcesSettings(teamId, { sni_hostnames: list, expected_version: settings.row_version }),
    onSuccess: (data) => {
      queryClient.setQueryData(cbomSourcesKeys.settings(teamId), data);
      onClose();
    },
    onError: (err) => {
      if (httpStatus(err) === 409) {
        toast.info(REAPPLY);
        onClose();
      }
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) }),
  });

  const importFile = async (file: File | undefined, kind: "zone" | "list") => {
    if (!file) return;
    try {
      const content = await readTextFile(file, MAX_ZONE_FILE);
      const found = cleanHostnames(kind === "zone" ? zoneFileHostnames(content) : csvFirstColumn(content));
      const merged = cleanHostnames([...names, ...found]);
      setText(merged.join("\n"));
      setError(null);
      setNote(`${file.name}: ${pluralize(found.length, "hostname")} found, ${pluralize(merged.length - names.length, "new one")} added.`);
    } catch (err) {
      setError((err as Error).message);
      setNote(null);
    }
  };

  const submit = () => {
    if (names.length > MAX_SNI) {
      setError(`At most ${MAX_SNI.toLocaleString()} hostnames; this list has ${names.length.toLocaleString()}`);
      return;
    }
    const bad = names.map(hostnameError).find(Boolean);
    if (bad) {
      setError(bad);
      return;
    }
    setError(null);
    save.mutate(names);
  };

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Hostnames for SNI</DialogTitle>
          <DialogDescription>
            One hostname per line, up to {MAX_SNI.toLocaleString()}. Import a DNS zone export or a plain list; duplicates are dropped.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2 min-w-0">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Field label="Import a DNS zone file" htmlFor="sni-zone" hint="BIND export; A, AAAA and CNAME names">
              <Input id="sni-zone" data-testid="network-sni-zone" type="file" accept=".zone,.db,.txt,text/plain" className="cursor-pointer" onChange={(e) => importFile(e.target.files?.[0], "zone")} />
            </Field>
            <Field label="Import a plain list" htmlFor="sni-list" hint="Text or CSV; the first column is used">
              <Input id="sni-list" data-testid="network-sni-list" type="file" accept=".txt,.csv,text/plain,text/csv" className="cursor-pointer" onChange={(e) => importFile(e.target.files?.[0], "list")} />
            </Field>
          </div>
          <Field label="Hostnames" htmlFor="sni-text" error={error} hint={note ?? `${pluralize(names.length, "hostname")}`}>
            <Textarea
              id="sni-text"
              data-testid="network-sni-text"
              className="font-mono text-xs min-h-[240px] max-h-[50vh]"
              value={text}
              spellCheck={false}
              placeholder={"www.example.com\napi.example.com\nmail.example.com"}
              onChange={(e) => setText(e.target.value)}
            />
          </Field>
        </div>
        <DialogFooter>
          <Button variant="outline" className="cursor-pointer" onClick={onClose}>
            Cancel
          </Button>
          <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={save.isPending} onClick={submit} data-testid="network-sni-save">
            {save.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            Save hostnames
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
