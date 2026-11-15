// Transports of the Fleet tab (F1.3, #318): Ansible (AWX / AAP), Salt and AWS Systems Manager run the collection
// through the customer's own configuration management instead of SSH. The rules here mirror the backend's
// (backend/routers/cbom_transports.py: AwxConfig, SaltConfig, SsmConfig, SECRETS), so a form names its problem before
// it is sent; the server checks again. Also the Apply message (applyText). Pure: transportsLogic.test.ts pins it.
import type { CbomReconcileRecord, CbomReconcileResult, CbomTransportKind } from "@/utils/api/cbom_fleet";

export const TRANSPORT_LABEL: Record<CbomTransportKind, string> = {
  awx: "Ansible (AWX / AAP)",
  salt: "Salt",
  ssm: "AWS Systems Manager (SSM)",
};

/** The secrets each kind stores, write-only (backend SECRETS). */
export const SECRETS_OF: Record<CbomTransportKind, string[]> = { awx: ["token"], salt: ["username", "password"], ssm: [] };

/** What the customer installs on their side for each kind (GET .../transports/artifacts/{name}). */
export const ARTIFACTS_OF: Record<CbomTransportKind, string[]> = {
  awx: ["ansible-collection", "sshca-trust-ansible"],
  salt: ["salt-state", "sshca-trust-salt"],
  ssm: ["ssm-document", "ssm-role-cfn", "sshca-trust-ssm"],
};

/** The files that are made from the active zs-collect release (backend artifacts.NEEDS_RELEASE): they answer 400
 * while none is active, so the UI does not offer them then. */
export const NEEDS_RELEASE: ReadonlySet<string> = new Set(["ssm-document", "salt-state", "ansible-collection", "zs-collect-manifest"]);

/** The backend's answer to Test for AWX and Salt (POST .../validate is SSM only). */
export const TEST_ELSEWHERE =
  "Tested through a source that uses it: its control plane is reached from a scan node inside your network, not from ZeroShield.";

export function canTest(kind: CbomTransportKind): boolean {
  return kind === "ssm";
}

export interface TransportDraft {
  kind: CbomTransportKind;
  name: string;
  // AWX and Salt
  baseUrl: string;
  verifyTls: boolean;
  caPem: string;
  // AWX
  jobTemplateId: string;
  token: string;
  // Salt
  eauth: string;
  client: "local" | "local_async" | "ssh";
  mode: "cmd" | "state";
  batchSize: string;
  username: string;
  password: string;
  // SSM
  roleArn: string;
  regions: string;
  documentName: string;
  bucket: string;
}

export function emptyTransportDraft(kind: CbomTransportKind): TransportDraft {
  return {
    kind, name: "", baseUrl: "", verifyTls: true, caPem: "", jobTemplateId: "", token: "",
    eauth: "pam", client: "local_async", mode: "cmd", batchSize: "50", username: "", password: "",
    roleArn: "", regions: "", documentName: "devsecshield-collect", bucket: "",
  };
}

const URL_RE = /^https:\/\/[A-Za-z0-9.-]{1,253}(:\d{1,5})?(\/[A-Za-z0-9._~/-]*)?$/;
const ROLE_RE = /^arn:aws(-cn|-us-gov)?:iam::\d{12}:role\/[\w+=,.@/-]{1,512}$/;
const REGION_RE = /^[a-z]{2}(-[a-z]+)+-\d$/;
const DOC_RE = /^devsecshield-[A-Za-z0-9_.-]{1,115}$/;
const BUCKET_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const MAX_SALT_SSH_BATCH = 100;

const url = (v: string) => v.trim().replace(/\/+$/, "");
const regionList = (v: string) => [...new Set(v.split(/[\s,]+/).map((r) => r.trim()).filter(Boolean))].sort();

/** The problem of each field that blocks Add ({} when none). */
export function transportProblems(d: TransportDraft): Partial<Record<keyof TransportDraft, string>> {
  const out: Partial<Record<keyof TransportDraft, string>> = {};
  if (!d.name.trim()) out.name = "Enter a name";
  if (d.kind === "awx" || d.kind === "salt") {
    if (!URL_RE.test(url(d.baseUrl))) out.baseUrl = "Enter the https:// URL of the control plane (no user, query or fragment)";
  }
  if (d.kind === "awx") {
    const id = Number(d.jobTemplateId);
    if (!Number.isInteger(id) || id < 1) out.jobTemplateId = "Enter the job template ID (a number from 1)";
    if (!d.token) out.token = "Enter the AWX / AAP token";
  }
  if (d.kind === "salt") {
    const batch = Number(d.batchSize);
    if (!Number.isInteger(batch) || batch < 1 || batch > 500) out.batchSize = "1 to 500 hosts per batch";
    else if (d.client === "ssh" && batch > MAX_SALT_SSH_BATCH) out.batchSize = `At most ${MAX_SALT_SSH_BATCH} with salt-ssh (one salt-api request per batch)`;
    if (!d.username.trim()) out.username = "Enter the salt-api user";
    if (!d.password) out.password = "Enter the salt-api password";
  }
  if (d.kind === "ssm") {
    if (!ROLE_RE.test(d.roleArn.trim())) out.roleArn = "Enter an IAM role ARN (arn:aws:iam::<account>:role/<name>)";
    const regions = regionList(d.regions);
    if (regions.length === 0) out.regions = "Enter at least one region";
    else if (regions.length > 16) out.regions = "At most 16 regions";
    else if (!regions.every((r) => REGION_RE.test(r))) out.regions = "Each region looks like ap-south-1";
    if (!DOC_RE.test(d.documentName.trim())) out.documentName = "The document name starts with devsecshield-";
    if (d.bucket.trim() && !BUCKET_RE.test(d.bucket.trim())) out.bucket = "An S3 bucket name (lowercase letters, digits, dots, hyphens)";
  }
  return out;
}

/** The create body: config as the backend's models take it, and only the secrets this kind stores. */
export function transportBody(d: TransportDraft): {
  kind: CbomTransportKind; name: string; config: Record<string, unknown>; secrets: Record<string, string>;
} {
  const name = d.name.trim();
  if (d.kind === "awx") {
    const config: Record<string, unknown> = { base_url: url(d.baseUrl), job_template_id: Number(d.jobTemplateId), verify_tls: d.verifyTls };
    if (d.caPem.trim()) config.ca_pem = d.caPem.trim();
    return { kind: "awx", name, config, secrets: { token: d.token } };
  }
  if (d.kind === "salt") {
    const config: Record<string, unknown> = {
      base_url: url(d.baseUrl), eauth: d.eauth.trim() || "pam", client: d.client, mode: d.mode, batch_size: Number(d.batchSize),
      verify_tls: d.verifyTls,
    };
    if (d.caPem.trim()) config.ca_pem = d.caPem.trim();
    return { kind: "salt", name, config, secrets: { username: d.username.trim(), password: d.password } };
  }
  const config: Record<string, unknown> = { role_arn: d.roleArn.trim(), regions: regionList(d.regions), document_name: d.documentName.trim() };
  if (d.bucket.trim()) config.output_s3_bucket = d.bucket.trim();
  return { kind: "ssm", name, config, secrets: {} };
}

/** Where a transport points, for its row (never a secret). */
export function endpointText(t: { kind: CbomTransportKind; config: Record<string, unknown> }): string {
  const c = t.config;
  if (t.kind === "awx") return `${String(c.base_url ?? "")} · job template ${String(c.job_template_id ?? "?")}`;
  if (t.kind === "salt") return `${String(c.base_url ?? "")} · ${c.client === "ssh" ? "salt-ssh" : `minions (${String(c.client ?? "local_async")})`}`;
  const regions = Array.isArray(c.regions) ? (c.regions as string[]).join(", ") : "";
  return `${String(c.role_arn ?? "")} · ${regions}`;
}

// ---------------------------------------------------------------------------- Apply (#318)
const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

function changeParts(r: CbomReconcileRecord): string[] {
  const parts: string[] = [];
  const group = (noun: [string, string], items: [number | undefined, string][]) => {
    let first = true;
    for (const [n, verb] of items) {
      if (!n) continue;
      parts.push(first ? `${n} ${plural(n, noun[0], noun[1])} ${verb}` : `${n} ${verb}`);
      first = false;
    }
  };
  group(["source", "sources"], [[r.sources_created, "created"], [r.sources_updated, "updated"], [r.sources_removed, "removed"]]);
  group(["schedule", "schedules"], [[r.schedules_created, "created"], [r.schedules_updated, "updated"], [r.schedules_removed, "removed"]]);
  if (r.deferred) parts.push(`${r.deferred} ${plural(r.deferred, "change waits", "changes wait")} for a running job`);
  return parts;
}

function utcTime(iso: string | undefined): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
}

/** The toast after Apply policies. Saving a policy already asks the fleet worker to apply it, so an Apply right after
 * often has nothing left to do: it then says what the save did instead of "0 sources added" (staging QA of #227). */
export function applyText(r: CbomReconcileResult): string {
  if (!r.materialize) return `Decisions refreshed (${r.decisions_changed} changed); managed sources are turned off in this deployment`;
  const now = changeParts(r);
  if (now.length) return `Applied: ${now.join(", ")}`;
  const prev = r.previous;
  const before = prev && prev.by === "automatic" ? changeParts(prev) : [];
  if (prev && before.length) {
    const at = utcTime(prev.at);
    return `Applied when saved${at ? ` (${at})` : ""}: ${before.join(", ")}. Nothing more to change.`;
  }
  return "Nothing to change: the managed sources already match the policies.";
}
