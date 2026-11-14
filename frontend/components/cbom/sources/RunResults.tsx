"use client";

// Shared pieces of a collection run's results: asset type labels, the impact badge, an asset's facts, and every
// target's outcome (nothing skipped silently). The run results page itself is the shared results template
// (CbomResults with components/cbom/results/*); the older page component that lived here was rendered nowhere.

import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";

import type { CbomAsset, CbomImpact, CbomJobTargets } from "@/utils/backend_api";

import { jobReadLabel, jobTargetsLine } from "./jobReadLabel";
import { pluralize, targetGuidance } from "./logic";
import { StatusBadge, type Tone } from "./shared";
import { InfoTip } from "@/components/ui/info-tip";

export const ASSET_TYPE_LABEL: Record<string, string> = {
  certificate: "Certificate",
  private_key: "Private key",
  public_key: "Public key",
  keystore: "Keystore",
  ssh_host_key: "SSH host key",
  ssh_server_config: "SSH server config",
  ssh_endpoint: "SSH endpoint",
  tls_endpoint: "TLS endpoint",
  crypto_library: "Crypto library",
  process_library: "Process library",
  disk_encryption: "Disk encryption",
  os_crypto_policy: "OS crypto policy",
  database_tls: "Database TLS",
  database_config: "Database settings",
  database_user_auth: "Database authentication",
  k8s_cluster: "Kubernetes cluster",
  k8s_tls_secret: "Kubernetes TLS secret",
  k8s_certificate: "cert-manager certificate",
  k8s_ingress_tls: "Ingress TLS",
  k8s_mesh_policy: "Mesh mTLS policy",
  kms_key: "KMS key",
  cloud_secret: "Cloud secret",
  host_secret: "Secret in a service or script",
  crypto_config: "Crypto configuration",
  storage_encryption: "Storage encryption",
  load_balancer_tls: "Load balancer TLS",
  cdn_tls: "CDN TLS",
  api_tls: "API TLS",
  cloud_ca: "Certificate authority",
  iam_certificate: "IAM certificate",
  identity_provider: "Identity provider",
  signing_key: "Signing key",
  open_port: "Open port",
  glue_catalog: "Glue Data Catalog",
  glue_connection: "Glue connection",
  key_vault: "Key vault",
  coverage: "Not collected",
};

const IMPACT_TONE: Record<CbomImpact, Tone> = { Critical: "red", High: "red", Medium: "amber", Low: "blue" };
const TARGET_TONE: Record<string, Tone> = { ok: "green", partial: "amber", skipped_never_scan: "zinc", skipped_window: "amber", skipped_stop: "amber",
  skipped_deadline: "amber", skipped_cancelled: "zinc", not_supported: "zinc", skipped_credential_refused: "amber" };
const TARGET_LABEL: Record<string, string> = {
  ok: "Read", partial: "Partly read", unreachable: "Unreachable", refused: "Connection refused", timeout: "Timed out", no_route: "No route",
  auth_failed: "Login failed", mfa_required: "MFA required", host_key_changed: "Host key changed", identity_unverified: "Server not verified", kex_unsupported: "Key exchange not supported", sudoers_missing: "Sudoers missing", rbac_denied: "Kubernetes RBAC denied",
  sudo_denied: "Sudo refused", winrm_denied: "WinRM shell refused", tls_unavailable: "No TLS", not_supported: "Not supported", error: "Error",
  skipped_never_scan: "Skipped: never-scan list", skipped_window: "Skipped: scan window closed", skipped_stop: "Skipped: scanning stopped",
  skipped_deadline: "Skipped: time limit", skipped_cancelled: "Skipped: cancelled",
  skipped_credential_refused: "Skipped: credential refused",
};

export function ImpactBadge({ impact }: { impact: CbomImpact | null }) {
  if (!impact) return <span className="text-xs text-zinc-500">Info</span>;
  return <StatusBadge tone={IMPACT_TONE[impact]}>{impact}</StatusBadge>;
}

export function factsRows(asset: CbomAsset): [string, string][] {
  const out: [string, string][] = [];
  for (const [key, value] of Object.entries(asset.facts ?? {})) {
    if (value === null || value === undefined || value === "" || (Array.isArray(value) && value.length === 0)) continue;
    const text = typeof value === "string" ? value : JSON.stringify(value);
    out.push([key.replace(/_/g, " "), text.length > 400 ? `${text.slice(0, 400)}…` : text]);
  }
  return out.slice(0, 30);
}

/** One target that was not fully read: its status, the node's reason and, where there is one, what to do. */
export function TargetProblemRow({ t }: { t: { target: string; status: string; error?: string | null } }) {
  const guidance = targetGuidance(t.status, t.error, t.target);
  return (
    <li className="flex flex-wrap items-start gap-2 text-xs">
      <span className="font-mono text-zinc-700 dark:text-zinc-300 break-all">{t.target}</span>
      <StatusBadge tone={TARGET_TONE[t.status] ?? "red"}>{TARGET_LABEL[t.status] ?? t.status}</StatusBadge>
      {t.error && <span className="text-zinc-500 break-words min-w-0">{t.error}</span>}
      {guidance && (
        <span className="basis-full text-zinc-600 dark:text-zinc-400 break-words" data-testid="run-results-guidance">
          {guidance}
        </span>
      )}
    </li>
  );
}

export function TargetsBlock({ jobs }: { jobs: CbomJobTargets[] }) {
  const [open, setOpen] = useState<number | null>(null);
  if (jobs.length === 0) return null;
  return (
    <div className="space-y-2" data-testid="run-results-targets">
      <p className="text-sm font-medium text-zinc-900 dark:text-white">Targets <InfoTip id="cbom.run.targets" /></p>
      <ul className="space-y-2">
        {jobs.map((job) => {
          const problems = job.targets.filter((t) => t.status !== "ok");
          const [tone, label] = jobReadLabel(job);
          const targetsLine = jobTargetsLine(job);
          const assetsRead = typeof job.assets_read === "number";
          return (
            <li key={job.job_id} className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3 text-sm" data-testid={`run-results-job-${job.job_id}`}>
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium text-zinc-900 dark:text-white break-all">{job.source_name ?? `Source ${job.source_id ?? "—"}`}</span>
                <StatusBadge tone={tone as Tone}>{label}</StatusBadge>
                {job.lab_mode && (
                  <StatusBadge tone="amber" title="Lab mode: same-account collection — not for production">
                    Lab mode
                  </StatusBadge>
                )}
                {job.truncated && <StatusBadge tone="amber">Truncated</StatusBadge>}
                {job.asset_mismatch && (
                  <StatusBadge tone="amber" title={`Node reported ${job.asset_mismatch.reported}, stored ${job.asset_mismatch.stored}`}>
                    Asset count mismatch
                  </StatusBadge>
                )}
              </div>
              <p className="mt-1 text-xs text-zinc-500">
                {targetsLine ?? job.summary ?? "No result yet"}
                {/* the badge already says how many assets were read; the stored-row count (gaps included) only when it does not */}
                {assetsRead ? "" : ` · ${pluralize(job.asset_count, "asset")}`}
                {job.duration_s != null ? ` · ${job.duration_s}s` : ""}
              </p>
              {job.error && <p className="mt-1 text-xs text-red-600 dark:text-red-400 break-words">{job.error}</p>}
              {problems.length > 0 && (
                <div className="mt-2">
                  <button
                    type="button"
                    className="inline-flex items-center gap-1 text-xs text-blue-600 dark:text-blue-400 cursor-pointer"
                    onClick={() => setOpen(open === job.job_id ? null : job.job_id)}
                    data-testid={`run-results-problems-${job.job_id}`}
                  >
                    {open === job.job_id ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                    {pluralize(problems.length, problems.every((t) => /:\d+$/.test(t.target)) ? "endpoint" : "target")} not fully read
                  </button>
                  {open === job.job_id && (
                    <ul className="mt-2 space-y-1">
                      {problems.slice(0, 200).map((t, i) => (
                        <TargetProblemRow key={`${t.target}-${i}`} t={t} />
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
