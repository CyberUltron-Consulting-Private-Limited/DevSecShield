/**
 * "Run again" for a failed code scan (SAST, IaC, SCA + SBOM, CBOM, AI BOM). A failed scan cannot be started again
 * (the server never resets a failure), so "Run again" creates a new scan and opens it with the failed scan's
 * settings filled in: the repository URL, platform and branch, and the options, from the scan's stored metadata
 * (backend utilities/db/metadata.py). Two things are never stored and must be given again (G3, round 5): an uploaded
 * file (uploads are deleted after every scan) and a repository access token. The estimate is shown before anything is
 * charged, as for any new scan.
 *
 * The settings travel to the new scan's page in sessionStorage (this tab only; never a token).
 */

export type CodeScanType = "sast" | "iac" | "sbom_sca" | "cbom" | "ai_bom";

export interface RerunPrefill {
  repo_url: string | null;
  mode: "github" | "gitlab" | "bitbucket" | null;
  branch: string | null;
  /** The failed scan read an uploaded file: which kind, to choose again (null: a repository). */
  upload: "archive" | "cbom_file" | "sbom_file" | "ai_bom_file" | null;
  options: Record<string, unknown>;
}

const MODES = new Set(["github", "gitlab", "bitbucket"]);
/** The options each sidebar takes over. The server returns them in scan_metadata (backend
 * utilities/dashboard/scan_metadata.py rerun_options; before lab UI r1 F4 it dropped them, so nothing was copied).
 * AI BOM has none: its sidebar offers no option (it never sends scan_binaries). */
export const OPTION_KEYS: Record<CodeScanType, string[]> = {
  sast: ["app_lang", "exclude_path_arrays"],
  iac: ["environment", "iac_contexts"],
  sbom_sca: [],
  cbom: ["scan_binaries", "include_vendored", "scan_history"],
  ai_bom: [],
};

function record(value: unknown): Record<string, unknown> | null {
  if (typeof value === "string") {
    try {
      value = JSON.parse(value);
    } catch {
      return null;
    }
  }
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

/** The failed scan's settings, or null when it stored none (it never started). */
export function rerunPrefill(type: CodeScanType, scan: unknown): RerunPrefill | null {
  const meta = record(record(scan)?.scan_metadata);
  if (!meta) return null;
  const upload = meta.cbom_file_used === true ? "cbom_file"
    : meta.sbom_file_used === true ? "sbom_file"
      : meta.ai_bom_file_used === true ? "ai_bom_file"
        : meta.zip_file_used === true ? "archive" : null;
  const mode = text(meta.repo_type);
  const options: Record<string, unknown> = {};
  for (const key of OPTION_KEYS[type]) {
    if (meta[key] !== undefined && meta[key] !== null) options[key] = meta[key];
  }
  return {
    repo_url: upload ? null : text(meta.repo_url),
    mode: !upload && mode && MODES.has(mode) ? (mode as RerunPrefill["mode"]) : null,
    branch: upload ? null : text(meta.branch),
    upload,
    options,
  };
}

/** What the customer must give again on the new scan. */
export function rerunNotes(p: RerunPrefill): string[] {
  if (p.upload) {
    const what = { archive: "archive", cbom_file: "CBOM file", sbom_file: "SBOM file", ai_bom_file: "AI BOM file" }[p.upload];
    return [`Settings copied from the earlier scan. Choose the ${what} again: uploaded files are deleted after every scan.`];
  }
  return ["Settings copied from the earlier scan. If the repository is private, enter its access token again: tokens " +
    "are not stored."];
}

export function rerunTitle(title: unknown): string {
  const base = (typeof title === "string" && title.trim() ? title.trim() : "Scan").replace(/\s*\(run again\)$/i, "");
  return `${base.slice(0, 80)} (run again)`;
}

const key = (type: CodeScanType, scanId: number) => `zs-rerun:${type}:${scanId}`;

export function saveRerun(type: CodeScanType, scanId: number, prefill: RerunPrefill): void {
  try {
    sessionStorage.setItem(key(type, scanId), JSON.stringify(prefill));
  } catch {
    // storage blocked: the new scan opens empty, as any new scan
  }
}

/** The settings saved for this new scan (kept for a reload of the page), or null. */
export function readRerun(type: CodeScanType, scanId: number): RerunPrefill | null {
  try {
    const raw = sessionStorage.getItem(key(type, scanId));
    const value = raw ? (JSON.parse(raw) as RerunPrefill) : null;
    return value && typeof value === "object" && "options" in value ? value : null;
  } catch {
    return null;
  }
}

export function clearRerun(type: CodeScanType, scanId: number): void {
  try {
    sessionStorage.removeItem(key(type, scanId));
  } catch {
    // nothing to clear
  }
}
