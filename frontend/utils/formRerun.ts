/**
 * "Run again" on a failed MCP or LLM scan (X1, Nov 11): their error view's "Try Again" reloaded the page into the same
 * failure (a failed scan cannot be started again). Run again creates a new scan and hands the form's settings to it in
 * sessionStorage (this tab only). Only non-secret fields are kept: MCP header values and LLM API keys are dropped and
 * typed again.
 */
export type FormScanType = "mcp" | "llm";

const SECRET = /(key|token|secret|password|header|authorization)/i;
const key = (type: FormScanType, scanId: number) => `zs-rerun-form:${type}:${scanId}`;

export function saveFormRerun(type: FormScanType, scanId: number, settings: Record<string, unknown>): void {
  const safe = Object.fromEntries(Object.entries(settings).filter(([k]) => !SECRET.test(k)));
  try {
    sessionStorage.setItem(key(type, scanId), JSON.stringify(safe));
  } catch {
    // storage blocked: the new scan opens empty, as any new scan
  }
}

export function readFormRerun(type: FormScanType, scanId: number): Record<string, unknown> | null {
  try {
    const raw = sessionStorage.getItem(key(type, scanId));
    const value = raw ? JSON.parse(raw) : null;
    return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}
