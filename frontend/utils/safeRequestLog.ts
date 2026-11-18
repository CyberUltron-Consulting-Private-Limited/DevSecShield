/**
 * The only way a failed API call reaches the browser console (#31). An AxiosError carries the whole request:
 * config.data is the body (the password of a refused sign-in, the current and new passwords on the Account page, the
 * temporary password of Create admin user, integration tokens) and config.headers holds the bearer token. Logging
 * the error printed them in plain text. This writes one line, "POST /account/password, status 400", read from the
 * method, the URL path and the status (or axios's error code when no response came): never the body, the headers,
 * the params, the query string, the fragment or the origin.
 */
import type { AxiosError } from "axios";

/** "/7/scan" from "/7/scan?x=1#y" or "https://user:pass@host/7/scan?x=1". */
function urlPath(url: unknown): string {
  if (typeof url !== "string" || url === "") return "(no URL)";
  try {
    return new URL(url, "http://relative.invalid").pathname;
  } catch {
    return "(unreadable URL)";
  }
}

/** "POST /account/password, status 400", or "POST /login, no response (ERR_NETWORK)". */
export function describeFailedRequest(error: Pick<AxiosError, "config" | "response" | "code">): string {
  const method = typeof error.config?.method === "string" ? error.config.method.toUpperCase() : "REQUEST";
  const request = `${method} ${urlPath(error.config?.url)}`;
  const status = error.response?.status;
  if (typeof status === "number") return `${request}, status ${status}`;
  // axios's own codes (ERR_NETWORK, ECONNABORTED, ERR_CANCELED, ...); anything else is left out
  const code = typeof error.code === "string" && /^[A-Z][A-Z0-9_]*$/.test(error.code) ? ` (${error.code})` : "";
  return `${request}, no response${code}`;
}

export function logFailedRequest(error: Pick<AxiosError, "config" | "response" | "code">): void {
  console.warn(`API request failed: ${describeFailedRequest(error)}`);
}
