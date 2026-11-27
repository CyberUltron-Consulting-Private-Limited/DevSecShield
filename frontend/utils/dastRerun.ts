/**
 * "Run again" for a failed DAST scan (X1 M2, Nov 11). A failed scan cannot be started again, so "Run again" creates a
 * new DAST scan and opens it with the failed scan's settings filled in: target URL, speed, URL limit, extra URLs,
 * include/exclude patterns, and the login form (login URL, XPaths, user name) from the scan's stored metadata
 * (backend utilities/dashboard/scan_metadata.py, dast branch). The login password is never stored or returned, so the
 * customer types it again. Nothing is charged until the new scan's estimate and Start.
 *
 * The settings travel to the new scan's page in sessionStorage (this tab only; never a password).
 */

export interface DastRerunPrefill {
  target_url: string | null;
  scan_speed: "fast" | "medium" | "slow" | null;
  max_urls: number | null;
  additional_urls: string[];
  pattern_mode: "none" | "include" | "exclude";
  patterns: string[];
  auth_type?: "password" | "session" | "otp_form";
  login_url: string;
  xpath_username: string;
  xpath_password: string;
  username: string;
  xpath_submit: string;
  auth_header_name?: string;
  session_check_url?: string;
  logged_in_indicator?: string;
  xpath_send_otp?: string;
  xpath_otp?: string;
  otp_source?: "static" | "totp";
  xpath_mpin?: string;
  xpath_mpin_submit?: string;
}

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

const text = (value: unknown): string => (typeof value === "string" ? value.trim() : "");
const list = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((v): v is string => typeof v === "string" && v.trim() !== "").map((v) => v.trim()) : [];
const SPEEDS = new Set(["fast", "medium", "slow"]);

/** The failed scan's settings, or null when it stored none (it never started). Never a password. */
export function dastRerunPrefill(scan: unknown): DastRerunPrefill | null {
  const meta = record(record(scan)?.scan_metadata);
  const target = meta ? text(meta.target_url) : "";
  if (!meta || !target) return null;
  const auth = record(meta.auth) ?? {};
  const include = list(meta.include_url_patterns);
  const exclude = list(meta.exclude_url_patterns);
  const speed = text(meta.scan_speed);
  const max = meta.max_urls;
  const rawType = text(auth.auth_type);
  const prefill: DastRerunPrefill = {
    target_url: target,
    scan_speed: SPEEDS.has(speed) ? (speed as DastRerunPrefill["scan_speed"]) : null,
    max_urls: typeof max === "number" && Number.isInteger(max) && max >= 1 ? max : null,
    additional_urls: list(meta.additional_urls_to_scan),
    pattern_mode: include.length ? "include" : exclude.length ? "exclude" : "none",
    patterns: include.length ? include : exclude,
    login_url: text(auth.login_url),
    xpath_username: text(auth.xpath_of_username_field),
    xpath_password: text(auth.xpath_of_password_field),
    username: text(auth.username),
    xpath_submit: text(auth.xpath_of_submit_button),
  };
  if (rawType === "session" || rawType === "otp_form") {
    prefill.auth_type = rawType;
    if (text(auth.auth_header_name)) prefill.auth_header_name = text(auth.auth_header_name);
    if (text(auth.session_check_url)) prefill.session_check_url = text(auth.session_check_url);
    if (text(auth.logged_in_indicator)) prefill.logged_in_indicator = text(auth.logged_in_indicator);
    if (text(auth.xpath_of_send_otp_button)) prefill.xpath_send_otp = text(auth.xpath_of_send_otp_button);
    if (text(auth.xpath_of_otp_field)) prefill.xpath_otp = text(auth.xpath_of_otp_field);
    if (auth.otp_source === "totp" || auth.otp_source === "static") prefill.otp_source = auth.otp_source;
    if (text(auth.xpath_of_mpin_field)) prefill.xpath_mpin = text(auth.xpath_of_mpin_field);
    if (text(auth.xpath_of_mpin_submit_button)) prefill.xpath_mpin_submit = text(auth.xpath_of_mpin_submit_button);
  }
  return prefill;
}

export const DAST_RERUN_NOTE =
  "Settings copied from the earlier scan. Enter the login password again (or fresh OTP / session token): secrets are not stored.";

const key = (scanId: number) => `zs-rerun:dast:${scanId}`;

export function saveDastRerun(scanId: number, prefill: DastRerunPrefill): void {
  try {
    sessionStorage.setItem(key(scanId), JSON.stringify(prefill));
  } catch {
    // storage blocked: the new scan opens empty, as any new scan
  }
}

/** The settings saved for this new scan (kept for a reload of the page), or null. */
export function readDastRerun(scanId: number): DastRerunPrefill | null {
  try {
    const raw = sessionStorage.getItem(key(scanId));
    const value = raw ? (JSON.parse(raw) as DastRerunPrefill) : null;
    return value && typeof value === "object" && typeof value.target_url === "string" ? value : null;
  } catch {
    return null;
  }
}
