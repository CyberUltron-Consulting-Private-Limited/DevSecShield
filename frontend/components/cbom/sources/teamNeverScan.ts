/**
 * Input checks and words for never-scan entries (the server is the authority), shared by the Network tab's team list,
 * its range sources and the Servers tab's source lists. The team list takes addresses and ranges only: the settings
 * API refuses a host name there with a 422, because on the scan node a listed name that does not resolve holds every
 * job of the team (fail closed).
 */

export const HOST_LABEL_RE = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/;

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
export function rangeError(raw: string, capped: boolean): string | null {
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
export function hostnameError(name: string): string | null {
  if (/[^\x00-\x7f]/.test(name)) return null; // internationalised names: the server converts and checks them
  const labels = name.split(".");
  if (name.length > 253 || !labels.every((l) => HOST_LABEL_RE.test(l)) || /^\d+$/.test(labels[labels.length - 1])) return `${name} is not a hostname`;
  return null;
}

/** Whether ``text`` is not an address or range but reads as a host name (what the server would store as one). */
export function readsAsHostName(text: string): boolean {
  const value = text.trim();
  return rangeError(value, false) !== null && hostnameError(value.toLowerCase().replace(/\.$/, "")) === null;
}

/**
 * The settings API's own words for a host name in the team list (its 422 detail after "network_exclusions: "). One
 * template on both sides: backend utilities/cbom_sources/targets.py HOST_NAME_NOT_ALLOWED, compared with this one by
 * backend/tests/test_never_scan_node_agreement.py. Keep it one JSON-style string on one line.
 */
export const HOST_NAME_NOT_ALLOWED = "{entry} is not an address or range (it reads as a host name); the team never-scan list takes addresses and ranges only. List host names in a server source's own Never scan field";

export function hostNameNotAllowed(text: string): string {
  return HOST_NAME_NOT_ALLOWED.replace("{entry}", () => text.trim());
}

/**
 * Names that are loopback by definition (RFC 6761 section 6.3: localhost and every name under .localhost; and the
 * loopback aliases of the default hosts files). On the scan node such a never-scan entry blocks 127.0.0.0/8 and ::1
 * and nothing else: it is never looked up and never holds a target. Same set as the node (netutil.LOOPBACK_NAMES) and
 * the backend (targets.LOOPBACK_NAMES); backend/tests/test_never_scan_node_agreement.py compares the three.
 */
export const LOOPBACK_NAMES: ReadonlySet<string> = new Set(["localhost", "ip6-localhost", "ip6-loopback", "localhost.localdomain", "localhost4", "localhost4.localdomain4", "localhost6", "localhost6.localdomain6"]);

export function isLoopbackName(text: string): boolean {
  const name = text.trim().toLowerCase().replace(/\.$/, "");
  return LOOPBACK_NAMES.has(name) || name.endsWith(".localhost");
}

/** Why a typed team never-scan entry cannot be added, or null. */
export function teamExclusionError(raw: string): string | null {
  const error = rangeError(raw, false);
  if (error === null) return null;
  return readsAsHostName(raw) ? hostNameNotAllowed(raw) : error;
}

/** The hint under a server source's own Never scan field (ServersTab): what a listed name does on the scan node. */
export const SOURCE_NEVER_SCAN_HINT =
  "IP addresses, ranges or hostnames, one per line or separated by commas. A listed hostname also covers every address it resolves to from the scan node; until it resolves there (an answer of only 0.0.0.0 or a loopback address does not count), none of these targets is scanned. localhost, names under .localhost and the other standard loopback names (ip6-localhost, localhost4, localhost.localdomain ...) are not looked up: they cover only 127.0.0.0/8 and ::1. A target name is skipped if any address it resolves to is listed; ranges are checked one address at a time. Never-scan always wins.";

/** Why a team never-scan entry already stored is a problem (a host name saved before the API refused them), or null. */
export function storedExclusionIssue(cidr: string): string | null {
  if (!readsAsHostName(cidr)) return null;
  if (isLoopbackName(cidr)) {
    // the node takes such a name as the loopback addresses: it holds nothing (re-review 5879769432)
    return "On the scan node this name only keeps the loopback addresses (127.0.0.0/8 and ::1) out; nothing is held. This list takes addresses and ranges only, so saving it is refused. Remove it, or list 127.0.0.0/8 and ::1 instead.";
  }
  return "Until this name resolves from the scan node it holds every job of this team (nothing is scanned), and saving the list is refused. Remove it; list host names in a server source's own Never scan field.";
}

/** The never-scan part of a refused settings save (400/422 whose detail names network_exclusions), shown inline. */
export function exclusionSaveError(error: unknown): string | null {
  const response = (error as { response?: { status?: number; data?: { detail?: unknown } } } | null)?.response;
  const detail = response?.data?.detail;
  if (!response || (response.status !== 400 && response.status !== 422) || typeof detail !== "string") return null;
  const prefix = "network_exclusions: ";
  return detail.startsWith(prefix) ? detail.slice(prefix.length) : null;
}
