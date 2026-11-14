// The harness's own price of a run (DEVILS-ADVOCATE.md §4.3 G9; E2E-PLAN UF-9), never the product's number (O-6).
// Moved here from CB-05's cb05.mjs `plannedCharge` unchanged in substance (INTERFACES v7 §C), so G9 can judge the
// estimate in CB-01 and CB-05 can import the same rule.
//   server 0.2 per target, database 1, network "1 per /24 or part" read as 1 credit per 256 addresses or part over
//   every range's addresses less the team never-scan addresses inside them, IdP free. In hundredths, as the product
//   stores charges.

export const RATES_C = { linux_servers: 20, windows_servers: 20, database: 100, network_range: 100, idp: 0 };
export const RATES_SOURCE = "DEVILS-ADVOCATE.md §4.3 G9 (rates); E2E-PLAN UF-9";

/** Addresses of an IPv4 CIDR (a /28 has 16). */
export function cidrSize(cidr) { return 2 ** (32 - Number(String(cidr || "").split("/")[1] ?? 32)); }

/** Is IPv4 `ip` inside `cidr`? */
export function inCidr(ip, cidr) {
  const [net, bits = "32"] = String(cidr).split("/");
  const n = (a) => String(a).split(".").reduce((x, o) => x * 256 + Number(o), 0);
  const size = 2 ** (32 - Number(bits));
  return Math.floor(n(ip) / size) === Math.floor(n(net) / size);
}

/**
 * The planned charge of the sources a customer configured.
 * sources: [{kind, name, config}] (the customer's own configuration, as typed); neverScan: addresses on the team's
 * never-scan list; failed: names of sources whose connection test the customer saw fail (not queued).
 */
export function plannedCharge(sources, neverScan = [], failed = []) {
  const failedSet = new Set(failed);
  const lines = [];
  let total = 0, netAddrs = 0;
  for (const { kind, name, config: c = {} } of sources) {
    if (failedSet.has(name)) { lines.push({ kind, name, queued: false, why: "connection test failed (seen by the customer)" }); continue; }
    if (kind === "network_range") {
      const n = cidrSize(c.cidr) - neverScan.filter((ip) => inCidr(ip, c.cidr)).length;
      netAddrs += n;
      lines.push({ kind, name, queued: true, addresses: n });
      continue;
    }
    const units = ["linux_servers", "windows_servers"].includes(kind)
      ? (Array.isArray(c.targets) ? c.targets : String(c.targets || "").split(/[\s,]+/)).filter(Boolean).length : 1;
    const rate = RATES_C[kind];
    lines.push({ kind, name, queued: true, units, rate_c: rate ?? null });
    if (rate !== undefined) total += rate * units;
  }
  const netC = netAddrs ? RATES_C.network_range * Math.ceil(netAddrs / 256) : 0;
  total += netC;
  const unknown = lines.filter((l) => l.queued && l.rate_c === null && l.kind !== "network_range");
  return { rates_c: RATES_C, source: RATES_SOURCE, network: { addresses: netAddrs, credits_c: netC }, lines, total_c: total, unknown };
}
