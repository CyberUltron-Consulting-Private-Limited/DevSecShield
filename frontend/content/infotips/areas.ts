/**
 * Which area (text module, one chunk) holds the text of a tip: the id's first two segments, else its first segment,
 * looked up in AREA_PREFIXES. An area groups the tips one page or tab shows, so a page loads only its own areas.
 * A new id prefix must be added here (content/infotips.test.ts fails otherwise); each area stays within the gzip
 * budget of content/infotipsBundle.test.ts.
 */
export const AREA_PREFIXES = {
  scan: ["scan", "repo"],
  results: ["results"],
  sast: ["sast"],
  sbom: ["sbom"],
  iac: ["iac"],
  dast: ["dast"],
  aibom: ["aibom"],
  mcp: ["mcp"],
  llm: ["llm"],
  team: ["team"],
  settings: ["settings", "account", "admin", "ticketing"],
  integrations: ["int"],
  "cbom-scans": ["cbom.cfg", "cbom.table", "cbom.kpi", "cbom.list", "cbom.estate", "cbom.deliverables"],
  "cbom-results": ["cbom.res", "cbom.chart", "cbom.cal", "cbom.reg", "cbom.q0", "cbom.ai"],
  "cbom-grade": ["cbom.agility", "cbom.qgrade", "cbom.source"],
  "cbom-run": ["cbom.run"],
  "cbsrc-common": ["cbsrc.col", "cbsrc.common", "cbsrc.sources", "cbsrc.sidebar", "cbsrc.meta", "cbsrc.compare", "cbsrc.waves"],
  "cbsrc-nodes": ["cbsrc.nodes", "cbsrc.pool", "cbsrc.sched"],
  "cbsrc-servers": ["cbsrc.servers", "cbsrc.test", "cbsrc.app"],
  "cbsrc-workloads": ["cbsrc.k8s", "cbsrc.k8sdb", "cbsrc.db", "cbsrc.km", "cbsrc.img"],
  "cbsrc-cloud": ["cbsrc.cloud", "cbsrc.aws", "cbsrc.azure", "cbsrc.gcp", "cbsrc.idp", "cbsrc.ca", "cbsrc.cert", "cbsrc.ct"],
  "cbsrc-network": ["cbsrc.net"],
  "cbsrc-evidence": ["cbsrc.ev", "cbsrc.cmdb"],
  "cbsrc-run": ["cbsrc.rr"],
  "cbsrc-ssh-ca": ["cbsrc.sshca"],
  fleet: ["fleet"],
} as const satisfies Record<string, readonly string[]>;

export type TipArea = keyof typeof AREA_PREFIXES;
export const TIP_AREAS = Object.keys(AREA_PREFIXES) as TipArea[];

const AREA_OF_PREFIX = new Map<string, TipArea>(
  TIP_AREAS.flatMap((area) => AREA_PREFIXES[area].map((prefix) => [prefix, area] as const)),
);

/** The area of a tip id, or undefined for a prefix not listed above. */
export function areaOf(id: string): TipArea | undefined {
  const parts = id.split(".");
  return AREA_OF_PREFIX.get(parts.slice(0, 2).join(".")) ?? AREA_OF_PREFIX.get(parts[0]);
}
