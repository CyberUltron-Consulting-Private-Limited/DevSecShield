/** Project a CycloneDX SBOM into the Software bill of materials table rows. */

export type SbomComplianceStatus = "pass" | "fail" | "unknown";

export type SbomInventoryRow = {
  name: string;
  supplier: string;
  version: string;
  uniqueId: string;
  relationship: string;
  subDependencies: string;
  subSubDependencies: string;
  author: string;
  hash: string;
  cves: string;
  dateAdded: string;
  status: SbomComplianceStatus;
};

type CdxProp = { name?: string; value?: string };
type CdxHash = { alg?: string; content?: string };
type CdxLicense = { license?: { id?: string; name?: string }; expression?: string };
type CdxOccurrence = { location?: string };
type CdxComponent = {
  "bom-ref"?: string;
  type?: string;
  name?: string;
  version?: string;
  purl?: string;
  author?: string;
  publisher?: string;
  supplier?: { name?: string } | string;
  licenses?: CdxLicense[];
  hashes?: CdxHash[];
  properties?: CdxProp[];
  evidence?: { occurrences?: CdxOccurrence[] };
};
type CdxBom = {
  metadata?: {
    timestamp?: string;
    authors?: Array<{ name?: string }>;
    component?: CdxComponent;
    properties?: CdxProp[];
  };
  components?: CdxComponent[];
  dependencies?: Array<{ ref?: string; dependsOn?: string[] }>;
  vulnerabilities?: Array<{ id?: string; affects?: Array<{ ref?: string }> }>;
};

const GIT_SHA = /^[0-9a-f]{40}$/i;

function dash(value: string | undefined | null): string {
  const t = (value || "").trim();
  return t || "—";
}

function joinList(items: string[], empty = "—"): string {
  const uniq = [...new Set(items.map((s) => s.trim()).filter(Boolean))];
  return uniq.length ? uniq.join(", ") : empty;
}

function canonicalPurl(purl: string | undefined): string {
  return (purl || "").trim().split("?")[0];
}

function identityKey(comp: CdxComponent): string {
  const purl = canonicalPurl(comp.purl).toLowerCase();
  if (purl) return purl;
  return `${(comp.name || "").trim().toLowerCase()}@${(comp.version || "").trim().toLowerCase()}`;
}

export function formatBomDate(iso: string | undefined): string {
  const raw = (iso || "").trim();
  const day = raw.slice(0, 10);
  const parts = day.split("-");
  if (parts.length === 3 && parts[0].length === 4) {
    return `${parts[1]}.${parts[2]}.${parts[0].slice(2)}`;
  }
  return dash(day);
}

export function formatComponentVersion(version: string | undefined): string {
  const v = (version || "")
    .trim()
    .replace(/\s*\((python|pypi|pip|npm|node|javascript|js|maven|java|golang|go|gem|ruby|cargo|rust|nuget|composer|php|github)\)\s*$/i, "");
  if (!v) return "—";
  if (GIT_SHA.test(v)) return `${v.slice(0, 7)} (commit)`;
  return v.split("/")[0].trim() || v;
}

const GITHUB_MIT_ORGS = new Set(["actions", "github", "pypa"]);

function licenseText(comp: CdxComponent): string {
  const bits: string[] = [];
  for (const item of comp.licenses || []) {
    const id = item.license?.id || item.license?.name || item.expression;
    if (id) bits.push(id);
  }
  if (bits.length) return bits.join(", ");
  const org = githubOrg(comp.purl);
  if (org && GITHUB_MIT_ORGS.has(org)) return "MIT";
  return "";
}

function githubOrg(purl: string | undefined): string {
  const body = canonicalPurl(purl);
  if (!body.startsWith("pkg:github/")) return "";
  return body.slice("pkg:github/".length).split("@")[0].split("/")[0] || "";
}

function supplierText(comp: CdxComponent): string {
  if (githubOrg(comp.purl)) return "GitHub";
  const s = comp.supplier;
  if (typeof s === "string" && s.trim()) return s.trim();
  if (s && typeof s === "object" && s.name?.trim()) {
    const name = s.name.trim();
    if (name.toLowerCase() === "actions") return "GitHub";
    return name;
  }
  if (comp.publisher?.trim()) return comp.publisher.trim();
  const purl = canonicalPurl(comp.purl);
  if (purl.startsWith("pkg:pypi/")) return "PyPI";
  if (purl.startsWith("pkg:npm/")) return "npm";
  if (purl.startsWith("pkg:maven/")) {
    const rest = purl.slice("pkg:maven/".length).split("@")[0];
    return rest.includes("/") ? rest.split("/").slice(0, -1).join("/") : rest || "Maven";
  }
  return "";
}

function authorText(comp: CdxComponent): string {
  const org = githubOrg(comp.purl);
  if (org) return org;
  const author = (comp.author || "").trim();
  if (author && author.toLowerCase() !== "devsecshield") return author;
  const pub = (comp.publisher || "").trim();
  if (pub && pub.toLowerCase() !== "devsecshield") return pub;
  return "";
}

function shortHash(content: string): string {
  const t = content.trim();
  if (t.length > 16) return `${t.slice(0, 12)}…`;
  return t;
}

function hashText(comp: CdxComponent): string {
  const h = (comp.hashes || []).find((x) => x.content);
  if (h?.content) return `${h.alg || "hash"}:${shortHash(h.content)}`;
  const v = (comp.version || "").trim();
  if (GIT_SHA.test(v)) return `SHA-1:${shortHash(v.toLowerCase())}`;
  return "";
}

function uniqueIdText(comp: CdxComponent): string {
  return licenseText(comp);
}

function declaredDepends(comp: CdxComponent): string[] {
  const out: string[] = [];
  for (const p of comp.properties || []) {
    if (p.name === "declared:depends" && p.value) {
      out.push(...p.value.split(",").map((s) => s.trim()).filter(Boolean));
    }
  }
  return out;
}

function hasDeclaredDepends(comp: CdxComponent): boolean {
  return (comp.properties || []).some((p) => p.name === "declared:depends");
}

function occurrenceFiles(comp: CdxComponent): string[] {
  const files: string[] = [];
  const add = (loc: string) => {
    const t = loc.trim();
    if (!t) return;
    files.push(t.split("/").filter(Boolean).slice(-1)[0] || t);
  };
  for (const o of comp.evidence?.occurrences || []) add(o.location || "");
  for (const p of comp.properties || []) {
    if (/^syft:location:\d+:path$/.test(p.name || "")) add(p.value || "");
  }
  return [...new Set(files)];
}

function propStatus(props: CdxProp[] | undefined): SbomComplianceStatus | null {
  for (const p of props || []) {
    if (p.name === "dss:compliance" && (p.value === "pass" || p.value === "fail" || p.value === "unknown")) {
      return p.value;
    }
  }
  return null;
}

export function overallComplianceFromBom(bom: unknown): SbomComplianceStatus {
  if (!bom || typeof bom !== "object") return "unknown";
  return propStatus((bom as CdxBom).metadata?.properties) || "unknown";
}

function nameByRef(bom: CdxBom): Map<string, string> {
  const map = new Map<string, string>();
  const meta = bom.metadata?.component;
  if (meta?.["bom-ref"] && meta.name) map.set(meta["bom-ref"], meta.name);
  for (const c of bom.components || []) {
    const ref = c["bom-ref"] || canonicalPurl(c.purl);
    if (ref && c.name) map.set(ref, c.name);
  }
  return map;
}

function parentMap(bom: CdxBom): Map<string, string> {
  const parents = new Map<string, string>();
  for (const dep of bom.dependencies || []) {
    const parent = dep.ref || "";
    for (const child of dep.dependsOn || []) {
      if (child && parent && !parents.has(child)) parents.set(child, parent);
    }
  }
  return parents;
}

function childrenMap(bom: CdxBom): Map<string, string[]> {
  const kids = new Map<string, string[]>();
  for (const dep of bom.dependencies || []) {
    if (dep.ref) kids.set(dep.ref, [...(dep.dependsOn || [])]);
  }
  return kids;
}

function cvesForComp(bom: CdxBom, comp: CdxComponent): string[] {
  const refs = new Set(
    [comp["bom-ref"], canonicalPurl(comp.purl), comp.purl].filter(Boolean) as string[],
  );
  const ids: string[] = [];
  for (const v of bom.vulnerabilities || []) {
    const id = (v.id || "").trim();
    if (!id) continue;
    if ((v.affects || []).some((a) => refs.has(a.ref || ""))) {
      if (!ids.includes(id)) ids.push(id);
    }
  }
  return ids;
}

function mergeComponents(comps: CdxComponent[]): CdxComponent[] {
  const merged = new Map<string, CdxComponent>();
  const order: string[] = [];
  for (const c of comps) {
    const key = identityKey(c);
    if (!key) continue;
    const prev = merged.get(key);
    if (!prev) {
      merged.set(key, { ...c, purl: canonicalPurl(c.purl) || c.purl });
      order.push(key);
      continue;
    }
    const locs = [
      ...(prev.evidence?.occurrences || []),
      ...(c.evidence?.occurrences || []),
    ];
    const seen = new Set<string>();
    const occurrences = locs.filter((o) => {
      const loc = o.location || "";
      if (!loc || seen.has(loc)) return false;
      seen.add(loc);
      return true;
    });
    merged.set(key, {
      ...prev,
      licenses: prev.licenses?.length ? prev.licenses : c.licenses,
      hashes: prev.hashes?.length ? prev.hashes : c.hashes,
      author: prev.author || c.author,
      supplier: prev.supplier || c.supplier,
      evidence: occurrences.length ? { occurrences } : prev.evidence,
    });
  }
  return order.map((k) => merged.get(k)!);
}

function relationshipText(
  comp: CdxComponent,
  bom: CdxBom,
  names: Map<string, string>,
  parents: Map<string, string>,
): string {
  const ref = comp["bom-ref"] || canonicalPurl(comp.purl) || "";
  const appName = bom.metadata?.component?.name || "";
  const files = occurrenceFiles(comp);
  const via = files.length ? ` via ${files.join(", ")}` : "";
  if (ref && ref === bom.metadata?.component?.["bom-ref"]) return `Primary${via}`;
  const parentRef = parents.get(ref);
  const parentName = parentRef ? names.get(parentRef) || appName : "";
  if (parentName) return `Included in ${parentName}${via}`;
  if (githubOrg(comp.purl) && appName) return `GitHub Action included in ${appName}${via}`;
  if (appName) return `Third-party library included in ${appName}${via}`;
  return files.length ? `Used in ${files.join(", ")}` : "Third-party library";
}

export function inventoryRowsFromCycloneDx(bom: unknown): SbomInventoryRow[] {
  if (!bom || typeof bom !== "object") return [];
  const doc = bom as CdxBom;
  const comps = mergeComponents((doc.components || []).filter((c) => (c.name || "").trim()));
  if (!comps.length) return [];
  const names = nameByRef(doc);
  const parents = parentMap(doc);
  const children = childrenMap(doc);
  const overall = overallComplianceFromBom(doc);
  const dateAdded = formatBomDate(doc.metadata?.timestamp);
  const childByName = new Map<string, CdxComponent>();
  for (const other of comps) {
    const n = (other.name || "").trim().toLowerCase();
    if (n && !childByName.has(n)) childByName.set(n, other);
  }

  // Only treat the inventory as CVE-assessed when the BOM carries a vulnerabilities[]
  // array (possibly empty). Missing the key means the scan never linked advisories —
  // that is the real "N/A". An assessed package with no matches is "None".
  const vulnsAssessed = Array.isArray(doc.vulnerabilities);
  const rows = comps.map((c) => {
    const ref = c["bom-ref"] || canonicalPurl(c.purl) || "";
    const kidRefs = children.get(ref) || [];
    const kidNames = kidRefs.map((r) => names.get(r) || "").filter(Boolean);
    const grandNames = kidRefs.flatMap((r) => (children.get(r) || []).map((g) => names.get(g) || "")).filter(Boolean);
    const declared = declaredDepends(c);
    const direct = kidNames.length ? kidNames : declared;
    const knownLeaf = hasDeclaredDepends(c);
    let nested = grandNames;
    if (!nested.length) {
      nested = direct.flatMap((dep) => declaredDepends(childByName.get(dep.toLowerCase()) || {}));
    }
    const cveList = cvesForComp(doc, c);
    return {
      name: c.name!.trim(),
      supplier: dash(supplierText(c)),
      version: formatComponentVersion(c.version),
      uniqueId: dash(uniqueIdText(c)),
      relationship: relationshipText(c, doc, names, parents),
      subDependencies: joinList(direct, knownLeaf ? "None" : "—"),
      subSubDependencies: joinList(nested, knownLeaf || kidNames.length ? "None" : "—"),
      author: dash(authorText(c)),
      hash: dash(hashText(c)),
      cves: cveList.length ? cveList.join(", ") : vulnsAssessed ? "None" : "N/A",
      dateAdded,
      status: propStatus(c.properties) || overall,
    };
  });
  // Vulnerable packages first so Known vulnerabilities is not buried under clean inventory.
  return rows.sort((a, b) => {
    const aHit = a.cves !== "None" && a.cves !== "N/A" && a.cves !== "—" ? 0 : 1;
    const bHit = b.cves !== "None" && b.cves !== "N/A" && b.cves !== "—" ? 0 : 1;
    if (aHit !== bHit) return aHit - bHit;
    return a.name.localeCompare(b.name) || a.version.localeCompare(b.version);
  });
}
