/**
 * Presentation-only grouping for PQC vulnerable / migration roadmap panels.
 * Instance rows stay 1:1 with quantum_vulnerable; grouping never collapses data.
 */

export type PqcMigrationRowLike = {
  name: string;
  primitive?: string | null;
  key_size?: string | null;
  curve?: string | null;
  nist_quantum_security_level?: number | null;
  migration_target?: string | null;
  migration_roadmap?: string | null;
  impact?: string | null;
  location?: string | null;
  bom_ref?: string | null;
  description?: string | null;
  suggested_fix?: string | null;
  finding_codes?: string[] | null;
  /** CBOM Sources run rows (issue #271): one row per asset, so they group by algorithm, finding and fix */
  asset_type?: string | null;
  type_label?: string | null;
  algorithm?: string | null;
  migration_code?: string | null;
  fix_code?: string | null;
  /** the knowledge-base title of migration_code (filled from pqc.kb by resolveMigrationRows) */
  finding_title?: string | null;
};

export type PqcMigrationGroup<T extends PqcMigrationRowLike = PqcMigrationRowLike> = {
  /** name|key_size|lower(curve)|roadmap */
  key: string;
  name: string;
  descriptor: string;
  roadmap: string;
  target: string;
  maxImpact: string | null;
  nistLevel: number;
  /** how to fix every instance of the group (pqcHowToFix of its first row) */
  fix: string;
  instances: T[];
};

/** A CBOM Sources run row: one per asset (an endpoint's name is its address), not one per algorithm. */
export function isRunMigrationRow(r: PqcMigrationRowLike): boolean {
  return r.asset_type != null;
}

const IMPACT_RANK: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
};

const PRIMITIVE_LABELS: Record<string, string> = {
  "block-cipher": "Block cipher",
  "stream-cipher": "Stream cipher",
  hash: "Hash",
  pke: "Public-key",
  signature: "Signature",
  "key-agree": "Key agreement",
  kem: "KEM",
  mac: "MAC",
  drbg: "DRBG",
  ae: "Authenticated encryption",
  combiner: "Combiner",
  other: "Other",
};

function labelPrimitive(k: string): string {
  return PRIMITIVE_LABELS[k] ?? k.replace(/[-_]/g, " ");
}

export function migrationDescriptor(r: PqcMigrationRowLike): string {
  const parts: string[] = [];
  if (r.primitive) parts.push(labelPrimitive(r.primitive));
  if (r.key_size) parts.push(`${r.key_size}-bit`);
  else if (r.curve) parts.push(r.curve);
  return parts.join(" · ") || "—";
}

/**
 * HoverCard "How to fix": prefer explicit suggested_fix, else sized roadmap,
 * else target family. Never return "—" when a roadmap/target exists.
 */
export function pqcHowToFix(r: PqcMigrationRowLike): string {
  const fix = (r.suggested_fix || "").trim();
  if (fix) return fix;
  const roadmap = (r.migration_roadmap || "").trim();
  if (roadmap) {
    return `Migrate to ${roadmap} (post-quantum); NIST deprecates quantum-vulnerable public-key cryptography after 2030 and disallows it after 2035.`;
  }
  const target = (r.migration_target || "").trim();
  if (target) {
    return `Plan migration to post-quantum cryptography (${target}); NIST deprecates quantum-vulnerable public-key cryptography after 2030 and disallows it after 2035.`;
  }
  return "—";
}

/**
 * HoverCard Description: finding description, else constructed from
 * primitive / key size / curve + quantum-vulnerable rationale.
 */
export function pqcDescription(r: PqcMigrationRowLike): string {
  const desc = (r.description || "").trim();
  if (desc) return desc;
  const parts: string[] = [];
  const descriptor = migrationDescriptor(r);
  if (descriptor && descriptor !== "—") parts.push(descriptor);
  if (r.key_size && !parts.some((p) => p.includes(`${r.key_size}-bit`))) {
    parts.push(`${r.key_size}-bit`);
  }
  if (r.curve && !parts.some((p) => p.toLowerCase().includes(String(r.curve).toLowerCase()))) {
    parts.push(`curve ${r.curve}`);
  }
  const detail = parts.length ? parts.join(" · ") : "public-key cryptography";
  const level = r.nist_quantum_security_level ?? 0;
  return (
    `Quantum-vulnerable algorithm ${r.name}: ${detail}. ` +
    `Broken by Shor's algorithm on a cryptographically-relevant quantum computer ` +
    `(NIST quantum security level ${level}).`
  );
}

/** Group key: name + key_size/curve + roadmap (curve lowercased). A run row (one per asset, named by its address) groups
 * by asset type + algorithm + quantum finding + fix instead, so 38 endpoints with the same key exchange and the same
 * fix are one card (issue #271). */
export function pqcMigrationGroupKey(r: PqcMigrationRowLike): string {
  if (isRunMigrationRow(r)) {
    const code = r.migration_code || r.fix_code || (r.finding_codes ?? [])[0] || "";
    return `run|${r.asset_type}|${(r.algorithm || "").trim().toLowerCase()}|${code}|${pqcHowToFix(r)}`;
  }
  const curveNorm = (r.curve || "").trim().toLowerCase();
  const keySize = (r.key_size || "").trim();
  const roadmap = (r.migration_roadmap || r.migration_target || "").trim();
  return `${r.name}|${keySize}|${curveNorm}|${roadmap}`;
}

export function groupPqcMigrationRows<T extends PqcMigrationRowLike>(
  rows: T[],
): PqcMigrationGroup<T>[] {
  const map = new Map<string, PqcMigrationGroup<T>>();
  for (const r of rows) {
    const key = pqcMigrationGroupKey(r);
    const roadmap = (r.migration_roadmap || r.migration_target || "").trim();
    let g = map.get(key);
    if (!g) {
      const run = isRunMigrationRow(r);
      g = {
        key,
        name: run ? runGroupName(r) : r.name,
        descriptor: run ? runGroupDescriptor(r) : migrationDescriptor(r),
        roadmap: roadmap || "ML-KEM / ML-DSA",
        target: (r.migration_target || roadmap || "ML-KEM / ML-DSA").trim(),
        maxImpact: r.impact ?? null,
        nistLevel: r.nist_quantum_security_level ?? 0,
        fix: pqcHowToFix(r),
        instances: [],
      };
      map.set(key, g);
    }
    g.instances.push(r);
    const cur = IMPACT_RANK[g.maxImpact ?? ""] ?? 9;
    const next = IMPACT_RANK[r.impact ?? ""] ?? 9;
    if (next < cur) g.maxImpact = r.impact ?? null;
  }
  return [...map.values()].sort((a, b) => {
    const d =
      (IMPACT_RANK[a.maxImpact ?? ""] ?? 9) - (IMPACT_RANK[b.maxImpact ?? ""] ?? 9);
    return d !== 0 ? d : a.name.localeCompare(b.name) || a.key.localeCompare(b.key);
  });
}

/** A run group's title: "<algorithm> on <type>" ("X25519 on TLS endpoint"); the row name when nothing is known. */
function runGroupName(r: PqcMigrationRowLike): string {
  const alg = (r.algorithm || "").trim();
  const type = (r.type_label || r.asset_type || "").trim();
  if (alg && type) return `${alg} on ${type}`;
  return alg || type || r.name;
}

/** A run group's second line: the quantum finding it carries, else the primitive and size. */
function runGroupDescriptor(r: PqcMigrationRowLike): string {
  const title = (r.finding_title || "").trim();
  return title || migrationDescriptor(r);
}

export type PqcFixGroup<T extends PqcMigrationRowLike = PqcMigrationRowLike> = {
  /** 1-based, in the order shown: "Fix 1" covers the most assets */
  index: number;
  fix: string;
  /** the group keys (pqcMigrationGroupKey) this fix covers */
  groupKeys: string[];
  /** the group names, once each */
  names: string[];
  instances: T[];
};

/** Each distinct fix once (issue #271): the groups that share a fix text, most assets first. Groups without a fix
 * ("—") are left out. */
export function distinctPqcFixes<T extends PqcMigrationRowLike>(groups: PqcMigrationGroup<T>[]): PqcFixGroup<T>[] {
  const map = new Map<string, Omit<PqcFixGroup<T>, "index">>();
  for (const g of groups) {
    if (!g.fix || g.fix === "—") continue;
    const f = map.get(g.fix) ?? { fix: g.fix, groupKeys: [], names: [], instances: [] };
    f.groupKeys.push(g.key);
    if (!f.names.includes(g.name)) f.names.push(g.name);
    f.instances.push(...g.instances);
    map.set(g.fix, f);
  }
  return [...map.values()]
    .sort((a, b) => b.instances.length - a.instances.length || a.fix.localeCompare(b.fix))
    .map((f, i) => ({ ...f, index: i + 1 }));
}

/** Fix number per group key, for the "Fix N" badge on each group card. */
export function fixIndexByGroup(fixes: PqcFixGroup[]): Map<string, number> {
  const out = new Map<string, number>();
  for (const f of fixes) for (const k of f.groupKeys) out.set(k, f.index);
  return out;
}

/** Collapse Accordion by default when the list would dominate the page. */
export function pqcAccordionDefaultCollapsed(
  groups: { key: string }[],
  instanceCount: number,
): boolean {
  return groups.length > 5 || instanceCount > 20;
}

/** Finding-shaped row used to backfill legacy migration[] (no location/bom_ref). */
export type PqcFindingJoinSource = {
  algorithm_name?: string | null;
  title?: string | null;
  location?: string | null;
  bom_ref?: string | null;
  description?: string | null;
  suggested_fix?: string | null;
  quantum_safe?: boolean | null;
  quantum_vulnerable?: boolean | null;
  impact?: string | null;
};

function findingName(f: PqcFindingJoinSource): string {
  return (f.algorithm_name || f.title || "").trim();
}

function isQuantumVulnerableFinding(f: PqcFindingJoinSource): boolean {
  if (f.quantum_vulnerable === true) return true;
  if (f.quantum_safe === false) return true;
  return false;
}

/**
 * Backfill migration instance detail from findings for legacy scan_data where
 * ``pqc.migration`` lacks ``location`` / ``bom_ref`` (pre-enrichment scans).
 *
 * Matching: prefer unused quantum-vulnerable findings with the same algorithm
 * name (stable order). Does not invent paths — empty stays empty when no join.
 */
export function enrichPqcMigrationFromFindings<T extends PqcMigrationRowLike>(
  migration: T[],
  findings: PqcFindingJoinSource[] | null | undefined,
): T[] {
  if (!migration.length || !findings?.length) return migration;

  const byName = new Map<string, PqcFindingJoinSource[]>();
  for (const f of findings) {
    if (!isQuantumVulnerableFinding(f)) continue;
    const name = findingName(f);
    if (!name) continue;
    const loc = (f.location || "").trim();
    if (!loc && !(f.bom_ref || "").trim()) continue;
    const list = byName.get(name) ?? [];
    list.push(f);
    byName.set(name, list);
  }
  // Stable: location then title
  for (const [, list] of byName) {
    list.sort((a, b) => {
      const la = (a.location || "").localeCompare(b.location || "");
      return la !== 0
        ? la
        : findingName(a).localeCompare(findingName(b));
    });
  }
  const nextIdx = new Map<string, number>();

  return migration.map((row) => {
    const hasLoc = Boolean((row.location || "").trim());
    const hasRef = Boolean((row.bom_ref || "").trim());
    if (hasLoc && hasRef) return row;

    const list = byName.get(row.name) ?? [];
    const i = nextIdx.get(row.name) ?? 0;
    nextIdx.set(row.name, i + 1);
    const f = list[i];
    if (!f) return row;

    return {
      ...row,
      location: hasLoc ? row.location : (f.location || "").trim() || row.location,
      bom_ref: hasRef ? row.bom_ref : f.bom_ref || row.bom_ref,
      description: (row.description || "").trim()
        ? row.description
        : f.description || row.description,
      suggested_fix: (row.suggested_fix || "").trim()
        ? row.suggested_fix
        : f.suggested_fix || row.suggested_fix,
    };
  });
}

/** The roadmap's groups. Code-scan rows: as the list (one per algorithm and size). Run rows: one per distinct fix, so a
 * fix shared by several algorithms or asset types is listed once, with all their assets (issue #271). */
export function pqcRoadmapGroups<T extends PqcMigrationRowLike>(rows: T[]): PqcMigrationGroup<T>[] {
  const groups = groupPqcMigrationRows(rows);
  if (!rows.some(isRunMigrationRow)) return groups;
  const fixes = distinctPqcFixes(groups);
  const covered = new Set(fixes.flatMap((f) => f.groupKeys));
  const byFix = fixes.map((f) => {
    const members = groups.filter((g) => f.groupKeys.includes(g.key));
    const maxImpact = members.map((g) => g.maxImpact).sort((a, b) => (IMPACT_RANK[a ?? ""] ?? 9) - (IMPACT_RANK[b ?? ""] ?? 9))[0] ?? null;
    return {
      key: `fix-${f.index}`, name: f.names.join(", "), descriptor: "", roadmap: f.fix, target: f.fix, maxImpact,
      nistLevel: members[0]?.nistLevel ?? 0, fix: f.fix, instances: f.instances,
    };
  });
  return [...byFix, ...groups.filter((g) => !covered.has(g.key))];
}
