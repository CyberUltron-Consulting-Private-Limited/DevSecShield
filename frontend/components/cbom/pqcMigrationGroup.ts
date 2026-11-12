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
  instances: T[];
};

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

/** Group key: name + key_size/curve + roadmap (curve lowercased). */
export function pqcMigrationGroupKey(r: PqcMigrationRowLike): string {
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
      g = {
        key,
        name: r.name,
        descriptor: migrationDescriptor(r),
        roadmap: roadmap || "ML-KEM / ML-DSA",
        target: (r.migration_target || roadmap || "ML-KEM / ML-DSA").trim(),
        maxImpact: r.impact ?? null,
        nistLevel: r.nist_quantum_security_level ?? 0,
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
