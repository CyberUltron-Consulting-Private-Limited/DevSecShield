/**
 * Match CERT-In / compliance bom-refs to persisted BOM findings.
 *
 * Compliance refs are CycloneDX bom-refs (e.g. crypto-algo-…, modelref-…,
 * sbom-dep-N). Finding `id` is usually a Mongo ObjectId after persist, so
 * naive id/includes(fullRef) filters yield zero rows.
 */

export type RelatedFindingFields = {
  id?: string | null;
  /** CycloneDX inventory identity (preferred join key when present) */
  bom_ref?: string | null;
  title?: string | null;
  description?: string | null;
  location?: string | null;
  algorithm_name?: string | null;
  asset_name?: string | null;
  dependency?: string | null;
  name?: string | null;
  component_name?: string | null;
};

export type RefAliasNode = {
  id?: string | null;
  label?: string | null;
};

const PREFIXES = [
  /^pkg:[^/]+\/+/i,
  /^modelref-/i,
  /^modelfile-/i,
  /^cloud_service-/i,
  /^lib-/i,
  /^crypto-(?:algo|cert|protocol|material(?:-misuse)?)-/i,
  /^sbom-dep-/i,
];

/** Turn a file path into the hyphen form used inside CBOM bom-refs. */
export function hyphenateLocation(location: string): string {
  return location
    .trim()
    .toLowerCase()
    .replace(/\\/g, "/")
    .replace(/[\/_.]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

function lastSegment(ref: string): string {
  const cleaned = ref.replace(/\\/g, "/");
  const bySlash = cleaned.split("/").pop() || cleaned;
  const byColon = bySlash.split(":").pop() || bySlash;
  return byColon;
}

/**
 * Expand a bom-ref into lowercase candidate strings for matching.
 */
export function expandRefCandidates(ref: string): string[] {
  const raw = (ref || "").trim();
  if (!raw) return [];
  const lower = raw.toLowerCase();
  const out = new Set<string>([lower]);

  const seg = lastSegment(lower);
  if (seg) out.add(seg);

  let stripped = lower;
  for (const re of PREFIXES) {
    const next = stripped.replace(re, "");
    if (next && next !== stripped) {
      stripped = next;
      out.add(next);
    }
  }

  // pkg:pypi/cryptography@41 → cryptography
  const at = stripped.split("@")[0] || stripped;
  if (at.includes("/")) {
    const name = at.split("/").pop();
    if (name) out.add(name);
  } else if (at !== stripped) {
    out.add(at);
  }

  // Drop trailing asset-type suffixes common on CBOM cert refs
  for (const s of [...out]) {
    const noType = s.replace(/-(?:cert|key|protocol|algorithm)$/i, "");
    if (noType && noType !== s) out.add(noType);
  }

  return [...out].filter(Boolean);
}

export function buildRefAliasMap(
  nodes: RefAliasNode[] | null | undefined,
): Record<string, string> {
  const map: Record<string, string> = {};
  if (!nodes) return map;
  for (const n of nodes) {
    const id = (n.id || "").trim();
    const label = (n.label || "").trim();
    if (id && label) map[id] = label;
  }
  return map;
}

function nameFields(f: RelatedFindingFields): string[] {
  return [
    f.algorithm_name,
    f.asset_name,
    f.component_name,
    f.name,
    f.title,
    f.dependency,
  ]
    .map((x) => (x || "").trim().toLowerCase())
    .filter(Boolean);
}

function descriptionHay(f: RelatedFindingFields): string {
  return [f.description, f.location]
    .map((x) => (x || "").toLowerCase())
    .join("\n");
}

export type MatchOpts = {
  /** bom-ref → display label from cbom_graph / ai_bom_graph */
  aliases?: Record<string, string>;
  /** Index of this finding in the list (for sbom-dep-N) */
  findingIndex?: number;
};

/**
 * True if the finding corresponds to any of the compliance bom-refs.
 * Empty `refs` → true (no related-ref filter).
 */
export function findingMatchesRelatedRefs(
  finding: RelatedFindingFields,
  refs: string[],
  opts?: MatchOpts,
): boolean {
  if (!refs.length) return true;

  const id = (finding.id || "").trim().toLowerCase();
  const bomRef = (finding.bom_ref || "").trim().toLowerCase();
  const names = nameFields(finding);
  const loc = (finding.location || "").trim().toLowerCase();
  const locHyphen = loc ? hyphenateLocation(loc) : "";
  const descHay = descriptionHay(finding);
  const aliases = opts?.aliases || {};
  const idx = opts?.findingIndex;

  for (const ref of refs) {
    const refLower = (ref || "").trim().toLowerCase();
    if (!refLower) continue;

    // 0) Exact inventory bom_ref (charts → findings join)
    if (bomRef && bomRef === refLower) return true;

    // 1) Exact id (legacy / pre-persist bom-ref ids)
    if (id && id === refLower) return true;

    // 2) sbom-dep-N → findings[N]
    const m = /^sbom-dep-(\d+)$/.exec(refLower);
    if (m && typeof idx === "number" && idx === Number(m[1])) return true;

    // 3) Graph alias label ↔ finding name (exact, case-insensitive)
    const alias = (aliases[ref] || aliases[refLower] || "").trim().toLowerCase();
    if (alias && names.some((n) => n === alias)) {
      return true;
    }

    // 4) Location path encoded in bom-ref (CBOM style)
    if (locHyphen && locHyphen.length >= 5 && refLower.includes(locHyphen)) {
      return true;
    }
    if (loc && loc.length >= 4 && refLower.includes(loc.replace(/\\/g, "/"))) {
      return true;
    }

    // 5) Expanded candidates vs id / names / location / description
    for (const cand of expandRefCandidates(refLower)) {
      if (cand.length < 2) continue;

      // Exact id only for short/numeric candidates (avoid "sbom-dep-99".includes("9")).
      if (id && id === cand) return true;
      if (
        id &&
        id.length >= 6 &&
        cand.length >= 6 &&
        (id.includes(cand) || cand.includes(id))
      ) {
        return true;
      }

      // Name fields: exact equality only (substring caused gpt-4 ⊂ gpt-4o and
      // path tokens like …-rsa-… matching algorithm "RSA").
      if (names.some((n) => n === cand)) return true;

      if (
        loc &&
        cand.length >= 4 &&
        !/^\d+$/.test(cand) &&
        (loc.includes(cand) || (locHyphen && cand.includes(locHyphen)))
      ) {
        return true;
      }

      // Description/location only — never name fields (gpt-4o ⊂ gpt-4o-mini).
      if (cand.length >= 6 && !/^\d+$/.test(cand) && descHay.includes(cand)) return true;
    }
  }

  return false;
}

/** Filter a findings list by related refs (preserves order). */
export function filterFindingsByRelatedRefs<T extends RelatedFindingFields>(
  findings: T[],
  refs: string[],
  opts?: { aliases?: Record<string, string> },
): T[] {
  if (!refs.length) return findings;
  return findings.filter((f, i) =>
    findingMatchesRelatedRefs(f, refs, {
      aliases: opts?.aliases,
      findingIndex: i,
    }),
  );
}

/**
 * Count findings that match compliance bom-refs — same predicate as
 * "View related findings" / filterFindingsByRelatedRefs. Prefer this over
 * `refs.length` in drilldown UI (refs may include inventory graph nodes that
 * are not in the persisted findings list, and may be capped at 50).
 */
export function countRelatedFindings(
  findings: RelatedFindingFields[] | null | undefined,
  refs: string[] | null | undefined,
  opts?: { aliases?: Record<string, string> },
): number {
  const list = findings ?? [];
  const r = Array.isArray(refs) ? refs : [];
  if (!r.length) return 0;
  return filterFindingsByRelatedRefs(list, r, opts).length;
}
