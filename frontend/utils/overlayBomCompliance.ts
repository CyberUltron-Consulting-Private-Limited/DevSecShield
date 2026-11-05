/**
 * Stamp a single advisory Pass/Fail onto a CycloneDX BOM for download.
 * Strips Syft noise and per-framework dss:compliance.* dumps. Keeps crypto:
 * (and other non-dss/syft) properties so CBOM/AIBOM assets stay intact.
 * Canonicalizes PURLs, folds Syft paths into evidence.occurrences, and
 * merges identical name@version rows so the download matches the table.
 * Crypto assets (type "cryptographic-asset") are never merged and keep their
 * bom-ref. A CBOM code scan's JSON download does not use this overlay: it is the
 * server's signed document (utils/api/cbom_outputs.ts downloadCbomScanBom).
 */
type Prop = { name: string; value: string };
type Comp = Record<string, unknown>;

function overallVerdict(compliance: unknown): "pass" | "fail" | "unknown" {
  if (!compliance || typeof compliance !== "object") return "unknown";
  const rec = compliance as Record<string, unknown>;
  let fails = 0;
  let passes = 0;
  for (const [fw, block] of Object.entries(rec)) {
    if (fw === "disclaimer" || !block || typeof block !== "object") continue;
    const b = block as Record<string, unknown>;
    const fail = Number(b.fail || 0);
    const pass = Number(b.pass || 0) + Number(b.pass_with_evidence || 0);
    if (fail > 0) fails += 1;
    else if (pass > 0) passes += 1;
  }
  if (fails) return "fail";
  if (passes) return "pass";
  return "unknown";
}

function asProps(raw: unknown): Prop[] {
  if (!Array.isArray(raw)) return [];
  const out: Prop[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object" || !("name" in item)) continue;
    out.push({
      name: String((item as { name?: unknown }).name ?? ""),
      value: String((item as { value?: unknown }).value ?? ""),
    });
  }
  return out;
}

function keepPropName(name: string): boolean {
  if (name === "dss:compliance" || name.startsWith("declared:")) return true;
  if (name.startsWith("dss:") || name.startsWith("syft:")) return false;
  return Boolean(name);
}

function filterProps(raw: unknown, extra?: Prop): Prop[] {
  const kept: Prop[] = [];
  const seen = new Set<string>();
  for (const p of asProps(raw)) {
    if (!keepPropName(p.name) || seen.has(p.name)) continue;
    kept.push(p);
    seen.add(p.name);
  }
  if (extra && !seen.has(extra.name)) kept.push(extra);
  return kept;
}

function componentVerdictFromProps(raw: unknown): "pass" | "fail" | null {
  for (const p of asProps(raw)) {
    if (p.name === "dss:compliance" && (p.value === "pass" || p.value === "fail")) {
      return p.value;
    }
  }
  for (const p of asProps(raw)) {
    if (p.name === "dss:compliant") {
      return p.value === "true" ? "pass" : "fail";
    }
  }
  return null;
}

function canonicalPurl(purl: unknown): string {
  return String(purl || "").trim().split("?")[0];
}

function identityKey(c: Comp): string {
  const purl = canonicalPurl(c.purl).toLowerCase();
  if (purl) return purl;
  return `${String(c.name || "").trim().toLowerCase()}@${String(c.version || "").trim().toLowerCase()}`;
}

function occurrenceLocations(c: Comp): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const add = (loc: string) => {
    const t = loc.trim();
    if (t && !seen.has(t)) {
      seen.add(t);
      out.push(t);
    }
  };
  for (const p of asProps(c.properties)) {
    if (/^syft:location:\d+:path$/.test(p.name)) add(p.value);
  }
  const evidence = c.evidence;
  if (evidence && typeof evidence === "object") {
    const occ = (evidence as { occurrences?: unknown }).occurrences;
    if (Array.isArray(occ)) {
      for (const item of occ) {
        if (item && typeof item === "object" && "location" in item) {
          add(String((item as { location?: unknown }).location || ""));
        }
      }
    }
  }
  return out;
}

function mergeComponent(dst: Comp, src: Comp): Comp {
  const licenses = Array.isArray(dst.licenses) && dst.licenses.length ? dst.licenses : src.licenses;
  const hashes = Array.isArray(dst.hashes) && dst.hashes.length ? dst.hashes : src.hashes;
  const author = dst.author || src.author;
  const supplier = dst.supplier || src.supplier;
  const union = [...occurrenceLocations(dst)];
  for (const loc of occurrenceLocations(src)) {
    if (!union.includes(loc)) union.push(loc);
  }
  const dstVerdict = componentVerdictFromProps(dst.properties);
  const srcVerdict = componentVerdictFromProps(src.properties);
  const verdict = dstVerdict === "fail" || srcVerdict === "fail" ? "fail" : dstVerdict || srcVerdict;
  return {
    ...dst,
    licenses,
    hashes,
    author,
    supplier,
    evidence: union.length ? { occurrences: union.map((location) => ({ location })) } : dst.evidence,
    properties: filterProps(dst.properties, verdict ? { name: "dss:compliance", value: verdict } : undefined),
  };
}

/** A CycloneDX crypto asset is one finding at one place: two MD5 calls in two files are two assets, each with its
 * own bom-ref that dependencies and the scan's findings point at. They are never merged, re-referenced or given
 * folded evidence here (their occurrences keep line numbers); only the properties are filtered and stamped. */
function isCryptoAsset(c: Comp): boolean {
  return c.type === "cryptographic-asset";
}

function prepareComponent(comp: unknown, overall: "pass" | "fail" | "unknown"): unknown {
  if (!comp || typeof comp !== "object") return comp;
  const c: Comp = { ...(comp as Comp) };
  if (!isCryptoAsset(c)) {
    const purl = canonicalPurl(c.purl);
    if (purl) {
      c.purl = purl;
      c["bom-ref"] = purl;
    }
    const locs = occurrenceLocations(c);
    if (locs.length) c.evidence = { occurrences: locs.map((location) => ({ location })) };
  }
  const local = componentVerdictFromProps(c.properties);
  c.properties = filterProps(c.properties, { name: "dss:compliance", value: local ?? overall });
  return c;
}

export function overlayBomCompliance(
  bom: unknown,
  compliance: unknown,
): unknown {
  if (!bom || typeof bom !== "object") return bom;
  const out = structuredClone(bom) as Record<string, unknown>;
  const overall = overallVerdict(compliance);
  const meta =
    out.metadata && typeof out.metadata === "object"
      ? { ...(out.metadata as Record<string, unknown>) }
      : {};
  meta.properties = filterProps(meta.properties, { name: "dss:compliance", value: overall });
  out.metadata = meta;
  if (Array.isArray(out.components)) {
    const merged = new Map<string, Comp>();
    const order: string[] = [];
    const passthrough: unknown[] = [];
    for (const [index, raw] of out.components.entries()) {
      const prepared = prepareComponent(raw, overall);
      if (!prepared || typeof prepared !== "object") {
        passthrough.push(prepared);
        continue;
      }
      const c = prepared as Comp;
      // crypto assets keep their own slot in document order (never merged by name@version)
      const key = isCryptoAsset(c) ? `\u0000crypto-asset#${index}` : identityKey(c);
      if (!key) {
        passthrough.push(c);
        continue;
      }
      const prev = merged.get(key);
      if (!prev) {
        merged.set(key, c);
        order.push(key);
      } else {
        merged.set(key, mergeComponent(prev, c));
      }
    }
    out.components = [...order.map((k) => merged.get(k)!), ...passthrough];
  }
  return out;
}
