// Run: npx --yes tsx components/cbom/sources/confidenceVocabulary.test.ts
// CB-18 (DA §2.3): evidence confidence is E0..E3; "Q0".."Q4" are the quantum risk grades. "Q0" is printed only as
// "Q0 gap(s)" and Q1..Q4 only with their risk word. The labels the UI keys by (CLASS_LABEL, CONFIDENCE_LABEL) are
// exactly the backend's values, read from its source, so a class or level the backend adds can never crash a view.
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const FRONTEND = process.cwd();
const BACKEND = join(FRONTEND, "..", "backend", "utilities", "cbom_sources");

function read(path: string): string {
  return readFileSync(path, "utf8");
}

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...walk(path));
    else if (/\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name)) out.push(path);
  }
  return out;
}

/** A Python tuple of strings, e.g. PQC_CLASSES = ("a", "b"). */
function pyTuple(source: string, name: string): string[] {
  const m = source.match(new RegExp(`^${name}\\s*=\\s*\\(([^)]*)\\)`, "m"));
  assert.ok(m, `${name} not found in the backend`);
  return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
}

/** The keys of a TS object literal `const NAME ... = { ... };` (quoted or bare keys). */
function tsKeys(source: string, name: string): string[] {
  const start = source.indexOf(`const ${name}`);
  assert.ok(start >= 0, `${name} not found`);
  const open = source.indexOf("{", source.indexOf("=", start));
  let depth = 0;
  let end = open;
  for (; end < source.length; end++) {
    if (source[end] === "{") depth++;
    if (source[end] === "}" && --depth === 0) break;
  }
  const body = source.slice(open + 1, end);
  const keys: string[] = [];
  let level = 0;
  for (const line of body.split("\n")) {
    const m = level === 0 ? line.match(/^\s*(?:"([^"]+)"|([A-Za-z0-9_]+))\s*:/) : null;
    if (m) keys.push(m[1] ?? m[2]);
    level += (line.match(/[[{(]/g) ?? []).length - (line.match(/[\]})]/g) ?? []).length;
  }
  return keys;
}

const posture = read(join(BACKEND, "posture.py"));
const evidence = read(join(BACKEND, "evidence.py"));
const shared = read(join(FRONTEND, "components", "cbom", "sources", "shared.tsx"));
const runPosture = read(join(FRONTEND, "components", "cbom", "sources", "RunPosture.tsx"));
const api = read(join(FRONTEND, "utils", "backend_api.ts"));

// 1. the keys the UI looks labels up by are exactly the backend's values
const classes = pyTuple(posture, "PQC_CLASSES");
assert.ok(classes.includes("unknown"), "the backend has the unknown class");
assert.deepEqual(tsKeys(runPosture, "CLASS_LABEL").sort(), [...classes].sort(), "CLASS_LABEL keys = posture.PQC_CLASSES");
const levels = pyTuple(evidence, "CONFIDENCE");
assert.deepEqual(levels, ["E0", "E1", "E2", "E3"]);
assert.deepEqual(tsKeys(shared, "CONFIDENCE_LABEL"), levels, "CONFIDENCE_LABEL keys = evidence.CONFIDENCE");
assert.match(api, /export type CbomConfidence = "E0" \| "E1" \| "E2" \| "E3"/);
for (const c of classes) assert.ok(api.includes(`"${c}"`), `CbomPqcClass lists ${c}`);

// 2. the confidence palette is not the risk palette (red, orange, amber, green, grey belong to Q0..Q4)
const style = shared.slice(shared.indexOf("const CONFIDENCE_STYLE"), shared.indexOf("export function ConfidenceBadge"));
assert.ok(style.length > 0);
assert.doesNotMatch(style, /\b(red|orange|amber|yellow|green|emerald|zinc|gray|grey|slate)-\d/, "confidence palette uses no risk colours");

// 3. no Q0..Q4 printed as a confidence level anywhere in the CBOM UI: "Q0" only as "Q0 gap(s)" (or the component name),
//    Q1..Q4 only next to their risk word
const files = [...walk(join(FRONTEND, "components", "cbom")), ...walk(join(FRONTEND, "app", "q")),
  join(FRONTEND, "utils", "backend_api.ts")];
const RISK_WORD: Record<string, string> = { Q1: "Critical", Q2: "High", Q3: "Medium", Q4: "Low" };
const bad: string[] = [];
for (const file of files) {
  read(file).split("\n").forEach((line, i) => {
    for (const m of line.matchAll(/\bQ([0-4])\b/g)) {
      const q = `Q${m[1]}`;
      const rest = line.slice(m.index ?? 0);
      if (q === "Q0" && /^Q0 gaps?\b/.test(rest)) continue;
      if (q === "Q0" && /^Q0GapBadge|^Q0Gap\b/.test(rest)) continue;
      if (q !== "Q0" && line.includes(RISK_WORD[q])) continue;
      bad.push(`${file.slice(FRONTEND.length + 1)}:${i + 1}: ${line.trim().slice(0, 120)}`);
    }
  });
}
assert.deepEqual(bad, [], `Q symbols printed as confidence levels:\n${bad.join("\n")}`);

// 4. negative control: the old vocabulary would fail check 3
assert.ok(/\bQ1\b/.test(`Set to Q1 when answered`) && !`Set to Q1 when answered`.includes("Critical"));

console.log("confidence vocabulary tests passed");
