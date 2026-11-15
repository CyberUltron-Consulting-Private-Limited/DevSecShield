/**
 * F2 (i) info tips are loaded per area (issue #145): a page ships the eager label index and loads only the text of the
 * areas whose tips it renders.
 *  1. Static import graph: no page, layout or other app entry reaches tip text through static imports; the text is
 *     reachable only through the literal `import()` calls in content/infotips/load.ts, one per area, so the bundler
 *     emits one chunk per area. The CBOM results pages (code scan and Sources run) are checked by content as well:
 *     their static closure holds no Fleet or SAST tip text, and it does hold <InfoTip>, so the check is not vacuous.
 *  2. Budgets: each area's text, compiled as the bundler sees it, is at most AREA_BUDGET_GZIP bytes gzip, and the eager
 *     part (label index, areas, loader) at most EAGER_BUDGET_GZIP bytes gzip.
 * The real chunk sizes from `next build --webpack` are recorded in the PR of #145; this test is the CI guard.
 * Run: npx --yes tsx content/infotipsBundle.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";

import ts from "typescript";

const frontend = path.join(__dirname, "..");
const rel = (p: string) => path.relative(frontend, p).split(path.sep).join("/");
const read = (p: string) => fs.readFileSync(p, "utf8");

/** At most this many bytes gzip per area chunk (issue #145: "no single tip chunk exceeds a budget"). */
const AREA_BUDGET_GZIP = 15 * 1024;
/** The eager part every page with an (i) tip loads: label index, area table and loader. */
const EAGER_BUDGET_GZIP = 12 * 1024;

const TIPS_DIR = path.join(frontend, "content", "infotips");
const TEXT_DIR = path.join(TIPS_DIR, "text");
/** Files that hold tip text: the per-area modules, the test-only full registry, and the old single registry. */
const isTextFile = (abs: string) =>
  abs.startsWith(TEXT_DIR + path.sep) || abs === path.join(TIPS_DIR, "all.ts") || abs === path.join(frontend, "content", "infotips.ts");

// ---------------------------------------------------------------- the static import graph
const EXTENSIONS = ["", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.tsx", "/index.js"];
function resolve(from: string, spec: string): string | null {
  let base: string;
  if (spec.startsWith("@/")) base = path.join(frontend, spec.slice(2));
  else if (spec.startsWith("./") || spec.startsWith("../")) base = path.join(path.dirname(from), spec);
  else return null; // a package
  for (const ext of EXTENSIONS) {
    const p = base + ext;
    if (fs.existsSync(p) && fs.statSync(p).isFile() && /\.[jt]sx?$/.test(p)) return p;
  }
  return null;
}

/** An import whose bindings are all types is erased by the compiler (tsc and SWC), so it is no edge. */
function typeOnly(decl: ts.ImportDeclaration): boolean {
  const clause = decl.importClause;
  if (!clause) return false; // a side-effect import
  if (clause.isTypeOnly) return true;
  if (clause.name) return false;
  const named = clause.namedBindings;
  if (!named || ts.isNamespaceImport(named)) return false;
  return named.elements.length > 0 && named.elements.every((e) => e.isTypeOnly);
}

interface Edges {
  statics: string[];
  dynamics: { spec: string; target: string | null }[];
}
const edgeCache = new Map<string, Edges>();
function edges(file: string): Edges {
  const hit = edgeCache.get(file);
  if (hit) return hit;
  const sf = ts.createSourceFile(file, read(file), ts.ScriptTarget.Latest, true, file.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const out: Edges = { statics: [], dynamics: [] };
  for (const st of sf.statements) {
    if (ts.isImportDeclaration(st) && ts.isStringLiteral(st.moduleSpecifier) && !typeOnly(st)) {
      const r = resolve(file, st.moduleSpecifier.text);
      if (r) out.statics.push(r);
    } else if (ts.isExportDeclaration(st) && st.moduleSpecifier && ts.isStringLiteral(st.moduleSpecifier) && !st.isTypeOnly) {
      const r = resolve(file, st.moduleSpecifier.text);
      if (r) out.statics.push(r);
    }
  }
  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n) && n.expression.kind === ts.SyntaxKind.ImportKeyword) {
      const arg = n.arguments[0];
      const spec = arg && ts.isStringLiteralLike(arg) ? arg.text : `<non-literal: ${arg?.getText(sf)}>`;
      out.dynamics.push({ spec, target: arg && ts.isStringLiteralLike(arg) ? resolve(file, arg.text) : null });
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  edgeCache.set(file, out);
  return out;
}

/** Every file a module pulls in through static imports (what lands in its bundle without an `import()`). */
function closure(entry: string): Set<string> {
  const seen = new Set<string>([entry]);
  const stack = [entry];
  while (stack.length) {
    for (const next of edges(stack.pop()!).statics) {
      if (!seen.has(next)) {
        seen.add(next);
        stack.push(next);
      }
    }
  }
  return seen;
}
/** How an entry reaches a file: the chain of static imports, for the failure message. */
function chain(entry: string, target: string): string[] {
  const prev = new Map<string, string>();
  const queue = [entry];
  const seen = new Set([entry]);
  while (queue.length) {
    const f = queue.shift()!;
    if (f === target) break;
    for (const n of edges(f).statics) {
      if (!seen.has(n)) {
        seen.add(n);
        prev.set(n, f);
        queue.push(n);
      }
    }
  }
  const out = [target];
  while (prev.has(out[0])) out.unshift(prev.get(out[0])!);
  return out.map(rel);
}

const ENTRY_NAME = /^(page|layout|template|loading|error|global-error|not-found|default)\.(tsx?|jsx?)$/;
function entries(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) return entries(p);
    return ENTRY_NAME.test(e.name) ? [p] : [];
  });
}
const appEntries = entries(path.join(frontend, "app"));
assert.ok(appEntries.length > 20, `expected the app's pages, found ${appEntries.length}`);

// 1a. no app entry reaches tip text statically
const leaks: string[] = [];
for (const entry of appEntries) {
  for (const f of closure(entry)) if (isTextFile(f)) leaks.push(`${rel(entry)} -> ${chain(entry, f).join(" -> ")}`);
}
assert.deepEqual(leaks, [], `tip text is bundled statically into ${leaks.length} page(s):\n${leaks.slice(0, 20).join("\n")}`);

// 1b. no source file outside content/infotips imports the text or the full registry statically (tests and the e2e
// harness may: they are not part of the app)
function sources(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) return ["node_modules", ".next", "e2e"].includes(e.name) ? [] : sources(p);
    return /\.tsx?$/.test(e.name) && !e.name.endsWith(".test.ts") ? [p] : [];
  });
}
const appSources = ["app", "components", "lib", "utils", "hooks", "content"]
  .map((d) => path.join(frontend, d))
  .filter((d) => fs.existsSync(d))
  .flatMap(sources);
const importsText = appSources.filter((f) => !f.startsWith(TIPS_DIR + path.sep) && edges(f).statics.some(isTextFile));
assert.deepEqual(importsText.map(rel), [], "these files import tip text statically; use <InfoTip> (it loads the area) instead");

// 1c. the text is reached only through load.ts, by one literal import() per area
const loadTs = path.join(TIPS_DIR, "load.ts");
const textImports = appSources.flatMap((f) => edges(f).dynamics.filter((d) => d.target && isTextFile(d.target)).map((d) => ({ f, ...d })));
assert.deepEqual([...new Set(textImports.map((d) => rel(d.f)))], ["content/infotips/load.ts"], "only content/infotips/load.ts may import() tip text");
const nonLiteral = edges(loadTs).dynamics.filter((d) => d.target === null);
assert.deepEqual(nonLiteral, [], "load.ts: every import() takes a literal path, so the bundler emits one chunk per area");
const textFiles = fs.readdirSync(TEXT_DIR).filter((n) => n.endsWith(".ts")).map((n) => path.join(TEXT_DIR, n)).sort();
assert.deepEqual(textImports.map((d) => d.target!).sort(), textFiles, "load.ts imports every area module exactly once");

// 1d. the CBOM results pages: no Fleet or SAST tip text in their static closure, and <InfoTip> is in it
const RESULTS_PAGES = ["app/[team_id]/cbom/[scan_id]/results/page.tsx", "app/[team_id]/cbom/runs/[run_id]/results/page.tsx"];
const infoTip = path.join(frontend, "components", "ui", "info-tip.tsx");

async function main() {
  const { INFO_TIPS } = await import("./infotips/all");
  const { TIP_AREAS, areaOf } = await import("./infotips/areas");
  const foreign = Object.entries(INFO_TIPS).filter(([id]) => /^(fleet|sast)\./.test(id));
  assert.ok(foreign.length > 50, "the registry has Fleet and SAST tips to look for");
  for (const page of RESULTS_PAGES) {
    const files = closure(path.join(frontend, page));
    assert.ok(files.has(infoTip), `${page}: renders <InfoTip> (its static closure has components/ui/info-tip.tsx)`);
    const bundle = [...files].map(read).join("\n");
    const found = foreign.filter(([, t]) => bundle.includes(t.what)).map(([id]) => id);
    assert.deepEqual(found, [], `${page}: its static bundle holds the text of ${found.length} Fleet/SAST tip(s)`);
  }

  // ---------------------------------------------------------------- 2. budgets
  const gzip = (s: string) => zlib.gzipSync(s, { level: 9 }).length;
  // as the bundler sees it: TypeScript compiled to JS without comments (a minifier only shortens the few keys)
  const compiled = (file: string) =>
    ts.transpileModule(read(file), { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2017, removeComments: true } }).outputText;
  assert.deepEqual(textFiles.map((f) => path.basename(f, ".ts")).sort(), [...TIP_AREAS].sort(), "one text module per area, named after it");
  const sizes: string[] = [];
  const over: string[] = [];
  for (const f of textFiles) {
    const js = compiled(f);
    const n = gzip(js);
    sizes.push(`${path.basename(f, ".ts")}: ${js.length} B, ${n} B gzip`);
    if (n > AREA_BUDGET_GZIP) over.push(`${rel(f)}: ${n} B gzip > ${AREA_BUDGET_GZIP}; split the area (content/infotips/areas.ts)`);
  }
  assert.deepEqual(over, [], over.join("\n"));
  const eager = [...closure(infoTip)].filter((f) => f.startsWith(TIPS_DIR + path.sep));
  assert.ok(eager.includes(path.join(TIPS_DIR, "labels.ts")), "<InfoTip> loads the label index eagerly (the button's name)");
  const eagerJs = eager.map(compiled).join("\n");
  const eagerGzip = gzip(eagerJs);
  assert.ok(eagerGzip <= EAGER_BUDGET_GZIP, `the eager tip index is ${eagerGzip} B gzip > ${EAGER_BUDGET_GZIP}`);
  // every id has an area (the loader needs it)
  const noArea = Object.keys(INFO_TIPS).filter((id) => !areaOf(id));
  assert.deepEqual(noArea, [], "ids with no area: add their prefix to AREA_PREFIXES in content/infotips/areas.ts");

  const total = gzip(textFiles.map(compiled).join("\n"));
  console.log(sizes.join("\n"));
  console.log(`eager index (${eager.map(rel).join(", ")}): ${eagerJs.length} B, ${eagerGzip} B gzip; all text in one: ${total} B gzip`);
  console.log(`info tips bundle: ${appEntries.length} app entries, ${textFiles.length} area chunks <= ${AREA_BUDGET_GZIP} B gzip, tests passed`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
