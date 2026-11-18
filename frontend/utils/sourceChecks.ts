/**
 * Test support for the source checks of utils/creditRefresh.test.ts and utils/toastOwnership.test.ts: a page or
 * component is parsed with the TypeScript compiler (as content/infotipCoverage.ts does), so a check reads the real
 * `useMutation` option, `finally` block or `if` branch, not a line range. Not imported by the app.
 */
import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

function parse(source: string): ts.SourceFile {
  return ts.createSourceFile("source.tsx", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
}

function nodes(sf: ts.SourceFile): ts.Node[] {
  const out: ts.Node[] = [];
  const visit = (node: ts.Node) => {
    out.push(node);
    node.forEachChild(visit);
  };
  visit(sf);
  return out;
}

/** The options of `const <name> = useMutation({ ... })`: option name -> its source text. Null when there is none. */
export function mutationOptions(source: string, name: string): Map<string, string> | null {
  const sf = parse(source);
  for (const node of nodes(sf)) {
    if (!ts.isVariableDeclaration(node) || node.name.getText(sf) !== name || !node.initializer) continue;
    const call = node.initializer;
    if (!ts.isCallExpression(call) || call.expression.getText(sf) !== "useMutation") continue;
    const options = call.arguments[0];
    if (!options || !ts.isObjectLiteralExpression(options)) continue;
    const out = new Map<string, string>();
    for (const p of options.properties) if (p.name) out.set(p.name.getText(sf), p.getText(sf));
    return out;
  }
  return null;
}

/** The `finally` block of every `try` whose `try` block contains `needle` ("" for a `try` without one). */
export function finallyBlocks(source: string, needle: string): string[] {
  const sf = parse(source);
  return nodes(sf)
    .filter((n): n is ts.TryStatement => ts.isTryStatement(n) && n.tryBlock.getText(sf).includes(needle))
    .map((n) => n.finallyBlock?.getText(sf) ?? "");
}

/** The branch taken by every `if` whose condition (whitespace removed) satisfies `test`. */
export function ifBranches(source: string, test: (condition: string) => boolean): string[] {
  const sf = parse(source);
  return nodes(sf)
    .filter((n): n is ts.IfStatement => ts.isIfStatement(n) && test(n.expression.getText(sf).replace(/\s+/g, "")))
    .map((n) => n.thenStatement.getText(sf));
}

const identifierIndex = new Map<string, Map<string, Set<string>>>();

/** The app files (app/, components/, hooks/, lib/, utils/; tests and utils/backend_api.ts left out) whose code uses
 * the identifier `name` (comments and strings do not count), relative to the frontend root, sorted. */
export function usersOf(frontendRoot: string, name: string): string[] {
  let index = identifierIndex.get(frontendRoot);
  if (!index) {
    index = new Map();
    const walk = (dir: string): string[] => (fs.existsSync(dir) ? fs.readdirSync(dir, { withFileTypes: true }) : [])
      .flatMap((e) => e.isDirectory() ? walk(path.join(dir, e.name))
        : /\.(tsx?|jsx?|mjs)$/.test(e.name) && !/\.test\.[a-z]+$/.test(e.name) ? [path.join(dir, e.name)] : []);
    for (const file of ["app", "components", "hooks", "lib", "utils"].flatMap((d) => walk(path.join(frontendRoot, d)))) {
      const rel = path.relative(frontendRoot, file).split(path.sep).join("/");
      if (rel === "utils/backend_api.ts") continue;
      const sf = parse(fs.readFileSync(file, "utf8"));
      index.set(rel, new Set(nodes(sf).filter(ts.isIdentifier).map((n) => n.text)));
    }
    identifierIndex.set(frontendRoot, index);
  }
  return [...index].filter(([, names]) => names.has(name)).map(([rel]) => rel).sort();
}
