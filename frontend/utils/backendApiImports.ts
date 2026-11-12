/**
 * Test support (the app does not import it): which helpers a source file takes from utils/backend_api. One detector for
 * the source guards in utils/creditBalance.test.ts (every helper that moves credits refreshes the balance) and
 * utils/teamSettingsToasts.test.ts (every user of the team helpers shows the error once). The two kept their own copies
 * of a regex, which missed `const { a } = await import(...)` and `import(...).then((m) => m.a(...))` (PR #67 review).
 * It reads the TypeScript syntax tree, so comments, strings and types never count, and finds:
 * - `import { a, b as c } from` by the exported name (`type` names and `import type` are not uses);
 * - `import * as api from`, a default import and `import api = require(...)`: the members read from it (`api.a`);
 * - `const { a, b: c } = await import(...)`, `const m = await import(...)` (`m.a`), `(await import(...)).a`,
 *   `import(...).then((m) => m.a())`, `import(...).then(({ a }) => a())`, and `require(...)` the same ways.
 * Anything else that takes the module as a value (an alias passed on, a re-export, `import(...)` kept as a promise)
 * throws: a guard then fails instead of missing a helper. `import("...").Type` in a type is not a use.
 */
import ts from "typescript";

/** utils/backend_api as the app imports it: "@/utils/backend_api", "../utils/backend_api", "./backend_api". */
const API_MODULE = /^(?:@\/utils\/|(?:\.\.?\/)+(?:utils\/)?)backend_api$/;

function parse(src: string, fileName: string): ts.SourceFile {
  return ts.createSourceFile(fileName, src, ts.ScriptTarget.Latest, true);
}

function isApiModule(node: ts.Node | undefined): boolean {
  return !!node && ts.isStringLiteralLike(node) && API_MODULE.test(node.text);
}

/** Where the static `import ... from` statements of utils/backend_api are (their names are not uses). */
export function backendApiImportRanges(src: string, fileName = "snippet.ts"): [number, number][] {
  const sf = parse(src, fileName);
  return sf.statements
    .filter((s): s is ts.ImportDeclaration => ts.isImportDeclaration(s) && isApiModule(s.moduleSpecifier))
    .map((s) => [s.getStart(sf), s.getEnd()]);
}

/** The names a source file takes from utils/backend_api (see the header); throws on a use it cannot follow. */
export function backendApiImports(src: string, fileName = "snippet.ts"): string[] {
  const sf = parse(src, fileName);
  const names = new Set<string>();
  const fail = (node: ts.Node, what: string): never => {
    const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
    throw new Error(`${fileName}:${line}: ${what} of utils/backend_api that the source guards cannot follow: ` +
      "import the helpers by name, or destructure them from await import(...)");
  };
  const textOf = (name: ts.PropertyName): string | null =>
    ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name) ? name.text : null;

  /** Every member read from `alias` in `scope` (a nested function with a parameter of that name shadows it). */
  const aliasMembers = (declared: ts.Identifier, scope: ts.Node) => {
    const visit = (node: ts.Node): void => {
      if (node !== scope && ts.isFunctionLike(node) &&
        node.parameters.some((p) => ts.isIdentifier(p.name) && p.name.text === declared.text)) return;
      if (ts.isIdentifier(node) && node !== declared && node.text === declared.text) {
        const parent = node.parent;
        if (ts.isPropertyAccessExpression(parent) && parent.expression === node) names.add(parent.name.text);
        else if (ts.isElementAccessExpression(parent) && parent.expression === node &&
          ts.isStringLiteralLike(parent.argumentExpression)) names.add(parent.argumentExpression.text);
        else if (!isNameOnly(node)) fail(node, `"${node.text}" passes on the module`);
      }
      ts.forEachChild(node, visit);
    };
    visit(scope);
  };

  /** What a module value is bound to: a name (an alias) or a destructuring pattern. */
  const bind = (target: ts.BindingName, scope: ts.Node) => {
    if (ts.isIdentifier(target)) return aliasMembers(target, scope);
    if (!ts.isObjectBindingPattern(target)) return fail(target, "an array pattern");
    for (const element of target.elements) {
      if (element.dotDotDotToken) {
        bind(element.name, scope); // `...rest`: an alias of the rest
        continue;
      }
      const name = element.propertyName ? textOf(element.propertyName) : ts.isIdentifier(element.name) ? element.name.text : null;
      if (name === null) fail(element, "a computed name");
      else names.add(name);
    }
  };

  /** The module as a value (`await import(...)` or `require(...)`, maybe in parentheses), by where it is used. */
  const followModule = (value: ts.Expression) => {
    let node: ts.Node = value;
    while (ts.isParenthesizedExpression(node.parent)) node = node.parent;
    const parent = node.parent;
    if (ts.isVariableDeclaration(parent) && parent.initializer === node) return bind(parent.name, scopeOf(parent));
    if (ts.isPropertyAccessExpression(parent) && parent.expression === node) return void names.add(parent.name.text);
    if (ts.isElementAccessExpression(parent) && parent.expression === node && ts.isStringLiteralLike(parent.argumentExpression)) {
      return void names.add(parent.argumentExpression.text);
    }
    fail(value, "a use");
  };

  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && isApiModule(node.moduleSpecifier)) {
      const clause = node.importClause;
      if (clause && clause.phaseModifier !== ts.SyntaxKind.TypeKeyword) {
        if (clause.name) aliasMembers(clause.name, sf);
        const bindings = clause.namedBindings;
        if (bindings && ts.isNamespaceImport(bindings)) aliasMembers(bindings.name, sf);
        if (bindings && ts.isNamedImports(bindings)) {
          for (const el of bindings.elements) if (!el.isTypeOnly) names.add((el.propertyName ?? el.name).text);
        }
      }
      return;
    }
    if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference) &&
      isApiModule(node.moduleReference.expression)) {
      if (!node.isTypeOnly) aliasMembers(node.name, sf);
      return;
    }
    if (ts.isExportDeclaration(node) && isApiModule(node.moduleSpecifier)) fail(node, "a re-export");
    if (ts.isCallExpression(node) && isApiModule(node.arguments[0])) {
      const isImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
      if (isImport || (ts.isIdentifier(node.expression) && node.expression.text === "require")) {
        let at: ts.Node = node;
        while (ts.isParenthesizedExpression(at.parent)) at = at.parent;
        const parent = at.parent;
        if (!isImport) followModule(node);
        else if (ts.isAwaitExpression(parent)) followModule(parent);
        else if (ts.isPropertyAccessExpression(parent) && parent.name.text === "then" && ts.isCallExpression(parent.parent) &&
          parent.parent.expression === parent) {
          const callback = parent.parent.arguments[0];
          if (!callback || !(ts.isArrowFunction(callback) || ts.isFunctionExpression(callback))) fail(parent, "a .then");
          else if (callback.parameters.length) bind(callback.parameters[0].name, callback);
        } else fail(node, "an import() kept as a promise");
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return [...names];
}

/** Where a declared name is visible: its block (let, const) or function (var). */
function scopeOf(declaration: ts.VariableDeclaration): ts.Node {
  const isVar = ts.isVariableDeclarationList(declaration.parent) &&
    (declaration.parent.flags & (ts.NodeFlags.Let | ts.NodeFlags.Const)) === 0;
  let node: ts.Node = declaration.parent;
  while (!ts.isSourceFile(node)) {
    if (ts.isFunctionLike(node) || (!isVar && (ts.isBlock(node) || ts.isModuleBlock(node) || ts.isCaseBlock(node) ||
      ts.isForStatement(node) || ts.isForOfStatement(node) || ts.isForInStatement(node)))) return node;
    node = node.parent;
  }
  return node;
}

/** An identifier that is not a value use of a variable: a property or member name, a JSX attribute, a declaration, a type. */
function isNameOnly(node: ts.Identifier): boolean {
  const parent = node.parent;
  return (ts.isPropertyAccessExpression(parent) && parent.name === node) ||
    ts.isQualifiedName(parent) || ts.isTypeQueryNode(parent) || ts.isTypeReferenceNode(parent) || // types are not values
    ((ts.isPropertyAssignment(parent) || ts.isPropertyDeclaration(parent) || ts.isPropertySignature(parent) ||
      ts.isMethodDeclaration(parent) || ts.isMethodSignature(parent) || ts.isGetAccessor(parent) ||
      ts.isSetAccessor(parent) || ts.isEnumMember(parent) || ts.isJsxAttribute(parent)) && parent.name === node) ||
    (ts.isBindingElement(parent) && parent.propertyName === node) ||
    ((ts.isImportSpecifier(parent) || ts.isExportSpecifier(parent)) && parent.propertyName === node) ||
    (ts.isVariableDeclaration(parent) && parent.name === node) ||
    (ts.isBindingElement(parent) && parent.name === node) ||
    (ts.isParameter(parent) && parent.name === node);
}
