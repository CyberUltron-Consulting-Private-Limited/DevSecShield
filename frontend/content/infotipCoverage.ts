/**
 * Static checks behind content/infotips.test.ts: which user-facing items of a page source lack an (i) tip of their own.
 * The source is parsed with the TypeScript compiler (TSX), so the checks follow the real JSX tree, not line distance.
 *
 * Rules, applied to every covered file:
 *  - "label":   `<Label>` (components/ui/label) is not used directly; `<FieldLabel infoId=…>` is (its infoId is
 *               required, so tsc rejects a label without a tip).
 *  - "control": every control (CONTROL_TAGS; not hidden inputs, not icon-only row menus) has a tip of its OWN, found in
 *               this order, and each tip serves one control only:
 *                 1. an `infoId` on the control itself (PathArraysInput, NodeSelect, …);
 *                 2. a `<FieldLabel infoId=… htmlFor=X>` where X is the control's `id` (same expression text);
 *                 3. an `{/* infotip-shared: <reason> *\/}` comment right before it in the same container (an explicit,
 *                    reviewed statement that the control shares the tip of the item before it);
 *                 4. the nearest unused tip in the same container: the control's parent, or up to MAX_CLIMB levels
 *                    above it, before the control (after the previous control) or else after it (before the next),
 *                    at most CONTROL_WINDOW_LINES lines away.
 *               A tip inside a heading, column header, description or paragraph (TEXT_TIP_PARENTS) explains that text
 *               and never serves a control; a FieldLabel whose htmlFor names another id never serves this one.
 *  - "heading": every `<CardTitle>`, every `<TableHead>` with visible text (except SELF_EXPLANATORY_HEADERS), and every
 *               `<p>` whose className has `font-medium` and whose content is literal text (KPI and metric labels)
 *               contains an `<InfoTip>`, or an `infotip-shared: <reason>` comment when the field right below it carries
 *               the tip.
 *  - "h2":      in dashboard files, every `<h2>`/`<h3>` with visible text contains an `<InfoTip>`.
 */
import ts from "typescript";

export interface Gap {
  rule: "label" | "control" | "heading" | "h2";
  line: number;
  snippet: string;
}

/** How a control was matched with its tip (for tests and for debugging a gap). */
export interface Pairing {
  tag: string;
  line: number;
  by: "own" | "htmlFor" | "shared" | "container" | null;
  tipLine?: number;
}

export const CONTROL_WINDOW_LINES = 25;
export const MAX_CLIMB = 3;

/** Table headers whose meaning is the word itself; everything else gets a tip. */
export const SELF_EXPLANATORY_HEADERS = new Set(["Actions", "Title", "Name", "#"]);

export const CONTROL_TAGS = new Set([
  "Input", "Textarea", "SelectTrigger", "Switch", "Checkbox", "input", "select", "textarea",
  "PathArraysInput", "NodeSelect", "DropdownMenuTrigger",
]);

/** Elements whose (i) explains their own text; a tip directly inside one never serves a control. */
export const TEXT_TIP_PARENTS = new Set([
  "CardTitle", "CardDescription", "TableHead", "DialogTitle", "DialogDescription",
  "h1", "h2", "h3", "h4", "h5", "h6", "p",
]);

interface El {
  tag: string;
  node: ts.JsxElement | ts.JsxSelfClosingElement | ts.JsxFragment;
  start: number; // element start (after trivia)
  end: number;
  openEnd: number; // end of the opening tag
  attrs: ts.JsxAttributes | null; // null for a fragment
  parent: El | null;
  line: number;
}

interface Tip {
  at: number;
  line: number;
  kind: "infotip" | "infoId" | "shared";
  parent: El | null; // nearest JSX element around it
  host: El | null; // the element that carries it (InfoTip / element with infoId); null for a comment
  htmlFor: string | null;
  used: boolean;
}

function tagName(n: ts.JsxTagNameExpression): string {
  return n.getText();
}

/** The attribute's expression text, normalised: `"a"`, `{"a"}` and `{'a'}` give `"a"`; `{x.id}` gives `x.id`. */
function attr(attrs: ts.JsxAttributes | null, name: string): string | null {
  for (const p of attrs?.properties ?? []) {
    if (!ts.isJsxAttribute(p) || p.name.getText() !== name) continue;
    const init = p.initializer;
    if (!init) return "true";
    if (ts.isStringLiteral(init)) return JSON.stringify(init.text);
    if (ts.isJsxExpression(init) && init.expression) {
      const e = init.expression;
      if (ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e)) return JSON.stringify(e.text);
      return e.getText().replace(/\s+/g, "");
    }
    return init.getText();
  }
  return null;
}

function hasAttr(attrs: ts.JsxAttributes | null, name: string): boolean {
  return (attrs?.properties ?? []).some((p) => ts.isJsxAttribute(p) && p.name.getText() === name);
}

function parse(source: string): ts.SourceFile {
  return ts.createSourceFile("x.tsx", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
}

/** Walks the file once and returns its JSX elements (each with its nearest JSX element ancestor) and shared comments. */
function collect(sf: ts.SourceFile) {
  const els: El[] = [];
  const shared: { at: number; parent: El | null }[] = [];
  const visit = (node: ts.Node, parent: El | null) => {
    let next = parent;
    if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) {
      const opening = ts.isJsxElement(node) ? node.openingElement : node;
      const el: El = {
        tag: tagName(opening.tagName),
        node,
        start: node.getStart(sf),
        end: node.getEnd(),
        openEnd: opening.getEnd(),
        attrs: opening.attributes,
        parent,
        line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1,
      };
      els.push(el);
      next = el;
    } else if (ts.isJsxFragment(node)) {
      // <>…</> is a container too
      const el: El = {
        tag: "<>",
        node,
        start: node.getStart(sf),
        end: node.getEnd(),
        openEnd: node.openingFragment.getEnd(),
        attrs: null,
        parent,
        line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1,
      };
      els.push(el);
      next = el;
    } else if (ts.isJsxExpression(node) && !node.expression && /infotip-shared:\s*\S/.test(node.getText(sf))) {
      shared.push({ at: node.getStart(sf), parent });
    }
    ts.forEachChild(node, (c) => visit(c, next));
  };
  visit(sf, null);
  return { els, shared };
}

const contains = (outer: El, at: number) => at >= outer.start && at < outer.end;

/** Literal JSX text inside an element (expressions and tags left out), whitespace collapsed. */
function visible(node: ts.Node): string {
  let out = "";
  const walk = (n: ts.Node) => {
    if (ts.isJsxText(n)) out += " " + n.getText();
    else if (ts.isJsxExpression(n)) return;
    else ts.forEachChild(n, walk);
  };
  if (ts.isJsxElement(node)) node.children.forEach(walk);
  return out.replace(/\s+/g, " ").trim();
}

function isControl(el: El): boolean {
  if (!CONTROL_TAGS.has(el.tag)) return false;
  if (attr(el.attrs, "type") === '"hidden"') return false;
  // a row's icon-only action menu ("…") is not a filter or a field
  if (el.tag === "DropdownMenuTrigger" && /size=["']icon["']/.test(el.node.getText())) return false;
  return true;
}

function analyse(source: string) {
  const sf = parse(source);
  const { els, shared } = collect(sf);
  const lineAt = (pos: number) => sf.getLineAndCharacterOfPosition(pos).line + 1;
  const snippet = (pos: number) => source.slice(pos, pos + 80).replace(/\s+/g, " ");

  const controls = els.filter(isControl);
  const tips: Tip[] = [];
  for (const el of els) {
    if (el.tag === "InfoTip") tips.push({ at: el.start, line: el.line, kind: "infotip", parent: el.parent, host: el, htmlFor: null, used: false });
    else if (hasAttr(el.attrs, "infoId")) {
      tips.push({ at: el.start, line: el.line, kind: "infoId", parent: el.parent, host: el, htmlFor: attr(el.attrs, "htmlFor"), used: false });
    }
  }
  for (const s of shared) tips.push({ at: s.at, line: lineAt(s.at), kind: "shared", parent: s.parent, host: null, htmlFor: null, used: false });
  tips.sort((a, b) => a.at - b.at);

  // A tip whose nearest element is a heading, description or paragraph explains that text (a "shared" comment there
  // says the field below carries the tip); neither serves a control.
  const servesControls = (t: Tip) => !(t.parent && TEXT_TIP_PARENTS.has(t.parent.tag));
  const pairing = new Map<El, { by: Pairing["by"]; tip?: Tip }>();
  const take = (c: El, t: Tip, by: Pairing["by"]) => {
    t.used = true;
    pairing.set(c, { by, tip: t });
  };

  // 1. the control's own infoId
  for (const c of controls) {
    const own = tips.find((t) => !t.used && t.host === c);
    if (own) take(c, own, "own");
  }
  // 2. FieldLabel htmlFor = the control's id (nearest such label first)
  for (const c of controls) {
    if (pairing.has(c)) continue;
    const id = attr(c.attrs, "id");
    if (!id) continue;
    const label = tips
      .filter((t) => !t.used && t.htmlFor === id)
      .sort((a, b) => Math.abs(a.at - c.start) - Math.abs(b.at - c.start))[0];
    if (label) take(c, label, "htmlFor");
  }
  // 3. an infotip-shared comment right before the control, in its own container (after the previous control)
  const order = controls.slice().sort((a, b) => a.start - b.start);
  order.forEach((c, i) => {
    if (pairing.has(c) || !c.parent) return;
    const prevEnd = i > 0 ? order[i - 1].openEnd : -1;
    const s = tips.filter((t) => !t.used && t.kind === "shared" && t.parent === c.parent && t.at > prevEnd && t.at < c.start).pop();
    if (s) take(c, s, "shared");
  });
  // 4. a tip in the same container (the parent or up to MAX_CLIMB levels up) with no other control between the two,
  // in document order. Tips sit before their control in forms and after it in filter bars, so a tip between two
  // controls may belong to either: the controls and tips are paired by a maximum matching, which leaves exactly
  // (controls - tips available to them) controls without a tip whatever the layout.
  const between = (a: number, b: number) => order.some((o) => o.start > Math.min(a, b) && o.start < Math.max(a, b));
  const edges = new Map<El, Tip[]>();
  for (const c of order) {
    if (pairing.has(c)) continue;
    const boxes: El[] = [];
    for (let box = c.parent, level = 0; box && level < MAX_CLIMB; box = box.parent, level++) boxes.push(box);
    const outer = boxes[boxes.length - 1];
    const cand = tips.filter(
      (t) =>
        !t.used &&
        t.kind !== "shared" &&
        t.htmlFor === null &&
        servesControls(t) &&
        !!outer &&
        contains(outer, t.at) &&
        !contains(c, t.at) &&
        Math.abs(t.line - c.line) <= CONTROL_WINDOW_LINES &&
        !between(t.at, c.start) &&
        // a tip inside another control's element (e.g. inside a menu trigger) is not this control's
        !order.some((o) => o !== c && o.start < t.at && t.at < o.end),
    );
    cand.sort((a, b) => Math.abs(a.at - c.start) - Math.abs(b.at - c.start));
    edges.set(c, cand);
  }
  const owner = new Map<Tip, El>();
  const augment = (c: El, seen: Set<Tip>): boolean => {
    for (const t of edges.get(c) ?? []) {
      if (seen.has(t)) continue;
      seen.add(t);
      const o = owner.get(t);
      if (!o || augment(o, seen)) {
        owner.set(t, c);
        return true;
      }
    }
    return false;
  };
  for (const c of edges.keys()) augment(c, new Set());
  for (const [t, c] of owner) take(c, t, "container");

  const gaps: Gap[] = [];
  for (const el of els) if (el.tag === "Label") gaps.push({ rule: "label", line: el.line, snippet: snippet(el.start) });
  for (const c of order) if (!pairing.has(c)) gaps.push({ rule: "control", line: c.line, snippet: snippet(c.start) });

  const hasTip = (el: El) =>
    els.some((x) => x.tag === "InfoTip" && x !== el && contains(el, x.start)) || shared.some((s) => contains(el, s.at));
  const need = (tag: string, rule: Gap["rule"], keep: (el: El) => boolean) => {
    for (const el of els) if (el.tag === tag && keep(el) && !hasTip(el)) gaps.push({ rule, line: el.line, snippet: snippet(el.start) });
  };
  return { sf, els, order, pairing, gaps, need, lineAt };
}

export function findGaps(source: string, opts: { dashboard?: boolean } = {}): Gap[] {
  const { gaps, need } = analyse(source);
  need("CardTitle", "heading", () => true);
  need("TableHead", "heading", (el) => {
    const text = visible(el.node);
    return text !== "" && !SELF_EXPLANATORY_HEADERS.has(text);
  });
  need("p", "heading", (el) => {
    // a label is literal text only; "{pct}% of total" is a value, not a label
    const cls = attr(el.attrs, "className");
    if (!cls || !cls.startsWith('"') || !/\bfont-medium\b/.test(cls)) return false;
    if (!ts.isJsxElement(el.node)) return false;
    const valueInside = el.node.children.some((ch) => ts.isJsxExpression(ch) && ch.expression);
    return !valueInside && visible(el.node) !== "";
  });
  if (opts.dashboard) {
    for (const h of ["h2", "h3"]) need(h, "h2", (el) => visible(el.node) !== "");
  }
  return gaps.sort((a, b) => a.line - b.line);
}

/** Every control of the source and how it was matched with a tip (null: no tip of its own). */
export function explain(source: string): Pairing[] {
  const { order, pairing } = analyse(source);
  return order.map((c) => {
    const p = pairing.get(c);
    return { tag: c.tag, line: c.line, by: p?.by ?? null, tipLine: p?.tip?.line };
  });
}
