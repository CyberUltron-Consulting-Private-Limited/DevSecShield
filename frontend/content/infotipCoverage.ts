/**
 * Static checks behind content/infotips.test.ts: which user-facing items of a page source lack an (i) tip.
 * Pure string processing (no React, no DOM), so a test can run it on fixtures as well as on the real pages.
 *
 * Rules, applied to every covered file:
 *  - "label":   `<Label` (components/ui/label) is not used directly; `<FieldLabel infoId=…>` is (its infoId is
 *               required, so tsc rejects a label without a tip).
 *  - "control": every control (Input, Textarea, SelectTrigger, Switch, Checkbox, native input/select/textarea,
 *               PathArraysInput, NodeSelect, and DropdownMenuTrigger except icon-only row menus) is matched with an
 *               info marker of its own (`infoId=`, `infoId:` or `<InfoTip`, or an `infotip-shared: <reason>` comment
 *               when it shares the tip of the control before it or of the heading above it): one in its opening tag,
 *               else the `<FieldLabel htmlFor=…>` whose htmlFor is the control's id, else between the previous control
 *               and it, else between it and the next control, at most CONTROL_WINDOW_LINES lines away. A marker serves
 *               one control only, and a tip inside a heading, column header, card description or KPI label (see
 *               HEADING_ELEMENTS) explains that text and never serves a control.
 *  - "heading": every `<CardTitle>`, every `<TableHead>` with visible text (except SELF_EXPLANATORY_HEADERS), and
 *               every `<p>` styled `font-medium` with visible literal text (KPI and metric labels) contains `<InfoTip`,
 *               or an `infotip-shared: <reason>` comment when the field right below it carries the tip.
 *  - "h2":      in dashboard files, every `<h2>`/`<h3>` with visible text contains `<InfoTip`.
 */

export interface Gap {
  rule: "label" | "control" | "heading" | "h2";
  line: number;
  snippet: string;
}

export const CONTROL_WINDOW_LINES = 25;

/** Table headers whose meaning is the word itself; everything else gets a tip. */
export const SELF_EXPLANATORY_HEADERS = new Set(["Actions", "Title", "Name", "#"]);

/** Elements whose (i) explains their own text; a tip inside one never counts as the tip of a nearby control. */
export const HEADING_ELEMENTS = ["CardTitle", "CardDescription", "TableHead", "DialogTitle", "DialogDescription", "h1", "h2", "h3", "h4", "h5", "h6"];

const CONTROL = /<(Input|Textarea|SelectTrigger|Switch|Checkbox|input|select|textarea|PathArraysInput|NodeSelect|DropdownMenuTrigger)\b/g;
const MARKER = /infoId\s*[=:]|<InfoTip\b|__INFOTIP_SHARED__/g;

/** Comments blanked (newlines kept, so line numbers hold); an `infotip-shared:` comment becomes a marker token. */
export function stripComments(src: string): string {
  const blank = (s: string) => s.replace(/[^\n]/g, " ");
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (c) => (/infotip-shared:\s*\S/.test(c) ? "__INFOTIP_SHARED__" + blank(c).slice(18) : blank(c)))
    .replace(/(^|[^:"'`\\])\/\/[^\n]*/g, (m, pre: string) => pre + blank(m.slice(pre.length)));
}

function lineOf(src: string, index: number): number {
  let n = 1;
  for (let i = 0; i < index && i < src.length; i++) if (src.charCodeAt(i) === 10) n++;
  return n;
}

/** The JSX element starting at `start` up to its closing tag (same name, nesting counted) or the end of a self-closing tag. */
export function elementAt(src: string, start: number, name: string): string {
  // end of the opening tag: the first ">" outside {...}
  let depth = 0;
  let i = start;
  for (; i < src.length; i++) {
    const ch = src[i];
    if (ch === "{") depth++;
    else if (ch === "}") depth--;
    else if (ch === ">" && depth === 0) break;
  }
  if (src[i - 1] === "/") return src.slice(start, i + 1);
  const open = new RegExp(`<${name}\\b`, "g");
  const close = `</${name}>`;
  let level = 1;
  let pos = i + 1;
  while (level > 0) {
    const c = src.indexOf(close, pos);
    if (c < 0) return src.slice(start);
    open.lastIndex = pos;
    let m: RegExpExecArray | null;
    while ((m = open.exec(src)) && m.index < c) level++;
    level--;
    pos = c + close.length;
  }
  return src.slice(start, pos);
}

/** Visible literal text of a JSX fragment: {expressions} and <tags> removed. */
export function visibleText(jsx: string): string {
  let out = "";
  let depth = 0;
  for (const ch of jsx) {
    if (ch === "{") depth++;
    else if (ch === "}") depth = Math.max(0, depth - 1);
    else if (depth === 0) out += ch;
  }
  return out.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
}

/** The raw value of a JSX attribute in an opening tag ("x", {expr} with nested braces), or null. */
export function attrValue(opening: string, name: string): string | null {
  const m = new RegExp(`\\s${name}=`).exec(opening);
  if (!m) return null;
  let i = m.index + m[0].length;
  const q = opening[i];
  if (q === '"' || q === "'") {
    const end = opening.indexOf(q, i + 1);
    return end < 0 ? null : opening.slice(i, end + 1);
  }
  if (q !== "{") return null;
  let depth = 0;
  for (let j = i; j < opening.length; j++) {
    if (opening[j] === "{") depth++;
    else if (opening[j] === "}" && --depth === 0) return opening.slice(i, j + 1).replace(/\s+/g, "");
  }
  return null;
}

function openingOf(el: string): string {
  let depth = 0;
  for (let i = 0; i < el.length; i++) {
    const ch = el[i];
    if (ch === "{") depth++;
    else if (ch === "}") depth--;
    else if (ch === ">" && depth === 0) return el.slice(0, i + 1);
  }
  return el;
}

/** Spans [start, end) of the elements whose tip explains their own text: HEADING_ELEMENTS and KPI labels. */
function headingSpans(src: string): [number, number][] {
  const spans: [number, number][] = [];
  for (const name of [...HEADING_ELEMENTS, "p"]) {
    for (const m of src.matchAll(new RegExp(`<${name}\\b`, "g"))) {
      const el = elementAt(src, m.index!, name);
      if (name === "p" && !/className=["'][^"']*\bfont-medium\b/.test(openingOf(el))) continue;
      spans.push([m.index!, m.index! + el.length]);
    }
  }
  return spans;
}

function innerOf(el: string): string {
  // the element without its opening tag
  let depth = 0;
  for (let i = 0; i < el.length; i++) {
    const ch = el[i];
    if (ch === "{") depth++;
    else if (ch === "}") depth--;
    else if (ch === ">" && depth === 0) return el.slice(i + 1);
  }
  return "";
}

export function findGaps(source: string, opts: { dashboard?: boolean } = {}): Gap[] {
  const src = stripComments(source);
  const gaps: Gap[] = [];
  const snippet = (i: number) => src.slice(i, i + 80).replace(/\s+/g, " ");

  for (const m of src.matchAll(/<Label\b/g)) gaps.push({ rule: "label", line: lineOf(src, m.index!), snippet: snippet(m.index!) });

  // Each control is matched with ONE info marker of its own: one inside its opening tag (infoId=…), else the nearest
  // unused marker after the previous control and before it, else the first unused one after it and before the next
  // control; always within CONTROL_WINDOW_LINES lines. So two controls can never share one tip by accident.
  // A tip inside a heading, column header or KPI label belongs to that text, so it is not offered to controls.
  const spans = headingSpans(src);
  const inHeading = (at: number) => spans.some(([s, e]) => at >= s && at < e);
  const markers = [...src.matchAll(MARKER)]
    .filter((m) => !inHeading(m.index!))
    .map((m) => ({ at: m.index!, line: lineOf(src, m.index!), used: false, htmlFor: null as string | null }));
  // a FieldLabel's tip goes first to the control its htmlFor names
  for (const m of src.matchAll(/<FieldLabel\b/g)) {
    const opening = openingOf(elementAt(src, m.index!, "FieldLabel"));
    const k = markers.find((x) => x.at > m.index! && x.at < m.index! + opening.length);
    if (k) k.htmlFor = attrValue(opening, "htmlFor");
  }
  const controls: { at: number; end: number; line: number; id: string | null }[] = [];
  for (const m of src.matchAll(CONTROL)) {
    const at = m.index!;
    const el = elementAt(src, at, m[1]);
    const opening = openingOf(el);
    if (/type=["'](hidden)["']/.test(opening)) continue;
    // a row's icon-only action menu ("…") is not a filter or a field
    if (m[1] === "DropdownMenuTrigger" && /size=["']icon["']/.test(el)) continue;
    controls.push({ at, end: at + opening.length, line: lineOf(src, at), id: attrValue(opening, "id") });
  }
  const done = new Set<number>();
  controls.forEach((c, i) => {
    const own = markers.find((k) => !k.used && k.at > c.at && k.at < c.end);
    const label = c.id ? markers.find((k) => !k.used && k.htmlFor === c.id) : undefined;
    const pick = own ?? label;
    if (pick) {
      pick.used = true;
      done.add(i);
    }
  });
  controls.forEach((c, i) => {
    if (done.has(i)) return;
    const prevEnd = i > 0 ? controls[i - 1].end : 0;
    const nextAt = i + 1 < controls.length ? controls[i + 1].at : src.length;
    // a FieldLabel that names another control by htmlFor is that control's, not a neighbour's
    const near = (k: { line: number; used: boolean; htmlFor: string | null }) =>
      !k.used && Math.abs(k.line - c.line) <= CONTROL_WINDOW_LINES && (k.htmlFor === null || k.htmlFor === c.id);
    const before = markers.filter((k) => near(k) && k.at >= prevEnd && k.at < c.at).pop();
    const after = markers.find((k) => near(k) && k.at >= c.end && k.at < nextAt);
    const pick = before ?? after;
    if (pick) pick.used = true;
    else gaps.push({ rule: "control", line: c.line, snippet: snippet(c.at) });
  });

  const needTip = (name: string, rule: Gap["rule"], keep: (el: string) => boolean) => {
    for (const m of src.matchAll(new RegExp(`<${name}\\b`, "g"))) {
      const el = elementAt(src, m.index!, name);
      if (!keep(el)) continue;
      if (!/<InfoTip\b|__INFOTIP_SHARED__/.test(el)) gaps.push({ rule, line: lineOf(src, m.index!), snippet: snippet(m.index!) });
    }
  };
  needTip("CardTitle", "heading", () => true);
  needTip("TableHead", "heading", (el) => {
    const text = visibleText(innerOf(el));
    return text !== "" && !SELF_EXPLANATORY_HEADERS.has(text);
  });
  needTip("p", "heading", (el) => {
    // a label is literal text only; "{pct}% of total" is a value, not a label
    const open = el.slice(0, el.indexOf(">") + 1);
    const inner = innerOf(el);
    const literal = !/\{/.test(inner.replace(/<InfoTip\b[^>]*>/g, "").replace(/\{\s*\}/g, ""));
    return /className=["'][^"']*\bfont-medium\b/.test(open) && visibleText(inner) !== "" && literal;
  });
  if (opts.dashboard) {
    for (const h of ["h2", "h3"]) needTip(h, "h2", (el) => visibleText(innerOf(el)) !== "");
  }
  return gaps;
}
