/**
 * Regression (R-qa on PR #120): a height limit on the Radix ScrollArea *root* does not bound its viewport (the
 * viewport is `size-full`, so it grows with the table): the findings table painted ~2,100 px into a 640 px box, over
 * the pager and "Top cryptographic risks"; the unmanaged-certificates table drew over the crypto charts. Every
 * height-limited ScrollArea on the run page must put the limit on the viewport, or use a fixed height on the root.
 * Run: npx --yes tsx components/cbom/results/scrollBounds.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const dir = __dirname;
const files = fs.readdirSync(dir).filter((f) => f.endsWith(".tsx"));
let checked = 0;
for (const file of files) {
  const src = fs.readFileSync(path.join(dir, file), "utf8");
  for (const m of src.matchAll(/<ScrollArea\b([^>]*)>/g)) {
    const attrs = m[1];
    const cls = (attrs.match(/className=(?:"([^"]*)"|\{`([^`]*)`\})/) ?? [])
      .slice(1).find((x) => x !== undefined) ?? "";
    // a max-h-* directly on the root (not inside the viewport variant) is the bug
    const rootMaxH = cls.split(/\s+/).filter((c) => /^max-h-/.test(c));
    assert.deepEqual(rootMaxH, [], `${file}: ${m[0]} limits the root, not the viewport`);
    checked += 1;
  }
}
assert.ok(checked >= 5, `found the run page's ScrollAreas (${checked})`);

// the two tables R-qa measured use the viewport-bounded classes
const table = fs.readFileSync(path.join(dir, "RunFindingsTable.tsx"), "utf8");
assert.match(table, /VIEWPORT_MAX_H_TABLE = "\[&>\[data-slot=scroll-area-viewport\]\]:max-h-\[640px\]"/);
assert.match(table, /<ScrollArea className=\{`[^`]*\$\{VIEWPORT_MAX_H_TABLE\}`\} data-testid="run-results-scroll">/);
const sections = fs.readFileSync(path.join(dir, "RunSections.tsx"), "utf8");
assert.match(sections, /VIEWPORT_MAX_H_72 = "\[&>\[data-slot=scroll-area-viewport\]\]:max-h-72"/);
assert.match(sections, /<ScrollArea className=\{`[^`]*\$\{VIEWPORT_MAX_H_72\}`\}/);
// the shadcn ScrollArea still marks its viewport with this data-slot (the selector above depends on it)
const ui = fs.readFileSync(path.join(dir, "..", "..", "ui", "scroll-area.tsx"), "utf8");
assert.ok(ui.includes('data-slot="scroll-area-viewport"'));

// mobile: the page does not clip sideways overflow (it must not have any); select + name stay sticky below 768 px
const page = fs.readFileSync(path.join(dir, "..", "..", "..", "app", "[team_id]", "cbom", "runs", "[run_id]", "results", "page.tsx"), "utf8");
assert.ok(!page.includes("overflow-x-hidden"), "no overflow clipping on the page wrapper");
assert.match(table, /const STICKY_SELECT = "max-md:sticky max-md:left-0/);
assert.match(table, /const STICKY_NAME = "max-md:sticky max-md:left-12/);

console.log(`scroll bounds tests passed (${checked} ScrollAreas)`);
