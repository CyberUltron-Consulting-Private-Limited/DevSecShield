/**
 * #366: the CMDB import dialog's content stays inside the dialog at 390, 768 and 1366 px, with a 20-column CSV and a
 * long preview, and its close button stays on screen. Measured in a real browser (Playwright + Chrome) on the real
 * components rendered to HTML with the app's compiled Tailwind CSS. The same harness first checks that the classes
 * before the fix overflow, so it detects the bug it guards against.
 * Needs Playwright and Chrome (PLAYWRIGHT_MODULE, CHROME_PATH; defaults /opt/npm-tools and /usr/bin/google-chrome):
 * where they are missing (CI) the browser part is skipped and only the class checks run.
 * Run: npx --yes tsx components/cbom/sources/cmdbDialogLayout.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import type { CmdbPlan } from "@/utils/api/integrations";

import { PlanView } from "./CmdbImportDialog";
import { DIALOG_LAYOUT } from "./cmdbLogic";

const frontend = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../../..");
const dialogSrc = fs.readFileSync(path.join(frontend, "components/ui/dialog.tsx"), "utf8");
const contentBase = /DialogPrimitive\.Content[\s\S]*?cn\(\s*"([^"]+)"/.exec(dialogSrc)?.[1];
assert.ok(contentBase && contentBase.includes("max-w-[calc(100%-2rem)]"), "DialogContent classes not found");

// the class checks (always): the CSV box never sizes to its content and never widens the body
assert.match(DIALOG_LAYOUT.csv, /\[field-sizing:fixed\]/);
assert.match(DIALOG_LAYOUT.csv, /max-w-full/);
assert.match(DIALOG_LAYOUT.body, /min-w-0/);
assert.match(DIALOG_LAYOUT.content, /overflow-x-hidden/);
const dialogTsx = fs.readFileSync(path.join(frontend, "components/cbom/sources/CmdbImportDialog.tsx"), "utf8");
assert.match(dialogTsx, /className=\{DIALOG_LAYOUT\.content\}/);
assert.match(dialogTsx, /wrap="off" className=\{DIALOG_LAYOUT\.csv\}/);

const columns = Array.from({ length: 20 }, (_, i) => `column_number_${i + 1}`);
const csv = [columns.join(","), ...Array.from({ length: 30 }, (_, r) => columns.map((c) => `${c}-row-${r}-value`).join(","))].join("\n");
const longName = "very-long-host-name-without-any-breaks-" + "x".repeat(120) + ".bank.local";
const plan: CmdbPlan = {
  rows: 31, digest: "d", unchanged: 1,
  counts: { create: 1, update: 0, conflict: 1, skipped: 1, new_targets: 1, merged: 1 },
  creates: [{ kind: "linux_servers", name: "CMDB servers", targets: [longName], metadata: { owner: "Team ".repeat(30) }, lines: [2] }],
  updates: [], truncated: false,
  conflicts: [{ source_id: null, source: null, host: longName, field: "owner", values: { "team-a": [2], "team-b": [3] } }],
  skipped: [{ line: 4, reason: "ca_pem: " + "a-very-long-reason-".repeat(20) }],
  merged: [{ label: longName, kind: "linux_servers", lines: [2, 3], notes: [] }],
  unchanged_items: [{ source_id: 9, source: longName, kind: "linux_servers", lines: [5] }],
  warnings: ["Scan node " + "n".repeat(150) + " has not registered yet."],
};

function page(layout: { content: string; body: string; csv: string; text: string }): string {
  const textarea = renderToStaticMarkup(h(Textarea, { id: "cmdb-csv", defaultValue: csv, wrap: layout.csv.includes("field-sizing:fixed") ? "off" : undefined, className: layout.csv, readOnly: true }));
  const planHtml = renderToStaticMarkup(h(PlanView, { plan }));
  return `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><style>${css}</style></head>
<body><div id="dialog" data-state="open" class="${cn(contentBase, layout.content)}">
<div class="flex flex-col gap-2 text-center sm:text-left"><h2 class="text-lg leading-none font-semibold ${layout.text}">Import sources and metadata from a CMDB</h2>
<p class="text-muted-foreground text-sm ${layout.text}">Preview first: nothing changes until you confirm. Columns: ${columns.join(", ")}</p></div>
<div class="${layout.body}">${textarea}${planHtml}</div>
<button id="close" class="absolute top-4 right-4">x</button></div></body></html>`;
}

let css = "";
async function main() {
  const requireFrom = createRequire(path.join(process.env.PLAYWRIGHT_MODULE ?? "/opt/npm-tools/node_modules", "noop.js"));
  // Playwright is not a dependency of the app: loaded from where it is installed, typed by what is used here
  type Page = { setContent(html: string): Promise<void>; evaluate<T>(fn: () => T): Promise<T>; close(): Promise<void> };
  type Browser = { newPage(o: { viewport: { width: number; height: number } }): Promise<Page>; close(): Promise<void> };
  let playwright: { chromium: { launch(o: { executablePath: string; args: string[] }): Promise<Browser> } } | null = null;
  try { playwright = requireFrom("playwright"); } catch { playwright = null; }
  const chrome = process.env.CHROME_PATH ?? "/usr/bin/google-chrome";
  if (!playwright || !fs.existsSync(chrome)) {
    console.log("cmdbDialogLayout.test.ts: class checks ok; browser layout check skipped (no Playwright or Chrome here)");
    return;
  }
  const req = createRequire(path.join(frontend, "package.json"));
  const { compile } = req("@tailwindcss/node");
  const { Scanner } = req("@tailwindcss/oxide");
  const compiler = await compile(fs.readFileSync(path.join(frontend, "app/globals.css"), "utf8"), { base: frontend, onDependency() {} });
  const scanner = new Scanner({ sources: ["components", "app"].map((d) => ({ base: path.join(frontend, d), pattern: "**/*.{ts,tsx}", negated: false })) });
  css = compiler.build(scanner.scan());
  const before = { content: "sm:max-w-3xl max-h-[90vh] overflow-y-auto", body: "space-y-4", csv: "font-mono text-xs min-h-[140px]", text: "" };
  const browser = await playwright.chromium.launch({ executablePath: chrome, args: ["--no-sandbox"] });
  try {
    const results: string[] = [];
    for (const [name, layout] of [["before", before], ["after", DIALOG_LAYOUT]] as const) {
      for (const width of [390, 768, 1366]) {
        const p = await browser.newPage({ viewport: { width, height: 900 } });
        await p.setContent(page(layout));
        const m = await p.evaluate(() => {
          const d = document.getElementById("dialog")!;
          const box = d.getBoundingClientRect();
          const close = document.getElementById("close")!.getBoundingClientRect();
          let widest = 0;
          d.querySelectorAll("*").forEach((el) => { widest = Math.max(widest, el.getBoundingClientRect().right - box.left); });
          return { scroll: d.scrollWidth, client: d.clientWidth, width: box.width, widest: Math.round(widest),
                   closeOnScreen: close.right <= window.innerWidth && close.left >= 0 };
        });
        results.push(`${name} ${width}px: dialog ${Math.round(m.width)} px, content ${m.scroll} px, widest child ${m.widest} px, close on screen ${m.closeOnScreen}`);
        if (name === "after") {
          assert.ok(m.scroll <= m.client + 1, `${width}px: content ${m.scroll} px in a ${m.client} px dialog`);
          assert.ok(m.width <= width, `${width}px: dialog ${m.width} px wider than the screen`);
          assert.ok(m.closeOnScreen, `${width}px: close button off screen`);
        } else if (width === 768) {
          assert.ok(m.scroll > m.client + 100, "the harness no longer reproduces #366 with the old classes");
        }
        await p.close();
      }
    }
    console.log(results.join("\n"));
  } finally {
    await browser.close();
  }
  console.log("cmdbDialogLayout.test.ts: ok");
}

main().catch((e) => { console.error(e); process.exit(1); });
