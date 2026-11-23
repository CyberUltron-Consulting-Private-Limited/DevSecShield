/**
 * Staging QA 23 Nov 2026: on /{team}/sast/{scan}/results at 390 px the header's "Download Scan Report" ran 6 px past
 * the viewport (and "Chat with the Results" was off screen), and on a tablet the scan chat header drew the scan title
 * under its Refresh button. This test renders both headers with their real classes (RESULTS_HEADER, SCAN_CHAT_HEADER)
 * and the app's compiled Tailwind CSS, and measures them in Chrome at 390, 820 and 1440 px (the results header) and in
 * chat columns of 180, 390 and 820 px (the chat header). The harness first checks the old classes: there the buttons
 * do overflow and the title is covered, so it detects the bug it guards against. Like
 * components/reports/exportDialogLayout.test.ts, the browser part is skipped where Playwright or Chrome is missing
 * (CI); the class and wiring checks always run.
 * LAYOUT_SHOTS=<dir> also saves a screenshot of each case there.
 * Run: npx --yes tsx components/resultsHeaderLayout.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { createElement as h, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { ArrowLeft, ChevronRightIcon, Download, MessageCircle, RefreshCcwIcon } from "lucide-react";

import { Button } from "@/components/ui/button";

import { RESULTS_HEADER, SCAN_CHAT_HEADER } from "./resultsHeaderLayout";

const frontend = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const src = (rel: string) => fs.readFileSync(path.join(frontend, rel), "utf8");

// ---------------------------------------------------------------- wiring (always)
const RESULT_PAGES = ["SASTResults", "SbomResults", "IACResults", "DASTResults", "MCPResults", "LLMResults", "AiBomResults",
  "DataLeakageResults", "AgentDiscoveryResults"];
for (const name of RESULT_PAGES) {
  const tsx = src(`components/${name}.tsx`);
  assert.ok(tsx.includes("className={RESULTS_HEADER.row}") && tsx.includes("className={RESULTS_HEADER.lead}"), `${name} uses RESULTS_HEADER`);
  assert.doesNotMatch(tsx, /<div className="flex items-center justify-between">\s*<div className="flex items-center gap-4">/,
    `${name} still has a header row that cannot wrap`);
}
assert.match(RESULTS_HEADER.row, /\bflex-wrap\b/);
assert.match(RESULTS_HEADER.actions, /\bflex-wrap\b/);
assert.match(RESULTS_HEADER.actions, /\blg:ml-auto\b/, "desktop actions stay at the right edge");
assert.match(RESULTS_HEADER.lead, /\bmin-w-0\b/);
const chat = src("components/ai/ChatWindow.tsx");
for (const key of ["row", "lead", "crumb", "crumbTitle", "status", "actions"]) {
  assert.ok(chat.includes(`SCAN_CHAT_HEADER.${key}`), `ChatWindow uses SCAN_CHAT_HEADER.${key}`);
}
assert.match(SCAN_CHAT_HEADER.crumbTitle, /\btruncate\b/);
assert.doesNotMatch(SCAN_CHAT_HEADER.crumb, /\bshrink-0\b/, "the breadcrumb must be able to shrink");

// ---------------------------------------------------------------- markup
type ResultsClasses = { row: string; lead: string; title: string; actions: string };
const OLD_RESULTS: ResultsClasses = { row: "flex items-center justify-between", lead: "flex items-center gap-4", title: "", actions: "flex items-center gap-2" };
const ACTIONS: Record<string, string[]> = {
  sast: ["Download Scan Report", "Chat with the Results"],
  sca: ["Download SBOM", "VEX", "Signature", "Evidence pack", "Download Scan Report", "Chat with the Results"],
  mcp: ["Refresh", "Download Scan Report", "Chat with the Results"],
};
const TITLES: Record<string, string> = { sast: "SAST Scan Results", sca: "SCA + SBOM Scan Results", mcp: "MCP Scan Results" };

function resultsHeader(c: ResultsClasses, kind: string): string {
  const btn = (label: string): ReactNode => label === "Refresh"  // MCP's icon-only refresh
    ? h(Button, { key: label, variant: "outline", size: "icon", title: "Refresh" }, h(RefreshCcwIcon, { className: "h-4 w-4" }))
    : h(Button, { key: label, variant: "outline", className: "cursor-pointer" },
      h(label.startsWith("Chat") ? MessageCircle : Download, { className: "h-4 w-4 mr-2" }), label);
  return renderToStaticMarkup(h("div", { className: "container mx-auto p-6 space-y-6" },
    h("div", { className: c.row, id: "header" },
      h("div", { className: c.lead },
        h(Button, { variant: "outline", size: "icon", "aria-label": "Back" }, h(ArrowLeft, { className: "h-4 w-4" })),
        h("div", { className: c.title || undefined },
          h("h1", { className: "text-3xl font-bold text-zinc-900 dark:text-white", id: "title" }, TITLES[kind]),
          h("p", { className: "text-sm text-zinc-600 dark:text-zinc-400 mt-1" }, "Agent analysis by logical component"))),
      h("div", { className: c.actions, id: "actions" }, ACTIONS[kind].map(btn)))));
}

type ChatClasses = { row: string; lead: string; crumb: string; crumbTitle: string; status: string; actions: string };
const OLD_CHAT: ChatClasses = {
  row: "flex items-center justify-between border-b bg-muted/50 px-4 py-3", lead: "flex items-center gap-3 flex-1 min-w-0",
  crumb: "flex items-center gap-2 shrink-0", crumbTitle: "text-neutral-200 font-medium truncate", status: "contents",
  actions: "flex flex-row justify-end items-center gap-3",
};
function chatHeader(c: ChatClasses): string {
  return renderToStaticMarkup(h("div", { className: c.row, id: "header" },
    h("div", { className: c.lead },
      h("div", { className: c.crumb },
        h("span", { className: "font-medium text-sm cursor-pointer shrink-0" }, "SAST"),
        h(ChevronRightIcon, { className: "size-4 shrink-0 text-zinc-500" }),
        h("span", { className: c.crumbTitle, id: "title" }, "e2e-security-demo-payments-service")),
      h("div", { className: c.status },
        h("div", { className: "h-4 w-px bg-border shrink-0" }),
        h("div", { className: "flex flex-row items-center gap-2" }, h("div", { className: "size-2 rounded-full bg-green-500" }),
          h("span", { className: "text-muted-foreground text-xs" }, "Scan Completed")))),
    h("div", { className: c.actions },
      h(Button, { className: "bg-blue-600 hover:bg-blue-700 text-white cursor-pointer", id: "refresh" }, h(RefreshCcwIcon, { className: "size-4" }), "Refresh"))));
}

// ---------------------------------------------------------------- browser
type Box = { left: number; right: number; top: number; bottom: number };
type Page = { setContent(html: string): Promise<void>; evaluate(expression: string): Promise<unknown>; close(): Promise<void>; screenshot(o: { path: string }): Promise<unknown> };
type Browser = { newPage(o: { viewport: { width: number; height: number } }): Promise<Page>; close(): Promise<void> };

async function main() {
  const requireFrom = createRequire(path.join(process.env.PLAYWRIGHT_MODULE ?? "/opt/npm-tools/node_modules", "noop.js"));
  let playwright: { chromium: { launch(o: { executablePath: string; args: string[] }): Promise<Browser> } } | null = null;
  try { playwright = requireFrom("playwright"); } catch { playwright = null; }
  const chrome = process.env.CHROME_PATH ?? "/usr/bin/google-chrome";
  if (!playwright || !fs.existsSync(chrome)) {
    console.log("resultsHeaderLayout.test.ts: wiring and class checks ok; browser layout check skipped (no Playwright or Chrome here)");
    return;
  }
  const req = createRequire(path.join(frontend, "package.json"));
  const { compile } = req("@tailwindcss/node");
  const { Scanner } = req("@tailwindcss/oxide");
  const compiler = await compile(src("app/globals.css"), { base: frontend, onDependency() {} });
  const scanner = new Scanner({ sources: ["components", "app"].map((d) => ({ base: path.join(frontend, d), pattern: "**/*.{ts,tsx}", negated: false })) });
  const css: string = compiler.build(scanner.scan());
  // the team sidebar takes 16rem from md up (the QA tablet shots); a phone has the mobile menu bar instead
  const doc = (body: string, column?: number) => `<!doctype html><html class="dark"><head><meta name="viewport" content="width=device-width, initial-scale=1"><style>${css}</style></head>
<body class="bg-background text-foreground"><div class="${column ? "" : "md:ml-64"}" ${column ? `style="width:${column}px"` : ""} id="column">${body}</div></body></html>`;

  // a string, not a function: tsx's name helpers (__name) do not exist inside the page
  const MEASURE = `(() => {
    const box = (e) => { const r = e.getBoundingClientRect(); return { left: Math.round(r.left), right: Math.round(r.right), top: Math.round(r.top), bottom: Math.round(r.bottom) }; };
    const column = box(document.getElementById("column"));
    const header = document.getElementById("header");
    const actions = document.getElementById("actions");
    const buttons = [...header.querySelectorAll("button")].map(box);
    const t = box(document.getElementById("title"));
    const refresh = document.getElementById("refresh");
    let covered = false;
    if (refresh) { const r = box(refresh); covered = t.right > r.left && t.left < r.right && t.bottom > r.top && t.top < r.bottom; }
    return { column, buttons, title: t, covered, header: box(header), actions: actions ? box(actions) : null,
      actionsRight: actions ? Math.round(Math.max(...[...actions.children].map((e) => e.getBoundingClientRect().right))) : null,
      pageWide: document.documentElement.scrollWidth > document.documentElement.clientWidth,
      headerWide: header.scrollWidth > header.clientWidth + 1 };
  })()`;
  type Measured = { column: Box; buttons: Box[]; title: Box; covered: boolean; pageWide: boolean; headerWide: boolean;
    header: Box; actions: Box | null; actionsRight: number | null };
  const measure = (p: Page) => p.evaluate(MEASURE) as Promise<Measured>;

  const browser = await playwright.chromium.launch({ executablePath: chrome, args: ["--no-sandbox"] });
  const lines: string[] = [];
  try {
    for (const kind of ["sast", "sca", "mcp"]) {
      for (const [name, classes] of [["before", OLD_RESULTS], ["after", RESULTS_HEADER]] as const) {
        for (const [width, height] of [[390, 844], [820, 1180], [1280, 800], [1440, 900]]) {
          const p = await browser.newPage({ viewport: { width, height } });
          await p.setContent(doc(resultsHeader(classes, kind)));
          const m = await measure(p);
          const out = m.buttons.filter((b) => b.left < m.column.left - 1 || b.right > Math.min(width, m.column.right) + 1);
          const rightGap = m.header.right - (m.actionsRight ?? 0);
          lines.push(`results ${kind} ${name} ${width}: buttons outside ${out.length}, page wider than screen ${m.pageWide}, title ${m.title.left}..${m.title.right}, last button ${rightGap}px from the header's right edge`);
          if (name === "after") {
            assert.equal(out.length, 0, `${kind} ${width}px: a button is outside the screen ${JSON.stringify(out)}`);
            if (width >= 1280) {  // desktop: the actions end at the header's right edge, as on dev
              assert.ok(Math.abs(rightGap) <= 1, `${kind} ${width}px: the actions end ${rightGap}px left of the header's right edge`);
            }
            assert.ok(!m.pageWide && !m.headerWide, `${kind} ${width}px: the header is wider than the screen`);
            assert.ok(m.title.right <= width, `${kind} ${width}px: the title runs off screen`);
          } else if (width === 390) {
            assert.ok(out.length > 0, `${kind}: the harness no longer shows the old header overflowing at 390 px`);
          }
          if (process.env.LAYOUT_SHOTS) await p.screenshot({ path: path.join(process.env.LAYOUT_SHOTS, `results-${kind}-${name}-${width}.png`) });
          await p.close();
        }
      }
    }
    for (const [name, classes] of [["before", OLD_CHAT], ["after", SCAN_CHAT_HEADER]] as const) {
      for (const column of [180, 390, 820]) {
        const p = await browser.newPage({ viewport: { width: Math.max(column, 390), height: 400 } });
        await p.setContent(doc(chatHeader(classes), column));
        const m = await measure(p);
        const out = m.buttons.filter((b) => b.left < m.column.left - 1 || b.right > m.column.right + 1);
        lines.push(`chat ${name} column ${column}: title covered by Refresh ${m.covered}, Refresh outside ${out.length > 0}, header wider ${m.headerWide}`);
        if (name === "after") {
          assert.ok(!m.covered, `chat column ${column}px: Refresh covers the scan title`);
          assert.equal(out.length, 0, `chat column ${column}px: Refresh is outside the column`);
          assert.ok(!m.headerWide, `chat column ${column}px: the header is wider than its column`);
        } else if (column === 180) {
          assert.ok(m.covered || out.length > 0, "the harness no longer shows the old chat header's overlap");
        }
        if (process.env.LAYOUT_SHOTS) await p.screenshot({ path: path.join(process.env.LAYOUT_SHOTS, `chat-${name}-${column}.png`) });
        await p.close();
      }
    }
  } finally {
    await browser.close();
  }
  console.log(lines.join("\n"));
  console.log("resultsHeaderLayout.test.ts: ok");
}

main().catch((e) => { console.error(e); process.exit(1); });
