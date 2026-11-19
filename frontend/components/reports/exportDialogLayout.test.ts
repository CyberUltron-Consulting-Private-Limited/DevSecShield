/**
 * Plan §7: the PDF export dialog fits small screens. Its content scrolls inside the viewport
 * (max-h-[calc(100dvh-2rem)] overflow-y-auto) and its footer is sticky, so Download stays on screen on a phone held
 * upright (390×844) or sideways (844×390), with the tallest form there is (an SCA + SBOM scan: every section, the
 * status filter and an error panel). Measured in a real browser (Playwright + Chrome) on the real form rendered to
 * HTML with the app's compiled Tailwind CSS, like components/cbom/sources/cmdbDialogLayout.test.ts. The harness first
 * checks the shared dialog's own classes without ours: there Download is off screen sideways, so it detects the bug
 * it guards against.
 * Needs Playwright and Chrome (PLAYWRIGHT_MODULE, CHROME_PATH; defaults /opt/npm-tools and /usr/bin/google-chrome):
 * where they are missing (CI) the browser part is skipped and only the class checks run.
 * LAYOUT_SHOTS=<dir> also saves a screenshot of each case there.
 * Run: npx --yes tsx components/reports/exportDialogLayout.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { TooltipProvider } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { ReportDownloadError } from "@/utils/backend_api";

import { EXPORT_DIALOG_LAYOUT, ExportPdfForm } from "./ExportPdfDialog";

const frontend = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const dialogSrc = fs.readFileSync(path.join(frontend, "components/ui/dialog.tsx"), "utf8");
const contentBase = /DialogPrimitive\.Content[\s\S]*?cn\(\s*"([^"]+)"/.exec(dialogSrc)?.[1];
assert.ok(contentBase && contentBase.includes("translate-y-[-50%]"), "DialogContent classes not found");

// the class checks (always)
assert.match(EXPORT_DIALOG_LAYOUT.content, /max-h-\[calc\(100dvh-2rem\)\]/);
assert.match(EXPORT_DIALOG_LAYOUT.content, /overflow-y-auto/);
assert.match(EXPORT_DIALOG_LAYOUT.content, /overflow-x-hidden/);
assert.match(EXPORT_DIALOG_LAYOUT.footer, /\bsticky bottom-0\b/);
assert.match(EXPORT_DIALOG_LAYOUT.footer, /\bbg-background\b/, "the sticky footer hides what scrolls under it");
const dialogTsx = fs.readFileSync(path.join(frontend, "components/reports/ExportPdfDialog.tsx"), "utf8");
assert.match(dialogTsx, /<DialogContent className=\{EXPORT_DIALOG_LAYOUT\.content\}/);
assert.match(dialogTsx, /<div className=\{EXPORT_DIALOG_LAYOUT\.footer\} data-testid="export-footer">/);

const error = new ReportDownloadError("Finding statuses aren't available for this scan yet", { status: 409, detail: null, retryAfter: null, field: null });
const form = renderToStaticMarkup(h(TooltipProvider, null, h(ExportPdfForm, {
  open: true, onOpenChange: () => undefined, teamId: 7, target: { family: "scan", type: "sbom_sca", scanId: 12 }, pending: false,
  error, onDownload: () => undefined, onClearError: () => undefined,
})));
assert.ok(form.includes('data-testid="export-download"') && form.includes("Package inventory"), "the form rendered");

type Layout = { content: string; header: string; footer: string };
function page(layout: Layout): string {
  const html = form.replace(`class="${EXPORT_DIALOG_LAYOUT.footer}"`, `class="${layout.footer}"`);
  return `<!doctype html><html class="dark"><head><meta name="viewport" content="width=device-width, initial-scale=1"><style>${css}</style></head>
<body><div id="dialog" data-state="open" class="${cn(contentBase, layout.content)}">
<div class="${cn("flex flex-col gap-2 text-center sm:text-left", layout.header)}"><h2 class="text-lg leading-none font-semibold">Download PDF report</h2>
<p class="text-muted-foreground text-sm">Choose what the report holds. The Full preset with every severity and status ticked gives the full report.</p></div>
${html}<button id="close" class="absolute top-4 right-4">x</button></div></body></html>`;
}

let css = "";
async function main() {
  const requireFrom = createRequire(path.join(process.env.PLAYWRIGHT_MODULE ?? "/opt/npm-tools/node_modules", "noop.js"));
  type Page = { setContent(html: string): Promise<void>; evaluate<T>(fn: () => T): Promise<T>; close(): Promise<void>; screenshot(o: { path: string }): Promise<unknown> };
  type Browser = { newPage(o: { viewport: { width: number; height: number } }): Promise<Page>; close(): Promise<void> };
  let playwright: { chromium: { launch(o: { executablePath: string; args: string[] }): Promise<Browser> } } | null = null;
  try { playwright = requireFrom("playwright"); } catch { playwright = null; }
  const chrome = process.env.CHROME_PATH ?? "/usr/bin/google-chrome";
  if (!playwright || !fs.existsSync(chrome)) {
    console.log("exportDialogLayout.test.ts: class checks ok; browser layout check skipped (no Playwright or Chrome here)");
    return;
  }
  const req = createRequire(path.join(frontend, "package.json"));
  const { compile } = req("@tailwindcss/node");
  const { Scanner } = req("@tailwindcss/oxide");
  const compiler = await compile(fs.readFileSync(path.join(frontend, "app/globals.css"), "utf8"), { base: frontend, onDependency() {} });
  const scanner = new Scanner({ sources: ["components", "app"].map((d) => ({ base: path.join(frontend, d), pattern: "**/*.{ts,tsx}", negated: false })) });
  css = compiler.build(scanner.scan());
  // the shared dialog as it is (no height limit, no sticky footer): the bug this layout prevents
  const before: Layout = { content: "sm:max-w-2xl", header: EXPORT_DIALOG_LAYOUT.header, footer: "flex flex-wrap items-center justify-end gap-2 px-6 py-3" };
  const browser = await playwright.chromium.launch({ executablePath: chrome, args: ["--no-sandbox"] });
  try {
    const results: string[] = [];
    for (const [name, layout] of [["before", before], ["after", EXPORT_DIALOG_LAYOUT]] as const) {
      for (const [width, height] of [[390, 844], [844, 390], [1366, 768]]) {
        const p = await browser.newPage({ viewport: { width, height } });
        await p.setContent(page(layout));
        const m = await p.evaluate(() => {
          const d = document.getElementById("dialog")!;
          const box = d.getBoundingClientRect();
          const dl = document.querySelector('[data-testid="export-download"]')!.getBoundingClientRect();
          const close = document.getElementById("close")!.getBoundingClientRect();
          // the element really on top at Download's centre (not covered by the scrolling content)
          const hit = document.elementFromPoint(dl.left + dl.width / 2, dl.top + dl.height / 2);
          return {
            dialog: { top: Math.round(box.top), bottom: Math.round(box.bottom), width: Math.round(box.width) },
            download: { top: Math.round(dl.top), bottom: Math.round(dl.bottom), left: Math.round(dl.left), right: Math.round(dl.right) },
            onTop: !!hit?.closest('[data-testid="export-download"]'),
            scrolls: d.scrollHeight > d.clientHeight,
            wide: d.scrollWidth > d.clientWidth + 1,
            closeOnScreen: close.top >= 0 && close.right <= window.innerWidth,
          };
        });
        const inView = m.download.top >= 0 && m.download.bottom <= height && m.download.left >= 0 && m.download.right <= width;
        results.push(`${name} ${width}x${height}: dialog ${m.dialog.top}..${m.dialog.bottom} (w ${m.dialog.width}), Download ${m.download.top}..${m.download.bottom}, in view ${inView}, clickable ${m.onTop}, scrolls ${m.scrolls}`);
        if (name === "after") {
          assert.ok(inView, `${width}x${height}: Download is off screen ${JSON.stringify(m.download)}`);
          assert.ok(m.onTop, `${width}x${height}: Download is covered`);
          assert.ok(m.dialog.top >= 0 && m.dialog.bottom <= height, `${width}x${height}: the dialog is taller than the screen`);
          assert.ok(!m.wide, `${width}x${height}: content wider than the dialog`);
          assert.ok(m.closeOnScreen, `${width}x${height}: close button off screen`);
        } else if (width === 844) {
          assert.ok(!inView, "the harness no longer shows Download off screen with the shared dialog's classes");
        }
        if (process.env.LAYOUT_SHOTS) await p.screenshot({ path: path.join(process.env.LAYOUT_SHOTS, `export-dialog-${name}-${width}x${height}.png`) });
        await p.close();
      }
    }
    console.log(results.join("\n"));
  } finally {
    await browser.close();
  }
  console.log("exportDialogLayout.test.ts: ok");
}

main().catch((e) => { console.error(e); process.exit(1); });
