#!/usr/bin/env node
/**
 * Reproduce Expand dependency graph on CBOM #94 and AIBOM #95.
 */
const fs = require("fs");
const { chromium } = require("/opt/homebrew/lib/node_modules/playwright");

const tokens = JSON.parse(fs.readFileSync("/tmp/bom_graph_tokens.json", "utf8"));
const base = process.env.FRONTEND_BASE || "http://127.0.0.1:3000";

async function probe(page, label, url) {
  const out = {
    label,
    url,
    expandVisible: false,
    expandEnabled: false,
    clicked: false,
    dialogOpen: false,
    dialogTitle: null,
    nodesBefore: 0,
    nodesInDialog: 0,
    closeWorks: false,
    escapeWorks: false,
    consoleErrors: [],
    pageErrors: [],
    notes: [],
    dialogHtmlSnippet: null,
  };

  page.removeAllListeners("console");
  page.removeAllListeners("pageerror");
  page.on("console", (msg) => {
    if (msg.type() === "error") out.consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => out.pageErrors.push(String(err)));

  await page.goto(`${base}/login`, { waitUntil: "domcontentloaded", timeout: 60000 });
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 90000 });

  // Wait for results / Expand button
  const expand = page.getByRole("button", { name: /Expand dependency graph/i });
  try {
    await expand.waitFor({ state: "visible", timeout: 60000 });
    out.expandVisible = true;
  } catch (e) {
    out.notes.push(`Expand not visible: ${e.message}`);
    // dump what's on page
    out.notes.push(`body text sample: ${(await page.locator("body").innerText()).slice(0, 400)}`);
    return out;
  }

  out.expandEnabled = await expand.isEnabled();
  out.nodesBefore = await page.locator(".react-flow__node").count();

  // Capture computed styles / stacking before click
  const pre = await expand.evaluate((el) => {
    const cs = window.getComputedStyle(el);
    const r = el.getBoundingClientRect();
    const top = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    return {
      pointerEvents: cs.pointerEvents,
      display: cs.display,
      visibility: cs.visibility,
      zIndex: cs.zIndex,
      rect: { x: r.x, y: r.y, w: r.width, h: r.height },
      topAtPoint: top ? `${top.tagName}.${top.className}`.slice(0, 120) : null,
      ariaDisabled: el.getAttribute("aria-disabled"),
      disabled: el.disabled,
    };
  });
  out.preClick = pre;

  await expand.click({ timeout: 10000 });
  out.clicked = true;
  await page.waitForTimeout(800);

  // Dialog content
  const dialog = page.locator('[data-slot="dialog-content"], [role="dialog"]');
  out.dialogOpen = (await dialog.count()) > 0 && (await dialog.first().isVisible().catch(() => false));
  if (out.dialogOpen) {
    out.dialogTitle = await dialog
      .first()
      .locator('[data-slot="dialog-title"], h2')
      .first()
      .innerText()
      .catch(() => null);
    out.nodesInDialog = await dialog.first().locator(".react-flow__node").count();
    const box = await dialog.first().boundingBox();
    out.dialogBox = box;
    const canvasBox = await dialog
      .first()
      .locator(".react-flow")
      .first()
      .boundingBox()
      .catch(() => null);
    out.reactFlowBox = canvasBox;
    out.dialogHtmlSnippet = (await dialog.first().innerHTML()).slice(0, 500);

    // Try Escape
    await page.keyboard.press("Escape");
    await page.waitForTimeout(400);
    out.escapeWorks = !(await dialog.first().isVisible().catch(() => false));

    if (!out.escapeWorks) {
      // reopen and try close button
      await expand.click().catch(() => {});
      await page.waitForTimeout(500);
    }
  } else {
    // Maybe dialog rendered but not visible
    out.notes.push(
      `dialog count=${await page.locator('[data-slot="dialog-content"]').count()} role=dialog=${await page.locator('[role="dialog"]').count()}`
    );
    out.notes.push(`open state attrs: ${await page.evaluate(() => {
      const d = document.querySelector('[data-slot="dialog-content"]');
      if (!d) return "no dialog-content";
      const cs = getComputedStyle(d);
      return JSON.stringify({
        state: d.getAttribute("data-state"),
        display: cs.display,
        visibility: cs.visibility,
        opacity: cs.opacity,
        zIndex: cs.zIndex,
        pointerEvents: cs.pointerEvents,
        rect: d.getBoundingClientRect(),
      });
    })}`);
  }

  // Re-open for close button test if needed
  if (out.dialogOpen && out.escapeWorks) {
    await expand.click();
    await page.waitForTimeout(500);
  }
  if (await dialog.first().isVisible().catch(() => false)) {
    const closeBtn = dialog.first().locator('[data-slot="dialog-close"]');
    if (await closeBtn.count()) {
      await closeBtn.click();
      await page.waitForTimeout(300);
      out.closeWorks = !(await dialog.first().isVisible().catch(() => false));
    }
  }

  return out;
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await ctx.addInitScript((t) => {
    localStorage.setItem("access_token", t.access);
    localStorage.setItem("refresh_token", t.refresh || t.access);
  }, tokens);

  const page = await ctx.newPage();
  const results = {
    cbom94: await probe(page, "cbom94", `${base}/1/cbom/94/results`),
    aibom95: await probe(page, "aibom95", `${base}/1/ai_bom/95/results`),
  };

  fs.writeFileSync("/tmp/bom_graph_expand_repro.json", JSON.stringify(results, null, 2));
  console.log(JSON.stringify(results, null, 2));
  await browser.close();
  process.exit(0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
