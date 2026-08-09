#!/usr/bin/env node
/**
 * Deep Expand diagnostics: dialog geometry + visible nodes inside canvas.
 */
const { chromium } = require("/opt/homebrew/lib/node_modules/playwright");
const fs = require("fs");
const access = fs.readFileSync("/tmp/cbom_demo_token.txt", "utf8").trim();
let refresh = access;
try {
  const j = JSON.parse(fs.readFileSync("/tmp/cbom_tokens.json", "utf8"));
  refresh = j.refresh || j.refresh_token || access;
} catch {}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await ctx.addInitScript(([a, r]) => {
    localStorage.setItem("access_token", a);
    localStorage.setItem("refresh_token", r);
  }, [access, refresh]);
  const page = await ctx.newPage();
  const out = {};

  for (const [lane, url] of [
    ["cbom94", "http://localhost:3000/1/cbom/94/results"],
    ["aibom95", "http://localhost:3000/1/ai_bom/95/results"],
  ]) {
    await page.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
    await page.goto(url, { waitUntil: "networkidle", timeout: 90000 }).catch(() => {});
    await page.waitForSelector('button:has-text("Expand")', { timeout: 60000 });

    // Scroll Expand into view
    const expand = page.getByRole("button", { name: /Expand/i }).first();
    await expand.scrollIntoViewIfNeeded();
    await page.waitForTimeout(300);
    await expand.click();
    await page.waitForTimeout(1000);

    const dialog = page.locator('[data-slot="dialog-content"]');
    const diag = await page.evaluate(() => {
      const d = document.querySelector('[data-slot="dialog-content"]');
      if (!d) return { error: "no dialog" };
      const dcs = getComputedStyle(d);
      const dbox = d.getBoundingClientRect();
      const rf = d.querySelector(".react-flow");
      const rfbox = rf ? rf.getBoundingClientRect() : null;
      const pane = d.querySelector(".react-flow__viewport, .react-flow__renderer");
      const nodes = [...d.querySelectorAll(".react-flow__node")];
      const visible = nodes.filter((n) => {
        const r = n.getBoundingClientRect();
        if (!rfbox) return false;
        const intersects =
          r.right > rfbox.left &&
          r.left < rfbox.right &&
          r.bottom > rfbox.top &&
          r.top < rfbox.bottom &&
          r.width > 2 &&
          r.height > 2;
        return intersects;
      });
      return {
        dialog: {
          state: d.getAttribute("data-state"),
          display: dcs.display,
          overflow: dcs.overflow,
          w: dbox.width,
          h: dbox.height,
          top: dbox.top,
          left: dbox.left,
        },
        reactFlow: rfbox
          ? { w: rfbox.width, h: rfbox.height, top: rfbox.top, left: rfbox.left }
          : null,
        nodeCount: nodes.length,
        visibleInCanvas: visible.length,
        sampleNodeBoxes: nodes.slice(0, 3).map((n) => {
          const r = n.getBoundingClientRect();
          return { w: r.width, h: r.height, x: r.x, y: r.y, text: n.textContent?.slice(0, 40) };
        }),
        transform: pane ? getComputedStyle(pane).transform : null,
      };
    });

    await page.screenshot({
      path: `/tmp/bom_expand_${lane}.png`,
      fullPage: false,
    });

    // Escape
    await page.keyboard.press("Escape");
    await page.waitForTimeout(300);
    const closed = !(await dialog.isVisible().catch(() => false));

    out[lane] = { ...diag, escapeClosed: closed };
  }

  fs.writeFileSync("/tmp/bom_expand_diag.json", JSON.stringify(out, null, 2));
  console.log(JSON.stringify(out, null, 2));
  await browser.close();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
