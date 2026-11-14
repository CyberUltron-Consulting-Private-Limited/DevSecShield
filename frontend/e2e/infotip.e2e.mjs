/**
 * Browser test of the (i) info tips (F2), in real Chrome through Playwright: hover, keyboard focus and Escape,
 * aria-describedby, touch tap at 390x844, and no tip clipped at the viewport edges, plus axe on the harness page.
 *
 * It bundles e2e/infotip-harness.tsx (the real <InfoTip>, Radix and registry) with esbuild and compiles the app's
 * app/globals.css with Tailwind, so the tooltip has the app's real size and styles. Not part of `next build` or of the
 * *.test.ts unit tests: Playwright and esbuild are not frontend dependencies. Run from frontend/:
 *
 *   node e2e/infotip.e2e.mjs                 # playwright + esbuild resolved from node_modules or $E2E_TOOLS
 *   E2E_TOOLS=/opt/npm-tools/node_modules CHROME=/usr/bin/google-chrome node e2e/infotip.e2e.mjs
 *
 * Exit code 0 when every check passes; screenshots go to $E2E_OUT (default /tmp/infotip-e2e).
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const frontend = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const out = process.env.E2E_OUT ?? "/tmp/infotip-e2e";
fs.mkdirSync(out, { recursive: true });

const requireHere = createRequire(path.join(frontend, "package.json"));
const requireTools = createRequire(path.join(process.env.E2E_TOOLS ?? "/opt/npm-tools/node_modules", "noop.js"));
const load = (name) => {
  try {
    return requireHere(name);
  } catch {
    return requireTools(name);
  }
};
const { chromium } = load("playwright");
const esbuild = load("esbuild");
const postcss = requireHere("postcss");
const tailwind = requireHere("@tailwindcss/postcss");

// ------------------------------------------------------------------ build the harness page
const js = await esbuild.build({
  entryPoints: [path.join(frontend, "e2e/infotip-harness.tsx")],
  bundle: true,
  write: false,
  format: "iife",
  jsx: "automatic",
  tsconfig: path.join(frontend, "tsconfig.json"),
  define: { "process.env.NODE_ENV": '"production"' },
  logLevel: "error",
});
const cssIn = fs.readFileSync(path.join(frontend, "app/globals.css"), "utf8");
const css = await postcss([tailwind({ base: frontend })]).process(cssIn, { from: path.join(frontend, "app/globals.css") });
const html = `<!doctype html><html lang="en" class="dark"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>InfoTip harness</title>
<style>${css.css}</style></head><body><div id="root"></div><script>${js.outputFiles[0].text}</script></body></html>`;
const page = path.join(out, "harness.html");
fs.writeFileSync(page, html);
const axeSource = fs.readFileSync(requireHere.resolve("axe-core/axe.min.js"), "utf8");

// ------------------------------------------------------------------ checks
const results = [];
const check = async (name, fn) => {
  try {
    await fn();
    results.push(`PASS ${name}`);
  } catch (e) {
    results.push(`FAIL ${name}: ${e.message.replace(/\s+/g, " ").slice(0, 700)}`);
  }
};

const browser = await chromium.launch({ executablePath: process.env.CHROME || undefined, channel: process.env.CHROME ? undefined : "chrome" });

/** The open tip of a trigger: its role=tooltip text (via aria-describedby) and the visible content box. */
async function openTip(p, trigger) {
  const describedBy = await trigger.getAttribute("aria-describedby");
  assert.ok(describedBy, "the open trigger has aria-describedby");
  const text = await p.locator(`[id="${describedBy}"]`).textContent();
  const box = await p.locator('[data-slot="tooltip-content"]').boundingBox();
  assert.ok(box, "the tip's content is visible");
  return { text, box };
}
const vp = (p) => p.viewportSize();
const inside = (box, size, label) => {
  assert.ok(box.x >= 0 && box.y >= 0, `${label}: starts off-screen (${box.x.toFixed(0)}, ${box.y.toFixed(0)})`);
  assert.ok(box.x + box.width <= size.width + 0.5, `${label}: right edge ${(box.x + box.width).toFixed(0)} > ${size.width}`);
  assert.ok(box.y + box.height <= size.height + 0.5, `${label}: bottom edge ${(box.y + box.height).toFixed(0)} > ${size.height}`);
};

// desktop: mouse and keyboard
{
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const p = await ctx.newPage();
  await p.goto(`file://${page}`);
  const credits = p.locator('[data-infotip="scan.table.credits"]');
  await check("desktop: the (i) is a button named About <label>", async () => {
    assert.equal(await credits.evaluate((el) => el.tagName), "BUTTON");
    assert.equal(await credits.getAttribute("aria-label"), "About Credits");
    assert.equal(await credits.getAttribute("aria-describedby"), null);
  });
  await check("desktop: hover opens, moving away closes", async () => {
    await credits.hover();
    await p.waitForSelector('[data-slot="tooltip-content"]', { timeout: 2000 }).catch(() => {
      throw new Error("hover did not open the tip");
    });
    const { text } = await openTip(p, credits);
    assert.ok(text.includes("credit estimate"), `tooltip text: ${text.slice(0, 60)}`);
    // a real pointer moves continuously; Radix keeps the tip open while the pointer heads for it (grace area)
    await p.mouse.move(1200, 700, { steps: 25 }); // an empty spot (the edge tips sit at the corners and mid-edges)
    await p.waitForSelector('[data-slot="tooltip-content"]', { state: "detached", timeout: 2000 });
  });
  await check("desktop: Tab focuses and opens, Escape closes and keeps focus", async () => {
    await p.locator("#scan-title").focus();
    await p.keyboard.press("Shift+Tab");
    // Shift+Tab from the input reaches the label's (i)
    assert.equal(await p.evaluate(() => document.activeElement?.getAttribute("data-infotip")), "scan.new.title");
    await p.waitForSelector('[data-slot="tooltip-content"]', { timeout: 2000 });
    await p.screenshot({ path: path.join(out, "desktop-focus.png") });
    await p.keyboard.press("Escape");
    await p.waitForSelector('[data-slot="tooltip-content"]', { state: "detached", timeout: 2000 });
    assert.equal(await p.evaluate(() => document.activeElement?.getAttribute("data-infotip")), "scan.new.title");
  });
  await check("desktop: the label names the input without the (i)", async () => {
    const name = await p.evaluate(() => document.querySelector('label[for="scan-title"]')?.textContent);
    assert.equal(name, "Scan title");
  });
  await check("desktop: no tip at an edge or corner is clipped (1440x900)", async () => {
    for (const spot of await p.locator("[data-spot]").all()) {
      const name = await spot.getAttribute("data-spot");
      const trigger = spot.locator("button");
      await trigger.focus();
      await p.waitForSelector('[data-slot="tooltip-content"]', { timeout: 2000 });
      await p.waitForTimeout(200); // the open animation (zoom-in-95) ends
      const { box } = await openTip(p, trigger);
      inside(box, vp(p), name);
      await p.screenshot({ path: path.join(out, `desktop-${name}.png`) });
      await p.keyboard.press("Escape");
      await p.waitForSelector('[data-slot="tooltip-content"]', { state: "detached", timeout: 2000 });
    }
  });
  await check("desktop: axe finds no serious or critical violation (tip open)", async () => {
    await credits.focus();
    await p.waitForSelector('[data-slot="tooltip-content"]', { timeout: 2000 });
    await p.addScriptTag({ content: axeSource });
    const res = await p.evaluate(async () => await window.axe.run(document, { resultTypes: ["violations"] }));
    const bad = res.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
    assert.deepEqual(bad.map((v) => `${v.id} (${v.nodes.length}): ${v.nodes.map((n) => n.target.join(" ")).join(", ").slice(0, 300)}`), []);
  });
  await ctx.close();
}

// phone: touch at 390x844
{
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true, deviceScaleFactor: 3 });
  const p = await ctx.newPage();
  await p.goto(`file://${page}`);
  const credits = p.locator('[data-infotip="scan.table.credits"]');
  await check("phone: a tap opens, a second tap closes", async () => {
    await credits.tap();
    await p.waitForSelector('[data-slot="tooltip-content"]', { timeout: 2000 });
    await openTip(p, credits);
    await p.screenshot({ path: path.join(out, "phone-tap.png") });
    await credits.tap();
    await p.waitForSelector('[data-slot="tooltip-content"]', { state: "detached", timeout: 2000 });
  });
  await check("phone: a tap outside closes", async () => {
    await credits.tap();
    await p.waitForSelector('[data-slot="tooltip-content"]', { timeout: 2000 });
    await p.locator("[data-outside]").tap();
    await p.waitForSelector('[data-slot="tooltip-content"]', { state: "detached", timeout: 2000 });
  });
  await check("phone: the (i) hit area is at least 24x24 CSS px", async () => {
    const box = await credits.boundingBox();
    assert.ok(box.width >= 24 && box.height >= 24, `${box.width}x${box.height}`);
  });
  await check("phone: no tip at an edge or corner is clipped (390x844)", async () => {
    for (const spot of await p.locator("[data-spot]").all()) {
      const name = await spot.getAttribute("data-spot");
      const trigger = spot.locator("button");
      await trigger.tap();
      await p.waitForSelector('[data-slot="tooltip-content"]', { timeout: 2000 });
      await p.waitForTimeout(200);
      const { box } = await openTip(p, trigger);
      inside(box, vp(p), name);
      await p.screenshot({ path: path.join(out, `phone-${name}.png`) });
      await trigger.tap();
      await p.waitForSelector('[data-slot="tooltip-content"]', { state: "detached", timeout: 2000 });
    }
  });
  await ctx.close();
}

await browser.close();
console.log(results.join("\n"));
const failed = results.filter((r) => r.startsWith("FAIL"));
console.log(`infotip e2e: ${results.length - failed.length}/${results.length} passed; screenshots in ${out}`);
process.exit(failed.length ? 1 : 0);
