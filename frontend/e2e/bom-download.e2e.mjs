/**
 * Browser check of the results pages' CycloneDX downloads (follow-up to PR #489), in real Chrome through Playwright:
 * the file a customer saves from the SBOM, CBOM and AI BOM pages ("Download SBOM", the BOM table's "Download
 * CycloneDX", the CBOM "JSON" and "XML" buttons, the AI BOM "CycloneDX 1.6 (JSON)" menu item, and every page's VEX
 * button) is the server's document: its SHA-256 equals that of GET /bom (or /vex) fetched with the same token, it
 * equals the X-Cbom-Sha256 header the server sent, the file name is the server's (Content-Disposition), and the
 * response carried an ES256 X-ZS-Signature; the page's toast says "signed", the page has no horizontal scroll, and
 * no console error is logged. Every download's toast is screenshotted. The AI BOM's SPDX 3.0 and SARIF menu items
 * save GET /spdx and /sarif (review 6036875286).
 *
 * It drives a running app and API; it is not part of `next build` or of the *.test.ts unit tests (Playwright is not a
 * frontend dependency). Run from frontend/:
 *
 *   APP_URL=http://localhost:3489 API_URL=http://127.0.0.1:8489 TEAM=1 TOKEN=<access token> \
 *   SCANS=sbom_sca:9901,cbom:9903,ai_bom:9904 CHROME=/usr/bin/google-chrome node e2e/bom-download.e2e.mjs
 *
 * WIDTHS (default 1366,390) sets the viewports. Exit code 0 when every check passes; a JSON log and screenshots go to
 * $E2E_OUT (default /tmp/bom-download-e2e).
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const frontend = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const out = process.env.E2E_OUT ?? "/tmp/bom-download-e2e";
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

const APP = (process.env.APP_URL ?? "http://localhost:3489").replace(/\/$/, "");
const API = (process.env.API_URL ?? "http://127.0.0.1:8489").replace(/\/$/, "");
const TEAM = process.env.TEAM ?? "1";
const TOKEN = process.env.TOKEN ?? "";
assert.ok(TOKEN, "TOKEN (an access token for TEAM) is required");
const SCANS = (process.env.SCANS ?? "sbom_sca:9901,cbom:9903,ai_bom:9904").split(",").map((s) => {
  const [type, id] = s.split(":");
  return { type, id };
});
const WIDTHS = (process.env.WIDTHS ?? "1366,390").split(",").map(Number);
const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

/** What the server serves for a route: bytes, digest, file name and signature headers. */
async function served(route) {
  const res = await fetch(`${API}${route}`, { headers: { Authorization: `Bearer ${TOKEN}` } });
  assert.equal(res.status, 200, `${route}: HTTP ${res.status}`);
  const body = Buffer.from(await res.arrayBuffer());
  const disposition = res.headers.get("content-disposition") ?? "";
  return {
    sha: sha256(body),
    size: body.length,
    name: (/filename="([^"]+)"/.exec(disposition) ?? [])[1] ?? null,
    signature: res.headers.get("x-zs-signature"),
    headerSha: res.headers.get("x-cbom-sha256"),
  };
}

// the controls, per page: how to reach them and which route they must save
const CONTROLS = {
  sbom_sca: [
    { label: "Download SBOM", open: null, testid: "sbom-download-bom", route: "bom?format=json", toast: "CycloneDX SBOM" },
    { label: "BOM table: Download CycloneDX", open: null, testid: "sbom-download-cyclonedx", route: "bom?format=json",
      toast: "CycloneDX SBOM" },
    { label: "VEX", open: null, testid: "sbom-download-vex", route: "vex", toast: "VEX" },
  ],
  cbom: [
    { label: "CycloneDX JSON", open: null, testid: "cbom-download-json", route: "bom?format=json",
      toast: "CycloneDX CBOM JSON" },
    { label: "CycloneDX XML", open: null, testid: "cbom-download-xml", route: "bom?format=xml", toast: "CycloneDX XML" },
    // the code-mode CBOM page must render exactly as its snapshot (codeModeUnchanged.test.ts): no test id added there
    { label: "VEX", open: null, testid: null, button: "VEX", route: "vex", toast: "VEX" },
  ],
  ai_bom: [
    { label: "CycloneDX 1.6 (JSON)", open: "Download BOM", testid: "aibom-download-cyclonedx", route: "bom?format=json",
      toast: "AI BOM CycloneDX" },
    { label: "SPDX 3.0 (JSON-LD)", open: "Download BOM", testid: "aibom-download-spdx", route: "spdx", toast: "SPDX 3.0" },
    { label: "SARIF 2.1.0", open: "Download BOM", testid: "aibom-download-sarif", route: "sarif", toast: "SARIF 2.1.0" },
    { label: "VEX", open: "Download BOM", testid: "aibom-download-vex", route: "vex", toast: "VEX" },
  ],
};
const PAGE = { sbom_sca: "sbom_sca", cbom: "cbom", ai_bom: "ai_bom" };

const browser = await chromium.launch({
  executablePath: process.env.CHROME ?? "/usr/bin/google-chrome",
  headless: true,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
const log = [];
let failed = 0;
try {
  for (const width of WIDTHS) {
    const mobile = width < 500;
    const ctx = await browser.newContext({
      viewport: { width, height: mobile ? 844 : 900 },
      acceptDownloads: true,
      ...(mobile ? { isMobile: true, hasTouch: true, deviceScaleFactor: 2 } : {}),
    });
    await ctx.addInitScript(([token]) => {
      localStorage.setItem("access_token", token);
      localStorage.setItem("refresh_token", "e2e");
    }, [TOKEN]);
    for (const { type, id } of SCANS) {
      const page = await ctx.newPage();
      const errors = [];
      page.on("console", (m) => m.type() === "error" && errors.push(m.text().slice(0, 200)));
      await page.goto(`${APP}/${TEAM}/${PAGE[type]}/${id}/results`, { waitUntil: "domcontentloaded" });
      await page.waitForLoadState("networkidle", { timeout: 240000 });
      for (const control of CONTROLS[type]) {
        const rec = { width, type, scan: id, control: control.label };
        try {
          if (control.open) await page.getByRole("button", { name: control.open }).first().click();
          const target = control.testid
            ? page.locator(`[data-testid="${control.testid}"]`).first()
            : page.getByRole("button", { name: control.button, exact: true }).first();
          await target.waitFor({ state: "visible", timeout: 120000 });
          await target.scrollIntoViewIfNeeded();
          const [download] = await Promise.all([page.waitForEvent("download", { timeout: 60000 }), target.click()]);
          const file = path.join(out, `w${width}-${type}-${id}-${control.testid ?? control.button}`);
          await download.saveAs(file);
          const saved = fs.readFileSync(file);
          const server = await served(`/${TEAM}/${type}/scan/${id}/${control.route}`);
          Object.assign(rec, {
            file_name: download.suggestedFilename(), server_name: server.name,
            file_sha256: sha256(saved), server_sha256: server.sha, header_sha256: server.headerSha,
            bytes: saved.length, signature: server.signature === "unsigned" ? "unsigned" : server.signature ? "ES256" : null,
          });
          assert.equal(rec.file_sha256, server.sha, `${type} ${control.label}: the file is GET ${control.route}`);
          assert.equal(rec.file_sha256, server.headerSha, `${type} ${control.label}: X-Cbom-Sha256 names this file`);
          assert.equal(rec.file_name, server.name, `${type} ${control.label}: the server's file name`);
          assert.ok(server.signature && server.signature !== "unsigned", `${type} ${control.label}: X-ZS-Signature signs it`);
          // the page's one message says the file is signed (a warning toast would say unsigned / not stated)
          const toast = page.locator("[data-sonner-toast]", { hasText: `${control.toast} downloaded (signed ES256` });
          await toast.last().waitFor({ state: "visible", timeout: 15000 });
          rec.toast = (await toast.last().innerText()).replace(/\s+/g, " ").slice(0, 160);
          rec.toast_type = await toast.last().getAttribute("data-type");
          assert.equal(rec.toast_type, "success", `${type} ${control.label}: a signed file is a success toast`);
          await page.screenshot({ path: path.join(out, `w${width}-${type}-${control.testid ?? control.button}-toast.png`) });
          rec.overflow_px = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
          assert.ok(rec.overflow_px <= 0, `${type}: no horizontal scroll at ${width} px`);
          rec.ok = true;
        } catch (err) {
          rec.ok = false;
          rec.error = String(err?.message ?? err).slice(0, 300);
          failed += 1;
          await page.screenshot({ path: path.join(out, `fail-w${width}-${type}-${control.testid ?? control.button}.png`) });
        }
        await page.keyboard.press("Escape").catch(() => undefined);
        log.push(rec);
        console.log(JSON.stringify(rec));
      }
      if (errors.length) {  // a console error fails the run (review 6036875286 nit)
        log.push({ width, type, scan: id, console_errors: errors, ok: false });
        failed += 1;
      }
      await page.close();
    }
    await ctx.close();
  }
} finally {
  await browser.close();
  fs.writeFileSync(path.join(out, "bom-download.json"), JSON.stringify(log, null, 1));
}
console.log(failed ? `bom-download.e2e: ${failed} failed` : "bom-download.e2e: ok");
process.exit(failed ? 1 : 0);
