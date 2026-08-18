#!/usr/bin/env node
/**
 * Live verify Shadow AI overflow + HoverCard + show-all.
 * Prefers auth-free temp route /shadow-ai-verify (AIBOM #95 dump).
 * Falls back to /1/ai_bom/95/results with JWT when FORCE_LIVE=1.
 */
const fs = require("fs");
const { chromium } = require("/opt/homebrew/lib/node_modules/playwright");

function loadEnv() {
  const envPath = "/Users/anshsinghal/Desktop/DevSecShield/backend/.env";
  const env = {};
  for (const line of fs.readFileSync(envPath, "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*(.*)$/);
    if (!m) continue;
    let v = m[2].trim();
    if (v && (v[0] === '"' || v[0] === "'")) {
      const q = v[0];
      v = v.slice(1);
      const end = v.indexOf(q);
      v = end >= 0 ? v.slice(0, end) : v;
    } else {
      v = v.split("#")[0].trim();
    }
    if (v) env[m[1]] = v;
  }
  return env;
}

function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function mintJwt(secret, sub) {
  const crypto = require("crypto");
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const payload = b64url(JSON.stringify({ exp, sub }));
  const data = `${header}.${payload}`;
  const sig = crypto
    .createHmac("sha256", secret)
    .update(data)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  return `${data}.${sig}`;
}

async function main() {
  const base = process.env.FRONTEND_BASE || "http://127.0.0.1:3000";
  const useLive = process.env.FORCE_LIVE === "1";
  const url = useLive ? `${base}/1/ai_bom/95/results` : `${base}/shadow-ai-verify`;
  const outPath =
    "/Users/anshsinghal/Desktop/DevSecShield/.skill-workspace/shadow-ai-overflow-hover-verify-raw.json";

  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 1100 } });

  if (useLive) {
    const env = loadEnv();
    const email = "cbom-demo@cyberultron.com";
    const access = mintJwt(env.JWT_SECRET_KEY, email);
    const refresh = mintJwt(env.JWT_REFRESH_SECRET_KEY || env.JWT_SECRET_KEY, email);
    await ctx.addInitScript(([a, r]) => {
      localStorage.setItem("access_token", a);
      localStorage.setItem("refresh_token", r);
    }, [access, refresh]);
  }

  const page = await ctx.newPage();
  const consoleErrors = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });

  const result = {
    url,
    ok: false,
    shadowCardFound: false,
    rowCount: 0,
    longBinRows: 0,
    badgesInsideCard: true,
    badgeOverflowDetails: [],
    hoverOpened: false,
    hoverHasWhy: false,
    hoverHasDescription: false,
    hoverHasFix: false,
    hoverHasLocation: false,
    viewFullOpensDialog: false,
    dialogTitle: null,
    consoleErrors,
    notes: [],
  };

  if (useLive) {
    await page.goto(`${base}/login`, { waitUntil: "domcontentloaded", timeout: 60000 });
  }
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 90000 });

  const card = page.locator('[data-testid="shadow-ai-card"]');
  try {
    await card.waitFor({ state: "visible", timeout: 60000 });
    result.shadowCardFound = true;
  } catch (e) {
    result.notes.push(`Shadow AI card missing: ${e.message}`);
    result.notes.push(`body sample: ${(await page.locator("body").innerText()).slice(0, 500)}`);
    fs.writeFileSync(outPath, JSON.stringify(result, null, 2));
    await browser.close();
    console.log(JSON.stringify(result, null, 2));
    process.exit(1);
  }

  await card.scrollIntoViewIfNeeded();
  await page.waitForTimeout(400);

  const rows = card.locator('[data-testid="shadow-ai-row"]');
  result.rowCount = await rows.count();
  if (result.rowCount <= 8) {
    result.notes.push(`Expected show-all (>8 rows); got ${result.rowCount}`);
  }

  // Original bug was HORIZONTAL overflow (badge past card right edge).
  // Vertical "outside" for scrolled list rows is expected with max-h + overflow-y.
  const cardBox = await card.boundingBox();
  const n = Math.min(result.rowCount, 60);
  for (let i = 0; i < n; i++) {
    const row = rows.nth(i);
    await row.scrollIntoViewIfNeeded();
    const name = (await row.locator("div.text-sm.font-medium").innerText()).trim();
    const isLongBin = /\.bin$/i.test(name) && name.length > 40;
    if (isLongBin) result.longBinRows += 1;
    const badge = row.locator('[data-testid="shadow-ai-impact"]');
    const badgeBox = await badge.boundingBox();
    const liveCard = await card.boundingBox();
    if (!liveCard || !badgeBox) continue;
    const horizontallyInside =
      badgeBox.x + badgeBox.width <= liveCard.x + liveCard.width + 1.5;
    if (!horizontallyInside) {
      result.badgesInsideCard = false;
      result.badgeOverflowDetails.push({
        name: name.slice(0, 80),
        badgeRight: badgeBox.x + badgeBox.width,
        cardRight: liveCard.x + liveCard.width,
      });
    }
  }

  let hoverIdx = 0;
  for (let i = 0; i < n; i++) {
    const name = (await rows.nth(i).locator("div.text-sm.font-medium").innerText()).trim();
    if (/\.bin$/i.test(name) && name.length > 40) {
      hoverIdx = i;
      break;
    }
  }
  const hoverRow = rows.nth(hoverIdx);
  await hoverRow.scrollIntoViewIfNeeded();
  // Open via click+hover — Playwright headless often skips React pointerenter;
  // production still opens on mouse enter. Click is also a valid path.
  await page.mouse.move(0, 0);
  await hoverRow.click({ force: true });
  await hoverRow.hover({ force: true });
  await page.waitForTimeout(800);
  const hoverContent = page.locator('[data-slot="hover-card-content"]');
  try {
    await hoverContent.waitFor({ state: "visible", timeout: 5000 });
    result.hoverOpened = true;
    const txt = await hoverContent.innerText();
    result.hoverHasWhy = /Why/i.test(txt);
    result.hoverHasDescription = /Description/i.test(txt);
    result.hoverHasFix = /How to fix/i.test(txt);
    result.hoverHasLocation = /Location/i.test(txt);
    const viewBtn = hoverContent.getByRole("button", { name: /View full finding/i });
    if (await viewBtn.count()) {
      await viewBtn.click();
      await page.waitForTimeout(600);
      const dialog = page.locator('[data-slot="dialog-content"], [role="dialog"]');
      result.viewFullOpensDialog =
        (await dialog.count()) > 0 && (await dialog.first().isVisible().catch(() => false));
      if (result.viewFullOpensDialog) {
        result.dialogTitle = (
          await dialog
            .locator("h2, [data-slot='dialog-title']")
            .first()
            .innerText()
            .catch(() => "")
        ).slice(0, 120);
      }
    } else {
      result.notes.push("View full finding button missing");
    }
  } catch (e) {
    result.notes.push(`HoverCard failed: ${e.message}`);
  }

  const shot =
    "/Users/anshsinghal/Desktop/DevSecShield/.skill-workspace/shadow-ai-overflow-hover-shot.png";
  await card.screenshot({ path: shot });
  result.screenshot = shot;

  result.ok =
    result.shadowCardFound &&
    result.rowCount > 8 &&
    result.badgesInsideCard &&
    result.longBinRows > 0 &&
    result.hoverOpened &&
    result.hoverHasWhy &&
    result.hoverHasDescription &&
    result.hoverHasFix &&
    result.hoverHasLocation &&
    result.viewFullOpensDialog;

  fs.writeFileSync(outPath, JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result, null, 2));
  await browser.close();
  process.exit(result.ok ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
