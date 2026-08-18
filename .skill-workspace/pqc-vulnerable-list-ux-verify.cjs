/**
 * Headless verify for PQC vulnerable-list UX (temp route /pqc-vuln-verify).
 * Asserts Accordion grouping + filled HoverCard (Description / How to fix / Location).
 */
const { chromium } = require("/opt/homebrew/lib/node_modules/playwright");

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const consoleErrors = [];
  page.on("console", (msg) => {
    if (msg.type() !== "error") return;
    const t = msg.text();
    // Next 16 headless: HMR websocket noise when using 127.0.0.1
    if (t.includes("webpack-hmr") || t.includes("_next/webpack-hmr")) return;
    consoleErrors.push(t);
  });
  page.on("pageerror", (err) => consoleErrors.push(String(err)));

  await page.goto("http://localhost:3000/pqc-vuln-verify", {
    waitUntil: "domcontentloaded",
    timeout: 60000,
  });
  await page.waitForSelector('[data-testid="pqc-vulnerable-list"]', {
    timeout: 30000,
  });

  // Ensure large-list mode (legacy scan79 — no location on migration rows)
  await page.getByTestId("mode-scan79").click();
  await page.waitForTimeout(500);

  const statsText = await page.getByTestId("pqc-stats").innerText();
  const vulnGroups = await page.locator('[data-testid="pqc-vuln-group"]').count();
  const roadmapGroups = await page
    .locator('[data-testid="pqc-roadmap-group"]')
    .count();
  const vulnScroll = await page
    .locator('[data-testid="pqc-vulnerable-list"] .max-h-\\[28rem\\]')
    .count();

  // Expand first group via AccordionTrigger (data-slot)
  const trigger = page
    .locator(
      '[data-testid="pqc-vulnerable-list"] [data-testid="pqc-vuln-group"] [data-slot="accordion-trigger"]',
    )
    .first();
  await trigger.click();
  await page.waitForSelector(
    '[data-testid="pqc-vulnerable-list"] [data-testid="pqc-vuln-group"][data-state="open"] [data-testid="pqc-instance-row"]',
    { timeout: 10000 },
  );
  const instances = await page
    .locator('[data-testid="pqc-vulnerable-list"] [data-testid="pqc-instance-row"]')
    .count();

  // HoverCard fields must be filled (not Description — / How to fix —)
  const firstInstance = page
    .locator('[data-testid="pqc-vulnerable-list"] [data-testid="pqc-instance-row"]')
    .first();
  await firstInstance.hover({ force: true });
  await page.waitForSelector('[data-testid="pqc-instance-hover"]', {
    timeout: 10000,
  });
  const hoverDesc = (
    await page.getByTestId("pqc-hover-description").innerText()
  ).trim();
  const hoverFix = (await page.getByTestId("pqc-hover-fix").innerText()).trim();
  const hoverLoc = (
    await page.getByTestId("pqc-hover-location").innerText()
  ).trim();
  const hoverWhy = (await page.getByTestId("pqc-hover-why").innerText()).trim();

  let opened = null;
  const viewBtn = page.getByTestId("pqc-view-finding");
  if ((await viewBtn.count()) > 0) {
    await viewBtn.first().click({ force: true });
    await page.waitForTimeout(300);
    opened = await page
      .getByTestId("opened-finding")
      .innerText()
      .catch(() => null);
  }

  await page.getByTestId("mode-fixture").click();
  await page.waitForTimeout(400);
  const fixtureGroups = await page.locator('[data-testid="pqc-vuln-group"]').count();

  // Fixture mode HoverCard (normalize-enriched rows)
  const fixTrigger = page
    .locator(
      '[data-testid="pqc-vulnerable-list"] [data-testid="pqc-vuln-group"] [data-slot="accordion-trigger"]',
    )
    .first();
  // Fixture defaults expanded for small lists — ensure at least one open
  if (
    (await page
      .locator('[data-testid="pqc-vulnerable-list"] [data-testid="pqc-instance-row"]')
      .count()) === 0
  ) {
    await fixTrigger.click();
  }
  await page.waitForSelector(
    '[data-testid="pqc-vulnerable-list"] [data-testid="pqc-instance-row"]',
    { timeout: 10000 },
  );
  await page
    .locator('[data-testid="pqc-vulnerable-list"] [data-testid="pqc-instance-row"]')
    .first()
    .hover({ force: true });
  await page.waitForSelector('[data-testid="pqc-instance-hover"]', {
    timeout: 10000,
  });
  const fixtureDesc = (
    await page.getByTestId("pqc-hover-description").innerText()
  ).trim();
  const fixtureFix = (await page.getByTestId("pqc-hover-fix").innerText()).trim();
  const fixtureLoc = (
    await page.getByTestId("pqc-hover-location").innerText()
  ).trim();

  const hoverOk =
    hoverDesc.length > 1 &&
    hoverDesc !== "—" &&
    !/^Description\s*[—-]\s*$/i.test(hoverDesc) &&
    hoverFix.length > 1 &&
    hoverFix !== "—" &&
    hoverLoc.length > 0 &&
    hoverLoc !== "Location not recorded" &&
    /quantum/i.test(hoverWhy) &&
    fixtureDesc.length > 1 &&
    fixtureDesc !== "—" &&
    fixtureFix.length > 1 &&
    fixtureFix !== "—" &&
    fixtureLoc.length > 0 &&
    fixtureLoc !== "Location not recorded";

  const result = {
    ok:
      vulnGroups === 17 &&
      roadmapGroups === 17 &&
      instances >= 1 &&
      vulnScroll >= 1 &&
      fixtureGroups >= 1 &&
      Boolean(opened) &&
      hoverOk &&
      consoleErrors.length === 0,
    statsText,
    vulnGroups,
    roadmapGroups,
    instancesAfterExpand: instances,
    vulnScrollContainers: vulnScroll,
    openedFinding: opened,
    fixtureGroups,
    hoverCard: {
      why: hoverWhy,
      description: hoverDesc.slice(0, 180),
      howToFix: hoverFix.slice(0, 180),
      location: hoverLoc,
      fixtureDescription: fixtureDesc.slice(0, 120),
      fixtureHowToFix: fixtureFix.slice(0, 120),
      fixtureLocation: fixtureLoc,
      hoverOk,
    },
    consoleErrors,
  };
  console.log(JSON.stringify(result, null, 2));
  await browser.close();
  process.exit(result.ok ? 0 : 1);
})().catch((e) => {
  console.error(String(e));
  process.exit(2);
});
