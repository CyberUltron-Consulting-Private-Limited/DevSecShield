/**
 * #36: two numbers on the SAST dashboard (app/[team_id]/sast/page.tsx) did not say what they showed.
 * 1. "0% Fix Rate" under the Average Risk Score gauge was hard-coded text. It is now the findings marked Fixed as a
 *    whole percent of all stored findings of the team's SAST scans (the list dashboard sends both counts:
 *    backend/utilities/dashboard/scan_list.py, fixed_findings and total_findings), a dash when there are none, and its
 *    tooltip says what counts as fixed.
 * 2. "Policy Compliance" showed each standard's share of the compliance-control references as if it were a pass rate:
 *    a green tick at 90 % or more, a red cross under 70 %, and an "Overall Compliance Score" that was the mean of the
 *    shares (one standard alone gave a green 100 %). The card now says what the number is, with no pass/fail icons
 *    and no overall score.
 * Failing-first on origin/dev dd9c2293: the page still said "0% Fix Rate".
 * Browser check: SAST > Dashboard: with 2 of 6 findings marked Fixed the gauge says "33% Fix Rate" and its tooltip
 * "2 of 6 findings ..."; a team without findings sees "— Fix Rate"; the Policy Compliance rows read
 * "N references · X% of all" without icons.
 * Run: npx --yes tsx@4.23.15 utils/fixRate.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const root = path.join(__dirname, "..");
const read = (rel: string) => fs.readFileSync(path.join(root, rel), "utf8");

async function main() {
  // 1. the page: no hard-coded fix rate; the computed one, with its tooltip
  const page = read("app/[team_id]/sast/page.tsx");
  assert.ok(!page.includes("0% Fix Rate"), 'the page still shows the hard-coded "0% Fix Rate"');
  assert.ok(page.includes("{fixRateText(dashboardData.fixed_findings, dashboardData.total_findings)} Fix Rate"),
    "the gauge shows the computed fix rate");
  assert.ok(page.includes("title={fixRateTitle(dashboardData.fixed_findings, dashboardData.total_findings)}"),
    "the fix rate says what counts as fixed");

  // 2. the Policy Compliance card: what the number is, no pass/fail icons, no overall score
  const card = page.slice(page.indexOf("{/* Policy Compliance */}"), page.indexOf("{/* Top Repositories by Risk */}"));
  assert.ok(card.length > 0, "the Policy Compliance card");
  assert.ok(card.includes("<CardDescription>Share of compliance-control references in findings</CardDescription>"), card);
  assert.ok(card.includes("{p.violations} references · {p.compliance}% of all"), "each row says what it counts");
  for (const icon of ["CheckCircle", "AlertTriangle", "XCircle"]) {
    assert.ok(!card.includes(`<${icon} `), `the card draws a pass/fail ${icon} for a share`);
  }
  assert.ok(!page.includes("Overall Compliance Score") && !page.includes("overallComplianceScore"),
    "the mean of the shares is shown as a score");
  // its (i) tip no longer explains an overall score
  const tips = read("content/infotips/text/sast.ts");
  const policy = tips.slice(tips.indexOf('"sast.chart.policy": {'), tips.indexOf("},", tips.indexOf('"sast.chart.policy": {')));
  assert.ok(policy.includes("It is not a pass rate") && !/overall/i.test(policy), policy);

  // 3. the numbers the page reads come from the list dashboard
  const api = read("utils/backend_api.ts");
  const type = api.slice(api.indexOf("export interface ScanListDashboardData {"), api.indexOf("export interface SastListResponse"));
  assert.ok(/\bfixed_findings\?: number/.test(type) && /\btotal_findings\?: number/.test(type), type);
  const backend = fs.readFileSync(path.join(root, "..", "backend", "utilities", "dashboard", "scan_list.py"), "utf8");
  const sast = backend.slice(backend.indexOf("def generate_sast_dashboard_data"), backend.indexOf("def generate_sbom_sca_dashboard_data"));
  // (what they count is tested in backend/tests/test_sast_dashboard_fix_rate.py)
  assert.ok(/"fixed_findings": /.test(sast) && sast.includes('"total_findings": len(findings)'),
    "the SAST list dashboard sends both counts");

  // 4. the text: a whole percent of all findings, a dash without findings (or from a server that sends no counts)
  const { fixRateText, fixRateTitle } = await import("./fixRate");
  assert.equal(fixRateText(2, 6), "33%");
  assert.equal(fixRateText(0, 5), "0%");
  assert.equal(fixRateText(5, 5), "100%");
  assert.equal(fixRateText(1, 200), "1%", "rounded, not floored to 0");
  assert.equal(fixRateText(0, 0), "—");
  assert.equal(fixRateText(undefined, undefined), "—");
  assert.equal(fixRateText(3, undefined), "—");
  assert.equal(fixRateText(9, 4), "100%", "never above 100%");
  const title = fixRateTitle(2, 6);
  assert.match(title, /^2 of 6 findings are marked Fixed\./);
  assert.match(title, /marked Fixed on its scan's results page/);
  assert.match(title, /Ignored and In progress findings do not count/);
  assert.match(fixRateTitle(1, 1), /^1 of 1 finding is marked Fixed\./);
  assert.match(fixRateTitle(0, 0), /^No findings yet\./);
  assert.match(fixRateTitle(undefined, undefined), /^No findings yet\./);

  console.log("SAST fix rate and policy share: tests passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
