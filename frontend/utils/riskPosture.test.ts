/**
 * One risk score across products (riskPosture.ts): the grade table is the engine's, the tiers sit on its bands, and
 * the SBOM, DAST, SAST and LLM list pages and results pages read the score from this one module instead of their own
 * 0-10 averages.
 * Run (frontend/): npx --yes tsx@4.23.15 --test utils/riskPosture.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import {
  RISK_GRADES,
  RISK_TIER_LABELS,
  gradeOf,
  matchesRiskTier,
  postureOf,
  postureScore,
  postureSortValue,
  postureStatus,
  riskCellHint,
  riskCellNote,
  riskCellText,
  riskScoreHint,
  riskScoreText,
  riskTone,
  triagePosture,
  triageScore,
} from "./riskPosture";

const repo = path.join(__dirname, "..", "..");
const read = (rel: string) => fs.readFileSync(path.join(repo, rel), "utf8");

test("the grade table is the engine's POSTURE_GRADES", () => {
  const engine = read("aibom/src/aibom/score/posture.py");
  const block = engine.slice(engine.indexOf("POSTURE_GRADES = ("), engine.indexOf("\n)\n", engine.indexOf("POSTURE_GRADES = (")));
  const rows = [...block.matchAll(/\((\d+), "([A-F])", "([a-z]+)"\)/g)].map((m) => [Number(m[1]), m[2], m[3]]);
  assert.deepEqual(rows, RISK_GRADES.map((g) => [g.floor, g.grade, g.band]));
  for (const g of RISK_GRADES) assert.equal(g.label, `${g.band[0].toUpperCase()}${g.band.slice(1)} risk`);
  // the backend helper every product's API and PDF reads
  assert.match(read("backend/utilities/dashboard/risk_scale.py"), /def posture\(impact_counts/);
});

test("grades and tiers on the bands", () => {
  assert.deepEqual([0, 14, 15, 29, 30, 49, 50, 69, 70, 100].map((s) => gradeOf(s).grade),
    ["A", "A", "B", "B", "C", "C", "D", "D", "F", "F"]);
  const tierOf = (s: number) => (["critical", "high", "medium", "low"] as const).filter((t) => matchesRiskTier(s, t));
  assert.deepEqual([0, 14, 15, 49, 50, 69, 70, 100].map(tierOf),
    [["low"], ["low"], ["medium"], ["medium"], ["high"], ["high"], ["critical"], ["critical"]]);
  assert.equal(matchesRiskTier(null, "low"), false);
  assert.equal(matchesRiskTier(null, "all"), true);
  assert.deepEqual(RISK_TIER_LABELS, { critical: "Critical (F, ≥70)", high: "High (D, 50–69)",
    medium: "Medium (B–C, 15–49)", low: "Low (A, <15)" });
});

test("postureOf reads risk_posture, or the CBOM's flat fields, never an older number", () => {
  const p = { score: 69, grade: "D", label: "High risk", band: "high" };
  assert.deepEqual(postureOf({ risk_posture: p, risk_score: 45 }), p);
  // the CBOM list row (PR #500): flat risk_score + risk_grade + risk_label
  assert.deepEqual(postureOf({ risk_score: 56, risk_grade: "D", risk_label: "High risk" }),
    { score: 56, grade: "D", label: "High risk", band: "high" });
  // the SAST list's weighted sum and the LLM card's 0-10 risk_score carry no grade: not a posture
  assert.equal(postureOf({ risk_score: 45 }), null);
  assert.equal(postureOf({ risk_posture: null }), null);
  assert.equal(postureOf(null), null);
  assert.equal(postureScore({ risk_posture: p }), 69);
  assert.equal(riskScoreText(postureOf({ risk_posture: p })), "69 · D");
  assert.equal(riskScoreText(null), "—");
  assert.equal(riskScoreHint(p), "of 100 · High risk");
  assert.equal(riskTone(69).icon, "text-red-500");
  assert.equal(riskTone(30).icon, "text-amber-500");
  assert.equal(riskTone(29).icon, "text-green-500");
});

test("a finished scan that cannot be scored reads incomplete; a failed or running one reads a dash; never A", () => {
  const p = { score: 0, grade: "A", label: "Low risk", band: "low" };
  assert.equal(riskCellText({ risk_posture: p, risk_posture_status: "scored" }), "0 · A");
  assert.equal(riskCellText({ risk_posture: null, risk_posture_status: "incomplete" }), "incomplete");
  assert.equal(riskCellHint({ risk_posture: null, risk_posture_status: "incomplete" }), "Scan incomplete: not enough to score");
  assert.equal(riskCellText({ risk_posture: null, risk_posture_status: "not_scored" }), "—");
  assert.equal(riskCellText({ risk_posture: null }), "—");
  assert.equal(postureStatus({ risk_posture: null, risk_posture_status: "incomplete" }), "incomplete");
  assert.equal(postureScore({ risk_posture: null, risk_posture_status: "incomplete" }), null);  // no filter tier keeps it
  for (const tier of ["critical", "high", "medium", "low"] as const) assert.equal(matchesRiskTier(null, tier), false);
});

test("round 2 (review 6064315680): a no-score status is never read from #500's flat CBOM fields", () => {
  // a failed CBOM scan after #500 merges: flat 0 / A next to the gate's not_scored
  const failed = { risk_score: 0, risk_grade: "A", risk_label: "Low risk", risk_posture: null, risk_posture_status: "not_scored" };
  assert.equal(postureOf(failed), null);
  assert.equal(riskCellText(failed), "—");
  assert.equal(postureScore(failed), null);
  // no status (an older backend with #500's fields only): the flat fields are still read
  assert.equal(postureOf({ risk_score: 56, risk_grade: "D" })?.score, 56);
});

test("round 2: guessed-version matches are flagged, and only-guessed scans keep a tier", () => {
  const unv = { risk_posture: { score: 100, grade: "F", label: "Critical risk", weighted: 100 }, risk_posture_status: "unverified",
                risk_unverified: { count: 10, worst: "critical" } };
  assert.equal(riskCellText(unv), "100 · F (unverified)");
  assert.equal(postureScore(unv), 100);
  assert.ok(matchesRiskTier(postureScore(unv), "critical"));
  assert.match(riskCellHint(unv) ?? "", /^worst case of guessed-version matches/);
  const noted = { risk_posture: { score: 4, grade: "A", label: "Low risk", weighted: 1 }, risk_posture_status: "scored",
                  risk_unverified: { count: 10, worst: "critical" } };
  assert.equal(riskCellText(noted), "4 · A");
  assert.equal(riskCellNote(noted), "unverified: 10 guessed-version matches (worst: Critical)");
  assert.equal(riskCellHint(noted), "of 100 · Low risk · unverified: 10 guessed-version matches (worst: Critical)");
  assert.equal(riskCellNote({ risk_unverified: null }), null);
});

test("round 2: the floor puts one Critical in the Critical tier, and the weighted sum breaks score ties", () => {
  assert.equal(gradeOf(70).grade, "F");
  assert.ok(matchesRiskTier(70, "critical"));
  const four = { risk_posture: { score: 69, grade: "D", label: "High risk", weighted: 20 } };
  const many = { risk_posture: { score: 69, grade: "D", label: "High risk", weighted: 5000 } };
  const critical = { risk_posture: { score: 70, grade: "F", label: "Critical risk", weighted: 10 } };
  assert.ok(postureSortValue(many) > postureSortValue(four));
  assert.ok(postureSortValue(critical) > postureSortValue(many));  // the score first
  assert.equal(postureSortValue({ risk_posture: null }), -1);
  for (const page of ["sbom_sca", "dast", "sast", "llm", "iac"]) {
    const src = read(`frontend/app/[team_id]/${page}/page.tsx`);
    assert.match(src, /const scoreA = postureSortValue\(a\);/, `${page}: sorts on the score then the weighted sum`);
  }
  assert.match(read("frontend/app/[team_id]/sbom_sca/page.tsx"), /riskCellNote\(conversation\)/);
});

test("round 3 (review 6065663183, 6): 1 confirmed Low + guessed Criticals is shown 4 · A and triaged as Critical", () => {
  const mixed = { risk_posture: { score: 4, grade: "A", label: "Low risk", weighted: 1 }, risk_posture_status: "scored",
                  risk_unverified: { count: 10, worst: "critical",
                                     worst_case: { score: 100, grade: "F", label: "Critical risk", weighted: 101 } } };
  // shown: the confirmed score and the note
  assert.equal(riskCellText(mixed), "4 · A");
  assert.equal(postureScore(mixed), 4);
  assert.equal(riskCellNote(mixed), "unverified: 10 guessed-version matches (worst: Critical)");
  // filter and sort: the higher of the two
  assert.equal(triageScore(mixed), 100);
  assert.equal(triagePosture(mixed)?.grade, "F");
  assert.ok(matchesRiskTier(triageScore(mixed), "critical"));
  assert.ok(!matchesRiskTier(triageScore(mixed), "low"));
  const confirmedF = { risk_posture: { score: 100, grade: "F", label: "Critical risk", weighted: 50 } };
  assert.ok(postureSortValue(mixed) > postureSortValue(confirmedF));  // 100 then weighted 101 > 50
  const plainHigh = { risk_posture: { score: 69, grade: "D", label: "High risk", weighted: 20 } };
  assert.ok(postureSortValue(mixed) > postureSortValue(plainHigh));
  // a lower worst case never lowers the shown score; no score stays no score
  const lower = { ...mixed, risk_unverified: { count: 1, worst: "low", worst_case: { score: 2, grade: "A", label: "Low risk" } } };
  assert.equal(triageScore(lower), 4);
  assert.equal(triageScore({ risk_posture_status: "not_scored", risk_unverified: mixed.risk_unverified }), null);
  assert.equal(triageScore({ risk_posture: { score: 50, grade: "D", label: "High risk" } }), 50);
  // the SBOM list filters on it
  assert.match(read("frontend/app/[team_id]/sbom_sca/page.tsx"), /return triageScore\(c\);/);
});

test("round 4 (review 6066492618): a CBOM's unconfirmed settings are unverified, in their own words", () => {
  const only = { risk_posture: { score: 70, grade: "F", label: "Critical risk", weighted: 10 }, risk_posture_status: "unverified",
                 risk_unverified: { count: 1, worst: "critical", kind: "unconfirmed_setting",
                                    worst_case: { score: 70, grade: "F", label: "Critical risk", weighted: 10 } } };
  assert.equal(riskCellText(only), "70 · F (unverified)");
  assert.equal(riskCellNote(only), "unverified: 1 unconfirmed setting (worst: Critical)");
  assert.match(riskCellHint(only) ?? "", /^worst case of unconfirmed settings/);
  const two = { ...only, risk_unverified: { ...only.risk_unverified, count: 2 } };
  assert.equal(riskCellNote(two), "unverified: 2 unconfirmed settings (worst: Critical)");
  // the backend says the same words
  assert.match(read("backend/utilities/dashboard/risk_scale.py"), /KIND_UNCONFIRMED: \("unconfirmed setting", "unconfirmed settings"\)/);
});

const PAGES = ["sbom_sca", "dast", "sast", "llm", "iac"] as const;

test("the SBOM, DAST, SAST and LLM list pages filter, sort, show and tile the one score", () => {
  for (const page of PAGES) {
    const src = read(`frontend/app/[team_id]/${page}/page.tsx`);
    assert.match(src, /from "@\/utils\/riskPosture"/, `${page}: imports the shared util`);
    assert.match(src, /matchesRiskTier\(/, `${page}: filters on the grade bands`);
    assert.match(src, /postureScore\(/, `${page}: sorts on the 0-100 score`);
    assert.match(src, /riskCellText\(/, `${page}: the table cell and tile say "56 · D" (or "incomplete")`);
    for (const tier of Object.keys(RISK_TIER_LABELS)) {
      assert.ok(src.includes(`{RISK_TIER_LABELS.${tier}}`), `${page}: the ${tier} filter item reads the shared label`);
    }
    // no page keeps its own 0-10 tiers or 0-10 rescaling
    assert.doesNotMatch(src, /score >= 9\b|Critical \(≥9\)|Math\.min\(10, Math\.max\(0, \(?(?:Number\()?(?:c|conversation)\.(?:average_)?risk_score/,
      `${page}: an own 0-10 score is left`);
    assert.doesNotMatch(src, /(?:average_risk_score|averageRiskScore)\} \/ 10|out of 10/, `${page}: a 0-10 risk score is left`);
  }
});

test("the MCP list page shows and tiles the one score (it has no risk filter)", () => {
  const src = read("frontend/app/[team_id]/mcp/page.tsx");
  assert.match(src, /from "@\/utils\/riskPosture"/);
  assert.match(src, /riskCellText\(conversation\)/);
  assert.match(src, /riskCellText\(card\)/);
  assert.doesNotMatch(src, /average_risk_score\} \/ 10|Number\(conversation\.average_risk_score\)/);
  assert.match(src, /risk_posture_trend/);
});

test("every results page shows the one score", () => {
  for (const file of ["SbomResults", "DASTResults", "SASTResults", "LLMResults", "IACResults", "MCPResults"]) {
    const src = read(`frontend/components/${file}.tsx`);
    assert.match(src, /from "@\/utils\/riskPosture"/, `${file}: imports the shared util`);
    assert.match(src, /postureOf\(|riskCellText\(/, `${file}: reads risk_posture`);
  }
  assert.doesNotMatch(read("frontend/components/MCPResults.tsx"), /\{cardData\.overall_risk_score \?\? "—"\}/);
});
