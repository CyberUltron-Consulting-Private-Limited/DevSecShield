/**
 * PDF report options (plan §2, §7): the browser's copy of the contract must equal the server's. This test reads the
 * constants block of backend/utilities/pdf/report_options.py and compares every constant with utils/reportOptions.ts,
 * then checks the query the dialog sends, the text rule (the same checks and words as the server's `_text`) and the
 * remembered options (only preset, sections, label and the snippet switch; validated on load; storage failures ignored).
 * Run: npx --yes tsx@4.23.15 utils/reportOptions.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import * as RO from "./reportOptions";

// ---------------------------------------------------------------- parity with the backend constants block
const py = fs.readFileSync(path.join(__dirname, "../../backend/utilities/pdf/report_options.py"), "utf8");
const start = py.indexOf("# --- constants");
const end = py.indexOf("# --- end constants");
assert.ok(start > 0 && end > start, "the constants block of report_options.py");
const block = py.slice(py.indexOf("\n", start) + 1, end);

/** The block's assignments as JSON values: tuples become arrays, names refer to earlier constants. */
function parseConstants(src: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const lines = src.split("\n").filter((l) => !/^\s*#/.test(l));
  const chunks: { name: string; text: string }[] = [];
  for (const line of lines) {
    const m = /^([A-Z_][A-Z0-9_]*) = (.*)$/.exec(line);
    if (m) chunks.push({ name: m[1], text: m[2] });
    else if (chunks.length && line.trim()) chunks[chunks.length - 1].text += "\n" + line;
  }
  for (const { name, text } of chunks) {
    let json = text
      .replace(/\(/g, "[").replace(/\)/g, "]")
      .replace(/\b0x([0-9A-Fa-f]+)\b/g, (_m, hex: string) => String(parseInt(hex, 16)))
      .replace(/,(\s*[\]}])/g, "$1");
    for (const known of Object.keys(out)) json = json.replace(new RegExp(String.raw`(?<![A-Z_"])${known}(?![A-Z_"])`, "g"), JSON.stringify(out[known]));
    out[name] = JSON.parse(json);
  }
  return out;
}
const backend = parseConstants(block);
const NAMES = ["FAMILIES", "PRESETS", "SEVERITIES", "STATUSES", "LABELS", "LABEL_TEXT", "SCAN_SECTIONS", "RUN_SECTIONS",
  "PRESET_SECTIONS", "TYPE_SECTIONS", "FAMILY_KEYS", "PREPARED_FOR_MAX", "TITLE_MAX", "TEXT_RANGES",
  "STRIP_RANGES"] as const;
assert.deepEqual(Object.keys(backend).sort(), [...NAMES].sort(), "every backend constant is mirrored (a new one needs a copy here)");
for (const name of NAMES) {
  assert.deepEqual(JSON.parse(JSON.stringify(RO[name])), backend[name], `${name} differs from report_options.py`);
}
// the frontend block cites its source, so the info tips' `// src:` lines stay honest
const ts = fs.readFileSync(path.join(__dirname, "reportOptions.ts"), "utf8");
assert.match(ts, /\/\/ --- constants \(backend parity: backend\/utilities\/pdf\/report_options\.py\)/);

// ---------------------------------------------------------------- the query
const opts = (o: Partial<RO.ReportOptions> = {}): RO.ReportOptions => ({ ...RO.DEFAULT_OPTIONS, ...o });
assert.deepEqual(RO.toQuery(opts(), "scan", "sast"), {}, "defaults: no parameter (today's report)");
assert.deepEqual(RO.toQuery(opts({ sections: [...RO.TYPE_SECTIONS.sast] }), "scan", "sast"), {}, "every section of the type is the full report");
assert.deepEqual(RO.toQuery(opts({ preset: "executive", sections: RO.presetSections("scan", "executive", "cbom") }), "scan", "cbom"),
  { preset: "executive" }, "a preset alone when its sections are untouched");
assert.deepEqual(RO.toQuery(opts({ preset: null, sections: ["catalog", "summary"] }), "scan", "cbom"), { sections: "summary,catalog" },
  "custom sections, in the server's order");
assert.deepEqual(RO.toQuery(opts({ preset: "executive", sections: ["summary"] }), "scan", "cbom"), { preset: "executive", sections: "summary" },
  "explicit sections with a preset (sections win on the server)");
assert.deepEqual(RO.toQuery(opts({ severities: ["high", "critical"], statuses: ["in_progress", "not_started"] }), "scan", "sast"),
  { severities: "critical,high", statuses: "not_started,in_progress" });
assert.deepEqual(RO.toQuery(opts({ severities: [...RO.SEVERITIES], statuses: [...RO.STATUSES] }), "scan", "sast"), {}, "full sets: no filter");
assert.deepEqual(RO.toQuery(opts({ prepared_for: "  Acme Bank  ", title: "Q4 review", label: "internal", hide_evidence: true }), "scan", "iac"),
  { prepared_for: "Acme Bank", title: "Q4 review", label: "internal", hide_evidence: "true" });
// a family never gets a key it does not take (the server answers 422 for one)
const everything = opts({ preset: "technical", sections: ["summary"], severities: ["low"], statuses: ["fixed"], prepared_for: "A", title: "T", label: "public", hide_evidence: true });
for (const family of ["scan", "run", "deliverable"] as const) {
  const keys = Object.keys(RO.toQuery(everything, family, family === "scan" ? "sast" : null));
  for (const k of keys) assert.ok((RO.FAMILY_KEYS[family] as readonly string[]).includes(k), `${family} sent ${k}`);
}
assert.deepEqual(RO.toQuery(everything, "run"), { preset: "technical", sections: "summary", severities: "low", prepared_for: "A", title: "T", label: "public" });
assert.deepEqual(RO.toQuery(everything, "deliverable"), { prepared_for: "A", label: "public" });
// presets intersect with the type: an LLM scan has no notes, so technical is all of it
assert.deepEqual(RO.presetSections("scan", "technical", "llm"), [...RO.TYPE_SECTIONS.llm]);
assert.equal(RO.presetFor("scan", [...RO.TYPE_SECTIONS.llm], "llm"), "full");
assert.equal(RO.presetFor("scan", ["summary", "compliance"], "cbom"), "executive");
assert.equal(RO.presetFor("scan", ["summary", "details"], "cbom"), null);

// ---------------------------------------------------------------- the text rule (the server's _text)
const v = RO.validateText;
assert.deepEqual(v("prepared_for", "   "), { value: "", error: null }, "blank is not set");
assert.equal(v("prepared_for", "Société Générale – Zürich").error, null, "Latin-1 and the cp1252 extras (en dash) are fine");
assert.equal(v("title", "Q4 “final” report € 2026").error, null);
assert.equal(v("prepared_for", "x".repeat(120)).error, null);
assert.equal(v("prepared_for", "x".repeat(121)).error, "must be 120 characters or fewer");
assert.equal(v("title", "x".repeat(141)).error, "must be 140 characters or fewer");
assert.equal(v("prepared_for", "é".repeat(120)).error, null, "NFC first: é is one character");
assert.equal(v("prepared_for", "two\nlines").error, "must be one line of plain text");
assert.equal(v("prepared_for", "zero​width").error, "must be one line of plain text", "Cf");
assert.equal(v("prepared_for", "para graph").error, "must be one line of plain text", "Zp");
const SCRIPTS = "can only use Latin, Greek, Cyrillic or Devanagari characters";
assert.equal(v("prepared_for", "東京銀行").error, SCRIPTS, "CJK: no font for it");
assert.equal(v("prepared_for", "بنك").error, SCRIPTS, "Arabic");
assert.equal(v("prepared_for", "Acme 🏦").error, SCRIPTS, "emoji");
assert.equal(v("prepared_for", "Ϣ").error, SCRIPTS, "Coptic letters in the Greek block: no glyph");
// other scripts the report fonts draw (the server's TEXT_RANGES)
for (const ok of ["Łódź Bank", "Tiếng Việt", "Ελληνική Τράπεζα", "ПАО Сбербанк", "Қазақстан", "प्रबंधन क्षेत्र", "Acme बैंक",
  "महाराष्ट्र राज्य सहकारी बँक", "मऱ्याद", "₹ 500 crore", "x̃"]) {
  assert.equal(v("title", ok).error, null, ok);
}
assert.equal(v("prepared_for", "र्‍य").error, null, "ZWJ (Cf) is Devanagari spelling: allowed");
assert.equal(v("prepared_for", "क्‌ष").error, null, "ZWNJ too");
assert.equal(v("prepared_for", "a​b").error, "must be one line of plain text", "zero-width space is still refused");
assert.equal(v("prepared_for", "a⁠b").error, "must be one line of plain text", "word joiner (Cf) too");
assert.equal(v("prepared_for", "कि").value, "कि", "NFC");
assert.equal(RO.textSupported("Acme बैंक"), true);
// trimming is Python's str.strip(), not String.prototype.trim()
assert.deepEqual(v("prepared_for", "\u001cAcme\u0085\u001f"), { value: "Acme", error: null }, "U+001C-U+001F and U+0085 are stripped");
assert.deepEqual(v("prepared_for", "\u3000\u2028Acme\u00a0\u202f"), { value: "Acme", error: null });
assert.deepEqual(v("prepared_for", "\ufeffAcme"), { value: "\ufeffAcme", error: "must be one line of plain text" },
  "U+FEFF is not stripped (trim() would): refused, as by the server");
assert.equal(v("prepared_for", "Acme\ufeff").error, "must be one line of plain text");
assert.equal(RO.textLength(" \u0085Acme\u001c "), 4);
assert.equal(RO.pyStrip("\ufeff x \ufeff"), "\ufeff x \ufeff");
// a vowel sign or accent that follows no letter would print on a dotted circle
const STRAY = "has a vowel sign or accent that follows no letter";
for (const bad of ["ि", "िकल", "\u0900क", "\ua8e0क", "\ua8f1क", "\u0301abc", "Acme ि", "Acme (ं)", "5\u0303"]) {
  assert.equal(v("title", bad).error, STRAY, JSON.stringify(bad));
}
for (const ok of ["कि", "किं", "x\u0303", "Acme किं", "क\u093c\u093f", "e\u0301\u0302"]) assert.equal(v("title", ok).error, null, ok);
assert.equal(RO.textSupported("東"), false);
assert.equal(v("prepared_for", "x".repeat(121) + "\n").error, "must be 120 characters or fewer", "trimmed, then length first");
assert.equal(RO.textLength("  ab  "), 2);

// problems block the download
assert.deepEqual(RO.optionProblems(opts({ severities: [] }), "scan", "sast"), { severities: "Choose at least one severity" });
assert.deepEqual(RO.optionProblems(opts({ statuses: [] }), "scan", "sast"), { statuses: "Choose at least one status" });
assert.deepEqual(RO.optionProblems(opts({ statuses: [] }), "run"), {}, "a run takes no status filter");
assert.deepEqual(RO.optionProblems(opts({ sections: ["inventory"] }), "scan", "sast"), { sections: "Choose at least one section" }, "SAST has no inventory");
// review 6015786659: validation judges the same set the request is built from (remediation/mappings need details)
assert.deepEqual(RO.optionProblems(opts({ sections: ["remediation"] }), "scan", "sast"), { sections: "Choose at least one section" });
assert.deepEqual(RO.optionProblems(opts({ sections: ["remediation", "mappings"] }), "scan", "sast"), { sections: "Choose at least one section" });
assert.deepEqual(RO.optionProblems(opts({ sections: ["details", "remediation"] }), "scan", "sast"), {});
assert.deepEqual(RO.optionProblems(opts({ title: "東" }), "deliverable"), {}, "a deliverable takes no title");
assert.deepEqual(RO.optionProblems(opts({ prepared_for: "東" }), "deliverable"), { prepared_for: SCRIPTS });
assert.deepEqual(RO.optionProblems(opts({ prepared_for: "भारतीय स्टेट बैंक" }), "deliverable"), {});

// ---------------------------------------------------------------- remembered options
const store = new Map<string, string>();
const g = globalThis as Record<string, unknown>;
g.localStorage = { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, val: string) => void store.set(k, val), removeItem: (k: string) => void store.delete(k) };
RO.saveRemembered(7, "scan", opts({ preset: null, sections: ["summary", "catalog"], severities: ["low"], statuses: ["fixed"], prepared_for: "Acme", title: "T", label: "internal", hide_evidence: true }));
assert.deepEqual(JSON.parse(store.get("zs.export.v1.7.scan")!), { preset: null, sections: ["summary", "catalog"], label: "internal", hide_evidence: true },
  "only preset, sections, label and the snippet switch: never names, titles or filters");
const back = RO.initialOptions(7, "scan", "sast");
assert.deepEqual([back.preset, back.sections, back.label, back.hide_evidence, back.prepared_for, back.severities], [null, ["summary", "catalog"], "internal", true, "", null]);
RO.saveRemembered(7, "run", opts({ preset: "executive", hide_evidence: true, label: "public" }));
assert.deepEqual(JSON.parse(store.get("zs.export.v1.7.run")!), { preset: "executive", sections: null, label: "public" }, "a run has no snippet switch");
RO.saveRemembered(7, "deliverable", opts({ label: "restricted", prepared_for: "Acme" }));
assert.deepEqual(JSON.parse(store.get("zs.export.v1.7.deliverable")!), { label: "restricted" });
// validated on load: unknown values and shapes are dropped field by field
store.set("zs.export.v1.8.scan", JSON.stringify({ preset: "everything", sections: ["summary", "bogus"], label: "secret", hide_evidence: "yes", prepared_for: "x" }));
assert.deepEqual(RO.loadRemembered(8, "scan"), {});
store.set("zs.export.v1.8.scan", "{not json");
assert.deepEqual(RO.loadRemembered(8, "scan"), {});
store.set("zs.export.v1.8.scan", JSON.stringify(["array"]));
assert.deepEqual(RO.loadRemembered(8, "scan"), {});
// custom sections another type lacks fall back to every section of this type
store.set("zs.export.v1.9.scan", JSON.stringify({ preset: null, sections: ["inventory"] }));
assert.deepEqual(RO.initialOptions(9, "scan", "sast").sections, [...RO.TYPE_SECTIONS.sast]);
assert.equal(RO.initialOptions(9, "scan", "sast").preset, "full");
assert.deepEqual(RO.initialOptions(9, "scan", "sbom_sca").sections, ["inventory"]);
// a preset is expanded for the type that opens the dialog
store.set("zs.export.v1.9.scan", JSON.stringify({ preset: "executive" }));
assert.deepEqual(RO.initialOptions(9, "scan", "sast").sections, ["summary"], "SAST has no compliance section");
// storage that throws (denied, full) never breaks the dialog
g.localStorage = { getItem: () => { throw new Error("denied"); }, setItem: () => { throw new Error("full"); } };
assert.deepEqual(RO.loadRemembered(7, "scan"), {});
RO.saveRemembered(7, "scan", opts());
Object.defineProperty(g, "localStorage", { get() { throw new Error("SecurityError"); }, configurable: true });
assert.deepEqual(RO.loadRemembered(7, "scan"), {});
assert.equal(RO.initialOptions(7, "scan", "sast").preset, "full");

// deliverable cover: the label is remembered, the name only for this session
assert.equal(RO.deliverableCover(7).prepared_for, "");
RO.setSessionPreparedFor(7, "Acme Bank");
assert.equal(RO.deliverableCover(7).prepared_for, "Acme Bank");
assert.equal(RO.deliverableCover(8).prepared_for, "", "per team");
RO.setSessionPreparedFor(7, "");
assert.equal(RO.getSessionPreparedFor(7), "");

// the summary is words, never counts
for (const o of [opts(), everything, opts({ severities: ["critical"], statuses: ["not_started"] })]) {
  for (const family of ["scan", "run", "deliverable"] as const) {
    assert.doesNotMatch(RO.summaryText(o, family, "sast"), /\d/, `${family}: no numbers in the summary`);
  }
}
assert.equal(RO.summaryText(opts(), "scan", "sast"), "The full report, every severity.");

// Remediation and Standards mappings are drawn inside Finding details (QA 23 Nov): never sent without it
assert.deepEqual(RO.SECTION_NEEDS, { remediation: "details", mappings: "details" });
assert.deepEqual(RO.consistentSections(["summary", "catalog", "remediation", "mappings", "notes"]), ["summary", "catalog", "notes"]);
assert.deepEqual(RO.consistentSections(["details", "remediation"]), ["details", "remediation"]);
assert.deepEqual(RO.toQuery(opts({ preset: null, sections: ["summary", "catalog", "remediation", "mappings"] }), "scan", "sast"),
  { sections: "summary,catalog" }, "an inconsistent set is never sent");
assert.deepEqual(RO.toQuery(opts({ preset: null, sections: ["summary", "details", "mappings"] }), "scan", "sast"),
  { sections: "summary,details,mappings" });
const kept = new Map<string, string>();
Object.defineProperty(g, "localStorage", { configurable: true, value: { getItem: (k: string) => kept.get(k) ?? null, setItem: (k: string, val: string) => void kept.set(k, val), removeItem: (k: string) => void kept.delete(k) } });
kept.set(RO.rememberedKey(9, "scan"), JSON.stringify({ preset: null, sections: ["summary", "remediation", "mappings"] }));
assert.deepEqual(RO.initialOptions(9, "scan", "sast").sections, ["summary"], "a remembered inconsistent set is fitted");

console.log("reportOptions.test.ts: ok");
