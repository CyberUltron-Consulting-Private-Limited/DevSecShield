import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { tlsGradeReasonList, tlsGradeReasons, tlsGradeText } from "./tlsGrade";

const b = { grade: "B*", letter: "B", score: 92, provisional: true, if_trusted: null,
  caps: ["TLS 1.0 / 1.1 offered"], warnings: ["TLS 1.3 not offered"], model: "ssllabs-2009r" };
assert.equal(tlsGradeText(b), "B* · score 92");
assert.equal(tlsGradeReasons(b), "TLS 1.0 / 1.1 offered; TLS 1.3 not offered");
assert.equal(tlsGradeText({ ...b, grade: "no TLS", letter: "-", score: null }), "no TLS");
assert.equal(tlsGradeText(null), "—");
assert.equal(tlsGradeReasons(undefined), "");
assert.equal(tlsGradeReasons({ ...b, caps: ["x"], warnings: ["x"] }), "x");
// review 6039899144 m6: the dialog prints each reason as a list item (touch screens cannot open a title tooltip)
assert.deepEqual(tlsGradeReasonList(b), ["TLS 1.0 / 1.1 offered", "TLS 1.3 not offered"]);
assert.deepEqual(tlsGradeReasonList({ ...b, caps: ["x"], warnings: ["x", "y"] }), ["x", "y"]);
assert.deepEqual(tlsGradeReasonList(null), []);
// source check (as pageWiring.test.ts): the endpoint dialog renders that list under the facts, not only the title
const dialog = readFileSync(join(__dirname, "RunFindingDialog.tsx"), "utf8");
assert.ok(dialog.includes('data-testid="run-finding-tls-reasons"'));
assert.ok(dialog.includes("tlsGradeReasonList(item.tls_grade).map((reason) => <li key={reason}>{reason}</li>)"));
console.log("tlsGrade: tests passed");
