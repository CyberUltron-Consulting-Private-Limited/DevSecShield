import assert from "node:assert/strict";

import { tlsGradeReasons, tlsGradeText } from "./tlsGrade";

const b = { grade: "B*", letter: "B", score: 92, provisional: true, if_trusted: null,
  caps: ["TLS 1.0 / 1.1 offered"], warnings: ["TLS 1.3 not offered"], model: "ssllabs-2009r" };
assert.equal(tlsGradeText(b), "B* · score 92");
assert.equal(tlsGradeReasons(b), "TLS 1.0 / 1.1 offered; TLS 1.3 not offered");
assert.equal(tlsGradeText({ ...b, grade: "no TLS", letter: "-", score: null }), "no TLS");
assert.equal(tlsGradeText(null), "—");
assert.equal(tlsGradeReasons(undefined), "");
assert.equal(tlsGradeReasons({ ...b, caps: ["x"], warnings: ["x"] }), "x");
console.log("tlsGrade: tests passed");
