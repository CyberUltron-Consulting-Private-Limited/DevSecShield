/**
 * Hermetic tests for modelCardDisplay helpers.
 * Run: npx --yes tsx components/ai-bom/modelCardDisplay.test.ts
 */
import assert from "node:assert/strict";
import {
  buildModelCandidates,
  fillModelCardRows,
  pickDefaultModel,
  rowsHaveNoBlanks,
  type Json,
} from "./modelCardDisplay";

function bom(models: Json[]): Json {
  return { components: models };
}

const emptyCatalog = {
  type: "machine-learning-model",
  name: "babbage-002",
  "bom-ref": "babbage-002",
};
const richInventory = {
  type: "machine-learning-model",
  name: "gpt-4",
  "bom-ref": "gpt-4",
  modelCard: {
    modelParameters: {
      task: "chat/completion",
      architectureFamily: "transformer",
      modelArchitecture: "GPT (proprietary)",
    },
  },
};
const thinInventory = {
  type: "machine-learning-model",
  name: "whisper-1",
  "bom-ref": "whisper-1",
};

const findings: Json[] = [
  { asset_name: "gpt-4", asset_type: "local_model_file" },
  { asset_name: "whisper-1", asset_type: "local_model_file" },
];

{
  const cands = buildModelCandidates(
    bom([emptyCatalog, richInventory, thinInventory]),
    findings,
  );
  assert.equal(cands.length, 2, "selector uses inventory intersection only");
  assert.ok(!cands.some((c) => c.name === "babbage-002"));
  const pick = pickDefaultModel(cands);
  assert.ok(pick);
  assert.equal(pick.candidate.name, "gpt-4");
  assert.match(pick.reason, /richest BOM model card/);
}

{
  const rows = fillModelCardRows(emptyCatalog);
  assert.ok(rowsHaveNoBlanks(rows));
  assert.equal(rows.cardSource, "Inferred from model identity");
  assert.equal(rows.version, "Unspecified");
}

{
  const rows = fillModelCardRows(richInventory);
  assert.ok(rowsHaveNoBlanks(rows));
  assert.equal(rows.cardSource, "BOM modelCard");
  assert.equal(rows.task, "chat/completion");
}

{
  const rows = fillModelCardRows(thinInventory);
  assert.ok(rowsHaveNoBlanks(rows));
  assert.equal(rows.task, "speech-to-text");
}

{
  // No inventory → fall back to models with cards, not empty first catalog entry
  const cands = buildModelCandidates(
    bom([emptyCatalog, richInventory]),
    [],
  );
  assert.ok(cands.every((c) => c.hasCard || c.name === "gpt-4"));
  const pick = pickDefaultModel(cands);
  assert.equal(pick?.candidate.name, "gpt-4");
}

console.log("modelCardDisplay.test.ts: all assertions passed");
