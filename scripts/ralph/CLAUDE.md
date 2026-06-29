# Ralph iteration — DevSecShield AIBOM + CBOM fix

You are ONE iteration of an autonomous loop with a FRESH context. Do exactly one story, well, then stop.

## Step 1 — Load state (always, first)
- Read `prd.json` (the stories), `progress.txt` (learnings from prior iterations), and `AGENTS.md` (conventions).
- Load the Ruflo memory contract: read keys `aibom/contract/*`, `cbom/contract/*`, `devsecshield/contract/*`, `devsecshield/rule/*`. These are the locked decisions — honor them exactly.

## Step 2 — Select ONE story
- Choose the story with the lowest `priority` number where `passes:false` AND every id in its `dependencies` has `passes:true`.
- State the chosen story id + title. If all stories are `passes:true`, output `<promise>COMPLETE</promise>` and stop.

## Step 3 — Implement only that story
- Scope discipline: implement ONLY this story. Do not expand or pull in other stories — Ralph handles those next iteration.
- Honor the contract (from Ruflo memory):
  - Lanes: scanners EMIT flags+edges; the scorer WEIGHTS from config; compliance checks QUERY the graph (never flags); reporters RENDER. Nothing crosses lanes.
  - Enrichment is DETERMINISTIC for the MVP (known-model KB + regex/AST) — the product ships NO runtime LLM. Keep a clean provider interface so the Anthropic API or Bedrock can be added later behind it; do not call any LLM from product code unless a story explicitly enables it. (Claude Code's own OAuth login is the agent — separate from, and unrelated to, the product.)
  - Product ships NO open-source BOM tool. OSS tools live only in the bench/ harness.
  - Compliance is TRI-STATE: out-of-scope ≠ not-BOM-evidenceable ≠ pass/fail. Never collapse them.
  - Frontend: MATCH the existing DevSecShield scanner theme/components/chart-lib/severity-palette. Never a new aesthetic.
  - CycloneDX is HAND-BUILT (modelCard for AIBOM, crypto-asset for CBOM) — the libs don't build these.
- Use skills for the story type: engineering skills (TDD test-first, anti-patterns = real ScanResult through the real normalizer, mock only true externals; systematic-debugging on failures); document/chart skills for reports/matrices; `dev-browser` to VERIFY any frontend story in the browser. Let Ruflo hooks auto-route; do not spawn a large swarm inside this single iteration.

## Step 4 — Quality gate (must be green)
- Run DevSecShield's typecheck + unit tests + the chart-data-contract tests + ruff + mypy.
- If anything fails, fix it within this iteration. If you cannot, REVERT your changes and append the blocker to `progress.txt` — never commit broken code (it compounds across iterations).

## Step 5 — Land it
- Commit with a conventional message scoped to the story (e.g., `feat(aibom): canonical model node + used-vs-catalog dedupe (A2)`).
- Set this story's `passes:true` in `prd.json` (commit that change too).
- Append a concise learning to `progress.txt` (pattern discovered, gotcha, file location).
- Update the relevant `AGENTS.md` with any discovered convention/gotcha — future fresh iterations rely on it.
- Persist a one-line state note to Ruflo memory: `memory_store "ralph/done/<story-id>" = "<what landed + key file>"`.

## Guardrails
- Do not break SBOM/SAST/DAST or the other scanner. Integration is additive.
- Do not use an open-source BOM tool anywhere in product code.
- One story per iteration. Then stop.
