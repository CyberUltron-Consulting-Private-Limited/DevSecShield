# Ralph iteration — DevSecShield CBOM: best-of-all clean-room CBOM

You are ONE iteration of an autonomous loop with a FRESH context. Do exactly one story, well, then stop.

## Mission
Make DevSecShield's CBOM the single best crypto-BOM scanner in the world by studying EVERY leading
open-source CBOM tool, distilling their best techniques/features, and **clean-room re-implementing**
them into DevSecShield's own CBOM lane — backend AND frontend. You are EXTENDING the existing CBOM
lane (`aibom/src/aibom/cbom/` + the worker route + `frontend/components/CbomResults.tsx`), never
rebuilding from scratch.

## ⛔ Non-negotiable LEGAL/ARCHITECTURE constraint (read every iteration)
- **The product ships ZERO open-source BOM/crypto tooling.** No importing, vendoring, copying, forking,
  shelling out to, or bundling any OSS tool (IBM CBOMkit/cbomkit-theia, Sonar-Cryptography, AWS
  cryptobom-forge, liboqs, OpenSSL CLI, semgrep, etc.) anywhere in PRODUCT code.
- **Techniques and features may be re-implemented clean-room** — learn the *behavior/spec* from public
  docs, papers, the CycloneDX schema, and tool OUTPUT, then write OUR OWN original implementation.
  Never read-and-paste their source. Capture provenance in the research ledger (Step 3) so every
  capability traces to a public-spec/behavioral source, not copied code.
- **OSS tools are allowed ONLY as benchmark oracles inside `bench/cbom/`** (already wired vs IBM
  cbomkit-theia). They run in the isolated harness to measure parity/recall — NEVER on the product
  import path. Adding a new oracle is fine; shipping one is forbidden.
- **No runtime LLM in product.** Enrichment is deterministic (rules/AST/known-crypto KB) behind a clean
  provider interface. (Claude Code's own login is the agent, separate from the product.)

## Step 1 — Load state (always first)
- Read `prd.json` (stories), `progress.txt` (prior-iteration learnings + gotchas — esp. worker-restart,
  Turbopack-404, dev-browser JWT), `AGENTS.md` (conventions), and `docs/cbom-research/LEDGER.md`
  (clean-room provenance ledger; create it if missing).
- Load the Ruflo memory contract: keys `cbom/contract/*`, `aibom/contract/*`, `devsecshield/contract/*`,
  `devsecshield/rule/*`. These are locked decisions — honor them exactly.
- Re-read the CBOM lane so you extend, not duplicate: `aibom/src/aibom/cbom/` (`pipeline.py:scan_crypto`,
  `scanners/`, `compliance.py`, `pqc.py`, `x509.py`, `normalize.py`, `scorer.py`, `registry.py`,
  `weakness.py`, `rules.py`), the worker route `RabbitMQ/worker/helpers/tools/cbom_agent/`, and the
  frontend `frontend/components/CbomResults.tsx`, `frontend/components/cbom/CbomCryptoCharts.tsx`,
  `frontend/components/cbom-options-sidebar.tsx`.

## Step 2 — Select ONE story
- Pick the lowest-`priority` story with `passes:false` whose `dependencies` are all `passes:true`.
- State the chosen story id + title.
- RESEARCH stories (web → distil → ledger → capability gap-list) and BUILD stories (clean-room
  implement one capability + tests + benchmark + frontend wiring) alternate. A BUILD story depends on
  the RESEARCH story that justified it.
- If a research story uncovers more capabilities than its BUILD stories cover, APPEND new BUILD stories
  to `prd.json` (so the backlog grows from evidence).
- COMPLETION: only when EVERY story is `passes:true` AND the full gate is green — backend
  (`aibom` cbom/crypto unit + chart-data-contract + compliance tri-state + `bench/cbom` differential
  gate vs the OSS oracles + ruff + mypy) AND frontend (tsc/build + dev-browser verification of the
  CBOM results page) — output exactly `<promise>COMPLETE and tested from frontend and backend</promise>`
  and stop. Otherwise do the next story.

## Step 3 — RESEARCH lane (for research stories)
Use WebSearch/WebFetch to study the best-in-class OSS CBOM tools and the underlying standards. Targets:
- **Tools to dissect (as oracles + technique sources):** IBM CBOMkit & cbomkit-theia (Sonar-Cryptography
  engine; source AST scan + filesystem cert/key/secret), the Sonar-Cryptography detection-rule DSL,
  AWS cryptobom-forge (CBOM aggregation + dependency graph + CI), Open Quantum Safe / liboqs surface,
  and any newer crypto-inventory / crypto-agility scanners you find.
- **Coverage to chase (where we're weakest vs them):** source-AST crypto-API detection across
  Java/Python/Go/JS-TS/C-C++/Rust/.NET; library/API→asset mapping (OpenSSL/BoringSSL, BouncyCastle,
  PyCA cryptography/pyOpenSSL, Go crypto, Node crypto/WebCrypto, libsodium/NaCl, JCA/JCE,
  .NET System.Security.Cryptography, RustCrypto/ring); certificate depth (x509 fields, chain, expiry,
  weak sig algos, key size); protocols (TLS/SSH/IPsec versions + cipher suites); related-crypto-material
  (keys, secrets, IVs, salts, nonces, tokens); weakness analysis (MD5/SHA-1/DES/3DES/RC4, RSA<2048, ECB,
  static IV/nonce, hardcoded keys, weak RNG); PQC grading (`nistQuantumSecurityLevel`, quantum-vulnerable
  RSA/ECC/DH/DSA flagging, ML-KEM/ML-DSA/SLH-DSA readiness, hybrid, migration roadmap).
- **Standards to encode:** CycloneDX 1.6 cryptoProperties (assetType + algorithm/certificate/protocol/
  relatedCryptoMaterial properties, cryptoRefArray, dependency graph) / ECMA-424; NIST SP 1800-38B/C,
  SP 800-57, FIPS 140-3, FIPS 203/204/205, CNSA 2.0 timeline, OMB M-23-02, EU CRA, DORA, PCI-DSS 4.0
  crypto reqs, BSI TR-02102.
- **Output of a research story:** append to `docs/cbom-research/LEDGER.md` one row per technique:
  `capability | source tool | public-spec/behavioral evidence (URL) | how WE will re-implement (original) |
  gap vs our current lane | proposed BUILD story`. Then add the resulting BUILD stories to `prd.json`.
  NOTHING in the ledger may be copied code — spec/behavior + our original design only.

## Step 4 — BUILD lane (for build stories) — honor the lanes
- **Scanners EMIT** crypto-asset components + flags + edges (never score). Add/extend a clean-room
  scanner under `aibom/src/aibom/cbom/scanners/`, registered in `registry.py`.
- **Scorer WEIGHTS** from config (nistQuantumSecurityLevel + weakness bands → severity). Compliance
  never reads flags.
- **Compliance QUERIES the graph** (tri-state: pass/fail/out_of_scope/not_bom_evidenceable/
  pass_with_evidence; coverage = pass/(pass+fail)). Add frameworks per the standards above.
- **CycloneDX is HAND-BUILT** (crypto-asset; the libs don't emit these). Keep schema-valid 1.6.
- **Worker:** route `RabbitMQ/worker` cbom task through the extended aibom lane (no logic in the worker).
- **Frontend:** EXTEND `CbomResults.tsx` + `cbom/CbomCryptoCharts.tsx` + `cbom-options-sidebar.tsx`.
  MATCH the existing DevSecShield scanner theme/components/chart-lib/severity-palette — never a new
  aesthetic. Surface every new capability (asset types, PQC gauge, weakness breakdown, compliance
  tri-state, dependency graph) through the existing scan-metadata → results-page contract.
- TDD: write tests FIRST against REAL fixtures (extend `aibom/tests/fixtures/synthetic-crypto-app` and
  add real-repo fixtures). Never mock `ScanResult`/the graph. Benchmark each capability in `bench/cbom/`
  vs the OSS oracle and assert the differential gate (true-miss==0, our-unique>0) still holds.

## Step 5 — Quality gate (must be green)
- Backend: `aibom` cbom/crypto unit tests + chart-data-contract + compliance tri-state + `bench/cbom`
  differential gate + `ruff` + `mypy`.
- Frontend: `tsc --noEmit` (+ `npm run build` if touched) + dev-browser render of the CBOM results page.
  Use the documented gotchas: restart the worker after any worker/aibom change; `rm -rf frontend/.next`
  if a results route 404s; mint the JWT via the backend's `create_access_token` (not a hand-rolled JWT);
  assert on `document.body.innerText` for the 404 check.
- If anything fails, fix it this iteration. If you can't, REVERT and append the blocker to `progress.txt`.
  Never commit broken code — it compounds across fresh contexts.

## Step 6 — Land it
- Conventional commit scoped to the story, e.g. `feat(cbom): clean-room AST crypto-API scanner for Go/Rust (C3)`.
- Set the story `passes:true` in `prd.json` (commit that too).
- Append a concise learning/gotcha to `progress.txt`; update `AGENTS.md` with any new convention.
- Update `docs/cbom-research/LEDGER.md` provenance row to "implemented" with the file path + oracle delta.
- Persist a Ruflo note: `memory_store "ralph/done/<story-id>" = "<what landed + key file + oracle delta>"`.

## Guardrails
- ONE story per iteration, then stop. Scope discipline — don't pull in other stories.
- Do NOT break SBOM/SAST/DAST/AIBOM. Integration is additive.
- NEVER ship/import/vendor an OSS BOM tool in product. Oracles live only in `bench/cbom/`.
- Every shipped capability must trace to a clean-room ledger row (spec/behavior source, original code).
- Keep it deterministic; no runtime LLM in product. Match the existing frontend aesthetic.
