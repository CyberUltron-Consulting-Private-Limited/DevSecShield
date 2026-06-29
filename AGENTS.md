# DevSecShield BOM scanners — conventions

- Scanners self-register via a registry pattern; adding a scanner/reporter/check/scan-level is ONE file.
- ScanResult { components, edges, flags, scores, compliance } flows scanners → scorer → checks → reporters. Graph helpers: by_ref / out_edges / neighbors.
- Healthcare/crypto-specific data goes in namespaced `properties` (clinical:/regulatory:/dataset:/crypto:), never non-spec top-level keys.
- CycloneDX is hand-built (AIBOM modelCard; CBOM crypto-asset). Validate every emitted BOM against its bundled schema in CI — a schema-invalid BOM is a build failure.
- Frontend: reuse the existing scanner components, theme tokens, chart library, and severity palette. The existing SBOM/SAST/DAST pages are the style authority.
- Compliance verdicts are tri-state: OUT_OF_SCOPE / NOT_BOM_EVIDENCEABLE / pass-fail. Coverage% = pass/(pass+fail); the other two are reported as their own counts.
- Enrichment is deterministic (known-model KB + regex/AST); the product ships NO runtime LLM. A provider interface allows adding the Anthropic API or Bedrock later — but product code must not call an LLM unless a story enables it. (Claude Code's OAuth login is the agent, unrelated to the product.)

## Discovered conventions / gotchas (append below)
- The standalone AIBOM engine lives at `aibom/` (uv package, src layout). The locked finding schema is STRICT — `test_every_finding_matches_the_locked_finding_schema` fails on any extra key; to exclude something from the dashboard drop it from the findings LIST (the adapter's `_inventory()`), never tag the finding.
- `aibom emit` CLI scans at LEVEL 1; the product runs at LEVEL 4 (`scan_to_devsecshield(level=4)`). A new deep scanner (cloud-iac, code-import) at level ≥2 won't affect the L1 emit goldens but DOES affect L4 (dashboard, benchmark, differential test).
- `model_refs.py` (MODEL_RE) is the model-id allowlist regex; `parsers/code_imports.py` (AI_IMPORTS) is the curated import allowlist — redis is deliberately omitted (it's a general datastore; adding it regresses test_license_resolver by flagging redis-as-cache in chroma).
- Two implementers shared branch `ansh`; coordinate before commits. The 71 MB chroma fixture is a gitignored upstream clone (absent in CI → differential/compliance chroma cases self-skip).
- Bench is ISOLATED (`aibom/bench/`, never product). Bedrock for the Cisco oracle: `us-east-1` + `global.anthropic.claude-haiku-4-5-20251001-v1:0` (the `apac` default id is invalid in this account).
