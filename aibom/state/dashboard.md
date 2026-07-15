# aibom/state/dashboard = verified-green (pre-benchmark gate)

Chroma + fixture dashboards asserted correct end-to-end through the REAL
`backend/utilities/dashboard/scan.py::generate_scan_dashboard("ai_bom", …)` — the
exact code the results page renders. All gates green; ruff + mypy clean.

## Chroma results-page dashboard — BEFORE → AFTER
| metric | before | after | fix |
|--------|--------|-------|-----|
| total_models | 46 | **26** | catalog refs excluded from findings (`_inventory`, model:reference_type=catalog) |
| total_high_risk_assets | 23 | **0** | secret false-positives removed |
| severity_distribution | {C:23, H:0, M:1, L:88} | **{C:0, H:0, M:1, L:68}** | 23 fake "critical" secrets gone — honest low-risk profile |
| total_unlicensed_assets | 40 | **1** | exclude secrets (FP) + external-provider services; true LIBRARY unknowns only |
| governance_readiness_score | 0.0 | **31.9** | `model_card` now carried into the finding (37/46 models carry a card) |
| total_datasets | 0 | 0 | correct (chroma has no training datasets) |
| owasp_top_10_llm_issues | 4 cats | 3 cats (LLM03/08/10) | populated; LLM02 dropped with the secret FPs |
| compliance_controls | eu:11, nist:6 | eu:11, nist:6 | correct — GMLP/FDA/HIPAA out_of_scope dropped out (tri-state) |

## Root causes fixed
1. **Catalog over-count** (other session's `_inventory` wiring + my helper): the 20
   catalog model refs (`gpt-4o`, `text-embedding-3`, … listed in registries, not
   used) are excluded from findings/graph; the 26 USAGE models are the true count.
   The full 46 remain in the CycloneDX `ai_bom_json`.
2. **Secret false-positives** (`scan/scanners/secret_scan.py`, mine): the generic
   rule flagged env-var NAMES (`CHROMA_OPENAI_API_KEY`), paths (`/x/y.htpasswd`),
   and identifiers as hardcoded secrets, and matched dummy keys in test files.
   Fix: `_NOT_SECRET_VALUE` rejects name/path-shaped values + `_is_test_file`
   skips test fixtures. chroma 23→0. Planted secrets in synthetic-ai-app /
   synthetic-scorer app.py STILL detected (regression-guarded).
3. **governance=0** (`integrations/devsecshield.py`, mine): the finding carried no
   `model_card`, so `has_card` was always False. Now `_card_summary(comp)` carries
   the populated card fields → governance reflects models with license + card.
4. **unlicensed counted services** (`dashboard/scan.py`, mine): 16 of 17 were
   external providers (OpenAI, AWS Bedrock, Ollama…) — hosted APIs, not licensable
   packages. Excluded external_provider → true library unknowns only (1).

## Severity flatness — HONEST, not broken
chroma's `{C:0,H:0,M:1,L:68}` is correct: it has exactly ONE real flag
(FRAMEWORK_NO_LICENSE on graphlib_backport); deps are licensed, models carry
resolved licenses + cards, no secrets (env vars), no PHI, no datasets. The engine
flags secrets/licenses/PHI — not version-pinning — so chroma is genuinely low-risk.
PROOF the tool produces non-flat distributions when warranted:
synthetic-scorer {C:1,H:1,M:1,L:1}; clinical-samd {C:1,…}; synthetic-ai-app {C:1,…}.
The 23 fake criticals were the actual bug, now removed.

## Gates
- full aibom suite GREEN (216; excl. 2 documented chroma-differential local-only
  gaps that self-skip in CI). backend test_ai_bom_chart_contract + e2e 4/4.
  ruff clean; mypy clean (61 files). regenerated backend chart-contract fixture
  (+model_card). updated _FINDING_FIELDS lock + deliverables tri-state tests.
- compliance tri-state verified on both: chroma GMLP/FDA/HIPAA out_of_scope,
  NIST/EU pass/fail; clinical-samd real pass/fail. See [[aibom-compliance-tristate]].

## Two-writer collision
Other session active throughout (catalog `_inventory` wiring at 10:08; I had also
written the same helper — they adopted it). I momentarily deleted `_inventory` as
"dead" and broke normalize → restored immediately. Lesson reinforced: grep for
USAGES before deleting in a hot shared file.
