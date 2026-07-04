---
# Engineered fixture for the CHART-DATA-CONTRACT tests. Deliberately risky so a
# real scan yields findings across severities + OWASP categories + compliance
# gaps — the data the results-page charts render. Not a real product.
name: triage-risk-demo
version: "0.1.0"
bom_ref: model-triage-risk
publisher: Demo Health AI
# NO license field -> MODEL_NO_LICENSE (High).

datasets:
  - dataset-risky-cohort

clinical:
  intended_use: demo worklist triage
  modality: DX (chest radiograph)
  body_part: chest
  # Processes PHI at inference -> MODEL_PHI_AT_INFERENCE (High).
  uses_sensitive_personal_information: "yes"
  # No human-in-the-loop -> EU AI Act Art 14 / GMLP-7 gaps.
  human_oversight: "no"

regulatory:
  # High-risk tier -> MODEL_EU_AI_ACT_HIGH_RISK (High).
  eu_ai_act_risk_tier: high-risk (Annex III)
# No served_by / BAA -> HIPAA served-by-vendor check fails (compliance gap).
---

# Triage Risk Demo (engineered)

An intentionally non-compliant model: **unlicensed**, **PHI at inference**,
**high-risk**, trained on a **non-de-identified** cohort, served without a BAA.
Used only to exercise the AI-BOM results-page charts (severity / OWASP /
compliance) end-to-end.
