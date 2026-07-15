---
# One model deployed across multiple hospital sites. Each deployed_at edge's
# site node carries version / last_validated / drift_status for Phase-4
# multi-site governance and drift surveillance.
name: chestxr-triage-multisite
version: "2.1.0"
bom_ref: model-chestxr-multisite
publisher: Acme Medical AI
license: Apache-2.0

application:
  name: ChestXR-Triage-MultiSite
  version: "2.1.0"

datasets:
  - dataset-chestxr-train

clinical:
  intended_use: triage and prioritization of chest radiographs (SaMD)
  modality: DX (chest radiograph)
  body_part: chest
  uses_sensitive_personal_information: "yes"

regulatory:
  eu_ai_act_risk_tier: high-risk (Annex I / MDR)

served_by:
  name: Acme Imaging AI Cloud
  bom_ref: service-acme-cloud
  baa: true

# Same model version, different per-site validation + drift state.
deployed_at:
  - name: Mercy General Hospital
    bom_ref: site-mercy-general
    version: "2.1.0"
    last_validated: "2026-03-01"
    drift_status: stable
  - name: Lakeside Regional Medical Center
    bom_ref: site-lakeside-regional
    version: "2.0.3"
    last_validated: "2025-11-15"
    drift_status: drift-detected
---

# ChestXR Triage (multi-site deployment)

The same chest-radiograph triage model deployed at two hospital sites. Mercy
General runs v2.1.0 (validated 2026-03, stable); Lakeside Regional still runs
v2.0.3 (validated 2025-11) and is showing drift — exactly the version/drift
sprawl multi-site governance must track.
