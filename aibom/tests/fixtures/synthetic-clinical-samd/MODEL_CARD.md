---
# Synthetic chest-X-ray SaMD model card — YAML frontmatter is the scan source.
name: cxr-pneumonia-triage
version: "1.3.0"
bom_ref: model-cxr-pneumonia
publisher: Synthetic Health AI
license: Apache-2.0

application:
  name: CXR-Pneumonia-Triage-SaMD
  version: "1.3.0"
  type: application

datasets:
  - dataset-cxr-pneumonia-train

pedigree_ancestors:
  - name: imagenet-densenet121
    version: "1.0"

performance_metrics:
  - { type: AUROC, value: "0.93", slice: overall }
  - { type: sensitivity, value: "0.90", slice: "age>=65" }

considerations:
  users:
    - board-certified radiologist (human-in-the-loop)
  use_cases:
    - triage/prioritization of frontal chest radiographs for suspected pneumonia
  technical_limitations:
    - not validated on pediatric or lateral films
  ethical_considerations:
    - name: demographic performance gap
      mitigation_strategy: subgroup monitoring
  fairness_assessments:
    - group_at_risk: underrepresented scanners/sites

clinical:
  intended_use: triage and prioritization of frontal chest radiographs for suspected pneumonia (SaMD)
  modality: DX (chest radiograph)
  body_part: chest
  pacs_ae_title: CXR_PNA_AI
  uses_sensitive_personal_information: "yes"
  human_oversight: "yes"

regulatory:
  fda_product_code: QFM
  device_class: II (SaMD)
  eu_ai_act_risk_tier: high-risk (Annex I / MDR)

# Inference service — under a signed BAA (HIPAA, since the model sees PHI).
served_by:
  name: Synthetic Imaging Cloud
  bom_ref: service-synthetic-imaging-cloud
  baa: true

# Deployment site(s).
deployed_at:
  - name: Northgate Regional Hospital
    bom_ref: site-northgate
    version: "1.3.0"
    last_validated: "2026-02-10"
    drift_status: stable
---

# CXR Pneumonia Triage (SaMD)

A supervised CNN (DenseNet-121) that triages frontal chest radiographs (DICOM
DX) for suspected pneumonia, flagging studies for prioritized radiologist
review. **Software as a Medical Device (SaMD)**, run **human-in-the-loop**.

## Intended use
Worklist triage and prioritization only — not a diagnosis, never autonomous.

## Performance
AUROC 0.93 overall; sensitivity 0.90 on patients aged >= 65.

## Regulatory
FDA 510(k) Class II (product code QFM) with a PCCP; EU AI Act high-risk
(Annex I / MDR). Mappings are advisory; see disclaimer.
