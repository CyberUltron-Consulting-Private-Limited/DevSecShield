---
# clinithread-aibom model card — YAML frontmatter is the scan source of truth.
# Identity, lineage, metrics, considerations and the clinical/regulatory blocks
# are parsed from here; modelParameters (architecture/task/io) come from config.json.
name: chestxr-nodule-detector
version: "2.1.0"
bom_ref: model-chestxr-cnn
publisher: Acme Medical AI
license: Apache-2.0

# The deployed SaMD application this model ships inside (CycloneDX metadata.component).
application:
  name: ChestXR-Triage-SaMD
  version: "2.1.0"
  type: application

# bom_refs of dataset components this model was trained on (see DATASET_CARD.md).
datasets:
  - dataset-chestxr-train

pedigree_ancestors:
  - name: imagenet-resnet50
    version: "1.0"

performance_metrics:
  - { type: AUROC, value: "0.94", slice: overall }
  - { type: sensitivity, value: "0.91", slice: "age>=65" }

considerations:
  users:
    - board-certified radiologist (human-in-the-loop)
  use_cases:
    - triage/prioritization of chest radiographs
  technical_limitations:
    - not validated on pediatric or portable AP supine films
  ethical_considerations:
    - name: demographic performance gap
      mitigation_strategy: subgroup monitoring
  fairness_assessments:
    - group_at_risk: underrepresented scanners/sites

# Clinical-imaging extensions -> emitted as clinical: namespaced properties.
clinical:
  intended_use: triage and prioritization of chest radiographs (SaMD)
  modality: DX (chest radiograph)
  body_part: chest
  pacs_ae_title: CHESTXR_AI
  # Model processes PHI (patient radiographs) at inference time.
  uses_sensitive_personal_information: "yes"
  # A board-certified radiologist makes the final read (human-in-the-loop).
  human_oversight: "yes"

# Regulatory extensions -> emitted as regulatory: namespaced properties (advisory).
regulatory:
  fda_product_code: QFM
  device_class: II (SaMD)
  eu_ai_act_risk_tier: high-risk (Annex I / MDR)

# Deployment graph. Because the model processes PHI at inference, it must be
# served by a vendor under a signed Business Associate Agreement (BAA). The
# served_by edge's service node carries service:baa for the Phase-3 HIPAA check.
served_by:
  name: Acme Imaging AI Cloud
  bom_ref: service-acme-cloud
  baa: true

external_references:
  - type: model-card
    url: https://acme.example/chestxr.modelcard.json
  - type: documentation
    url: https://www.accessdata.fda.gov/scripts/cdrh/cfdocs/cfpmn/pmn.cfm?id=K2xxxx
    comment: FDA 510(k) K2xxxx; PCCP authorized
---

# ChestXR Nodule Detector

A supervised CNN (ResNet-50) that triages frontal chest radiographs (DICOM DX)
by flagging suspected pulmonary nodules for prioritized radiologist review. It
is **Software as a Medical Device (SaMD)** and runs **human-in-the-loop**: a
board-certified radiologist makes the final read.

## Intended use

Worklist triage and prioritization only. The model does **not** make a diagnosis
and must not be used autonomously. Not validated on pediatric or portable AP
supine films.

## Performance

Reported AUROC 0.94 overall; sensitivity 0.91 on patients aged ≥ 65. Subgroup
monitoring is in place for a known demographic performance gap.

## Regulatory

Cleared under FDA 510(k) K2xxxx (product code QFM, Class II), with a
Predetermined Change Control Plan (PCCP). Under the EU AI Act this is a
high-risk AI system (Annex I / MDR). *Mappings are advisory; see disclaimer.*
