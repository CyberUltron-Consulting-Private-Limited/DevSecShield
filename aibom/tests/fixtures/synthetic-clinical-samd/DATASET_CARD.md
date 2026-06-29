---
name: cxr-pneumonia-cohort
bom_ref: dataset-cxr-pneumonia-train
dataset_type: image (DICOM)
dataset_size: "180,000 studies"
provenance: 2 US health systems, 2020-2025, IRB-approved, de-identified
sensitivity: PHI removed; Safe Harbor de-identification
known_bias: skews adult, 2 scanner vendors
license: internal-restricted
data_collection_process: Retrospective PACS extraction under IRB approval.
data_preprocessing:
  - DICOM windowing to lung presets
  - resize to 1024x1024, single channel
  - HIPAA Safe Harbor de-identification
anonymization_method:
  - HIPAA Safe Harbor
confidentiality_level: amber
intended_use: training and validation of the pneumonia triage model
has_sensitive_personal_information: "no"
---

# CXR Pneumonia Cohort

180,000 de-identified frontal chest radiograph studies from two US health
systems (2020-2025) under IRB approval. PHI removed via HIPAA Safe Harbor.
