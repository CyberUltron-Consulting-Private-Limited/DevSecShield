---
# Dataset card (Datasheet-style). Parsed into a CycloneDX `data` component;
# the dataset_* fields are emitted as dataset: namespaced properties.
name: chestxr-training-cohort
bom_ref: dataset-chestxr-train
dataset_type: image (DICOM)
dataset_size: "412,000 studies"
provenance: 3 US health systems, 2019-2024, IRB-approved, de-identified
sensitivity: PHI removed; Safe Harbor de-identification
known_bias: skews adult, 2 scanner vendors
license: internal-restricted

# Richer Dataset-Profile capture (folds into SPDX 3.0 Dataset Profile).
data_collection_process: Retrospective extraction from PACS across 3 US health systems (2019-2024) under IRB approval.
data_preprocessing:
  - DICOM windowing to soft-tissue/lung presets
  - resize to 1024x1024, single channel
  - HIPAA Safe Harbor de-identification of DICOM headers and pixels
anonymization_method:
  - HIPAA Safe Harbor
confidentiality_level: amber
intended_use: training and validation of the chest radiograph triage model
has_sensitive_personal_information: "no"
---

# ChestXR Training Cohort

412,000 de-identified frontal chest radiograph studies drawn from three US
health systems (2019–2024) under IRB approval. PHI was removed via HIPAA Safe
Harbor de-identification.

## Known biases

The cohort skews adult and was acquired predominantly on two scanner vendors;
performance on underrepresented scanners/sites is monitored as a fairness risk.
