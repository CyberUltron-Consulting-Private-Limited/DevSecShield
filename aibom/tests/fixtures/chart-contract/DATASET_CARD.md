---
# Engineered: PHI present and NOT de-identified -> DATASET_NO_DEIDENT (Critical).
name: risky-cohort
bom_ref: dataset-risky-cohort
dataset_type: image (DICOM)
dataset_size: "10,000 studies"
provenance: single site, no IRB documented
sensitivity: contains PHI (patient radiographs)
known_bias: small single-site cohort
# has_sensitive_personal_information=yes AND no anonymization_method ->
# is_deidentified() is False -> DATASET_NO_DEIDENT.
has_sensitive_personal_information: "yes"
intended_use: training the demo triage model
---

# Risky Cohort (engineered)

PHI present, **not de-identified** (no anonymization method declared) — fires the
critical de-identification gap the charts surface.
