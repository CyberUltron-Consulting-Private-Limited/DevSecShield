---
# HIGH: a real model card with NO concluded license -> MODEL_NO_LICENSE (8) -> high.
# Deliberately not PHI / not EU-high-risk so its stacked weight is exactly "high",
# not critical.
name: scorer-demo-model
version: "0.1.0"
bom_ref: model-scorer-demo
publisher: Scorer Demo
# (no license: field on purpose)
clinical:
  intended_use: severity-band calibration only
---

# Scorer Demo Model

An unlicensed model card used to produce exactly one HIGH-severity finding.
