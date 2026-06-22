---
# A research model that does NOT process PHI and is not clinically deployed.
# Exercises the HIPAA "not-applicable" path: scanning produces NO
# clinical:processes_phi property and no served_by edge.
name: bone-age-estimator
version: "1.0.0"
bom_ref: model-bone-age
publisher: OpenRad Research
license: MIT

application:
  name: BoneAge-Research-Tool
  version: "1.0.0"

datasets:
  - dataset-rsna-boneage

clinical:
  intended_use: research-only pediatric bone-age estimation (not for clinical use)
  modality: DX (hand radiograph)
  body_part: hand
  # Operates only on a public, fully de-identified research dataset.
  uses_sensitive_personal_information: "no"

regulatory:
  eu_ai_act_risk_tier: minimal (research use, not a deployed medical device)
---

# Bone Age Estimator (research)

A ResNet-18 regression model that estimates pediatric skeletal bone age from
hand radiographs. **Research use only** — it is not a medical device, is not
clinically deployed, and processes only a public, de-identified dataset, so it
falls outside HIPAA's PHI scope.
