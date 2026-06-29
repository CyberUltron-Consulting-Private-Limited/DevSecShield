# aibom/state/compliance — tri-state verdicts + evidence-attachment (DONE)

Honest compliance verdicts: the old 3-state (`pass`/`fail`/`na`) is replaced by a
graph-driven taxonomy that never fakes evidence. Coverage = `pass/(pass+fail)`;
`out_of_scope` and `not_bom_evidenceable` are each their **own** count, never
folded into pass/fail/na.

## Verdict taxonomy (`compliance/base.py` `Verdict`)
- `pass` / `fail` — the BOM **graph** evidences the requirement (or its breach).
- `pass_with_evidence` — a `not_bom_evidenceable` requirement satisfied by an
  uploaded attestation (counts toward coverage as a pass).
- `out_of_scope` — the **framework** does not apply to this artifact. Decided by a
  per-framework applicability gate, NOT a fail and NOT a generic NA.
- `not_bom_evidenceable` — a real, in-scope obligation whose evidence is
  process/attestation a static scan structurally cannot see (`register_manual`).
- `na` — in-scope framework but this requirement has no subject in the graph (rare).

## Applicability gates (`register_applicability`, applied in `engine.run_framework`)
A framework whose predicate is False → **every** requirement `out_of_scope`.
- `gmlp`, `fda_524b` → `clinical_models(r)` (a model with a `clinical:`/`regulatory:`
  property or a clinical model-card field: intended_use / modality / device_class /
  fda_product_code). A bare embedding/LLM reference (chroma's) qualifies for none.
- `hipaa` → `phi_models(r)` (the existing PHI gate; now surfaces `out_of_scope`,
  not `na`, when no PHI is in scope).
- `eu_ai_act_annexIV`, `nist_rmf` → ungated (general AI-governance; evaluate pass/fail
  whenever models exist — this is the "NIST + supply-chain stays pass/fail" lane).

## Evidence-attachment (engine overlay; checks stay pure)
`run_all(result, evidence={framework: {requirement_id: note}})`. After a check
returns `not_bom_evidenceable`, a matching attestation flips it to
`pass_with_evidence` with `evidence="satisfied by uploaded attestation: …"`. Only
`not_bom_evidenceable` is attestable — you cannot attest away an `out_of_scope`
framework or a real graph `fail`. Each requirement carries `attestable: bool`.

## Verified behavior (`AIBOM_LLM_OFFLINE=1`)
- `synthetic-clinical-samd` (clinical): GMLP `pass=6 fail=1 nbe=3` (REAL pass/fail),
  FDA `pass=7 nbe=1`, EU `pass=11 nbe=6`, HIPAA `pass=3 nbe=10`, NIST `pass=6 nbe=10`.
- `chroma` (non-clinical vector DB): GMLP `oos=10`, FDA `oos=8`, HIPAA `oos=13`
  (all OUT_OF_SCOPE — distinguished from fail); NIST `fail=6`, EU `fail=11` (pass/fail).
- attestation flips `GMLP-1` `not_bom_evidenceable → pass_with_evidence` end-to-end
  through `scan_to_devsecshield(..., attestations=…)`.

## Files
Owned by the parallel session: `compliance/{base,engine,gmlp,fda_524b,hipaa,
eu_ai_act_annexIV,nist_rmf}.py`, `tests/test_compliance{,_na}.py`, and the frontend
`components/ai-bom/AiBomVisualizations.tsx` (`ComplianceCoverage`: 6-state legend +
per-requirement reasons table + `+ Attach attestation` file affordance).
Gap-fills (this session): `deliverables/xlsx.py` (Summary now has Pass/Fail/
Out-of-Scope/Not-Evidenceable/N-A/Coverage columns + verdict fills for the new
states) + `tests/test_deliverables.py`; `integrations/devsecshield.py`
(`run_native_scan`/`scan_to_devsecshield` thread `attestations` → `run_all(evidence=)`,
docstrings updated to the tri-state).

## Notes
- The dashboard `compliance_controls` reads `fail` per framework, so out-of-scope
  frameworks correctly DROP OUT of the failure bar chart (chroma shows only NIST+EU).
  The frontend `ComplianceCoverage` consumes the full `ai_bom_compliance` object
  directly (no dashboard change needed for the tri-state UI).
- Known, pre-existing, local-only RED (NOT a regression, documented in
  `test_differential.py`): `chroma-provider`/`chroma-framework` recall — the engine
  is requirements.txt-only, the "headline gap"; these cases self-skip in CI when the
  71 MB clone is absent.
