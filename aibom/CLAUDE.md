# CLAUDE.md — clinithread-aibom (the `aibom/` package)

Project conventions for the standalone healthcare AI-BOM generator. The full
background + standards field-mapping live in `../docs/research-dossier.md`.

## What it is
Scans an ML model repo into a scored **`ScanResult`** (a typed inventory graph)
and renders schema-validated **CycloneDX 1.6 ML-BOM**, **SPDX 3.0 AI+Dataset**,
and **SARIF 2.1.0** via a reporter registry.

## Architecture (the graph is the product)
- `model/result.py` — `ScanResult{subject, components, edges, flags, scores, compliance, properties}` + `Edge`/`Flag` (frozen) + graph helpers (`by_ref`/`out_edges`/`neighbors`/`flags_for`).
- `model/component.py` — Pydantic `AIComponent` union (model/dataset/framework/prompt/service/infra/secret) + clinical-imaging extensions.
- `scan/` — self-registering `Scanner` registry (explicit `order`); scanners append components + **edges** + **flags**, never scores.
- `score/` — config-driven scorer (`config/risk-weights.yaml`) → `ScanResult.scores`.
- `emit/` — stateless `BaseReporter.render(result)->str` registry; hand-built serializers; **offline** schema validation (`referencing`-based for CycloneDX).

## Hard rules
1. **Every emitted report MUST schema-validate** against the bundled schema (a failure is a build failure, not a warning).
2. **No invented field names.** Healthcare data goes in `properties[]` under `clinical:` / `regulatory:` / `dataset:`, never as non-spec top-level keys.
3. **Golden discipline.** `examples/*/expected/` BOMs are committed; output changes update goldens deliberately.
4. **Checks read the GRAPH, never flags.** A compliance check decides applicability/pass/fail from a node property or an edge (e.g. `clinical:processes_phi` + the `served_by` edge's `service:baa`), never from a flag like `MODEL_PHI_AT_INFERENCE`. Flags are the scoring echo, parallel to the authoritative graph facts.
5. **Advisory only.** Every report carries the disclaimer; mappings support but do not satisfy FDA/EU-AI-Act/HIPAA obligations.
6. **Deterministic + pure.** Serializers do no I/O/network; identical input → byte-identical output.

## Edge vocabulary
`trained_on` (model→dataset), `depends_on` (model→framework), `served_by`
(model→inference service, node carries `service:baa`), `deployed_at`
(model→site, node carries `site:version`/`site:last_validated`/`site:drift_status`).
CycloneDX collapses all edges to `dependsOn`; SPDX maps `trained_on`/`depends_on`
to native relationshipTypes and `served_by`/`deployed_at` to `other` + a comment.

## Risk-score scale
The scorer keeps `risk_total` as the raw flag-weight sum, maps each component's
STACKED flag weight to a severity (`severity:` bands in `config/risk-weights.yaml`)
and, for an AI BOM, publishes the headline **0-100 `risk_normalized`** from
`posture_score` over every counted component's severity (an unflagged component is
low; a model only named in a catalog / doc / test, `model:reference_type` catalog or
test, is in the BOM but not counted). The formula, the cap table and the grade
words live in ONE stdlib-only module, `score/posture.py`, which the backend PDF
loads by path (`backend/utilities/pdf/aibom_posture.py`), so the dashboard band and
the PDF grade say the same word:

```
risk_normalized = min(100, 4 x (10 critical + 5 high + 2 medium + 1 low)),
                  capped by the worst severity: no critical <= 69, no critical/high <= 49,
                  low only <= 14 (grade A), nothing -> 0
grade / risk_band: >=70 F critical, >=50 D high, >=30 C elevated, >=15 B moderate, else A low
```

`scores` carries `risk_total`, `risk_normalized`, `risk_band`, `risk_grade`,
`risk_label`, `severity_counts`, `by_flag`, `by_component`, `component_severity`,
`flag_count`. The CBOM (`cbom/scorer.py`, `score_result(..., posture=False)`) keeps
its own flag-weight scale: `normalize_score` (raw sum / max_raw) and the YAML
`scale.bands` (low / medium / high), unchanged by the AI BOM posture score.

## Document identity and disclaimer
`emit/identity.py`: tool `DevSecShield AI BOM` (CBOM: `DevSecShield CBOM`), version
from `DSS_BUILD_VERSION` / `DSS_BUILD_SHA` (else the package version), supplier Zero
Shield, creation time `ScanResult.generated_at` (the adapters stamp the scan time;
None keeps the goldens on a pinned time). `emit/_disclaimer.py` (`disclaimer_of`):
CBOM wording for a crypto inventory, the FDA/HIPAA wording only for an AI BOM with
clinical / regulatory metadata, else the neutral AI BOM wording.
