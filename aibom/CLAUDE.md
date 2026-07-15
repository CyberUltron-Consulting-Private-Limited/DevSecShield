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

## Risk-score scale (locked before the Phase-4 heatmap)
The scorer keeps `risk_total` as the raw flag-weight sum **and** publishes a
**Trusera-style 0–100 normalized score** plus **low/medium/high bands**, defined
in `config/risk-weights.yaml` under `scale:`:

```
risk_normalized = min(100, round(risk_total / scale.max_raw * 100, 1))
band:  ≤ scale.bands.low → low;  ≤ scale.bands.medium → medium;  else → high
```

`scale.max_raw` is the calibration ceiling = "every defined flag tripped once →
100" (currently 27 = 8+10+5+4); omit it to auto-compute from the flag weights.
Defaults: `max_raw=27`, bands `low≤33`, `medium≤66`. Rationale: 0–100 matches the
dossier's Trusera reference and the dashboard's heatmap, so the scale never needs
retrofitting; bands give a coarse triage signal. Editing the YAML re-scales with
no code change. `scores` carries `risk_total`, `risk_normalized`, `risk_band`,
`by_flag`, `by_component`, `flag_count`.
