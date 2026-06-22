# clinithread-aibom

Healthcare-grade **AI Bill of Materials (AI BOM)** generator. Scans an ML model
repo into a normalized inventory and emits schema-validated **CycloneDX 1.6
ML-BOM** JSON, with clinical-imaging / regulatory metadata carried in
namespaced `properties[]` (`clinical:` / `regulatory:` / `dataset:`). A
healthcare extension of DevSecShield's AIBOM.

> Regulatory mappings are **advisory only** — an AI BOM creates visibility, not
> assurance, and does not by itself satisfy FDA / EU AI Act / HIPAA obligations.

## Quickstart

```bash
uv sync
uv run aibom scan examples/clinical-imaging              # normalized inventory (JSON)
uv run aibom emit --format cyclonedx examples/clinical-imaging -o out.cdx.json
uv run aibom validate out.cdx.json                       # schema gate (exit 1 on error)
uv run pytest
```

## Layout

```
src/aibom/
  scan/      manifest + config.json + model-card + dataset-card + model-file parsers -> AIComponents
  model/     Pydantic v2 AIComponent contract (+ clinical-imaging extensions)
  emit/      cyclonedx.py serializer + offline jsonschema validation
  schemas/   bundled CycloneDX 1.6 (+ SPDX/JSF) JSON schemas (offline)
  compliance/ shadow/   (later phases)
examples/clinical-imaging/   sample chest X-ray triage SaMD repo + expected/ golden BOM
```

Status: **Phase 1 (MVP)** — a valid CycloneDX 1.6 ML-BOM for a clinical-imaging
model, scanned from a repo. SPDX 3.0 and the compliance layer are later phases.
