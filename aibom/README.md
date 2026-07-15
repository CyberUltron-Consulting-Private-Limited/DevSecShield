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

### Compliance mapping & client deliverables

```bash
uv run aibom map --framework all examples/clinical-imaging     # advisory pass/fail/na per framework
uv run aibom report --format pdf examples/clinical-imaging      # xlsx | pdf | docx deliverable
```

### Shadow-AI discovery (Phase 4)

Five independent, self-registering scan **levels** (1 filesystem → 2 docker →
3 net/env → 4 cloud IaC → 5 live cloud). Diff what's discovered against an
allowlist to flag **unsanctioned** shadow AI; the scorer weights the flags.

```bash
uv run aibom discover examples/shadow-demo --level 4 \
    --allowlist config/allowlist.yaml \
    -o scan.json --findings findings.xlsx        # findings.xlsx | .pdf

# Cedar runtime-governance projection (entities + sample policy):
uv run aibom cedar examples/multi-site -o entities.json -p policies.cedar

# Self-contained dashboard (inventory, risk heatmap, compliance, per-site drift):
uv run aibom dashboard examples/multi-site -o dashboard-out
python -m http.server -d dashboard-out          # then open http://localhost:8000
```

The dashboard is a single self-contained HTML file (React + Tailwind via CDN,
zero build) that fetches the co-located `scan.json` and renders purely from it.
No `localStorage`; reload re-reads the file.

## Layout

```
src/aibom/
  scan/       parsers + self-registering Scanner registry (level 1-5: model-repo, requirements,
              docker, net/env, cloud-IaC, live-cloud) -> components + edges + flags
  model/      Pydantic v2 AIComponent contract (27-kind taxonomy) + ScanResult graph
  score/      config-driven scorer (config/risk-weights.yaml) -> risk_total + 0-100 band
  emit/       CycloneDX 1.6 / SPDX 3.0 / SARIF reporters + offline jsonschema validation
  compliance/ graph-aware checks: FDA §524B, EU AI Act Annex IV, GMLP, HIPAA, NIST AI RMF
  shadow/     allowlist diff -> UNSANCTIONED_COMPONENT flags
  governance/ Cedar entities + policy export (runtime governance)
  deliverables/ xlsx / pdf / docx + shadow-AI findings report
  dashboard/  self-contained ScanResult-JSON SPA
  schemas/    bundled CycloneDX 1.6 / SPDX / SARIF JSON schemas (offline)
examples/{clinical-imaging,no-phi-model,multi-site,shadow-demo}/   fixtures (+ expected/ goldens)
```

Status: **Phase 0–4** — CycloneDX 1.6 ML-BOM + SPDX 3.0 + SARIF; five-framework
advisory compliance mapping; multi-level shadow-AI discovery with allowlist diff;
Cedar governance export; and a self-contained dashboard.
