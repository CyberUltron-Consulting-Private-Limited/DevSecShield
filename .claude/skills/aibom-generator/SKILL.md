---
name: aibom-generator
description: Use when generating a healthcare AI Bill of Materials (AI BOM), validating a CycloneDX 1.6 / SPDX BOM, or mapping an AI inventory to FDA §524B / EU AI Act compliance. Emits schema-validated CycloneDX 1.6 ML-BOMs with clinical-imaging and regulatory metadata. Healthcare extension of DevSecShield's AIBOM.
---

# aibom-generator

Generate, validate, and (later) compliance-map healthcare AI Bills of Materials.
This is the **clinithread-aibom** engine — a healthcare extension of DevSecShield's
AIBOM, rooted at `aibom/` (the package is `aibom/`, not a separate repo).

## When to use

- Generate an AI BOM for a clinical AI system (e.g. a radiology/PACS imaging model).
- Validate any CycloneDX 1.6 BOM against the bundled offline schema.
- Map (phase 3) an AI inventory to FDA §524B / EU AI Act Annex IV / GMLP readiness.

## Workflow

```
scan repo  ->  normalize to AIComponent  ->  emit validated CycloneDX 1.6  ->  [phase 2: SPDX 3.0 AI+Dataset]  ->  [phase 3: compliance map]
```

Phase 1 (now): `normalize -> emit CycloneDX 1.6 -> validate`. `scan`, `map`, and
`discover` are CLI stubs until later phases.

## Run it (always use the venv python)

```bash
cd aibom
.venv/bin/python cli.py validate examples/clinical-imaging/chestxr.cdx.json   # schema gate; exit 1 on error
.venv/bin/python cli.py emit -o out.cdx.json                                   # emit the clinical-imaging demo BOM
.venv/bin/python cli.py emit                                                   # BOM -> stdout, advisory -> stderr
```

To build a BOM in code: construct `model.component.AIBom` from the locked
`AIComponent` contract, then call `emit_and_validate(aibom)` (raises
`BomValidationError` on any schema error). See `emit/build_chestxr.py` for a
complete, validating example.

## Key files

- `aibom/model/component.py` — the locked Pydantic v2 `AIComponent` contract
  (discriminated union on `kind`: model/dataset/framework/prompt/service/infra/secret)
  and `AIBom` assembly. Serializer-agnostic; healthcare fields are typed here.
- `aibom/emit/cyclonedx.py` — **pure** CycloneDX 1.6 serializer.
  `emit_cyclonedx(aibom) -> dict` (no I/O, no network, deterministic) and
  `emit_and_validate(aibom) -> dict` (the build-failure enforcement point).
- `aibom/emit/validate.py` — `validate_cyclonedx(bom) -> list[str]` ([] == valid),
  the offline schema gate, also runnable as `python emit/validate.py <file>`.
- `aibom/cli.py` — the `aibom` Typer CLI.
- `aibom/schemas/` — bundled offline schemas: `bom-1.6.schema.json`,
  `spdx.schema.json`, `jsf-0.82.schema.json`. No network fetch, ever.
- `aibom/examples/clinical-imaging/chestxr.cdx.json` — the schema-valid golden BOM.
- `docs/research-dossier.md` — standards landscape, field crosswalk, and roadmap.

## Hard rules (these override convenience)

1. **Schema-valid or it's a build failure.** Every emitted BOM MUST pass
   `validate_cyclonedx`. `emit_and_validate` raises rather than emit an invalid
   document; the `validate` CLI exits 1 on any error. Treat a failing BOM as a
   broken build, not a warning.
2. **No invented field names.** Use the EXACT CycloneDX spec names
   (`modelCard.modelParameters`, `quantitativeAnalysis`, `considerations`,
   `pedigree`, `externalReferences`, …). The serializer owns all spec-name mapping.
3. **Healthcare data goes in `properties[]`**, namespaced `clinical:` /
   `regulatory:` / `dataset:` — never as non-spec top-level keys. Clinical model
   extensions (intended_use, modality, body_part, pacs_ae_title, fda_product_code,
   device_class, eu_ai_act_risk_tier) emit as `clinical:`/`regulatory:` properties;
   dataset extensions (type, size, provenance, sensitivity, known_bias) as `dataset:`.
4. **Serializers are pure.** No network calls, no I/O, deterministic output
   (golden-file discipline — diff against the committed golden on every change).
5. **External references require a `url`.** The contract enforces it.
6. **Compliance is advisory only.** An AI BOM creates visibility, not assurance;
   it does not by itself satisfy FDA / EU AI Act / HIPAA. The serializer stamps an
   advisory disclaimer; a qualified regulatory reviewer must sign off.

See `docs/research-dossier.md` for the CycloneDX ↔ SPDX ↔ G7/CISA crosswalk and
the phased roadmap (CycloneDX 1.6 now → SPDX 3.0 → FDA/EU compliance mapping).
