# AI BOM native-scanner adapter — wiring note

The standalone clinithread-aibom engine is now a **drop-in** for DevSecShield's
`ai_bom` scanner. The adapter lives in the standalone package
(`aibom/src/aibom/integrations/devsecshield.py`) so neither codebase depends on
the other at edit time and the engine's lanes stay intact.

> **Not yet applied.** The `ai_bom`/`ai_bom_estimation` worker tasks are
> currently uncommitted, in-flight work by a concurrent session (the in-tree
> `AIBOMAgent`). Per the additive contract, this session did **not** edit any
> worker/backend file. Apply the two changes below when coordinating with that
> session — both build against the same locked contract
> (`devsecshield/contract/*`).

## What the adapter returns
`scan_to_devsecshield(path) -> dict` returns the **locked run-object** the worker
stores in `Scan.scan_data` and the API serves via `GET …/scan/{id}`:

```python
{
  # --- locked contract fields (unchanged names/semantics) ---
  "results":          [ AIComponentVulnerability dicts ],   # one per engine flag
  "ai_bom_json":      { ... },   # CycloneDX 1.6 ML-BOM
  "ai_bom_compliance":{ "<framework>": {"pass","fail","na","coverage","requirements"}, "disclaimer" },
  "duration_of_scan": float,
  # --- additive (do not remove a locked field; these are new) ---
  "ai_bom_spdx":   { ... },   # SPDX 3.0 JSON-LD   (downloadable artifact)
  "ai_bom_sarif":  { ... },   # SARIF 2.1.0        (downloadable artifact)
  "ai_bom_graph":  { "nodes":[{id,label,kind,type}], "edges":[{source,target,rel}] },
  "ai_bom_scores": { "risk_total","risk_normalized","risk_band","by_flag","by_component","flag_count" },
}
```

Each `results[]` element is a valid `AIComponentVulnerability` (verified by
cross-environment construction against the live worker model): `impact ∈
{Low,Medium,High,Critical}`, `component_type ∈ AIComponentType`, `source ∈
ModelProvider`, `risk_category ∈ AIRiskCategory`, `license` flattened to `str |
None`, `owasp_top_10 / owasp_top_10_llm / compliance_controls = []`.

## Change 1 — worker pyproject (add the engine as a path dependency)
`RabbitMQ/worker/pyproject.toml`:
```toml
[project]
dependencies = [
    # … existing …
    "clinithread-aibom",
]

[tool.uv.sources]
clinithread-aibom = { path = "../../aibom", editable = true }
```
then `uv lock && uv sync` in `RabbitMQ/worker/`. (Engine requires-python `>=3.11`;
the worker is `>=3.12,<3.13` — compatible.)

## Change 2 — swap the engine in the `ai_bom` task
`RabbitMQ/worker/scan_worker.py`, inside `def ai_bom(...)`. Replace the
`AIBOMAgent(...)` body with one call (per context kind — repo/zip/file — pass the
resolved local path the existing code already prepares):
```python
from aibom.integrations.devsecshield import scan_to_devsecshield

state_update_writer = StateUpdateWriter(self)
# progress(pct, msg) bridges to the existing StateUpdateWriter
return scan_to_devsecshield(
    repo_path,                       # the local checkout/unzip path
    level=4,                         # full discovery (filesystem→docker→net→cloud-IaC)
    progress=lambda pct, msg: state_update_writer.write(pct, msg),
)
```
`ai_bom_estimation` maps to `aibom.integrations.devsecshield.run_native_scan` +
the engine's existing credit logic, or keep the current estimator (unchanged).

## Why this is additive / zero-regression
- No SBOM/SAST/DAST/CBOM code path is touched — only the `ai_bom` task body and
  the worker's dependency list change.
- The `results` / `ai_bom_json` / `ai_bom_compliance` / `duration_of_scan`
  contract is preserved byte-for-byte in shape, so every downstream read surface
  (`create_findings.py`, `db/findings.py`, `dashboard/scan.py`, the frontend
  `AiBomResults.tsx`) keeps working with no change.
- New fields (`ai_bom_spdx/sarif/graph/scores`) are ignored by current readers
  and available when the UI wants the graph tab / extra exports.

## Tests
`aibom/tests/test_integration_devsecshield.py` (TDD, real fixtures, engine not
mocked): locked+additive keys present; every finding matches the
`AIComponentVulnerability` field set with valid enum values; license flattened to
a string; findings derived 1:1 from flags; edges preserved (incl. `deployed_at`);
compliance `{pass,fail,na}` preserved; `ai_bom_json` validates as CycloneDX;
deterministic.
