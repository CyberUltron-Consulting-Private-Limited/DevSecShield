"""Model-recall gate vs the synthetic ground-truth manifest.

The synthetic fixture's ``expected_assets.json`` is hand-labeled ground truth.
Ours must detect EVERY model reference it lists — recall 1.0 on the controlled
fixture. A scanner change that drops a model id (e.g. a broken MODEL_RE) fails here.
"""

from __future__ import annotations

import json
import os

from aibom.scan.pipeline import scan_repo

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-ai-app")
_THRESHOLD = 1.0  # ground-truth fixture -> full recall required


def _norm(s: str) -> str:
    return s.strip().lower()


def test_model_recall_vs_synthetic_manifest() -> None:
    with open(os.path.join(_FX, "expected_assets.json")) as fh:
        manifest = json.load(fh)
    expected = {_norm(m) for m in manifest["model_references"]}
    result = scan_repo(_FX, level=4)
    detected = {_norm(c.name) for c in result.components if c.kind == "model"}
    hit = expected & detected
    missing = expected - detected
    recall = len(hit) / len(expected) if expected else 1.0
    assert recall >= _THRESHOLD, (
        f"model recall {recall:.2f} < {_THRESHOLD:.2f} vs the synthetic manifest; "
        f"missing: {sorted(missing)} (detected models: {sorted(detected)})"
    )
