"""The run UI's quantum-risk and fix-class vocabulary equals the backend's (CB-19 / CB-24 PR-1u).

``contracts/cbom/grade_keys.json`` holds what the frontend's label maps and tips must match: the grade keys and their
risk words, every reason code with its grade, the signed model text and its sha256, the PQC classes the grade reads,
the six fix-class values with their served text, the inferred text, the self-fixable classes and the unknown reasons.
This test fails when the backend changes any of them and the file does not; ``frontend/components/cbom/grade/
gradeContract.test.ts`` fails when the frontend disagrees with the file (the HF-9 crash class, cx4 OB-1 §3).

Rewrite the file after an intended backend change: ``CBOM_WRITE_CONTRACTS=1 pytest tests/test_cbom_cb19_cb24_ui_contract.py``.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from backend.utilities.cbom_sources import agility as AGILITY
from backend.utilities.cbom_sources import qgrade as QGRADE

FIXTURE = Path(__file__).resolve().parents[2] / "contracts" / "cbom" / "grade_keys.json"


def _expected() -> dict:
    served = QGRADE.model_payload()
    model = AGILITY.model()
    return {
        "grade_model": QGRADE.GRADE_MODEL,
        "grades": [{"grade": g, "label": QGRADE.LABELS[g]} for g in QGRADE.GRADES],
        "reasons": {r["code"]: r["grade"] for r in served["reasons"]},
        "formula_sha256": served["text_sha256"],
        "formula_text": served["text"],
        "pqc_classes": list(QGRADE.CLASSES),
        "agility_model": AGILITY.MODEL,
        "fix_classes": list(AGILITY.CLASSES),
        "fix_values": list(AGILITY.VALUES),
        "fix_class_text": {c["key"]: {"label": c["label"], "what": c["what"], "example": c["example"]}
                           for c in model["classes"]},
        "fix_inferred_text": model["inferred"],
        "self_fixable": list(AGILITY.SELF_FIXABLE),
        "unknown_reasons": dict(AGILITY.UNKNOWN_REASONS),
    }


def test_grade_keys_file_matches_backend():
    expected = _expected()
    if os.environ.get("CBOM_WRITE_CONTRACTS") == "1":
        FIXTURE.write_text(json.dumps(expected, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    assert json.loads(FIXTURE.read_text(encoding="utf-8")) == expected, \
        "contracts/cbom/grade_keys.json is out of date: rewrite it (see the module docstring) and update the UI"


def test_served_sha_is_the_sha_of_the_served_text():
    # what the "How grades are computed" dialog shows: the served text and its served sha256 belong together
    served = QGRADE.model_payload()
    assert hashlib.sha256(served["text"].encode("utf-8")).hexdigest() == served["text_sha256"] == QGRADE.FORMULA_SHA256
