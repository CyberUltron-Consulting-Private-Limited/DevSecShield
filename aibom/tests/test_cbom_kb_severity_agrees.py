"""The knowledge base's default_impact for a code equals the severity the engine raises it at (posture SEVERITY,
mapped error/warning/note -> High/Medium/Low as normalize does), for every code both know.  KMS_KEY_POLICY_PUBLIC
said Critical in the KB while the engine raised it at High (the spec's R table says High)."""

from __future__ import annotations

import json
from pathlib import Path

from aibom.cbom.normalize import _SEVERITY_IMPACT
from aibom.cbom.posture.findings import SEVERITY

KB = Path(__file__).resolve().parents[1] / "src" / "aibom" / "cbom" / "data" / "crypto_kb.json"
BACKEND_KB = Path(__file__).resolve().parents[2] / "backend" / "utilities" / "cbom_sources" / "data" / "crypto_kb.json"


def test_kb_default_impact_equals_the_engine_severity() -> None:
    findings = json.loads(KB.read_text(encoding="utf-8"))["findings"]["code"]
    shared = sorted(set(SEVERITY) & set(findings))
    assert "KMS_KEY_POLICY_PUBLIC" in shared and len(shared) >= 10
    wrong = {code: (findings[code]["default_impact"], _SEVERITY_IMPACT[SEVERITY[code]]) for code in shared
             if findings[code]["default_impact"] != _SEVERITY_IMPACT[SEVERITY[code]]}
    assert wrong == {}


def test_both_kb_copies_are_the_same_build() -> None:
    assert KB.read_bytes() == BACKEND_KB.read_bytes()
    assert json.loads(KB.read_text(encoding="utf-8"))["kb_version"] > "2026.11.05.1"
