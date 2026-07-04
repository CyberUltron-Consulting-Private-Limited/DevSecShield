"""Secret scanner — REAL fixtures, never mocked (aibom/contract/testing).

The planted FAKE key in synthetic-ai-app is detected exactly once (even though it
matches both the explicit ``sk-`` rule and the generic ``OPENAI_API_KEY = "…"``
rule — dedup is by value), and the clinical SaMD fixture has no secret.
"""
from __future__ import annotations

import os

from aibom.scan.pipeline import scan_repo

_HERE = os.path.dirname(os.path.abspath(__file__))


def _fx(name: str) -> str:
    return os.path.join(_HERE, "fixtures", name)


def test_planted_key_detected_exactly_once() -> None:
    result = scan_repo(_fx("synthetic-ai-app"), level=1)

    secrets = [c for c in result.components if c.kind == "secret"]
    assert len(secrets) == 1, (
        f"expected exactly 1 secret, got {len(secrets)}: "
        f"{[(c.name, (c.properties or {}).get('discovery:source')) for c in secrets]}"
    )

    flags = [f for f in result.flags if f.code == "HARDCODED_SECRET"]
    assert len(flags) == 1, f"expected 1 HARDCODED_SECRET flag, got {len(flags)}"
    assert flags[0].severity == "error", "secret flag must be high (SARIF error)"
    assert flags[0].target == secrets[0].bom_ref

    props = secrets[0].properties or {}
    assert props.get("discovery:source") == "app.py"
    # The raw secret must never be stored — only a masked form.
    assert "0000000000" not in props.get("secret:masked", "")


def test_no_secret_in_clinical_fixture() -> None:
    result = scan_repo(_fx("synthetic-clinical-samd"), level=1)
    secrets = [c for c in result.components if c.kind == "secret"]
    assert secrets == [], (
        f"clinical SaMD fixture must contain no secrets, found: "
        f"{[c.name for c in secrets]}"
    )
    assert not [f for f in result.flags if f.code == "HARDCODED_SECRET"]
