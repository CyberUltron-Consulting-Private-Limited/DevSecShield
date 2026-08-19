"""CERT-In Phase 6 Gate A — hermetic regression lock (named bundle).

  cd backend && uv run pytest tests/test_certin_phase6_hermetic.py -q
"""
from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_FRONTEND = _REPO / "frontend"

pytestmark = pytest.mark.certin_phase6_hermetic


def test_phase6_certin_modules_importable() -> None:
    sys.path.insert(0, str(_REPO))
    from backend.utilities.dashboard import certin_posture  # noqa: F401

    assert callable(certin_posture.build_certin_posture)
    # aibom package imports require aibom/.venv (jsonschema); assert sources present
    cert_in = _REPO / "aibom/src/aibom/compliance/cert_in"
    for name in ("common.py", "sign.py", "vex.py", "ledger.yaml", "crypto.py", "ai.py", "sbom.py"):
        assert (cert_in / name).is_file(), name
    assert (_REPO / "aibom/config/cert-in-rollup.yaml").is_file()
    # Backend image context is backend/ only — VEX/sign must also ship there.
    backend_cert_in = _REPO / "backend/utilities/compliance/cert_in"
    for name in ("vex.py", "sign.py"):
        assert (backend_cert_in / name).is_file(), name


def test_phase6_matrix_manifest_has_15_rows() -> None:
    path = _REPO / "bench" / "certin" / "repos.tsv"
    assert path.is_file(), "bench/certin/repos.tsv missing"
    rows = [
        ln
        for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")
    ]
    assert len(rows) == 15, f"expected 15 matrix rows, got {len(rows)}"
    lanes = {r.split("\t")[0] for r in rows}
    assert lanes == {"cbom", "ai_bom", "sbom_sca"}


def test_phase6_product_fe_zero_qbom() -> None:
    pat = re.compile(r"\bQBOM\b")
    hits: list[str] = []
    for root_name in ("app", "components", "utils"):
        root = _FRONTEND / root_name
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.suffix not in {".ts", ".tsx", ".js", ".jsx"}:
                continue
            if "node_modules" in path.parts or ".next" in path.parts:
                continue
            if pat.search(path.read_text(encoding="utf-8", errors="ignore")):
                hits.append(str(path.relative_to(_REPO)))
    assert hits == [], f"QBOM in product FE: {hits}"


def test_phase6_india_default_still_all() -> None:
    targets = [
        _FRONTEND / "components/cbom/CbomCryptoCharts.tsx",
        _FRONTEND / "components/SbomResults.tsx",
        _FRONTEND / "components/compliance/ComplianceMatrix.tsx",
    ]
    for path in targets:
        text = path.read_text(encoding="utf-8")
        assert 'defaultGroup="all"' in text or 'defaultGroup = "all"' in text
        assert 'defaultGroup="india"' not in text
