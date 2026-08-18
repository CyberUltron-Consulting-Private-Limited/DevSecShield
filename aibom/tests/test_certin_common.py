"""CERT-In Phase 0: common loaders + runner isolation locks."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

from aibom.compliance.cert_in.common import (
    CERTIN_DISCLAIMER,
    FRAMEWORK_LABELS,
    load_ledger,
    requirement_ids,
    requirements_for,
)


def test_ledger_loads_and_id_floor() -> None:
    doc = load_ledger()
    assert isinstance(doc, dict)
    ids = requirement_ids()
    assert len(ids) > 50
    assert CERTIN_DISCLAIMER
    assert "CERT-In" in CERTIN_DISCLAIMER or "09.07.2025" in CERTIN_DISCLAIMER
    assert set(FRAMEWORK_LABELS) == {
        "cert_in_cbom",
        "cert_in_aibom",
        "cert_in_sbom",
    }


def test_requirements_for_lanes_nonempty() -> None:
    for lane in ("cbom", "aibom", "sbom"):
        reqs = requirements_for(lane)
        assert reqs, f"expected requirements for lane={lane}"
        assert all(r.framework.startswith("cert_in_") for r in reqs)


def test_requirements_for_framework_key() -> None:
    reqs = requirements_for("cert_in_cbom")
    assert any(r.id.startswith("T9-") for r in reqs)
    assert any(r.id.startswith("8.4.1.") for r in reqs)


def test_cert_in_runner_isolation() -> None:
    from aibom.cbom.compliance import CBOM_FRAMEWORKS
    from aibom.compliance import engine
    from aibom.sbom.compliance import SBOM_FRAMEWORKS

    # Phase 1: CBOM; Phase 2: AIBOM; Phase 3: SBOM — each on its own runner.
    assert "cert_in_cbom" in CBOM_FRAMEWORKS
    assert "cert_in_aibom" in engine.FRAMEWORKS
    assert "cert_in_sbom" in SBOM_FRAMEWORKS
    assert "cert_in_aibom" not in CBOM_FRAMEWORKS
    assert "cert_in_sbom" not in CBOM_FRAMEWORKS
    assert "cert_in_sbom" not in engine.FRAMEWORKS
    assert "cert_in_cbom" not in engine.FRAMEWORKS
    assert "cert_in_cbom" not in SBOM_FRAMEWORKS
    assert "cert_in_aibom" not in SBOM_FRAMEWORKS


def test_compliance_init_imports_ai_only() -> None:
    src = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "aibom"
        / "compliance"
        / "__init__.py"
    ).read_text(encoding="utf-8")
    # Phase 2: ai is imported; CBOM/SBOM lane modules must stay out of AIBOM __init__.
    assert "from aibom.compliance.cert_in import ai" in src
    assert "import crypto" not in src
    assert "import sbom" not in src or "cert_in.sbom" not in src
    assert "cert_in import crypto" not in src
    assert "cert_in import sbom" not in src


def test_predicates_have_no_cbom_import() -> None:
    text = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "aibom"
        / "compliance"
        / "cert_in"
        / "predicates.py"
    ).read_text(encoding="utf-8")
    assert "aibom.cbom" not in text


def test_import_common_no_cbom_scanner_side_effects() -> None:
    doomed = [k for k in list(sys.modules) if k.startswith("aibom.cbom.scanners")]
    for k in doomed:
        del sys.modules[k]
    importlib.invalidate_caches()
    importlib.import_module("aibom.compliance.cert_in.common")
    leaked = [k for k in sys.modules if k.startswith("aibom.cbom.scanners")]
    assert leaked == [], f"common import leaked scanners: {leaked}"
