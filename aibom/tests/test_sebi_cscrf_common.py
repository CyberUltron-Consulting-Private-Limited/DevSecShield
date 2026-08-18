"""SEBI CSCRF Phase 0: common loaders + runner isolation locks."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

from aibom.compliance.sebi_cscrf.common import (
    FRAMEWORK_LABELS,
    SEBI_DISCLAIMER,
    load_ledger,
    requirement_ids,
    requirements_for,
)


def test_ledger_loads_and_id_floor() -> None:
    doc = load_ledger()
    assert isinstance(doc, dict)
    ids = requirement_ids()
    assert len(ids) >= 40
    assert SEBI_DISCLAIMER
    assert "SEBI" in SEBI_DISCLAIMER
    assert "certification" in SEBI_DISCLAIMER.lower()
    assert set(FRAMEWORK_LABELS) == {
        "sebi_cscrf_cbom",
        "sebi_cscrf_aibom",
        "sebi_cscrf_sbom",
    }


def test_requirements_for_lanes_nonempty() -> None:
    for lane in ("cbom", "aibom", "sbom"):
        reqs = requirements_for(lane)
        assert reqs, f"expected requirements for lane={lane}"
        assert all(r.framework.startswith("sebi_cscrf_") for r in reqs)


def test_requirements_for_framework_key() -> None:
    reqs = requirements_for("sebi_cscrf_cbom")
    assert any(r.id.startswith("CSCRF-QC-") for r in reqs)
    assert any(r.id.startswith("CSCRF-DS-") for r in reqs)


def test_sebi_runner_isolation() -> None:
    from aibom.cbom.compliance import CBOM_FRAMEWORKS
    from aibom.compliance import engine
    from aibom.sbom.compliance import SBOM_FRAMEWORKS

    assert "sebi_cscrf_cbom" in CBOM_FRAMEWORKS
    assert "sebi_cscrf_aibom" in engine.FRAMEWORKS
    assert "sebi_cscrf_sbom" in SBOM_FRAMEWORKS
    assert "sebi_cscrf_aibom" not in CBOM_FRAMEWORKS
    assert "sebi_cscrf_sbom" not in CBOM_FRAMEWORKS
    assert "sebi_cscrf_sbom" not in engine.FRAMEWORKS
    assert "sebi_cscrf_cbom" not in engine.FRAMEWORKS
    assert "sebi_cscrf_cbom" not in SBOM_FRAMEWORKS
    assert "sebi_cscrf_aibom" not in SBOM_FRAMEWORKS


def test_compliance_init_imports_ai_only() -> None:
    src = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "aibom"
        / "compliance"
        / "__init__.py"
    ).read_text(encoding="utf-8")
    assert "from aibom.compliance.sebi_cscrf import ai" in src
    assert "sebi_cscrf import crypto" not in src
    assert "sebi_cscrf import sbom" not in src


def test_import_common_no_cbom_scanner_side_effects() -> None:
    doomed = [k for k in list(sys.modules) if k.startswith("aibom.cbom.scanners")]
    for k in doomed:
        del sys.modules[k]
    importlib.invalidate_caches()
    importlib.import_module("aibom.compliance.sebi_cscrf.common")
    leaked = [k for k in sys.modules if k.startswith("aibom.cbom.scanners")]
    assert leaked == [], f"common import leaked scanners: {leaked}"


def test_ledger_md_covers_yaml_ids() -> None:
    yaml_ids = requirement_ids()
    md = (
        Path(__file__).resolve().parents[2] / "docs" / "sebi" / "LEDGER.md"
    ).read_text(encoding="utf-8")
    missing = [
        rid
        for rid in sorted(yaml_ids)
        if f"`{rid}`" not in md and rid not in md
    ]
    assert missing == [], f"LEDGER.md missing ids: {missing[:10]}"
