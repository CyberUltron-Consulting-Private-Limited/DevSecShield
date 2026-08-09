"""CERT-In Phase 1: cert_in_cbom compliance on synthetic-crypto-app."""

from __future__ import annotations

import copy
import os
from pathlib import Path

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


@pytest.fixture(scope="module")
def certin_cbom_result():
    # Import crypto module via CBOM compliance (side-effect registration).
    from aibom.cbom.compliance import run_cbom_compliance
    from aibom.cbom.pipeline import scan_crypto

    result = scan_crypto(Path(_FX))
    run_cbom_compliance(result)
    return result


def test_cert_in_cbom_present(certin_cbom_result) -> None:
    assert "cert_in_cbom" in certin_cbom_result.compliance
    fw = certin_cbom_result.compliance["cert_in_cbom"]
    assert isinstance(fw, dict)
    for k in (
        "pass",
        "fail",
        "na",
        "out_of_scope",
        "not_bom_evidenceable",
        "coverage",
        "requirements",
    ):
        assert k in fw
    assert fw["requirements"], "expected non-empty drilldown"


def test_cert_in_cbom_requirement_ids_complete(certin_cbom_result) -> None:
    from aibom.compliance.cert_in.common import requirements_for

    expected = {r.id for r in requirements_for("cert_in_cbom")}
    got = {r["id"] for r in certin_cbom_result.compliance["cert_in_cbom"]["requirements"]}
    assert expected == got, f"only_expected={expected - got} only_got={got - expected}"


def test_oid_unknown_is_nbe(certin_cbom_result) -> None:
    by_id = {
        r["id"]: r
        for r in certin_cbom_result.compliance["cert_in_cbom"]["requirements"]
    }
    for rid in ("T9-Algorithms-OID", "T9-Protocols-OID"):
        assert by_id[rid]["verdict"] == "not_bom_evidenceable", rid


def test_manuals_are_nbe(certin_cbom_result) -> None:
    by_id = {
        r["id"]: r
        for r in certin_cbom_result.compliance["cert_in_cbom"]["requirements"]
    }
    for n in range(1, 14):
        rid = f"8.4.1.{n}"
        assert by_id[rid]["verdict"] == "not_bom_evidenceable", rid


def test_core_identity_fields_pass(certin_cbom_result) -> None:
    by_id = {
        r["id"]: r
        for r in certin_cbom_result.compliance["cert_in_cbom"]["requirements"]
    }
    for rid in (
        "T9-Algorithms-Name",
        "T9-Algorithms-AssetType",
        "T9-Algorithms-Primitive",
        "T9-Certificates-Subject-Name",
        "T9-Certificates-Issuer-Name",
        "T9-Protocols-Name",
    ):
        assert by_id[rid]["verdict"] == "pass", (
            rid,
            by_id[rid]["verdict"],
            by_id[rid].get("evidence"),
        )


def test_cert_in_never_reads_flags(certin_cbom_result) -> None:
    from aibom.cbom.compliance import run_cbom_compliance

    cleared = copy.deepcopy(certin_cbom_result)
    cleared.flags.clear()
    run_cbom_compliance(cleared)
    a = {
        r["id"]: r["verdict"]
        for r in certin_cbom_result.compliance["cert_in_cbom"]["requirements"]
    }
    b = {
        r["id"]: r["verdict"]
        for r in cleared.compliance["cert_in_cbom"]["requirements"]
    }
    assert a == b


def test_cert_in_cbom_not_in_aibom_or_sbom_runners() -> None:
    from aibom.compliance import engine
    from aibom.sbom.compliance import SBOM_FRAMEWORKS

    assert "cert_in_cbom" not in engine.FRAMEWORKS
    assert "cert_in_cbom" not in SBOM_FRAMEWORKS


def test_empty_repo_out_of_scope(tmp_path: Path) -> None:
    from aibom.cbom.compliance import run_cbom_compliance
    from aibom.cbom.pipeline import scan_crypto

    empty = tmp_path / "empty"
    empty.mkdir()
    result = scan_crypto(empty)
    run_cbom_compliance(result)
    fw = result.compliance["cert_in_cbom"]
    assert fw["out_of_scope"] > 0
    assert fw["coverage"] is None
