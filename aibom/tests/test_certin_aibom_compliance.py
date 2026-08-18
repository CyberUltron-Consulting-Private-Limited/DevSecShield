"""CERT-In Phase 2: cert_in_aibom compliance on clinical-imaging example."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

_EX = Path(__file__).resolve().parent.parent / "examples" / "clinical-imaging"


@pytest.fixture(scope="module")
def certin_aibom_result():
    import aibom.compliance  # noqa: F401 — side-effect registers cert_in_aibom
    from aibom.compliance.engine import run_all
    from aibom.scan.pipeline import scan_repo

    result = scan_repo(_EX)
    run_all(result)
    return result


def test_cert_in_aibom_present(certin_aibom_result) -> None:
    assert "cert_in_aibom" in certin_aibom_result.compliance
    fw = certin_aibom_result.compliance["cert_in_aibom"]
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


def test_cert_in_aibom_requirement_ids_complete(certin_aibom_result) -> None:
    from aibom.compliance.cert_in.common import requirements_for

    expected = {r.id for r in requirements_for("cert_in_aibom")}
    got = {
        r["id"]
        for r in certin_aibom_result.compliance["cert_in_aibom"]["requirements"]
    }
    assert expected == got, f"only_expected={expected - got} only_got={got - expected}"
    assert len(got) == 32


def test_manuals_are_nbe(certin_aibom_result) -> None:
    by_id = {
        r["id"]: r
        for r in certin_aibom_result.compliance["cert_in_aibom"]["requirements"]
    }
    for n in range(1, 14):
        rid = f"9.4.1.{n}"
        assert by_id[rid]["verdict"] == "not_bom_evidenceable", rid


def test_core_fail_mode_fields_pass(certin_aibom_result) -> None:
    by_id = {
        r["id"]: r
        for r in certin_aibom_result.compliance["cert_in_aibom"]["requirements"]
    }
    for rid in (
        "T10-Model-Name",
        "T10-Model-Version",
        "T10-Model-Licensing-Information",
        "T10-Software-Dependencies",
    ):
        assert by_id[rid]["verdict"] == "pass", (
            rid,
            by_id[rid]["verdict"],
            by_id[rid].get("evidence"),
        )


def test_cert_in_never_reads_flags(certin_aibom_result) -> None:
    from aibom.compliance.engine import run_all

    cleared = copy.deepcopy(certin_aibom_result)
    cleared.flags.clear()
    run_all(cleared)
    a = {
        r["id"]: r["verdict"]
        for r in certin_aibom_result.compliance["cert_in_aibom"]["requirements"]
    }
    b = {
        r["id"]: r["verdict"]
        for r in cleared.compliance["cert_in_aibom"]["requirements"]
    }
    assert a == b


def test_cert_in_aibom_not_in_cbom_or_sbom_runners() -> None:
    from aibom.cbom.compliance import CBOM_FRAMEWORKS
    from aibom.sbom.compliance import SBOM_FRAMEWORKS

    assert "cert_in_aibom" not in CBOM_FRAMEWORKS
    assert "cert_in_aibom" not in SBOM_FRAMEWORKS


def test_empty_repo_out_of_scope(tmp_path: Path) -> None:
    import aibom.compliance  # noqa: F401
    from aibom.compliance.engine import run_all
    from aibom.scan.pipeline import scan_repo

    empty = tmp_path / "empty"
    empty.mkdir()
    result = scan_repo(empty)
    run_all(result)
    fw = result.compliance["cert_in_aibom"]
    assert fw["out_of_scope"] > 0
    assert fw["coverage"] is None
