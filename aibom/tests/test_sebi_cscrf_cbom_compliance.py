"""SEBI CSCRF CBOM hermetic compliance tests."""

from __future__ import annotations

import copy
import os
from pathlib import Path

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


@pytest.fixture(scope="module")
def sebi_cbom_result():
    from aibom.cbom.compliance import run_cbom_compliance
    from aibom.cbom.pipeline import scan_crypto

    result = scan_crypto(Path(_FX))
    run_cbom_compliance(result)
    return result


def test_sebi_cscrf_cbom_present(sebi_cbom_result) -> None:
    assert "sebi_cscrf_cbom" in sebi_cbom_result.compliance
    fw = sebi_cbom_result.compliance["sebi_cscrf_cbom"]
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
    assert fw["requirements"]


def test_sebi_cscrf_cbom_requirement_ids_match_ledger(sebi_cbom_result) -> None:
    from aibom.compliance.sebi_cscrf.common import requirements_for

    expected = {r.id for r in requirements_for("sebi_cscrf_cbom")}
    reqs = sebi_cbom_result.compliance["sebi_cscrf_cbom"]["requirements"]
    got = {r["id"] for r in reqs}
    assert expected == got, f"only_expected={expected - got} only_got={got - expected}"


def test_sebi_cscrf_cbom_manuals_are_nbe(sebi_cbom_result) -> None:
    from aibom.compliance.sebi_cscrf.common import manual_ids_for

    by_id = {
        r["id"]: r
        for r in sebi_cbom_result.compliance["sebi_cscrf_cbom"]["requirements"]
    }
    for rid in manual_ids_for("cbom"):
        assert by_id[rid]["verdict"] == "not_bom_evidenceable", rid


def test_sebi_cscrf_cbom_qc_inventory_and_migration(sebi_cbom_result) -> None:
    by_id = {
        r["id"]: r
        for r in sebi_cbom_result.compliance["sebi_cscrf_cbom"]["requirements"]
    }
    assert by_id["CSCRF-QC-1"]["verdict"] == "pass"
    # Fixture has RSA QV assets with migration targets from PQC scanner.
    assert by_id["CSCRF-QC-2"]["verdict"] == "pass"
    assert by_id["CSCRF-QC-9"]["verdict"] == "pass"
    # Weak fixture: DS checks fail.
    assert by_id["CSCRF-DS-1"]["verdict"] == "fail"
    assert by_id["CSCRF-DS-6"]["verdict"] == "fail"
    assert by_id["CSCRF-SC-1"]["verdict"] == "pass"


def test_sebi_cscrf_cbom_never_reads_flags(sebi_cbom_result) -> None:
    from aibom.cbom.compliance import run_cbom_compliance

    cleared = copy.deepcopy(sebi_cbom_result)
    cleared.flags = []
    run_cbom_compliance(cleared)
    before = {
        r["id"]: r["verdict"]
        for r in sebi_cbom_result.compliance["sebi_cscrf_cbom"]["requirements"]
    }
    after = {
        r["id"]: r["verdict"]
        for r in cleared.compliance["sebi_cscrf_cbom"]["requirements"]
    }
    assert before == after


def test_sebi_cscrf_cbom_empty_is_oos() -> None:
    from aibom.cbom.compliance import run_cbom_compliance
    from aibom.model.component import MetadataComponent
    from aibom.model.result import ScanResult

    empty = ScanResult(subject=MetadataComponent(name="empty"))
    run_cbom_compliance(empty)
    fw = empty.compliance["sebi_cscrf_cbom"]
    assert fw["coverage"] is None
    assert fw["out_of_scope"] > 0
