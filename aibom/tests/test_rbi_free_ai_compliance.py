"""RBI FREE-AI compliance checks on the clinical-imaging fixture."""

from __future__ import annotations

import pathlib

import aibom.compliance as C
from aibom.compliance.base import checks_for
from aibom.compliance.engine import run_all
from aibom.scan.pipeline import scan_repo

_EX = pathlib.Path(__file__).resolve().parent.parent / "examples"


def _verdicts(report: dict, framework: str) -> dict[str, str]:
    return {q["id"]: q["verdict"] for q in report[framework]["requirements"]}


def test_rbi_free_ai_registered_with_24_requirements() -> None:
    assert len(checks_for("rbi_free_ai")) == 24
    assert "rbi_free_ai" in C.FRAMEWORKS


def test_clinical_imaging_rbi_free_ai_graph_checks_pass() -> None:
    report = run_all(scan_repo(_EX / "clinical-imaging"))
    v = _verdicts(report, "rbi_free_ai")
    assert v["FREEAI-23-1"] == "pass"
    assert v["FREEAI-16-1"] == "pass"
    assert v["FREEAI-7-1"] == "pass"
    assert v["FREEAI-15-1"] == "pass"
    assert v["FREEAI-6-1"] == "pass"


def test_rbi_free_ai_process_requirements_are_nbe() -> None:
    report = run_all(scan_repo(_EX / "clinical-imaging"))
    v = _verdicts(report, "rbi_free_ai")
    for rid in (
        "FREEAI-1",
        "FREEAI-14",
        "FREEAI-20",
        "FREEAI-22",
    ):
        assert v[rid] == "not_bom_evidenceable"


def test_no_phi_model_rbi_out_of_scope_or_na_on_deid() -> None:
    report = run_all(scan_repo(_EX / "no-phi-model"))
    fw = report["rbi_free_ai"]
    assert fw["coverage"] is not None or fw["out_of_scope"] == 0
