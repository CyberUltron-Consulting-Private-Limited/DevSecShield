"""HIPAA applicability (NA) gate + negative flips — verdicts come from the GRAPH:
removing an edge or a node property flips pass->fail, and absence of a PHI model
makes HIPAA not-applicable (NA), never a failure.
"""

from __future__ import annotations

import pathlib

from aibom.compliance.engine import run_all
from aibom.scan.pipeline import scan_repo

_EX = pathlib.Path(__file__).resolve().parent.parent / "examples"


def _v(report: dict, framework: str) -> dict[str, str]:
    return {q["id"]: q["verdict"] for q in report[framework]["requirements"]}


def test_no_phi_fixture_hipaa_is_all_out_of_scope() -> None:
    report = run_all(scan_repo(_EX / "no-phi-model"))
    hipaa = report["hipaa"]
    assert hipaa["pass"] == 0 and hipaa["fail"] == 0
    # No PHI -> the framework is OUT_OF_SCOPE (distinct from a generic na).
    assert hipaa["out_of_scope"] == 13 and hipaa["na"] == 0
    assert hipaa["coverage"] is None  # 0 applicable -> NOT 0.0
    assert all(v == "out_of_scope" for v in _v(report, "hipaa").values())


def test_removing_phi_property_makes_hipaa_out_of_scope() -> None:
    r = scan_repo(_EX / "clinical-imaging")
    model = next(c for c in r.components if c.kind == "model")
    assert (model.properties or {}).get("clinical:processes_phi") == "true"
    model.properties = None
    # also clear the dataset PHI back-fill so the gate truly closes
    ds = next(c for c in r.components if c.kind == "dataset")
    ds.has_sensitive_personal_information = "no"
    report = run_all(r)
    assert report["hipaa"]["coverage"] is None
    assert all(v == "out_of_scope" for v in _v(report, "hipaa").values())


def test_dropping_served_by_edge_fails_hipaa_baa() -> None:
    r = scan_repo(_EX / "clinical-imaging")
    r.edges = [e for e in r.edges if e.rel != "served_by"]
    assert _v(run_all(r), "hipaa")["HIPAA-1"] == "fail"


def test_non_baa_service_fails_hipaa_baa() -> None:
    r = scan_repo(_EX / "clinical-imaging")
    svc = next(c for c in r.components if c.kind == "service")
    svc.properties = {"service:baa": "false"}
    assert _v(run_all(r), "hipaa")["HIPAA-1"] == "fail"


def test_flipping_dataset_to_phi_fails_deident_and_governance() -> None:
    r = scan_repo(_EX / "clinical-imaging")
    ds = next(c for c in r.components if c.kind == "dataset")
    ds.has_sensitive_personal_information = "yes"  # not de-identified, PHI retained
    report = run_all(r)
    assert _v(report, "hipaa")["HIPAA-2"] == "fail"  # de-identification
    assert _v(report, "hipaa")["HIPAA-3"] == "fail"  # retention proxy
    assert _v(report, "eu_ai_act_annexIV")["EUAIACT-7"] == "fail"  # data governance


def test_phi_model_with_no_datasets_fails_closed() -> None:
    r = scan_repo(_EX / "clinical-imaging")
    model = next(c for c in r.components if c.kind == "model")
    assert (model.properties or {}).get("clinical:processes_phi") == "true"
    r.edges = [e for e in r.edges if e.rel != "trained_on"]  # PHI model, no data
    v = _v(run_all(r), "hipaa")
    assert v["HIPAA-2"] == "fail" and v["HIPAA-3"] == "fail"


def test_phi_by_dataset_back_fills_hipaa_scope() -> None:
    """Card omits PHI but the dataset is PHI+non-de-identified -> still in scope."""
    r = scan_repo(_EX / "clinical-imaging")
    model = next(c for c in r.components if c.kind == "model")
    model.properties = None
    ds = next(c for c in r.components if c.kind == "dataset")
    ds.has_sensitive_personal_information = "yes"
    ds.anonymization_method = []
    report = run_all(r)
    assert report["hipaa"]["coverage"] is not None  # framework IS in scope
    assert _v(report, "hipaa")["HIPAA-2"] == "fail"


def test_removing_trained_on_fails_eu_governance_and_training() -> None:
    r = scan_repo(_EX / "clinical-imaging")
    r.edges = [e for e in r.edges if e.rel != "trained_on"]
    report = run_all(r)
    assert _v(report, "eu_ai_act_annexIV")["EUAIACT-2"] == "fail"  # no training data
    assert _v(report, "eu_ai_act_annexIV")["EUAIACT-7"] == "fail"  # data governance
