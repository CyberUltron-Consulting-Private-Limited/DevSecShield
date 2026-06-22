"""HIPAA applicability (NA) gate + negative flips — proving verdicts come from
the GRAPH: removing an edge or a node property flips pass->fail, and absence of a
PHI model makes HIPAA not-applicable (NA), never a failure.
"""

from __future__ import annotations

import pathlib

from aibom.compliance.engine import run_all
from aibom.scan.pipeline import scan_repo

_EX = pathlib.Path(__file__).resolve().parent.parent / "examples"


def _v(report: dict, framework: str) -> dict[str, str]:
    return {q["id"]: q["verdict"] for q in report[framework]["requirements"]}


# --------------------------------------------------------------------------- #
# NA gate: no PHI model -> HIPAA all NA, coverage None (not a 0% failure)
# --------------------------------------------------------------------------- #


def test_no_phi_fixture_hipaa_is_all_na() -> None:
    report = run_all(scan_repo(_EX / "no-phi-model"))
    hipaa = report["hipaa"]
    assert hipaa["pass"] == 0 and hipaa["fail"] == 0 and hipaa["na"] == 5
    assert hipaa["coverage"] is None  # 0 applicable -> NOT 0.0
    assert all(v == "na" for v in _v(report, "hipaa").values())


def test_removing_phi_property_makes_hipaa_na() -> None:
    """The HIPAA gate reads clinical:processes_phi (a node property), not a flag."""
    r = scan_repo(_EX / "clinical-imaging")
    model = next(c for c in r.components if c.kind == "model")
    assert (model.properties or {}).get("clinical:processes_phi") == "true"
    model.properties = None  # strip the authoritative PHI graph fact
    report = run_all(r)
    assert report["hipaa"]["coverage"] is None
    assert all(v == "na" for v in _v(report, "hipaa").values())


# --------------------------------------------------------------------------- #
# Negative flips: drop the served_by edge / flip de-identification -> fail
# --------------------------------------------------------------------------- #


def test_dropping_served_by_edge_fails_hipaa_baa() -> None:
    r = scan_repo(_EX / "clinical-imaging")
    r.edges = [e for e in r.edges if e.rel != "served_by"]
    report = run_all(r)
    assert _v(report, "hipaa")["HIPAA-1"] == "fail"  # no BAA'd serving vendor
    assert _v(report, "hipaa")["HIPAA-3"] == "fail"  # no documented data flow


def test_non_baa_service_fails_hipaa_baa() -> None:
    r = scan_repo(_EX / "clinical-imaging")
    svc = next(c for c in r.components if c.kind == "service")
    svc.properties = {"service:baa": "false"}
    assert _v(run_all(r), "hipaa")["HIPAA-1"] == "fail"


def test_flipping_dataset_to_phi_fails_deidentification() -> None:
    r = scan_repo(_EX / "clinical-imaging")
    ds = next(c for c in r.components if c.kind == "dataset")
    ds.has_sensitive_personal_information = "yes"  # no longer de-identified
    report = run_all(r)
    assert _v(report, "hipaa")["HIPAA-2"] == "fail"
    assert _v(report, "eu_ai_act_annexIV")["AIV-2"] == "fail"  # data governance


def test_removing_trained_on_edge_fails_eu_data_governance() -> None:
    r = scan_repo(_EX / "clinical-imaging")
    r.edges = [e for e in r.edges if e.rel != "trained_on"]
    report = run_all(r)
    assert _v(report, "eu_ai_act_annexIV")["AIV-2"] == "fail"  # no training data
    assert _v(report, "eu_ai_act_annexIV")["AIV-5"] == "fail"  # no lineage


def test_unlabeled_dataset_sensitivity_fails_hipaa_minimum_necessary() -> None:
    """HIPAA-5 reads the dataset's sensitivity label off the graph: an *unlabeled*
    (None) dataset flips minimum-necessary pass->fail (the one fallible HIPAA
    check whose fail path was otherwise untested)."""
    r = scan_repo(_EX / "clinical-imaging")
    ds = next(c for c in r.components if c.kind == "dataset")
    ds.has_sensitive_personal_information = None  # sensitivity unlabeled
    report = run_all(r)
    assert _v(report, "hipaa")["HIPAA-5"] == "fail"
    assert report["hipaa"]["coverage"] == 0.75  # 3 pass / (3 pass + 1 fail)


def test_phi_model_with_no_datasets_fails_closed() -> None:
    """A PHI model with no trained_on data cannot vacuously pass HIPAA-2/HIPAA-5."""
    r = scan_repo(_EX / "clinical-imaging")
    model = next(c for c in r.components if c.kind == "model")
    assert (model.properties or {}).get("clinical:processes_phi") == "true"
    r.edges = [e for e in r.edges if e.rel != "trained_on"]  # PHI model, no datasets
    v = _v(run_all(r), "hipaa")
    assert v["HIPAA-2"] == "fail"  # de-identification cannot be asserted
    assert v["HIPAA-5"] == "fail"  # sensitivity labeling cannot be asserted


def test_phi_by_dataset_back_fills_hipaa_scope() -> None:
    """A model whose card omits PHI but whose dataset is PHI+non-de-identified is
    pulled into HIPAA scope (fail-closed gate) — not silently all-NA."""
    r = scan_repo(_EX / "clinical-imaging")
    model = next(c for c in r.components if c.kind == "model")
    model.properties = None  # card no longer asserts PHI
    ds = next(c for c in r.components if c.kind == "dataset")
    ds.has_sensitive_personal_information = "yes"  # dataset graph indicates PHI
    ds.anonymization_method = []  # and is not de-identified
    report = run_all(r)
    assert report["hipaa"]["coverage"] is not None  # framework IS in scope
    assert _v(report, "hipaa")["HIPAA-2"] == "fail"  # non-de-identified PHI training
