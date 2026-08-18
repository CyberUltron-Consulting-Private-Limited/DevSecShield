"""SEBI CSCRF AIBOM hermetic compliance tests."""

from __future__ import annotations

import copy

from aibom.compliance.base import models
from aibom.compliance.engine import run_all, run_framework
from aibom.compliance.sebi_cscrf.common import manual_ids_for, requirements_for
from aibom.model.component import MetadataComponent, ModelCard, ModelComponent
from aibom.model.result import ScanResult


def _model(
    *,
    name: str = "demo-model",
    version: str | None = "1.0.0",
    licenses: list | None = None,
    props: dict | None = None,
) -> ModelComponent:
    return ModelComponent(
        bom_ref=f"model-{name}",
        name=name,
        version=version,
        licenses=licenses if licenses is not None else [],
        model_card=ModelCard(),
        properties=props or {},
    )


_LIC_MIT = [{"license": {"id": "MIT"}}]
_LIC_APACHE = [{"license": {"id": "Apache-2.0"}}]


def _result(*comps) -> ScanResult:
    return ScanResult(
        subject=MetadataComponent(name="sebi-aibom-fixture"),
        components=list(comps),
    )


def test_sebi_cscrf_aibom_present_and_ids() -> None:
    r = _result(_model(licenses=_LIC_MIT))
    report = run_all(r)
    assert "sebi_cscrf_aibom" in report
    fw = report["sebi_cscrf_aibom"]
    expected = {req.id for req in requirements_for("sebi_cscrf_aibom")}
    got = {q["id"] for q in fw["requirements"]}
    assert expected == got


def test_sebi_cscrf_aibom_autos_on_named_versioned_model() -> None:
    r = _result(_model(licenses=_LIC_APACHE, props={"sha256": "abc"}))
    fw = run_framework(r, "sebi_cscrf_aibom")
    by_id = {q["id"]: q["verdict"] for q in fw["requirements"]}
    assert by_id["CSCRF-ID.AM.S1-inv"] == "pass"
    assert by_id["CSCRF-ID.AM.S1-ver"] == "pass"
    assert by_id["CSCRF-GV.SC.S5-dep"] == "na"  # no framework edges
    assert by_id["CSCRF-GV.SC.S5-lic"] == "pass"
    assert by_id["CSCRF-GV.SC.S5-hash"] == "pass"


def test_sebi_cscrf_aibom_missing_version_fails() -> None:
    r = _result(_model(version=None))
    fw = run_framework(r, "sebi_cscrf_aibom")
    by_id = {q["id"]: q["verdict"] for q in fw["requirements"]}
    assert by_id["CSCRF-ID.AM.S1-ver"] == "fail"


def test_sebi_cscrf_aibom_missing_license_is_nbe() -> None:
    r = _result(_model(licenses=[]))
    fw = run_framework(r, "sebi_cscrf_aibom")
    by_id = {q["id"]: q["verdict"] for q in fw["requirements"]}
    assert by_id["CSCRF-GV.SC.S5-lic"] == "not_bom_evidenceable"
    assert by_id["CSCRF-GV.SC.S5-hash"] == "not_bom_evidenceable"


def test_sebi_cscrf_aibom_manuals_are_nbe() -> None:
    r = _result(_model())
    fw = run_framework(r, "sebi_cscrf_aibom")
    by_id = {q["id"]: q["verdict"] for q in fw["requirements"]}
    for rid in manual_ids_for("aibom"):
        assert by_id[rid] == "not_bom_evidenceable", rid


def test_sebi_cscrf_aibom_empty_is_oos() -> None:
    r = _result()
    assert models(r) == []
    fw = run_framework(r, "sebi_cscrf_aibom")
    assert fw["coverage"] is None
    assert fw["out_of_scope"] > 0


def test_sebi_cscrf_aibom_never_reads_flags() -> None:
    from aibom.model.result import Flag

    r = _result(_model(licenses=_LIC_MIT, props={"sha256": "x"}))
    fw1 = run_framework(r, "sebi_cscrf_aibom")
    before = {q["id"]: q["verdict"] for q in fw1["requirements"]}
    r2 = copy.deepcopy(r)
    r2.flags = [Flag("FAKE", "x", "error", "should not affect")]
    fw2 = run_framework(r2, "sebi_cscrf_aibom")
    after = {q["id"]: q["verdict"] for q in fw2["requirements"]}
    assert before == after
