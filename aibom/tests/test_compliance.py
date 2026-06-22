"""Phase-3 compliance checks over REAL fixture graphs (never mock ScanResult).

Granular requirement enumeration (fda 8 / eu 17 / gmlp 10 / hipaa 13 / nist 16).
Asserts requirement->verdict mapping, coverage math (pass/(pass+fail), NA
excluded), and the LANE invariant: no check reads a flag.
"""

from __future__ import annotations

import dataclasses
import pathlib

import aibom.compliance as C
from aibom.compliance.base import checks_for
from aibom.compliance.engine import run_all
from aibom.scan.pipeline import scan_repo

_EX = pathlib.Path(__file__).resolve().parent.parent / "examples"


def _verdicts(report: dict, framework: str) -> dict[str, str]:
    return {q["id"]: q["verdict"] for q in report[framework]["requirements"]}


def _report(fixture: str) -> dict:
    return run_all(scan_repo(_EX / fixture))


def test_registry_has_all_frameworks_with_expected_counts() -> None:
    counts = {fw: len(checks_for(fw)) for fw in C.FRAMEWORKS}
    assert counts == {
        "fda_524b": 8,
        "eu_ai_act_annexIV": 17,
        "gmlp": 10,
        "hipaa": 13,
        "nist_rmf": 16,
    }


def test_run_all_writes_compliance_and_disclaimer() -> None:
    r = scan_repo(_EX / "clinical-imaging")
    report = run_all(r)
    assert r.compliance is report
    assert "advisory only" in report["disclaimer"]
    for fw in C.FRAMEWORKS:
        assert set(report[fw]) == {"pass", "fail", "na", "coverage", "requirements"}


def test_clinical_imaging_flagship_and_subcategory_verdicts() -> None:
    report = _report("clinical-imaging")
    # EU data-governance flagship (de-identified training data).
    assert _verdicts(report, "eu_ai_act_annexIV")["EUAIACT-7"] == "pass"
    assert _verdicts(report, "eu_ai_act_annexIV")["EUAIACT-11"] == "pass"  # high-risk
    # HIPAA BAA flagship.
    assert _verdicts(report, "hipaa")["HIPAA-1"] == "pass"
    assert _verdicts(report, "hipaa")["HIPAA-2"] == "pass"
    # NIST subcategories that are graph-evidenceable.
    nist = _verdicts(report, "nist_rmf")
    assert nist["GV-2"] == "pass" and nist["MP-1"] == "pass" and nist["ME-2"] == "pass"
    assert nist["MG-1"] == "na" and nist["GV-1"] == "na"  # process subcategories


def test_coverage_excludes_na_from_denominator() -> None:
    nist = _report("clinical-imaging")["nist_rmf"]
    # 6 pass, 0 fail, 10 na -> coverage = 6/6 = 1.0 (NA excluded), not 6/16.
    assert nist["pass"] == 6 and nist["fail"] == 0 and nist["na"] == 10
    assert nist["coverage"] == 1.0


def test_multi_site_drift_passes_gmlp10() -> None:
    report = _report("multi-site")
    assert _verdicts(report, "gmlp")["GMLP-10"] == "pass"  # site:drift_status present
    assert _verdicts(report, "nist_rmf")["GV-2"] == "pass"  # BAA-bound vendor


def test_no_check_reads_flags() -> None:
    r = scan_repo(_EX / "clinical-imaging")
    assert r.flags  # precondition
    r_noflags = dataclasses.replace(r, flags=[])
    for fw in C.FRAMEWORKS:
        for requirement, check in checks_for(fw):
            assert (
                check(r, requirement).verdict
                == check(r_noflags, requirement).verdict
            )


def test_every_verdict_is_pass_fail_or_na() -> None:
    for fixture in ("clinical-imaging", "no-phi-model", "multi-site"):
        report = _report(fixture)
        for fw in C.FRAMEWORKS:
            for q in report[fw]["requirements"]:
                assert q["verdict"] in {"pass", "fail", "na"}


def test_resolve_framework_aliases() -> None:
    assert C.resolve_framework("hipaa") == "hipaa"
    assert C.resolve_framework("euaiact") == "eu_ai_act_annexIV"
    assert C.resolve_framework("nist") == "nist_rmf"
