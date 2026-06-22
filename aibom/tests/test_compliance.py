"""Phase-3 compliance checks over REAL fixture graphs (never mock ScanResult).

Asserts the requirement→verdict mapping per framework, the coverage math
(pass/(pass+fail), NA excluded), and the LANE invariant: no check reads a flag
(clearing result.flags must not change any verdict).
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


# --------------------------------------------------------------------------- #
# Registry shape
# --------------------------------------------------------------------------- #


def test_registry_has_all_frameworks_with_expected_counts() -> None:
    counts = {fw: len(checks_for(fw)) for fw in C.FRAMEWORKS}
    assert counts == {
        "fda_524b": 6,
        "eu_ai_act_annexIV": 6,
        "gmlp": 10,
        "hipaa": 5,
        "nist_rmf": 4,
    }


def test_run_all_writes_compliance_and_disclaimer() -> None:
    r = scan_repo(_EX / "clinical-imaging")
    report = run_all(r)
    assert r.compliance is report  # written in place
    assert "advisory only" in report["disclaimer"]
    for fw in C.FRAMEWORKS:
        assert set(report[fw]) == {"pass", "fail", "na", "coverage", "requirements"}


# --------------------------------------------------------------------------- #
# Per-framework verdicts on the well-formed clinical-imaging fixture
# --------------------------------------------------------------------------- #


def test_clinical_imaging_verdicts() -> None:
    report = _report("clinical-imaging")
    eu = _verdicts(report, "eu_ai_act_annexIV")
    assert eu["AIV-1"] == "pass" and eu["AIV-2"] == "pass" and eu["AIV-3"] == "pass"
    assert eu["AIV-4"] == "pass" and eu["AIV-5"] == "pass" and eu["AIV-6"] == "pass"

    hipaa = _verdicts(report, "hipaa")
    assert hipaa["HIPAA-1"] == "pass"  # served_by a BAA'd vendor
    assert hipaa["HIPAA-2"] == "pass"  # de-identified training data
    assert hipaa["HIPAA-4"] == "na"  # retention terms not in graph

    nist = _verdicts(report, "nist_rmf")
    assert all(v == "pass" for v in nist.values())

    gmlp = _verdicts(report, "gmlp")
    assert gmlp["GMLP-1"] == "na" and gmlp["GMLP-4"] == "na" and gmlp["GMLP-5"] == "na"
    assert gmlp["GMLP-10"] == "na"  # not deployed in this fixture
    assert gmlp["GMLP-7"] == "pass"  # human-in-the-loop


def test_coverage_excludes_na_from_denominator() -> None:
    report = _report("clinical-imaging")
    gmlp = report["gmlp"]
    # 6 pass, 0 fail, 4 na -> coverage = 6/6 = 1.0 (NA excluded), not 6/10.
    assert gmlp["pass"] == 6 and gmlp["fail"] == 0 and gmlp["na"] == 4
    assert gmlp["coverage"] == 1.0


# --------------------------------------------------------------------------- #
# Multi-site: deployed_at drift drives GMLP-10 + NIST-MANAGE (graph-aware)
# --------------------------------------------------------------------------- #


def test_multi_site_drift_passes_gmlp10_and_nist_manage() -> None:
    report = _report("multi-site")
    assert _verdicts(report, "gmlp")["GMLP-10"] == "pass"  # site:drift_status present
    assert _verdicts(report, "nist_rmf")["NIST-MANAGE"] == "pass"


# --------------------------------------------------------------------------- #
# LANE invariant: no check reads result.flags
# --------------------------------------------------------------------------- #


def test_no_check_reads_flags() -> None:
    """Clearing result.flags must not change any verdict (checks read the graph)."""
    r = scan_repo(_EX / "clinical-imaging")
    assert r.flags  # precondition: the fixture does raise flags
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


def test_human_oversight_is_structured_not_free_text() -> None:
    """AIV-4 / GMLP-7 read the structured model_card.human_oversight fact, not the
    free-text users list — so it cannot be false-passed by a negation."""
    r = scan_repo(_EX / "clinical-imaging")
    model = next(c for c in r.components if c.kind == "model")
    assert model.model_card.human_oversight == "yes"  # fixture asserts oversight
    assert _verdicts(run_all(r), "eu_ai_act_annexIV")["AIV-4"] == "pass"

    # Flip the structured fact off: the users text still says "radiologist
    # (human-in-the-loop)", but the verdict must FAIL (no substring false-pass).
    model.model_card.human_oversight = "no"
    report = run_all(r)
    assert "radiologist" in " ".join(model.model_card.considerations.users).lower()
    assert _verdicts(report, "eu_ai_act_annexIV")["AIV-4"] == "fail"
    assert _verdicts(report, "gmlp")["GMLP-7"] == "fail"
