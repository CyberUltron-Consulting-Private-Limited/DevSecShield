"""Tri-state compliance verdicts + evidence-attachment — real pipeline, no mocks.

OUT_OF_SCOPE (framework doesn't apply) is distinct from fail and from a generic
NA; NOT_BOM_EVIDENCEABLE (process evidence a scan can't see) is attestable and
flips to pass_with_evidence. clinical-samd yields REAL pass/fail across
GMLP/EU/FDA; chroma shows GMLP/FDA/HIPAA out_of_scope (not fail) while NIST + EU
resolve to pass/fail. Coverage = pass/(pass+fail); the other states are excluded.
"""
from __future__ import annotations

import os
from collections import Counter

import pytest

from aibom.compliance.engine import run_all
from aibom.scan.pipeline import scan_repo

_HERE = os.path.dirname(os.path.abspath(__file__))


def _fx(name: str) -> str:
    return os.path.join(_HERE, "fixtures", name)


def _spread(comp: dict, fw: str) -> Counter:
    return Counter(q["verdict"] for q in comp[fw]["requirements"])


def test_clinical_samd_yields_real_pass_fail_across_gmlp_eu_fda() -> None:
    r = scan_repo(_fx("synthetic-clinical-samd"), level=4)
    run_all(r)
    for fw in ("gmlp", "eu_ai_act_annexIV", "fda_524b"):
        f = r.compliance[fw]
        assert f["pass"] >= 1, f"{fw} produced no pass: {f}"
        assert f["coverage"] is not None, f"{fw} should be in scope"
        assert f["out_of_scope"] == 0
    # GMLP resolves graph pass/fail — not the old 'no model component' NA.
    g = _spread(r.compliance, "gmlp")
    assert g.get("pass", 0) >= 1 and g.get("fail", 0) >= 0
    assert "out_of_scope" not in g


def test_chroma_medical_frameworks_out_of_scope_not_fail() -> None:
    if not os.path.isdir(_fx("chroma")):
        pytest.skip("chroma clone absent (gitignored)")
    r = scan_repo(_fx("chroma"), level=4)
    run_all(r)
    # GMLP / FDA / HIPAA do not apply to a non-medical, non-PHI artifact.
    for fw in ("gmlp", "fda_524b", "hipaa"):
        f = r.compliance[fw]
        assert f["out_of_scope"] >= 1 and f["fail"] == 0 and f["pass"] == 0, (
            f"{fw} should be out_of_scope on chroma, got {f}"
        )
        assert f["coverage"] is None
    # NIST + EU DO apply to any AI artifact -> real pass/fail.
    for fw in ("nist_rmf", "eu_ai_act_annexIV"):
        f = r.compliance[fw]
        assert (f["pass"] + f["fail"]) >= 1 and f["out_of_scope"] == 0, (
            f"{fw} should resolve pass/fail on chroma, got {f}"
        )


def test_attestation_flips_not_evidenceable_to_pass_with_evidence() -> None:
    base = run_all(scan_repo(_fx("synthetic-clinical-samd"), level=4))["gmlp"]
    nbe = [q["id"] for q in base["requirements"] if q["verdict"] == "not_bom_evidenceable"]
    assert nbe, "expected >=1 process (not_bom_evidenceable) requirement"

    r2 = scan_repo(_fx("synthetic-clinical-samd"), level=4)
    rep = run_all(r2, evidence={"gmlp": {nbe[0]: "team-attestation.pdf"}})["gmlp"]
    q = next(x for x in rep["requirements"] if x["id"] == nbe[0])
    assert q["verdict"] == "pass_with_evidence"
    assert q["attestable"] is True
    assert rep["pass_with_evidence"] == 1
    assert rep["not_bom_evidenceable"] == base["not_bom_evidenceable"] - 1
    # pass_with_evidence counts toward coverage.
    assert rep["coverage"] >= base["coverage"]


def test_coverage_math_excludes_oos_and_not_evidenceable() -> None:
    r = scan_repo(_fx("synthetic-clinical-samd"), level=4)
    run_all(r)
    for fw, f in r.compliance.items():
        if fw == "disclaimer" or f.get("coverage") is None:
            continue
        passing = f["pass"] + f["pass_with_evidence"]
        denom = passing + f["fail"]
        assert f["coverage"] == round(passing / denom, 3)
        # out_of_scope / not_bom_evidenceable / na are NOT in the denominator.
