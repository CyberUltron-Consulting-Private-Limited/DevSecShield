"""C7 — CBOM compliance mapping (tri-state, graph-evidenced).

Drives the real CBOM pipeline (:func:`aibom.cbom.pipeline.scan_crypto`) over the
hand-labeled ``synthetic-crypto-app`` fixture and asserts the crypto-regulatory
frameworks — NIST SP 1800-38B (PQC readiness), NIST SP 800-57 (key / certificate
management), OMB M-23-02 (cryptographic inventory), plus the optional EU CRA /
DORA — produce REAL ``pass`` / ``fail`` verdicts using the SAME tri-state verdict
model as the AIBOM compliance lane (``aibom.compliance.base.Verdict``).

Lane discipline (``aibom/contract/lanes`` + CLAUDE.md hard rule #4): a CBOM check
reads the GRAPH — ``crypto_asset`` components + their ``crypto:`` properties — and
decides applicability / pass / fail from that, NEVER from ``result.flags`` (which
are the scoring echo). This is asserted directly by
``test_compliance_never_reads_flags``.
"""

from __future__ import annotations

import json
import os

import pytest

from aibom.cbom.compliance import (
    CBOM_FRAMEWORKS,
    run_cbom_compliance,
)
from aibom.cbom.pipeline import scan_crypto
from aibom.compliance.base import Verdict
from aibom.compliance.engine import FRAMEWORKS as AIBOM_FRAMEWORKS
from aibom.model.component import MetadataComponent
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")

# The closed set of tri-state verdict states, mirrored from the AIBOM lane.
_VERDICTS = set(Verdict.__args__)  # type: ignore[attr-defined]


def _manifest() -> dict:
    with open(os.path.join(_FX, "expected_crypto.json")) as fh:
        return json.load(fh)


def _scan() -> ScanResult:
    return scan_crypto(_FX)


def _report() -> dict:
    return run_cbom_compliance(_scan())


def _verdicts(framework_block: dict) -> dict[str, str]:
    return {r["id"]: r["verdict"] for r in framework_block["requirements"]}


# --------------------------------------------------------------------------- #
# Shape: the three mandated frameworks (+ optional CRA/DORA) are reported.
# --------------------------------------------------------------------------- #


def test_reports_the_mandated_crypto_frameworks() -> None:
    report = _report()
    for fw in ("nist_1800_38b", "nist_800_57", "omb_m_23_02"):
        assert fw in report, f"missing mandated framework {fw}"
    # optional CRA / DORA are present too
    assert "eu_cra" in report and "eu_dora" in report
    assert set(CBOM_FRAMEWORKS) <= set(report)


def test_every_requirement_has_the_full_tri_state_shape() -> None:
    report = _report()
    for fw in CBOM_FRAMEWORKS:
        block = report[fw]
        for key in (
            "pass",
            "pass_with_evidence",
            "fail",
            "out_of_scope",
            "not_bom_evidenceable",
            "na",
            "coverage",
            "requirements",
        ):
            assert key in block, f"{fw} missing {key}"
        assert block["requirements"], f"{fw} has no requirements"
        for req in block["requirements"]:
            assert set(req) >= {
                "id",
                "title",
                "source",
                "verdict",
                "evidence",
                "refs",
                "attestable",
            }
            assert req["verdict"] in _VERDICTS
            assert req["evidence"], "every verdict carries graph evidence"


def test_report_carries_the_advisory_disclaimer() -> None:
    assert "disclaimer" in _report()


# --------------------------------------------------------------------------- #
# NIST SP 800-57 — key / certificate management: the weak fixture FAILS, with a
# distinct fail per crypto weakness category.
# --------------------------------------------------------------------------- #


def test_nist_800_57_fails_on_the_weak_fixture() -> None:
    block = _report()["nist_800_57"]
    v = _verdicts(block)
    # broken/deprecated algorithms present (MD5/DES/RC4/RSA-1024) -> fail
    assert v["KM-1"] == "fail"
    # an undersized asymmetric key (RSA-1024) -> fail
    assert v["KM-2"] == "fail"
    # a hardcoded private key -> fail
    assert v["KM-3"] == "fail"
    # a self-signed certificate -> fail
    assert v["KM-4"] == "fail"
    # an ECB cipher mode -> fail
    assert v["KM-5"] == "fail"
    assert block["fail"] >= 5
    # coverage is a real fraction, not None (there ARE applicable checks)
    assert block["coverage"] is not None
    assert block["coverage"] < 1.0


# --------------------------------------------------------------------------- #
# NIST SP 1800-38B — PQC readiness: quantum-vulnerable RSA fails the readiness
# gauge but is correctly GRADED (level + migration target) -> those checks pass.
# --------------------------------------------------------------------------- #


def test_nist_1800_38b_grades_quantum_vulnerable_assets() -> None:
    block = _report()["nist_1800_38b"]
    v = _verdicts(block)
    # quantum-vulnerable public-key algorithms are in use -> not PQC-ready
    assert v["PQC-1"] == "fail"
    # ...but they are graded: nistQuantumSecurityLevel assigned
    assert v["PQC-2"] == "pass"
    # ...and a NIST migration target is identified for each
    assert v["PQC-3"] == "pass"
    assert block["pass"] >= 2 and block["fail"] >= 1


# --------------------------------------------------------------------------- #
# OMB M-23-02 — cryptographic inventory: the BOM IS the inventory, quantum-
# vulnerable systems are prioritized (migration target present) -> pass; the
# agency migration-plan submission is process evidence -> not_bom_evidenceable.
# --------------------------------------------------------------------------- #


def test_omb_m_23_02_inventory_and_prioritization() -> None:
    block = _report()["omb_m_23_02"]
    v = _verdicts(block)
    # the inventory enumerates algorithm primitives
    assert v["OMB-1"] == "pass"
    # quantum-vulnerable systems are prioritized with a migration target
    assert v["OMB-2"] == "pass"
    # the agency migration plan submission is not BOM-evidenceable
    assert block["not_bom_evidenceable"] >= 1


# --------------------------------------------------------------------------- #
# Optional EU CRA / DORA also produce real pass/fail on the weak fixture.
# --------------------------------------------------------------------------- #


def test_eu_cra_and_dora_flag_the_weak_fixture() -> None:
    report = _report()
    assert report["eu_cra"]["fail"] >= 1
    assert report["eu_dora"]["fail"] >= 1
    # DORA's transport check fails because TLS 1.0 is in use
    assert _verdicts(report["eu_dora"])["DORA-1"] == "fail"


# --------------------------------------------------------------------------- #
# Applicability gate: a repo with NO crypto assets -> every framework
# out_of_scope (NOT fail), coverage None. Tri-state, never a 0% false failure.
# --------------------------------------------------------------------------- #


def test_no_crypto_assets_makes_every_framework_out_of_scope(tmp_path) -> None:
    (tmp_path / "readme.md").write_text("# nothing cryptographic here\n")
    report = run_cbom_compliance(scan_crypto(tmp_path))
    for fw in CBOM_FRAMEWORKS:
        block = report[fw]
        assert block["fail"] == 0
        assert block["pass"] == 0
        assert block["coverage"] is None
        assert block["out_of_scope"] == len(block["requirements"])
        assert all(r["verdict"] == "out_of_scope" for r in block["requirements"])


# --------------------------------------------------------------------------- #
# Evidence attachment: an uploaded attestation flips a not_bom_evidenceable
# requirement to pass_with_evidence (same mechanism as the AIBOM lane).
# --------------------------------------------------------------------------- #


def test_uploaded_attestation_flips_not_evidenceable_to_pass() -> None:
    base = _report()["omb_m_23_02"]
    attestable = [
        r["id"] for r in base["requirements"] if r["verdict"] == "not_bom_evidenceable"
    ]
    assert attestable, "fixture should have a process-evidence requirement"
    rid = attestable[0]
    report = run_cbom_compliance(
        _scan(),
        evidence={"omb_m_23_02": {rid: "OMB migration plan submitted 2026-05-01"}},
    )
    block = report["omb_m_23_02"]
    v = _verdicts(block)
    assert v[rid] == "pass_with_evidence"
    assert block["pass_with_evidence"] >= 1


# --------------------------------------------------------------------------- #
# LANE PURITY: a CBOM check reads the GRAPH, never flags. Clearing every flag
# must NOT change a single verdict.
# --------------------------------------------------------------------------- #


def test_compliance_never_reads_flags() -> None:
    scanned = _scan()
    assert scanned.flags, "fixture should raise weak/PQC flags (C5/C6)"
    with_flags = run_cbom_compliance(scanned)

    flagless = ScanResult(
        subject=scanned.subject or MetadataComponent(name="x"),
        components=scanned.components,
        edges=scanned.edges,
        flags=[],
        properties=scanned.properties,
    )
    without_flags = run_cbom_compliance(flagless)

    for fw in CBOM_FRAMEWORKS:
        assert _verdicts(with_flags[fw]) == _verdicts(without_flags[fw]), (
            f"{fw} verdict changed when flags were cleared — it read a flag"
        )


# --------------------------------------------------------------------------- #
# scan_crypto fills the compliance seam in place; CBOM frameworks never leak
# into the AIBOM compliance run.
# --------------------------------------------------------------------------- #


def test_scan_crypto_populates_compliance_in_place() -> None:
    result = _scan()
    assert result.compliance, "scan_crypto should fill result.compliance (C7 seam)"
    for fw in CBOM_FRAMEWORKS:
        assert fw in result.compliance
    standalone = run_cbom_compliance(_scan())
    # same frameworks, same verdicts as the standalone runner
    for fw in CBOM_FRAMEWORKS:
        assert _verdicts(result.compliance[fw]) == _verdicts(standalone[fw])


def test_cbom_frameworks_do_not_leak_into_the_aibom_lane() -> None:
    for fw in CBOM_FRAMEWORKS:
        assert fw not in AIBOM_FRAMEWORKS


@pytest.mark.parametrize("fw", ["nist_1800_38b", "nist_800_57", "omb_m_23_02"])
def test_coverage_is_pass_over_pass_plus_fail(fw: str) -> None:
    block = _report()[fw]
    n_pass = block["pass"] + block["pass_with_evidence"]
    applicable = n_pass + block["fail"]
    if applicable:
        assert block["coverage"] == round(n_pass / applicable, 3)
    else:
        assert block["coverage"] is None
