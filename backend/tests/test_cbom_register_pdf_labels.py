"""Staging QA 14 Nov (b2e86fa), deliverable #2 Quantum Risk Register PDF, section B heat-map: cells holding only
assets with no grade (Library, DES / 3DES, Other: counts {"none": n}) printed "Q0 only" and no count at all, so the
libraries read as Q0 gaps; section D printed reason codes ("evidence e0 6, mosca missing 1") and the Mosca gap as
"inputs:mosca". Literals only: no product aggregator is used to compute the expected text."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.utilities.pdf import cbom_risk_register_pdf as PDF  # noqa: E402


def test_a_cell_with_only_ungraded_assets_says_no_grade_and_shows_its_count():
    assert PDF.heat_cell_text({"worst": None, "q0": 0, "counts": {"none": 11}}) == "No grade\n—:11"


def test_a_q0_only_cell_and_a_graded_cell_keep_their_labels():
    assert PDF.heat_cell_text({"worst": None, "q0": 2, "counts": {"Q0": 2}}) == "Q0 only\nQ0:2"
    assert PDF.heat_cell_text({"worst": None, "q0": 5, "counts": {"Q0": 5, "none": 1}}) == "Q0 only\nQ0:5 —:1"
    assert PDF.heat_cell_text({"worst": "Q4", "q0": 0, "counts": {"Q4": 5}}) == "Q4 Low\nQ4:5"


def test_open_gap_reasons_and_the_mosca_item_read_as_words():
    assert PDF.reason_line({"evidence_e0": 6, "mosca_missing": 1, "unknown_verdict": 5}) == (
        "Open Q0 gaps by reason: evidence at E0 6, Mosca inputs missing 1, PQC class unknown 5")
    assert PDF.gap_item({"item_kind": "inputs", "item_key": "inputs:mosca", "title": "inputs:mosca",
                         "detail": {"count": 80}}) == "Mosca X, Y or Z not set (80 quantum-vulnerable assets left ungraded)"
    assert PDF.gap_item({"item_kind": "asset", "item_key": "asset:1", "title": "ssh_host_rsa_key", "detail": {}}) == \
        "ssh_host_rsa_key"
