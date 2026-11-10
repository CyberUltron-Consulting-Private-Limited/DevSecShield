"""Quantum readiness never counts an algorithm that is broken today (MD5, DES, RC4 ...) as quantum-safe.

The PQC readiness gauge showed 77 % on a lab scan full of MD5 and DES: they carry ``quantum_safe: true`` (a quantum
computer adds nothing to their weakness) and were counted as ready. The results table's Quantum column calls them
"Broken today"; the card, the PDF and the gauge now use that rule (round 5, G3 item 1).
"""
import json
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.cbom_sources.cbom_metrics import code_row_broken_today, summarize_code_rows  # noqa: E402
from backend.utilities.pdf.combined import generate_pdf_for_type  # noqa: E402
from backend.tests.support.pdf_text import pdf_text  # noqa: E402

MD5 = {"algorithm_name": "MD5", "quantum_safe": True, "crypto_strength": "weak", "impact": "High"}
DES = {"algorithm_name": "DES", "quantum_safe": True, "crypto_strength": "Weak", "impact": "High"}
AES = {"algorithm_name": "AES-256-GCM", "quantum_safe": True, "crypto_strength": "strong", "impact": "Info"}
RSA = {"algorithm_name": "RSA-2048", "quantum_safe": False, "crypto_strength": "moderate", "impact": "Medium"}
LIB = {"algorithm_name": "openssl", "quantum_safe": None, "crypto_strength": "weak", "impact": "Low"}


def test_broken_today_rule_matches_the_quantum_column():
    assert code_row_broken_today(MD5) and code_row_broken_today(DES)
    assert not code_row_broken_today(AES) and not code_row_broken_today(RSA) and not code_row_broken_today(LIB)


def test_readiness_counts_broken_today_as_not_ready():
    summary = summarize_code_rows([MD5, DES, AES, RSA, LIB])
    assert summary.quantum == {"quantum_safe": 1, "quantum_vulnerable": 1, "broken_today": 2}
    assert summary.readiness_pct == 25.0  # was 75.0: MD5 + DES + AES counted as safe
    assert summarize_code_rows([LIB]).readiness_pct is None


def test_pdf_prints_the_same_readiness_and_lists_broken_today(tmp_path):
    out = tmp_path / "cbom.pdf"
    generate_pdf_for_type("cbom", {"results": [MD5, DES, AES, RSA, LIB]}, str(out))
    text = pdf_text(out.read_bytes())
    assert "25.0%" in text
    assert "75.0%" not in text
    assert "Broken today (classically broken, not quantum-safe)" in text


def test_fixture_scan_readiness(tmp_path):
    fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "cbom_export_scandata.json")
    with open(fixture, encoding="utf-8") as fh:
        rows = json.load(fh)["results"]
    summary = summarize_code_rows(rows)
    broken = sum(1 for r in rows if r.get("quantum_safe") is True and str(r.get("crypto_strength")).lower() == "weak")
    assert summary.quantum["broken_today"] == broken >= 4
