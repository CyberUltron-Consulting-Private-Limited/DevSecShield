"""The CBOM PDF's "Quantum status" follows the results page: a classically broken algorithm is "Broken today".

The PDF said "Quantum-Safe" for 3DES, MD5, DES and RC4 findings while the results page says "Broken today" for the
same rows (lab UI run u2, round 5).
"""
import json
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.pdf.cbom_pdf import _quantum_label  # noqa: E402
from backend.utilities.pdf.combined import generate_pdf_for_type  # noqa: E402
from backend.tests.support.pdf_text import pdf_text  # noqa: E402

_FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "cbom_export_scandata.json")


def test_quantum_label_rule():
    assert _quantum_label(True, "weak") == "Broken today (classically broken: replace now)"
    assert _quantum_label(True, "WEAK") == "Broken today (classically broken: replace now)"
    assert _quantum_label(True, "strong") == "Quantum-Safe"
    assert _quantum_label(True) == "Quantum-Safe"
    assert _quantum_label(False, "weak") == "Quantum-Vulnerable"
    assert _quantum_label(None, "weak") == "Unknown"


def test_the_pdf_never_calls_a_broken_algorithm_quantum_safe(tmp_path):
    with open(_FIXTURE, encoding="utf-8") as fh:
        payload = json.load(fh)
    out = tmp_path / "cbom.pdf"
    generate_pdf_for_type("cbom", payload, str(out))
    text = pdf_text(out.read_bytes())
    weak_safe = sum(1 for f in payload["results"] if f.get("quantum_safe") is True and f.get("crypto_strength") == "weak")
    assert weak_safe >= 4  # 3DES-CBC, AES-ECB, MD5, RC4 in the fixture
    assert text.count("Broken today") >= weak_safe
