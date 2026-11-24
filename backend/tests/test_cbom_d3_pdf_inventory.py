"""The CBOM code-scan PDF carries the full cryptographic inventory (SOW D3, audit-C G-D3-4).

Staging (peva3/SmarterRouter, cbom #7): the PDF showed 2 findings and said "7 clean inventory item(s) with no finding
are listed in the CycloneDX download, not here". The report now lists every asset from the scan's CycloneDX document:
algorithms with primitive, mode, key size and KDF parameters, the NIST level and the library with its version; salt /
IV literals with their length and use (never their value); the crypto libraries with their version or why it is not
known; the container images. ``fixtures/cbom_d3_bank_scandata.json`` is the aibom adapter's output for
``aibom/tests/fixtures/cbom-d3-bank`` (regenerate: see that file's test, ``aibom/tests/test_cbom_d3_deliverable.py``).

Run (repo root): PYTHONPATH=. backend/.venv/bin/python -m pytest backend/tests/test_cbom_d3_pdf_inventory.py -q
"""
from __future__ import annotations

import io
import json
import pathlib

import pytest

from backend.utilities.pdf.cbom_pdf import generate_pdf

_FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "cbom_d3_bank_scandata.json"
_LITERALS = ("bank_router_salt_v1", "constant-scrypt-salt", "0123456789abcdef", "fixed-iv-16bytes")


@pytest.fixture(scope="module")
def text(tmp_path_factory) -> str:
    pypdf = pytest.importorskip("pypdf")
    out = tmp_path_factory.mktemp("cbom") / "cbom.pdf"
    generate_pdf(json.loads(_FIXTURE.read_text(encoding="utf-8")), str(out))
    reader = pypdf.PdfReader(io.BytesIO(out.read_bytes()))
    return " ".join(" ".join(page.extract_text() or "" for page in reader.pages).split())


def test_the_pdf_lists_the_inventory_not_only_the_findings(text):
    assert "listed in the CycloneDX download, not here" not in text
    assert "listed in the cryptographic inventory at the end of this report" in text
    assert "Cryptographic inventory" in text
    for heading in ("Algorithms (", "Keys, certificates, protocols and crypto material (", "Crypto libraries (",
                    "Container images ("):
        assert heading in text, heading


def test_algorithms_carry_mode_key_size_parameters_and_library_version(text):
    flat = text.replace(" ", "")  # table cells wrap inside words
    assert "128bits;builtfromAES-128-CBC+HMAC-SHA256" in flat  # Fernet, NIST level 1 (was AES-256 / level 5)
    assert "PRFHMAC-SHA256;iterations480000;outputbytes32;saltbytes19" in flat
    assert "N16384;r8;p1" in flat
    assert "timecost3;memoryKiB65536;parallelism4" in flat
    assert "pyca/cryptography@43.0.1" in flat


def test_literals_are_described_never_printed(text):
    assert "hard-coded literal (value not shown)" in text
    flat = text.replace(" ", "")
    assert "19bytes;feedsPBKDF2" in flat
    for literal in _LITERALS:
        assert literal not in flat


def test_libraries_and_images(text):
    flat = text.replace(" ", "")
    assert "43.0.1fromuv.lock(declared>=41.0)" in flat
    assert "python:3.11-slim" in flat  # hashlib (stdlib): the runtime of the Dockerfile base image
    assert "ghcr.io/acme/bank-router1.4.2ComposeImage".lower() in flat.lower()
    assert "redis7.2-alpine" in flat
