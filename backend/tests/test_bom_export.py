"""EXPORT-PATTERN regression (backend side) for the two BOM scanners.

Story I3: the AIBOM ML-BOM + CBOM crypto exports must wire into DevSecShield's
existing export pattern — the generic ``GET /{team_id}/{type}/scan/{scan_id}/export``
route hands ``scan.scan_data["results"]`` to ``generate_pdf_for_type(type, ...)``,
and the CycloneDX JSON download is a client-side blob over the persisted
``cbom_json`` / ``ai_bom_json``.

After the I1 reconcile the CBOM (and AIBOM) run-object is produced by the
``aibom/`` adapter (``scan_crypto_to_devsecshield`` / ``scan_to_devsecshield``),
NOT the legacy ``*Agent``. The PDF generators read LEGACY per-row keys
(``algorithm_name``/``crypto_strength``/``quantum_safe``/``compliance_controls`` …
for CBOM; ``component_name``/``risk_category``/``license`` … for AIBOM) which the
adapter's ``_enrich`` preserves as a drop-in superset. This test locks that
contract: a reconciled run-object must still export a valid PDF, and the
CycloneDX download source must be a valid CycloneDX 1.6 document — so a future
refactor of the adapter row-shape can't silently break either export button.

Offline: drives the REAL ``generate_pdf_for_type`` against captured adapter
run-objects (committed fixtures). Only reportlab is exercised — no DB, no
network, no LLM. Regenerate the fixtures from the aibom package venv:

    aibom/.venv/bin/python -c "import json,sys; \
      sys.path.insert(0,'aibom/src'); \
      from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield as sc; \
      from aibom.integrations.devsecshield import scan_to_devsecshield as sa; \
      c=sc('aibom/tests/fixtures/synthetic-crypto-app',level=4); \
      a=sa('aibom/tests/fixtures/synthetic-ai-app',level=4); \
      json.dump({'results':c['results'],'cbom_json':c['cbom_json']}, \
        open('backend/tests/fixtures/cbom_export_scandata.json','w'),indent=1,sort_keys=True,default=str); \
      json.dump({'results':a['results'],'ai_bom_json':a['ai_bom_json']}, \
        open('backend/tests/fixtures/ai_bom_export_scandata.json','w'),indent=1,sort_keys=True,default=str)"
"""

import json
import os
import sys

import pytest

# The PDF code uses absolute ``backend.*`` imports, so the repo root must be
# importable regardless of the pytest working directory (backend/ or root).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.pdf.combined import generate_pdf_for_type  # noqa: E402

_FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

# (scan_type, fixture file, the persisted CycloneDX-download key)
_CASES = [
    ("cbom", "cbom_export_scandata.json", "cbom_json"),
    ("ai_bom", "ai_bom_export_scandata.json", "ai_bom_json"),
]


def _load(fname):
    with open(os.path.join(_FIXTURES, fname)) as fh:
        return json.load(fh)


def _assert_valid_pdf(path):
    with open(path, "rb") as fh:
        head = fh.read(5)
    size = os.path.getsize(path)
    assert head == b"%PDF-", f"not a PDF (magic {head!r})"
    assert size > 1000, f"PDF suspiciously small ({size} bytes)"


@pytest.mark.parametrize("scan_type,fixture,_bom_key", _CASES)
def test_export_pdf_with_rbi_compliance_appendix(scan_type, fixture, _bom_key, tmp_path):
    """Full scan_data dict (export route shape) still produces a valid PDF."""
    payload = _load(fixture)
    out = tmp_path / f"{scan_type}_rbi_report.pdf"
    enriched = {
        **payload,
        f"{'ai_bom' if scan_type == 'ai_bom' else 'cbom'}_compliance": {
            "rbi_free_ai" if scan_type == "ai_bom" else "rbi_free_ai_protection": {
                "pass": 1,
                "fail": 0,
                "out_of_scope": 0,
                "not_bom_evidenceable": 0,
                "na": 0,
                "coverage": 1.0,
                "requirements": [],
            },
            "disclaimer": "advisory",
        },
    }
    generate_pdf_for_type(scan_type, enriched, str(out))
    _assert_valid_pdf(str(out))
    assert out.stat().st_size > 1000


@pytest.mark.parametrize("scan_type,fixture,_bom_key", _CASES)
def test_export_pdf_from_reconciled_run_object(scan_type, fixture, _bom_key, tmp_path):
    """The export route's ``generate_pdf_for_type(type, results, path)`` produces a
    valid PDF from the I1-reconciled adapter run-object — for both BOM scanners."""
    results = _load(fixture)["results"]
    assert isinstance(results, list) and results, f"{scan_type}: empty fixture results"
    out = tmp_path / f"{scan_type}_report.pdf"
    generate_pdf_for_type(scan_type, results, str(out))
    _assert_valid_pdf(str(out))


@pytest.mark.parametrize("scan_type", ["cbom", "ai_bom"])
def test_export_pdf_survives_empty_and_sparse_results(scan_type, tmp_path):
    """A completed-but-empty scan and a row missing every optional key must still
    export (the generators read every per-row field defensively)."""
    out_empty = tmp_path / f"{scan_type}_empty.pdf"
    generate_pdf_for_type(scan_type, [], str(out_empty))
    _assert_valid_pdf(str(out_empty))

    out_sparse = tmp_path / f"{scan_type}_sparse.pdf"
    generate_pdf_for_type(scan_type, [{"title": "bare finding"}], str(out_sparse))
    _assert_valid_pdf(str(out_sparse))


@pytest.mark.parametrize("scan_type,fixture,bom_key", _CASES)
def test_cyclonedx_download_source_is_valid(scan_type, fixture, bom_key):
    """The client-side CycloneDX JSON download reads the persisted ``*_json`` off
    the run-object — it must be a valid CycloneDX 1.6 document with components."""
    run = _load(fixture)
    bom = run[bom_key]
    assert isinstance(bom, dict), f"{scan_type}: {bom_key} is not a dict"
    assert bom.get("bomFormat") == "CycloneDX", f"{scan_type}: wrong bomFormat"
    assert bom.get("specVersion") == "1.6", f"{scan_type}: expected CycloneDX 1.6"
    assert bom.get("components"), f"{scan_type}: CycloneDX has no components"


def test_sbom_sca_export_pdf_with_full_scan_data_dict(tmp_path):
    """Export route passes full scan_data (not just results[]) for sbom_sca so
    RBI/CERT-In appendix helpers can read compliance keys. The generator must:

    1. Unwrap ``results`` for findings (not treat the dict as legacy ``matches``).
    2. Define ``small_style`` used by the appendix sections (prod 500 was
       NameError: small_style is not defined).
    """
    payload = {
        "results": [
            {
                "title": "CVE-2024-0001",
                "description": "Test vulnerability",
                "impact": "High",
                "suggested_fix": "Upgrade package",
                "dependencies": ["demo@1.0.0"],
                "cves": {"CVE-2024-0001": "demo issue"},
                "owasp_top_10": {},
                "compliance_controls": {},
            }
        ],
        "rbi_compliance": {
            "disclaimer": "advisory",
            "rbi_free_ai_protection": {
                "pass": 1,
                "fail": 0,
                "out_of_scope": 0,
                "not_bom_evidenceable": 0,
                "na": 0,
                "coverage": 1.0,
                "requirements": [],
            },
        },
    }
    out = tmp_path / "sbom_sca_full_scan_data.pdf"
    generate_pdf_for_type("sbom_sca", payload, str(out))
    _assert_valid_pdf(str(out))
    # Findings must actually render — empty PDF after unwrap-miss was the silent
    # failure mode once small_style was defined.
    assert out.stat().st_size > 5000


def test_sbom_sca_export_pdf_list_and_legacy_shapes(tmp_path):
    """List (legacy route) and Syft-style matches dict still export."""
    out_list = tmp_path / "sbom_list.pdf"
    generate_pdf_for_type(
        "sbom_sca",
        [{"title": "bare finding", "impact": "Low"}],
        str(out_list),
    )
    _assert_valid_pdf(str(out_list))

    out_legacy = tmp_path / "sbom_legacy.pdf"
    generate_pdf_for_type(
        "sbom_sca",
        {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-X",
                        "description": "d",
                        "severity": "HIGH",
                        "fix": {"state": "fixed", "versions": ["1.2"]},
                        "cves": {},
                    },
                    "artifact": {"name": "pkg", "version": "1.0"},
                }
            ]
        },
        str(out_legacy),
    )
    _assert_valid_pdf(str(out_legacy))
