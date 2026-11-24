"""Review 6032108510 (PR #489, second review): backend and route-level checks.

* m2  a match on a version read from a manifest range is listed in the PDF catalogue as unverified and not
      counted, and the headline says how many, so "Total Issues 0" never sits above "7 issues" unexplained.
* M-1 the PDF states licence and hash coverage; an SBOM with components of unknown licence gets a partial
      (not BOM-evidenceable) licence-risk verdict, not a pass.

Run (repo root): backend/.venv/bin/python -m pytest backend/tests/test_sbom_review_6032108510.py -q
"""
from __future__ import annotations

import copy
import io

import pypdf

from backend.utilities.pdf.sbom_sca_pdf import generate_pdf
from backend.tests.test_sbom_d4_pdf import ROWS, SBOM

PILLOW = "pkg:pypi/pillow@10.0"


def _guessed_rows(n: int) -> list[dict]:
    return [{"detected_by": "grype", "vuln_id": f"GHSA-3f63-hfp8-52j{i}", "impact": "Critical",
             "title": f"GHSA-3f63-hfp8-52j{i} in pillow ≥ 10.0 (range >=10.0,<13.0)",
             "dependency": "pillow (≥ 10.0, range >=10.0,<13.0)", "purl": PILLOW,
             "version_guessed_from": ">=10.0,<13.0", "cves": {}, "inventory_only": False, "vuln_assessed": True}
            for i in range(n)]


def _pdf_text(tmp_path, rows, bom) -> str:
    out = tmp_path / "sbom.pdf"
    generate_pdf({"results": rows, "duration_of_scan": 3.0, "sbom_json": bom}, str(out))
    return "\n".join(p.extract_text() or "" for p in pypdf.PdfReader(io.BytesIO(out.read_bytes())).pages)


def _bom_with_pillow() -> dict:
    bom = copy.deepcopy(SBOM)
    bom["components"].append({"bom-ref": PILLOW, "type": "library", "name": "pillow", "version": "10.0",
                              "purl": PILLOW, "properties": [
                                  {"name": "dss:version_source", "value": "range_lower_bound"},
                                  {"name": "dss:version_constraint", "value": ">=10.0,<13.0"}]})
    return bom


def test_m2_pdf_headline_counts_the_unverified_matches_the_catalogue_lists(tmp_path):
    inventory = [r for r in ROWS if r.get("inventory_only")]
    text = " ".join(_pdf_text(tmp_path, inventory + _guessed_rows(7), _bom_with_pillow()).split())
    assert "7 unverified (not counted)" in text  # next to the grade, in the Total Issues card
    assert "7 issues · 7 unverified version, not counted" in text  # the catalogue header
    assert text.count("(not counted)") >= 8  # the headline plus every catalogue row
    assert "in pillow 10.0" not in text and "pillow==10.0" not in text


def test_m2_stored_scan_without_the_worker_label_is_marked_too(tmp_path):
    rows = [dict(r, title=r["title"].replace(" ≥ 10.0 (range >=10.0,<13.0)", " 10.0")) for r in _guessed_rows(1)]
    text = " ".join(_pdf_text(tmp_path, rows, _bom_with_pillow()).split())
    assert "in pillow 10.0 - unverified version (not counted)" in text


ACME = "pkg:pypi/acme-internal@1.0"


def _offline_bom() -> dict:
    """The fixture SBOM as an offline worker scan stores it: one package no source gave a licence for."""
    bom = copy.deepcopy(SBOM)
    bom["components"].append({"bom-ref": ACME, "type": "library", "name": "acme-internal", "version": "1.0",
                              "purl": ACME})
    bom["metadata"]["properties"] = [
        {"name": "dss:registry", "value": "off: no registry lookup (DSS_SBOM_REGISTRY is not 1); licences and "
                                          "hashes from the inventory only"}]
    return bom


def test_m1_pdf_states_licence_and_hash_coverage(tmp_path):
    text = " ".join(_pdf_text(tmp_path, ROWS, _offline_bom()).split())
    assert "Licence coverage: 3/4 components; hash coverage: 1/4; package registries: off" in text
    assert "Licence-risk checks report the components without a licence as not assessed" in text


def test_m1_licence_risk_on_the_served_bom_is_partial_when_a_licence_is_unknown():
    from aibom.sbom.compliance import run_sbom_compliance
    from backend.utilities.pdf.sbom_sca_pdf import _downloaded_bom

    rows = ROWS + [{"dependency": "acme-internal==1.0", "purl": ACME, "inventory_only": True, "cves": {},
                    "license": "LicenseRef-not-declared", "impact": "Low", "vuln_assessed": True}]
    served = _downloaded_bom({"results": rows, "sbom_json": _offline_bom()})
    result = run_sbom_compliance([r for r in rows if r.get("purl")], sbom_json=served)
    verdicts = {q["id"]: q for fw in ("sebi_cscrf_sbom", "rbi_free_ai_supply") for q in result[fw]["requirements"]}
    for rid in ("CSCRF-GV.SC.S5-lic-risk", "FREEAI-SUPPLY-4"):
        assert verdicts[rid]["verdict"] == "not_bom_evidenceable", verdicts[rid]
        assert verdicts[rid]["evidence"].startswith("partial: 1/4 component(s) have no resolved licence")
        assert verdicts[rid]["refs"] == [ACME]


def test_m2_jira_ticket_marks_a_guessed_version_unverified():
    from backend.utilities.integrations.jira_ticketing import extract_finding_summary, finding_ticket_description

    stored = {"title": "GHSA-3f63-hfp8-52jq in pillow 10.0", "impact": "Critical", "description": "d",
              "version_guessed_from": ">=10.0,<13.0"}  # a scan stored before the worker labelled its title
    assert extract_finding_summary(stored) == "GHSA-3f63-hfp8-52jq in pillow 10.0 - unverified version"
    text = finding_ticket_description("sbom_sca", 7, stored)
    assert "Version: unverified. It was read from the manifest range >=10.0,<13.0" in text
    labelled = dict(stored, title="GHSA-3f63-hfp8-52jq in pillow ≥ 10.0 (range >=10.0,<13.0) - unverified version")
    assert extract_finding_summary(labelled) == labelled["title"]
    pinned = {"title": "GHSA-m2qf in flask 0.12.2", "impact": "High", "description": "d"}
    assert extract_finding_summary(pinned) == pinned["title"]
    assert "unverified" not in finding_ticket_description("sbom_sca", 7, pinned)
