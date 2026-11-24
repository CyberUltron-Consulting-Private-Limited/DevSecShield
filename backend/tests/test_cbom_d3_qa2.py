"""Staging QA round 2 on D3 (code-scan CBOM reports): Q2-01, Q2-03, Q2-09, Q2-10, A-13b/c/d, G-D3-6, N1, N4, N8.

Q2-01 (Rule P): ONE risk score. The engine stores it (``cbom_scores``: ``aibom/score/posture.py`` over the scan's
findings, with the worst-severity cap); the API (``get_scan_metadata``' ``cbom_scores``, the dashboard's
``card_data``), the PDF headline and summary page and the results page's KPI tile all show that number, grade and
words. ``fixtures/cbom_d3_bank_scandata.json`` is the aibom adapter's output for ``aibom/tests/fixtures/cbom-d3-bank``.
"""
from __future__ import annotations

import io
import json
import pathlib
import types

import pytest

from backend.utilities.cbom_sources.cbom_metrics import (
    code_row_broken_today,
    code_row_quantum_vulnerable,
    risk_posture,
    summarize_code_rows,
)
from backend.utilities.pdf.aibom_posture import posture_risk

_HERE = pathlib.Path(__file__).resolve().parent
_REPO = _HERE.parents[1]
_FIXTURE = _HERE / "fixtures" / "cbom_d3_bank_scandata.json"


@pytest.fixture(scope="module")
def scan_data() -> dict:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def _pdf_text(data: dict, tmp_path: pathlib.Path) -> str:
    pypdf = pytest.importorskip("pypdf")
    from backend.utilities.pdf.cbom_pdf import generate_pdf

    out = tmp_path / "d3.pdf"
    generate_pdf(data, str(out))
    reader = pypdf.PdfReader(io.BytesIO(out.read_bytes()))
    return " ".join(" ".join(page.extract_text() or "" for page in reader.pages).split())


# ----------------------------------------------------------------------------- Q2-01 one risk score
def test_engine_api_pdf_and_ui_show_one_risk_score(scan_data, tmp_path, monkeypatch):
    from backend.utilities.dashboard import scan as dashboard
    from backend.utilities.dashboard.scan_metadata import get_scan_metadata

    engine = scan_data["cbom_scores"]
    risk = summarize_code_rows(scan_data["results"]).risk
    # the engine's stored number is the backend's (the same posture function over the same findings)
    assert engine["risk_scale"] == "posture"
    assert (engine["risk_normalized"], engine["risk_grade"], engine["risk_label"]) == (
        float(risk["risk_score"]), risk["risk_grade"], risk["risk_label"])
    assert engine["severity_counts"] == risk["severity_counts"]
    # the API: scan metadata's cbom_scores and the dashboard's KPI card data
    meta = get_scan_metadata("cbom", types.SimpleNamespace(scan_metadata={}, scan_data=scan_data))
    assert meta["cbom_scores"]["risk_normalized"] == engine["risk_normalized"]
    assert meta["cbom_scores"]["risk_label"] == engine["risk_label"]
    monkeypatch.setattr(dashboard, "get_findings_for_scan_id", lambda **_kw: [])
    card = dashboard.generate_scan_dashboard("cbom", scan_object=types.SimpleNamespace(id=1, scan_data=scan_data))[
        "card_data"]
    assert (card["risk_score"], card["risk_grade"], card["risk_label"]) == (
        risk["risk_score"], risk["risk_grade"], risk["risk_label"])
    # the PDF: headline tile (grade, number, words) and the summary page's rows say the same
    text = _pdf_text(scan_data, tmp_path)
    headline = f"{risk['risk_grade']} Risk score {risk['risk_score']} {risk['risk_label']}"
    assert headline in text, text[:1500]
    summary = f"{risk['risk_score']} / 100 · grade {risk['risk_grade']} · {risk['risk_label']}"
    assert summary in text, "the summary page's posture table prints the engine's number"
    assert "Average risk score" not in text, "no second, 0-10 number"


def test_ui_kpi_reads_the_api_risk_score_not_the_average():
    src = (_REPO / "frontend" / "components" / "cbom" / "results" / "CbomDashboardCharts.tsx").read_text()
    tile = next(line for line in src.splitlines() if 'key: "avg_risk"' in line)
    assert "riskScoreText" in tile and "riskScoreHint" in tile and "average_risk_score" not in tile
    fn = src[src.index("export function riskScoreText"):]
    fn = fn[: fn.index("\n}\n")]
    assert "c.risk_score" in fn and "c.risk_grade" in fn
    hint = src[src.index("export function riskScoreHint"):]
    hint = hint[: hint.index("\n}\n")]
    assert "of 100" in hint and "c.risk_label" in hint


def test_cap_keeps_securenote_out_of_critical():
    """SecureNote (staging): 0 Critical, 3 High, 1 Medium, 6 Low printed 92 / F "Critical risk" in the PDF."""
    out = risk_posture({"critical": 0, "high": 3, "medium": 1, "low": 6})
    assert (out["risk_score"], out["risk_grade"], out["risk_label"]) == (69, "D", "High risk")
    assert posture_risk(0, 3, 1, 6) == (69, "D", "High risk")


def test_sbom_and_ai_bom_pdfs_use_the_capped_headline():
    for name in ("sbom_sca_pdf.py", "ai_bom_pdf.py", "cbom_pdf.py"):
        src = (_REPO / "backend" / "utilities" / "pdf" / name).read_text()
        assert "risk_score_fn=compute_posture_risk_score" in src, name


# ----------------------------------------------------------------------------- G-D3-6 broken today
def test_md5_stored_either_way_is_broken_today_not_quantum_vulnerable():
    old = {"quantum_safe": True, "crypto_strength": "weak"}
    new = {"quantum_safe": False, "quantum_vulnerable": False, "crypto_strength": "weak"}
    rsa1024 = {"quantum_safe": False, "quantum_vulnerable": True, "crypto_strength": "weak"}
    for row in (old, new):
        assert code_row_broken_today(row) and code_row_quantum_vulnerable(row) is False
    assert not code_row_broken_today(rsa1024) and code_row_quantum_vulnerable(rsa1024) is True
    summary = summarize_code_rows([{**new, "finding_codes": ["WEAK_ALGORITHM"], "impact": "Low"}])
    assert summary.quantum == {"quantum_safe": 0, "quantum_vulnerable": 0, "broken_today": 1}


def test_pdf_card_and_row_score_read_md5_as_broken_today_in_both_encodings():
    """The PDF detail card printed "Quantum-Vulnerable" for the new MD5 encoding while p2 counted it broken today
    (SmarterRouter router.py, re-render on this branch), and the 0-10 row score added the quantum bump for it."""
    from backend.utilities.dashboard.bom_risk_score import cbom_finding_risk_score
    from backend.utilities.pdf.cbom_pdf import _quantum_label

    base = {"crypto_strength": "weak", "finding_codes": ["WEAK_ALGORITHM"], "impact": "Low"}
    old = {**base, "quantum_safe": True}
    new = {**base, "quantum_safe": False, "quantum_vulnerable": False}
    rsa1024 = {**base, "quantum_safe": False, "quantum_vulnerable": True}
    for row in (old, new):
        assert _quantum_label(row).startswith("Broken today")
    assert _quantum_label(rsa1024) == "Quantum-Vulnerable"
    assert _quantum_label({"quantum_safe": True, "crypto_strength": "strong"}) == "Quantum-Safe"
    assert _quantum_label({"quantum_safe": None}) == "Unknown"
    assert cbom_finding_risk_score(new) == cbom_finding_risk_score(old)
    assert cbom_finding_risk_score(rsa1024) > cbom_finding_risk_score(new)
    # the results page's "Top cryptographic risks" badge needs the engine's verdict too (it said "No" for MD5)
    top = summarize_code_rows([{**new, "algorithm_name": "MD5"}]).top(1)[0]
    assert top["quantum_safe"] is False and top["quantum_vulnerable"] is False


# ----------------------------------------------------------------------------- Q2-03 compliance table
def _appendix_text(payload: dict) -> str:
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import KeepTogether

    from backend.utilities.pdf.rbi_compliance_pdf import append_rbi_compliance_pdf_section

    story: list = []
    st = getSampleStyleSheet()
    append_rbi_compliance_pdf_section(story, payload, st["Heading2"], st["Normal"], st["Normal"])

    def walk(items):
        for f in items:
            if isinstance(f, KeepTogether):
                yield from walk(f._content)
            elif hasattr(f, "getPlainText"):
                yield f.getPlainText()
            elif hasattr(f, "_cellvalues"):
                for row in f._cellvalues:
                    yield " | ".join(str(c) for c in row)
    return "\n".join(walk(story))


def test_compliance_table_heading_names_and_team_applicability(scan_data):
    from backend.utilities.cbom_sources.regulated_entity import profile
    from backend.utilities.pdf.rbi_compliance_pdf import TEAM_PROFILE_KEY

    nbfc = _appendix_text({**scan_data, TEAM_PROFILE_KEY: profile("nbfc")})
    assert "RBI FREE-AI Compliance" not in nbfc
    assert "Regulatory and standards mapping (Advisory)" in nbfc
    assert "CERT-In CBOM (Guidelines v2.0)" in nbfc and "RBI FREE-AI (Protection)" in nbfc
    for raw in ("eu_cra", "eu_dora", "omb_m_23_02", "pci_dss_4", "bsi_tr_02102", "cert_in_cbom"):
        assert raw not in nbfc, raw
    # frameworks that do not bind an NBFC in India are named once, never listed as rows
    assert "EU DORA |" not in nbfc and "Not applicable to this team's regulatory profile" in nbfc
    assert "EU DORA" in nbfc and "PCI-DSS 4.0" in nbfc
    # a card processor gets PCI-DSS; a SEBI-regulated entity gets SEBI CSCRF
    card = _appendix_text({**scan_data, TEAM_PROFILE_KEY: profile("nbfc", ["processes_card_data"])})
    assert "PCI-DSS 4.0 |" in card
    assert "SEBI CSCRF (CBOM) |" not in nbfc
    sebi = _appendix_text({**scan_data, TEAM_PROFILE_KEY: profile("nbfc", ["sebi_regulated"])})
    assert "SEBI CSCRF (CBOM) |" in sebi


# ----------------------------------------------------------------------------- Q2-10 PDF readability
def test_pdf_has_readable_labels_and_no_raw_enums(scan_data, tmp_path):
    text = _pdf_text(scan_data, tmp_path)
    for raw in ("Quantum_Safe", "Kdf ", "Pke ", "CRYPTOGRAPHIC_FAILURES:", "ISO27001_A10_CRYPTOGRAPHY:"):
        assert raw not in text, raw
    assert "Key derivation (KDF)" in text


def test_non_ascii_evidence_is_drawn_or_escaped_never_a_black_box():
    from reportlab.platypus import Preformatted
    from reportlab.platypus import XPreformatted

    from backend.utilities.pdf.report_branding import _code_markup, _evidence_font, evidence_flowable, get_report_styles

    style = get_report_styles()["code"]
    assert isinstance(evidence_flowable("x = 1  # plain", style), Preformatted)
    flow = evidence_flowable('"""Paroladan şifreleme anahtarı türet 🔑"""', style)
    assert isinstance(flow, XPreformatted)
    markup = _code_markup('şı 🔑 <redacted:21>', style)
    face, _glyphs = _evidence_font()  # report_fonts' Noto Sans with HarfBuzz (CI), the plain fallback without
    assert f'<font face="{face}">ş</font>' in markup and f'<font face="{face}">ı</font>' in markup
    assert "\\U0001f511" in markup  # no glyph in the report fonts: a visible escape
    assert "&lt;redacted:21&gt;" in markup


# ----------------------------------------------------------------------------- A-13b/c/d served CBOM and VEX
def test_served_cbom_subject_grades_and_vulnerabilities(scan_data):
    from backend.utilities.compliance.certin_attest import bom_dict_from_scan_data

    bom = bom_dict_from_scan_data("cbom", scan_data, subject_name="acme/bank-router")
    assert bom["metadata"]["component"]["name"] == "acme/bank-router"
    by_ref = {r["bom_ref"]: r for r in scan_data["results"]}
    graded = [c for c in bom["components"] if c.get("bom-ref") in by_ref]
    assert graded
    for comp in graded:
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        for name in ("zs:q_grade", "zs:pqc_class", "zs:fix_class"):
            assert name in props, (comp["name"], name)
        assert props["zs:q_grade"] in ("Q0", "Q1", "Q2", "Q3", "Q4", "none")
    ids = {v["id"] for v in bom.get("vulnerabilities", [])}
    assert ids, "the BOM lists the vulnerabilities its VEX states"
    refs = {c["bom-ref"] for c in bom["components"]}
    for v in bom["vulnerabilities"]:
        assert all(a["ref"] in refs for a in v["affects"])


def test_md5_grade_is_deprecated_not_quantum_safe():
    from backend.utilities.cbom_sources.code_bom import assessment

    props = {p["name"]: p["value"] for p in assessment(
        {"title": "MD5", "asset_type": "algorithm", "weak": True, "quantum_vulnerable": False,
         "finding_codes": ["WEAK_ALGORITHM"], "location": "app.py"})}
    assert props["zs:pqc_class"] == "deprecated"
    assert props["zs:q_grade"] == "Q2" and props["zs:q_reason"] == "deprecated"


def test_code_scan_vex_uses_bom_links_and_no_unjustified_not_affected(scan_data):
    from backend.utilities.cbom_sources import vex_semantics as VEX
    from backend.utilities.compliance.certin_attest import bom_dict_from_scan_data

    bom = bom_dict_from_scan_data("cbom", scan_data, subject_name="acme/bank-router")
    serial = bom.get("serialNumber") or "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
    comps = [c["bom-ref"] for c in bom["components"]]
    vex = VEX.code_scan_vex(scan_data["results"], scan_id=9, components=comps, bom_serial=serial,
                            bom_version=bom.get("version") or 1)
    assert vex["metadata"]["properties"][0] == {"name": "zs:vex_rules", "value": "cb22-2"}
    assert {v["id"] for v in vex["vulnerabilities"]} == {v["id"] for v in bom["vulnerabilities"]}
    uuid = serial.removeprefix("urn:uuid:")
    for v in vex["vulnerabilities"]:
        assert v["analysis"]["state"] != "not_affected" or v["analysis"].get("justification")
        for a in v["affects"]:
            assert a["ref"].startswith(f"urn:cdx:{uuid}/"), a["ref"]
            assert a["ref"].split("#", 1)[1] in comps


# ----------------------------------------------------------------------------- N8 verify input
def test_verify_strips_a_utf8_bom_and_refuses_lone_surrogates_cleanly():
    from backend.utilities.cbom_sources import bom_verify as BV

    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6"}
    assert BV.loads_file(io.BytesIO(b"\xef\xbb\xbf" + json.dumps(doc).encode())) == doc
    with pytest.raises(BV.InputError) as err:
        BV.loads_file(io.BytesIO(b'{"bomFormat": "CycloneDX", "x": "\\ud800"}'))
    assert "lone UTF-16 surrogate" in str(err.value) and "codec" not in str(err.value)
    assert BV.loads(b'{"x": "\\ud83d\\udd11"}') == {"x": "\U0001F511"}  # a real pair is fine


# ----------------------------------------------------------------------------- Q2-09 PDF library row
def test_pdf_library_row_says_the_range_is_unverified():
    from backend.utilities.pdf.cbom_inventory_pdf import _library_rows

    lib = {"type": "library", "bom-ref": "crypto-lib-pyca-cryptography", "name": "pyca/cryptography",
           "properties": [{"name": "crypto:role", "value": "library"},
                          {"name": "crypto:versionConstraint", "value": ">=38.0.0"},
                          {"name": "crypto:versionUnknownReason", "value": "only a version range is declared"},
                          {"name": "crypto:versionVerified", "value": "false"},
                          {"name": "crypto:unverifiedAdvisoryCount", "value": "20"}]}
    rows = _library_rows([lib])
    assert len(rows) == 1 and rows[0][1] == "not known"
    assert "version unverified" in rows[0][2] and "20 advisories (not counted)" in rows[0][2]
