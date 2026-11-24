"""PR #485 review 6031163017 (second and final): merge with dev, two entity-filter gaps, issue records, KB coverage.

One test (or a few) per finding; each failed on 29e4c2ded (the merge of origin/dev f48c240f3 into fc50ed60d) before
the fixes:

* B1' ``document_id(view, "D2")`` prints D02; the Document ID's digest covers D2's live set-up (``methodology``) and
      D10's vendor register (``vendors``), which those documents print.
* M1  the code-scan OSCAL download cites the team's own RBI instrument (it cited NBFC para 118 to every team);
      ``team`` is a required keyword of ``OSCAL.scan_document`` / ``run_document`` / ``assessment_results``.
* M2  the CI/CD CBOM results page cites the team's own instrument (it cited all seven); ``team`` is a required
      keyword of ``kb_remediation.explain`` / ``remediation`` and ``project_cbom_ci_page``, and a guard fails on any
      backend caller that leaves it out.
* m1  a board-report issue is written through ``common.audit`` (an API-key caller is recorded as one), once per
      team, report, Document ID and day; the audit model documents the exception.
* m2  the three profile flags are strict booleans.
* m3  every entity type with an RBI cryptographic paragraph gets an RBI clause for plaintext and at-rest codes, and
      UCB para 25 for the five configuration codes the other six instruments carry.
* m4  the RBI FREE-AI row and the RBI clause framework do not bind an "other" entity.
* m5  the previous issue is part of the D14 digest, and a re-issue of earlier content prints what it printed then.
* n1  Appendix A's grade-input sentence reads as one sentence.
* IR 8547: the KB entry keeps the citation and the status apart (PR #490 builds its citation from the status).
"""
from __future__ import annotations

import ast
import dataclasses
import inspect
import json
import re
import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_cbom_pr485_review as R  # noqa: E402
from test_cbom_fa3_board_scope import staging_like_view  # noqa: E402

from backend.new_models import CbomCollectionAuditEvent  # noqa: E402
from backend.utilities.cbom_sources import crypto_kb, kb_remediation, regulated_entity  # noqa: E402
from backend.utilities.integrations import oscal as OSCAL  # noqa: E402
from backend.utilities.pdf import cbom_deliverable_common as common  # noqa: E402

world, api, seeded = R.world, R.api, R.seeded
NBFC_CLAUSE, BANK_CLAUSE, SETTINGS, D14 = R.NBFC_CLAUSE, R.BANK_CLAUSE, R.SETTINGS, R.D14
RBI_CRYPTO = {"nbfc": "rbi-nbfc-2026-para-118", "bank": "rbi-cb-2026-para-140", "sfb": "rbi-sfb-2026-para-139",
              "payments_bank": "rbi-pb-2026-para-139", "ucb": "rbi-ucb-2026-para-25",
              "aifi": "rbi-aifi-2026-para-135", "credit_info_company": "rbi-cic-2026-para-135"}
WEAK_ROW = {"title": "RSA-1024", "algorithm_name": "RSA", "asset_type": "algorithm", "algorithm_type": "pke",
            "location": "src/crypto_utils.py", "bom_ref": "crypto-algo-rsa-1024", "impact": "High",
            "finding_codes": ["WEAK_ALGORITHM", "QUANTUM_VULNERABLE"], "quantum_safe": False,
            "crypto_strength": "weak", "weak": True, "key_size": "1024"}


def _rbi_keys(refs) -> set[str]:
    return {r["key"] for r in refs if r.get("framework") == "RBI"}


def _d14_id(text: str) -> str:
    return re.search(r"CBOM-D14-T1-\d{8}-[0-9a-f]{8}", text).group(0)


# ---------------------------------------------------------------------------------------------- B1'
def test_b1_a_string_deliverable_number_prints_two_digits():
    view = staging_like_view()
    assert common.document_id(view, "D2") == common.document_id(view, 2)
    assert common.document_id(view, "D2").startswith("CBOM-D02-T1-")
    assert common.document_id(view, "D14") == common.document_id(view, 14)


def test_b1_the_digest_covers_the_d2_setup_and_the_d10_vendor_register():
    base = staging_like_view()
    setup = staging_like_view()
    setup.methodology = {"sources": {"total": 3}, "settings": {"port_protocols": ["tls"], "window_hours": 24}}
    other_setup = staging_like_view()
    other_setup.methodology = {"sources": {"total": 3}, "settings": {"port_protocols": ["tls"], "window_hours": 8}}
    vendors = staging_like_view()
    vendors.vendors = ({"name": "Acme Payments Gateway", "confidence": "E2", "attested_on": "2026-11-12"},)
    digests = [v.document_digest for v in (base, setup, other_setup, vendors)]
    assert len(set(digests)) == 4, digests
    assert staging_like_view().document_digest == base.document_digest  # same content, same digest


# ---------------------------------------------------------------------------------------------- M1
@pytest.mark.parametrize("name", ["scan_document", "run_document", "assessment_results"])
def test_m1_team_is_a_required_keyword_of_the_oscal_builders(name):
    param = inspect.signature(getattr(OSCAL, name)).parameters["team"]
    assert param.kind is inspect.Parameter.KEYWORD_ONLY and param.default is inspect.Parameter.empty


def test_m1_the_code_scan_oscal_download_cites_the_bank_directions_to_a_bank(api, seeded):  # noqa: F811
    nbfc = json.dumps(api("GET", "/1/cbom/code-scans/74/oscal").json())
    assert NBFC_CLAUSE in nbfc and BANK_CLAUSE not in nbfc
    assert api("PATCH", SETTINGS, json={"regulated_entity": "bank"}).status_code == 200
    bank = api("GET", "/1/cbom/code-scans/74/oscal")
    assert bank.status_code == 200
    text = json.dumps(bank.json())
    assert BANK_CLAUSE in text and NBFC_CLAUSE not in text
    engine, _w = seeded
    assert text.count("para 140") == json.dumps(OSCAL.document_for(engine, 1, scan_id=74)).count("para 140")


# ---------------------------------------------------------------------------------------------- M2
@pytest.mark.parametrize("func", [kb_remediation.explain, kb_remediation.remediation])
def test_m2_team_is_a_required_keyword_of_kb_remediation(func):
    param = inspect.signature(func).parameters["team"]
    assert param.kind is inspect.Parameter.KEYWORD_ONLY and param.default is inspect.Parameter.empty


@pytest.mark.parametrize(("entity", "clause"), [("nbfc", NBFC_CLAUSE), ("bank", BANK_CLAUSE)])
def test_m2_the_cicd_cbom_page_cites_only_the_team_instrument(monkeypatch, entity, clause):
    from backend.utilities.cicd.cbom_page import project_cbom_ci_page
    from backend.utilities.dashboard import scan as scan_dashboard

    monkeypatch.setattr(scan_dashboard, "get_findings_for_scan_id", lambda *a, **k: [])  # a CI run has no stored rows

    page = project_cbom_ci_page({"results": [dict(WEAK_ROW)], "cbom_json": {"components": []}},
                                team=regulated_entity.profile(entity))
    refs = page["findings"][0]["remediation"]["details"]
    keys = {r["key"] for d in refs for r in d["compliance"] if r["framework"] == "RBI"}
    assert keys == {RBI_CRYPTO[entity]}, keys
    others = {c for c in (NBFC_CLAUSE, BANK_CLAUSE) if c != clause}
    assert clause in json.dumps(page) and not {c for c in others if c in json.dumps(page)}


def test_m2_the_cicd_route_passes_the_team_profile(monkeypatch):
    """``routers/cicd.py`` builds the page with the team's profile (a TypeError there is swallowed into no page)."""
    tree = ast.parse((ROOT / "backend/routers/cicd.py").read_text())
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "project_cbom_ci_page"]
    assert calls and all(any(k.arg == "team" for k in c.keywords) for c in calls)


_TEAM_FUNCS = {"scan_document", "run_document", "assessment_results", "project_cbom_ci_page"}
_KB_MODULE = "backend.utilities.cbom_sources.kb_remediation"


def _missing_team(path: Path) -> list[str]:
    tree = ast.parse(path.read_text())
    kb_names = {a.asname or a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module == _KB_MODULE
                for a in n.names if a.name in ("explain", "remediation")}
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        owner = getattr(getattr(node.func, "value", None), "id", None)
        passed = [a for a in node.args if isinstance(a, ast.Name) and a.id in kb_names]  # run_in_threadpool(fn, ...)
        wanted = (name in _TEAM_FUNCS or name in kb_names or passed
                  or (owner == "kb_remediation" and name in ("explain", "remediation")))
        if wanted and not any(k.arg == "team" for k in node.keywords):
            out.append(f"{path.relative_to(ROOT)}:{node.lineno} {name}")
    return out


def test_m2_no_backend_caller_leaves_out_the_team():
    """The guard: every non-test backend call of a clause-citing builder names ``team`` (None only on purpose)."""
    missing = [m for path in sorted((ROOT / "backend").rglob("*.py")) if "tests" not in path.parts
               and ".venv" not in path.parts for m in _missing_team(path)]
    assert not missing, missing


# ---------------------------------------------------------------------------------------------- m1
def test_m1_minor_the_audit_model_documents_the_issue_record_exception():
    doc = CbomCollectionAuditEvent.__doc__ or ""
    assert "deliverable_issued" in doc and "cbom_deliverable_issue" in doc


def test_m1_minor_an_issue_is_recorded_through_common_audit_once_per_document_and_day(world):  # noqa: F811
    from backend.utilities.cbom_sources import api_keys
    from backend.utilities.dashboard import cbom_board_issues as issues

    engine, _ = world
    snap = {"document_id": "CBOM-D14-T1-20261124-0123abcd", "content_id": "CBOM-D14-T1-20261124-0123abcd",
            "as_of": "2026-11-24", "grade": "C", "score": 42}
    token = api_keys._ACTIVE_KEY.set(7)
    try:
        with Session(engine) as s:
            assert issues.record(s, 1, 14, snap, 1) is True
        with Session(engine) as s:
            assert issues.record(s, 1, 14, snap, 1) is False  # same team, report, Document ID and day
    finally:
        api_keys._ACTIVE_KEY.reset(token)
    with Session(engine) as s:
        rows = s.exec(select(CbomCollectionAuditEvent).where(
            CbomCollectionAuditEvent.action == issues.ACTION)).all()
    assert len(rows) == 1
    assert (rows[0].actor_type, rows[0].actor_id) == ("api_key", 7)
    assert issues.decode(rows[0].changed_fields)["document_id"] == snap["document_id"]


# ---------------------------------------------------------------------------------------------- m2
@pytest.mark.parametrize("payload", [{"sebi_regulated": "yes"}, {"government_entity": 1},
                                     {"processes_card_data": "true"}])
def test_m2_minor_profile_flags_are_strict_booleans(api, seeded, payload):  # noqa: F811
    r = api("PATCH", SETTINGS, json=payload)
    assert r.status_code in (400, 422), r.text
    body = api("GET", SETTINGS).json()
    body = body.get("data", body)
    body = body.get("settings", body) if isinstance(body, dict) else body
    assert body[next(iter(payload))] is False


# ---------------------------------------------------------------------------------------------- m3
AT_REST = [("node", "DISK_UNENCRYPTED"), ("node", "STORAGE_UNENCRYPTED"), ("node", "SECRET_PLAINTEXT_PARAM"),
           ("node", "DB_PLAINTEXT_PW"), ("code", "UNENCRYPTED_AT_REST")]
IN_TRANSIT = [("node", "NO_TLS"), ("node", "DB_NO_TLS"), ("node", "PLAINTEXT_LISTENER"),
              ("code", "UNENCRYPTED_IN_TRANSIT")]


@pytest.mark.parametrize("entity", sorted(RBI_CRYPTO))
@pytest.mark.parametrize(("namespace", "code"), AT_REST + IN_TRANSIT)
def test_m3_minor_every_entity_type_gets_an_rbi_clause_for_plaintext_and_at_rest(entity, namespace, code):
    refs = crypto_kb.clauses_for(namespace, code, None, team=regulated_entity.profile(entity))
    keys = _rbi_keys(refs)
    assert keys, (entity, code)
    assert all(k.startswith({"nbfc": "rbi-nbfc", "bank": "rbi-cb", "sfb": "rbi-sfb", "payments_bank": "rbi-pb",
                             "ucb": "rbi-ucb", "aifi": "rbi-aifi", "credit_info_company": "rbi-cic"}[entity])
               for k in keys), keys


def test_m3_minor_the_new_paragraphs_are_the_entity_wise_counterparts_of_cb_106():
    clauses = crypto_kb.load()["clauses"]
    for key in ("rbi-sfb-2026-para-105", "rbi-pb-2026-para-105", "rbi-aifi-2026-para-105", "rbi-cic-2026-para-105",
                "rbi-ucb-2026-para-120"):
        assert "at rest" in clauses[key]["text"] and "in-transit" in clauses[key]["text"], key
    assert "Level II" in clauses["rbi-ucb-2026-para-120"]["note"]
    assert "transmitted over the network" in clauses["rbi-ucb-2026-para-23"]["text"]
    assert "secure storage" in clauses["rbi-nbfc-2026-para-95"]["text"]
    ucb = regulated_entity.profile("ucb")
    assert "rbi-ucb-2026-para-23" in _rbi_keys(crypto_kb.clauses_for("node", "NO_TLS", None, team=ucb))
    assert "rbi-ucb-2026-para-120" in _rbi_keys(crypto_kb.clauses_for("node", "DISK_UNENCRYPTED", None, team=ucb))


@pytest.mark.parametrize("code", ["REUSED_NONCE", "STATIC_IV", "STATIC_SALT", "WEAK_KDF_ITERATIONS", "WEAK_RNG"])
def test_m3_minor_ucb_para_25_joins_the_other_six_instruments(code):
    every = _rbi_keys(crypto_kb.clauses_for("code", code, None, team=None))
    assert set(RBI_CRYPTO.values()) <= every, every - set(RBI_CRYPTO.values())


@pytest.mark.parametrize("code", ["KERBEROS_DES_ENABLED", "KERBEROS_RC4_ONLY", "KERBEROS_RC4_ENABLED"])
def test_m3_minor_kerberos_codes_from_488_cite_every_entity_types_own_paragraph(code):
    """#488 (merged into dev after review 2) cited the superseded 2023 MD and CB para 140 only."""
    every = _rbi_keys(crypto_kb.clauses_for("node", code, None, team=None))
    assert every == set(RBI_CRYPTO.values()), every
    for entity, key in RBI_CRYPTO.items():
        assert _rbi_keys(crypto_kb.clauses_for("node", code, None, team=regulated_entity.profile(entity))) == {key}


def test_m3_minor_both_kb_copies_are_byte_identical():
    a, b = (p.read_bytes() for p in R.KB)
    assert a == b


# ---------------------------------------------------------------------------------------------- m4
def test_m4_minor_rbi_rows_do_not_bind_an_other_entity():
    other = regulated_entity.profile("other")
    assert not regulated_entity.framework_binds("rbi_free_ai_protection", other)
    assert not regulated_entity.framework_binds("RBI", other)
    for entity in RBI_CRYPTO:
        assert regulated_entity.framework_binds("rbi_free_ai_protection", regulated_entity.profile(entity)), entity
        assert regulated_entity.framework_binds("RBI", regulated_entity.profile(entity)), entity
    assert "other" not in crypto_kb.load()["applicability"]["frameworks"]["rbi_free_ai_protection"]["entities"]


# ---------------------------------------------------------------------------------------------- m5
def test_m5_the_previous_issue_is_part_of_the_d14_digest():
    first, later = staging_like_view(), staging_like_view()
    later.previous_issue = {"document_id": "CBOM-D14-T1-20261123-aaaaaaaa", "as_of": "2026-11-23", "grade": "C"}
    other = dataclasses.replace(later)
    other.previous_issue = {**later.previous_issue, "document_id": "CBOM-D14-T1-20261123-bbbbbbbb"}
    assert len({common.document_id(v, 14) for v in (first, later, other)}) == 3


def test_m5_a_document_id_always_prints_the_same_trend(api, seeded, tmp_path):  # noqa: F811
    """X (first issue) -> Y (trend against X) -> X again: the same ID as the first X and the same "First issue"
    text; Y again: the same ID and trend as before. Two PDFs never share an ID."""
    pdf = R._pdf_text
    x1 = pdf(api("GET", D14).content, tmp_path, "x1")
    assert "First issue" in x1
    assert api("PATCH", SETTINGS, json={"regulated_entity": "bank"}).status_code == 200
    y1 = pdf(api("GET", D14).content, tmp_path, "y1")
    assert f"Previous issue: {_d14_id(x1)}" in y1
    assert api("PATCH", SETTINGS, json={"regulated_entity": "nbfc"}).status_code == 200
    x2 = pdf(api("GET", D14).content, tmp_path, "x2")
    assert _d14_id(x2) == _d14_id(x1)
    assert "First issue" in x2 and "Previous issue:" not in x2
    assert api("PATCH", SETTINGS, json={"regulated_entity": "bank"}).status_code == 200
    y2 = pdf(api("GET", D14).content, tmp_path, "y2")
    assert _d14_id(y2) == _d14_id(y1) and f"Previous issue: {_d14_id(x1)}" in y2


# ---------------------------------------------------------------------------------------------- n1
def test_n1_the_grade_input_sentence_with_posture_is_one_sentence(monkeypatch):
    from backend.utilities.pdf import cbom_board_report_pdf as board

    monkeypatch.setattr(board, "posture_active", lambda _view: True)  # the Appendix A variant with posture findings
    text = board._grade_input_text(staging_like_view())
    assert "plus configuration posture findings by impact" in text
    assert "excluded. plus" not in text and ". plus" not in text
    assert text.endswith("Inventory-only assets without findings are excluded.")


# ---------------------------------------------------------------------------------------------- IR 8547 (#490)
def test_ir8547_kb_entry_keeps_citation_and_status_apart():
    from backend.utilities.pdf import cbom_kb_text as kb_text

    entry = crypto_kb.load()["pqc_context"]["nist_ir_8547"]
    assert entry["citation"] == "NIST IR 8547" and entry["status"] == "final" and entry["published"] == "2026-10-27"
    assert kb_text.ir8547()["label"] == "NIST IR 8547 (final, 2026)"
    assert kb_text.ir8547_label({**entry, "status": "draft", "published": "2024-11-12"}) == "NIST IR 8547 (draft, 2024)"
