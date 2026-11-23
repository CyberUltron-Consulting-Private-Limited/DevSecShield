"""PR #490 review 6027867612: D12 quantum risk register and D13 PQC migration roadmap fixes.

* M1  a classical weakness of waves 1-3 (SP 800-131A disallows it today: TLS 1.0, RSA-1024, Triple DES ...) is dated
      from the assessment (90 / 180 / 365 days, a team setting), never from a post-quantum milestone; IR 8547 / CNSA 2.0
      dates are for the post-quantum migration only ("PQ by").
* M2  an asset SP 800-131A disallows is graded the worse of its class grade and rules 24-25, whatever its class
      (RSA-1024, DSA-1024 as well as Triple DES), under any Mosca inputs.
* M3  qg-1 rule 6 (not_correlated) is applied inside ``GradeContext.grade_row``: the run posture, the run asset rows
      and the register agree (Rule P).
* M4  every NIST IR 8547 status, date and URL in D12 / D13 comes from the one KB entry; a PDF never cites it as both a
      draft and final.
* M5  the CNSA 2.0 code-signing target lists only the single-tree stateful hash-based schemes (NSA CNSA 2.0 FAQ).
* minors: CSV class with the grade's read-elsewhere rule, the deprecated class on every surface, readable labels,
  appendix words not cut mid-token, Z anchored to 2035, one weekly series, the D13 readiness formula.

    cd backend && PYTHONPATH=..:tests python -m pytest tests/test_cbom_d12_d13_review_fixes.py -q
"""
from __future__ import annotations

import datetime as dt
import re
import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

REPO = Path(__file__).resolve().parents[2]
TESTS = Path(__file__).resolve().parent
for p in (REPO, TESTS):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from backend.new_models import CbomCollectedAsset  # noqa: E402
from backend.utilities.cbom_sources import crypto_kb  # noqa: E402
from backend.utilities.cbom_sources import posture as P  # noqa: E402
from backend.utilities.cbom_sources import pqc_targets as T  # noqa: E402
from backend.utilities.cbom_sources import qgrade as QG  # noqa: E402
from backend.utilities.cbom_sources import risk_register as REG  # noqa: E402
from backend.utilities.cbom_sources import waves as W  # noqa: E402
from backend.utilities.cbom_sources.classify import shown  # noqa: E402
from backend.utilities.cbom_sources.common import utcnow  # noqa: E402
from backend.utilities.cbom_sources.schemas import RiskModel  # noqa: E402
from backend.utilities.cbom_sources.settings import get_or_create_settings  # noqa: E402
from backend.utilities.pdf import cbom_pqc_roadmap_pdf as roadmap  # noqa: E402
from backend.utilities.pdf import cbom_risk_register_pdf as RPDF  # noqa: E402
from test_cbom_cb20_estate import World, _sqlite  # noqa: E402
from test_cbom_deliverable_pqc_roadmap import algo, make_view, pdf_full_text, squash  # noqa: E402

AS_OF = dt.date(2026, 11, 24)


# ============================================================================ M1: classical weaknesses dated now
def _classical_codes() -> list[str]:
    """Every KB finding code a classical attacker can use today (not the quantum verdict, not a coverage note)."""
    kb = crypto_kb.load()["findings"]
    return sorted({c for ns in kb.values() for c, e in ns.items()
                   if e.get("category") != "pqc" and not c.startswith("COVERAGE_")})


@pytest.mark.parametrize("wave,days", [(1, 90), (2, 180), (3, 365)])
def test_a_classical_weakness_is_never_dated_later_than_the_engagement_window(wave, days):
    limit = (AS_OF + dt.timedelta(days=days)).isoformat()
    codes = _classical_codes()
    assert "PROTO_TLS10" in codes and len(codes) > 50
    for code in codes:
        for qv in (True, False, None):
            got = T.proposed_dates(wave, [code], qv, AS_OF)
            assert got["kind"] == "fix" and got["date"] == got["fix_by"] == limit, (code, qv, got)
            # the post-quantum date is a second date, on quantum-vulnerable assets only
            assert (got["pq_by"] is not None) == (qv is True)


def test_the_post_quantum_dates_are_only_for_the_quantum_part():
    tls10 = T.proposed_dates(1, ["PROTO_TLS10", "QUANTUM_VULNERABLE"], True, AS_OF)
    assert tls10 == {"date": "2027-02-22", "kind": "fix", "fix_by": "2027-02-22", "pq_by": "2027-12-31"}
    hndl_only = T.proposed_dates(1, ["QUANTUM_VULNERABLE"], True, AS_OF)
    assert hndl_only == {"date": "2027-12-31", "kind": "pq", "fix_by": None, "pq_by": "2027-12-31"}
    no_pq_kex = T.proposed_dates(3, ["NO_PQ_KEX"], True, AS_OF)  # a quantum-only finding: the PQ milestone
    assert no_pq_kex["kind"] == "pq" and no_pq_kex["fix_by"] is None
    assert T.proposed_dates(4, ["QUANTUM_VULNERABLE"], True, AS_OF)["date"] == "2033-12-31"
    assert T.proposed_dates(None, ["PROTO_TLS10"], True, AS_OF)["date"] is None


def test_the_windows_are_a_team_setting_with_kb_defaults():
    assert T.fix_windows() == {1: 90, 2: 180, 3: 365}
    assert T.fix_windows({"wave1_fix_days": 30, "wave3_fix_days": 0, "wave2_fix_days": True}) == {1: 30, 2: 180,
                                                                                                    3: 365}
    assert RiskModel(wave1_fix_days=30).wave1_fix_days == 30
    for bad in (0, 3651):
        with pytest.raises(ValueError):
            RiskModel(wave2_fix_days=bad)
    got = T.proposed_dates(1, ["RSA_KEY_TOO_SHORT"], True, AS_OF, {1: 30, 2: 180, 3: 365})
    assert got["fix_by"] == "2026-12-24"


def test_wave_api_items_carry_a_fix_date_and_a_pq_date():
    today = dt.datetime.utcnow().date()
    tls = {"asset_key": "a", "suggested_wave": 1, "finding_codes": ["PROTO_TLS10"], "quantum_vulnerable": True}
    rsa = {"asset_key": "b", "suggested_wave": 2, "finding_codes": ["FINDING"], "quantum_vulnerable": True}
    out = {i["asset_key"]: i for i in W._with_assignment([tls, rsa], {}, {1: 90, 2: 180, 3: 365})}
    assert out["a"]["proposed_date"] == (today + dt.timedelta(days=90)).isoformat()
    assert out["a"]["proposed_date_kind"] == "fix" and out["a"]["pq_by"] == "2027-12-31"
    assert out["b"]["proposed_date"] == (today + dt.timedelta(days=180)).isoformat()
    assert out["b"]["proposed_date"] < "2030-12-31" and out["b"]["pq_by"] == "2030-12-31"


def test_the_d13_rows_date_rsa_1024_and_tls_1_0_from_the_assessment():
    rsa = algo("RSA-1024", key_size="1024", impact="High", ident="r1")
    plans = {}
    from backend.utilities.dashboard.cbom_team_rollup import plan_key
    plans[plan_key(rsa)] = {"assigned": {}, "suggested": 2, "finding_codes": ["WEAK_KEY"], "quantum_vulnerable": True}
    node = {"asset_id": 1, "label": "www.chola.example:443", "type": "tls_endpoint", "algorithm": "ECDHE-RSA",
            "impact": "High", "source_name": "dmz", "target": "203.0.113.10:443", "location": "",
            "suggested_wave": 1, "wave": 1, "assignment": None, "finding_codes": ["PROTO_TLS10"],
            "quantum_vulnerable": True, **W.target_fields("tls_endpoint", None, {})}
    view = make_view([rsa], remediation={"code_plans": plans, "node_rows": [node], "node_rows_omitted": 0})
    text = pdf_full_text(roadmap.build_pdf(view))
    flat = squash(text)
    as_of = view.as_of
    assert squash(f"{(as_of + dt.timedelta(days=180)).isoformat()} fix") in flat  # RSA-1024, wave 2
    assert squash(f"{(as_of + dt.timedelta(days=90)).isoformat()} fix") in flat  # TLS 1.0, wave 1
    assert squash("PQ by 2030-12-31") in flat and squash("PQ by 2027-12-31") in flat
    # the RSA-1024 row's date cell leads with its classical fix date; 2030-12-31 is only its "PQ by" date
    from test_cbom_d13_roadmap_targets import _table_with
    from test_cbom_deliverable_pqc_roadmap import body_of
    table = _table_with(body_of(view), "NIST PQ target", also="Seen")
    col = next(i for i, h in enumerate(table[0]) if str(h).startswith("Target date"))
    cell = next(r[col] for r in table[1:] if r[1] == "RSA-1024")
    lines = re.split(r"\n|<br/>", cell)
    assert lines[0] == f"{(as_of + dt.timedelta(days=180)).isoformat()} fix (proposed)", cell
    assert "PQ by 2030-12-31" in cell


def test_the_wave_3_basis_no_longer_contradicts_its_date_and_wave_2_says_high_value_assets():
    w2, w3 = T.wave_milestone(2), T.wave_milestone(3)
    assert "before the 2030 deprecation" not in w3["pq_basis"] and w3["pq_date"] == "2031-12-31"
    assert "December 2031" in w3["pq_basis"]
    assert "high value assets and high impact systems" in w2["pq_basis"]
    assert "Federal key establishment" not in w2["pq_basis"]
    for m in T.milestones():  # m8: never cut by the table's cell limit
        assert len(m["pq_basis"]) + len(m.get("fix_basis") or "") < 650


# ============================================================================ M2: SP 800-131A disallowed, any class
@pytest.mark.parametrize("exposure,expect", [("internet", ("Q1", "deprecated_internet")),
                                             ("internal", ("Q2", "deprecated")),
                                             ("unknown", ("Q2", "deprecated"))])
@pytest.mark.parametrize("x,y,z", [(3, 2, 15), (7, 5, 9), (10, 5, 9), (0, 0, 100)])
def test_a_disallowed_quantum_vulnerable_key_takes_the_worse_grade(exposure, expect, x, y, z):
    out = QG.grade(QG.GradeInput(cls="quantum-vulnerable", exposure=exposure, x=x, y=y, z=z, disallowed=True))
    plain = QG.grade(QG.GradeInput(cls="quantum-vulnerable", exposure=exposure, x=x, y=y, z=z))
    rank = {"Q1": 1, "Q2": 2, "Q3": 3, "Q4": 4}
    assert rank[out.q_grade] == min(rank[plain.q_grade], rank[expect[0]])
    if rank[expect[0]] <= rank[plain.q_grade]:
        assert (out.q_grade, out.q_reason) == expect


def test_a_disallowed_anchor_keeps_its_worse_quantum_reason():
    out = QG.grade(QG.GradeInput(cls="quantum-vulnerable", exposure="internal", anchor=True, x=10, y=5, z=9,
                                 disallowed=True))
    assert (out.q_grade, out.q_reason) == ("Q1", "qv_exceeds_anchor")
    # rules 1-6 keep their precedence
    assert QG.grade(QG.GradeInput(cls="unknown", disallowed=True)).q_reason == "unknown_verdict"
    assert QG.grade(QG.GradeInput(cls="quantum-vulnerable", correlation_missing=True, disallowed=True)
                    ).q_reason == "not_correlated"


def _key(name, alg, qv, facts, typ="private_key"):
    return {"type": typ, "target": "h", "location": f"/{name}", "name": name, "algorithm": alg, "qv": qv,
            "facts": facts}


@pytest.mark.parametrize("mosca", [None, {"data_shelf_life_years": 3, "migration_years": 2, "threat_years": 15},
                                   {"data_shelf_life_years": 10, "migration_years": 5, "threat_years": 5}])
def test_rsa_1024_dsa_1024_and_3des_are_graded_disallowed_under_any_mosca(tmp_path, mosca):
    w = World(_sqlite(tmp_path / "edges.db"))
    if mosca is not None:
        with Session(w.engine) as s:
            row = get_or_create_settings(s, 1)
            row.risk_model = mosca
            s.add(row)
            s.commit()
    sid = w.source("linux_servers", "edge")
    rows = [_key("rsa1024", "RSA", True, {"key_alg": "RSA", "key_size": 1024}),
            _key("dsa1024", "DSA", True, {"key_alg": "DSA", "key_size": 1024}),
            _key("3des", "DES-EDE3", None, {}, "managed_key"),
            _key("rsa2048", "RSA", True, {"key_alg": "RSA", "key_size": 2048}),
            _key("hmac-sha1", "HMAC-SHA1", None, {}, "managed_key")]
    run_id = w.run({sid: {"rows": rows}})
    w.finalise(run_id)
    with Session(w.engine) as s:
        items = {i["label"].split(" · ")[0]: i for i in REG.list_register(
            s, 1, {}, after=None, limit=100, detail=True, now=utcnow())["items"]}
        ctx = QG.load_context(s, team_id=1, run_id=run_id)
        run = {r.name: ctx.grade_row(r, [c for c in shown(r, utcnow())["finding_codes"]
                                         if not c.startswith("COVERAGE_")], explain=True)
               for r in s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id)).all()}
    for name in ("rsa1024", "dsa1024", "3des"):
        assert items[name]["sp800_131a"] == "disallowed", name
        assert (items[name]["q_grade"], items[name]["q_reason"]) == ("Q2", "deprecated"), (name, items[name])
        assert (run[name].q_grade, run[name].q_reason) == ("Q2", "deprecated")
        assert run[name].explain["sp800_131a_disallowed"] is True
    assert items["rsa1024"]["pqc_class"] == "quantum-vulnerable" and items["3des"]["pqc_class"] == "deprecated"
    assert items["rsa2048"]["q_reason"].startswith("qv_")  # an approved key stays on the Mosca path
    assert items["hmac-sha1"]["q_grade"] is None  # HMAC-SHA1 stays acceptable: no false positive


# ============================================================================ M3: Rule P with not-correlated keys
def _seed_not_correlated(tmp_path):
    w = World(_sqlite(tmp_path / "rulep.db"))
    sid = w.source("linux_servers", "linux-dc")
    rows = [
        {"type": "private_key", "target": "app-01", "location": "/etc/ssl/private/web.key", "name": "web.key",
         "algorithm": "RSA", "qv": True, "facts": {"key_alg": "RSA", "key_size": 2048}},
        {"type": "certificate", "target": "app-01", "location": "/etc/ssl/certs/web.pem", "name": "CN=web.example",
         "algorithm": "ECDSA", "qv": True, "facts": {"key_alg": "EC", "curve": "P-256", "is_ca": False}},
        {"type": "certificate", "target": "ca-01", "location": "/etc/pki/ca/root.pem", "name": "CN=Root CA",
         "algorithm": "RSA", "qv": True, "facts": {"key_alg": "RSA", "key_size": 4096, "is_ca": True}},
        {"type": "managed_key", "target": "db", "location": "db#k/aes", "name": "LabAes", "algorithm": "AES",
         "qv": False, "facts": {"key_size": 256}},
    ]
    run_id = w.run({sid: {"rows": rows}})
    w.finalise(run_id)
    return w, run_id


def test_run_posture_grades_equal_the_register_for_not_correlated_keys(tmp_path):
    w, run_id = _seed_not_correlated(tmp_path)
    with Session(w.engine) as s:
        post = P.run_posture(s, team_id=1, run_id=run_id, risk_model=None)
        summary = REG.summary(s, 1, utcnow())
        items = REG.list_register(s, 1, {}, after=None, limit=100, detail=True, now=utcnow())["items"]
        assert any(i["q_reason"] == "not_correlated" for i in items), "the fixture must hold a not-correlated key"
        assert post["q_grades"] == summary["q_grades"]
        ctx = QG.load_context(s, team_id=1, run_id=run_id)
        for row in s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id)).all():
            codes = [c for c in shown(row, utcnow())["finding_codes"] if not c.startswith("COVERAGE_")]
            fast, full = ctx.grade_row(row, codes, explain=False), ctx.grade_row(row, codes, explain=True)
            assert (fast.q_grade, fast.q_reason) == (full.q_grade, full.q_reason)
            reg = next(i for i in items if i["label"].split(" · ")[0] == row.name)
            assert (full.q_grade, full.q_reason) == (reg["q_grade"], reg["q_reason"]), row.name
            assert full.explain["class"] == reg["pqc_class"]  # m1: the CSV class is the grade's class


def test_the_review_rule_p_script_reports_no_mismatch(tmp_path):
    """The review's own reproduction (qa/490/scripts/rule_p.py) on the same kind of team: 0 mismatches."""
    w, run_id = _seed_not_correlated(tmp_path)
    with Session(w.engine) as s:
        ctx = QG.load_context(s, team_id=1, run_id=run_id)
        by = {}
        for row in s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id)).all():
            codes = [c for c in shown(row, utcnow())["finding_codes"] if not c.startswith("COVERAGE_")]
            g = ctx.grade_row(row, codes, explain=True)
            by[row.name] = (g.q_grade, g.q_reason, g.explain.get("class"), g.explain.get("x"))
        mism = [i for i in REG.list_register(s, 1, {}, after=None, limit=500, detail=True, now=utcnow())["items"]
                if by.get(i["label"].split(" · ")[0]) not in (None, (i["q_grade"], i["q_reason"], i["pqc_class"],
                                                                    i["data_lifetime_years"]))]
        assert mism == []


# ============================================================================ M4: one IR 8547 entry
def _ir_lines(text: str) -> list[str]:
    flat = re.sub(r"\s+", " ", text)
    return [m.group(0) for m in re.finditer(r".{0,160}8547.{0,160}", flat)]


def assert_one_ir8547_status(text: str, status: str) -> None:
    """A document never cites NIST IR 8547 as both a draft (or its /ipd URL) and final."""
    lines = " ".join(_ir_lines(text)).lower()
    draft = bool(re.search(r"\bdraft\b|/ipd\b|\.ipd\.|initial public", lines))
    final = bool(re.search(r"\bfinal\b", lines))
    assert not (draft and final), lines[:600]
    assert (final if status == "final" else draft), lines[:600]


def test_d13_cites_ir_8547_once_with_the_kb_status_url_and_years():
    ir = T.ir8547()
    assert ir["status"] == "final" and "ipd" not in ir["url"] and ir["url"].startswith("https://")
    text = pdf_full_text(roadmap.build_pdf(make_view([algo("RSA-2048", ident="k1")])))
    assert_one_ir8547_status(text, "final")
    assert "initial public draft" not in text.lower()
    assert squash(ir["url"]) in squash(text)
    assert f"After {ir['disallowed_after']}" in text and f"After {ir['deprecated_after']}" in text
    assert QG.DEFAULT_Z_YEAR == ir["disallowed_after"]  # the default Z is anchored to the same KB year


def test_a_draft_kb_entry_makes_every_mention_a_draft(monkeypatch):
    ctx = dict(crypto_kb.pqc_context())
    ipd = "https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf"
    ctx["nist_ir_8547"] = {**ctx["nist_ir_8547"], "source": ipd}
    ctx["nist_ir_8547"].pop("status", None)
    ctx["nist_ir_8547"].pop("landing", None)
    monkeypatch.setattr(crypto_kb, "pqc_context", lambda: ctx)
    assert T.ir8547()["status"] == "draft"
    assert roadmap.timeline_footnote().startswith("NIST IR 8547 is a draft")
    assert all(r[2] == "Draft" for r in roadmap.timeline_rows() if "8547" in r[3])


def test_d12_never_cites_ir_8547_as_a_draft():
    view = make_view([algo("RSA-2048", ident="k1")])
    view.register = {"summary": {"total": 0, "q_grades": {}, "closures_by_week": [], "default_assumptions": {}},
                     "heatmap": {"cells": [], "columns": []}, "top_q1": [], "q0": [], "assets": [],
                     "mosca_definition": QG.MOSCA_DEFINITION}
    text = pdf_full_text(RPDF.build_pdf(view))
    lines = " ".join(_ir_lines(text)).lower()
    assert "8547" in lines and "2035" in lines  # the default Z's anchor, cited without a status
    assert not re.search(r"\bdraft\b|/ipd\b|\.ipd\.|initial public", lines)


# ============================================================================ M5: CNSA 2.0 code signing
def test_the_cnsa_code_signing_target_lists_only_single_tree_schemes():
    row = T.table()["code_signing"]
    nist = set(row["target"].split(" or ")[0].split(" / "))
    cnsa = set(row["cnsa_target"].split(" or ")[0].split(" / "))
    assert nist == {"HSS", "LMS", "XMSS", "XMSS^MT"}  # NIST: every SP 800-208 scheme
    assert cnsa == {"LMS", "XMSS"} and row["cnsa_excluded"] == ["HSS", "XMSS^MT"]
    assert "ML-DSA-87" in row["cnsa_target"]
    assert "SHA-256/192" in row["note"]


def test_d13_says_why_the_cnsa_column_names_fewer_schemes():
    node = {"asset_id": 1, "label": "release-signing", "type": "signing_key", "algorithm": "RSA", "impact": "Info",
            "source_name": "build", "target": "build-01", "location": "/opt/sign", "suggested_wave": 4, "wave": 4,
            "assignment": None, "quantum_vulnerable": True,
            **W.target_fields("signing_key", "RSA", {"usage": "code signing"})}
    view = make_view([], remediation={"code_plans": {}, "node_rows": [node], "node_rows_omitted": 0})
    text = re.sub(r"\s+", " ", pdf_full_text(roadmap.build_pdf(view)))
    assert "Not approved under CNSA 2.0: HSS, XMSS^MT" in text
    assert "CNSA 2.0: LMS / XMSS or ML-DSA-87" in text


def test_a_selector_name_algid_does_not_know_is_refused():
    with pytest.raises(LookupError):
        T._select(T._key({"standard": "SP 800-208", "all": True, "names": ["LMS", "NOT-A-SCHEME"]}))


# ============================================================================ minors
def test_m2_the_deprecated_class_is_on_the_posture_page_and_the_cbom(tmp_path):
    w = World(_sqlite(tmp_path / "m2.db"))
    sid = w.source("linux_servers", "db")
    run_id = w.run({sid: {"rows": [_key("3des", "DES-EDE3", None, {}, "managed_key"),
                                   _key("rc4", "RC4", None, {}, "managed_key"),
                                   _key("aes", "AES", False, {"key_size": 256}, "managed_key")]}})
    w.finalise(run_id)
    with Session(w.engine) as s:
        post = P.run_posture(s, team_id=1, run_id=run_id, risk_model=None)
        assert post["pqc_classes"]["deprecated"] == 2 and post["pqc_classes"]["not-applicable"] == 0
        assert P.run_class_summary(s, team_id=1, run_id=run_id)["pqc_classes"]["deprecated"] == 2
        assert P.PQC_CLASS_MODEL == "pc-3" and "deprecated" in P.PQC_CLASSES
        assert post["pqc_readiness_pct"] == 100.0  # outside readiness, as not-applicable was
    ts = (REPO / "frontend" / "utils" / "backend_api.ts").read_text(encoding="utf-8")
    assert '| "deprecated"' in ts.split("export type CbomPqcClass", 1)[1][:400]
    posture_tsx = (REPO / "frontend" / "components" / "cbom" / "sources" / "RunPosture.tsx").read_text("utf-8")
    assert "deprecated: [" in posture_tsx and "graded separately" in posture_tsx


def test_m3_appendix_words_break_only_at_punctuation():
    for value, width in (("quantum-vulnerable", 64), ("payments-ops@chola.example", 56),
                         ("curve25519-sha256", 50), ("configurable", 54)):
        out = RPDF.breakable(value, width)
        assert out.replace("\n", "") == value
        for line in out.split("\n")[:-1]:
            assert line[-1] in "@./_-:", (value, out)
    assert RPDF.breakable("payments-ops@chola.example", 64).split("\n")[0].endswith("@")  # the Owner column


def test_m4_m5_readable_labels_and_the_no_grade_card():
    assert RPDF.status_word("not_applicable") == "n/a" and RPDF.status_word("not_compliant") == "not compliant"
    assert RPDF.class_word("deprecated") == "SP 800-131A disallowed"
    texts = {code: meta["text"] for code, meta in QG.REASONS.items()}
    assert RPDF.reason_word("qv_exceeds_internet", texts).startswith("Quantum-vulnerable")
    assert RPDF.reason_word("qv_exceeds_internet") == "qv exceeds internet"  # never the raw code
    assert RPDF.gap_reason("not_correlated") == "not correlated across sources"
    cards = RPDF._summary({"summary": {"q_grades": {}}}, 720)
    assert cards  # the subtitle is checked on the text below
    import inspect
    src = inspect.getsource(RPDF._summary)
    assert "no public-key or disallowed cryptography" not in src and "disallowed items are graded" in src


def test_m6_x_y_z_are_defined_and_z_is_anchored_to_2035():
    assert QG.default_z(2026) == 9 and QG.default_z(2035) == 0 and QG.default_z(2040) == 0
    x, y, z, _basis, assumed = QG.effective_mosca(None, None, None, None, None, 2027)
    assert (x, y, z) == (QG.DEFAULT_X, QG.DEFAULT_Y, 8) and assumed == ("x", "y", "z")
    text = RPDF.mosca_definition({"mosca_definition": QG.MOSCA_DEFINITION})
    for needle in ("X is how many years the data must stay secret", "planning assumption", "until 2035",
                   "X + Y > Z"):
        assert needle in text
    assert "planning assumption" in QG.FORMULA_TEXT and "to 2035" in QG.FORMULA_TEXT


def test_m6_the_register_regrades_when_the_default_z_changes(monkeypatch, tmp_path):
    w, _run = _seed_not_correlated(tmp_path)
    with Session(w.engine) as s:
        now = REG.team_inputs(s, 1).digest
        monkeypatch.setattr(QG, "default_z", lambda year=None: 3)
        assert REG.team_inputs(s, 1).digest != now


def test_m7_one_weekly_series_named_for_q0_gaps():
    weeks = [{"week": "2026-11-16", "total": 1, "by_cause": {}, "q0_gaps_opened": 2, "q0_gaps_open_at_week_end": 1}]
    view = make_view([])
    view.register = {"summary": {"total": 1, "q_grades": {}, "closures_by_week": weeks, "default_assumptions": {}},
                     "heatmap": {"cells": [], "columns": []}, "top_q1": [], "q0": [], "assets": []}
    text = re.sub(r"\s+", " ", pdf_full_text(RPDF.build_pdf(view)))
    assert "Quantum gaps opened / closed per week" in text and "Q0 gaps closed" in text


def test_d13_readiness_prints_the_formula_of_the_number_it_shows():
    view = make_view([algo("RSA-2048", ident="k1")], pqc_safe=26, pqc_vulnerable=22, pqc_broken_today=8,
                     readiness_pct=46.4)
    line = roadmap.readiness_line(view)
    assert line == ("Quantum readiness 46.4% = 26 quantum-safe / (26 quantum-safe + 8 broken today + 22 "
                    "quantum-vulnerable).")
    assert round(100 * 26 / (26 + 8 + 22), 1) == 46.4
    text = re.sub(r"\s+", " ", pdf_full_text(roadmap.build_pdf(view)))
    assert "safe / (safe + broken today + vulnerable)" in text
    assert "quantum-safe / (safe + vulnerable)" not in text
