"""PR #490 review 6031265209 (second and final review): D12 quantum risk register and D13 PQC migration roadmap.

* A  a classical fix date counts from the day the asset was FIRST FOUND (node assets: the estate's first_seen_at; code
     rows: the earliest included scan with the same stable key; else the as-of day), never from the day D13 is
     rendered or the wave API is called: the same estate gives the same fix_by on every download, and a later day
     shows the row "overdue". The wave API and D13 agree.
* B  the wave windows are ordered (wave1 <= wave2 <= wave3), in the body and after the settings merge.
* C  a grade-model re-grade closes the team's ``inputs:mosca`` item as ``model_change``: no forwarded q0_closed drift
     event, nothing in drift_report.weekly_drift, not counted as closed in D12 section E (the week is marked).
* D  NIST IR 8547's printed name is built from the KB entry's status and published date, never from a citation string
     that embeds a status (#485's KB: "NIST IR 8547 (final, 2026)").
* E  the D12 no-grade note says DSA is disallowed at any size.
* F  the wave basis cites SP 800-131A only for assets whose algorithm or key size is disallowed.
* the collectors' certificate signature key is ``sig_alg``: sha1WithRSA / md5WithRSA certificates grade Q2 deprecated.

    cd backend && PYTHONPATH=..:tests python -m pytest tests/test_cbom_d12_d13_final_review.py -q
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

from backend.new_models import (  # noqa: E402
    CbomDriftEvent,
    CbomEstateAsset,
    CbomQ0Gap,
    Scan,
)
from backend.utilities.cbom_sources import crypto_kb  # noqa: E402
from backend.utilities.cbom_sources import drift_report as DR  # noqa: E402
from backend.utilities.cbom_sources import pqc_targets as T  # noqa: E402
from backend.utilities.cbom_sources import q0register as Q0  # noqa: E402
from backend.utilities.cbom_sources import qgrade as QG  # noqa: E402
from backend.utilities.cbom_sources import risk_register as REG  # noqa: E402
from backend.utilities.cbom_sources import waves as W  # noqa: E402
from backend.utilities.cbom_sources.common import utcnow  # noqa: E402
from backend.utilities.cbom_sources.schemas import RiskModel  # noqa: E402
from backend.utilities.cbom_sources.settings import get_or_create_settings  # noqa: E402
from backend.utilities.dashboard.cbom_team_rollup import load_team_cbom_view  # noqa: E402
from backend.utilities.pdf import cbom_pqc_roadmap_pdf as roadmap  # noqa: E402
from backend.utilities.pdf import cbom_risk_register_pdf as RPDF  # noqa: E402
from test_cbom_cb20_estate import NOW, World, _sqlite  # noqa: E402
from test_cbom_deliverable_pqc_roadmap import pdf_full_text  # noqa: E402

UTC = dt.timezone.utc
FIRST = NOW.date()  # the World's first run is collected on 2026-11-14
EARLY = dt.datetime(2026, 11, 20, 9, tzinfo=UTC)  # inside every window
LATE = dt.datetime(2027, 6, 1, 9, tzinfo=UTC)  # past the 90- and 180-day windows from 2026-11-14
REPO_META = {"repo_url": "https://github.com/acme/pay", "branch": "main"}
RSA_ROW = {"title": "RSA-1024", "algorithm_name": "RSA", "asset_type": "algorithm", "algorithm_type": "pke",
           "location": "src/crypto_utils.py:12", "bom_ref": "crypto-algo-rsa", "impact": "High", "key_size": 1024,
           "finding_codes": ["WEAK_KEY_SIZE", "QUANTUM_VULNERABLE"], "crypto_strength": "weak", "weak": True,
           "quantum_vulnerable": True, "quantum_safe": False}
CODE_FIRST = dt.datetime(2026, 10, 1, 9)  # the first code scan that carries RSA_ROW


def _tls_row(name: str = "www.chola.example:443") -> dict:
    return {"type": "tls_endpoint", "target": name, "location": "", "name": name, "algorithm": "ECDHE-RSA",
            "qv": True, "impact": "High", "codes": ["PROTO_TLS10", "QUANTUM_VULNERABLE"],
            "facts": {"protocol": "TLSv1.0", "negotiated_group": "secp256r1"}}


def _code_scan(engine, scan_id: int, created: dt.datetime, rows: list[dict], status: str = "success") -> None:
    with Session(engine) as s:
        s.add(Scan(id=scan_id, team_id=1, owner_user_id=1, scan_type="cbom", title="code", scan_status=status,
                   scan_metadata=REPO_META, created_at=created, last_updated=created, scan_data={"results": rows}))
        s.commit()


@pytest.fixture()
def estate(tmp_path):
    """A team with one TLS 1.0 endpoint first collected at NOW and seen again by a later run, plus two successful
    code scans of one repository that both carry RSA-1024 (first on CODE_FIRST)."""
    w = World(_sqlite(tmp_path / "anchor.db"))
    sid = w.source("network_endpoints", "dmz")
    w.finalise(w.run({sid: {"rows": [_tls_row()]}}))
    second = w.run({sid: {"rows": [_tls_row()]}})
    w.finalise(second)
    _code_scan(w.engine, 901, CODE_FIRST, [RSA_ROW])
    _code_scan(w.engine, 902, CODE_FIRST + dt.timedelta(days=30), [RSA_ROW])
    return {"world": w, "engine": w.engine, "run_id": second}


def _wave_api(engine, run_id: int, monkeypatch, now: dt.datetime) -> dict:
    """The run's wave API (GET .../runs/{id}/remediation) and the code scan's, answered on ``now``."""
    from backend.routers import cbom_ops

    monkeypatch.setattr(W, "_today", lambda: now.date(), raising=False)
    node = {i["label"].split(" · ")[0]: i for i in cbom_ops._run_remediation(engine, 1, run_id)["items"]}
    code = {i["label"].split(" · ")[0]: i for i in cbom_ops._code_remediation(engine, 1, 902)["items"]}
    return {**node, **code}


def _d13(engine, now: dt.datetime) -> str:
    view = load_team_cbom_view(engine, 1, now=now)
    return re.sub(r"\s+", " ", pdf_full_text(roadmap.build_pdf(view)))


def _fix_dates(text: str) -> list[str]:
    return sorted(set(re.findall(r"(\d{4}-\d{2}-\d{2}) fix \(proposed\)", text)))


# ============================================================================ A: fix_by from the first observation
def test_the_estate_records_when_the_endpoint_was_first_found(estate):
    with Session(estate["engine"]) as s:
        firsts = {a.first_seen_at for a in s.exec(select(CbomEstateAsset)).all()}
    assert {f.date() for f in firsts} == {FIRST} and len(firsts) == 1  # the first run, not the second


def test_the_wave_api_dates_a_node_asset_from_its_first_observation(estate, monkeypatch):
    early = _wave_api(estate["engine"], estate["run_id"], monkeypatch, EARLY)["www.chola.example:443"]
    late = _wave_api(estate["engine"], estate["run_id"], monkeypatch, LATE)["www.chola.example:443"]
    due = (FIRST + dt.timedelta(days=90)).isoformat()
    assert early["wave"] == 1 and early["fix_by"] == late["fix_by"] == due  # never counted from the day of the call
    assert early["found_on"] == late["found_on"] == FIRST.isoformat() and early["found_basis"] == "first_seen"
    assert early["overdue"] is False and late["overdue"] is True
    assert early["pq_by"] == late["pq_by"] == "2027-12-31"


def test_the_wave_api_dates_a_code_row_from_the_earliest_included_scan(estate, monkeypatch):
    early = _wave_api(estate["engine"], estate["run_id"], monkeypatch, EARLY)["RSA-1024"]
    late = _wave_api(estate["engine"], estate["run_id"], monkeypatch, LATE)["RSA-1024"]
    assert early["found_on"] == CODE_FIRST.date().isoformat()  # scan 901, not 902 (the one asked about)
    assert early["fix_by"] == late["fix_by"] == (CODE_FIRST.date() + dt.timedelta(days=180)).isoformat()
    assert early["overdue"] is False and late["overdue"] is True


def test_a_failed_older_scan_is_not_the_first_observation(estate, monkeypatch):
    _code_scan(estate["engine"], 900, CODE_FIRST - dt.timedelta(days=60), [RSA_ROW], status="failure")
    got = _wave_api(estate["engine"], estate["run_id"], monkeypatch, EARLY)["RSA-1024"]
    assert got["found_on"] == CODE_FIRST.date().isoformat()  # only included (successful) scans count


def test_d13_prints_the_same_fix_dates_on_two_days_and_marks_them_overdue_later(estate):
    early, late = _d13(estate["engine"], EARLY), _d13(estate["engine"], LATE)
    tls_due = (FIRST + dt.timedelta(days=90)).isoformat()
    rsa_due = (CODE_FIRST.date() + dt.timedelta(days=180)).isoformat()
    assert _fix_dates(early) == _fix_dates(late) == sorted([tls_due, rsa_due])
    assert f"found {FIRST.isoformat()}" in early and f"found {CODE_FIRST.date().isoformat()}" in early
    row_overdue = r"found \d{4}-\d{2}-\d{2} (?:PQ by \S+ \(proposed\) )?overdue"
    assert not re.search(row_overdue, early) and len(re.findall(row_overdue, late)) == 2
    # the wave table: the window, the per-asset date and the overdue count, never a date counted from today
    assert "within 90 days of first found" in late and f"{tls_due} 1 overdue" in late
    assert (LATE.date() + dt.timedelta(days=90)).isoformat() not in late


def test_the_wave_api_and_d13_agree_on_every_fix_date(estate, monkeypatch):
    api = _wave_api(estate["engine"], estate["run_id"], monkeypatch, LATE)
    text = _d13(estate["engine"], LATE)
    for label in ("www.chola.example:443", "RSA-1024"):
        item = api[label]
        assert f"{item['fix_by']} fix (proposed) found {item['found_on']}" in text, label
    view = load_team_cbom_view(estate["engine"], 1, now=LATE)
    node = next(r for r in view.remediation["node_rows"] if r["label"].startswith("www.chola.example:443"))
    assert node["fix_by"] == api["www.chola.example:443"]["fix_by"]


def test_without_a_first_observation_the_as_of_day_is_the_anchor():
    got = T.proposed_dates(1, ["PROTO_TLS10"], True, dt.date(2026, 11, 24))
    assert got["fix_by"] == "2027-02-22" and got["found_basis"] == "as_of" and got["overdue"] is False
    anchored = T.proposed_dates(1, ["PROTO_TLS10"], True, dt.date(2027, 3, 1), found_on="2026-11-14")
    assert anchored["fix_by"] == "2027-02-12" and anchored["overdue"] is True and anchored["found_basis"] == "first_seen"


def test_an_assigned_date_is_overdue_until_the_item_is_done():
    late = dt.date(2027, 6, 1)

    class _A:  # a stored assignment
        wave, owner, target_date, status, note, row_version = 1, "ops", "2027-01-31", "open", None, 1
        last_updated = ticket_key = ticket_url = done_at = None

    item = {"asset_key": "k", "suggested_wave": 1, "finding_codes": ["PROTO_TLS10"], "quantum_vulnerable": True,
            "first_seen_on": "2026-11-14"}
    out = W._with_assignment([dict(item)], {"k": _A()}, {1: 90, 2: 180, 3: 365}, late)[0]
    assert out["due_date"] == "2027-01-31" and out["overdue"] is True
    _A.status = "done"
    assert W._with_assignment([dict(item)], {"k": _A()}, {1: 90, 2: 180, 3: 365}, late)[0]["overdue"] is False


# ============================================================================ B: ordered wave windows
@pytest.mark.parametrize("body", [{"wave1_fix_days": 365, "wave2_fix_days": 30},
                                  {"wave2_fix_days": 400, "wave3_fix_days": 365},
                                  {"wave1_fix_days": 200, "wave3_fix_days": 100}])
def test_an_inverted_window_body_is_rejected(body):
    with pytest.raises(ValueError, match="must not take longer"):
        RiskModel(**body)


def test_equal_and_ordered_windows_are_accepted():
    assert RiskModel(wave1_fix_days=30, wave2_fix_days=30, wave3_fix_days=365).wave2_fix_days == 30
    assert T.window_order_error({1: 90, 2: 180, 3: 365}) is None
    # after the settings merge a partial PUT is checked against the stored values and the KB defaults
    assert T.window_order_error(T.fix_windows({"wave2_fix_days": 30})) is not None  # 90 (KB) > 30
    assert T.window_order_error(T.fix_windows({"wave1_fix_days": 30, "wave2_fix_days": 60})) is None


# ============================================================================ C: a model change is not a team closure
def _with_old_model_register(tmp_path):
    """A register a previous grade model wrote: quantum-vulnerable rows graded Q0 ``mosca_missing`` (no team Mosca
    inputs) and the team's open ``inputs:mosca`` item, as dev's model left them (the reviewer's upgrade-dev seed)."""
    w = World(_sqlite(tmp_path / "upgrade.db"))
    sid = w.source("linux_servers", "edge")
    rows = [{"type": "private_key", "target": "h", "location": f"/k{i}", "name": f"k{i}", "algorithm": "RSA",
             "qv": True, "facts": {"key_alg": "RSA", "key_size": 2048}} for i in range(3)]
    w.finalise(w.run({sid: {"rows": rows}}))
    with Session(w.engine) as s:
        digest = REG.team_inputs(s, 1).digest
        s.execute(REG._RT.update().where(REG._RT.c.team_id == 1, REG._RT.c.q_reason.like("qv%")).values(
            model_version="q", q_grade="Q0", q_reason="mosca_missing", inputs_digest=digest))
        Q0.sync_mosca(s, 1, NOW)
        s.commit()
        gap = s.exec(select(CbomQ0Gap).where(CbomQ0Gap.item_key == "inputs:mosca")).one()
        assert gap.closed_at is None
    return w


def test_a_grade_model_regrade_closes_the_mosca_item_as_a_model_change(tmp_path):
    w = _with_old_model_register(tmp_path)
    at = dt.datetime(2026, 11, 25, 9)
    with Session(w.engine) as s:
        out = REG.regrade_team(s, 1, at)
        s.commit()
        assert out["model"] == 3
        gap = s.exec(select(CbomQ0Gap).where(CbomQ0Gap.item_key == "inputs:mosca")).one()
        assert gap.closed_at == at and gap.close_cause == "model_change"
        events = s.exec(select(CbomDriftEvent).where(CbomDriftEvent.kind == "q0_closed")).all()
        assert events == []  # nothing for the integrations dispatcher
        week = DR.weekly_drift(s, 1, at)[-1]
        assert week["q0_closed"] == 0
        summary = REG.summary(s, 1, at)
    week = next(x for x in summary["closures_by_week"] if x["week"] == "2026-11-23")
    assert week["total"] == 0 and week["by_cause"] == {} and week["model_changes"] == 1


def test_d12_section_e_marks_the_week_the_grade_model_changed():
    weeks = [{"week": "2026-11-23", "total": 0, "by_cause": {}, "q0_gaps_opened": 0, "q0_gaps_open_at_week_end": 2,
              "model_changes": 1}]
    from backend.utilities.pdf.cbom_deliverable_common import get_deliverable_styles

    flow = RPDF._trend({"summary": {"closures_by_week": weeks}}, get_deliverable_styles(), 720.0)
    text = " ".join(str(getattr(f, "text", "")) + str(getattr(f, "_cellvalues", "")) for f in flow)
    assert "grade model changed: 1 re-graded, not counted as closed" in text


def test_a_team_mosca_edit_still_closes_the_item_as_inputs(tmp_path):
    w = _with_old_model_register(tmp_path)
    at = dt.datetime(2026, 11, 25, 9)
    with Session(w.engine) as s:
        # the register rows are current-model rows; the team now sets its Mosca inputs
        s.execute(REG._RT.update().where(REG._RT.c.team_id == 1).values(model_version=QG.GRADE_MODEL_VERSION))
        row = get_or_create_settings(s, 1)
        row.risk_model = {"data_shelf_life_years": 3, "migration_years": 2, "threat_years": 15}
        s.add(row)
        s.commit()
        out = REG.regrade_team(s, 1, at)
        s.commit()
        assert out["model"] == 0 and out["inputs"] == 3
        gap = s.exec(select(CbomQ0Gap).where(CbomQ0Gap.item_key == "inputs:mosca")).one()
        assert gap.close_cause == "inputs"
        assert len(s.exec(select(CbomDriftEvent).where(CbomDriftEvent.kind == "q0_closed")).all()) == 1


def test_the_mosca_cause_follows_the_team_inputs():
    assert Q0.mosca_cause({"x": 3, "y": 2, "z": 15}) == "inputs"
    assert Q0.mosca_cause({"x": None, "y": 2, "z": 15}) == "model_change"
    assert Q0.mosca_cause({}) == "model_change"


# ============================================================================ D: IR 8547 name from status + date
_IR485 = {"citation": "NIST IR 8547 (final, 2026)", "deprecated_after": 2030, "disallowed_after": 2035,
          "landing": "https://csrc.nist.gov/pubs/ir/8547/final", "published": "2026-10-27",
          "source": "https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8547.pdf", "status": "final",
          "title": "Transition to Post-Quantum Cryptography Standards"}


def _with_ir(monkeypatch, entry: dict) -> None:
    ctx = dict(crypto_kb.pqc_context())
    ctx["nist_ir_8547"] = entry
    monkeypatch.setattr(crypto_kb, "pqc_context", lambda: ctx)


def test_pr_485s_final_entry_prints_its_citation(monkeypatch):
    _with_ir(monkeypatch, dict(_IR485))
    ir = T.ir8547()
    assert (ir["name"], ir["citation"], ir["status"]) == ("NIST IR 8547", "NIST IR 8547 (final, 2026)", "final")
    assert roadmap.timeline_footnote().startswith("NIST IR 8547 (final, 2026) was published in final form on 27 Oct")


@pytest.mark.parametrize("change", [{"status": "draft"}, {"status": None}])
def test_pr_485s_entry_as_a_draft_never_prints_final(monkeypatch, change):
    entry = {**_IR485, **change, "source": "https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf"}
    entry.pop("landing")
    _with_ir(monkeypatch, {k: v for k, v in entry.items() if v is not None})
    assert T.ir8547()["status"] == "draft" and T.ir8547()["citation"] == "NIST IR 8547"
    assert roadmap.timeline_footnote().startswith("NIST IR 8547 is a draft")
    rows = [r for r in roadmap.timeline_rows() if "8547" in r[3]]
    assert rows and all(r[2] == "Draft" and "final" not in f"{r[1]} {r[3]}" for r in rows)


def test_a_status_written_only_into_the_citation_never_decides(monkeypatch):
    _with_ir(monkeypatch, {"citation": "NIST IR 8547 (draft)", "source": _IR485["source"]})
    assert T.ir8547()["status"] == "final" and T.ir8547()["citation"] == "NIST IR 8547"  # the URL is final


# ============================================================================ E: DSA at any size
def test_the_d12_no_grade_note_says_dsa_is_disallowed_at_any_size():
    note = RPDF.NO_GRADE_NOTE
    assert "DSA at any size" in note and "FIPS 186-5" in note
    assert "RSA or DSA below 2048" not in note and "SHA-1 or MD5 signatures" in note


# ============================================================================ F: SP 800-131A only where disallowed
def test_the_wave_basis_never_says_sp_800_131a_disallows_every_weakness():
    for m in T.milestones():
        assert "800-131A disallows it" not in (m.get("fix_basis") or "")
        assert not (m.get("fix_basis") or "").startswith("Urgent")  # nit: no "Classical: Urgent:"
    assert T.proposed_dates(1, ["CERT_EXPIRED"], False, dt.date(2026, 11, 24))["fix_basis"] == "classical"
    assert T.proposed_dates(1, ["WEAK_KEY_SIZE"], True, dt.date(2026, 11, 24), disallowed=True)["fix_basis"] == \
        "disallowed"


def test_d13_names_which_assets_are_disallowed_and_which_are_other_weaknesses(estate):
    text = _d13(estate["engine"], EARLY)
    assert "Classical: Urgent" not in text
    assert re.search(r"1 asset: an algorithm or key size NIST disallows today", text)  # RSA-1024
    assert re.search(r"1 asset: a weakness a classical attacker can use today", text)  # TLS 1.0
    assert "SP 800-131A disallows it today" not in text


# ============================================================================ the collectors' sig_alg key
@pytest.mark.parametrize("sig", ["sha1WithRSAEncryption", "md5WithRSAEncryption"])
def test_a_certificate_signed_with_sha1_or_md5_under_sig_alg_is_q2_deprecated(tmp_path, sig):
    w = World(_sqlite(tmp_path / "sig.db"))
    with Session(w.engine) as s:
        row = get_or_create_settings(s, 1)
        row.risk_model = {"data_shelf_life_years": 3, "migration_years": 2, "threat_years": 15}
        s.add(row)
        s.commit()
    sid = w.source("linux_servers", "edge")
    facts = {"key_alg": "RSA", "key_size": 2048, "sig_alg": sig, "fingerprint_sha256": "ab" * 32, "serial": "1",
             "subject": "CN=leaf", "issuer": "CN=Some CA", "not_after": "2028-01-01T00:00:00Z"}
    good = {**facts, "sig_alg": "sha256WithRSAEncryption", "fingerprint_sha256": "cd" * 32, "subject": "CN=ok"}
    rows = [{"type": "certificate", "target": "h", "location": "/leaf", "name": "leaf", "algorithm": "RSA",
             "qv": True, "facts": facts},
            {"type": "certificate", "target": "h", "location": "/ok", "name": "ok", "algorithm": "RSA", "qv": True,
             "facts": good}]
    w.finalise(w.run({sid: {"rows": rows}}))
    with Session(w.engine) as s:
        items = {i["label"].split(" · ")[0]: i for i in REG.list_register(
            s, 1, {}, after=None, limit=100, detail=True, now=utcnow())["items"]}
    assert (items["leaf"]["q_grade"], items["leaf"]["q_reason"], items["leaf"]["sp800_131a"]) == \
        ("Q2", "deprecated", "disallowed")
    assert items["ok"]["q_grade"] == "Q3" and items["ok"]["sp800_131a"] == "acceptable"
    # the key path itself: the hash read from ``sig_alg``; the never-emitted ``signature_algorithm`` is not it
    assert QG.sp800_131a("certificate", "RSA", 2048, facts)["status"] == "disallowed"
    moved = {k: v for k, v in facts.items() if k != "sig_alg"} | {"signature_algorithm": sig}
    assert (QG.sp800_131a("certificate", "RSA", 2048, moved) or {}).get("status") != "disallowed"

