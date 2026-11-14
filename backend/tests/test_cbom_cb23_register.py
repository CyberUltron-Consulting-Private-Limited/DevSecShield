"""CB-23 PR-B: the quantum risk register (CB-19 PLAN §2.5 ``cb23register001``, §2.6, §2.10, §4 CB-23 PR-B).

* DA-8: totals are sums of distinct estate keys (a certificate four collectors see is one row; the DA-P3 ACM /
  node pair is one row);
* stored grades: an unchanged re-run grades nothing; a changed asset is re-graded alone;
* the background re-grade after an inputs change (Mosca set: ``inputs:mosca`` closes with cause ``inputs`` and a
  forwarded ``q0_closed``, DA-7) and after a grade-model change (asset Q0 closes as ``model_change``, not forwarded);
* DA-7 observation: an unknown asset read again with a known class closes its Q0 item with a ``q0_closed`` event;
* the API (list keyset + filters, summary = rows, item, CSV rows = register count, team isolation);
* migration ``cb23register001`` up / down / up, chained on the one head.

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_cb23_register.py -q
"""
from __future__ import annotations

import csv
import datetime as dt
import importlib.util
import io
import re
import sys
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_cb20_estate import ISSUER, NOT_AFTER, SERIAL, SHA1, SHA256, SUBJECT, World, _sqlite, cert  # noqa: E402
from test_cbom_sources_api import api, world as api_world  # noqa: E402,F401
from test_cbom_wp10_outputs import two_runs  # noqa: E402,F401

from backend.new_models import CbomDriftEvent, CbomEstateAsset, CbomQ0Gap, CbomRiskRegister  # noqa: E402
from backend.utilities.cbom_sources import drift as DRIFT  # noqa: E402
from backend.utilities.cbom_sources import posture as P  # noqa: E402
from backend.utilities.cbom_sources import qgrade as QG  # noqa: E402
from backend.utilities.cbom_sources import risk_register as REG  # noqa: E402
from backend.utilities.cbom_sources.settings import get_or_create_settings  # noqa: E402

world = api_world  # the API fixtures' SQLite world (two_runs needs it under this name)
_FIXTURES = (api, two_runs)
ROOT = Path(__file__).resolve().parents[2]
VERSIONS = ROOT / "prod_database_migrations" / "migrations" / "versions"
MIGRATION = VERSIONS / "cb23register001_risk_register.py"
MOSCA = {"data_shelf_life_years": 10, "migration_years": 5, "threat_years": 12}
T0 = dt.datetime(2030, 1, 1, 12, 0, 0)


@pytest.fixture()
def lab(tmp_path):
    w = World(_sqlite(tmp_path / "register.db"))
    yield w
    w.engine.dispose()


def mosca(w: World, value: dict | None) -> None:
    with Session(w.engine) as s:
        row = get_or_create_settings(s, 1)
        row.risk_model = value or {}
        s.add(row)
        s.commit()


def register(w: World, team_id: int = 1) -> dict[str, CbomRiskRegister]:
    with Session(w.engine) as s:
        return {r.item_key: r for r in s.exec(select(CbomRiskRegister).where(CbomRiskRegister.team_id == team_id))}


def gaps(w: World, prefix: str = "") -> list[CbomQ0Gap]:
    with Session(w.engine) as s:
        return [g for g in s.exec(select(CbomQ0Gap).order_by(CbomQ0Gap.id)) if g.item_key.startswith(prefix)]


def closed_events(w: World) -> list[CbomDriftEvent]:
    with Session(w.engine) as s:
        return list(s.exec(select(CbomDriftEvent).where(CbomDriftEvent.kind == "q0_closed")
                           .order_by(CbomDriftEvent.id)))


def rsa_cert(target: str, location: str, **facts) -> dict:
    return {**cert(target, location, **facts), "qv": True}


def key_row(**over) -> dict:
    return {"type": "private_key", "target": "app-01", "location": "/etc/ssl/private/web.key", "name": "web.key",
            **over}


UNKNOWN_KEY = key_row(facts={"encrypted": True, "detail": "passphrase-protected"})
RSA_KEY = key_row(algorithm="RSA", qv=True, facts={"key_alg": "RSA", "key_size": 2048})


# ----------------------------------------------------------------------------- DA-8: one row per distinct key
def test_da8_a_certificate_four_collectors_see_is_one_register_row(lab):
    mosca(lab, MOSCA)
    src = [lab.source(k, n) for k, n in (("network", "prober"), ("linux_servers", "linux"),
                                         ("windows_servers", "win"), ("aws_account", "aws"))]
    facts = {"serial": SERIAL, "not_after": NOT_AFTER, "fingerprint_sha256": SHA256, "subject": SUBJECT,
             "issuer": ISSUER, "is_ca": True}
    rows = [rsa_cert("10.0.0.5", "10.0.0.5:443#chain[0]", **facts), rsa_cert("app-01", "/etc/ssl/ca.pem", **facts),
            rsa_cert("win-01", "LocalMachine\\Root\\" + SHA1, **facts),
            rsa_cert("aws", "arn:aws:acm:eu-west-1:1:certificate/x", **facts)]
    lab.finalise(lab.run({s: {"rows": [r]} for s, r in zip(src, rows)}))
    reg = register(lab)
    assert set(reg) == set(lab.assets()) and len(reg) == 1
    (row,) = reg.values()
    assert row.sources == 4 and row.q_grade == "Q1" and row.q_reason == "qv_exceeds_anchor"  # a CA, X + Y > Z
    with Session(lab.engine) as s:
        summary = REG.summary(s, 1, T0)
    assert summary["total"] == 1 == sum(summary["q_grades"].values())


def test_da8_the_acm_and_node_pair_is_one_row(lab):
    """DA-P3: ACM says issuer "Amazon", Windows has only a thumbprint; CB-21 joins all four observations."""
    mosca(lab, MOSCA)
    src = [lab.source(k, n) for k, n in (("network", "prober"), ("linux_servers", "linux"),
                                         ("windows_servers", "win"), ("aws_account", "aws"))]
    full = {"serial": SERIAL, "not_after": NOT_AFTER, "fingerprint_sha256": SHA256, "fingerprint_sha1": SHA1,
            "subject": SUBJECT, "issuer": ISSUER}
    rows = [rsa_cert("10.0.0.5", "10.0.0.5:443#chain[0]", **full),
            rsa_cert("app-01", "/etc/ssl/pay.pem", serial=SERIAL.replace(":", "").lower(), not_after=NOT_AFTER,
                     subject=SUBJECT, issuer=ISSUER),
            rsa_cert("win-01", "LocalMachine\\My", thumbprint=SHA1.upper(), subject=SUBJECT, issuer=ISSUER,
                     not_after=NOT_AFTER),
            rsa_cert("aws", "arn:aws:acm:eu-west-1:1:certificate/x", serial=SERIAL, not_after=NOT_AFTER,
                     issuer="Amazon", subject="CN=pay.example.com")]
    lab.finalise(lab.run({s: {"rows": [r]} for s, r in zip(src, rows)}))
    reg = register(lab)
    assert len(reg) == 1 and next(iter(reg.values())).sources == 4


# ----------------------------------------------------------------------------- stored grades
def test_an_unchanged_rerun_grades_nothing_and_a_changed_asset_is_graded_alone(lab, monkeypatch):
    mosca(lab, MOSCA)
    calls: list[int] = []
    real = REG.Grader.grade
    monkeypatch.setattr(REG.Grader, "grade", lambda self, row: calls.append(row.id) or real(self, row))
    s1 = lab.source("linux_servers", "linux")
    rows = [rsa_cert("app-01", "/etc/ssl/a.pem", serial="01", subject="CN=a", issuer="CN=ca", not_after=NOT_AFTER),
            rsa_cert("app-01", "/etc/ssl/b.pem", serial="02", subject="CN=b", issuer="CN=ca", not_after=NOT_AFTER),
            RSA_KEY]
    lab.finalise(lab.run({s1: {"rows": rows}}))
    first = register(lab)
    assert len(first) == 3 and len(calls) == 3
    calls.clear()
    lab.finalise(lab.run({s1: {"rows": rows}}))  # the same estate again
    assert calls == []
    again = register(lab)
    assert {k: (r.q_grade, r.grade_digest, r.updated_at) for k, r in again.items()} == \
        {k: (r.q_grade, r.grade_digest, r.updated_at) for k, r in first.items()}
    changed = [rows[0], rows[1], key_row(algorithm="ML-KEM-768", qv=False, facts={"key_alg": "ML-KEM-768"})]
    lab.finalise(lab.run({s1: {"rows": changed}}))
    assert len(calls) == 1  # only the key whose content changed


# ----------------------------------------------------------------------------- re-grade after inputs / model change
def test_inputs_change_regrades_in_the_background_and_closes_mosca_with_a_forwarded_event(lab):
    s1 = lab.source("linux_servers", "linux")
    lab.finalise(lab.run({s1: {"rows": [RSA_KEY]}}))
    (row,) = register(lab).values()
    assert (row.q_grade, row.q_reason) == ("Q0", "mosca_missing")
    assert [(g.item_key, g.closed_at) for g in gaps(lab, "inputs:")] == [("inputs:mosca", None)]
    mosca(lab, MOSCA)  # the team's inputs change; no run
    with Session(lab.engine) as s:
        assert REG.pending(s, 1) == 1
    out = REG.regrade_due(lab.engine, T0)
    assert out["graded"] == 1
    (row,) = register(lab).values()
    assert row.q_grade in ("Q1", "Q2") and row.q_reason.startswith("qv_exceeds")
    [g] = gaps(lab, "inputs:")
    assert g.close_cause == "inputs"
    [e] = closed_events(lab)
    assert e.detail["cause"] == "inputs" and e.code == "mosca_missing"
    with Session(lab.engine) as s:
        assert REG.pending(s, 1) == 0
    assert REG.regrade_due(lab.engine, T0)["graded"] == 0  # nothing left


def test_a_grade_model_change_regrades_and_its_closures_are_not_forwarded(lab, monkeypatch):
    mosca(lab, MOSCA)
    s1 = lab.source("linux_servers", "linux")
    lab.finalise(lab.run({s1: {"rows": [UNKNOWN_KEY]}}))
    (key, row), = register(lab).items()
    assert (row.q_grade, row.q_reason) == ("Q0", "unknown_verdict")
    [g] = gaps(lab, "asset:")
    assert g.item_key == f"asset:{key}" and g.closed_at is None and g.reason == "unknown_verdict"
    # a new model identifies the key: every row re-graded in the background, the Q0 closes as model_change
    monkeypatch.setattr(QG, "GRADE_MODEL_VERSION", "qg-1+newmodel0000")
    real = P.classify_pqc
    monkeypatch.setattr(P, "classify_pqc", lambda r, codes, **kw: ("quantum-vulnerable", "test")
                        if r.asset_type == "private_key" else real(r, codes, **kw))
    assert REG.regrade_due(lab.engine, T0)["graded"] == 1
    (row,) = register(lab).values()
    assert row.model_version == "qg-1+newmodel0000" and row.q_grade in ("Q1", "Q2")
    [g] = gaps(lab, "asset:")
    assert g.close_cause == "model_change" and g.closed_grade == row.q_grade
    assert closed_events(lab) == []  # never forwarded


def test_da7_an_unknown_asset_read_again_with_a_known_class_closes_with_a_q0_closed(lab):
    mosca(lab, MOSCA)
    s1 = lab.source("linux_servers", "linux")
    lab.finalise(lab.run({s1: {"rows": [UNKNOWN_KEY]}}))
    [g] = gaps(lab, "asset:")
    assert g.closed_at is None
    lab.finalise(lab.run({s1: {"rows": [RSA_KEY]}}))
    [g] = gaps(lab, "asset:")
    (row,) = register(lab).values()
    assert g.close_cause == "observation" and g.closed_grade == row.q_grade and row.q_grade in ("Q1", "Q2")
    [e] = closed_events(lab)
    assert (e.detail["cause"], e.detail["new_grade"], e.detail["item_kind"]) == ("observation", row.q_grade, "asset")


def test_an_asset_removed_from_the_estate_leaves_the_register(lab):
    mosca(lab, MOSCA)
    s1 = lab.source("linux_servers", "linux")
    a = rsa_cert("app-01", "/etc/ssl/a.pem", serial="01", subject="CN=a", issuer="CN=ca", not_after=NOT_AFTER)
    lab.finalise(lab.run({s1: {"rows": [a, UNKNOWN_KEY]}}))
    assert len(register(lab)) == 2
    lab.finalise(lab.run({s1: {"rows": [a]}}))  # a complete collection without the key: removed
    assert {r.asset_type for r in register(lab).values()} == {"certificate"}
    [g] = gaps(lab, "asset:")
    assert g.close_cause == "observation" and g.closed_grade is None
    with Session(lab.engine) as s:
        removed = s.exec(select(CbomEstateAsset).where(CbomEstateAsset.presence == "removed")).all()
    assert len(removed) == 1


def test_the_scheduler_runs_the_regrade(lab, monkeypatch):
    from backend.workers import cbom_scheduler

    seen = []
    monkeypatch.setattr(REG, "regrade_due", lambda eng, now: seen.append(now) or {"teams": 0, "graded": 0})
    out = cbom_scheduler.tick(lab.engine, T0)
    assert seen == [T0] and out["risk_register"] == {"teams": 0, "graded": 0}


# ----------------------------------------------------------------------------- the API
def _get(api, url, who="alice", **params):
    r = api("GET", url, who, params=params)
    assert r.status_code == 200, r.text
    return r


def test_register_api_list_summary_item_and_csv(api, two_runs):
    engine = two_runs["engine"]
    assert DRIFT.record_pending_drift(engine, T0) == 2
    with Session(engine) as s:
        keys = {a.asset_key for a in s.exec(select(CbomEstateAsset).where(CbomEstateAsset.team_id == 1,
                                                                          CbomEstateAsset.presence != "removed"))}
    listed, after = [], None
    while True:
        page = _get(api, "/1/cbom/register", limit=2, **({"after": after} if after else {})).json()
        listed += page["items"]
        after = page["next_after"]
        if not after:
            break
    assert {i["item_key"] for i in listed} == keys and len(listed) == len(keys) == page["total"]
    ranks = [REG.RANK.get(i["q_grade"], 6) for i in listed]
    assert ranks == sorted(ranks)  # worst first
    summary = _get(api, "/1/cbom/register/summary").json()
    assert summary["total"] == len(keys)
    for grade, n in summary["q_grades"].items():
        assert n == sum(1 for i in listed if (i["q_grade"] or "none") == grade), grade
    assert summary["pending_regrade"] == 0 and len(summary["closures_by_week"]) == 12
    some = listed[0]
    filtered = _get(api, "/1/cbom/register", grade=some["q_grade"] or "none").json()
    assert filtered["items"] and all(i["q_grade"] == some["q_grade"] for i in filtered["items"])
    item = _get(api, f"/1/cbom/register/items/{some['item_key']}").json()
    assert item["item"] == some and item["observations"]
    assert api("GET", "/1/cbom/register/items/nope").status_code == 404
    body = _get(api, "/1/cbom/register.csv").content.decode()
    table = list(csv.reader(io.StringIO(body)))
    assert tuple(table[0]) == REG.CSV_COLUMNS and len(table) - 1 == summary["total"]
    assert api("GET", "/1/cbom/register", params={"after": "garbage"}).status_code == 400
    assert api("GET", "/1/cbom/register", params={"grade": "Q9"}).status_code in (400, 422)
    assert api("GET", "/1/cbom/register", "carol").status_code in (403, 404)
    assert _get(api, "/2/cbom/register", "carol").json()["items"] == []


def test_csv_cells_never_run_as_formulas():
    assert REG._csv_cell("=HYPERLINK(1)") == "'=HYPERLINK(1)" and REG._csv_cell("+1") == "'+1"
    assert REG._csv_cell("pay.example.com") == "pay.example.com" and REG._csv_cell(3) == 3


# ----------------------------------------------------------------------------- migration
def _migration():
    spec = importlib.util.spec_from_file_location("cb23register001", MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_migration_is_the_one_head():
    mod = _migration()
    revisions, parents = set(), set()
    for path in VERSIONS.glob("*.py"):
        text = path.read_text()
        rev = re.search(r"^revision(?::\s*str)?\s*=\s*['\"]([^'\"]+)['\"]", text, re.M)
        down = re.search(r"^down_revision[^=]*=\s*['\"]([^'\"]+)['\"]", text, re.M)
        if rev:
            revisions.add(rev.group(1))
        if down:
            parents.add(down.group(1))
    assert mod.revision == "cb23register001" and mod.down_revision in revisions
    assert len(revisions - parents) == 1 and ("cb23register001" in parents or
                                              revisions - parents == {"cb23register001"})


def test_migration_up_down_up_matches_the_model(tmp_path):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    engine = sa.create_engine(f"sqlite:///{tmp_path / 'm.db'}")

    def run(step):
        with engine.begin() as conn:
            with Operations.context(MigrationContext.configure(conn)):
                getattr(_migration(), step)()

    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE team (id integer PRIMARY KEY)"))
        conn.execute(sa.text("INSERT INTO team (id) VALUES (1)"))
    run("upgrade")
    cols = {c["name"] for c in sa.inspect(engine).get_columns("cbomriskregister")}
    assert cols == set(CbomRiskRegister.__table__.columns.keys())
    idx = {i["name"] for i in sa.inspect(engine).get_indexes("cbomriskregister")}
    assert {"ix_cbomriskregister_team_rank_key", "ix_cbomriskregister_team_reason",
            "ix_cbomriskregister_team_family_source_grade"} <= idx
    run("downgrade")
    assert "cbomriskregister" not in sa.inspect(engine).get_table_names()
    run("upgrade")
    assert "cbomriskregister" in sa.inspect(engine).get_table_names()
    engine.dispose()
