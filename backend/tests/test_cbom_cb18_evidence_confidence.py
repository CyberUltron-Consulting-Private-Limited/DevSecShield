"""CB-18 PR-1: evidence confidence E0..E3 (no longer the risk-grade symbols Q0..Q3), the E0 => Q0-gap rule with a
reason per gap, one gap count on every surface, vendor re-links that keep the answer, old stored values, and the data
migration ``cb18evconf001`` (up / down / up on a populated database: SQLite always, PostgreSQL when
``CBOM_TEST_PG_URL`` is set, as in CI).

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_cb18_evidence_confidence.py -q
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import os
import re
import sys
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as _base  # noqa: E402  (shared fixtures: SQLite world + real routers)

from backend.new_models import CbomEvidenceArea, CbomEvidenceVendor  # noqa: E402
from backend.utilities.cbom_sources import evidence as EV  # noqa: E402

world = _base.world
api = _base.api
ROOT = Path(__file__).resolve().parents[2]
VERSIONS = ROOT / "prod_database_migrations" / "migrations" / "versions"
MIGRATION = VERSIONS / "cb18evconf001_evidence_confidence_e_levels.py"
PG = os.environ.get("CBOM_TEST_PG_URL")
TODAY = dt.datetime.utcnow().date()
DOC = {"evidence_title": "Key policy", "evidence_url": "https://intranet.example/policy.pdf"}


def ev(api) -> dict:
    r = api("GET", "/1/cbom/sources/evidence")
    assert r.status_code == 200, r.text
    return r.json()


def area(body: dict, key: str) -> dict:
    return next(a for a in body["areas"] if a["area_key"] == key)


def overview(api) -> dict:
    r = api("GET", "/1/cbom/sources/overview")
    assert r.status_code == 200, r.text
    return r.json()


def patch(api, key: str, **body):
    return api("PATCH", f"/1/cbom/sources/evidence/{key}", json=body)


# ----------------------------------------------------------------------------- levels and reasons
def test_vocabulary_is_e0_to_e3():
    assert EV.CONFIDENCE == ("E0", "E1", "E2", "E3")
    assert EV.CONFIDENCE_LABEL == {"E0": "Unknown", "E1": "Self-attested", "E2": "Documented", "E3": "Verified"}
    assert [EV.level(v) for v in ("E2", "Q3", "q1", "", None, "X9", "E7")] == ["E2", "E3", "E1", "E0", "E0", "E0", "E0"]
    assert EV.effective_confidence("E3", (TODAY - dt.timedelta(days=400)).isoformat(), TODAY) == "E0"
    assert EV.effective_confidence("Q3", TODAY.isoformat(), TODAY) == "E3"
    assert EV.effective_confidence("E2", "not a date", TODAY) == "E0"  # EC-10: never a 500


def test_expired_evidence_is_e0_with_its_reason_everywhere(api):
    """DA CB-18 failing-first: evidence dated 400 days ago -> E0 with a Q0 reason; Review & Run says why (FP-5)."""
    old = (TODAY - dt.timedelta(days=400)).isoformat()
    r = patch(api, "key_hierarchy", confidence="E2", evidence_date=old, answers={"roots": "HSM"}, **DOC)
    assert r.status_code == 200, r.text
    a = r.json()["area"]
    assert (a["confidence"], a["effective_confidence"], a["confidence_label"]) == ("E2", "E0", "Unknown")
    assert a["q0_gap"]["reason"] == "evidence_expired" and old in a["q0_gap"]["detail"]
    body = ev(api)
    gap = next(g for g in body["q0_gaps"] if g["id"] == "area:key_hierarchy")
    assert (gap["kind"], gap["reason"], gap["counted"], gap["as_of"]) == ("area", "evidence_expired", True,
                                                                          TODAY.isoformat())
    rows = [s for s in overview(api)["plan"]["skipped"] if s.get("gap_id") == "area:key_hierarchy"]
    assert len(rows) == 1 and "older than 12 months" in rows[0]["reason"] and "unanswered" not in rows[0]["reason"]
    assert rows[0]["gap_reason"] == "evidence_expired" and "Q0 gap" in rows[0]["reason"]


def test_unanswered_and_rated_unknown(api):
    assert area(ev(api), "escrow_recovery")["q0_gap"]["reason"] == "no_answer"
    r = patch(api, "escrow_recovery", answers={"escrow": "nobody"}, confidence="E0")
    assert r.json()["area"]["q0_gap"]["reason"] == "rated_unknown"
    r = patch(api, "escrow_recovery", confidence="E1")
    a = r.json()["area"]
    assert (a["effective_confidence"], a["q0_gap"]) == ("E1", None)


def test_one_gap_count_on_every_surface(api):
    """OB-3: the overview (Review & Run badge, sidebar), its skipped list and the Evidence tab agree; the vendor
    area's roll-up repeats its vendors' gaps and is not counted again (FP-8)."""
    patch(api, "escrow_recovery", answers={"escrow": "none"}, confidence="E1")
    v1 = api("POST", "/1/cbom/sources/evidence/vendors", json={"name": "V never asked"}).json()["vendor"]
    v2 = api("POST", "/1/cbom/sources/evidence/vendors", json={"name": "V asked"}).json()["vendor"]
    api("POST", f"/1/cbom/sources/evidence/vendors/{v2['id']}/link")
    body = ev(api)
    counted = [g for g in body["q0_gaps"] if g["counted"]]
    # 5 E0 areas without the vendor area (its roll-up is listed, not counted) + 2 vendors
    assert body["q0_gap_count"] == len(counted) == 6
    rollup = [g for g in body["q0_gaps"] if g["kind"] == "area_rollup"]
    assert [g["area_key"] for g in rollup] == ["third_party_vendors"] and rollup[0]["reason"] == "vendors_missing"
    by_id = {g["id"]: g for g in body["q0_gaps"]}
    assert by_id[f"vendor:{v1['id']}"]["reason"] == "vendor_not_asked"
    assert by_id[f"vendor:{v2['id']}"]["reason"] == "vendor_no_response"
    ov = overview(api)
    assert ov["evidence"]["q0_gap_count"] == 6
    assert len([s for s in ov["plan"]["skipped"] if s["kind"] == "evidence"]) == 6
    assert ov["evidence"]["by_confidence"] == body["by_confidence"] == {"E0": 5, "E1": 1, "E2": 0, "E3": 0}
    assert body["answered"] == ov["evidence"]["answered"] == 1


def test_vendor_levels(api):
    vendor = api("POST", "/1/cbom/sources/evidence/vendors", json={"name": "Core banking"}).json()["vendor"]
    assert (vendor["effective_confidence"], vendor["q0_gap"]["reason"]) == ("E0", "vendor_not_asked")
    # OB-4: a level set by hand on a vendor that never answered does not count
    r = api("PATCH", f"/1/cbom/sources/evidence/vendors/{vendor['id']}", json={"confidence": "E3"})
    assert r.status_code == 200
    v = r.json()["vendor"]
    assert (v["confidence"], v["effective_confidence"], v["q0_gap"]["reason"]) == ("E3", "E0", "vendor_not_asked")
    link = api("POST", f"/1/cbom/sources/evidence/vendors/{vendor['id']}/link").json()
    token = link["path"].rsplit("/", 1)[-1]
    ans = api("POST", f"/cbom/vendor-questionnaire/{token}", None,
              json={"answers": {"tls": "TLS 1.3"}, "evidence_url": "https://vendor.example/soc2.pdf"})
    assert ans.status_code == 200 and ans.json() == {"received": True}
    v = ev(api)["vendors"][0]
    assert (v["confidence"], v["effective_confidence"], v["q0_gap"]) == ("E2", "E2", None)
    assert area(ev(api), "third_party_vendors")["effective_confidence"] == "E2"


def test_a_new_link_keeps_the_vendors_answer(api):
    """EC-5: renewing vendor evidence must not turn a vendor that answered into "did not respond"."""
    vendor = api("POST", "/1/cbom/sources/evidence/vendors", json={"name": "HSM vendor"}).json()["vendor"]
    t1 = api("POST", f"/1/cbom/sources/evidence/vendors/{vendor['id']}/link").json()["path"].rsplit("/", 1)[-1]
    api("POST", f"/cbom/vendor-questionnaire/{t1}", None,
        json={"answers": {"keys": "HSM"}, "evidence_url": "https://vendor.example/a.pdf"})
    relink = api("POST", f"/1/cbom/sources/evidence/vendors/{vendor['id']}/link")
    assert relink.status_code == 200
    v = relink.json()["vendor"]
    assert (v["status"], v["effective_confidence"], v["answers"]) == ("refresh_pending", "E2", {"keys": "HSM"})
    assert v["q0_gap"] is None and area(ev(api), "third_party_vendors")["effective_confidence"] == "E2"
    t2 = relink.json()["path"].rsplit("/", 1)[-1]
    assert api("GET", f"/cbom/vendor-questionnaire/{t1}", None).status_code == 404  # the old link is gone
    ans = api("POST", f"/cbom/vendor-questionnaire/{t2}", None, json={"answers": {"keys": "KMS now"}})
    assert ans.status_code == 200
    v = ev(api)["vendors"][0]
    assert (v["status"], v["effective_confidence"], v["answers"]) == ("answered", "E1", {"keys": "KMS now"})
    assert api("POST", f"/cbom/vendor-questionnaire/{t2}", None, json={"answers": {"keys": "x"}}).status_code == 404


def test_old_stored_q_values_read_as_e_levels(api, world):
    """Rows stored before the migration (or written by an old process mid-deploy) read at their level (ST-H)."""
    engine, _ids = world
    ev(api)  # creates the areas
    with Session(engine) as s:
        for key, value in (("hsm_firmware", "Q3"), ("escrow_recovery", "Q1")):
            row = s.exec(select(CbomEvidenceArea).where(CbomEvidenceArea.team_id == 1,
                                                        CbomEvidenceArea.area_key == key)).one()
            row.confidence, row.evidence_date, row.answers = value, TODAY.isoformat(), {"x": "y"}
            row.evidence_url = "https://intranet.example/x.pdf"
            s.add(row)
        s.commit()
    body = ev(api)
    hsm, escrow = area(body, "hsm_firmware"), area(body, "escrow_recovery")
    assert (hsm["confidence"], hsm["effective_confidence"], hsm["q0_gap"]) == ("E3", "E3", None)
    assert (escrow["confidence"], escrow["effective_confidence"]) == ("E1", "E1")
    assert body["by_confidence"] == {"E0": 4, "E1": 1, "E2": 0, "E3": 1}
    # a browser tab on the previous bundle still sends Q values: stored as E
    r = patch(api, "backup_encryption", confidence="Q2", evidence_date=TODAY.isoformat(), **DOC)
    assert r.status_code == 200 and r.json()["area"]["confidence"] == "E2"
    with Session(engine) as s:
        stored = s.exec(select(CbomEvidenceArea).where(CbomEvidenceArea.area_key == "backup_encryption")).one()
        assert stored.confidence == "E2"


def test_api_accepts_only_known_levels(api):
    assert patch(api, "hsm_firmware", confidence="X9").status_code in (400, 422)
    assert patch(api, "hsm_firmware", confidence="E4").status_code in (400, 422)
    assert patch(api, "hsm_firmware", confidence="E1").status_code == 200


def test_bad_stored_date_does_not_break_the_tab(api, world):
    engine, _ids = world
    ev(api)
    with Session(engine) as s:
        row = s.exec(select(CbomEvidenceArea).where(CbomEvidenceArea.area_key == "hsm_firmware")).one()
        row.confidence, row.evidence_date = "E3", "2025-13-45"
        s.add(row)
        s.commit()
    a = area(ev(api), "hsm_firmware")
    assert (a["effective_confidence"], a["q0_gap"]["reason"]) == ("E0", "evidence_expired")
    assert overview(api)["evidence"]["q0_gap_count"] >= 1


def test_no_backend_q_confidence_literal_left():
    """HF-10: a missed "Q0".."Q3" confidence site fails silently. The evidence code paths hold none, except the two
    places that read the old spelling (evidence.LEGACY_LEVELS, schemas._legacy_level)."""
    router = (ROOT / "backend/routers/cbom_sources.py").read_text()
    sources = {
        "serialize": (ROOT / "backend/utilities/cbom_sources/serialize.py").read_text(),
        "vendor_public": (ROOT / "backend/routers/cbom_vendor_public.py").read_text(),
        "router_evidence": router[router.index("# ============================================================================ evidence"):],
        "router_overview": router[router.index("def _overview("):router.index("def _evidence_state(")],
        "evidence": "\n".join(line for line in (ROOT / "backend/utilities/cbom_sources/evidence.py").read_text().splitlines()
                              if not line.startswith("LEGACY_LEVELS")),
        "schemas": "\n".join(line for line in (ROOT / "backend/utilities/cbom_sources/schemas.py").read_text().splitlines()
                             if '("Q0", "Q1", "Q2", "Q3")' not in line),
    }
    for name, text in sources.items():
        assert re.findall(r"[\"']Q[0-3][\"']", text) == [], name


# ----------------------------------------------------------------------------- the migration
def _migration():
    spec = importlib.util.spec_from_file_location("cb18evconf001", MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_migration_is_the_one_head():
    mod = _migration()
    assert (mod.revision, mod.down_revision) == ("cb18evconf001", "r6f14sshca002")
    revisions, parents = set(), set()
    for path in VERSIONS.glob("*.py"):
        text = path.read_text()
        rev = re.search(r"^revision(?::\s*str)?\s*=\s*['\"]([^'\"]+)['\"]", text, re.M)
        down = re.search(r"^down_revision[^=]*=\s*['\"]([^'\"]+)['\"]", text, re.M)
        if rev:
            revisions.add(rev.group(1))
        if down:
            parents.add(down.group(1))
    assert revisions - parents == {"cb18evconf001"}


def _populate(conn):
    conn.execute(sa.text("DROP TABLE IF EXISTS cbomevidencearea"))
    conn.execute(sa.text("DROP TABLE IF EXISTS cbomevidencevendor"))
    conn.execute(sa.text("CREATE TABLE cbomevidencearea (id integer PRIMARY KEY, confidence varchar(2) NOT NULL, "
                         "row_version integer NOT NULL, last_updated varchar(32))"))
    conn.execute(sa.text("CREATE TABLE cbomevidencevendor (id integer PRIMARY KEY, confidence varchar(2) NOT NULL, "
                         "row_version integer NOT NULL, last_updated varchar(32))"))
    for table in ("cbomevidencearea", "cbomevidencevendor"):
        for i, value in enumerate(("Q0", "Q1", "Q2", "Q3", "Z9", "E2"), start=1):
            conn.execute(sa.text(f"INSERT INTO {table} (id, confidence, row_version, last_updated) "
                                 "VALUES (:i, :v, 3, '2026-01-01T00:00:00Z')"), {"i": i, "v": value})


def _values(conn):
    return {t: [tuple(r) for r in conn.execute(sa.text(f"SELECT id, confidence, row_version, last_updated FROM {t} "
                                                       "ORDER BY id"))]
            for t in ("cbomevidencearea", "cbomevidencevendor")}


def _up_down_up(engine):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    def run(step):
        with engine.begin() as conn:
            with Operations.context(MigrationContext.configure(conn)):
                getattr(_migration(), step)()
            return _values(conn)

    with engine.begin() as conn:
        _populate(conn)
    try:
        up = run("upgrade")
        for rows in up.values():
            assert [r[1] for r in rows] == ["E0", "E1", "E2", "E3", "Z9", "E2"]  # an odd value is left as it is
            assert {(r[2], r[3]) for r in rows} == {(3, "2026-01-01T00:00:00Z")}  # not a user's edit (ST-F)
        assert run("upgrade") == up  # idempotent
        down = run("downgrade")
        for rows in down.values():
            assert [r[1] for r in rows] == ["Q0", "Q1", "Q2", "Q3", "Z9", "Q2"]
        assert run("upgrade") == up
    finally:
        with engine.begin() as conn:
            conn.execute(sa.text("DROP TABLE IF EXISTS cbomevidencearea"))
            conn.execute(sa.text("DROP TABLE IF EXISTS cbomevidencevendor"))
        engine.dispose()


def test_migration_up_down_up_on_sqlite(tmp_path):
    _up_down_up(sa.create_engine(f"sqlite:///{tmp_path / 'm.db'}"))


@pytest.mark.skipif(not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL")
def test_migration_up_down_up_on_postgresql():
    _up_down_up(sa.create_engine(PG))


def test_migrated_rows_read_through_the_models(world):
    """The ORM default for new rows is E0 (no server default exists on the column)."""
    engine, _ids = world
    with Session(engine) as s:
        s.add(CbomEvidenceVendor(team_id=1, name="fresh"))
        s.commit()
        assert s.exec(select(CbomEvidenceVendor).where(CbomEvidenceVendor.name == "fresh")).one().confidence == "E0"
