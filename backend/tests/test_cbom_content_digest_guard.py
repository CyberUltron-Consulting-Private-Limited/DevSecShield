"""#352 guard: no code path or data migration changes a digested column of cbomcollectedasset and keeps a stale
``content_digest`` (``content_digest_guard``).

* static: every Python file under ``backend/`` (outside the tests) and every Alembic revision is scanned for SQL
  strings and SQLAlchemy ``update(...).values(...)`` calls on the table;
* at run time: the suite's engine listener (``conftest._content_digest_follows_its_columns``) checks every statement
  every test executes, ORM flushes included; this file shows that it catches an ORM change, a Core UPDATE and raw SQL,
  and lets through an UPDATE that recomputes the digest or sets it to NULL.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sqlalchemy as sa  # noqa: E402
from sqlmodel import Session, create_engine, select  # noqa: E402

import content_digest_guard as GUARD  # noqa: E402
from backend.new_models import CONTENT_DIGEST_COLUMNS, CbomCollectedAsset, content_digest  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SCANNED = [p for p in sorted((ROOT / "backend").rglob("*.py")) if "tests" not in p.relative_to(ROOT).parts
           and ".venv" not in p.parts] + sorted((ROOT / "prod_database_migrations/migrations/versions").glob("*.py"))


def test_no_code_or_migration_updates_a_digested_column_without_the_digest():
    assert len(SCANNED) > 100  # the tree was found
    findings = [f for path in SCANNED for f in GUARD.scan_source(path.read_text(encoding="utf-8"),
                                                                  str(path.relative_to(ROOT)))]
    assert findings == []


@pytest.mark.parametrize("source, bad", [
    ('sa.update(CbomCollectedAsset).where(CbomCollectedAsset.id == 1).values(facts={})', True),
    ('update(CbomCollectedAsset).values(impact="high", content_digest=None)', False),
    ('sa.update(CbomCollectedAsset.__table__).values({"finding_codes": []})', True),
    ('CbomCollectedAsset.__table__.update().values(q_grade="Q1")', False),  # not a digested column
    ('update(CbomCollectedAsset).values(**changes)', True),  # cannot be read
    ('update(CbomCollectedAsset).values(**changes, content_digest=None)', False),
    ('update(CbomCollectedAsset).where(x).values(source_id=None)', False),
    ('op.execute("UPDATE cbomcollectedasset SET location = lower(location) WHERE 1 = 1")', True),
    ('op.execute("UPDATE cbomcollectedasset SET location = lower(location), content_digest = NULL")', False),
    ('text(f"UPDATE cbomcollectedasset SET facts = :f WHERE team_id = {team}")', True),
    ('text("UPDATE cbomcollectedasset SET q_reason = NULL")', False),
    ('text("UPDATE cbomestateobservation SET facts = NULL")', False),  # another table
])
def test_the_scanner_finds_what_it_must(source, bad):
    assert bool(GUARD.scan_source(source)) is bad


def test_every_digested_column_counts():
    for column in CONTENT_DIGEST_COLUMNS:
        assert GUARD.check_statement(f"UPDATE cbomcollectedasset SET {column}=%(x)s WHERE id = %(id)s")
        assert GUARD.check_statement(f'UPDATE "cbomcollectedasset" SET {column} = ?, content_digest = ? WHERE id = ?') \
            is None


@pytest.fixture()
def engine(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'g.db'}")
    with eng.begin() as conn:
        conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
    CbomCollectedAsset.__table__.create(eng)
    with Session(eng) as s:
        s.add(CbomCollectedAsset(team_id=1, job_id=1, attempt=1, asset_key="k", asset_type="kms_key", cdx_type="c",
                                 location="vault:k", facts={"key_spec": "AES"}))
        s.commit()
    yield eng
    eng.dispose()


def test_the_suite_listener_stops_an_update_that_keeps_a_stale_digest(engine):
    t = CbomCollectedAsset.__table__
    with Session(engine) as s:
        row = s.exec(select(CbomCollectedAsset)).one()
        row.facts = {"key_spec": "RSA"}  # an ORM change
        s.add(row)
        with pytest.raises(AssertionError, match="content_digest"):
            s.commit()
    with engine.begin() as conn:
        with pytest.raises(AssertionError, match="content_digest"):
            conn.execute(sa.update(t).values(impact="high"))
        with pytest.raises(AssertionError, match="content_digest"):
            conn.exec_driver_sql("UPDATE cbomcollectedasset SET finding = 'x'")


def test_an_update_that_recomputes_or_clears_the_digest_passes(engine):
    t = CbomCollectedAsset.__table__
    with engine.begin() as conn:
        conn.execute(sa.update(t).values(impact="high", content_digest=None))
        conn.exec_driver_sql("UPDATE cbomcollectedasset SET finding = 'x', content_digest = NULL")
        conn.execute(sa.update(t).values(q_grade="Q1"))  # not a digested column
    with Session(engine) as s:
        row = s.exec(select(CbomCollectedAsset)).one()
        row.facts = {"key_spec": "RSA"}
        row.content_digest = content_digest({c: getattr(row, c) for c in CONTENT_DIGEST_COLUMNS})
        s.add(row)
        s.commit()
        assert row.content_digest and row.impact == "high"
