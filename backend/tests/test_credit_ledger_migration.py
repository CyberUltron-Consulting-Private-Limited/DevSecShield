"""The credits ledger's migration r6t2ledger001 (#33; #57 architecture review 5871780828).

* The migrations have exactly one head, and this revision is on the path from ``rv6p1nodename001`` (the revision it
  was written against) to that head (not pinned to its parent: other migrations may be chained in between).
* On PostgreSQL the table has the shape #52 needs from its first line (it is append-only, so it can never be
  backfilled): int8 id, ``movement_key`` NOT NULL UNIQUE, a generic reference, integer milli-credit amounts, the
  covering ``(team_id, id) INCLUDE (delta_mc, created_at)`` index and the partial scan / reference indexes; the model
  and the migration agree (alembic autogenerate finds no difference).
* UPDATE, DELETE and TRUNCATE are refused by triggers calling the shared ``zs_append_only()`` (SQLSTATE 42501, the
  table named in the message); inserts work. A downgrade keeps every line (renamed ``creditledger_archive``, triggers
  kept, the shared function kept) and the next upgrade brings it back; an archive of the pre-review shape is refused
  with a clear message.

The PostgreSQL test needs a throwaway database: CANCEL_RACE_PG_URL=postgresql+psycopg2://postgres:pw@127.0.0.1:55432/c1
(skipped without; CI sets it, .github/workflows/ci.yml backend job). It creates and drops only the ledger's tables.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import sqlalchemy as sa  # noqa: E402
from sqlalchemy.exc import DBAPIError  # noqa: E402
from sqlmodel import create_engine  # noqa: E402

PG_URL = os.environ.get("CANCEL_RACE_PG_URL")
needs_pg = pytest.mark.skipif(not PG_URL, reason="CANCEL_RACE_PG_URL not set (throwaway PostgreSQL)")
MIGRATIONS = _REPO_ROOT / "prod_database_migrations"
MIGRATION = MIGRATIONS / "migrations/versions/r6t2ledger001_credit_ledger.py"


def _migration():
    spec = importlib.util.spec_from_file_location("r6t2ledger001", MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _scripts():
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    return ScriptDirectory.from_config(Config(str(MIGRATIONS / "alembic.ini")))


def test_the_migrations_have_exactly_one_head():
    heads = _scripts().get_heads()
    assert len(heads) == 1, f"alembic has {len(heads)} heads {heads}: re-chain the newest migration's down_revision"


def test_the_ledger_migration_is_on_the_path_to_the_head():
    scripts = _scripts()
    (head,) = scripts.get_heads()
    to_head = {rev.revision for rev in scripts.iterate_revisions(head, "base")}
    below = {rev.revision for rev in scripts.iterate_revisions("r6t2ledger001", "base")}
    assert "r6t2ledger001" in to_head, f"r6t2ledger001 is not an ancestor of the head {head}"
    assert "rv6p1nodename001" in below, "r6t2ledger001 must come after rv6p1nodename001 (the schema it was written for)"


def _run(engine, step: str) -> None:
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            getattr(_migration(), step)()


# literal statements only (semgrep avoid-sqlalchemy-text): the values go in as bind parameters
INSERT_LINE = sa.text(
    "INSERT INTO creditledger (movement_key, team_id, ref_type, ref_id, scan_id, user_id, delta_mc, balance_after_mc, "
    "reason, detail, created_at) VALUES (:key, 1, 'scan', '7', 7, 1, :delta, 93500, 'scan_reinitialize_charge', "
    "'{}', now())")
DELTAS = sa.text("SELECT delta_mc FROM creditledger ORDER BY id")
COLUMNS = sa.text("SELECT column_name, data_type, character_maximum_length, is_nullable FROM information_schema.columns "
                  "WHERE table_name = 'creditledger' ORDER BY ordinal_position")
INDEXES = sa.text("SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'creditledger' ORDER BY indexname")
TRIGGERS = sa.text("SELECT t.tgname, p.proname, c.relname FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid "
                   "JOIN pg_class c ON c.oid = t.tgrelid WHERE NOT t.tgisinternal AND c.relname LIKE 'creditledger%' "
                   "ORDER BY t.tgname")
FUNCTIONS = sa.text("SELECT proname FROM pg_proc WHERE proname IN ('zs_append_only', 'creditledger_append_only')")


def _refused(engine, statement) -> tuple[str, str]:
    with pytest.raises(DBAPIError) as caught, engine.begin() as conn:
        conn.execute(statement)
    return caught.value.orig.pgcode, str(caught.value.orig)


def _clean(engine) -> None:
    with engine.begin() as conn:
        conn.execute(sa.text("DROP TABLE IF EXISTS creditledger CASCADE"))
        conn.execute(sa.text("DROP TABLE IF EXISTS creditledger_archive CASCADE"))
        conn.execute(sa.text("DROP FUNCTION IF EXISTS zs_append_only() CASCADE"))
        conn.execute(sa.text("DROP FUNCTION IF EXISTS creditledger_append_only() CASCADE"))


@needs_pg
def test_the_ledger_has_the_shape_52_needs_and_matches_the_model():
    engine = create_engine(PG_URL)
    _clean(engine)
    try:
        _run(engine, "upgrade")
        with engine.begin() as conn:
            columns = {name: (kind, length, nullable) for name, kind, length, nullable in conn.execute(COLUMNS)}
            indexes = dict(conn.execute(INDEXES).all())
        assert columns == {
            "id": ("bigint", None, "NO"), "movement_key": ("character varying", 96, "NO"),
            "team_id": ("integer", None, "NO"), "ref_type": ("character varying", 32, "NO"),
            "ref_id": ("character varying", 64, "NO"), "scan_id": ("integer", None, "YES"),
            "user_id": ("integer", None, "YES"), "delta_mc": ("bigint", None, "NO"),
            "balance_after_mc": ("bigint", None, "YES"), "reason": ("character varying", 48, "NO"),
            "detail": ("json", None, "YES"), "created_at": ("timestamp without time zone", None, "NO")}
        assert "UNIQUE" in indexes["uq_creditledger_movement_key"] and "(movement_key)" in indexes[
            "uq_creditledger_movement_key"]
        assert indexes["ix_creditledger_team_id_id"].endswith("(team_id, id) INCLUDE (delta_mc, created_at)")
        assert indexes["ix_creditledger_scan_id"].endswith("(scan_id) WHERE (scan_id IS NOT NULL)")
        assert indexes["ix_creditledger_ref"].endswith(
            "(ref_type, ref_id) WHERE ((ref_type)::text <> 'scan'::text)")
        assert set(indexes) == {"creditledger_pkey", "uq_creditledger_movement_key", "ix_creditledger_team_id_id",
                                "ix_creditledger_scan_id", "ix_creditledger_ref"}

        from alembic.autogenerate import compare_metadata
        from alembic.migration import MigrationContext
        from sqlmodel import SQLModel

        import backend.new_models  # noqa: F401  (registers the tables)

        with engine.connect() as conn:
            diffs = compare_metadata(MigrationContext.configure(conn), SQLModel.metadata)

        assert [d for d in diffs if "creditledger" in repr(d)] == []  # e.g. ('remove_index', Index(...))
    finally:
        _clean(engine)
        engine.dispose()


@needs_pg
def test_the_ledger_is_append_only_on_postgresql_and_survives_a_downgrade():
    engine = create_engine(PG_URL)
    _clean(engine)
    try:
        _run(engine, "upgrade")
        with engine.begin() as conn:
            conn.execute(INSERT_LINE, {"key": "scan:7:reinit:a", "delta": -6500})
            conn.execute(INSERT_LINE, {"key": "scan:7:reinit:b", "delta": -2500})
            assert conn.execute(TRIGGERS).all() == [
                ("creditledger_no_truncate", "zs_append_only", "creditledger"),
                ("creditledger_no_update_delete", "zs_append_only", "creditledger")]
            assert conn.execute(FUNCTIONS).scalars().all() == ["zs_append_only"]

        for statement, op in ((sa.text("UPDATE creditledger SET delta_mc = 0 WHERE delta_mc = -6500"), "UPDATE"),
                              (sa.text("DELETE FROM creditledger"), "DELETE"), (sa.text("TRUNCATE creditledger"),
                                                                                  "TRUNCATE")):
            code, message = _refused(engine, statement)
            assert code == "42501" and f"creditledger is append-only: {op} refused" in message, message
        dup_code, _msg = _refused(engine, sa.text(
            "INSERT INTO creditledger (movement_key, team_id, ref_type, ref_id, delta_mc, reason, created_at) "
            "VALUES ('scan:7:reinit:a', 1, 'scan', '7', -1, 'scan_reinitialize_charge', now())"))
        assert dup_code == "23505"  # unique_violation: one movement, one line
        with engine.begin() as conn:
            assert conn.execute(DELTAS).scalars().all() == [-6500, -2500]

        _run(engine, "downgrade")  # renamed, never dropped, and still append-only; the shared function stays
        with engine.begin() as conn:
            assert not sa.inspect(conn).has_table("creditledger")
            assert conn.execute(sa.text("SELECT count(*) FROM creditledger_archive")).scalar() == 2
            assert [t[0] for t in conn.execute(TRIGGERS)] == ["creditledger_no_truncate",
                                                              "creditledger_no_update_delete"]
            assert conn.execute(FUNCTIONS).scalars().all() == ["zs_append_only"]
        code, message = _refused(engine, sa.text("DELETE FROM creditledger_archive"))
        assert code == "42501" and "creditledger_archive is append-only: DELETE refused" in message

        _run(engine, "upgrade")  # the lines come back, the triggers with them
        with engine.begin() as conn:
            conn.execute(INSERT_LINE, {"key": "scan:7:reinit-refund:b", "delta": 2500})
            assert conn.execute(DELTAS).scalars().all() == [-6500, -2500, 2500]
            assert not sa.inspect(conn).has_table("creditledger_archive")
        code, _message = _refused(engine, sa.text("UPDATE creditledger SET reason = 'x'"))
        assert code == "42501"
    finally:
        _clean(engine)
        engine.dispose()


@needs_pg
def test_an_archive_of_the_pre_review_shape_is_refused_with_a_clear_message():
    engine = create_engine(PG_URL)
    _clean(engine)
    try:
        with engine.begin() as conn:
            conn.execute(sa.text("CREATE TABLE creditledger_archive (id integer PRIMARY KEY, delta float)"))
        with pytest.raises(RuntimeError, match="pre-review shape"):
            _run(engine, "upgrade")
    finally:
        _clean(engine)
        engine.dispose()
