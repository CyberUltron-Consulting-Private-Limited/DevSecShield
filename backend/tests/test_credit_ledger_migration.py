"""The credits ledger's migration r6t2ledger001 (#33).

* The migrations have exactly one head, and this revision is chained on the head it was written against.
* On PostgreSQL the ledger is append-only in the database itself: UPDATE, DELETE and TRUNCATE are refused by a
  trigger, inserts work; a downgrade keeps every line (renamed, still append-only) and the next upgrade brings it back.

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


def test_the_migrations_have_exactly_one_head():
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    heads = ScriptDirectory.from_config(Config(str(MIGRATIONS / "alembic.ini"))).get_heads()
    assert len(heads) == 1, f"alembic has {len(heads)} heads {heads}: re-chain the newest migration's down_revision"


def test_the_ledger_migration_is_chained_on_the_scan_node_name_revision():
    mod = _migration()
    assert (mod.revision, mod.down_revision) == ("r6t2ledger001", "rv6p1nodename001")


def _run(engine, step: str) -> None:
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            getattr(_migration(), step)()


# literal statements only (semgrep avoid-sqlalchemy-text): the values go in as bind parameters
INSERT_LINE = sa.text("INSERT INTO creditledger (team_id, scan_id, user_id, delta, balance_after, reason, detail, "
                      "created_at) VALUES (1, 7, 1, :delta, 93.5, 'scan_reinitialize_charge', '{}', now())")
DELTAS = sa.text("SELECT delta FROM creditledger ORDER BY id")


def _refused(engine, statement) -> str:
    with pytest.raises(DBAPIError) as caught, engine.begin() as conn:
        conn.execute(statement)
    return str(caught.value.orig)


def _clean(engine) -> None:
    with engine.begin() as conn:
        conn.execute(sa.text("DROP TABLE IF EXISTS creditledger CASCADE"))
        conn.execute(sa.text("DROP TABLE IF EXISTS creditledger_archive CASCADE"))
        conn.execute(sa.text("DROP FUNCTION IF EXISTS creditledger_append_only() CASCADE"))


@needs_pg
def test_the_ledger_is_append_only_on_postgresql_and_survives_a_downgrade():
    engine = create_engine(PG_URL)
    _clean(engine)
    try:
        _run(engine, "upgrade")
        with engine.begin() as conn:
            conn.execute(INSERT_LINE, {"delta": -6.5})
            conn.execute(INSERT_LINE, {"delta": -2.5})

        assert "append-only" in _refused(engine, sa.text("UPDATE creditledger SET delta = 0 WHERE delta = -6.5"))
        assert "append-only" in _refused(engine, sa.text("DELETE FROM creditledger"))
        assert "append-only" in _refused(engine, sa.text("TRUNCATE creditledger"))
        with engine.begin() as conn:
            assert conn.execute(DELTAS).scalars().all() == [-6.5, -2.5]

        _run(engine, "downgrade")  # renamed, never dropped, and still append-only
        with engine.begin() as conn:
            assert not sa.inspect(conn).has_table("creditledger")
            assert conn.execute(sa.text("SELECT count(*) FROM creditledger_archive")).scalar() == 2
        assert "append-only" in _refused(engine, sa.text("DELETE FROM creditledger_archive"))

        _run(engine, "upgrade")  # the lines come back, the trigger with them
        with engine.begin() as conn:
            conn.execute(INSERT_LINE, {"delta": 6.5})
            assert conn.execute(DELTAS).scalars().all() == [-6.5, -2.5, 6.5]
            assert not sa.inspect(conn).has_table("creditledger_archive")
        assert "append-only" in _refused(engine, sa.text("UPDATE creditledger SET reason = 'x'"))
    finally:
        _clean(engine)
        engine.dispose()
