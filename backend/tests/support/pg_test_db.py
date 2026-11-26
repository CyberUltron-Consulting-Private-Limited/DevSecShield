"""The PostgreSQL database the tests may drop tables in (PR #499 review 6065677758 n1).

Many tests drop every table (``SQLModel.metadata.drop_all``, ``DROP TABLE``, ``DROP SCHEMA``) in the database
``CBOM_TEST_PG_URL`` names.  Pointed at a real database by mistake, that would wipe it.  So every such test reads the
URL through ``cbom_test_pg_url()`` (or ``guarded`` for another variable), never from ``os.environ`` directly
(``test_cbom_posture_review_6065677758`` checks every test file):

* a database whose name contains "test" is used as given;
* any other name is replaced by ``<name>_cbom_test`` on the same server, which the session fixture
  ``_cbom_test_databases`` (``conftest.py``) creates once before the first test (CI's ``cbom`` -> ``cbom_cbom_test``).

``guarded`` itself never connects (module-level ``PG = cbom_test_pg_url()`` constants are read at collection).
"""
from __future__ import annotations

import os

ENV = "CBOM_TEST_PG_URL"
_TO_CREATE: dict[str, str] = {}  # guarded URL -> the URL it came from (its server's configured database)
_STARTED = False  # the session fixture ran: a URL guarded later is created at once


def safe_database_name(name: str) -> str:
    """``name`` itself when it says "test", else ``<name>_cbom_test``."""
    return name if "test" in name.lower() else f"{name}_cbom_test"


def guarded(url: str | None) -> str | None:
    """``url`` with its database replaced by a test one (``safe_database_name``); None stays None."""
    if not url:
        return None
    import sqlalchemy as sa

    parsed = sa.engine.make_url(url)
    target = safe_database_name(parsed.database or "postgres")
    if target == parsed.database:
        return url
    safe = parsed.set(database=target).render_as_string(hide_password=False)
    _TO_CREATE.setdefault(safe, url)
    if _STARTED:
        ensure_databases()
    return safe


def cbom_test_pg_url() -> str | None:
    """``CBOM_TEST_PG_URL``, guarded (None when unset)."""
    return guarded(os.environ.get(ENV))


def ensure_databases() -> list[str]:
    """Create every test database ``guarded`` substituted (once; ``CREATE DATABASE`` on the original URL's server).
    Returns the database names created."""
    import sqlalchemy as sa

    global _STARTED
    _STARTED = True
    created = []
    for safe, original in list(_TO_CREATE.items()):
        target = sa.engine.make_url(safe).database
        admin = sa.create_engine(original, isolation_level="AUTOCOMMIT")
        try:
            with admin.connect() as conn:
                if not conn.execute(sa.text("SELECT 1 FROM pg_database WHERE datname = :n"), {"n": target}).scalar():
                    conn.execute(sa.text(f'CREATE DATABASE "{target}"'))
                    created.append(target)
        finally:
            admin.dispose()
        _TO_CREATE.pop(safe, None)
    return created


__all__ = ["ENV", "cbom_test_pg_url", "ensure_databases", "guarded", "safe_database_name"]
