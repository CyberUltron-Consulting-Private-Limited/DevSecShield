"""Shared fixtures for the backend tests."""
import sys

import pytest


@pytest.fixture(autouse=True)
def _fresh_rate_limits():
    """Every test starts with empty rate-limit windows: the limiters are real (decorator-level, per user), and
    in-process tests that reuse one user across tests would otherwise share a budget."""
    try:
        from backend.utilities import ratelimit
    except ImportError:  # a test that runs without the backend package on the path
        yield
        return
    ratelimit.reset_all()
    yield
    ratelimit.reset_all()


def _mongo_singletons():
    """The modules that hold the process-wide Mongo client (``get_db._mongo_db``), under either import name."""
    return [m for m in (sys.modules.get("backend.get_db"), sys.modules.get("get_db")) if m is not None]


def close_mongo_clients_opened_since(before):
    """Close the process-wide Mongo client a test opened (``before``: ``{module: _mongo_db}`` at the test's start).

    ``get_mongo_client_db()`` keeps one ``MongoClient`` for the life of the process, and pymongo runs a monitor
    thread for it that connects to MONGO_HOST:MONGO_PORT every 10 s (there is no Mongo in CI, so it never stops
    trying). Left open, those connects land inside later tests' socket audits (#126: test_cbom_ai.py's Bedrock
    tests saw ``('127.0.0.1', 27017)``). A client that already existed when the test started is left alone."""
    from pymongo.database import Database

    for mod in _mongo_singletons():
        db = getattr(mod, "_mongo_db", None)
        if isinstance(db, Database) and db is not before.get(mod):
            mod._mongo_db = before.get(mod)
            db.client.close()


@pytest.fixture(autouse=True)
def _no_mongo_client_outlives_its_test():
    before = {mod: getattr(mod, "_mongo_db", None) for mod in _mongo_singletons()}
    yield
    close_mongo_clients_opened_since(before)
