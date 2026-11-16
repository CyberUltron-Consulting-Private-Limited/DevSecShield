"""#126: a Mongo client opened by one test must not keep connecting during the tests after it.

``get_mongo_client_db()`` keeps one process-wide ``MongoClient`` whose pymongo monitor thread connects to
MONGO_HOST:MONGO_PORT every 10 s. When a test opened it (via ``POST /admin/create_admin_user``), the thread kept
connecting to 127.0.0.1:27017 for the rest of the CI run and landed in the socket audits of test_cbom_ai.py's
Bedrock tests, failing a different one each time. ``conftest.close_mongo_clients_opened_since`` closes such a
client when its test ends.
"""
from __future__ import annotations

import socket
import threading
import time

import conftest
import backend.get_db as get_db_module


def _wait(predicate, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


def test_a_mongo_client_a_test_opens_stops_connecting_when_the_test_ends(monkeypatch):
    monkeypatch.setattr(get_db_module, "MONGO_HOST", "127.0.0.1")
    monkeypatch.setattr(get_db_module, "MONGO_PORT", "27017")
    before = {get_db_module: get_db_module._mongo_db}
    assert get_db_module._mongo_db is None, "another test left the process-wide Mongo client open"
    connects = []
    real_connect = socket.socket.connect

    def watch(self, addr, *a):
        if isinstance(addr, tuple) and addr[1:2] == (27017,):
            connects.append((threading.current_thread().name, time.monotonic()))
        return real_connect(self, addr, *a)

    monkeypatch.setattr(socket.socket, "connect", watch)
    threads_before = set(threading.enumerate())
    db = get_db_module.get_mongo_client_db()  # constructing the client needs no server
    assert _wait(lambda: connects), "pymongo's monitor connects right away (this is what leaked into later tests)"
    monitors = set(threading.enumerate()) - threads_before
    assert monitors, "the client runs background threads"

    conftest.close_mongo_clients_opened_since(before)

    assert get_db_module._mongo_db is None  # the next caller gets a fresh client, not a closed one
    assert _wait(lambda: not any(t.is_alive() for t in monitors)), "the client's threads end with it"
    closed_at = time.monotonic()
    time.sleep(0.5)
    assert [c for c in connects if c[1] > closed_at] == []
    assert db.client is not None


def test_a_client_that_was_open_before_the_test_is_left_alone(monkeypatch):
    """Only the client the test itself opened is closed: one that existed at the test's start is not touched."""
    from pymongo.database import Database

    class Client:
        closed = False

        def close(self):
            self.closed = True

    existing = object.__new__(Database)  # a Database instance without a connection
    client = Client()
    monkeypatch.setattr(Database, "client", property(lambda self: client))
    monkeypatch.setattr(get_db_module, "_mongo_db", existing)
    conftest.close_mongo_clients_opened_since({get_db_module: existing})
    assert get_db_module._mongo_db is existing and client.closed is False
