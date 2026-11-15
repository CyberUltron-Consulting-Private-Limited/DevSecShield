"""Scan node side of #210 (PostgreSQL password-hash path), #212 (KMIP without a CA) and #216 (Oracle and MongoDB
passwords only to a verified server)."""
from __future__ import annotations

import time

import pytest

from zs_scan_node.collectors import database as D
from zs_scan_node.collectors import kmip as K
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan, Target
from zs_scan_node.scrub import Scrubber


# ----------------------------------------------------------------------------- #210
class _PgError(Exception):
    def __init__(self, sqlstate: str) -> None:
        super().__init__(f"error {sqlstate}")
        self.sqlstate = sqlstate


class _FakePg:
    """Answers like PostgreSQL for one login: ``superuser``, whether the function is installed and callable."""

    def __init__(self, superuser=False, function=True, callable_=True, path_query_fails=False):
        self.superuser, self.function, self.callable, self.path_fails = superuser, function, callable_, path_query_fails
        self.sql: list[str] = []

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, args=None):
        self.sql.append(sql)
        if "to_regprocedure" in sql:
            if self.path_fails:
                raise _PgError("42883")
            self.rows = [(self.superuser, self.function, False)]
        elif "pg_authid" in sql:
            if not self.superuser:
                raise _PgError("42501")  # what the issue's audit log shows: permission denied for table pg_authid
            self.rows = [("app", "scram-sha-256"), ("legacy", "md5")]  # the CASE in _PG_AUTHID_SQL
        elif "zs_role_password_types" in sql:
            if not self.function:
                raise _PgError("42883")
            if not self.callable:
                raise _PgError("42501")
            self.rows = [("app", "scram-sha-256"), ("legacy", "md5")]
        else:
            self.rows = []

    def fetchall(self):
        return list(self.rows)


@pytest.fixture(autouse=True)
def _psycopg_errors(monkeypatch):
    import psycopg

    monkeypatch.setattr(psycopg, "Error", _PgError)


def test_a_login_with_the_published_grants_never_touches_pg_authid():
    conn = _FakePg(superuser=False, function=True)
    out = D.pg_role_hashes(conn, set(), "zs_cbom", "postgres")
    assert out.source == "zs_role_password_types" and out.types == {"app": "scram-sha-256", "legacy": "md5"}
    assert not [s for s in conn.sql if "pg_authid" in s], conn.sql


def test_a_login_without_the_function_gets_the_fix_and_still_no_pg_authid_query():
    conn = _FakePg(superuser=False, function=False)
    out = D.pg_role_hashes(conn, set(), "zs_cbom", "postgres")
    assert out.types is None and out.gap[0] == "denied" and "zs_role_password_types" in out.gap[1]
    assert not [s for s in conn.sql if "pg_authid" in s]


def test_a_function_this_login_may_not_call_names_the_grant():
    conn = _FakePg(superuser=False, function=True, callable_=False)
    out = D.pg_role_hashes(conn, set(), "zs_cbom", "postgres")
    assert out.gap[0] == "denied" and "GRANT EXECUTE ON FUNCTION public.zs_role_password_types()" in out.gap[1]
    assert not [s for s in conn.sql if "pg_authid" in s]


def test_a_superuser_without_the_function_reads_pg_authid():
    conn = _FakePg(superuser=True, function=False)
    out = D.pg_role_hashes(conn, set(), "postgres", "postgres")
    assert out.source == "pg_authid" and out.types == {"app": "scram-sha-256", "legacy": "md5"}


def test_when_the_path_cannot_be_read_pg_authid_is_still_not_probed():
    conn = _FakePg(superuser=False, function=True, path_query_fails=True)
    out = D.pg_role_hashes(conn, set(), "zs_cbom", "postgres")
    assert out.source == "zs_role_password_types" and not [s for s in conn.sql if "pg_authid" in s]


# ----------------------------------------------------------------------------- #216
def _ctx(kind="collect") -> JobContext:
    return JobContext(job_id=1, attempt=1, run_id=None, kind=kind, source_kind="database", scrubber=Scrubber(),
                      never_scan=NeverScan(), deadline=time.monotonic() + 60)


@pytest.mark.parametrize("engine", ["oracle", "mongodb"])
@pytest.mark.parametrize("tls,ca", [(False, None), (True, None)])
def test_oracle_and_mongodb_never_send_a_password_to_an_unverified_server(monkeypatch, engine, tls, ca):
    from zs_scan_node.collectors import oracle

    monkeypatch.setattr(oracle, "collect_login", lambda *a, **k: pytest.fail("Oracle login attempted"))
    monkeypatch.setattr(D, "_mongodb", lambda *a, **k: pytest.fail("MongoDB login attempted"))
    status, error, _n = D._login_and_read(_ctx(), Target("db.lab", "10.0.0.5"),
                                          {"engine": engine, "login": "zs_cbom", "ca_pem": ca}, {"password": "pw"},
                                          engine, 1521, tls, False, {}, None)
    assert status == "identity_unverified" and "the password was not sent" in error


def test_a_mongodb_without_a_password_is_still_read_without_a_ca(monkeypatch):
    monkeypatch.setattr(D, "_mongodb", lambda *a, **k: 2)
    status, _error, n = D._login_and_read(_ctx(), Target("db.lab", "10.0.0.5"), {"engine": "mongodb"}, {}, "mongodb",
                                          27017, False, False, {}, None)
    assert (status, n) == ("ok", 2)


# ----------------------------------------------------------------------------- #212
@pytest.mark.parametrize("ca,warned", [(None, True), ("-----BEGIN CERTIFICATE-----", False)])
def test_a_kmip_test_without_a_ca_carries_the_unverified_warning(monkeypatch, ca, warned):
    monkeypatch.setattr(K, "run", lambda ctx, config, secrets, test_only=False: (
        Target("kmip.lab", "10.0.0.6"), "ok", "KMIP 2.0/1.4", 2))
    ctx = _ctx("test_connection")
    K.test(ctx, {"host": "kmip.lab", "ca_pem": ca}, {}, {})
    sample = ctx.samples[0]
    assert sample["status"] == "ready" and sample["server_verified"] is (not warned)
    assert ("server not verified" in sample.get("warning", "")) is warned
    summary = K.collect(_ctx(), {"host": "kmip.lab", "ca_pem": ca}, {}, {})
    assert ("server not verified" in summary) is warned
