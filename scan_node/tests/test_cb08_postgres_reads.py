"""CB-08: the Databases form's PostgreSQL "what ZeroShield reads" lines, run against the collector.

The form text is ``templates.DB_READS["postgres"]`` (backend, pure data).  ``database._postgres`` runs here against a
fake ``psycopg`` that plays a server whose state this test sets (the oracle is the fake server, never the product):
each line must be visible in what the node emits, and nothing may be read that the form does not say.  The old line
"pgcrypto use" had no such behaviour: the collector lists extensions and their versions, never where they are used.
"""
from __future__ import annotations

import importlib.util
import sys
import time
import types
from pathlib import Path

import pytest

from zs_scan_node.collectors import database as D
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan, Target
from zs_scan_node.scrub import Scrubber

_TEMPLATES = Path(__file__).resolve().parents[2] / "backend" / "utilities" / "cbom_sources" / "templates.py"


def _db_reads() -> dict[str, list[str]]:
    spec = importlib.util.spec_from_file_location("cb08_templates", _TEMPLATES)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # data only: os and re, no network
    return module.DB_READS


# The fake server's state (set here, independent of the product).
SERVER = {
    "settings": [("server_version", "16.4"), ("ssl", "on"), ("ssl_min_protocol_version", "TLSv1.2"),
                 ("ssl_ciphers", "HIGH:!aNULL"), ("password_encryption", "scram-sha-256")],
    "own": [("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256)],
    "live": [(True, "TLSv1.3", "TLS_AES_256_GCM_SHA384", 3), (False, None, None, 1)],
    "hba": [("hostssl", ["all"], ["all"], "0.0.0.0/0", "scram-sha-256"), ("host", ["all"], ["legacy"], "10.0.0.0/8", "md5")],
    "extensions": [("plpgsql", "1.0"), ("pgcrypto", "1.3")],
    "roles": [("app", "scram-sha-256"), ("legacy", "md5")],
}


class _Cursor:
    def __init__(self, log: list[str]) -> None:
        self.log, self.rows = log, []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, args=None):
        self.log.append(sql)
        if "FROM pg_settings" in sql:
            self.rows = SERVER["settings"]
        elif "pg_backend_pid()" in sql:
            self.rows = SERVER["own"]
        elif "FROM pg_stat_ssl s" in sql:
            self.rows = SERVER["live"]
        elif "pg_hba_file_rules" in sql:
            self.rows = SERVER["hba"]
        elif "FROM pg_extension" in sql:
            self.rows = SERVER["extensions"]
        elif "pg_authid" in sql:
            self.rows = SERVER["roles"]
        else:
            self.rows = []

    def fetchall(self):
        return list(self.rows)


class _Conn:
    def __init__(self, log):
        self.log = log

    def cursor(self):
        return _Cursor(self.log)

    def close(self):
        pass


@pytest.fixture()
def run(monkeypatch):
    log: list[str] = []
    fake = types.ModuleType("psycopg")

    class Error(Exception):
        sqlstate = None

    fake.Error = Error
    fake.OperationalError = type("OperationalError", (Error,), {})
    fake.connect = lambda **kw: _Conn(log)
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    ctx = JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="database", scrubber=Scrubber(),
                     never_scan=NeverScan(), deadline=time.monotonic() + 60)
    D._postgres(ctx, Target("pg.lab", "10.231.0.41"), {"engine": "postgres", "login": "zs_cbom", "port": 5432}, "pw",
                D._CaFile(None))
    ctx.flush()
    assets = {a["type"]: a for a in ctx.collected}
    return assets, log


def _check_tls_settings(assets, log):
    s = assets["database_config"]["facts"]["settings"]
    return s["ssl"] == "on" and s["ssl_min_protocol_version"] == "TLSv1.2" and s["ssl_ciphers"] == "HIGH:!aNULL"


def _check_hashing(assets, log):
    auth = assets["database_user_auth"]["facts"]
    return (auth["password_encryption"] == "scram-sha-256"
            and [r["method"] for r in auth["hba_rules"]] == ["scram-sha-256", "md5"])


def _check_role_hash_types(assets, log):
    return assets["database_user_auth"]["facts"]["role_hash_types"] == {"app": "scram-sha-256", "legacy": "md5"} \
        and not any("SELECT rolpassword" in sql for sql in log)


def _check_live_tls(assets, log):
    live = assets["database_tls"]["facts"]["live_connections"]
    return {(r["ssl"], r["version"], r["count"]) for r in live} == {(True, "TLSv1.3", 3), (False, None, 1)}


def _check_extensions(assets, log):
    exts = assets["database_config"]["facts"]["extensions"]
    usage_reads = [sql for sql in log if any(t in sql for t in ("pg_proc", "pg_depend", "prosrc", "pg_stat_statements"))]
    return {"name": "pgcrypto", "version": "1.3"} in exts and not usage_reads


CHECKS = {
    "TLS on or off, minimum TLS version and ciphers": _check_tls_settings,
    "Password hashing setting and the method of each HBA rule": _check_hashing,
    "Password hash type of each login role (md5 or SCRAM; never the hash itself)": _check_role_hash_types,
    "TLS used by live client connections": _check_live_tls,
    "Installed extensions and their versions (for example pgcrypto); not where they are used": _check_extensions,
}


def test_every_postgres_read_line_is_what_the_collector_emits(run):
    assets, log = run
    lines = _db_reads()["postgres"]
    unbacked = [line for line in lines if line not in CHECKS]
    assert not unbacked, f"the Databases form promises {unbacked} but the collector does nothing of the kind"
    failing = [line for line in lines if not CHECKS[line](assets, log)]
    assert not failing, f"the collector does not deliver {failing}"
    # and nothing the form does not mention: every statement belongs to one of the lines above
    known = ("FROM pg_settings", "pg_backend_pid()", "FROM pg_stat_ssl s", "pg_hba_file_rules", "FROM pg_extension",
             "pg_authid", "pg_roles")
    assert all(any(k in sql for k in known) for sql in log), log
