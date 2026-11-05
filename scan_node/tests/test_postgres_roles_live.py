"""PostgreSQL role password hash types against a real server (the postgres:16 container matrix).

Skipped unless ZS_TEST_PG_HOST / ZS_TEST_PG_PORT / ZS_TEST_PG_SUPERPASS point at a disposable PostgreSQL whose
superuser is ``postgres``.  The test creates its own roles and function and drops them again.  Driver:
scan_node/tests/pg_matrix.sh (starts postgres:16 in Docker, runs this file, removes the container).
"""
import os
import time

import pytest

from zs_scan_node.collectors import database as D
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

HOST = os.environ.get("ZS_TEST_PG_HOST")
PORT = int(os.environ.get("ZS_TEST_PG_PORT") or 5432)
SUPERPASS = os.environ.get("ZS_TEST_PG_SUPERPASS", "")
pytestmark = pytest.mark.skipif(not HOST, reason="needs a disposable PostgreSQL (scan_node/tests/pg_matrix.sh)")
READER_PW = "Reader-Pa55-wp5-test"
CHECK = "postgres role password hash types"


def _template_function_sql() -> str:
    """The function block of the shipped grant template (backend/utilities/cbom_sources/templates.py)."""
    from pathlib import Path
    import ast

    src = (Path(__file__).resolve().parents[2] / "backend/utilities/cbom_sources/templates.py").read_text()
    tree = ast.parse(src)
    grants = next(n.value for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "DB_GRANTS")
    text = ast.literal_eval(grants)["postgres"]
    start = text.index("CREATE OR REPLACE FUNCTION")
    end = text.index("GRANT EXECUTE ON FUNCTION public.zs_role_password_types()")
    return text[start:end]  # CREATE ... ; REVOKE ... FROM PUBLIC;


def _admin():
    import psycopg

    return psycopg.connect(host=HOST, port=PORT, user="postgres", password=SUPERPASS, dbname="postgres",
                           autocommit=True, connect_timeout=10)


# the reader holds grants on pg_hba_file_rules: drop them before the role (and on a re-run against the same server)
_DROP_GRANTS = ("DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zs_cbom') THEN "
                "EXECUTE 'DROP OWNED BY zs_cbom'; END IF; END $$")


@pytest.fixture(scope="module")
def roles():
    with _admin() as c:
        for stmt in (
            "DROP FUNCTION IF EXISTS public.zs_role_password_types()", _DROP_GRANTS,
            "DROP ROLE IF EXISTS zs_cbom", "DROP ROLE IF EXISTS app_md5", "DROP ROLE IF EXISTS app_scram",
            "DROP ROLE IF EXISTS app_nopw", "DROP ROLE IF EXISTS app_plain", "DROP ROLE IF EXISTS rdsadmin",
            f"CREATE ROLE zs_cbom LOGIN PASSWORD '{READER_PW}'",  # SCRAM (the server default)
            "GRANT pg_monitor, pg_read_all_settings TO zs_cbom",
            "GRANT SELECT ON pg_hba_file_rules TO zs_cbom",
            "GRANT EXECUTE ON FUNCTION pg_hba_file_rules() TO zs_cbom",
            "SET password_encryption = 'md5'",
            "CREATE ROLE app_md5 LOGIN PASSWORD 'md5-role-pw'",
            "SET password_encryption = 'scram-sha-256'",
            "CREATE ROLE app_scram LOGIN PASSWORD 'scram-role-pw'",
            "CREATE ROLE app_nopw LOGIN",
            "CREATE ROLE app_plain LOGIN PASSWORD 'x'",
            # PostgreSQL 10+ cannot store an unhashed password; an upgraded catalog can still hold one
            "UPDATE pg_authid SET rolpassword = 'plaintext-legacy' WHERE rolname = 'app_plain'",
        ):
            c.execute(stmt)
    yield
    with _admin() as c:
        for stmt in ("DROP FUNCTION IF EXISTS public.zs_role_password_types()", _DROP_GRANTS, "DROP ROLE IF EXISTS zs_cbom",
                     "DROP ROLE IF EXISTS app_md5", "DROP ROLE IF EXISTS app_scram", "DROP ROLE IF EXISTS app_nopw",
                     "DROP ROLE IF EXISTS app_plain", "DROP ROLE IF EXISTS rdsadmin"):
            c.execute(stmt)


def _run(login, password):
    ctx = JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="database", scrubber=Scrubber(),
                     never_scan=NeverScan(), deadline=time.monotonic() + 120)
    D.collect(ctx, {"engine": "postgres", "host": HOST, "port": PORT, "login": login, "require_tls": False,
                    "database_name": "postgres"}, {"password": password}, {})
    ctx.flush()  # CLI mode (no poster): flushed assets land in ctx.collected
    assert ctx.outcomes[-1].status == "ok", ctx.outcomes[-1]
    auth = next(a for a in ctx.collected if a["type"] == "database_user_auth")["facts"]
    gaps = [a["facts"] for a in ctx.collected if a["type"] == "coverage" and a["facts"]["check"] == CHECK]
    others = [a["facts"] for a in ctx.collected if a["type"] == "coverage" and a["facts"]["check"] != CHECK]
    return auth, gaps, others


EXPECTED = {"app_md5": "md5", "app_scram": "scram-sha-256", "app_nopw": "none", "app_plain": "other"}


def _check_types(auth):
    got = {k: v for k, v in auth["role_hash_types"].items() if k in EXPECTED}
    assert got == EXPECTED
    assert auth["role_hash_types"]["zs_cbom"] == "scram-sha-256"
    assert all(v in ("md5", "scram-sha-256", "none", "other") for v in auth["role_hash_types"].values())


def test_superuser_reads_pg_authid(roles):
    auth, gaps, _ = _run("postgres", SUPERPASS)
    assert auth["role_hash_source"] == "pg_authid" and gaps == []
    _check_types(auth)


def test_least_privilege_reader_without_the_function_gets_one_gap_naming_the_fix(roles):
    auth, gaps, others = _run("zs_cbom", READER_PW)
    assert auth["role_hash_types"] is None and auth["role_hash_source"] is None
    assert len(gaps) == 1 and gaps[0]["status"] == "denied"
    assert "public.zs_role_password_types() section of zs-cbom-grant-postgres.sql" in gaps[0]["detail"]
    assert others == []  # the template's grants cover everything else; no stray "denied" rows


def test_reader_with_the_function_but_no_grant_is_told_the_grant(roles):
    with _admin() as c:
        c.execute(_template_function_sql())  # CREATE ... SECURITY DEFINER ...; REVOKE EXECUTE ... FROM PUBLIC;
    auth, gaps, _ = _run("zs_cbom", READER_PW)
    assert auth["role_hash_types"] is None and len(gaps) == 1
    assert gaps[0]["detail"].endswith('fix: GRANT EXECUTE ON FUNCTION public.zs_role_password_types() TO "zs_cbom";  '
                                      '(as a superuser, in database "postgres")')


def test_reader_with_the_granted_function_gets_types_and_no_gap(roles):
    with _admin() as c:
        c.execute(_template_function_sql())
        c.execute("GRANT EXECUTE ON FUNCTION public.zs_role_password_types() TO zs_cbom")
    auth, gaps, others = _run("zs_cbom", READER_PW)
    assert auth["role_hash_source"] == "zs_role_password_types" and gaps == [] and others == []
    _check_types(auth)
    # the function hands out types only: no hash can come back through it
    import psycopg

    with psycopg.connect(host=HOST, port=PORT, user="zs_cbom", password=READER_PW, dbname="postgres", autocommit=True) as c:
        rows = c.execute("SELECT * FROM public.zs_role_password_types()").fetchall()
        assert rows and all(len(r) == 2 and r[1] in ("md5", "scram-sha-256", "none", "other") for r in rows)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):  # SQLSTATE 42501, the code the collector checks
            c.execute("SELECT rolpassword FROM pg_authid")


def test_a_server_that_looks_like_rds_is_told_about_rds_tools(roles):
    with _admin() as c:
        c.execute("DROP FUNCTION IF EXISTS public.zs_role_password_types()")
        c.execute("CREATE ROLE rdsadmin NOLOGIN")
    try:
        auth, gaps, _ = _run("zs_cbom", READER_PW)
        assert auth["server_type"] == "rds" and len(gaps) == 1
        assert "CREATE EXTENSION IF NOT EXISTS rds_tools;" in gaps[0]["detail"]
        # RDS: the extension's function is executable only by rds_superuser until granted (AWS lab, round 5)
        assert 'GRANT EXECUTE ON FUNCTION rds_tools.role_password_encryption_type() TO "zs_cbom";' in gaps[0]["detail"]
    finally:
        with _admin() as c:
            c.execute("DROP ROLE IF EXISTS rdsadmin")


def test_rds_hba_denial_points_at_the_parameter_group(roles):
    """RDS: the master user cannot grant pg_hba_file_rules (AWS lab, round 5), so the row names where the policy is."""
    with _admin() as c:
        c.execute("REVOKE SELECT ON pg_hba_file_rules FROM zs_cbom")
        c.execute("REVOKE EXECUTE ON FUNCTION pg_hba_file_rules() FROM zs_cbom")
    try:
        _, _, others = _run("zs_cbom", READER_PW)  # self-managed: the server's own message
        hba = [g for g in others if g["check"] == "postgres HBA rules"]
        assert len(hba) == 1 and hba[0]["status"] == "denied" and "parameter group" not in hba[0]["detail"]
        with _admin() as c:
            c.execute("CREATE ROLE rdsadmin NOLOGIN")
        _, _, others = _run("zs_cbom", READER_PW)
        hba = [g for g in others if g["check"] == "postgres HBA rules"]
        assert len(hba) == 1 and hba[0]["status"] == "denied"
        assert "rds.accepted_password_auth_method" in hba[0]["detail"] and "cannot grant" in hba[0]["detail"]
    finally:
        with _admin() as c:
            c.execute("DROP ROLE IF EXISTS rdsadmin")
            c.execute("GRANT SELECT ON pg_hba_file_rules TO zs_cbom")
            c.execute("GRANT EXECUTE ON FUNCTION pg_hba_file_rules() TO zs_cbom")
