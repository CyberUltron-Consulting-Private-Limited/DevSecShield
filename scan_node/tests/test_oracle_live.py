"""Oracle collector against Oracle Database Free (gvenzl/oracle-free:slim; skipped unless ZS_TEST_ORACLE_PORT is set).

ZS_TEST_ORACLE_PORT (127.0.0.1), ZS_TEST_ORACLE_PASSWORD (SYS/SYSTEM) and ZS_TEST_ORACLE_CONTAINER (to edit
sqlnet.ora with docker exec).  The test creates the read-only login with exactly the grants shipped to customers
(templates.DB_GRANTS["oracle"]), a user with the legacy 11G verifier, collects over plain TCP (the Free image has no
TCPS listener) and then makes the server require native network encryption to prove DPY-3001 becomes a finding.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

PORT = os.environ.get("ZS_TEST_ORACLE_PORT")
PW = os.environ.get("ZS_TEST_ORACLE_PASSWORD")
CONTAINER = os.environ.get("ZS_TEST_ORACLE_CONTAINER")
live = pytest.mark.skipif(not (PORT and PW and CONTAINER), reason="ZS_TEST_ORACLE_* not set")
ORACLE11_PORT = os.environ.get("ZS_TEST_ORACLE11_PORT")  # gvenzl/oracle-xe:11-slim: older than thin mode supports
REPO = Path(__file__).resolve().parents[2]
READER_PW = "Wp6Reader_7d2fQ9x"
LEGACY_PW = "Wp6Legacy_4c1eZ2m"
SERVICE = "FREEPDB1"


def _exec(script: str) -> str:
    return subprocess.run(["docker", "exec", CONTAINER, "bash", "-c", script], capture_output=True, text=True,
                          timeout=60).stdout


def _tns_admin() -> str:
    return _exec('echo "${TNS_ADMIN:-$ORACLE_HOME/network/admin}"').strip()


def _sys(statements):
    import oracledb

    from zs_scan_node import drivergate
    from zs_scan_node.netutil import NeverScan

    with drivergate.scope(NeverScan(), {}):
        conn = oracledb.connect(user="sys", password=PW, host="127.0.0.1", port=int(PORT), service_name=SERVICE,
                                mode=oracledb.AUTH_MODE_SYSDBA)
    try:
        with conn.cursor() as cur:
            for sql in statements:
                cur.execute(sql)
    finally:
        conn.close()


@pytest.fixture(scope="module")
def seeded():
    import oracledb  # noqa: F401 - loads the thin/base implementation modules
    import oracledb.base_impl as base_impl  # (oracledb removes these names from the package namespace)
    import oracledb.thin_impl as thin_impl

    from zs_scan_node import drivergate

    drivergate.install(thin_impl)
    drivergate.install(base_impl)
    sys.path.insert(0, str(REPO))
    from backend.utilities.cbom_sources import templates

    grant = templates.DB_GRANTS["oracle"].replace("<from your vault>", READER_PW)
    statements = [line.split("--")[0].strip().rstrip(";") for line in grant.splitlines()
                  if line.strip() and not line.strip().startswith("--")]
    _sys(statements)
    admin = _tns_admin()
    # new passwords get the 11G (salted SHA-1) verifier too when the server allows 11G logons
    _exec(f'cp {admin}/sqlnet.ora {admin}/sqlnet.ora.wp6 2>/dev/null; echo "SQLNET.ALLOWED_LOGON_VERSION_SERVER=11" >> {admin}/sqlnet.ora')
    _sys([f'CREATE USER wp6_legacy IDENTIFIED BY "{LEGACY_PW}"', "GRANT CREATE SESSION TO wp6_legacy"])
    _exec(f'if [ -f {admin}/sqlnet.ora.wp6 ]; then mv {admin}/sqlnet.ora.wp6 {admin}/sqlnet.ora; else rm -f {admin}/sqlnet.ora; fi')
    return admin


def _ctx(kind="collect", secrets=()):
    from zs_scan_node.jobctx import JobContext
    from zs_scan_node.netutil import NeverScan
    from zs_scan_node.scrub import Scrubber

    return JobContext(job_id=1, attempt=1, run_id=None, kind=kind, source_kind="database",
                      scrubber=Scrubber(list(secrets)), never_scan=NeverScan(), deadline=time.monotonic() + 180)


def _config(**over):
    cfg = {"engine": "oracle", "host": "127.0.0.1", "port": int(PORT), "login": "zs_cbom", "require_tls": False,
           "credential_type": "password", "database_name": SERVICE}
    cfg.update(over)
    return cfg


def _codes(a):
    from backend.utilities.cbom_sources import classify

    return set(classify.classify(a["type"], a["algorithm"], a["key_size"], a["protocol"], a["facts"])["finding_codes"])


@live
def test_oracle_collects_with_the_shipped_grants(seeded):
    from zs_scan_node.collectors import database

    ctx = _ctx(secrets=[READER_PW])
    database.collect(ctx, _config(), {"password": READER_PW}, {})
    ctx.flush()
    assert [o.status for o in ctx.outcomes] == ["ok"], ctx.outcomes
    gaps = [a["facts"] for a in ctx.collected if a["type"] == "coverage"]
    assert not gaps, gaps  # every query the collector runs is covered by the shipped grants
    by_type: dict[str, list] = {}
    for a in ctx.collected:
        by_type.setdefault(a["type"], []).append(a)
    config = by_type["database_config"][0]["facts"]
    assert "Oracle" in str(config["version"]) and config["network_protocol"] == "tcp"
    assert "NO_TLS" in _codes(by_type["tls_endpoint"][0])
    users = {u["name"]: u for u in by_type["db_login_policy"][0]["facts"]["users"]}
    assert "11G" in users["WP6_LEGACY"]["password_versions"]
    assert "DB_LEGACY_PW_HASH" in _codes(by_type["db_login_policy"][0])
    tablespaces = {a["name"]: a for a in by_type["db_encryption"]}
    assert "USERS" in tablespaces and tablespaces["USERS"]["facts"]["encrypted"] is False
    assert "DB_TDE_OFF" in _codes(tablespaces["USERS"])
    assert by_type["key_store"][0]["facts"]["store"] == "oracle_wallet"
    blob = json.dumps(ctx.collected)
    assert READER_PW not in blob and PW not in blob and LEGACY_PW not in blob


@live
def test_oracle_required_native_encryption_is_a_finding(seeded):
    from zs_scan_node.collectors import database

    admin = seeded
    _exec(f'cp {admin}/sqlnet.ora {admin}/sqlnet.ora.wp6 2>/dev/null; echo "SQLNET.ENCRYPTION_SERVER=REQUIRED" >> {admin}/sqlnet.ora')
    try:
        ctx = _ctx()
        database.collect(ctx, _config(), {"password": READER_PW}, {})
        ctx.flush()
    finally:
        _exec(f'if [ -f {admin}/sqlnet.ora.wp6 ]; then mv {admin}/sqlnet.ora.wp6 {admin}/sqlnet.ora; else rm -f {admin}/sqlnet.ora; fi')
    assert [o.status for o in ctx.outcomes] == ["not_supported"]
    assert "native network encryption" in ctx.outcomes[0].error
    policy = [a for a in ctx.collected if a["type"] == "db_crypto_policy"]
    assert policy and "DB_LEGACY_NNE" in _codes(policy[0])


@live
def test_oracle_wrong_password_and_never_scan(seeded):
    from zs_scan_node.collectors import database

    ctx = _ctx()
    database.collect(ctx, _config(), {"password": "Wrong_password_1"}, {})
    assert [o.status for o in ctx.outcomes] == ["auth_failed"]
    ctx = _ctx()
    ctx.never_scan.update(["127.0.0.0/8"])
    database.collect(ctx, _config(), {"password": READER_PW}, {})
    assert [o.status for o in ctx.outcomes] == ["skipped_never_scan"]


@pytest.mark.skipif(not ORACLE11_PORT, reason="ZS_TEST_ORACLE11_PORT not set")
def test_oracle_11g_is_an_end_of_life_finding_not_unreachable():
    """DPY-3010: the listener answers with a TNS version older than 12.1; reported as a finding."""
    sys.path.insert(0, str(REPO))
    from zs_scan_node.collectors import database

    ctx = _ctx()
    database.collect(ctx, {"engine": "oracle", "host": "127.0.0.1", "port": int(ORACLE11_PORT), "login": "zs_cbom",
                           "require_tls": False, "credential_type": "password", "database_name": "XE"},
                     {"password": "Not_used_1"}, {})
    ctx.flush()
    assert [o.status for o in ctx.outcomes] == ["not_supported"], ctx.outcomes
    assert "older than 12.1" in ctx.outcomes[0].error
    policy = [a for a in ctx.collected if a["type"] == "db_crypto_policy"]
    assert policy and _codes(policy[0]) == {"DB_EOL_VERSION"}
    tls = [a for a in ctx.collected if a["type"] == "tls_endpoint"]
    assert tls and tls[0]["facts"]["tls"] is False
