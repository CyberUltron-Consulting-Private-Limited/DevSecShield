"""SQL Server collector against a real SQL Server 2022 container (skipped unless ZS_TEST_MSSQL_PORT is set).

ZS_TEST_MSSQL_PORT (on 127.0.0.1) and ZS_TEST_MSSQL_SA_PASSWORD point at a throw-away container.  The test seeds, as
sa: the read-only login with exactly the grants shipped to customers (templates.DB_GRANTS["mssql"]), a database with
TDE (AES-128; SQL Server 2022 no longer accepts TRIPLE_DES_3KEY for TDE), symmetric keys (Triple DES, AES-256), an RSA-1024 asymmetric key, a certificate, a plain
database and a login with CHECK_POLICY off; then collects as the read-only login with the server's certificate
uploaded as the CA, and checks facts, findings, the password rules and that no secret reached the assets.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

PORT = os.environ.get("ZS_TEST_MSSQL_PORT")
SA = os.environ.get("ZS_TEST_MSSQL_SA_PASSWORD")
pytestmark = pytest.mark.skipif(not (PORT and SA), reason="ZS_TEST_MSSQL_* not set")
REPO = Path(__file__).resolve().parents[2]
READER_PW = "Wp6-Reader-9d2f-Q7x!"
SECRET_KEY_PW = "Wp6-KeyPass-55aa-Zz!"


def _sa(sql_batches):
    import pytds

    conn = pytds.connect(server="127.0.0.1", port=int(PORT), user="sa", password=SA, autocommit=True, login_timeout=20,
                         cafile=None, database="master")
    try:
        with conn.cursor() as cur:
            for sql in sql_batches:
                cur.execute(sql)
    finally:
        conn.close()


@pytest.fixture(scope="module")
def seeded():
    sys.path.insert(0, str(REPO))
    from backend.utilities.cbom_sources import templates
    from zs_scan_node import drivergate
    import pytds

    drivergate.install(pytds)
    from zs_scan_node.netutil import NeverScan

    grant = templates.DB_GRANTS["mssql"].replace("<from your vault>", READER_PW)
    statements = [line for line in grant.splitlines() if line.strip() and not line.strip().startswith("--")]
    with drivergate.scope(NeverScan(), {}):
        _sa(statements + [
            f"CREATE LOGIN weak_policy WITH PASSWORD = '{SECRET_KEY_PW}', CHECK_POLICY = OFF",
            f"CREATE MASTER KEY ENCRYPTION BY PASSWORD = '{SECRET_KEY_PW}'",
            "CREATE CERTIFICATE wp6_tde_cert WITH SUBJECT = 'wp6 TDE'",
            "CREATE DATABASE wp6app", "CREATE DATABASE wp6plain",
        ])
        _sa([
            "USE wp6app",
            "CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_128 ENCRYPTION BY SERVER CERTIFICATE wp6_tde_cert",
            "ALTER DATABASE wp6app SET ENCRYPTION ON",
        ])
        legacy = True
        try:  # SQL Server 2022 refuses new Triple DES keys at compatibility level 160; an upgraded server keeps them
            _sa(["ALTER DATABASE wp6app SET COMPATIBILITY_LEVEL = 100", "USE wp6app",
                 f"CREATE SYMMETRIC KEY wp6_3des WITH ALGORITHM = TRIPLE_DES ENCRYPTION BY PASSWORD = '{SECRET_KEY_PW}'"])
        except pytds.ProgrammingError:
            legacy = False
        _sa([
            "USE wp6app",
            f"CREATE SYMMETRIC KEY wp6_aes WITH ALGORITHM = AES_256 ENCRYPTION BY PASSWORD = '{SECRET_KEY_PW}'",
            f"CREATE ASYMMETRIC KEY wp6_rsa1024 WITH ALGORITHM = RSA_1024 ENCRYPTION BY PASSWORD = '{SECRET_KEY_PW}'",
            f"CREATE CERTIFICATE wp6_cert ENCRYPTION BY PASSWORD = '{SECRET_KEY_PW}' WITH SUBJECT = 'wp6 app cert'",
        ])
    time.sleep(2)  # the TDE encryption scan of the empty database runs in the background
    return {"legacy_3des": legacy}


def _ctx(kind="collect", secrets=()):
    from zs_scan_node.jobctx import JobContext
    from zs_scan_node.netutil import NeverScan
    from zs_scan_node.scrub import Scrubber

    return JobContext(job_id=1, attempt=1, run_id=None, kind=kind, source_kind="database",
                      scrubber=Scrubber(list(secrets)), never_scan=NeverScan(), deadline=time.monotonic() + 180)


def _server_cert_pem():
    """The certificate the server presents (read through TDS like the collector does), used as the pinned CA."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    from zs_scan_node.collectors import mssql
    from zs_scan_node.netutil import Target

    facts = mssql.probe_endpoint(_ctx(), Target("127.0.0.1", "127.0.0.1"), int(PORT))
    der = facts["_certs"][0]
    return x509.load_der_x509_certificate(der).public_bytes(Encoding.PEM).decode()


def _config(**over):
    cfg = {"engine": "mssql", "host": "127.0.0.1", "port": int(PORT), "login": "svc_zscbom", "require_tls": True,
           "credential_type": "password"}
    cfg.update(over)
    return cfg


def test_mssql_collects_with_the_shipped_grants(seeded):
    from zs_scan_node.collectors import database

    ca = _server_cert_pem()
    ctx = _ctx(secrets=[READER_PW])
    database.collect(ctx, _config(ca_pem=ca), {"password": READER_PW}, {})
    ctx.flush()
    assert [o.status for o in ctx.outcomes] == ["ok"], ctx.outcomes
    by_type: dict[str, list] = {}
    for a in ctx.collected:
        by_type.setdefault(a["type"], []).append(a)
    tls = by_type["tls_endpoint"][0]["facts"]
    assert tls["tls"] is True and tls["encryption_name"] in ("ENCRYPT_OFF", "ENCRYPT_REQ")
    assert tls["versions"]["TLSv1.2"] is True
    tde = {a["name"]: a for a in by_type["db_encryption"]}
    assert tde["wp6app"]["algorithm"] == "AES" and tde["wp6app"]["key_size"] == 128
    assert tde["wp6app"]["facts"]["tde_state"] in ("encrypting", "encrypted")
    assert tde["wp6plain"]["facts"]["encrypted"] is False
    keys = {a["name"]: a for a in by_type["managed_key"]}
    assert keys["wp6_aes"]["algorithm"] == "AES"
    if seeded["legacy_3des"]:
        assert keys["wp6_3des"]["algorithm"] == "3DES"
    assert keys["wp6_rsa1024"]["algorithm"] == "RSA" and keys["wp6_rsa1024"]["key_size"] == 1024
    assert "##MS_DatabaseMasterKey##" in keys
    certs = [a for a in by_type["certificate"] if a["name"] == "wp6_cert"]
    assert certs, [(a["name"], a["location"]) for a in ctx.collected if a["type"] in ("coverage", "certificate")]
    assert certs[0]["facts"]["subject"].endswith("wp6 app cert")
    logins = {x["name"]: x for x in by_type["db_login_policy"][0]["facts"]["logins"]}
    assert logins["weak_policy"]["policy_checked"] is False
    blob = json.dumps(ctx.collected)
    assert READER_PW not in blob and SECRET_KEY_PW not in blob and SA not in blob and "PRIVATE KEY" not in blob

    sys.path.insert(0, str(REPO))
    from backend.utilities.cbom_sources import classify

    def codes(a):
        return set(classify.classify(a["type"], a["algorithm"], a["key_size"], a["protocol"], a["facts"])["finding_codes"])

    assert not codes(keys["wp6_aes"])
    if seeded["legacy_3des"]:
        assert "KEY_WEAK_SYMMETRIC" in codes(keys["wp6_3des"])
    print("legacy Triple DES key creatable:", seeded["legacy_3des"])
    assert "RSA_LT_2048" in codes(keys["wp6_rsa1024"])
    assert "DB_TDE_OFF" in codes(tde["wp6plain"])
    assert "DB_LOGIN_NO_POLICY" in codes(by_type["db_login_policy"][0])
    policy = by_type["db_crypto_policy"][0]
    if policy["facts"]["force_encryption"] is False:
        assert "DB_TLS_OPTIONAL" in codes(policy)


def test_mssql_password_rules_and_gate(seeded):
    from zs_scan_node.collectors import database

    # no CA: transport facts only, the password is never sent
    ctx = _ctx()
    database.collect(ctx, _config(), {"password": READER_PW}, {})
    ctx.flush()
    assert [o.status for o in ctx.outcomes] == ["identity_unverified"]
    assert [a for a in ctx.collected if a["type"] == "tls_endpoint"]
    # wrong password with the pinned certificate
    ctx = _ctx()
    database.collect(ctx, _config(ca_pem=_server_cert_pem()), {"password": "Wrong-Password-1!"}, {})
    assert [o.status for o in ctx.outcomes] == ["auth_failed"]
    # a CA that did not sign the server certificate: the login is refused before the password is sent
    from test_kmip_live import _pki  # a fresh unrelated CA
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        other = Path(_pki(Path(d))["ca"]).read_text()
    ctx = _ctx()
    database.collect(ctx, _config(ca_pem=other), {"password": READER_PW}, {})
    assert [o.status for o in ctx.outcomes] == ["identity_unverified"]
    # never-scan
    ctx = _ctx()
    ctx.never_scan.update(["127.0.0.1"])
    database.collect(ctx, _config(ca_pem=_server_cert_pem()), {"password": READER_PW}, {})
    assert [o.status for o in ctx.outcomes] == ["skipped_never_scan"]
