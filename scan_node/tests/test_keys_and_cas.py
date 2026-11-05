"""WP6 collectors with recorded responses and local fakes: SQL Server, Oracle, PKCS#11, KMIP (TTLV), Vault parsing,
EJBCA over mutual TLS, AD CS PowerShell output, and the driver network gate.  The live proofs against real servers are
in test_mssql_live.py, test_oracle_live.py, test_hsm_softhsm_live.py, test_kmip_live.py and test_ca_vault_live.py.
"""
from __future__ import annotations

import datetime as dt
import json
import socket
import ssl
import struct
import threading
import time
from pathlib import Path

import pytest

from zs_scan_node import drivergate, kmip_ttlv as K, netutil
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import Blocked, NeverScan, Target
from zs_scan_node.scrub import Scrubber


def _ctx(kind="collect", secrets=()):
    return JobContext(job_id=1, attempt=1, run_id=None, kind=kind, source_kind="database", scrubber=Scrubber(list(secrets)),
                      never_scan=NeverScan(), deadline=time.monotonic() + 60)


# ----------------------------------------------------------------------------- the driver gate
def test_driver_gate_pins_checks_and_refuses_outside_a_job():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]
    with pytest.raises(drivergate.OutsideScope):
        drivergate.create_connection(("db.corp", port))
    with drivergate.scope(NeverScan(), {"db.corp": "127.0.0.1"}) as state:
        drivergate.create_connection(("DB.corp.", port), 2).close()
        assert state.connected == [("127.0.0.1", port)]
        info = drivergate.getaddrinfo("db.corp", port)
        assert info[0][4] == ("127.0.0.1", port)
    never = NeverScan(["127.0.0.1"])
    with drivergate.scope(never, {"db.corp": "127.0.0.1"}):
        with pytest.raises(Blocked):
            drivergate.create_connection(("db.corp", port), 2)
    srv.close()


def test_new_collectors_pass_the_ast_gate_with_driver_connectors(monkeypatch):
    import test_network_gate as gate

    monkeypatch.setattr(gate, "CONNECTORS", gate.CONNECTORS | {"pytds.connect", "oracledb.connect", "W._session",
                                                               "http_client"})
    sources = {p.name: p.read_text(encoding="utf-8") for p in sorted(gate.COLLECTORS.glob("*.py"))}
    assert {"mssql.py", "oracle.py", "kmip.py", "hsm_pkcs11.py", "ca.py"} <= set(sources)
    problems = [p for p in gate.check_sources(sources) if p.split(":")[0] in
                ("mssql.py", "oracle.py", "kmip.py", "hsm_pkcs11.py", "ca.py")]
    assert problems == []


# ----------------------------------------------------------------------------- SQL Server
def _tds_server(encryption: int):
    """Answers each PRELOGIN with the given ENCRYPTION value, then closes (no TLS)."""
    from zs_scan_node.collectors import mssql

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                try:
                    head = conn.recv(8)
                    length = struct.unpack("!H", head[2:4])[0]
                    conn.recv(length - 8)
                    body = mssql.prelogin_payload(encryption)
                    conn.sendall(struct.pack("!BBHHBB", 0x04, 0x01, 8 + len(body), 0, 1, 0) + body)
                    conn.recv(4096)
                except OSError:
                    pass

    threading.Thread(target=serve, daemon=True).start()
    return srv, stop


@pytest.mark.parametrize("encryption, tls, forced", [(0, True, False), (3, True, True), (2, False, False)])
def test_mssql_prelogin_policy_and_no_password_without_a_ca(encryption, tls, forced):
    from zs_scan_node.collectors import mssql

    srv, stop = _tds_server(encryption)
    port = srv.getsockname()[1]
    ctx = _ctx()
    asked = []
    try:
        status, error, n = mssql.collect_target(ctx, Target("sql.corp", "127.0.0.1"), port,
                                                {"engine": "mssql", "require_tls": True, "login": "svc_zscbom"},
                                                lambda: asked.append(1) or "pw", "sql.corp")
    finally:
        stop.set()
        srv.close()
    ctx.flush()
    tls_row = [a for a in ctx.collected if a["type"] == "tls_endpoint"][0]["facts"]
    assert tls_row["tls"] is tls and tls_row["force_encryption"] is forced
    assert status == ("identity_unverified" if tls else "tls_unavailable")
    assert asked == []  # the password was never read, so it could not be sent
    policy = [a for a in ctx.collected if a["type"] == "db_crypto_policy"][0]["facts"]
    assert policy["force_encryption"] is forced


def test_mssql_prelogin_parsing():
    from zs_scan_node.collectors import mssql
    from zs_scan_node import tlsprobe as T

    facts = mssql.parse_prelogin(mssql.prelogin_payload(3))
    assert facts["encryption_name"] == "ENCRYPT_REQ" and facts["server_version"] == "15.0.2000"
    with pytest.raises(T.ProbeError):
        mssql.parse_prelogin(b"\xff")


class _Cursor:
    def __init__(self, answers, sql_log):
        self.answers, self.sql_log, self.description = answers, sql_log, None
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, args=None):
        self.sql_log.append(sql)
        for needle, rows in self.answers:
            if needle in sql:
                if isinstance(rows, Exception):
                    raise rows
                cols, data = rows if isinstance(rows, tuple) else (None, rows)
                self.rows = list(data)
                self.description = [(c,) for c in cols] if cols else [("c",)]
                return
        self.rows = []

    def fetchall(self):
        return self.rows

    def fetchmany(self, n):
        return self.rows[:n]


class _Conn:
    def __init__(self, answers):
        self.answers, self.sql = answers, []

    def cursor(self):
        return _Cursor(self.answers, self.sql)

    def close(self):
        pass


def test_mssql_reads_recorded_catalog_rows():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from zs_scan_node.collectors import mssql

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "app signing")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=30)).sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    conn = _Conn([
        ("SERVERPROPERTY", [("16.0.4305.5", "Developer Edition (64-bit)", "RTM")]),
        ("WHERE session_id = @@SPID", [("TRUE", "SQL", "TSQL", "TCP")]),
        ("GROUP BY encrypt_option", [("TRUE", "SQL", 3), ("FALSE", "NTLM", 2)]),
        ("sys.dm_server_registry", [("0",)]),
        ("FROM sys.databases", [("master", 1, False, "ONLINE", 1), ("app", 5, True, "ONLINE", 1),
                                ("hr", 6, False, "ONLINE", 0), ("plain", 7, False, "ONLINE", 1)]),
        ("sys.dm_database_encryption_keys", [("app", 3, "AES", 256, "CERTIFICATE")]),
        ("sys.sql_logins", [("sa", False, True, True, 2), ("legacy_app", False, False, False, 1)]),
        ("[app].sys.symmetric_keys", [("##MS_DatabaseMasterKey##", "TRIPLE_DES", 128, None, None),
                                      ("k_aes", "AES_256", 256, None, None)]),
        ("[app].sys.asymmetric_keys", [("k_rsa", "RSA_1024", 1024, "PASSWORD")]),
        ("[app].sys.certificates", [("c_app", "ENCRYPTED_BY_MASTER_KEY", None, "app signing", "app signing", None, der)]),
        ("[app].sys.column_encryption_keys", [("CEK1", "CMK1", "RSA_OAEP")]),  # (joins column_master_keys: first)
        ("[app].sys.column_master_keys", [("CMK1", "AZURE_KEY_VAULT", "https://kv.vault.azure.net/keys/cmk1", False)]),
    ])
    ctx = _ctx()
    n = mssql._read(ctx, mssql._Db(conn, ctx, "sql.corp"), Target("sql.corp", "10.0.0.5"), "sql.corp:1433")
    ctx.flush()
    assert n == len([a for a in ctx.collected if a["type"] != "coverage"])
    assert not any("password_hash" in s and "SUBSTRING(password_hash, 1, 1)" not in s for s in conn.sql)
    keys = {a["name"]: a for a in ctx.collected if a["type"] == "managed_key"}
    assert keys["##MS_DatabaseMasterKey##"]["algorithm"] == "3DES"
    assert keys["##MS_DatabaseMasterKey##"]["facts"]["role"] == "database master key"
    assert keys["k_rsa"]["key_size"] == 1024 and keys["CMK1"]["facts"]["key_store_provider"] == "AZURE_KEY_VAULT"
    tde = {a["name"]: a["facts"] for a in ctx.collected if a["type"] == "db_encryption"}
    assert tde["app"]["encrypted"] is True and tde["plain"]["encrypted"] is False and "master" not in tde
    certs = [a for a in ctx.collected if a["type"] == "certificate"]
    assert certs[0]["facts"]["sig_alg"].lower().startswith("sha256") and certs[0]["facts"]["database"] == "app"
    gaps = [a["facts"]["detail"] for a in ctx.collected if a["type"] == "coverage"]
    assert any("hr" in g and "CONNECT ANY DATABASE" in g for g in gaps)
    logins = [a for a in ctx.collected if a["type"] == "db_login_policy"][0]["facts"]["logins"]
    assert {x["name"]: x["hash_version"] for x in logins} == {"sa": 2, "legacy_app": 1}
    tls = [a for a in ctx.collected if a["type"] == "database_tls"][0]["facts"]
    assert tls["unencrypted_live_connections"] == 2


# ----------------------------------------------------------------------------- Oracle
class _OraErr:
    def __init__(self, code, message):
        self.full_code, self.message = code, message


def _ora_exc(code, message, inner=None):
    import oracledb

    exc = oracledb.OperationalError(_OraErr(code, f"{code}: {message}" + (f"\n{inner}" if inner else "")))
    return exc


def test_oracle_thin_errors_become_findings_not_unreachable():
    from zs_scan_node.collectors import oracle

    code, msg = oracle.thin_error(_ora_exc("DPY-6005", "cannot connect to database (CONNECTION_ID=x).",
                                           "DPY-3010: connections to this database server version are not supported "
                                           "by python-oracledb in thin mode"))
    assert code == "DPY-3010"
    cases = {
        "DPY-3001": ("Native Network Encryption and Data Integrity is only supported in python-oracledb thick mode",
                     "not_supported", "DB_LEGACY_NNE"),
        "DPY-3015": ("password verifier type 0x939 is not supported by python-oracledb in thin mode", "not_supported",
                     "DB_10G_VERIFIER"),
        "DPY-3010": ("connections to this database server version are not supported by python-oracledb in thin mode",
                     "not_supported", "DB_EOL_VERSION"),
        "ORA-01017": ("invalid credential or not authorized; logon denied", "auth_failed", None),
    }
    for code, (text, status, finding) in cases.items():
        ctx = _ctx()
        fail = oracle._classify(ctx, Target("ora.corp", "10.0.0.9"), 1521, {"login": "zs_cbom"}, code, f"{code}: {text}")
        ctx.flush()
        assert fail.status == status, code
        assert bool(ctx.collected) == bool(finding), code
    # a different thick-only feature is not mistaken for native network encryption
    ctx = _ctx()
    fail = oracle._classify(ctx, Target("ora.corp", "10.0.0.9"), 1521, {}, "DPY-3001",
                            "DPY-3001: bequeath is only supported in python-oracledb thick mode")
    assert fail.status == "error" and not ctx.collected


def test_oracle_reads_recorded_views():
    from zs_scan_node.collectors import oracle

    conn = _Conn([
        ("FROM v$version", [("Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production",)]),
        ("NETWORK_PROTOCOL", [("tcp",)]),
        ("WHERE sid = SYS_CONTEXT", [("TCP/IP NT Protocol Adapter for Linux: Version 19.0.0.0.0 - Production",),
                                     ("Encryption service for Linux: Version 19.0.0.0.0 - Production",)]),
        ("GROUP BY network_service_banner", [("AES256 Encryption service adapter for Linux: Version 19.0.0.0.0", 4),
                                             ("3DES168 Encryption service adapter for Linux: Version 19.0.0.0.0", 1),
                                             ("SHA256 Crypto-checksumming service adapter for Linux", 5)]),
        ("v$encryption_wallet", (["WRL_TYPE", "WRL_PARAMETER", "STATUS", "WALLET_TYPE", "CON_ID"],
                                 [("FILE", "/u01/wallet/", "OPEN", "AUTOLOGIN", 0)])),
        ("v$encrypted_tablespaces", [("FIN_DATA", "AES256", "YES"), ("OLD_DATA", "3DES168", "YES")]),
        ("dba_tablespaces", [("SYSTEM", "NO", "PERMANENT"), ("USERS", "NO", "PERMANENT"), ("FIN_DATA", "YES", "PERMANENT"),
                             ("OLD_DATA", "YES", "PERMANENT"), ("TEMP", "NO", "TEMPORARY")]),
        ("dba_encrypted_columns", [("HR", "EMP", "SSN", "AES 192 bits key", "YES", "SHA-1")]),
        ("dba_users", [("APP", "10G 11G 12C", "OPEN", "PASSWORD"), ("BATCH", "11G 12C", "OPEN", "PASSWORD"),
                       ("NEWAPP", "12C", "OPEN", "PASSWORD")]),
        ("v$parameter", [("encrypt_new_tablespaces", "CLOUD_ONLY")]),
    ])
    ctx = _ctx()
    oracle.read(ctx, conn, Target("ora.corp", "10.0.0.9"), "ora.corp:1521")
    ctx.flush()
    assert not any("PASSWORD " in s.upper().replace("PASSWORD_VERSIONS", "") and "dba_users" in s for s in conn.sql)
    rows = {(a["type"], a["name"]): a for a in ctx.collected}
    wallet = rows[("key_store", "Oracle TDE keystore FILE")]["facts"]
    assert wallet["wallet_type"] == "AUTOLOGIN" and "wrl_parameter" not in wallet
    assert rows[("db_encryption", "USERS")]["facts"]["encrypted"] is False
    assert rows[("db_encryption", "OLD_DATA")]["algorithm"] == "3DES168"
    assert ("db_encryption", "SYSTEM") not in rows and ("db_encryption", "TEMP") not in rows
    policy = rows[("db_crypto_policy", "Oracle network encryption")]["facts"]
    assert policy["sessions_nne_algorithms"] == ["3DES168", "AES256"] and policy["sessions_checksum_algorithms"] == ["SHA256"]
    users = {u["name"]: u for u in rows[("db_login_policy", "Oracle password verifiers")]["facts"]["users"]}
    assert users["APP"]["password_versions"] == "10G 11G 12C"


def test_oracle_queries_never_select_password_or_wallet_secrets():
    from zs_scan_node.collectors import oracle

    for name in dir(oracle):
        if name.startswith("Q_"):
            sql = getattr(oracle, name).upper()
            assert " PASSWORD," not in sql and "SPARE4" not in sql and "USER$" not in sql


# ----------------------------------------------------------------------------- PKCS#11
def test_pkcs11_module_comes_only_from_the_node_allow_list(tmp_path):
    from zs_scan_node.collectors import ConfigError, hsm_pkcs11

    lib = tmp_path / "libfake.so"
    lib.write_bytes(b"\x7fELF")
    env = f"luna=/opt/luna/lib.so; softhsm={lib}"
    assert hsm_pkcs11.module_path("SoftHSM", env) == str(lib)
    with pytest.raises(ConfigError, match="not allowed"):
        hsm_pkcs11.module_path("/usr/lib/evil.so", env)
    with pytest.raises(ConfigError, match="not a file"):
        hsm_pkcs11.module_path("luna", env)
    with pytest.raises(ValueError):
        hsm_pkcs11.read_attributes(object(), ("LABEL", "VALUE"))


def test_pkcs11_key_facts_from_recorded_attributes():
    pkcs11 = pytest.importorskip("pkcs11")
    from zs_scan_node.collectors import hsm_pkcs11

    klass, alg, size, facts = hsm_pkcs11.key_facts({
        "CLASS": pkcs11.ObjectClass.SECRET_KEY, "KEY_TYPE": pkcs11.KeyType.AES, "VALUE_LEN": 16, "LABEL": "k",
        "ID": b"\x01\x02", "SENSITIVE": True, "EXTRACTABLE": True, "NEVER_EXTRACTABLE": False, "LOCAL": True})
    assert (klass, alg, size) == ("secret", "AES", 128) and facts["extractable"] is True and facts["id"] == "0102"
    klass, alg, size, facts = hsm_pkcs11.key_facts({
        "CLASS": pkcs11.ObjectClass.PRIVATE_KEY, "KEY_TYPE": pkcs11.KeyType.EC, "EC_PARAMS": bytes.fromhex("06052b81040022")})
    assert (klass, alg, size, facts["curve"]) == ("private", "EC", 384, "P-384")
    klass, alg, size, facts = hsm_pkcs11.key_facts({"CLASS": pkcs11.ObjectClass.PRIVATE_KEY, "KEY_TYPE": pkcs11.KeyType.RSA,
                                                    "MODULUS": ((1 << 1023) | 1).to_bytes(128, "big")})
    assert size == 1024
    assert hsm_pkcs11.key_facts({"CLASS": pkcs11.ObjectClass.SECRET_KEY, "KEY_TYPE": pkcs11.KeyType.DES3})[2] == 168


# ----------------------------------------------------------------------------- KMIP TTLV
def test_ttlv_round_trip_and_hostile_input():
    msg = K.request((2, 0), "Locate", K.locate((2, 0), 500, 500))
    item = K.decode(msg)
    assert item.name == "Request Message"
    batch = item.first("Batch Item")
    assert batch.get("Operation") == K.OPERATION["Locate"]
    payload = batch.first("Request Payload")
    assert payload.get("Maximum Items") == 500 and payload.get("Offset Items") == 500 and payload.first("Attributes")
    assert K.decode(K.request((1, 2), "Locate", K.locate((1, 2), 500, 500))).first("Batch Item").first(
        "Request Payload").first("Offset Items") is None  # 1.2 has no Offset Items
    for bad in (msg[:-3], msg[:5], b"\x42\x00\x78\x01\xff\xff\xff\xf0" + b"\0" * 8):
        with pytest.raises(K.TTLVError):
            K.decode(bad)
    deep = K.Item(K.TAG["Attribute"], K.STRUCTURE)
    node = deep
    for _ in range(K.MAX_DEPTH + 2):
        child = K.Item(K.TAG["Attribute"], K.STRUCTURE)
        node.children.append(child)
        node = child
    with pytest.raises(K.TTLVError, match="deeply"):
        K.decode(K.encode(deep))
    # only read-only operations can be built
    assert set(K.OPERATION) == {"Locate", "Get Attributes", "Query", "Discover Versions"}


def test_ttlv_attributes_1x_and_2x():
    def attr(name, value):
        return K.S("Attribute", [K.T("Attribute Name", name), value])

    v1 = K.S("Response Payload", [
        K.T("Unique Identifier", "7"),
        attr("Cryptographic Algorithm", K.E("Attribute Value", 2)),
        attr("Cryptographic Length", K.I("Attribute Value", 168)),
        attr("State", K.E("Attribute Value", 4)),
        attr("Object Type", K.E("Attribute Value", 2)),
        attr("Cryptographic Usage Mask", K.I("Attribute Value", 12)),
        attr("Name", K.S("Attribute Value", [K.T("Name Value", "legacy-3des"), K.E("Name Type", 1)])),
        attr("Activation Date", K.Item(K.TAG["Attribute Value"], K.DATETIME, 1_700_000_000)),
        attr("Digest", K.S("Attribute Value", [K.Item(0x420034, K.BYTES, b"\x01" * 32)])),
    ])
    facts = K.attributes_to_facts(K.decode(K.encode(v1)))
    assert facts["algorithm"] == "3DES" and facts["length"] == 168 and facts["state"] == "Compromised"
    assert facts["usage"] == ["Encrypt", "Decrypt"] and facts["names"] == ["legacy-3des"]
    assert facts["activation_date"] == "2023-11-14T22:13:20Z" and "digest" not in json.dumps(facts).lower()
    v2 = K.S("Response Payload", [K.T("Unique Identifier", "9"), K.S("Attributes", [
        K.E("Cryptographic Algorithm", 4), K.I("Cryptographic Length", 2048), K.E("Object Type", 4), K.E("State", 2),
        K.Item(K.TAG["Sensitive"], K.BOOL, False)])])
    facts = K.attributes_to_facts(K.decode(K.encode(v2)))
    assert (facts["algorithm"], facts["length"], facts["object_type"], facts["sensitive"]) == ("RSA", 2048, "Private Key",
                                                                                               False)


# ----------------------------------------------------------------------------- Vault / AD CS parsing
def test_vault_mounts_and_durations():
    from zs_scan_node.collectors import ca

    body = {"pki/": {"type": "pki"}, "transit/": {"type": "transit"}, "request_id": "x",
            "data": {"pki/": {"type": "pki"}, "transit/": {"type": "transit"}, "secret/": {"type": "kv"}}}
    assert ca.vault_mounts(body) == {"pki": "pki", "transit": "transit", "secret": "kv"}
    assert ca._seconds(2592000) == 2592000 and ca._seconds("720h") == 2592000 and ca._seconds("0") == 0


ADCS_CA = json.dumps({"Name": "Corp-Issuing-CA", "HashAlgorithm": "SHA1", "Provider": "Microsoft Software Key Storage Provider",
                      "ValidityPeriod": "Years", "ValidityPeriodUnits": 2, "CRLPeriod": "Weeks", "CRLPeriodUnits": 1,
                      "EditFlags": 0x0011014E | 0x00040000, "CACert": None})
ADCS_TEMPLATES = json.dumps([
    {"Name": "WebServer", "Cached": True, "MinKeySize": 1024, "NameFlag": 1, "EnrollmentFlag": 0, "RASignature": 0,
     "EKU": ["1.3.6.1.5.5.7.3.1"], "AppPolicy": [], "RAAppPolicies": [], "Validity": -630720000000000, "Schema": 1},
    {"Name": "VulnUser", "Cached": True, "MinKeySize": 2048, "NameFlag": 1, "EnrollmentFlag": 0, "RASignature": 0,
     "EKU": ["1.3.6.1.5.5.7.3.2"], "AppPolicy": [], "RAAppPolicies": [
         "msPKI-Asymmetric-Algorithm`PZPWSTR`ECDH_P256`msPKI-Hash-Algorithm`PZPWSTR`SHA256"],
     "Validity": -315360000000000, "Schema": 4},
    {"Name": "ApprovedUser", "Cached": True, "MinKeySize": 2048, "NameFlag": 1, "EnrollmentFlag": 2, "RASignature": 0,
     "EKU": ["1.3.6.1.5.5.7.3.2"], "Validity": -315360000000000, "Schema": 2},
    {"Name": "NotCached", "Cached": False, "EKU": []},
    # what an older script produced from certutil's last line, "CertUtil: -CATemplates command completed successfully."
    {"Name": "CertUtil", "Cached": False, "EKU": []},
])


def test_adcs_recorded_powershell_output():
    from zs_scan_node.collectors import ca

    parsed = ca.parse_adcs_ca(ADCS_CA)
    facts = parsed["facts"]
    assert facts["hash_algorithm"] == "SHA1" and facts["san_from_request_attributes"] is True
    assert facts["issued_validity_s"] == 2 * 365 * 86400 and parsed["cert_der"] is None
    templates = {t["name"]: t for t in ca.parse_adcs_templates(ADCS_TEMPLATES)}
    assert templates["WebServer"]["key_bits"] == 1024 and templates["WebServer"]["max_ttl_s"] == 2 * 365 * 86400
    assert templates["VulnUser"]["enrollee_supplies_subject"] is True and templates["VulnUser"]["client_auth"] is True
    assert templates["VulnUser"]["key_type"] == "EC"
    assert templates["ApprovedUser"]["enrollee_supplies_subject"] is False  # manager approval stops ESC1
    assert templates["NotCached"]["cached"] is False
    assert ca.parse_adcs_ca("") is None and ca.parse_adcs_templates("not json") == []
    assert "CertUtil" not in templates  # certutil's status line is not a template (AWS lab, round 5)


# Real security descriptors (DACL, SDDL Access section via RawSecurityDescriptor) of the 11 templates the AWS lab's
# Windows Server 2022 enterprise CA publishes, read from its CertificateTemplateCache (review round 5); the domain SID is
# replaced with S-1-5-21-1-2-3.
LAB_SDDL = dict(line.rstrip("\n").split("|", 1) for line in
                (Path(__file__).parent / "fixtures/adcs/template-sddl.txt").read_text().splitlines() if line.strip())
EA = "S-1-5-21-1-2-3-519"


def test_template_acl_from_the_lab_matches_the_windows_defaults():
    """Review round 5, H1: SubCA was reported as AD CS ESC1 because the template ACL was never read.  The defaults: only
    Domain / Enterprise Admins enroll in SubCA, WebServer and Administrator; Domain Users in User and EFS; Domain
    Computers in Machine; domain controllers in the DC templates.  Only DA / EA may change any of them (the RPWPCR
    entries for Domain Users are scoped to the Enroll right and change nothing)."""
    from zs_scan_node.collectors import ca

    assert len(LAB_SDDL) == 11
    acl = {name: ca.template_acl(sddl) for name, sddl in LAB_SDDL.items()}
    assert all(a["acl_status"] == "read" and a["write_principals"] == ["DA", EA] for a in acl.values())
    admins = ["DA", EA]
    assert acl["SubCA"]["enroll_principals"] == acl["WebServer"]["enroll_principals"] == admins
    assert acl["Administrator"]["enroll_principals"] == acl["EFSRecovery"]["enroll_principals"] == admins
    assert acl["User"]["enroll_principals"] == acl["EFS"]["enroll_principals"] == ["DA", "DU", EA]
    assert acl["Machine"]["enroll_principals"] == ["DA", "DC", EA]
    for dc in ("DomainController", "DomainControllerAuthentication", "KerberosAuthentication", "DirectoryEmailReplication"):
        assert acl[dc]["enroll_principals"] == ["DA", "DD", "ED", "S-1-5-21-1-2-3-498", EA], dc


def test_template_acl_rights_denies_and_unreadable_values():
    from zs_scan_node.collectors import ca

    enroll = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
    auto = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
    sddl = (f"D:PAI(OA;;CR;{enroll};;AU)(OA;;CR;{auto};;S-1-5-21-1-2-3-1105)(A;;CR;;;S-1-5-21-1-2-3-1106)"
            "(A;;GA;;;S-1-5-21-1-2-3-1107)(A;;WD;;;WD)(A;;WP;;;S-1-5-21-1-2-3-515)"
            "(OA;;WP;bf967a86-0de6-11d0-a285-00aa003049e2;;S-1-5-11)"   # write to one property: not counted as write
            "(A;CIIO;GA;;;BU)"                                          # inherit-only: not on the template itself
            "(A;;0x100;;;S-1-1-0)")                                     # hex control-access mask, Everyone (S-1-1-0)
    acl = ca.template_acl(sddl)
    assert acl["enroll_principals"] == ["AU", "S-1-5-21-1-2-3-1105", "S-1-5-21-1-2-3-1106", "S-1-5-21-1-2-3-1107", "WD"]
    assert acl["write_principals"] == ["S-1-5-21-1-2-3-1107", "S-1-5-21-1-2-3-515", "WD"]
    denied = ca.template_acl(f"D:PAI(OD;;CR;{enroll};;DU)(OA;;CR;{enroll};;DU)(OA;;CR;{enroll};;DA)")
    assert denied["enroll_principals"] == ["DA"]
    assert ca.template_acl(f"D:PAI(D;;CR;;;AU)(OA;;CR;{enroll};;DU)")["enroll_principals"] == []
    assert ca.template_acl(None) == {"acl_status": "not_read"} and ca.template_acl("") == {"acl_status": "not_read"}
    assert ca.template_acl("#too-long") == {"acl_status": "too_long"}
    assert ca.template_acl("#unreadable") == {"acl_status": "unreadable"}
    assert ca.template_acl("not sddl") == {"acl_status": "unreadable"}


def test_adcs_templates_carry_acl_and_ca_flag_and_the_ca_its_sid_extension():
    from zs_scan_node.collectors import ca

    raw = json.loads(ADCS_TEMPLATES)
    raw.append({"Name": "SubCA", "Cached": True, "MinKeySize": 2048, "NameFlag": 1, "EnrollmentFlag": 0,
                "RASignature": 0, "EKU": [None], "AppPolicy": [None], "RAAppPolicies": [None],
                "Validity": -5 * 315360000000000, "Schema": 1, "Flags": 0x102D0, "Acl": LAB_SDDL["SubCA"]})
    raw[0].update(Flags=0x10260, Acl=LAB_SDDL["WebServer"])
    templates = {t["name"]: t for t in ca.parse_adcs_templates(json.dumps(raw))}
    sub = templates["SubCA"]
    assert sub["is_ca"] is True and sub["client_auth"] is True and sub["enrollee_supplies_subject"] is True
    assert sub["acl_status"] == "read" and sub["enroll_principals"] == ["DA", EA]
    assert templates["WebServer"]["is_ca"] is False and templates["WebServer"]["acl_status"] == "read"
    # output of the round-5 script (no Flags / Acl): no ACL, and a template without EKU is taken for a CA template
    assert templates["VulnUser"]["acl_status"] == "not_read" and templates["VulnUser"]["is_ca"] is False
    assert templates["NotCached"]["is_ca"] is True and templates["NotCached"]["acl_status"] == "not_read"
    base = json.loads(ADCS_CA)
    assert ca.parse_adcs_ca(json.dumps(base))["facts"]["sid_extension_disabled"] is None  # older script
    for value, expected in (([None], False), (["1.3.6.1.4.1.311.25.2"], True), ("1.3.6.1.4.1.311.25.2", True),
                            (["1.3.6.1.4.1.311.21.7"], False)):
        facts = ca.parse_adcs_ca(json.dumps({**base, "DisableExtensionList": value}))["facts"]
        assert facts["sid_extension_disabled"] is expected, value
    no_policy = ca.parse_adcs_ca(json.dumps({**base, "EditFlags": None, "DisableExtensionList": [None]}))["facts"]
    assert no_policy["sid_extension_disabled"] is None  # the policy module key was not readable


def test_adcs_scripts_read_the_template_dacl_and_change_nothing():
    """The template DACL comes from the CA server's own template cache (binary Security value, no AD second hop),
    bounded to 8000 characters per template; both AD CS scripts only read."""
    import re

    from zs_scan_node.collectors import ca

    script = ca.ADCS_SCRIPTS["adcs_templates"]
    assert "RawSecurityDescriptor" in script and "GetSddlForm('Access')" in script and "$v.Security" in script
    assert "$s.Length -le 8000" in script and "Flags=$v.Flags" in script
    assert "DisableExtensionList=@($e.DisableExtensionList)" in ca.ADCS_SCRIPTS["adcs_ca"]
    for name, text in ca.ADCS_SCRIPTS.items():
        assert not re.search(r"\b(Set|New|Remove|Rename|Clear|Move|Copy)-Item|-setreg|-delreg|Remove-|Set-Acl|Invoke-",
                             text.replace("New-Object", "")), name


def test_adcs_template_script_skips_the_certutil_status_line():
    """Real `certutil -catemplates` output on Windows Server 2022 (AWS lab DC): templates, then the tool's status."""
    import re

    from zs_scan_node.collectors import ca

    script = ca.ADCS_SCRIPTS["adcs_templates"]
    assert "if ($_ -match '^([^:\\s]+):' -and $Matches[1] -ne 'CertUtil')" in script
    lines = ["DirectoryEmailReplication: Directory Email Replication -- Auto-Enroll: Access is denied.",
             "WebServer: Web Server -- Auto-Enroll: Access is denied.",
             "CertUtil: -CATemplates command completed successfully."]
    names = [m.group(1) for m in (re.match(r"^([^:\s]+):", x) for x in lines) if m and m.group(1) != "CertUtil"]
    assert names == ["DirectoryEmailReplication", "WebServer"]


# ----------------------------------------------------------------------------- EJBCA over mutual TLS (recorded API)
def _pki(tmp: Path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = dt.datetime.now(dt.timezone.utc)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(name("test CA")).issuer_name(name("test CA")).public_key(ca_key.public_key())
          .serial_number(1).not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ca_key, hashes.SHA256()))
    out = {"ca": ca.public_bytes(serialization.Encoding.PEM).decode()}
    for who, eku, cn in (("server", ExtendedKeyUsageOID.SERVER_AUTH, "ejbca.test"), ("client", ExtendedKeyUsageOID.CLIENT_AUTH,
                                                                                    "zs-reader")):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(ca.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(now + dt.timedelta(days=1)).add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False).sign(ca_key, hashes.SHA256()))
        out[f"{who}_cert"] = cert.public_bytes(serialization.Encoding.PEM).decode()
        out[f"{who}_key"] = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()).decode()
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = (x509.CertificateBuilder().subject_name(name("ManagementCA")).issuer_name(name("ManagementCA"))
            .public_key(root_key.public_key()).serial_number(2).not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(root_key, hashes.SHA256()))
    out["managed_ca"] = root.public_bytes(serialization.Encoding.PEM).decode()
    return out


def test_ejbca_over_mutual_tls_with_recorded_responses(tmp_path, monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from zs_scan_node.collectors import ca

    pki = _pki(tmp_path)
    for k in ("ca", "server_cert", "server_key"):
        (tmp_path / k).write_text(pki[k])
    seen = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            peer = self.connection.getpeercert()
            seen.append((self.path, dict(x[0] for x in peer["subject"])["commonName"]))
            base = "/ejbca/ejbca-rest-api"
            if self.path == f"{base}/v1/ca":
                body, ctype = json.dumps({"certificate_authorities": [{"id": 1, "name": "ManagementCA",
                                                                        "subject_dn": "CN=ManagementCA",
                                                                        "issuer_dn": "CN=ManagementCA",
                                                                        "expiration_date": "2036-01-01T00:00:00Z"}]}), "application/json"
            elif self.path == f"{base}/v1/ca/CN%3DManagementCA/certificate/download":
                body, ctype = pki["managed_ca"], "application/x-pem-file"
            elif self.path == f"{base}/v2/certificate/profile/ENDUSER":
                body, ctype = json.dumps({"certificate_profile_id": 1, "available_key_algs": ["RSA", "ECDSA"],
                                          "available_bit_lengths": [1024, 2048, 4096], "available_cas": ["ManagementCA"]}), "application/json"
            else:
                self.send_response(404)
                self.end_headers()
                return
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(tmp_path / "server_cert", tmp_path / "server_key")
    sctx.load_verify_locations(tmp_path / "ca")
    sctx.verify_mode = ssl.CERT_REQUIRED  # EJBCA's REST API authenticates clients by certificate
    httpd.socket = sctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    monkeypatch.setattr(netutil, "resolve", lambda name, timeout=5.0: ["127.0.0.1"])
    cfg = {"provider": "ejbca", "api_url": f"https://ejbca.test:{httpd.server_port}", "ca_pem": pki["ca"]}
    secrets = {"client_cert": pki["client_cert"], "client_key": pki["client_key"]}
    try:
        ctx = _ctx(secrets=list(secrets.values()))
        ca.collect(ctx, cfg, secrets, {})
        ctx.flush()
        assert [o.status for o in ctx.outcomes] == ["ok"], ctx.outcomes
        assert seen and all(cn == "zs-reader" for _p, cn in seen)  # the client certificate was presented
        rows = {(a["type"], a["name"]): a for a in ctx.collected}
        managed = rows[("ca_authority", "ManagementCA")]
        assert managed["facts"]["signature_algorithm"].lower().startswith("sha256") and managed["key_size"] == 2048
        profile = rows[("ca_template", "EJBCA ENDUSER")]
        assert profile["key_size"] == 1024 and profile["facts"]["available_bit_lengths"] == [1024, 2048, 4096]
        assert "PRIVATE KEY" not in json.dumps(ctx.collected)
        # without the client certificate the server refuses the handshake
        ctx = _ctx()
        ca.collect(ctx, cfg, {"client_cert": pki["server_cert"], "client_key": pki["server_key"]}, {})
        assert ctx.outcomes[0].status in ("auth_failed", "unreachable")
        # never-scan applies to the API host
        ctx = _ctx()
        ctx.never_scan.update(["127.0.0.1"])
        ca.collect(ctx, cfg, secrets, {})
        assert [o.status for o in ctx.outcomes] == ["skipped_never_scan"]
    finally:
        httpd.shutdown()
