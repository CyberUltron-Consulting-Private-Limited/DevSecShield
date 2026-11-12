"""Oracle Database with a read-only login (python-oracledb in thin mode: pure Python, no Instant Client).

The TLS check (a ClientHello on the listener port) and the certificate are read by database.py like for the other
engines.  The login uses O5LOGON, which never sends the password itself (the client proves it knows the verifier), so
like PostgreSQL's SCRAM it may be used without the server's CA; with TCPS and a CA certificate the server is verified
against it.  python-oracledb resolves names and connects by itself and the listener can redirect it, so the driver
runs inside ``drivergate.scope``: every lookup and connection it makes passes the network gate.

Thin mode cannot connect when the server insists on Oracle Native Network Encryption (DPY-3001), when the login has
only the 10G password verifier (DPY-3015), or to releases before 12.1 (DPY-3010).  Each of these is reported as a
finding on the database, not as "unreachable".  Only fixed catalog queries run; DBA_USERS.PASSWORD and wallet
contents are never selected.
"""
from __future__ import annotations

import re
import ssl
from typing import Any

from zs_scan_node import drivergate
from zs_scan_node.jobctx import JobContext, register_asset_types
from zs_scan_node.netutil import Blocked, Target, checked_target

register_asset_types("db_encryption", "db_login_policy", "db_crypto_policy", "key_store")

Q_VERSION = "SELECT banner FROM v$version"
Q_PROTOCOL = "SELECT SYS_CONTEXT('USERENV', 'NETWORK_PROTOCOL') FROM dual"
Q_OWN_BANNERS = ("SELECT network_service_banner FROM v$session_connect_info "
                 "WHERE sid = SYS_CONTEXT('USERENV', 'SID')")
Q_ALL_BANNERS = ("SELECT network_service_banner, count(*) FROM v$session_connect_info "
                 "GROUP BY network_service_banner")
Q_WALLET = "SELECT * FROM v$encryption_wallet"  # columns differ by release; WRL_PARAMETER is a directory, not a secret
WALLET_COLUMNS = ("WRL_TYPE", "STATUS", "WALLET_TYPE", "WALLET_ORDER", "KEYSTORE_MODE", "FULLY_BACKED_UP", "CON_ID")
Q_ENCRYPTED_TS = ("SELECT t.name, e.encryptionalg, e.encryptedts FROM v$encrypted_tablespaces e "
                  "JOIN v$tablespace t ON t.ts# = e.ts# AND t.con_id = e.con_id")
Q_TABLESPACES = "SELECT tablespace_name, encrypted, contents FROM dba_tablespaces"
Q_COLUMNS = ("SELECT owner, table_name, column_name, encryption_alg, salt, integrity_alg FROM dba_encrypted_columns "
             "WHERE ROWNUM <= 500")
Q_USERS = ("SELECT username, password_versions, account_status, authentication_type FROM dba_users "
           "WHERE password_versions IS NOT NULL AND ROWNUM <= 1000")
Q_PARAMETERS = ("SELECT name, value FROM v$parameter WHERE name IN ('encrypt_new_tablespaces', 'tde_configuration', "
                "'wallet_root', 'sec_case_sensitive_logon')")
SYSTEM_TABLESPACES = ("SYSTEM", "SYSAUX")

# active Native Network Encryption / checksumming algorithms, as v$session_connect_info names them
_NNE = re.compile(r"^(AES256|AES192|AES128|3DES168|3DES112|DES40|DES|RC4_256|RC4_128|RC4_56|RC4_40) Encryption service adapter",
                  re.I)
_CHECKSUM = re.compile(r"^(?:(MD5|SHA1|SHA256|SHA384|SHA512) Crypto-checksumming service adapter|"
                       r"Crypto-checksumming service adapter for (MD5|SHA1|SHA256|SHA384|SHA512))", re.I)


class OracleFail(Exception):
    def __init__(self, status: str, error: str) -> None:
        super().__init__(error)
        self.status, self.error = status, error


def nne_from_banners(banners: list[str]) -> dict[str, Any]:
    enc, chk = [], []
    for banner in banners:
        text = str(banner or "").strip()
        m = _NNE.match(text)
        if m:
            enc.append(m.group(1).upper())
        m = _CHECKSUM.match(text)
        if m:
            chk.append((m.group(1) or m.group(2)).upper())
    return {"encryption": sorted(set(enc)), "checksum": sorted(set(chk))}


# python-oracledb wraps the reason a connection failed in DPY-6005 ("cannot connect to database"): the specific code
# (DPY-3010, DPY-3001 ...) is on a later line of the message or in the chained cause, so look at all of them.
_SPECIFIC = ("DPY-3001", "DPY-3010", "DPY-3015", "ORA-01017", "ORA-28000", "ORA-28001", "ORA-01045", "ORA-12514",
             "ORA-12505")


def thin_error(exc: BaseException) -> tuple[str | None, str]:
    """(the most specific DPY-/ORA- code, its message line) of a python-oracledb error."""
    texts, seen, node = [], 0, exc
    while node is not None and seen < 5:
        err = node.args[0] if getattr(node, "args", None) else None
        texts.append(str(getattr(err, "message", None) or node))
        node, seen = node.__cause__ or node.__context__, seen + 1
    lines = [line.strip() for text in texts for line in text.split("\n") if line.strip()]
    codes = [(m.group(1), line) for line in lines for m in [re.match(r"((?:DPY|ORA)-\d+)", line)] if m]
    for code, line in codes:
        if code in _SPECIFIC:
            return code, line[:300]
    first = exc.args[0] if getattr(exc, "args", None) else None
    code = getattr(first, "full_code", None) or (codes[0][0] if codes else None)
    return code, (lines[0] if lines else str(exc))[:300]


def _ssl_context(ca_pem: str | None) -> ssl.SSLContext:
    if ca_pem:
        ctx = ssl.create_default_context(cadata=ca_pem)
        ctx.check_hostname = False  # chain verified against the uploaded CA (like PostgreSQL verify-ca)
        return ctx
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # encrypts the session; O5LOGON protects the password without trusting the server
    return ctx


def connect(ctx: JobContext, target: Target, port: int, config: dict, password: str, tls: bool):
    import oracledb
    import oracledb.base_impl as base_impl  # (oracledb removes these names from the package namespace)
    import oracledb.thin_impl as thin_impl

    drivergate.install(thin_impl)
    drivergate.install(base_impl)
    # the network gate, every address of a name; the driver's own lookups and sockets pass it in scope()
    checked_target(target, ctx.never_scan)
    kwargs: dict[str, Any] = dict(user=config.get("login"), password=password, host=target.label, port=port,
                                  service_name=config.get("database_name") or None, tcp_connect_timeout=10,
                                  protocol="tcps" if tls else "tcp", disable_oob=True, program="zeroshield-cbom",
                                  retry_count=0)
    if tls:
        kwargs.update(ssl_context=_ssl_context(config.get("ca_pem")), ssl_server_dn_match=False)
    with drivergate.scope(ctx.never_scan, {target.label: target.ip}):
        try:
            return oracledb.connect(**kwargs)
        except Blocked:
            raise
        except oracledb.Error as exc:
            code, message = thin_error(exc)
            if isinstance(exc.__cause__, Blocked) or isinstance(exc.__context__, Blocked):
                raise Blocked(target.label) from None
            raise _classify(ctx, target, port, config, code, message) from None


def _classify(ctx: JobContext, target: Target, port: int, config: dict, code: str | None, message: str) -> OracleFail:
    loc = f"{target.label}:{port}"
    if code == "DPY-3001" and "network encryption" in message.lower():  # DPY-3001 is "<feature> needs thick mode"
        ctx.emit("db_crypto_policy", target.label, f"{loc}#native-encryption", name="Oracle network encryption",
                 facts={"engine": "oracle", "native_encryption_required": True, "detail": message})
        return OracleFail("not_supported", "the server requires Oracle native network encryption (NNE) instead of TLS; "
                                           "the scan node connects with TLS only, so nothing else was read")
    if code == "DPY-3015":
        ctx.emit("db_login_policy", target.label, f"{loc}#logins", name="Oracle password verifiers",
                 facts={"engine": "oracle", "users": [{"name": config.get("login"), "password_versions": "10G",
                                                       "source": "login refused: only a 10G verifier"}]})
        return OracleFail("not_supported", "the login has only the 10G password verifier (DES-based, case-insensitive); "
                                           "reset its password so a 12C verifier is created, then test again")
    if code == "DPY-3010":
        ctx.emit("db_crypto_policy", target.label, f"{loc}#release", name="Oracle release",
                 facts={"engine": "oracle", "version_unsupported": True, "detail": message})
        return OracleFail("not_supported", "Oracle Database older than 12.1 (past Oracle's extended support); "
                                           "the scan node cannot read it")
    if code in ("ORA-01017", "ORA-28000", "ORA-28001", "ORA-01045"):
        return OracleFail("auth_failed", f"Oracle refused the login ({code})")
    if code in ("ORA-12514", "ORA-12505"):
        return OracleFail("error", f"the listener does not know the service name ({code})")
    if code == "DPY-6005" and ("certificate" in message.lower() or "SSL" in message):
        return OracleFail("identity_unverified", "the server's certificate does not chain to the uploaded CA "
                                                 "certificate; nothing was sent")
    if code in ("DPY-6005", "DPY-4011", "DPY-6000"):
        return OracleFail("unreachable", f"could not connect to Oracle ({code})")
    return OracleFail("error", f"Oracle connection failed ({code or 'unknown'}): {message[:160]}")


class _Reader:
    def __init__(self, conn, ctx: JobContext, label: str) -> None:
        self.conn, self.ctx, self.label = conn, ctx, label

    def q(self, sql: str, what: str, gap: bool = True) -> tuple[list | None, list[str]]:
        import oracledb

        try:
            with self.conn.cursor() as cur:
                cur.execute(sql)
                rows = cur.fetchmany(2000)
                return list(rows), [str(d[0]).upper() for d in cur.description or []]
        except oracledb.Error as exc:
            code, message = thin_error(exc)
            if gap:
                status = {"ORA-00942": "denied", "ORA-01031": "denied", "ORA-00904": "not_supported"}.get(code or "",
                                                                                                         "error")
                self.ctx.coverage(self.label, f"oracle {what}", status, message[:200])
            return None, []


def read(ctx: JobContext, conn, target: Target, loc: str) -> int:
    r = _Reader(conn, ctx, target.label)
    n = 0
    banner = ((r.q(Q_VERSION, "version")[0] or [[None]])[0] or [None])[0]
    protocol = ((r.q(Q_PROTOCOL, "network protocol")[0] or [[None]])[0] or [None])[0]
    params = {str(k): v for k, v in (r.q(Q_PARAMETERS, "parameters")[0] or [])}
    ctx.emit("database_config", target.label, loc, name=str(banner or "Oracle Database")[:120], protocol="oracle",
             facts={"engine": "oracle", "version": banner, "network_protocol": protocol, "parameters": params})
    n += 1
    own, _ = r.q(Q_OWN_BANNERS, "own session network services")
    every, _ = r.q(Q_ALL_BANNERS, "session network services", gap=False)
    sessions = nne_from_banners([row[0] for row in every or []])
    ctx.emit("db_crypto_policy", target.label, f"{loc}#native-encryption", name="Oracle network encryption",
             facts={"engine": "oracle", "native_encryption_required": False, "network_protocol": protocol,
                    "own_session": nne_from_banners([row[0] for row in own or []]),
                    "sessions_nne_algorithms": sessions["encryption"],
                    "sessions_checksum_algorithms": sessions["checksum"]})
    n += 1
    wallet_rows, cols = r.q(Q_WALLET, "TDE wallet")
    for i, row in enumerate(wallet_rows or []):
        info = {c.lower(): row[cols.index(c)] for c in WALLET_COLUMNS if c in cols}
        ctx.emit("key_store", target.label, f"{loc}#wallet[{i}]", name=f"Oracle TDE keystore {info.get('wrl_type') or ''}".strip(),
                 facts={"store": "oracle_wallet", "engine": "oracle", **info})
        n += 1
    encrypted_ts = {str(row[0]): (row[1], row[2]) for row in r.q(Q_ENCRYPTED_TS, "encrypted tablespaces")[0] or []}
    for name, encrypted, contents in r.q(Q_TABLESPACES, "tablespaces")[0] or []:
        if str(contents).upper() != "PERMANENT" or str(name).upper() in SYSTEM_TABLESPACES:
            continue
        alg, flag = encrypted_ts.get(str(name), (None, None))
        is_enc = str(encrypted).upper() == "YES" or str(flag).upper() == "YES"
        ctx.emit("db_encryption", target.label, f"{loc}/{name}#tde", name=str(name), algorithm=alg or None,
                 facts={"engine": "oracle", "scope": "tablespace", "tablespace": name, "encrypted": is_enc,
                        "algorithm_desc": alg})
        n += 1
    for owner, table, column, alg, salt, integrity in r.q(Q_COLUMNS, "encrypted columns")[0] or []:
        ctx.emit("db_encryption", target.label, f"{loc}/{owner}.{table}.{column}#column", name=f"{owner}.{table}.{column}",
                 algorithm=str(alg or "") or None,
                 facts={"engine": "oracle", "scope": "column", "encrypted": True, "algorithm_desc": alg,
                        "salt": str(salt or "").upper() == "YES", "integrity": integrity})
        n += 1
    users, _ = r.q(Q_USERS, "password verifiers (DBA_USERS)")
    if users is not None:
        ctx.emit("db_login_policy", target.label, f"{loc}#logins", name="Oracle password verifiers",
                 facts={"engine": "oracle", "users": [{"name": u[0], "password_versions": str(u[1] or "").strip(),
                                                        "account_status": u[2], "authentication_type": u[3]}
                                                       for u in users]})
        n += 1
    return n


def collect_login(ctx: JobContext, target: Target, port: int, config: dict, password: str, tls: bool, loc: str) -> int:
    conn = connect(ctx, target, port, config, password, tls)
    try:
        return read(ctx, conn, target, loc)
    finally:
        conn.close()
