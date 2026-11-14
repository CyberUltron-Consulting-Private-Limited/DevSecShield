"""Microsoft SQL Server over TDS with a read-only login (python-tds, pure Python).

Before any credential is sent the node reads, without logging in:
* the PRELOGIN answer to a client that offers no encryption: ENCRYPT_REQ means Force Encryption is on, ENCRYPT_OFF
  means only the login packet is encrypted and everything after it travels in clear text (MS-TDS 2.2.6.5);
* the server's TLS (carried inside TDS PRELOGIN packets): the TLS versions it accepts, the cipher and the certificate
  chain.  A server with Force Strict Encryption (TDS 8.0) expects TLS before PRELOGIN; it is recognised by a direct
  TLS handshake with the ALPN "tds/8.0" and reported as such.

The SQL Server login packet only XORs the password with a fixed pattern (MS-TDS 2.2.6.4), so the password is sent
only inside TLS to a server whose certificate chains to the CA certificate uploaded for the source; otherwise the
target is ``identity_unverified`` and the password never leaves the node.  python-tds opens its own socket and can be
routed elsewhere by the server, so it runs inside ``drivergate.scope``: every connection it makes passes the network
gate.  Only catalog views are read; password hashes are never selected (only the 2-byte hash version header).
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import ssl
import struct
import tempfile
import time
from typing import Any

from zs_scan_node import drivergate, netutil
from zs_scan_node import tlsprobe as T
from zs_scan_node.certparse import cert_facts, load_certs
from zs_scan_node.jobctx import JobContext, register_asset_types
from zs_scan_node.netutil import Blocked, Target, checked_target, is_ip

register_asset_types("managed_key", "db_encryption", "db_login_policy", "db_crypto_policy")

PRELOGIN = 0x12
ENCRYPT_OFF, ENCRYPT_ON, ENCRYPT_NOT_SUP, ENCRYPT_REQ = 0, 1, 2, 3
ENCRYPTION_NAMES = {0: "ENCRYPT_OFF", 1: "ENCRYPT_ON", 2: "ENCRYPT_NOT_SUP", 3: "ENCRYPT_REQ"}
SYSTEM_DATABASES = ("master", "model", "msdb", "tempdb")
MAX_DATABASES = 200


class MssqlFail(Exception):
    def __init__(self, status: str, error: str) -> None:
        super().__init__(error)
        self.status, self.error = status, error


# ----------------------------------------------------------------------------- TDS framing (no login)
def _recv_exact(sock: socket.socket, n: int, deadline: float) -> bytes:
    buf = b""
    while len(buf) < n:
        left = deadline - time.monotonic()
        if left <= 0:
            raise T.ProbeError("timeout", "no answer")
        sock.settimeout(left)
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            raise T.ProbeError("timeout", "no answer") from None
        except OSError as exc:
            raise T.ProbeError("error", exc.__class__.__name__) from None
        if not chunk:
            raise T.ProbeError("error", "connection closed")
        buf += chunk
    return buf


def send_packet(sock: socket.socket, ptype: int, payload: bytes, size: int = 4096) -> None:
    chunk = size - 8
    parts = [payload[i:i + chunk] for i in range(0, len(payload), chunk)] or [b""]
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        sock.sendall(struct.pack("!BBHHBB", ptype, 0x01 if last else 0x00, 8 + len(part), 0, (i + 1) & 0xFF, 0) + part)


def recv_message(sock: socket.socket, deadline: float, limit: int = 1 << 20) -> tuple[int, bytes]:
    """One TDS message (packets up to the end-of-message bit).  Raises ProbeError for anything that is not TDS."""
    data, ptype = b"", None
    while True:
        head = _recv_exact(sock, 8, deadline)
        t, status, length = head[0], head[1], struct.unpack("!H", head[2:4])[0]
        if t not in (0x04, PRELOGIN) or length < 8 or length > 32768:
            raise T.ProbeError("error", "not a TDS response")
        ptype = t if ptype is None else ptype
        data += _recv_exact(sock, length - 8, deadline)
        if len(data) > limit:
            raise T.ProbeError("error", "TDS answer too large")
        if status & 0x01:
            return ptype, data


def prelogin_payload(encryption: int) -> bytes:
    options = [(0x00, b"\x0f\x00\x07\xd0\x00\x00"), (0x01, bytes([encryption])), (0x02, b"\x00"),
               (0x03, b"\x00\x00\x00\x00"), (0x04, b"\x00")]
    header_len = 5 * len(options) + 1
    table, data = b"", b""
    for token, value in options:
        table += struct.pack("!BHH", token, header_len + len(data), len(value))
        data += value
    return table + b"\xff" + data


def parse_prelogin(body: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    pos = 0
    while pos + 5 <= len(body) and body[pos] != 0xFF:
        token, offset, length = struct.unpack("!BHH", body[pos:pos + 5])
        value = body[offset:offset + length]
        if token == 0x00 and len(value) >= 4:
            out["server_version"] = f"{value[0]}.{value[1]}.{(value[2] << 8) | value[3]}"
        elif token == 0x01 and len(value) >= 1:
            out["encryption"] = value[0]
            out["encryption_name"] = ENCRYPTION_NAMES.get(value[0], f"0x{value[0]:x}")
        pos += 5
    if "encryption" not in out:
        raise T.ProbeError("error", "no ENCRYPTION option in the PRELOGIN answer")
    return out


def prelogin(sock: socket.socket, encryption: int, deadline: float) -> dict[str, Any]:
    send_packet(sock, PRELOGIN, prelogin_payload(encryption))
    _t, body = recv_message(sock, deadline)
    return parse_prelogin(body)


_TLS_VERSIONS = (("TLSv1", "TLS1_VERSION"), ("TLSv1.1", "TLS1_1_VERSION"), ("TLSv1.2", "TLS1_2_VERSION"),
                 ("TLSv1.3", "TLS1_3_VERSION"))


def tls_in_tds(sock: socket.socket, deadline: float, version: str | None = None) -> dict[str, Any]:
    """TLS handshake carried in PRELOGIN packets (TDS 7.x), after a PRELOGIN that asked for encryption.  The
    certificate is read, not trusted: nothing secret is sent on this connection.  ``version`` pins one TLS version."""
    from OpenSSL import SSL

    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    ctx.set_verify(SSL.VERIFY_NONE, lambda *_a: True)
    try:
        ctx.set_cipher_list(b"ALL:@SECLEVEL=0")
    except SSL.Error:
        pass
    if version:
        const = getattr(SSL, dict(_TLS_VERSIONS)[version])
        ctx.set_min_proto_version(const)
        ctx.set_max_proto_version(const)
    conn = SSL.Connection(ctx, None)
    conn.set_connect_state()
    for _ in range(20):
        try:
            conn.do_handshake()
            break
        except SSL.WantReadError:
            try:
                out = conn.bio_read(65536)
            except SSL.WantReadError:
                out = b""
            if out:
                send_packet(sock, PRELOGIN, out)
            _t, data = recv_message(sock, deadline)
            conn.bio_write(data)
        except SSL.Error as exc:
            raise T.ProbeError("error", f"TLS handshake failed ({str(exc)[:80]})") from None
    else:
        raise T.ProbeError("error", "TLS handshake did not finish")
    chain = []
    for cert in conn.get_peer_cert_chain() or []:
        from cryptography.hazmat.primitives.serialization import Encoding

        chain.append(cert.to_cryptography().public_bytes(Encoding.DER))
    return {"version": conn.get_protocol_version_name(), "cipher": conn.get_cipher_name(), "certs_der": chain}


def strict_tls(sock: socket.socket, sni: str | None, timeout: float) -> dict[str, Any]:
    """TDS 8.0 (Force Strict Encryption): TLS first, with the ALPN tds/8.0 (MS-TDS 2.2.6.5, SQL Server 2022)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["tds/8.0"])
    sock.settimeout(timeout)
    with ctx.wrap_socket(sock, server_hostname=sni) as tls:
        der = tls.getpeercert(binary_form=True)
        cipher = tls.cipher()
        return {"version": tls.version(), "cipher": cipher[0] if cipher else None, "certs_der": [der] if der else [],
                "alpn": tls.selected_alpn_protocol()}


def probe_endpoint(ctx: JobContext, target: Target, port: int) -> dict[str, Any]:
    """Everything readable without a login: encryption policy, TLS versions, cipher and certificate chain."""
    never = ctx.never_scan
    deadline = time.monotonic() + 10
    facts: dict[str, Any] = {"engine": "mssql", "service": "mssql", "strict": False}
    sock = netutil.connect(target.ip, port, never, 5)
    try:
        try:
            pre = prelogin(sock, ENCRYPT_OFF, deadline)
        except T.ProbeError as exc:
            pre = None
            facts["prelogin_error"] = exc.detail
    finally:
        sock.close()
    sni = None if is_ip(target.label) else target.label
    if pre is None:
        sock = netutil.connect(target.ip, port, never, 5)
        try:
            hs = strict_tls(sock, sni, 8)
        except (OSError, ssl.SSLError):
            raise T.ProbeError("error", "the port answered neither TDS PRELOGIN nor TDS 8.0 TLS") from None
        finally:
            sock.close()
        facts.update(strict=True, tls=True, force_encryption=True, encryption_name="STRICT (TDS 8.0)",
                     negotiated_version=hs["version"], negotiated_cipher=hs["cipher"], alpn=hs["alpn"])
        facts["_certs"] = hs["certs_der"]
        return facts
    facts.update(server_version=pre.get("server_version"), encryption_name=pre["encryption_name"],
                 tls=pre["encryption"] != ENCRYPT_NOT_SUP, force_encryption=pre["encryption"] == ENCRYPT_REQ)
    if not facts["tls"]:
        facts["plaintext_only"] = True
        return facts
    versions: dict[str, bool] = {}
    best: dict[str, Any] | None = None
    for name, _const in _TLS_VERSIONS:
        sock = netutil.connect(target.ip, port, never, 5)
        try:
            pre_on = prelogin(sock, ENCRYPT_ON, time.monotonic() + 8)
            if pre_on["encryption"] == ENCRYPT_NOT_SUP:
                versions[name] = False
                continue
            hs = tls_in_tds(sock, time.monotonic() + 8, name)
            versions[name] = hs["version"] == name
            if versions[name]:
                best = hs
        except T.ProbeError:
            versions[name] = False
        finally:
            sock.close()
    facts["versions"] = versions
    if best is not None:
        facts.update(negotiated_version=best["version"], negotiated_cipher=best["cipher"])
        facts["_certs"] = best["certs_der"]
    return facts


# ----------------------------------------------------------------------------- queries (read-only)
Q_VERSION = ("SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(64)), CAST(SERVERPROPERTY('Edition') AS "
             "nvarchar(128)), CAST(SERVERPROPERTY('ProductLevel') AS nvarchar(64))")
Q_OWN = ("SELECT encrypt_option, auth_scheme, protocol_type, net_transport FROM sys.dm_exec_connections "
         "WHERE session_id = @@SPID")
Q_LIVE = "SELECT encrypt_option, auth_scheme, count(*) FROM sys.dm_exec_connections GROUP BY encrypt_option, auth_scheme"
Q_FORCE = ("SELECT CAST(value_data AS nvarchar(64)) FROM sys.dm_server_registry WHERE value_name = 'ForceEncryption'")
Q_DATABASES = ("SELECT name, database_id, is_encrypted, state_desc, HAS_DBACCESS(name) FROM sys.databases "
               "ORDER BY database_id")
Q_TDE = ("SELECT DB_NAME(database_id), encryption_state, key_algorithm, key_length, encryptor_type "
         "FROM sys.dm_database_encryption_keys")
# hash VERSION only: 1 = SHA-1 (SQL Server 2000-2008 R2), 2 = SHA-512 (2012+); NULL without CONTROL SERVER
Q_LOGINS = ("SELECT TOP 500 name, is_disabled, is_policy_checked, is_expiration_checked, "
            "CASE WHEN password_hash IS NULL THEN NULL ELSE CONVERT(int, SUBSTRING(password_hash, 1, 1)) END "
            "FROM sys.sql_logins ORDER BY name")
TDE_STATES = {0: "no key", 1: "unencrypted", 2: "encrypting", 3: "encrypted", 4: "key change", 5: "decrypting",
              6: "protection change"}


def _quote(name: str) -> str:
    return "[" + str(name).replace("]", "]]") + "]"


def per_db_queries(db: str) -> dict[str, str]:
    q = _quote(db)
    return {
        "symmetric_keys": f"SELECT name, algorithm_desc, key_length, create_date, modify_date FROM {q}.sys.symmetric_keys",
        "asymmetric_keys": f"SELECT name, algorithm_desc, key_length, pvt_key_encryption_type_desc FROM {q}.sys.asymmetric_keys",
        # CERTENCODED returns the public certificate only (never the private key)
        "certificates": f"SELECT name, pvt_key_encryption_type_desc, expiry_date, subject, issuer_name, start_date, "
                        f"CERTENCODED(certificate_id) FROM {q}.sys.certificates",
        # CERTENCODED needs compatibility level 110+; older databases give the catalog columns only
        "certificates_meta": f"SELECT name, pvt_key_encryption_type_desc, expiry_date, subject, issuer_name, start_date "
                             f"FROM {q}.sys.certificates",
        "column_master_keys": f"SELECT name, key_store_provider_name, key_path, allow_enclave_computations "
                              f"FROM {q}.sys.column_master_keys",
        "column_encryption_keys": f"SELECT k.name, m.name, v.encryption_algorithm_name FROM {q}.sys.column_encryption_keys k "
                                  f"JOIN {q}.sys.column_encryption_key_values v ON v.column_encryption_key_id = "
                                  f"k.column_encryption_key_id JOIN {q}.sys.column_master_keys m ON "
                                  f"m.column_master_key_id = v.column_master_key_id",
    }


_DENIED = re.compile(r"permission|denied|not able to access|cannot open database|server principal", re.I)


def _algo(desc: Any) -> tuple[str | None, str | None]:
    """(algorithm family, display) from sys.*_keys algorithm_desc (AES_256, TRIPLE_DES_3KEY, RSA_2048 ...)."""
    text = str(desc or "").upper()
    if not text:
        return None, None
    if text.startswith("RSA"):
        return "RSA", text
    if text.startswith("AES"):
        return "AES", text
    if "TRIPLE_DES" in text or text in ("DESX",):
        return "3DES", text
    if text.startswith("DES"):
        return "DES", text
    if text.startswith("RC4") or text == "RC4_128":
        return "RC4", text
    if text.startswith("RC2"):
        return "RC2", text
    return text, text


class _Db:
    def __init__(self, conn, ctx: JobContext, label: str) -> None:
        self.conn, self.ctx, self.label = conn, ctx, label

    def q(self, sql: str, what: str, gap: bool = True) -> list | None:
        import pytds

        try:
            with self.conn.cursor() as cur:
                cur.execute(sql)
                return list(cur.fetchall())
        except pytds.Error as exc:
            if gap:
                status = "denied" if _DENIED.search(str(exc)) else "error"
                self.ctx.coverage(self.label, f"mssql {what}", status, str(exc).split("\n")[0][:200])
            return None


def _tls_error(exc: BaseException) -> bool:
    module = type(exc).__module__ or ""
    return module.startswith("OpenSSL") or isinstance(exc, ssl.SSLError) or "certificate verify failed" in str(exc)


def collect_login(ctx: JobContext, target: Target, port: int, config: dict, password: str, ca_path: str,
                  loc: str) -> int:
    import pytds

    drivergate.install(pytds)
    # the network gate, every address of a name; the driver's own sockets pass it in drivergate.scope
    checked_target(target, ctx.never_scan)
    kwargs = dict(server=target.label, port=port, user=config.get("login"), password=password, cafile=ca_path,
                  validate_host=False, login_timeout=15, timeout=30, autocommit=True, appname="zeroshield-cbom",
                  database=config.get("database_name") or "master", disable_connect_retry=True)
    with drivergate.scope(ctx.never_scan, {target.label: target.ip}):
        try:
            conn = pytds.connect(**kwargs)
        except Blocked:
            raise
        except Exception as exc:  # pytds.Error, OpenSSL.SSL.Error (certificate), socket errors, TimeoutError
            text = str(exc)
            if _tls_error(exc):
                raise MssqlFail("identity_unverified", "the server's certificate does not chain to the uploaded CA "
                                "certificate; the password was not sent") from None
            if isinstance(exc, pytds.LoginError) or "18456" in text or "Login failed" in text:
                raise MssqlFail("auth_failed", "SQL Server refused the login") from None
            raise MssqlFail("unreachable", f"could not log in to SQL Server ({exc.__class__.__name__})") from None
        try:
            return _read(ctx, _Db(conn, ctx, target.label), target, loc)
        finally:
            conn.close()


def _read(ctx: JobContext, db: _Db, target: Target, loc: str) -> int:
    n = 0
    version = (db.q(Q_VERSION, "version") or [[None, None, None]])[0]
    own = (db.q(Q_OWN, "own connection") or [[None] * 4])[0]
    live = db.q(Q_LIVE, "live connection encryption")
    force = db.q(Q_FORCE, "ForceEncryption registry value", gap=False)
    ctx.emit("database_tls", target.label, loc, name="SQL Server connections",
             facts={"engine": "mssql", "own_connection": {"encrypt_option": own[0], "auth_scheme": own[1],
                                                          "protocol_type": own[2], "net_transport": own[3]},
                    "live_connections": [{"encrypt_option": r[0], "auth_scheme": r[1], "count": r[2]} for r in live or []],
                    "unencrypted_live_connections": sum(int(r[2]) for r in live or [] if str(r[0]).upper() != "TRUE")
                    if live is not None else None})
    n += 1
    databases = db.q(Q_DATABASES, "databases") or []
    tde = {str(r[0]): r for r in db.q(Q_TDE, "Transparent Data Encryption keys") or []}
    ctx.emit("database_config", target.label, loc, name=f"SQL Server {version[0] or ''}".strip(), protocol="mssql",
             facts={"engine": "mssql", "version": version[0], "edition": version[1], "level": version[2],
                    "force_encryption_registry": (force[0][0] if force else None),
                    "databases": len(databases)})
    n += 1
    for name, _dbid, is_encrypted, state, _access in databases[:MAX_DATABASES]:
        if name in ("master", "model", "msdb", "tempdb"):
            continue
        key = tde.get(str(name))
        state_code = int(key[1]) if key is not None and key[1] is not None else 0
        ctx.emit("db_encryption", target.label, f"{loc}/{name}#tde", name=str(name),
                 algorithm=(str(key[2]) if key is not None and key[2] else None),
                 key_size=(int(key[3]) if key is not None and key[3] else None),
                 facts={"engine": "mssql", "scope": "database", "database": name, "state": state,
                        "encrypted": bool(is_encrypted) and state_code == 3,
                        "tde_state": TDE_STATES.get(state_code, str(state_code)),
                        "encryptor_type": (key[4] if key is not None else None)})
        n += 1
    logins = db.q(Q_LOGINS, "SQL logins")
    if logins is not None:
        rows = [{"name": r[0], "disabled": bool(r[1]), "policy_checked": bool(r[2]), "expiration_checked": bool(r[3]),
                 "hash_version": r[4]} for r in logins]
        if rows and all(r["hash_version"] is None for r in rows):
            ctx.coverage(target.label, "mssql password hash versions", "denied",
                         "sys.sql_logins.password_hash is visible only with CONTROL SERVER; the hash version "
                         "(SHA-1 or SHA-512) of each login was not read")
        ctx.emit("db_login_policy", target.label, f"{loc}#logins", name="SQL Server logins",
                 facts={"engine": "mssql", "logins": rows})
        n += 1
    readable = [r[0] for r in databases if r[4] == 1][:MAX_DATABASES]
    unreadable = [r[0] for r in databases if r[4] != 1]
    if unreadable:
        ctx.coverage(target.label, "mssql per-database keys", "denied",
                     f"{len(unreadable)} database(s) not readable by this login (GRANT CONNECT ANY DATABASE): "
                     + ", ".join(map(str, unreadable[:10])))
    for name in readable:
        n += _read_keys(ctx, db, target, loc, str(name))
    return n


def _iso(value: Any) -> str | None:
    try:
        return value.strftime("%Y-%m-%dT%H:%M:%SZ") if value else None
    except AttributeError:
        return str(value) or None


def _read_keys(ctx: JobContext, db: _Db, target: Target, loc: str, name: str) -> int:
    n = 0
    queries = per_db_queries(name)
    for key_name, desc, length, created, modified in db.q(queries["symmetric_keys"], f"symmetric keys in {name}") or []:
        fam, display = _algo(desc)
        ctx.emit("managed_key", target.label, f"{loc}/{name}#symmetric_key/{key_name}", name=str(key_name), algorithm=fam,
                 key_size=length, facts={"store": "mssql", "engine": "mssql", "database": name, "key_class": "secret",
                                         "algorithm_desc": display, "created": str(created or "") or None,
                                         "modified": str(modified or "") or None,
                                         "role": {"##MS_DatabaseMasterKey##": "database master key",
                                                  "##MS_ServiceMasterKey##": "service master key"}.get(str(key_name))})
        n += 1
    for key_name, desc, length, protection in db.q(queries["asymmetric_keys"], f"asymmetric keys in {name}") or []:
        fam, display = _algo(desc)
        ctx.emit("managed_key", target.label, f"{loc}/{name}#asymmetric_key/{key_name}", name=str(key_name), algorithm=fam,
                 key_size=length, facts={"store": "mssql", "engine": "mssql", "database": name, "key_class": "private",
                                         "algorithm_desc": display, "private_key_protection": protection})
        n += 1
    rows = db.q(queries["certificates"], f"certificates in {name}", gap=False)
    if rows is None:
        rows = [(*r, None) for r in db.q(queries["certificates_meta"], f"certificates in {name}") or []]
    for cert_name, protection, expiry, subject, issuer, start, der in rows:
        certs = load_certs(bytes(der)) if der else []
        where = f"{loc}/{name}#certificate/{cert_name}"
        if certs:
            f = cert_facts(certs[0], "mssql")
            ctx.emit("certificate", target.label, where, name=str(cert_name), algorithm=f.get("key_alg"),
                     key_size=f.get("key_size"),
                     facts={**f, "database": name, "private_key_protection": protection, "role": "mssql"})
        else:  # CERTENCODED gives NULL below compatibility level 110: the catalog columns only
            ctx.emit("certificate", target.label, where, name=str(cert_name), algorithm="RSA",  # SQL Server certs are RSA
                     facts={"subject": subject, "issuer": issuer, "not_after": _iso(expiry), "not_before": _iso(start),
                            "self_signed": bool(subject) and subject == issuer, "key_alg": "RSA", "database": name,
                            "private_key_protection": protection, "role": "mssql", "source": "mssql-catalog"})
        n += 1
    for cmk, provider, path, enclave in db.q(queries["column_master_keys"], f"Always Encrypted master keys in {name}",
                                             gap=False) or []:
        ctx.emit("managed_key", target.label, f"{loc}/{name}#column_master_key/{cmk}", name=str(cmk), algorithm="RSA",
                 facts={"store": "mssql", "engine": "mssql", "database": name, "key_class": "private",
                        "role": "Always Encrypted column master key", "key_store_provider": provider,
                        "key_path": path, "enclave": bool(enclave)})
        n += 1
    for cek, cmk, wrap in db.q(queries["column_encryption_keys"], f"Always Encrypted column keys in {name}",
                               gap=False) or []:
        ctx.emit("managed_key", target.label, f"{loc}/{name}#column_encryption_key/{cek}", name=str(cek), algorithm="AES",
                 key_size=256, facts={"store": "mssql", "engine": "mssql", "database": name, "key_class": "secret",
                                      "role": "Always Encrypted column encryption key", "wrapped_by": wrap,
                                      "master_key": cmk, "cell_algorithm": "AEAD_AES_256_CBC_HMAC_SHA_256"})
        n += 1
    return n


# ----------------------------------------------------------------------------- one target
def collect_target(ctx: JobContext, target: Target, port: int, config: dict, password_fn, where: str) -> tuple[str, str | None, int]:
    """(status, error, assets) for one SQL Server.  ``password_fn`` reads the password only when it may be sent."""
    loc = f"{where}:{port}"
    n = 0
    try:
        facts = probe_endpoint(ctx, target, port)
    except T.ProbeError as exc:
        return exc.code, exc.detail, 0
    except OSError as exc:
        code = "refused" if isinstance(exc, ConnectionRefusedError) else (
            "timeout" if isinstance(exc, socket.timeout) else "unreachable")
        return code, exc.__class__.__name__, 0
    for i, der in enumerate((facts.pop("_certs", None) or [])[:5]):
        for cert in load_certs(der):
            f = cert_facts(cert, "tls")
            ctx.emit("certificate", target.label, f"{loc}#chain[{i}]", name=f.get("subject", ""), algorithm=f.get("key_alg"),
                     key_size=f.get("key_size"), facts={**f, "chain_index": i, "role": "mssql"})
            n += 1
    ctx.emit("tls_endpoint", target.label, loc, name=f"mssql {target.ip}:{port}", algorithm=facts.get("negotiated_cipher"),
             protocol=facts.get("negotiated_version") or "mssql", facts=facts)
    n += 1
    ctx.emit("db_crypto_policy", target.label, f"{loc}#transport", name="SQL Server transport encryption",
             facts={"engine": "mssql", "encryption": facts.get("encryption_name"),
                    "force_encryption": facts.get("force_encryption"), "strict": facts.get("strict"),
                    "tls": facts.get("tls")})
    n += 1
    require_tls = bool(config.get("require_tls", True))
    if not facts.get("tls"):
        if require_tls:
            return "tls_unavailable", "the server does not offer TLS; the password was not sent", n
    if facts.get("strict"):
        return "not_supported", ("the server requires TDS 8.0 strict encryption, which the scan node's SQL Server "
                                 "driver does not support yet; transport facts were read without logging in"), n
    if not (facts.get("tls") and config.get("ca_pem")):
        return "identity_unverified", ("SQL Server logins only obfuscate the password, so it is sent only inside TLS "
                                       "to a server proven by its CA certificate; upload the CA. Transport facts were "
                                       "read without logging in"), n
    password = password_fn()
    folder = tempfile.mkdtemp(prefix="zsmssql-")
    try:
        ca_path = os.path.join(folder, "ca.pem")
        with open(ca_path, "w", encoding="ascii") as fh:
            fh.write(config["ca_pem"])
        n += collect_login(ctx, target, port, config, password or "", ca_path, loc)
    except MssqlFail as fail:
        return fail.status, fail.error, n
    except Blocked:
        return "skipped_never_scan", None, n
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    return "ok", None, n
