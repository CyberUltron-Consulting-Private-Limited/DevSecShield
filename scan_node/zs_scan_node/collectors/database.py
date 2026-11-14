"""Databases: PostgreSQL, MySQL, Redis, MongoDB, SQL Server (mssql.py) and Oracle (oracle.py) with a read-only login.

Before any credential is sent the node checks whether the server offers TLS (Postgres SSLRequest, MySQL greeting
CLIENT_SSL flag, a raw ClientHello for Redis/MongoDB).  With ``require_tls`` and no TLS the target is
``tls_unavailable`` and the password is never sent.  Only fixed queries and fixed setting names are read; nothing
that holds a secret (Redis ``requirepass``/``tls-key-file-pass``, MySQL ``authentication_string``, Postgres password
hashes) is ever selected.  Postgres password hash *types* are computed in SQL so no hash leaves the database.
"""
from __future__ import annotations

import ipaddress

import os
import shutil
import ssl
import tempfile
import threading
import time
from typing import Any

from zs_scan_node import tls_registry as R
from zs_scan_node import tlsenum as E
from zs_scan_node import tlsprobe as T
from zs_scan_node.certparse import cert_facts, load_certs
from zs_scan_node.collectors import ConfigError
from zs_scan_node import netutil
from zs_scan_node.jobctx import MAX_FACTS_BYTES, JobContext
from zs_scan_node.netutil import Blocked, Target, checked_ip, checked_target, is_ip, resolve_checked

SUPPORTED = ("postgres", "mysql", "redis", "mongodb", "mssql", "oracle")
DEFAULT_PORTS = {"postgres": 5432, "mysql": 3306, "redis": 6379, "mongodb": 27017, "mssql": 1433, "oracle": 1521}
REDIS_TLS_SETTINGS = ["port", "tls-port", "tls-protocols", "tls-ciphers", "tls-ciphersuites", "tls-auth-clients",
                      "tls-replication", "tls-cluster", "tls-prefer-server-ciphers", "tls-session-caching"]
MYSQL_VARIABLES = ["version", "have_ssl", "tls_version", "ssl_cipher", "tls_ciphersuites", "require_secure_transport",
                   "default_authentication_plugin", "authentication_policy", "default_table_encryption",
                   "innodb_redo_log_encrypt", "innodb_undo_log_encrypt", "binlog_encryption", "admin_tls_version",
                   "ssl_fips_mode", "table_encryption_privilege_check", "max_connect_errors"]
PG_SETTINGS = ["server_version", "ssl", "ssl_min_protocol_version", "ssl_max_protocol_version", "ssl_ciphers",
               "ssl_ecdh_curve", "ssl_prefer_server_ciphers", "ssl_library", "password_encryption",
               "ssl_dh_params_file"]
MONGO_OPTS = [("net", "tls", "mode"), ("net", "ssl", "mode"), ("net", "tls", "disabledProtocols"),
              ("net", "tls", "allowConnectionsWithoutCertificates"), ("net", "tls", "FIPSMode"),
              ("security", "authorization"), ("security", "enableEncryption"), ("security", "encryptionCipherMode"),
              ("security", "clusterAuthMode"), ("setParameter", "authenticationMechanisms")]


class DbFail(Exception):
    def __init__(self, status: str, error: str) -> None:
        super().__init__(error)
        self.status, self.error = status, error



def _where(target) -> str:
    """Asset location host: the name the customer configured (an RDS or cloud endpoint keeps its name when its IP
    changes on failover), else the address; IPv6 in brackets so ':port' stays unambiguous."""
    label = str(target.label or "")
    try:
        ipaddress.ip_address(label)
        is_ip = True
    except ValueError:
        is_ip = False
    host = target.ip if is_ip or not label else label
    return f"[{host}]" if ":" in str(host) else str(host)

def _password(ctx: JobContext, config: dict, secrets: dict) -> str | None:
    if config.get("credential_type") == "vault":
        from zs_scan_node import vault

        ref = config.get("vault") or {}
        creds = vault.fetch(str(ref.get("provider")), str(ref.get("path") or ""), ctx.vault_prefix)
        for v in creds.values():
            ctx.scrubber.add(v)
        return creds.get("password")
    return secrets.get("password")


class _CaFile:
    def __init__(self, pem: str | None) -> None:
        self.dir = tempfile.mkdtemp(prefix="zsdb-")
        self.path = None
        if pem:
            self.path = os.path.join(self.dir, "ca.pem")
            with open(self.path, "w", encoding="ascii") as f:
                f.write(pem)

    def close(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


def _tls_offered(ip: str, port: int, engine: str, never) -> tuple[bool, dict]:
    """Does the server offer TLS?  Uses the engine's own upgrade or a raw ClientHello."""
    checked_ip(ip, never)
    if engine in ("postgres", "mysql"):
        proto = f"starttls-{engine}"
        try:
            sock, facts = T.open_tls_socket(ip, port, proto, 8.0)
            sock.close()
            return True, facts
        except T.StarttlsUnavailable as exc:
            return False, {"detail": str(exc)}
    try:
        r = T.probe(ip, port, "tls", T.build_client_hello(T.TLS12, T.LEGACY_SUITES), 6.0)
        return bool(r.ok), {}
    except T.ProbeError as exc:
        if exc.code in ("refused", "unreachable", "no_route"):
            raise
        return False, {}


def _server_tls(ctx: JobContext, target: Target, port: int, engine: str, scope: dict | None = None,
                enumerate_now: bool = True) -> tuple[dict, int]:
    """Full handshake details + certificate for the database port, then (``enumerate_now``) what the server accepts:
    every protocol version, every suite per version, the TLS 1.3 groups (CB-12), each through the engine's own TLS
    upgrade (PostgreSQL SSLRequest) and the node's rate limiter.  MySQL is enumerated after its login instead
    (``mysql_accepted_tls``): it counts every unfinished connection against ``max_connect_errors``."""
    checked_target(target, ctx.never_scan)
    proto = {"postgres": "starttls-postgres", "mysql": "starttls-mysql"}.get(engine, "tls")
    limiter = _limiter(scope)
    if not limiter.acquire(ctx.cancel, ctx.deadline):
        raise DbFail("skipped_deadline", "the scan window or the job deadline came before the TLS read")
    with limiter.server(target.ip):
        fh = T.s_client(target.ip, port, proto, None) if T.have_openssl() else \
            T.python_handshake(target.ip, port, proto, None)
    code = R.suite_code(fh.cipher)
    facts: dict[str, Any] = {"negotiated_version": fh.version,
                             "negotiated_cipher": R.suite_name(code) if code is not None else fh.cipher,
                             "negotiated_cipher_code": R.code_hex(code) if code is not None else None,
                             "negotiated_group": E.iana_group(fh.group), "peer_signature_type": fh.peer_sig_type}
    n = 0
    for i, der in enumerate(fh.certs_der[:5]):
        for cert in load_certs(der):
            f = cert_facts(cert, "tls")
            ctx.emit("certificate", target.label, f"{_where(target)}:{port}#chain[{i}]", name=f.get("subject", ""),
                     algorithm=f.get("key_alg"), key_size=f.get("key_size"), facts={**f, "chain_index": i, "role": engine})
            n += 1
    if enumerate_now:
        facts.update(_accepted_tls(ctx, target, port, proto, fh.version if fh.ok else None, code, scope))
    return facts, n


DB_TLS_BUDGET = 64  # handshakes per database port: versions, then suites and groups (CB-12)
DB_TLS_MAX_S = 60.0
# MySQL blocks a client host after ``max_connect_errors`` successive connections that did not log in, and every probe
# counts (a raw ClientHello, a full TLS handshake then close, even a bare TCP connect: measured on MySQL 8.4 with its
# host cache on).  Only a successful login resets the count, so MySQL probes run after the read-only login, in batches
# of at most half the server's limit, each batch followed by one login: the count never passes half the limit and the
# scan leaves it at 0.
MYSQL_ASSUMED_MAX_CONNECT_ERRORS = 10  # when the variable could not be read: a hardened server's usual value
MYSQL_MAX_BATCHES = 8
_ENDPOINT_LOCKS: dict[tuple[str, int], threading.Lock] = {}
_ENDPOINT_LOCKS_LOCK = threading.Lock()


def _limiter(scope: dict | None) -> netutil.RateLimiter:
    rl = (scope or {}).get("rate_limits") or {}
    if rl.get("connections_per_second"):
        return netutil.node_limiter(rl["connections_per_second"], rl.get("parallel_per_server") or 2)
    return netutil.shared_limiter()


def _endpoint_lock(ip: str, port: int) -> threading.Lock:
    """One TLS probe at a time per database endpoint, whatever jobs run on this node."""
    with _ENDPOINT_LOCKS_LOCK:
        return _ENDPOINT_LOCKS.setdefault((ip, port), threading.Lock())


def mysql_accepted_tls(ctx: JobContext, target: Target, port: int, version: str | None, code: int | None,
                       max_connect_errors: Any, login, scope: dict | None = None) -> dict[str, Any]:
    """MySQL's accepted versions, suites and groups after a successful login (``login()`` logs in and out once, which
    resets the server's count of unfinished connections from this node)."""
    try:
        limit = int(max_connect_errors)
    except (TypeError, ValueError):
        limit = MYSQL_ASSUMED_MAX_CONNECT_ERRORS
    batch = max(limit, 0) // 2
    if batch < 1:
        return {"enumeration": {"complete": False, "not_complete": [
            f"MySQL max_connect_errors={limit}: a single probe could block this node, none was sent"]}}
    return _accepted_tls(ctx, target, port, "starttls-mysql", version, code, scope,
                         budget=min(DB_TLS_BUDGET, batch * MYSQL_MAX_BATCHES), batch=batch, reset=login)


def _accepted_tls(ctx: JobContext, target: Target, port: int, proto: str, version: str | None, code: int | None,
                  scope: dict | None = None, budget: int | None = None, batch: int | None = None,
                  reset=None) -> dict[str, Any]:
    budget = DB_TLS_BUDGET if budget is None else budget
    used = [0]
    since_reset = [0]
    dropped: list[str] = []
    deadline = time.monotonic() + DB_TLS_MAX_S
    limiter = _limiter(scope)
    lock = _endpoint_lock(target.ip, port)

    def send(hello: bytes, want_kex: bool = False):
        if dropped:
            raise E.Stop(f"server stopped answering ({dropped[0]})")
        if used[0] >= budget:
            raise E.Stop(f"handshake budget ({budget})")
        if time.monotonic() > deadline or ctx.should_stop():
            raise E.Stop("time cap")
        if batch is not None and since_reset[0] >= batch:
            if not reset():
                dropped.append("the MySQL login that resets max_connect_errors failed")
                raise E.Stop(dropped[0])
            since_reset[0] = 0
        checked_target(target, ctx.never_scan)  # the list can change while the job runs (every address of a name)
        if not limiter.acquire(ctx.cancel, min(deadline, ctx.deadline)):
            raise E.Stop("time cap")
        used[0] += 1
        since_reset[0] += 1
        with lock, limiter.server(target.ip):
            try:
                return T.probe(target.ip, port, proto, hello, 8.0, want_kex)
            except T.ProbeError as exc:
                if exc.code == "timeout" or isinstance(exc, T.ConnectRefused) or "MySQL refused" in exc.detail:
                    dropped.append(exc.detail or exc.code)  # every later probe would wait or be refused the same way
                raise

    try:
        return _enumerate(send, version, code, budget, used)
    finally:
        if reset is not None and since_reset[0]:
            reset()  # the count back to 0: the next scan, or the customer's own clients, start clean


def _enumerate(send, version: str | None, code: int | None, budget: int, used: list[int]) -> dict[str, Any]:
    known: dict[str, set[int]] = {}
    if version and code is not None and version in T.VERSION_NAMES.values():
        known.setdefault(version, set()).add(code)
    versions: dict[str, bool | None] = {}
    not_complete: list[str] = []
    for v in (T.SSL3, T.TLS10, T.TLS11, T.TLS12):
        name = T.VERSION_NAMES[v]
        if version == name:
            versions[name] = True
            continue
        try:
            r = send(T.build_client_hello(v, T.LEGACY_SUITES))
        except T.ConnectionReset:  # a reset is how some stacks refuse a version
            versions[name] = False
            continue
        except E.Stop as stop:
            versions[name] = None
            not_complete.append(f"{name}: {stop.reason}")
            continue
        except (T.ProbeError, T.StarttlsUnavailable) as exc:
            versions[name] = None
            not_complete.append(f"{name}: {getattr(exc, 'code', 'starttls')}")
            continue
        versions[name] = bool(r.ok and r.version == v)
        if versions[name] and r.cipher is not None:
            known.setdefault(name, set()).add(r.cipher)
    if version == "TLSv1.3":
        versions["TLSv1.3"] = True
    else:
        try:
            r = send(T.build_client_hello(T.TLS12, T.TLS13_SUITES, tls13=True, key_share_groups=[29]))
            versions["TLSv1.3"] = bool(r.ok and (r.version == T.TLS13 or r.hrr))
            if versions["TLSv1.3"] and r.cipher is not None:
                known.setdefault("TLSv1.3", set()).add(r.cipher)
        except T.ConnectionReset:
            versions["TLSv1.3"] = False
        except (E.Stop, T.ProbeError, T.StarttlsUnavailable) as exc:
            versions["TLSv1.3"] = None
            not_complete.append(f"TLSv1.3: {getattr(exc, 'reason', None) or getattr(exc, 'code', 'starttls')}")
    complete: dict[str, bool] = {}
    found_groups: list[int] = []
    groups_done = True
    kex: dict[str, Any] = {}
    pq = E.Pass()
    if versions.get("TLSv1.3"):
        pq = E.tls13_groups(send, E.PQ_OFFER, None)
        classical = E.tls13_groups(send, E.CLASSICAL13_OFFER, None)
        for p, label in ((pq, "PQ groups"), (classical, "TLS 1.3 groups")):
            found_groups += p.found
            groups_done = groups_done and p.complete
            if not p.complete:
                not_complete.append(f"{label}: {p.reason}")
        p = E.tls13_suites(send, known.get("TLSv1.3", set()), None)
        known.setdefault("TLSv1.3", set()).update(p.found)
        complete["TLSv1.3"] = p.complete
        if not p.complete:
            not_complete.append(f"TLSv1.3 suites: {p.reason}")
    for v in E.VERSION_ORDER:
        vname = T.VERSION_NAMES[v]
        if versions.get(vname):
            p = E.legacy_suites(send, v, known.get(vname, set()), None, kex)
            known.setdefault(vname, set()).update(p.found)
            complete[vname] = p.complete
            if not p.complete:
                not_complete.append(f"{vname} suites: {p.reason}")
    codes = sorted({c for s in known.values() for c in s})
    out: dict[str, Any] = {
        "versions": versions,
        "ciphers": [R.suite_name(c) for c in codes],
        "cipher_suites": {v: [E.suite_entry(c) for c in sorted(known[v])] for v in sorted(known)},
        "cipher_suites_complete": {v: complete.get(v, False) for v in sorted(known)},
        "groups": sorted({E.group_name(g) for g in found_groups} | {E.group_name(g) for g in kex.get("curves") or ()}),
        "groups_complete": bool(versions.get("TLSv1.3")) and groups_done,
        "enumeration": {"complete": not not_complete, "not_complete": not_complete[:12]},
        "handshakes_used": used[0] + 1, "handshake_budget": budget + 1,  # + the full handshake
    }
    if versions.get("TLSv1.3"):
        # as the network prober: no answer to the PQ pass (budget, time, an error) is "unknown", never "no hybrid"
        out["pq_hybrid"] = bool(pq.found) if pq.answered else None
        out["pq_groups"] = [E.group_name(g) for g in pq.found]
        out["pq_groups_enumerated"] = pq.complete
    weak: dict[str, set[str]] = {}
    for vname, cs in known.items():
        if vname != "TLSv1.3":
            for c in cs:
                for label in E.suite_classes(R.suite_name(c)):
                    weak.setdefault(label, set()).add(R.suite_name(c))
    if any(versions.get(T.VERSION_NAMES[v]) for v in E.VERSION_ORDER):
        out["weak_ciphers_accepted"] = {k: sorted(v) for k, v in sorted(weak.items())}
    if kex.get("dh_bits"):
        out["dh_bits"] = kex["dh_bits"]
    return out


# ----------------------------------------------------------------------------- engines
def _postgres(ctx, target, config, password, ca: _CaFile) -> int:
    import psycopg

    ip = checked_target(target, ctx.never_scan)  # the network gate, again just before the driver connects
    port = int(config.get("port") or 5432)
    require_tls = bool(config.get("require_tls", True))
    verified = bool(ca.path) and require_tls  # only verify-ca proves the server; "prefer" never checks the CA
    sslmode = ("verify-ca" if verified else "require") if require_tls else "prefer"
    kwargs = dict(host=target.label, hostaddr=ip, port=port, user=config.get("login"), password=password or None,
                  dbname=config.get("database_name") or "postgres", sslmode=sslmode, connect_timeout=10,
                  application_name="zeroshield-cbom",
                  options="-c default_transaction_read_only=on -c statement_timeout=15000")
    if verified:
        kwargs["sslrootcert"] = ca.path
    else:
        # the server is not proven: allow only SCRAM, which never sends the password, and bind it to the TLS
        # channel when there is one, so a man in the middle cannot relay the login either
        kwargs["require_auth"] = "scram-sha-256"
        if require_tls:
            kwargs["channel_binding"] = "require"
    try:
        conn = psycopg.connect(**kwargs, autocommit=True)
    except psycopg.OperationalError as exc:
        msg = str(exc)
        if "authentication method requirement" in msg or "channel binding" in msg:
            raise DbFail("identity_unverified", "the server asked for a login method that would reveal the password; "
                         "without its CA certificate only SCRAM is allowed, so the password was not sent") from None
        if "password authentication failed" in msg or "no pg_hba.conf entry" in msg or "authentication" in msg:
            raise DbFail("auth_failed", "PostgreSQL refused the login") from None
        if "certificate" in msg.lower() or "SSL" in msg:
            raise DbFail("tls_unavailable", "TLS to PostgreSQL failed (certificate not trusted or TLS refused)") from None
        raise DbFail("unreachable", "could not connect to PostgreSQL") from None
    n = 0
    loc = f"{_where(target)}:{port}"
    try:
        def q(sql: str, label: str, args=None):
            rows, state, message = _pg_try(conn, sql, args)
            if rows is None:
                ctx.coverage(target.label, f"postgres {label}", _PG_STATUS.get(state or "", "error"), message)
            return rows

        settings = {k: v for k, v in (q("SELECT name, setting FROM pg_settings WHERE name = ANY(%s)", "settings",
                                        [PG_SETTINGS]) or [])}
        own = q("SELECT version, cipher, bits FROM pg_stat_ssl WHERE pid = pg_backend_pid()", "own connection TLS")
        live = q("SELECT s.ssl, s.version, s.cipher, count(*) FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid) "
                 "WHERE a.backend_type = 'client backend' GROUP BY 1, 2, 3", "live connection TLS")
        hba, hba_state, hba_message = _pg_try(
            conn, "SELECT type, database, user_name, address, auth_method FROM pg_hba_file_rules LIMIT 500")
        exts = q("SELECT extname, extversion FROM pg_extension", "extensions")
        hashes = pg_role_hashes(conn, {str(e[0]) for e in exts or []}, str(config.get("login") or ""),
                                str(config.get("database_name") or "postgres"))
        if hba is None:
            hba_status = _PG_STATUS.get(hba_state or "", "error")
            if hba_status == "denied" and hashes.server_type == "rds":
                # Measured on RDS for PostgreSQL 16 (AWS lab): the master user reads pg_hba_file_rules through
                # rds_superuser but "GRANT SELECT ON pg_hba_file_rules" fails with permission denied, so no grant
                # script can open it.  The same policy lives in the DB parameter group.
                hba_message = ("Amazon RDS: only rds_superuser can read pg_hba_file_rules and the master user cannot "
                               "grant it; add the AWS account as a source to read the parameter group instead "
                               "(rds.accepted_password_auth_method, rds.force_ssl)")
            ctx.coverage(target.label, "postgres HBA rules", hba_status, hba_message)
        if hashes.gap:
            ctx.coverage(target.label, "postgres role password hash types", hashes.gap[0], hashes.gap[1])
        ctx.emit("database_config", target.label, loc, name=f"PostgreSQL {settings.get('server_version', '')}".strip(),
                 protocol="postgres", facts={"engine": "postgres", "settings": settings,
                                             "extensions": [{"name": e[0], "version": e[1]} for e in exts or []]})
        n += 1
        ctx.emit("database_tls", target.label, loc, name="PostgreSQL connections",
                 algorithm=(own[0][1] if own else None), protocol=(own[0][0] if own else None),
                 facts={"engine": "postgres", "own_connection": {"version": own[0][0], "cipher": own[0][1],
                                                                 "bits": own[0][2]} if own else None,
                        "live_connections": [{"ssl": r[0], "version": r[1], "cipher": r[2], "count": r[3]}
                                             for r in live or []]})
        n += 1
        methods: dict[str, int] = {}
        for r in hba or []:
            methods[str(r[4])] = methods.get(str(r[4]), 0) + 1
        ctx.emit("database_user_auth", target.label, f"{loc}#auth", name="PostgreSQL authentication",
                 facts={"engine": "postgres", "password_encryption": settings.get("password_encryption"),
                        "hba_methods": methods,
                        "hba_rules": [{"type": r[0], "database": r[1], "users": r[2], "address": r[3], "method": r[4]}
                                      for r in (hba or [])[:200]],
                        "role_hash_types": hashes.types, "role_hash_source": hashes.source,
                        "iam_auth_roles": hashes.iam_roles, "server_type": hashes.server_type})
        n += 1
    finally:
        conn.close()
    return n


# SQLSTATE -> coverage status (classified by code, never by message text, which is localised)
_PG_STATUS = {"42501": "denied", "42883": "not_supported", "3F000": "not_supported", "42P01": "not_supported"}
PG_HASH_FUNCTION = "public.zs_role_password_types"
_PG_AUTHID_SQL = ("SELECT rolname, CASE WHEN rolpassword IS NULL OR rolpassword = '' THEN 'none' "
                  "WHEN rolpassword LIKE 'md5%' THEN 'md5' WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'scram-sha-256' "
                  "ELSE 'other' END FROM pg_catalog.pg_authid WHERE rolcanlogin")
_PG_FUNCTION_SQL = f"SELECT rolname, password_type FROM {PG_HASH_FUNCTION}()"
# AWS documents rds_tools.role_password_encryption_type() (columns rolname, encryption_type; blank = no password).
# It lists every role, so it is joined with pg_roles (readable by everyone) to keep login roles only.
_PG_RDS_SQL = ("SELECT t.rolname, t.encryption_type FROM rds_tools.role_password_encryption_type() t "
               "JOIN pg_catalog.pg_roles r ON r.rolname = t.rolname WHERE r.rolcanlogin")
_PG_SERVICE_ROLES_SQL = ("SELECT rolname FROM pg_catalog.pg_roles WHERE rolname IN "
                         "('rdsadmin', 'rds_superuser', 'rds_iam', 'cloudsqlsuperuser', 'azure_pg_admin', 'azuresu')")
_PG_IAM_SQL = ("SELECT m.rolname FROM pg_catalog.pg_roles m JOIN pg_catalog.pg_auth_members am ON am.member = m.oid "
               "JOIN pg_catalog.pg_roles g ON g.oid = am.roleid WHERE g.rolname = 'rds_iam' ORDER BY 1 LIMIT 500")


def _pg_try(conn, sql: str, args=None) -> tuple[list | None, str | None, str]:
    """(rows, None, "") or (None, SQLSTATE, first line of the error).  The connection is in autocommit, so a failed
    statement leaves it usable for the next one."""
    import psycopg

    try:
        with conn.cursor() as cur:
            cur.execute(sql, args)
            return cur.fetchall(), None, ""
    except psycopg.Error as exc:
        return None, getattr(exc, "sqlstate", None), str(exc).split("\n")[0][:300]


def _hash_type(value) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "none"
    return text if text in ("md5", "scram-sha-256", "none", "other") else "other"


def _ident(name: str) -> str:
    return '"' + (name or "zs_cbom").replace('"', '""') + '"'


class PgRoleHashes:
    """Exactly one outcome for the role password-hash check: types (with the source that gave them) or one gap."""

    def __init__(self) -> None:
        self.types: dict[str, str] | None = None
        self.source: str | None = None
        self.iam_roles: list[str] = []
        self.server_type = "self-managed"
        self.gap: tuple[str, str] | None = None  # (coverage status, detail naming the fix)


def pg_role_hashes(conn, extensions: set[str], login: str, database: str) -> PgRoleHashes:
    """Password hash TYPES of login roles (never the hashes), trying in order: pg_authid (superuser) -> the
    DBA-installed SECURITY DEFINER function public.zs_role_password_types() -> rds_tools on Amazon RDS/Aurora -> one
    coverage gap naming the fix for this kind of server."""
    out = PgRoleHashes()
    service = {str(r[0]) for r in (_pg_try(conn, _PG_SERVICE_ROLES_SQL)[0] or [])}
    if service & {"rdsadmin", "rds_superuser"}:
        out.server_type = "rds"
    elif "cloudsqlsuperuser" in service:
        out.server_type = "cloudsql"
    elif service & {"azure_pg_admin", "azuresu"}:
        out.server_type = "azure"
    if "rds_iam" in service:
        out.iam_roles = [str(r[0]) for r in (_pg_try(conn, _PG_IAM_SQL)[0] or [])]

    def done(rows, source: str) -> PgRoleHashes:
        out.types = {str(r[0]): _hash_type(r[1]) for r in rows}
        out.source = source
        return out

    rows, state, message = _pg_try(conn, _PG_AUTHID_SQL)
    if rows is not None:
        return done(rows, "pg_authid")
    if state != "42501":
        out.gap = ("error", f"reading pg_authid failed ({state}): {message}")
        return out
    rows, fn_state, message = _pg_try(conn, _PG_FUNCTION_SQL)
    if rows is not None:
        return done(rows, "zs_role_password_types")
    if fn_state not in ("42501", "42883", "3F000"):
        out.gap = ("error", f"{PG_HASH_FUNCTION}() failed ({fn_state}): {message}")
        return out
    rds_state = None
    if "rds_tools" in extensions:
        rows, rds_state, message = _pg_try(conn, _PG_RDS_SQL)
        if rows is not None:
            return done(rows, "rds_tools")
        if rds_state not in ("42501", "42883", "3F000"):
            out.gap = ("error", f"rds_tools.role_password_encryption_type() failed ({rds_state}): {message}")
            return out
    who, db = _ident(login), _ident(database)
    if fn_state == "42501":  # the function is installed, this login may not call it
        fix = f"GRANT EXECUTE ON FUNCTION {PG_HASH_FUNCTION}() TO {who};  (as a superuser, in database {db})"
    elif out.server_type == "rds":
        # Measured on RDS for PostgreSQL 16: the function's ACL is {rds_superuser=X/rds_superuser}, so creating the
        # extension is not enough; the login also needs EXECUTE on it.
        grant = f"GRANT EXECUTE ON FUNCTION rds_tools.role_password_encryption_type() TO {who};"
        fix = (f"CREATE EXTENSION IF NOT EXISTS rds_tools; {grant}  (as the master user, in database {db}); "
               "ZeroShield then reads rds_tools.role_password_encryption_type()") if "rds_tools" not in extensions \
            else f"{grant}  (as the master user)"
    elif out.server_type in ("cloudsql", "azure"):
        out.gap = ("not_supported", "this managed PostgreSQL lets no login read password hash types; set "
                                    "password_encryption = scram-sha-256 and have every user reset their password")
        return out
    else:
        fix = (f"as a superuser in database {db}, run the {PG_HASH_FUNCTION}() section of zs-cbom-grant-postgres.sql "
               "(Privilege tab): a SECURITY DEFINER function that returns role names and hash types only")
    out.gap = ("denied", f"password hash types of login roles are readable only by a superuser; fix: {fix}")
    return out


def _strict_mysql():
    """A PyMySQL connection that logs in only inside the TLS it was asked for.  Stock PyMySQL silently continues in
    plain text when a server's greeting leaves out TLS, and answers a switch to the clear-text plugin with the
    password: an impostor could use either to read it (independent review, 2026-10-31)."""
    import pymysql
    from pymysql.constants import CLIENT

    class StrictTLSConnection(pymysql.connections.Connection):
        def _request_authentication(self):
            if self.ssl and not (self.server_capabilities & CLIENT.SSL):
                raise pymysql.err.OperationalError(2026, "the server did not offer TLS on this connection")
            return super()._request_authentication()

        def _process_auth(self, plugin_name, auth_packet):
            if plugin_name == b"mysql_clear_password":
                raise pymysql.err.OperationalError(2059, "the server asked for the clear-text password plugin")
            return super()._process_auth(plugin_name, auth_packet)

    return StrictTLSConnection


def _mysql_connect(ctx, target, config, password, ca: _CaFile, tls: bool):
    ip = checked_target(target, ctx.never_scan)
    port = int(config.get("port") or 3306)
    ssl_arg = None
    if tls:
        sctx = ssl.create_default_context(cafile=ca.path) if ca.path else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        sctx.check_hostname = False
        if not ca.path:
            sctx.verify_mode = ssl.CERT_NONE
        ssl_arg = sctx
    return _strict_mysql()(host=ip, port=port, user=config.get("login"), password=password or "",
                           connect_timeout=10, read_timeout=20, ssl=ssl_arg, autocommit=True)


def _mysql_login(ctx, target, config, password, ca: _CaFile, tls: bool) -> bool:
    """Log in and out once: MySQL resets its count of this node's unfinished connections (max_connect_errors)."""
    try:
        _mysql_connect(ctx, target, config, password, ca, tls).close()
        return True
    except Exception:  # noqa: BLE001  (any failure: the caller stops probing)
        return False


def _mysql(ctx, target, config, password, ca: _CaFile, tls: bool, seen: dict | None = None) -> int:
    import pymysql

    port = int(config.get("port") or 3306)
    try:
        conn = _mysql_connect(ctx, target, config, password, ca, tls)
    except pymysql.err.OperationalError as exc:
        code = exc.args[0] if exc.args else 0
        if code in (2026, 2059) and len(exc.args) > 1 and "the server" in str(exc.args[1]):
            raise DbFail("identity_unverified", f"{exc.args[1]}; the password was not sent") from None
        if code in (1045, 1698):
            raise DbFail("auth_failed", "MySQL refused the login") from None
        if code == 3159:
            raise DbFail("tls_unavailable", "MySQL requires a secure transport") from None
        raise DbFail("unreachable", f"could not connect to MySQL ({code})") from None
    n = 0
    loc = f"{_where(target)}:{port}"
    try:
        def q(sql: str, label: str, args=None):
            try:
                with conn.cursor() as cur:
                    cur.execute(sql, args)
                    return cur.fetchall()
            except pymysql.err.MySQLError as exc:
                ctx.coverage(target.label, f"mysql {label}", "denied" if exc.args and exc.args[0] in (1142, 1044, 1227)
                             else "error", str(exc)[:200])
                return None

        placeholders = ",".join(["%s"] * len(MYSQL_VARIABLES))
        variables = {r[0]: r[1] for r in q(f"SHOW GLOBAL VARIABLES WHERE Variable_name IN ({placeholders})",
                                          "variables", MYSQL_VARIABLES) or []}
        if seen is not None:
            seen.update(variables)
        users = q("SELECT user, host, plugin, ssl_type FROM mysql.user", "users")
        own = {r[0]: r[1] for r in q("SHOW SESSION STATUS WHERE Variable_name IN ('Ssl_version','Ssl_cipher')",
                                     "own connection TLS") or []}
        live = q("SELECT VARIABLE_NAME, VARIABLE_VALUE, count(*) FROM performance_schema.status_by_thread "
                 "WHERE VARIABLE_NAME IN ('Ssl_version','Ssl_cipher') GROUP BY 1, 2", "live connection TLS")
        keyring = q("SELECT PLUGIN_NAME, PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_NAME LIKE 'keyring%'",
                    "keyring plugins")
        encrypted = q("SELECT TABLE_SCHEMA, TABLE_NAME, CREATE_OPTIONS FROM information_schema.TABLES "
                      "WHERE CREATE_OPTIONS LIKE '%ENCRYPTION%' LIMIT 500", "encrypted tables")
        ctx.emit("database_config", target.label, loc, name=f"MySQL {variables.get('version', '')}".strip(), protocol="mysql",
                 facts={"engine": "mysql", "variables": variables,
                        "keyring_plugins": [{"name": r[0], "status": r[1]} for r in keyring or []],
                        "encrypted_tables": [f"{r[0]}.{r[1]}" for r in encrypted or []][:500],
                        "encrypted_tables_visible_only": True})
        n += 1
        ctx.emit("database_tls", target.label, loc, name="MySQL connections", algorithm=own.get("Ssl_cipher") or None,
                 protocol=own.get("Ssl_version") or None,
                 facts={"engine": "mysql", "own_connection": own,
                        "live_connections": [{"variable": r[0], "value": r[1], "count": r[2]} for r in live or []]})
        n += 1
        plugins: dict[str, int] = {}
        for u in users or []:
            plugins[str(u[2])] = plugins.get(str(u[2]), 0) + 1
        ctx.emit("database_user_auth", target.label, f"{loc}#auth", name="MySQL authentication",
                 facts={"engine": "mysql", "plugins": plugins,
                        "users": [{"user": u[0], "host": u[1], "plugin": u[2], "ssl_type": u[3]} for u in (users or [])[:500]]
                        if users is not None else None,
                        "default_authentication_plugin": variables.get("default_authentication_plugin"),
                        "authentication_policy": variables.get("authentication_policy")})
        n += 1
    finally:
        conn.close()
    return n


def _redis(ctx, target, config, password, ca: _CaFile, tls: bool) -> int:
    import redis

    ip = checked_target(target, ctx.never_scan)
    port = int(config.get("port") or 6379)
    kwargs: dict[str, Any] = dict(host=ip, port=port, socket_timeout=10, socket_connect_timeout=5,
                                  username=config.get("login") or None, password=password or None)
    if tls:
        kwargs.update(ssl=True, ssl_cert_reqs="required" if ca.path else "none", ssl_ca_certs=ca.path,
                      ssl_check_hostname=False)
    client = redis.Redis(**kwargs)
    loc = f"{_where(target)}:{port}"
    try:
        try:
            client.ping()
            auth_required = None if password else False
        except redis.exceptions.AuthenticationError:
            raise DbFail("auth_failed", "Redis refused the login") from None
        except redis.exceptions.ResponseError as exc:
            if "NOAUTH" in str(exc):
                raise DbFail("auth_failed", "Redis requires AUTH; store the read-only ACL user's password") from None
            raise DbFail("error", "Redis refused PING") from None
        except redis.exceptions.ConnectionError:
            raise DbFail("unreachable", "could not connect to Redis") from None
        info = {}
        try:
            server = client.info("server")
            info = {k: server.get(k) for k in ("redis_version", "redis_mode", "os", "ssl_version") if k in server}
        except redis.exceptions.RedisError as exc:
            ctx.coverage(target.label, "redis INFO", "denied", str(exc)[:200])
        settings = {}
        for name in REDIS_TLS_SETTINGS:
            try:
                settings.update(client.config_get(name))
            except redis.exceptions.RedisError as exc:
                ctx.coverage(target.label, "redis CONFIG GET", "denied", str(exc)[:200])
                break
        whoami = None
        try:
            whoami = client.execute_command("ACL", "WHOAMI")
        except redis.exceptions.RedisError:
            pass
        ctx.emit("database_config", target.label, loc, name=f"Redis {info.get('redis_version', '')}".strip(), protocol="redis",
                 facts={"engine": "redis", "info": info, "tls_settings": settings, "tls": tls,
                        "auth_required": auth_required, "acl_user": whoami if isinstance(whoami, str) else
                        (whoami.decode() if isinstance(whoami, bytes) else None)})
        return 1
    finally:
        client.close()


def _mongodb(ctx, target, config, password, ca: _CaFile, tls: bool) -> int:
    import pymongo

    ip = checked_target(target, ctx.never_scan)
    port = int(config.get("port") or 27017)
    kwargs: dict[str, Any] = dict(host=ip, port=port, directConnection=True, serverSelectionTimeoutMS=8000,
                                  connectTimeoutMS=5000, socketTimeoutMS=15000, tls=tls)
    if tls:
        if ca.path:
            kwargs["tlsCAFile"] = ca.path
            kwargs["tlsAllowInvalidHostnames"] = True
        else:
            kwargs["tlsAllowInvalidCertificates"] = True
    if config.get("login"):
        kwargs.update(username=config["login"], password=password or "",
                      authSource=config.get("database_name") or "admin")
    client = pymongo.MongoClient(**kwargs)
    loc = f"{_where(target)}:{port}"
    try:
        try:
            build = client.admin.command("buildInfo")
        except pymongo.errors.OperationFailure as exc:
            if exc.code in (18, 13):
                raise DbFail("auth_failed", "MongoDB refused the login") from None
            raise DbFail("error", "MongoDB refused buildInfo") from None
        except pymongo.errors.PyMongoError:
            raise DbFail("unreachable", "could not connect to MongoDB") from None
        facts: dict[str, Any] = {"engine": "mongodb", "version": build.get("version"), "tls": tls,
                                 "openssl": (build.get("openssl") or {}), "tls_verified": bool(ca.path)}
        try:
            opts = client.admin.command("getCmdLineOpts").get("parsed") or {}
            picked = {}
            for path in MONGO_OPTS:
                node: Any = opts
                for part in path:
                    node = node.get(part) if isinstance(node, dict) else None
                if node is not None:
                    picked[".".join(path)] = node
            facts["options"] = picked
            facts["auth_required"] = bool(picked.get("security.authorization") == "enabled")
        except pymongo.errors.OperationFailure as exc:
            ctx.coverage(target.label, "mongodb getCmdLineOpts", "denied", str(exc)[:200])
        ctx.emit("database_config", target.label, loc, name=f"MongoDB {facts.get('version') or ''}".strip(),
                 protocol="mongodb", facts=facts)
        return 1
    finally:
        client.close()


# ----------------------------------------------------------------------------- entry points
def _one(ctx: JobContext, config: dict, secrets: dict, scope: dict | None = None
         ) -> tuple[Target, str, str | None, int]:
    engine = config.get("engine")
    if engine not in SUPPORTED:
        raise ConfigError(f"{engine} is not collected by this scan node version")
    host = str(config.get("host") or "").strip()
    label = host.strip("[]").lower().rstrip(".")  # an IPv6 literal may come in brackets
    try:  # the network gate: resolve once, apply never-scan, connect only to the checked address
        addresses = resolve_checked(host, ctx.never_scan)
        # a name keeps every address it resolved to: each connection re-checks all of them (checked_target)
        target = Target(label, addresses[0], addresses=() if is_ip(label) else tuple(addresses))
    except Blocked as exc:
        return Target(label, None), "skipped_never_scan", str(exc), 0
    except OSError as exc:
        return Target(label, None), "unreachable", f"could not resolve {label}: {exc.__class__.__name__}", 0
    port = int(config.get("port") or DEFAULT_PORTS[engine])
    if engine == "mssql":  # TLS travels inside TDS packets: the engine module reads it before any login
        from zs_scan_node.collectors import mssql

        return (target, *mssql.collect_target(ctx, target, port, config, lambda: _password(ctx, config, secrets),
                                              _where(target)))
    require_tls = bool(config.get("require_tls", True))
    try:
        tls, pre = _tls_offered(checked_target(target, ctx.never_scan), port, engine, ctx.never_scan)
    except Blocked as exc:
        return target, "skipped_never_scan", str(exc), 0
    except T.ProbeError as exc:
        return target, exc.code, exc.detail, 0
    n = 0
    tls_facts: dict[str, Any] = {"engine": engine, "tls_offered": tls, **pre}
    # MySQL's accepted versions and suites are read after its login (max_connect_errors, mysql_accepted_tls)
    mysql_later = engine == "mysql" and tls
    if tls:
        try:
            hs, n = _server_tls(ctx, target, port, engine, scope, enumerate_now=not mysql_later)
        except Blocked as exc:
            return target, "skipped_never_scan", str(exc), 0
        except DbFail as fail:
            return target, fail.status, fail.error, 0
        tls_facts.update(hs)
    if mysql_later:
        tls_facts["enumeration"] = {"complete": False, "not_complete": [
            "MySQL: versions and suites are probed only after a successful login (each probe counts against "
            "max_connect_errors until a login resets it)"]}

    def emit_tls() -> int:
        E.fit_facts(tls_facts, MAX_FACTS_BYTES)
        ctx.emit("tls_endpoint", target.label, f"{_where(target)}:{port}", name=f"{engine} {target.ip}:{port}",
                 algorithm=tls_facts.get("negotiated_cipher"), protocol=tls_facts.get("negotiated_version") or engine,
                 facts={**tls_facts, "service": engine, "tls": tls, "plaintext_only": not tls})
        return 1

    if not mysql_later:
        n += emit_tls()
    status, error, added = _login_and_read(ctx, target, config, secrets, engine, port, tls, require_tls, tls_facts,
                                           scope)
    if mysql_later:
        added += emit_tls()
    return target, status, error, n + added


def _login_and_read(ctx: JobContext, target: Target, config: dict, secrets: dict, engine: str, port: int, tls: bool,
                    require_tls: bool, tls_facts: dict[str, Any], scope: dict | None) -> tuple[str, str | None, int]:
    n = 0
    if require_tls and not tls:
        return "tls_unavailable", "the server does not offer TLS; the password was not sent", n
    password = _password(ctx, config, secrets)
    if password and engine in ("mysql", "redis") and not (tls and config.get("ca_pem")):
        # MySQL full authentication and Redis AUTH hand the password to whatever answers; only a server proven by
        # the CA certificate may receive it.  (PostgreSQL is held to SCRAM instead; MongoDB uses SCRAM.)
        return "identity_unverified", ("the server's identity cannot be checked without its CA certificate "
                                       "and TLS; the password was not sent"), n
    ca = _CaFile(config.get("ca_pem"))
    try:
        if engine == "postgres":
            n += _postgres(ctx, target, config, password, ca)
        elif engine == "mysql":
            variables: dict[str, Any] = {}
            n += _mysql(ctx, target, config, password, ca, tls, variables)
            if tls:  # logged in: probe, in batches each closed by a login (the count of unfinished connections)
                tls_facts.update(mysql_accepted_tls(
                    ctx, target, port, tls_facts.get("negotiated_version"),
                    R.suite_code(tls_facts.get("negotiated_cipher")), variables.get("max_connect_errors"),
                    lambda: _mysql_login(ctx, target, config, password, ca, tls), scope))
        elif engine == "redis":
            n += _redis(ctx, target, config, password, ca, tls)
        elif engine == "oracle":
            from zs_scan_node.collectors import oracle

            try:
                n += oracle.collect_login(ctx, target, port, config, password or "", tls, f"{_where(target)}:{port}")
            except oracle.OracleFail as fail:
                raise DbFail(fail.status, fail.error) from None
        else:
            n += _mongodb(ctx, target, config, password, ca, tls)
    except DbFail as fail:
        return fail.status, fail.error, n
    except Blocked as exc:  # added to never-scan while this target was being read
        return "skipped_never_scan", str(exc), n
    finally:
        ca.close()
    return "ok", None, n


def collect(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    started = time.monotonic()
    target, status, error, n = _one(ctx, config, secrets, scope)
    ctx.outcome(target.label, status, error, started=started, assets=n)
    return f"{config.get('engine')} {target.label}: {status}"


def test(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    started = time.monotonic()
    try:
        target, status, error, n = _one(ctx, config, secrets, scope)
    except ConfigError as exc:
        ctx.samples.append({"target": str(config.get("host")), "status": "error", "reachable": None, "login": False,
                            "privilege": None, "note": str(exc)})
        return str(exc)
    reachable = status not in ("unreachable", "refused", "timeout", "no_route")
    ctx.samples.append({"target": target.label, "status": "ready" if status == "ok" else status, "reachable": reachable,
                        "login": status == "ok", "privilege": None,
                        "note": error or f"{n} facts read in {int(time.monotonic() - started)} s"})
    return error or "ready"
