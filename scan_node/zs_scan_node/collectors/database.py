"""Databases: PostgreSQL, MySQL, Redis and MongoDB with a read-only login.

Before any credential is sent the node checks whether the server offers TLS (Postgres SSLRequest, MySQL greeting
CLIENT_SSL flag, a raw ClientHello for Redis/MongoDB).  With ``require_tls`` and no TLS the target is
``tls_unavailable`` and the password is never sent.  Only fixed queries and fixed setting names are read; nothing
that holds a secret (Redis ``requirepass``/``tls-key-file-pass``, MySQL ``authentication_string``, Postgres password
hashes) is ever selected.  Postgres password hash *types* are computed in SQL so no hash leaves the database.
"""
from __future__ import annotations

import os
import shutil
import ssl
import tempfile
import time
from typing import Any

from zs_scan_node import tlsprobe as T
from zs_scan_node.certparse import cert_facts, load_certs
from zs_scan_node.collectors import ConfigError
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import Target, expand_targets

SUPPORTED = ("postgres", "mysql", "redis", "mongodb")
REDIS_TLS_SETTINGS = ["port", "tls-port", "tls-protocols", "tls-ciphers", "tls-ciphersuites", "tls-auth-clients",
                      "tls-replication", "tls-cluster", "tls-prefer-server-ciphers", "tls-session-caching"]
MYSQL_VARIABLES = ["version", "have_ssl", "tls_version", "ssl_cipher", "tls_ciphersuites", "require_secure_transport",
                   "default_authentication_plugin", "authentication_policy", "default_table_encryption",
                   "innodb_redo_log_encrypt", "innodb_undo_log_encrypt", "binlog_encryption", "admin_tls_version",
                   "ssl_fips_mode", "table_encryption_privilege_check"]
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


def _tls_offered(ip: str, port: int, engine: str) -> tuple[bool, dict]:
    """Does the server offer TLS?  Uses the engine's own upgrade or a raw ClientHello."""
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


def _server_tls(ctx: JobContext, target: Target, port: int, engine: str) -> tuple[dict, int]:
    """Full handshake details + certificate for the database port."""
    proto = {"postgres": "starttls-postgres", "mysql": "starttls-mysql"}.get(engine, "tls")
    fh = T.s_client(target.ip, port, proto, None) if T.have_openssl() else T.python_handshake(target.ip, port, proto, None)
    facts = {"negotiated_version": fh.version, "negotiated_cipher": fh.cipher, "negotiated_group": fh.group,
             "peer_signature_type": fh.peer_sig_type}
    n = 0
    for i, der in enumerate(fh.certs_der[:5]):
        for cert in load_certs(der):
            f = cert_facts(cert, "tls")
            ctx.emit("certificate", target.label, f"{target.ip}:{port}#chain[{i}]", name=f.get("subject", ""),
                     algorithm=f.get("key_alg"), key_size=f.get("key_size"), facts={**f, "chain_index": i, "role": engine})
            n += 1
    return facts, n


# ----------------------------------------------------------------------------- engines
def _postgres(ctx, target, config, password, ca: _CaFile) -> int:
    import psycopg

    port = int(config.get("port") or 5432)
    require_tls = bool(config.get("require_tls", True))
    verified = bool(ca.path) and require_tls  # only verify-ca proves the server; "prefer" never checks the CA
    sslmode = ("verify-ca" if verified else "require") if require_tls else "prefer"
    kwargs = dict(host=target.label, hostaddr=target.ip, port=port, user=config.get("login"), password=password or None,
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
    loc = f"{target.ip}:{port}"
    try:
        def q(sql: str, label: str, args=None):
            try:
                with conn.cursor() as cur:
                    cur.execute(sql, args)
                    return cur.fetchall()
            except psycopg.Error as exc:
                ctx.coverage(target.label, f"postgres {label}", "denied" if "permission" in str(exc) else "error",
                             str(exc).split("\n")[0][:200])
                return None

        settings = {k: v for k, v in (q("SELECT name, setting FROM pg_settings WHERE name = ANY(%s)", "settings",
                                        [PG_SETTINGS]) or [])}
        own = q("SELECT version, cipher, bits FROM pg_stat_ssl WHERE pid = pg_backend_pid()", "own connection TLS")
        live = q("SELECT s.ssl, s.version, s.cipher, count(*) FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid) "
                 "WHERE a.backend_type = 'client backend' GROUP BY 1, 2, 3", "live connection TLS")
        hba = q("SELECT type, database, user_name, address, auth_method FROM pg_hba_file_rules LIMIT 500", "HBA rules")
        roles = q("SELECT rolname, CASE WHEN rolpassword IS NULL THEN 'none' WHEN rolpassword LIKE 'md5%' THEN 'md5' "
                  "WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'scram-sha-256' ELSE 'other' END "
                  "FROM pg_authid WHERE rolcanlogin", "role password hash types")
        exts = q("SELECT extname, extversion FROM pg_extension", "extensions")
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
                        "role_hash_types": {r[0]: r[1] for r in roles or []} if roles is not None else None})
        n += 1
    finally:
        conn.close()
    return n


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


def _mysql(ctx, target, config, password, ca: _CaFile, tls: bool) -> int:
    import pymysql

    port = int(config.get("port") or 3306)
    ssl_arg = None
    if tls:
        sctx = ssl.create_default_context(cafile=ca.path) if ca.path else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        sctx.check_hostname = False
        if not ca.path:
            sctx.verify_mode = ssl.CERT_NONE
        ssl_arg = sctx
    try:
        conn = _strict_mysql()(host=target.ip, port=port, user=config.get("login"), password=password or "",
                               connect_timeout=10, read_timeout=20, ssl=ssl_arg, autocommit=True)
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
    loc = f"{target.ip}:{port}"
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

    port = int(config.get("port") or 6379)
    kwargs: dict[str, Any] = dict(host=target.ip, port=port, socket_timeout=10, socket_connect_timeout=5,
                                  username=config.get("login") or None, password=password or None)
    if tls:
        kwargs.update(ssl=True, ssl_cert_reqs="required" if ca.path else "none", ssl_ca_certs=ca.path,
                      ssl_check_hostname=False)
    client = redis.Redis(**kwargs)
    loc = f"{target.ip}:{port}"
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

    port = int(config.get("port") or 27017)
    kwargs: dict[str, Any] = dict(host=target.ip, port=port, directConnection=True, serverSelectionTimeoutMS=8000,
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
    loc = f"{target.ip}:{port}"
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
def _one(ctx: JobContext, config: dict, secrets: dict) -> tuple[Target, str, str | None, int]:
    engine = config.get("engine")
    if engine not in SUPPORTED:
        raise ConfigError(f"{engine} is not collected by this scan node version")
    host = str(config.get("host") or "")
    targets, skipped = expand_targets([host], ctx.never_scan)
    if skipped or not targets:
        return Target(host, None), "skipped_never_scan", None, 0
    target = targets[0]
    if target.ip is None:
        return target, "unreachable", target.error, 0
    port = int(config.get("port") or {"postgres": 5432, "mysql": 3306, "redis": 6379, "mongodb": 27017}[engine])
    require_tls = bool(config.get("require_tls", True))
    try:
        tls, pre = _tls_offered(target.ip, port, engine)
    except T.ProbeError as exc:
        return target, exc.code, exc.detail, 0
    n = 0
    tls_facts: dict[str, Any] = {"engine": engine, "tls_offered": tls, **pre}
    if tls:
        hs, n = _server_tls(ctx, target, port, engine)
        tls_facts.update(hs)
    ctx.emit("tls_endpoint", target.label, f"{target.ip}:{port}", name=f"{engine} {target.ip}:{port}",
             algorithm=tls_facts.get("negotiated_cipher"), protocol=tls_facts.get("negotiated_version") or engine,
             facts={**tls_facts, "service": engine, "tls": tls, "plaintext_only": not tls})
    n += 1
    if require_tls and not tls:
        return target, "tls_unavailable", "the server does not offer TLS; the password was not sent", n
    password = _password(ctx, config, secrets)
    if password and engine in ("mysql", "redis") and not (tls and config.get("ca_pem")):
        # MySQL full authentication and Redis AUTH hand the password to whatever answers; only a server proven by
        # the CA certificate may receive it.  (PostgreSQL is held to SCRAM instead; MongoDB uses SCRAM.)
        return target, "identity_unverified", ("the server's identity cannot be checked without its CA certificate "
                                               "and TLS; the password was not sent"), n
    ca = _CaFile(config.get("ca_pem"))
    try:
        if engine == "postgres":
            n += _postgres(ctx, target, config, password, ca)
        elif engine == "mysql":
            n += _mysql(ctx, target, config, password, ca, tls)
        elif engine == "redis":
            n += _redis(ctx, target, config, password, ca, tls)
        else:
            n += _mongodb(ctx, target, config, password, ca, tls)
    except DbFail as fail:
        return target, fail.status, fail.error, n
    finally:
        ca.close()
    return target, "ok", None, n


def collect(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    started = time.monotonic()
    target, status, error, n = _one(ctx, config, secrets)
    ctx.outcome(target.label, status, error, started=started, assets=n)
    return f"{config.get('engine')} {target.label}: {status}"


def test(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    started = time.monotonic()
    try:
        target, status, error, n = _one(ctx, config, secrets)
    except ConfigError as exc:
        ctx.samples.append({"target": str(config.get("host")), "status": "error", "reachable": None, "login": False,
                            "privilege": None, "note": str(exc)})
        return str(exc)
    reachable = status not in ("unreachable", "refused", "timeout", "no_route")
    ctx.samples.append({"target": target.label, "status": "ready" if status == "ok" else status, "reachable": reachable,
                        "login": status == "ok", "privilege": None,
                        "note": error or f"{n} facts read in {int(time.monotonic() - started)} s"})
    return error or "ready"
