"""Database, cache, search, disk, and SQL encryption facts.

Readers are ``pg_transport``, ``redis_transport``, ``cryptsetup`` and
``sql_labels``. Signals live on ``BasisEntry``. No model fields are added.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from types import MappingProxyType

from aibom.cbom.posture.directives import (
    DirectiveFile,
    parse_crypttab,
    parse_mysql_cnf,
    parse_pg_hba,
    parse_postgresql,
    parse_redis,
    split_words,
)
from aibom.cbom.posture.findings import derive_findings
from aibom.cbom.posture.model import BasisEntry, EncryptionFact, fact_id, path_context
from aibom.cbom.posture.sqllabels import label_sql
from aibom.cbom.posture.verdict import LayerResult, resource_verdict
from aibom.cbom.posture.yamlsafe import flatten_dotted, parse_yaml

_ENABLE = frozenset({"on", "1", "force", "true", "yes"})
_DISABLE = frozenset({"off", "0", "false", "no"})
_HBA_TYPES = frozenset({"local", "host", "hostssl", "hostnossl", "hostgssenc"})
_PLAIN = frozenset({"host", "hostnossl"})
_TLS_ONLY = frozenset({"hostssl", "hostgssenc"})
_FILE_BACKED = ("keyring_file", "keyring_encrypted_file", "file_key_management")
_EPHEMERAL = frozenset({"/dev/urandom", "/dev/random", "/dev/hwrng"})
_SCOPE = {
    "innodb_encrypt_tables": "tables",
    "default_table_encryption": "tables",
    "aria_encrypt_tables": "tables",
    "innodb_encrypt_log": "log",
    "binlog_encryption": "binlog",
    "encrypt_binlog": "binlog",
    "encrypt_tmp_files": "temp",
}
_VERBS = frozenset(
    {"luksformat", "luksopen", "open", "create", "plainopen", "tcryptopen"}
)
_LONG = {
    "--cipher": "cipher",
    "--key-size": "size",
    "--hash": "hash",
    "--type": "type",
    "--pbkdf": "pbkdf",
    "--key-file": "key_file",
}
_SHORT = {"-c": "cipher", "-s": "size", "-h": "hash", "-d": "key_file"}
_SQL_LAYER = {
    "pgcrypto_symmetric": "application",
    "pgcrypto_public_key": "application",
}
_UNSEEN = LayerResult("UNKNOWN", "layer_not_observable")
HbaRow = tuple[str, str | None, str, int]


def _bind(
    table: dict[tuple[str, str], str],
    software: str,
    treatment: str,
    names: str,
) -> None:
    for name in names.split():
        table[(software, name)] = treatment


def _settings() -> dict[tuple[str, str], str]:
    table: dict[tuple[str, str], str] = {}
    _bind(table, "postgresql", "layer", "ssl host hostssl hostnossl hostgssenc")
    _bind(
        table,
        "postgresql",
        "protocol_set",
        "ssl_min_protocol_version ssl_max_protocol_version",
    )
    _bind(table, "postgresql", "cipher_list", "ssl_ciphers")
    _bind(
        table,
        "postgresql",
        "attr:prefer_server_ciphers",
        "ssl_prefer_server_ciphers",
    )
    _bind(table, "postgresql", "curves", "ssl_ecdh_curve")
    _bind(table, "postgresql", "dh_file", "ssl_dh_params_file")
    _bind(table, "postgresql", "cert_link", "ssl_cert_file")
    _bind(table, "postgresql", "attr:key_file_declared", "ssl_key_file")
    for software in ("mysql", "mariadb"):
        _bind(table, software, "layer", "require_secure_transport skip_ssl ssl")
        _bind(table, software, "protocol_set", "tls_version")
        _bind(table, software, "cipher_list", "ssl_cipher")
        _bind(table, software, "attr:ca_declared", "ssl_ca")
        _bind(table, software, "cert_link", "ssl_cert")
        _bind(table, software, "attr:key_file_declared", "ssl_key")
    _bind(
        table,
        "mysql",
        "layer",
        "innodb_encrypt_tables default_table_encryption innodb_encrypt_log "
        "binlog_encryption",
    )
    _bind(
        table,
        "mysql",
        "evidence",
        "early-plugin-load early_plugin_load plugin_load_add plugin-load-add keyring_*",
    )
    _bind(
        table,
        "mariadb",
        "layer",
        "innodb_encrypt_tables aria_encrypt_tables innodb_encrypt_log "
        "encrypt_binlog encrypt_tmp_files",
    )
    _bind(table, "mariadb", "evidence", "plugin_load_add file_key_management")
    _bind(
        table,
        "mongodb",
        "layer",
        "net.tls.mode net.ssl.mode security.enableEncryption",
    )
    _bind(
        table,
        "mongodb",
        "protocol_set",
        "net.tls.disabledProtocols net.ssl.disabledProtocols",
    )
    _bind(
        table,
        "mongodb",
        "client_auth",
        "net.tls.allowConnectionsWithoutCertificates "
        "net.ssl.allowConnectionsWithoutCertificates",
    )
    _bind(
        table,
        "mongodb",
        "verification",
        "net.tls.allowInvalidCertificates net.tls.allowInvalidHostnames "
        "net.ssl.allowInvalidCertificates net.ssl.allowInvalidHostnames",
    )
    _bind(table, "mongodb", "attr:ca_declared", "net.tls.CAFile net.ssl.CAFile")
    _bind(
        table,
        "mongodb",
        "cert_link",
        "net.tls.certificateKeyFile net.ssl.certificateKeyFile",
    )
    _bind(
        table,
        "mongodb",
        "attr:encryption_cipher_mode",
        "security.encryptionCipherMode",
    )
    _bind(table, "mongodb", "evidence", "security.encryptionKeyFile security.kmip")
    _bind(table, "elasticsearch", "layer", "xpack.security.enabled")
    for channel in ("http", "transport"):
        root = f"xpack.security.{channel}.ssl"
        _bind(table, "elasticsearch", "layer", f"{root}.enabled")
        _bind(table, "elasticsearch", "protocol_set", f"{root}.supported_protocols")
        _bind(table, "elasticsearch", "cipher_list", f"{root}.cipher_suites")
        _bind(table, "elasticsearch", "verification", f"{root}.verification_mode")
        _bind(table, "elasticsearch", "client_auth", f"{root}.client_authentication")
    _bind(table, "redis", "layer", "port tls-port")
    _bind(table, "redis", "protocol_set", "tls-protocols")
    _bind(table, "redis", "cipher_list", "tls-ciphers tls-ciphersuites")
    _bind(table, "redis", "attr:prefer_server_ciphers", "tls-prefer-server-ciphers")
    _bind(table, "redis", "client_auth", "tls-auth-clients")
    _bind(table, "redis", "attr:tls_replication", "tls-replication")
    _bind(table, "redis", "attr:tls_cluster", "tls-cluster")
    return table


DB_SETTINGS = MappingProxyType(_settings())


def _loopback(address: str | None) -> bool:
    if not address:
        return False
    token = address.casefold().strip()
    host = token.split("%", 1)[0].split("/", 1)[0]
    if host in {"localhost", "::1"} or token in {"::1/128", "127.0.0.0/8"}:
        return True
    return host.startswith("127.")


def _plaintext(row: HbaRow) -> bool:
    kind, address, method, _line = row
    return kind in _PLAIN and method != "reject" and not _loopback(address)


def _tls_only(row: HbaRow) -> bool:
    kind, address, method, _line = row
    return kind in _TLS_ONLY and method != "reject" and not _loopback(address)


def pg_transport(ssl: str | None, hba: tuple[HbaRow, ...] | None) -> LayerResult:
    """PostgreSQL transport. A reject, local, or loopback record is not plaintext."""
    if ssl is not None and ssl.startswith("unresolved:"):
        return LayerResult("UNKNOWN", ssl.split(":", 1)[1] or "unresolved_expression")
    if ssl == "off":
        return LayerResult("NOT_ENCRYPTED")
    if hba is not None and any(_plaintext(row) for row in hba):
        return LayerResult("NOT_ENCRYPTED")
    if hba is not None and ssl == "on" and any(_tls_only(row) for row in hba):
        return LayerResult("ENCRYPTED_DECLARED")
    return _UNSEEN


def redis_transport(
    port: int | None,
    tls_port: int | None,
    bind: tuple[str, ...] | None,
) -> LayerResult:
    """Redis transport. Loopback plaintext does not count as exposure."""
    tls = tls_port is not None and tls_port > 0
    if port == 0 and tls:
        return LayerResult("ENCRYPTED_DECLARED")
    if port is None or bind is None:
        return _UNSEEN
    remote = any(not _loopback(item) for item in bind)
    if port > 0 and remote:
        return LayerResult("NOT_ENCRYPTED")
    if tls and port > 0 and bind and not remote:
        return LayerResult("ENCRYPTED_DECLARED")
    return _UNSEEN


def _codes(
    verdict: str, *, at_rest: bool, in_transit: bool, weak: bool, verify: bool
) -> tuple[str, ...]:
    holder = type("_Fact", (), {"verdict": verdict})()
    return derive_findings(
        holder,
        {
            "at_rest": at_rest,
            "in_transit": in_transit,
            "AT_REST_ENCRYPTION_WEAK": weak,
            "TLS_VERIFICATION_DISABLED": verify,
        },
    )


def _fact(
    *,
    kind: str,
    native_type: str,
    address: str,
    path: str,
    line: int,
    form: str,
    layers: dict[str, LayerResult],
    basis: list[BasisEntry],
    key_management: str = "unspecified",
    weak: bool = False,
    verify: bool = False,
    identity: str | None = None,
) -> EncryptionFact:
    """``identity`` replaces ``address`` in the fact id when the address carries a line number."""
    shown = {name: item.verdict for name, item in layers.items()}
    verdict = resource_verdict(shown, transport_only=False) or "UNKNOWN"
    reason = None
    if verdict == "UNKNOWN":
        reason = next(
            (
                item.reason
                for item in layers.values()
                if item.verdict == "UNKNOWN" and item.reason
            ),
            "layer_not_observable",
        )
    return EncryptionFact(
        id=fact_id(kind, "self_hosted", native_type, identity or address, path),
        kind=kind,
        provider="self_hosted",
        native_type=native_type,
        address=address,
        path=path,
        line=line if line > 0 else 1,
        format=form,
        layers=shown,
        verdict=verdict,
        basis=tuple(basis[:40]),
        key_management=key_management,
        unknown_reason=reason,
        path_context=path_context(path),
        finding_codes=_codes(
            verdict,
            at_rest=any(
                name != "transport" and item.verdict == "NOT_ENCRYPTED"
                for name, item in layers.items()
            ),
            in_transit=layers.get("transport") is not None
            and layers["transport"].verdict == "NOT_ENCRYPTED",
            weak=weak,
            verify=verify,
        ),
    )


def _mask(token: str) -> bool:
    parts = token.split(".")
    return len(parts) == 4 and all(part.isdigit() for part in parts)


def _hba_rows(doc: DirectiveFile) -> tuple[HbaRow, ...]:
    rows: list[HbaRow] = []
    for entry in doc.entries:
        kind = entry.name.casefold()
        if kind not in _HBA_TYPES:
            continue
        if kind == "local":
            method = entry.args[-1].casefold() if entry.args else ""
            rows.append((kind, None, method, entry.line))
            continue
        method = entry.args[-1].casefold() if entry.args else ""
        address = entry.args[2] if len(entry.args) >= 3 else None
        if len(entry.args) >= 5 and _mask(entry.args[3]):
            method = entry.args[4].casefold()
        rows.append((kind, address, method, entry.line))
    return tuple(rows)


def _ssl_of(doc: DirectiveFile | None) -> str | None:
    if doc is None:
        return None
    args = doc.lookup("ssl")
    if not args:
        return None
    raw = args[0].strip()
    if "$" in raw:
        return "unresolved:unresolved_expression"
    value = raw.casefold()
    if value in _ENABLE:
        return "on"
    if value in _DISABLE:
        return "off"
    return "unresolved:unresolved_expression"


def _preload_hit(names: tuple[str, ...]) -> bool:
    if not names:
        return False
    from aibom.cbom.posture.defaults import load_registry

    try:
        rows = load_registry().rows
    except Exception:
        return False
    known: set[str] = set()
    for row in rows:
        if "shared_preload_libraries" not in row.type:
            continue
        known.add(row.attribute.casefold())
        known.add(row.documented_default.casefold())
    return any(name.casefold() in known for name in names)


def _pg_database(doc: DirectiveFile | None) -> LayerResult:
    if doc is None:
        return _UNSEEN
    args = doc.lookup("shared_preload_libraries")
    if not args:
        return _UNSEEN
    names = tuple(
        part.strip()
        for part in " ".join(args).replace(",", " ").split()
        if part.strip()
    )
    if _preload_hit(names):
        return LayerResult("ENCRYPTED_DECLARED")
    return _UNSEEN


def _pg_notes(
    ssl: str | None,
    rows: tuple[HbaRow, ...] | None,
    hba_path: str | None,
) -> list[BasisEntry]:
    notes: list[BasisEntry] = []
    if ssl is None:
        notes.append(BasisEntry("ssl", None, "layer_not_observable"))
    elif ssl.startswith("unresolved:"):
        notes.append(BasisEntry("ssl", None, ssl.split(":", 1)[1]))
    else:
        notes.append(BasisEntry("ssl", ssl))
    if rows is None:
        notes.append(BasisEntry("pg_hba", "absent", "layer_not_observable"))
        return notes
    notes.append(BasisEntry("hba_path", hba_path or "pg_hba.conf"))
    plain = next((row for row in rows if _plaintext(row)), None)
    if plain is not None:
        notes.append(BasisEntry("pg_hba_line", str(plain[3])))
    elif not any(_tls_only(row) for row in rows):
        notes.append(
            BasisEntry("pg_hba_scope", "no_remote_tls", "layer_not_observable")
        )
    return notes


_TLS_RANK = ("SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")


def _protocol_floor(
    pairs: list[tuple[str, str]], names: tuple[str, ...]
) -> BasisEntry | None:
    raw = next(
        (
            value
            for name, value in pairs
            if name.casefold() in names and value
        ),
        None,
    )
    if raw is None:
        return None
    allowed = set(_TLS_RANK)
    found = [
        part.strip().strip("'\"")
        for part in raw.replace(",", " ").split()
        if part.strip().strip("'\"") in allowed
    ]
    if not found:
        return BasisEntry("protocol_min", None, "unresolved_expression")
    rank = {token: index for index, token in enumerate(_TLS_RANK)}
    return BasisEntry("protocol_min", min(found, key=lambda token: rank[token]))


def _cipher_note(pairs: list[tuple[str, str]]) -> BasisEntry | None:
    """Evaluate a PostgreSQL ``ssl_ciphers`` list into IANA suite names."""
    raw = next(
        (value for name, value in pairs if name.casefold() == "ssl_ciphers" and value),
        None,
    )
    if raw is None:
        return None
    from aibom.cbom.posture.ciphers import evaluate_cipher_list
    from aibom.cbom.posture.defaults import load_registry

    result = evaluate_cipher_list(raw, load_registry())
    names = result.explicit or result.suites
    if not names:
        if result.unresolved:
            return BasisEntry("cipher_suite", None, "unresolved_expression")
        return None
    return BasisEntry("cipher_suite", ",".join(names[:8]))


def _known(software: str, pairs: list[tuple[str, str]]) -> list[BasisEntry]:
    return [
        BasisEntry(name, value)
        for name, value in pairs
        if (software, name) in DB_SETTINGS
    ]


def extract_postgresql(
    text: str | None,
    path: str,
    *,
    hba: str | None = None,
    hba_path: str | None = None,
) -> EncryptionFact:
    """One PostgreSQL unit. ``hba is None`` means the directory has no pg_hba.conf."""
    doc = parse_postgresql(text, path=path) if text is not None else None
    ssl = _ssl_of(doc)
    if hba is None:
        rows: tuple[HbaRow, ...] | None = None
    else:
        parsed = parse_pg_hba(hba, path=hba_path or "pg_hba.conf")
        rows = () if parsed is None else _hba_rows(parsed)
    transport = pg_transport(ssl, rows)
    line = 1
    pairs: list[tuple[str, str]] = []
    if doc is not None:
        for entry in doc.entries:
            if entry.name.casefold() == "ssl":
                line = entry.line
            pairs.append((entry.name, " ".join(entry.args)))
    basis = _pg_notes(ssl, rows, hba_path) + _known("postgresql", pairs)
    cipher = _cipher_note(pairs)
    if cipher is not None:
        basis.append(cipher)
    floor = _protocol_floor(pairs, ("ssl_min_protocol_version",))
    if floor is not None:
        basis.append(floor)
    dh_path = next(
        (
            value.strip("'\"")
            for name, value in pairs
            if name.casefold() == "ssl_dh_params_file" and value.strip("'\"")
        ),
        None,
    )
    if dh_path:
        basis.append(BasisEntry("dh_path", dh_path))
    key_file = next(
        (
            value.strip().strip("'\"")
            for name, value in pairs
            if name.casefold() == "ssl_key_file" and value.strip().strip("'\"")
        ),
        None,
    )
    if key_file:
        basis.append(BasisEntry("key_file_declared", key_file))
    prefer = _on_off_value(pairs, "ssl_prefer_server_ciphers")
    if prefer:
        basis.append(BasisEntry("prefer_server_ciphers", prefer))
    return _fact(
        kind="relational_db",
        native_type="postgresql",
        address=path,
        path=path,
        line=line,
        form="db_config",
        layers={
            "database": _pg_database(doc),
            "volume": _UNSEEN,
            "transport": transport,
        },
        basis=basis,
    )


def _server(parent: str | None) -> bool:
    folded = (parent or "").casefold()
    if folded in {"mysqld", "server", "mariadb"}:
        return True
    return folded.startswith("mariadb-") or folded.startswith("mysqld-")


def _mysql_engine(doc: DirectiveFile) -> str:
    for entry in doc.entries:
        parent = (entry.parent or "").casefold()
        name = entry.name.casefold()
        if parent == "mariadb" or parent.startswith("mariadb-"):
            return "mariadb"
        if name in {"aria_encrypt_tables", "encrypt_binlog", "encrypt_tmp_files"}:
            return "mariadb"
    return "mysql"


def _file_keyring(doc: DirectiveFile) -> bool:
    for entry in doc.entries:
        if not _server(entry.parent):
            continue
        blob = f"{entry.name} {' '.join(entry.args)}".casefold().replace("-", "_")
        if any(token in blob for token in _FILE_BACKED):
            return True
    return False


def _mysql_database(doc: DirectiveFile) -> tuple[LayerResult, list[BasisEntry]]:
    enabled: list[str] = []
    disabled = False
    for entry in doc.entries:
        if not _server(entry.parent):
            continue
        scope = _SCOPE.get(entry.name.casefold())
        if scope is None:
            continue
        value = entry.args[0].casefold() if entry.args else ""
        if value in _ENABLE:
            enabled.append(scope)
        elif value in _DISABLE:
            disabled = True
    notes: list[BasisEntry] = []
    if enabled:
        notes.append(BasisEntry("encrypted_scopes", ",".join(dict.fromkeys(enabled))))
    if enabled and disabled:
        return LayerResult("UNKNOWN", "conflicting_declaration"), notes
    if enabled:
        return LayerResult("ENCRYPTED_DECLARED"), notes
    if disabled:
        return LayerResult("NOT_ENCRYPTED"), notes
    return _UNSEEN, notes


def _mysql_transport(doc: DirectiveFile) -> LayerResult:
    enable = False
    disable = False
    for entry in doc.entries:
        if not _server(entry.parent):
            continue
        name = entry.name.casefold()
        value = entry.args[0].casefold() if entry.args else ""
        if name == "require_secure_transport" and value in _ENABLE:
            enable = True
        elif name == "skip_ssl" or (
            name in {"require_secure_transport", "ssl"} and value in _DISABLE
        ):
            disable = True
    if enable and disable:
        return LayerResult("UNKNOWN", "conflicting_declaration")
    if enable:
        return LayerResult("ENCRYPTED_DECLARED")
    if disable:
        return LayerResult("NOT_ENCRYPTED")
    return _UNSEEN


def extract_mysql(text: str, path: str) -> tuple[EncryptionFact, ...]:
    doc = parse_mysql_cnf(text, path=path)
    if doc is None:
        return ()
    software = _mysql_engine(doc)
    database, notes = _mysql_database(doc)
    weak = _file_keyring(doc)
    if weak:
        notes.append(BasisEntry("custody", "local_file"))
        notes.append(BasisEntry("at_rest_weakness", "local_file_keyring"))
    pairs = [
        (entry.name, " ".join(entry.args))
        for entry in doc.entries
        if _server(entry.parent)
    ]
    floor = _protocol_floor(pairs, ("tls_version",))
    if floor is not None:
        notes.append(floor)
    key_file = next(
        (
            value.strip().strip("'\"")
            for name, value in pairs
            if name.casefold() == "ssl_key" and value.strip().strip("'\"")
        ),
        None,
    )
    if key_file:
        notes.append(BasisEntry("key_file_declared", key_file))
    return (
        _fact(
            kind="relational_db",
            native_type=software,
            address=path,
            path=path,
            line=doc.entries[0].line if doc.entries else 1,
            form="db_config",
            layers={
                "database": database,
                "volume": _UNSEEN,
                "transport": _mysql_transport(doc),
            },
            basis=notes + _known(software, pairs),
            weak=weak,
        ),
    )


def _on_off_value(pairs: list[tuple[str, str]], name: str) -> str | None:
    raw = next(
        (value for key, value in pairs if key.casefold() == name and value),
        None,
    )
    if raw is None:
        return None
    folded = raw.strip().strip("'\"").casefold()
    if folded in {"on", "off", "yes", "no"}:
        return "on" if folded in {"on", "yes"} else "off"
    return None


def _client_word(value: object) -> str | None:
    if value is None:
        return None
    return {"none": "none", "optional": "optional", "required": "required"}.get(
        _show(value).strip().casefold()
    )


def _flag(value: object) -> str | None:
    if isinstance(value, bool):
        return "on" if value else "off"
    if value in {0, 1}:
        return "on" if value == 1 else "off"
    text = str(value).strip().casefold()
    if text in _ENABLE:
        return "on"
    if text in _DISABLE:
        return "off"
    return None


def _yaml(text: str, path: str) -> dict[str, object] | None:
    docs = parse_yaml(text, path=path)
    if not docs or not isinstance(docs[0], dict):
        return None
    flat = flatten_dotted(docs[0])
    return flat if isinstance(flat, dict) else None


def _show(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return ",".join(_show(item) for item in value)
    return str(value)


def _mongo_transport(flat: dict[str, object]) -> LayerResult:
    mode = None
    for key in ("net.tls.mode", "net.ssl.mode"):
        if key in flat:
            mode = _show(flat[key]).casefold()
            break
    if mode is None:
        return _UNSEEN
    if mode == "requiretls":
        return LayerResult("ENCRYPTED_DECLARED")
    if mode in {"disabled", "allowtls", "prefertls"}:
        return LayerResult("NOT_ENCRYPTED")
    return LayerResult("UNKNOWN", "attribute_not_modeled")


def _mongo_database(flat: dict[str, object]) -> LayerResult:
    if "security.enableEncryption" not in flat:
        return _UNSEEN
    flag = _flag(flat["security.enableEncryption"])
    if flag == "on":
        return LayerResult("ENCRYPTED_DECLARED")
    if flag == "off":
        return LayerResult("NOT_ENCRYPTED")
    return LayerResult("UNKNOWN", "attribute_not_modeled")


def extract_mongo(text: str, path: str) -> tuple[EncryptionFact, ...]:
    flat = _yaml(text, path)
    if flat is None:
        return ()
    notes = _known("mongodb", [(key, _show(value)) for key, value in flat.items()])
    weak = "security.encryptionKeyFile" in flat
    managed = "unspecified"
    if weak:
        notes.append(BasisEntry("custody", "local_file"))
        notes.append(BasisEntry("at_rest_weakness", "key_file"))
    if any(key.startswith("security.kmip") for key in flat):
        managed = "customer_managed"
        notes.append(BasisEntry("key_management", "customer_managed"))
    verify = any(
        key in flat and _flag(flat[key]) == "on"
        for key in (
            "net.tls.allowInvalidCertificates",
            "net.tls.allowInvalidHostnames",
            "net.ssl.allowInvalidCertificates",
            "net.ssl.allowInvalidHostnames",
        )
    )
    if verify:
        notes.append(BasisEntry("verification", "disabled"))
    allow = flat.get(
        "net.tls.allowConnectionsWithoutCertificates",
        flat.get("net.ssl.allowConnectionsWithoutCertificates"),
    )
    if _flag(allow) == "on":
        notes.append(BasisEntry("client_auth", "optional"))
    floor = _disabled_protocol_floor(flat)
    if floor is not None:
        notes.append(floor)
    return (
        _fact(
            kind="nosql_db",
            native_type="mongodb",
            address=path,
            path=path,
            line=1,
            form="db_config",
            layers={
                "database": _mongo_database(flat),
                "volume": _UNSEEN,
                "transport": _mongo_transport(flat),
            },
            basis=notes,
            key_management=managed,
            weak=weak,
            verify=verify,
        ),
    )


_MONGO_TLS = (
    ("TLS1_0", "TLSv1"),
    ("TLS1_1", "TLSv1.1"),
    ("TLS1_2", "TLSv1.2"),
    ("TLS1_3", "TLSv1.3"),
)


def _disabled_protocol_floor(flat: dict[str, object]) -> BasisEntry | None:
    """The lowest TLS version MongoDB did not disable."""
    raw = flat.get("net.tls.disabledProtocols", flat.get("net.ssl.disabledProtocols"))
    if raw is None:
        return None
    text = _show(raw).upper().replace(",", " ")
    disabled = set(text.split())
    for token, version in _MONGO_TLS:
        if token not in disabled:
            return BasisEntry("protocol_min", version)
    return BasisEntry("protocol_min", None, "unresolved_expression")


def _elastic_transport(flat: dict[str, object], channel: str) -> LayerResult:
    if _flag(flat.get("xpack.security.enabled")) == "off":
        return LayerResult("NOT_ENCRYPTED")
    key = f"xpack.security.{channel}.ssl.enabled"
    if key not in flat:
        return _UNSEEN
    flag = _flag(flat[key])
    if flag == "on":
        return LayerResult("ENCRYPTED_DECLARED")
    if flag == "off":
        return LayerResult("NOT_ENCRYPTED")
    return LayerResult("UNKNOWN", "attribute_not_modeled")


def extract_elasticsearch(text: str, path: str) -> tuple[EncryptionFact, ...]:
    flat = _yaml(text, path)
    if flat is None:
        return ()
    facts: list[EncryptionFact] = []
    for channel in ("http", "transport"):
        notes = _known(
            "elasticsearch",
            [(key, _show(value)) for key, value in flat.items()],
        )
        mode = flat.get(f"xpack.security.{channel}.ssl.verification_mode")
        verify = isinstance(mode, str) and mode.casefold() == "none"
        if verify:
            notes.append(BasisEntry("verification", "disabled"))
            notes.append(
                BasisEntry(
                    "verification_setting",
                    f"{channel}.ssl.verification_mode",
                )
            )
        auth = _client_word(
            flat.get(f"xpack.security.{channel}.ssl.client_authentication")
        )
        if auth is not None:
            notes.append(BasisEntry("client_auth", auth))
        offered = flat.get(f"xpack.security.{channel}.ssl.supported_protocols")
        if offered is not None:
            floor = _protocol_floor(
                [("supported_protocols", _show(offered))],
                ("supported_protocols",),
            )
            if floor is not None:
                notes.append(floor)
        facts.append(
            _fact(
                kind="search_index",
                native_type="elasticsearch",
                address=f"{path}#{channel}",
                path=path,
                line=1,
                form="db_config",
                layers={
                    "database": _UNSEEN,
                    "volume": _UNSEEN,
                    "transport": _elastic_transport(flat, channel),
                },
                basis=notes,
                verify=verify,
            )
        )
    return tuple(facts)


def _port(args: tuple[str, ...] | None) -> int | None:
    if not args:
        return None
    try:
        return int(args[0])
    except ValueError:
        return None


def extract_redis(text: str, path: str) -> tuple[EncryptionFact, ...]:
    doc = parse_redis(text, path=path)
    if doc is None:
        return ()
    bind = doc.lookup("bind")
    transport = redis_transport(
        _port(doc.lookup("port")),
        _port(doc.lookup("tls-port")),
        bind,
    )
    notes = _known(
        "redis",
        [(entry.name, " ".join(entry.args)) for entry in doc.entries],
    )
    auth = doc.lookup("tls-auth-clients")
    if auth:
        word = {"no": "none", "optional": "optional", "yes": "required"}.get(
            auth[0].casefold()
        )
        if word:
            notes.append(BasisEntry("client_auth", word))
    prefer = doc.lookup("tls-prefer-server-ciphers")
    if prefer:
        folded = prefer[0].casefold()
        mapped = {"yes": "on", "no": "off", "on": "on", "off": "off"}.get(folded)
        if mapped:
            notes.append(BasisEntry("prefer_server_ciphers", mapped))
    floor = _protocol_floor(
        [(entry.name, " ".join(entry.args)) for entry in doc.entries],
        ("tls-protocols",),
    )
    if floor is not None:
        notes.append(floor)
    return (
        _fact(
            kind="cache",
            native_type="redis",
            address=path,
            path=path,
            line=doc.entries[0].line if doc.entries else 1,
            form="db_config",
            layers={"database": _UNSEEN, "volume": _UNSEEN, "transport": transport},
            basis=notes,
        ),
    )


def _crypt_options(raw: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for part in raw.split(","):
        piece = part.strip()
        if not piece:
            continue
        if "=" in piece:
            key, _, value = piece.partition("=")
            found[key.casefold()] = value
        else:
            found[piece.casefold()] = "true"
    return found


def _key_notes(keyfile: str) -> list[BasisEntry]:
    token = keyfile.strip()
    folded = token.casefold()
    if folded in {"", "none", "-"}:
        return [BasisEntry("key_source", "passphrase")]
    if folded in _EPHEMERAL:
        return [BasisEntry("encryption", "ephemeral")]
    return [BasisEntry("key_source", "keyfile"), BasisEntry("custody", "local_file")]


def extract_crypttab(text: str, path: str) -> tuple[EncryptionFact, ...]:
    """One disk fact per crypttab record. A keyfile is custody, not a weak finding."""
    doc = parse_crypttab(text, path=path)
    if doc is None:
        return ()
    facts: list[EncryptionFact] = []
    for entry in doc.entries:
        source = entry.args[0] if entry.args else ""
        keyfile = entry.args[1] if len(entry.args) > 1 else ""
        options = _crypt_options(",".join(entry.args[2:]))
        notes = [
            BasisEntry("volume", entry.name),
            BasisEntry("source", source),
            *_key_notes(keyfile),
        ]
        for name in (
            "cipher",
            "size",
            "hash",
            "luks",
            "plain",
            "tcrypt",
            "swap",
            "tmp",
            "discard",
        ):
            if name in options:
                notes.append(BasisEntry(name, options[name]))
        if "cipher" not in options:
            notes.append(BasisEntry("cipher", "unspecified"))
        facts.append(
            _fact(
                kind="disk_encryption",
                native_type="crypttab",
                address=entry.name,
                path=path,
                line=entry.line,
                form="crypttab",
                layers={"volume": LayerResult("ENCRYPTED_DECLARED")},
                basis=notes,
                weak=False,
            )
        )
    return tuple(facts)


def _uncomment(line: str) -> str:
    quote = ""
    out: list[str] = []
    for char in line:
        if quote:
            out.append(char)
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
            out.append(char)
            continue
        if char == "#":
            break
        out.append(char)
    return "".join(out)


def _pieces(line: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    quote = ""
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            buf.append(char)
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in "\"'":
            quote = char
            buf.append(char)
            index += 1
            continue
        if line.startswith("&&", index) or line.startswith("||", index):
            parts.append("".join(buf))
            buf = []
            index += 2
            continue
        if char in ";&|":
            parts.append("".join(buf))
            buf = []
            index += 1
            continue
        buf.append(char)
        index += 1
    parts.append("".join(buf))
    return parts


def _lead(words: tuple[str, ...]) -> tuple[str, ...]:
    index = 0
    while index < len(words) and words[index].casefold() in {"sudo", "env"}:
        index += 1
        while (
            index < len(words)
            and "=" in words[index]
            and not words[index].startswith("-")
        ):
            index += 1
    return words[index:]


def _commands(text: str) -> list[tuple[int, tuple[str, ...]]]:
    found: list[tuple[int, tuple[str, ...]]] = []
    buf = ""
    start = 1
    for number, raw in enumerate(text.splitlines(), 1):
        if not buf:
            start = number
        piece = _uncomment(raw).strip()
        if piece.endswith("\\"):
            buf += piece[:-1] + " "
            continue
        buf += piece
        for command in _pieces(buf):
            words = _lead(split_words(command))
            if words and words[0].casefold() == "cryptsetup":
                found.append((start, words))
        buf = ""
    return found


def _options(words: tuple[str, ...]) -> dict[str, tuple[str, str | None]]:
    found: dict[str, tuple[str, str | None]] = {}
    index = 0
    while index < len(words):
        name = _LONG.get(words[index]) or _SHORT.get(words[index])
        if name is None:
            index += 1
            continue
        value = words[index + 1] if index + 1 < len(words) else ""
        marker = "template_marker" if "$" in value else None
        found[name] = (value, marker)
        index += 2
    return found


def cryptsetup(
    text: str, path: str, *, form: str = "shell"
) -> tuple[EncryptionFact, ...]:
    """Disk facts for cryptsetup luksFormat, luksOpen, open, and the plain variants."""
    facts: list[EncryptionFact] = []
    seen: dict[str, int] = {}
    for line, words in _commands(text):
        verb = words[1].casefold() if len(words) > 1 else ""
        if verb not in _VERBS:
            continue
        seen[verb] = seen.get(verb, 0) + 1
        opts = _options(words[2:])
        notes = [BasisEntry("command", verb)]
        cipher = opts.get("cipher")
        if cipher is None:
            notes.append(BasisEntry("cipher", "unspecified"))
        elif cipher[1]:
            notes.append(BasisEntry("cipher", None, cipher[1]))
        else:
            notes.append(BasisEntry("cipher", cipher[0]))
        for name in ("size", "hash", "type", "pbkdf", "key_file"):
            if name in opts:
                value, marker = opts[name]
                notes.append(BasisEntry(name, None if marker else value, marker))
        facts.append(
            _fact(
                kind="disk_encryption",
                native_type="cryptsetup",
                address=f"{path}:{line}",
                path=path,
                line=line,
                form=form,
                layers={"volume": LayerResult("ENCRYPTED_DECLARED")},
                basis=notes,
                weak=False,
                # the n-th command with this verb in the file: moving a line is not a new asset
                identity=f"{path}#cryptsetup-{verb}-{seen[verb]}",
            )
        )
    return tuple(facts)


def sql_labels(text: str, path: str) -> tuple[EncryptionFact, ...]:
    """One evidence fact per label. The statement text is discarded."""
    grouped: dict[str, list[int]] = {}
    for label, line in label_sql(text):
        grouped.setdefault(label, []).append(line)
    facts: list[EncryptionFact] = []
    for label, lines in grouped.items():
        shown = ",".join(str(number) for number in lines[:20])
        layer = _SQL_LAYER.get(label, "database")
        facts.append(
            _fact(
                kind="relational_db",
                native_type="sql",
                address=label,
                path=path,
                line=lines[0],
                form="sql",
                layers={layer: LayerResult("ENCRYPTED_DECLARED")},
                basis=[
                    BasisEntry("evidence_only", "true"),
                    BasisEntry("lines", shown),
                ],
            )
        )
    return tuple(facts)


def _disk_form(path: str, text: str) -> str | None:
    name = PurePosixPath(path.replace("\\", "/")).name.casefold()
    if name == "crypttab":
        return "crypttab"
    docker = (
        name in {"dockerfile", "containerfile"}
        or name.startswith("dockerfile.")
        or name.endswith(".dockerfile")
    )
    shell = (
        name.endswith((".sh", ".bash"))
        or name == "makefile"
        or text.startswith("#cloud-config")
    )
    if docker:
        return "dockerfile"
    if shell:
        return "shell"
    return None


def extract_databases(
    text: str,
    path: str,
    *,
    hba: str | None = None,
    hba_path: str | None = None,
) -> tuple[EncryptionFact, ...]:
    """Facts for one database, disk, or SQL file. Scanners are not invoked here."""
    name = PurePosixPath(path.replace("\\", "/")).name.casefold()
    if name in {"postgresql.conf", "postgresql.auto.conf"}:
        return (extract_postgresql(text, path, hba=hba, hba_path=hba_path),)
    if name == "pg_hba.conf":
        return (extract_postgresql(None, path, hba=text, hba_path=path),)
    if name.endswith(".cnf"):
        return extract_mysql(text, path)
    if name.startswith("mongod") and name.endswith((".conf", ".yml", ".yaml")):
        return extract_mongo(text, path)
    if name.startswith("elasticsearch") and name.endswith((".yml", ".yaml")):
        return extract_elasticsearch(text, path)
    if name.startswith("redis") and name.endswith(".conf"):
        return extract_redis(text, path)
    if name.endswith(".sql"):
        return sql_labels(text, path)
    form = _disk_form(path, text)
    if form == "crypttab":
        return extract_crypttab(text, path)
    if form in {"dockerfile", "shell"}:
        return cryptsetup(text, path, form=form)
    return ()


READERS = MappingProxyType(
    {
        "pg_transport": pg_transport,
        "redis_transport": redis_transport,
        "cryptsetup": cryptsetup,
        "sql_labels": sql_labels,
    }
)
