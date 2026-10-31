"""Inline database posture cases for pg_hba, crypttab, and SQL labels."""

from __future__ import annotations

import json
from dataclasses import asdict

from aibom.cbom.posture.extract_databases import (
    extract_crypttab,
    extract_postgresql,
    sql_labels,
)
from aibom.cbom.posture.model import EncryptionFact
from aibom.cbom.posture.sqllabels import label_sql


def _blob(fact: EncryptionFact) -> str:
    return json.dumps(asdict(fact), sort_keys=True)


def test_reject_record_is_not_plaintext() -> None:
    only_reject = "host all all 10.0.0.0/8 reject\n"
    rejected = extract_postgresql(
        "ssl = on\n",
        "srv/postgresql.conf",
        hba=only_reject,
    )
    assert rejected.layers["transport"] != "NOT_ENCRYPTED"
    assert rejected.verdict != "NOT_ENCRYPTED"

    beside_tls = (
        "hostssl all all 0.0.0.0/0 scram-sha-256\n"
        "host all all 10.0.0.0/8 reject\n"
    )
    declared = extract_postgresql(
        "ssl = on\n",
        "srv/postgresql.conf",
        hba=beside_tls,
    )
    assert declared.layers["transport"] == "ENCRYPTED_DECLARED"
    assert declared.layers["transport"] != "NOT_ENCRYPTED"


def test_ssl_on_without_pg_hba_is_not_declared() -> None:
    fact = extract_postgresql("ssl = on\n", "srv/postgresql.conf")
    assert fact.layers["transport"] != "ENCRYPTED_DECLARED"
    assert fact.verdict != "ENCRYPTED_DECLARED"
    assert fact.unknown_reason


def test_vacuous_pg_hba_is_not_declared() -> None:
    samples = {
        "loopback": "host all all 127.0.0.1/32 trust\nhost all all ::1/128 trust\n",
        "localhost": "host all all localhost scram-sha-256\n",
        "local": "local all all peer\n",
        "reject": "host all all 10.1.0.0/16 reject\n",
        "empty": "",
        "comment": "# host all all 0.0.0.0/0 trust\n",
        "mixed": (
            "local all all peer\n"
            "host all all 127.0.0.1/32 trust\n"
            "host all all 10.0.0.0/8 reject\n"
        ),
    }
    for label, sample in samples.items():
        fact = extract_postgresql(
            "ssl = on\n",
            "srv/postgresql.conf",
            hba=sample,
        )
        assert fact.layers["transport"] != "ENCRYPTED_DECLARED", label


def test_crypttab_keyfile_records_local_custody_without_weak_finding() -> None:
    text = "data /dev/disk/by-uuid/abc /etc/keys/data.key luks,cipher=aes-xts-plain64\n"
    facts = extract_crypttab(text, "etc/crypttab")
    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "disk_encryption"
    custody = [item.value for item in fact.basis if item.name == "custody"]
    assert custody == ["local_file"]
    assert "AT_REST_ENCRYPTION_WEAK" not in fact.finding_codes


def test_sql_create_table_labels_are_not_stored_on_the_fact() -> None:
    statement = "CREATE TABLE ledger (id INT) ENCRYPTION='Y';\n"
    labels = label_sql(statement)
    assert any(label == "mysql_table_encryption" for label, _line in labels)
    facts = sql_labels(statement, "schema/tables.sql")
    assert facts
    for fact in facts:
        blob = _blob(fact)
        assert statement.strip() not in blob
        assert "ledger" not in blob
        assert "CREATE TABLE" not in blob


def test_postgres_ssl_off_is_not_encrypted_in_transit(tmp_path) -> None:
    from aibom.cbom.normalize import normalize_crypto
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "postgresql.conf").write_text("ssl = off\n", encoding="utf-8")
    result = scan_crypto(tmp_path)
    run = normalize_crypto(result, duration_of_scan=0.0)
    fact = next(
        row
        for row in run["cbom_posture"]["facts"]
        if row["kind"] == "relational_db"
    )
    assert fact["layers"]["transport"] == "NOT_ENCRYPTED"
    assert fact["verdict"] == "UNKNOWN"
    assert "UNENCRYPTED_IN_TRANSIT" not in fact["finding_codes"]


def test_postgres_tls_10_floor_is_a_weak_protocol(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "postgresql.conf").write_text(
        "ssl = on\nssl_min_protocol_version = 'TLSv1'\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    props = protocol.properties or {}
    assert props["crypto:protocolVersion"] == "TLSv1"
    assert props["crypto:strength"] == "weak"
    assert "WEAK_PROTOCOL" in {flag.code for flag in result.flags}


def test_postgres_tls_12_floor_is_not_weak(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "postgresql.conf").write_text(
        "ssl = on\nssl_min_protocol_version = 'TLSv1.2'\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    props = protocol.properties or {}
    assert props["crypto:protocolVersion"] == "TLSv1.2"
    assert "crypto:strength" not in props
    assert "WEAK_PROTOCOL" not in {flag.code for flag in result.flags}


def test_cloud_keyring_is_not_weak_at_rest(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "my.cnf").write_text(
        "[mysqld]\nearly-plugin-load=keyring_aws.so\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assert "AT_REST_ENCRYPTION_WEAK" not in {flag.code for flag in result.flags}


def test_mongo_key_file_is_weak_at_rest(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "mongod.conf").write_text(
        "security:\n  encryptionKeyFile: /etc/mongo.key\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assert "AT_REST_ENCRYPTION_WEAK" in {flag.code for flag in result.flags}


def test_mysql_file_keyring_is_weak_at_rest(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "my.cnf").write_text(
        "[mysqld]\nearly-plugin-load=keyring_file.so\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assert "AT_REST_ENCRYPTION_WEAK" in {flag.code for flag in result.flags}


def test_mysql_and_redis_keep_the_lowest_tls_token(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "my.cnf").write_text(
        "[mysqld]\ntls_version = TLSv1.2,TLSv1\n",
        encoding="utf-8",
    )
    (tmp_path / "redis.conf").write_text(
        "tls-port 6379\ntls-protocols TLSv1.3 TLSv1.1\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    versions = {
        (comp.properties or {}).get("discovery:source"): (
            comp.properties or {}
        ).get("crypto:protocolVersion")
        for comp in result.components
        if comp.name == "TLS"
    }
    assert versions["my.cnf"] == "TLSv1"
    assert versions["redis.conf"] == "TLSv1.1"
    assert "WEAK_PROTOCOL" in {flag.code for flag in result.flags}


def test_code_patterns_disable_tls_checks(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "client.py").write_text(
        "requests.get(url, verify=False)\n",
        encoding="utf-8",
    )
    (tmp_path / "fetch.sh").write_text(
        "wget --no-check-certificate https://example.invalid\n"
        "curl -k https://example.invalid\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    kinds = {
        (comp.properties or {}).get("crypto:factNativeType")
        for comp in result.components
        if comp.kind == "infra"
    }
    assert {"py.requests.verify", "wget.insecure", "curl.insecure"} <= kinds
    assert "TLS_VERIFICATION_DISABLED" in {flag.code for flag in result.flags}


def test_elasticsearch_verification_none_disables_tls_checks(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "elasticsearch.yml").write_text(
        "xpack:\n"
        "  security:\n"
        "    http.ssl.verification_mode: none\n"
        "    transport.ssl.verification_mode: certificate\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    codes = {flag.code for flag in result.flags}
    assert "TLS_VERIFICATION_DISABLED" in codes
    flagged = [
        flag for flag in result.flags if flag.code == "TLS_VERIFICATION_DISABLED"
    ]
    assert len(flagged) == 1


def test_elasticsearch_supported_protocols_use_the_lowest_token(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "elasticsearch.yml").write_text(
        "xpack:\n"
        "  security:\n"
        "    http.ssl.supported_protocols: [TLSv1, TLSv1.2]\n"
        "    transport.ssl.supported_protocols: [TLSv1.2, TLSv1.3]\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    versions = {
        (comp.properties or {}).get("crypto:protocolVersion")
        for comp in result.components
        if comp.name == "TLS"
    }
    assert versions == {"TLSv1", "TLSv1.2"}
    weak = []
    for comp in result.components:
        props = comp.properties or {}
        if comp.name == "TLS" and props.get("crypto:strength") == "weak":
            weak.append(comp)
    assert len(weak) == 1
    assert "WEAK_PROTOCOL" in {flag.code for flag in result.flags}


def _fact_basis(result, address_end: str) -> str:
    fact = next(
        comp
        for comp in result.components
        if str((comp.properties or {}).get("crypto:factAddress") or "").endswith(
            address_end
        )
    )
    return str((fact.properties or {}).get("crypto:factBasis"))


def test_database_cipher_preference_is_recorded(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "postgresql.conf").write_text(
        "ssl = on\nssl_prefer_server_ciphers = on\n",
        encoding="utf-8",
    )
    postgres = scan_crypto(tmp_path)
    assert "prefer_server_ciphers" in _fact_basis(postgres, "postgresql.conf")
    assert not {flag.code for flag in postgres.flags}
    (tmp_path / "postgresql.conf").unlink()
    (tmp_path / "redis.conf").write_text(
        "tls-port 6379\ntls-prefer-server-ciphers no\n",
        encoding="utf-8",
    )
    redis = scan_crypto(tmp_path)
    recorded = _fact_basis(redis, "redis.conf")
    assert '"prefer_server_ciphers"' in recorded
    assert '"off"' in recorded


def test_database_client_authentication_is_not_disabled_verification(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "elasticsearch.yml").write_text(
        "xpack:\n"
        "  security:\n"
        "    http.ssl.client_authentication: NONE\n",
        encoding="utf-8",
    )
    elastic = scan_crypto(tmp_path)
    http = _fact_basis(elastic, "#http")
    assert '"name": "client_auth"' in http
    assert '"value": "none"' in http
    assert '"name": "client_auth"' not in _fact_basis(elastic, "#transport")
    assert "TLS_VERIFICATION_DISABLED" not in {flag.code for flag in elastic.flags}
    (tmp_path / "elasticsearch.yml").unlink()
    (tmp_path / "redis.conf").write_text(
        "tls-port 6379\ntls-auth-clients yes\n",
        encoding="utf-8",
    )
    required = scan_crypto(tmp_path)
    assert "required" in _fact_basis(required, "redis.conf")
    (tmp_path / "redis.conf").write_text(
        "tls-port 6379\ntls-auth-clients no\n",
        encoding="utf-8",
    )
    opened = scan_crypto(tmp_path)
    assert "none" in _fact_basis(opened, "redis.conf")
    assert "TLS_VERIFICATION_DISABLED" not in {flag.code for flag in opened.flags}
    (tmp_path / "redis.conf").unlink()
    (tmp_path / "mongod.conf").write_text(
        "net:\n"
        "  tls:\n"
        "    allowConnectionsWithoutCertificates: true\n",
        encoding="utf-8",
    )
    mongo = scan_crypto(tmp_path)
    assert "optional" in _fact_basis(mongo, "mongod.conf")
    assert "TLS_VERIFICATION_DISABLED" not in {flag.code for flag in mongo.flags}


def test_mongo_invalid_certificates_disable_tls_checks(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "mongod.conf").write_text(
        "net:\n  tls:\n    allowInvalidCertificates: true\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assert "TLS_VERIFICATION_DISABLED" in {flag.code for flag in result.flags}


def test_mongo_disabled_protocols_leave_the_lowest_enabled_version(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "mongod.conf").write_text(
        "net:\n  tls:\n    disabledProtocols: [TLS1_0, TLS1_1]\n",
        encoding="utf-8",
    )
    kept = scan_crypto(tmp_path)
    protocol = next(comp for comp in kept.components if comp.name == "TLS")
    assert (protocol.properties or {})["crypto:protocolVersion"] == "TLSv1.2"
    assert "WEAK_PROTOCOL" not in {flag.code for flag in kept.flags}
    (tmp_path / "mongod.conf").write_text(
        "net:\n  tls:\n    disabledProtocols: [TLS1_3]\n",
        encoding="utf-8",
    )
    opened = scan_crypto(tmp_path)
    weak = next(comp for comp in opened.components if comp.name == "TLS")
    assert (weak.properties or {})["crypto:protocolVersion"] == "TLSv1"
    assert "WEAK_PROTOCOL" in {flag.code for flag in opened.flags}


def test_weak_postgres_cipher_is_a_protocol_finding(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "postgresql.conf").write_text(
        "ssl = on\nssl_ciphers = 'DES-CBC3-SHA'\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    suite = (protocol.properties or {})["crypto:cipherSuite"]
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in suite
    assert "WEAK_CIPHER_SUITE" in {flag.code for flag in result.flags}


def test_postgres_dh_params_file_is_a_diffie_hellman_asset(tmp_path) -> None:
    import binascii

    from aibom.cbom.pipeline import scan_crypto

    prime = (1 << 1023) | 1
    raw = prime.to_bytes(128, "big")
    integer = b"\x02\x81\x80" + raw
    base = b"\x02\x01\x02"
    body = integer + base
    der = b"\x30\x81\x85" + body
    (tmp_path / "dhparam.pem").write_text(
        "-----BEGIN DH PARAMETERS-----\n"
        + binascii.b2a_base64(der).decode("ascii")
        + "-----END DH PARAMETERS-----\n",
        encoding="utf-8",
    )
    (tmp_path / "postgresql.conf").write_text(
        "ssl = on\nssl_dh_params_file = 'dhparam.pem'\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    asset = next(comp for comp in result.components if comp.name == "Diffie-Hellman")
    assert (asset.properties or {})["crypto:keySize"] == "1024"
    assert any(
        edge.rel == "depends_on" and edge.dst == asset.bom_ref for edge in result.edges
    )
    assert "WEAK_KEY_SIZE" in {flag.code for flag in result.flags}
