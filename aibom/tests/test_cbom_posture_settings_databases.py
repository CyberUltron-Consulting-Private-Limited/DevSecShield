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
