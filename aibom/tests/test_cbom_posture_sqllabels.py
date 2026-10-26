"""SQL labels are a closed vocabulary and do not keep statement text."""

from __future__ import annotations

import pytest

from aibom.cbom.posture.sqllabels import SQL_LABELS, label_sql, load_sql
from support.generators import mutate_bytes


def test_each_label_is_recognised() -> None:
    samples = {
        "CREATE DATABASE ENCRYPTION KEY;": "tde_database_encryption_key",
        "ALTER DATABASE db1 SET ENCRYPTION ON;": "tde_enable",
        "ENCRYPTED WITH ( COLUMN_ENCRYPTION_KEY = k )": "always_encrypted_column",
        "CREATE TABLE t (id int) ENCRYPTION = 'Y';": "mysql_table_encryption",
        "CREATE TABLESPACE ts ADD DATAFILE 'a' ENCRYPTION = 'Y';": (
            "mysql_encrypted_tablespace"
        ),
        "SELECT pgp_sym_encrypt(data, 'k');": "pgcrypto_symmetric",
        "SELECT pgp_pub_encrypt(data, key);": "pgcrypto_public_key",
    }
    for text, label in samples.items():
        found = label_sql(text)
        assert found == ((label, 1),)
        assert found[0][0] in SQL_LABELS
        assert len(found[0]) == 2


def test_strings_and_comments_do_not_match() -> None:
    text = (
        "SELECT 'CREATE DATABASE ENCRYPTION KEY';\n"
        "/* CREATE DATABASE ENCRYPTION KEY */\n"
        "-- CREATE DATABASE ENCRYPTION KEY\n"
        "SELECT 1;\n"
    )
    assert label_sql(text) == ()


def test_bytes_return_a_result_or_one_diagnostic() -> None:
    seen: list[str] = []
    result = load_sql(b"\xff SELECT 1;", seen.append)
    assert result == () or isinstance(result, tuple)
    assert seen == [] or seen == ["parse_error"]


@pytest.mark.parametrize("seed", range(1, 21))
def test_mutated_bytes_never_raise(seed: int) -> None:
    base = b"CREATE DATABASE ENCRYPTION KEY;\n"
    for payload in mutate_bytes(seed, base=base):
        load_sql(payload, lambda _code: None)
