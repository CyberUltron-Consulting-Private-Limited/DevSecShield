"""Terraform posture extraction. Inline sources, no fixture trees."""

from __future__ import annotations

import pytest

from aibom.cbom.posture.codec import make_fact_id
from aibom.cbom.posture.defaults import load_registry
from aibom.cbom.posture.extract_terraform import assess_sources, extract_terraform
from aibom.cbom.posture.resolve import Absent

_DECLARED = "ENCRYPTED_DECLARED"
_PLAIN = "NOT_ENCRYPTED"
_DEFAULT = "ENCRYPTED_PROVIDER_DEFAULT"
_RDS_ROW = "aws.rds.instance.storage_encrypted"
_S3_ROW = "aws.s3.sse_default"


def _db(body: str) -> str:
    return f'resource "aws_db_instance" "db" {{\n{body}}}\n'


@pytest.mark.parametrize(
    ("body", "verdict", "default_row"),
    [
        ("  storage_encrypted = true\n", _DECLARED, None),
        ("  storage_encrypted = false\n", _PLAIN, None),
        ("", _PLAIN, _RDS_ROW),
    ],
)
def test_storage_encrypted_literal_and_default(
    body: str, verdict: str, default_row: str | None
) -> None:
    fact = extract_terraform(_db(body), "main.tf")[0]
    assert fact.verdict == verdict
    assert fact.default_row == default_row
    assert fact.unknown_reason is None
    assert fact.layers["service"] == verdict
    assert fact.native_type == "aws_db_instance"
    assert fact.format == "terraform"


def test_s3_absence_is_the_encrypted_provider_default() -> None:
    text = 'resource "aws_s3_bucket" "b" {}\n'
    fact = extract_terraform(text, "main.tf")[0]
    assert fact.verdict == _DEFAULT
    assert fact.default_row == _S3_ROW
    assert fact.unknown_reason is None


def test_s3_literal_false_is_not_the_provider_default() -> None:
    text = (
        'resource "aws_s3_bucket" "b" {\n'
        "  server_side_encryption_configuration = false\n"
        "}\n"
    )
    fact = extract_terraform(text, "main.tf")[0]
    assert fact.verdict == _PLAIN
    assert fact.default_row is None


def test_unassessable_not_encrypted_default_is_unknown() -> None:
    row = load_registry().by_id["aws.elasticache.at_rest.redis"]
    assert row.effect == "NOT_ENCRYPTED"
    assert row.assessable_as_unencrypted is False
    got = assess_sources((Absent(),), row)
    assert got.verdict == "UNKNOWN"
    assert got.reason == "default_unknown"


def test_ebs_without_a_default_row_is_unknown() -> None:
    text = 'resource "aws_ebs_volume" "v" {}\n'
    fact = extract_terraform(text, "main.tf")[0]
    assert fact.verdict == "UNKNOWN"
    assert fact.unknown_reason == "default_unknown"
    assert fact.default_row is None


def test_count_zero_emits_no_fact() -> None:
    text = (
        'resource "aws_db_instance" "off" {\n'
        "  count = 0\n"
        "  storage_encrypted = false\n"
        "}\n"
        'resource "aws_db_instance" "on" {\n'
        "  storage_encrypted = true\n"
        "}\n"
    )
    facts = extract_terraform(text, "main.tf")
    assert [fact.address for fact in facts] == ["aws_db_instance.on"]
    assert facts[0].verdict == _DECLARED


def test_variable_reference_is_not_treated_as_unencrypted() -> None:
    text = (
        'variable "encrypt" {\n'
        "  default = false\n"
        "}\n"
        'resource "aws_db_instance" "db" {\n'
        "  storage_encrypted = var.encrypt\n"
        "}\n"
    )
    fact = extract_terraform(text, "main.tf")[0]
    assert fact.verdict == "UNKNOWN"
    assert fact.unknown_reason == "variable_no_default"
    assert fact.default_row is None


def test_local_reference_stays_an_unresolved_expression() -> None:
    text = _db("  storage_encrypted = local.encrypt\n")
    fact = extract_terraform(text, "main.tf")[0]
    assert fact.verdict == "UNKNOWN"
    assert fact.unknown_reason == "unresolved_expression"


def test_replica_does_not_take_the_unencrypted_default() -> None:
    text = _db('  replicate_source_db = "src"\n')
    fact = extract_terraform(text, "main.tf")[0]
    assert fact.verdict == "UNKNOWN"
    assert fact.unknown_reason == "default_unknown"


def test_serverless_cluster_uses_the_encrypted_sibling_row() -> None:
    text = (
        'resource "aws_rds_cluster" "c" {\n'
        '  engine_mode = "serverless"\n'
        "}\n"
    )
    fact = extract_terraform(text, "main.tf")[0]
    assert fact.verdict == _DEFAULT
    row = "aws.rds.cluster.storage_encrypted.serverless"
    assert fact.default_row == row


def test_type_outside_the_table_is_skipped() -> None:
    assert extract_terraform('resource "aws_iam_role" "r" {}\n', "main.tf") == ()


def test_parse_error_emits_nothing() -> None:
    assert extract_terraform("resource {", "main.tf") == ()


def test_fact_id_matches_the_codec() -> None:
    fact = extract_terraform(_db("  storage_encrypted = true\n"), "main.tf")[0]
    assert fact.id == make_fact_id(
        "relational_db",
        "aws",
        "aws_db_instance",
        "aws_db_instance.db",
        "main.tf",
    )
    assert fact.line >= 1
