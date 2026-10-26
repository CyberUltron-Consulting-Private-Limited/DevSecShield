"""Fact identity and redaction."""

from aibom.cbom.posture.model import (
    HIDDEN_SUBSTRINGS,
    fact_id,
    is_hidden_path,
    path_context,
)


def test_fact_id_is_stable() -> None:
    left = fact_id("object_store", "aws", "aws_s3_bucket", "b", "main.tf")
    right = fact_id("object_store", "aws", "aws_s3_bucket", "b", "main.tf")
    other = fact_id("object_store", "aws", "aws_s3_bucket", "b", "other.tf")
    assert left == right
    assert left != other
    assert len(left) == 16


def test_hidden_substrings_are_the_eleven_names() -> None:
    assert HIDDEN_SUBSTRINGS == (
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "access_key",
        "private_key",
        "credential",
        "connection_string",
        "encryption_key",
        "key_material",
    )


def test_hidden_path_is_case_insensitive_on_any_segment() -> None:
    assert is_hidden_path("spec.tls.secretName")
    assert is_hidden_path("db.PASSWORD")
    assert not is_hidden_path("spec.replicas")


def test_path_context_labels_non_production_segments() -> None:
    assert path_context("tests/app.py") == "non_production_hint"
    assert path_context("src/app.py") == "production_like"
