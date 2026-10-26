"""Coverage loader against synthetic tables. No shipped JSON."""

from __future__ import annotations

import hashlib
import json
from types import MappingProxyType

import pytest

from aibom.cbom.posture.coverage import (
    READER_NAMES,
    CoverageError,
    build_coverage,
)
from aibom.cbom.posture.defaults import (
    DefaultRow,
    DefaultsRegistry,
    VersionRange,
    build_registry,
)

FILE = "provider_defaults_aws.json"


def _default(**extra: object) -> dict[str, object]:
    row: dict[str, object] = {
        "id": "aws.example",
        "provider": "aws",
        "type": "aws_kinesis_stream",
        "attribute": "encryption_type",
        "documented_default": "NONE",
        "effect": "NOT_ENCRYPTED",
        "assessable_as_unencrypted": False,
        "caveat": "Provider documents NONE when the argument is omitted.",
        "versions": "all",
        "url": "https://example.com/kinesis",
        "valid_as_of": "2026-10-25",
        "when": {},
        "unless_attrs": {},
        "override": None,
    }
    row.update(extra)
    return row


def _registry(rows: list[dict[str, object]]) -> DefaultsRegistry:
    body = {"data_version": 1, "valid_as_of": "2026-10-26", "rows": rows}
    blob = json.dumps(body, sort_keys=True).encode("utf-8")
    return build_registry({FILE: blob})


def _source(**extra: object) -> dict[str, object]:
    source: dict[str, object] = {
        "from": "attr",
        "tf": "encryption_type",
        "cfn": "EncryptionType",
        "enabling": ["KMS"],
        "disabling": ["NONE"],
        "as_absent": [],
        "row": "aws.example",
    }
    source.update(extra)
    return source


def _rule(**extra: object) -> dict[str, object]:
    row: dict[str, object] = {
        "id": "aws.stream",
        "role": "resource",
        "kind": "data_stream",
        "provider": "aws",
        "native": {
            "terraform": ["aws_kinesis_stream"],
            "cloudformation": ["AWS::Kinesis::Stream"],
        },
        "layers": {
            "service": {
                "default_row": "aws.example",
                "self_hosted": False,
                "sources": [_source()],
            }
        },
        "refs": [],
        "presence": [],
    }
    row.update(extra)
    return row


def _build(rows: list[dict[str, object]], registry: DefaultsRegistry | None = None):
    reg = _registry([_default()]) if registry is None else registry
    body = {"data_version": 1, "valid_as_of": "2026-10-26", "rows": rows}
    blob = json.dumps(body, sort_keys=True).encode("utf-8")
    return build_coverage(blob, reg), blob


def test_reader_names_are_the_eight_closed_names() -> None:
    expected = frozenset(
        {
            "key_policy",
            "deny_insecure_transport",
            "gcp_iam_bindings",
            "pg_transport",
            "redis_transport",
            "cryptsetup",
            "sql_labels",
            "listener_reader",
        }
    )
    assert expected == READER_NAMES
    assert all(isinstance(name, str) for name in READER_NAMES)


def test_builds_a_rule_and_hashes_the_blob() -> None:
    table, blob = _build([_rule()])
    assert table.table.sha256 == hashlib.sha256(blob).hexdigest()
    rule = table.by_id["aws.stream"]
    assert "encryption_type" in rule.consulted["terraform"]
    assert "EncryptionType" in rule.consulted["cloudformation"]
    assert table.row_hashes["aws.stream"]


def test_predicate_paths_are_consulted() -> None:
    registry = _registry(
        [
            _default(
                when={
                    "terraform": {"engine_mode": ["provisioned", None]},
                    "cloudformation": {"EngineMode": ["provisioned", None]},
                }
            )
        ]
    )
    table, _ = _build([_rule()], registry)
    consulted = table.by_id["aws.stream"].consulted
    assert "engine_mode" in consulted["terraform"]
    assert "EngineMode" in consulted["cloudformation"]


def test_rejects_a_predicate_that_names_only_one_iac_syntax() -> None:
    row = DefaultRow(
        id="aws.example",
        provider="aws",
        type=("aws_db_instance",),
        attribute="storage_encrypted",
        documented_default="false",
        effect="NOT_ENCRYPTED",
        assessable_as_unencrypted=False,
        caveat="stated",
        versions=VersionRange(None, None),
        url="https://example.com/row",
        valid_as_of="2026-10-26",
        when=MappingProxyType({}),
        unless_attrs=MappingProxyType({"terraform": ("replicate_source_db",)}),
        override=None,
        finding_default=None,
    )
    registry = DefaultsRegistry(
        tables=(),
        rows=(row,),
        by_id=MappingProxyType({row.id: row}),
        patterns=(),
        row_hashes=MappingProxyType({}),
        line_patterns=(),
    )
    with pytest.raises(CoverageError, match="cloudformation"):
        _build([_rule()], registry)


def test_rejects_a_hidden_path_outside_refs_and_presence() -> None:
    rule = _rule(
        attrs=[
            {
                "name": "key",
                "tf": "disk_encryption_key.kms_key_self_link",
                "cfn": "KmsKeyId",
            }
        ]
    )
    with pytest.raises(CoverageError, match="neither refs nor presence"):
        _build([rule])


def test_rejects_a_hidden_predicate_path() -> None:
    registry = _registry(
        [
            _default(
                when={
                    "terraform": {"disk_encryption_key": ["on"]},
                    "cloudformation": {"DiskEncryptionKey": ["on"]},
                }
            )
        ]
    )
    with pytest.raises(CoverageError, match="neither refs nor presence"):
        _build([_rule()], registry)


def test_accepts_a_hidden_path_declared_as_a_key_ref() -> None:
    path = "disk_encryption_key.kms_key_self_link"
    rule = _rule(
        attrs=[{"name": "key", "tf": path, "cfn": "KmsKeyId"}],
        refs=[{"path": path, "role": "key_ref"}],
    )
    table, _ = _build([rule])
    assert table.by_id["aws.stream"].refs[0].role == "key_ref"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        ("plain-ref", "not hidden"),
        ("unconsulted", "not consulted"),
        ("both-lists", "disjoint"),
        ("unknown-field", "unknown field"),
        ("unknown-reader", "unknown reader"),
        ("no-paths", "consults no attributes"),
        ("missing-row", "missing"),
        ("duplicate", "duplicate id"),
        ("same-native", "native type"),
        ("two-unselected", "native type"),
    ],
)
def test_rejects_bad_rows(mutate: str, message: str) -> None:
    rule = _rule()
    rows = [rule]
    if mutate == "plain-ref":
        rule["attrs"] = [{"name": "count", "tf": "replicas", "cfn": "Replicas"}]
        rule["refs"] = [{"path": "replicas", "role": "key_ref"}]
    elif mutate == "unconsulted":
        rule["refs"] = [{"path": "spec.secretName", "role": "secret_ref"}]
    elif mutate == "both-lists":
        path = "aescbc.secret"
        rule["attrs"] = [{"name": "secret_set", "tf": path, "cfn": "Secret"}]
        rule["refs"] = [{"path": path, "role": "secret_ref"}]
        rule["presence"] = [path]
    elif mutate == "unknown-field":
        rule["notes"] = "no"
    elif mutate == "unknown-reader":
        rule["layers"]["service"]["sources"] = [_source(reader="admin")]
    elif mutate == "no-paths":
        rule["layers"]["service"]["sources"] = []
        rule["layers"]["service"]["default_row"] = None
    elif mutate == "missing-row":
        rule["layers"]["service"]["default_row"] = "aws.missing"
    elif mutate == "duplicate":
        rows = [_rule(), _rule(id="aws.stream")]
    elif mutate == "same-native":
        rows = [_rule(), _rule(id="aws.other")]
    elif mutate == "two-unselected":
        first = _rule(
            id="aws.kms",
            native={"cloudformation": ["AWS::KMS::Key"]},
            cfn_when={},
        )
        second = _rule(
            id="aws.kms.external",
            native={"cloudformation": ["AWS::KMS::Key"]},
            cfn_when={},
        )
        rows = [first, second]
    with pytest.raises(CoverageError, match=message):
        _build(rows)


def test_mutually_exclusive_cfn_selectors_share_a_type() -> None:
    selected = _rule(
        id="aws.kms.external",
        kind="kms_key",
        native={"cloudformation": ["AWS::KMS::Key"]},
        cfn_when={"Origin": "EXTERNAL"},
    )
    fallback = _rule(
        id="aws.kms",
        kind="kms_key",
        native={"cloudformation": ["AWS::KMS::Key"]},
    )
    table, _ = _build([selected, fallback])
    assert set(table.by_id) == {"aws.kms.external", "aws.kms"}


def test_rejects_a_predicate_that_skips_a_native_syntax() -> None:
    registry = _registry(
        [
            _default(
                when={
                    "terraform": {"engine": ["redis", None]},
                    "cloudformation": {"Engine": ["redis", None]},
                }
            )
        ]
    )
    rule = _rule(
        native={
            "terraform": ["aws_kinesis_stream"],
            "cloudformation": ["AWS::Kinesis::Stream"],
            "kubernetes": [{"group": "example.com", "kind": "Widget"}],
        }
    )
    with pytest.raises(CoverageError, match="kubernetes"):
        _build([rule], registry)


def test_rejects_an_unknown_field_name() -> None:
    with pytest.raises(CoverageError, match="unknown field extra"):
        _build([_rule(extra=True)])
