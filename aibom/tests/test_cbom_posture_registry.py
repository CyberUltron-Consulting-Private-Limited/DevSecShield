"""Registry loader against synthetic blobs. No shipped JSON."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from aibom.cbom.posture.defaults import (
    DATA_FILES,
    RegistryError,
    build_registry,
    read_data_bytes,
    reviewed_problems,
    url_problems,
)

ROOT = Path(__file__).resolve().parents[1]
ALLOW = ROOT / "tests" / "cbom_posture_url_allowlist.txt"
REVIEWED = ROOT / "tests" / "cbom_posture_reviewed_rows.txt"
FILE = "provider_defaults_aws.json"


def _prefixes() -> list[str]:
    lines: list[str] = []
    for line in ALLOW.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text and not text.startswith("#"):
            lines.append(text)
    return lines


def _row(**extra: object) -> dict[str, object]:
    row: dict[str, object] = {
        "id": "aws.example",
        "provider": "aws",
        "type": "aws_kinesis_stream",
        "attribute": "encryption_type",
        "documented_default": "NONE",
        "effect": "NOT_ENCRYPTED",
        "assessable_as_unencrypted": True,
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


def _blob(rows: list[dict[str, object]]) -> bytes:
    body = {"data_version": 1, "valid_as_of": "2026-10-26", "rows": rows}
    return json.dumps(body, sort_keys=True).encode("utf-8")


def _load(rows: list[dict[str, object]]):
    return build_registry({FILE: _blob(rows)})


def test_read_data_bytes_uses_importlib_resources() -> None:
    source = Path(read_data_bytes.__code__.co_filename).read_text(encoding="utf-8")
    assert 'files("aibom.cbom")' in source
    assert '.joinpath("data")' in source
    assert "Path(__file__)" not in source
    assert "os.environ" not in source
    assert "getenv" not in source
    assert "coverage_table.json" not in DATA_FILES


def test_hashes_file_bytes_and_rows() -> None:
    raw = _row()
    blob = _blob([raw])
    registry = build_registry({FILE: blob})
    table = registry.tables[0]
    assert table.name == FILE
    assert table.data_version == 1
    assert table.valid_as_of == "2026-10-26"
    assert table.sha256 == hashlib.sha256(blob).hexdigest()
    encoded = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert registry.row_hashes["aws.example"] == hashlib.sha256(
        encoded.encode("utf-8")
    ).hexdigest()
    assert registry.by_id["aws.example"].url.startswith("https://")


def test_rejects_a_non_https_url() -> None:
    with pytest.raises(RegistryError, match="https"):
        _load([_row(url="http://example.com/kinesis")])


def test_rejects_when_that_names_only_terraform() -> None:
    with pytest.raises(RegistryError, match="cloudformation"):
        _load([_row(when={"terraform": {"engine": ["redis", None]}})])


def test_rejects_unless_attrs_that_name_only_cloudformation() -> None:
    with pytest.raises(RegistryError, match="terraform"):
        _load([_row(unless_attrs={"cloudformation": ["SnapshotIdentifier"]})])


def test_accepts_predicates_stated_for_both_syntaxes() -> None:
    registry = _load(
        [
            _row(
                id="aws.redis",
                when={
                    "terraform": {"engine": ["redis", None]},
                    "cloudformation": {"Engine": ["redis", None]},
                },
            ),
            _row(
                id="aws.valkey",
                when={
                    "terraform": {"engine": ["valkey"]},
                    "cloudformation": {"Engine": ["valkey"]},
                },
            ),
        ]
    )
    assert set(registry.by_id) == {"aws.redis", "aws.valkey"}


def test_rejects_duplicate_ids_overlapping_versions_and_missing_fields() -> None:
    with pytest.raises(RegistryError, match="duplicate id"):
        _load([_row(), _row()])
    with pytest.raises(RegistryError, match="overlap"):
        _load([_row(id="aws.a"), _row(id="aws.b")])
    with pytest.raises(RegistryError, match="missing field caveat"):
        row = _row()
        del row["caveat"]
        _load([row])


def test_rejects_duplicate_json_keys() -> None:
    blob = (
        b'{"data_version": 1, "data_version": 2, "valid_as_of": "2026-10-26", '
        b'"rows": []}'
    )
    with pytest.raises(RegistryError, match="duplicate key"):
        build_registry({FILE: blob})


def test_reviewed_and_url_checks_take_the_test_lists() -> None:
    registry = _load([_row()])
    assert any("not reviewed" in item for item in reviewed_problems(registry, {}))
    listed = {"aws.example": "assessable"}
    assert reviewed_problems(registry, listed) == []
    assert url_problems(registry, _prefixes()) == []
    assert url_problems(registry, ["https://docs.aws.amazon.com/"])
    assert "https://example.com" in _prefixes()


def test_allowlist_files_are_text_and_list_reviewed_rows() -> None:
    assert "https://example.com" in ALLOW.read_text(encoding="utf-8")
    data = [
        line.strip()
        for line in REVIEWED.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    kinds = [line.split("|", 2)[1] for line in data]
    assert kinds.count("assessable") == 10
    assert kinds.count("finding_default") == 3


def test_finding_default_is_closed() -> None:
    row = _row(
        id="aws.kms.enable_key_rotation",
        effect="UNKNOWN",
        assessable_as_unencrypted=False,
        documented_default="false",
        caveat="Provider documents rotation off when the argument is omitted.",
        finding_default={"code": "KMS_KEY_ROTATION_DISABLED", "when_absent": True},
    )
    registry = _load([row])
    listed = {"aws.kms.enable_key_rotation": "finding_default"}
    assert reviewed_problems(registry, listed) == []
    with pytest.raises(RegistryError, match="finding_default"):
        _load([_row(finding_default={"code": "OTHER", "when_absent": True})])
