"""Reference catalogs that do not raise a finding by themselves."""

import json

from aibom.cbom.posture.defaults import load_registry, read_data_bytes


def _rows(name: str) -> list[dict]:
    document = json.loads(read_data_bytes(name))
    return document["rows"]


def test_catalogs_load_with_the_registry() -> None:
    registry = load_registry()
    assert {spec.id for spec in registry.patterns} >= {
        "py.insecure",
        "go.skip",
        "dotnet.invalid",
        "curl.insecure",
    }
    images = {row["image"] for row in _rows("datastore_images.json")}
    assert {"postgres", "redis", "rabbitmq", "minio"} <= images
    scored = {row["id"]: row["scored"] for row in _rows("named_vulnerabilities.json")}
    assert scored["HEARTBLEED"] is True
    assert scored["BEAST"] is False
    assert scored["LUCKY13"] is False
    assert {row["tool"] for row in _rows("tls_import_formats.json")} == {
        "testssl",
        "sslyze",
        "nmap",
    }
    keys = {row["key"] for row in _rows("key_policy_conditions.json")}
    assert "aws:SourceVpc" in keys
