"""Cedar governance export: entities + sample policy from a real ScanResult.

Real fixture graphs (never mock ScanResult). The export is a pure consumer of
the scored result — these tests assert the projection, not a scanner.
"""

from __future__ import annotations

import json
import pathlib

from aibom.governance.cedar import (
    cedar_type,
    sample_policy,
    to_cedar_entities,
    write_entities,
    write_policy,
)
from aibom.scan.pipeline import scan_repo

_EX = pathlib.Path(__file__).resolve().parent.parent / "examples"
_DEMO = _EX / "shadow-demo"
_MULTISITE = _EX / "multi-site"
_ALLOW = pathlib.Path(__file__).resolve().parent.parent / "config" / "allowlist.yaml"


def _by_id(entities: list[dict]) -> dict[str, dict]:
    return {e["uid"]["id"]: e for e in entities}


def test_cedar_type_pascalcases_kind() -> None:
    assert cedar_type("model") == "Model"
    assert cedar_type("cloud_service") == "CloudService"
    assert cedar_type("vector_store") == "VectorStore"


def test_every_component_becomes_an_entity() -> None:
    result = scan_repo(_DEMO, level=4, allowlist=_ALLOW)
    entities = to_cedar_entities(result)
    assert len(entities) == len(result.components)
    refs = {e["uid"]["id"] for e in entities}
    assert {c.bom_ref for c in result.components} == refs


def test_allowlist_drives_sanctioned_attr() -> None:
    result = scan_repo(_DEMO, level=4, allowlist=_ALLOW)
    by_id = _by_id(to_cedar_entities(result))
    # On the allowlist -> sanctioned.
    assert by_id["cloud_service-aws-bedrock"]["attrs"]["sanctioned"] is True
    assert by_id["vector_store-chromadb"]["attrs"]["sanctioned"] is True
    # Not on the allowlist -> NOT sanctioned.
    assert by_id["container-ollama"]["attrs"]["sanctioned"] is False
    assert by_id["cloud_service-api-openai-com"]["attrs"]["sanctioned"] is False


def test_site_and_service_facts_become_attrs() -> None:
    result = scan_repo(_MULTISITE, level=1)
    by_id = _by_id(to_cedar_entities(result))
    # Site nodes carry drift_status for policy 3.
    assert by_id["site-lakeside-regional"]["attrs"]["drift_status"] == "drift-detected"
    assert by_id["site-mercy-general"]["attrs"]["drift_status"] == "stable"
    # Serving service carries baa for policy 2.
    assert "baa" in by_id["service-acme-cloud"]["attrs"]


def test_deployed_at_edges_become_entity_references() -> None:
    result = scan_repo(_MULTISITE, level=1)
    by_id = _by_id(to_cedar_entities(result))
    model = by_id["model-chestxr-multisite"]["attrs"]
    deployed = {ref["__entity"]["id"] for ref in model["deployed_at"]}
    assert deployed == {"site-mercy-general", "site-lakeside-regional"}
    # Every edge target is a typed Cedar entity reference.
    for ref in model["deployed_at"]:
        assert ref["__entity"]["type"] == "Infra"


def test_sample_policy_has_the_four_rules() -> None:
    pol = sample_policy()
    assert "resource.sanctioned == false" in pol
    assert 'action == Action::"serve"' in pol
    assert 'resource.drift_status == "drift-detected"' in pol
    assert pol.count("forbid (") == 3 and pol.count("permit (") == 1


def test_export_is_deterministic_and_writes(tmp_path) -> None:
    result = scan_repo(_DEMO, level=4, allowlist=_ALLOW)
    assert to_cedar_entities(result) == to_cedar_entities(result)
    ents = tmp_path / "entities.json"
    pol = tmp_path / "policies.cedar"
    write_entities(result, ents)
    write_policy(pol)
    loaded = json.loads(ents.read_text())  # valid JSON
    assert loaded == to_cedar_entities(result)
    assert pol.read_text() == sample_policy()
