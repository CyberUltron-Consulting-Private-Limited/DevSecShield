"""Phase-4 shadow-AI discovery: scan levels, allowlist diff, taxonomy.

Real fixture graphs (never mock the scanner/ScanResult). The live-cloud test
mocks the PROVIDER client only (the scanner is the unit under test) and awaits
its terminal result — no sleeping.
"""

from __future__ import annotations

import pathlib

import pytest

from aibom.emit.cyclonedx import emit_and_validate
from aibom.scan.pipeline import scan_repo
from aibom.scan.scanners.live_cloud_scan import LiveCloudScanner

_EX = pathlib.Path(__file__).resolve().parent.parent / "examples"
_DEMO = _EX / "shadow-demo"
_ALLOW = pathlib.Path(__file__).resolve().parent.parent / "config" / "allowlist.yaml"


def _kinds(result) -> dict[str, int]:
    out: dict[str, int] = {}
    for c in result.components:
        out[c.kind] = out.get(c.kind, 0) + 1
    return out


# --------------------------------------------------------------------------- #
# Scan levels are independent registry entries; level filtering works.
# --------------------------------------------------------------------------- #


def test_level_1_finds_no_shadow_components() -> None:
    # The demo has no MODEL_CARD/requirements -> level 1 yields nothing.
    assert scan_repo(_DEMO, level=1).components == []


def test_docker_scanner_level_2() -> None:
    result = scan_repo(_DEMO, level=2)
    names = {c.name for c in result.components}
    assert "Ollama" in names  # container
    assert "Chroma" in names  # vector_store
    assert _kinds(result).get("container") == 1


def test_net_env_scanner_level_3() -> None:
    names = {c.name for c in scan_repo(_DEMO, level=3).components}
    assert "OpenAI API" in names and "Anthropic API" in names
    assert "Ollama (local)" in names  # localhost:11434 endpoint


def test_cloud_iac_scanner_level_4() -> None:
    names = {c.name for c in scan_repo(_DEMO, level=4).components}
    assert "AWS Bedrock" in names and "AWS SageMaker" in names


# --------------------------------------------------------------------------- #
# Shadow diff: allowlisted -> sanctioned; everything else -> UNSANCTIONED.
# --------------------------------------------------------------------------- #


def test_allowlist_diff_flags_unsanctioned() -> None:
    result = scan_repo(_DEMO, level=4, allowlist=_ALLOW)
    unsanctioned = {
        f.target for f in result.flags if f.code == "UNSANCTIONED_COMPONENT"
    }
    by_ref = {c.bom_ref: c for c in result.components}
    # On the allowlist -> present AND NOT flagged.
    assert "cloud_service-aws-bedrock" in by_ref
    assert "cloud_service-aws-bedrock" not in unsanctioned
    assert "vector_store-chromadb" in by_ref
    assert "vector_store-chromadb" not in unsanctioned
    # Not on the allowlist -> flagged.
    assert "container-ollama" in unsanctioned
    assert "cloud_service-api-openai-com" in unsanctioned
    assert by_ref["container-ollama"].kind == "container"


def test_unsanctioned_flags_are_scored() -> None:
    result = scan_repo(_DEMO, level=4, allowlist=_ALLOW)
    # 5 unsanctioned x weight 6 = 30 raw risk.
    assert result.scores["by_flag"]["UNSANCTIONED_COMPONENT"] == 30.0
    assert result.scores["risk_total"] >= 30.0


def test_no_allowlist_means_no_shadow_flags() -> None:
    result = scan_repo(_DEMO, level=4)  # no allowlist
    assert not any(f.code == "UNSANCTIONED_COMPONENT" for f in result.flags)


# --------------------------------------------------------------------------- #
# Live-cloud (level 5): mock the PROVIDER, not the scanner. Await terminal data.
# --------------------------------------------------------------------------- #


class _FakeBedrock:
    """A fake cloud provider client (the upstream provider we mock)."""

    def list_ai_resources(self) -> list[dict]:
        return [
            {"ref": "cloud_service-bedrock-claude", "name": "bedrock/claude-3",
             "vendor": "AWS", "region": "us-east-1"},
            {"ref": "cloud_service-sagemaker-ep", "name": "sagemaker/triage-ep",
             "vendor": "AWS"},
        ]


def test_live_cloud_scanner_mocks_provider_not_scanner(tmp_path) -> None:
    LiveCloudScanner.client_factory = _FakeBedrock  # inject the mocked provider
    result = scan_repo(tmp_path, level=5)  # real scanner, fake client
    by_name = {c.name: c for c in result.components}
    assert "bedrock/claude-3" in by_name and "sagemaker/triage-ep" in by_name
    # The provider's region flows through to discovery properties.
    assert by_name["bedrock/claude-3"].properties["discovery:region"] == "us-east-1"


def test_live_cloud_accepts_a_function_factory(tmp_path) -> None:
    # The documented production wiring is a *callable* (not necessarily a class).
    # A plain function must NOT bind as a method and receive `self` — regression
    # guard for the class-attribute descriptor pitfall.
    LiveCloudScanner.client_factory = lambda: _FakeBedrock()
    names = {c.name for c in scan_repo(tmp_path, level=5).components}
    assert "bedrock/claude-3" in names


def test_live_cloud_skipped_without_client(tmp_path) -> None:
    assert LiveCloudScanner.client_factory is None  # default: no credentials
    assert scan_repo(tmp_path, level=5).components == []


# --------------------------------------------------------------------------- #
# Taxonomy: discovered kinds emit valid CycloneDX.
# --------------------------------------------------------------------------- #


def test_discovered_components_emit_valid_cyclonedx() -> None:
    bom = emit_and_validate(scan_repo(_DEMO, level=4, allowlist=_ALLOW))
    types = {c["type"] for c in bom["components"]}
    assert types <= {"application", "data", "platform", "container", "library",
                     "machine-learning-model", "file"}


@pytest.mark.parametrize("level,expect_min", [(2, 2), (3, 3), (4, 5)])
def test_higher_levels_discover_at_least_lower(level: int, expect_min: int) -> None:
    assert len(scan_repo(_DEMO, level=level).components) >= expect_min
