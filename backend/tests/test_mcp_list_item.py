"""MCP list rows count prompts and resources.

``for prompt in <list> and <bool>`` evaluates to ``True`` when the list is non-empty, and
``for ... in True`` raises TypeError. One scan with a prompt then 500s the whole team list.
"""
from __future__ import annotations

import os
import sys
import types
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "mcp-list-test-secret-not-for-production-use")


def _scan(results: dict):
    owner = types.SimpleNamespace(email="a@example.test", first_name="Ada", last_name="Lovelace")
    return types.SimpleNamespace(
        id=1, title="mcp", created_at=None, last_updated=None, scan_status="success",
        credit_consumed=1.0, owner_user=owner, info=None, scan_metadata={}, scan_data={"results": results},
    )


def test_a_prompt_and_a_resource_are_counted():
    from backend.utilities.db.scan_list_item import return_mcp_list_item

    item = return_mcp_list_item(_scan({
        "tools": [],
        "prompts": [{"prompt_risk_level": "low", "vulnerabilities": [{"impact": "Low"}]}],
        "resources": [{"resource_risk_level": "high", "vulnerabilities": [{"impact": "High"}]}],
    }))
    assert item["discovery_metrics"] == {"total_tools": 0, "total_prompts": 1, "total_resources": 1}
    assert item["risk_data"]["total_low"] == 1
    assert item["risk_data"]["total_high"] == 1
    assert item["risky_assets"] == 1


def test_empty_prompts_and_resources_do_not_raise():
    from backend.utilities.db.scan_list_item import return_mcp_list_item

    item = return_mcp_list_item(_scan({"tools": [], "prompts": [], "resources": []}))
    assert item["discovery_metrics"] == {"total_tools": 0, "total_prompts": 0, "total_resources": 0}
