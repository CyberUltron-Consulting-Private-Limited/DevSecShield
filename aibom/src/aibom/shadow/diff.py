"""Shadow-AI diff: discovered components vs an allowlist -> UNSANCTIONED flags.

A finalize step over the scan context: any discovered shadow-AI component
(agent, MCP server, vector store, cloud service, endpoint, …) whose name / ref /
purl is not on the sanctioned allowlist gets an ``UNSANCTIONED_COMPONENT`` flag.
Lane-clean: this EMITS flags (the scorer weights them via
``config/risk-weights.yaml``); it never computes a score.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from aibom.scan.registry import ScanContext

# The Phase-4 "shadow-AI" kinds subject to allowlist diffing. The Phase-0-3
# declared inventory (model/dataset/framework/prompt/service/infra/secret) is
# the sanctioned baseline and is never shadow-flagged.
SHADOW_KINDS = frozenset(
    {
        "agent", "tool", "mcp_server", "mcp_client", "guardrail", "orchestrator",
        "plugin", "vector_store", "knowledge_base", "retriever", "reranker",
        "embedding_model", "notebook", "container", "cloud_service", "endpoint",
        "registry", "pipeline", "fine_tuning", "evaluation",
    }
)


def load_allowlist(path: str | Path) -> set[str]:
    """Return the set of sanctioned identifiers (names / bom_refs / purls)."""
    data = yaml.safe_load(Path(path).read_text()) or {}
    sanctioned = data.get("sanctioned", []) if isinstance(data, dict) else []
    return {str(s).strip().lower() for s in sanctioned}


def _identifiers(comp: object) -> set[str]:
    ids = {
        str(getattr(comp, "bom_ref", "") or "").lower(),
        str(getattr(comp, "name", "") or "").lower(),
        str(getattr(comp, "purl", "") or "").lower(),
    }
    return {i for i in ids if i}


def flag_unsanctioned(ctx: ScanContext, allowlist: str | Path) -> None:
    """Flag each discovered shadow-AI component not on the allowlist (in place)."""
    allow = load_allowlist(allowlist)
    for comp in ctx.components:
        if comp.kind not in SHADOW_KINDS:
            continue
        if _identifiers(comp) & allow:
            continue
        ctx.add_flag(
            "UNSANCTIONED_COMPONENT",
            comp.bom_ref,
            severity="warning",
            message=(
                f"Unsanctioned {comp.kind} {comp.name!r} discovered "
                "(not on the allowlist); review or sanction it."
            ),
        )


__all__ = ["SHADOW_KINDS", "load_allowlist", "flag_unsanctioned"]
