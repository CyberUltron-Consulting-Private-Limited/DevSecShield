"""Cedar runtime-governance export from a :class:`ScanResult`.

A thin, OPTIONAL governance layer. The BOM answers *"what AI do we have?"*;
Cedar answers *"what is each component allowed to do at runtime?"*. This module
projects the inventory graph into the two artifacts a Cedar authorizer consumes:

* **entities** — every component as a Cedar entity (`{uid, attrs, parents}`),
  with the graph facts a policy needs to decide: ``sanctioned`` (shadow-AI
  allowlist status), ``processes_phi``, ``baa``, ``drift_status``, ``risk_band``,
  and the typed edges (``served_by`` / ``trained_on`` / ``deployed_at`` /
  ``depends_on``) as entity references.
* **policies** — a starting-point ``.cedar`` policy set that forbids runtime use
  of unsanctioned components, BAA-less serving vendors, and drift-flagged sites.

It is a *pure consumer* of the already-scored ``ScanResult`` (reporter lane: it
may read flags, like the SARIF reporter — it is NOT a compliance check). It does
no I/O beyond the explicit ``write_*`` helpers and is deterministic.

Standalone use (no clinithread-aibom runtime needed)::

    aibom cedar examples/multi-site -o entities.json -p policies.cedar
    # then, with the Cedar CLI (https://www.cedarpolicy.com/):
    cedar authorize \\
        --policies policies.cedar --entities entities.json \\
        --principal 'Agent::"triage-bot"' --action 'Action::"serve"' \\
        --resource 'CloudService::"service-acme-cloud"'

The emitted entities are valid Cedar JSON entities; the policies are valid Cedar
syntax. Mappings are ADVISORY — review the generated policies before enforcing.
"""

from __future__ import annotations

import json
from pathlib import Path

from aibom.model.component import AIComponent
from aibom.model.result import (
    REL_DEPENDS_ON,
    REL_DEPLOYED_AT,
    REL_SERVED_BY,
    REL_TRAINED_ON,
    ScanResult,
)

# Edge relationship -> the Cedar attribute name it becomes (entity-ref set).
_EDGE_ATTRS = {
    REL_SERVED_BY: "served_by",
    REL_TRAINED_ON: "trained_on",
    REL_DEPLOYED_AT: "deployed_at",
    REL_DEPENDS_ON: "depends_on",
}

# Header used by `cedar` to identify the advisory provenance of the policy set.
_POLICY_HEADER = (
    "// clinithread-aibom — sample Cedar runtime-governance policies (ADVISORY).\n"
    "// Generated from an AI-BOM inventory. Load alongside the exported entities\n"
    "// and authorize (principal, action, resource) at your gateway/application.\n"
    "// These are STARTING-POINT policies; a reviewer must adapt them before use.\n"
)


def cedar_type(kind: str) -> str:
    """Map a component ``kind`` to a PascalCase Cedar entity type.

    ``cloud_service`` -> ``CloudService``; ``model`` -> ``Model``. Stable and
    reversible enough to read in a policy (``CloudService::"service-acme"``).
    """
    return "".join(part.capitalize() for part in kind.split("_"))


def _uid(comp: AIComponent) -> dict[str, str]:
    return {"type": cedar_type(comp.kind), "id": comp.bom_ref}


def _entity_ref(comp: AIComponent) -> dict[str, dict[str, str]]:
    """A Cedar entity-reference value (used inside attribute sets)."""
    return {"__entity": _uid(comp)}


def to_cedar_entities(result: ScanResult) -> list[dict]:
    """Project the inventory graph into a list of Cedar JSON entities.

    Deterministic: entities sorted by ``(type, id)``; edge-reference sets sorted
    by target ``bom_ref``.
    """
    unsanctioned = {
        f.target for f in result.flags if f.code == "UNSANCTIONED_COMPONENT"
    }
    by_component = result.scores.get("by_component", {}) or {}
    risk_band = result.scores.get("risk_band")

    entities: list[dict] = []
    for comp in result.components:
        props = comp.properties or {}
        attrs: dict[str, object] = {
            "name": comp.name,
            "kind": comp.kind,
            "vendor": comp.publisher or "",
            # Shadow-AI allowlist verdict (reporter lane reads the flag echo).
            "sanctioned": comp.bom_ref not in unsanctioned,
        }
        if comp.version:
            attrs["version"] = comp.version
        if risk_band is not None:
            attrs["risk_band"] = risk_band
            attrs["risk_contribution"] = float(by_component.get(comp.bom_ref, 0.0))

        # Graph facts a runtime policy cares about (only when present).
        if (phi := props.get("clinical:processes_phi")) is not None:
            attrs["processes_phi"] = phi == "true"
        if (baa := props.get("service:baa")) is not None:
            attrs["baa"] = baa == "true"
        if (drift := props.get("site:drift_status")) is not None:
            attrs["drift_status"] = drift

        # Typed edges -> entity-reference sets (deterministic order).
        for rel, attr_name in _EDGE_ATTRS.items():
            targets = sorted(
                result.neighbors(comp.bom_ref, rel), key=lambda c: c.bom_ref
            )
            if targets:
                attrs[attr_name] = [_entity_ref(t) for t in targets]

        entities.append({"uid": _uid(comp), "attrs": attrs, "parents": []})

    return sorted(entities, key=lambda e: (e["uid"]["type"], e["uid"]["id"]))


def sample_policy() -> str:
    """A starting-point Cedar policy set governing runtime USE of the inventory."""
    return (
        _POLICY_HEADER
        + "\n"
        + "// 1) Deny use of any UNSANCTIONED (shadow-AI) component.\n"
        "forbid (principal, action, resource)\n"
        "when { resource has sanctioned && resource.sanctioned == false };\n"
        "\n"
        "// 2) Deny routing inference to a serving vendor without a signed BAA.\n"
        'forbid (principal, action == Action::"serve", resource)\n'
        "when { resource has baa && resource.baa == false };\n"
        "\n"
        "// 3) Deny use of a deployment site flagged drift-detected until\n"
        "//    it has been re-validated.\n"
        "forbid (principal, action, resource)\n"
        "when { resource has drift_status &&\n"
        '       resource.drift_status == "drift-detected" };\n'
        "\n"
        "// 4) Permit use of sanctioned components (closes the default-deny model).\n"
        "permit (principal, action, resource)\n"
        "when { resource has sanctioned && resource.sanctioned == true };\n"
    )


def write_entities(result: ScanResult, path: str | Path) -> None:
    """Write the Cedar entities JSON for ``result`` to ``path`` (deterministic)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(to_cedar_entities(result), indent=2) + "\n")


def write_policy(path: str | Path) -> None:
    """Write the sample Cedar policy set to ``path``."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(sample_policy())


__all__ = [
    "cedar_type",
    "to_cedar_entities",
    "sample_policy",
    "write_entities",
    "write_policy",
]
