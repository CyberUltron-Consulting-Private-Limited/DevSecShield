"""Literal resolution. Expressions that are not literals stay unresolved."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from aibom.cbom.posture.hcl import Unresolved as HclUnresolved

_NODE_CAP = 2_000


@dataclass(frozen=True, slots=True)
class Resolved:
    value: object


@dataclass(frozen=True, slots=True)
class Unresolved:
    reason: str


@dataclass(frozen=True, slots=True)
class Absent:
    pass


Value = Resolved | Unresolved | Absent


@dataclass(frozen=True, slots=True)
class VarDecl:
    name: str
    default: Value
    overridden: bool = False


@dataclass(frozen=True, slots=True)
class Scope:
    unit: str = ""
    provider_alias: str = ""
    variables: Mapping[str, VarDecl] | None = None
    versions: Mapping[str, tuple[int, ...]] | None = None
    declared: Mapping[tuple[str, str], str] | None = None
    overrides: Mapping[tuple[str, str], Value] | None = None
    documents: Mapping[str, Value] | None = None


def _count(node: object) -> int:
    if isinstance(node, (list, tuple)):
        return 1 + sum(_count(item) for item in node)
    if isinstance(node, dict):
        return 1 + sum(_count(item) for item in node.values())
    return 1


def _literal(node: object) -> Resolved | None:
    if isinstance(node, (str, int, float, bool)) or node is None:
        return Resolved(node)
    if isinstance(node, (list, tuple)) and all(
        isinstance(item, (str, int, float, bool)) or item is None for item in node
    ):
        return Resolved(tuple(node))
    return None


def resolve_expr(node: object, scope: Scope | None = None) -> Value:
    """Resolve a literal or a variable default. Everything else is unresolved."""
    if _count(node) > _NODE_CAP:
        return Unresolved("unresolved_expression")
    literal = _literal(node)
    if literal is not None:
        return literal
    if isinstance(node, HclUnresolved):
        return _hcl(node, scope or Scope())
    if isinstance(node, dict) and node.get("kind") == "data.aws_iam_policy_document":
        name = str(node.get("name") or "")
        documents = (scope.documents if scope else None) or {}
        return documents.get(name, Unresolved("unresolved_expression"))
    return Unresolved("unresolved_expression")


def _hcl(node: HclUnresolved, scope: Scope) -> Value:
    blocked = {
        "local",
        "module",
        "data",
        "each",
        "count",
        "splat",
        "for",
        "call",
        "conditional",
    }
    if node.kind in blocked:
        return Unresolved("unresolved_expression")
    if node.kind != "variable":
        return Unresolved("unresolved_expression")
    name = node.raw_span
    variables = scope.variables or {}
    decl = variables.get(name)
    if decl is None or isinstance(decl.default, Absent):
        return Unresolved("variable_no_default")
    if decl.overridden:
        return Unresolved("variable_overridden")
    if isinstance(decl.default, Resolved):
        return decl.default
    return Unresolved("variable_no_default")
