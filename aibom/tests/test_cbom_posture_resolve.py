"""Variable resolution stays unresolved unless the value is a literal."""

from aibom.cbom.posture.hcl import Unresolved as HclUnresolved
from aibom.cbom.posture.resolve import (
    Absent,
    Resolved,
    Scope,
    Unresolved,
    VarDecl,
    resolve_expr,
)


def test_literal_resolves() -> None:
    assert resolve_expr(True) == Resolved(True)
    assert resolve_expr("on") == Resolved("on")


def test_variable_default_resolves() -> None:
    scope = Scope(variables={"size": VarDecl("size", Resolved(2048))})
    node = HclUnresolved("variable", "size", ())
    assert resolve_expr(node, scope) == Resolved(2048)


def test_tfvars_override_is_unresolved() -> None:
    scope = Scope(variables={"size": VarDecl("size", Resolved(2048), overridden=True)})
    node = HclUnresolved("variable", "size", ())
    assert resolve_expr(node, scope) == Unresolved("variable_overridden")


def test_missing_default_is_not_absent() -> None:
    scope = Scope(variables={"size": VarDecl("size", Absent())})
    node = HclUnresolved("variable", "size", ())
    got = resolve_expr(node, scope)
    assert got == Unresolved("variable_no_default")
    assert not isinstance(got, Absent)


def test_locals_and_data_stay_unresolved() -> None:
    for kind in ("local", "module", "data"):
        got = resolve_expr(HclUnresolved(kind, "x", ()))
        assert got == Unresolved("unresolved_expression")


def test_policy_document_uses_scope_documents() -> None:
    scope = Scope(documents={"pub": Resolved({"Statement": []})})
    node = {"kind": "data.aws_iam_policy_document", "name": "pub"}
    assert resolve_expr(node, scope) == Resolved({"Statement": []})


def test_oversized_expression_is_unresolved() -> None:
    node = [0] * 2001
    assert resolve_expr(node) == Unresolved("unresolved_expression")
