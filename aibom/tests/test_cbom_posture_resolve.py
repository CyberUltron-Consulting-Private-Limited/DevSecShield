"""Variable resolution stays unresolved unless the value is a literal."""

from aibom.cbom.posture.hcl import Unresolved as HclUnresolved
from aibom.cbom.posture.resolve import (
    Absent,
    Resolved,
    Scope,
    Unresolved,
    VarDecl,
    gcp_binding_exposure,
    policy_exposure,
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


def test_gcp_public_member_stays_public_with_a_condition() -> None:
    assert gcp_binding_exposure(["allUsers"], {"title": "only-prod"}) == (
        "public",
        True,
    )
    assert gcp_binding_exposure(["allUsers"], None) == ("public", False)
    assert gcp_binding_exposure(["allAuthenticatedUsers"], None) == ("public", False)
    assert gcp_binding_exposure(["user:a@example.com"], None) == ("private", False)


def test_known_condition_keeps_a_star_principal_restricted() -> None:
    restricted = {
        "Effect": "Allow",
        "Principal": "*",
        "Condition": {"StringEquals": {"aws:SourceVpc": "vpc-1"}},
    }
    public = {"Effect": "Allow", "Principal": "*"}
    assert policy_exposure(restricted) == "restricted"
    assert policy_exposure(public) == "public"
    assert policy_exposure(dict(restricted)) == policy_exposure(restricted)


def test_oversized_expression_is_unresolved() -> None:
    node = [0] * 2001
    assert resolve_expr(node) == Unresolved("unresolved_expression")
