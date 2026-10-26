"""Decision table. First match wins, and a default is not a false fail."""

from aibom.cbom.posture.resolve import Absent, Resolved
from aibom.cbom.posture.verdict import (
    LayerCase,
    assess_layer,
    coverage,
    resource_verdict,
    tri_state,
)


def test_enabling_literal_is_declared() -> None:
    got = assess_layer(LayerCase(sources=(Resolved(True),)))
    assert got.verdict == "ENCRYPTED_DECLARED"


def test_disabling_literal_is_not_encrypted() -> None:
    got = assess_layer(LayerCase(sources=(Resolved(False),), caveat="off"))
    assert got.verdict == "NOT_ENCRYPTED"
    assert got.caveat == "off"


def test_other_literal_is_not_enabling() -> None:
    got = assess_layer(LayerCase(sources=(Resolved("maybe"),)))
    assert got.verdict == "UNKNOWN"
    assert got.reason == "attribute_not_modeled"


def test_declared_outranks_provider_default() -> None:
    layers = {"service": "ENCRYPTED_PROVIDER_DEFAULT", "backup": "ENCRYPTED_DECLARED"}
    assert resource_verdict(layers, transport_only=False) == "ENCRYPTED_DECLARED"


def test_absent_unassessable_default_is_unknown() -> None:
    got = assess_layer(
        LayerCase(
            sources=(Absent(),),
            effect="NOT_ENCRYPTED",
            assessable=False,
            row_id="ebs",
        )
    )
    assert got.verdict == "UNKNOWN"
    assert got.reason == "default_unknown"


def test_assessable_absent_default_fails() -> None:
    got = assess_layer(
        LayerCase(
            sources=(Absent(),),
            effect="NOT_ENCRYPTED",
            assessable=True,
            row_id="row",
        )
    )
    assert got.verdict == "NOT_ENCRYPTED"
    assert got.default_row == "row"


def test_unpinned_version_does_not_pick_the_newest_row() -> None:
    got = assess_layer(
        LayerCase(
            sources=(Absent(),),
            effect="ENCRYPTED",
            version_dependent=True,
            version_pinned=False,
            row_id="nginx",
        )
    )
    assert got.verdict == "UNKNOWN"
    assert got.reason == "provider_version_dependent"


def test_unknown_is_not_a_pass() -> None:
    assert tri_state("UNKNOWN") == "not_bom_evidenceable"
    assert tri_state("ENCRYPTED_DECLARED") == "pass"
    assert tri_state("NOT_ENCRYPTED") == "fail"
    assert coverage(["not_bom_evidenceable"]) is None
    assert coverage(["pass", "fail"]) == 0.5


def test_as_absent_literal_uses_the_default() -> None:
    got = assess_layer(
        LayerCase(
            sources=(Resolved(False),),
            as_absent=frozenset({False}),
            effect="ENCRYPTED",
            row_id="dynamodb",
        )
    )
    assert got.verdict == "ENCRYPTED_PROVIDER_DEFAULT"
