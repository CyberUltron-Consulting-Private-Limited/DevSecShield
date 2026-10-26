"""Consulted paths are the only attributes a record may read."""

import pytest

from aibom.cbom.posture.records import AttrView
from aibom.cbom.posture.resolve import Absent, Resolved


def test_unlisted_attribute_is_not_readable() -> None:
    view = AttrView(
        {"encrypted": Resolved(True), "secret": Resolved("nope")},
        frozenset({"encrypted"}),
    )
    assert view.get("encrypted") == Resolved(True)
    with pytest.raises(KeyError):
        view.get("secret")


def test_missing_consulted_path_is_absent() -> None:
    view = AttrView({}, frozenset({"encrypted"}))
    assert view.get("encrypted") == Absent()
