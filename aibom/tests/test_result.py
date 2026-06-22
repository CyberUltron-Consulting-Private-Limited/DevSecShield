"""ScanResult graph helpers + Edge/Flag dataclasses."""

from __future__ import annotations

from aibom.model.component import (
    DatasetComponent,
    FrameworkComponent,
    MetadataComponent,
    ModelComponent,
)
from aibom.model.result import (
    REL_DEPENDS_ON,
    REL_TRAINED_ON,
    Edge,
    Flag,
    ScanResult,
)


def _result() -> ScanResult:
    model = ModelComponent(bom_ref="m", name="model")
    dataset = DatasetComponent(bom_ref="d", name="data")
    lib = FrameworkComponent(bom_ref="l", name="lib")
    return ScanResult(
        subject=MetadataComponent(name="app"),
        components=[model, dataset, lib],
        edges=[
            Edge("m", REL_TRAINED_ON, "d"),
            Edge("m", REL_DEPENDS_ON, "l"),
        ],
        flags=[Flag("MODEL_NO_LICENSE", "m", "error", "no license")],
    )


def test_by_ref() -> None:
    r = _result()
    assert r.by_ref("m").name == "model"  # type: ignore[union-attr]
    assert r.by_ref("nope") is None


def test_out_edges_filtering() -> None:
    r = _result()
    assert len(r.out_edges("m")) == 2
    assert [e.dst for e in r.out_edges("m", REL_TRAINED_ON)] == ["d"]
    assert [e.dst for e in r.out_edges("m", REL_DEPENDS_ON)] == ["l"]
    assert r.out_edges("d") == []


def test_neighbors_resolves_and_filters() -> None:
    r = _result()
    assert {c.bom_ref for c in r.neighbors("m")} == {"d", "l"}
    assert [c.bom_ref for c in r.neighbors("m", REL_TRAINED_ON)] == ["d"]


def test_flags_for_and_component_bom_refs() -> None:
    r = _result()
    assert [f.code for f in r.flags_for("m")] == ["MODEL_NO_LICENSE"]
    assert r.flags_for("d") == []
    assert r.component_bom_refs() == ["d", "l", "m"]


def test_edge_and_flag_are_hashable_frozen() -> None:
    # frozen dataclasses -> usable in sets / as keys (dedup-friendly).
    assert Edge("a", "r", "b").key() == ("a", "r", "b")
    assert len({Edge("a", "r", "b"), Edge("a", "r", "b")}) == 1
    assert Flag("X", "t").key() == ("t", "X")


def test_sort_is_deterministic() -> None:
    r = ScanResult(
        subject=MetadataComponent(name="app"),
        edges=[Edge("z", "r", "a"), Edge("a", "r", "b")],
        flags=[Flag("Z", "t2"), Flag("A", "t1")],
    )
    r.sort()
    assert [e.src for e in r.edges] == ["a", "z"]
    assert [f.code for f in r.flags] == ["A", "Z"]
