"""Internal-consistency gate for synthetic-config-* posture oracles (R45.3).

Peer of ``test_crypto_fixture_manifest.py``. Does not call ``scan_crypto``.
Each tree under ``fixtures/synthetic-config-*`` must carry
``expected_config_<suffix>.json`` and ``SOURCE.md``. ``totals`` must equal the
sums of the per-resource entries.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from support.oracle import read_oracle

_FIX = Path(__file__).resolve().parent / "fixtures"
_REQUIRED_FACT_KEYS = frozenset(
    {
        "address",
        "path",
        "line",
        "kind",
        "native_type",
        "provider",
        "layers",
        "verdict",
        "key_management",
        "unknown_reason",
        "default_row",
        "finding_codes",
        "covers",
        "outcome",
        "why",
    }
)
_REQUIRED_TOTAL_KEYS = frozenset(
    {
        "facts",
        "by_kind",
        "by_verdict",
        "by_code",
        "out_of_scope",
        "disabled",
        "diagnostic_totals",
    }
)


def _trees() -> list[Path]:
    return sorted(
        path
        for path in _FIX.iterdir()
        if path.is_dir() and path.name.startswith("synthetic-config-")
    )


def _oracle_path(tree: Path) -> Path:
    suffix = tree.name.removeprefix("synthetic-config-").replace("-", "_")
    return tree / f"expected_config_{suffix}.json"


@pytest.mark.parametrize("tree", _trees(), ids=lambda path: path.name)
def test_each_tree_has_oracle_and_source(tree: Path) -> None:
    assert _oracle_path(tree).is_file(), f"missing oracle for {tree.name}"
    assert (tree / "SOURCE.md").is_file(), f"missing SOURCE.md for {tree.name}"


@pytest.mark.parametrize("tree", _trees(), ids=lambda path: path.name)
def test_oracle_shape_and_totals(tree: Path) -> None:
    oracle = read_oracle(_oracle_path(tree))
    assert "facts" in oracle
    assert "totals" in oracle
    facts = oracle["facts"]
    totals = oracle["totals"]
    assert isinstance(facts, list)
    assert _REQUIRED_TOTAL_KEYS <= set(totals)
    assert totals["facts"] == len(facts)

    by_kind: dict[str, int] = {}
    by_verdict: dict[str, int] = {}
    by_code: dict[str, int] = {}
    for entry in facts:
        missing = _REQUIRED_FACT_KEYS - set(entry)
        assert not missing, f"{tree.name}: fact missing {sorted(missing)}"
        assert isinstance(entry["layers"], dict) and entry["layers"]
        assert isinstance(entry["finding_codes"], list)
        assert isinstance(entry["covers"], list)
        assert entry["outcome"] in {"positive", "negative"}
        assert isinstance(entry["why"], str) and entry["why"]
        by_kind[entry["kind"]] = by_kind.get(entry["kind"], 0) + 1
        by_verdict[entry["verdict"]] = by_verdict.get(entry["verdict"], 0) + 1
        for code in entry["finding_codes"]:
            by_code[code] = by_code.get(code, 0) + 1

    assert totals["by_kind"] == by_kind
    assert totals["by_verdict"] == by_verdict
    assert totals["by_code"] == by_code
    assert isinstance(totals["out_of_scope"], int)
    assert isinstance(totals["disabled"], int)
    assert isinstance(totals["diagnostic_totals"], dict)


def test_at_least_one_config_tree_is_present() -> None:
    assert _trees(), "no synthetic-config-* trees under fixtures/"
