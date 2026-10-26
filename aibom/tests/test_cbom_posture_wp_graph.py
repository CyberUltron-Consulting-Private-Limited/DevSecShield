"""WP0 import-edge controls. Missing posture modules are skipped."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from support.wp_graph import (  # noqa: E402
    EDGES,
    OWNER,
    PACKAGES,
    ancestors,
    edges_are_acyclic,
    violations,
)

CBOM = Path(__file__).resolve().parents[2] / "src" / "aibom" / "cbom"


def _write(root: Path, rel: str, source: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(source), encoding="utf-8")


def test_edges_are_acyclic_and_name_every_package() -> None:
    assert edges_are_acyclic()
    named = {node for edge in EDGES for node in edge} | set(OWNER.values())
    assert named >= PACKAGES


def test_wp1_is_before_wp2() -> None:
    assert "WP1" in ancestors("WP2")
    assert "WP2" not in ancestors("WP1")


def test_real_tree_has_no_forward_import() -> None:
    assert violations(CBOM) == []


def test_forward_import_is_reported(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "support.wp_graph.OWNER",
        {"posture/early.py": "WP1", "posture/late.py": "WP2"},
    )
    _write(tmp_path, "posture/late.py", "X = 1\n")
    _write(
        tmp_path,
        "posture/early.py",
        "from aibom.cbom.posture.late import X\n",
    )
    lines = violations(tmp_path)
    assert any("early.py (WP1) imports posture/late.py (WP2)" in line for line in lines)


def test_type_checking_import_is_reported(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "support.wp_graph.OWNER",
        {"posture/early.py": "WP1", "posture/late.py": "WP2"},
    )
    _write(tmp_path, "posture/late.py", "class Late:\n    pass\n")
    _write(
        tmp_path,
        "posture/early.py",
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from aibom.cbom.posture.late import Late\n",
    )
    lines = violations(tmp_path)
    assert any("imports posture/late.py (WP2)" in line for line in lines)


def test_relative_forward_import_is_reported(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "support.wp_graph.OWNER",
        {"posture/early.py": "WP1", "posture/late.py": "WP2"},
    )
    _write(tmp_path, "posture/late.py", "X = 1\n")
    _write(tmp_path, "posture/early.py", "from .late import X\n")
    lines = violations(tmp_path)
    assert any("imports posture/late.py (WP2)" in line for line in lines)


def test_function_import_is_reported(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "support.wp_graph.OWNER",
        {"posture/early.py": "WP1", "posture/late.py": "WP2"},
    )
    _write(tmp_path, "posture/late.py", "X = 1\n")
    _write(
        tmp_path,
        "posture/early.py",
        "def load():\n    from aibom.cbom.posture.late import X\n    return X\n",
    )
    lines = violations(tmp_path)
    assert any("imports posture/late.py (WP2)" in line for line in lines)


def test_same_package_and_earlier_and_pair_pass(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "support.wp_graph.OWNER",
        {
            "posture/a.py": "WP1",
            "posture/b.py": "WP1",
            "posture/c.py": "WP2",
            "posture/left.py": "WP7",
            "posture/right.py": "WP7b",
        },
    )
    _write(tmp_path, "posture/b.py", "X = 1\n")
    _write(tmp_path, "posture/a.py", "from aibom.cbom.posture.b import X\n")
    _write(tmp_path, "posture/c.py", "from aibom.cbom.posture.a import X\n")
    _write(tmp_path, "posture/right.py", "Y = 1\n")
    _write(tmp_path, "posture/left.py", "from aibom.cbom.posture.right import Y\n")
    assert violations(tmp_path) == []


def test_cycle_is_reported(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "support.wp_graph.OWNER",
        {"posture/a.py": "WP1", "posture/b.py": "WP1"},
    )
    _write(tmp_path, "posture/a.py", "from aibom.cbom.posture.b import X\n")
    _write(tmp_path, "posture/b.py", "from aibom.cbom.posture.a import Y\n")
    lines = violations(tmp_path)
    assert any(line.startswith("cycle ") for line in lines)


def test_unowned_module_is_reported(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("support.wp_graph.OWNER", {})
    _write(tmp_path, "posture/orphan.py", "X = 1\n")
    lines = violations(tmp_path)
    assert "posture/orphan.py (none) has no owner" in lines
