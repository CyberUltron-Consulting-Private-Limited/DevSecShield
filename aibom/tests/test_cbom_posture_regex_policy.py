"""WP1 does not compile a regular expression from file text."""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "aibom" / "cbom" / "posture"


def test_re_compile_uses_only_literals() -> None:
    for path in sorted(ROOT.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = getattr(func, "attr", None) or getattr(func, "id", None)
            if name != "compile" or not node.args:
                continue
            assert isinstance(node.args[0], ast.Constant), path.name
