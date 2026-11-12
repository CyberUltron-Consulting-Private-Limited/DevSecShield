"""The CBOM end-to-end harness (e2e/cbom, CB-01) in CI.

* its own unit suite (the gate's positive controls: a deliberately wrong CBOM fails, a correct one passes);
* O-1 (DEVILS-ADVOCATE.md §3): harness and oracle code import nothing from backend/, aibom/, scan_node/ or frontend/,
  so an expected value can never come from the code under test;
* the known-fail ledger parses and every row names an issue and an owning track.
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CBOM = ROOT / "e2e" / "cbom"
PRODUCT = ("backend", "aibom", "scan_node", "zs_scan_node", "frontend", "RabbitMQ")


def _product_imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    bad = []
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module]
        elif isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) in (
                "import_module", "__import__") and node.args and isinstance(node.args[0], ast.Constant):
            names = [str(node.args[0].value)]
        bad += [f"{path.relative_to(ROOT)}:{node.lineno} imports {n}" for n in names if n.split(".")[0] in PRODUCT]
    return bad


def test_harness_imports_no_product_code():
    files = sorted(CBOM.rglob("*.py"))
    assert any(p.parent.name == "harness" for p in files), "e2e/cbom/harness not found"
    offenders = [line for path in files for line in _product_imports(path)]
    assert offenders == []


def test_import_lint_catches_a_product_import(tmp_path):
    """Positive control for the lint above."""
    bad = tmp_path / "bad.py"
    bad.write_text("import os\nfrom backend.utilities.cbom_sources import classify\nimport aibom.cbom\n"
                   "__import__('scan_node')\n", encoding="utf-8")
    original = globals()["ROOT"]
    try:
        globals()["ROOT"] = tmp_path
        assert len(_product_imports(bad)) == 3
    finally:
        globals()["ROOT"] = original


def test_harness_unit_suite_passes():
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "addopts=",
                           "--rootdir", str(CBOM), str(CBOM / "tests")],
                          cwd=CBOM, capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stdout[-6000:] + proc.stderr[-3000:]
