"""CI entry for the CB-02 CBOM lab's unit tests (e2e/cbom/lab/tests/test_lab.py).

The lab is harness code: it imports nothing from the product (oracle rule O-1), and no CI suite collects e2e/.
The backend suite already reads e2e/ (its path filter includes it), so its tests are collected here, by name, without
copying them. They need no Docker; the live proofs (gen.py up/selfcheck/negative) are gate evidence, not unit tests.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_LAB_TESTS = Path(__file__).resolve().parents[2] / "e2e" / "cbom" / "lab" / "tests" / "test_lab.py"
_spec = importlib.util.spec_from_file_location("cb02_lab_tests", _LAB_TESTS)
assert _spec and _spec.loader, _LAB_TESTS
_mod = importlib.util.module_from_spec(_spec)
sys.modules["cb02_lab_tests"] = _mod
_spec.loader.exec_module(_mod)

globals().update({name: obj for name, obj in vars(_mod).items() if name.startswith("test_") and callable(obj)})
