"""P7 benchmark true-miss gate (hermetic, CI-blocking).

Runs OUR scanner on the committed synthetic fixture and diffs it against the
FROZEN Trusera + Cisco oracle snapshots (``bench/ci_baseline/``) via the same
normalize + FP-triage logic the full benchmark uses. ZERO true-positive misses
is the contract: if a scanner change starts dropping an entity the oracles find
(and it isn't a documented OSS false positive), the build fails.

Hermetic — no network, no Bedrock, no clone (synthetic is a committed fixture).
The full 10-repo live benchmark runs on the nightly workflow; the cloned
"representative repos" (hf-model / tf-bedrock) gate runs as a CI step via
``bench/ci_gate.py``.
"""

from __future__ import annotations

import os
import sys
import tempfile

from aibom.emit import get_reporter
from aibom.scan.pipeline import scan_repo

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "bench"))
import ci_gate  # noqa: E402  (bench/ is isolated harness code, added to path above)

_FX = os.path.join(_HERE, "fixtures", "synthetic-ai-app")


def _emit_ours(path: str) -> str:
    result = scan_repo(path, level=4)  # production depth
    fd, out_path = tempfile.mkstemp(suffix=".cdx.json")
    with os.fdopen(fd, "w") as fh:
        fh.write(get_reporter("cyclonedx").render(result))
    return out_path


def test_synthetic_zero_true_misses() -> None:
    ours = _emit_ours(_FX)
    misses = ci_gate.true_misses("synthetic", ours)
    os.unlink(ours)
    assert misses == [], (
        "P7 regression: ours now misses true positives the OSS oracles find "
        f"(and they are not documented FPs): {misses}"
    )
