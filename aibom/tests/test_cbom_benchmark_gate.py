"""B2 CBOM benchmark true-miss gate (hermetic, CI-blocking).

Runs OUR crypto scanner on the committed synthetic-crypto-app fixture and diffs
it against the FROZEN IBM cbomkit-theia oracle snapshot
(``bench/cbom/ci_baseline/``) via the same normalize + FP-triage logic the full
benchmark uses. The contract is two-sided:

* ZERO true-positive misses — if a scanner change starts dropping a crypto asset
  the oracle finds (and it isn't a documented oracle FP / cert-decomposition /
  finer-granularity detection), the build fails.
* our-unique > 0 — the CBOM lane must keep adding the source-code algorithm
  usage, TLS protocols, PQC grading and tri-state compliance the filesystem
  oracle structurally cannot see.

Hermetic — no docker, no network, no oracle run (the oracle is the committed
snapshot; only OUR offline, deterministic scanner runs). The full multi-repo
live benchmark runs via ``bench/cbom/run_all.sh``; the cloned representative-repo
gate runs via ``bench/cbom/ci_repos.sh``.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile

from aibom.cbom.pipeline import scan_crypto
from aibom.emit import get_reporter

_HERE = os.path.dirname(os.path.abspath(__file__))
_CBOM_BENCH = os.path.join(_HERE, "..", "..", "bench", "cbom")


def _load_harness(name: str):
    """Load a bench/cbom flat module under a unique name.

    ``bench/ci_gate.py`` (AIBOM) and ``bench/cbom/ci_gate.py`` (CBOM) share the
    bare module names ``ci_gate`` / ``diff`` / ``normalize``; importing by bare
    name would collide in ``sys.modules`` with whichever gate test ran first. We
    load each file fresh and register it under BOTH a namespaced alias and the
    bare name (the latter only transiently, so the CBOM ``ci_gate``'s internal
    ``from diff import`` / ``from normalize import`` resolve to its siblings)."""
    path = os.path.join(_CBOM_BENCH, f"{name}.py")
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # so sibling `from diff/normalize import` resolves
    spec.loader.exec_module(mod)
    sys.modules[f"cbom_bench_{name}"] = mod
    return mod


# load in dependency order: normalize <- diff <- ci_gate
_load_harness("normalize")
_load_harness("diff")
ci_gate = _load_harness("ci_gate")

_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


def _emit_ours(path: str) -> str:
    result = scan_crypto(path, level=4)  # production depth
    fd, out_path = tempfile.mkstemp(suffix=".cdx.json")
    with os.fdopen(fd, "w") as fh:
        fh.write(get_reporter("cyclonedx").render(result))
    return out_path


def test_synthetic_zero_true_misses() -> None:
    ours = _emit_ours(_FX)
    try:
        misses = ci_gate.true_misses("synthetic", ours)
    finally:
        os.unlink(ours)
    assert misses == [], (
        "CBOM regression: ours now misses true positives the cbomkit-theia oracle "
        f"finds (and they are not documented FPs): {misses}"
    )


def test_synthetic_our_unique_positive() -> None:
    ours = _emit_ours(_FX)
    try:
        unique = ci_gate.our_unique_count("synthetic", ours)
    finally:
        os.unlink(ours)
    assert unique > 0, (
        "CBOM regression: our crypto lane no longer adds source-code crypto the "
        "filesystem oracle lacks (source algorithms / TLS / PQC / compliance)."
    )
