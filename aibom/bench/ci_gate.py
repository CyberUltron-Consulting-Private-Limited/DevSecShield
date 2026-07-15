"""bench/ci_gate.py — the P7 true-miss gate for ONE repo, against FROZEN oracles.

Compares OUR CycloneDX output for a repo to the committed Trusera+Cisco oracle
snapshots in ``ci_baseline/`` and returns the TRUE-positive misses (raw
``(Cisco ∪ Trusera) \\ Ours`` minus the documented OSS false positives in
``fp_exclusions.json``). Zero true-misses = the gate passes.

Used two ways:
* hermetic pytest (``tests/test_benchmark_gate.py``) for the synthetic fixture, and
* the CI "representative repos" step (clones hf-model / tf-bedrock at a pinned SHA,
  emits ours, then ``python ci_gate.py <repo> <ours.cdx.json>`` — exit 1 if >0).
"""

from __future__ import annotations

import json
import os
import re
import sys

from normalize import canonical_set

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(HERE, "ci_baseline")
FP = os.path.join(HERE, "fp_exclusions.json")


def _fp():
    with open(FP) as fh:
        data = json.load(fh)
    exact = {(e["repo"], e["class"], e["name"]) for e in data.get("exact", [])}
    pats = [(p["class"], re.compile(p["name_regex"])) for p in data.get("patterns", [])]
    return exact, pats


def _is_fp(repo: str, cls: str, name: str, exact, pats) -> bool:
    return (repo, cls, name) in exact or any(
        pc == cls and rx.search(name) for pc, rx in pats
    )


def true_misses(repo: str, ours_cdx_path: str) -> list[tuple[str, str]]:
    """(class, name) the oracles found and ours missed, after FP triage."""
    exact, pats = _fp()
    tru_p = os.path.join(BASE, f"{repo}.trusera.cdx.json")
    cis_p = os.path.join(BASE, f"{repo}.cisco.json")
    tru = canonical_set("trusera", tru_p) if os.path.exists(tru_p) else set()
    cis = canonical_set("cisco", cis_p) if os.path.exists(cis_p) else set()
    ours = canonical_set("ours", ours_cdx_path)
    return sorted(
        (c, n) for n, c in ((tru | cis) - ours) if not _is_fp(repo, c, n, exact, pats)
    )


if __name__ == "__main__":
    repo, ours_path = sys.argv[1], sys.argv[2]
    miss = true_misses(repo, ours_path)
    if miss:
        print(f"FAIL {repo}: {len(miss)} true-miss(es): "
              + ", ".join(f"{c}:{n}" for c, n in miss))
        raise SystemExit(1)
    print(f"PASS {repo}: 0 true-misses vs frozen Cisco+Trusera oracles")
