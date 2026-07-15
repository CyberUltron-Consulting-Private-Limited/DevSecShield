"""bench/ci_gate.py — the hermetic P7 true-miss check used by the CI gates.

Given a repo id + the path to OUR freshly-emitted CycloneDX, return the list of
TRUE-POSITIVE misses vs the FROZEN OSS oracle snapshots in ``bench/ci_baseline/``,
after the documented FP-exclusions (``fp-exclusions.json``) and the same
detected-under-different-class / model-family-detected reconciliation the full
``diff.py`` applies. ``[]`` = pass. No network, no OSS tools — the oracles are the
committed snapshots, so only OUR (offline, deterministic) detection is exercised.

Used by ``aibom/tests/test_benchmark_gate.py`` (synthetic, hermetic) and
``bench/ci_repos.sh`` (representative repos cloned at a pinned SHA).
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from diff import _excluded, _load_exclusions  # noqa: E402
from normalize import model_family_root, normalize  # noqa: E402

BASELINE = HERE / "ci_baseline"

# the test refers to repos by short name; the FP-exclusions + snapshots use the
# canonical benchmark id (so a repo-scoped exclusion still matches).
_ALIAS = {
    "synthetic": "00-synthetic",
    "hf-model": "07-hf-minilm",
    "tf-bedrock": "09-tf-bedrock",
}


def true_misses(repo_id: str, ours_cdx_path: str) -> list[tuple[str, str]]:
    rid = _ALIAS.get(repo_id, repo_id)
    ours = normalize(Path(ours_cdx_path), "ours")
    oss: set[tuple[str, str]] = set()
    for tool, suffix in (("trusera", ".trusera.cdx.json"), ("cisco", ".cisco.json")):
        snap = BASELINE / f"{rid}{suffix}"
        if snap.exists():
            oss |= normalize(snap, tool)

    rules = _load_exclusions()
    our_names = {n for n, _ in ours}
    our_model_roots = {model_family_root(n) for n, t in ours if t == "model"}
    out: list[tuple[str, str]] = []
    for nm, tc in sorted(oss - ours):
        if _excluded(nm, tc, rid, rules) is not None:
            continue
        if nm in our_names:  # detected under a different type_class
            continue
        if tc == "model" and model_family_root(nm) in our_model_roots:
            continue          # we detect this model family at finer granularity
        out.append((nm, tc))
    return out


if __name__ == "__main__":  # CLI: ci_gate.py <repo_id> <ours.cdx.json>  -> exit 1 on miss
    misses = true_misses(sys.argv[1], sys.argv[2])
    if misses:
        print(f"FAIL {sys.argv[1]}: {len(misses)} true-positive miss(es): {misses}")
        sys.exit(1)
    print(f"PASS {sys.argv[1]}: 0 true-positive misses")
