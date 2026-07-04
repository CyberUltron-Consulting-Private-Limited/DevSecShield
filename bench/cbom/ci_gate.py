"""bench/cbom/ci_gate.py — the hermetic CBOM true-miss check used by the gate.

Given a repo id + the path to OUR freshly-emitted CycloneDX CBOM, return the list
of TRUE-POSITIVE misses vs the FROZEN cbomkit-theia oracle snapshot in
``bench/cbom/ci_baseline/``, after the documented FP-exclusions
(``fp-exclusions.json``) and the same detected-under-different-class /
algorithm-family reconciliation the full ``diff.py`` applies. ``[]`` = pass. No
network, no docker, no oracle run — the oracle is the committed snapshot, so only
OUR (offline, deterministic) crypto detection is exercised.

Used by ``aibom/tests/test_cbom_benchmark_gate.py`` (synthetic, hermetic) and
``bench/cbom/ci_repos.sh`` (representative repos cloned at a pinned SHA).
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from diff import _excluded, _load_exclusions  # noqa: E402
from normalize import (  # noqa: E402
    all_cert_key_evidence,
    crypto_family_root,
    evidence_index,
    normalize,
)

BASELINE = HERE / "ci_baseline"

# the test refers to repos by short name; snapshots use the canonical benchmark id.
_ALIAS = {
    "synthetic": "00-synthetic",
}


def true_misses(repo_id: str, ours_cdx_path: str) -> list[tuple[str, str]]:
    rid = _ALIAS.get(repo_id, repo_id)
    ours = normalize(Path(ours_cdx_path), "ours")
    snap = BASELINE / f"{rid}.cbomkit.cdx.json"
    oracle = normalize(snap, "cbomkit") if snap.exists() else set()

    rules = _load_exclusions()
    our_names = {n for n, _ in ours}
    our_algo_roots = {crypto_family_root(n) for n, t in ours if t == "algorithm"}
    ours_has_cert_or_key = any(
        t in ("certificate", "related-crypto-material") for _, t in ours
    )
    orc_evidence = evidence_index(snap) if snap.exists() else {}
    out: list[tuple[str, str]] = []
    for nm, tc in sorted(oracle - ours):
        if _excluded(nm, tc, rid, rules) is not None:
            continue
        if nm in our_names:  # detected under a different asset_class
            continue
        if tc == "algorithm" and crypto_family_root(nm) in our_algo_roots:
            continue          # we detect this algorithm family at finer granularity
        if (
            tc in ("algorithm", "related-crypto-material")
            and ours_has_cert_or_key
            and all_cert_key_evidence(orc_evidence.get((nm, tc), []))
        ):
            continue          # R3: oracle decomposed a cert/key binary we inventory
        out.append((nm, tc))
    return out


def our_unique_count(repo_id: str, ours_cdx_path: str) -> int:
    """Crypto assets OURS reports that the frozen oracle lacks (must be > 0)."""
    rid = _ALIAS.get(repo_id, repo_id)
    ours = normalize(Path(ours_cdx_path), "ours")
    snap = BASELINE / f"{rid}.cbomkit.cdx.json"
    oracle = normalize(snap, "cbomkit") if snap.exists() else set()
    return len(ours - oracle)


if __name__ == "__main__":  # CLI: ci_gate.py <repo_id> <ours.cdx.json> -> exit 1 on miss
    misses = true_misses(sys.argv[1], sys.argv[2])
    unique = our_unique_count(sys.argv[1], sys.argv[2])
    if misses:
        print(f"FAIL {sys.argv[1]}: {len(misses)} true-positive miss(es): {misses}")
        sys.exit(1)
    if unique <= 0:
        print(f"FAIL {sys.argv[1]}: our-unique={unique} (must be > 0)")
        sys.exit(1)
    print(f"PASS {sys.argv[1]}: 0 true-positive misses, our-unique={unique}")
