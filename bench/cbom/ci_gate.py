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
    crypto_libraries,
    evidence_index,
    normalize,
)

BASELINE = HERE / "ci_baseline"

# the test refers to repos by short name; snapshots use the canonical benchmark id.
_ALIAS = {
    "synthetic": "00-synthetic",
}

# Oracle registry (B1): each frozen oracle snapshot lives at
# ``ci_baseline/{repo}.{oracle}.cdx.json`` and is compared in its own LANE.
#   cbomkit — IBM cbomkit-theia, FILESYSTEM oracle, compared in the crypto-asset lane.
#   cdxgen  — @cyclonedx/cdxgen, DEPENDENCY oracle, compared in the crypto-library lane.
ORACLE_LANE = {"cbomkit": "crypto_asset", "cdxgen": "library"}


def _snap(repo_id: str, oracle: str) -> Path:
    return BASELINE / f"{_ALIAS.get(repo_id, repo_id)}.{oracle}.cdx.json"


def available_oracles(repo_id: str) -> list[str]:
    """Oracles that have a committed frozen baseline for this repo."""
    return [o for o in ORACLE_LANE if _snap(repo_id, o).exists()]


def _library_true_misses(repo_id: str, ours_cdx_path: str, oracle: str) -> list[tuple[str, str]]:
    """Crypto-library lane: oracle crypto-libs \\ ours, minus documented FPs."""
    rid = _ALIAS.get(repo_id, repo_id)
    snap = _snap(repo_id, oracle)
    ours = crypto_libraries(Path(ours_cdx_path))
    oracle_set = crypto_libraries(snap) if snap.exists() else set()
    rules = _load_exclusions()
    return [
        (nm, tc)
        for nm, tc in sorted(oracle_set - ours)
        if _excluded(nm, tc, rid, rules) is None
    ]


def true_misses(
    repo_id: str, ours_cdx_path: str, oracle: str = "cbomkit"
) -> list[tuple[str, str]]:
    if ORACLE_LANE.get(oracle) == "library":
        return _library_true_misses(repo_id, ours_cdx_path, oracle)
    rid = _ALIAS.get(repo_id, repo_id)
    ours = normalize(Path(ours_cdx_path), "ours")
    snap = _snap(repo_id, oracle)
    oracle_set = normalize(snap, "cbomkit") if snap.exists() else set()

    rules = _load_exclusions()
    our_names = {n for n, _ in ours}
    our_algo_roots = {crypto_family_root(n) for n, t in ours if t == "algorithm"}
    ours_has_cert_or_key = any(
        t in ("certificate", "related-crypto-material") for _, t in ours
    )
    orc_evidence = evidence_index(snap) if snap.exists() else {}
    out: list[tuple[str, str]] = []
    for nm, tc in sorted(oracle_set - ours):
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


def our_unique_count(repo_id: str, ours_cdx_path: str, oracle: str = "cbomkit") -> int:
    """Crypto assets/libraries OURS reports that the frozen oracle lacks (> 0)."""
    lane = ORACLE_LANE.get(oracle)
    extract = crypto_libraries if lane == "library" else (
        lambda p: normalize(p, "ours")
    )
    snap = _snap(repo_id, oracle)
    ours = extract(Path(ours_cdx_path))
    oracle_set = extract(snap) if snap.exists() else set()
    return len(ours - oracle_set)


if __name__ == "__main__":  # CLI: ci_gate.py <repo_id> <ours.cdx.json> -> exit 1 on miss
    repo_id, ours_path = sys.argv[1], sys.argv[2]
    oracles = available_oracles(repo_id) or ["cbomkit"]
    fail = False
    for orc in oracles:
        misses = true_misses(repo_id, ours_path, oracle=orc)
        unique = our_unique_count(repo_id, ours_path, oracle=orc)
        if misses:
            print(f"FAIL {repo_id} [{orc}]: {len(misses)} true-positive miss(es): {misses}")
            fail = True
        elif unique <= 0:
            print(f"FAIL {repo_id} [{orc}]: our-unique={unique} (must be > 0)")
            fail = True
        else:
            print(f"PASS {repo_id} [{orc}]: 0 true-positive misses, our-unique={unique}")
    sys.exit(1 if fail else 0)
