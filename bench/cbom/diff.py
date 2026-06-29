#!/usr/bin/env python3
"""bench/cbom/diff.py — per-repo + aggregate CBOM diff matrix with FP-triage + gate.

For each repo, normalise the cbomkit-theia oracle output and OUR output to
canonical ``{(name, asset_class)}`` sets (``bench/cbom/normalize.py``) and compute:

    Misses    = CBOMkit \\ Ours        # crypto the oracle finds, we don't
    OurUnique = Ours \\ CBOMkit        # crypto we add the oracle lacks
    Overlap   = Ours ∩ CBOMkit

The GATE is on TRUE-POSITIVE misses, not raw set difference. Each Miss is triaged
against ``bench/cbom/fp-exclusions.json``; what survives is a REAL miss → a fix
task against our crypto scanner. Two reconciliations (mirroring the AIBOM bench)
are applied before a Miss counts:

* detected_under_different_class — we inventory the SAME name under a different
  asset_class (cbomkit lists the cert's RSA key as related-crypto-material; we
  list ``RSA-2048`` as an algorithm).
* algorithm_family_detected — for an ``algorithm`` Miss, we inventory the same
  FAMILY at finer granularity (cbomkit's bare ``RSA`` vs our ``RSA-2048`` /
  ``RSA-1024``).

Pass = (true-miss == 0 for every repo) AND (OurUnique > 0). OurUnique > 0 is the
whole point of the CBOM lane: the filesystem oracle cannot see source-code
algorithm usage, TLS protocol versions, PQC grading, or tri-state compliance.

Usage: diff.py            # all repos found in out/, writes report.md + state
       diff.py <repo-id>  # one repo, prints to stdout
NOT product code — bench/cbom/ only.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from normalize import (
    all_cert_key_evidence,
    crypto_family_root,
    evidence_index,
    normalize,
)

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
BASELINE = HERE / "ci_baseline"
EXCL_FILE = HERE / "fp-exclusions.json"


def _load_exclusions() -> list[dict]:
    if EXCL_FILE.exists():
        return json.loads(EXCL_FILE.read_text())
    return []


def _excluded(name: str, klass: str, repo: str, rules: list[dict]) -> str | None:
    """Return the justification if (name, klass[, repo]) is a known oracle FP."""
    for r in rules:
        if r.get("asset_class") not in (klass, "*"):
            continue
        nm_ok = r.get("name") in (name, "*") or (
            "name_re" in r and re.search(r["name_re"], name) is not None
        )
        if not nm_ok:
            continue
        if r.get("repo", "*") in ("*", repo):
            return r.get("reason", "(no reason given)")
    return None


def _oracle_path(repo: str) -> Path:
    """The committed frozen oracle snapshot, else a fresh out/ snapshot."""
    snap = BASELINE / f"{repo}.cbomkit.cdx.json"
    return snap if snap.exists() else OUT / f"{repo}.cbomkit.cdx.json"


def _repos() -> list[str]:
    ids = set()
    for p in OUT.glob("*.ours.cdx.json"):
        ids.add(p.name.split(".ours.cdx.json")[0])
    return sorted(ids)


def _sets(repo: str) -> dict[str, set]:
    ours_f = OUT / f"{repo}.ours.cdx.json"
    orc_f = _oracle_path(repo)
    return {
        "cbomkit": normalize(orc_f, "cbomkit") if orc_f.exists() else set(),
        "ours": normalize(ours_f, "ours") if ours_f.exists() else set(),
    }


def diff_repo(repo: str, rules: list[dict]) -> dict:
    s = _sets(repo)
    oracle = s["cbomkit"]
    ours = s["ours"]
    misses = sorted(oracle - ours)
    our_names = {n for n, _ in ours}
    our_algo_roots = {crypto_family_root(n) for n, t in ours if t == "algorithm"}
    ours_has_cert_or_key = any(
        t in ("certificate", "related-crypto-material") for _, t in ours
    )
    orc_evidence = evidence_index(_oracle_path(repo)) if _oracle_path(repo).exists() else {}
    triaged = []
    true_misses = []
    for nm, tc in misses:
        reason = _excluded(nm, tc, repo, rules)
        if reason is None and nm in our_names:
            reason = (
                f"detected_under_different_class: we inventory '{nm}' "
                f"(the oracle assigned it asset_class='{tc}')"
            )
        if reason is None and tc == "algorithm" and crypto_family_root(nm) in our_algo_roots:
            reason = (
                f"algorithm_family_detected: we inventory the "
                f"'{crypto_family_root(nm)}' family at finer granularity"
            )
        # R3 — cert/key-decomposition: a filesystem oracle decomposes a binary
        # cert/key file into its embedded algorithm + key material; our source-
        # code lane inventories that file as a certificate / key asset instead.
        if (
            reason is None
            and tc in ("algorithm", "related-crypto-material")
            and ours_has_cert_or_key
            and all_cert_key_evidence(orc_evidence.get((nm, tc), []))
        ):
            reason = (
                "cert_key_decomposition: the oracle decomposed a binary cert/key "
                f"file ({', '.join(sorted(set(orc_evidence.get((nm, tc), []))))}); "
                "our source-code lane inventories that file as a certificate / "
                "key-material asset"
            )
        triaged.append(
            {"name": nm, "asset_class": tc, "fp": reason is not None, "reason": reason}
        )
        if reason is None:
            true_misses.append((nm, tc))
    return {
        "repo": repo,
        "cbomkit": len(oracle),
        "ours": len(ours),
        "overlap": len(ours & oracle),
        "misses_raw": len(misses),
        "true_misses": [list(x) for x in true_misses],
        "our_unique": sorted(list(x) for x in (ours - oracle)),
        "triaged": triaged,
    }


def main() -> int:
    rules = _load_exclusions()
    repos = [sys.argv[1]] if len(sys.argv) > 1 else _repos()
    results = [diff_repo(r, rules) for r in repos]

    lines = [
        "# CBOM benchmark — diff matrix (ours vs IBM cbomkit-theia)\n",
        "Canonical key = (normalized_name, asset_class). Misses = "
        "CBOMkit \\ Ours; triaged against `fp-exclusions.json`. The oracle is a "
        "FILESYSTEM scanner (certs/keys/secrets); ours adds source-code algorithm "
        "usage, TLS protocols, PQC grading and tri-state compliance — hence the "
        "large our-unique column.\n",
        "| repo | CBOMkit | Ours | overlap | raw-miss | **true-miss** | our-unique |",
        "|------|--------:|-----:|--------:|---------:|--------------:|-----------:|",
    ]
    agg_true = 0
    agg_unique = 0
    for r in results:
        tm = len(r["true_misses"])
        agg_true += tm
        agg_unique += len(r["our_unique"])
        lines.append(
            f"| {r['repo']} | {r['cbomkit']} | {r['ours']} | {r['overlap']} | "
            f"{r['misses_raw']} | **{tm}** | {len(r['our_unique'])} |"
        )
    lines.append(f"| **TOTAL** | | | | | **{agg_true}** | {agg_unique} |\n")

    any_true = False
    for r in results:
        if r["true_misses"]:
            any_true = True
            lines.append(f"### TRUE MISSES — {r['repo']} (fix our crypto scanner)")
            for nm, tc in r["true_misses"]:
                lines.append(f"- `{tc}` **{nm}**")
    if not any_true:
        lines.append("### TRUE MISSES — none across all repos ✅")

    gate_pass = agg_true == 0 and agg_unique > 0
    lines.append(
        f"\n## GATE: {'PASS ✅' if gate_pass else 'FAIL ❌'} — "
        f"true-misses={agg_true} (must be 0), our-unique={agg_unique} (must be >0)"
    )

    report = "\n".join(lines) + "\n"
    if len(sys.argv) > 1:
        print(report)
    else:
        (HERE / "report.md").write_text(report)
        state = {
            r["repo"]: {
                "cbomkit": r["cbomkit"],
                "ours": r["ours"],
                "true_misses": r["true_misses"],
                "our_unique_count": len(r["our_unique"]),
            }
            for r in results
        }
        (HERE / "state" / "benchmark.json").write_text(json.dumps(state, indent=2))
        print(report)
    return 0 if gate_pass else 1


if __name__ == "__main__":
    sys.exit(main())
