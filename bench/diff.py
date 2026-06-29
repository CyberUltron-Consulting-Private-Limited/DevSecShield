#!/usr/bin/env python3
"""bench/diff.py — per-repo + aggregate diff matrix with FP-aware triage + gate.

For each repo, normalise the three tool outputs to canonical {(name, type_class)}
sets (bench/normalize.py) and compute:

    Misses    = (Cisco ∪ Trusera) \\ Ours          # what the OSS tools find, we don't
    OurUnique = Ours \\ (Cisco ∪ Trusera)          # what we add the OSS tools lack
    Overlap   = Ours ∩ (Cisco ∪ Trusera)

The GATE is on TRUE-POSITIVE misses, not raw set difference: each Miss is triaged
against bench/fp-exclusions.json. An excluded Miss is an OSS FALSE POSITIVE (regex
noise / mislabel) with a written reason; what survives is a REAL miss → a fix task
against our scanner. Pass = (true-miss == 0 for every repo) AND (OurUnique > 0).

Usage: diff.py            # all repos found in out/, writes report.md + state
       diff.py <repo-id>  # one repo, prints to stdout
NOT product code — bench/ only.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from normalize import model_family_root, normalize

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
EXCL_FILE = HERE / "fp-exclusions.json"


def _load_exclusions() -> list[dict]:
    if EXCL_FILE.exists():
        return json.loads(EXCL_FILE.read_text())
    return []


def _excluded(name: str, tclass: str, repo: str, rules: list[dict]) -> str | None:
    """Return the justification if (name, tclass[, repo]) is a known OSS FP, else None.

    A rule matches when its ``type_class`` matches (or '*') AND the name matches —
    by exact ``name`` ('*' = any) OR by ``name_re`` (a regex, for noise CLASSES like
    Cisco's prose/hyperparameter extractions) — AND the repo matches (or '*').
    """
    for r in rules:
        if r.get("type_class") not in (tclass, "*"):
            continue
        nm_ok = r.get("name") in (name, "*") or (
            "name_re" in r and re.search(r["name_re"], name) is not None
        )
        if not nm_ok:
            continue
        rr = r.get("repo", "*")
        if rr in ("*", repo):
            return r.get("reason", "(no reason given)")
    return None


def _repos() -> list[str]:
    ids = set()
    for p in OUT.glob("*.ours.cdx.json"):
        ids.add(p.name.split(".ours.cdx.json")[0])
    return sorted(ids)


def _sets(repo: str) -> dict[str, set]:
    sets: dict[str, set] = {}
    for tool, suffix in (("trusera", ".trusera.cdx.json"),
                         ("cisco", ".cisco.json"),
                         ("ours", ".ours.cdx.json")):
        f = OUT / f"{repo}{suffix}"
        sets[tool] = normalize(f, tool) if f.exists() else set()
    return sets


def diff_repo(repo: str, rules: list[dict]) -> dict:
    s = _sets(repo)
    oss = s["trusera"] | s["cisco"]
    ours = s["ours"]
    misses = sorted(oss - ours)
    our_names = {n for n, _ in ours}  # names we detect, regardless of type_class
    our_model_roots = {model_family_root(n) for n, t in ours if t == "model"}
    triaged = []
    true_misses = []
    for nm, tc in misses:
        reason = _excluded(nm, tc, repo, rules)
        # Not a real miss if WE detect the same component under a different
        # type_class (the OSS tools disagree on class — e.g. they tag the boto3 /
        # vllm / yfinance LIBRARY as a model/mcp_server). We inventoried it.
        if reason is None and nm in our_names:
            reason = (f"detected_under_different_class: we inventory '{nm}' "
                      f"(the OSS tool assigned it type_class='{tc}')")
        # Not a real miss if we detect the same MODEL FAMILY at finer granularity
        # (the OSS pick a bare/different-version id of a family we inventory — e.g.
        # they list 'gpt-3.5-turbo' / 'gpt-4o-2024-11-20', we list
        # 'gpt-3.5-turbo-16k-0613' / 'gpt-4o-2024-08-06').
        if reason is None and tc == "model" and model_family_root(nm) in our_model_roots:
            reason = (f"model_family_detected: we inventory the "
                      f"'{model_family_root(nm)}' family at finer granularity")
        triaged.append({"name": nm, "type_class": tc, "fp": reason is not None,
                        "reason": reason})
        if reason is None:
            true_misses.append((nm, tc))
    return {
        "repo": repo,
        "trusera": len(s["trusera"]), "cisco": len(s["cisco"]), "ours": len(ours),
        "overlap": len(ours & oss),
        "misses_raw": len(misses),
        "true_misses": [list(x) for x in true_misses],
        "our_unique": sorted(list(x) for x in (ours - oss)),
        "triaged": triaged,
    }


def main() -> int:
    rules = _load_exclusions()
    repos = [sys.argv[1]] if len(sys.argv) > 1 else _repos()
    results = [diff_repo(r, rules) for r in repos]

    lines = ["# AI-BOM benchmark — diff matrix\n",
             "Canonical key = (normalized_name, type_class). Misses = "
             "(Cisco ∪ Trusera) \\ Ours; triaged against `fp-exclusions.json`.\n",
             "| repo | Cisco | Trusera | Ours | overlap | raw-miss | **true-miss** | our-unique |",
             "|------|------:|--------:|-----:|--------:|---------:|--------------:|-----------:|"]
    agg_true = 0
    agg_unique = 0
    for r in results:
        tm = len(r["true_misses"])
        agg_true += tm
        agg_unique += len(r["our_unique"])
        lines.append(
            f"| {r['repo']} | {r['cisco']} | {r['trusera']} | {r['ours']} | "
            f"{r['overlap']} | {r['misses_raw']} | **{tm}** | {len(r['our_unique'])} |")
    lines.append(f"| **TOTAL** | | | | | | **{agg_true}** | {agg_unique} |\n")

    # detail: surviving true-misses (the fix backlog) per repo
    any_true = False
    for r in results:
        if r["true_misses"]:
            any_true = True
            lines.append(f"### TRUE MISSES — {r['repo']} (fix our scanner)")
            for nm, tc in r["true_misses"]:
                lines.append(f"- `{tc}` **{nm}**")
    if not any_true:
        lines.append("### TRUE MISSES — none across all repos ✅")

    gate_pass = agg_true == 0 and agg_unique > 0
    lines.append(f"\n## GATE: {'PASS ✅' if gate_pass else 'FAIL ❌'} — "
                 f"true-misses={agg_true} (must be 0), our-unique={agg_unique} (must be >0)")

    report = "\n".join(lines) + "\n"
    if len(sys.argv) > 1:
        print(report)
    else:
        (HERE / "report.md").write_text(report)
        state = {r["repo"]: {"cisco": r["cisco"], "trusera": r["trusera"],
                             "ours": r["ours"], "true_misses": r["true_misses"],
                             "our_unique_count": len(r["our_unique"])}
                 for r in results}
        (HERE / "state" / "benchmark.json").write_text(json.dumps(state, indent=2))
        print(report)
    return 0 if gate_pass else 1


if __name__ == "__main__":
    sys.exit(main())
