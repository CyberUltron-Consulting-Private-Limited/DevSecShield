r"""bench/diff.py — diff matrix + gate over the normalized tool outputs.

ISOLATED benchmark code. For each repo that has all available tool outputs in
``bench/out/<repo>.{trusera.cdx,cisco,ours.cdx}.json`` it computes:

  Misses     = (Cisco ∪ Trusera) \ Ours        (entities an OSS tool found, we didn't)
  OurUnique  = Ours \ (Cisco ∪ Trusera)        (entities only we add)
  Overlap    = Ours ∩ (Cisco ∪ Trusera)

Each raw Miss is triaged via ``bench/fp_exclusions.json`` (a recorded list of
``{repo, name, class, reason}``) into OSS FALSE POSITIVE (excluded) vs TRUE miss.

GATE: total true-misses == 0  AND  total OurUnique > 0.

Writes ``bench/report.md`` (aggregate table + per-repo detail) and prints the gate.
Missing tool outputs are reported (NOT silently treated as empty).
"""

from __future__ import annotations

import json
import os

from normalize import canonical_set

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
FP_PATH = os.path.join(HERE, "fp_exclusions.json")
REPORT = os.path.join(HERE, "report.md")
SHA_PATH = os.path.join(OUT, "shas.json")

TOOL_FILE = {
    "trusera": "{}.trusera.cdx.json",
    "cisco": "{}.cisco.json",
    "ours": "{}.ours.cdx.json",
}


def _load_fp():
    """Return (exact_dict, pattern_list). fp_exclusions.json is {exact:[...], patterns:[...]}.
    exact entry  = {repo, class, name, reason}
    pattern rule = {class, name_regex, scope:"all"|<repo>, reason}  (documented OSS noise)."""
    import re as _re
    if not os.path.exists(FP_PATH):
        return {}, []
    data = json.load(open(FP_PATH))
    if isinstance(data, list):  # legacy flat list
        data = {"exact": data, "patterns": []}
    exact = {(e["repo"], e["class"], e["name"]): e.get("reason", "")
             for e in data.get("exact", [])}
    patterns = [(p["class"], _re.compile(p["name_regex"]), p.get("scope", "all"),
                 p.get("reason", "")) for p in data.get("patterns", [])]
    return exact, patterns


def _is_fp(repo, cls, name, exact, patterns) -> bool:
    if (repo, cls, name) in exact:
        return True
    for pcls, prx, scope, _ in patterns:
        if pcls == cls and (scope == "all" or scope == repo) and prx.search(name):
            return True
    return False


def _repos() -> list[str]:
    names = set()
    for f in os.listdir(OUT):
        for suf in (".ours.cdx.json", ".trusera.cdx.json", ".cisco.json"):
            if f.endswith(suf):
                names.add(f[: -len(suf)])
    return sorted(names)


def _set_or_none(tool: str, repo: str):
    path = os.path.join(OUT, TOOL_FILE[tool].format(repo))
    if not os.path.exists(path):
        return None
    try:
        return canonical_set(tool, path)
    except Exception as e:  # noqa: BLE001 - report, don't crash the matrix
        return f"ERROR: {type(e).__name__}: {e}"


def main() -> int:
    exact, patterns = _load_fp()
    shas = json.load(open(SHA_PATH)) if os.path.exists(SHA_PATH) else {}
    rows, details = [], []
    tot_true_miss = tot_unique = 0
    missing_outputs = []

    for repo in _repos():
        sets = {t: _set_or_none(t, repo) for t in ("trusera", "cisco", "ours")}
        for t, s in sets.items():
            if s is None:
                missing_outputs.append(f"{repo}/{t}")
            elif isinstance(s, str):
                missing_outputs.append(f"{repo}/{t} ({s})")
        tru = sets["trusera"] if isinstance(sets["trusera"], set) else set()
        cis = sets["cisco"] if isinstance(sets["cisco"], set) else set()
        ours = sets["ours"] if isinstance(sets["ours"], set) else set()
        oss = tru | cis
        raw_miss = sorted(oss - ours)
        unique = sorted(ours - oss)
        true_miss = [(c, n) for (n, c) in raw_miss if not _is_fp(repo, c, n, exact, patterns)]
        fp_miss = [(c, n) for (n, c) in raw_miss if _is_fp(repo, c, n, exact, patterns)]
        tot_true_miss += len(true_miss)
        tot_unique += len(unique)
        rows.append((repo, len(cis), len(tru), len(ours),
                     len(true_miss), len(unique), shas.get(repo, "—")))
        details.append((repo, raw_miss, true_miss, fp_miss, unique))

    # ── write report.md ──
    L = []
    L.append("# AI-BOM Benchmark — diff matrix (Ours vs Cisco vs Trusera)\n")
    L.append("Live runs of three tools on real repos. Misses = (Cisco ∪ Trusera) "
             "\\ Ours, triaged into TRUE miss vs OSS false-positive "
             "(`fp_exclusions.json`). Gate: true-misses = 0 AND our-unique > 0.\n")
    L.append("| repo | Cisco | Trusera | Ours | true-misses | our-unique | SHA |")
    L.append("|------|------:|--------:|-----:|------------:|-----------:|-----|")
    for r in rows:
        L.append(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} | {r[5]} | `{r[6][:12]}` |")
    L.append(f"| **TOTAL** | | | | **{tot_true_miss}** | **{tot_unique}** | |")
    L.append("")
    gate_miss = tot_true_miss == 0
    gate_uniq = tot_unique > 0
    L.append(f"\n**GATE — true-misses == 0:** {'✅ PASS' if gate_miss else '❌ FAIL'} "
             f"({tot_true_miss})")
    L.append(f"**GATE — our-unique > 0:** {'✅ PASS' if gate_uniq else '❌ FAIL'} "
             f"({tot_unique})")
    if missing_outputs:
        L.append(f"\n> ⚠️ missing/failed tool outputs (NOT counted as empty): "
                 f"{', '.join(missing_outputs)}")
    L.append("\n## Per-repo detail\n")
    for repo, raw_miss, true_miss, fp_miss, unique in details:
        L.append(f"### {repo}")
        L.append(f"- **TRUE misses ({len(true_miss)}):** "
                 + (", ".join(f"`{c}:{n}`" for c, n in true_miss) or "none ✅"))
        L.append(f"- OSS-FP excluded ({len(fp_miss)}): "
                 + (", ".join(f"`{c}:{n}`" for c, n in fp_miss) or "none"))
        L.append(f"- our-unique ({len(unique)}): "
                 + (", ".join(f"`{c}:{n}`" for n, c in unique) or "none"))
        L.append("")
    open(REPORT, "w").write("\n".join(L))

    print(f"repos={len(rows)} true_misses={tot_true_miss} our_unique={tot_unique}")
    print(f"GATE true-misses==0: {'PASS' if gate_miss else 'FAIL'}")
    print(f"GATE our-unique>0:  {'PASS' if gate_uniq else 'FAIL'}")
    if missing_outputs:
        print("MISSING:", ", ".join(missing_outputs))
    print(f"wrote {REPORT}")
    return 0 if (gate_miss and gate_uniq) else 1


if __name__ == "__main__":
    raise SystemExit(main())
