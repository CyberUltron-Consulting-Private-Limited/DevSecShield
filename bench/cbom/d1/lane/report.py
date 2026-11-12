"""report.json (the stable contract, schema zs-cbom-d1-report/1) and report.md (the CI job summary)."""
from __future__ import annotations

import hashlib
import json

from . import SCHEMA_REPORT

# The fields of report.json that depend only on the inputs (labels, observed rows, code map, floors): two runs on
# the same product build and pins must give the same result_sha256 (exit F of CB-07).
STABLE = ("inputs", "results", "cases", "extras", "osv_answers", "floors", "verdict")


def result_sha256(report: dict) -> str:
    stable = {k: report[k] for k in STABLE}
    return hashlib.sha256(json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _pct(x) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def _frac(m: dict, metric: str) -> str:
    if metric == "recall":
        return f"{m['tp']}/{m['vulnerable']}"
    if metric == "precision":
        return f"{m['tp']}/{m['tp'] + m['fp']}"
    return f"{m['tn']}/{m['secure']}"


def _row(name: str, mm: dict) -> str:
    m, a = mm["matched"], mm["any"]
    return (f"| {name} | {m['vulnerable']} | {m['secure']} | {_pct(m['recall'])} ({_frac(m, 'recall')}) | "
            f"{_pct(m['precision'])} ({_frac(m, 'precision')}) | {_pct(m['specificity'])} ({_frac(m, 'specificity')}) | "
            f"{_pct(a['recall'])} | {_pct(a['precision'])} |")


HEAD = ("| slice | vulnerable | secure | recall | precision | specificity | recall (any code) | precision (any code) |\n"
        "|---|---:|---:|---:|---:|---:|---:|---:|")


def markdown(rep: dict) -> str:
    p = rep["product"]
    out = [f"# CBOM code lane: D1 independent benchmark lane ({rep['verdict'].upper()})", "",
           f"Product: `{p.get('entry')}` level {p.get('level')}, repo `{p.get('git_sha', '')[:12]}`, "
           f"KB `{p.get('kb_version')}`. Lane: code map v{rep['lane']['codemap_version']}, floors "
           f"v{rep['lane']['floors_version']}. result_sha256 `{rep['result_sha256'][:16]}`.", "",
           "Expected values come only from the benchmarks' own labels, the corpus labels and OSV at test time. "
           "`recall` / `precision` count a finding only when its code fits the case's weakness (codemap.json); "
           "the `any code` columns count any finding on the case's file.", ""]
    for bench, keys in (("cryptoapi-bench", ["category", "complexity"]), ("owasp-benchmark", ["category"]),
                        ("corpus", ["language", "lane_category"]), ("libraries", ["category"])):
        res = rep["results"].get(bench)
        if not res:
            continue
        src = rep["inputs"].get(bench, {}).get("source", {})
        pin = f" `{src.get('repo', '')}` @ `{src.get('commit', '')[:7]}`" if src.get("commit") else ""
        out += [f"## {bench}{pin}", "", HEAD, _row("**overall**", res["overall"])]
        for key in keys:
            for name, mm in res.get(f"by_{key}", {}).items():
                out.append(_row(f"{key}: {name}", mm))
        out.append("")
    corpus = [c for c in rep["cases"] if c["bench"] in ("corpus", "libraries")]
    if corpus:
        out += ["### Corpus and library items", "", "| item | where | category | status | finding |", "|---|---|---|---|---|"]
        for c in corpus:
            where = f"{c['files'][0]}:{','.join(str(x) for x in c.get('lines', []))}" if c.get("lines") else c["files"][0]
            ev = "; ".join(f"{e[2]} {e[3]} @{e[1]}" for e in c["evidence"][:2])
            name = c.get("label") or f"{c.get('package')} {c.get('version')}"
            out.append(f"| {c['case_id']} {name} | {where} | {c['lane_category']} | {c['status']} | {ev} |")
        out.append("")
    extras = rep["extras"].get("corpus", [])
    out += [f"Corpus findings not on a labelled item (extras; the no-new-false-positive floor compares this list): "
            f"{len(extras)}.", ""]
    if rep.get("osv_error"):
        out += [f"OSV: not answered ({rep['osv_error']}): library rows are NOT-RUN.", ""]
    out += ["## Floors", "", "| floor | kind | owner | slice | metric | want | observed | status |", "|---|---|---|---|---|---|---|---|"]
    for f in rep["floors"]:
        obs = f["observed"]
        if isinstance(obs, list):
            obs = f"{len(obs)} ids"
        want = f["value"] if not isinstance(f["value"], list) else f"{len(f['value'])} ids"
        where = ", ".join(f"{k}={v if not isinstance(v, list) else '+'.join(map(str, v))}" for k, v in f.get("where", {}).items())
        out.append(f"| {f['id']} | {f['kind']} | {f.get('owner', '')} | {f['bench']} {where} | {f['metric']} "
                   f"({f.get('mode', 'matched')}) | {f['op']} {want} | {obs} | **{f['status']}** |")
    out.append("")
    notes = []
    for bench, inp in rep["inputs"].items():
        for e in inp.get("labels", {}).get("excluded", []):
            notes.append(f"- {bench} case {e['case_id']} not judged: {e['reason']}")
        for a in inp.get("labels", {}).get("anomalies", []):
            notes.append(f"- {bench} case {a['case_id']}: {a['note']}")
    if notes:
        out += ["## Label notes (the benchmark's own data, reported, not corrected)", "", *notes, ""]
    return "\n".join(out) + "\n"


def build(*, generated_at: str, lane: dict, product: dict, inputs: dict, results: dict, cases: list,
          extras: dict, osv: dict | None, floors: list, verdict: str) -> dict:
    rep = {"schema": SCHEMA_REPORT, "generated_at": generated_at, "lane": lane, "product": product,
           "inputs": inputs, "results": results, "cases": cases, "extras": extras,
           "osv_answers": (osv or {}).get("answers"), "osv_asked_at": (osv or {}).get("asked_at"),
           "osv_error": (osv or {}).get("error"), "floors": floors, "verdict": verdict}
    rep["result_sha256"] = result_sha256(rep)
    return rep
