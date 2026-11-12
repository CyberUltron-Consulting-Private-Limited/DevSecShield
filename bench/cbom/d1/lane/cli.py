"""bench/cbom/d1/d1.py <command> --work DIR

  prepare   fetch the pinned benchmarks, verify them, build the scan trees, read the labels, ask OSV
  product   run the product on each scan tree (run_product.py, with --python = an interpreter that has aibom)
  score     judge observed/*.json against the labels, evaluate floors.json, write report.json + report.md
  all       prepare + product + score

Exit codes: 0 every floor holds; 1 a floor failed (a regression, an unexpected pass, a floor not run);
2 the lane could not judge (a pin, label count, code map or input mismatch): never a pass.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

from . import BENCHES, SCHEMA_CASES
from . import fetch as F
from . import floors as FL
from . import judge as J
from . import labels as L
from . import observed as O
from . import osv as OSV
from . import report as R

HERE = Path(__file__).resolve().parents[1]          # bench/cbom/d1
REPO = HERE.parents[2]


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, sort_keys=False) + "\n", encoding="utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _log(msg: str) -> None:
    print(f"[d1 {_now()}] {msg}", file=sys.stderr, flush=True)


def cmd_prepare(a: argparse.Namespace) -> int:
    work, sources = Path(a.work), json.loads((HERE / "sources.json").read_text())
    cache = Path(a.cache) if a.cache else work / "cache"
    timings = {}
    for name in ("cryptoapi-bench", "owasp-benchmark"):
        spec = sources["benches"][name]
        t = time.monotonic()
        checkout = F.fetch(name, spec, cache)
        tree = F.scan_tree(name, spec, checkout, work / "scan" / name)
        reader = L.cryptoapi_cases if name == "cryptoapi-bench" else L.owasp_cases
        cases, meta = reader(checkout, spec)
        timings[name] = round(time.monotonic() - t, 2)
        _write(work / "cases" / f"{name}.json", {
            "schema": SCHEMA_CASES, "bench": name,
            "source": {"repo": spec["repo"], "commit": spec["commit"], "license": spec["license"],
                       "labels": spec["labels"], "scan_tree": tree},
            "labels": meta, "cases": cases})
        _log(f"{name}: {meta['judged']} cases judged ({meta['judged_vulnerable']} vulnerable), scan tree "
             f"{tree['files']} files, {timings[name]} s")
    corpus = REPO / sources["corpus"]["path"]
    labels_path = REPO / sources["corpus"]["labels"]
    cases, libs, meta = L.corpus_cases(corpus, labels_path)
    tree = F.corpus_tree(corpus, work / "scan" / "corpus")
    _write(work / "cases" / "corpus.json", {
        "schema": SCHEMA_CASES, "bench": "corpus",
        "source": {"path": sources["corpus"]["path"], "labels": sources["corpus"]["labels"],
                   "labels_sha256": _sha(labels_path), "scan_tree": tree},
        "labels": meta, "cases": cases, "libraries": libs})
    osv = {"schema": "zs-cbom-d1-osv/1", "answers": {}, "error": "skipped (--no-osv)", "asked_at": None} \
        if a.no_osv else OSV.query(libs, sources["osv"]["url"], sources["osv"]["timeout_s"])
    _write(work / "osv.json", osv)
    _log(f"corpus: {meta['judged']} items, {len(libs)} libraries; OSV "
         f"{'answered' if not osv['error'] else 'NOT answered: ' + osv['error']}")
    _write(work / "prepare.json", {"prepared_at": _now(), "seconds": timings})
    return 0


def cmd_product(a: argparse.Namespace) -> int:
    work = Path(a.work)
    for bench in BENCHES:
        t = time.monotonic()
        res = subprocess.run([a.python, str(HERE / "run_product.py"), "--scan-root", str(work / "scan" / bench),
                              "--bench", bench, "--out", str(work / "observed" / f"{bench}.json"),
                              "--repo", str(REPO)], capture_output=True, text=True, timeout=1800)
        if res.returncode != 0:
            raise L.LaneError(f"product scan of {bench} failed ({res.returncode}): {res.stderr.strip()[-1500:]}")
        _log(f"{bench}: product scan {time.monotonic() - t:.1f} s")
    return 0


def score(work: Path, floors_path: Path, codemap_path: Path, lane_commit: str) -> dict:
    cm = J.CodeMap.load(codemap_path)
    fdoc = FL.load(floors_path)
    results: dict[str, list[dict]] = {}
    extras: dict[str, list] = {}
    inputs, product, timings = {}, {}, {}
    osv = json.loads((work / "osv.json").read_text()) if (work / "osv.json").exists() else None
    for bench in BENCHES:
        cdoc = json.loads((work / "cases" / f"{bench}.json").read_text())
        odoc = O.load(work / "observed" / f"{bench}.json", bench)
        if odoc["product"].get("scan_tree_sha256") != cdoc["source"]["scan_tree"]["sha256"]:
            raise L.LaneError(f"{bench}: the product scanned tree {odoc['product'].get('scan_tree_sha256')}, the "
                              f"labels belong to {cdoc['source']['scan_tree']['sha256']}")
        unknown = cm.unknown(odoc["rows"])
        if unknown:
            raise L.LaneError(f"{bench}: product codes not in codemap.json (accept or ignore them there): {unknown}")
        product = {k: v for k, v in odoc["product"].items() if k not in ("seconds", "scan_tree_sha256")}
        inputs[bench] = {"source": cdoc["source"], "labels": cdoc["labels"], "observed_rows": len(odoc["rows"])}
        timings[bench] = odoc["product"].get("seconds")
        if bench == "corpus":
            consumed: set = set()
            results["libraries"] = J.judge_libraries(cdoc["libraries"], osv, odoc["rows"], cm, consumed)
            results["corpus"], extras["corpus"] = J.judge_by_line(cdoc["cases"], odoc["rows"], cm, consumed)
        else:
            results[bench] = J.judge_by_file(cdoc["cases"], odoc["rows"], cm)
    keys = {"cryptoapi-bench": ["category", "lane_category", "complexity"], "owasp-benchmark": ["category"],
            "corpus": ["language", "lane_category"], "libraries": ["category"]}
    sl = {b: J.slices(rs, keys[b]) for b, rs in results.items()}
    if "cryptoapi-bench" in results:  # per complexity class x category, the cut CB-27's targets use
        groups: dict = {}
        for r in results["cryptoapi-bench"]:
            groups.setdefault(r["complexity"], []).append(r)
        sl["cryptoapi-bench"]["by_complexity_category"] = {
            cls: J.slices(rs, ["category"])["by_category"] for cls, rs in sorted(groups.items())}
    evaluated = FL.evaluate(fdoc, results, extras)
    lane = {"commit": lane_commit, "codemap_version": cm.version, "codemap_sha256": _sha(codemap_path),
            "floors_version": fdoc["version"], "floors_sha256": _sha(floors_path),
            "sources_sha256": _sha(HERE / "sources.json")}
    cases = [r for b in ("cryptoapi-bench", "owasp-benchmark", "corpus", "libraries") for r in results.get(b, [])]
    rep = R.build(generated_at=_now(), lane=lane, product=product, inputs=inputs, results=sl, cases=cases,
                  extras=extras, osv=osv, floors=evaluated, verdict=FL.verdict(evaluated))
    rep["product_seconds"] = timings  # volatile: outside result_sha256
    return rep


def cmd_score(a: argparse.Namespace) -> int:
    work = Path(a.work)
    rep = score(work, Path(a.floors), Path(a.codemap), a.lane_commit or _git_head())
    out = Path(a.out) if a.out else work
    _write(out / "report.json", rep)
    (out / "report.md").write_text(R.markdown(rep), encoding="utf-8")
    bad = [f for f in rep["floors"] if f["status"] in ("fail", "unexpected-pass", "not-run")]
    for f in bad:
        _log(f"floor {f['id']}: {f['status']} (want {f['op']} {f['value'] if not isinstance(f['value'], list) else len(f['value'])}, "
             f"observed {f['observed'] if not isinstance(f['observed'], list) else len(f['observed'])})")
    _log(f"verdict {rep['verdict']}; result_sha256 {rep['result_sha256']}; report {out / 'report.json'}")
    return 0 if rep["verdict"] == "pass" else 1


def _git_head() -> str:
    try:
        return subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True,
                              timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="d1.py", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("prepare", "product", "score", "all"):
        p = sub.add_parser(name)
        p.add_argument("--work", required=True)
        if name in ("prepare", "all"):
            p.add_argument("--cache", help="checkout cache (default WORK/cache)")
            p.add_argument("--no-osv", action="store_true", help="do not ask OSV (library rows become NOT-RUN)")
        if name in ("product", "all"):
            p.add_argument("--python", required=True, help="interpreter with the aibom package (aibom/.venv/bin/python)")
        if name in ("score", "all"):
            p.add_argument("--floors", default=str(HERE / "floors.json"))
            p.add_argument("--codemap", default=str(HERE / "codemap.json"))
            p.add_argument("--out", help="where report.json / report.md go (default WORK)")
            p.add_argument("--lane-commit", help="git commit of the lane (default: git rev-parse HEAD)")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "prepare":
            return cmd_prepare(a)
        if a.cmd == "product":
            return cmd_product(a)
        if a.cmd == "score":
            return cmd_score(a)
        cmd_prepare(a)
        cmd_product(a)
        return cmd_score(a)
    except L.LaneError as exc:
        _log(f"NOT JUDGED: {exc}")
        return 2
