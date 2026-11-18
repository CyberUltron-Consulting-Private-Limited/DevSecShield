"""CB-07 review 5878689101 [major]: floors.json only rises.

* `lane.floorcheck.compare` (used by `d1.py check-floors --base REF`, which ci.sh runs): no floor id disappears, a
  value never loosens, a row's definition (`bench`, `where`, `metric`, `mode`, `op`) never changes, a target goes only
  when a non-regression row at least as high replaces it; a loosening needs a new `lowered` / `removed` record.
* `test_floors_only_rise`: the working tree's floors.json against the base branch (D1_FLOORS_BASE; locally origin/dev).
* The non-regression floors equal the numbers of the observation they were taken from (baseline/observed-*.json), so
  the floors and the baseline cannot drift apart.
"""
from __future__ import annotations

import copy
import json
import os
import subprocess
from pathlib import Path

import pytest
from helpers import D1, REPO, case, floors_doc, make_work
from test_lane import OSV_TODAY, corpus_results

from lane import cli, floorcheck, floors, judge, observed, report
from lane.labels import LaneError

FLOORS_REL = "bench/cbom/d1/floors.json"


def nr(fid, value, **kw):
    base = {"id": fid, "kind": "non-regression", "bench": "b", "where": {}, "metric": "recall", "mode": "matched",
            "op": ">=", "value": value}
    base.update(kw)
    return base


def tgt(fid, value, **kw):
    return nr(fid, value, kind="target", owner="CB-27", **kw)


BASE = floors_doc([
    nr("ratio", 0.5),
    nr("ids", ["a", "b"], metric="flagged_ids", op="superset", where={"vulnerable": True}),
    nr("fps", ["x"], metric="fp_ids", op="subset", where={"vulnerable": False}),
    nr("cap", 3, metric="fp", op="<="),
    tgt("t", 0.9, where={"category": "c1"}),
])
LOWERED = {"reason": "benchmark pin moved; case relabelled upstream", "pr": "#999"}


def edit(fn) -> dict:
    doc = copy.deepcopy(BASE)
    fn(doc)
    return doc


def row(doc, fid):
    return next(f for f in doc["floors"] if f["id"] == fid)


def drop(doc, fid):
    doc["floors"] = [f for f in doc["floors"] if f["id"] != fid]


LOOSENINGS = {
    "ratio lowered": lambda d: row(d, "ratio").update(value=0.4),
    "superset loses an id": lambda d: row(d, "ids").update(value=["a"]),
    "subset gains an id": lambda d: row(d, "fps").update(value=["x", "y"]),
    "<= cap raised": lambda d: row(d, "cap").update(value=4),
    "NR removed": lambda d: drop(d, "ratio"),
    "mode changed": lambda d: row(d, "ratio").update(mode="any"),
    "metric changed": lambda d: row(d, "ratio").update(metric="precision"),
    "where changed": lambda d: row(d, "ratio").update(where={"category": "c1"}),
    "op changed": lambda d: row(d, "cap").update(op=">="),
    "bench changed": lambda d: row(d, "ratio").update(bench="other"),
    "not_run_ok added": lambda d: row(d, "ratio").update(not_run_ok="OSV is down"),
    "NR became a target": lambda d: row(d, "ratio").update(kind="target", owner="CB-27"),
    "target removed": lambda d: drop(d, "t"),
    "target lowered": lambda d: row(d, "t").update(value=0.5),
    "target became NR below it": lambda d: (row(d, "t").update(kind="non-regression", value=0.0),
                                            row(d, "t").pop("owner")),
    "target replaced by a lower NR": lambda d: (drop(d, "t"),
                                                d["floors"].append(nr("t-nr", 0.8, where={"category": "c1"}))),
}


@pytest.mark.parametrize("what", sorted(LOOSENINGS))
def test_every_loosening_is_refused(what):
    problems = floorcheck.compare(BASE, edit(LOOSENINGS[what]))
    assert len(problems) == 1, problems


RISES = {
    "nothing changed": lambda d: None,
    "ratio raised": lambda d: row(d, "ratio").update(value=0.6),
    "superset gains an id": lambda d: row(d, "ids").update(value=["a", "b", "c"]),
    "subset loses an id": lambda d: row(d, "fps").update(value=[]),
    "<= cap lowered": lambda d: row(d, "cap").update(value=2),
    "new NR row": lambda d: d["floors"].append(nr("new", 0.1)),
    "new target": lambda d: d["floors"].append(tgt("t2", 0.95)),
    "target raised": lambda d: row(d, "t").update(value=0.95),
    "met target turned into NR at least as high": lambda d: (row(d, "t").update(kind="non-regression", value=1.0),
                                                            row(d, "t").pop("owner")),
    "met target replaced by a new NR id at least as high": lambda d: (
        drop(d, "t"), d["floors"].append(nr("NR-t", 0.9, where={"category": "c1"}))),
    "NR renamed, same definition and value": lambda d: (drop(d, "ratio"), d["floors"].append(nr("ratio-2", 0.5))),
    "why text edited": lambda d: row(d, "ratio").update(why="today on dev abc"),
}


@pytest.mark.parametrize("what", sorted(RISES))
def test_rises_and_neutral_edits_pass(what):
    assert floorcheck.compare(BASE, edit(RISES[what])) == []


def test_where_lists_compare_as_sets():
    base = floors_doc([tgt("t", 1.0, where={"case_id": ["N6", "N8"]})])
    head = floors_doc([tgt("t", 1.0, where={"case_id": ["N8", "N6"]})])
    assert floorcheck.compare(base, head) == []


@pytest.mark.parametrize("what", ["ratio lowered", "superset loses an id", "mode changed", "target lowered",
                                  "NR became a target", "not_run_ok added"])
def test_a_new_lowered_record_allows_the_loosening(what):
    head = edit(LOOSENINGS[what])
    fid = next(f["id"] for f in BASE["floors"] if f != row(head, f["id"]))
    row(head, fid)["lowered"] = dict(LOWERED)
    assert floorcheck.compare(BASE, head) == []


def test_an_old_lowered_record_does_not_cover_a_new_loosening():
    base = edit(lambda d: row(d, "ratio").update(lowered=dict(LOWERED)))
    head = edit(lambda d: row(d, "ratio").update(lowered=dict(LOWERED), value=0.3))
    assert len(floorcheck.compare(base, head)) == 1
    head["floors"][0]["lowered"] = {"reason": "a second, reviewed reason", "pr": "#1000"}
    assert floorcheck.compare(base, head) == []


def test_a_removal_needs_a_new_removed_record():
    head = edit(lambda d: drop(d, "ratio"))
    head["removed"] = [{"id": "ratio", **LOWERED}]
    assert floorcheck.compare(BASE, head) == []
    base = copy.deepcopy(BASE)
    base["removed"] = [{"id": "ratio", **LOWERED}]                     # recorded before: does not count again
    assert len(floorcheck.compare(base, head)) == 1


@pytest.mark.parametrize("bad", [{"reason": "", "pr": "#1"}, {"reason": "x"}, "because", {"reason": "x", "pr": " "}])
def test_lowered_records_must_name_a_reason_and_a_pr(tmp_path, bad):
    p = tmp_path / "floors.json"
    p.write_text(json.dumps(floors_doc([nr("ratio", 0.5, lowered=bad)])))
    with pytest.raises(LaneError, match="lowered"):
        floors.load(p)
    p.write_text(json.dumps({**floors_doc([]), "removed": [{"id": "x", **bad} if isinstance(bad, dict) else bad]}))
    with pytest.raises(LaneError, match="removed"):
        floors.load(p)


def test_report_md_prints_lowered_and_removed_records(tmp_path):
    work = make_work(tmp_path, {
        "cryptoapi-bench": ([case("cryptoapi-bench", "1", ["H.java"], "brokenhash", "broken_hash", True,
                                  complexity="basis-benchmark")], []),
        "owasp-benchmark": ([], []), "corpus": ([], [])})
    fpath = tmp_path / "floors.json"
    doc = floors_doc([nr("NR-x", 0.0, bench="cryptoapi-bench", lowered=dict(LOWERED))])
    doc["removed"] = [{"id": "NR-gone", "reason": "slice emptied by the new pin", "pr": "#998"}]
    fpath.write_text(json.dumps(doc))
    rep = cli.score(work, fpath, D1 / "codemap.json", "x")
    text = report.markdown(rep)
    assert "## Lowered or removed floors" in text
    assert "| NR-x | lowered | #999 | benchmark pin moved; case relabelled upstream |" in text
    assert "| NR-gone | removed | #998 | slice emptied by the new pin |" in text


# ------------------------------------------------------------------------------------------------ against git
def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True,
                          env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_AUTHOR_NAME": "t",
                               "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                               "GIT_COMMITTER_EMAIL": "t@t"}).stdout.strip()


def repo_with_floors(tmp_path: Path, doc: dict | None) -> Path:
    repo = tmp_path / "repo"
    (repo / "bench/cbom/d1").mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    (repo / "README").write_text("x\n")
    if doc is not None:
        (repo / FLOORS_REL).write_text(json.dumps(doc))
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")
    return repo


def test_check_floors_against_a_git_base(tmp_path, capsys):
    repo = repo_with_floors(tmp_path, BASE)
    head = repo / FLOORS_REL
    head.write_text(json.dumps(edit(LOOSENINGS["ratio lowered"])))
    assert cli.main(["check-floors", "--base", "HEAD", "--floors", str(head), "--repo", str(repo)]) == 1
    assert "ratio: value loosened: 0.5 -> 0.4" in capsys.readouterr().out
    head.write_text(json.dumps(edit(RISES["ratio raised"])))
    assert cli.main(["check-floors", "--base", "HEAD", "--floors", str(head), "--repo", str(repo)]) == 0
    # a base that cannot be resolved is NOT JUDGED (exit 2), never a pass
    assert cli.main(["check-floors", "--base", "no-such-ref", "--floors", str(head), "--repo", str(repo)]) == 2


def test_check_floors_when_the_base_has_no_floors_file(tmp_path, capsys):
    repo = repo_with_floors(tmp_path, None)
    head = repo / FLOORS_REL
    head.write_text(json.dumps(BASE))
    assert cli.main(["check-floors", "--base", "HEAD", "--floors", str(head), "--repo", str(repo)]) == 0
    assert "has no bench/cbom/d1/floors.json" in capsys.readouterr().out


def _base_ref() -> str | None:
    ref = os.environ.get("D1_FLOORS_BASE")
    if ref:
        return ref
    ok = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--verify", "--quiet", "origin/dev^{commit}"],
                        capture_output=True).returncode == 0
    return "origin/dev" if ok else None


def test_floors_only_rise():
    """floors.json in this tree against the base branch's copy. CI (ci.sh) sets D1_FLOORS_BASE to the base the job
    tests against; locally the default is origin/dev."""
    ref = _base_ref()
    if ref is None:
        pytest.skip("no base: set D1_FLOORS_BASE=<ref> (origin/dev is not available here)")
    base = floorcheck.load_at(REPO, ref, FLOORS_REL)     # LaneError (a failure) when D1_FLOORS_BASE does not resolve
    if base is None:
        return                                           # the base has no floors.json yet: nothing to compare
    problems = floorcheck.compare(base, floors.load(D1 / "floors.json"))
    assert problems == [], "\n".join(problems)


# ------------------------------------------------------------------------------------------------ tight floors
def tight(f: dict, observed_value) -> bool:
    if f["op"] in ("superset", "subset"):
        return observed_value is not None and sorted(observed_value) == sorted(f["value"])
    return observed_value == f["value"]


def nr_rows_not_tight(evaluated: list[dict]) -> list[str]:
    return [f"{e['id']}: floor {e['value'] if not isinstance(e['value'], list) else len(e['value'])}, baseline "
            f"{e['observed'] if not isinstance(e['observed'], list) else len(e['observed'])}"
            for e in evaluated if e["kind"] == "non-regression" and not tight(e, e["observed"])]


def test_nr_floors_are_tight_on_the_baseline_corpus():
    """Hermetic: the corpus and library non-regression floors are exactly the numbers of baseline/observed-corpus.json
    (with the OSV answer of the baseline run)."""
    rows = observed.load(D1 / "baseline" / "observed-corpus.json", "corpus")["rows"]
    doc = floors.load(D1 / "floors.json")
    doc["floors"] = [f for f in doc["floors"] if f["bench"] in ("corpus", "libraries")]
    ev = floors.evaluate(doc, *corpus_results(rows, OSV_TODAY))
    assert sum(e["kind"] == "non-regression" for e in ev) >= 5
    assert nr_rows_not_tight(ev) == []


@pytest.mark.skipif(not os.environ.get("D1_WORK"),
                    reason="needs the fetched benchmarks: D1_WORK=<d1.py prepare --work>")
def test_nr_floors_are_tight_on_the_baseline_benchmarks():
    """The benchmark non-regression floors are exactly the numbers of baseline/observed-<bench>.json on the pinned
    labels (ci.sh always sets D1_WORK, so CI runs this)."""
    work = Path(os.environ["D1_WORK"])
    res = {}
    for bench in ("cryptoapi-bench", "owasp-benchmark"):
        cases = json.loads((work / "cases" / f"{bench}.json").read_text())["cases"]
        rows = observed.load(D1 / "baseline" / f"observed-{bench}.json", bench)["rows"]
        res[bench] = judge.judge_by_file(cases, rows, judge.CodeMap.load(D1 / "codemap.json"))
    doc = floors.load(D1 / "floors.json")
    doc["floors"] = [f for f in doc["floors"] if f["bench"] in res]
    ev = floors.evaluate(doc, res, {})
    assert sum(e["kind"] == "non-regression" for e in ev) >= 20
    assert nr_rows_not_tight(ev) == []
