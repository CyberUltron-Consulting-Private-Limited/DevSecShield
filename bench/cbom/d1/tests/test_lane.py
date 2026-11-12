"""CB-07 D1 lane: hermetic unit tests (no network, no product). Run: python -m pytest bench/cbom/d1/tests."""
from __future__ import annotations

import ast
import copy
import json
import os
import shutil
from pathlib import Path

import pytest
from helpers import D1, REPO, case, floors_doc, make_work, row, write_xlsx

from lane import cli, floors, judge, labels, observed, xlsx
from lane.labels import LaneError

PRODUCT = ("backend", "aibom", "scan_node", "zs_scan_node", "frontend", "RabbitMQ")
CODEMAP = judge.CodeMap.load(D1 / "codemap.json")
SOURCES = json.loads((D1 / "sources.json").read_text())


# ------------------------------------------------------------------------------------------------ O-1 independence
def product_imports(path: Path) -> list[str]:
    bad = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module]
        elif isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) in (
                "import_module", "__import__") and node.args and isinstance(node.args[0], ast.Constant):
            names = [str(node.args[0].value)]
        bad += [f"{path.name}:{node.lineno} {n}" for n in names if n.split(".")[0] in PRODUCT]
    return bad


def test_the_judge_imports_no_product_code():
    files = sorted((D1 / "lane").glob("*.py")) + [D1 / "d1.py"] + sorted((D1 / "tests").glob("*.py"))
    assert len(files) > 8
    assert [b for f in files for b in product_imports(f)] == []


def test_import_lint_positive_control(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("import os\nfrom aibom.cbom import pipeline\nimport backend.x\n__import__('scan_node')\n")
    assert len(product_imports(bad)) == 3


def test_run_product_is_the_one_file_that_runs_the_product():
    assert any("aibom" in b for b in product_imports(D1 / "run_product.py"))
    text = (D1 / "run_product.py").read_text()
    # the worker's call (RabbitMQ/worker/helpers/tools/cbom_agent/main.py) with its level
    assert "scan_crypto_to_devsecshield(str(a.scan_root), level=4)" in text
    worker = (REPO / "RabbitMQ/worker/helpers/tools/cbom_agent/main.py").read_text()
    assert "scan_crypto_to_devsecshield(" in worker and "level=4" in worker


# ------------------------------------------------------------------------------------------------ label readers
def cab_spec(**over) -> dict:
    spec = copy.deepcopy(SOURCES["benches"]["cryptoapi-bench"])
    spec["pinned"] = {}
    spec.update(over)
    return spec


def tiny_cab(tmp: Path) -> Path:
    root = tmp / "cab"
    src = root / "src/main/java/org/cryptoapi/bench"
    for d, f in (("brokenhash", "BrokenHashBBCase1.java"), ("brokenhash", "BrokenHashCorrected.java"),
                 ("staticsalts", "StaticSaltsBBCase1.java"), ("predictableseeds", "PredictableSeedsABMCCase1.java"),
                 ("predictableseeds", "PredictableSeedsABMC1.java"), ("predictablepbepassword", "X.java")):
        (src / d).mkdir(parents=True, exist_ok=True)
        (src / d / f).write_text("class X {}\n" * 30)
    write_xlsx(root / "CryptoAPI-Bench_details.xlsx", [
        [("A", "s", "Properties", None), ("B", "s", "Files", None), ("C", "s", "Code Number", None),
         ("D", "s", "Vulnerability Exists?", None), ("G", "s", "Line number", None)],
        [("A", "s", "Basis benchmark", None), ("B", "s", "BrokenHashBBCase1.java", None), ("C", "s", "16.1.1", None),
         ("D", "f", "TRUE", None), ("G", "n", "9", None)],
        [("B", "s", "BrokenHashCorrected", None), ("C", "s", "16.1.5", None), ("D", "f", "FALSE", None)],
        [("B", "s", "StaticSaltsBBCase1.java", None), ("C", "s", "10.1.1", None), ("D", "n", "1", None),
         ("G", "n", "43720", 1)],                                                     # a "9,12" Excel made a date
        [("A", "s", "Multiple java classes", None), ("B", "s", "PredictableSeedsABMCCase1.java\nPredictableSeedsABMC1",
                                                                None), ("C", "s", "9.8.1", None), ("D", "f", "TRUE", None)],
        [("B", "s", "Missing.java\nAlsoMissing.java", None), ("C", "s", "9.8.2", None), ("D", "f", "TRUE", None)],
        [("B", "s", "X.java", None), ("C", "s", "3.1.2", None), ("D", "s", "maybe", None)],
    ])
    return root


def test_cryptoapi_reader_reads_the_sheet_as_published(tmp_path):
    root = tiny_cab(tmp_path)
    cases, meta = labels.cryptoapi_cases(root, cab_spec())
    by = {c["case_id"]: c for c in cases}
    assert by["16.1.1"]["vulnerable"] is True and by["16.1.5"]["vulnerable"] is False
    assert by["10.1.1"]["vulnerable"] is True                     # a plain 1, as row 1.5.1 of the real sheet
    assert by["10.1.1"]["lines_date_styled"] is True and meta["date_styled_line_cells"] == 1
    assert by["9.8.1"]["files"] == ["src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABMCCase1.java",
                                    "src/main/java/org/cryptoapi/bench/predictableseeds/PredictableSeedsABMC1.java"]
    assert by["9.8.1"]["complexity"] == "multiple-java-classes" and by["16.1.1"]["complexity"] == "basis-benchmark"
    assert by["16.1.1"]["category"] == "brokenhash" and by["16.1.1"]["lane_category"] == "broken_hash"
    reasons = {e["case_id"]: e["reason"] for e in meta["excluded"]}
    assert "not in the tree" in reasons["9.8.2"]                  # never remapped to a similar file name
    assert "neither TRUE nor FALSE" in reasons["3.1.2"]
    assert meta["unresolved_files"] == ["AlsoMissing.java", "Missing.java"]


def test_cryptoapi_reader_refuses_counts_that_differ_from_the_pin(tmp_path):
    root = tiny_cab(tmp_path)
    with pytest.raises(LaneError, match="judged: pinned 170, read 4"):
        labels.cryptoapi_cases(root, cab_spec(pinned={"judged": 170}))


def test_boolean_cells():
    assert xlsx.boolean_cell({"formula": "TRUE()", "text": "1"}) is True
    assert xlsx.boolean_cell({"formula": "", "text": "=FALSE()"}) is False
    assert xlsx.boolean_cell({"formula": "", "text": "1"}) is True
    assert xlsx.boolean_cell({"formula": "", "text": "---"}) is None
    assert xlsx.boolean_cell(None) is None


def test_owasp_reader(tmp_path):
    (tmp_path / "expectedresults-1.2.csv").write_text(
        "# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1\n"
        "BenchmarkTest00001,pathtraver,true,22\nBenchmarkTest00003,hash,true,328\n"
        "BenchmarkTest00004,weakrand,false,330\nBenchmarkTest00005,crypto,true,327\n")
    spec = copy.deepcopy(SOURCES["benches"]["owasp-benchmark"])
    spec["pinned"] = {"judged": 3, "hash_true": 1, "weakrand_false": 1, "crypto_true": 1}
    cases, meta = labels.owasp_cases(tmp_path, spec)
    assert [(c["case_id"], c["category"], c["lane_category"], c["vulnerable"]) for c in cases] == [
        ("BenchmarkTest00003", "hash", "broken_hash", True), ("BenchmarkTest00004", "weakrand", "weak_rng", False),
        ("BenchmarkTest00005", "crypto", "cwe327_cipher", True)]
    assert cases[0]["files"] == ["src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00003.java"]


CORPUS = REPO / SOURCES["corpus"]["path"]
CORPUS_LABELS = REPO / SOURCES["corpus"]["labels"]


def test_corpus_labels_are_the_corpus_own_comments():
    cases, libs, meta = labels.corpus_cases(CORPUS, CORPUS_LABELS)
    planted = labels.corpus_comment_items(CORPUS)
    assert len(planted) == 57 and meta["judged_vulnerable"] == 57 and meta["judged_secure"] == 1
    assert {c["case_id"] for c in cases if c["source"] == "comment"} == {p["id"] for p in planted}
    assert [p for p in planted if p["id"] in ("G2", "G3")] == [
        {"id": "G2", "file": "go/main.go", "line": 19, "label": "3DES"},
        {"id": "G3", "file": "go/main.go", "line": 19, "label": "hard-coded key"}]
    assert len(libs) == 6


def test_corpus_labels_that_drift_from_the_corpus_are_refused(tmp_path):
    corpus = tmp_path / "corpus"
    shutil.copytree(CORPUS, corpus)
    doc = json.loads(CORPUS_LABELS.read_text())
    doc["items"][0]["line"] += 1
    bad = tmp_path / "labels.json"
    bad.write_text(json.dumps(doc))
    with pytest.raises(LaneError, match="corpus labels disagree"):
        labels.corpus_cases(corpus, bad)
    # an item planted in the corpus without a label row is refused too
    (corpus / "go/main.go").write_text((corpus / "go/main.go").read_text() + "// G11 new item\n")
    with pytest.raises(LaneError, match="G11: in the corpus only"):
        labels.corpus_cases(corpus, CORPUS_LABELS)


def test_every_category_used_has_a_codemap_entry():
    used = set(SOURCES["benches"]["cryptoapi-bench"]["categories"].values())
    used |= set(SOURCES["benches"]["owasp-benchmark"]["categories"].values())
    used |= {i["category"] for i in json.loads(CORPUS_LABELS.read_text())["items"]} | {"vulnerable_library"}
    assert used <= set(CODEMAP.rules)


# ------------------------------------------------------------------------------------------------ observed rows
def test_from_run_object_keeps_flagged_rows_only():
    rows = observed.from_run_object([
        {"location": "./a/B.java", "line": "9", "occurrences": ["9", 12], "finding_codes": ["WEAK_ALGORITHM"],
         "algorithm_name": "MD5"},
        {"location": "a/C.java", "line": 3, "finding_codes": [], "algorithm_name": "AES"},
        {"location": ".github/x.yml", "line": None, "finding_codes": ["WEAK_PROTOCOL"], "title": "TLS"}])
    assert rows == [
        {"location": ".github/x.yml", "line": None, "occurrences": [], "codes": ["WEAK_PROTOCOL"], "algorithm": "TLS",
         "asset_type": None},
        {"location": "a/B.java", "line": 9, "occurrences": [9, 12], "codes": ["WEAK_ALGORITHM"], "algorithm": "MD5",
         "asset_type": None}]


# ------------------------------------------------------------------------------------------------ matching
def test_file_matching_needs_a_code_that_fits_the_weakness():
    cases = [case("b", "hash-1", ["H.java"], "brokenhash", "broken_hash", True),
             case("b", "hash-2", ["I.java"], "brokenhash", "broken_hash", True),
             case("b", "hash-ok", ["J.java"], "brokenhash", "broken_hash", False),
             case("b", "rsa", ["R.java"], "insecureasymmetriccrypto", "weak_key_size", True)]
    rows = [row("H.java", 9, ["WEAK_ALGORITHM"], "SHA-1"),
            row("I.java", 9, ["WEAK_ALGORITHM"], "RSA-1024"),        # a weak finding, but not a broken hash
            row("J.java", 5, ["QUANTUM_VULNERABLE"], "RSA"),         # ignored code: neither matched nor any
            row("R.java", 7, ["QUANTUM_VULNERABLE"], "RSA")]
    out = {r["case_id"]: r for r in judge.judge_by_file(cases, rows, CODEMAP)}
    assert (out["hash-1"]["flagged_matched"], out["hash-1"]["flagged_any"]) == (True, True)
    assert (out["hash-2"]["flagged_matched"], out["hash-2"]["flagged_any"]) == (False, True)
    assert (out["hash-ok"]["flagged_matched"], out["hash-ok"]["flagged_any"]) == (False, False)
    assert (out["rsa"]["flagged_matched"], out["rsa"]["flagged_any"]) == (False, False)
    m = judge.metrics(list(out.values()), "matched")
    assert (m["tp"], m["fn"], m["fp"], m["tn"], m["recall"], m["precision"], m["specificity"]) == \
        (1, 2, 0, 1, 0.3333, 1.0, 1.0)


def test_empty_denominators_are_none():
    m = judge.metrics([], "matched")
    assert (m["recall"], m["precision"], m["specificity"]) == (None, None, None)


def line_cases():
    return [case("corpus", "A", ["x.cs"], "csharp", "cert_validation_off", True, lines=[17], line_tolerance=1),
            case("corpus", "FP", ["x.cs"], "csharp", "cert_validation_off", False, lines=[16], line_tolerance=1),
            case("corpus", "B", ["x.cs"], "csharp", "weak_tls_version", True, lines=[18], line_tolerance=1),
            case("corpus", "C", ["x.cs"], "csharp", "broken_hash", True, lines=[31], line_tolerance=1),
            case("corpus", "D", ["x.cs"], "csharp", "weak_cipher_suite", True, lines=[28], line_tolerance=1)]


def test_line_matching_is_exact_first_one_to_one_and_ignores_occurrences():
    rows = [row("x.cs", 16, ["TLS_VERIFICATION_DISABLED"], "tls_endpoint:java.trustall"),
            row("x.cs", 17, ["TLS_VERIFICATION_DISABLED"], "tls_endpoint:dotnet.validation_callback_true"),
            row("x.cs", 5, ["WEAK_ALGORITHM"], "MD5", occurrences=[5, 31]),           # only listed at 31
            row("x.cs", 27, ["WEAK_CIPHER_SUITE", "WEAK_PROTOCOL"], "TLS 1.0")]       # one row, two codes
    res, extras = judge.judge_by_line(line_cases(), rows, CODEMAP, set())
    st = {r["case_id"]: r["status"] for r in res}
    # A takes its exact line; FP takes the line-16 row (a false positive); B (line 18) must not steal A's row;
    # D (line 28) gets the suite code of the line-27 row within the tolerance
    assert st == {"A": "hit", "FP": "fp", "B": "miss", "C": "listed", "D": "hit"}
    assert sorted(extras) == [["x.cs", 5, "WEAK_ALGORITHM", "MD5"], ["x.cs", 27, "WEAK_PROTOCOL", "TLS 1.0"]]


def test_without_the_false_positive_the_negative_item_is_a_true_negative():
    rows = [row("x.cs", 17, ["TLS_VERIFICATION_DISABLED"], "tls_endpoint:dotnet.validation_callback_true")]
    res, _ = judge.judge_by_line(line_cases(), rows, CODEMAP, set())
    assert {r["case_id"]: r["status"] for r in res}["FP"] == "tn"     # the line-17 row is A's, not the negative's


def test_libraries_follow_the_osv_answer():
    libs = [{"id": "L1", "file": "pom.xml", "line": 3, "ecosystem": "Maven", "name": "g:a", "version": "1"},
            {"id": "L2", "file": "pom.xml", "line": 4, "ecosystem": "Maven", "name": "g:b", "version": "2"},
            {"id": "L3", "file": "pom.xml", "line": 5, "ecosystem": "Maven", "name": "g:c", "version": "3"}]
    rows = [row("pom.xml", 3, ["VULNERABLE_CRYPTO_LIBRARY"], "g:a@1"), row("pom.xml", 4, ["VULNERABLE_CRYPTO_LIBRARY"], "g:b@2")]
    osv = {"answers": {"L1": {"ids": ["GHSA-1"]}, "L2": {"ids": []}, "L3": {"ids": ["GHSA-3"]}}}
    consumed: set = set()
    res = {r["case_id"]: r["status"] for r in judge.judge_libraries(libs, osv, rows, CODEMAP, consumed)}
    assert res == {"L1": "hit", "L2": "fp", "L3": "miss"} and consumed == {(0, "VULNERABLE_CRYPTO_LIBRARY"),
                                                                          (1, "VULNERABLE_CRYPTO_LIBRARY")}
    res = {r["case_id"]: r["status"] for r in judge.judge_libraries(libs, None, rows, CODEMAP, set())}
    assert res == {"L1": "not-run", "L2": "not-run", "L3": "not-run"}    # no OSV answer is never "secure"


# ------------------------------------------------------------------------------------------------ floors
def results_fixture():
    return {"b": [case("b", "v1", ["a"], "c1", "broken_hash", True, flagged_matched=True, flagged_any=True),
                  case("b", "v2", ["b"], "c1", "broken_hash", True, flagged_matched=False, flagged_any=False),
                  case("b", "s1", ["c"], "c1", "broken_hash", False, flagged_matched=False, flagged_any=True)]}


def fl(**kw):
    base = {"id": "F", "kind": "non-regression", "bench": "b", "where": {}, "metric": "recall", "mode": "matched",
            "op": ">=", "value": 0.5}
    base.update(kw)
    return base


def test_floor_semantics():
    res = results_fixture()
    ev = floors.evaluate(floors_doc([
        fl(id="nr-ok"), fl(id="nr-bad", value=0.6),
        fl(id="t-fail", kind="target", owner="CB-27", value=0.9),
        fl(id="t-pass", kind="target", owner="CB-27", value=0.5),
        fl(id="nr-set", metric="flagged_ids", where={"vulnerable": True}, op="superset", value=["v1"]),
        fl(id="nr-fp", metric="fp_ids", where={"vulnerable": False}, op="subset", value=[]),
        fl(id="nr-fp-any", metric="fp_ids", mode="any", where={"vulnerable": False}, op="subset", value=[]),
        fl(id="missing", bench="nope"), fl(id="missing-ok", bench="nope", not_run_ok="reason"),
        fl(id="empty", where={"category": "zzz"})]), res, {})
    st = {e["id"]: e["status"] for e in ev}
    assert st == {"nr-ok": "pass", "nr-bad": "fail", "t-fail": "expected-fail", "t-pass": "unexpected-pass",
                  "nr-set": "pass", "nr-fp": "pass", "nr-fp-any": "fail", "missing": "not-run",
                  "missing-ok": "not-run-ok", "empty": "not-run"}
    assert floors.verdict([e for e in ev if e["id"] in ("nr-ok", "t-fail", "missing-ok")]) == "pass"
    for bad in ("nr-bad", "t-pass", "missing"):
        assert floors.verdict([e for e in ev if e["id"] in ("nr-ok", bad)]) == "fail"


def test_floors_file_is_valid_and_every_target_has_an_owner():
    doc = floors.load(D1 / "floors.json")
    assert doc["version"] >= 1
    targets = [f for f in doc["floors"] if f["kind"] == "target"]
    assert targets and {f["owner"] for f in targets} == {"CB-27", "CB-28", "CB-29"}
    assert {f["bench"] for f in doc["floors"]} <= {"cryptoapi-bench", "owasp-benchmark", "corpus", "libraries"}


# ------------------------------------------------------------------------------------------------ whole score
def mini_work(tmp: Path, extra_cab_rows=()) -> Path:
    cab = [case("cryptoapi-bench", "16.1.1", ["H.java"], "brokenhash", "broken_hash", True, complexity="basis-benchmark"),
           case("cryptoapi-bench", "16.1.5", ["G.java"], "brokenhash", "broken_hash", False, complexity="basis-benchmark")]
    ow = [case("owasp-benchmark", "BenchmarkTest00003", ["T3.java"], "hash", "broken_hash", True)]
    cp = [case("corpus", "N1", ["x.cs"], "csharp", "broken_hash", True, lines=[10], line_tolerance=1,
               language="csharp", label="MD5")]
    return make_work(tmp, {"cryptoapi-bench": (cab, [row("H.java", 9, ["WEAK_ALGORITHM"], "MD5"), *extra_cab_rows]),
                           "owasp-benchmark": (ow, []), "corpus": (cp, [row("x.cs", 10, ["WEAK_ALGORITHM"], "MD5")])})


def test_score_is_deterministic(tmp_path):
    work = mini_work(tmp_path)
    fpath = tmp_path / "floors.json"
    fpath.write_text(json.dumps(floors_doc([fl(id="nr", bench="cryptoapi-bench", value=1.0)])))
    one = cli.score(work, fpath, D1 / "codemap.json", "x")
    two = cli.score(work, fpath, D1 / "codemap.json", "x")
    assert one["result_sha256"] == two["result_sha256"] and one["verdict"] == "pass"
    assert one["results"]["cryptoapi-bench"]["by_complexity_category"]["basis-benchmark"]["brokenhash"]["matched"][
        "recall"] == 1.0


def test_an_unmapped_product_code_stops_the_lane(tmp_path):
    work = mini_work(tmp_path, extra_cab_rows=[row("G.java", 3, ["STATIC_SALT"], "salt")])
    fpath = tmp_path / "floors.json"
    fpath.write_text(json.dumps(floors_doc([])))
    with pytest.raises(LaneError, match="not in codemap.json.*STATIC_SALT"):
        cli.score(work, fpath, D1 / "codemap.json", "x")


def test_observed_from_another_tree_is_refused(tmp_path):
    work = mini_work(tmp_path)
    doc = json.loads((work / "observed" / "corpus.json").read_text())
    doc["product"]["scan_tree_sha256"] = "other"
    (work / "observed" / "corpus.json").write_text(json.dumps(doc))
    fpath = tmp_path / "floors.json"
    fpath.write_text(json.dumps(floors_doc([])))
    with pytest.raises(LaneError, match="the labels belong to"):
        cli.score(work, fpath, D1 / "codemap.json", "x")


# ------------------------------------------------------------------------------------------------ failing-first
def corpus_results(rows: list[dict], osv: dict) -> dict:
    cases, libs, _ = labels.corpus_cases(CORPUS, CORPUS_LABELS)
    consumed: set = set()
    lib = judge.judge_libraries(libs, osv, rows, CODEMAP, consumed)
    items, extras = judge.judge_by_line(cases, rows, CODEMAP, consumed)
    return {"corpus": items, "libraries": lib}, {"corpus": extras}


OSV_TODAY = {"answers": {"L1": {"ids": ["GHSA-6xx3-rg99-gc3p"]}, "L2": {"ids": []}, "L3": {"ids": ["GHSA-6xx3-rg99-gc3p"]},
                         "L4": {"ids": ["GHSA-59j7-ghrg-fj52"]}, "L5": {"ids": ["GO-2021-0227"]},
                         "L6": {"ids": ["GO-2020-0017"]}}}


def corpus_floors() -> dict:
    doc = floors.load(D1 / "floors.json")
    doc["floors"] = [f for f in doc["floors"] if f["bench"] in ("corpus", "libraries")]
    return doc


def test_corpus_targets_fail_on_todays_product_and_floors_hold():
    """Failing-first (CB-07): on dev's code-lane output (baseline/observed-corpus.json, dev 3df26fd) every CB-28 and
    CB-29 target fails and every non-regression floor holds."""
    rows = observed.load(D1 / "baseline" / "observed-corpus.json", "corpus")["rows"]
    res, extras = corpus_results(rows, OSV_TODAY)
    ev = {e["id"]: e for e in floors.evaluate(corpus_floors(), res, extras)}
    targets = [e for e in ev.values() if e["kind"] == "target"]
    assert len(targets) == 5 and all(e["status"] == "expected-fail" for e in targets)
    assert all(e["status"] == "pass" for e in ev.values() if e["kind"] == "non-regression")
    assert ev["T28-dotnet-trustall-fp"]["observed"] == 0.0 and ev["T29-libraries"]["observed"] == 0.0


def test_a_met_target_fails_the_lane_until_it_becomes_a_floor():
    rows = observed.load(D1 / "baseline" / "observed-corpus.json", "corpus")["rows"]
    rows = [r for r in rows if not (r["location"] == "dotnet/Crypto.cs" and r["line"] == 16)]  # CB-28 removes the FP
    res, extras = corpus_results(rows, OSV_TODAY)
    ev = {e["id"]: e for e in floors.evaluate(corpus_floors(), res, extras)}
    assert ev["T28-dotnet-trustall-fp"]["status"] == "unexpected-pass"
    assert floors.verdict(list(ev.values())) == "fail"


def test_a_lost_detection_or_a_new_false_positive_fails_a_floor():
    rows = observed.load(D1 / "baseline" / "observed-corpus.json", "corpus")["rows"]
    lost = [r for r in rows if not (r["location"] == "go/main.go" and r["line"] == 21)]           # G4 MD5
    ev = {e["id"]: e for e in floors.evaluate(corpus_floors(), *corpus_results(lost, OSV_TODAY))}
    assert ev["NR-CORPUS-detected"]["status"] == "fail" and ev["NR-CORPUS-recall"]["status"] == "fail"
    extra = rows + [row("go/main.go", 3, ["WEAK_ALGORITHM"], "MD5")]
    ev = {e["id"]: e for e in floors.evaluate(corpus_floors(), *corpus_results(extra, OSV_TODAY))}
    assert ev["NR-CORPUS-no-new-extras"]["status"] == "fail"


@pytest.mark.skipif(not os.environ.get("D1_WORK"), reason="needs the fetched benchmarks: D1_WORK=<d1.py prepare --work>")
def test_benchmark_targets_fail_on_todays_product():
    """Failing-first on the public benchmarks: with dev's code-lane output (baseline/, dev 3df26fd) every CB-27 target
    fails, e.g. the BB cases of static IV 0/1, static salts 0/1, seeds 0/2, and every non-regression floor holds."""
    work = Path(os.environ["D1_WORK"])
    res = {}
    for bench in ("cryptoapi-bench", "owasp-benchmark"):
        cases = json.loads((work / "cases" / f"{bench}.json").read_text())["cases"]
        rows = observed.load(D1 / "baseline" / f"observed-{bench}.json", bench)["rows"]
        res[bench] = judge.judge_by_file(cases, rows, CODEMAP)
    doc = floors.load(D1 / "floors.json")
    doc["floors"] = [f for f in doc["floors"] if f["bench"] in res]
    ev = {e["id"]: e for e in floors.evaluate(doc, res, {})}
    assert all(e["status"] == "expected-fail" for e in ev.values() if e["kind"] == "target")
    assert all(e["status"] == "pass" for e in ev.values() if e["kind"] == "non-regression")
    bb = {c: judge.metrics(judge.select(res["cryptoapi-bench"], {"complexity": "basis-benchmark", "category": c}),
                           "matched") for c in ("staticinitializationvector", "staticsalts", "predictableseeds")}
    assert [(m["tp"], m["vulnerable"]) for m in bb.values()] == [(0, 1), (0, 1), (0, 2)]


# ------------------------------------------------------------------------------------------------ review 5878689101
def test_a_vulnerable_item_wins_a_shared_line_over_a_negative():
    """M14: vulnerable items consume findings before negative items, whatever the label order."""
    cases = [case("corpus", "NEG", ["x.cs"], "csharp", "cert_validation_off", False, lines=[16], line_tolerance=1),
             case("corpus", "VUL", ["x.cs"], "csharp", "cert_validation_off", True, lines=[16], line_tolerance=1)]
    rows = [row("x.cs", 16, ["TLS_VERIFICATION_DISABLED"], "tls_endpoint:java.trustall")]
    res, extras = judge.judge_by_line(cases, rows, CODEMAP, set())
    assert {r["case_id"]: r["status"] for r in res} == {"NEG": "tn", "VUL": "hit"} and extras == []


def test_slices_leave_not_run_library_rows_out():
    """M15: a library row with no OSV answer (vulnerable None) is in no denominator: never counted as secure."""
    results = [case("libraries", "L1", ["pom.xml"], "Maven", "vulnerable_library", None, flagged_matched=True,
                    flagged_any=True),
               case("libraries", "L2", ["pom.xml"], "Maven", "vulnerable_library", True, flagged_matched=True,
                    flagged_any=True)]
    sl = judge.slices(results, ["category"])
    for m in (sl["overall"]["matched"], sl["by_category"]["Maven"]["any"]):
        assert (m["cases"], m["vulnerable"], m["secure"], m["fp"], m["specificity"]) == (1, 1, 0, 0, None)


def test_a_floor_change_changes_the_result_hash(tmp_path):
    """M19: the floors are inside result_sha256."""
    work = mini_work(tmp_path)
    shas = []
    for value in (1.0, 0.5):
        fpath = tmp_path / f"floors-{value}.json"
        fpath.write_text(json.dumps(floors_doc([fl(id="nr", bench="cryptoapi-bench", value=value)])))
        rep = cli.score(work, fpath, D1 / "codemap.json", "x")
        assert rep["verdict"] == "pass"
        shas.append(rep["result_sha256"])
    assert shas[0] != shas[1]


def test_a_target_without_an_owner_is_refused(tmp_path):
    """M20: every target names the track that owns it."""
    fpath = tmp_path / "floors.json"
    fpath.write_text(json.dumps(floors_doc([fl(id="t", kind="target", value=0.9)])))
    with pytest.raises(LaneError, match="target floor t names no owning track"):
        floors.load(fpath)


def lib_work(tmp: Path, ids: list[str]) -> Path:
    libs = [{"id": "L1", "file": "pom.xml", "line": 3, "ecosystem": "Maven", "name": "g:a", "version": "1"}]
    work = mini_work(tmp)
    cdoc = json.loads((work / "cases" / "corpus.json").read_text())
    cdoc["libraries"] = libs
    (work / "cases" / "corpus.json").write_text(json.dumps(cdoc))
    (work / "osv.json").write_text(json.dumps({"schema": "zs-cbom-d1-osv/1", "answers": {"L1": {"ids": ids}},
                                               "error": None, "asked_at": "2026-11-12T00:00:00Z"}))
    return work


def test_the_result_hash_reads_the_osv_verdict_not_the_advisory_ids(tmp_path):
    """A new advisory for an already-vulnerable library does not change result_sha256; a changed verdict does
    (README: equal for two runs on the same build, pins and per-library OSV verdicts)."""
    fpath = tmp_path / "floors.json"
    fpath.write_text(json.dumps(floors_doc([])))
    sha = {}
    for name, ids in (("one", ["GHSA-1"]), ("two", ["GHSA-1", "GO-2026-0001"]), ("none", [])):
        rep = cli.score(lib_work(tmp_path / name, ids), fpath, D1 / "codemap.json", "x")
        sha[name] = rep["result_sha256"]
        assert rep["osv_answers"]["L1"]["ids"] == ids                     # the full answer stays in report.json
    assert sha["one"] == sha["two"] and sha["one"] != sha["none"]


def test_ecb_named_by_a_weak_algorithm_row_counts_as_ecb():
    """Review 5878689101 nit: the product reports DES in ECB as WEAK_ALGORITHM `DES-ECB`; that row names ECB."""
    for cat in ("ecb_mode", "cwe327_cipher"):
        assert CODEMAP.accepts(cat, "WEAK_ALGORITHM", "DES-ECB")
        assert CODEMAP.accepts(cat, "WEAK_ALGORITHM", "AES-128-ECB")
        assert CODEMAP.accepts(cat, "WEAK_CIPHER_MODE", "AES-ECB")
    assert not CODEMAP.accepts("ecb_mode", "WEAK_ALGORITHM", "DES")
    assert not CODEMAP.accepts("ecb_mode", "WEAK_ALGORITHM", "DES-CBC")


TLS_PATTERNS = json.loads((REPO / "aibom/src/aibom/cbom/data/verification_patterns.json").read_text())["rows"]


def test_trust_and_hostname_findings_credit_only_their_own_category():
    """Review 5878689101 nit: TLS_VERIFICATION_DISABLED is split on the pattern id the row carries. Every pattern the
    product has (read from its data file: this is the product's vocabulary, not an expected value) is read as exactly
    one of the two; patterns that switch all verification off count as certificate validation."""
    seen = {}
    for p in TLS_PATTERNS:
        alg = f"tls_endpoint:{p['id']}"
        got = [c for c in ("cert_validation_off", "hostname_verification_off")
               if CODEMAP.accepts(c, "TLS_VERIFICATION_DISABLED", alg)]
        assert len(got) == 1, (alg, got)
        seen[p["id"]] = got[0]
    assert {k for k, v in seen.items() if v == "hostname_verification_off"} == {
        "java.hostname_verify_all", "java.hostname_verifier_lambda", "java.allow_all_hostnames",
        "java.noop_hostname_verifier"}
    assert seen["java.trustall"] == seen["go.skip"] == seen["openssl.verify_none"] == "cert_validation_off"
    # a TLS_VERIFICATION_DISABLED row from another emitter (no pattern id) still counts somewhere
    assert CODEMAP.accepts("cert_validation_off", "TLS_VERIFICATION_DISABLED", "PostgreSQL sslmode")
    cases = [case("b", "cert", ["T.java"], "dummycertvalidation", "cert_validation_off", True),
             case("b", "host", ["H.java"], "dummyhostnameverifier", "hostname_verification_off", True)]
    rows = [row("T.java", 5, ["TLS_VERIFICATION_DISABLED"], "tls_endpoint:java.hostname_verify_all"),
            row("H.java", 5, ["TLS_VERIFICATION_DISABLED"], "tls_endpoint:java.trustall")]
    out = {r["case_id"]: (r["flagged_matched"], r["flagged_any"]) for r in judge.judge_by_file(cases, rows, CODEMAP)}
    assert out == {"cert": (False, True), "host": (False, True)}


def test_a_detector_on_the_empty_check_server_trusted_counts_for_j9():
    """Review 5878689101 [minor]: J9's trust-all body is the empty checkServerTrusted on line 59 (CryptoAPI-Bench labels
    its trust-manager cases by that method); the comment and the anonymous class are on line 57. A correct CB-27
    detector reporting line 59 is a hit, not a new extra."""
    rows = observed.load(D1 / "baseline" / "observed-corpus.json", "corpus")["rows"]
    rows = rows + [row("java/src/main/java/com/bank/Crypto.java", 59, ["TLS_VERIFICATION_DISABLED"],
                       "tls_endpoint:java.empty_check_server_trusted")]
    res, extras = corpus_results(rows, OSV_TODAY)
    j9 = next(r for r in res["corpus"] if r["case_id"] == "J9")
    assert j9["lines"] == [57, 59] and j9["status"] == "hit"
    ev = {e["id"]: e for e in floors.evaluate(corpus_floors(), res, extras)}
    assert ev["NR-CORPUS-no-new-extras"]["status"] == "pass"
