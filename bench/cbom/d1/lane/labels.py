"""Ground truth readers. Every expected value here comes from the benchmark's own published label file, the corpus
labels transcribed from the corpus's own item comments, or an OSV answer recorded at test time (O-2)."""
from __future__ import annotations

import collections
import csv
import json
import re
from pathlib import Path

from . import SCHEMA_CORPUS, xlsx


class LaneError(Exception):
    """A lane input is not what was pinned or reviewed: the run is not judged (exit 2), never a pass."""


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _case(bench, case_id, files, category, lane_category, vulnerable, **extra) -> dict:
    return {"bench": bench, "case_id": case_id, "files": files, "category": category,
            "lane_category": lane_category, "vulnerable": vulnerable, **extra}


# --------------------------------------------------------------------------------------------- CryptoAPI-Bench
def cryptoapi_cases(tree: Path, spec: dict) -> tuple[list[dict], dict]:
    """Cases from CryptoAPI-Bench_details.xlsx. Category = the case file's directory in the benchmark tree; complexity
    = the sheet's own section header (column A); vulnerable = column D. A case whose files are not in the tree, or
    whose column D is neither TRUE nor FALSE, is excluded with its reason (never remapped)."""
    rows = xlsx.read_rows(tree / spec["labels"]["path"])
    src = tree / spec["source_root"]
    java: dict[str, list[str]] = collections.defaultdict(list)
    for p in sorted(src.rglob("*.java")):
        java[p.name].append(p.relative_to(tree).as_posix())
    cat_map = spec["categories"]
    cases, excluded, section = [], [], ""
    seen_ids: collections.Counter = collections.Counter()
    labelled_files: set[str] = set()
    date_cells = 0
    for r in rows[1:]:
        a = r.get("A", {}).get("text", "")
        if a:
            section = a
        names = [n.strip() for n in r.get("B", {}).get("text", "").splitlines() if n.strip()]
        if not names:
            continue
        code = r.get("C", {}).get("text", "")
        seen_ids[code] += 1
        case_id = code if seen_ids[code] == 1 else f"{code}#{seen_ids[code]}"
        files = [n if n.endswith(".java") else n + ".java" for n in names]
        labelled_files.update(files)
        vulnerable = xlsx.boolean_cell(r.get("D"))
        g = r.get("G", {})
        date_cells += bool(g.get("date_styled"))
        paths = [java[f][0] if len(java.get(f, [])) == 1 else None for f in files]
        dirs = sorted({Path(p).parent.name for p in paths if p})
        extra = {"complexity": slug(section), "section": section, "class_no": (code.split(".") + ["", ""])[1],
                 "label_raw": r.get("D", {}).get("formula") or r.get("D", {}).get("text", ""),
                 "vulnerability_type": r.get("E", {}).get("text", ""),
                 "lines_raw": g.get("text", ""), "lines_date_styled": bool(g.get("date_styled"))}
        if not all(paths):
            missing = [f for f, p in zip(files, paths) if not p]
            excluded.append({"case_id": case_id, "files": files, "vulnerable": vulnerable,
                             "reason": f"file(s) not in the tree at the pinned commit: {', '.join(missing)}"})
            continue
        if vulnerable is None:
            excluded.append({"case_id": case_id, "files": files, "vulnerable": None,
                             "reason": f"column D is neither TRUE nor FALSE: {extra['label_raw']!r}"})
            continue
        category = dirs[0] if len(dirs) == 1 else "+".join(dirs)
        if category not in cat_map:
            raise LaneError(f"CryptoAPI-Bench category {category!r} (case {case_id}) has no lane category in sources.json")
        cases.append(_case("cryptoapi-bench", case_id, paths, category, cat_map[category], vulnerable, **extra))
    # Label anomalies the benchmark itself carries (reported, not corrected): the code number's first field names a
    # different category than most rows of the same directory.
    modal = {}
    by_dir = collections.defaultdict(collections.Counter)
    for c in cases:
        by_dir[c["category"]][c["case_id"].split(".")[0]] += 1
    for d, cnt in by_dir.items():
        modal[d] = cnt.most_common(1)[0][0]
    anomalies = [{"case_id": c["case_id"], "files": c["files"],
                  "note": f"code number names category {c['case_id'].split('.')[0]}, the file is in {c['category']}/ "
                          f"(whose other rows use {modal[c['category']]}); the directory is used"}
                 for c in cases if c["case_id"].split(".")[0] != modal[c["category"]]]
    meta = {"labelled": len(cases) + len(excluded),
            "vulnerable": sum(1 for c in cases if c["vulnerable"]) + sum(1 for e in excluded if e["vulnerable"] is True),
            "secure": sum(1 for c in cases if not c["vulnerable"]) + sum(1 for e in excluded if e["vulnerable"] is False),
            "judged": len(cases), "judged_vulnerable": sum(1 for c in cases if c["vulnerable"]),
            "judged_secure": sum(1 for c in cases if not c["vulnerable"]),
            "date_styled_line_cells": date_cells, "excluded": excluded, "anomalies": anomalies,
            "unresolved_files": sorted(f for e in excluded for f in e["files"] if f not in java),
            "java_files": sum(len(v) for v in java.values()),
            "java_files_without_label": sorted(set(java) - labelled_files)}
    check_pinned("cryptoapi-bench", meta, spec.get("pinned", {}))
    return cases, meta


def check_pinned(bench: str, meta: dict, pinned: dict) -> None:
    """The label file must read exactly as pinned (counts read independently by CB-02 and its reviewer, and by this
    lane). Anything else means the labels or the reader changed: not judged."""
    bad = [f"{k}: pinned {v!r}, read {meta.get(k)!r}" for k, v in pinned.items() if meta.get(k) != v]
    if bad:
        raise LaneError(f"{bench} labels do not match the pinned reading: " + "; ".join(bad))


# --------------------------------------------------------------------------------------------- OWASP Benchmark
def owasp_cases(tree: Path, spec: dict) -> tuple[list[dict], dict]:
    """Cases from expectedresults-1.2.csv (`# test name, category, real vulnerability, cwe`), for the categories the
    lane covers. The case file is the test's own class."""
    wanted = spec["categories"]
    cases, counts = [], collections.Counter()
    with open(tree / spec["labels"]["path"], newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row or row[0].lstrip().startswith("#"):
                continue
            name, cat, real, cwe = (x.strip() for x in row[:4])
            if cat not in wanted:
                continue
            if real not in ("true", "false"):
                raise LaneError(f"OWASP expected result for {name} is {real!r}, not true/false")
            vulnerable = real == "true"
            counts[f"{cat}_{'true' if vulnerable else 'false'}"] += 1
            cases.append(_case("owasp-benchmark", name, [spec["case_path"].format(name=name)], cat, wanted[cat],
                               vulnerable, cwe=f"CWE-{cwe}"))
    meta = {"judged": len(cases), "judged_vulnerable": sum(1 for c in cases if c["vulnerable"]),
            "judged_secure": sum(1 for c in cases if not c["vulnerable"]), **dict(sorted(counts.items())),
            "excluded": [], "anomalies": []}
    check_pinned("owasp-benchmark", meta, spec.get("pinned", {}))
    return cases, meta


# --------------------------------------------------------------------------------------------- corpus
ID_RE = re.compile(r"(?<![A-Za-z0-9])([JNGCTFK][1-9][0-9]?)(?![A-Za-z0-9])")
COMMENT_RE = re.compile(r"(//|/\*|(?<![A-Za-z0-9_])#(?!include|define|if|endif|pragma))(.*)$")


def corpus_comment_items(corpus: Path) -> list[dict]:
    """The planted item ids as the corpus author wrote them: `// J3 static zero IV`, `/* C1 TLS 1.0 */`, `# T5 ...`.
    One comment may name several items (`// G2 3DES + G3 hard-coded key`)."""
    out = []
    for path in sorted(p for p in corpus.rglob("*") if p.is_file()):
        rel = path.relative_to(corpus).as_posix()
        for no, text in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            m = COMMENT_RE.search(text)
            if not m:
                continue
            body = m.group(2).replace("*/", "")
            ids = list(ID_RE.finditer(body))
            for i, idm in enumerate(ids):
                end = ids[i + 1].start() if i + 1 < len(ids) else len(body)
                label = body[idm.end():end].strip().rstrip("+").strip()
                out.append({"id": idm.group(1), "file": rel, "line": no, "label": label})
    return out


def corpus_cases(corpus: Path, labels_path: Path) -> tuple[list[dict], list[dict], dict]:
    """Code items (line-level) and library items from labels.json, checked against the corpus itself: every comment
    item has exactly one label row with the same file, line and text, and every library is in its manifest."""
    doc = json.loads(labels_path.read_text(encoding="utf-8"))
    if doc.get("schema") != SCHEMA_CORPUS:
        raise LaneError(f"{labels_path}: schema {doc.get('schema')!r}")
    planted = {i["id"]: i for i in corpus_comment_items(corpus)}
    items, problems = doc["items"], []
    labelled = {i["id"]: i for i in items if i.get("source", "comment") == "comment"}
    for iid in sorted(set(planted) | set(labelled)):
        p, l_ = planted.get(iid), labelled.get(iid)
        if not p or not l_:
            problems.append(f"{iid}: in {'labels.json' if l_ else 'the corpus'} only")
        elif (p["file"], p["line"], p["label"]) != (l_["file"], l_["line"], l_["label"]):
            problems.append(f"{iid}: corpus says {p['file']}:{p['line']} {p['label']!r}, labels.json "
                            f"{l_['file']}:{l_['line']} {l_['label']!r}")
    for lib in doc.get("libraries", []):
        text = (corpus / lib["file"]).read_text(encoding="utf-8").splitlines()
        line = text[lib["line"] - 1] if 0 < lib["line"] <= len(text) else ""
        short = lib["name"].split(":")[-1]
        if short not in line or lib["version"] not in line:
            problems.append(f"{lib['id']}: {lib['name']} {lib['version']} not on {lib['file']}:{lib['line']}")
    if problems:
        raise LaneError("corpus labels disagree with the corpus: " + "; ".join(problems))
    tol = int(doc.get("match", {}).get("line_tolerance", 0))
    cases = [_case("corpus", i["id"], [i["file"]], i["language"], i["category"], i["vulnerable"],
                   lines=i.get("lines") or [i["line"]], line_tolerance=tol, language=i["language"],
                   label=i["label"], source=i.get("source", "comment")) for i in items]
    meta = {"judged": len(cases), "judged_vulnerable": sum(1 for c in cases if c["vulnerable"]),
            "judged_secure": sum(1 for c in cases if not c["vulnerable"]), "libraries": len(doc.get("libraries", [])),
            "line_tolerance": tol, "excluded": [], "anomalies": [], "author": doc["source"]}
    return cases, doc.get("libraries", []), meta
