"""Match observed findings to labelled cases and compute recall / precision / specificity.

Matching rules (README "Scoring"):
* Benchmarks (CryptoAPI-Bench, OWASP): per case, by file. A case is flagged when a finding on one of its files
  carries a code the code map accepts for the case's lane category (`matched`), or any code that is not ignored
  (`any`). Line numbers are not used: 18 of CryptoAPI-Bench's line cells are Excel dates and OWASP gives none.
* Corpus: per item, by line. A finding counts for an item when it is on the item's file, its primary `line` is one
  of the item's lines (exact pass first, then within the labels' tolerance), its code is accepted for the item's
  category, and that (finding, code) pair has not counted for another item. `listed` = the line only appears in the
  row's `occurrences` (reported, never counted). Pairs left over are `extras`.
* Libraries: per manifest entry; expected vulnerable = OSV lists at least one advisory for that version.
"""
from __future__ import annotations

import collections
import json
import re
from pathlib import Path

from .labels import LaneError


class CodeMap:
    def __init__(self, doc: dict):
        self.version = doc["version"]
        self.ignored = set(doc.get("ignored", {}))
        self.rules: dict[str, list[tuple[str, re.Pattern | None]]] = {}
        for cat, spec in doc["categories"].items():
            self.rules[cat] = [(a["code"], re.compile(a["algorithm"], re.I) if a.get("algorithm") else None)
                               for a in spec["accept"]]
        self.known = {code for rules in self.rules.values() for code, _ in rules} | self.ignored

    @classmethod
    def load(cls, path: Path) -> "CodeMap":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def accepts(self, category: str, code: str, algorithm: str) -> bool:
        if category not in self.rules:
            raise LaneError(f"lane category {category!r} is not in codemap.json")
        return any(code == c and (rx is None or rx.search(algorithm or "")) for c, rx in self.rules[category])

    def unknown(self, rows: list[dict]) -> list[str]:
        return sorted({c for r in rows for c in r["codes"]} - self.known)


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def metrics(results: list[dict], mode: str) -> dict:
    key = f"flagged_{mode}"
    tp = sum(1 for r in results if r["vulnerable"] and r[key])
    fn = sum(1 for r in results if r["vulnerable"] and not r[key])
    fp = sum(1 for r in results if not r["vulnerable"] and r[key])
    tn = sum(1 for r in results if not r["vulnerable"] and not r[key])
    return {"cases": len(results), "vulnerable": tp + fn, "secure": fp + tn, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "recall": _ratio(tp, tp + fn), "precision": _ratio(tp, tp + fp), "specificity": _ratio(tn, tn + fp)}


def _evidence(row: dict, code: str) -> list:
    return [row["location"], row["line"], code, row["algorithm"]]


def judge_by_file(cases: list[dict], rows: list[dict], cm: CodeMap) -> list[dict]:
    by_file: dict[str, list[dict]] = collections.defaultdict(list)
    for r in rows:
        by_file[r["location"]].append(r)
    out = []
    for c in cases:
        pairs = [(r, code) for f in c["files"] for r in by_file.get(f, []) for code in r["codes"]
                 if code not in cm.ignored]
        matched = [p for p in pairs if cm.accepts(c["lane_category"], p[1], p[0]["algorithm"])]
        out.append({**{k: c[k] for k in ("bench", "case_id", "files", "category", "lane_category", "vulnerable")},
                    **{k: c[k] for k in ("complexity", "section", "class_no", "cwe") if k in c},
                    "flagged_matched": bool(matched), "flagged_any": bool(pairs),
                    "evidence": [_evidence(r, code) for r, code in (matched or pairs)]})
    return out


def judge_by_line(cases: list[dict], rows: list[dict], cm: CodeMap, consumed: set) -> tuple[list[dict], list[dict]]:
    """Corpus items. `consumed` holds (row index, code) pairs already used (by the library judge)."""
    state = {c["case_id"]: {"hit": None, "any": False, "listed": False} for c in cases}
    order = [c for c in cases if c["vulnerable"]] + [c for c in cases if not c["vulnerable"]]
    for tol in (0, None):  # exact lines first, then within the item's tolerance
        for c in order:
            if state[c["case_id"]]["hit"] is not None:
                continue
            t = 0 if tol == 0 else c.get("line_tolerance", 0)
            window = {ln + d for ln in c["lines"] for d in range(-t, t + 1)}
            for i, r in enumerate(rows):
                if r["location"] not in c["files"] or r["line"] not in window:
                    continue
                code = next((code for code in r["codes"] if (i, code) not in consumed
                             and cm.accepts(c["lane_category"], code, r["algorithm"])), None)
                if code:
                    consumed.add((i, code))
                    state[c["case_id"]]["hit"] = _evidence(r, code)
                    break
    out = []
    for c in cases:
        s = state[c["case_id"]]
        t = c.get("line_tolerance", 0)
        window = {ln + d for ln in c["lines"] for d in range(-t, t + 1)}
        # `any` for a line item: any code on exactly the item's lines (the tolerance would pull in neighbours)
        near = [(r, code) for r in rows if r["location"] in c["files"] and r["line"] in c["lines"]
                for code in r["codes"] if code not in cm.ignored]
        listed = [(r, code) for r in rows if r["location"] in c["files"] and set(c["lines"]) & set(r["occurrences"])
                  and r["line"] not in window for code in r["codes"]
                  if cm.accepts(c["lane_category"], code, r["algorithm"])]
        status = ("hit" if s["hit"] else "listed" if listed else "miss") if c["vulnerable"] else \
                 ("fp" if s["hit"] else "tn")
        out.append({**{k: c[k] for k in ("bench", "case_id", "files", "category", "lane_category", "vulnerable",
                                          "lines")},
                    "language": c.get("language", c["category"]), "label": c.get("label", ""),
                    "status": status, "flagged_matched": bool(s["hit"]), "flagged_any": bool(s["hit"] or near),
                    "evidence": [s["hit"]] if s["hit"] else [_evidence(r, code) for r, code in (listed or near)]})
    extras = [_evidence(r, code) for i, r in enumerate(rows) for code in r["codes"]
              if (i, code) not in consumed and code not in cm.ignored]
    return out, extras


def judge_libraries(libs: list[dict], osv: dict | None, rows: list[dict], cm: CodeMap, consumed: set) -> list[dict]:
    answers = (osv or {}).get("answers", {})
    out = []
    for lib in libs:
        ans = answers.get(lib["id"])
        hit = None
        for i, r in enumerate(rows):
            if r["location"] != lib["file"] or not r["algorithm"].lower().startswith(lib["name"].lower() + "@"):
                continue
            code = next((c for c in r["codes"] if cm.accepts("vulnerable_library", c, r["algorithm"])), None)
            if code:
                consumed.update((i, c) for c in r["codes"])
                hit = _evidence(r, code)
                break
        base = {"bench": "libraries", "case_id": lib["id"], "files": [lib["file"]], "category": lib["ecosystem"],
                "lane_category": "vulnerable_library", "package": lib["name"], "version": lib["version"]}
        if ans is None:
            out.append({**base, "vulnerable": None, "status": "not-run", "flagged_matched": bool(hit),
                        "flagged_any": bool(hit), "advisories": None, "evidence": [hit] if hit else []})
            continue
        vulnerable = bool(ans["ids"])
        out.append({**base, "vulnerable": vulnerable, "advisories": ans["ids"],
                    "status": ("hit" if hit else "miss") if vulnerable else ("fp" if hit else "tn"),
                    "flagged_matched": bool(hit), "flagged_any": bool(hit), "evidence": [hit] if hit else []})
    return out


def slices(results: list[dict], keys: list[str]) -> dict:
    """{"overall": {...}, "by_<key>": {value: {...}}} with both modes."""
    judged = [r for r in results if r["vulnerable"] is not None]
    out = {"overall": {m: metrics(judged, m) for m in ("matched", "any")}}
    for key in keys:
        groups: dict[str, list[dict]] = collections.defaultdict(list)
        for r in judged:
            groups[str(r.get(key))].append(r)
        out[f"by_{key}"] = {g: {m: metrics(rs, m) for m in ("matched", "any")} for g, rs in sorted(groups.items())}
    return out


def select(results: list[dict], where: dict) -> list[dict]:
    def ok(r: dict) -> bool:
        for k, v in where.items():
            want = v if isinstance(v, list) else [v]
            if r.get(k) not in want:
                return False
        return True
    return [r for r in results if ok(r)]
