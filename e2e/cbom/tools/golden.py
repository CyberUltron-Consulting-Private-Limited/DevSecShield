"""Make the golden negative-control fixture (tests/golden/) from a real Tier-L run directory.

    python3 e2e/cbom/tools/golden.py <run> e2e/cbom/tests/golden

Keeps what the judge reads, trimmed so CI can re-judge it 28 times in seconds:
* api/, ui/, db/*.csv, exports/*.json (CycloneDX JSON only), oracle/run<k>.json, lab/{lab,selfcheck,gen}.json,
  lab/listeners/*.jsonl, flow-state.json, MANIFEST.json, steps/<G>/step.json and the small JSON next to it, logs/*.log;
* har/: the 5xx entries plus the first API calls of each file, response bodies cut to 2 KB.
Drops every lab secret and planted file (lab/secrets, lab/targets, selfcheck-raw), oracle/canaries.json and
oracle/facts (the test generates its own canary at run time), screenshots, traces, videos, XML/OSCAL bodies and the
judge's outputs. Then refuses to finish if any of the run's real canary values, a private-key block, a JWT or a node
token survives in the fixture (checked with the run's own oracle/canaries.json, which is never copied).
"""
from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from harness import canary, redact  # noqa: E402

KEEP_TOP = ("flow-state.json", "MANIFEST.json")
KEEP_DIRS = {"api": ("*.json",), "ui": ("*.json",), "db": ("*.csv",), "exports": ("*.cdx.json",),
             "logs": ("*.log",)}
HAR_KEEP = 30
BODY_MAX = 2048
BAD = [re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), re.compile(r"eyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}"),
       re.compile(r"zsr_[A-Za-z0-9]{16,}")]


def _har(src: Path, dst: Path) -> None:
    doc = json.loads(src.read_text(encoding="utf-8"))
    entries = (doc.get("log") or {}).get("entries") or []
    keep = [e for e in entries if int((e.get("response") or {}).get("status") or 0) >= 500]
    keep += [e for e in entries if "/cbom/" in str((e.get("request") or {}).get("url"))][:HAR_KEEP]
    seen, out = set(), []
    for e in sorted(keep, key=lambda e: str(e.get("startedDateTime"))):
        key = (e.get("startedDateTime"), (e.get("request") or {}).get("url"))
        if key in seen:
            continue
        seen.add(key)
        content = (e.get("response") or {}).get("content") or {}
        if len(str(content.get("text") or "")) > BODY_MAX:
            content["text"] = str(content["text"])[:BODY_MAX] + "...<cut by tools/golden.py>"
        req = e.get("request") or {}
        if (req.get("postData") or {}).get("text") and len(req["postData"]["text"]) > BODY_MAX:
            req["postData"]["text"] = req["postData"]["text"][:BODY_MAX] + "...<cut>"
        out.append(e)
    doc.setdefault("log", {})["entries"] = out
    dst.write_text(json.dumps(doc, indent=1), encoding="utf-8")


def make(run: Path, dest: Path) -> Path:
    out = dest / run.name
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for name in KEEP_TOP:
        if (run / name).is_file():
            shutil.copy2(run / name, out / name)
    for sub, globs in KEEP_DIRS.items():
        for g in globs:
            for f in sorted((run / sub).glob(g)):
                (out / sub).mkdir(exist_ok=True)
                shutil.copy2(f, out / sub / f.name)
    (out / "oracle").mkdir()
    for f in sorted((run / "oracle").glob("run*.json")):
        shutil.copy2(f, out / "oracle" / f.name)
    (out / "lab" / "listeners").mkdir(parents=True)
    for name in ("lab.json", "selfcheck.json", "gen.json"):
        if (run / "lab" / name).is_file():
            shutil.copy2(run / "lab" / name, out / "lab" / name)
    for f in sorted((run / "lab" / "listeners").glob("*.jsonl")):
        shutil.copy2(f, out / "lab" / "listeners" / f.name)
    for step in sorted((run / "steps").iterdir()):
        if not step.is_dir():
            continue
        for f in sorted(step.glob("*.json")):
            if f.stat().st_size <= 256 * 1024:
                (out / "steps" / step.name).mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, out / "steps" / step.name / f.name)
    (out / "har").mkdir()
    for f in sorted((run / "har").glob("*.har")):
        _har(f, out / "har" / f.name)
    (out / "diff").mkdir()
    _refuse_secrets(run, out)
    return out


def _refuse_secrets(run: Path, out: Path) -> None:
    doc = json.loads((run / "oracle" / "canaries.json").read_text(encoding="utf-8"))
    canaries = doc.get("canaries") or []
    shared = canary._shared_lines(canaries, run)
    plan = [(c, canary.needles_for(c, run, shared)) for c in canaries]
    leaks = []
    for f in sorted(p for p in out.rglob("*") if p.is_file()):
        data = f.read_bytes()
        text = data.decode("utf-8", "replace")
        rel = f.relative_to(out).as_posix()
        for c, needles in plan:
            for enc, values in needles.items():
                if any(v and v in data for v in values):
                    leaks.append(f"{rel}: canary {c['id']} [{enc}]")
        leaks += [f"{rel}: {rx.pattern[:24]}" for rx in BAD if rx.search(text)]
        leaks += [f"{rel}: residual {kind}" for kind in redact.residual_secrets(text, [])]
    if leaks:
        shutil.rmtree(out)
        raise SystemExit("refusing the fixture, secrets left:\n  " + "\n  ".join(leaks[:40]))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    print(make(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()))
