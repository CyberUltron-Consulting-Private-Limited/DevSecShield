"""The run-directory layout (INTERFACES.md §2) and small file helpers.

    L-<sha12>-<YYYYmmddTHHMMSSZ>/
      MANIFEST.json SHA256SUMS report.json report.md     written last by the harness
      oracle/ lab/                                         written by the lab (CB-02, gen.py)
      steps/<G>/ har/ ui/ api/ db/ exports/ logs/ diff/    written by the flow and collect-evidence.sh
      canaries.txt
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable

# oracle/ and lab/ belong to the lab generator (CB-02), which creates them with its own owner and modes
SUBDIRS = ("steps", "har", "ui", "api", "db", "exports", "logs", "diff")
RUN_NAME = re.compile(r"^(?P<tier>[LASV])-(?P<sha>[0-9a-f]{7,40})-(?P<utc>\d{8}T\d{6}Z)$")


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def iso(ts: dt.datetime) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    return ts.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: Any) -> dt.datetime | None:
    """ISO-8601 in any of the shapes the product, docker and the lab write; naive values are UTC."""
    if value in (None, ""):
        return None
    text = str(value).strip().replace(" ", "T")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # docker --timestamps writes nanoseconds; Python takes at most microseconds
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        ts = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    return ts.astimezone(dt.timezone.utc)


def run_name(sha: str, when: dt.datetime | None = None, tier: str = "L") -> str:
    when = when or utc_now()
    return f"{tier}-{sha[:12]}-{when.strftime('%Y%m%dT%H%M%SZ')}"


def create(root: Path, sha: str, when: dt.datetime | None = None, tier: str = "L") -> Path:
    run = Path(root) / run_name(sha, when, tier)
    run.mkdir(parents=True, exist_ok=False)
    for sub in SUBDIRS:
        (run / sub).mkdir()
    return run


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_tree(paths: Iterable[Path], base: Path) -> str:
    """One hash over several files: sha256 of the sorted "<sha256>  <relative path>" lines (O-5 oracle hash)."""
    lines = sorted(f"{sha256_file(p)}  {p.relative_to(base).as_posix()}" for p in paths if p.is_file())
    return hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest()


def read_json(path: Path, default: Any = None) -> Any:
    path = Path(path)
    if not path.is_file():
        return default
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: Path, data: Any) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True, default=str)
        fh.write("\n")
    tmp.replace(path)
    return path


def read_csv(path: Path) -> list[dict[str, str]]:
    path = Path(path)
    if not path.is_file():
        return []
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str] | None = None) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = fields or sorted({k for row in rows for k in row})
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: _cell(row.get(k)) for k in fields})
    tmp.replace(path)
    return path


def write_text(path: Path, text: str) -> Path:
    """Write by replacing the file (a new inode): a judge run on a hard-linked copy of a sealed bundle (cp -al,
    negative controls) never rewrites the bundle's own bytes."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)
    return path


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value)


def run_steps(run: Path) -> list[str]:
    """Run indexes of a gate run: the union of ``oracle/run<k>.json``, ``api/assets-run<k>.json`` and the product runs
    the flow started (``flow-state.json`` ``runs``, 1-based). A run with an oracle but no API capture is still judged
    (its rows become NOT-RUN and must be ledgered), never skipped (m4)."""
    run = Path(run)
    found: set[str] = set()
    for sub, pattern in (("api", r"assets-run(\d+)\.json$"), ("oracle", r"run(\d+)\.json$")):
        for p in (run / sub).glob("*.json") if (run / sub).is_dir() else []:
            m = re.match(pattern, p.name)
            if m:
                found.add(m.group(1))
    state = read_json(run / "flow-state.json") or {}
    found |= {str(i + 1) for i in range(len(state.get("runs") or []))}
    return sorted(found, key=int)
