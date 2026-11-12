"""Canary grep (G15, O-8): every planted secret is searched in every evidence file in several encodings.

A canary passes when it is found ONLY in its allowed locations AND at its control location (the positive control: a
grep that cannot find the canary where it is known to be proves nothing about where it is not).

Encodings:
  string       raw, base64 (3 alignments), URL-encoded (quote and quote_plus), JSON-escaped
  private_key  PEM base64 body lines, DER hex, SPKI sha256 (from ``openssl pkey -pubout``)
Files are searched as bytes; zip members (trace.zip) are searched inside. ``canaries.txt`` lists ids, encodings and
paths only, never a value.
"""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import quote, quote_plus

from .checks import Checks
from .rundir import read_json

GATE = "G15"
MAX_FILE = 256 * 1024 * 1024


def b64_needles(value: bytes) -> list[bytes]:
    """The part of base64(value) that is the same wherever ``value`` sits in a longer base64 stream."""
    out = []
    for pad in range(3):
        enc = base64.b64encode(b"\0" * pad + value)
        start = ((pad + 2) // 3) * 4
        end = ((pad + len(value)) // 3) * 4
        if end - start >= 8:
            out.append(enc[start:end])
    return out


def string_needles(value: str) -> dict[str, list[bytes]]:
    raw = value.encode()
    return {
        "raw": [raw],
        "base64": b64_needles(raw),
        "url": sorted({quote(value, safe="").encode(), quote_plus(value, safe="").encode()} - {raw}),
        "json": sorted({json.dumps(value)[1:-1].encode()} - {raw}),
        "hex": [raw.hex().encode()],
    }


def _der_from_pem(pem: str) -> bytes:
    body = "".join(line.strip() for line in pem.splitlines() if line.strip() and not line.startswith("-----"))
    return base64.b64decode(body)


def key_needles(pem: str) -> dict[str, list[bytes]]:
    lines = [line.strip() for line in pem.splitlines() if line.strip() and not line.startswith("-----")]
    der = _der_from_pem(pem)
    needles: dict[str, list[bytes]] = {
        # full-width PEM lines (the last one is short and too generic)
        "pem-line": [line.encode() for line in lines if len(line) >= 40][:64],
        # a 48-hex window from the middle of the DER: the private part, not the shared algorithm header
        "der-hex": [der[len(der) // 2: len(der) // 2 + 24].hex().encode()] if len(der) >= 64 else [],
    }
    try:
        spki = subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=pem.encode(),
                              capture_output=True, timeout=20, check=True).stdout
        needles["spki-sha256"] = [hashlib.sha256(spki).hexdigest().encode()]
    except (OSError, subprocess.SubprocessError):
        needles["spki-sha256"] = []
    return needles


def _files(run: Path) -> Iterator[tuple[str, bytes]]:
    for path in sorted(p for p in run.rglob("*") if p.is_file()):
        rel = path.relative_to(run).as_posix()
        if rel in ("canaries.txt", "SHA256SUMS", "report.json", "report.md") or path.stat().st_size > MAX_FILE:
            continue
        data = path.read_bytes()
        yield rel, data
        if path.suffix == ".zip":
            try:
                with zipfile.ZipFile(path) as zf:
                    for name in zf.namelist():
                        info = zf.getinfo(name)
                        if info.file_size <= MAX_FILE and not name.endswith("/"):
                            yield f"{rel}!{name}", zf.read(name)
            except zipfile.BadZipFile:
                pass


def _allowed(rel: str, patterns: list[str]) -> bool:
    base = rel.split("!", 1)[0]
    return any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(base, pat) for pat in patterns)


def needles_for(canary: dict[str, Any], run: Path) -> dict[str, list[bytes]]:
    if canary.get("kind") == "private_key":
        pem_path = run / str(canary.get("pem_path", ""))
        pem = canary.get("value") or (pem_path.read_text(encoding="utf-8") if pem_path.is_file() else "")
        return key_needles(pem) if pem else {}
    return string_needles(str(canary.get("value", "")))


def judge(run: Path, checks: Checks) -> list[str]:
    run = Path(run)
    doc = read_json(run / "oracle" / "canaries.json")
    report: list[str] = []
    if doc is None:
        checks.not_run(f"{GATE}/canaries", GATE, "canary", "oracle/canaries.json not written (lab not run)", {})
        (run / "canaries.txt").write_text("no canaries: oracle/canaries.json absent\n", encoding="utf-8")
        return report
    canaries = doc.get("canaries") or []
    plan = [(c, needles_for(c, run)) for c in canaries]
    hits: dict[str, list[tuple[str, str]]] = {c["id"]: [] for c in canaries}
    for rel, data in _files(run):
        for canary, needles in plan:
            for encoding, values in needles.items():
                if any(v and v in data for v in values):
                    hits[canary["id"]].append((rel, encoding))
    for canary, needles in plan:
        cid = canary["id"]
        subject = {"kind": "canary", "canary": cid, "canary_kind": canary.get("kind")}
        if not any(needles.values()):
            checks.fail(f"{GATE}/canary/{cid}/needles", GATE, "canary", "no-needles", subject,
                        expected="at least one encoding", observed="none (value or key file missing)")
            continue
        allowed = list(canary.get("allowed") or []) + [str(canary.get("control") or "")]
        leaks = sorted({f"{rel} [{enc}]" for rel, enc in hits[cid] if not _allowed(rel, allowed)})
        control = str(canary.get("control") or "")
        found_control = any(_allowed(rel, [control]) for rel, _ in hits[cid]) if control else False
        checks.verdict(f"{GATE}/canary/{cid}/control", GATE, "canary", found_control, "control-missing",
                       {**subject, "check": "control"}, expected=f"found at {control or '<no control set>'}",
                       observed="found" if found_control else "not found")
        checks.verdict(f"{GATE}/canary/{cid}/leaks", GATE, "canary", not leaks, "leak", {**subject, "check": "leak"},
                       expected="0 hits outside the allowed locations", observed=leaks)
        report.append(f"{cid} ({canary.get('kind')}): encodings={','.join(k for k, v in needles.items() if v)} "
                      f"control={'found' if found_control else 'MISSING'} leaks={len(leaks)}")
        report.extend(f"  leak: {leak}" for leak in leaks)
    (run / "canaries.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    return report


def is_hex(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]+", value))
