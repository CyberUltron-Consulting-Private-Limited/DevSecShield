#!/usr/bin/env python3
"""Index and verify the dss-e2e evidence directory. Standard library only.

Called by collect-evidence.sh. In order, it

1. harvests Playwright's per-test video / screenshot attachments (reports/playwright.json) into
   videos/<spec>.webm and screenshots/<spec>-auto-NN.png, never overwriting an artefact a spec
   already saved under its own name;
2. writes <pdf>.sha256 sidecars and <video>.ffprobe.json sidecars;
3. proves the backend container made no outbound connection except to postgres / mongo / loopback
   by decoding /proc/net/tcp{,6} (logs/80-no-egress-proc-net-tcp.txt);
4. checks that each of the six deliverables has its complete artefact set (Definition of Done 5);
5. writes reports/index.json (file -> sha256, bytes, duration, pages, ...) and SUMMARY.md, both
   generated from what is on disk: nothing in them is hand-written.

Exit status: 0 normally; with --strict, 1 when a deliverable is incomplete, a Playwright test
failed, or the egress proof failed or could not be taken.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import shutil
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# (number, slug): the six PDFs. Artefact names are NN-<slug>* (plan 7.6 / 7.7).
DELIVERABLES: list[tuple[str, str]] = [
    ("07", "certificate-estate-register"),
    ("16", "board-executive-report"),
    ("03", "methodology-evidence-plan"),
    ("15", "pqc-migration-roadmap"),
    ("01", "scope-baseline-register"),
    ("10", "third-party-assurance-register"),
]
MIN_SCREENSHOTS = 5
MIN_VIDEO_SECONDS = 10.0
VIDEO_SIZE = (1440, 900)
BACKEND_CONTAINER = "dss-e2e-backend"
POSTGRES_CONTAINER = "dss-e2e-postgres"
MONGO_CONTAINER = "dss-e2e-mongo"
TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}
INDEX_SKIP_PARTS = {"test-results", "html"}


# --------------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def png_size(path: Path) -> tuple[int, int] | None:
    try:
        with path.open("rb") as fh:
            head = fh.read(24)
    except OSError:
        return None
    if len(head) < 24 or head[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    width, height = struct.unpack(">II", head[16:24])
    return width, height


def ffprobe_video(path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {"duration_s": None, "width": None, "height": None, "codec": None}
    proc = run(
        [
            "ffprobe",
            "-v",
            "error",
            "-select_streams",
            "v:0",
            "-show_entries",
            "stream=codec_name,width,height,duration:format=duration",
            "-of",
            "json",
            str(path),
        ]
    )
    if proc is None or proc.returncode != 0:
        return info
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return info
    streams = data.get("streams") or [{}]
    stream = streams[0]
    info["width"], info["height"], info["codec"] = stream.get("width"), stream.get("height"), stream.get("codec_name")
    for raw in (stream.get("duration"), (data.get("format") or {}).get("duration")):
        try:
            info["duration_s"] = round(float(raw), 3)
            break
        except (TypeError, ValueError):
            continue
    if info["duration_s"] is None:  # WebM from Playwright can lack container duration: decode it
        dec = run(["ffmpeg", "-v", "error", "-stats", "-i", str(path), "-f", "null", "-"], timeout=300)
        if dec is not None:
            times = re.findall(r"time=(\d+):(\d+):(\d+(?:\.\d+)?)", dec.stderr)
            if times:
                hh, mm, ss = times[-1]
                info["duration_s"] = round(int(hh) * 3600 + int(mm) * 60 + float(ss), 3)
    return info


def pdfinfo(path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {"pages": None, "title": None, "magic_ok": False}
    try:
        with path.open("rb") as fh:
            info["magic_ok"] = fh.read(5) == b"%PDF-"
    except OSError:
        return info
    proc = run(["pdfinfo", str(path)])
    if proc is not None and proc.returncode == 0:
        pages = re.search(r"^Pages:\s+(\d+)", proc.stdout, re.M)
        title = re.search(r"^Title:\s*(.*)$", proc.stdout, re.M)
        info["pages"] = int(pages.group(1)) if pages else None
        info["title"] = title.group(1).strip() if title and title.group(1).strip() else None
    return info


# --------------------------------------------------------------------------------------------
# 1. Playwright harvest
# --------------------------------------------------------------------------------------------
def collect_results(suite: dict[str, Any], out: list[dict[str, Any]]) -> None:
    for spec in suite.get("specs") or []:
        for test in spec.get("tests") or []:
            results = test.get("results") or []
            last = results[-1] if results else {}
            out.append(
                {
                    "file": spec.get("file") or suite.get("file") or "",
                    "title": spec.get("title") or "",
                    "status": last.get("status") or test.get("status") or "unknown",
                    "duration_ms": last.get("duration"),
                    "attachments": [a for r in results for a in (r.get("attachments") or [])],
                }
            )
    for child in suite.get("suites") or []:
        collect_results(child, out)


def spec_base(file: str) -> str:
    name = Path(file).name
    for suffix in (".spec.ts", ".spec.js", ".ts", ".js"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def harvest_playwright(evidence: Path) -> dict[str, Any]:
    report = evidence / "reports" / "playwright.json"
    summary: dict[str, Any] = {"report_present": report.is_file(), "stats": {}, "tests": [], "harvested": []}
    if not report.is_file():
        return summary
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        summary["report_unreadable"] = True
        return summary
    summary["stats"] = data.get("stats") or {}
    tests: list[dict[str, Any]] = []
    for suite in data.get("suites") or []:
        collect_results(suite, tests)
    seen: dict[str, int] = {}
    for test in tests:
        base = spec_base(test["file"])
        seen[base] = seen.get(base, 0) + 1
        suffix = "" if seen[base] == 1 else f"-t{seen[base]}"
        shots = 0
        for att in test["attachments"]:
            src = Path(att.get("path") or "")
            if not src.is_file():
                continue
            if att.get("name") == "video":
                dest = evidence / "videos" / f"{base}{suffix}.webm"
            elif att.get("name") == "screenshot":
                shots += 1
                dest = evidence / "screenshots" / f"{base}{suffix}-auto-{shots:02d}.png"
            else:
                continue
            if not dest.exists():
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
                summary["harvested"].append(str(dest.relative_to(evidence)))
        summary["tests"].append(
            {"file": test["file"], "title": test["title"], "status": test["status"], "duration_ms": test["duration_ms"]}
        )
    return summary


# --------------------------------------------------------------------------------------------
# 3. no-egress proof
# --------------------------------------------------------------------------------------------
def decode_addr(hex_addr: str) -> tuple[Any, int]:
    host_hex, port_hex = hex_addr.split(":")
    raw = bytes.fromhex(host_hex)
    if len(raw) == 4:
        address: Any = ipaddress.IPv4Address(struct.pack("<I", struct.unpack(">I", raw)[0]))
    else:
        words = [struct.pack("<I", struct.unpack(">I", raw[i : i + 4])[0]) for i in range(0, 16, 4)]
        address = ipaddress.IPv6Address(b"".join(words))
        if address.ipv4_mapped is not None:
            address = address.ipv4_mapped
    return address, int(port_hex, 16)


def parse_proc_net_tcp(text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4 or ":" not in parts[1] or ":" not in parts[2]:
            continue
        try:
            local_ip, local_port = decode_addr(parts[1])
            remote_ip, remote_port = decode_addr(parts[2])
        except (ValueError, struct.error):
            continue
        rows.append(
            {
                "local": f"{local_ip}:{local_port}",
                "local_port": local_port,
                "remote": f"{remote_ip}:{remote_port}",
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": TCP_STATES.get(parts[3].upper(), parts[3]),
            }
        )
    return rows


def container_ips(name: str) -> list[str]:
    proc = run(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name])
    if proc is None or proc.returncode != 0:
        return []
    return [ip for ip in proc.stdout.split() if ip]


def read_proc_net(container: str, proc_dir: Path | None) -> tuple[str, str] | None:
    if proc_dir is not None:  # test hook: pre-captured files instead of docker exec
        tcp = (proc_dir / "tcp").read_text(encoding="utf-8") if (proc_dir / "tcp").is_file() else ""
        tcp6 = (proc_dir / "tcp6").read_text(encoding="utf-8") if (proc_dir / "tcp6").is_file() else ""
        return tcp, tcp6
    outputs = []
    for table in ("tcp", "tcp6"):
        proc = run(["docker", "exec", container, "cat", f"/proc/net/{table}"])
        if proc is None:
            return None
        if proc.returncode != 0:
            if table == "tcp":
                return None
            outputs.append("")  # IPv6 disabled in the container: no tcp6 table
            continue
        outputs.append(proc.stdout)
    return outputs[0], outputs[1]


def egress_proof(evidence: Path, proc_dir: Path | None, pg_ips: list[str], mongo_ips: list[str]) -> dict[str, Any]:
    proof: dict[str, Any] = {
        "taken": False,
        "ok": False,
        "container": BACKEND_CONTAINER,
        "violations": [],
        "outbound": [],
    }
    captured = read_proc_net(BACKEND_CONTAINER, proc_dir)
    log_path = evidence / "logs" / "80-no-egress-proc-net-tcp.txt"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if captured is None:
        proof["reason"] = f"could not read /proc/net/tcp of {BACKEND_CONTAINER} (is the stack up?)"
        log_path.write_text(f"{now_iso()}  egress proof NOT taken: {proof['reason']}\n", encoding="utf-8")
        return proof
    tcp_text, tcp6_text = captured
    pg_ips = pg_ips or (container_ips(POSTGRES_CONTAINER) if proc_dir is None else [])
    mongo_ips = mongo_ips or (container_ips(MONGO_CONTAINER) if proc_dir is None else [])
    allowed = {(ip, 5432) for ip in pg_ips} | {(ip, 27017) for ip in mongo_ips}
    rows = parse_proc_net_tcp(tcp_text) + parse_proc_net_tcp(tcp6_text)
    listening = {row["local_port"] for row in rows if row["state"] == "LISTEN"}

    lines = [
        f"{now_iso()}  decoded /proc/net/tcp + /proc/net/tcp6 of {BACKEND_CONTAINER}",
        f"allowed outbound peers: loopback, postgres {sorted(pg_ips)}:5432, mongo {sorted(mongo_ips)}:27017",
        f"listening ports (their peers are inbound clients and are not egress): {sorted(listening)}",
        "",
        f"{'local':<28}{'remote':<28}{'state':<13}class",
    ]
    for row in rows:
        if row["state"] == "LISTEN":
            kind = "listen"
        elif row["local_port"] in listening:
            kind = "inbound"
        elif row["remote_ip"].is_loopback or (str(row["remote_ip"]), row["remote_port"]) in allowed:
            kind = "outbound-allowed"
            proof["outbound"].append(row["remote"])
        else:
            kind = "OUTBOUND-VIOLATION"
            proof["violations"].append(row["remote"])
        lines.append(f"{row['local']:<28}{row['remote']:<28}{row['state']:<13}{kind}")
    proof["taken"] = True
    proof["ok"] = not proof["violations"] and bool(pg_ips or mongo_ips or proc_dir is not None)
    proof["peers"] = sorted(set(proof["outbound"]))
    lines += [
        "",
        f"verdict: {'OK' if proof['ok'] else 'FAIL'}; "
        f"outbound peers observed: {proof['peers'] or 'none'}; "
        f"violations: {proof['violations'] or 'none'}",
    ]
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return proof


# --------------------------------------------------------------------------------------------
# 4. per-deliverable completeness
# --------------------------------------------------------------------------------------------
def first_match(directory: Path, pattern: str) -> list[Path]:
    return sorted(p for p in directory.glob(pattern) if p.is_file()) if directory.is_dir() else []


def deliverable_report(
    evidence: Path, number: str, slug: str, tests: list[dict[str, Any]], infos: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    videos = first_match(evidence / "videos", f"{number}-*.webm")
    video = videos[0] if videos else None
    vinfo = infos.get(str(video.relative_to(evidence))) if video else None
    checks["video"] = {
        "ok": bool(
            vinfo
            and vinfo.get("duration_s") is not None
            and vinfo["duration_s"] >= MIN_VIDEO_SECONDS
            and (vinfo.get("width"), vinfo.get("height")) == VIDEO_SIZE
        ),
        "file": str(video.relative_to(evidence)) if video else None,
        "detail": vinfo,
        "need": f">= {MIN_VIDEO_SECONDS:.0f}s at {VIDEO_SIZE[0]}x{VIDEO_SIZE[1]}",
    }
    shots = first_match(evidence / "screenshots", f"{number}-*.png")
    checks["screenshots"] = {"ok": len(shots) >= MIN_SCREENSHOTS, "count": len(shots), "need": f">= {MIN_SCREENSHOTS}"}
    pdfs = first_match(evidence / "downloads", f"{number}-*.pdf")
    pdf = pdfs[0] if pdfs else None
    pinfo = infos.get(str(pdf.relative_to(evidence))) if pdf else None
    checks["pdf"] = {
        "ok": bool(
            pinfo
            and pinfo.get("magic_ok")
            and (pinfo.get("pages") or 0) >= 1
            and pinfo.get("bytes", 0) > 3 * 1024
            and (evidence / "downloads" / f"{pdf.name}.sha256").is_file()
        ),
        "file": str(pdf.relative_to(evidence)) if pdf else None,
        "detail": pinfo,
        "need": "%PDF- magic, > 3 KB, >= 1 page, .sha256 sidecar",
    }
    for token in ("pdfinfo", "pdftotext", "pdffonts", "api"):
        found = first_match(evidence / "logs", f"{number}-*{token}*")
        checks[f"log_{token}"] = {"ok": bool(found), "files": [str(p.relative_to(evidence)) for p in found]}
    pages = first_match(evidence / "pdf-pages", f"{number}-*.png")
    checks["pdf_pages"] = {"ok": bool(pages), "count": len(pages)}
    pytest_logs = first_match(evidence / "logs", f"pytest-{number}*")
    checks["pytest_log"] = {"ok": bool(pytest_logs), "files": [str(p.relative_to(evidence)) for p in pytest_logs]}
    spec_tests = [t for t in tests if spec_base(t["file"]).startswith(f"{number}-")]
    checks["playwright_spec"] = {
        "ok": bool(spec_tests) and all(t["status"] == "passed" for t in spec_tests),
        "tests": [{"title": t["title"], "status": t["status"]} for t in spec_tests],
    }
    return {"number": number, "slug": slug, "complete": all(c["ok"] for c in checks.values()), "checks": checks}


# --------------------------------------------------------------------------------------------
# 5. index + summary
# --------------------------------------------------------------------------------------------
def build_file_index(evidence: Path) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    entries: list[dict[str, Any]] = []
    infos: dict[str, dict[str, Any]] = {}
    for path in sorted(evidence.rglob("*")):
        if not path.is_file() or path.name == "index.json" or path.name.startswith("."):
            continue
        rel = path.relative_to(evidence)
        if INDEX_SKIP_PARTS & set(rel.parts):
            continue
        entry: dict[str, Any] = {"path": str(rel), "bytes": path.stat().st_size, "sha256": sha256_file(path)}
        suffix = path.suffix.lower()
        if suffix == ".webm":
            entry["kind"] = "video"
            entry.update(ffprobe_video(path))
            sidecar = path.with_name(path.name + ".ffprobe.json")
            sidecar.write_text(
                json.dumps({k: entry[k] for k in ("duration_s", "width", "height", "codec")}, indent=2) + "\n",
                encoding="utf-8",
            )
        elif suffix == ".pdf":
            entry["kind"] = "pdf"
            entry.update(pdfinfo(path))
            path.with_name(path.name + ".sha256").write_text(f"{entry['sha256']}  {path.name}\n", encoding="utf-8")
        elif suffix == ".png":
            entry["kind"] = "image"
            size = png_size(path)
            if size:
                entry["width"], entry["height"] = size
        else:
            entry["kind"] = "log" if rel.parts[0] == "logs" else "file"
        entries.append(entry)
        infos[str(rel)] = entry
    return entries, infos


def write_summary(evidence: Path, index: dict[str, Any]) -> None:
    pw = index["playwright"]
    stats = pw.get("stats") or {}
    lines = [
        "# dss-e2e evidence summary",
        "",
        f"Generated {index['generated_at']} by `e2e/scripts/collect_evidence.py` from `reports/index.json`. "
        "Every figure below is derived from the files on disk; nothing is hand-written.",
        "",
        f"- git: `{index['git']['sha']}` (dirty e2e inputs: {index['git']['dirty_e2e']})",
        f"- evidence dir: `{index['evidence_dir']}`",
        f"- files indexed: {len(index['files'])}",
        "",
        "## Playwright",
        "",
    ]
    if pw.get("report_present"):
        lines.append(
            f"expected {stats.get('expected', '?')} · unexpected {stats.get('unexpected', '?')} · "
            f"flaky {stats.get('flaky', '?')} · skipped {stats.get('skipped', '?')}"
        )
        lines += ["", "| spec | test | status | ms |", "|---|---|---|---|"]
        for t in pw["tests"]:
            lines.append(f"| `{t['file']}` | {t['title']} | {t['status']} | {t['duration_ms']} |")
    else:
        lines.append("No `reports/playwright.json` found: the specs have not been run.")
    lines += [
        "",
        "## Deliverables (Definition of Done item 5)",
        "",
        "| # | document | video | screenshots | PDF | pdf logs | pages | pytest | spec | complete |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]

    def mark(ok: bool) -> str:
        return "yes" if ok else "**NO**"

    for d in index["deliverables"]:
        c = d["checks"]
        logs_ok = all(c[f"log_{t}"]["ok"] for t in ("pdfinfo", "pdftotext", "pdffonts", "api"))
        lines.append(
            f"| {d['number']} | {d['slug']} | {mark(c['video']['ok'])} | "
            f"{mark(c['screenshots']['ok'])} ({c['screenshots']['count']}) | "
            f"{mark(c['pdf']['ok'])} | {mark(logs_ok)} | "
            f"{mark(c['pdf_pages']['ok'])} ({c['pdf_pages']['count']}) | "
            f"{mark(c['pytest_log']['ok'])} | {mark(c['playwright_spec']['ok'])} | {mark(d['complete'])} |"
        )
    eg = index["egress"]
    lines += ["", "## Backend network egress (Definition of Done item 12)", ""]
    if eg.get("taken"):
        lines.append(
            f"- verdict: **{'OK' if eg['ok'] else 'FAIL'}**; "
            f"outbound peers observed: {eg.get('peers') or 'none'}; "
            f"violations: {eg.get('violations') or 'none'}"
        )
        lines.append("- raw decode: `logs/80-no-egress-proc-net-tcp.txt`")
    else:
        lines.append(f"- not taken: {eg.get('reason', 'unknown')}")
    build = evidence / "logs" / "01-build-summary.txt"
    if build.is_file():
        lines += [
            "",
            "## Images (from logs/01-build-summary.txt)",
            "",
            "```",
            build.read_text(encoding="utf-8").rstrip(),
            "```",
        ]
    lines += ["", f"## Overall: **{'PASS' if index['ok'] else 'NOT COMPLETE'}**", ""]
    (evidence / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--git-sha", default="unknown")
    parser.add_argument("--git-dirty", default="unknown")
    parser.add_argument("--strict", action="store_true", help="exit 1 unless everything is complete")
    parser.add_argument("--skip-egress", action="store_true")
    parser.add_argument(
        "--proc-net-dir", type=Path, help="test hook: read tcp/tcp6 files from here instead of docker exec"
    )
    parser.add_argument("--pg-ip", action="append", default=[], help="test hook: postgres IP (repeatable)")
    parser.add_argument("--mongo-ip", action="append", default=[], help="test hook: mongo IP (repeatable)")
    args = parser.parse_args()

    evidence: Path = args.evidence_dir.resolve()
    for sub in ("videos", "screenshots", "downloads", "pdf-pages", "logs", "reports"):
        (evidence / sub).mkdir(parents=True, exist_ok=True)

    playwright = harvest_playwright(evidence)
    files, infos = build_file_index(evidence)
    egress: dict[str, Any] = {"taken": False, "ok": False, "reason": "skipped (--skip-egress)"}
    if not args.skip_egress:
        egress = egress_proof(evidence, args.proc_net_dir, args.pg_ip, args.mongo_ip)
        files, infos = build_file_index(evidence)  # pick up the new log

    deliverables = [deliverable_report(evidence, n, s, playwright["tests"], infos) for n, s in DELIVERABLES]
    failed_tests = [t for t in playwright["tests"] if t["status"] not in ("passed", "skipped")]
    ok = all(d["complete"] for d in deliverables) and not failed_tests and bool(egress.get("ok"))
    index = {
        "schema": 1,
        "generated_at": now_iso(),
        "git": {"sha": args.git_sha, "dirty_e2e": args.git_dirty},
        "evidence_dir": str(evidence),
        "ok": ok,
        "playwright": playwright,
        "deliverables": deliverables,
        "egress": egress,
        "files": files,
    }
    (evidence / "reports" / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    write_summary(evidence, index)

    for d in deliverables:
        missing = [name for name, c in d["checks"].items() if not c["ok"]]
        print(
            f"{'COMPLETE ' if d['complete'] else 'INCOMPLETE'} {d['number']}-{d['slug']}"
            + (f"  missing: {', '.join(missing)}" if missing else "")
        )
    print(
        f"playwright tests: {len(playwright['tests'])} (failed: {len(failed_tests)}); egress: "
        f"{'ok' if egress.get('ok') else ('FAIL' if egress.get('taken') else 'not taken')}; files indexed: {len(files)}"
    )
    print(f"wrote {evidence / 'reports' / 'index.json'} and {evidence / 'SUMMARY.md'}")
    if args.strict and not ok:
        print("STRICT: evidence is not complete", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
