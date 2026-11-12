"""Gate CLI: judge a run directory, freeze its oracle, redact it, write and verify its checksums.

    python3 -m harness.gate judge   <run> [--ledger e2e/cbom/known-fail.yaml]    exit 0 pass, 1 gate fails, 2 error
    python3 -m harness.gate freeze-oracle <run>                                    O-5, before "Start scan"
    python3 -m harness.gate redact  <run> [--secrets-file F]                       scrub har/ api/ ui/ steps/ logs/
    python3 -m harness.gate sums    <run>                                          SHA256SUMS; prints its sha256
    python3 -m harness.gate verify  <run>                                          re-hash; exit 1 on any change
    python3 -m harness.gate compare <run_a> <run_b>                                same-SHA verdicts identical (CB-05 F)

Run from ``e2e/cbom`` (``cd e2e/cbom && python3 -m harness.gate ...``) or with ``PYTHONPATH=e2e/cbom``.

What ``judge`` reads (all optional; a missing input becomes NOT-RUN checks, which the ledger must list):
  steps/<G>/step.json   checks the flow and the runner recorded (G0..G10, G12..G14, G17)
  api/ db/ exports/ ui/ the four views (G11 join), oracle/ lab/ (G11 oracle and derived), logs/ har/ (G16),
  oracle/canaries.json (G15)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import SCHEMA_REPORT, canary, compare, derived, join, ledger, logs, manifest, oracle, redact, timing
from .checks import Check, Checks
from .rundir import iso, read_json, run_steps, utc_now, write_json, write_text

GATES = [f"G{i}" for i in range(18)] + ["G5b", "G13b"]
# the waves of DEVILS-ADVOCATE §4.5 (a deferred lab part may name one)
WAVES = ["W-NET", "W-HOST", "W-KEY", "W-STATE", "W-OUT", "W-INT", "W-D1", "W-CLOUD", "W-UPGRADE", "W-SKEW", "W-SCALE"]
# the steps whose checks come from the flow / runner (step.json); G11 also gets the join, oracle and derived checks
# judged here from the evidence, G15 and G16 only those
FLOW_STEPS = ["G0", "G1", "G2", "G3", "G4", "G5", "G5b", "G6", "G7", "G8", "G9", "G10", "G11", "G12", "G13", "G13b", "G14",
              "G17"]
DEFAULT_LEDGER = Path(__file__).resolve().parents[1] / "known-fail.yaml"


def load_step_checks(run: Path, checks: Checks) -> dict[str, Any]:
    info: dict[str, Any] = {}
    for step in FLOW_STEPS:
        doc = read_json(Path(run) / "steps" / step / "step.json")
        if doc is None:
            checks.not_run(f"{step}/step", step, "flow", "step did not run (no steps/%s/step.json)" % step,
                           {"step": step})
            continue
        info[step] = {k: doc.get(k) for k in ("status", "started", "ended", "seconds", "note")}
        if doc.get("status") == "not-run":
            checks.not_run(f"{step}/step", step, "flow", doc.get("note") or "step not run", {"step": step})
        for raw in doc.get("checks") or []:
            checks.add(Check(id=raw["id"], gate=raw.get("gate", step), kind=raw.get("kind", "flow"),
                             verdict=raw["verdict"], subject=raw.get("subject") or {}, reason=raw.get("reason", ""),
                             expected=raw.get("expected"), observed=raw.get("observed"),
                             evidence=raw.get("evidence") or []))
    return info


def deferred_checks(run: Path, checks: Checks) -> list[str]:
    """INTERFACES v2.1: every lab part the lab marks ``deferred`` (lab.json or oracle/run<k>.json) becomes a NOT-RUN
    check ``<gate>/deferred_<part>`` with the lab's reason, so the ledger must name it. A step that already recorded
    the same check (CB-05) keeps its own."""
    added = []
    docs = [read_json(Path(run) / "lab" / "lab.json")] + [read_json(p) for p in sorted((Path(run) / "oracle").glob("run*.json"))]
    for doc in docs:
        for part in (doc or {}).get("deferred") or []:
            for gate_name in part.get("gate") or []:
                cid = f"{gate_name}/deferred_{part.get('part')}"
                if checks.get(cid) is not None:
                    continue
                checks.not_run(cid, gate_name, "lab", str(part.get("reason") or "deferred by the lab"),
                               {"check": "deferred", "part": part.get("part"), "address": part.get("address"),
                                "issue_draft": part.get("issue_draft")})
                added.append(cid)
    return added


def judge(run: Path, ledger_path: Path = DEFAULT_LEDGER) -> tuple[bool, dict[str, Any]]:
    run = Path(run)
    checks = Checks()
    steps = load_step_checks(run, checks)
    deferred_checks(run, checks)
    same, why = manifest.oracle_unchanged(run)
    if (run / "oracle").is_dir() and any((run / "oracle").iterdir()):
        checks.verdict("G0/oracle-frozen", "G0", "oracle", same, "oracle-changed", {"check": "oracle_frozen"},
                       expected="sha256(oracle/*) == MANIFEST.oracle.sha256", observed=why)
    ks = run_steps(run) or ["1"]
    scope = (read_json(run / "flow-state.json") or {}).get("scope")
    details: dict[str, Any] = {}
    for k in ks:
        join.join(run, k, checks)
        views = join.load_views(run, k)
        pairs: dict[str, int] = {}
        oracle.match(run, k, checks, views["api"], views["export"], scope, pairs)
        details[f"derived-run{k}"] = derived.judge(run, k, checks, pairs, scope)
        details[f"timing-run{k}"] = timing.judge(run, k, checks)
    canary.judge(run, checks)
    man = read_json(run / manifest.MANIFEST, {}) or {}
    teams = [t for t in ((man.get("teams") or {}).values()) if t]
    details["logs"] = logs.judge(run, checks, teams)

    rows = ledger.load(ledger_path)  # LedgerError / OSError: main() exits 2 (an error, not a gate verdict)
    results, blocking = ledger.apply(rows, checks)
    passed = ledger.verdict(results, blocking)
    report = {
        "schema": SCHEMA_REPORT, "judged_at": iso(utc_now()), "run": run.name, "passed": passed,
        "counts": checks.by_verdict(), "steps": steps, "details": details,
        "ledger": [r.__dict__ for r in results],
        "blocking": [c.as_dict() for c in blocking][:500],
        "blocking_total": len(blocking),
        "by_gate": _by_gate(checks),
        "checks": [c.as_dict() for c in checks],
    }
    write_json(run / "report.json", report)
    write_text(run / "report.md", render_md(report))
    return passed, report


def _by_gate(checks: Checks) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for c in checks:
        out.setdefault(c.gate, {}).setdefault(c.verdict, 0)
        out[c.gate][c.verdict] += 1
    return dict(sorted(out.items(), key=lambda kv: (int("".join(ch for ch in kv[0][1:] if ch.isdigit()) or 0),
                                                    kv[0])))


def render_md(report: dict[str, Any]) -> str:
    lines = [f"# CBOM Tier-L gate: {report['run']}", "",
             f"**Verdict: {'PASS' if report['passed'] else 'FAIL'}** (judged {report['judged_at']})", "",
             "| Verdict | Checks |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in report["counts"].items()]
    lines += ["", "## By gate step", "", "| Step | PASS | FAIL | KNOWN-FAIL | NOT-RUN | NOT-JUDGED |",
              "|---|---|---|---|---|---|"]
    for gate, counts in report["by_gate"].items():
        lines.append(f"| {gate} | {counts.get('PASS', 0)} | {counts.get('FAIL', 0)} | {counts.get('KNOWN-FAIL', 0)} | "
                     f"{counts.get('NOT-RUN', 0)} | {counts.get('NOT-JUDGED', 0)} |")
    lines += ["", "## Ledger", "", "| Row | Status | Matched | Failing | Passing | Owner | Issue |",
              "|---|---|---|---|---|---|---|"]
    for r in report["ledger"]:
        lines.append(f"| {r['row']} | {r['status']} | {r['matched']} | {r['failing']} | {r['passing']} | "
                     f"{r['owner']} | {r['issue']} |")
    lines += ["", f"## Blocking checks ({report['blocking_total']})", ""]
    for c in report["blocking"][:200]:
        lines.append(f"* `{c['id']}` {c['verdict']} {c.get('reason', '')}: expected `{_short(c.get('expected'))}`, "
                     f"observed `{_short(c.get('observed'))}`")
    return "\n".join(lines) + "\n"


def _short(value: Any, n: int = 160) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return (text[: n - 1] + "…") if len(text) > n else text


def redact_run(run: Path, known: list[str]) -> list[str]:
    """Scrub every evidence file the flow wrote (har/ api/ ui/ steps/ logs/); exports/ and db/ are only scanned (their
    bytes are evidence: an export's sha256 must equal the HAR body's). Return residual-secret problems (kinds and
    paths only, never values)."""
    run = Path(run)
    problems = []
    for sub in ("har", "api", "ui", "steps", "logs", "exports", "db"):
        rewrite = sub not in ("exports", "db")
        for path in sorted((run / sub).rglob("*")):
            if path.is_file() and path.suffix == ".zip":
                # Playwright traces carry typed values, headers and bodies: scrubbed member by member when the
                # evidence may be rewritten, and always scanned (m6: a skipped zip made G17 a false PASS)
                problems += redact_zip(path, run, known, rewrite)
                continue
            if not path.is_file() or path.suffix in (".png", ".webm", ".jpg"):
                continue
            original = path.read_text(encoding="utf-8", errors="replace")
            text = original
            if rewrite:
                if path.suffix == ".har":
                    text = json.dumps(redact.scrub_har(json.loads(text)), indent=1)
                elif path.suffix == ".json":
                    try:
                        text = json.dumps(redact.scrub_obj(json.loads(text)), indent=2, sort_keys=True)
                    except ValueError:
                        text = redact.scrub_text(text)
                else:
                    text = redact.scrub_text(text)
                for k, value in enumerate(known):
                    if value and len(value) >= 8:
                        text = text.replace(value, redact.mark(f"known-{k}", value))
                if text != original:
                    write_text(path, text)
            left = redact.residual_secrets(text, known)
            problems += [f"{path.relative_to(run).as_posix()}: {kind}" for kind in left]
    return problems


_BINARY = (".png", ".jpg", ".jpeg", ".webp", ".webm", ".woff", ".woff2", ".ttf", ".ico", ".gif")


def redact_zip(path: Path, run: Path, known: list[str], rewrite: bool = True) -> list[str]:
    """Playwright traces (steps/<G>/trace.zip) hold the typed values of fill actions and the request/response bodies
    and headers (tokens, the database password the customer typed): rewrite every text member through the same scrub
    as the other evidence (CB-05, found by the G15 canary grep on a full run). Image members are kept as they are.
    With ``rewrite`` False the members are only scanned."""
    import zipfile
    problems = []
    try:
        with zipfile.ZipFile(path) as zin:
            members = [(info, zin.read(info.filename)) for info in zin.infolist()]
    except (zipfile.BadZipFile, OSError):
        # a trace cut short (the flow was stopped while writing it): unreadable, so it is removed when it holds a
        # known secret (and the evidence may be rewritten), and reported either way
        raw = path.read_bytes()
        leaked = any(v and len(v) >= 8 and v.encode() in raw for v in known)
        if leaked and rewrite:
            path.unlink()
        what = ("removed: held a known secret" if rewrite else "held a known secret") if leaked else "kept"
        return [f"{path.relative_to(run).as_posix()}: unreadable zip ({what})"]
    changed = False
    out = []
    for info, data in members:
        if info.filename.lower().endswith(_BINARY):
            out.append((info, data))
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            out.append((info, data))
            continue
        new = text
        if rewrite:
            new = redact.scrub_text(text)
            for k, value in enumerate(known):
                if value and len(value) >= 8:
                    new = new.replace(value, redact.mark(f"known-{k}", value))
        if new != text:
            changed = True
        out.append((info, new.encode("utf-8")))
        left = redact.residual_secrets(new, known)
        problems += [f"{path.relative_to(run).as_posix()}!{info.filename}: {kind}" for kind in left]
    if changed:
        tmp = path.with_suffix(".zip.tmp")
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            for info, data in out:
                zout.writestr(info, data)
        tmp.replace(path)
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="harness.gate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    j = sub.add_parser("judge")
    j.add_argument("run", type=Path)
    j.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    for name in ("freeze-oracle", "sums", "verify"):
        sub.add_parser(name).add_argument("run", type=Path)
    c = sub.add_parser("compare")
    c.add_argument("run", type=Path)
    c.add_argument("other", type=Path)
    r = sub.add_parser("redact")
    r.add_argument("run", type=Path)
    r.add_argument("--secrets-file", type=Path, help="JSON list of raw secret values the run used (deleted after)")
    args = ap.parse_args(argv)
    if not args.run.is_dir():
        print(f"no such run directory: {args.run}", file=sys.stderr)
        return 2
    if args.cmd == "compare":
        if not args.other.is_dir():
            print(f"no such run directory: {args.other}", file=sys.stderr)
            return 2
        result = compare.compare(args.run, args.other)
        print(json.dumps(result, indent=1))
        return 0 if result["identical"] else 1
    if args.cmd == "judge":
        try:
            passed, report = judge(args.run, args.ledger)
        except (OSError, ledger.LedgerError) as exc:
            print(f"ledger: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({"passed": passed, "counts": report["counts"], "blocking": report["blocking_total"],
                          "ledger": {r["row"]: r["status"] for r in report["ledger"]}}, indent=1))
        return 0 if passed else 1
    if args.cmd == "freeze-oracle":
        print(json.dumps(manifest.freeze_oracle(args.run)))
        return 0
    if args.cmd == "sums":
        print(manifest.write_sums(args.run))
        return 0
    if args.cmd == "verify":
        problems = manifest.verify(args.run)
        print("\n".join(problems) if problems else "SHA256SUMS: OK")
        return 1 if problems else 0
    if args.cmd == "redact":
        known: list[str] = []
        if args.secrets_file and args.secrets_file.is_file():
            known = [str(v) for v in json.loads(args.secrets_file.read_text(encoding="utf-8")) if v]
        problems = redact_run(args.run, known)
        print("\n".join(problems) if problems else "redaction: no residual secrets")
        return 1 if problems else 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
