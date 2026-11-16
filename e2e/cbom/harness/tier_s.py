"""CB-37 Tier S acceptance. Judge a recorded staging acceptance and write the sign-off.

Preflight (one build SHA, alembic current at the head, cloud worker + scheduler + dispatcher
started, a canary IdP finished within 5 minutes, a canary schedule that fired in its slot) plus
the Tier-L steps G0–G17 with the Tier S differences: no allowed command diff, the published image
digest, no credit top-up, G13 receivers dropped unless a public receiver was approved, and DB/log
rows either collected (OA-7) or inherited from Tier L at the same SHA.

This module does not reach staging, a browser, or a deploy. A missing preflight is NOT-RUN and
does not pass. The sign-off is ``sign-off/staging-acceptance-<date>.md``.

    python3 -m harness.tier_s plan --root <dir> --sha <40-hex>
    python3 -m harness.tier_s accept <run> [--date YYYY-MM-DD]
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any

from . import SCHEMA_TIER_S
from .checks import PASS, NOT_RUN, Checks
from .gate import FLOW_STEPS
from .preflight import same_sha
from .redact import scrub_text
from .rundir import RUN_NAME, create, iso, utc_now, write_json, write_text

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
CANARY_LIMIT_S = 300
DROPPED_STEPS = ("G13", "G13b")
WORKERS = ("cloud_worker", "scheduler", "dispatcher")
BUILD_KEYS = ("health", "header", "frontend", "node")
PREFLIGHT_KEYS = (
    "sha", "builds", "alembic_current", "alembic_head", "workers", "canary_idp", "canary_schedule",
    "node_image", "allowed_diff", "topup", "oa7", "g13_public_receiver_approved", "inherited_from_l_sha",
)


def plan(root: Path, sha: str, when=None) -> Path:
    """Create an empty ``S-<sha12>-<utc>`` directory and the acceptance contract. No network calls."""
    sha = _full_sha(sha)
    run = create(Path(root), sha, when, tier="S")
    write_json(run / "tier-s" / "contract.json", {
        "schema": SCHEMA_TIER_S, "track": "CB-37", "tier": "S", "sha": sha,
        "preflight": list(PREFLIGHT_KEYS), "steps": list(FLOW_STEPS),
        "dropped_unless_public_receiver": list(DROPPED_STEPS), "canary_idp_max_s": CANARY_LIMIT_S,
        "evidence": ["tier-s/preflight.json", "steps/<G>/step.json"],
    })
    return run


def accept(run: Path, date: str | None = None) -> tuple[bool, dict[str, Any]]:
    """Write ``tier-s/report.json`` and the sign-off. Passes only when every required check is PASS."""
    run = Path(run)
    if not run.is_dir():
        raise FileNotFoundError(run)
    day = _date(date)
    checks = Checks()
    doc, err = _load(run / "tier-s" / "preflight.json")
    note = "Preflight was not recorded."
    sha: str | None = None
    if err == "missing" or doc is None and err:
        if err == "missing":
            checks.not_run("S/preflight", "S", "tier-s", "tier-s/preflight.json was not recorded",
                           {"check": "preflight"}, evidence=["tier-s/preflight.json"])
        else:
            checks.fail("S/preflight", "S", "tier-s", err or "unreadable", {"check": "preflight"},
                        evidence=["tier-s/preflight.json"])
    else:
        sha, note = _preflight(checks, run, doc)
    passed = _passed(checks)
    rel = f"sign-off/staging-acceptance-{day}.md"
    report: dict[str, Any] = {
        "schema": SCHEMA_TIER_S, "track": "CB-37", "judged_at": iso(utc_now()), "run": run.name,
        "sha": sha, "date": day, "passed": passed, "evidence_note": note, "signoff": rel,
        "counts": checks.by_verdict(), "checks": [c.as_dict() for c in checks],
    }
    write_text(run / rel, render_signoff(report))
    write_json(run / "tier-s" / "report.json", report)
    return passed, report


def render_signoff(report: dict[str, Any]) -> str:
    """The acceptance note. Bearer tokens and registration tokens in a cell are scrubbed."""
    lines = [
        f"# CBOM Tier S acceptance {report.get('date')}",
        "",
        f"**Verdict: {'PASS' if report.get('passed') else 'FAIL'}**",
        "",
        f"Run `{report.get('run')}` at commit `{report.get('sha') or 'unknown'}`.",
        "",
        str(report.get("evidence_note") or ""),
        "",
        "| Check | Verdict | Detail |",
        "|---|---|---|",
    ]
    for check in report.get("checks") or []:
        detail = check.get("reason") or ""
        observed = check.get("observed")
        if observed not in (None, "", [], {}):
            detail = f"{detail} {_cell(observed)}".strip()
        lines.append(f"| `{check.get('id')}` | {check.get('verdict')} | {_cell(detail)} |")
    lines.append("")
    return scrub_text("\n".join(lines) + "\n")


def _full_sha(sha: str) -> str:
    sha = (sha or "").strip().lower()
    if not FULL_SHA.fullmatch(sha):
        raise ValueError("sha must be a 40-character commit")
    return sha


def _date(value: str | None) -> str:
    if value is None:
        return utc_now().date().isoformat()
    try:
        return dt.date.fromisoformat(value).isoformat()
    except ValueError:
        raise ValueError("date must be YYYY-MM-DD") from None


def _load(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.is_file():
        return None, "missing"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, "unreadable"
    if not isinstance(data, dict):
        return None, "not a JSON object"
    return data, None


def _passed(checks: Checks) -> bool:
    items = list(checks)
    if not any(c.verdict == PASS for c in items):
        return False
    for check in items:
        if check.verdict == PASS:
            continue
        if check.verdict == NOT_RUN and check.subject.get("accepted_skip"):
            continue
        return False
    return True


def _cell(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str, sort_keys=True)
    text = text.replace("\n", " ").replace("|", "/")
    return text if len(text) <= 160 else text[:159] + "…"


def _preflight(checks: Checks, run: Path, doc: dict[str, Any]) -> tuple[str | None, str]:
    evidence = ["tier-s/preflight.json"]
    sha = _sha(checks, run, doc, evidence)
    if sha is not None:
        _builds(checks, sha, doc.get("builds"), evidence)
    _alembic(checks, doc, evidence)
    _workers(checks, doc.get("workers"), evidence)
    _canary(checks, doc, evidence)
    _node_image(checks, doc.get("node_image"), evidence)
    _flag(checks, doc, "allowed_diff", False, "S/allowed-diff", "an allowed command diff is not accepted on Tier S",
          evidence)
    _flag(checks, doc, "topup", False, "S/topup", "the acceptance account is not topped up", evidence)
    note = _evidence_rows(checks, run, doc, sha, evidence)
    _receivers(checks, run, doc, evidence)
    for step in FLOW_STEPS:
        if step in DROPPED_STEPS:
            continue
        _step(checks, run, step)
    return sha, note


def _sha(checks: Checks, run: Path, doc: dict[str, Any], evidence: list[str]) -> str | None:
    raw = doc.get("sha")
    sha = raw.strip().lower() if isinstance(raw, str) else ""
    named = RUN_NAME.match(run.name)
    if not FULL_SHA.fullmatch(sha):
        checks.fail("S/sha", "S", "tier-s", "sha is not a 40-character commit", {"check": "sha"}, expected=40,
                    observed=raw, evidence=evidence)
        return None
    if named and named.group("tier") != "S":
        checks.fail("S/sha", "S", "tier-s", "run directory is not a Tier S acceptance", {"check": "sha"},
                    expected="S", observed=named.group("tier"), evidence=evidence)
        return None
    if named and not same_sha(named.group("sha"), sha):
        checks.fail("S/sha", "S", "tier-s", "preflight sha does not match the run directory", {"check": "sha"},
                    expected=sha, observed=named.group("sha"), evidence=evidence)
        return None
    checks.ok("S/sha", "S", "tier-s", {"check": "sha"}, expected=sha, observed=sha, evidence=evidence)
    return sha


def _builds(checks: Checks, sha: str, builds: Any, evidence: list[str]) -> None:
    if not isinstance(builds, dict):
        checks.fail("S/build", "S", "tier-s", "builds were not recorded", {"check": "build"}, evidence=evidence)
        return
    for key in BUILD_KEYS:
        value = builds.get(key)
        ok = isinstance(value, str) and same_sha(value, sha)
        checks.verdict(f"S/build/{key}", "S", "tier-s", ok, "build", {"check": key, "part": "build"},
                       expected=sha, observed=value, evidence=evidence)


def _alembic(checks: Checks, doc: dict[str, Any], evidence: list[str]) -> None:
    current, head = doc.get("alembic_current"), doc.get("alembic_head")
    ok = isinstance(current, str) and isinstance(head, str) and current != "" and current == head
    checks.verdict("S/alembic", "S", "tier-s", ok, "alembic", {"check": "alembic"}, expected=head, observed=current,
                   evidence=evidence)


def _workers(checks: Checks, workers: Any, evidence: list[str]) -> None:
    if not isinstance(workers, dict):
        checks.fail("S/workers", "S", "tier-s", "workers were not recorded", {"check": "workers"}, evidence=evidence)
        return
    for name in WORKERS:
        checks.verdict(f"S/worker/{name}", "S", "tier-s", workers.get(name) is True, "not started",
                       {"check": name, "part": "workers"}, expected=True, observed=workers.get(name),
                       evidence=evidence)


def _canary(checks: Checks, doc: dict[str, Any], evidence: list[str]) -> None:
    idp = doc.get("canary_idp")
    if not isinstance(idp, dict):
        checks.fail("S/canary/idp", "S", "tier-s", "canary IdP was not recorded", {"check": "canary_idp"},
                    evidence=evidence)
    else:
        seconds = idp.get("seconds")
        number = float(seconds) if type(seconds) in (int, float) else None
        on_time = number is not None and 0 <= number <= CANARY_LIMIT_S
        checks.verdict("S/canary/idp", "S", "tier-s", idp.get("ran") is True and on_time,
                       "canary IdP did not finish within 5 minutes", {"check": "canary_idp"},
                       expected={"ran": True, "seconds": f"<= {CANARY_LIMIT_S}"}, observed=idp, evidence=evidence)
    sched = doc.get("canary_schedule")
    if not isinstance(sched, dict):
        checks.fail("S/canary/schedule", "S", "tier-s", "canary schedule was not recorded",
                    {"check": "canary_schedule"}, evidence=evidence)
        return
    checks.verdict("S/canary/schedule", "S", "tier-s", sched.get("fired") is True and sched.get("in_slot") is True,
                   "canary schedule did not fire in its slot", {"check": "canary_schedule"},
                   expected={"fired": True, "in_slot": True}, observed=sched, evidence=evidence)


def _node_image(checks: Checks, image: Any, evidence: list[str]) -> None:
    digest = image.get("digest") if isinstance(image, dict) else None
    published = image.get("published") if isinstance(image, dict) else None
    ok = isinstance(digest, str) and DIGEST.fullmatch(digest) is not None and published is True
    checks.verdict("S/node-image", "S", "tier-s", ok, "image is not the published digest", {"check": "node_image"},
                   expected="sha256:<64 hex> published", observed=image, evidence=evidence)


def _flag(checks: Checks, doc: dict[str, Any], key: str, want: bool, cid: str, reason: str,
          evidence: list[str]) -> None:
    if key not in doc:
        checks.fail(cid, "S", "tier-s", f"{key} was not recorded", {"check": key}, expected=want, evidence=evidence)
        return
    checks.verdict(cid, "S", "tier-s", doc[key] is want, reason, {"check": key}, expected=want, observed=doc[key],
                   evidence=evidence)


def _evidence_rows(checks: Checks, run: Path, doc: dict[str, Any], sha: str | None,
                   evidence: list[str]) -> str:
    oa7 = doc.get("oa7")
    if oa7 is True:
        for name in ("db", "logs"):
            ok = _has_file(run / name)
            checks.verdict(f"S/evidence/{name}", "S", "tier-s", ok, "not collected", {"check": name, "part": "oa7"},
                           expected=f"{name}/ has a file", observed=ok, evidence=[name])
        return "DB and log rows were collected for this acceptance."
    if oa7 is False:
        inherited = doc.get("inherited_from_l_sha")
        ok = sha is not None and isinstance(inherited, str) and same_sha(inherited, sha)
        checks.verdict("S/evidence/inherited", "S", "tier-s", ok, "not the same SHA",
                       {"check": "inherited_from_l_sha"}, expected=sha, observed=inherited, evidence=evidence)
        if ok and sha is not None:
            return f"DB and log rows are inherited from Tier L at the same SHA {sha}."
        return "DB and log rows were not inherited from Tier L at the same SHA."
    checks.fail("S/oa7", "S", "tier-s", "oa7 was not recorded", {"check": "oa7"}, evidence=evidence)
    return "OA-7 was not recorded, so DB and log rows were not judged."


def _has_file(path: Path) -> bool:
    return path.is_dir() and any(p.is_file() for p in path.rglob("*"))


def _receivers(checks: Checks, run: Path, doc: dict[str, Any], evidence: list[str]) -> None:
    approved = doc.get("g13_public_receiver_approved")
    if approved is True:
        for step in DROPPED_STEPS:
            _step(checks, run, step)
        return
    if approved is False:
        for step in DROPPED_STEPS:
            checks.not_run(f"S/step/{step}", "S", "tier-s",
                           "receivers dropped unless a public receiver is approved",
                           {"check": "g13", "step": step, "accepted_skip": True}, evidence=evidence)
        return
    checks.fail("S/g13", "S", "tier-s", "g13_public_receiver_approved was not recorded", {"check": "g13"},
                evidence=evidence)


def _step(checks: Checks, run: Path, step: str) -> None:
    rel = f"steps/{step}/step.json"
    doc, err = _load(run / "steps" / step / "step.json")
    cid = f"S/step/{step}"
    subject = {"check": "step", "step": step}
    if err == "missing":
        checks.not_run(cid, "S", "tier-s", f"{rel} was not recorded", subject, evidence=[rel])
        return
    if err or doc is None:
        checks.fail(cid, "S", "tier-s", err or "unreadable", subject, evidence=[rel])
        return
    recorded = doc.get("checks")
    rows = recorded if isinstance(recorded, list) else []
    bad: list[Any] = []
    for row in rows:
        if isinstance(row, dict) and row.get("verdict") == PASS:
            continue
        bad.append(row.get("id", row.get("verdict")) if isinstance(row, dict) else row)
    ok = doc.get("status") == "ran" and bool(rows) and not bad
    checks.verdict(cid, "S", "tier-s", ok, "step did not pass", subject,
                   expected="status ran and every check PASS",
                   observed={"status": doc.get("status"), "not_pass": bad}, evidence=[rel])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m harness.tier_s", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    plan_p = sub.add_parser("plan", help="create an empty Tier S acceptance directory")
    plan_p.add_argument("--root", type=Path, required=True)
    plan_p.add_argument("--sha", required=True)
    acc = sub.add_parser("accept", help="judge a recorded acceptance and write the sign-off")
    acc.add_argument("run", type=Path)
    acc.add_argument("--date", default=None)
    args = parser.parse_args(argv)
    try:
        if args.cmd == "plan":
            print(plan(args.root, args.sha))
            return 0
        ok, report = accept(args.run, args.date)
    except FileNotFoundError:
        print(f"no run directory {args.run}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"passed": ok, "signoff": report.get("signoff"), "counts": report["counts"]}))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
