"""CB-36 Tier V replica runs. Judge evidence a release candidate already recorded.

The replica is a self-destructing sandbox (at most 180 minutes, ``Project=DevSecShield``, shutdown
behavior ``terminate``) plus four rows: Windows, RDS Postgres, an internal ALB, and a FIPS Rocky 9
host. Headless browser evidence is recorded, not launched. A download over SSM is reassembled from
chunks because ``StandardOutputContent`` holds 24,000 characters, then checked with sha256.

This module does not call AWS, a browser, or a deploy. A missing evidence file is NOT-RUN. A row
with no oracle value is NOT-JUDGED. Neither verdict passes.

    python3 -m harness.tier_v plan --root <dir> --sha <40-hex>
    python3 -m harness.tier_v judge <run>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from . import SCHEMA_TIER_V
from .checks import PASS, Checks
from .preflight import same_sha
from .rundir import RUN_NAME, create, iso, parse_ts, utc_now, write_json

MAX_LIFETIME_MIN = 180
SSM_INLINE_CAP = 24000  # characters; SSM GetCommandInvocation StandardOutputContent
MAX_SSM_CHUNKS = 10000
MAX_SSM_CHARS = 32 * 1024 * 1024
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
TARGETS = ("windows", "rds", "alb", "fips")
REQUIRED_TEARDOWN = frozenset({"ec2", "rds", "alb"})
WINDOWS_REQUIRED: dict[str, Any] = {
    "least_privilege_user": True,
    "schannel_tls10_server": True,
    "rsa1024_sha1": True,
    "rdp_nla": False,
    "ecc_p256": True,
    "cert_cng": True,
    "cert_capi": True,
    "cert_tpm": True,
    "lockout_threshold": 3,
}


class _Missing:
    def __repr__(self) -> str:
        return "<missing>"


MISSING = _Missing()


def plan(root: Path, sha: str, when=None) -> Path:
    """Create an empty ``V-<sha12>-<utc>`` directory and the evidence contract. No cloud calls."""
    sha = _full_sha(sha)
    run = create(Path(root), sha, when, tier="V")
    write_json(run / "tier-v" / "contract.json", {
        "schema": SCHEMA_TIER_V, "track": "CB-36", "tier": "V", "sha": sha,
        "max_lifetime_min": MAX_LIFETIME_MIN, "ssm_inline_cap": SSM_INLINE_CAP,
        "targets": list(TARGETS), "windows": WINDOWS_REQUIRED, "lockout_counter": "< 3",
        "rds_engine": "postgres", "alb_scheme": "internal",
        "fips": {"name_contains": "Rocky", "version_major": "9", "fips_enabled": 1},
        "teardown_checked": sorted(REQUIRED_TEARDOWN),
        "evidence": [
            "tier-v/sandbox.json", "tier-v/playwright.json", "tier-v/teardown.json",
            "tier-v/targets/windows.json", "tier-v/targets/rds.json", "tier-v/targets/alb.json",
            "tier-v/targets/fips.json", "tier-v/ssm/<name>.json",
        ],
    })
    return run


def reassemble_ssm(payload: dict[str, Any]) -> tuple[bytes | None, str]:
    """Join SSM output chunks in index order and check sha256. ``("", reason)``-style: bytes or None.

    Each chunk is one ``StandardOutputContent`` body. The digest is sha256 of the UTF-8 bytes of the
    joined text. String chunks are already in order. Object chunks (``index`` + ``text``) may arrive
    out of order; a gap, a duplicate, or a mix of the two shapes fails.
    """
    chunks = payload.get("chunks")
    digest = str(payload.get("sha256") or "").strip().lower()
    if not isinstance(chunks, list) or not chunks:
        return None, "no chunks"
    if len(chunks) > MAX_SSM_CHUNKS:
        return None, f"more than {MAX_SSM_CHUNKS} chunks"
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        return None, "sha256 is not 64 hex characters"
    shaped = [isinstance(c, dict) for c in chunks]
    if any(shaped) and not all(shaped):
        return None, "chunks mix strings and index objects"
    rows: list[tuple[int, str]] = []
    for position, chunk in enumerate(chunks):
        if isinstance(chunk, str):
            index, text = position, chunk
        elif isinstance(chunk, dict) and isinstance(chunk.get("text"), str) and type(chunk.get("index")) is int:
            index, text = chunk["index"], chunk["text"]
        else:
            return None, f"chunk {position} is not text"
        if len(text) > SSM_INLINE_CAP:
            return None, (f"chunk {index} is {len(text)} characters; StandardOutputContent holds "
                          f"{SSM_INLINE_CAP}")
        if text == "":
            return None, f"chunk {index} is empty"
        rows.append((index, text))
    if sorted(i for i, _ in rows) != list(range(len(rows))):
        return None, "chunk indexes are not 0..n-1"
    if sum(len(text) for _, text in rows) > MAX_SSM_CHARS:
        return None, f"download is larger than {MAX_SSM_CHARS} characters"
    body = "".join(text for _, text in sorted(rows)).encode("utf-8")
    if hashlib.sha256(body).hexdigest() != digest:
        return None, "sha256 does not match the reassembled download"
    return body, ""


def judge(run: Path) -> tuple[bool, dict[str, Any]]:
    """Write ``tier-v/report.json``. Passes only when every check is PASS."""
    run = Path(run)
    if not run.is_dir():
        raise FileNotFoundError(run)
    checks = Checks()
    sha, problem = _resolve_sha(run)
    if problem:
        checks.fail("V/sha", "V", "tier-v", problem, {"check": "sha"}, expected="40-character commit",
                    observed=run.name, evidence=["tier-v/contract.json"])
    else:
        checks.ok("V/sha", "V", "tier-v", {"check": "sha"}, expected=sha, observed=sha,
                  evidence=["tier-v/contract.json"])
    _sandbox(checks, run, sha)
    _playwright(checks, run)
    _teardown(checks, run)
    for target in TARGETS:
        _target(checks, run, target)
    _ssm(checks, run)
    passed = _passed(checks)
    report = {
        "schema": SCHEMA_TIER_V, "track": "CB-36", "judged_at": iso(utc_now()), "run": run.name,
        "sha": sha, "passed": passed, "counts": checks.by_verdict(),
        "checks": [c.as_dict() for c in checks],
    }
    write_json(run / "tier-v" / "report.json", report)
    return passed, report


def _full_sha(sha: str) -> str:
    sha = (sha or "").strip().lower()
    if not FULL_SHA.fullmatch(sha):
        raise ValueError("sha must be a 40-character commit")
    return sha


def _resolve_sha(run: Path) -> tuple[str | None, str | None]:
    path = run / "tier-v" / "contract.json"
    data, err = _load(path)
    if err == "missing":
        return None, "no commit SHA recorded"
    if err or data is None:
        return None, "contract.json is unreadable"
    sha = data.get("sha")
    sha = sha.strip().lower() if isinstance(sha, str) else ""
    if not FULL_SHA.fullmatch(sha):
        return None, "contract sha is not a 40-character commit"
    named = RUN_NAME.match(run.name)
    if named and named.group("tier") != "V":
        return None, "run directory is not a Tier V run"
    if named and not same_sha(named.group("sha"), sha):
        return None, "contract sha does not match the run directory"
    return sha, None


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
    return bool(items) and all(c.verdict == PASS for c in items)


def _span_min(start: Any, end: Any) -> float | None:
    a, b = parse_ts(start), parse_ts(end)
    if a is None or b is None:
        return None
    return (b - a).total_seconds() / 60.0


def _sandbox(checks: Checks, run: Path, sha: str | None) -> None:
    path = run / "tier-v" / "sandbox.json"
    doc, err = _load(path)
    evidence = ["tier-v/sandbox.json"]
    if err == "missing":
        checks.not_run("V/sandbox", "V", "tier-v", "tier-v/sandbox.json was not recorded", {"check": "sandbox"},
                       evidence=evidence)
        return
    if err or doc is None:
        checks.fail("V/sandbox", "V", "tier-v", err or "unreadable", {"check": "sandbox"}, evidence=evidence)
        return
    if sha is not None:
        build = doc.get("build")
        ok = isinstance(build, str) and same_sha(build, sha)
        checks.verdict("V/build", "V", "tier-v", ok, "build", {"check": "build"}, expected=sha, observed=build,
                       evidence=evidence)
    tags = doc.get("tags") if isinstance(doc.get("tags"), dict) else {}
    checks.verdict("V/tags", "V", "tier-v", tags.get("Project") == "DevSecShield", "tag", {"check": "tags"},
                   expected="Project=DevSecShield", observed=tags.get("Project", MISSING), evidence=evidence)
    checks.verdict("V/shutdown", "V", "tier-v", doc.get("shutdown_behavior") == "terminate", "shutdown",
                   {"check": "shutdown"}, expected="terminate", observed=doc.get("shutdown_behavior", MISSING),
                   evidence=evidence)
    life = _span_min(doc.get("started"), doc.get("deadline"))
    gone = _span_min(doc.get("started"), doc.get("destroyed_at"))
    within = life is not None and gone is not None and 0 < gone <= life <= MAX_LIFETIME_MIN
    checks.verdict("V/lifetime", "V", "tier-v", within, "lifetime", {"check": "lifetime"},
                   expected=f"destroyed within the deadline and 0 < deadline <= {MAX_LIFETIME_MIN} min",
                   observed={"started": doc.get("started"), "deadline": doc.get("deadline"),
                             "destroyed_at": doc.get("destroyed_at"), "deadline_min": life, "ran_min": gone},
                   evidence=evidence)


def _playwright(checks: Checks, run: Path) -> None:
    doc, err = _load(run / "tier-v" / "playwright.json")
    evidence = ["tier-v/playwright.json"]
    if err == "missing":
        checks.not_run("V/playwright", "V", "tier-v", "tier-v/playwright.json was not recorded",
                       {"check": "playwright"}, evidence=evidence)
        return
    if err or doc is None:
        checks.fail("V/playwright", "V", "tier-v", err or "unreadable", {"check": "playwright"}, evidence=evidence)
        return
    checks.verdict("V/playwright", "V", "tier-v", doc.get("headless") is True, "headless", {"check": "playwright"},
                   expected=True, observed=doc.get("headless", MISSING), evidence=evidence)


def _teardown(checks: Checks, run: Path) -> None:
    doc, err = _load(run / "tier-v" / "teardown.json")
    evidence = ["tier-v/teardown.json"]
    if err == "missing":
        checks.not_run("V/teardown", "V", "tier-v", "tier-v/teardown.json was not recorded", {"check": "teardown"},
                       evidence=evidence)
        return
    if err or doc is None:
        checks.fail("V/teardown", "V", "tier-v", err or "unreadable", {"check": "teardown"}, evidence=evidence)
        return
    checked = doc.get("checked")
    remaining = doc.get("remaining")
    covered = isinstance(checked, list) and REQUIRED_TEARDOWN <= {str(x) for x in checked}
    clear = isinstance(remaining, list) and remaining == []
    checks.verdict("V/teardown", "V", "tier-v", covered and clear, "teardown", {"check": "teardown"},
                   expected={"checked": sorted(REQUIRED_TEARDOWN), "remaining": []},
                   observed={"checked": checked, "remaining": remaining}, evidence=evidence)


def _target(checks: Checks, run: Path, target: str) -> None:
    rel = f"tier-v/targets/{target}.json"
    doc, err = _load(run / rel)
    if err == "missing":
        checks.not_run(f"V/{target}", "V", "tier-v", f"{rel} was not recorded", {"check": target}, evidence=[rel])
        return
    if err or doc is None:
        checks.fail(f"V/{target}", "V", "tier-v", err or "unreadable", {"check": target}, evidence=[rel])
        return
    oracle, observed = doc.get("oracle"), doc.get("observed")
    if not isinstance(oracle, dict) or not isinstance(observed, dict):
        checks.fail(f"V/{target}", "V", "tier-v", "oracle and observed must be objects", {"check": target},
                    evidence=[rel])
        return
    if target == "windows":
        _windows(checks, oracle, observed, rel)
    elif target == "rds":
        _rds(checks, oracle, observed, rel)
    elif target == "alb":
        _alb(checks, oracle, observed, rel)
    else:
        _fips(checks, oracle, observed, rel)


def _fact(checks: Checks, key: str, oracle: dict, observed: dict, required: Any, rel: str) -> None:
    cid = f"V/windows/{key}"
    got_o = oracle.get(key, MISSING)
    got_p = observed.get(key, MISSING)
    subject = {"check": key, "part": "windows"}
    if got_o is MISSING:
        checks.not_judged(cid, "V", "tier-v", "no oracle value for this Tier V row", subject, expected=required,
                          evidence=[rel])
    elif got_o != required:
        checks.fail(cid, "V", "tier-v", "oracle", subject, expected=required, observed=got_o, evidence=[rel])
    elif got_p is MISSING:
        checks.fail(cid, "V", "tier-v", "missing", subject, expected=required, observed=MISSING, evidence=[rel])
    elif got_p != required:
        checks.fail(cid, "V", "tier-v", "mismatch", subject, expected=required, observed=got_p, evidence=[rel])
    else:
        checks.ok(cid, "V", "tier-v", subject, expected=required, observed=got_p, evidence=[rel])


def _windows(checks: Checks, oracle: dict, observed: dict, rel: str) -> None:
    for key, required in WINDOWS_REQUIRED.items():
        _fact(checks, key, oracle, observed, required, rel)
    cid = "V/windows/lockout_counter"
    subject = {"check": "lockout_counter", "part": "windows"}
    got_o = oracle.get("lockout_counter", MISSING)
    got_p = observed.get("lockout_counter", MISSING)
    if got_o is MISSING:
        checks.not_judged(cid, "V", "tier-v", "no oracle value for this Tier V row", subject, expected="< 3",
                          evidence=[rel])
    elif not _under_lockout(got_o):
        checks.fail(cid, "V", "tier-v", "oracle", subject, expected="< 3", observed=got_o, evidence=[rel])
    elif got_p != got_o:
        checks.fail(cid, "V", "tier-v", "mismatch", subject, expected=got_o, observed=got_p, evidence=[rel])
    else:
        checks.ok(cid, "V", "tier-v", subject, expected="< 3", observed=got_p, evidence=[rel])


def _under_lockout(value: Any) -> bool:
    return type(value) is int and 0 <= value < 3


def _pick(doc: dict, *keys: str) -> Any:
    for key in keys:
        if key in doc:
            return doc[key]
    return MISSING


def _differing(oracle: dict, observed: dict) -> list[str]:
    return [key for key, value in oracle.items() if observed.get(key, MISSING) != value]


def _rds(checks: Checks, oracle: dict, observed: dict, rel: str) -> None:
    describe = oracle.get("describe")
    got = observed.get("describe")
    subject = {"check": "describe", "part": "rds"}
    if not isinstance(describe, dict) or not describe:
        checks.not_judged("V/rds/describe", "V", "tier-v", "describe output is the oracle and was not recorded",
                          subject, evidence=[rel])
        return
    if not isinstance(got, dict):
        checks.fail("V/rds/describe", "V", "tier-v", "missing", subject, expected=describe, observed=MISSING,
                    evidence=[rel])
        return
    engine = str(_pick(describe, "engine", "Engine")).lower()
    diffs = _differing(describe, got)
    ok = engine == "postgres" and not diffs
    reason = "" if ok else ("not-postgres" if engine != "postgres" else "mismatch")
    checks.verdict("V/rds/describe", "V", "tier-v", ok, reason, subject,
                   expected={"engine": "postgres", "describe": describe},
                   observed={"engine": engine, "differing": diffs}, evidence=[rel])


def _alb(checks: Checks, oracle: dict, observed: dict, rel: str) -> None:
    describe = oracle.get("describe") if isinstance(oracle.get("describe"), dict) else None
    got = observed.get("describe") if isinstance(observed.get("describe"), dict) else None
    subject = {"check": "scheme", "part": "alb"}
    scheme = _pick(describe or {}, "scheme", "Scheme")
    seen = _pick(got or {}, "scheme", "Scheme")
    if describe is None or scheme is MISSING:
        checks.not_judged("V/alb/scheme", "V", "tier-v", "no oracle value for the load balancer scheme", subject,
                          expected="internal", evidence=[rel])
        return
    diffs = _differing(describe, got or {})
    ok = scheme == "internal" and seen == "internal" and not diffs
    checks.verdict("V/alb/scheme", "V", "tier-v", ok, "mismatch", subject, expected="internal",
                   observed={"scheme": seen, "differing": diffs}, evidence=[rel])


def _rocky9(doc: dict | None) -> bool | None:
    if not isinstance(doc, dict):
        return None
    name, version = _pick(doc, "name", "os"), _pick(doc, "version_id", "version")
    if name is MISSING or version is MISSING:
        return None
    return "rocky" in str(name).lower() and str(version).split(".")[0] == "9"


def _fips_bit(value: Any) -> int | None:
    if value in (1, True, "1"):
        return 1
    if value in (0, False, "0"):
        return 0
    return None


def _fips(checks: Checks, oracle: dict, observed: dict, rel: str) -> None:
    subject = {"check": "fips", "part": "fips"}
    o_host, p_host = _rocky9(oracle), _rocky9(observed)
    o_bit, p_bit = _fips_bit(oracle.get("fips_enabled", MISSING)), _fips_bit(observed.get("fips_enabled", MISSING))
    if o_host is None or o_bit is None:
        checks.not_judged("V/fips/host", "V", "tier-v", "no oracle value for the FIPS Rocky 9 host", subject,
                          expected={"os": "Rocky 9", "fips_enabled": 1}, evidence=[rel])
        return
    observed_ok = {"oracle_rocky9": o_host, "observed_rocky9": p_host, "oracle_fips": o_bit, "observed_fips": p_bit}
    if o_host is not True or o_bit != 1:
        checks.fail("V/fips/host", "V", "tier-v", "oracle", subject, expected={"os": "Rocky 9", "fips_enabled": 1},
                    observed=observed_ok, evidence=[rel])
    elif p_host is not True or p_bit != 1:
        checks.fail("V/fips/host", "V", "tier-v", "mismatch", subject, expected={"os": "Rocky 9", "fips_enabled": 1},
                    observed=observed_ok, evidence=[rel])
    else:
        checks.ok("V/fips/host", "V", "tier-v", subject, expected={"os": "Rocky 9", "fips_enabled": 1},
                  observed=observed_ok, evidence=[rel])


def _ssm(checks: Checks, run: Path) -> None:
    folder = run / "tier-v" / "ssm"
    files = sorted(p for p in folder.glob("*.json") if p.is_file()) if folder.is_dir() else []
    if not files:
        checks.not_run("V/ssm", "V", "tier-v", "no chunked SSM download was recorded", {"check": "ssm"},
                       evidence=["tier-v/ssm/"])
        return
    for path in files:
        rel = path.relative_to(run).as_posix()
        doc, err = _load(path)
        cid = f"V/ssm/{path.stem}"
        if err or doc is None:
            checks.fail(cid, "V", "tier-v", err or "unreadable", {"check": "ssm", "part": path.stem}, evidence=[rel])
            continue
        body, reason = reassemble_ssm(doc)
        if body is None:
            checks.fail(cid, "V", "tier-v", reason, {"check": "ssm", "part": path.stem}, evidence=[rel])
        else:
            checks.ok(cid, "V", "tier-v", {"check": "ssm", "part": path.stem},
                      observed={"bytes": len(body), "sha256": doc.get("sha256")}, evidence=[rel])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m harness.tier_v", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    plan_p = sub.add_parser("plan", help="create an empty Tier V run directory")
    plan_p.add_argument("--root", type=Path, required=True)
    plan_p.add_argument("--sha", required=True)
    judge_p = sub.add_parser("judge", help="judge recorded Tier V evidence")
    judge_p.add_argument("run", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.cmd == "plan":
            print(plan(args.root, args.sha))
            return 0
        ok, report = judge(args.run)
    except FileNotFoundError:
        print(f"no run directory {args.run}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"passed": ok, "counts": report["counts"]}))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
