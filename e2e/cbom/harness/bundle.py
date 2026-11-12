"""G17 bundle: MANIFEST.json contents, the residual-secret check, and the runtime budget.

    python3 -m harness.bundle manifest <run> --sha <sha> --ref <ref> --started <utc> [--node-image IMG]
    python3 -m harness.bundle seal <run> --secrets-file F --started <utc> [--budget-min 45]
        redact (scrub har/ api/ ui/ steps/ logs/), delete the secrets file, write steps/G17/step.json
"""
from __future__ import annotations

import argparse
import email.utils
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import gate, manifest
from .preflight import API, CA, http_get
from .rundir import iso, parse_ts, read_csv, read_json, utc_now, write_json

STACK_MD = "/home/claude/round6/local/STACK.md"
PW = "/home/claude/round6/local/pw"


def _sh(*cmd: str) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def lab_containers(run: Path) -> list[str]:
    """Lab container names from the lab's own lab.json (INTERFACES v7 §A.6; no prefix assumed)."""
    lab = read_json(Path(run) / "lab" / "lab.json") or {}
    return sorted({x["container"] for x in (lab.get("targets") or []) + (lab.get("listeners") or []) if x.get("container")})


def images(run: Path) -> dict[str, Any]:
    out = {}
    lab = set(lab_containers(run))
    for name in _sh("docker", "ps", "--format", "{{.Names}}").split():
        if not (re.match(r"^(dss-staging-|zs-scan-node-)", name) or name in lab):
            continue
        image_id = _sh("docker", "inspect", "--format", "{{.Image}}", name)
        ref = _sh("docker", "inspect", "--format", "{{.Config.Image}}", name)
        labels = _sh("docker", "image", "inspect", "--format", "{{json .Config.Labels}}", image_id)
        try:
            lab = json.loads(labels or "null") or {}
        except ValueError:
            lab = {}
        out[name] = {"image": ref, "id": image_id, "revision": lab.get("org.opencontainers.image.revision"),
                     "version": lab.get("org.opencontainers.image.version")}
    return out


def write_manifest(run: Path, sha: str, ref: str, started: str, node_image: str | None) -> dict[str, Any]:
    status_line = ""
    if Path(STACK_MD).is_file():
        m = re.search(r"STATUS:BEGIN -->\s*\n(.*?)\n", Path(STACK_MD).read_text(encoding="utf-8"))
        status_line = m.group(1).strip() if m else ""
    _, headers, _ = http_get(f"{API}/health", CA)
    try:
        server = email.utils.parsedate_to_datetime(headers["date"]) if headers.get("date") else None
    except (TypeError, ValueError):
        server = None
    offset = round((utc_now() - server).total_seconds(), 1) if server else None
    pw = read_json(Path(PW) / "node_modules" / "playwright" / "package.json") or {}
    browsers = sorted(p.name for p in (Path(PW) / "browsers").glob("chromium*")) if (Path(PW) / "browsers").is_dir() else []
    node_digest = _sh("docker", "image", "inspect", "--format", "{{.Id}}", node_image) if node_image else None
    state = read_json(Path(run) / "flow-state.json") or {}
    node_image = (state.get("node") or {}).get("image") or node_image
    node_digest = _sh("docker", "image", "inspect", "--format", "{{.Id}}", node_image) if node_image else node_digest
    gen = read_json(Path(run) / "lab" / "gen.json") or {}
    jobs = [{"id": r.get("id"), "run_id": r.get("run_id"), "kind": r.get("kind"), "status": r.get("status"),
             "outcome": r.get("outcome"), "asset_count": r.get("asset_count")}
            for r in read_csv(Path(run) / "db" / "jobs.csv")]
    assets: dict[str, list[int]] = {}
    serials: dict[str, str] = {}
    for p in sorted((Path(run) / "api").glob("assets-run*.json")):
        k = p.stem.rsplit("run", 1)[-1]
        assets[k] = sorted(int(i["id"]) for i in (read_json(p) or {}).get("items") or [])
        exp = read_json(Path(run) / "exports" / f"run{k}.cdx.json") or {}
        if exp.get("serialNumber"):
            serials[k] = exp["serialNumber"]
    here = Path(__file__).resolve().parents[1]
    harness = {"commit": _sh("git", "-C", str(here), "rev-parse", "HEAD"),
               "dirty": bool(_sh("git", "-C", str(here), "status", "--porcelain", "--", "."))}
    return manifest.update(run, sha=sha, ref=ref, tier="L", started=started, stack_status=status_line, harness=harness,
                           images=images(run), node_image={"ref": node_image, "id": node_digest},
                           lab={"containers": lab_containers(run), "images": gen.get("images") or {},
                                "generator": gen.get("generator"), "commit": gen.get("commit")},
                           playwright={"version": pw.get("version"), "browsers": browsers},
                           clock_offset_s=offset, teams=state.get("teams") or {}, runs=state.get("runs") or [],
                           node=state.get("node") or {}, jobs=jobs, assets=assets, serialNumbers=serials)


def seal(run: Path, secrets_file: Path | None, started: str, budget_min: float) -> int:
    known: list[str] = []
    if secrets_file and secrets_file.is_file():
        known = [str(v) for v in json.loads(secrets_file.read_text(encoding="utf-8")) if v]
    problems = gate.redact_run(run, known)
    if secrets_file and secrets_file.is_file():
        secrets_file.unlink()
    t0 = parse_ts(started)
    elapsed = (utc_now() - t0).total_seconds() if t0 else None
    man = read_json(Path(run) / manifest.MANIFEST) or {}
    need = ("sha", "images", "playwright", "teams", "started", "runs", "jobs", "assets", "serialNumbers", "node_image",
            "lab", "harness")
    checks = [
        _check("no_residual_secrets", not problems, "no token, password or registration token left", problems[:20]),
        _check("manifest_complete", not _incomplete(man, need), list(need), _incomplete(man, need) or "complete"),
        _check("oracle_hash_in_manifest", bool((man.get("oracle") or {}).get("sha256")), "MANIFEST.oracle.sha256",
               (man.get("oracle") or {}).get("sha256") or "<none>"),
        _check("runtime_le_budget", elapsed is not None and elapsed <= budget_min * 60, f"<= {budget_min} min",
               None if elapsed is None else f"{elapsed / 60:.1f} min"),
    ]
    state = read_json(Path(run) / "flow-state.json") or {}
    logged_out = state.get("logged_out") or {}
    checks.append(_check("customers_logged_out", bool(logged_out) and all(logged_out.values()),
                         "both customers signed out through the UI", logged_out or "not recorded"))
    write_json(Path(run) / "steps" / "G17" / "step.json", {"gate": "G17", "status": "ran", "started": started,
                                                          "ended": iso(utc_now()), "checks": checks})
    manifest.update(run, gate_seconds=None if elapsed is None else round(elapsed))
    print(json.dumps({"residual_secrets": problems[:5], "elapsed_min": None if elapsed is None else round(elapsed / 60, 1)}))
    return 0


def _incomplete(man: dict[str, Any], need: tuple[str, ...]) -> list[str]:
    missing = [k for k in need if not man.get(k)]
    if not (man.get("node_image") or {}).get("id"):
        missing.append("node_image.id")
    if not (man.get("lab") or {}).get("containers"):
        missing.append("lab.containers")
    if not (man.get("harness") or {}).get("commit"):
        missing.append("harness.commit")
    return sorted(set(missing))


def _check(name: str, ok: bool, expected: Any, observed: Any) -> dict[str, Any]:
    return {"id": f"G17/{name}", "gate": "G17", "kind": "bundle", "verdict": "PASS" if ok else "FAIL",
            "subject": {"check": name}, "reason": "" if ok else "bundle", "expected": expected, "observed": observed}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="harness.bundle")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("manifest")
    m.add_argument("run", type=Path)
    m.add_argument("--sha", required=True)
    m.add_argument("--ref", default="")
    m.add_argument("--started", required=True)
    m.add_argument("--node-image")
    s = sub.add_parser("seal")
    s.add_argument("run", type=Path)
    s.add_argument("--secrets-file", type=Path)
    s.add_argument("--started", required=True)
    s.add_argument("--budget-min", type=float, default=45)
    args = ap.parse_args(argv)
    if args.cmd == "manifest":
        man = write_manifest(args.run, args.sha, args.ref, args.started, args.node_image)
        print(json.dumps({"images": len(man.get("images") or {}), "clock_offset_s": man.get("clock_offset_s")}))
        return 0
    return seal(args.run, args.secrets_file, args.started, args.budget_min)


if __name__ == "__main__":
    sys.exit(main())
