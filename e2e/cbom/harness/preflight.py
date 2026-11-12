"""G0 pre-flight: one build everywhere, the database at the ref's migration head, the workers started, the lab
self-checked and the oracle frozen. Writes ``steps/G0/step.json``.

    python3 -m harness.preflight <run> --sha <40-hex> [--repo /path/to/clone] [--api URL] [--ui URL] [--ca PEM]

Build identity (CB-03): ``/health.build``, the ``X-ZS-Build`` header, ``<meta name="zs-build">`` and the node image's
build must all equal the SHA under test. Until CB-03 lands these fail (ledger row PRE-build-identity) and the OCI
``org.opencontainers.image.revision`` labels of the running images carry the identity instead.
"""
from __future__ import annotations

import argparse
import json
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .rundir import read_json, write_json

API = "https://api.dss.test"
UI = "https://devsec.dss.test"
CA = "/home/claude/round6/local/ca/ca.pem"
PREFIX = "dss-staging-"
REV_LABEL = "org.opencontainers.image.revision"
MIGRATIONS = "prod_database_migrations/migrations/versions"


class Step:
    def __init__(self, gate: str) -> None:
        self.gate = gate
        self.checks: list[dict[str, Any]] = []
        self.started = time.time()

    def add(self, check: str, ok: bool | None, expected: Any, observed: Any, reason: str = "mismatch",
            note: str = "") -> None:
        verdict = "NOT-RUN" if ok is None else ("PASS" if ok else "FAIL")
        self.checks.append({"id": f"{self.gate}/{check}", "gate": self.gate, "kind": "preflight", "verdict": verdict,
                            "subject": {"check": check}, "reason": (note or reason) if verdict != "PASS" else "",
                            "expected": expected, "observed": observed})

    def write(self, run: Path, note: str = "") -> Path:
        return write_json(Path(run) / "steps" / self.gate / "step.json", {
            "gate": self.gate, "status": "ran", "started": _epoch(self.started),
            "ended": _epoch(time.time()), "seconds": round(time.time() - self.started, 1), "note": note,
            "checks": self.checks})


def _epoch(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def _opener(ca: str):
    ctx = ssl.create_default_context(cafile=ca) if Path(ca).is_file() else ssl.create_default_context()
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))


def http_get(url: str, ca: str) -> tuple[int, dict[str, str], bytes]:
    try:
        with _opener(ca).open(urllib.request.Request(url), timeout=20) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()
    except (urllib.error.URLError, OSError) as e:
        return 0, {}, str(e).encode()


def sh(*cmd: str, timeout: int = 60) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.SubprocessError) as e:
        return 127, str(e)


def same_sha(a: str | None, sha: str) -> bool:
    a = (a or "").strip().lower()
    return len(a) >= 7 and (sha.lower().startswith(a) or a.startswith(sha.lower()))


def migration_heads(repo: str, sha: str) -> list[str]:
    code, out = sh("git", "-C", repo, "ls-tree", "--name-only", f"{sha}:{MIGRATIONS}")
    if code:
        return []
    revisions, downs = set(), set()
    for name in out.split():
        if not name.endswith(".py"):
            continue
        code, text = sh("git", "-C", repo, "show", f"{sha}:{MIGRATIONS}/{name}")
        m = re.search(r"^revision[^=\n]*=\s*['\"]([^'\"]+)['\"]", text, re.M)
        if m:
            revisions.add(m.group(1))
        d = re.search(r"^down_revision[^=\n]*=\s*(.+)$", text, re.M)
        if d:
            downs |= set(re.findall(r"['\"]([^'\"]+)['\"]", d.group(1)))
    return sorted(revisions - downs)


def psql(sql: str, pg: str = PREFIX + "postgres-1") -> tuple[int, str]:
    try:
        p = subprocess.run(["docker", "exec", "-i", pg, "sh", "-c",
                            'exec psql -X -q -At -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'],
                           input=f"BEGIN READ ONLY;\n{sql};\nCOMMIT;\n", capture_output=True, text=True, timeout=60)
        return p.returncode, (p.stdout or p.stderr).strip()
    except (OSError, subprocess.SubprocessError) as e:
        return 127, str(e)


def image_label(container: str) -> str | None:
    code, out = sh("docker", "inspect", "--format", "{{.Image}}", container)
    if code:
        return None
    code, labels = sh("docker", "image", "inspect", "--format", "{{json .Config.Labels}}", out.strip())
    try:
        return (json.loads(labels) or {}).get(REV_LABEL) if not code else None
    except ValueError:
        return None


def run(run_dir: Path, sha: str, repo: str, api: str, ui: str, ca: str, node_image: str | None) -> Step:
    st = Step("G0")
    # memory (DA §4.1)
    code, out = sh("free", "-m")
    m = re.search(r"^Mem:\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)", out, re.M)
    avail = int(m.group(1)) if m else 0
    st.add("memory", avail >= 1536, ">= 1536 MB available", f"{avail} MB")
    # build identity (CB-03)
    status, headers, body = http_get(f"{api}/health", ca)
    try:
        health = json.loads(body or b"{}")
    except ValueError:
        health = {}
    st.add("health", status == 200, "GET /health 200", status)
    st.add("build_health", same_sha(health.get("build"), sha), sha, health.get("build") or "<no build field>")
    st.add("build_header", same_sha(headers.get("x-zs-build"), sha), sha, headers.get("x-zs-build") or "<no header>")
    status, _, html = http_get(f"{ui}/login", ca)
    meta = re.search(rb'<meta[^>]+name="zs-build"[^>]+content="([0-9a-f]+)"', html or b"")
    st.add("build_frontend_meta", bool(meta) and same_sha(meta.group(1).decode(), sha), sha,
           meta.group(1).decode() if meta else f"<no zs-build meta> (GET /login {status})")
    if node_image:
        code, labels = sh("docker", "image", "inspect", "--format", "{{json .Config.Labels}}", node_image)
        lab = {} if code else (json.loads(labels or "null") or {})
        code, env = sh("docker", "image", "inspect", "--format", "{{json .Config.Env}}", node_image)
        env_build = next((e.split("=", 1)[1] for e in (json.loads(env or "null") or []) if e.startswith("ZS_NODE_BUILD=")),
                         None) if not code else None
        st.add("build_node_label", same_sha(env_build, sha) and same_sha(lab.get(REV_LABEL), sha), sha,
               {"ZS_NODE_BUILD": env_build, REV_LABEL: lab.get(REV_LABEL), "image": node_image})
    else:
        st.add("build_node_label", False, sha, "<no scan-node image on this stack>")
    # the OCI revision labels the stack sets today (restack.sh): the running app is the SHA under test
    for svc in ("backend", "frontend", "cbom-cloud-worker"):
        rev = image_label(f"{PREFIX}{svc}-1")
        st.add(f"image_revision_{svc}", same_sha(rev, sha), sha, rev or "<no label>")
    # database at the ref's head
    heads = migration_heads(repo, sha)
    code, current = psql("SELECT version_num FROM alembic_version")
    st.add("alembic_head", bool(heads) and code == 0 and set(current.split()) == set(heads), heads,
           current if code == 0 else f"<psql failed: {current[:200]}>")
    # workers started since their last restart
    code, logs = sh("docker", "logs", f"{PREFIX}cbom-cloud-worker-1", timeout=60)
    for line, check in (("cloud worker started", "cloud_worker_started"), ("scheduler started", "scheduler_started"),
                        ("integration dispatcher started", "dispatcher_started")):
        st.add(check, line in logs, f"'cbom sources {line}' in the cloud-worker log", "found" if line in logs else
               "not found")
    # the lab (CB-02) and the frozen oracle (O-5)
    sc = read_json(Path(run_dir) / "lab" / "selfcheck.json")
    if sc is None:
        st.add("lab_selfcheck", None, "lab/selfcheck.json with every target agreeing", "<no lab>",
               note="lab not run (CB-02 gen.py)")
    else:
        bad = [t.get("target_id") for t in sc.get("targets") or [] if not t.get("agree")]
        st.add("lab_selfcheck", not bad, "every target agrees", bad or "all agree")
    man = read_json(Path(run_dir) / "MANIFEST.json") or {}
    if (Path(run_dir) / "oracle").is_dir() and any((Path(run_dir) / "oracle").iterdir()):
        st.add("oracle_frozen_before_start", bool((man.get("oracle") or {}).get("sha256")),
               "MANIFEST.oracle.sha256 set", (man.get("oracle") or {}).get("sha256") or "<not frozen>")
    else:
        st.add("oracle_frozen_before_start", None, "an oracle", "<no oracle>", note="lab not run (CB-02 gen.py)")
    return st


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="harness.preflight")
    ap.add_argument("run", type=Path)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--repo", default="/home/claude/devsecshield")
    ap.add_argument("--api", default=API)
    ap.add_argument("--ui", default=UI)
    ap.add_argument("--ca", default=CA)
    ap.add_argument("--node-image", default=None)
    args = ap.parse_args(argv)
    st = run(args.run, args.sha, args.repo, args.api, args.ui, args.ca, args.node_image)
    st.write(args.run)
    bad = [c["id"] for c in st.checks if c["verdict"] != "PASS"]
    print(json.dumps({"G0": "ok" if not bad else "see checks", "not_pass": bad}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
