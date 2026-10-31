#!/usr/bin/env python3
"""Standalone REAL CBOM scanner (bypasses Celery/RabbitMQ).
Runs the real CBOMAgent: real git clone + the deterministic aibom crypto engine (no LLM).
Scans a list of public repos and writes one JSON per repo to /tmp/cbom_runs/.
"""
import json, os, re, sys, time, subprocess, traceback
from pathlib import Path
from dotenv import load_dotenv

WORKER = Path(__file__).parent
sys.path.insert(0, str(WORKER))
# load env (worker + context)
for fp in [WORKER/".env", WORKER/"helpers"/"context"/".env"]:
    if fp.exists():
        load_dotenv(fp, override=False)

from helpers.context.scan_context import validate_dict_with_context  # noqa
from helpers.tools.cbom_agent.main import CBOMAgent  # noqa

OUT = Path("/tmp/cbom_runs"); OUT.mkdir(parents=True, exist_ok=True)
LOG = OUT/"progress.log"

def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line+"\n")

class NoOpWriter:
    def write_progress_percentage(self, p): log(f"   progress {p:.0f}%")
    def write_progress_out_of_total(self, c, t): log(f"   progress {c}/{t}")
    def update_state_with_meta(self, m): pass

def default_branch(url):
    try:
        r = subprocess.run(["git","ls-remote","--symref",url,"HEAD"],
                           capture_output=True, text=True, timeout=60)
        m = re.search(r"ref:\s+refs/heads/(\S+)\s+HEAD", r.stdout)
        return m.group(1) if m else "main"
    except Exception:
        return "main"

REPOS = [
    "https://github.com/golang-jwt/jwt",
    "https://github.com/jpadilla/pyjwt",
    "https://github.com/firebase/php-jwt",
    "https://github.com/pyca/bcrypt",
    "https://github.com/auth0/node-jsonwebtoken",
]

def scan(url):
    branch = default_branch(url)
    name = url.rstrip("/").split("/")[-1]
    log(f"=== SCAN START {name} ({url} @ {branch}) ===")
    t0 = time.time()
    ctx = validate_dict_with_context({"mode":"github","repo_url":url,"branch":branch,"PAT":""})
    agent = CBOMAgent(context=ctx, scan_binaries=False, state_update_writer=NoOpWriter())
    run = agent.run_agent()
    results = run["results"]
    cbom_json = run.get("cbom_json")
    dur = time.time()-t0
    payload = {"repo_url":url,"branch":branch,"name":name,
               "results":results,"cbom_json":cbom_json,"duration_of_scan":dur}
    outp = OUT/f"{name}.json"
    json.dump(payload, open(outp,"w"), indent=2, default=str)
    log(f"=== SCAN DONE  {name}: {len(results)} findings in {dur:.0f}s -> {outp} ===")
    return outp

if __name__ == "__main__":
    repos = sys.argv[1:] if len(sys.argv) > 1 else REPOS
    open(LOG,"w").close()
    log(f"Starting {len(repos)} real CBOM scans (deterministic engine)")
    summary=[]
    for url in repos:
        try:
            p = scan(url)
            summary.append({"url":url,"status":"success","out":str(p)})
        except Exception as e:
            log(f"!!! SCAN FAILED {url}: {type(e).__name__}: {e}")
            log(traceback.format_exc())
            summary.append({"url":url,"status":"failed","error":f"{type(e).__name__}: {e}"})
    json.dump(summary, open(OUT/"summary.json","w"), indent=2)
    ok=sum(1 for s in summary if s["status"]=="success")
    log(f"ALL DONE: {ok}/{len(REPOS)} succeeded")
