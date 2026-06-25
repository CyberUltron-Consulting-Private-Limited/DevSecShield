#!/usr/bin/env python3
"""Determinism test: scan the SAME repo N times, capture findings + raw CBOM
components each run, save to /tmp/cbom_consistency/run_<i>.json."""
import json, sys, time
from pathlib import Path
from dotenv import load_dotenv
WORKER = Path(__file__).parent
sys.path.insert(0, str(WORKER))
for fp in [WORKER/".env", WORKER/"helpers"/"context"/".env"]:
    if fp.exists():
        load_dotenv(fp, override=False)
from helpers.context.scan_context import validate_dict_with_context
from helpers.tools.cbom_agent.main import CBOMAgent

OUT = Path("/tmp/cbom_consistency"); OUT.mkdir(parents=True, exist_ok=True)
REPO = sys.argv[1] if len(sys.argv) > 1 else "https://github.com/golang-jwt/jwt"
BRANCH = sys.argv[2] if len(sys.argv) > 2 else "main"
N = int(sys.argv[3]) if len(sys.argv) > 3 else 3

class NoOp:
    def write_progress_percentage(self, p): pass
    def write_progress_out_of_total(self, c, t): pass
    def update_state_with_meta(self, m): pass

def keyset(results):
    return sorted({f"{(r.get('algorithm_name') or '').lower()}|{r.get('algorithm_type')}|{r.get('crypto_strength')}|{r.get('location')}" for r in results})

print(f"Determinism test: {REPO}@{BRANCH} x{N}", flush=True)
runs = []
for i in range(1, N+1):
    t0 = time.time()
    ctx = validate_dict_with_context({"mode":"github","repo_url":REPO,"branch":BRANCH,"PAT":""})
    agent = CBOMAgent(context=ctx, scan_binaries=False, state_update_writer=NoOp())
    res = agent.run_agent()
    results = agent.to_dict_list(res)
    cbom = agent.get_cyclonedx_cbom() or {}
    comps = len(cbom.get("components", []))
    rec = {"run": i, "findings": len(results), "raw_components": comps,
           "keys": keyset(results),
           "algos": sorted({(r.get("algorithm_name") or "").lower() for r in results}),
           "dur": round(time.time()-t0, 1), "results": results}
    json.dump(rec, open(OUT/f"run_{i}.json", "w"), indent=2, default=str)
    runs.append(rec)
    print(f"run {i}: findings={rec['findings']} raw_components={comps} algos={len(rec['algos'])} dur={rec['dur']}s", flush=True)

# comparison
print("\n=== DETERMINISM REPORT ===", flush=True)
counts = [r["findings"] for r in runs]
raws = [r["raw_components"] for r in runs]
print(f"findings counts per run: {counts}  -> {'STABLE' if len(set(counts))==1 else 'VARYING'}", flush=True)
print(f"raw component counts:    {raws}  -> {'STABLE' if len(set(raws))==1 else 'VARYING'}", flush=True)
base = set(runs[0]["keys"])
for r in runs[1:]:
    s = set(r["keys"])
    inter = len(base & s); union = len(base | s) or 1
    print(f"run1 vs run{r['run']}: jaccard(keys)={inter/union:.2f}  only_in_run1={len(base-s)} only_in_run{r['run']}={len(s-base)}", flush=True)
algobase = set(runs[0]["algos"])
for r in runs[1:]:
    print(f"run1 vs run{r['run']} algorithms: {'SAME' if set(r['algos'])==algobase else 'DIFFERENT'} (run1={sorted(algobase)} run{r['run']}={sorted(r['algos'])})", flush=True)
json.dump([{k:v for k,v in r.items() if k!='results'} for r in runs], open(OUT/"comparison.json","w"), indent=2)
print("\nsaved comparison.json", flush=True)
