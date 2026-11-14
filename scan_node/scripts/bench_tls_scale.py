"""Scale bench for the TLS prober (CB-12): one network job over a real /24, at the team's rate limits, per handshake
budget.  It prints the wall time, the connections the node made (sweep + handshakes, from the node's limiter), and
the handshakes per TLS endpoint (from the facts the node would store).

Run against the lab of scan_node/tests/tls_lab.sh (`up`, then `bench-up` for the 100-endpoint /24):
    python scan_node/scripts/bench_tls_scale.py 10.232.12.0/24 --ports 443,8443,9443,10443 --budgets 12,32,64,128
Nothing is posted anywhere: assets stay in memory (JobContext without a poster).
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zs_scan_node import netutil  # noqa: E402
from zs_scan_node.collectors import network as N  # noqa: E402
from zs_scan_node.jobctx import JobContext  # noqa: E402
from zs_scan_node.netutil import NeverScan  # noqa: E402
from zs_scan_node.scrub import Scrubber  # noqa: E402


def one_run(cidr: str, ports: list[int], budget: int, cps: int, per_server: int) -> dict:
    ctx = JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="network_range",
                     scrubber=Scrubber(), never_scan=NeverScan([]), deadline=time.monotonic() + 3600)
    scope = {"ranges": [{"cidr": cidr, "mode": "full"}],
             "ports": [{"port": p, "protocol": "tls", "label": "https"} for p in ports],
             "rate_limits": {"connections_per_second": cps, "parallel_per_server": per_server,
                             "handshakes_per_endpoint": budget}}
    limiter = netutil.node_limiter(cps, per_server)
    before = limiter.connections
    t0 = time.monotonic()
    summary = N.run_network(ctx, scope)
    wall = time.monotonic() - t0
    ctx.flush()
    tls = [a for a in ctx.collected if a["type"] == "tls_endpoint"]
    used = [a["facts"].get("handshakes_used") or 0 for a in tls]
    complete = sum(1 for a in tls if (a["facts"].get("enumeration") or {}).get("complete"))
    return {"budget": budget, "wall_s": round(wall, 1), "connections": limiter.connections - before,
            "tls_endpoints": len(tls), "handshakes_total": sum(used),
            "handshakes_per_endpoint": {"median": statistics.median(used) if used else 0, "max": max(used or [0])},
            "enumeration_complete": complete, "summary": summary}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cidr")
    ap.add_argument("--ports", default="443")
    ap.add_argument("--budgets", default="12,128")
    ap.add_argument("--cps", type=int, default=20)
    ap.add_argument("--per-server", type=int, default=2)
    ap.add_argument("--out")
    args = ap.parse_args()
    ports = [int(p) for p in args.ports.split(",")]
    results = []
    for budget in [int(b) for b in args.budgets.split(",")]:
        r = one_run(args.cidr, ports, budget, args.cps, args.per_server)
        print(json.dumps(r), flush=True)
        results.append(r)
    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
