"""Run one collector locally, without a ZeroShield server, and print its assets and result as JSON.

    python -m zs_scan_node.collect --kind network_range --config cfg.json --scope scope.json
    python -m zs_scan_node.collect --kind linux_servers --config cfg.json --secrets sec.json --scope scope.json \
        --job-kind test_connection --state-dir ./state

``--kind`` is the source kind (linux_servers, windows_servers, kubernetes, database, network_range) or
``discovery``.  Files are JSON objects: config = source config, secrets = source secrets, scope = claim scope.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from zs_scan_node.collectors import run_job
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber


def _load(path: str | None) -> dict:
    if not path:
        return {}
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected a JSON object")
    return data


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="zs_scan_node.collect")
    p.add_argument("--kind", required=True)
    p.add_argument("--job-kind", default="collect", choices=["collect", "test_connection", "discovery"])
    p.add_argument("--config")
    p.add_argument("--secrets")
    p.add_argument("--scope")
    p.add_argument("--state-dir", default=os.environ.get("ZS_STATE_DIR", "./zs-node-state"))
    p.add_argument("--max-runtime", type=int, default=3600)
    p.add_argument("--out", help="write JSON here instead of stdout")
    args = p.parse_args(argv)
    config, secrets, scope = _load(args.config), _load(args.secrets), _load(args.scope)
    os.makedirs(args.state_dir, exist_ok=True)
    scrubber = Scrubber([v for v in secrets.values() if isinstance(v, str)])
    job_kind = "discovery" if args.kind == "discovery" else args.job_kind
    ctx = JobContext(job_id=0, attempt=1, run_id=None, kind=job_kind,
                     source_kind=None if args.kind == "discovery" else args.kind, scrubber=scrubber,
                     never_scan=NeverScan(scope.get("never_scan") or []),
                     deadline=time.monotonic() + args.max_runtime, state_dir=args.state_dir,
                     node_private_key_path=os.path.join(args.state_dir, "id_ed25519"),
                     vault_prefix=os.environ.get("ZS_VAULT_PATH_PREFIX"))
    job = {"id": 0, "kind": job_kind}
    source = None if args.kind == "discovery" else {"kind": args.kind, "config": config, "secrets": secrets}
    started = time.monotonic()
    status, error, summary = run_job(ctx, job, scope, source)
    ctx.flush()
    out = {"status": status, "error": error, "result": ctx.result(summary), "assets": ctx.collected,
           "elapsed_s": round(time.monotonic() - started, 2)}
    text = json.dumps(out, indent=2, default=str)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"{status}: {len(ctx.collected)} assets, {out['result']['summary']} -> {args.out}")
    else:
        sys.stdout.write(text + "\n")
    return 0 if status == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
