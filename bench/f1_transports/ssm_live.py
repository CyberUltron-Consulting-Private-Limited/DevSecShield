#!/usr/bin/env python3
"""Live proof of the AWS SSM transport: the cloud worker's ``SsmTransport`` against one sandbox EC2 instance.

    python bench/f1_transports/ssm_live.py --instance-id i-... --region ap-south-1 \
        --manifest zs-collect-1.0.0.manifest.json --public scan_node/zs_collect/zs-release-ed25519.pub \
        --direct out-direct.txt --direct-nonce NONCE --label 127.0.0.1 [--unreachable-id i-...] --out DIR

1. Renders the launcher for the signed release (``wrappers.render_wrapper``: sha256 + Ed25519 signature baked in) and
   the Command document (``wrappers.ssm_document_json``) exactly as the ``ssm-document`` artifact does, and creates it
   as ``devsecshield-zs-collect-<version>-f13`` (tagged Project=DevSecShield, zs-lab=sandbox, zs-owner=f1-3).
2. ``SsmTransport.check``, then the cloud worker's own entry ``cloud.collect_ssm`` (never-scan first, then
   ``SsmTransport.run_collect``, then each validated document's assets emitted with ``target`` = the inventory
   address) for three inventory targets: the instance (explicit id), an id SSM does not manage (must be
   ``unreachable``, never sent a command), and an address on the never-scan list whose handle is the same live
   instance (must be ``skipped_never_scan``; SSM never sees it).  Tier 2, inline chunked output (the sandbox may not
   tag S3 buckets, so no output bucket).  A document name outside ``devsecshield-*`` is refused before any AWS call.
3. Compares the emitted assets with the launcher run directly on the same host (``ec2.sh direct``) after
   normalize.py: the diff must be empty.
The boto3 clients act as the sandbox user (from the environment: source awsenv.sh in the same shell; never printed).
Assuming the customer's run-command role with the team's external id is ``role_client_factory``, covered by the
Stubber tests; the sandbox has no role to assume.  Exit 0 only when every check holds.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import normalize  # noqa: E402

from backend.utilities.cbom_sources.transports import cloud, wrappers, zsdoc  # noqa: E402
from backend.utilities.cbom_sources.transports.base import (CollectTarget,  # noqa: E402
                                                            TransportCredential, TransportError)
from backend.utilities.cbom_sources.transports.ssm import SsmTransport  # noqa: E402

TAGS = [{"Key": "Project", "Value": "DevSecShield"}, {"Key": "zs-lab", "Value": "sandbox"},
        {"Key": "zs-owner", "Value": "f1-3"}]


def ensure_document(ssm, name: str, content: str) -> str:
    """Create the document, or replace our own earlier copy when its content differs.  Returns its sha256."""
    digest = hashlib.sha256(content.encode()).hexdigest()
    try:
        current = ssm.get_document(Name=name)["Content"]
        if hashlib.sha256(current.encode()).hexdigest() == digest:
            return digest
        ssm.delete_document(Name=name)
        time.sleep(3)
    except ssm.exceptions.InvalidDocument:
        pass
    ssm.create_document(Name=name, DocumentType="Command", DocumentFormat="JSON", Content=content, Tags=TAGS)
    return digest


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--instance-id", required=True)
    ap.add_argument("--region", default="ap-south-1")
    ap.add_argument("--manifest", required=True, help="the release manifest (its .sig next to it)")
    ap.add_argument("--public", required=True, help="the release public key (PEM)")
    ap.add_argument("--label", default="127.0.0.1", help="the inventory address of the instance (asset.target)")
    ap.add_argument("--direct", help="the launcher's stdout from the same host (ec2.sh direct)")
    ap.add_argument("--direct-nonce")
    ap.add_argument("--unreachable-id", help="an instance id SSM does not manage (e.g. a terminated sandbox instance)")
    ap.add_argument("--tier", type=int, default=2)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    if not args.instance_id.startswith("i-"):
        raise SystemExit("an explicit instance id is required")

    import boto3

    session = boto3.session.Session(region_name=args.region)
    calls: list[tuple[str, str]] = []
    sent: list[dict] = []

    def _seen(service: str):
        def hook(model, params, **_):
            calls.append((service, model.name))
            if model.name == "SendCommand":
                sent.append({"InstanceIds": list(params.get("InstanceIds") or []),
                             "DocumentName": params.get("DocumentName"), "Parameters": params.get("Parameters")})
        return hook

    def factory(service: str, region: str):
        client = session.client(service, region_name=region)
        client.meta.events.register("provide-client-params.*.*", _seen(service))
        return client

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    manifest_bytes = Path(args.manifest).read_bytes()
    manifest = json.loads(manifest_bytes)
    sig_b64 = Path(args.manifest + ".sig").read_text().strip()
    launcher = wrappers.render_wrapper(manifest, Path(args.public).read_text(), sig_b64)
    version = str(manifest["version"])
    doc_name = f"devsecshield-zs-collect-{version}-f13"
    content = wrappers.ssm_document_json(version, launcher)
    doc_sha = ensure_document(session.client("ssm"), doc_name, content)
    (out / "ssm-document.json").write_text(content)
    report: dict = {"instance_id": args.instance_id, "region": args.region, "document": doc_name,
                    "document_sha256": doc_sha, "release": {"version": version, "files": manifest.get("files")},
                    "checks": {}}
    transport = SsmTransport(factory, log=lambda *a, **k: print("  log:", a, k, file=sys.stderr), poll_s=3.0)

    # 1. a document outside devsecshield-* is refused before any AWS call
    calls.clear()
    bad = TransportCredential("aws_role", {"regions": [args.region], "document_name": "AWS-RunShellScript"}, {})
    try:
        transport.check(bad, [CollectTarget(args.label, args.instance_id)])
        refused = None
    except TransportError as exc:
        refused = (exc.status, exc.detail)
    report["checks"]["non_devsecshield_document_refused"] = {"ok": bool(refused and refused[0] == "refused"
                                                                         and not calls), "result": refused,
                                                             "aws_calls": list(calls)}

    cred = TransportCredential("aws_role", {"regions": [args.region], "document_name": doc_name}, {})
    targets = [CollectTarget(args.label, args.instance_id)]
    if args.unreachable_id:
        targets.append(CollectTarget("not-managed", args.unreachable_id))

    # 2. check(): the document and which instances SSM manages, no command sent
    calls.clear()
    checked = transport.check(cred, targets)
    report["checks"]["check"] = {"ok": checked[0].status == "ok" and all(r.status == "unreachable"
                                                                          for r in checked[1:])
                                 and ("ssm", "SendCommand") not in calls,
                                 "results": [(r.target.handle, r.status, r.error) for r in checked],
                                 "aws_calls": list(calls)}

    # 3. the cloud worker's collect_ssm: never-scan first, SendCommand to the explicit instance id only, relabel
    never = "10.250.0.7"
    labels = [args.label, never] + (["not-managed"] if args.unreachable_id else [])
    handles = {args.label: args.instance_id, never: args.instance_id}
    if args.unreachable_id:
        handles["not-managed"] = args.unreachable_id
    sha = {f["arch"]: f["sha256"] for f in manifest["files"]}
    config = {"transport": dict(cred.config), "zs_collect": {"version": version, "sha256": sha}, "targets": labels,
              "handles": handles, "tier": args.tier, "timeout_s": 600}
    emitted: list[dict] = []
    calls.clear()
    sent.clear()
    started = time.time()
    result = cloud.collect_ssm({"id": 7301, "attempt": 1, "kind": "collect"}, config, [never + "/32"], transport,
                               emitted.append, lambda: None, time.monotonic() + 1200)
    seconds = round(time.time() - started, 1)
    rows = {r["target"]: r for r in result["targets"]}
    report["checks"]["collect_ssm"] = {
        "ok": rows.get(args.label, {}).get("status") == "ok"
        and rows.get(never, {}).get("status") == "skipped_never_scan"
        and (not args.unreachable_id or rows.get("not-managed", {}).get("status") == "unreachable")
        and len(sent) == 1 and sent[0]["InstanceIds"] == [args.instance_id] and sent[0]["DocumentName"] == doc_name
        and len(emitted) == rows[args.label]["assets"] > 0 and all(a.get("target") == args.label for a in emitted),
        "seconds": seconds, "summary": result["summary"], "targets": result["targets"], "send_command": sent,
        "assets_emitted": len(emitted), "aws_calls": sorted(set(f"{s_}:{n}" for s_, n in calls))}
    (out / "emitted-assets.json").write_text(json.dumps(emitted, indent=1, default=str))

    # 4. the same host through the launcher directly: identical after normalisation
    if args.direct and emitted:
        direct = zsdoc.parse_output(Path(args.direct).read_text(), args.direct_nonce)
        problem = zsdoc.validate_document(direct, args.direct_nonce, version)
        a = normalize.normalise({"assets": emitted}, args.label)
        b = normalize.normalise({"assets": zsdoc.relabel(direct, args.label)}, args.label)
        lines = normalize.diff(a, b)
        (out / "direct-document.json").write_text(json.dumps(direct, indent=1, default=str))
        report["checks"]["same_as_direct_run"] = {"ok": not lines and problem is None and len(a["assets"]) > 0,
                                                  "direct_valid": problem, "direct_status": direct.get("status"),
                                                  "assets_ssm": len(a["assets"]), "assets_direct": len(b["assets"]),
                                                  "diff": lines[:20],
                                                  "pid_diff": normalize.pid_differences(
                                                      {"assets": emitted}, {"assets": zsdoc.relabel(direct, args.label)},
                                                      args.label)}
    report["ok"] = all(c["ok"] for c in report["checks"].values())
    (out / "report.json").write_text(json.dumps(report, indent=1, default=str))
    print(json.dumps({k: (v["ok"] if isinstance(v, dict) and "ok" in v else v)
                      for k, v in report["checks"].items()}))
    print(json.dumps({"ok": report["ok"], "seconds": seconds, "targets": result["targets"], "sent": sent},
                     default=str)[:3000])
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
