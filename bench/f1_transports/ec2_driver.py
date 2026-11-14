#!/usr/bin/env python3
"""Drive the F1.3 scale proof on one sandbox EC2 over SSM (no SSH, no inbound port, no S3).

    ec2_driver.py launch --minutes 120          one tagged instance that terminates itself (shutdown -h +N)
    ec2_driver.py wait                          until its SSM agent is Online
    ec2_driver.py upload LOCAL REMOTE           base64 chunks over SendCommand, sha256 checked on the box
    ec2_driver.py run 'shell command' [--timeout S]
    ec2_driver.py terminate                     terminate it and delete the documents this driver created
Guardrails (ROUND7/TEAM-PROCESS): every resource is tagged Project=DevSecShield, zs-lab=sandbox, zs-owner=f1-3; the
instance runs in the sandbox subnet and security group with the sandbox instance profile, has
``--instance-initiated-shutdown-behavior terminate`` and user data that starts with ``shutdown -h +N``; SendCommand is
only ever sent with a ``devsecshield-*`` document to the explicit instance id this driver launched.  State (instance
id, documents) is kept in ``--state`` so a later call (or a person) can clean up.  Credentials come from the
environment (source awsenv.sh in the same shell); they are never printed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import time
from pathlib import Path

REGION = "ap-south-1"
SUBNET = "subnet-0dd252df2cad964fe"
SG = "sg-0c617f55ec5ff0bbd"
PROFILE = "devsecshield-ec2-instance-profile"
TAGS = [{"Key": "Project", "Value": "DevSecShield"}, {"Key": "zs-lab", "Value": "sandbox"},
        {"Key": "zs-owner", "Value": "f1-3"}]
SHELL_DOC = "devsecshield-f1-3-shell"
CHUNK = 48_000


def clients():
    import boto3

    s = boto3.session.Session(region_name=REGION)
    return s.client("ec2"), s.client("ssm")


def load(path: Path) -> dict:
    return json.loads(path.read_text()) if path.exists() else {}


def save(path: Path, state: dict) -> None:
    path.write_text(json.dumps(state, indent=1))


def ensure_shell_doc(ssm, state: dict, path: Path) -> None:
    try:
        ssm.describe_document(Name=SHELL_DOC)
        return
    except ssm.exceptions.InvalidDocument:
        pass
    content = {"schemaVersion": "2.2", "description": "F1.3 bench: run shell commands on the f1-3 sandbox instance",
               "parameters": {"commands": {"type": "StringList"},
                              "executionTimeout": {"type": "String", "default": "3600",
                                                   "allowedPattern": "^[0-9]{1,5}$"}},
               "mainSteps": [{"action": "aws:runShellScript", "name": "run",
                              "inputs": {"runCommand": "{{ commands }}",
                                         "timeoutSeconds": "{{ executionTimeout }}"}}]}
    ssm.create_document(Name=SHELL_DOC, DocumentType="Command", Content=json.dumps(content), Tags=TAGS)
    state.setdefault("documents", []).append(SHELL_DOC)
    save(path, state)


def launch(args, path: Path) -> None:
    ec2, ssm = clients()
    state = load(path)
    if state.get("instance_id") and not state.get("terminated"):
        raise SystemExit(f"already launched: {state['instance_id']}")
    try:
        ami = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")
    except Exception:  # GetParameter not granted: the newest Amazon-owned AL2023 x86_64 image instead
        images = ec2.describe_images(Owners=["amazon"], Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-kernel-*-x86_64"]}, {"Name": "state", "Values": ["available"]}])
        newest = max(images["Images"], key=lambda i: i["CreationDate"])
        ami = {"Parameter": {"Value": newest["ImageId"]}}
    user_data = f"#!/bin/bash\nshutdown -h +{int(args.minutes)}\n"
    out = ec2.run_instances(
        ImageId=ami["Parameter"]["Value"], InstanceType=args.type, MinCount=1, MaxCount=1,
        SubnetId=SUBNET, SecurityGroupIds=[SG], IamInstanceProfile={"Name": PROFILE},
        InstanceInitiatedShutdownBehavior="terminate", UserData=user_data,
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": args.disk_gb, "VolumeType": "gp3",
                                                                 "DeleteOnTermination": True}}],
        MetadataOptions={"HttpTokens": "required"},
        TagSpecifications=[{"ResourceType": "instance", "Tags": TAGS + [{"Key": "Name", "Value": "f1-3-scale"}]},
                           {"ResourceType": "volume", "Tags": TAGS}])
    inst = out["Instances"][0]
    launched = inst["LaunchTime"]
    terminate_by = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(launched.timestamp() + 60 * int(args.minutes)))
    state.update(instance_id=inst["InstanceId"], type=args.type, launched=launched.strftime("%Y-%m-%dT%H:%M:%SZ"),
                 terminate_by=terminate_by, ami=ami["Parameter"]["Value"])
    save(path, state)
    print(json.dumps({k: state[k] for k in ("instance_id", "type", "launched", "terminate_by")}))


def wait(args, path: Path) -> None:
    _ec2, ssm = clients()
    state = load(path)
    iid = state["instance_id"]
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        info = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [iid]}])
        rows = info.get("InstanceInformationList") or []
        if rows and rows[0].get("PingStatus") == "Online":
            ensure_shell_doc(ssm, state, path)
            print(f"{iid} online: {rows[0].get('PlatformName')} {rows[0].get('PlatformVersion')} agent "
                  f"{rows[0].get('AgentVersion')}")
            return
        time.sleep(10)
    raise SystemExit(f"{iid} did not come online")


def run_cmd(ssm, iid: str, commands: list[str], timeout: int = 3600) -> dict:
    cmd = ssm.send_command(InstanceIds=[iid], DocumentName=SHELL_DOC,
                           Parameters={"commands": commands, "executionTimeout": [str(timeout)]},
                           TimeoutSeconds=600, Comment="f1-3 bench")
    cid = cmd["Command"]["CommandId"]
    deadline = time.time() + timeout + 120
    while True:
        time.sleep(3)
        try:
            inv = ssm.get_command_invocation(CommandId=cid, InstanceId=iid)
        except ssm.exceptions.InvocationDoesNotExist:
            continue
        if inv["Status"] not in ("Pending", "InProgress", "Delayed"):
            return inv
        if time.time() > deadline:
            ssm.cancel_command(CommandId=cid)
            return inv


def run(args, path: Path) -> None:
    _ec2, ssm = clients()
    iid = load(path)["instance_id"]
    inv = run_cmd(ssm, iid, [args.command], args.timeout)
    sys.stdout.write(inv.get("StandardOutputContent") or "")
    err = inv.get("StandardErrorContent") or ""
    if err.strip():
        sys.stderr.write(err[-3000:])
    print(f"\n[{inv['Status']}]", file=sys.stderr)
    if inv["Status"] != "Success":
        raise SystemExit(1)


def upload(args, path: Path) -> None:
    _ec2, ssm = clients()
    iid = load(path)["instance_id"]
    data = Path(args.local).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    b64 = base64.b64encode(data).decode()
    remote = args.remote
    tmp = remote + ".b64"
    pieces = [b64[i:i + CHUNK] for i in range(0, len(b64), CHUNK)]
    inv = run_cmd(ssm, iid, [f"mkdir -p $(dirname {remote}) && : > {tmp}"], 60)
    assert inv["Status"] == "Success", inv.get("StandardErrorContent")
    for i, piece in enumerate(pieces):
        inv = run_cmd(ssm, iid, [f"printf '%s' '{piece}' >> {tmp}"], 60)
        if inv["Status"] != "Success":
            raise SystemExit(f"chunk {i}: {inv['Status']} {inv.get('StandardErrorContent', '')[-300:]}")
    inv = run_cmd(ssm, iid, [f"base64 -d {tmp} > {remote} && rm -f {tmp} && echo '{digest}  {remote}' | sha256sum -c"],
                  120)
    print(f"{args.local} -> {remote}: {len(data)} bytes in {len(pieces)} chunks; "
          f"{(inv.get('StandardOutputContent') or '').strip()} [{inv['Status']}]")
    if inv["Status"] != "Success":
        raise SystemExit(1)


def terminate(args, path: Path) -> None:
    ec2, ssm = clients()
    state = load(path)
    iid = state.get("instance_id")
    if iid and not state.get("terminated"):
        ec2.terminate_instances(InstanceIds=[iid])
        ec2.get_waiter("instance_terminated").wait(InstanceIds=[iid], WaiterConfig={"Delay": 10, "MaxAttempts": 60})
        state["terminated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for name in list(state.get("documents") or []):
        try:
            ssm.delete_document(Name=name)
        except ssm.exceptions.InvalidDocument:
            pass
        state.setdefault("documents_deleted", []).append(name)
        state["documents"].remove(name)
    save(path, state)
    desc = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0] if iid else {}
    print(json.dumps({"instance_id": iid, "state": (desc.get("State") or {}).get("Name"),
                      "terminated": state.get("terminated"), "documents_deleted": state.get("documents_deleted")}))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", default="ec2-state.json")
    sub = ap.add_subparsers(dest="cmd", required=True)
    la = sub.add_parser("launch")
    la.add_argument("--minutes", type=int, default=120)
    la.add_argument("--type", default="t3.xlarge")
    la.add_argument("--disk-gb", type=int, default=30)
    wa = sub.add_parser("wait")
    wa.add_argument("--timeout", type=int, default=600)
    up = sub.add_parser("upload")
    up.add_argument("local")
    up.add_argument("remote")
    ru = sub.add_parser("run")
    ru.add_argument("command")
    ru.add_argument("--timeout", type=int, default=3600)
    sub.add_parser("terminate")
    args = ap.parse_args()
    if args.cmd == "launch" and not 10 <= args.minutes <= 180:
        raise SystemExit("--minutes must be 10..180 (ROUND7: hard self-destruct at most 180)")
    path = Path(args.state)
    {"launch": launch, "wait": wait, "upload": upload, "run": run, "terminate": terminate}[args.cmd](args, path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
