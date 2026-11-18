"""F1.4 live KMS proof: wrap and unwrap an SSH CA key with a real AWS KMS customer-managed key.

Creates ONE symmetric KMS key tagged Project=DevSecShield, zs-lab=sandbox, zs-owner=f1-4; wraps a fresh CA key with
``sshca.keywrap`` (GenerateDataKey + AES-GCM, EncryptionContext team + CA fingerprint), unwraps it, checks that a
wrong team or CA in the context is refused by KMS, signs a certificate with the unwrapped key, then schedules the key
for deletion after the minimum 7 days.  Prints a JSON report (ids and outcomes only; no key material).

    cd backend && env -u AWS_SESSION_TOKEN sh -c '. $R6/secrets/aws-dev.env && uv run --frozen python \
        ../bench/f1_sshca/kms_live.py --ledger $R6/aws/ledger.txt --ledger-lock $L/aws-ledger.lock'
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "bench")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "bench")

import boto3  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from backend.utilities.cbom_sources.sshca import certs as C  # noqa: E402
from backend.utilities.cbom_sources.sshca import keywrap as KW  # noqa: E402

TAGS = [{"TagKey": "Project", "TagValue": "DevSecShield"}, {"TagKey": "zs-lab", "TagValue": "sandbox"},
        {"TagKey": "zs-owner", "TagValue": "f1-4"}]


def ledger(path: str | None, lock: str | None, line: str) -> None:
    if not path:
        return
    with open(lock or path + ".lock", "a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line.rstrip() + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", default=None)
    ap.add_argument("--ledger-lock", default=None)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    region = os.environ.get("AWS_DEFAULT_REGION") or "ap-south-1"
    kms = boto3.client("kms", region_name=region)
    now = dt.datetime.now(dt.timezone.utc)
    created = kms.create_key(Description="DevSecShield F1.4 SSH CA key-wrap proof (delete after test)",
                             KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT", Tags=TAGS)["KeyMetadata"]
    arn, key_id = created["Arn"], created["KeyId"]
    ledger(args.ledger, args.ledger_lock, f"{now:%Y-%m-%dT%H:%M:%SZ} f1-4 kms-key {arn} region={region} "
                                          f"tags=Project=DevSecShield,zs-lab=sandbox,zs-owner=f1-4 status=created")
    report: dict = {"region": region, "key_arn": arn, "created": now.isoformat()}
    try:
        os.environ[KW.KMS_ENV] = arn
        KW.set_kms_client_factory(lambda r: boto3.client("kms", region_name=r))
        ca_private = C.generate_ca_key("ed25519")
        public = C.public_line(ca_private)
        fp = C.fingerprint(public)
        wrapped = KW.wrap(C.private_to_openssh(ca_private), team_id=4242, ca_fingerprint=fp, key_wrap="aws_kms",
                          kms_key_ref=arn)
        doc = json.loads(wrapped.split(":", 1)[1])
        report["wrapped"] = {"scheme": wrapped.split(":", 1)[0], "fields": sorted(doc), "edk_bytes": len(doc["edk"]),
                             "contains_pem": "PRIVATE KEY" in wrapped}
        pem = KW.unwrap(wrapped, team_id=4242, ca_fingerprint=fp)
        unwrapped = C.private_from_openssh(pem)
        report["unwrap_matches_ca"] = C.fingerprint(C.public_line(unwrapped)) == fp
        refused = {}
        for label, team, ca_fp in (("other_team", 4243, fp), ("other_ca", 4242, "SHA256:not-this-ca")):
            try:
                KW.unwrap(wrapped, team_id=team, ca_fingerprint=ca_fp)
                refused[label] = "NOT REFUSED"
            except KW.WrapError as exc:
                refused[label] = str(exc)
        report["context_binding"] = refused
        node = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        start = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
        cert = C.sign_user_cert(unwrapped, node.decode(), serial=1, key_id="zs:kms-proof:1", principals=["zs-1-prod"],
                                valid_after=start, valid_before=start + dt.timedelta(minutes=5),
                                source_addresses=["10.0.0.5"])
        facts = C.read_cert(cert)
        report["certificate_signed_by_unwrapped_key"] = facts.signature_key_blob == C.public_blob(public)
    except KW.WrapError as exc:
        report["wrap_error"] = str(exc)  # e.g. the identity may create keys but not use them (AccessDenied)
    finally:
        try:
            deletion = kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
            state = kms.describe_key(KeyId=key_id)["KeyMetadata"]
            report["deletion"] = {"key_state": state["KeyState"], "deletion_date": str(deletion["DeletionDate"]),
                                  "pending_window_days": 7}
            status = f"status={state['KeyState']} deletion_date={deletion['DeletionDate']:%Y-%m-%dT%H:%M:%SZ}"
        except Exception as exc:  # noqa: BLE001 - recorded, never worked around
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
            report["deletion"] = {"key_state": "Enabled", "refused": code}
            status = f"status=Enabled deletion REFUSED ({code}): owner action needed"
        ledger(args.ledger, args.ledger_lock,
               f"{dt.datetime.now(dt.timezone.utc):%Y-%m-%dT%H:%M:%SZ} f1-4 kms-key {arn} {status}")
    text = json.dumps(report, indent=2, default=str)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n")
    assert "wrap_error" not in report, report["wrap_error"]
    assert report["unwrap_matches_ca"] and report["certificate_signed_by_unwrapped_key"]
    assert all(v != "NOT REFUSED" for v in report["context_binding"].values())
    assert report["deletion"]["key_state"] == "PendingDeletion"


if __name__ == "__main__":
    main()
