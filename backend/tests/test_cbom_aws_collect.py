"""AWS collector against moto (no network): safety checks and what each service turns into.

    cd backend && PYTHONPATH=.. uv run --with pytest --with 'moto[all]' python -m pytest tests/test_cbom_aws_collect.py -q
"""
from __future__ import annotations

import datetime as dt
import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

moto = pytest.importorskip("moto")
import boto3  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402

from backend.utilities.cbom_sources import aws_collect  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402

ACCOUNT = "123456789012"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/ZeroShieldCBOMReader"
EXTERNAL_ID = "zs-ext-AAAA-BBBB-CCCC-DDDD"


class _StsGuard:
    """moto does not evaluate trust policies; refuse AssumeRole without the external ID like AWS would."""

    def __init__(self, client, allow_without_external_id: bool):
        self._client, self._allow = client, allow_without_external_id

    def assume_role(self, **kwargs):
        if "ExternalId" not in kwargs and not self._allow:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "AssumeRole")
        return self._client.assume_role(**kwargs)

    def __getattr__(self, name):
        return getattr(self._client, name)


class _Session:
    def __init__(self, allow_without_external_id=False):
        self._s = boto3.session.Session(aws_access_key_id="zs", aws_secret_access_key="zs", region_name="us-east-1")
        self._allow = allow_without_external_id

    def client(self, service, **kwargs):
        client = self._s.client(service, **kwargs)
        return _StsGuard(client, self._allow) if service == "sts" else client


def _self_signed_pem(bits=1024):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legacy.example.com")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(9)
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=10))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("legacy.example.com")]), critical=False)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))


@pytest.fixture()
def aws(monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(k, "testing")
    with moto.mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(RoleName="ZeroShieldCBOMReader", AssumeRolePolicyDocument="{}")
        yield monkeypatch


def _run(monkeypatch, *, allow_without_external_id=False, regions=("us-east-1",)):
    monkeypatch.setattr(aws_collect, "_boto", lambda **kw: (_Session(allow_without_external_id), None))
    found = []
    result = aws_collect.collect_aws(1, {"role_arn": ROLE, "regions": list(regions), "scope": "account"}, EXTERNAL_ID,
                                     found.append, lambda: None)
    return result, found


def test_role_that_does_not_require_the_external_id_is_refused(aws):
    with pytest.raises(aws_collect.AwsCollectError, match="without the external ID"):
        _run(aws, allow_without_external_id=True)


def test_inventory_covers_kms_acm_s3_ebs_secrets(aws):
    kms = boto3.client("kms", region_name="us-east-1")
    sym = kms.create_key(Description="payments-data")["KeyMetadata"]["KeyId"]
    kms.create_key(Description="signing", KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")
    cert, key = _self_signed_pem(1024)
    boto3.client("acm", region_name="us-east-1").import_certificate(Certificate=cert, PrivateKey=key)
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="zs-lab-no-tls-policy")
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=False)
    boto3.client("secretsmanager", region_name="us-east-1").create_secret(Name="db/password", SecretString="never-read-7781")

    result, found = _run(aws)
    by_type: dict[str, list] = {}
    for asset in found:
        by_type.setdefault(asset["type"], []).append(asset)
    assert result["counts"]["total"] == 2 and result["counts"]["ok"] >= 1  # global + us-east-1
    keys = {a["facts"]["key_spec"]: a for a in by_type["kms_key"]}
    assert keys["SYMMETRIC_DEFAULT"]["facts"]["rotation_enabled"] is False and sym in keys["SYMMETRIC_DEFAULT"]["location"]
    assert classify("kms_key", "RSA_2048", 2048, None, keys["RSA_2048"]["facts"])["quantum_vulnerable"] is True
    acm = by_type["certificate"][0]
    assert acm["key_size"] == 1024 and acm["facts"]["in_use"] is False
    verdict = classify("certificate", acm["algorithm"], acm["key_size"], None, acm["facts"])
    assert verdict["impact"] == "High" and "RSA_LT_2048" in verdict["finding_codes"]
    bucket = next(a for a in by_type["storage_encryption"] if a["location"] == "arn:aws:s3:::zs-lab-no-tls-policy")
    assert bucket["facts"]["tls_only_policy"] is False
    volumes = [a for a in by_type["storage_encryption"] if ":volume/" in a["location"]]
    assert len(volumes) == 1 and volumes[0]["facts"]["encrypted"] is False
    secret = by_type["cloud_secret"][0]
    assert secret["facts"]["rotation_enabled"] is False
    assert "never-read-7781" not in repr(found)  # metadata only


def test_a_denied_service_becomes_a_coverage_gap_not_silence(aws, monkeypatch):
    real_client = boto3.session.Session.client

    def deny_secrets(self, service, *a, **k):
        client = real_client(self, service, *a, **k)
        if service == "secretsmanager":
            def denied(*_a, **_k):
                raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "SCP"}}, "ListSecrets")
            client.get_paginator = lambda *_a, **_k: type("P", (), {"paginate": denied})()
        return client

    monkeypatch.setattr(boto3.session.Session, "client", deny_secrets)
    result, found = _run(aws)
    gaps = [a for a in found if a["type"] == "coverage"]
    assert any(g["facts"]["status"] == "denied" and "secretsmanager" in g["facts"]["check"] for g in gaps)
    region = next(t for t in result["targets"] if t["target"].endswith("/us-east-1"))
    assert region["status"] == "error" and region["services"]["secretsmanager"] == "denied"
