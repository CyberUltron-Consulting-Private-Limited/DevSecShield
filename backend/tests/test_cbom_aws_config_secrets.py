"""AWS collector: keys and secrets written into configuration (Lambda environment, ECS task definitions, EC2 user data)
and the full EBS inventory.  Stub clients, no network, no moto.

    cd backend && PYTHONPATH=.. .venv/bin/python -m pytest tests/test_cbom_aws_config_secrets.py -q
"""
from __future__ import annotations

import base64
import gzip
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from botocore.exceptions import ClientError  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402

from backend.utilities.cbom_sources import aws_collect  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402

REGION, ACCOUNT = "ap-south-1", "123456789012"


def _rsa_pem(bits=2048) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption()).decode()


def _ec_der_b64() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return base64.b64encode(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption())).decode()


RSA_PEM = _rsa_pem()
RSA_BODY = "".join(RSA_PEM.splitlines()[1:-1])  # base64 DER without the PEM armour, as people paste it into env vars
EC_B64 = _ec_der_b64()
PASSWORD = "Sup3r-Secret-Db-Pass-7781"


class _Pager:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **_kw):
        return iter(self.pages)


class _Client:
    def __init__(self, service, data):
        self.service, self.data = service, data

    def get_paginator(self, method):
        if (self.service, method) not in self.data:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "stub"}}, method)
        return _Pager(self.data[(self.service, method)])

    def __getattr__(self, method):
        if (self.service, method) not in self.data:
            def denied(**_kw):
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "stub"}}, method)
            return denied
        value = self.data[(self.service, method)]
        return value if callable(value) else (lambda **_kw: value)


class _Acct:
    account = ACCOUNT

    def __init__(self, data):
        self.data = data

    def client(self, service, _region):
        return _Client(service, self.data)


def _userdata(text: str, zipped=False) -> str:
    blob = text.encode()
    return base64.b64encode(gzip.compress(blob) if zipped else blob).decode()


def _data():
    fn_arn = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:legacy-signer"
    td_arn = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/legacy-task:3"
    script = f"#!/bin/bash\nexport APP_ENV=prod\nexport DB_PASSWORD='{PASSWORD}'\ncat > /etc/app/tls.key <<'EOF'\n{RSA_PEM}EOF\n"
    return {
        ("ec2", "get_ebs_encryption_by_default"): {"EbsEncryptionByDefault": False},
        ("ec2", "describe_volumes"): [{"Volumes": [
            {"VolumeId": "vol-plain", "Encrypted": False, "Size": 8},
            {"VolumeId": "vol-cmk", "Encrypted": True, "KmsKeyId": f"arn:aws:kms:{REGION}:{ACCOUNT}:key/abc", "Size": 20,
             "Attachments": [{"InstanceId": "i-1"}]}]}],
        ("lambda", "list_functions"): [{"Functions": [
            {"FunctionArn": fn_arn, "FunctionName": "legacy-signer", "Environment": {"Variables": {
                "SIGNING_KEY": RSA_BODY, "API_TOKEN": "tok_9f8e7d6c5b4a", "KMS_KEY_ID": "alias/app",
                "DB_SECRET_ARN": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:db", "LOG_LEVEL": "debug"}}},
            {"FunctionArn": fn_arn + "2", "FunctionName": "clean"}]}],
        ("ecs", "list_task_definitions"): [{"taskDefinitionArns": [td_arn]}],
        ("ecs", "describe_task_definition"): {"taskDefinition": {"family": "legacy-task", "revision": 3, "containerDefinitions": [
            {"name": "legacy", "environment": [{"name": "TLS_PRIVATE_KEY", "value": EC_B64}, {"name": "PORT", "value": "8443"}],
             "secrets": [{"name": "DB_PASSWORD", "valueFrom": f"arn:aws:ssm:{REGION}:{ACCOUNT}:parameter/db"}]}]}},
        ("ec2", "describe_instances"): [{"Reservations": [{"Instances": [
            {"InstanceId": "i-boot", "State": {"Name": "running"}},
            {"InstanceId": "i-gz", "State": {"Name": "running"}},
            {"InstanceId": "i-clean", "State": {"Name": "running"}},
            {"InstanceId": "i-gone", "State": {"Name": "terminated"}}]}]}],
        ("ec2", "describe_instance_attribute"): lambda InstanceId, Attribute: {"UserData": {"Value": {
            "i-boot": _userdata(script), "i-gz": _userdata(script, zipped=True),
            "i-clean": _userdata("#!/bin/bash\nyum -y install nginx\n")}.get(InstanceId)}},
    }


def _collect():
    found = []
    rows = aws_collect._region_services(_Acct(_data()), REGION, f"aws:{ACCOUNT}", found.append)
    return {svc: status for svc, status, _d in rows}, found


def test_every_ebs_volume_is_inventoried_with_its_kms_key():
    _status, found = _collect()
    vols = {a["name"]: a for a in found if a["type"] == "storage_encryption" and ":volume/" in a["location"]}
    assert set(vols) == {"vol-plain", "vol-cmk"}
    assert vols["vol-cmk"]["facts"]["encrypted"] is True and vols["vol-cmk"]["facts"]["kms_key_id"].endswith("key/abc")
    assert vols["vol-cmk"]["facts"]["attached_to"] == ["i-1"]
    assert classify("storage_encryption", None, None, None, vols["vol-cmk"]["facts"])["finding_codes"] == []
    assert "STORAGE_UNENCRYPTED" in classify("storage_encryption", None, None, None, vols["vol-plain"]["facts"])["finding_codes"]


def test_lambda_environment_keys_and_tokens_are_found_by_shape_only():
    status, found = _collect()
    assert status["lambda"] == "ok"
    fn = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:legacy-signer"
    by_loc = {a["location"]: a for a in found}
    key = by_loc[f"{fn}#environment/SIGNING_KEY"]
    assert key["type"] == "private_key" and key["algorithm"] == "RSA" and key["key_size"] == 2048
    assert key["facts"]["encoding"] == "base64-der" and key["facts"]["plaintext_in_cloud_config"] is True
    verdict = classify("private_key", key["algorithm"], key["key_size"], None, key["facts"])
    assert "SECRET_IN_CONFIG" in verdict["finding_codes"] and verdict["impact"] == "High" and verdict["quantum_vulnerable"] is True
    token = by_loc[f"{fn}#environment/API_TOKEN"]
    assert token["type"] == "cloud_secret" and token["facts"]["length"] == len("tok_9f8e7d6c5b4a")
    assert "SECRET_IN_CONFIG" in classify("cloud_secret", None, None, None, token["facts"])["finding_codes"]
    # references, identifiers and ordinary settings are not secrets
    for var in ("KMS_KEY_ID", "DB_SECRET_ARN", "LOG_LEVEL"):
        assert f"{fn}#environment/{var}" not in by_loc


def test_ecs_task_definition_environment_and_not_valuefrom_secrets():
    status, found = _collect()
    assert status["ecs"] == "ok"
    td = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/legacy-task:3"
    hits = [a for a in found if a["location"].startswith(td)]
    assert [a["location"] for a in hits] == [f"{td}#containerDefinitions/legacy/environment/TLS_PRIVATE_KEY"]
    assert hits[0]["type"] == "private_key" and hits[0]["algorithm"] == "ECDSA" and hits[0]["key_size"] == 256


def test_ec2_user_data_plain_and_gzip_with_line_numbers():
    status, found = _collect()
    assert status["ec2-userdata"] == "ok"
    by_loc = {a["location"]: a for a in found if a["location"].endswith("#userData")}
    assert set(by_loc) == {f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-boot#userData",
                           f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-gz#userData"}
    asset = by_loc[f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-boot#userData"]
    assert asset["type"] == "private_key" and asset["key_size"] == 2048 and asset["facts"]["line"] == 5
    items = asset["facts"]["items"]
    assert {"material": "secret", "variable": "DB_PASSWORD", "line": 3, "encoding": "text", "length": len(PASSWORD)} in items
    assert any(i.get("material") == "private-key" and i.get("key_bits") == 2048 for i in items)


def test_no_value_ever_leaves_the_collector():
    _status, found = _collect()
    dump = repr(found)
    for secret in (PASSWORD, "tok_9f8e7d6c5b4a", RSA_BODY[40:80], EC_B64[40:80], "BEGIN RSA PRIVATE KEY"):
        assert secret not in dump


def test_value_shape_rules():
    shape = aws_collect._value_shape
    assert shape("TLS_KEY", RSA_PEM)["pem_label"] == "RSA PRIVATE KEY"
    assert shape("ANYTHING", RSA_PEM.replace("\n", "\\n"))["key_bits"] == 2048  # escaped newlines as in JSON env
    assert shape("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")["material"] == "secret"
    assert shape("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE") is None
    assert shape("PASSWORD", "${DB_PASSWORD}") is None and shape("PASSWORD", "changeme") is None
    assert shape("PASSWORD", "short") is None and shape("TIMEOUT", "a-long-but-harmless-value") is None
    assert shape("CERT", "MII" + "A" * 400) is None  # base64 that is not a private key


def test_denied_services_become_coverage_gaps():
    found = []
    rows = aws_collect._region_services(_Acct({}), REGION, f"aws:{ACCOUNT}", found.append)
    status = {svc: s for svc, s, _d in rows}
    assert status["lambda"] == status["ecs"] == status["ec2-userdata"] == "denied"
    assert {g["facts"]["check"] for g in found if g["type"] == "coverage"} >= {f"lambda in {REGION}", f"ecs in {REGION}",
                                                                               f"ec2-userdata in {REGION}"}
