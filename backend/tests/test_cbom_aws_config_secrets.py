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
    script = (f"#!/bin/bash\nexport APP_ENV=prod\nexport DB_PASSWORD='{PASSWORD}'\ncat > /etc/app/tls.key <<'EOF'\n{RSA_PEM}EOF\n"
              "REDIS_PASSWORD=$REDIS_PASSWORD\nJWT_SECRET=\"$(aws secretsmanager get-secret-value --secret-id jwt)\"\n")
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
            {"FunctionArn": fn_arn + "2", "FunctionName": "clean"},
            {"FunctionArn": fn_arn + "3", "FunctionName": "cmk-env",
             "Environment": {"Error": {"ErrorCode": "AccessDeniedException", "Message": "KMS decrypt denied"}}}]}],
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
    assert not any(i.get("variable") in ("REDIS_PASSWORD", "JWT_SECRET") for i in items)  # references, not values


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
    # shell / batch variable references in bootstrap scripts (seen in the lab account: REDIS_PASSWORD=$REDIS_PASSWORD)
    assert shape("REDIS_PASSWORD", "$REDIS_PASSWORD") is None and shape("DB_PASSWORD", "%DB_PASSWORD%") is None
    assert shape("PASSWORD", "short") is None and shape("TIMEOUT", "a-long-but-harmless-value") is None
    assert shape("CERT", "MII" + "A" * 400) is None  # base64 that is not a private key


def _public_material():
    """An RSA public key (PEM, SPKI) and a self-signed certificate, as people paste them into environment variables."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.example.test")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(7)
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    return pub, cert.public_bytes(serialization.Encoding.PEM).decode()


PUBLIC_PEM, CERT_PEM = _public_material()
# Review round 5, M3: values the classifier reported as SECRET_IN_CONFIG (High) although none is a secret
NOT_SECRETS = {
    "JWT_PUBLIC_KEY": PUBLIC_PEM.replace("\n", "\\n"),           # a public key (JSON-escaped newlines)
    "SAML_IDP_CERT": CERT_PEM,                                   # a certificate
    "STRIPE_PUBLISHABLE_KEY": "pk_live_51HqLyjWDarjtT1zdp7dcAAAAAAAAAAAA",
    "STRIPE_KEY": "pk_test_51HqLyjWDarjtT1zdp7dcAAAAAAAAAAAA",  # publishable by its value
    "DB_SECRET": "prod/rds/app-user",                            # a Secrets Manager secret name
    "KMS_KEY": f"arn:aws:kms:{REGION}:{ACCOUNT}:key/1234abcd-12ab-34cd-56ef-1234567890ab",
    "APP_KMS_KEY": "1234abcd-12ab-34cd-56ef-1234567890ab",       # a KMS key id: KMS key material never leaves KMS
    "TOKEN_AUDIENCE": "api.example.com",
    "S3_KEY_PREFIX": "uploads/2024/",
    "API_KEY_HEADER": "X-Api-Key",
}


def test_public_material_references_and_settings_are_not_secrets():
    shape = aws_collect._value_shape
    for var, value in NOT_SECRETS.items():
        got = shape(var, value)
        assert got is None or got["material"] in ("public-key", "certificate"), (var, got)
    assert shape("JWT_PUBLIC_KEY", NOT_SECRETS["JWT_PUBLIC_KEY"]) == {
        "material": "public-key", "encoding": "pem", "algorithm": "RSA", "key_bits": 2048}
    ssh = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ops@example"
    assert shape("DEPLOY_KEY", ssh)["material"] == "public-key" and shape("DEPLOY_KEY", ssh)["algorithm"] == "ED25519"
    cert = shape("SAML_IDP_CERT", CERT_PEM)
    assert cert["material"] == "certificate" and cert["subject"] == "CN=idp.example.test" and cert["key_bits"] == 2048
    # still secrets: real values under the same kinds of names, a private key in a 'public' variable, a mixed-case
    # AWS secret access key with '/', and a secret key next to its publishable one
    assert shape("DB_PASSWORD", PASSWORD)["material"] == "secret"
    assert shape("STRIPE_SECRET_KEY", "sk_live_51HqLyjWDarjtT1zdp7dcAAAAAAAAAAAA")["material"] == "secret"
    assert shape("JWT_PUBLIC_KEY", RSA_PEM)["material"] == "private-key"
    assert shape("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")["material"] == "secret"
    assert shape("TOKEN_SECRET", "UPPER/Case/Mixed-Secret-9")["material"] == "secret"


def test_lambda_public_material_becomes_inventory_and_never_a_secret_finding():
    fn = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:reviewer-env"
    data = {**_data(), ("lambda", "list_functions"): [{"Functions": [
        {"FunctionArn": fn, "FunctionName": "reviewer-env", "Environment": {"Variables": {
            **NOT_SECRETS, "DB_PASSWORD": PASSWORD}}}]}]}
    found = []
    aws_collect._region_services(_Acct(data), REGION, f"aws:{ACCOUNT}", found.append)
    by_var = {a["location"].rsplit("/", 1)[-1]: a for a in found if a["location"].startswith(f"{fn}#environment/")}
    assert set(by_var) == {"JWT_PUBLIC_KEY", "SAML_IDP_CERT", "DB_PASSWORD"}
    pub, cert, pw = by_var["JWT_PUBLIC_KEY"], by_var["SAML_IDP_CERT"], by_var["DB_PASSWORD"]
    assert (pub["type"], pub["algorithm"], pub["key_size"]) == ("public_key", "RSA", 2048)
    assert cert["type"] == "certificate" and cert["facts"]["not_after"]
    for row in (pub, cert):
        assert "plaintext_in_cloud_config" not in row["facts"]
        verdict = classify(row["type"], row["algorithm"], row["key_size"], None, row["facts"])
        assert "SECRET_IN_CONFIG" not in verdict["finding_codes"] and verdict["quantum_vulnerable"] is True, row["type"]
    assert "SECRET_IN_CONFIG" in classify("cloud_secret", None, None, None, pw["facts"])["finding_codes"]
    dump = repr(found)
    assert PASSWORD not in dump and "BEGIN PUBLIC KEY" not in dump and "BEGIN CERTIFICATE" not in dump


def test_denied_services_become_coverage_gaps():
    found = []
    rows = aws_collect._region_services(_Acct({}), REGION, f"aws:{ACCOUNT}", found.append)
    status = {svc: s for svc, s, _d in rows}
    assert status["lambda"] == status["ecs"] == status["ec2-userdata"] == "denied"
    assert {g["facts"]["check"] for g in found if g["type"] == "coverage"} >= {f"lambda in {REGION}", f"ecs in {REGION}",
                                                                               f"ec2-userdata in {REGION}"}


def test_lambda_environment_that_cannot_be_decrypted_is_a_coverage_gap():
    # the reader's deny on kms:Decrypt also blocks Lambda from decrypting variables for it (seen in the AWS lab)
    _status, found = _collect()
    gaps = [a for a in found if a["type"] == "coverage" and a["location"].endswith("legacy-signer3#environment")]
    assert len(gaps) == 1 and gaps[0]["facts"]["status"] == "denied" and "AccessDenied" in gaps[0]["facts"]["detail"]
