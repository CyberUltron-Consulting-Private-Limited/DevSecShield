"""Read-only AWS inventory of cryptographic configuration for one customer account (or organisation).

Runs in the cloud worker.  Safety rules, all checked before anything is read:
* only ZeroShield's own principal (CBOM_AWS_*) is used, never ambient credentials;
* the role must REFUSE AssumeRole without the team's external ID (confused-deputy protection);
* the assumed identity must be in the account named by the role ARN.
Every service is read in its own try block: AccessDenied, a disabled opt-in region or throttling
becomes a ``coverage`` asset and a target row, never a silent "nothing found".
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import time
from typing import Any, Callable

from backend.utilities.cbom_sources.aws_validate import _boto, _code
from backend.utilities.cbom_sources.common import log, new_ref
from backend.utilities.cbom_sources.idp_collect import saml_assets_from_xml
from backend.utilities.cbom_sources.kinds import aws_account_id

PER_SERVICE_CAP = 1000
GLOBAL_REGION = "us-east-1"
_DENIED = ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError",
           "AuthorizationErrorException")
_NOT_ENABLED = ("OptInRequired", "UnrecognizedClientException", "InvalidClientTokenId", "AuthFailure")

Emit = Callable[[dict[str, Any]], None]


class AwsCollectError(Exception):
    """``str(err)`` is safe to show."""


def _iso(value: Any) -> str | None:
    if isinstance(value, _dt.datetime):
        if value.tzinfo is not None:
            value = value.astimezone(_dt.timezone.utc).replace(tzinfo=None)
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def _bits(spec: str | None) -> int | None:
    match = re.search(r"(\d{3,5})", spec or "")
    if match:
        return int(match.group(1))
    curve = {"P256": 256, "P384": 384, "P521": 521, "SECG_P256K1": 256, "PRIME256V1": 256, "SECP384R1": 384}
    for name, bits in curve.items():
        if name in (spec or "").upper().replace("_", ""):
            return bits
    return None


class _Account:
    """Assumed-role session for one account, re-assumed before the 1-hour credentials expire."""

    def __init__(self, base, cfg, role_arn: str, external_id: str, team_id: int):
        self.base, self.cfg, self.role_arn, self.external_id, self.team_id = base, cfg, role_arn, external_id, team_id
        self.account = aws_account_id(role_arn)
        self.session = None
        self.expires = 0.0

    def assume(self, region: str) -> None:
        import boto3

        sts = self.base.client("sts", region_name=region, config=self.cfg)
        out = sts.assume_role(RoleArn=self.role_arn, RoleSessionName=f"zs-cbom-collect-{self.team_id}"[:64],
                              ExternalId=self.external_id, DurationSeconds=3600)
        creds = out["Credentials"]
        self.session = boto3.session.Session(aws_access_key_id=creds["AccessKeyId"],
                                             aws_secret_access_key=creds["SecretAccessKey"],
                                             aws_session_token=creds["SessionToken"])
        self.expires = time.monotonic() + 3300  # re-assume 5 minutes early
        who = self.session.client("sts", region_name=region, config=self.cfg).get_caller_identity()
        if str(who.get("Account")) != str(self.account):
            raise AwsCollectError("The assumed role is not in the account named by its ARN")

    def client(self, service: str, region: str):
        if self.session is None or time.monotonic() > self.expires:
            self.assume(region if region != "global" else GLOBAL_REGION)
        return self.session.client(service, region_name=GLOBAL_REGION if region == "global" else region, config=self.cfg)


def _paginate(client, method: str, key: str, cap: int = PER_SERVICE_CAP, **kwargs) -> tuple[list[Any], bool]:
    out: list[Any] = []
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**kwargs):
        out.extend(page.get(key) or [])
        if len(out) >= cap:
            return out[:cap], True
    return out, False


def _cert_asset(arn: str, label: str, detail: dict[str, Any], kind: str = "certificate") -> dict[str, Any]:
    key_alg = detail.get("KeyAlgorithm") or ""
    family = "RSA" if key_alg.upper().startswith("RSA") else ("ECDSA" if key_alg.upper().startswith("EC") else key_alg)
    in_use = detail.get("InUseBy")
    return {"type": kind, "target": label, "location": arn, "name": detail.get("DomainName") or arn.rsplit("/", 1)[-1],
            "algorithm": family or None, "key_size": _bits(key_alg),
            "facts": {"subject": detail.get("Subject"), "issuer": detail.get("Issuer"), "serial": detail.get("Serial"),
                      "not_before": _iso(detail.get("NotBefore")), "not_after": _iso(detail.get("NotAfter")),
                      "sig_alg": detail.get("SignatureAlgorithm"), "key_alg": family, "key_size": _bits(key_alg),
                      "san": (detail.get("SubjectAlternativeNames") or [])[:50], "status": detail.get("Status"),
                      "aws_type": detail.get("Type"), "in_use": bool(in_use) if in_use is not None else None,
                      "in_use_by": (in_use or [])[:10], "renewal_eligibility": detail.get("RenewalEligibility"),
                      "source": "aws", "identity": arn}}


_SECRET_NAME = re.compile(r"(private|secret|passw|pwd|token|api[-_]?key|credential|tls[-_]?key|ssh[-_]?key|"
                          r"(^|[/_.-])key($|[/_.-]))", re.I)


# --- secrets written into configuration (Lambda environment, ECS task definitions, EC2 user data) -----------------
# The value is inspected in memory and only its shape leaves this module: material (private key / secret), encoding,
# length, and for a private key its algorithm and size.  Nothing that could rebuild the value is ever emitted.
_PEM_KEY = re.compile(r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----.*?-----END \1-----", re.S)
_DER_B64 = re.compile(r"MI[A-Za-z0-9+/]{100,}={0,2}")  # a DER SEQUENCE; kept only if it parses as a private key
_ENV_SECRET_NAME = re.compile(r"(KEY|SECRET|PASSWORD|PASSWD|PASSPHRASE|TOKEN|CREDENTIAL)", re.I)
_ENV_NOT_SECRET = re.compile(r"(_FILE|_PATH|_DIR|_ID|_URL|_URI|_NAME|_ARN|_ALIAS|_TYPE|_SIZE|_LEN|_BITS|_ALG|_REGION|_ENABLED)$", re.I)
_REFERENCE = ("arn:", "{{resolve:", "${", "$(", "ssm:", "secretsmanager:", "s3://", "/", "file:", "alias/", "http://", "https://")
_USERDATA_ASSIGN = re.compile(r"^\s*(?:export\s+|set\s+|\$env:)?([A-Za-z_][A-Za-z0-9_]{0,127})\s*=\s*(.+?)\s*$")
CONFIG_SCAN_CAP = 300  # functions / task definitions / instances read per region


def _key_shape(data: bytes, label: str | None) -> tuple[str | None, int | None]:
    """Algorithm and size of a private key held in memory; (None, None) when it is encrypted or unreadable."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

    try:
        if label == "OPENSSH PRIVATE KEY":
            key = serialization.load_ssh_private_key(data, password=None)
        elif label is None:
            key = serialization.load_der_private_key(data, password=None)
        else:
            key = serialization.load_pem_private_key(data, password=None)
    except Exception:
        return None, None
    if isinstance(key, rsa.RSAPrivateKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return "ECDSA", key.curve.key_size
    if isinstance(key, dsa.DSAPrivateKey):
        return "DSA", key.key_size
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "ED25519", 256
    if isinstance(key, ed448.Ed448PrivateKey):
        return "ED448", 456
    return None, None


def _value_shape(name: str, value: Any) -> dict[str, Any] | None:
    """What a configuration value holds -- never the value.  None when it is neither key material nor a secret."""
    import base64

    text = str(value or "").strip().replace("\\n", "\n")  # JSON-escaped newlines, as keys are often pasted
    if not text:
        return None
    pem = _PEM_KEY.search(text)
    if pem:
        label = pem.group(1)
        alg, bits = _key_shape(pem.group(0).encode(), label)
        return {"material": "private-key", "encoding": "pem", "pem_label": label, "algorithm": alg, "key_bits": bits,
                "passphrase_protected": "ENCRYPTED" in label or "Proc-Type: 4,ENCRYPTED" in pem.group(0) or None}
    compact = re.sub(r"\s+", "", text)
    if _DER_B64.fullmatch(compact):
        try:
            der = base64.b64decode(compact + "=" * (-len(compact) % 4))
        except Exception:
            der = b""
        alg, bits = _key_shape(der, None) if der else (None, None)
        if alg:
            return {"material": "private-key", "encoding": "base64-der", "algorithm": alg, "key_bits": bits}
    if not _ENV_SECRET_NAME.search(name) or _ENV_NOT_SECRET.search(name):
        return None
    if text.startswith(_REFERENCE) or text.lower() in ("true", "false", "none", "null", "changeme", "placeholder") \
            or len(text) < 8 or text.isdigit():
        return None
    return {"material": "secret", "encoding": "text", "length": len(text)}


def _embedded_asset(label: str, location: str, name: str, shape: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any]:
    """A private key becomes a private_key asset; any other secret a cloud_secret.  Both carry the store, never the value."""
    facts = {**facts, **{k: v for k, v in shape.items() if v is not None}, "plaintext_in_cloud_config": True,
             "identity": location}
    if shape["material"] == "private-key":
        return {"type": "private_key", "target": label, "location": location, "name": name,
                "algorithm": shape.get("algorithm"), "key_size": shape.get("key_bits"),
                "facts": {**facts, "encrypted": bool(shape.get("passphrase_protected")) if shape.get("algorithm") else None}}
    return {"type": "cloud_secret", "target": label, "location": location, "name": name, "facts": facts}


def _userdata_shapes(raw: str) -> list[dict[str, Any]]:
    """EC2 user data (base64, possibly gzip) -> shapes of the key material and secret assignments it contains, with lines."""
    import base64
    import gzip

    try:
        blob = base64.b64decode(raw)
        if blob[:2] == b"\x1f\x8b":
            blob = gzip.decompress(blob)[:262144]
        text = blob[:262144].decode("utf-8", "replace")
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for pem in _PEM_KEY.finditer(text):
        shape = _value_shape("", pem.group(0)) or {}
        out.append({**shape, "line": text.count("\n", 0, pem.start()) + 1})
    covered = [(m.start(), m.end()) for m in _PEM_KEY.finditer(text)]
    offset = 0
    for number, line in enumerate(text.splitlines(), 1):
        start = offset
        offset += len(line) + 1
        if any(a <= start < b for a, b in covered):
            continue
        m = _USERDATA_ASSIGN.match(line)
        if not m:
            continue
        shape = _value_shape(m.group(1), m.group(2).strip().strip("'\""))
        if shape:
            out.append({**shape, "variable": m.group(1), "line": number})
    return out[:50]


def _ssh_public_bits(public_key: str) -> int | None:
    """RSA modulus size from an OpenSSH public key line ("ssh-rsa AAAA... comment")."""
    import base64
    import struct

    try:
        blob = base64.b64decode(public_key.split()[1])
        parts, i = [], 0
        while i < len(blob) and len(parts) < 3:
            (n,) = struct.unpack(">I", blob[i:i + 4])
            parts.append(blob[i + 4:i + 4 + n])
            i += 4 + n
        if parts[0] != b"ssh-rsa":
            return None
        return int.from_bytes(parts[2], "big").bit_length()
    except Exception:
        return None


def _tls_protocol_names(values: list[str]) -> list[str]:
    out = []
    for value in values:
        text = str(value)
        out.append({"TLSv1": "TLSv1.0", "SSLv3": "SSLv3"}.get(text, text))
    return out


def _region_services(acct: _Account, region: str, label: str, emit: Emit) -> list[tuple[str, str, str | None]]:
    """Read every regional service.  Returns (service, status, detail) rows."""
    rows: list[tuple[str, str, str | None]] = []
    arn_prefix = f"arn:aws:{{svc}}:{region}:{acct.account}"

    def run(service: str, fn: Callable[[], str | None]) -> None:
        try:
            note = fn()
            rows.append((service, "ok", note))
        except AwsCollectError:
            raise
        except Exception as exc:  # one service failing never stops the others
            code = _code(exc)
            status = "denied" if code in _DENIED else ("not_enabled" if code in _NOT_ENABLED else "error")
            rows.append((service, status, code))
            emit({"type": "coverage", "target": label, "location": f"{arn_prefix.format(svc=service)}:{service}",
                  "facts": {"check": f"{service} in {region}", "status": status, "detail": code}})

    def kms() -> str | None:
        client = acct.client("kms", region)
        keys, truncated = _paginate(client, "list_keys", "Keys")
        for key in keys:
            meta = client.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            spec = meta.get("KeySpec") or meta.get("CustomerMasterKeySpec")
            rotation = None
            if meta.get("KeyManager") == "CUSTOMER" and spec == "SYMMETRIC_DEFAULT" and meta.get("KeyState") == "Enabled":
                try:
                    rotation = bool(client.get_key_rotation_status(KeyId=key["KeyId"]).get("KeyRotationEnabled"))
                except Exception as exc:  # e.g. imported key material
                    rotation = None if _code(exc) not in _DENIED else None
            emit({"type": "kms_key", "target": label, "location": meta["Arn"], "name": meta.get("Description") or meta["KeyId"],
                  "algorithm": spec, "key_size": 256 if spec == "SYMMETRIC_DEFAULT" else _bits(spec),
                  "facts": {"key_spec": spec, "key_usage": meta.get("KeyUsage"), "key_manager": meta.get("KeyManager"),
                            "key_state": meta.get("KeyState"), "origin": meta.get("Origin"),
                            "multi_region": meta.get("MultiRegion"), "rotation_enabled": rotation,
                            "signing_algorithms": meta.get("SigningAlgorithms"), "identity": meta["Arn"]}})
        return "truncated" if truncated else None

    def acm() -> str | None:
        client = acct.client("acm", region)
        everything = {"keyTypes": ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"]}
        summaries, truncated = _paginate(client, "list_certificates", "CertificateSummaryList", Includes=everything)
        for summary in summaries:
            detail = client.describe_certificate(CertificateArn=summary["CertificateArn"])["Certificate"]
            emit(_cert_asset(summary["CertificateArn"], label, detail))
        return "truncated" if truncated else None

    def pca() -> str | None:
        client = acct.client("acm-pca", region)
        cas, truncated = _paginate(client, "list_certificate_authorities", "CertificateAuthorities")
        for ca in cas:
            cfg = ca.get("CertificateAuthorityConfiguration") or {}
            key_alg = cfg.get("KeyAlgorithm") or ""
            emit({"type": "cloud_ca", "target": label, "location": ca["Arn"],
                  "name": json.dumps(cfg.get("Subject") or {})[:255], "algorithm": "RSA" if key_alg.startswith("RSA") else "ECDSA",
                  "key_size": _bits(key_alg),
                  "facts": {"key_alg": key_alg, "sig_alg": cfg.get("SigningAlgorithm"), "status": ca.get("Status"),
                            "ca_type": ca.get("Type"), "not_after": _iso(ca.get("NotAfter")),
                            "not_before": _iso(ca.get("NotBefore")), "is_ca": True, "source": "aws", "identity": ca["Arn"]}})
        return "truncated" if truncated else None

    def secrets() -> str | None:
        client = acct.client("secretsmanager", region)
        items, truncated = _paginate(client, "list_secrets", "SecretList")
        for item in items:  # metadata only; GetSecretValue is denied by the role and never called
            emit({"type": "cloud_secret", "target": label, "location": item["ARN"], "name": item.get("Name"),
                  "facts": {"rotation_enabled": bool(item.get("RotationEnabled")), "kms_key_id": item.get("KmsKeyId") or "aws/secretsmanager",
                            "last_rotated": _iso(item.get("LastRotatedDate")), "identity": item["ARN"]}})
        return "truncated" if truncated else None

    def ebs() -> str | None:
        client = acct.client("ec2", region)
        default = bool(client.get_ebs_encryption_by_default().get("EbsEncryptionByDefault"))
        emit({"type": "storage_encryption", "target": label, "location": f"arn:aws:ec2:{region}:{acct.account}:ebs-encryption-by-default",
              "name": f"EBS encryption by default ({region})", "facts": {"resource": "EBS default", "default_encryption": default}})
        volumes, truncated = _paginate(client, "describe_volumes", "Volumes")
        plain = [v for v in volumes if not v.get("Encrypted")]
        # every volume is inventory (encrypted ones with their KMS key); unencrypted ones first so the cap never hides them
        for volume in (plain + [v for v in volumes if v.get("Encrypted")])[:PER_SERVICE_CAP]:
            encrypted = bool(volume.get("Encrypted"))
            attached = [a.get("InstanceId") for a in volume.get("Attachments") or [] if a.get("InstanceId")]
            emit({"type": "storage_encryption", "target": label,
                  "location": f"arn:aws:ec2:{region}:{acct.account}:volume/{volume['VolumeId']}", "name": volume["VolumeId"],
                  "facts": {"resource": f"EBS volume {volume['VolumeId']}", "encrypted": encrypted, "size_gib": volume.get("Size"),
                            "kms_key_id": volume.get("KmsKeyId") if encrypted else None, "volume_type": volume.get("VolumeType"),
                            "attached_to": attached[:5], "identity": volume["VolumeId"]}})
        return f"{len(volumes)} volumes, {len(plain)} unencrypted" + (" (truncated)" if truncated else "")

    def lambdas() -> str | None:
        # ListFunctions returns each function's environment; values are inspected here and only their shape is kept.
        # Variables under a customer-managed key come back as an error (kms:Decrypt is denied) and are not readable.
        client = acct.client("lambda", region)
        functions, truncated = _paginate(client, "list_functions", "Functions", cap=CONFIG_SCAN_CAP)
        hits = 0
        for fn in functions:
            env = fn.get("Environment") or {}
            for var, value in sorted((env.get("Variables") or {}).items()):
                shape = _value_shape(var, value)
                if not shape:
                    continue
                hits += 1
                emit(_embedded_asset(label, f"{fn['FunctionArn']}#environment/{var}", f"{fn.get('FunctionName')} env {var}", shape,
                                     {"service": "lambda", "store": f"Lambda function {fn.get('FunctionName')} environment",
                                      "variable": var, "kms_key_id": fn.get("KMSKeyArn") or "aws/lambda"}))
        return f"{len(functions)} functions, {hits} secrets in environment" + (" (truncated)" if truncated else "")

    def ecs_taskdefs() -> str | None:
        # Active task definitions: plain `environment` entries are checked; `secrets` (valueFrom references) are fine.
        client = acct.client("ecs", region)
        arns, truncated = _paginate(client, "list_task_definitions", "taskDefinitionArns", cap=CONFIG_SCAN_CAP, status="ACTIVE")
        hits = 0
        for arn in arns:
            td = client.describe_task_definition(taskDefinition=arn).get("taskDefinition") or {}
            for container in td.get("containerDefinitions") or []:
                for item in container.get("environment") or []:
                    var = str(item.get("name") or "")
                    shape = _value_shape(var, item.get("value"))
                    if not shape:
                        continue
                    hits += 1
                    family = f"{td.get('family')}:{td.get('revision')}"
                    emit(_embedded_asset(label, f"{arn}#containerDefinitions/{container.get('name')}/environment/{var}",
                                         f"{family} {container.get('name')} env {var}", shape,
                                         {"service": "ecs", "store": f"ECS task definition {family} container {container.get('name')}",
                                          "variable": var}))
        return f"{len(arns)} task definitions, {hits} secrets in environment" + (" (truncated)" if truncated else "")

    def userdata() -> str | None:
        # DescribeInstanceAttribute(userData): bootstrap scripts often carry keys; only shapes and line numbers are kept.
        client = acct.client("ec2", region)
        reservations, truncated = _paginate(client, "describe_instances", "Reservations", cap=CONFIG_SCAN_CAP)
        instances = [i for r in reservations for i in r.get("Instances") or []
                     if (i.get("State") or {}).get("Name") not in ("terminated", "shutting-down")][:CONFIG_SCAN_CAP]
        hits = 0
        for inst in instances:
            raw = ((client.describe_instance_attribute(InstanceId=inst["InstanceId"], Attribute="userData")
                    .get("UserData") or {}).get("Value")) or ""
            shapes = _userdata_shapes(raw) if raw else []
            if not shapes:
                continue
            hits += 1
            primary = next((s for s in shapes if s.get("material") == "private-key"), shapes[0])
            items = [{k: s.get(k) for k in ("material", "algorithm", "key_bits", "variable", "line", "encoding", "length") if s.get(k)}
                     for s in shapes]
            emit(_embedded_asset(label, f"arn:aws:ec2:{region}:{acct.account}:instance/{inst['InstanceId']}#userData",
                                 f"{inst['InstanceId']} user data", {k: v for k, v in primary.items() if k not in ("line", "variable")},
                                 {"service": "ec2", "store": f"EC2 instance {inst['InstanceId']} user data",
                                  "line": primary.get("line"), "items": items}))
        return f"{len(instances)} instances, {hits} with secrets in user data" + (" (truncated)" if truncated else "")

    def rds() -> str | None:
        client = acct.client("rds", region)
        dbs, truncated = _paginate(client, "describe_db_instances", "DBInstances")
        for db in dbs:
            emit({"type": "storage_encryption", "target": label, "location": db["DBInstanceArn"], "name": db["DBInstanceIdentifier"],
                  "facts": {"resource": f"RDS {db.get('Engine')} {db['DBInstanceIdentifier']}", "encrypted": bool(db.get("StorageEncrypted")),
                            "kms_key_id": db.get("KmsKeyId"), "engine": db.get("Engine")}})
            details = db.get("CertificateDetails") or {}
            ca_id = details.get("CAIdentifier") or db.get("CACertificateIdentifier")
            if ca_id:
                emit({"type": "cloud_ca", "target": label, "location": f"{db['DBInstanceArn']}#ca", "name": ca_id,
                      "algorithm": "ECDSA" if "ecc" in ca_id else "RSA", "key_size": 384 if "ecc384" in ca_id else (4096 if "rsa4096" in ca_id else 2048),
                      "facts": {"not_after": _iso(details.get("ValidTill")), "is_ca": True, "source": "aws", "identity": ca_id}})
        return "truncated" if truncated else None

    def elbv2() -> str | None:
        client = acct.client("elbv2", region)
        lbs, truncated = _paginate(client, "describe_load_balancers", "LoadBalancers")
        policies: dict[str, dict[str, Any]] = {}
        for lb in lbs:
            listeners, _t = _paginate(client, "describe_listeners", "Listeners", LoadBalancerArn=lb["LoadBalancerArn"])
            for listener in listeners:
                proto = listener.get("Protocol")
                if proto not in ("HTTPS", "TLS"):
                    if proto == "HTTP":
                        emit({"type": "load_balancer_tls", "target": label, "location": listener["ListenerArn"],
                              "name": f"{lb['LoadBalancerName']}:{listener.get('Port')}", "protocol": "HTTP",
                              "facts": {"tls": False, "port": listener.get("Port")}})
                    continue
                name = listener.get("SslPolicy")
                if name and name not in policies:
                    found = client.describe_ssl_policies(Names=[name]).get("SslPolicies") or [{}]
                    policies[name] = found[0]
                policy = policies.get(name or "", {})
                ciphers = [c.get("Name") for c in policy.get("Ciphers") or [] if c.get("Name")]
                emit({"type": "load_balancer_tls", "target": label, "location": listener["ListenerArn"],
                      "name": f"{lb['LoadBalancerName']}:{listener.get('Port')}", "protocol": proto,
                      "facts": {"ssl_policy": name, "protocols": _tls_protocol_names(policy.get("SslProtocols") or []),
                                "ciphers": ciphers[:100],
                                "static_rsa_kex": any(not c.startswith(("ECDHE", "DHE", "TLS_")) for c in ciphers),
                                "certificates": [c.get("CertificateArn") for c in listener.get("Certificates") or []][:10]}})
        return "truncated" if truncated else None

    def apigw() -> str | None:
        client = acct.client("apigateway", region)
        items, truncated = _paginate(client, "get_domain_names", "items")
        for item in items:
            policy = item.get("securityPolicy") or "TLS_1_0"
            emit({"type": "api_tls", "target": label, "location": f"arn:aws:apigateway:{region}::/domainnames/{item['domainName']}",
                  "name": item["domainName"], "protocol": "TLS",
                  "facts": {"security_policy": policy, "min_version": "TLSv1.0" if policy == "TLS_1_0" else "TLSv1.2"}})
        return "truncated" if truncated else None

    def eks() -> str | None:
        client = acct.client("eks", region)
        names, truncated = _paginate(client, "list_clusters", "clusters")
        for name in names:
            cluster = client.describe_cluster(name=name)["cluster"]
            encrypted = bool(cluster.get("encryptionConfig"))
            emit({"type": "storage_encryption", "target": label, "location": cluster["arn"], "name": f"EKS {name} secrets",
                  "facts": {"resource": f"EKS cluster {name} Kubernetes secrets", "encrypted": encrypted,
                            "version": cluster.get("version")}})
        return "truncated" if truncated else None

    def keypairs() -> str | None:
        # Public half only (IncludePublicKey): the key type and RSA modulus size; private keys never leave AWS.
        client = acct.client("ec2", region)
        pairs = client.describe_key_pairs(IncludePublicKey=True).get("KeyPairs") or []
        for pair in pairs[:PER_SERVICE_CAP]:
            key_type = str(pair.get("KeyType") or "").lower()
            bits = _ssh_public_bits(pair.get("PublicKey") or "") if key_type == "rsa" else (256 if key_type == "ed25519" else None)
            emit({"type": "public_key", "target": label,
                  "location": f"arn:aws:ec2:{region}:{acct.account}:key-pair/{pair.get('KeyName')}",
                  "name": pair.get("KeyName"), "algorithm": "ED25519" if key_type == "ed25519" else "RSA", "key_size": bits,
                  "facts": {"service": "ec2", "key_type": key_type, "bits": bits, "key_pair_id": pair.get("KeyPairId"),
                            "created": _iso(pair.get("CreateTime")), "fingerprint": pair.get("KeyFingerprint")}})
        return f"{len(pairs)} key pairs"

    def ssm() -> str | None:
        # DescribeParameters is metadata (name, type, KMS key); GetParameter is denied to the role and never called.
        client = acct.client("ssm", region)
        params, truncated = _paginate(client, "describe_parameters", "Parameters")
        for param in params:
            name = param.get("Name") or ""
            emit({"type": "cloud_secret", "target": label,
                  "location": f"arn:aws:ssm:{region}:{acct.account}:parameter/{name.lstrip('/')}", "name": name,
                  "facts": {"service": "ssm", "parameter_type": param.get("Type"), "kms_key_id": param.get("KeyId"),
                            "tier": param.get("Tier"), "last_modified": _iso(param.get("LastModifiedDate")),
                            "secret_like_name": bool(_SECRET_NAME.search(name)), "identity": name}})
        return f"{len(params)} parameters" + (" (truncated)" if truncated else "")

    for service, fn in (("kms", kms), ("acm", acm), ("acm-pca", pca), ("secretsmanager", secrets), ("ec2", ebs),
                        ("ec2-keypairs", keypairs), ("ssm", ssm), ("lambda", lambdas), ("ecs", ecs_taskdefs),
                        ("ec2-userdata", userdata),
                        ("rds", rds), ("elasticloadbalancing", elbv2), ("apigateway", apigw), ("eks", eks)):
        run(service, fn)
    return rows


def _global_services(acct: _Account, label: str, emit: Emit) -> list[tuple[str, str, str | None]]:
    rows: list[tuple[str, str, str | None]] = []

    def run(service: str, fn: Callable[[], str | None]) -> None:
        try:
            rows.append((service, "ok", fn()))
        except AwsCollectError:
            raise
        except Exception as exc:
            code = _code(exc)
            status = "denied" if code in _DENIED else "error"
            rows.append((service, status, code))
            emit({"type": "coverage", "target": label, "location": f"arn:aws:{service}::{acct.account}:global",
                  "facts": {"check": f"{service} (global)", "status": status, "detail": code}})

    def iam() -> str | None:
        client = acct.client("iam", "global")
        certs, _t = _paginate(client, "list_server_certificates", "ServerCertificateMetadataList")
        for meta in certs:
            emit({"type": "iam_certificate", "target": label, "location": meta["Arn"], "name": meta.get("ServerCertificateName"),
                  "facts": {"not_after": _iso(meta.get("Expiration")), "not_before": _iso(meta.get("UploadDate")),
                            "source": "aws", "identity": meta["Arn"]}})
        for provider in client.list_saml_providers().get("SAMLProviderList", [])[:50]:
            doc = client.get_saml_provider(SAMLProviderArn=provider["Arn"]).get("SAMLMetadataDocument") or ""
            for asset in saml_assets_from_xml(doc.encode(), provider["Arn"], label):
                emit(asset)
        for provider in client.list_open_id_connect_providers().get("OpenIDConnectProviderList", [])[:50]:
            detail = client.get_open_id_connect_provider(OpenIDConnectProviderArn=provider["Arn"])
            emit({"type": "identity_provider", "target": label, "location": provider["Arn"], "name": detail.get("Url"),
                  "protocol": "OIDC", "facts": {"kind": "oidc", "thumbprints": (detail.get("ThumbprintList") or [])[:5]}})
        return None

    def s3() -> str | None:
        client = acct.client("s3", "global")
        buckets = client.list_buckets().get("Buckets", [])[:PER_SERVICE_CAP]
        for bucket in buckets:
            name = bucket["Name"]
            facts: dict[str, Any] = {"resource": f"S3 bucket {name}"}
            try:
                rules = client.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"]
                sse = rules[0]["ApplyServerSideEncryptionByDefault"] if rules else {}
                facts.update(encrypted=True, sse_algorithm=sse.get("SSEAlgorithm"), kms_key_id=sse.get("KMSMasterKeyID"))
            except Exception as exc:
                code = _code(exc)
                facts.update(encrypted=False if code == "ServerSideEncryptionConfigurationNotFoundError" else None,
                             encryption_error=None if code == "ServerSideEncryptionConfigurationNotFoundError" else code)
            try:
                policy = json.loads(client.get_bucket_policy(Bucket=name)["Policy"])
                facts["tls_only_policy"] = any(
                    st.get("Effect") == "Deny" and "aws:SecureTransport" in json.dumps(st.get("Condition") or {})
                    for st in policy.get("Statement", []))
            except Exception as exc:
                facts["tls_only_policy"] = False if _code(exc) == "NoSuchBucketPolicy" else None
            emit({"type": "storage_encryption", "target": label, "location": f"arn:aws:s3:::{name}", "name": name, "facts": facts})
        return f"{len(buckets)} buckets"

    def cloudfront() -> str | None:
        client = acct.client("cloudfront", "global")
        items = (client.list_distributions().get("DistributionList") or {}).get("Items") or []
        for dist in items[:PER_SERVICE_CAP]:
            viewer = dist.get("ViewerCertificate") or {}
            minimum = str(viewer.get("MinimumProtocolVersion") or "TLSv1")
            version = minimum.split("_")[0]  # TLSv1.2_2021 -> TLSv1.2, TLSv1_2016 -> TLSv1
            emit({"type": "cdn_tls", "target": label, "location": dist["ARN"], "name": dist.get("DomainName"), "protocol": "TLS",
                  "facts": {"min_version": "TLSv1.0" if version == "TLSv1" else version,
                            "minimum_protocol_version": minimum, "default_certificate": bool(viewer.get("CloudFrontDefaultCertificate")),
                            "acm_certificate_arn": viewer.get("ACMCertificateArn")}})
        return None

    for service, fn in (("iam", iam), ("s3", s3), ("cloudfront", cloudfront)):
        run(service, fn)
    return rows


def collect_aws(team_id: int, cfg: dict[str, Any], external_id: str, emit: Emit,
                should_stop: Callable[[], str | None]) -> dict[str, Any]:
    """Collect one AWS source.  Raises AwsCollectError when nothing may be read (safety checks failed)."""
    started = time.monotonic()
    role_arn = cfg["role_arn"]
    regions = list(cfg.get("regions") or ["us-east-1"])
    try:
        base, boto_cfg = _boto(retries=5, mode="adaptive")
    except Exception as exc:
        raise AwsCollectError(f"ZeroShield AWS credentials are not configured (ref {new_ref()})") from exc
    first = regions[0]
    sts = base.client("sts", region_name=first, config=boto_cfg)
    try:  # the trust policy must refuse us without the external ID
        sts.assume_role(RoleArn=role_arn, RoleSessionName=f"zs-cbom-noext-{team_id}"[:64], DurationSeconds=900)
        raise AwsCollectError("The role can be assumed without the external ID; add the sts:ExternalId condition and validate again")
    except AwsCollectError:
        raise
    except Exception as exc:
        if _code(exc) not in _DENIED:
            raise AwsCollectError(f"Could not check the role's trust policy: {_code(exc)}") from exc
    accounts = [_Account(base, boto_cfg, role_arn, external_id, team_id)]
    try:
        accounts[0].assume(first)
    except AwsCollectError:
        raise
    except Exception as exc:
        raise AwsCollectError(f"AssumeRole failed: {_code(exc)}") from exc
    if cfg.get("scope") == "organization":
        try:
            org = accounts[0].client("organizations", "global")
            members, _t = _paginate(org, "list_accounts", "Accounts", cap=200)
            role_name = role_arn.split(":role/", 1)[1]
            partition = role_arn.split(":")[1]
            for member in members:
                if member.get("Status") != "ACTIVE" or member["Id"] == accounts[0].account:
                    continue
                accounts.append(_Account(base, boto_cfg, f"arn:{partition}:iam::{member['Id']}:role/{role_name}", external_id, team_id))
        except Exception as exc:
            emit({"type": "coverage", "target": accounts[0].account or "", "location": f"arn:aws:organizations::{accounts[0].account}:accounts",
                  "facts": {"check": "organization member accounts", "status": "error", "detail": _code(exc)}})
    targets: list[dict[str, Any]] = []
    for acct in accounts:
        label = f"aws:{acct.account}"
        for region in ["global", *regions]:
            reason = should_stop()
            if reason:
                targets.append({"target": f"{label}/{region}", "status": "skipped_cancelled", "error": reason[:256], "assets": 0})
                continue
            t0 = time.monotonic()
            try:
                rows = _global_services(acct, label, emit) if region == "global" else _region_services(acct, region, label, emit)
            except AwsCollectError as exc:
                targets.append({"target": f"{label}/{region}", "status": "error", "error": str(exc)[:256], "assets": 0})
                continue
            except Exception as exc:  # AssumeRole in a member account failed
                targets.append({"target": f"{label}/{region}", "status": "auth_failed", "error": _code(exc)[:256], "assets": 0})
                continue
            bad = [f"{svc}: {status} {detail or ''}".strip() for svc, status, detail in rows if status != "ok"]
            enabled = [r for r in rows if r[1] != "not_enabled"]
            status = "ok" if not bad else ("not_supported" if not enabled else "error")
            targets.append({"target": f"{label}/{region}", "status": status, "error": "; ".join(bad)[:256] or None,
                            "duration_ms": int((time.monotonic() - t0) * 1000),
                            "services": {svc: status_ for svc, status_, _d in rows}})
    ok = sum(1 for t in targets if t["status"] == "ok")
    skipped = sum(1 for t in targets if t["status"].startswith("skipped"))
    log("aws collected", team=team_id, accounts=len(accounts), targets=len(targets), ok=ok,
        duration_s=int(time.monotonic() - started))
    return {"targets": targets, "accounts": len(accounts),
            "counts": {"total": len(targets), "ok": ok, "failed": len(targets) - ok - skipped, "skipped": skipped},
            "duration_s": int(time.monotonic() - started)}

