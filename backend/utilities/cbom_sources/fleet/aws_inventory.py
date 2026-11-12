"""AWS inventory: list the hosts, databases, clusters, load balancers, certificates, keys and secrets of one account
through the customer's read-only role, across regions (contract section 3, ``AwsInventorySource``).

The safety rules are those of ``aws_collect`` and are checked before anything is listed: only ZeroShield's own
principal (``CBOM_AWS_*``, through ``aws_validate._boto``) is used; the role must REFUSE AssumeRole without the team's
external ID (confused-deputy protection); the assumed identity must be in the account the role ARN names
(``aws_collect._Account``, reused, not modified).  Only list/describe calls are made: no secret value, no key
material, no object is read.

Every (region, service) gets a status in ``coverage``: ``ok``, ``truncated`` (more than the cap), ``denied``,
``not_enabled`` (opt-in region), ``not_available`` (the service has no endpoint there), ``unreachable`` (no answer:
reset, timeout, TLS or proxy), ``skipped:region_unreachable`` (EC2 of that region was unreachable, so the region's
other services are not tried), ``cancelled`` (the sync ran out of time) or ``error:<code>``.  Only an ``ok`` scope
lets a sync mark targets that disappeared as missing.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, ClassVar, Iterable
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.utilities.cbom_sources.aws_collect import _DENIED, _NOT_ENABLED, AwsCollectError, _Account
from backend.utilities.cbom_sources.aws_validate import _boto, _code
from backend.utilities.cbom_sources.common import log, new_ref
from backend.utilities.cbom_sources.fleet.inventory_sources import InventoryError, Target, normalize
from backend.utilities.cbom_sources.kinds import AWS_REGION_RE

SERVICES = ("ec2", "rds", "eks", "elb", "acm", "kms", "secretsmanager")
MAX_REGIONS = 20
PER_SERVICE_CAP = 5000
MAX_TAG_LOOKUPS = 1000  # per region and service that needs one call per resource (ACM, KMS)


class AwsInventoryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    aws_account_source_id: int = Field(ge=1, le=2_147_483_647)
    regions: list[str] = Field(min_length=1, max_length=MAX_REGIONS)
    services: list[str] = Field(default_factory=lambda: list(SERVICES), min_length=1, max_length=len(SERVICES))

    @field_validator("regions")
    @classmethod
    def _regions(cls, v: list[str]) -> list[str]:
        clean = sorted({r.strip() for r in v})
        for region in clean:
            if not AWS_REGION_RE.match(region):
                raise ValueError(f"{region[:30]!r} is not an AWS region (e.g. ap-south-1)")
        return clean

    @field_validator("services")
    @classmethod
    def _services(cls, v: list[str]) -> list[str]:
        bad = [s for s in v if s not in SERVICES]
        if bad:
            raise ValueError(f"services must be from {', '.join(SERVICES)}")
        return [s for s in SERVICES if s in set(v)]


@dataclass
class Discovery:
    account_id: str
    targets: list[Target] = field(default_factory=list)
    coverage: dict[str, dict[str, str]] = field(default_factory=dict)
    errors: list[dict[str, Any]] = field(default_factory=list)  # rows AWS returned that did not normalise

    @property
    def complete(self) -> bool:
        return all(status == "ok" for region in self.coverage.values() for status in region.values())


def _host_of(endpoint: str | None) -> str | None:
    if not endpoint:
        return None
    return urlsplit(endpoint).hostname if "://" in endpoint else endpoint


def _paginate(client, method: str, key: str, cap: int = PER_SERVICE_CAP, **kwargs) -> tuple[list[Any], bool]:
    out: list[Any] = []
    for page in client.get_paginator(method).paginate(**kwargs):
        out.extend(page.get(key) or [])
        if len(out) > cap:
            return out[:cap], True
    return out, False


def _iso(value: Any) -> str | None:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ") if hasattr(value, "strftime") else None


class _Lister:
    """One region of one account: each method returns (raw rows, truncated)."""

    def __init__(self, acct: _Account, region: str, partition: str):
        self.acct, self.region, self.partition = acct, region, partition

    def _arn(self, service: str, resource: str) -> str:
        return f"arn:{self.partition}:{service}:{self.region}:{self.acct.account}:{resource}"

    def _base(self, service: str) -> dict[str, Any]:
        return {"account_id": self.acct.account, "region": self.region}

    def ec2(self) -> tuple[list[dict], bool]:
        client = self.acct.client("ec2", self.region)
        reservations, cut = _paginate(client, "describe_instances", "Reservations", Filters=[
            {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}])
        rows = []
        for reservation in reservations:
            for inst in reservation.get("Instances") or []:
                addresses = [inst.get("PrivateIpAddress")]
                for eni in inst.get("NetworkInterfaces") or []:
                    addresses += [p.get("PrivateIpAddress") for p in eni.get("PrivateIpAddresses") or []]
                    addresses += [p.get("Ipv6Address") for p in eni.get("Ipv6Addresses") or []]
                addresses.append(inst.get("PublicIpAddress"))
                windows = str(inst.get("Platform") or "").lower() == "windows"
                rows.append({
                    **self._base("ec2"), "external_id": self._arn("ec2", f"instance/{inst['InstanceId']}"),
                    "kind": "windows_host" if windows else "linux_host",
                    "address": inst.get("PrivateIpAddress") or inst.get("PublicIpAddress"),
                    "addresses": [a for a in addresses if a][:32], "hostname": inst.get("PrivateDnsName") or None,
                    "tags": inst.get("Tags") or [], "platform": inst.get("PlatformDetails") or ("Windows" if windows else "Linux/UNIX"),
                    "handles": {"ssm": inst["InstanceId"]},
                    "attributes": {"service": "ec2", "instance_id": inst["InstanceId"],
                                   "instance_type": inst.get("InstanceType"),
                                   "state": (inst.get("State") or {}).get("Name"), "vpc_id": inst.get("VpcId"),
                                   "subnet_id": inst.get("SubnetId"), "image_id": inst.get("ImageId")}})
        return rows, cut

    def rds(self) -> tuple[list[dict], bool]:
        client = self.acct.client("rds", self.region)
        items, cut = _paginate(client, "describe_db_instances", "DBInstances")
        rows = []
        for db in items:
            endpoint = db.get("Endpoint") or {}
            rows.append({
                **self._base("rds"), "external_id": db.get("DBInstanceArn") or self._arn("rds", f"db:{db['DBInstanceIdentifier']}"),
                "kind": "database", "address": endpoint.get("Address"), "tags": db.get("TagList") or [],
                "platform": db.get("Engine"),
                "attributes": {"service": "rds", "identifier": db.get("DBInstanceIdentifier"), "engine": db.get("Engine"),
                               "engine_version": db.get("EngineVersion"), "port": endpoint.get("Port"),
                               "instance_class": db.get("DBInstanceClass"),
                               "storage_encrypted": bool(db.get("StorageEncrypted")),
                               "publicly_accessible": bool(db.get("PubliclyAccessible")),
                               "ca_certificate": db.get("CACertificateIdentifier")}})
        return rows, cut

    def eks(self) -> tuple[list[dict], bool]:
        client = self.acct.client("eks", self.region)
        names, cut = _paginate(client, "list_clusters", "clusters")
        rows = []
        for name in names:
            cluster = client.describe_cluster(name=name).get("cluster") or {}
            rows.append({
                **self._base("eks"), "external_id": cluster.get("arn") or self._arn("eks", f"cluster/{name}"),
                "kind": "k8s_cluster", "address": _host_of(cluster.get("endpoint")), "tags": cluster.get("tags") or {},
                "platform": "eks",
                "attributes": {"service": "eks", "name": name, "version": cluster.get("version"),
                               "secrets_encrypted": bool(cluster.get("encryptionConfig"))}})
        return rows, cut

    def elb(self) -> tuple[list[dict], bool]:
        client = self.acct.client("elbv2", self.region)
        items, cut = _paginate(client, "describe_load_balancers", "LoadBalancers")
        tags: dict[str, list] = {}
        arns = [lb["LoadBalancerArn"] for lb in items]
        for i in range(0, len(arns), 20):
            for desc in client.describe_tags(ResourceArns=arns[i:i + 20]).get("TagDescriptions") or []:
                tags[desc["ResourceArn"]] = desc.get("Tags") or []
        rows = [{**self._base("elb"), "external_id": lb["LoadBalancerArn"], "kind": "load_balancer",
                 "address": lb.get("DNSName"), "tags": tags.get(lb["LoadBalancerArn"], []), "platform": lb.get("Type"),
                 "attributes": {"service": "elb", "name": lb.get("LoadBalancerName"), "scheme": lb.get("Scheme"),
                                "type": lb.get("Type"), "vpc_id": lb.get("VpcId")}} for lb in items]
        return rows, cut

    def acm(self) -> tuple[list[dict], bool]:
        client = self.acct.client("acm", self.region)
        items, cut = _paginate(client, "list_certificates", "CertificateSummaryList")
        rows = []
        for n, cert in enumerate(items):
            arn = cert["CertificateArn"]
            tags = client.list_tags_for_certificate(CertificateArn=arn).get("Tags") or [] if n < MAX_TAG_LOOKUPS else []
            domain = cert.get("DomainName") or None
            rows.append({**self._base("acm"), "external_id": arn, "kind": "certificate",
                         # a wildcard (*.example.com) names many hosts, not one to connect to: it stays an attribute
                         "hostname": domain if domain and not domain.startswith("*") else None, "tags": tags,
                         "attributes": {"service": "acm", "domain": cert.get("DomainName"),
                                        "key_algorithm": cert.get("KeyAlgorithm"), "type": cert.get("Type"),
                                        "status": cert.get("Status"), "in_use": cert.get("InUse"),
                                        "not_after": _iso(cert.get("NotAfter"))}})
        return rows, cut or len(items) > MAX_TAG_LOOKUPS

    def kms(self) -> tuple[list[dict], bool]:
        client = self.acct.client("kms", self.region)
        items, cut = _paginate(client, "list_keys", "Keys")
        rows = []
        looked = 0
        for key in items:
            if looked >= MAX_TAG_LOOKUPS:
                cut = True
                break
            looked += 1
            meta = client.describe_key(KeyId=key["KeyId"]).get("KeyMetadata") or {}
            if meta.get("KeyManager") == "AWS":
                continue  # AWS-managed keys belong to the services that made them
            tags = client.list_resource_tags(KeyId=key["KeyId"]).get("Tags") or []
            rows.append({**self._base("kms"), "external_id": meta.get("Arn") or key.get("KeyArn"), "kind": "kms_key",
                         "tags": [{"Key": t.get("TagKey"), "Value": t.get("TagValue")} for t in tags],
                         "attributes": {"service": "kms", "key_id": key["KeyId"],
                                        "key_spec": meta.get("KeySpec") or meta.get("CustomerMasterKeySpec"),
                                        "key_usage": meta.get("KeyUsage"), "key_state": meta.get("KeyState"),
                                        "multi_region": bool(meta.get("MultiRegion"))}})
        return rows, cut

    def secretsmanager(self) -> tuple[list[dict], bool]:
        client = self.acct.client("secretsmanager", self.region)
        items, cut = _paginate(client, "list_secrets", "SecretList")
        rows = [{**self._base("secretsmanager"), "external_id": s["ARN"], "kind": "secret", "tags": s.get("Tags") or [],
                 "attributes": {"service": "secretsmanager", "name": s.get("Name"),
                                "rotation_enabled": bool(s.get("RotationEnabled")),
                                "customer_key": bool(s.get("KmsKeyId"))}} for s in items]
        return rows, cut


def _connection_level(exc: Exception) -> bool:
    """The request never got an AWS answer (reset, timeout, TLS, proxy, DNS)."""
    from botocore.exceptions import ConnectionError as _BotoConnectionError, HTTPClientError

    return isinstance(exc, (_BotoConnectionError, HTTPClientError))


def _status(exc: Exception) -> str:
    code = _code(exc)
    if code in _DENIED:
        return "denied"
    if code in _NOT_ENABLED:
        return "not_enabled"
    if type(exc).__name__ in ("EndpointConnectionError", "UnknownEndpointError"):
        return "not_available"
    if _connection_level(exc):
        return "unreachable"
    return f"error:{code}"[:64]


def discover_account(acct: _Account, regions: list[str], services: list[str],
                     should_stop: Callable[[], str | None] = lambda: None) -> Discovery:
    """List every requested service in every region with an already-checked ``_Account`` (no pre-checks here)."""
    partition = acct.role_arn.split(":")[1] if acct.role_arn.count(":") >= 2 else "aws"
    out = Discovery(account_id=acct.account)
    for region in regions:
        lister = _Lister(acct, region, partition)
        out.coverage[region] = {}
        region_down = False
        for service in services:
            if should_stop():
                out.coverage[region][service] = "cancelled"
                continue
            if region_down:  # one call told us: the region's endpoints cannot be reached from here
                out.coverage[region][service] = "skipped:region_unreachable"
                continue
            try:
                rows, cut = getattr(lister, service)()
            except Exception as exc:  # one service or region never hides the others
                out.coverage[region][service] = _status(exc)
                # EC2 is offered in every region: no connection to it means none to the region (an opt-in region
                # behind an egress filter, a blocked endpoint).  Each further call would cost its retries again.
                region_down = service == "ec2" and _connection_level(exc)
                continue
            out.coverage[region][service] = "truncated" if cut else "ok"
            for row in rows:
                try:
                    out.targets.append(normalize(row))
                except InventoryError as exc:
                    if len(out.errors) < 100:
                        out.errors.append({"external_id": str(row.get("external_id"))[:255], "error": str(exc)})
    return out


class AwsInventorySource:
    """The production path: the pre-checks of ``aws_collect.collect_aws``, then ``discover_account``."""
    kind: ClassVar[str] = "aws"

    def __init__(self, team_id: int, role_arn: str, external_id: str, regions: list[str], services: list[str],
                 should_stop: Callable[[], str | None] = lambda: None):
        self.team_id, self.role_arn, self.external_id = team_id, role_arn, external_id
        self.regions, self.services, self.should_stop = regions, services, should_stop
        self.result: Discovery | None = None

    def discover(self) -> Iterable[Target]:
        started = time.monotonic()
        try:
            base, boto_cfg = _boto(retries=5, mode="adaptive")
        except Exception as exc:
            raise InventoryError("not_configured", f"ZeroShield AWS credentials are not configured (ref {new_ref()})") from exc
        first = self.regions[0]
        sts = base.client("sts", region_name=first, config=boto_cfg)
        try:  # the trust policy must refuse us without the external ID
            sts.assume_role(RoleArn=self.role_arn, RoleSessionName=f"zs-cbom-inv-noext-{self.team_id}"[:64],
                            DurationSeconds=900)
            raise InventoryError("no_external_id", "The role can be assumed without the external ID; add the "
                                                   "sts:ExternalId condition and validate the AWS account again")
        except InventoryError:
            raise
        except Exception as exc:
            if _code(exc) not in _DENIED:
                raise InventoryError("trust_check", f"Could not check the role's trust policy: {_code(exc)}") from exc
        acct = _Account(base, boto_cfg, self.role_arn, self.external_id, self.team_id)
        try:
            acct.assume(first)
        except AwsCollectError as exc:
            raise InventoryError("wrong_account", str(exc)) from exc
        except Exception as exc:
            raise InventoryError("assume_failed", f"AssumeRole failed: {_code(exc)}") from exc
        self.result = discover_account(acct, self.regions, self.services, self.should_stop)
        log("aws inventory listed", team=self.team_id, targets=len(self.result.targets),
            regions=len(self.regions), complete=self.result.complete, duration_s=int(time.monotonic() - started))
        return self.result.targets
