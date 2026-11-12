"""F1.2 inventory: CSV/JSON import, the API, idempotent upsert, inventory sources and their sync, and AWS discovery
through the read-only role against moto (EC2, RDS, EKS, ELB, ACM, KMS, Secrets Manager; three regions).

Real routers, real JWTs, SQLite (``test_cbom_sources_api`` world); moto 5 for AWS.
"""
from __future__ import annotations

import datetime as dt
import json

import pytest
from sqlmodel import Session, select

from test_cbom_sources_api import api, world
from backend.new_models import CbomCollectionSource
from backend.utilities.cbom_sources.cleanup import delete_cbom_sources_for_team
from backend.utilities.cbom_sources.fleet import store
from backend.utilities.cbom_sources.fleet import sync as SYNC
from backend.utilities.cbom_sources.fleet.inventory_sources import InventoryError, normalize, parse_csv, parse_json
from backend.utilities.cbom_sources.fleet.models import CbomInventorySource, CbomInventoryTarget
from backend.workers import cbom_inventory_sync

FIXTURES = (api, world)
INV = "/1/cbom/sources/fleet/inventory"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


@pytest.fixture(autouse=True)
def _flags(monkeypatch):
    for name in ("CBOM_FLEET_POLICIES", "CBOM_FLEET_MATERIALIZE", "CBOM_FLEET_TRANSPORTS", "CBOM_SSH_CA"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CBOM_FLEET_INVENTORY", "1")


def _csv(n: int, *, env: str = "prod", start: int = 0) -> str:
    lines = ["external_id,kind,address,hostname,tag:Env,tag:team,tags"]
    for i in range(start, start + n):
        lines.append(f"srv-{i:05d},linux_host,10.1.{i // 250}.{i % 250 + 1},app-{i:05d}.bank.local,{env},payments,"
                     f"Owner=ops;Tier=1")
    return "\n".join(lines) + "\n"


def _import(api, content: str, fmt: str = "csv", who: str = "alice", **extra):
    return api("POST", f"{INV}/import", who, json={"format": fmt, "content": content, **extra})


# ----------------------------------------------------------------------------- normalisation (pure)
def test_normalize_is_strict_and_canonical():
    t = normalize({"external_id": "a", "address": "10.0.0.5", "addresses": "10.0.0.6; ::ffff:10.0.0.7 2001:db8::1",
                   "tags": {"Env": "prod", " Team ": "pay"}, "hostname": "App-01.Bank.Local."})
    assert t.address == "10.0.0.5" and t.addresses == ("10.0.0.5", "10.0.0.6", "10.0.0.7", "2001:db8::1")
    assert t.hostname == "app-01.bank.local" and dict(t.tags) == {"env": "prod", "team": "pay"}
    assert t.kind == "linux_host" and t.fingerprint() == normalize(
        {"tags": {"team": "pay", "env": "prod"}, "external_id": "a", "hostname": "app-01.bank.local",
         "address": "10.0.0.5", "addresses": ["10.0.0.6", "10.0.0.7", "2001:db8::1"]}).fingerprint()
    assert normalize({"address": "db.bank.local"}).external_id == "db.bank.local"
    for bad, match in [({"address": "10.0.0.0/24"}, "one address"), ({"kind": "router", "address": "x.y"}, "kind"),
                       ({"address": "1.2.3.4", "tags": {"k": "v" * 300}}, "256"), ({"nope": 1}, "unknown field"),
                       ({"address": "1.2.3.4", "handles": {"ssh": "x"}}, "unknown key"), ({}, "external_id"),
                       ({"address": "1.2.3.4", "hostname": "5.6.7.8"}, "IP address"),
                       ({"address": "1.2.3.4", "attributes": {"a": {"b": 1}}}, "only text")]:
        with pytest.raises(InventoryError, match=match):
            normalize(bad)


def test_tag_keys_that_differ_only_in_case_fold_the_same_way_whatever_their_order():
    """AWS tag keys are case-sensitive and a resource can carry both ``Env`` and ``env``; AWS does not promise the
    order of ``Tags``.  Keys are compared lower-cased, so the folded value must not depend on the order the tags came
    in (else the same resource flips between syncs: another fingerprint, an update every sync, another policy).
    Rule: the key already written in lower case wins; otherwise the smallest key in code-point order."""
    import itertools

    aws = [{"Key": "Env", "Value": "prod"}, {"Key": "env", "Value": "stage"}, {"Key": "ENV", "Value": "dev"},
           {"Key": "Team", "Value": "pay"}]
    seen = set()
    for order in itertools.permutations(aws):
        t = normalize({"external_id": "arn:aws:ec2:ap-south-1:1:instance/i-1", "address": "10.0.0.5", "tags": list(order)})
        seen.add((tuple(sorted(t.tags.items())), t.fingerprint()))
    assert len(seen) == 1 and dict(seen.pop()[0]) == {"env": "stage", "team": "pay"}
    no_lower = [{"Key": "Env", "Value": "prod"}, {"Key": "ENV", "Value": "dev"}]
    for order in (no_lower, no_lower[::-1]):
        assert dict(normalize({"address": "10.0.0.5", "tags": order}).tags) == {"env": "dev"}  # "ENV" < "Env"
    # the same rule for a JSON object and for CSV columns, in either column order
    assert dict(normalize({"address": "10.0.0.5", "tags": {"Env": "prod", "env": "stage"}}).tags) == {"env": "stage"}
    assert dict(normalize({"address": "10.0.0.5", "tags": {"env": "stage", "Env": "prod"}}).tags) == {"env": "stage"}
    one = parse_csv("external_id,address,tag:Env,tag:env\na,10.0.0.1,prod,stage\n").targets[0]
    two = parse_csv("external_id,address,tag:env,tag:Env\na,10.0.0.1,stage,prod\n").targets[0]
    three = parse_csv("external_id,address,tags,tag:Env\na,10.0.0.1,env=stage,prod\n").targets[0]
    assert dict(one.tags) == dict(two.tags) == dict(three.tags) == {"env": "stage"}
    assert one.fingerprint() == two.fingerprint() == three.fingerprint()
    # a value that is refused is refused whether its key would win or lose
    for order in (["Env", "env"], ["env", "Env"]):
        with pytest.raises(InventoryError, match="256"):
            normalize({"address": "10.0.0.5", "tags": {k: ("x" * 300 if k == "Env" else "ok") for k in order}})
    # a column given twice (which copy wins would depend on the column order) is refused
    for header in ("external_id,address,tag:Env,tag: Env", "external_id,address,Address", "external_id,TAG:env,tag:env"):
        with pytest.raises(InventoryError, match="appears twice"):
            parse_csv(header + "\na,10.0.0.1,x,y\n")


def test_csv_and_json_parsing_report_rows_and_cap_errors():
    parsed = parse_csv("external_id,address,tag:env\na,10.0.0.1,prod\nb,not an address!,prod\na,10.0.0.3,dev\n")
    assert [t.external_id for t in parsed.targets] == ["a"] and parsed.error_count == 2
    assert parsed.errors[0]["row"] == 3 and "address" in parsed.errors[0]["error"]
    assert "duplicate external_id (first on row 2)" in parsed.errors[1]["error"]
    with pytest.raises(InventoryError, match="unknown column 'environment'"):
        parse_csv("external_id,environment\na,prod\n")
    bad = parse_json(json.dumps([{"address": "x" * 300}] * 150))
    assert bad.error_count == 150 and len(bad.errors) == 100
    assert parse_json({"targets": [{"address": "10.0.0.9"}]}).targets[0].address == "10.0.0.9"
    with pytest.raises(InventoryError, match="more than 3"):
        parse_json([{"address": f"10.0.0.{i}"} for i in range(4)], limit=3)
    with pytest.raises(InventoryError, match="not valid JSON"):
        parse_json("{nope")


# ----------------------------------------------------------------------------- import and idempotency
def test_routes_do_not_exist_while_the_flag_is_off(api, monkeypatch):
    monkeypatch.setenv("CBOM_FLEET_INVENTORY", "0")
    assert api("GET", f"{INV}/targets").status_code == 404
    assert _import(api, _csv(1)).status_code == 404
    monkeypatch.setenv("CBOM_FLEET_INVENTORY", "1")
    assert api("GET", f"{INV}/targets").status_code == 200


def test_import_is_idempotent_and_updates_instead_of_duplicating(api, world):
    engine, _ = world
    first = _import(api, _csv(300))
    assert first.status_code == 200, first.text
    body = first.json()
    assert (body["created"], body["updated"], body["unchanged"], body["missing"]) == (300, 0, 0, 0)
    again = _import(api, _csv(300)).json()
    assert (again["created"], again["updated"], again["unchanged"], again["missing"]) == (0, 0, 300, 0)
    assert again["digest"] == body["digest"]
    with Session(engine) as s:
        rows = s.exec(select(CbomInventoryTarget).where(CbomInventoryTarget.team_id == 1)).all()
        versions = {r.external_id: r.row_version for r in rows}
        assert len(rows) == 300 and set(versions.values()) == {1}  # a no-op re-import changed no row
        r0 = next(r for r in rows if r.external_id == "srv-00000")
        assert r0.tags == {"env": "prod", "team": "payments", "owner": "ops", "tier": "1"}
    # one tag changes, the last 10 rows go: 1 updated, 10 missing, nothing duplicated
    changed = _csv(290).replace("srv-00007,linux_host,10.1.0.8,app-00007.bank.local,prod",
                                "srv-00007,linux_host,10.1.0.8,app-00007.bank.local,stage")
    third = _import(api, changed).json()
    assert (third["created"], third["updated"], third["unchanged"], third["missing"]) == (0, 1, 289, 10)
    back = _import(api, _csv(300)).json()  # the missing ones come back (updated), the tag goes back
    assert (back["created"], back["updated"], back["unchanged"]) == (0, 11, 289)
    with Session(engine) as s:
        assert len(s.exec(select(CbomInventoryTarget)).all()) == 300
        assert all(r.missing_since is None for r in s.exec(select(CbomInventoryTarget)).all())


def test_dry_run_writes_nothing_and_a_file_with_errors_marks_nothing_missing(api, world):
    engine, _ = world
    dry = _import(api, _csv(5), dry_run=True).json()
    assert dry["dry_run"] and dry["created"] == 5
    with Session(engine) as s:
        assert s.exec(select(CbomInventoryTarget)).all() == []
    _import(api, _csv(5))
    partial = _import(api, _csv(2) + "srv-x,linux_host,999.1.1.1,,prod,,\n").json()
    assert partial["error_count"] == 1 and partial["missing"] == 0 and partial["missing_skipped"] is True
    assert partial["errors"][0]["row"] == 4


def test_json_import_and_the_api_source(api, world):
    engine, _ = world
    rows = [{"external_id": f"vm-{i}", "address": f"10.9.0.{i}", "tags": {"env": "prod"}, "platform": "ubuntu",
             "handles": {"salt": f"minion-{i}"}} for i in range(1, 4)]
    r = _import(api, json.dumps({"targets": rows}), fmt="json")
    assert r.status_code == 200 and r.json()["created"] == 3
    put = api("PUT", f"{INV}/targets", json={"source_name": "cmdb sync", "targets": [
        {"external_id": "vm-1", "address": "10.9.0.1", "tags": {"env": "stage"}},  # takes over vm-1
        {"external_id": "vm-9", "address": "10.9.0.9"}]})
    assert put.status_code == 200, put.text
    assert (put.json()["created"], put.json()["updated"], put.json()["missing"]) == (1, 1, 0)  # PUT never marks missing
    sources = api("GET", f"{INV}/sources").json()["sources"]
    assert {(s["kind"], s["name"]) for s in sources} == {("json", "JSON import"), ("api", "cmdb sync")}
    too_many = api("PUT", f"{INV}/targets", json={"source_name": "x", "targets": [{"address": "10.0.0.1"}] * 1001})
    assert too_many.status_code == 400
    listing = api("GET", f"{INV}/targets", params={"tag": "env:stage"}).json()
    assert [t["external_id"] for t in listing["targets"]] == ["vm-1"] and listing["total"] == 1
    assert api("GET", f"{INV}/targets", params={"q": "VM-9"}).json()["total"] == 1


def test_permissions_and_tenancy(api, world):
    assert _import(api, _csv(2), who="bob").status_code == 400  # a member reads, an admin writes
    assert "team admin" in _import(api, _csv(2), who="bob").json()["detail"]
    assert _import(api, _csv(2)).status_code == 200
    assert api("GET", f"{INV}/targets", "bob").json()["total"] == 2
    tid = api("GET", f"{INV}/targets").json()["targets"][0]["id"]
    assert api("GET", f"/2/cbom/sources/fleet/inventory/targets/{tid}", "carol").status_code == 404
    assert api("GET", f"{INV}/targets/{tid}", "carol").status_code == 403  # not a member of team 1
    assert api("GET", "/2/cbom/sources/fleet/inventory/targets", "carol").json()["total"] == 0
    assert api("DELETE", f"{INV}/targets/{tid}", "bob").status_code == 400
    gone = api("DELETE", f"{INV}/targets/{tid}")
    assert gone.status_code == 200
    detail = api("GET", f"{INV}/targets/{tid}").json()["target"]
    assert detail["missing_since"] and detail["managed_source_id"] is None
    assert api("GET", f"{INV}/targets").json()["total"] == 1
    assert api("GET", f"{INV}/targets", params={"missing": "all"}).json()["total"] == 2


def test_a_member_import_is_refused_before_the_file_is_parsed(api, monkeypatch):
    """A member who is not an admin gets the 400 without the server parsing up to 10 MB / 10,000 rows first."""
    from backend.routers import cbom_fleet_inventory as ROUTES

    parsed = []
    real_csv, real_json = ROUTES.parse_csv, ROUTES.parse_json
    monkeypatch.setattr(ROUTES, "parse_csv", lambda *a, **k: parsed.append("csv") or real_csv(*a, **k))
    monkeypatch.setattr(ROUTES, "parse_json", lambda *a, **k: parsed.append("json") or real_json(*a, **k))
    refused = _import(api, _csv(500), who="bob")
    assert refused.status_code == 400 and "team admin" in refused.json()["detail"]
    assert _import(api, json.dumps([{"external_id": "a", "address": "10.0.0.1"}]), "json", who="bob").status_code == 400
    assert parsed == []
    assert _import(api, _csv(2)).status_code == 200 and parsed == ["csv"]


def test_body_and_row_caps(api):
    big = "x" * (10 * 1024 * 1024 + 70 * 1024)
    r = api("POST", f"{INV}/import", content=json.dumps({"format": "csv", "content": big}),
            headers={"content-type": "application/json"})
    assert r.status_code == 413
    rows = "external_id,address\n" + "".join(f"h{i},10.{i // 65000}.{i // 250 % 250}.{i % 250 + 1}\n" for i in range(10_001))
    r = _import(api, rows)
    assert r.status_code == 400 and "10,000" in r.json()["detail"]


def test_a_concurrent_insert_of_the_same_target_is_updated_not_duplicated(world, monkeypatch):
    """Two imports race: ours sees nothing, the other inserts first; ON CONFLICT DO NOTHING + the update pass."""
    engine, _ = world
    from backend.utilities.cbom_sources.fleet.inventory_sources import normalize as norm

    with Session(engine) as s:
        src = CbomInventorySource(team_id=1, kind="api", name="a", config={})
        other = CbomInventorySource(team_id=1, kind="api", name="b", config={})
        s.add(src)
        s.add(other)
        s.commit()
        s.refresh(src)
        s.refresh(other)
        now = dt.datetime(2026, 11, 11, 12, 0)
        real = store._existing
        calls = {"n": 0}

        def racing(session, team_id, ids):
            calls["n"] += 1
            if calls["n"] == 1:  # the other import commits between our read and our insert
                store.upsert(session, team_id, other, [norm({"external_id": "h1", "address": "10.0.0.1"})], now,
                             engine=None)
                return {}
            return real(session, team_id, ids)

        monkeypatch.setattr(store, "_existing", racing)
        result = store.upsert(s, 1, src, [norm({"external_id": "h1", "address": "10.0.0.2"})], now, engine=None)
        s.commit()
        rows = s.exec(select(CbomInventoryTarget)).all()
        assert len(rows) == 1 and rows[0].address == "10.0.0.2" and rows[0].inventory_source_id == src.id
        assert (result.created, result.updated) == (0, 1)


def test_team_delete_removes_the_fleet_rows(api, world):
    engine, _ = world
    _import(api, _csv(3))
    counts = delete_cbom_sources_for_team(engine, 1)
    assert counts["cbominventorytarget"] == 3 and counts["cbominventorysource"] == 1


# ----------------------------------------------------------------------------- inventory sources and sync
def _aws_account(engine, team_id=1, validated=True) -> int:
    with Session(engine) as s:
        src = CbomCollectionSource(team_id=team_id, owner_user_id=1, kind="aws_account", name="prod-aws",
                                   name_lower="prod-aws", config={"role_arn": ROLE, "regions": ["us-east-1"],
                                                                  "scope": "account"},
                                   last_test_status="passed" if validated else "failed")
        s.add(src)
        s.commit()
        return src.id


def test_inventory_source_crud_and_sync_queue(api, world):
    engine, _ = world
    acct = _aws_account(engine)
    other_team_acct = _aws_account(engine, team_id=2)
    bad = api("POST", f"{INV}/sources", json={"kind": "aws", "name": "aws", "config": {
        "aws_account_source_id": acct, "regions": ["mars-1"]}})
    assert bad.status_code == 400 and "AWS region" in bad.json()["detail"]
    assert api("POST", f"{INV}/sources", json={"kind": "aws", "name": "aws", "config": {
        "aws_account_source_id": other_team_acct, "regions": ["us-east-1"]}}).status_code == 400
    created = api("POST", f"{INV}/sources", json={"kind": "aws", "name": "aws", "config": {
        "aws_account_source_id": acct, "regions": ["us-west-2", "us-east-1", "us-east-1"], "services": ["kms", "ec2"]}})
    assert created.status_code == 201, created.text
    src = created.json()["source"]
    assert src["config"]["regions"] == ["us-east-1", "us-west-2"] and src["config"]["services"] == ["ec2", "kms"]
    assert src["last_sync_status"] == "queued"  # the first sync runs right away
    with Session(engine) as s:
        assert SYNC.due_ids(s, _now()) == [src["id"]]
        assert SYNC.claim(s, src["id"], _now()) is True
        assert SYNC.claim(s, src["id"], _now()) is False  # one process wins the lease
    assert api("POST", f"{INV}/sources/{src['id']}/sync").status_code == 409  # running
    csv_src = api("POST", f"{INV}/sources", json={"kind": "csv", "name": "spreadsheet"}).json()["source"]
    assert api("POST", f"{INV}/sources/{csv_src['id']}/sync").status_code == 400
    stale = api("PATCH", f"{INV}/sources/{csv_src['id']}", json={"name": "renamed", "expected_version": 99})
    assert stale.status_code == 409
    assert api("PATCH", f"{INV}/sources/{csv_src['id']}", json={"enabled": False}).json()["source"]["enabled"] is False
    assert api("DELETE", f"{INV}/sources/{csv_src['id']}").status_code == 200
    assert api("PATCH", f"{INV}/sources/{csv_src['id']}", json={"enabled": True}).status_code == 404


def test_the_sync_thread_starts_only_with_the_flag(monkeypatch, world):
    engine, _ = world
    monkeypatch.setenv("CBOM_FLEET_INVENTORY", "0")
    assert cbom_inventory_sync.start_thread(engine) is None
    monkeypatch.setenv("CBOM_FLEET_INVENTORY", "1")
    monkeypatch.setenv("CBOM_INVENTORY_SYNC", "0")
    assert cbom_inventory_sync.start_thread(engine) is None


# ----------------------------------------------------------------------------- AWS discovery (moto)
moto = pytest.importorskip("moto")
import boto3  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402

from backend.utilities.cbom_sources.fleet import aws_inventory  # noqa: E402

ACCOUNT = "123456789012"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/DevSecShieldScannerReadOnlyRole"
REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]


class _StsGuard:
    """moto does not evaluate trust policies; refuse AssumeRole without the external ID like a correct role does."""

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


@pytest.fixture()
def aws(monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(k, "testing")
    with moto.mock_aws():
        boto3.client("iam", region_name="us-east-1").create_role(
            RoleName="DevSecShieldScannerReadOnlyRole", AssumeRolePolicyDocument="{}")
        monkeypatch.setattr(aws_inventory, "_boto", lambda **kw: (_Session(), None))
        yield monkeypatch


TAGS = [{"Key": "Project", "Value": "DevSecShield"}, {"Key": "zs-lab", "Value": "sandbox"}]


def _self_signed():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab.bank.test")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(7)
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("lab.bank.test")]), critical=False)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()))


def _populate() -> dict[str, list[str]]:
    made: dict[str, list[str]] = {"ec2": []}
    for i, region in enumerate(REGIONS):
        ec2 = boto3.client("ec2", region_name=region)
        image = next(i["ImageId"] for i in ec2.describe_images(Owners=["amazon"])["Images"] if not i.get("Platform"))
        out = ec2.run_instances(ImageId=image, MinCount=2, MaxCount=2, InstanceType="t3.micro", TagSpecifications=[
            {"ResourceType": "instance", "Tags": TAGS + [{"Key": "env", "Value": "prod" if i == 0 else "stage"}]}])
        made["ec2"] += [x["InstanceId"] for x in out["Instances"]]
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(DBInstanceIdentifier="zs-lab-db", DBInstanceClass="db.t4g.micro", Engine="postgres",
                           MasterUsername="zs", MasterUserPassword="never-read-9917", AllocatedStorage=20,
                           StorageEncrypted=True, Tags=TAGS)
    eks = boto3.client("eks", region_name="us-west-2")
    eks.create_cluster(name="zs-lab", roleArn=f"arn:aws:iam::{ACCOUNT}:role/eks",
                       resourcesVpcConfig={"subnetIds": []}, tags={"Project": "DevSecShield"})
    ec2 = boto3.client("ec2", region_name="eu-west-1")
    vpc = ec2.create_vpc(CidrBlock="10.7.0.0/16")["Vpc"]["VpcId"]
    subnets = [ec2.create_subnet(VpcId=vpc, CidrBlock=f"10.7.{n}.0/24", AvailabilityZone=f"eu-west-1{z}")["Subnet"]["SubnetId"]
               for n, z in ((1, "a"), (2, "b"))]
    boto3.client("elbv2", region_name="eu-west-1").create_load_balancer(Name="zs-lab-alb", Subnets=subnets, Tags=TAGS)
    cert, key = _self_signed()
    boto3.client("acm", region_name="us-east-1").import_certificate(Certificate=cert, PrivateKey=key, Tags=TAGS)
    kms = boto3.client("kms", region_name="us-west-2")
    kms.create_key(Description="lab", Tags=[{"TagKey": "Project", "TagValue": "DevSecShield"}])
    boto3.client("secretsmanager", region_name="eu-west-1").create_secret(
        Name="devsecshield-canary", SecretString="never-read-4471", Tags=TAGS)
    return made


def _discover(regions=REGIONS, services=aws_inventory.SERVICES):
    src = aws_inventory.AwsInventorySource(1, ROLE, "zs-ext-1", list(regions), list(services))
    targets = list(src.discover())
    return src.result, targets


def test_aws_discovery_covers_every_service_in_every_region(aws):
    _populate()
    result, targets = _discover()
    by_kind: dict[str, list] = {}
    for t in targets:
        by_kind.setdefault(t.kind, []).append(t)
    assert {k: len(v) for k, v in by_kind.items()} == {
        "linux_host": 6, "database": 1, "k8s_cluster": 1, "load_balancer": 1, "certificate": 1, "kms_key": 1, "secret": 1}
    assert {t.region for t in by_kind["linux_host"]} == set(REGIONS)
    host = by_kind["linux_host"][0]
    assert host.external_id.startswith(f"arn:aws:ec2:{host.region}:{ACCOUNT}:instance/i-")
    assert host.tags["project"] == "DevSecShield" and host.tags["zs-lab"] == "sandbox"
    assert host.handles["ssm"].startswith("i-") and host.address in host.addresses and host.account_id == ACCOUNT
    db = by_kind["database"][0]
    assert db.attributes["engine"] == "postgres" and db.attributes["storage_encrypted"] is True and db.address
    assert by_kind["k8s_cluster"][0].region == "us-west-2" and by_kind["load_balancer"][0].address.endswith("amazonaws.com")
    assert by_kind["certificate"][0].hostname == "lab.bank.test"
    assert result.complete and all(v == "ok" for r in result.coverage.values() for v in r.values())
    assert set(result.coverage) == set(REGIONS) and len(result.coverage["us-east-1"]) == 7
    blob = repr(targets)
    assert "never-read-9917" not in blob and "never-read-4471" not in blob  # metadata only


def test_a_role_that_does_not_require_the_external_id_is_refused(aws):
    aws.setattr(aws_inventory, "_boto", lambda **kw: (_Session(allow_without_external_id=True), None))
    with pytest.raises(InventoryError, match="without the external ID"):
        _discover()


def test_a_denied_service_is_a_coverage_gap_and_never_marks_targets_missing(aws, api, world):
    engine, _ = world
    made = _populate()
    acct = _aws_account(engine)
    src = api("POST", f"{INV}/sources", json={"kind": "aws", "name": "lab", "config": {
        "aws_account_source_id": acct, "regions": REGIONS}}).json()["source"]
    first = SYNC.run_sync(engine, src["id"])
    assert first["status"] == "ok" and first["created"] == 12, first
    again = SYNC.run_sync(engine, src["id"])
    assert again["status"] == "ok" and (again["created"], again["updated"], again["unchanged"]) == (0, 0, 12)

    real_client = boto3.session.Session.client

    def deny_kms(self, service, *a, **k):
        client = real_client(self, service, *a, **k)
        if service == "kms":
            def denied(*_a, **_k):
                raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "SCP"}}, "ListKeys")
            client.get_paginator = lambda *_a, **_k: type("P", (), {"paginate": denied})()
        return client

    aws.setattr(boto3.session.Session, "client", deny_kms)
    boto3.client("ec2", region_name="us-east-1").terminate_instances(InstanceIds=[made["ec2"][0]])
    third = SYNC.run_sync(engine, src["id"])
    assert third["status"] == "partial" and third["missing"] == 1  # the terminated one; the KMS key stays
    with Session(engine) as s:
        row = s.get(CbomInventorySource, src["id"])
        assert row.coverage["us-west-2"]["kms"] == "denied" and row.lease_until is None
        kms_rows = s.exec(select(CbomInventoryTarget).where(CbomInventoryTarget.kind == "kms_key")).all()
        assert len(kms_rows) == 1 and kms_rows[0].missing_since is None
    listed = api("GET", f"{INV}/sources").json()["sources"][0]
    assert listed["last_sync_status"] == "partial" and listed["target_count"] == 11


def test_an_unvalidated_account_is_not_read(aws, api, world):
    engine, _ = world
    acct = _aws_account(engine, validated=False)
    src = api("POST", f"{INV}/sources", json={"kind": "aws", "name": "lab", "config": {
        "aws_account_source_id": acct, "regions": ["us-east-1"]}}).json()["source"]
    out = SYNC.run_sync(engine, src["id"])
    assert out["status"] == "failed" and "Validate the AWS account first" in out["error"]
    with Session(engine) as s:
        assert s.get(CbomInventorySource, src["id"]).lease_until is None


def test_the_sync_tick_runs_queued_sources(aws, api, world):
    engine, _ = world
    _populate()
    acct = _aws_account(engine)
    api("POST", f"{INV}/sources", json={"kind": "aws", "name": "lab", "config": {
        "aws_account_source_id": acct, "regions": ["us-east-1"], "services": ["ec2"]}})
    ran = cbom_inventory_sync.tick(engine)
    assert len(ran) == 1 and ran[0]["status"] == "ok" and ran[0]["created"] == 2
    assert cbom_inventory_sync.tick(engine) == []  # not due again for an hour
