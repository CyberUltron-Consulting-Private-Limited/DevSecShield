"""F1.3 transports in the backend: routes (flag, permissions, isolation, secrets, delete guard, artifacts), releases
(signature verification), the claim plugin, fleet source kinds and credits, the SSM adapter (botocore Stubber) and the
cloud worker's ssm_hosts path.  Shared files with the scan node must stay byte-identical."""
from __future__ import annotations

import base64
import datetime as _dt
import io
import json
import secrets as _secrets
import time
from pathlib import Path

import pytest
from botocore.response import StreamingBody
from botocore.stub import Stubber
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlmodel import Session, select

from test_cbom_sources_api import api, enroll_node, world
from backend.new_models import CbomCollectedAsset, CbomCollectionAuditEvent, CbomCollectionJob, CbomCollectionSource
from backend.utilities.cbom_sources.transports import artifacts as A
from backend.utilities.cbom_sources.transports import claim as CLAIM
from backend.utilities.cbom_sources.transports import registry as R
from backend.utilities.cbom_sources.transports import zsdoc
from backend.utilities.cbom_sources.transports.base import CollectOptions, CollectTarget, TransportCredential
from backend.utilities.cbom_sources.transports.cloud import collect_ssm
from backend.utilities.cbom_sources.transports.models import CbomTransport, CbomZsCollectRelease
from backend.utilities.cbom_sources.transports.ssm import SsmTransport

FIXTURES = (api, enroll_node, world)  # the shared CBOM Sources fixtures, used by name below
ROOT = Path(__file__).resolve().parents[2]
BASE = "/1/cbom/sources/fleet/transports"
FIXTURE = json.loads((ROOT / "scan_node/tests/fixtures/zs-collect/lab-target.json").read_text())

# Test secrets are built at runtime, so no key-shaped literal sits in the source (gitleaks scans every commit).
# Each keeps an upper-case marker the assertions look for in responses and stored rows.
AWX_TOKEN = "-".join(("awx", "token", "SECRET", _secrets.token_hex(6)))
SALT_PASSWORD = "-".join(("salt", "PASSWORD", _secrets.token_hex(4)))
ROTATED_TOKEN = "-".join(("rotated", "SECRET", _secrets.token_hex(6)))
MOVED_TOKEN = "-".join(("new", "SECRET", _secrets.token_hex(4)))
AWX = {"kind": "awx", "name": "awx-prod", "config": {"base_url": "https://awx.bank.local", "job_template_id": 42},
       "secrets": {"token": AWX_TOKEN}}
SALT = {"kind": "salt", "name": "salt-dc", "config": {"base_url": "https://salt.bank.local:8000", "client": "ssh"},
        "secrets": {"username": "zs", "password": SALT_PASSWORD}}
SSM = {"kind": "ssm", "name": "aws-prod", "config": {"role_arn": "arn:aws:iam::111122223333:role/ZeroShieldCBOMRunCommand",
                                                     "regions": ["ap-south-1"],
                                                     "document_name": "devsecshield-zs-collect-1.0.0"}}


@pytest.fixture(autouse=True)
def _flag_on(monkeypatch):
    monkeypatch.setenv("CBOM_FLEET_TRANSPORTS", "1")


@pytest.fixture
def release_key(monkeypatch):
    """An ephemeral release key standing in for the committed one (the private half of which is offline)."""
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    monkeypatch.setattr(R, "public_key_pem", lambda: pem)
    monkeypatch.setattr(A, "public_key_pem", lambda: pem)
    return key


def signed_manifest(key, version="1.0.0", sha="ab" * 32) -> tuple[bytes, str]:
    manifest = {"format": "zs-collect-manifest/1", "version": version, "git_commit": "0" * 40,
                "files": [{"name": f"zs-collect-{version}-linux-amd64", "arch": "amd64", "sha256": sha, "size": 1}]}
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    return raw, base64.b64encode(key.sign(raw)).decode()


def import_active(engine, key, **kw) -> CbomZsCollectRelease:
    raw, sig = signed_manifest(key, **kw)
    with Session(engine) as s:
        row = R.import_release(s, raw, sig, activate=True, now=_dt.datetime(2026, 11, 12))
        s.commit()
        s.refresh(row)
        return row


# ----------------------------------------------------------------------------- shared files
@pytest.mark.parametrize("node,backend", [
    ("scan_node/zs_scan_node/transports/base.py", "backend/utilities/cbom_sources/transports/base.py"),
    ("scan_node/zs_scan_node/transports/zsdoc.py", "backend/utilities/cbom_sources/transports/zsdoc.py"),
    ("scan_node/zs_scan_node/transports/wrappers.py", "backend/utilities/cbom_sources/transports/wrappers.py"),
    ("scan_node/zs_collect/zs-release-ed25519.pub", "backend/utilities/cbom_sources/transports/zs-release-ed25519.pub"),
])
def test_files_shared_with_the_scan_node_are_byte_identical(node, backend):
    assert (ROOT / node).read_bytes() == (ROOT / backend).read_bytes(), f"{backend} must be a copy of {node}"


# ----------------------------------------------------------------------------- routes
def test_routes_do_not_exist_while_the_flag_is_off(api, monkeypatch):
    monkeypatch.setenv("CBOM_FLEET_TRANSPORTS", "0")
    for method, url in (("GET", BASE), ("POST", BASE), ("PATCH", BASE + "/1"), ("DELETE", BASE + "/1"),
                        ("POST", BASE + "/1/validate"), ("GET", BASE + "/artifacts/zs-collect-pubkey")):
        r = api(method, url, json={})
        assert r.status_code == 404 and r.json() == {"detail": "Not Found"}, (method, url, r.text)


def test_create_list_update_with_write_only_secrets_and_an_audit_trail(api, world):
    engine, _ids = world
    r = api("POST", BASE, json=AWX)
    assert r.status_code == 201, r.text
    t = r.json()["transport"]
    assert t["secrets_set"] == ["token"] and "SECRET" not in r.text and t["config"]["verify_tls"] is True
    assert api("POST", BASE, json=SALT).status_code == 201
    assert api("POST", BASE, json=SSM).status_code == 201
    listing = api("GET", BASE, "bob")  # any member may read
    assert listing.status_code == 200 and [x["kind"] for x in listing.json()["transports"]] == ["awx", "salt", "ssm"]
    assert "SECRET" not in listing.text and "PASSWORD" not in listing.text
    assert listing.json()["release"] is None and listing.json()["release_key_fingerprint"].startswith("SHA256:")
    up = api("PATCH", f"{BASE}/{t['id']}", json={"expected_version": t["row_version"], "name": "awx-main",
                                                  "secrets": {"token": ROTATED_TOKEN}})
    assert up.status_code == 200, up.text
    assert up.json()["transport"]["row_version"] == t["row_version"] + 1 and "SECRET" not in up.text
    stale = api("PATCH", f"{BASE}/{t['id']}", json={"expected_version": t["row_version"], "enabled": False})
    assert stale.status_code == 409
    with Session(engine) as s:
        row = s.get(CbomTransport, t["id"])
        assert "SECRET" not in (row.secret_encrypted or "") and row.name == "awx-main"
        actions = [e.action for e in s.exec(select(CbomCollectionAuditEvent)).all()]
        assert actions.count("transport.create") == 3 and "transport.update" in actions
        assert all("SECRET" not in json.dumps(e.changed_fields) for e in s.exec(select(CbomCollectionAuditEvent)).all())


def test_members_cannot_write_and_other_teams_cannot_see(api):
    t = api("POST", BASE, json=AWX).json()["transport"]
    r = api("POST", BASE, "bob", json={**AWX, "name": "x"})
    assert r.status_code == 400 and "team admin" in r.json()["detail"]
    assert api("PATCH", f"{BASE}/{t['id']}", "bob", json={"enabled": False}).status_code == 400
    assert api("DELETE", f"{BASE}/{t['id']}", "bob").status_code == 400
    assert api("GET", BASE, "carol").status_code == 403  # not a member of team 1: the existing answer
    assert api("GET", BASE, None).status_code == 401
    other = "/2/cbom/sources/fleet/transports"
    assert api("PATCH", f"{other}/{t['id']}", "carol", json={"enabled": False}).status_code == 404
    assert api("DELETE", f"{other}/{t['id']}", "carol").status_code == 404
    assert api("GET", other, "carol").json()["transports"] == []


@pytest.mark.parametrize("body,needle", [
    ({**AWX, "config": {**AWX["config"], "base_url": "http://awx.bank.local"}}, "https"),
    ({**AWX, "config": {**AWX["config"], "base_url": "https://user:pw@awx.bank.local"}}, "https"),
    ({**AWX, "secrets": {}}, "secrets.token"),
    ({**AWX, "secrets": {"token": "t", "password": "p"}}, "secrets.password"),
    ({**SALT, "config": {**SALT["config"], "client": "runner"}}, "Client"),
    ({**SSM, "config": {**SSM["config"], "document_name": "AWS-RunShellScript"}}, "Document name"),
    ({**SSM, "config": {**SSM["config"], "role_arn": "arn:aws:iam::111122223333:user/x"}}, "role"),
    ({**AWX, "config": {**AWX["config"], "surprise": 1}}, "Surprise"),
])
def test_bad_bodies_are_a_readable_400_that_never_echoes_secrets(api, body, needle):
    r = api("POST", BASE, json=body)
    assert r.status_code == 400 and needle.lower() in r.json()["detail"].lower(), r.text
    assert "SECRET" not in r.text and "PASSWORD" not in r.text


def test_moving_the_control_plane_needs_the_secret_again(api):
    t = api("POST", BASE, json=AWX).json()["transport"]
    moved = {**AWX["config"], "base_url": "https://awx.elsewhere.example"}
    r = api("PATCH", f"{BASE}/{t['id']}", json={"config": moved})
    assert r.status_code == 400 and "re-enter" in r.json()["detail"]
    r = api("PATCH", f"{BASE}/{t['id']}", json={"config": moved, "secrets": {"token": MOVED_TOKEN}})
    assert r.status_code == 200 and r.json()["transport"]["config"]["base_url"] == "https://awx.elsewhere.example"


def fleet_source(api, transport_id, kind="awx_hosts", node_id=None, targets=("10.30.0.1", "10.30.0.2"), **cfg):
    handles = {t: f"i-0{i}23456789abcdef0" if kind == "ssm_hosts" else f"host-{i}" for i, t in enumerate(targets)}
    body = {"kind": kind, "name": f"{kind}-fleet", "node_id": node_id,
            "config": {"transport_id": transport_id, "targets": list(targets), "handles": handles, "tier": 2, **cfg}}
    return api("POST", "/1/cbom/sources/items", json=body)


def test_delete_is_refused_while_a_source_uses_the_transport_and_erases_its_secrets(api, world):
    engine, _ = world
    t = api("POST", BASE, json=AWX).json()["transport"]
    node_id, _token, _ = enroll_node(api)
    src = fleet_source(api, t["id"], node_id=node_id)
    assert src.status_code == 201, src.text
    r = api("DELETE", f"{BASE}/{t['id']}")
    assert r.status_code == 409 and "awx_hosts-fleet" in r.json()["detail"]
    assert api("GET", BASE).json()["transports"][0]["used_by"] == [{"id": src.json()["source"]["id"],
                                                                     "name": "awx_hosts-fleet"}]
    assert api("DELETE", f"/1/cbom/sources/items/{src.json()['source']['id']}").status_code == 200
    assert api("DELETE", f"{BASE}/{t['id']}").status_code == 200
    with Session(engine) as s:
        row = s.get(CbomTransport, t["id"])
        assert row.deleted_at is not None and row.secret_encrypted is None and row.enabled is False
    assert api("GET", BASE).json()["transports"] == []
    assert api("PATCH", f"{BASE}/{t['id']}", json={"enabled": True}).status_code == 404


def test_validate_is_for_ssm_only(api):
    t = api("POST", BASE, json=SALT).json()["transport"]
    r = api("POST", f"{BASE}/{t['id']}/validate")
    assert r.status_code == 400 and "Test a source" in r.json()["detail"]


def test_ssm_validate_without_zeroshield_aws_principal_fails_cleanly(api, monkeypatch):
    for name in ("CBOM_AWS_ACCESS_KEY_ID", "CBOM_AWS_SECRET_ACCESS_KEY"):
        monkeypatch.delenv(name, raising=False)
    t = api("POST", BASE, json=SSM).json()["transport"]
    r = api("POST", f"{BASE}/{t['id']}/validate")
    assert r.status_code == 200 and r.json()["status"] == "failed" and "not configured" in r.json()["summary"]


# ----------------------------------------------------------------------------- releases and artifacts
def test_release_import_verifies_the_signature(world, release_key):
    engine, _ = world
    raw, sig = signed_manifest(release_key)
    other = ed25519.Ed25519PrivateKey.generate()
    with Session(engine) as s:
        with pytest.raises(R.ReleaseError, match="signature"):
            R.import_release(s, raw.replace(b"1.0.0", b"1.0.1"), sig, activate=True, now=_dt.datetime(2026, 11, 12))
        with pytest.raises(R.ReleaseError, match="signature"):
            R.import_release(s, raw, base64.b64encode(other.sign(raw)).decode(), activate=True,
                             now=_dt.datetime(2026, 11, 12))
        assert s.exec(select(CbomZsCollectRelease)).all() == []
    row = import_active(engine, release_key)
    assert row.active and row.sha256_amd64 == "ab" * 32 and row.key_fingerprint.startswith("SHA256:")
    with Session(engine) as s:
        assert R.active_release(s).id == row.id
        db_row = s.get(CbomZsCollectRelease, row.id)
        db_row.sha256_amd64 = "cd" * 32  # edited in the database: no longer what was signed
        s.commit()
        assert R.active_release(s) is None


def test_artifacts_are_rendered_for_the_active_release(api, world, release_key):
    engine, _ = world
    r = api("GET", BASE + "/artifacts/ssm-document")
    assert r.status_code == 400 and "No verified zs-collect release" in r.json()["detail"]
    pub = api("GET", BASE + "/artifacts/zs-collect-pubkey", "bob").json()
    assert pub["public_key"].startswith("-----BEGIN PUBLIC KEY-----") and pub["fingerprint"].startswith("SHA256:")
    cfn = api("GET", BASE + "/artifacts/ssm-role-cfn")
    assert cfn.status_code == 200 and "document/devsecshield-*" in cfn.text and "sts:ExternalId" in cfn.text
    assert "SecurityAudit" not in cfn.text  # the run-command role is not the reader role
    import_active(engine, release_key, sha="ef" * 32)
    doc = api("GET", BASE + "/artifacts/ssm-document").json()
    assert doc["name"] == "devsecshield-zs-collect-1.0.0"
    script = "\n".join(doc["content"]["mainSteps"][0]["inputs"]["runCommand"])
    assert "ef" * 32 in script and "openssl pkeyutl -verify" in script
    salt = api("GET", BASE + "/artifacts/salt-state").json()["files"]
    assert set(salt) == {"zeroshield/zs_collect.sls", "zeroshield/zs-collect-run.sh"} and "ef" * 32 in salt[
        "zeroshield/zs-collect-run.sh"]
    ans = api("GET", BASE + "/artifacts/ansible-collection").json()["files"]
    assert set(ans) == {"zs-collect.yml", "files/zs-collect-run.sh"}
    man = api("GET", BASE + "/artifacts/zs-collect-manifest").json()
    assert R.verify_manifest(man["manifest"].encode(), man["signature"])["version"] == "1.0.0"
    assert api("GET", BASE + "/artifacts/nope").status_code == 404


# ----------------------------------------------------------------------------- fleet kinds, credits, claim plugin
def test_fleet_sources_cost_what_linux_servers_cost(api, world):
    t = api("POST", BASE, json=AWX).json()["transport"]
    node_id, _token, _ = enroll_node(api)
    assert fleet_source(api, t["id"], node_id=node_id, targets=[f"10.30.0.{i}" for i in range(1, 11)]).status_code == 201
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"servers": True}}).json()
    items = [i for i in est["items"] if i["kind"] == "awx_hosts"]
    assert items and items[0]["units"] == 10 and items[0]["credits"] == 2.0  # 0.2 per target, RATES_C["server"]


@pytest.mark.parametrize("kind,targets,handles,needle", [
    ("awx_hosts", ["10.0.0.0/30"], {}, "range"),
    ("awx_hosts", ["10.0.0.1"], {"10.0.0.1": "web:&all"}, "awx host name"),
    ("ssm_hosts", ["10.0.0.1"], {"10.0.0.1": "web-1"}, "instance id"),
    ("salt_hosts", ["10.0.0.1"], {"10.0.0.9": "m1"}, "not one of the targets"),
])
def test_fleet_source_configs_are_checked(api, kind, targets, handles, needle):
    t = api("POST", BASE, json=AWX).json()["transport"]
    node_id, _token, _ = enroll_node(api)
    r = api("POST", "/1/cbom/sources/items", json={"kind": kind, "name": "bad", "node_id": None if kind == "ssm_hosts"
                                                    else node_id, "config": {"transport_id": t["id"], "targets": targets,
                                                                             "handles": handles}})
    assert r.status_code == 400 and needle in r.json()["detail"].lower(), r.text


def test_fleet_kinds_are_refused_while_the_flag_is_off(api, monkeypatch):
    t = api("POST", BASE, json=AWX).json()["transport"]
    node_id, _token, _ = enroll_node(api)
    monkeypatch.setenv("CBOM_FLEET_TRANSPORTS", "0")
    r = fleet_source(api, t["id"], node_id=node_id)
    assert r.status_code == 400 and "turned off" in r.json()["detail"]


def test_claim_plugin_gives_the_transport_its_secrets_and_the_release(api, world, release_key, monkeypatch):
    engine, _ = world
    t = api("POST", BASE, json=AWX).json()["transport"]
    node_id, _token, _ = enroll_node(api)
    src_id = fleet_source(api, t["id"], node_id=node_id).json()["source"]["id"]
    import_active(engine, release_key)
    with Session(engine) as s:
        src = s.get(CbomCollectionSource, src_id)
        out = CLAIM.claim_extras(s, src, None, None, {"config": dict(src.config), "secrets": {}})
        assert out["config"]["transport"]["base_url"] == "https://awx.bank.local"
        assert out["secrets"] == {"token": AWX_TOKEN}
        assert out["config"]["zs_collect"] == {"version": "1.0.0", "sha256": {"amd64": "ab" * 32}}
        assert CLAIM.known_secrets(s, src) == [AWX_TOKEN]
        v1 = CLAIM.version_input(s, src)
    api("PATCH", f"{BASE}/{t['id']}", json={"config": {**AWX["config"], "timeout_s": 60}})
    with Session(engine) as s:
        src = s.get(CbomCollectionSource, src_id)
        assert CLAIM.version_input(s, src) != v1  # an edited transport changes the job's connection version
        # a transport of another team behind the same id is never used
        row = s.get(CbomTransport, t["id"])
        row.team_id = 2
        s.commit()
        out = CLAIM.claim_extras(s, src, None, None, {"config": dict(src.config), "secrets": {}})
        assert out["config"]["transport"] is None and "deleted or does not exist" in out["config"]["transport_problem"]
        assert out["secrets"] == {}
        row.team_id, row.enabled = 1, False
        s.commit()
        out = CLAIM.claim_extras(s, src, None, None, {"config": dict(src.config), "secrets": {}})
        assert "disabled" in out["config"]["transport_problem"] and out["secrets"] == {}
        row.enabled = True
        s.commit()
    monkeypatch.setenv("CBOM_FLEET_TRANSPORTS", "0")
    with Session(engine) as s:
        src = s.get(CbomCollectionSource, src_id)
        out = CLAIM.claim_extras(s, src, None, None, {"config": dict(src.config), "secrets": {}})
        assert out["config"]["transport"] is None and "turned off" in out["config"]["transport_problem"]


def test_claim_plugin_leaves_other_kinds_alone(world):
    engine, _ = world

    class Src:
        kind, team_id, config = "linux_servers", 1, {"transport_id": 1}

    with Session(engine) as s:
        assert CLAIM.claim_extras(s, Src(), None, None, {"config": {}, "secrets": {}}) is None
        assert CLAIM.version_input(s, Src()) is None and CLAIM.known_secrets(s, Src()) == []


# ----------------------------------------------------------------------------- SSM adapter (botocore Stubber)
NONCE = "zs-7-1-0123456789abcdef"


def doc_for(label: str, nonce: str = NONCE) -> dict:
    doc = json.loads(json.dumps(FIXTURE))
    own = doc["target_label"]
    doc.update(run_nonce=nonce, target_label=label)
    for a in doc["assets"]:
        a["target"] = label
        if a["type"] == "coverage":
            a["location"] = label + a["location"][len(own):]
    return doc


def options(stop=None) -> CollectOptions:
    return CollectOptions(tier=2, run_nonce=NONCE, deadline=time.monotonic() + 60, timeout_per_target_s=60,
                          max_concurrency="10%", zs_collect_sha256={"amd64": "a" * 64},
                          should_stop=stop or (lambda: None), collector_version=FIXTURE["collector_version"])


class Clients:
    def __init__(self):
        import boto3

        session = boto3.session.Session(aws_access_key_id="x", aws_secret_access_key="y", region_name="ap-south-1")
        self.ssm = session.client("ssm", region_name="ap-south-1")
        self.s3 = session.client("s3", region_name="ap-south-1")
        self.ssm_stub, self.s3_stub = Stubber(self.ssm), Stubber(self.s3)

    def __call__(self, service, region):
        return {"ssm": self.ssm, "s3": self.s3}[service]


CMD = "0f3c2b1a-1111-4222-8333-444455556666"
IDS = ["i-0123456789abcdef0", "i-0123456789abcdef1", "i-0123456789abcdef2"]
CRED = TransportCredential("aws_role", {"role_arn": "arn:aws:iam::111122223333:role/R", "regions": ["ap-south-1"],
                                        "document_name": "devsecshield-zs-collect-1.0.0"}, {})


def _stub_common(c: Clients, online: list[str], sent: list[str], bucket=None, ids=None):
    c.ssm_stub.add_response("describe_document", {"Document": {"Name": "devsecshield-zs-collect-1.0.0"}},
                            {"Name": "devsecshield-zs-collect-1.0.0"})
    c.ssm_stub.add_response("describe_instance_information", {"InstanceInformationList": [
        {"InstanceId": i, "PingStatus": "Online"} for i in online]},
        {"Filters": [{"Key": "InstanceIds", "Values": ids or IDS}], "MaxResults": 50})
    if not sent:
        return
    params = {"InstanceIds": sent, "DocumentName": "devsecshield-zs-collect-1.0.0",
              "Parameters": {"nonce": [NONCE], "tier": ["2"], "output": ["json" if bucket else "chunks"]},
              "TimeoutSeconds": 600, "Comment": f"ZeroShield CBOM collection {NONCE}", "MaxConcurrency": "10%",
              "MaxErrors": "100%"}
    if bucket:
        params.update(OutputS3BucketName=bucket, OutputS3KeyPrefix="zs")
    c.ssm_stub.add_response("send_command", {"Command": {"CommandId": CMD}}, params)


def test_ssm_inline_output_unmanaged_instances_and_integrity_refusals():
    c = Clients()
    _stub_common(c, online=IDS[:2], sent=IDS[:2])
    c.ssm_stub.add_response("list_command_invocations", {"CommandInvocations": [
        {"InstanceId": IDS[0], "Status": "Success"}, {"InstanceId": IDS[1], "Status": "Failed"}]},
        {"CommandId": CMD, "Details": False, "MaxResults": 50})
    line = "\n".join(zsdoc.encode_chunks(doc_for("10.0.0.1"), NONCE, 512 * 1024))
    assert len(line) < 24000
    c.ssm_stub.add_response("get_command_invocation", {"StandardOutputContent": line, "StandardErrorContent": "ZSRC 0\n"},
                            {"CommandId": CMD, "InstanceId": IDS[0], "PluginName": "zsCollect"})
    c.ssm_stub.add_response("get_command_invocation", {"StandardOutputContent": "",
                                                       "StandardErrorContent": "zs-collect: checksum mismatch\nZSRC 4\n"},
                            {"CommandId": CMD, "InstanceId": IDS[1], "PluginName": "zsCollect"})
    targets = [CollectTarget(f"10.0.0.{i + 1}", h) for i, h in enumerate(IDS)]
    with c.ssm_stub:
        out = {r.target.handle: r for r in SsmTransport(c, poll_s=0).run_collect(targets, CRED, options())}
    assert out[IDS[2]].status == "unreachable"  # never sent a command
    assert out[IDS[0]].status == "ok" and out[IDS[0]].document["run_nonce"] == NONCE
    assert out[IDS[1]].status == "refused" and "integrity" in out[IDS[1]].error


def test_ssm_output_bucket_is_read_from_s3_and_inline_overflow_is_refused():
    c = Clients()
    cred = TransportCredential("aws_role", {**CRED.config, "output_s3_bucket": "cust-ssm-out", "output_s3_prefix": "zs"},
                               {})
    _stub_common(c, online=IDS[:1], sent=IDS[:1], bucket="cust-ssm-out", ids=IDS[:1])
    c.ssm_stub.add_response("list_command_invocations", {"CommandInvocations": [
        {"InstanceId": IDS[0], "Status": "Success"}]}, {"CommandId": CMD, "Details": False, "MaxResults": 50})
    c.ssm_stub.add_response("get_command_invocation", {"StandardOutputContent": "x" * 24000, "StandardErrorContent": ""},
                            {"CommandId": CMD, "InstanceId": IDS[0], "PluginName": "zsCollect"})
    big = doc_for("10.0.0.1")
    big["assets"] += [{**a, "location": f"{a['location']}#copy{i}"} for i, a in enumerate(big["assets"] * 3)]
    body = json.dumps(big).encode()
    c.s3_stub.add_response("get_object", {"Body": StreamingBody(io.BytesIO(body), len(body))},
                           {"Bucket": "cust-ssm-out", "Key": f"zs/{CMD}/{IDS[0]}/awsrunShellScript/zsCollect/stdout"})
    with c.ssm_stub, c.s3_stub:
        out = list(SsmTransport(c, poll_s=0).run_collect([CollectTarget("10.0.0.1", IDS[0])], cred, options()))
    assert out[0].status == "ok" and len(body) > 24000  # the whole document, past the inline limit
    assert len(out[0].document["assets"]) == len(big["assets"])
    c2 = Clients()
    _stub_common(c2, online=IDS[:1], sent=IDS[:1], ids=IDS[:1])
    c2.ssm_stub.add_response("list_command_invocations", {"CommandInvocations": [
        {"InstanceId": IDS[0], "Status": "Success"}]}, {"CommandId": CMD, "Details": False, "MaxResults": 50})
    c2.ssm_stub.add_response("get_command_invocation", {"StandardOutputContent": "ZSC1 " + "x" * 23995,
                                                        "StandardErrorContent": ""},
                             {"CommandId": CMD, "InstanceId": IDS[0], "PluginName": "zsCollect"})
    with c2.ssm_stub:
        out = list(SsmTransport(c2, poll_s=0).run_collect([CollectTarget("10.0.0.1", IDS[0])], CRED, options()))
    assert out[0].status == "error" and "output bucket" in out[0].error


def test_ssm_refusals():
    from backend.utilities.cbom_sources.transports.base import TransportError

    c = Clients()
    with pytest.raises(TransportError) as e:
        list(SsmTransport(c).run_collect([CollectTarget("10.0.0.1", IDS[0])],
                                         TransportCredential("aws_role", {**CRED.config, "document_name": "AWS-RunShellScript"}, {}),
                                         options()))
    assert e.value.status == "refused"
    c.ssm_stub.add_client_error("describe_document", "AccessDeniedException")
    with c.ssm_stub, pytest.raises(TransportError) as e:
        list(SsmTransport(c).run_collect([CollectTarget("10.0.0.1", IDS[0])], CRED, options()))
    assert e.value.status == "auth_failed"


def test_cloud_side_checks_never_scan_and_relabels():
    class Fake:
        def __init__(self):
            self.seen = []

        def run_collect(self, targets, credential, options):
            from backend.utilities.cbom_sources.transports.base import TargetResult

            self.seen = [t.label for t in targets]
            for t in targets:
                yield TargetResult(t, "ok", None, doc_for("ip-10-0-0-1.internal", options.run_nonce))

    emitted = []
    fake = Fake()
    config = {"targets": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
              "handles": {"10.0.0.1": IDS[0], "10.0.0.2": IDS[1], "10.0.0.3": IDS[2]},
              "addresses": {"10.0.0.3": ["10.0.0.3", "192.168.9.3"]}, "tier": 2,
              "transport": dict(CRED.config), "zs_collect": {"version": FIXTURE["collector_version"], "sha256": {}}}
    result = collect_ssm({"id": 5, "attempt": 1, "kind": "collect"}, config, ["10.0.0.2", "192.168.9.0/24"], fake,
                         emitted.append, lambda: None, time.monotonic() + 60)
    assert fake.seen == ["10.0.0.1"]
    rows = {r["target"]: r for r in result["targets"]}
    assert rows["10.0.0.2"]["status"] == rows["10.0.0.3"]["status"] == "skipped_never_scan"
    assert rows["10.0.0.1"]["status"] == "ok" and {a["target"] for a in emitted} == {"10.0.0.1"}
    assert all(a["location"].startswith("10.0.0.1#") for a in emitted if a["type"] == "coverage")


def test_cloud_worker_runs_an_ssm_job_end_to_end(api, world, release_key, monkeypatch):
    from backend.workers import cbom_cloud_worker as W
    from backend.utilities.cbom_sources import transports as _pkg  # noqa: F401
    from backend.utilities.cbom_sources.transports import ssm as SSM_MOD

    engine, _ = world
    import_active(engine, release_key)
    t = api("POST", BASE, json=SSM).json()["transport"]
    src = fleet_source(api, t["id"], kind="ssm_hosts")
    assert src.status_code == 201, src.text

    class FakeSsm:
        def __init__(self, *_a, **_k):
            pass

        def run_collect(self, targets, credential, options):
            from backend.utilities.cbom_sources.transports.base import TargetResult

            assert credential.config["document_name"] == "devsecshield-zs-collect-1.0.0"
            for t_ in targets:
                yield TargetResult(t_, "ok", None, doc_for("some-hostname", options.run_nonce))

    monkeypatch.setattr(SSM_MOD, "SsmTransport", FakeSsm)
    monkeypatch.setattr(SSM_MOD, "role_client_factory", lambda *a: None)
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": "ssm-run-0001"})
    assert run.status_code == 201, run.text
    assert W.run_once(engine, "test-worker") is True
    with Session(engine) as s:
        job = s.exec(select(CbomCollectionJob)).all()[-1]
        assert job.status == "success", (job.status, job.error)
        targets = {a.target for a in s.exec(select(CbomCollectedAsset)).all()}
        assert targets == {"10.30.0.1", "10.30.0.2"}
