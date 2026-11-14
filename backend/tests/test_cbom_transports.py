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
    return CollectOptions(tier=2, run_nonce=NONCE, deadline=time.monotonic() + 3600, timeout_per_target_s=60,
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


def timeout_seconds(n_sent: int, max_concurrency: str = "10%", per_target_s: int = 60) -> int:
    """What SendCommand's TimeoutSeconds must be: SSM runs n instances in waves of MaxConcurrency (a percentage is
    read rounded down, at least 1), each within the per-target timeout plus zs-collect's 60 s command overrun, plus
    120 s of slack."""
    import math

    pct = int(max_concurrency[:-1]) if max_concurrency.endswith("%") else None
    at_once = max(1, min(n_sent, n_sent * pct // 100 if pct is not None else int(max_concurrency)))
    return math.ceil(n_sent / at_once) * (per_target_s + 60) + 120 + 60  # + the margin before DeliveryTimedOut


def _stub_common(c: Clients, online: list[str], sent: list[str], bucket=None, ids=None):
    c.ssm_stub.add_response("describe_document", {"Document": {"Name": "devsecshield-zs-collect-1.0.0"}},
                            {"Name": "devsecshield-zs-collect-1.0.0"})
    c.ssm_stub.add_response("describe_instance_information", {"InstanceInformationList": [
        {"InstanceId": i, "PingStatus": "Online"} for i in online]},
        {"Filters": [{"Key": "InstanceIds", "Values": ids or IDS}], "MaxResults": 50})
    if not sent:
        return
    params = {"InstanceIds": sent, "DocumentName": "devsecshield-zs-collect-1.0.0",
              # the source's per-host timeout (options: 60 s) reaches zs-collect as the document's timeout parameter
              "Parameters": {"nonce": [NONCE], "tier": ["2"], "timeout": ["60"],
                             "output": ["json" if bucket else "chunks"]},
              "TimeoutSeconds": timeout_seconds(len(sent)), "Comment": f"ZeroShield CBOM collection {NONCE}",
              "MaxConcurrency": "10%",
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


# ----------------------------------------------------------------------------- SSM: one instance never fails the batch
def nested_line(depth: int = 11_500) -> str:
    """A JSON line nested past the parser's recursion limit, still under SSM's 24,000-character inline cap."""
    return '{"format":"zs-collect/1","x":' + "[" * depth + "]" * depth + "}"


def test_ssm_an_instance_with_a_nested_document_is_its_own_error_and_the_others_are_kept():
    text = nested_line()
    assert len(text) < 24_000
    with pytest.raises(RecursionError):  # the hazard: json.loads alone would raise out of the transport
        json.loads(text)
    c = Clients()
    _stub_common(c, online=IDS, sent=IDS)
    c.ssm_stub.add_response("list_command_invocations", {"CommandInvocations": [
        {"InstanceId": i, "Status": "Success"} for i in IDS]}, {"CommandId": CMD, "Details": False, "MaxResults": 50})
    for i, instance in enumerate(IDS):
        out = text if i == 1 else "\n".join(zsdoc.encode_chunks(doc_for(f"10.0.0.{i + 1}"), NONCE, 512 * 1024))
        c.ssm_stub.add_response("get_command_invocation", {"StandardOutputContent": out,
                                                           "StandardErrorContent": "ZSRC 0\n"},
                                {"CommandId": CMD, "InstanceId": instance, "PluginName": "zsCollect"})
    config = {"targets": ["10.0.0.1", "10.0.0.2", "10.0.0.3"], "handles": dict(zip(["10.0.0.1", "10.0.0.2", "10.0.0.3"], IDS)),
              "tier": 2, "timeout_s": 60, "transport": dict(CRED.config),
              "zs_collect": {"version": FIXTURE["collector_version"], "sha256": {}}}
    emitted = []
    import backend.utilities.cbom_sources.transports.cloud as CLOUD

    real_nonce = CLOUD._secrets.token_hex
    try:  # the nonce collect_ssm makes is NONCE, so the stubbed parameters match
        CLOUD._secrets.token_hex = lambda n: NONCE.rsplit("-", 1)[1]
        with c.ssm_stub:
            result = collect_ssm({"id": 7, "attempt": 1, "kind": "collect"}, config, [], SsmTransport(c, poll_s=0),
                                 emitted.append, lambda: None, time.monotonic() + 3600)
            c.ssm_stub.assert_no_pending_responses()
    finally:
        CLOUD._secrets.token_hex = real_nonce
    rows = {r["target"]: r for r in result["targets"]}
    assert rows["10.0.0.1"]["status"] == rows["10.0.0.3"]["status"] == "ok"
    assert rows["10.0.0.2"]["status"] == "error" and "not a JSON document" in rows["10.0.0.2"]["error"]
    assert {a["target"] for a in emitted} == {"10.0.0.1", "10.0.0.3"}
    assert result["summary"].startswith("2 of 3 instances collected")


def test_cloud_one_instances_failure_never_fails_the_others():
    from backend.utilities.cbom_sources.transports.base import TargetResult

    class Dies:
        def run_collect(self, targets, credential, options):
            yield TargetResult(targets[0], "ok", None, doc_for("h", options.run_nonce))
            raise RuntimeError("the boto3 client broke")

    config = {"targets": ["10.0.0.1", "10.0.0.2"], "handles": {"10.0.0.1": IDS[0], "10.0.0.2": IDS[1]}, "tier": 2,
              "transport": dict(CRED.config), "zs_collect": {"version": FIXTURE["collector_version"], "sha256": {}}}
    emitted = []
    result = collect_ssm({"id": 5, "attempt": 1, "kind": "collect"}, config, [], Dies(), emitted.append,
                         lambda: None, time.monotonic() + 60)
    rows = {r["target"]: r for r in result["targets"]}
    assert rows["10.0.0.1"]["status"] == "ok" and emitted
    assert rows["10.0.0.2"]["status"] == "error" and "RuntimeError" in rows["10.0.0.2"]["error"]


# ----------------------------------------------------------------------------- SSM: waves, statuses, batches
class FakeClock:
    def __init__(self):
        self.t = 10_000.0

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.t += s


class WaveSsm:
    """An SSM that runs a command in waves of MaxConcurrency (a percentage rounded up, as SSM does at least as fast
    as the transport assumes) and never starts an instance after TimeoutSeconds (DeliveryTimedOut)."""

    def __init__(self, clock: FakeClock, per_host_s: float):
        self.clock, self.per_host_s, self.sent, self.cancelled = clock, per_host_s, [], []

    def describe_document(self, Name):
        return {"Document": {"Name": Name}}

    def describe_instance_information(self, **kw):
        return {"InstanceInformationList": [{"InstanceId": i, "PingStatus": "Online"}
                                            for i in kw["Filters"][0]["Values"]]}

    def send_command(self, **kw):
        import math

        mc, n = kw["MaxConcurrency"], len(kw["InstanceIds"])
        self.at_once = max(1, math.ceil(n * int(mc[:-1]) / 100)) if mc.endswith("%") else int(mc)
        self.sent.append({**kw, "t0": self.clock.t})
        return {"Command": {"CommandId": f"cmd-{len(self.sent)}"}}

    def _status(self, k: int) -> str:
        cmd = self.sent[-1]
        start = (k // self.at_once) * self.per_host_s
        elapsed = self.clock.t - cmd["t0"]
        if self.cancelled:
            return "Success" if elapsed >= start + self.per_host_s else "Cancelled"
        if start > cmd["TimeoutSeconds"] and elapsed > cmd["TimeoutSeconds"]:
            return "DeliveryTimedOut"
        return "Pending" if elapsed < start else "InProgress" if elapsed < start + self.per_host_s else "Success"

    def list_command_invocations(self, **kw):
        ids = self.sent[-1]["InstanceIds"]
        return {"CommandInvocations": [{"InstanceId": i, "Status": self._status(k)} for k, i in enumerate(ids)]}

    def cancel_command(self, CommandId):
        self.cancelled.append((CommandId, self.clock.t))

    def get_command_invocation(self, CommandId, InstanceId, PluginName):
        label = f"10.1.{int(InstanceId[-4:], 16) // 256}.{int(InstanceId[-4:], 16) % 256}"
        nonce = self.sent[-1]["Parameters"]["nonce"][0]
        return {"StandardOutputContent": json.dumps(doc_for(label, nonce)), "StandardErrorContent": "ZSRC 0\n"}


def wave_targets(n: int) -> list[CollectTarget]:
    return [CollectTarget(f"10.1.{k // 256}.{k % 256}", f"i-{k:017x}") for k in range(n)]


@pytest.mark.parametrize("per_host_s", [8.5, 60, 120, 280])
def test_ssm_50_instances_at_10_percent_all_finish_inside_the_wait(monkeypatch, per_host_s):
    """50 instances, MaxConcurrency 10% (5 at a time, 10 waves), each host well inside its 300 s timeout: every one
    is collected.  Before the wave-aware budget (one timeout + 120 s for the whole command, TimeoutSeconds 600) the
    same run gave 35 ok / 15 timeout at 60 s per host and 15 ok / 35 timeout at 120 s (review 5874466030)."""
    from backend.utilities.cbom_sources.transports import ssm as SSM_MOD

    clock = FakeClock()
    monkeypatch.setattr(SSM_MOD, "time", clock)
    fake = WaveSsm(clock, per_host_s)
    opts = CollectOptions(tier=1, run_nonce=NONCE, deadline=clock.t + 8 * 3600, timeout_per_target_s=300,
                          max_concurrency="10%", zs_collect_sha256={}, should_stop=lambda: None,
                          collector_version=FIXTURE["collector_version"])
    started = clock.t
    out = list(SsmTransport(lambda svc, region: fake, poll_s=3.0).run_collect(wave_targets(50), CRED, opts))
    assert [r.status for r in out].count("ok") == 50, sorted({(r.status, r.error) for r in out if r.status != "ok"})
    (cmd,) = fake.sent
    assert cmd["MaxConcurrency"] == "10%" and len(cmd["InstanceIds"]) == 50
    assert cmd["TimeoutSeconds"] >= 10 * 300 + 120  # 10 waves of a 300 s timeout, plus slack
    assert fake.cancelled == [] and clock.t - started <= 10 * per_host_s + 3 * 2


def test_ssm_wait_never_passes_the_job_deadline(monkeypatch):
    """A budget longer than the job has left: the command is cancelled at the deadline, what finished is kept, the
    rest is reported, and TimeoutSeconds still covers the whole wait."""
    from backend.utilities.cbom_sources.transports import ssm as SSM_MOD

    clock = FakeClock()
    monkeypatch.setattr(SSM_MOD, "time", clock)
    fake = WaveSsm(clock, 120)
    opts = CollectOptions(tier=1, run_nonce=NONCE, deadline=clock.t + 700, timeout_per_target_s=300,
                          max_concurrency="10%", zs_collect_sha256={}, should_stop=lambda: None,
                          collector_version=FIXTURE["collector_version"])
    out = list(SsmTransport(lambda svc, region: fake, poll_s=3.0).run_collect(wave_targets(50), CRED, opts))
    statuses = [r.status for r in out]
    # waves 1-5 done by 600 s; wave 6 running at 700 s (timeout); waves 7-10 never started (skipped, not unreachable)
    assert (statuses.count("ok"), statuses.count("timeout"), statuses.count("skipped_deadline")) == (25, 5, 20)
    assert fake.sent[0]["TimeoutSeconds"] >= 700 and fake.cancelled and fake.cancelled[0][1] <= opts.deadline + 3
    clock.t = opts.deadline + 1  # nothing is sent once the deadline has passed
    out = list(SsmTransport(lambda svc, region: fake, poll_s=3.0).run_collect(wave_targets(2), CRED, opts))
    assert {r.status for r in out} == {"skipped_deadline"} and len(fake.sent) == 1


@pytest.mark.parametrize("final,expected", [
    ("Undeliverable", "unreachable"), ("Terminated", "unreachable"), ("DeliveryTimedOut", "unreachable"),
    ("InvalidPlatform", "unreachable"), ("TimedOut", "timeout"), ("ExecutionTimedOut", "timeout"),
    ("AccessDenied", "refused"), ("Cancelled", "timeout"), ("Cancelling", "timeout"),
])
def test_ssm_final_statuses_map_to_target_statuses_without_reading_output(final, expected):
    c = Clients()
    _stub_common(c, online=IDS[:1], sent=IDS[:1], ids=IDS[:1])
    c.ssm_stub.add_response("list_command_invocations", {"CommandInvocations": [
        {"InstanceId": IDS[0], "Status": final}]}, {"CommandId": CMD, "Details": False, "MaxResults": 50})
    with c.ssm_stub:  # no GetCommandInvocation is stubbed: reading output for these would be an unstubbed call
        (out,) = SsmTransport(c, poll_s=0).run_collect([CollectTarget("10.0.0.1", IDS[0])], CRED, options())
        c.ssm_stub.assert_no_pending_responses()
    assert out.status == expected and out.document is None


def test_ssm_failed_reads_the_launchers_exit_status():
    c = Clients()
    _stub_common(c, online=IDS[:1], sent=IDS[:1], ids=IDS[:1])
    c.ssm_stub.add_response("list_command_invocations", {"CommandInvocations": [
        {"InstanceId": IDS[0], "Status": "Failed"}]}, {"CommandId": CMD, "Details": False, "MaxResults": 50})
    c.ssm_stub.add_response("get_command_invocation", {"StandardOutputContent": "",
                                                       "StandardErrorContent": "zs-collect: ... is missing\nZSRC 3\n"},
                            {"CommandId": CMD, "InstanceId": IDS[0], "PluginName": "zsCollect"})
    with c.ssm_stub:
        (out,) = SsmTransport(c, poll_s=0).run_collect([CollectTarget("10.0.0.1", IDS[0])], CRED, options())
    assert out.status == "error" and "not installed" in out.error


def test_ssm_51_instances_are_two_send_commands_of_50_and_1():
    from botocore.stub import ANY

    ids = [f"i-{k:017x}" for k in range(51)]
    targets = [CollectTarget(f"10.2.0.{k}", i) for k, i in enumerate(ids)]
    c = Clients()
    c.ssm_stub.add_response("describe_document", {"Document": {"Name": "devsecshield-zs-collect-1.0.0"}},
                            {"Name": "devsecshield-zs-collect-1.0.0"})
    for batch, cmd in ((ids[:50], CMD), (ids[50:], CMD.replace("0f3c", "1f3c"))):
        c.ssm_stub.add_response("describe_instance_information", {"InstanceInformationList": [
            {"InstanceId": i, "PingStatus": "Online"} for i in batch]},
            {"Filters": [{"Key": "InstanceIds", "Values": batch}], "MaxResults": 50})
        c.ssm_stub.add_response("send_command", {"Command": {"CommandId": cmd}},
                                {"InstanceIds": batch, "DocumentName": "devsecshield-zs-collect-1.0.0",
                                 "Parameters": ANY, "TimeoutSeconds": timeout_seconds(len(batch)), "Comment": ANY,
                                 "MaxConcurrency": "10%", "MaxErrors": "100%"})
        c.ssm_stub.add_response("list_command_invocations", {"CommandInvocations": [
            {"InstanceId": i, "Status": "Success"} for i in batch]},
            {"CommandId": cmd, "Details": False, "MaxResults": 50})
        for i in batch:
            label = targets[ids.index(i)].label
            c.ssm_stub.add_response("get_command_invocation", {
                "StandardOutputContent": json.dumps(doc_for(label)), "StandardErrorContent": "ZSRC 0\n"},
                {"CommandId": cmd, "InstanceId": i, "PluginName": "zsCollect"})
    with c.ssm_stub:
        out = list(SsmTransport(c, poll_s=0).run_collect(targets, CRED, options()))
        c.ssm_stub.assert_no_pending_responses()
    assert len(out) == 51 and {r.status for r in out} == {"ok"}


# ----------------------------------------------------------------------------- fleet sources fit one job's asset cap
def test_a_fleet_source_holds_at_most_200_hosts_so_its_assets_fit_one_job(api):
    from backend.utilities.cbom_sources import jobs as J
    from backend.utilities.cbom_sources.transports.limits import MAX_FLEET_TARGETS_PER_SOURCE

    # coordinator decision on review 5874466030: 200 hosts x the live AL2023 host's 187 assets fit 50,000
    assert MAX_FLEET_TARGETS_PER_SOURCE == 200
    assert MAX_FLEET_TARGETS_PER_SOURCE * 187 <= J.MAX_ASSETS_PER_ATTEMPT
    t = api("POST", BASE, json=AWX).json()["transport"]
    node_id, _token, _ = enroll_node(api)
    hosts = [f"10.40.{k // 250}.{k % 250 + 1}" for k in range(201)]
    r = fleet_source(api, t["id"], node_id=node_id, targets=hosts)
    assert r.status_code == 400 and "at most 200 hosts per fleet source" in r.json()["detail"], r.text
    ssm = api("POST", BASE, json=SSM).json()["transport"]
    r = fleet_source(api, ssm["id"], kind="ssm_hosts", targets=hosts)
    assert r.status_code == 400 and "at most 200" in r.json()["detail"], r.text
    r = fleet_source(api, t["id"], node_id=node_id, targets=hosts[:200])
    assert r.status_code == 201, r.text
    assert len(r.json()["source"]["config"]["targets"]) == 200


# ----------------------------------------------------------------------------- review 5874466030 minors (backend)
def test_salt_ssh_batches_are_at_most_100_and_minion_batches_up_to_500(api):
    def make(client, batch):
        return api("POST", BASE, json={**SALT, "name": f"salt-{client}-{batch}",
                                       "config": {**SALT["config"], "client": client, "batch_size": batch}})

    r = make("ssh", 101)
    assert r.status_code == 400 and "at most 100 with client ssh" in r.json()["detail"], r.text
    assert make("ssh", 100).status_code == 201
    assert make("local_async", 500).status_code == 201


def _jinja():
    import re

    import jinja2

    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.filters["regex_match"] = lambda value, pattern: re.match(pattern, str(value))
    return env


@pytest.mark.parametrize("pillar,args", [
    ({"zs_nonce": NONCE, "zs_tier": 2, "zs_timeout_s": 1200}, f"--nonce {NONCE} --tier 2 --timeout-s 1200 --output json"),
    ({"zs_nonce": NONCE, "zs_tier": 1}, f"--nonce {NONCE} --tier 1 --timeout-s 300 --output json"),
    ({"zs_nonce": NONCE, "zs_tier": 1, "zs_timeout_s": 10}, f"--nonce {NONCE} --tier 1 --timeout-s 10 --output json"),
    ({"zs_nonce": NONCE, "zs_tier": 1, "zs_timeout_s": 3600},
     f"--nonce {NONCE} --tier 1 --timeout-s 3600 --output json"),
    ({"zs_nonce": NONCE, "zs_tier": 1, "zs_timeout_s": 9}, None),
    ({"zs_nonce": NONCE, "zs_tier": 1, "zs_timeout_s": 5}, None),  # review 5879001771 (N17): pillar the customer sets
    ({"zs_nonce": NONCE, "zs_tier": 1, "zs_timeout_s": 3601}, None),
    ({"zs_nonce": NONCE, "zs_tier": 1, "zs_timeout_s": "60; id"}, None),
])
def test_the_salt_state_passes_a_checked_timeout_to_the_launcher(pillar, args):
    import yaml

    from backend.utilities.cbom_sources.transports import wrappers

    sls = wrappers.render_salt("1.0.0", "#!/bin/sh\n")["zeroshield/zs_collect.sls"]
    assert "512 MB + 80 MB x ssh_max_procs" in sls  # the master sizing the review asked for travels with the state
    rendered = _jinja().from_string(sls).render(salt={"pillar.get": lambda key, default=None: pillar.get(key, default)})
    state = yaml.safe_load(rendered)["zs_collect"]
    if args is None:
        assert "test.fail_without_changes" in state
    else:
        assert {"args": args} in state["cmd.script"]


def test_the_ansible_script_line_renders_the_timeout():
    import yaml

    from backend.utilities.cbom_sources.transports import wrappers

    play = yaml.safe_load(wrappers.render_ansible("1.0.0", "#!/bin/sh\n")["zs-collect.yml"])[0]
    line = {t["name"]: t for t in play["tasks"]}["zs-collect"]["ansible.builtin.script"]
    out = _jinja().from_string(line).render(zs_nonce=NONCE, zs_tier=2, zs_timeout_s=900, zs_chunk_bytes=393216)
    assert out == f"zs-collect-run.sh --nonce {NONCE} --tier 2 --timeout-s 900 --output chunks --chunk-bytes 393216"


def test_active_release_is_re_verified_on_every_use(api, world, release_key):
    """AC9: the stored manifest is checked against the release key each time (a row edited in the database is not
    trusted), and a claim then carries no release."""
    engine, _ = world
    t = api("POST", BASE, json=AWX).json()["transport"]
    node_id, _token, _ = enroll_node(api)
    src_id = fleet_source(api, t["id"], node_id=node_id).json()["source"]["id"]
    row = import_active(engine, release_key)
    with Session(engine) as s:
        src = s.get(CbomCollectionSource, src_id)
        assert CLAIM.claim_extras(s, src, None, None, {"config": dict(src.config), "secrets": {}})[
            "config"]["zs_collect"]["version"] == "1.0.0"
        db_row = s.get(CbomZsCollectRelease, row.id)
        # still valid JSON with the same files and sha256: only the signature can tell
        db_row.manifest_raw = db_row.manifest_raw.replace('"git_commit":"' + "0" * 40, '"git_commit":"' + "1" * 40)
        s.commit()
        assert json.loads(db_row.manifest_raw)["files"] == row.manifest["files"]
        assert R.active_release(s) is None
        out = CLAIM.claim_extras(s, src, None, None, {"config": dict(src.config), "secrets": {}})
        assert out["config"]["zs_collect"] is None


def test_a_source_of_one_kind_never_runs_through_a_transport_of_another(api, world):
    engine, _ = world
    t = api("POST", BASE, json=AWX).json()["transport"]
    node_id, _token, _ = enroll_node(api)
    src_id = fleet_source(api, t["id"], node_id=node_id).json()["source"]["id"]
    with Session(engine) as s:
        s.get(CbomTransport, t["id"]).kind = "ssm"  # the awx_hosts source now points at an SSM transport
        s.commit()
        src = s.get(CbomCollectionSource, src_id)
        out = CLAIM.claim_extras(s, src, None, None, {"config": dict(src.config), "secrets": {}})
        assert out["config"]["transport"] is None and out["secrets"] == {}
        assert "is a ssm transport, not awx" in out["config"]["transport_problem"]
        row, why = R.usable_transport(s, 1, t["id"], kind="awx")
        assert row is None and "not awx" in why


# ----------------------------------------------------------------------------- review 5879001771
def _dberr_job(monkeypatch, batch: int = 4, fail_calls=(1,)):
    """The cloud worker's real _Job (emit, flush, should_stop) with a database error (not an HTTPException) on the
    given add_assets calls; returns (job, stored)."""
    from sqlalchemy.exc import OperationalError

    from backend.workers import cbom_cloud_worker as W

    class NoDb:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def commit(self):
            pass

        def rollback(self):
            pass

    stored, calls = [], [0]

    def add_assets(session, _node, job_id, lease_id, assets, now, **kw):
        calls[0] += 1
        if calls[0] in fail_calls:
            raise OperationalError("INSERT INTO cbom_collected_asset ...", {}, Exception("connection closed"))
        stored.extend(assets)

    monkeypatch.setattr(W, "Session", NoDb)
    monkeypatch.setattr(W.J, "add_assets", add_assets)
    monkeypatch.setattr(W, "BATCH", batch)
    job = W._Job(None, {"job": {"id": 9, "attempt": 1, "team_id": 1, "lease_id": "L", "max_runtime_s": 3600},
                        "source": {"id": 1, "kind": "ssm_hosts", "config": {}}})
    return job, stored


def _small_doc(label: str, nonce: str, n: int = 3) -> dict:
    d = doc_for(label, nonce)
    d["assets"] = [a for a in d["assets"] if a["type"] != "coverage"][:n]
    d["result"]["targets"][0]["assets"] = n
    return d


class _Instances:
    def __init__(self):
        self.closed = False
        self.reported = 0

    def run_collect(self, targets, credential, options):
        from backend.utilities.cbom_sources.transports.base import TargetResult

        try:
            for t in targets:
                self.reported += 1
                yield TargetResult(t, "ok", None, _small_doc(t.label, options.run_nonce))
        finally:
            self.closed = True


SSM_CONFIG = {"targets": ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"], "tier": 2,
              "handles": {f"10.0.0.{k + 1}": f"i-{k:017x}" for k in range(4)}, "transport": dict(CRED.config),
              "zs_collect": {"version": FIXTURE["collector_version"], "sha256": {}}}


def test_cloud_a_database_error_while_storing_fails_the_ssm_job_and_never_reports_unstored_assets_ok(monkeypatch):
    """Review 5879001771 (cloud.py:92): the per-instance guard wrapped emit, so an OperationalError in the worker's
    flush became one instance's error row while the batch it dropped (other instances' assets) was reported ok.  Now
    only reading a document is guarded: the error leaves collect_ssm, the transport is closed (no next command), and
    the worker stores "Collection failed"."""
    from sqlalchemy.exc import OperationalError

    job, stored = _dberr_job(monkeypatch)
    fake = _Instances()
    with pytest.raises(OperationalError):
        collect_ssm({"id": 9, "attempt": 1, "kind": "collect"}, SSM_CONFIG, [], fake, job.emit, job.should_stop,
                    job.deadline)
    assert fake.closed and fake.reported == 2  # the flush failed on instance 2's assets: nothing after it was read
    assert stored == [] and job.store_failed == "OperationalError"
    assert job.should_stop()  # and anything that still asks is told to stop


def test_cloud_worker_fails_a_job_whose_assets_were_not_stored_even_if_the_collector_swallows_it(monkeypatch):
    """Defence in depth in the worker: a collector that catches the store error itself (any kind, not only SSM) still
    ends as a failure, never success or cancelled."""
    from backend.workers import cbom_cloud_worker as W

    job, stored = _dberr_job(monkeypatch, batch=2)
    job.source = {**job.source, "kind": "aws_account"}

    def swallowing_collector(self):
        for k in range(6):
            try:
                self.emit({"type": "kms_key", "target": "acct", "location": f"arn:k/{k}", "facts": {}})
            except Exception:
                pass
        return {"summary": "6 keys", "targets": [{"target": "acct", "status": "ok"}]}

    finished = {}

    def finish_job(session, node, job_id, lease_id, status, result, error, now, **kw):
        finished.update(status=status, error=error)

        class Row:
            asset_count = len(stored)
        return Row()

    monkeypatch.setattr(W._Job, "_aws", swallowing_collector)
    monkeypatch.setattr(W.J, "finish_job", finish_job)
    job.run()
    assert finished["status"] == "failure" and finished["error"].startswith("Collection failed (ref ")
    assert stored == []  # once a batch was lost nothing more was stored for a job that fails anyway


def test_cloud_one_unreadable_document_is_that_instances_row(monkeypatch):
    """The per-instance guard that stays: reading one instance's document (relabel, its outcome) raising is that
    instance's error row; the others are stored and ok (review 5879001771, mutant BO8)."""
    import backend.utilities.cbom_sources.transports.cloud as CLOUD

    real = CLOUD.zsdoc.relabel

    def relabel(doc, label):
        if label == "10.0.0.2":
            raise RecursionError("maximum recursion depth exceeded")
        return real(doc, label)

    monkeypatch.setattr(CLOUD.zsdoc, "relabel", relabel)
    emitted = []
    result = collect_ssm({"id": 9, "attempt": 1, "kind": "collect"}, SSM_CONFIG, [], _Instances(), emitted.append,
                         lambda: None, time.monotonic() + 60)
    rows = {r["target"]: r for r in result["targets"]}
    assert rows["10.0.0.2"]["status"] == "error" and "RecursionError" in rows["10.0.0.2"]["error"]
    assert [rows[f"10.0.0.{k}"]["status"] for k in (1, 3, 4)] == ["ok"] * 3
    assert {a["target"] for a in emitted} == {"10.0.0.1", "10.0.0.3", "10.0.0.4"} and len(emitted) == 9


@pytest.mark.parametrize("reason,past_deadline,expected", [
    ("Stopped at the maximum run time", True, "skipped_deadline"),
    ("This job is no longer leased to this worker", False, "skipped_cancelled"),
    ("skipped_cancelled", False, "skipped_cancelled"),
])
def test_cloud_rows_carry_a_skip_status_never_the_workers_stop_text(reason, past_deadline, expected):
    """The cloud worker's should_stop answers why it stops (text); the SSM transport and collect_ssm put what
    should_stop answers into the rows' status.  It is mapped to a skip status."""
    class StopsAfterOne:
        def run_collect(self, targets, credential, options):
            from backend.utilities.cbom_sources.transports.base import TargetResult

            yield TargetResult(targets[0], "ok", None, _small_doc(targets[0].label, options.run_nonce))
            for t in targets[1:]:
                yield TargetResult(t, options.should_stop() or "skipped_deadline", "stopped", None)

    stop = {"v": None}

    def should_stop():
        return stop["v"]

    def emit(asset):
        stop["v"] = reason  # the job is told to stop while the first instance's assets are stored

    deadline = time.monotonic() + (-1 if past_deadline else 3600)
    result = collect_ssm({"id": 9, "attempt": 1, "kind": "collect"}, SSM_CONFIG, [], StopsAfterOne(), emit,
                         should_stop, deadline)
    statuses = [r["status"] for r in result["targets"]]
    assert statuses == ["ok"] + [expected] * 3


def _waves(monkeypatch, n: int, per_host_s: float, max_concurrency: str = "10%", deadline_s: float = 8 * 3600,
           timeout_s: int = 300):
    from backend.utilities.cbom_sources.transports import ssm as SSM_MOD

    clock = FakeClock()
    monkeypatch.setattr(SSM_MOD, "time", clock)
    fake = WaveSsm(clock, per_host_s)
    opts = CollectOptions(tier=1, run_nonce=NONCE, deadline=clock.t + deadline_s, timeout_per_target_s=timeout_s,
                          max_concurrency=max_concurrency, zs_collect_sha256={}, should_stop=lambda: None,
                          collector_version=FIXTURE["collector_version"])
    cred = TransportCredential("aws_role", {**CRED.config, "max_concurrency": max_concurrency}, {})
    out = list(SsmTransport(lambda svc, region: fake, poll_s=3.0).run_collect(wave_targets(n), cred, opts))
    return fake, [r.status for r in out]


@pytest.mark.parametrize("max_concurrency,waves", [("2", 25), ("4%", 25), ("25", 2)])
def test_ssm_the_wait_follows_the_transports_own_max_concurrency(monkeypatch, max_concurrency, waves):
    """Review 5879001771 (ssm.py:63, mutant BO15): the budget is computed from the MaxConcurrency the transport
    sends, not the default 10%.  "2" (or 4% of 50) is 25 waves: every instance finishes, and TimeoutSeconds covers
    25 waves of the 300 s timeout plus zs-collect's overrun."""
    fake, statuses = _waves(monkeypatch, 50, 300, max_concurrency)
    assert statuses.count("ok") == 50, sorted(set(statuses))
    (cmd,) = fake.sent
    assert cmd["MaxConcurrency"] == max_concurrency
    assert cmd["TimeoutSeconds"] >= waves * (300 + 60) + 120


@pytest.mark.parametrize("per_host_s", [315, 330, 360])
def test_ssm_hosts_that_overrun_their_timeout_by_a_command_are_still_waited_for(monkeypatch, per_host_s):
    """zs-collect checks --timeout-s between commands, so a host can run up to one command timeout (60 s) past it.
    The slack is per wave: 50 instances at 10% that each take 315-360 s are all collected (the per-batch slack gave
    45 ok and 5 timeout at 315 s)."""
    fake, statuses = _waves(monkeypatch, 50, per_host_s)
    assert statuses.count("ok") == 50, sorted(set(statuses))
    assert fake.sent[0]["TimeoutSeconds"] == 10 * (300 + 60) + 120 + 60


@pytest.mark.parametrize("left_s,sent", [(5, False), (200, False), (479, False), (480, True)])
def test_ssm_sends_nothing_when_the_job_cannot_wait_for_one_instance(monkeypatch, left_s, sent):
    """Review 5879001771 (ssm.py:173): with less time left than one instance may need (300 + 60 + 120 s), no command
    starts zs-collect on the customer's hosts only to be cancelled: every instance is skipped_deadline."""
    fake, statuses = _waves(monkeypatch, 50, 8.5, deadline_s=left_s)
    assert bool(fake.sent) is sent
    if not sent:
        assert statuses == ["skipped_deadline"] * 50
    else:
        assert fake.sent[0]["TimeoutSeconds"] >= 480 and "timeout" not in statuses[:5]


def test_ssm_one_instances_unreadable_result_is_its_own_error(monkeypatch):
    """The SSM adapter's own per-instance guard (ssm.py, mutant BO7): _result raising for one instance gives it an
    error row; the others of the same command are collected."""
    from backend.utilities.cbom_sources.transports import ssm as SSM_MOD

    real = SSM_MOD.SsmTransport._result

    def result(self, ssm, region, command_id, t, *rest):
        if t.handle == wave_targets(3)[1].handle:
            raise RuntimeError("an unexpected shape in this instance's output")
        return real(self, ssm, region, command_id, t, *rest)

    monkeypatch.setattr(SSM_MOD.SsmTransport, "_result", result)
    _fake, statuses = _waves(monkeypatch, 3, 8.5)
    assert statuses == ["ok", "error", "ok"]

