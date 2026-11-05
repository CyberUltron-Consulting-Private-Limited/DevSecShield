"""Round-5 review, group C1: coverage gaps feed the job outcome, and drift never reads a gap as a removal.

Reviewer repros turned into regression tests:
* rev4 H1 -- a Lambda environment that became unreadable, an organization whose member accounts could not be listed,
  a KMS list cut at its cap, GCP / Azure lists cut at theirs, Glue connections not read (option off): each left the
  job "ok" and drift reported the unread assets removed / their findings resolved (ServiceNow auto-resolves them);
* rev4 M4 -- OSCAL claimed "reviewed" for sources never read;
* rev3 #1 -- a code scan with other scope options or another engine version marked real findings fixed (and closed
  their Jira tickets); a truncated uploaded CBOM was compared;
* rev3 #6 -- a legacy library row was resolved by drift but never marked fixed (two identities for one row).

    cd backend && .venv/bin/python -m pytest tests/test_cbom_r5_coverage_drift.py -q
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import boto3  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from test_cbom_aws_collect import EXTERNAL_ID, ROLE, _Session, aws  # noqa: E402,F401
from test_cbom_azure_gcp_collect import _azure, _azure_routes, _gcp, _gcp_routes  # noqa: E402
from test_cbom_sources_api import api, enroll_node, linux_body, world  # noqa: E402,F401
from test_cbom_wp10_outputs import GONE, OPENSSL, WEAK_TLS, _claim, _FakeMongo, _row, _run  # noqa: E402

from backend.new_models import CbomDriftEvent, Scan  # noqa: E402
from backend.utilities.cbom_sources import aws_collect, azure_collect, gcp_collect  # noqa: E402
from backend.utilities.cbom_sources import drift as D  # noqa: E402
from backend.utilities.cbom_sources import identity as ID  # noqa: E402
from backend.utilities.cbom_sources import jobs as J  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402
from backend.utilities.integrations import oscal as OSCAL  # noqa: E402

FN = "arn:aws:lambda:us-east-1:123456789012:function:payments"
PEM = ("-----BEGIN RSA PRIVATE KEY-----\\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\\n"
       "-----END RSA PRIVATE KEY-----")


# ----------------------------------------------------------------------------- helpers
class _Stub:
    """A service moto cannot load here answers like an empty account, except the Lambda listing a test gives."""

    def __init__(self, service, functions=None):
        self.service, self.functions = service, functions

    def get_paginator(self, method, *_a, **_k):
        pages = [{}]
        if self.service == "lambda" and method == "list_functions" and self.functions is not None:
            pages = [{"Functions": self.functions}]
        return type("P", (), {"paginate": lambda *_a, **_k: iter(pages)})()

    def __getattr__(self, _name):
        return lambda *_a, **_k: {}


def _collect_aws(monkeypatch, cfg=None, functions=None):
    real_client = boto3.session.Session.client

    def client(self, service, *a, **k):
        if service in ("apigateway", "apigatewayv2", "glue", "lambda"):
            return _Stub(service, functions)
        return real_client(self, service, *a, **k)

    monkeypatch.setattr(boto3.session.Session, "client", client)
    monkeypatch.setattr(aws_collect, "_boto", lambda **kw: (_Session(False), None))
    found: list[dict] = []
    result = aws_collect.collect_aws(1, {"role_arn": ROLE, "regions": ["us-east-1"], "scope": "account", **(cfg or {})},
                                     EXTERNAL_ID, found.append, lambda: None)
    return result, found


def _rows(found):
    """Collected assets as the server stores them (verdict, asset key), for drift's pure functions."""
    rows = []
    for i, a in enumerate(found):
        verdict = classify(a["type"], a.get("algorithm"), a.get("key_size"), a.get("protocol"), a.get("facts") or {})
        rows.append(SimpleNamespace(
            id=i, asset_type=a["type"], finding_codes=verdict["finding_codes"], impact=verdict["impact"],
            quantum_vulnerable=verdict["quantum_vulnerable"], facts=a.get("facts") or {}, created_at=dt.datetime(2026, 11, 5),
            target=a["target"], location=a["location"], name=a.get("name"), algorithm=a.get("algorithm"),
            key_size=a.get("key_size"), protocol=a.get("protocol"), cdx_type=None,
            asset_key=J._asset_key(a["type"], a["target"], a["location"], a.get("facts") or {}, a.get("name"))))
    return rows


def _diff(found_before, found_after):
    after = _rows(found_after)
    return D.compare(D.node_views(_rows(found_before), "src", reclassify=False), D.node_views(after, "src", reclassify=False),
                     D.job_gaps(after))


def _finished(result, found):
    outcome, extra = J._outcome(SimpleNamespace(kind="collect"), "success", result, len(found))
    return outcome, D.job_comparable(SimpleNamespace(kind="collect", status="success", result={**result, **extra},
                                                     outcome=outcome))


def _lambda(env, version="$LATEST"):
    return [{"FunctionName": "payments", "FunctionArn": FN, "Version": version, "Environment": env}]


DENIED_ENV = {"Error": {"ErrorCode": "AccessDeniedException", "Message": "kms:Decrypt"}}


# ----------------------------------------------------------------------------- AWS: Lambda environment
@pytest.mark.parametrize("switch_on", [False, True])
def test_an_unreadable_lambda_environment_never_resolves_the_secret_it_held(aws, monkeypatch, switch_on):
    cfg = {"decrypt_lambda_cmk": switch_on}
    _r1, run1 = _collect_aws(monkeypatch, cfg, _lambda({"Variables": {"SIGNING_KEY": PEM}}))
    r2, run2 = _collect_aws(monkeypatch, cfg, _lambda(DENIED_ENV))
    assert any("#environment/SIGNING_KEY" in a["location"] for a in run1)
    region = next(t for t in r2["targets"] if t["target"].endswith("/us-east-1"))
    outcome, comparable = _finished(r2, run2)
    if switch_on:  # a real gap: the target is read in part, the job partial -- and still compared around the gap
        assert region["status"] == "partial" and region["services"]["lambda"] == "partial"
        assert outcome == "partial" and r2["counts"]["partial"] == 1
    else:  # the customer left decryption off: a known, stable gap that keeps the run "ok"
        assert region["status"] == "ok" and region["services"]["lambda"] == "ok" and outcome == "ok"
    assert comparable == (True, None)
    diff = _diff(run1, run2)
    assert diff["resolved"] == [] and diff["removed"] == []  # before the fix: SECRET_IN_CONFIG resolved, asset removed
    assert [x["codes"] for x in diff["not_read"]] == [["SECRET_IN_CONFIG"]]


def test_a_gap_hides_only_what_it_covers(aws, monkeypatch):
    """Unrelated drift still works: a secret really removed from a readable function version is resolved."""
    other = [{"FunctionName": "billing", "FunctionArn": FN.replace("payments", "billing"), "Version": "$LATEST",
              "Environment": {"Variables": {"API_TOKEN": "tok-8f2a9c71e4b0d3a6"}}}]
    _r1, run1 = _collect_aws(monkeypatch, {}, _lambda({"Variables": {"SIGNING_KEY": PEM}}) + other)
    _r2, run2 = _collect_aws(monkeypatch, {}, _lambda(DENIED_ENV) + [{**other[0], "Environment": {"Variables": {}}}])
    diff = _diff(run1, run2)
    assert [(x["code"], x["location"].rsplit("/", 1)[-1]) for x in diff["resolved"]] == [("SECRET_IN_CONFIG", "API_TOKEN")]
    assert [x["location"].rsplit("/", 1)[-1] for x in diff["not_read"]] == ["SIGNING_KEY"]


# ----------------------------------------------------------------------------- AWS: organization, caps, Glue
def test_organization_member_listing_failure_is_a_failed_target_not_a_note(aws, monkeypatch):
    real_client = boto3.session.Session.client

    def deny_org(self, service, *a, **k):
        client = real_client(self, service, *a, **k)
        if service == "organizations":
            def denied(*_a, **_k):
                raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "SCP"}}, "ListAccounts")
            client.get_paginator = lambda *_a, **_k: type("P", (), {"paginate": denied})()
        return client

    monkeypatch.setattr(boto3.session.Session, "client", deny_org)
    monkeypatch.setattr(aws_collect, "_boto", lambda **kw: (_Session(False), None))
    monkeypatch.setattr(aws_collect, "_region_services", lambda acct, region, label, emit, cfg: [("kms", "ok", None)])
    monkeypatch.setattr(aws_collect, "_global_services", lambda acct, label, emit: [("iam", "ok", None)])
    found: list[dict] = []
    result = aws_collect.collect_aws(1, {"role_arn": ROLE, "regions": ["us-east-1"], "scope": "organization"},
                                     EXTERNAL_ID, found.append, lambda: None)
    org = next(t for t in result["targets"] if t["target"].endswith("/organization"))
    assert org["status"] == "error" and "AccessDeniedException" in org["error"]
    assert result["counts"]["failed"] == 1
    outcome, (comparable, why) = _finished(result, found)
    assert outcome == "partial" and not comparable and "not read" in why  # before the fix: ok, compared


def test_a_kms_list_cut_at_its_cap_is_a_scoped_gap_and_a_partial_target(aws, monkeypatch):
    kms = boto3.client("kms", region_name="us-east-1")
    for i in range(3):
        kms.create_key(Description=f"k{i}")
    original = aws_collect._paginate
    monkeypatch.setattr(aws_collect, "_paginate",
                        lambda client, method, key, cap=1000, **kw: original(client, method, key, cap=min(cap, 2), **kw))
    result, found = _collect_aws(monkeypatch)
    gaps = [a for a in found if a["type"] == "coverage" and a["facts"]["check"] == "kms in us-east-1"]
    assert len(gaps) == 1 and gaps[0]["facts"]["status"] == "truncated"  # before the fix: no row at all
    assert gaps[0]["facts"]["scope"] == ["arn:aws:kms:us-east-1:123456789012:key/"]
    region = next(t for t in result["targets"] if t["target"].endswith("/us-east-1"))
    assert region["status"] == "partial" and region["services"]["kms"] == "partial" and region["gaps"] >= 1
    outcome, comparable = _finished(result, found)
    assert outcome == "partial" and comparable == (True, None)
    # a key past the cap is not "removed": the first run saw 3, this one 2
    before = [a for a in found if a["type"] == "kms_key"] + [
        {"type": "kms_key", "target": "aws:123456789012", "location": "arn:aws:kms:us-east-1:123456789012:key/zz",
         "name": "zz", "algorithm": "SYMMETRIC_DEFAULT", "key_size": 256,
         "facts": {"key_spec": "SYMMETRIC_DEFAULT", "key_manager": "CUSTOMER", "key_state": "Enabled",
                   "rotation_enabled": False, "identity": "arn:aws:kms:us-east-1:123456789012:key/zz"}}]
    diff = _diff(before, found)
    assert diff["removed"] == [] and diff["resolved"] == [] and len(diff["not_read"]) == 1


def test_glue_connections_left_off_are_not_reported_gone():
    from test_cbom_aws_collect_wp4 import CATALOG_OFF, INLINE
    from test_cbom_aws_collect_wp4 import _run as run_region
    from test_cbom_aws_collect_wp4 import _glue_plan

    services_on, on = run_region(_glue_plan(CATALOG_OFF, [INLINE]), {"read_glue": True})
    services_off, off = run_region(_glue_plan(CATALOG_OFF, [], read=False), {})
    assert services_on["glue"] == services_off["glue"] == "ok"  # the option is the customer's choice
    gap = next(a for a in off if a["type"] == "coverage" and a["facts"].get("by_choice"))
    assert gap["facts"]["scope"] == ["arn:aws:glue:ap-south-1:123456789012:connection/"]
    diff = _diff(on, off)
    assert not [x for x in diff["resolved"] if x["type"] == "glue_connection"] and not diff["removed"]
    assert {x["type"] for x in diff["not_read"]} == {"glue_connection"}


# ----------------------------------------------------------------------------- GCP / Azure caps
def test_gcp_list_cut_at_its_cap_is_partial_not_ok(monkeypatch):
    monkeypatch.setattr(gcp_collect, "ITEM_CAP", 3)  # the sample project has 4 KMS keys
    out, found, _rec = _gcp(_gcp_routes())
    target = out["targets"][0]
    assert target["services"]["cloudkms"] == "truncated" and target["status"] == "partial"  # was "ok"
    assert out["counts"] == {"total": 1, "ok": 0, "partial": 1, "failed": 0, "skipped": 0}
    gap = next(a for a in found if a["type"] == "coverage")
    assert gap["facts"]["status"] == "truncated" and gap["facts"]["scope"] == ["projects/payments-prod/locations/"]
    outcome, comparable = _finished(out, found)
    assert outcome == "partial" and comparable == (True, None)


def test_azure_list_cut_at_its_cap_is_partial_not_ok(monkeypatch):
    monkeypatch.setattr(azure_collect, "ITEM_CAP", 1)  # the sample vault lists 3 keys
    out, found, _rec = _azure(_azure_routes())
    assert out["targets"][0]["status"] == "partial" and out["counts"]["partial"] == 1  # was "ok"
    gaps = {a["facts"]["check"]: a["facts"] for a in found if a["type"] == "coverage"}
    assert gaps["key vault sample-vault keys"]["scope"] == ["https://sample-vault.vault.azure.net/keys/"]
    outcome, comparable = _finished(out, found)
    assert outcome == "partial" and comparable == (True, None)


# ----------------------------------------------------------------------------- outcome and comparability
@pytest.mark.parametrize("counts,truncated,outcome,comparable", [
    ({"total": 2, "ok": 2, "failed": 0, "skipped": 0}, False, "ok", True),
    ({"total": 2, "ok": 1, "partial": 1, "failed": 0, "skipped": 0}, False, "partial", True),
    ({"total": 1, "ok": 0, "partial": 1, "failed": 0, "skipped": 0}, False, "partial", True),  # never "failed"
    ({"total": 2, "ok": 0, "partial": 1, "failed": 1, "skipped": 0}, False, "partial", False),
    ({"total": 2, "ok": 1, "partial": 1, "failed": 0, "skipped": 1}, False, "partial", False),
    ({"total": 1, "ok": 0, "partial": 1, "failed": 0, "skipped": 0}, True, "partial", False),
    ({"total": 2, "ok": 1, "failed": 1, "skipped": 0}, False, "partial", False),
])
def test_partial_targets_make_the_job_partial_and_only_gap_partial_jobs_compare(counts, truncated, outcome, comparable):
    result = {"counts": counts, "truncated": truncated}
    got, (ok, _why) = _finished(result, [])
    assert (got, ok) == (outcome, comparable)


# ----------------------------------------------------------------------------- drift end to end (API, stored rows)
def _send(api, hdr, claim, assets, counts):
    job = claim["job"]
    if assets:
        r = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr,
                json={"lease_id": job["lease_id"], "batch_id": "b1", "assets": assets})
        assert r.status_code == 200, r.text
    r = api("POST", f"/cbom/node/jobs/{job['id']}/result", None, headers=hdr, json={
        "lease_id": job["lease_id"], "status": "success",
        "result": {"counts": counts, "asset_count": len(assets), "targets": [{"target": "10.20.0.1", "status": "ok"}]}})
    assert r.status_code == 200, r.text


@pytest.mark.parametrize("gap,hidden", [
    ({"facts": {"check": "key and certificate files", "status": "denied", "detail": "no sudo"}}, True),  # no scope
    ({"facts": {"check": "ssh host keys", "status": "denied", "scope": ["/etc/ssh/"]}}, True),
    ({"facts": {"check": "ssh host keys", "status": "denied", "scope": ["/opt/"]}}, False),  # covers something else
    ({"facts": {"check": "BitLocker", "status": "not_supported", "detail": "not installed"}}, False),
])
def test_drift_events_and_diff_never_read_a_gap_as_a_removal(api, world, gap, hidden):
    engine, _ = world
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    api("POST", "/1/cbom/sources/items", json=linux_body("src-a", node_id=node_id, targets=["10.20.0.1"], window="any"))
    _run(api, "c1-run-0001")
    _send(api, hdr, _claim(api, hdr), [WEAK_TLS, GONE, OPENSSL], {"total": 1, "ok": 1, "failed": 0, "skipped": 0})
    run2 = _run(api, "c1-run-0002")
    row = {"type": "coverage", "target": "10.20.0.1", "location": "10.20.0.1#gap", **gap}
    # the second run read the target with a gap (reported as a cloud collector does: one partial target)
    _send(api, hdr, _claim(api, hdr), [WEAK_TLS, OPENSSL, row], {"total": 1, "ok": 0, "partial": 1, "failed": 0, "skipped": 0})
    d = api("GET", f"/1/cbom/sources/runs/{run2['id']}/diff").json()
    assert d["sources"][0]["status"] == "compared"
    removed = [x["label"].split(" · ")[0] for x in d["removed"]]
    assert removed == ([] if hidden else ["DSA host key"])
    assert [x["label"].split(" · ")[0] for x in d["not_read"]] == (["DSA host key"] if hidden else [])
    changes = api("GET", f"/1/cbom/sources/runs/{run2['id']}/changes").json()
    kinds = {e["kind"] for e in changes["events"]}
    assert ("removed_asset" in kinds) is (not hidden) and "resolved" not in kinds  # WEAK_TLS is unchanged


# ----------------------------------------------------------------------------- OSCAL
def test_oscal_never_claims_a_source_that_was_not_read_as_reviewed(api, world):
    engine, _ = world
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    for name, target in (("src-ok", "10.20.0.1"), ("src-gap", "10.20.0.2"), ("src-down", "10.20.0.3")):
        api("POST", "/1/cbom/sources/items", json=linux_body(name, node_id=node_id, targets=[target], window="any"))
    run = _run(api, "c1-oscal-0001")
    _send(api, hdr, _claim(api, hdr), [WEAK_TLS], {"total": 1, "ok": 1, "failed": 0, "skipped": 0})
    _send(api, hdr, _claim(api, hdr), [{**OPENSSL, "target": "10.20.0.2"},
                                       {"type": "coverage", "target": "10.20.0.2", "location": "10.20.0.2#files",
                                        "facts": {"check": "key and certificate files", "status": "denied"}}],
          {"total": 1, "ok": 1, "failed": 0, "skipped": 0})
    claim = _claim(api, hdr)
    r = api("POST", f"/cbom/node/jobs/{claim['job']['id']}/result", None, headers=hdr,
            json={"lease_id": claim["job"]["lease_id"], "status": "failure", "error": "unreachable"})
    assert r.status_code == 200, r.text
    doc = OSCAL.document_for(engine, 1, run_id=run["id"])
    assert OSCAL.validate(doc) == []
    result = doc["assessment-results"]["results"][0]
    props = {(p["name"], p["value"]) for p in result.get("props", [])}
    assert ("source-not-read", "src-down (failure)") in props  # before the fix: nothing said so
    assert ("source-partly-read", "src-gap: 1 check(s) not collected") in props
    assert not any("src-ok" in v for _n, v in props)
    assert "src-down" in result["reviewed-controls"]["remarks"] and "not checked" in result["reviewed-controls"]["remarks"]


# ----------------------------------------------------------------------------- code scans
TOOLS1 = {"metadata": {"tools": [{"name": "aibom", "version": "1"}]}}
TOOLS2 = {"metadata": {"tools": [{"name": "aibom", "version": "2"}]}}


def _mongo(monkeypatch, docs):
    closed: list = []
    from backend.utilities.integrations import jira_ticketing
    monkeypatch.setattr(jira_ticketing, "close_jira_issue_for_finding", lambda doc, team: closed.append(doc["_id"]))
    import backend.get_db as get_db_module
    monkeypatch.setattr(get_db_module, "get_mongo_client_db", lambda: _FakeMongo(docs))
    return closed


def _scans(engine, ids, *specs):
    with Session(engine) as s:
        for scan_id, meta, day, results, extra in specs:
            s.add(Scan(id=scan_id, team_id=1, owner_user_id=ids["alice"], scan_type="cbom", title="pay",
                       scan_status="success", scan_metadata=meta, created_at=dt.datetime(2026, 10, day),
                       scan_data={"results": results, **extra}))
        s.commit()


def _events(engine, scan_id):
    with Session(engine) as s:
        return {(e.kind, e.code) for e in s.exec(select(CbomDriftEvent).where(CbomDriftEvent.scan_id == scan_id)).all()}


REPO = {"repo_url": "https://github.com/acme/pay.git", "branch": "main"}


def test_turning_vendored_scanning_off_does_not_fix_vendored_findings(world, monkeypatch):
    engine, ids = world
    vend = _row("3DES-CBC", "node_modules/legacy/des.js", ["WEAK_ALGORITHM"])
    app = _row("RSA-2048", "keys.py", ["QUANTUM_VULNERABLE"], impact="Low", quantum_safe=False)
    _scans(engine, ids, (50, {**REPO, "include_vendored": True}, 1, [vend, app], {"cbom_json": TOOLS1}),
           (51, {**REPO, "include_vendored": False}, 2, [app], {"cbom_json": TOOLS1}),
           (52, {**REPO, "include_vendored": True}, 3, [app], {"cbom_json": TOOLS1}))
    docs = [{"_id": 1, "scan_id": 50, "finding_data": vend, "finding_status": "not_started", "info": {"jira_issue_key": "SEC-9"}}]
    closed = _mongo(monkeypatch, docs)
    out = D.on_code_scan_success(51, engine, now=dt.datetime(2026, 10, 2, 12))
    assert out["fixed"] == 0 and closed == [] and docs[0]["finding_status"] == "not_started"  # before: fixed + closed
    assert _events(engine, 51) == set()  # no baseline with the same scope options
    with Session(engine) as s:  # the next vendored scan compares with the last vendored scan and proves the fix
        assert D.previous_code_scan(s, s.get(Scan, 52)).id == 50
    assert D.on_code_scan_success(52, engine, now=dt.datetime(2026, 10, 3, 12))["fixed"] == 1 and closed == [1]


def test_another_engine_version_records_the_change_but_marks_nothing_fixed(world, monkeypatch):
    engine, ids = world
    old = _row("End-of-life base image python:3.6", "Dockerfile", ["EOL_BASE_IMAGE"], ref="crypto-cfg_aaaa1111",
               asset_type="other")
    new = {**old, "bom_ref": "crypto-cfg_bbbb2222"}  # WP13: the engine's fact id changed, the Dockerfile did not
    _scans(engine, ids, (60, REPO, 1, [old], {"cbom_json": TOOLS1}), (61, REPO, 2, [new], {"cbom_json": TOOLS2}))
    with Session(engine) as s:
        diff = D.code_scan_diff(s.get(Scan, 61), s.get(Scan, 60))
    assert diff["resolutions"] == {"proven": False, "reason": "the scans were made by different engine versions"}
    assert all(x.get("rule_change") for x in diff["resolved"] + diff["opened"])  # the diff is still shown, labelled
    docs = [{"_id": 7, "scan_id": 60, "finding_data": old, "finding_status": "not_started", "info": {"jira_issue_key": "SEC-7"}}]
    closed = _mongo(monkeypatch, docs)
    out = D.on_code_scan_success(61, engine, now=dt.datetime(2026, 10, 2, 12))
    assert out["fixed"] == 0 and closed == [] and docs[0]["finding_status"] == "not_started"
    kinds = {k for k, _c in _events(engine, 61)}
    assert "opened" in kinds and not kinds & {"resolved", "removed_asset", "cert_renewed"}  # nothing closes downstream


def test_uploads_of_the_same_title_never_mark_findings_fixed(world, monkeypatch):
    engine, ids = world
    des = _row("3DES-CBC", "app.py", ["WEAK_ALGORITHM"])
    zipped = {"zip_file_used": True}
    _scans(engine, ids, (70, zipped, 1, [des], {}), (71, zipped, 2, [], {}))
    docs = [{"_id": 3, "scan_id": 70, "finding_data": des, "finding_status": "not_started"}]
    closed = _mongo(monkeypatch, docs)
    out = D.on_code_scan_success(71, engine, now=dt.datetime(2026, 10, 2, 12))
    assert out["fixed"] == 0 and closed == [] and docs[0]["finding_status"] == "not_started"
    assert not {k for k, _c in _events(engine, 71)} & {"resolved", "removed_asset"}


def test_a_truncated_uploaded_cbom_is_never_compared(world, monkeypatch):
    engine, ids = world
    des = _row("3DES-CBC", "app.py", ["WEAK_ALGORITHM"])
    rsa = _row("RSA-2048", "keys.py", ["QUANTUM_VULNERABLE"], impact="Low", quantum_safe=False)
    _scans(engine, ids, (80, REPO, 1, [des, rsa], {"cbom_json": TOOLS1}),
           (81, REPO, 2, [rsa], {"cbom_json": TOOLS1, "cbom_input": {"truncated": True, "crypto_assets": 9000}}),
           (82, REPO, 3, [rsa], {"cbom_json": TOOLS1}))
    docs = [{"_id": 4, "scan_id": 80, "finding_data": des, "finding_status": "not_started"}]
    closed = _mongo(monkeypatch, docs)
    assert D.on_code_scan_success(81, engine, now=dt.datetime(2026, 10, 2, 12)) == {"events": 0, "fixed": 0}
    assert _events(engine, 81) == set() and closed == []
    with Session(engine) as s:  # nor is it ever a baseline
        assert D.previous_code_scan(s, s.get(Scan, 82)).id == 80
        doc = OSCAL.scan_document(s.get(Scan, 81))
    assert "truncated" in doc["assessment-results"]["results"][0]["reviewed-controls"]["remarks"]


def test_a_legacy_library_row_that_drift_resolves_is_the_row_marked_fixed(world, monkeypatch):
    engine, ids = world
    legacy = {"title": "openssl 1.0.2", "algorithm_type": "other", "location": "requirements.txt",
              "bom_ref": "crypto-lib-openssl", "finding_codes": ["VULNERABLE_CRYPTO_LIBRARY"], "impact": "High"}
    rsa = _row("RSA-2048", "keys.py", ["QUANTUM_VULNERABLE"], impact="Low", quantum_safe=False)
    _scans(engine, ids, (90, REPO, 1, [legacy, rsa], {"cbom_json": TOOLS1}), (91, REPO, 2, [rsa], {"cbom_json": TOOLS1}))
    docs = [{"_id": 5, "scan_id": 90, "finding_data": legacy, "finding_status": "not_started"}]
    _mongo(monkeypatch, docs)
    out = D.on_code_scan_success(91, engine, now=dt.datetime(2026, 10, 2, 12))
    assert ("resolved", "VULNERABLE_CRYPTO_LIBRARY") in _events(engine, 91)
    assert out["fixed"] == 1 and docs[0]["finding_status"] == "fixed"  # before the fix: resolved, never marked
    with Session(engine) as s:  # drift keys the stored row exactly as the roll-up does
        view = next(iter(D.code_views([legacy], "k").values()))
    assert view.identity == ID.code_identity(legacy)
