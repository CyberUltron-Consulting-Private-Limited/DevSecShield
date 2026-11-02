"""CMDB import (WP11): CSV parsing, the preview plan (update / conflict / create / skip), confirm with a digest, metadata
updates that never cancel running or queued jobs, and the ServiceNow CMDB pull (Table API, display values, paging)."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import api, enroll_node, linux_body, world  # noqa: E402,F401

from backend.new_models import CbomCollectionJob, CbomCollectionSource  # noqa: E402
from backend.utilities.cbom_sources import jobs as J  # noqa: E402
from backend.utilities.integrations import cmdb as CMDB  # noqa: E402
from backend.utilities.integrations import outbound, servicenow  # noqa: E402

CSV = """﻿Hostname,IP Address,Owner,Application,Business Criticality,Exposure,Data Classification,Environment,OS
app-01.bank.local,,Payments Team,Payments,1 - most critical,Internet,Restricted,Production,Linux
,10.20.0.3,Payments Team,Payments,high,internal,confidential,Production,Linux
new-01.bank.local,,Cards Team,Cards,medium,internal,internal,Staging,Red Hat Linux
new-02.bank.local,,Cards Team,Cards,medium,internal,internal,Staging,Ubuntu
win-01.bank.local,,Cards Team,Cards,low,internal,internal,Staging,Windows Server 2022
not a host!!,,x,y,,,,,
10.30.0.0/24,,Network Team,,,,,,
,,,,,,,,
"""


def _source(api, node_id, name, targets):
    r = api("POST", "/1/cbom/sources/items", json=linux_body(name, node_id=node_id, targets=targets))
    assert r.status_code == 201, r.text
    return r.json()["source"]


def test_parse_csv_aliases_bom_delimiters_and_limits():
    rows = CMDB.parse_csv(CSV)
    assert len(rows) == 7  # the blank row is skipped
    assert rows[0] == {"line": 2, "hosts": ["app-01.bank.local"], "owner": "Payments Team", "application": "Payments",
                       "criticality": "1 - most critical", "exposure": "Internet", "data_classification": "Restricted",
                       "environment": "Production", "os": "Linux"}
    assert rows[1]["hosts"] == ["10.20.0.3"]
    semi = CMDB.parse_csv("fqdn;owned_by;u_application\nh1.local;A;B\n")
    assert semi[0]["hosts"] == ["h1.local"] and semi[0]["owner"] == "A" and semi[0]["application"] == "B"
    with pytest.raises(CMDB.ImportError_, match="host column"):
        CMDB.parse_csv("owner,app\na,b\n")
    with pytest.raises(CMDB.ImportError_, match="more than"):
        CMDB.parse_csv("host\n" + "\n".join(f"h{i}.local" for i in range(CMDB.MAX_ROWS + 1)))
    assert CMDB.norm_criticality("4 - not critical") == "low" and CMDB.norm_exposure("DMZ") == "internet"
    assert CMDB.norm_classification("Highly Confidential") == "restricted"


def test_preview_then_apply_updates_metadata_creates_groups_and_keeps_jobs(api, world):
    engine, _ = world
    node_id, _token, _ = enroll_node(api)
    existing = _source(api, node_id, "linux-dc", ["10.20.0.0/29", "app-01.bank.local", "10.20.0.3"])
    # a queued collection job on the source: a metadata import must not cancel it
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": "cmdb-run-0001"})
    assert run.status_code == 201, run.text
    with Session(engine) as s:
        job_before = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.source_id == existing["id"],
                                                            CbomCollectionJob.kind == "collect")).one()
        conn_before = J.connection_version(s.get(CbomCollectionSource, existing["id"]))
    assert api("POST", "/1/cbom/sources/cmdb/preview", "bob", json={"csv": CSV}).status_code == 400  # admin only
    r = api("POST", "/1/cbom/sources/cmdb/preview", json={"csv": CSV, "node_id": node_id})
    assert r.status_code == 200, r.text
    plan = r.json()["plan"]
    # app-01 and 10.20.0.3 are both in linux-dc but disagree on criticality / exposure / classification: conflicts
    conflicts = {c["field"] for c in plan["conflicts"]}
    assert conflicts == {"criticality", "exposure", "data_classification"}
    (update,) = plan["updates"]
    assert update["source_id"] == existing["id"]
    assert update["changes"] == {"owner": [None, "Payments Team"], "application": [None, "Payments"],
                                 "environment": [None, "production"]}
    # new-01 and new-02 share metadata: one source; win-01 is not created; the CIDR becomes a network range
    (create,) = [c for c in plan["creates"] if c["kind"] == "linux_servers"]
    (net,) = [c for c in plan["creates"] if c["kind"] == "network_range"]
    assert create["targets"] == ["new-01.bank.local", "new-02.bank.local"]
    assert create["name"] == "CMDB Cards staging" and create["metadata"]["business_criticality"] == "medium"
    assert net["cidr"] == "10.30.0.0/24" and net["metadata"] == {"owner": "Network Team"}
    reasons = " ".join(s["reason"] for s in plan["skipped"])
    assert "Windows server" in reasons and "not a host" in reasons
    # confirm with a stale digest: 409; without a node: 400
    bad = api("POST", "/1/cbom/sources/cmdb/apply", json={"csv": CSV, "node_id": node_id, "digest": "0" * 32})
    assert bad.status_code == 409
    assert api("POST", "/1/cbom/sources/cmdb/apply", json={"csv": CSV, "digest": plan["digest"]}).status_code == 400
    ok = api("POST", "/1/cbom/sources/cmdb/apply", json={"csv": CSV, "node_id": node_id, "digest": plan["digest"]})
    assert ok.status_code == 200, ok.text
    assert ok.json()["result"]["created"] == 2 and ok.json()["result"]["updated"] == 1
    with Session(engine) as s:
        src = s.get(CbomCollectionSource, existing["id"])
        assert src.config["owner"] == "Payments Team" and src.config["environment"] == "production"
        assert src.config["business_criticality"] is None  # conflicting field left alone
        assert J.connection_version(src) == conn_before  # metadata only
        job_after = s.get(CbomCollectionJob, job_before.id)
        assert job_after.status == job_before.status and job_after.cancel_requested_at is None
        new = s.exec(select(CbomCollectionSource).where(CbomCollectionSource.name == "CMDB Cards staging")).one()
        assert new.node_id == node_id and new.config["credential_type"] == "node_key" and new.secret_encrypted is None
    # importing again changes nothing
    again = api("POST", "/1/cbom/sources/cmdb/preview", json={"csv": CSV, "node_id": node_id}).json()["plan"]
    assert again["counts"]["create"] == 0 and again["counts"]["update"] == 0 and again["unchanged"] == 3  # linux-dc, the new servers, the range


def test_network_rows_and_create_switch(api, world):
    node_id, _t, _ = enroll_node(api)
    csv_text = "cidr,owner,environment\n10.30.0.0/24,Network Team,prod\n10.0.0.0/8,too big,prod\n"
    plan = api("POST", "/1/cbom/sources/cmdb/preview", json={"csv": csv_text, "node_id": node_id}).json()["plan"]
    (net,) = plan["creates"]
    assert net == {"kind": "network_range", "name": "CMDB net 10.30.0.0-24", "cidr": "10.30.0.0/24",
                   "metadata": {"environment": "prod", "owner": "Network Team"}, "lines": [2]}
    assert any("larger than" in s["reason"] for s in plan["skipped"])
    r = api("POST", "/1/cbom/sources/cmdb/apply", json={"csv": csv_text, "node_id": node_id, "digest": plan["digest"]})
    assert r.status_code == 200 and r.json()["result"]["created"] == 1
    off = api("POST", "/1/cbom/sources/cmdb/preview", json={"csv": "host\nfresh.local\n", "create_missing": False}).json()
    assert off["plan"]["counts"]["create"] == 0 and "creating is off" in off["plan"]["skipped"][0]["reason"]


class FakeCmdb:
    def __init__(self, rows):
        self.rows = rows
        self.queries: list[dict] = []

    def __call__(self, method, url, *, headers=None, body=None, ca_pem=None, total=20.0, max_body=0):
        parts = urlsplit(url)
        q = {k: v[0] for k, v in parse_qs(parts.query).items()}
        self.queries.append({"path": parts.path, **q})
        assert headers["Authorization"].startswith("Basic ")
        offset, limit = int(q["sysparm_offset"]), int(q["sysparm_limit"])
        page = self.rows[offset:offset + limit]
        return outbound.Response(200, "", {}, json.dumps({"result": page}).encode())


def _ci(i, cls="cmdb_ci_linux_server", **extra):
    def dv(value, display=None):
        return {"value": value, "display_value": display if display is not None else value}
    return {"sys_id": dv(f"{i:032x}"), "name": dv(f"srv{i}"), "fqdn": dv(f"srv{i}.bank.local"),
            "ip_address": dv(f"10.50.{i // 250}.{i % 250 + 1}"), "sys_class_name": dv(cls, "Linux Server"),
            "owned_by": dv("6816f79cc0a8016401c5a33be04be441", "Fred Luddy"), "u_application": dv("Core Banking"),
            "used_for": dv("Production"), **extra}


def test_servicenow_cmdb_pull_pages_and_maps_display_values(api, world, monkeypatch):
    node_id, _t, _ = enroll_node(api)
    rows = [_ci(i) for i in range(600)] + [_ci(900, "cmdb_ci_win_server")]
    fake = FakeCmdb(rows)
    monkeypatch.setattr(servicenow.outbound, "request", fake)
    assert api("POST", "/1/cbom/sources/cmdb/preview", json={"source": "servicenow"}).status_code == 400  # not set up
    saved = api("PUT", "/1/integrations/servicenow", json={
        "enabled": False, "config": {"instance_url": "https://acme.service-now.com", "username": "zs",
                                     "cmdb_table": "cmdb_ci_server", "cmdb_query": "operational_status=1"},
        "secrets": {"password": "pw"}})
    assert saved.status_code == 200, saved.text
    r = api("POST", "/1/cbom/sources/cmdb/preview", json={"source": "servicenow", "node_id": node_id})
    assert r.status_code == 200, r.text
    plan = r.json()["plan"]
    assert plan["rows"] == 601 and [q["sysparm_offset"] for q in fake.queries] == ["0", "500"]
    q = fake.queries[0]
    assert q["path"] == "/api/now/table/cmdb_ci_server" and q["sysparm_display_value"] == "all"
    assert q["sysparm_query"] == "operational_status=1" and "owned_by" in q["sysparm_fields"]
    (create,) = plan["creates"]
    assert len(create["targets"]) == 600 and create["targets"][0] == "srv0.bank.local"
    assert create["metadata"] == {"application": "Core Banking", "environment": "production", "owner": "Fred Luddy"}
    assert any("Windows server" in s["reason"] for s in plan["skipped"])
    ok = api("POST", "/1/cbom/sources/cmdb/apply", json={"source": "servicenow", "node_id": node_id,
                                                        "digest": plan["digest"]})
    assert ok.status_code == 200 and ok.json()["result"]["created"] == 1


def test_servicenow_cmdb_pull_refuses_private_destinations(api, world, monkeypatch):
    monkeypatch.delenv(outbound.ENV_ALLOWED_PRIVATE, raising=False)
    api("PUT", "/1/integrations/servicenow", json={"enabled": False, "config": {
        "instance_url": "https://10.9.8.7", "username": "zs"}, "secrets": {"password": "pw"}})
    r = api("POST", "/1/cbom/sources/cmdb/preview", json={"source": "servicenow"})
    assert r.status_code == 400 and "INTEGRATION_ALLOWED_PRIVATE" in r.json()["detail"]
