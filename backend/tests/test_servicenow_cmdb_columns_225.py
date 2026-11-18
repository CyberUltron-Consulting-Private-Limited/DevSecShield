"""#225 follow-up: a ServiceNow CMDB pull carries the same optional columns as a CSV (segment, scan node, kind, engine,
port, login, database name, vault path, API URL, context, PKCS#11 module and token label), mapped in the integration's
``cmdb_mapping``. Recorded Table API responses only (``sysparm_display_value=all``: every field is
{value, display_value}); nothing leaves the test."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import api, world  # noqa: E402,F401
from test_integrations_cmdb import FakeCmdb  # noqa: E402

from backend.new_models import CbomCollectionSource  # noqa: E402
from backend.utilities.integrations import cmdb as CMDB  # noqa: E402
from backend.utilities.integrations import servicenow  # noqa: E402

PREVIEW, APPLY = "/1/cbom/sources/cmdb/preview", "/1/cbom/sources/cmdb/apply"
MAPPING = {"segment": "u_segment", "scan_node": "u_scan_node", "kind": "u_cbom_kind", "engine": "u_db_engine",
           "port": "tcp_port", "login": "u_db_login", "database_name": "u_db_name", "vault_path": "u_vault_path",
           "api_url": "u_api_url", "context": "u_kube_context", "module": "u_pkcs11_module",
           "token_label": "u_token_label"}


def dv(value, display=None):
    return {"value": value, "display_value": display if display is not None else value}


def ci(i: int, cls: str, **fields):
    """One recorded CI as the Table API returns it with sysparm_display_value=all."""
    return {"sys_id": dv(f"{i:032x}"), "name": dv(f"ci{i}"), "sys_class_name": dv(cls, cls),
            "owned_by": dv("6816f79cc0a8016401c5a33be04be441", "Fred Luddy"), "u_application": dv("Core Banking"),
            "used_for": dv("Production"), **{k: (v if isinstance(v, dict) else dv(v)) for k, v in fields.items()}}


RECORDED = [
    # Linux and Windows servers, the segment a reference to a location record (its display value is the name)
    ci(1, "cmdb_ci_linux_server", fqdn="l1.bank.local", u_segment=dv("a1b2c3d4e5f6", "dc-mumbai")),
    ci(2, "cmdb_ci_linux_server", fqdn="l2.bank.local", u_segment=dv("f6e5d4c3b2a1", "dc-chennai")),
    ci(3, "cmdb_ci_win_server", fqdn="w1.bank.local", u_segment=dv("a1b2c3d4e5f6", "dc-mumbai"),
       u_vault_path="secret/data/winrm/mumbai"),
    # a database instance class: kind from the class, engine / port / login / name / vault path from fields
    ci(4, "cmdb_ci_db_postgresql_instance", fqdn="pg1.bank.local", u_db_engine=dv("postgresql", "PostgreSQL"),
       tcp_port="5433", u_db_login="cbom_ro", u_vault_path="secret/data/db/pg1", u_segment=dv("a1", "dc-mumbai")),
    # a cluster and an HSM named by the kind field, routed by a scan_node field (the node's name)
    ci(5, "cmdb_ci_kubernetes_cluster", u_api_url="https://k8s-prod.bank.local:6443", u_kube_context="prod",
       u_vault_path="secret/data/k8s/prod", u_scan_node="che-01"),
    ci(6, "u_cmdb_ci_hsm", u_cbom_kind=dv("hsm", "HSM"), u_pkcs11_module="luna", u_token_label="payments-01",
       u_segment=dv("a1", "dc-mumbai")),
]


def node(api, name, segment):  # noqa: F811 (the api fixture, passed in)
    r = api("POST", "/1/cbom/sources/nodes", json={"name": name, "segment": segment})
    assert r.status_code == 201, r.text
    return r.json()["node"]["id"]


def setup_servicenow(api, monkeypatch, rows, mapping=None):  # noqa: F811 (the api fixture, passed in)
    fake = FakeCmdb(rows)
    monkeypatch.setattr(servicenow.outbound, "request", fake)
    config = {"instance_url": "https://acme.service-now.com", "username": "zs", "cmdb_table": "cmdb_ci"}
    if mapping is not None:
        config["cmdb_mapping"] = mapping
    saved = api("PUT", "/1/integrations/servicenow", json={"enabled": False, "config": config,
                                                           "secrets": {"password": "pw"}})
    assert saved.status_code == 200, saved.text
    return fake


def test_mapping_accepts_the_new_fields_and_refuses_bad_names():
    cfg = servicenow.CmdbMapping.model_validate(MAPPING)
    assert cfg.segment == "u_segment" and cfg.token_label == "u_token_label"
    assert servicenow.CmdbMapping().segment is None  # every new field is off unless mapped
    assert set(servicenow.CMDB_EXTRA_FIELDS) == set(CMDB.EXTRA_ALIASES)  # the same columns as a CSV
    with pytest.raises(ValueError):
        servicenow.CmdbMapping.model_validate({"vault_path": "u vault; drop"})
    assert servicenow.CmdbMapping.model_validate({"segment": "location.name"}).segment == "location.name"  # dot-walk


def test_a_servicenow_pull_carries_the_csv_columns(api, world, monkeypatch):  # noqa: F811 (pytest fixtures)
    engine, _ = world
    mumbai, chennai = node(api, "mum-01", "dc-mumbai"), node(api, "che-01", "dc-chennai")
    fake = setup_servicenow(api, monkeypatch, RECORDED, MAPPING)
    body = {"source": "servicenow", "vault_provider": "hashicorp"}
    r = api("POST", PREVIEW, json=body)
    assert r.status_code == 200, r.text
    plan = r.json()["plan"]
    fields = set(fake.queries[0]["sysparm_fields"].split(","))
    assert set(MAPPING.values()) <= fields, fields  # every mapped field is requested
    assert plan["counts"]["skipped"] == 0, plan["skipped"]
    by_kind = {(c["kind"], c["node_name"]) for c in plan["creates"]}
    assert by_kind == {("linux_servers", "mum-01"), ("linux_servers", "che-01"), ("windows_servers", "mum-01"),
                       ("database", "mum-01"), ("kubernetes", "che-01"), ("key_manager", "mum-01")}, by_kind
    win = next(c for c in plan["creates"] if c["kind"] == "windows_servers")
    assert win["config"]["vault"] == {"provider": "hashicorp", "path": "secret/data/winrm/mumbai"}
    db = next(c for c in plan["creates"] if c["kind"] == "database")
    assert (db["config"]["engine"], db["config"]["port"], db["config"]["login"]) == ("postgres", 5433, "cbom_ro")
    a = api("POST", APPLY, json={**body, "digest": plan["digest"]})
    assert a.status_code == 200 and a.json()["result"]["created"] == 6, a.text
    with Session(engine) as s:
        made = {(x.kind, x.node_id) for x in s.exec(select(CbomCollectionSource)).all()}
    assert made == {("linux_servers", mumbai), ("linux_servers", chennai), ("windows_servers", mumbai),
                    ("database", mumbai), ("kubernetes", chennai), ("key_manager", mumbai)}


def test_without_the_new_mapping_a_pull_reads_as_before(api, world, monkeypatch):  # noqa: F811 (pytest fixtures)
    """No new field mapped: the same request fields as before, Windows rows skipped, the default node used."""
    default = node(api, "hq-01", "hq")
    fake = setup_servicenow(api, monkeypatch, RECORDED)
    plan = api("POST", PREVIEW, json={"source": "servicenow", "node_id": default}).json()["plan"]
    fields = set(fake.queries[0]["sysparm_fields"].split(","))
    assert not fields & set(MAPPING.values()), fields
    assert fields == {"fqdn", "ip_address", "host_name", "name", "owned_by", "u_application", "used_for", "sys_id",
                      "sys_class_name"}
    assert any("Windows server" in s["reason"] for s in plan["skipped"])
    assert {c["node_name"] for c in plan["creates"]} == {"hq-01"}


def test_a_class_alone_still_marks_database_and_cluster_rows(api, world, monkeypatch):  # noqa: F811 (pytest fixtures)
    """With only the vault path mapped, the CI class says what a row is (cmdb_ci_db_*, *kubernetes*)."""
    n = node(api, "mum-01", "dc-mumbai")
    rows = [ci(7, "cmdb_ci_db_mssql_instance", fqdn="sql1.bank.local", u_vault_path="secret/data/db/sql1"),
            ci(8, "cmdb_ci_kubernetes_cluster", fqdn="k8s.bank.local", u_vault_path="secret/data/k8s")]
    setup_servicenow(api, monkeypatch, rows, {"vault_path": "u_vault_path"})
    plan = api("POST", PREVIEW, json={"source": "servicenow", "node_id": n, "vault_provider": "hashicorp"}).json()["plan"]
    reasons = {s["label"]: s["reason"] for s in plan["skipped"]}
    # recognised as a database (its engine is not mapped) and a cluster (no API URL mapped): said so, not imported
    # as Linux servers
    assert "engine" in reasons["ci7"] and "api_url" in reasons["ci8"], reasons
    assert plan["counts"]["create"] == 0
