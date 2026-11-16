"""Customer QA of the CMDB import (15 Nov): #362 a host on two rows is one source, its disagreements are conflicts in
the first preview, and merged rows are reported; #363 MySQL / SQL Server / MongoDB rows import with a CA given once per
engine in the import (the TLS + CA rule kept); #367 the preview names the unchanged rows and the segments of the file,
and prefers registered scan nodes."""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import api, world  # noqa: E402,F401

from backend.new_models import CbomCollectionSource  # noqa: E402

PREVIEW, APPLY = "/1/cbom/sources/cmdb/preview", "/1/cbom/sources/cmdb/apply"


def node(api, name, segment="", enroll=True):  # noqa: F811 (the api fixture, passed in)
    r = api("POST", "/1/cbom/sources/nodes", json={"name": name, "segment": segment})
    assert r.status_code == 201, r.text
    node_id, reg = r.json()["node"]["id"], r.json()["registration_token"]
    if enroll:
        e = api("POST", "/cbom/node/enroll", None, json={"registration_token": reg, "hostname": name, "version": "1.0",
                                                         "source_ips": ["10.20.1.15"],
                                                         "clock": dt.datetime.utcnow().isoformat() + "Z"})
        assert e.status_code == 200, e.text
    return node_id


def sources(engine):
    with Session(engine) as s:
        return list(s.exec(select(CbomCollectionSource).order_by(CbomCollectionSource.id)).all())


def preview(api, body):  # noqa: F811 (the api fixture, passed in)
    r = api("POST", PREVIEW, json=body)
    assert r.status_code == 200, r.text
    return r.json()["plan"]


def ca_pem(cn="Bank DB CA") -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(7)
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ----------------------------------------------------------------------------- #362
def test_one_host_on_two_rows_is_one_source_with_its_conflicts_on_the_first_preview(api, world):  # noqa: F811
    engine, _ = world
    n = node(api, "dc-01")
    csv_text = ("fqdn,ip,owner,application,environment\n"
                "qa-dup.bank.local,,team-a,Payments,prod\n"
                "qa-dup.bank.local,10.9.0.5,team-b,Payments,prod\n"   # same host, other owner
                ",10.9.0.5,,Payments,prod\n"                           # the same host by its address
                "solo.bank.local,,team-a,Payments,prod\n")
    plan = preview(api, {"csv": csv_text, "node_id": n})
    targets = [t for c in plan["creates"] for t in c["targets"]]
    assert sorted(targets) == ["qa-dup.bank.local", "solo.bank.local"], plan["creates"]
    (conflict,) = [c for c in plan["conflicts"] if c["field"] == "owner"]
    assert conflict["host"] == "qa-dup.bank.local" and conflict["source_id"] is None
    assert conflict["values"] == {"team-a": [2], "team-b": [3]}
    (merged,) = plan["merged"]
    assert merged["label"] == "qa-dup.bank.local" and merged["lines"] == [2, 3, 4]
    assert plan["counts"]["merged"] == 1
    dup = next(c for c in plan["creates"] if "qa-dup.bank.local" in c["targets"])
    assert "owner" not in dup["metadata"] and dup["metadata"]["application"] == "Payments"  # agreed fields kept
    a = api("POST", APPLY, json={"csv": csv_text, "node_id": n, "digest": plan["digest"]})
    assert a.status_code == 200, a.text
    hosting = [s for s in sources(engine) if "qa-dup.bank.local" in (s.config.get("targets") or [])]
    assert len(hosting) == 1
    again = preview(api, {"csv": csv_text, "node_id": n})  # against the team's sources now: nothing new
    assert again["counts"]["create"] == 0


def test_duplicate_cidrs_and_databases_merge_too(api, world):  # noqa: F811 (pytest fixtures)
    n = node(api, "dc-01")
    csv_text = ("kind,host,engine,port,login,vault_path,owner\n"
                "database,pg1.bank.local,postgres,,ro,secret/db/pg1,DBA\n"
                "database,PG1.bank.local,postgresql,5432,ro,secret/db/pg1,Data team\n"  # same engine + host + port
                "database,pg1.bank.local,postgres,5433,ro,secret/db/pg1-b,DBA\n"        # another port: another DB
                "network,10.30.0.0/24,,,,,Net\n"
                "network,10.30.0.0/24,,,,,Net\n")
    plan = preview(api, {"csv": csv_text, "node_id": n, "vault_provider": "hashicorp"})
    dbs = sorted((c["config"]["host"].lower(), c["config"]["port"]) for c in plan["creates"] if c["kind"] == "database")
    assert dbs == [("pg1.bank.local", 5432), ("pg1.bank.local", 5433)], plan["creates"]
    assert [c["cidr"] for c in plan["creates"] if c["kind"] == "network_range"] == ["10.30.0.0/24"]
    assert {(c["field"], tuple(sorted(c["values"]))) for c in plan["conflicts"]} == {("owner", ("DBA", "Data team"))}
    assert sorted(m["lines"] for m in plan["merged"]) == [[2, 3], [5, 6]]


# ----------------------------------------------------------------------------- #363
DB_CSV = ("kind,host,engine,login,vault_path,owner\n"
          "database,my1.bank.local,mysql,ro,secret/db/my1,DBA\n"
          "database,sql1.bank.local,mssql,ro,secret/db/sql1,DBA\n"
          "database,mongo1.bank.local,mongodb,ro,secret/db/mongo1,DBA\n")


def test_mysql_sql_server_and_mongodb_rows_import_with_a_ca_given_once_per_engine(api, world):  # noqa: F811
    engine, _ = world
    n = node(api, "dc-01")
    body = {"csv": DB_CSV, "node_id": n, "vault_provider": "hashicorp"}
    without = preview(api, body)
    assert without["counts"]["create"] == 0 and without["counts"]["skipped"] == 3
    assert all("in the import" in s["reason"] and "CA" in s["reason"] for s in without["skipped"]), without["skipped"]
    my_ca, other_ca = ca_pem("MySQL CA"), ca_pem("Platform CA")
    body["database_ca"] = {"mysql": my_ca, "*": other_ca}  # one engine's own, and one for every other engine
    plan = preview(api, body)
    assert plan["counts"]["skipped"] == 0 and plan["counts"]["create"] == 3, plan["skipped"]
    a = api("POST", APPLY, json={**body, "digest": plan["digest"]})
    assert a.status_code == 200, a.text
    made = {s.config["engine"]: s.config for s in sources(engine)}
    assert made["mysql"]["ca_pem"] == my_ca and made["mysql"]["require_tls"] is True
    assert made["mssql"]["ca_pem"] == other_ca and made["mongodb"]["ca_pem"] == other_ca


def test_a_bad_database_ca_is_refused(api, world):  # noqa: F811 (pytest fixtures)
    n = node(api, "dc-01")
    for ca, code in ((("mysql", "not a certificate"), 400), (("db2", ca_pem()), 400)):
        r = api("POST", PREVIEW, json={"csv": DB_CSV, "node_id": n, "vault_provider": "hashicorp",
                                       "database_ca": {ca[0]: ca[1]}})
        assert r.status_code == code and "database_ca" in r.json()["detail"], r.text


# ----------------------------------------------------------------------------- #367
def test_unchanged_rows_are_listed_with_the_source_they_matched(api, world):  # noqa: F811 (pytest fixtures)
    n = node(api, "dc-01")
    csv_text = "fqdn,owner\nkeep-1.bank.local,Ops\nkeep-2.bank.local,Ops\n"
    plan = preview(api, {"csv": csv_text, "node_id": n})
    api("POST", APPLY, json={"csv": csv_text, "node_id": n, "digest": plan["digest"]})
    again = preview(api, {"csv": csv_text, "node_id": n})
    assert again["unchanged"] == 1
    (item,) = again["unchanged_items"]
    assert item["lines"] == [2, 3] and item["kind"] == "linux_servers" and item["source"].startswith("CMDB")


def test_segments_of_the_file_are_listed_and_registered_nodes_preferred(api, world):  # noqa: F811
    m1 = node(api, "mum-01", "dc-mumbai")
    node(api, "rgrg", "dc-mumbai", enroll=False)       # never registered: not a candidate while one is registered
    c1, c2 = node(api, "che-01", "dc-chennai"), node(api, "che-02", "dc-chennai")
    node(api, "dmz-1", "dmz"), node(api, "dmz-2", "dmz")  # a shared segment no row uses
    lonely = node(api, "lonely", "dc-pune", enroll=False)
    csv_text = ("fqdn,segment\nm.bank.local,dc-mumbai\nc.bank.local,dc-chennai\np.bank.local,dc-pune\n")
    plan = preview(api, {"csv": csv_text})
    seg = {s["segment"]: s for s in plan["segments"]}
    assert set(seg) == {"dc-mumbai", "dc-chennai", "dc-pune"}  # only the file's segments; never "dmz"
    assert seg["dc-mumbai"]["chosen"] == m1 and [x["name"] for x in seg["dc-mumbai"]["nodes"]] == ["mum-01"]
    assert seg["dc-chennai"]["chosen"] is None and {x["id"] for x in seg["dc-chennai"]["nodes"]} == {c1, c2}
    assert seg["dc-pune"]["chosen"] == lonely and seg["dc-pune"]["nodes"] == []
    creates = {c["node_name"]: c for c in plan["creates"]}
    assert set(creates) == {"mum-01", "lonely"}
    assert any("lonely" in w and "has not registered" in w for w in plan["warnings"]), plan["warnings"]
    reasons = {s["line"]: s["reason"] for s in plan["skipped"]}
    assert "che-01" in reasons[3] and "che-02" in reasons[3]
    # a segment cannot be mapped to a node that never registered
    rgrg = next(x for x in api("GET", "/1/cbom/sources/nodes").json()["nodes"] if x["name"] == "rgrg")["id"]
    r = api("POST", PREVIEW, json={"csv": csv_text, "segment_nodes": {"dc-mumbai": rgrg}})
    assert r.status_code == 400 and "has not registered" in r.json()["detail"], r.text
