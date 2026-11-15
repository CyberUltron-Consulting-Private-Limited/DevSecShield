"""Engine step 3 (correlate): estate assets with their owners, applications and data classification (their sources'
current metadata, CMDB-fed or typed), and with the SBOM / code-scan components that use them (stored links, rebuilt
only when the scans or the estate change). Exposed on the estate list and asset, the run asset drawer, the quantum
risk register (and its CSV) and the estate CycloneDX export.
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as HARNESS  # noqa: E402
from test_cbom_sources_api import enroll_node, linux_body  # noqa: E402
from test_cbom_wp10_outputs import _claim, _collect, _run  # noqa: E402

from backend.new_models import CbomCollectionSource, CbomEstateLinkState, Scan  # noqa: E402
from backend.utilities.cbom_sources import drift as DRIFT  # noqa: E402
from backend.utilities.cbom_sources import estate_links as LINKS  # noqa: E402

api, world = HARNESS.api, HARNESS.world

NOW = dt.datetime.utcnow().replace(microsecond=0)
Z = "%Y-%m-%dT%H:%M:%SZ"
NB, NA = (NOW - dt.timedelta(days=30)).strftime(Z), (NOW + dt.timedelta(days=300)).strftime(Z)
ENDPOINT = {"type": "tls_endpoint", "target": "api.bank.example", "location": "api.bank.example:443",
            "facts": {"protocols": ["TLSv1.0", "TLSv1.2"], "pq_group_supported": False}}
LIB = {"type": "crypto_library", "target": "10.20.0.1", "location": "/usr/lib/libssl.so.1.1", "name": "openssl",
       "algorithm": "OpenSSL", "facts": {"package": "openssl", "version": "1.1.1k"}}
CERT = {"type": "certificate", "target": "10.20.0.1", "location": "/etc/ssl/certs/same.pem", "name": "CN=same.lab",
        "algorithm": "RSA", "key_size": 2048,
        "facts": {"subject": "CN=same.lab", "issuer": "CN=Lab CA", "not_before": NB, "not_after": NA,
                  "serial": "0a0b0c0d0e0f10111213", "key_alg": "RSA", "key_size": 2048, "source": "file"}}


@pytest.fixture()
def estate(api, world):
    """Source A (owner Alice, Payments, confidential) reads the endpoint, an OpenSSL library and a certificate;
    source B (owner Bob, Payments, restricted) reads the same public endpoint (one estate asset, CB-21)."""
    engine, _ = world
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    meta = {"src-a": {"owner": "Alice", "application": "Payments", "data_classification": "confidential"},
            "src-b": {"owner": "Bob", "application": "Payments", "data_classification": "restricted"}}
    for name, target in (("src-a", "10.20.0.1"), ("src-b", "10.20.0.2")):
        r = api("POST", "/1/cbom/sources/items", json=linux_body(name, node_id=node_id, targets=[target],
                                                                 window="any", **meta[name]))
        assert r.status_code == 201, r.text
    per = {"src-a": [ENDPOINT, LIB, CERT], "src-b": [ENDPOINT]}
    run = _run(api, "corr-run-0001")
    for _ in range(2):
        claim = _claim(api, hdr)
        _collect(api, hdr, claim, per[claim["source"]["name"]])
    DRIFT.record_pending_drift(engine, dt.datetime.utcnow())
    with Session(engine) as s:
        s.add(Scan(id=501, team_id=1, owner_user_id=1, scan_type="sbom_sca", title="payments sbom",
                   scan_status="success", created_at=NOW, last_updated=NOW, scan_data={"sbom_json": {"components": [
                       {"name": "openssl", "version": "1.1.1k", "purl": "pkg:generic/openssl@1.1.1k"},
                       {"name": "zlib", "version": "1.2.11"}]}}))
        s.add(Scan(id=502, team_id=1, owner_user_id=1, scan_type="cbom", title="payments code", scan_status="success",
                   scan_metadata={"repo_url": "https://github.com/acme/pay", "branch": "main"}, created_at=NOW,
                   last_updated=NOW, scan_data=_code_scan_data()))
        s.commit()
    return {"engine": engine, "run": run}


def _code_scan_data() -> dict:
    row = {"title": "same.crt", "algorithm_name": "same.crt", "asset_type": "certificate",
           "algorithm_type": "certificate", "location": "deploy/same.crt", "bom_ref": "crypto-cert-same",
           "impact": None, "finding_codes": []}
    comp = {"name": "same.crt", "type": "cryptographic-asset", "bom-ref": "crypto-cert-same",
            "properties": [{"name": "crypto:subjectName", "value": "same.lab"},
                           {"name": "crypto:issuerName", "value": "Lab CA"},
                           {"name": "crypto:notValidBefore", "value": NB},
                           {"name": "crypto:notValidAfter", "value": NA}],
            "cryptoProperties": {"assetType": "certificate"}}
    return {"results": [row], "cbom_json": {"components": [comp]}}


def _estate(api) -> dict[str, dict]:
    r = api("GET", "/1/cbom/estate")
    assert r.status_code == 200, r.text
    return {i["type"]: i for i in r.json()["items"]}


def test_owners_applications_and_the_highest_data_classification(api, estate):
    items = _estate(api)
    ep = items["tls_endpoint"]
    assert ep["owners"] == ["Alice", "Bob"] and ep["applications"] == ["Payments"]
    assert ep["data_classification"] == "restricted"  # the most sensitive system it sits in
    r = api("GET", f"/1/cbom/estate/{ep['asset_key']}")
    corr = r.json()["correlation"]
    assert corr["conflicts"] == ["owner", "data_classification"] and corr["unknown"] == []
    assert corr["data_classifications"] == ["confidential", "restricted"]
    assert {b["source_name"]: b["owner"] for b in corr["by_source"]} == {"src-a": "Alice", "src-b": "Bob"}


def test_metadata_changes_show_at_once_and_a_deleted_source_keeps_its_snapshot(api, estate):
    engine = estate["engine"]
    with Session(engine) as s:  # what a CMDB import does: the source's metadata changes, nothing is collected
        src = s.exec(select(CbomCollectionSource).where(CbomCollectionSource.name == "src-a")).one()
        src.config = {**src.config, "owner": "Carol"}
        s.add(src)
        s.commit()
    assert _estate(api)["crypto_library"]["owners"] == ["Carol"]
    with Session(engine) as s:
        src_b = s.exec(select(CbomCollectionSource).where(CbomCollectionSource.name == "src-b")).one().id
    r = api("DELETE", f"/1/cbom/sources/items/{src_b}")
    assert r.status_code in (200, 204), r.text
    # the endpoint is still observed through the deleted source's last run: its job's snapshot names Bob
    assert _estate(api)["tls_endpoint"]["owners"] == ["Bob", "Carol"]


def test_sbom_and_code_scan_components_that_use_an_asset(api, estate):
    items = _estate(api)
    lib = api("GET", f"/1/cbom/estate/{items['crypto_library']['asset_key']}").json()["correlation"]
    assert [(link["kind"], link["scan_id"], link["component"], link["match"]) for link in lib["links"]] == [
        ("sbom", 501, "openssl@1.1.1k", "name_version")]
    cert = api("GET", f"/1/cbom/estate/{items['certificate']['asset_key']}").json()["correlation"]
    assert [(link["kind"], link["scan_id"], link["match"]) for link in cert["links"]] == [("code", 502, "cert_key")]
    assert items["crypto_library"]["linked_components"] == 1 and items["tls_endpoint"]["linked_components"] == 0


def test_links_are_stored_and_rebuilt_only_when_the_scans_change(api, estate, monkeypatch):
    calls = []
    original = LINKS.build_links
    monkeypatch.setattr(LINKS, "build_links", lambda *a, **k: (calls.append(1), original(*a, **k))[1])
    _estate(api)
    _estate(api)
    key = _estate(api)["crypto_library"]["asset_key"]
    api("GET", f"/1/cbom/estate/{key}")
    assert len(calls) == 1  # one build, then the stored links (fingerprint unchanged)
    with Session(estate["engine"]) as s:
        assert s.exec(select(CbomEstateLinkState)).one().links == 2
        s.add(Scan(id=503, team_id=1, owner_user_id=1, scan_type="sbom_sca", title="newer sbom", scan_status="success",
                   created_at=NOW + dt.timedelta(minutes=1), last_updated=NOW + dt.timedelta(minutes=1),
                   scan_data={"sbom_json": {"components": [{"name": "openssl", "version": "3.0.2"}]}}))
        s.commit()
    corr = api("GET", f"/1/cbom/estate/{key}").json()["correlation"]
    assert len(calls) == 2 and {(link["scan_id"], link["match"]) for link in corr["links"]} == {
        (501, "name_version"), (503, "name")}


def test_the_run_asset_drawer_carries_the_correlation(api, estate):
    run_id = estate["run"]["id"]
    items = api("GET", f"/1/cbom/sources/runs/{run_id}/assets?page_size=200").json()["items"]
    lib = next(i for i in items if i["type"] == "crypto_library")
    detail = api("GET", f"/1/cbom/sources/assets/{lib['id']}").json()["asset"]
    corr = detail["correlation"]
    assert corr["estate_key"] == _estate(api)["crypto_library"]["asset_key"]
    assert corr["owners"] == ["Alice"] and corr["data_classification"] == "confidential"
    assert corr["links"][0]["component"] == "openssl@1.1.1k"


def test_the_register_and_its_csv_name_owners_and_data_classification(api, estate):
    r = api("GET", "/1/cbom/register")
    assert r.status_code == 200, r.text
    rows = {i["asset_type"]: i for i in r.json()["items"]}
    assert rows["tls_endpoint"]["owners"] == ["Alice", "Bob"]
    assert rows["tls_endpoint"]["data_classification"] == "restricted"
    csv = api("GET", "/1/cbom/register.csv").text.splitlines()
    assert csv[0].endswith(",owners,data_classification")
    assert any(line.endswith(",Alice; Bob,restricted") for line in csv[1:])


def test_the_estate_export_carries_the_correlation(api, estate):
    r = api("GET", "/1/cbom/estate-export", params={"format": "json"})
    assert r.status_code == 200, r.text
    doc = r.json()
    meta = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert meta["zs:correlation"] == "included"
    by_type = {}
    for comp in doc["components"]:
        props = comp.get("properties") or []
        if any(p["name"] == "zs:estate_key" for p in props):
            by_type[comp.get("type") + ":" + comp.get("name", "")] = props
    owners = [[p["value"] for p in props if p["name"] == "zs:owner"] for props in by_type.values()]
    assert ["Alice", "Bob"] in owners
    assert any(p["name"] == "zs:used_by_sbom" and p["value"].startswith("scan 501: openssl@1.1.1k")
               for props in by_type.values() for p in props)
    assert any(p["name"] == "zs:data_classification" and p["value"] == "restricted"
               for props in by_type.values() for p in props)


def test_highest_classification_and_team_scope(api, estate):
    assert LINKS.highest_classification(["internal", "public", "nonsense"]) == "internal"
    assert LINKS.highest_classification([]) is None
    key = _estate(api)["tls_endpoint"]["asset_key"]
    assert api("GET", f"/1/cbom/estate/{key}", "carol").status_code in (403, 404)
    r = api("GET", "/2/cbom/estate", "carol")
    assert r.status_code == 200 and r.json()["items"] == []
