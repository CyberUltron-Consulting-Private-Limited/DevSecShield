"""FIX-B3: Active Directory (SOW L2, LDAPS) is a collectable source with its own asset types and findings.

Before: ``kinds.py`` registered ``active_directory`` with collectable ``_never`` (run 51 on staging skipped it with
"Collection for this connector is not available yet").  Now the scan node reads it over LDAPS / StartTLS
(scan_node/zs_scan_node/collectors/active_directory.py); these tests cover the server side: configuration rules,
planning, the job scope, classification into findings, and CycloneDX types.
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest
from sqlmodel import Session

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import (  # noqa: F401  (the shared fixtures)
    PASSWORD,
    _collect_job,
    api,
    enroll_node,
    world,
)

from backend.new_models import CbomCollectionSource
from backend.utilities.cbom_sources import classify as C
from backend.utilities.cbom_sources import kinds as K
from backend.utilities.cbom_sources import run_assets as RA
from backend.utilities.cbom_sources.classify import classify
from backend.utilities.cbom_sources.jobs import connection_version

NOW = dt.datetime(2026, 11, 23, tzinfo=dt.timezone.utc).replace(tzinfo=None)  # classify's clock: naive UTC


def _ad(**cfg):
    return {"targets": ["dc01.corp.example"], "credential_type": "password", "login_user": "svc-zscbom@corp.example",
            **cfg}


# ----------------------------------------------------------------------------- configuration
def test_active_directory_is_collectable_now():
    spec = K.KINDS["active_directory"]
    cfg = spec.model.model_validate(_ad())
    assert spec.collectable(cfg) is True and spec.needs_node(cfg) is True
    assert "tls_mode" in spec.where_fields  # changing it clears the stored password (where the login goes)


@pytest.mark.parametrize("cfg,ok", [
    ({"port": 636}, True), ({"port": 3269}, True),
    ({"port": 389, "tls_mode": "starttls"}, True), ({"port": 3268, "tls_mode": "starttls"}, True),
    ({"port": 389}, False), ({"port": 636, "tls_mode": "starttls"}, False), ({"port": 8080, "tls_mode": "starttls"}, False),
])
def test_ldaps_and_starttls_ports(cfg, ok):
    model = K.KINDS["active_directory"].model
    try:
        parsed = model.model_validate(_ad(**cfg))
        problem = K.credential_target_problem("active_directory", parsed, {"password": PASSWORD})
    except ValueError as exc:
        problem = str(exc)
    assert (problem is None) == ok, (cfg, problem)


def test_ldaps_default_keeps_the_connection_version_of_sources_saved_before():
    model = K.KINDS["active_directory"].model
    dumped = model.model_validate(_ad()).model_dump(mode="json")
    assert "tls_mode" not in dumped  # a source saved before tls_mode existed dumps the same
    assert model.model_validate(_ad(tls_mode="starttls", port=389)).model_dump(mode="json")["tls_mode"] == "starttls"


def test_an_ad_source_is_saved_planned_and_its_job_carries_the_targets(api, world):  # noqa: F811
    engine, _ = world
    node_id, token, _ = enroll_node(api)
    r = api("POST", "/1/cbom/sources/items", json={"kind": "active_directory", "name": "corp-ad", "node_id": node_id,
                                                   "config": _ad(port=389, tls_mode="starttls", window="any"),
                                                   "secrets": {"password": PASSWORD}})
    assert r.status_code == 201, r.text
    src = r.json()["source"]
    assert src["last_test_status"] == "never"
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"servers": True}}).json()
    item = next(i for i in est["items"] if i["source_id"] == src["id"])
    assert item["status"] == "queued", item  # was "Collection for this connector is not available yet"
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": "fixb3-ad-0001"})
    assert run.status_code == 201, run.text
    claim = api("POST", "/cbom/node/jobs/claim", None, headers={"X-ZS-Node-Token": token})
    assert claim.status_code == 200, claim.text
    body = claim.json()
    assert body["source"]["kind"] == "active_directory"
    assert body["scope"]["targets"] == ["dc01.corp.example"] and body["source"]["config"]["tls_mode"] == "starttls"
    assert body["source"]["secrets"]["password"] == PASSWORD  # delivered to the node only (encrypted at rest)
    with Session(engine) as s:
        row = s.get(CbomCollectionSource, src["id"])
        assert PASSWORD not in str(row.config) and connection_version(row)


# ----------------------------------------------------------------------------- classification
def _codes(asset_type, facts):
    v = classify(asset_type, None, None, "kerberos", facts, NOW)
    return v, set(v["finding_codes"])


def test_kerberos_rc4_only_des_and_aes_accounts():
    v, codes = _codes("kerberos_account", {"account": "svc-sql", "rc4_only": True, "rc4_enabled": True,
                                           "enc_types_source": "default", "enc_types": []})
    assert codes == {"KERBEROS_RC4_ONLY"} and v["impact"] == "High"
    _v, codes = _codes("kerberos_account", {"account": "svc-legacy", "des_enabled": True, "use_des_key_only": True,
                                            "enc_types": ["DES-CBC-CRC", "DES-CBC-MD5"]})
    assert codes == {"KERBEROS_DES_ENABLED"}
    v, codes = _codes("kerberos_account", {"account": "DC1$", "rc4_enabled": True, "aes_enabled": True,
                                           "enc_types": ["RC4-HMAC", "AES128-CTS-HMAC-SHA1-96", "AES256-CTS-HMAC-SHA1-96"]})
    assert codes == {"KERBEROS_RC4_ENABLED"} and v["impact"] == "Medium"
    _v, codes = _codes("kerberos_account", {"account": "svc-web", "aes_enabled": True,
                                            "enc_types": ["AES128-CTS-HMAC-SHA1-96", "AES256-CTS-HMAC-SHA1-96"]})
    assert codes == set()


def test_domain_functional_level_and_krbtgt_age():
    v, codes = _codes("ad_domain", {"domain_functional_level": 2, "domain_functional_level_name": "Windows Server 2003",
                                    "krbtgt_password_last_set": "2024-01-01T00:00:00Z"})
    assert codes == {"AD_FUNCTIONAL_LEVEL_LEGACY", "KRBTGT_KEY_OLD"} and v["impact"] == "High"
    v, codes = _codes("ad_domain", {"domain_functional_level": 6, "krbtgt_password_last_set": "2026-10-01T00:00:00Z"})
    assert codes == {"AD_FUNCTIONAL_LEVEL_LEGACY"} and v["impact"] == "Low"
    _v, codes = _codes("ad_domain", {"domain_functional_level": 7, "krbtgt_password_last_set": "2026-11-01T00:00:00Z"})
    assert codes == set()


@pytest.mark.parametrize("bad", [7, "x", [1], {"a": 1}, None, True])
def test_any_fact_shape_is_ignored_not_raised(bad):
    for asset_type in ("ad_domain", "kerberos_account"):
        for key in ("domain_functional_level", "krbtgt_password_last_set", "rc4_only", "des_enabled", "enc_types",
                    "account", "domain_functional_level_name"):
            classify(asset_type, None, None, None, {key: bad}, NOW)


def test_cyclonedx_types_and_labels():
    assert C.CDX_TYPE["kerberos_account"] == "related-crypto-material" and C.CDX_TYPE["ad_domain"] == "other"
    assert RA.type_label("kerberos_account") == "Kerberos account"
    assert RA.type_label_plural("ad_domain") == "Active Directory domains"


def test_the_node_api_stores_and_judges_ad_assets(api, world):  # noqa: F811
    engine, _ = world
    _src, run, claim, hdr = _collect_job(api, engine)
    job, lease = claim["job"], claim["job"]["lease_id"]
    assets = [
        {"type": "kerberos_account", "target": "dc1.corp.example", "location": "ad:corp.example/service_account/svc-sql",
         "name": "svc-sql", "algorithm": "RC4-HMAC", "protocol": "kerberos",
         "facts": {"account": "svc-sql", "account_type": "service_account", "rc4_only": True, "rc4_enabled": True,
                   "enc_types": [], "enc_types_source": "default"}},
        {"type": "ad_domain", "target": "dc1.corp.example", "location": "ad:corp.example", "name": "corp.example",
         "protocol": "kerberos", "facts": {"domain": "corp.example", "domain_functional_level": 7,
                                           "krbtgt_password_last_set": "2020-01-01T00:00:00Z"}},
    ]
    r = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr,
            json={"lease_id": lease, "batch_id": "ad1", "assets": assets})
    assert r.status_code == 200 and r.json()["accepted"] == 2, r.text
    items = {a["location"]: a for a in api("GET", f"/1/cbom/sources/runs/{run['id']}/assets").json()["items"]}
    svc = items["ad:corp.example/service_account/svc-sql"]
    dom = items["ad:corp.example"]
    assert "KERBEROS_RC4_ONLY" in svc["finding_codes"] and svc["impact"] == "High"
    assert dom["finding_codes"] == ["KRBTGT_KEY_OLD"]
