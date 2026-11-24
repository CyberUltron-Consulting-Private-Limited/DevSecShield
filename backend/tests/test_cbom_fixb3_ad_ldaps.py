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


def _ad_capable(api, token):  # noqa: F811
    """The node reports the AD collector (#488 review m3: older nodes never claim AD jobs)."""
    r = api("POST", "/cbom/node/heartbeat", None, headers={"X-ZS-Node-Token": token},
            json={"version": "1.0.7", "capabilities": {"collectors": ["linux_ssh", "network_tls", "ad_ldaps"]}})
    assert r.status_code == 200, r.text


def test_an_ad_source_is_saved_planned_and_its_job_carries_the_targets(api, world):  # noqa: F811
    engine, _ = world
    node_id, token, _ = enroll_node(api)
    _ad_capable(api, token)
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
    v, codes = _codes("kerberos_account", {"account": "svc-rc4", "rc4_only": True, "rc4_enabled": True,
                                           "aes_enabled": False, "enc_types_source": "attribute", "enc_types": ["RC4-HMAC"],
                                           "enc_types_value": 4})
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


@pytest.mark.parametrize("facts", [
    # what the collector now writes for an unset attribute (rc4/aes unknown)
    {"account": "svc-sql", "account_type": "service_account", "rc4_only": None, "rc4_enabled": None,
     "aes_enabled": None, "dc_default": True, "enc_types_source": "default", "enc_types": []},
    # and a row stored by the collector before #488 review M1 (it assumed RC4 for an unset attribute)
    {"account": "svc-sql", "account_type": "service_account", "rc4_only": True, "rc4_enabled": True,
     "enc_types_source": "default", "enc_types": []},
])
def test_m1_an_unset_attribute_is_the_dc_default_low_never_rc4_high(facts):
    """#488 review M1: since KB5073381 (CVE-2026-20833, April 2026) a patched DC issues AES-SHA1 only (0x18) to an
    account without msDS-SupportedEncryptionTypes; Samba's svc-sql was a false KERBEROS_RC4_ONLY High."""
    v, codes = _codes("kerberos_account", facts)
    assert codes == {"KERBEROS_ENCTYPES_DEFAULT"} and v["impact"] == "Low"
    assert "KB5073381" in v["finding"] and "DefaultDomainSupportedEncTypes" in v["finding"]


@pytest.mark.parametrize("facts", [
    {"account": "krbtgt", "account_type": "krbtgt", "rc4_only": True, "rc4_enabled": True, "enc_types": [],
     "enc_types_source": "default"},  # as stored before M2 on Samba (domain functional level 2008 R2)
    {"account": "krbtgt", "account_type": "krbtgt", "rc4_only": None, "rc4_enabled": None, "dc_default": True,
     "enc_types": [], "enc_types_source": "default", "judged_by": "domain_functional_level_and_key_age"},
    {"account": "krbtgt", "account_type": "krbtgt", "rc4_only": True, "rc4_enabled": True, "aes_enabled": False,
     "enc_types": ["RC4-HMAC"], "enc_types_source": "attribute", "enc_types_value": 4},
])
def test_m2_krbtgt_is_judged_by_the_domain_not_by_its_enctype_attribute(facts):
    """#488 review M2: TGTs use krbtgt's keys (domain functional level, password age: the ad_domain row)."""
    _v, codes = _codes("kerberos_account", facts)
    assert codes == set()


def test_domain_functional_level_and_krbtgt_age():
    v, codes = _codes("ad_domain", {"domain_functional_level": 2, "domain_functional_level_name": "Windows Server 2003",
                                    "krbtgt_password_last_set": "2024-01-01T00:00:00Z"})
    # below 2008 its own High code (#493 review 6032906354 M1), so the KB default and D6 say High too
    assert codes == {"AD_FUNCTIONAL_LEVEL_PRE2008", "KRBTGT_KEY_OLD"} and v["impact"] == "High"
    assert v["impacts"]["AD_FUNCTIONAL_LEVEL_PRE2008"] == "High"
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
        {"type": "kerberos_account", "target": "dc1.corp.example", "location": "ad:corp.example/service_account/svc-rc4",
         "name": "svc-rc4", "algorithm": "RC4-HMAC", "protocol": "kerberos",
         "facts": {"account": "svc-rc4", "account_type": "service_account", "rc4_only": True, "rc4_enabled": True,
                   "aes_enabled": False, "enc_types": ["RC4-HMAC"], "enc_types_value": 4,
                   "enc_types_source": "attribute"}},
        {"type": "kerberos_account", "target": "dc1.corp.example", "location": "ad:corp.example/service_account/svc-sql",
         "name": "svc-sql", "protocol": "kerberos",
         "facts": {"account": "svc-sql", "account_type": "service_account", "rc4_only": None, "rc4_enabled": None,
                   "aes_enabled": None, "dc_default": True, "enc_types": [], "enc_types_source": "default"}},
        {"type": "ad_domain", "target": "dc1.corp.example", "location": "ad:corp.example", "name": "corp.example",
         "protocol": "kerberos", "facts": {"domain": "corp.example", "domain_functional_level": 7,
                                           "krbtgt_password_last_set": "2020-01-01T00:00:00Z"}},
    ]
    r = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr,
            json={"lease_id": lease, "batch_id": "ad1", "assets": assets})
    assert r.status_code == 200 and r.json()["accepted"] == 3, r.text
    items = {a["location"]: a for a in api("GET", f"/1/cbom/sources/runs/{run['id']}/assets").json()["items"]}
    svc = items["ad:corp.example/service_account/svc-rc4"]
    default = items["ad:corp.example/service_account/svc-sql"]
    dom = items["ad:corp.example"]
    assert "KERBEROS_RC4_ONLY" in svc["finding_codes"] and svc["impact"] == "High"
    assert default["finding_codes"] == ["KERBEROS_ENCTYPES_DEFAULT"] and default["impact"] == "Low"
    assert dom["finding_codes"] == ["KRBTGT_KEY_OLD"]


# ----------------------------------------------------------------------------- #488 review M4: CycloneDX
def _row(name, facts, algorithm=None, row_id=1):
    from backend.new_models import CbomCollectedAsset

    return CbomCollectedAsset(id=row_id, team_id=1, run_id=1, job_id=1, attempt=1, source_id=1,
                              asset_type="kerberos_account", cdx_type="related-crypto-material",
                              target="dc1.corp.test", location=f"ad:corp.test/domain_controller/{name}", name=name,
                              algorithm=algorithm, protocol="kerberos", facts=facts, impact="Medium",
                              finding="x", finding_codes=["KERBEROS_RC4_ENABLED"], created_at=NOW)


def test_m4_a_kerberos_account_is_a_secret_key_with_every_key_type():
    """DC1$ (0x1C: AES256 + AES128 + RC4) was exported as relatedCryptoMaterialProperties.type "other" with
    zs:algorithm RC4-HMAC (the lowest bit, the weakest); the enctype list and the attribute never reached the BOM."""
    from backend.utilities.cbom_sources import inventory as INV

    facts = {"account": "DC1$", "account_type": "domain_controller", "enc_types_value": 28,
             "enc_types_source": "attribute", "rc4_enabled": True, "aes_enabled": True,
             "enc_types": ["RC4-HMAC", "AES128-CTS-HMAC-SHA1-96", "AES256-CTS-HMAC-SHA1-96"]}
    parts = INV.CertificateParts()
    comp = INV._component(_row("DC1$", facts, algorithm="RC4-HMAC"), "corp AD", parts=parts)  # a row stored before M4
    material = comp["cryptoProperties"]["relatedCryptoMaterialProperties"]
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert comp["cryptoProperties"]["assetType"] == "related-crypto-material" and material["type"] == "secret-key"
    assert props["zs:algorithm"] == "AES256-CTS-HMAC-SHA1-96"
    assert props["zs:kerberos_enc_types"] == "RC4-HMAC,AES128-CTS-HMAC-SHA1-96,AES256-CTS-HMAC-SHA1-96"
    assert props["zs:msds_supported_encryption_types"] == "28" and props["zs:enc_types_source"] == "attribute"
    algs = {c["bom-ref"]: c for c in parts.components()}
    assert material["algorithmRef"] in algs and algs[material["algorithmRef"]]["name"] == "AES256-CTS-HMAC-SHA1-96"
    refs = props["zs:kerberos_enc_type_refs"].split(",")
    assert sorted(algs[r]["name"] for r in refs) == ["AES128-CTS-HMAC-SHA1-96", "AES256-CTS-HMAC-SHA1-96", "RC4-HMAC"]
    rc4 = next(c for c in algs.values() if c["name"] == "RC4-HMAC")["cryptoProperties"]["algorithmProperties"]
    assert rc4["primitive"] == "stream-cipher" and "nistQuantumSecurityLevel" not in rc4
    assert {p["value"] for c in algs.values() for p in c["properties"]} == {"kerberos_key"}
    # a second account with the same types shares the parts
    INV._component(_row("DC2$", facts, row_id=2), "corp AD", parts=parts)
    assert len(parts.components()) == 3


def test_m4_an_unset_attribute_exports_as_unset_with_no_algorithm():
    from backend.utilities.cbom_sources import inventory as INV

    facts = {"account": "svc-sql", "account_type": "service_account", "enc_types": [], "enc_types_value": None,
             "enc_types_source": "default", "dc_default": True}
    parts = INV.CertificateParts()
    comp = INV._component(_row("svc-sql", facts, algorithm="RC4-HMAC"), "corp AD", parts=parts)  # stored before M1
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["zs:msds_supported_encryption_types"] == "unset" and props["zs:enc_types_source"] == "default"
    assert "zs:algorithm" not in props and "algorithmRef" not in comp["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert parts.components() == []


def test_m4_the_kerberos_components_validate_against_cyclonedx_1_6():
    """The components above in a CycloneDX 1.6 document, checked against the official 1.6.2 JSON schema (the
    independent validator in tests/support, as the CB-06 export tests use)."""
    from support.cyclonedx_schema import json_errors

    from backend.utilities.cbom_sources import inventory as INV

    parts = INV.CertificateParts()
    rows = [_row("DC1$", {"account": "DC1$", "account_type": "domain_controller", "enc_types_value": 28,
                          "enc_types_source": "attribute",
                          "enc_types": ["RC4-HMAC", "AES128-CTS-HMAC-SHA1-96", "AES256-CTS-HMAC-SHA1-96"]}),
            _row("svc-legacy", {"account": "svc-legacy", "account_type": "service_account", "enc_types_value": 7,
                                "enc_types_source": "attribute",
                                "enc_types": ["DES-CBC-CRC", "DES-CBC-MD5", "RC4-HMAC"]}, row_id=2),
            _row("svc-sql", {"account": "svc-sql", "account_type": "service_account", "enc_types": [],
                             "enc_types_source": "default"}, row_id=3)]
    components = [INV._component(r, "corp AD", parts=parts) for r in rows] + parts.components()
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components}
    assert json_errors(doc) == []
    des = next(c for c in parts.components() if c["name"] == "DES-CBC-MD5")["cryptoProperties"]["algorithmProperties"]
    assert des == {"primitive": "block-cipher", "parameterSetIdentifier": "56", "mode": "cbc"}


# ----------------------------------------------------------------------------- #488 review m3: node capability
def test_m3_a_node_without_the_ad_collector_never_claims_an_ad_job_and_the_plan_says_why(api, world):  # noqa: F811
    from backend.utilities.cbom_sources import capabilities as CAPS

    assert CAPS.required_capabilities("active_directory", {}) == frozenset({"ad_ldaps"})
    _engine, _ = world
    node_id, token, _ = enroll_node(api)
    old = api("POST", "/cbom/node/heartbeat", None, headers={"X-ZS-Node-Token": token},
              json={"version": "1.0.6", "capabilities": {"collectors": ["linux_ssh", "network_tls"]}})
    assert old.status_code == 200
    r = api("POST", "/1/cbom/sources/items", json={"kind": "active_directory", "name": "corp-ad", "node_id": node_id,
                                                   "config": _ad(window="any"), "secrets": {"password": PASSWORD}})
    assert r.status_code == 201, r.text
    src = r.json()["source"]
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"servers": True}}).json()
    item = next(i for i in est["skipped"] if i["source_id"] == src["id"])
    assert item["reason"].startswith("Needs a scan node with Active Directory support") and "1.0.6" in item["reason"]
    _ad_capable(api, token)  # the node is updated: the source is planned
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"servers": True}}).json()
    assert any(i["source_id"] == src["id"] and i["status"] == "queued" for i in est["items"])
