"""Identity-provider bugs from the 14 Nov customer test (C3, C5, C10b, C10c), against recorded metadata documents
(``fixtures/idp``, made by a one-off script: an ADFS farm whose token-signing certificate is published in both its
JWKS ``x5c`` and its federation metadata, an expired SAML signing certificate, an unreadable SAML certificate).

* C3: an ADFS source needs its server address, is listed by the API like every IdP and is named in the run list and
  the run's provenance (the Cloud & Identity tab lists it: ``frontend/.../idpProviders.test.ts``).
* C5: one certificate published in the JWKS and in the SAML metadata is ONE certificate row (and one signing key),
  carrying every publication point in ``facts.published_in``.
* C10b: a SAML document whose certificate cannot be read is never "Passed, 0 keys": the test says what failed.
* C10c: an expired SAML signing key is CERT_EXPIRED / High, the code and severity of every expired certificate.

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_idp_adfs_saml.py -q
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
)
from backend.tests.test_cbom_sources_api import api, world  # noqa: F401
from backend.utilities.cbom_sources import idp_collect
from backend.utilities.cbom_sources.classify import classify
from backend.utilities.cbom_sources.kinds import IdpConfig
from backend.utilities.cbom_sources.safe_fetch import Fetched
from sqlmodel import Session, select

FIX = Path(__file__).parent / "fixtures" / "idp"
BASE = "/1/cbom/sources"
ADFS = "https://adfs.bank.test"
A_SHA256 = "6cd232a46701644ef4172ec31a44122e075fd68bdcf38490894f49f14f25a9b1"  # in the JWKS and the SAML metadata
B_SHA256 = "93380a381235604f2eedc2fb424cc55bca713fc3dfe2f30d6047aee762c00395"  # SAML metadata only (next key)


def _serve(monkeypatch, documents: dict[str, str]) -> list[str]:
    """idp_collect.fetch answers from the fixture files; any other URL is a 404."""
    asked: list[str] = []

    def fake_fetch(url, *, accept="application/json", private_allowlist=None):
        asked.append(url)
        name = documents.get(url)
        if name is None:
            return Fetched(url=url, status=404, content_type="text/plain", body=b"not found")
        return Fetched(url=url, status=200, content_type="application/xml" if name.endswith(".xml") else "application/json",
                       body=(FIX / name).read_bytes())

    monkeypatch.setattr(idp_collect, "fetch", fake_fetch)
    return asked


ADFS_DOCS = {
    f"{ADFS}/adfs/.well-known/openid-configuration": "adfs_openid_configuration.json",
    f"{ADFS}/adfs/discovery/keys": "adfs_jwks.json",
    f"{ADFS}/FederationMetadata/2007-06/FederationMetadata.xml": "adfs_federation_metadata.xml",
}


def _run(call, engine, rid: str) -> CbomCollectionRun:
    from backend.workers import cbom_cloud_worker

    run = call("POST", f"{BASE}/runs", json={"include": {"cloud": True}, "client_request_id": rid})
    assert run.status_code == 201, run.text
    while cbom_cloud_worker.run_once(engine, "idp-test-worker"):
        pass
    with Session(engine) as s:
        return s.get(CbomCollectionRun, run.json()["run"]["id"])


def _rows(engine, run_id: int) -> list[CbomCollectedAsset]:
    with Session(engine) as s:
        return list(s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id)).all())


# ----------------------------------------------------------------------------- C3: ADFS is a first-class IdP
def test_adfs_needs_its_server_address_and_reads_both_documents():
    with pytest.raises(ValueError, match="ADFS"):
        IdpConfig(provider="adfs")  # was accepted: collection then read "/adfs/.well-known/..." with no host
    cfg = IdpConfig(provider="adfs", base_url=ADFS + "/")
    assert idp_collect.discovery_urls(cfg.model_dump()) == [
        ("oidc", f"{ADFS}/adfs/.well-known/openid-configuration"),
        ("saml", f"{ADFS}/FederationMetadata/2007-06/FederationMetadata.xml")]


def test_adfs_source_is_listed_collected_and_named_in_the_run_list_and_provenance(api, world, monkeypatch):  # noqa: F811
    from backend.utilities.cbom_sources.run_list import runs_for_scan_list

    engine, _ids = world
    _serve(monkeypatch, ADFS_DOCS)
    bad = api("POST", f"{BASE}/items", json={"kind": "idp", "name": "ADFS", "config": {"provider": "adfs"}})
    assert bad.status_code == 400 and "ADFS server address" in bad.json()["detail"], bad.text  # was 201
    made = api("POST", f"{BASE}/items", json={"kind": "idp", "name": "ADFS", "config": {"provider": "adfs", "base_url": ADFS}})
    assert made.status_code == 201, made.text
    listed = api("GET", f"{BASE}/items").json()["sources"]
    adfs = next(s for s in listed if s["name"] == "ADFS")
    assert (adfs["kind"], adfs["kind_label"], adfs["group"], adfs["config"]["provider"]) == \
        ("idp", "Identity provider", "identity", "adfs")

    run = _run(api, engine, "adfs-run-01")
    assert run.status in ("done", "partial"), run.status
    rows = _rows(engine, run.id)
    assert {r.asset_type for r in rows} >= {"identity_provider", "certificate", "signing_key"}
    listed_runs = runs_for_scan_list(engine, 1)["runs_list_data"]
    row = next(r for r in listed_runs if r["id"] == run.id)
    assert {"id": adfs["id"], "name": "ADFS", "kind": "idp"} in row["sources"] and "ADFS" in row["title"]
    results = api("GET", f"{BASE}/runs/{run.id}/results")
    assert results.status_code == 200, results.text
    provenance = results.json()["provenance"]
    assert [(p["source"], p["kind"], p["outcome"]) for p in provenance] == [("ADFS", "idp", "ok")]


# ----------------------------------------------------------------------------- C5: one certificate, one row
def test_certificate_in_jwks_and_saml_metadata_is_one_asset_with_both_publication_points(monkeypatch):
    _serve(monkeypatch, ADFS_DOCS)
    out = idp_collect.collect_idp({"provider": "adfs", "base_url": ADFS}, "ADFS")
    certs = [a for a in out["assets"] if a["type"] == "certificate"]
    keys = [a for a in out["assets"] if a["type"] == "signing_key"]
    # before: A three times (JWKS x5c, SAML signing, SAML encryption) and B once; signing keys kidA, A, B
    assert sorted(c["facts"]["fingerprint_sha256"] for c in certs) == sorted([A_SHA256, B_SHA256])
    a = next(c for c in certs if c["facts"]["fingerprint_sha256"] == A_SHA256)
    assert a["location"] == f"{ADFS}/adfs/discovery/keys#kidA/x5c0"  # the first publication point names the row
    assert [(p["document"], p["use"]) for p in a["facts"]["published_in"]] == \
        [("jwks", "signing"), ("saml", "signing"), ("saml", "encryption")]
    assert a["facts"]["published_in"][1]["location"].startswith(f"{ADFS}/FederationMetadata/2007-06/FederationMetadata.xml#")
    assert len(keys) == 2, [k["location"] for k in keys]
    kid_a = next(k for k in keys if k["facts"].get("kid") == "kidA")
    assert kid_a["facts"]["certificate_sha256"] == A_SHA256 and kid_a["facts"]["not_after"] == "2036-01-01T00:00:00Z"
    assert [p["document"] for p in kid_a["facts"]["published_in"]] == ["jwks", "saml"]
    # every document is still counted as read, with the rows it contributed before de-duplication
    assert [t["status"] for t in out["targets"]] == ["ok", "ok"]


def test_a_run_stores_the_shared_certificate_once(api, world, monkeypatch):  # noqa: F811
    engine, _ids = world
    _serve(monkeypatch, ADFS_DOCS)
    assert api("POST", f"{BASE}/items", json={"kind": "idp", "name": "ADFS",
                                              "config": {"provider": "adfs", "base_url": ADFS}}).status_code == 201
    run = _run(api, engine, "adfs-run-dedupe")
    rows = _rows(engine, run.id)
    certs = [r for r in rows if r.asset_type == "certificate"]
    assert sorted(r.facts["fingerprint_sha256"] for r in certs) == sorted([A_SHA256, B_SHA256])
    assert len([r for r in rows if r.asset_type == "signing_key"]) == 2
    with Session(engine) as s:
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run.id)).one()
    assert job.asset_count == len(rows)


# ----------------------------------------------------------------------------- C10b: unreadable certificate
def test_saml_with_an_unreadable_certificate_is_not_passed_and_names_the_parse_error(api, world, monkeypatch):  # noqa: F811
    url = "https://login.bank.test/saml/metadata"
    _serve(monkeypatch, {url: "saml_unreadable_cert.xml"})
    out = idp_collect.collect_idp({"provider": "saml_metadata", "metadata_url": url}, "saml-login")
    assert out["targets"][0]["status"] == "partial" and "could not be parsed" in out["targets"][0]["error"]
    gap = next(a for a in out["assets"] if a["type"] == "coverage")
    assert gap["facts"]["detail"].startswith("certificate could not be parsed: ") and \
        len(gap["facts"]["detail"]) > len("certificate could not be parsed: ")

    made = api("POST", f"{BASE}/items", json={"kind": "idp", "name": "saml-login",
                                              "config": {"provider": "saml_metadata", "metadata_url": url}})
    assert made.status_code == 201, made.text
    tested = api("POST", f"{BASE}/items/{made.json()['source']['id']}/test")
    assert tested.status_code == 200, tested.text
    body = tested.json()
    assert body["status"] == "failed", body  # was "passed" with "1 of 1 metadata documents; 0 signing key(s) found"
    assert "could not be parsed" in body["message"] and "0 signing key" in body["message"]
    source = api("GET", f"{BASE}/items/{made.json()['source']['id']}").json()["source"]
    assert source["last_test_status"] == "failed" and "could not be parsed" in source["last_test_summary"]


def test_idp_verdict_warns_when_some_certificates_are_unreadable_but_keys_were_found():
    out = {"counts": {"total": 1, "ok": 0, "partial": 1, "failed": 0, "skipped": 0},
           "targets": [{"target": "u", "status": "partial", "error": "1 certificate could not be parsed: bad"}],
           "assets": [{"type": "signing_key"}]}
    status, summary = idp_collect.idp_test_verdict(out)
    assert status == "partial" and "1 signing key(s) found" in summary and "could not be parsed: bad" in summary
    clean = {"counts": {"total": 2, "ok": 2, "partial": 0, "failed": 0, "skipped": 0},
             "targets": [{"status": "ok", "error": None}] * 2, "assets": [{"type": "signing_key"}] * 3}
    assert idp_collect.idp_test_verdict(clean) == ("passed", "Read 2 of 2 metadata documents; 3 signing key(s) found")


# ----------------------------------------------------------------------------- C10c: expired SAML signing key
def test_expired_saml_signing_key_is_flagged_like_every_expired_certificate(api, world, monkeypatch):  # noqa: F811
    engine, _ids = world
    url = "https://old.bank.test/saml/metadata"
    _serve(monkeypatch, {url: "saml_expired_signing.xml"})
    assets = idp_collect.saml_assets_from_xml((FIX / "saml_expired_signing.xml").read_bytes(), url, "old")
    key = next(a for a in assets if a["type"] == "signing_key")
    cert = next(a for a in assets if a["type"] == "certificate")
    now = dt.datetime.fromisoformat("2026-11-14T00:00:00")  # naive UTC, as the rules use
    key_v = classify("signing_key", key["algorithm"], key["key_size"], None, key["facts"], now)
    cert_v = classify("certificate", cert["algorithm"], cert["key_size"], None, cert["facts"], now)
    assert "CERT_EXPIRED" in cert_v["finding_codes"]
    assert "CERT_EXPIRED" in key_v["finding_codes"], key_v  # was absent: the signing key looked healthy
    assert key_v["impact"] == cert_v["impact"] == "High"

    assert api("POST", f"{BASE}/items", json={"kind": "idp", "name": "old-saml",
                                              "config": {"provider": "saml_metadata", "metadata_url": url}}).status_code == 201
    run = _run(api, engine, "saml-expired-01")
    stored = {r.asset_type: r for r in _rows(engine, run.id) if r.asset_type in ("signing_key", "certificate")}
    assert "CERT_EXPIRED" in (stored["signing_key"].finding_codes or [])
    assert stored["signing_key"].impact == stored["certificate"].impact == "High"
