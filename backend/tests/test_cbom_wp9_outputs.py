"""Outputs (WP9): clean rows, the CycloneDX XML export, the import report, self-signed SHA-1, the success-ingestion
race, and credits (estimate digest, re-estimate at start, 1-credit minimum for CBOM code scans, charged vs refunded).

Hermetic: SQLite + TestClient, a fake Mongo and fake Celery; no network.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "wp9-outputs-test-secret-not-for-production-use")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_consistency import FakeMongo  # noqa: E402

from backend.new_models import Scan, Team, TeamMembership, User  # noqa: E402

FIXTURE = json.loads((Path(__file__).resolve().parent / "fixtures" / "cbom_consistency_scan.json").read_text())
ZIP_PAYLOAD = json.dumps({"cbom": {"zip_file_used": True}})
FILE_PAYLOAD = json.dumps({"cbom": {"cbom_file_used": True}})


# ===================================================================================== shared row rules
def test_clean_rows_are_informational_in_old_and_new_scans():
    from backend.utilities.cbom_sources.cbom_metrics import finding_severity, summarize_code_rows
    from backend.utilities.dashboard.bom_risk_score import cbom_finding_risk_score

    new_clean = {"title": "AES-GCM", "impact": None, "finding_codes": [], "weak": False, "quantum_safe": True}
    old_clean = {"title": "AES-GCM", "impact": "Low", "finding_codes": [], "weak": False, "quantum_safe": True}
    legacy = {"title": "DES", "impact": None}  # stored before finding_codes existed: a finding, Low by default
    flagged = {"title": "MD5", "impact": "High", "finding_codes": ["WEAK_ALGORITHM"], "weak": True}
    assert [finding_severity(r) for r in (new_clean, old_clean, legacy, flagged)] == [None, None, "low", "high"]
    assert cbom_finding_risk_score(new_clean) == cbom_finding_risk_score(old_clean) == 0.0
    assert cbom_finding_risk_score(flagged) > 0
    s = summarize_code_rows([new_clean, old_clean, legacy, flagged, "junk", None])
    assert (s.rows, s.findings, s.informational) == (4, 2, 2)
    assert s.severity == {"critical": 0, "high": 1, "medium": 0, "low": 1}
    assert s.severity_distribution()["informational"] == 2
    assert s.average_risk == 4.5  # (7 + 2) / 2 findings, inventory excluded
    assert s.readiness_pct == 100.0  # two judged rows, none quantum-vulnerable


def test_old_library_rows_count_as_weak_everywhere():
    from backend.utilities.cbom_sources.cbom_metrics import summarize_code_rows

    old = {"title": "node-forge@0.9.0", "algorithm_type": "other", "crypto_strength": "strong",
           "finding_codes": ["VULNERABLE_CRYPTO_LIBRARY"], "impact": "High"}
    s = summarize_code_rows([old])
    assert s.weak == 1 and s.algorithm_types == {"library": 1} and s.findings == 1


# ===================================================================================== CycloneDX XML
def test_vendored_xsds_are_the_pinned_upstream_files():
    import hashlib

    from backend.utilities.cbom_sources import cdx_xml

    digests = {Path(p).name: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in (cdx_xml.BOM_XSD, cdx_xml.SPDX_XSD)}
    assert digests == {"bom-1.6.xsd": "e2e09271aea918657f08b11c3d682413fddc8b1ee3944b9a902bf6d339a5b130",
                       "spdx.xsd": "cbc2211755af5ecf9b52dd514c14e4af6f74985b76cf75876ad2608741cb58dc"}


def test_xsd_validation_is_real_and_offline(monkeypatch):
    import socket

    from backend.utilities.cbom_sources.cdx_xml import _schema, to_xml, validate_xml

    _schema.cache_clear()

    def no_network(*_a, **_k):
        raise AssertionError("network access during XML validation")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    good = to_xml(FIXTURE["cbom_json"], strict=True)
    assert validate_xml(good) == []
    # an element out of the XSD's order and an invalid enum are both refused
    swapped = good.replace(b"<name>", b"<nameX>", 1).replace(b"</name>", b"</nameX>", 1)
    assert validate_xml(swapped)
    bad_enum = good.replace(b"<primitive>", b"<primitive>not-a-primitive", 1)
    assert validate_xml(bad_enum)
    assert validate_xml(b"<bom") and validate_xml(b"<?xml version='1.0'?><!DOCTYPE x [<!ENTITY a 'b'>]><x>&a;</x>")


def test_xml_round_trips_key_fields_of_the_json():
    from lxml import etree

    from backend.utilities.cbom_sources.cdx_xml import NS, to_xml

    bom = FIXTURE["cbom_json"]
    doc = etree.fromstring(to_xml(bom, strict=True))
    ns = {"c": NS}
    assert doc.get("serialNumber") == bom["serialNumber"] and doc.get("version") == str(bom["version"])
    comps = doc.findall("c:components/c:component", ns)
    assert [(c.get("type"), c.get("bom-ref"), c.findtext("c:name", namespaces=ns)) for c in comps] == \
        [(c["type"], c.get("bom-ref"), c["name"]) for c in bom["components"]]
    for xml_c, json_c in zip(comps, bom["components"]):
        props = [(p.get("name"), p.text or "") for p in xml_c.findall("c:properties/c:property", ns)]
        assert props == [(p["name"], p.get("value", "")) for p in json_c.get("properties") or []]
        asset = json_c.get("cryptoProperties", {}).get("assetType")
        assert xml_c.findtext("c:cryptoProperties/c:assetType", namespaces=ns) == asset
        occ = [(o.findtext("c:location", namespaces=ns), o.findtext("c:line", namespaces=ns))
               for o in xml_c.findall("c:evidence/c:occurrences/c:occurrence", ns)]
        assert occ == [(o["location"], str(o["line"]) if "line" in o else None)
                       for o in (json_c.get("evidence") or {}).get("occurrences") or []]
    deps = {d.get("ref"): [x.get("ref") for x in d.findall("c:dependency", ns)]
            for d in doc.findall("c:dependencies/c:dependency", ns)}
    assert deps == {d["ref"]: d.get("dependsOn", []) for d in bom.get("dependencies") or []}


def test_xml_strips_control_characters_and_keeps_bom_refs_unique():
    from lxml import etree

    from backend.utilities.cbom_sources.cdx_xml import NS, to_xml, validate_xml

    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
           "components": [
               {"type": "cryptographic-asset", "bom-ref": "a", "name": "x\x00y\x1b<&>\ud800",
                "cryptoProperties": {"assetType": "algorithm"},
                "properties": [{"name": "zs:note", "value": "tab\tok\x0bbad"}]},
               {"type": "cryptographic-asset", "bom-ref": "a", "name": "second",
                "cryptoProperties": {"assetType": "algorithm"}}],
           "dependencies": [{"ref": "a", "dependsOn": ["a"]}]}
    xml = to_xml(bom, strict=True)
    assert validate_xml(xml) == []
    doc = etree.fromstring(xml)
    ns = {"c": NS}
    comps = doc.findall("c:components/c:component", ns)
    assert [c.get("bom-ref") for c in comps] == ["a", "a#2"]
    assert comps[0].findtext("c:name", namespaces=ns) == "xy<&>"
    assert comps[0].find("c:properties/c:property", ns).text == "tab\tokbad"


def test_xml_renames_into_free_bom_refs_and_fills_empty_ones():
    """rev5 #11: bom-refs a, a, a#2 renamed the second a to a#2 (a duplicate key), and a bom-ref that is empty or only
    control characters became '' (refType minLength 1): the XML failed its own XSD. Validated against the bundled
    XSD."""
    from lxml import etree

    from backend.utilities.cbom_sources.cdx_xml import EMPTY_REF, NS, to_xml, validate_xml

    def algo(ref, name):
        return {"type": "cryptographic-asset", "bom-ref": ref, "name": name,
                "cryptoProperties": {"assetType": "algorithm"}}

    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
           "components": [algo("a", "one"), algo("a", "two"), algo("a#2", "three"), algo("", "four"),
                          algo("\x00\x1b", "five"), algo("a#3", "six"),
                          {"type": "cryptographic-asset", "bom-ref": "cert", "name": "c",
                           "cryptoProperties": {"assetType": "certificate",
                                                "certificateProperties": {"signatureAlgorithmRef": "\x01",
                                                                          "subjectPublicKeyRef": "a"}}}],
           "dependencies": [{"ref": "a", "dependsOn": ["a#2", "", "\x02"]}, {"ref": "", "dependsOn": ["a"]}]}
    xml = to_xml(bom, strict=True)
    assert validate_xml(xml) == []
    doc = etree.fromstring(xml)
    ns = {"c": NS}
    refs = [c.get("bom-ref") for c in doc.findall("c:components/c:component", ns)]
    assert refs == ["a", "a#4", "a#2", EMPTY_REF, f"{EMPTY_REF}#2", "a#3", "cert"]
    assert len(set(refs)) == len(refs)
    cert = doc.findall("c:components/c:component", ns)[-1]
    assert cert.find(".//c:signatureAlgorithmRef", ns) is None  # an empty optional reference is left out
    assert cert.findtext(".//c:subjectPublicKeyRef", namespaces=ns) == "a"
    deps = [(d.get("ref"), [x.get("ref") for x in d.findall("c:dependency", ns)])
            for d in doc.findall("c:dependencies/c:dependency", ns)]
    assert deps == [("a", ["a#2", EMPTY_REF, EMPTY_REF]), (EMPTY_REF, ["a"])]


def test_xml_strict_mode_names_keys_without_a_mapping():
    from backend.utilities.cbom_sources.cdx_xml import to_xml

    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "inventedKey": 1,
           "components": [{"type": "library", "name": "x", "madeUp": {"a": 1}}]}
    with pytest.raises(ValueError, match=r"\$\.components\[0\]\.madeUp.*|\$\.inventedKey"):
        to_xml(bom, strict=True)
    assert b"madeUp" not in to_xml(bom)  # non-strict: left out (and logged by path)


# ===================================================================================== import report
def test_import_notes_reach_the_scan_metadata():
    from backend.utilities.dashboard.scan_metadata import get_scan_metadata

    scan = types.SimpleNamespace(scan_metadata={"cbom_file_used": True}, scan_data={
        "results": [], "cbom_json": {}, "cbom_input": {
            "components_total": 5, "crypto_assets": 3, "imported": 2, "skipped_not_crypto": 2, "skipped_invalid": 1,
            "duplicates": 0, "truncated": True, "spec_version": "1.6",
            "notes": ["Only the first 5000 cryptographic assets were analysed.", "", 7, "x" * 900],
            "unexpected": "<script>"}})
    out = get_scan_metadata(scan_type="cbom", scan=scan)["cbom_input"]
    assert out["imported"] == 2 and out["truncated"] is True and out["spec_version"] == "1.6"
    assert out["notes"][0].startswith("Only the first") and len(out["notes"]) == 2 and len(out["notes"][1]) == 300
    assert "unexpected" not in out
    code = types.SimpleNamespace(scan_metadata={}, scan_data={"results": [], "cbom_json": {}})
    assert get_scan_metadata(scan_type="cbom", scan=code)["cbom_input"] is None


# ===================================================================================== self-signed SHA-1
def test_self_signed_sha1_is_explained_not_raised():
    from backend.utilities.cbom_sources.classify import classify

    now = dt.datetime(2026, 10, 31)
    base = {"subject": "CN=a", "issuer": "CN=a", "not_after": "2030-01-01T00:00:00Z", "sig_alg": "sha1WithRSAEncryption",
            "key_alg": "RSA", "key_size": 2048, "self_signed": True}
    leaf = classify("certificate", "RSA", 2048, None, base, now)

    def codes(v):
        return [c for c in v["finding_codes"] if c != "QUANTUM_VULNERABLE"]  # RSA is quantum-vulnerable anyway

    assert "SIG_SHA1" not in leaf["finding_codes"] and codes(leaf) == ["CERT_SELF_SIGNED"]
    assert "not checked by clients" in leaf["texts"]["CERT_SELF_SIGNED"] and "SHA-256" in leaf["texts"]["CERT_SELF_SIGNED"]
    # the finding says plainly why there is no SIG_SHA1 (owner decision: keep, and say so in the text)
    assert "deliberately not reported as a weak SHA-1 signature (SIG_SHA1)" in leaf["texts"]["CERT_SELF_SIGNED"]
    weak_key = classify("certificate", "RSA", 1024, None, {**base, "key_size": 1024}, now)  # lab HST-U-002 / HST-A-003
    assert "SIG_SHA1" not in weak_key["finding_codes"] and "RSA_LT_2048" in weak_key["finding_codes"]
    assert "(SIG_SHA1)" in weak_key["texts"]["CERT_SELF_SIGNED"]
    ca = classify("certificate", "RSA", 2048, None, {**base, "is_ca": True}, now)
    assert codes(ca) == ["CERT_SELF_SHA1"] and ca["impacts"]["CERT_SELF_SHA1"] is None
    assert "CA certificate" in ca["texts"]["CERT_SELF_SHA1"] and "(SIG_SHA1)" in ca["texts"]["CERT_SELF_SHA1"]
    idp = classify("certificate", "RSA", 2048, None, {**base, "source": "idp"}, now)
    assert codes(idp) == ["CERT_SELF_SHA1"] and "identity-provider" in idp["texts"]["CERT_SELF_SHA1"]
    issued = classify("certificate", "RSA", 2048, None, {**base, "self_signed": False, "issuer": "CN=ca"}, now)
    assert "SIG_SHA1" in issued["finding_codes"]  # a CA-issued SHA-1 signature is still High
    sha256_ca = classify("certificate", "RSA", 2048, None, {**base, "is_ca": True, "sig_alg": "sha256WithRSAEncryption"}, now)
    assert codes(sha256_ca) == []


# ===================================================================================== ingestion race
class _Result:
    def __init__(self, state, result):
        self.state, self.result, self.info, self.traceback = state, result, None, None


@pytest.fixture()
def ingest(monkeypatch):
    from backend.utilities.celery import celery_connection as cc
    from backend.utilities.integrations import jira_ticketing

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Team(id=1, name="t", credit_balance=10.0))
        s.add(User(id=1, email="u@example.test", password="x", first_name="u", last_name="t", default_team_id=1))
        s.add(Scan(id=9, team_id=1, owner_user_id=1, scan_type="cbom", scan_status="started", task_id="t-9",
                   credit_consumed=3.0, credit_charged=2.0))
        s.commit()
    state = {"result": _Result("SUCCESS", FIXTURE), "jira": 0, "refunds": []}
    mongo = FakeMongo()
    monkeypatch.setattr(cc, "get_celery_app", lambda: types.SimpleNamespace(AsyncResult=lambda _t: state["result"]))
    monkeypatch.setattr(cc, "get_mongo_client_db", lambda: mongo)
    monkeypatch.setattr(cc, "refund_credits_to_team", lambda team, credits: state["refunds"].append(credits))

    def jira(_scan_id, _engine):
        state["jira"] += 1
        return 0

    monkeypatch.setattr(jira_ticketing, "auto_create_tickets_for_successful_scan", jira)
    return engine, mongo, state


def test_success_is_ingested_once_even_when_a_second_poll_runs_mid_ingest(ingest, monkeypatch):
    from backend.utilities.celery import celery_connection as cc

    engine, mongo, state = ingest
    real_create = cc.create_findings_in_mongo_db
    inserts = []

    def create_and_race(**kwargs):
        inserts.append(kwargs["scan_id"])
        if len(inserts) == 1:  # a concurrent poll arrives after the winner's compare-and-set
            status, data, _scan = cc.get_status_and_update_db(9, "t-9", Scan, engine)
            assert status == "success" and data == FIXTURE
        return real_create(**kwargs)

    monkeypatch.setattr(cc, "create_findings_in_mongo_db", create_and_race)
    status, data, scan = cc.get_status_and_update_db(9, "t-9", Scan, engine)
    assert status == "success" and data == FIXTURE and scan.scan_status == "success"
    cc.get_status_and_update_db(9, "t-9", Scan, engine)  # a later poll
    assert inserts == [9] and state["jira"] == 1
    assert len(mongo["scan_findings"].find({"scan_id": 9})) == len(FIXTURE["results"])


def test_a_failed_ingest_gives_the_transition_back(ingest, monkeypatch):
    from backend.utilities.celery import celery_connection as cc

    engine, mongo, state = ingest

    def broken(**_k):
        raise RuntimeError("mongo down")

    monkeypatch.setattr(cc, "create_findings_in_mongo_db", broken)
    with pytest.raises(Exception):
        cc.get_status_and_update_db(9, "t-9", Scan, engine)
    with Session(engine) as s:
        assert s.get(Scan, 9).scan_status == "started" and state["jira"] == 0


def test_failure_refunds_the_charged_amount_once(ingest):
    from backend.utilities.celery import celery_connection as cc

    engine, _mongo, state = ingest
    state["result"] = _Result("FAILURE", RuntimeError("worker crashed\nTraceback ..."))
    cc.get_status_and_update_db(9, "t-9", Scan, engine)
    cc.get_status_and_update_db(9, "t-9", Scan, engine)
    assert state["refunds"] == [2.0]  # credit_charged, not the 3.0 estimate; once
    with Session(engine) as s:
        assert s.get(Scan, 9).info == {"error": "worker crashed"}


# ===================================================================================== credits
def test_digest_ignores_secrets_and_tracks_the_input():
    from backend.utilities.scan import credit_estimate as ce

    repo = {"repo_context": {"mode": "github", "repo_url": "https://github.com/o/r", "PAT": "ghp_secret", "branch": "main"}}
    a = ce.input_digest("cbom", repo, None)
    b = ce.input_digest("cbom", {"repo_context": {**repo["repo_context"], "PAT": "ghp_other"}}, None)
    c = ce.input_digest("cbom", {"repo_context": {**repo["repo_context"], "branch": "dev"}}, None)
    assert a["digest"] == b["digest"] != c["digest"] and "ghp_secret" not in json.dumps(a)
    z1, z2 = ce.input_digest("cbom", {"zip_file_used": True}, b"PK1"), ce.input_digest("cbom", {"zip_file_used": True}, b"PK2")
    assert z1["digest"] != z2["digest"] and z1["file_size"] == 3
    assert ce.needs_reestimate(None, a) and not ce.needs_reestimate({**a}, a)
    assert ce.needs_reestimate({**a, "formula": "old"}, a)
    assert ce.priced("cbom", {"zip_file_used": True}, 0.004) == 1.0
    assert ce.priced("cbom", {"cbom_file_used": True}, 0.01) == 0.01
    assert ce.priced("cbom", {"zip_file_used": True}, 7.456) == 7.46
    assert ce.priced("sast", {}, 0.2) == 0.2


@pytest.fixture()
def http(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    now = dt.datetime.now(dt.timezone.utc)
    with Session(engine) as s:
        s.add(Team(id=1, name="t", credit_balance=100.0))
        s.add(User(id=1, email="u@example.test", password="x", first_name="u", last_name="t", default_team_id=1))
        s.add(TeamMembership(team_id=1, user_id=1, role="admin"))
        s.add(Scan(id=1, team_id=1, owner_user_id=1, scan_type="cbom", scan_status="NOT_STARTED", created_at=now))
        s.add(Scan(id=2, team_id=1, owner_user_id=1, scan_type="cbom", scan_status="success", created_at=now,
                   scan_data=FIXTURE))
        s.add(Scan(id=3, team_id=1, owner_user_id=1, scan_type="sbom_sca", scan_status="success", created_at=now,
                   scan_data={"results": [], "sbom_json": {"bomFormat": "CycloneDX", "specVersion": "1.6"}}))
        s.add(Scan(id=4, team_id=1, owner_user_id=1, scan_type="cbom", scan_status="NOT_STARTED", created_at=now,
                   credit_consumed=0.004))  # estimated before the digest existed
        s.commit()
    calls = {"estimate": [], "dispatch": 0, "fail_dispatch": False}

    async def fake_estimate(scan_type, engine, start_scan_payload, uploaded_file=None):
        data = await uploaded_file.read() if uploaded_file is not None else b""
        calls["estimate"].append(len(data))
        if start_scan_payload.cbom and start_scan_payload.cbom.cbom_file_used:
            return 0.01
        return len(data) / 100  # 1 credit per 100 bytes in this test

    async def fake_dispatch(**kwargs):
        calls["dispatch"] += 1
        if calls["fail_dispatch"]:
            raise RuntimeError("broker down")
        with Session(engine) as s:
            scan = s.get(Scan, kwargs["scan_id"])
            scan.task_id = "task"
            s.add(scan)
            s.commit()

    async def fake_user(*_a, **_k):
        return types.SimpleNamespace(id=1, email="u@example.test")

    from backend.routers import certin as certin_router
    from backend.routers import scans as scans_router
    from backend.utilities.team import credits as credits_mod

    for mod in (scans_router, certin_router):
        monkeypatch.setattr(mod, "get_db", lambda: engine)
        monkeypatch.setattr(mod, "check_if_user_is_in_team", lambda *_a, **_k: None)
        monkeypatch.setattr(mod, "get_user_from_header_or_raise_exception", fake_user)
    monkeypatch.setattr(credits_mod, "get_db", lambda: engine)
    monkeypatch.setattr(scans_router, "get_mongo_client_db", lambda: FakeMongo())
    monkeypatch.setattr(scans_router, "estimate_credits", fake_estimate)
    monkeypatch.setattr(scans_router, "start_scan_and_update_db", fake_dispatch)
    from backend.main import app

    return TestClient(app), engine, calls


def _post(client, scan_id, action, payload, data=b"x" * 50):
    files = {"uploaded_file": ("a.zip", data, "application/zip")} if data is not None else None
    return client.post(f"/1/cbom/scan/{scan_id}/{action}", data={"start_scan_payload_string": payload}, files=files,
                       headers={"Authorization": "Bearer t"})


def _row(engine, scan_id):
    with Session(engine) as s:
        scan = s.get(Scan, scan_id)
        team = s.get(Team, 1)
        return scan, team.credit_balance


def test_estimate_stores_the_digest_and_applies_the_minimum(http):
    client, engine, calls = http
    r = _post(client, 1, "estimate_credits", ZIP_PAYLOAD)
    assert r.status_code == 200, r.text
    assert r.json() == {"credits_required": 1.0, "minimum_credits": 1.0}  # 0.5 measured, 1 credit minimum (D3)
    scan, _ = _row(engine, 1)
    assert scan.credit_consumed == 1.0 and scan.credit_estimate["file_size"] == 50
    assert scan.credit_estimate["formula"] == "cbom-2026.11-min1-bin5" and len(scan.credit_estimate["digest"]) == 64
    start = _post(client, 1, "start", ZIP_PAYLOAD)
    assert start.status_code == 200, start.text
    scan, balance = _row(engine, 1)
    assert calls["estimate"] == [50] and calls["dispatch"] == 1  # same input: no re-estimate
    assert (scan.credit_charged, balance) == (1.0, 99.0)


def test_start_with_another_file_re_estimates_inside_the_claim(http):
    client, engine, calls = http
    assert _post(client, 1, "estimate_credits", ZIP_PAYLOAD, b"x" * 50).status_code == 200
    r = _post(client, 1, "start", ZIP_PAYLOAD, b"y" * 750)
    assert r.status_code == 200, r.text
    scan, balance = _row(engine, 1)
    assert calls["estimate"] == [50, 750]
    assert (scan.credit_consumed, scan.credit_charged, balance) == (7.5, 7.5, 92.5)
    assert scan.credit_estimate["file_size"] == 750


def test_an_estimate_from_before_the_digest_is_redone_and_clamped(http):
    client, engine, calls = http
    r = _post(client, 4, "start", ZIP_PAYLOAD, b"z" * 10)
    assert r.status_code == 200, r.text
    scan, balance = _row(engine, 4)
    assert calls["estimate"] == [10] and (scan.credit_charged, balance) == (1.0, 99.0)


def test_an_uploaded_cbom_file_stays_a_flat_cent(http):
    client, engine, _calls = http
    r = _post(client, 1, "estimate_credits", FILE_PAYLOAD, b"{}")
    assert r.json() == {"credits_required": 0.01, "minimum_credits": 0.0}


def test_a_failed_dispatch_refunds_what_was_charged_and_releases_the_claim(http):
    client, engine, calls = http
    assert _post(client, 1, "estimate_credits", ZIP_PAYLOAD).status_code == 200
    calls["fail_dispatch"] = True
    r = _post(client, 1, "start", ZIP_PAYLOAD)
    assert r.status_code == 500
    scan, balance = _row(engine, 1)
    assert (scan.scan_status, scan.credit_charged, balance) == ("NOT_STARTED", None, 100.0)


def test_scan_bom_download_json_and_xml(http):
    from backend.utilities.cbom_sources.cdx_xml import validate_xml

    client, _engine, _calls = http
    hdr = {"Authorization": "Bearer t"}
    j = client.get("/1/cbom/scan/2/bom", headers=hdr)
    assert j.status_code == 200 and j.json()["serialNumber"] == FIXTURE["cbom_json"]["serialNumber"]
    x = client.get("/1/cbom/scan/2/bom?format=xml", headers=hdr)
    assert x.status_code == 200 and x.headers["content-type"].startswith("application/vnd.cyclonedx+xml")
    assert x.headers["x-zs-signature-scope"] == "json" and validate_xml(x.content) == []
    assert client.get("/1/sbom_sca/scan/3/bom?format=xml", headers=hdr).status_code == 400
    assert client.get("/1/cbom/scan/1/bom", headers=hdr).status_code == 400  # not finished


def test_scan_bom_json_download_is_the_signed_server_document(http):
    """rev4 H2: the scan page's "CycloneDX JSON" button downloads this response (frontend
    utils/api/cbom_outputs.test.ts proves it saves it unchanged). It is the document the BOM signature covers: every
    crypto asset with its own bom-ref (two MD5 calls stay two assets), library purls, no client-side stamps."""
    import copy

    from backend.routers import certin as certin_router
    from backend.utilities.compliance.certin_attest import bom_dict_from_scan_data

    client, engine, _calls = http
    data = copy.deepcopy(FIXTURE)
    md5 = next(c for c in data["cbom_json"]["components"] if c["name"] == "MD5")
    data["cbom_json"]["components"].append({**copy.deepcopy(md5), "bom-ref": "crypto-algo-md5-other-py",
                                            "evidence": {"occurrences": [{"location": "other.py", "line": 9}]}})
    with Session(engine) as s:
        s.add(Scan(id=5, team_id=1, owner_user_id=1, scan_type="cbom", scan_status="success",
                   created_at=dt.datetime.now(dt.timezone.utc), scan_data=data))
        s.commit()
    hdr = {"Authorization": "Bearer t"}
    signature = client.post("/1/cbom/scan/5/sign", headers=hdr).json()["bom_signature"]
    downloaded = json.loads(client.get("/1/cbom/scan/5/bom?format=json", headers=hdr).content)
    assert downloaded == bom_dict_from_scan_data("cbom", data)
    assert [c["bom-ref"] for c in downloaded["components"]] == [c["bom-ref"] for c in data["cbom_json"]["components"]]
    assert sum(1 for c in downloaded["components"] if c["name"] == "MD5") == 2
    assert next(c for c in downloaded["components"] if c["name"] == "pyca/cryptography")["purl"] == "pkg:pypi/cryptography"
    assert not any(p.get("name") == "dss:compliance" for c in downloaded["components"] for p in c.get("properties") or [])
    sign = certin_router._load_certin_module("sign")
    assert sign.verify_signature(downloaded, signature, secret=certin_router._hmac_secret())
    tampered = copy.deepcopy(downloaded)
    tampered["components"].pop()  # what the old client-side merge did to the second MD5
    assert not sign.verify_signature(tampered, signature, secret=certin_router._hmac_secret())
