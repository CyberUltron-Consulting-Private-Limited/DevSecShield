"""A completed CBOM Sources run is a CBOM result, just as a completed code scan is (M1x, X1 Nov 11).

X1: a Sources run found 9 assets (an RSA-1024/SHA-1 certificate, weak and anonymous suites, a certificate expiring in
29 days) and yet the CBOM dashboard said 0 certificates and "No scans yet", the team home counted 0 completed scans,
every data deliverable was disabled ("No completed CBOM scans yet") and the Network TLS PDF listed no endpoint and
said "The platform does not probe any endpoint".

The rule (``collections_view``): each source's latest completed collection counts next to the code scans; an asset
seen by both (a certificate in the repository and on the endpoint) is counted once, from the latest observation.
These tests check that the dashboard API, the team home, the deliverables manifest, the roll-up behind the PDFs and
the Network TLS PDF agree, with no double counting.
"""
from __future__ import annotations

import datetime as dt
import subprocess
import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import api, enroll_node, linux_body, world  # noqa: E402,F401
from test_cbom_wp10_outputs import _claim, _collect, _run  # noqa: E402

from backend.new_models import CbomCollectionJob, Scan  # noqa: E402
from backend.utilities.cbom_sources import collections_view as CV  # noqa: E402

NOW = dt.datetime.utcnow().replace(microsecond=0)
NOT_BEFORE = (NOW - dt.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
NOT_AFTER = (NOW + dt.timedelta(days=29)).strftime("%Y-%m-%dT%H:%M:%SZ")
LEAF = {"subject": "CN=x1-tls.lab.test", "issuer": "CN=x1-tls.lab.test", "not_after": NOT_AFTER, "key_alg": "RSA",
        "key_size": 1024, "sig_alg": "sha1WithRSAEncryption", "fingerprint_sha256": "94" * 32, "self_signed": True}
# what the X1 scan node stored for 172.17.0.4:8443 (run #8), with this test's target
TLS = {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:8443", "name": "HTTPS 10.20.0.1:8443",
       "algorithm": "TLS_AES_256_GCM_SHA384",
       "facts": {"protocol_label": "HTTPS", "service": "tls", "mode": "full", "negotiated_version": "TLSv1.3",
                 "negotiated_cipher": "TLS_AES_256_GCM_SHA384", "negotiated_group": "X25519", "chain_length": 1,
                 "leaf": LEAF, "versions": {"SSLv3": False, "TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True,
                                            "TLSv1.3": True},
                 "pq_hybrid": False, "fallback_scsv": True, "downgrade_exposed": False,
                 "weak_ciphers_accepted": {"obsolete": ["TLS_ECDH_anon_WITH_AES_128_CBC_SHA"],
                                           "static_rsa": ["TLS_RSA_WITH_AES_128_GCM_SHA256"]},
                 "weak_cipher_probe_version": "TLSv1.2", "tls": True}}
CERT = {"type": "certificate", "target": "10.20.0.1", "location": "10.20.0.1:8443#chain[0]", "name": "CN=x1-tls.lab.test",
        "algorithm": "RSA", "key_size": 1024,
        "facts": {"source": "tls", "subject": "CN=x1-tls.lab.test", "issuer": "CN=x1-tls.lab.test", "serial": "57ab",
                  "not_before": NOT_BEFORE, "not_after": NOT_AFTER, "sig_alg": "sha1WithRSAEncryption", "key_alg": "RSA",
                  "key_size": 1024, "san": [], "is_ca": True, "self_signed": True, "fingerprint_sha256": "94" * 32,
                  "chain_index": 0}}
HOST_KEY = {"type": "ssh_host_key", "target": "10.20.0.1", "location": "/etc/ssh/ssh_host_rsa_key.pub",
            "name": "RSA host key", "algorithm": "ssh-rsa", "key_size": 3072, "facts": {"type": "ssh-rsa", "bits": 3072}}


def _code_scan(created: dt.datetime) -> Scan:
    """A code scan of a repository that holds the endpoint's certificate (the overlapping asset) and an RSA-1024."""
    cert_row = {"title": "tls.crt", "algorithm_name": "tls.crt", "asset_type": "certificate",
                "algorithm_type": "certificate", "location": "deploy/tls.crt", "bom_ref": "crypto-cert-tls-crt",
                "impact": "High", "finding_codes": ["WEAK_CERTIFICATE_KEY"], "quantum_safe": None,
                "crypto_strength": "weak", "weak": True, "key_size": "1024", "not_valid_after": NOT_AFTER}
    rsa_row = {"title": "RSA-1024", "algorithm_name": "RSA", "asset_type": "algorithm", "algorithm_type": "pke",
               "location": "src/crypto_utils.py", "bom_ref": "crypto-algo-rsa-1024", "impact": "High",
               "finding_codes": ["WEAK_ALGORITHM", "QUANTUM_VULNERABLE"], "quantum_safe": False,
               "crypto_strength": "weak", "weak": True, "key_size": "1024"}
    component = {"name": "tls.crt", "type": "cryptographic-asset", "bom-ref": "crypto-cert-tls-crt",
                 "properties": [{"name": "crypto:subjectName", "value": "x1-tls.lab.test"},
                                {"name": "crypto:issuerName", "value": "x1-tls.lab.test"},
                                {"name": "crypto:notValidBefore", "value": NOT_BEFORE},
                                {"name": "crypto:notValidAfter", "value": NOT_AFTER},
                                {"name": "crypto:keySize", "value": "1024"},
                                {"name": "discovery:source", "value": "deploy/tls.crt"}],
                 "cryptoProperties": {"assetType": "certificate"}}
    return Scan(id=74, team_id=1, owner_user_id=1, scan_type="cbom", title="x1 cbom code", scan_status="success",
                scan_metadata={"repo_url": "https://github.com/acme/x1", "branch": "main"}, created_at=created,
                last_updated=created, scan_data={"results": [cert_row, rsa_row], "cbom_json": {"components": [component]}})


@pytest.fixture()
def no_mongo(monkeypatch, world):
    """The dashboards read code-scan finding statuses from Mongo; this sandbox has none (no findings recorded).
    The list, team and deliverables routes read the test database."""
    from backend.routers import cbom_deliverables, scans, team as team_router
    from backend.utilities.dashboard import scan_list, team

    engine, _ = world
    monkeypatch.setattr(scan_list, "get_findings_for_scan_id", lambda *a, **k: [])
    monkeypatch.setattr(team, "get_findings_for_scan_id", lambda *a, **k: [])
    monkeypatch.setattr(scans, "update_status_of_scan_in_main_db", lambda *a, **k: None)
    for module in (scans, team_router, cbom_deliverables):
        monkeypatch.setattr(module, "get_db", lambda: engine)
    for limiter in (scans.read_limiter, cbom_deliverables.limiter):
        limiter.requests.clear()


@pytest.fixture()
def sources_run(api, world):
    """One Sources run of one source: the X1 endpoint (weak suites), its certificate and an SSH host key."""
    engine, _ = world
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    api("POST", "/1/cbom/sources/items", json=linux_body("x1-ssh-lab", node_id=node_id, targets=["10.20.0.1"],
                                                         window="any"))
    run = _run(api, "m1x-run-0001")
    _collect(api, hdr, _claim(api, hdr), [TLS, CERT, HOST_KEY])
    with Session(engine) as s:
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run["id"])).one()
        assert job.status == "success"
        finished = job.finished_at
    return {"engine": engine, "run": run, "finished": finished, "hdr": hdr}


def _pdf_text(api, tmp_path: Path, slug: str) -> tuple[str, dict]:
    r = api("GET", f"/1/cbom/deliverables/{slug}")
    assert r.status_code == 200 and r.content.startswith(b"%PDF-"), r.text[:200]
    path = tmp_path / f"{slug}.pdf"
    path.write_bytes(r.content)
    out = subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True, check=True).stdout
    return " ".join(out.split()), dict(r.headers)


def _all_views(api):
    listing = api("GET", "/1/cbom/scans")
    assert listing.status_code == 200, listing.text
    home = api("GET", "/team/1/dashboard")
    assert home.status_code == 200, home.text
    manifest = api("GET", "/1/cbom/deliverables")
    assert manifest.status_code == 200, manifest.text
    return listing.json(), home.json(), manifest.json()


# ----------------------------------------------------------------------------------------------- X1: Sources only
def test_x1_a_sources_run_alone_is_a_cbom_result_everywhere(api, sources_run, no_mongo, tmp_path):
    from backend.utilities.dashboard.cbom_team_rollup import load_team_cbom_view

    listing, home, manifest = _all_views(api)
    cards = listing["dashboard_data"]["card_data"]
    assert cards["total_crypto_assets"] == 3 and cards["total_certificates"] == 1 and cards["total_keys"] == 1
    assert listing["dashboard_data"]["severity_distribution"]["high"] >= 1
    assert [r["run_id"] for r in listing["sources_runs"]] == [sources_run["run"]["id"]]
    assert listing["sources_runs"][0]["source_name"] == "x1-ssh-lab" and listing["sources_runs"][0]["endpoints_probed"] == 1
    origins = {CV.origin_label(r["origin"]) for r in listing["dashboard_data"]["top_risks"]}
    assert origins == {f"Sources run #{sources_run['run']['id']}: x1-ssh-lab"}
    assert home["card_data"]["total_completed_scans"] == 1  # the run
    assert home["scan_type_count"]["cbom"] == 2  # the world's not-started code scan #77 and the run
    assert home["high_and_critical_vuln_in_past_month"]["high"] >= 1
    basis = manifest["basis"]
    assert basis["eligible"] == 1 and basis["sources"] == 1
    assert all(d["available"] for d in manifest["deliverables"]), manifest["deliverables"]

    view = load_team_cbom_view(sources_run["engine"], 1)
    assert not view.is_empty and view.included == 1 and len(view.collections) == 1
    assert view.asset_occurrences == cards["total_crypto_assets"]
    assert view.assets_by_type.get("certificate", 0) == cards["total_certificates"]
    assert sum(view.issue_by_impact.values()) == sum(listing["dashboard_data"]["severity_distribution"][s]
                                                     for s in ("critical", "high", "medium", "low"))
    assert [c.subject_cn for c in view.certs if c.current] == ["CN=x1-tls.lab.test"]

    text, headers = _pdf_text(api, tmp_path, "network-tls-protocol-assessment")
    assert headers["x-cbom-scans-included"] == "1"
    assert "10.20.0.1:8443" in text and "TLS_ECDH_anon_WITH_AES_128_CBC_SHA" in text
    assert "probed:CBOM Sources" in text and "CN=x1-tls.lab.test" in text
    assert "does not probe any endpoint" not in text and "did not probe any endpoint" not in text
    assert "1 endpoint was probed" in text
    assert "NO COMPLETED CBOM SCANS" not in text

    cert_text, _ = _pdf_text(api, tmp_path, "certificate-estate-register")
    assert "x1-tls.lab.test" in cert_text and "NO COMPLETED CBOM SCANS" not in cert_text


# ------------------------------------------------------------------------- one code scan + one Sources run, overlap
@pytest.mark.parametrize("code_newer", [False, True], ids=["sources-newer", "code-newer"])
def test_code_scan_and_sources_run_agree_and_the_shared_certificate_counts_once(
        api, sources_run, no_mongo, tmp_path, code_newer):
    from backend.utilities.dashboard.cbom_team_rollup import load_team_cbom_view

    finished = sources_run["finished"]
    created = finished + dt.timedelta(minutes=5) if code_newer else finished - dt.timedelta(days=1)
    with Session(sources_run["engine"]) as s:
        s.add(_code_scan(created))
        s.commit()

    listing, home, manifest = _all_views(api)
    data = listing["dashboard_data"]
    cards = data["card_data"]
    # code: certificate + RSA-1024; Sources: endpoint + certificate + host key; the certificate is one asset
    assert cards["total_crypto_assets"] == 4
    assert cards["total_certificates"] == 1
    assert data["sources"]["collections"] == 1 and data["sources"]["deduplicated"] == 1
    kinds = {r["origin"]["kind"] for r in data["top_risks"]}
    assert kinds == {CV.ORIGIN_CODE, CV.ORIGIN_SOURCES}
    cert_risk = [r for r in data["top_risks"] if r["algorithm_type"] == "certificate"]
    assert len(cert_risk) == 1
    assert cert_risk[0]["origin"]["kind"] == (CV.ORIGIN_CODE if code_newer else CV.ORIGIN_SOURCES)

    assert home["card_data"]["total_completed_scans"] == 2  # one code scan, one Sources run
    assert manifest["basis"]["eligible"] == 2 and manifest["basis"]["sources"] == 2

    view = load_team_cbom_view(sources_run["engine"], 1)
    assert view.included == 2 and view.eligible == 2 and len(view.sources) == 2
    assert view.asset_occurrences == cards["total_crypto_assets"]
    assert view.assets_by_type.get("certificate", 0) == 1
    assert len([c for c in view.certs if c.current]) == 1
    current_cert = next(c for c in view.certs if c.current)
    winner = "github.com/acme/x1" if code_newer else "Sources run"
    assert any(winner in label for label, _path in current_cert.locations)
    assert sum(view.issue_by_impact.values()) == sum(data["severity_distribution"][s]
                                                     for s in ("critical", "high", "medium", "low"))
    assert view.pqc_vulnerable == data["quantum_readiness"]["quantum_vulnerable"]

    text, headers = _pdf_text(api, tmp_path, "network-tls-protocol-assessment")
    assert headers["x-cbom-scans-included"] == "2" and headers["x-cbom-sources"] == "2"
    assert text.count("probed:CBOM Sources") >= 1 and "10.20.0.1:8443" in text
    assert "does not probe any endpoint" not in text


# ------------------------------------------------------------------------------------- the wording stays true
def test_code_only_team_keeps_the_no_probe_statement(api, world, no_mongo, tmp_path):
    engine, _ = world
    with Session(engine) as s:
        s.add(_code_scan(dt.datetime(2026, 11, 1)))
        s.commit()
    listing, home, manifest = _all_views(api)
    assert listing["sources_runs"] == [] and listing["dashboard_data"]["sources"]["collections"] == 0
    assert listing["dashboard_data"]["card_data"]["total_crypto_assets"] == 2
    assert home["card_data"]["total_completed_scans"] == 1 and manifest["basis"]["eligible"] == 1
    text, _ = _pdf_text(api, tmp_path, "network-tls-protocol-assessment")
    assert "does not probe any endpoint" in text and "probed:CBOM Sources" not in text


def test_an_older_collection_of_the_same_source_is_history_not_a_second_result(api, sources_run, no_mongo):
    """Run history and drift keep every run; the views count each source's LATEST completed collection only."""
    hdr = sources_run["hdr"]
    run2 = _run(api, "m1x-run-0002")
    _collect(api, hdr, _claim(api, hdr), [HOST_KEY])
    listing, home, manifest = _all_views(api)
    assert [r["run_id"] for r in listing["sources_runs"]] == [run2["id"]]
    assert listing["dashboard_data"]["card_data"]["total_crypto_assets"] == 1
    assert manifest["basis"]["eligible"] == 1  # one source, one current result
    assert home["card_data"]["total_completed_scans"] == 2  # both runs completed (history)
    with Session(sources_run["engine"]) as s:  # run history keeps both runs and their assets
        jobs = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.kind == "collect")).all()
        assert {j.run_id for j in jobs} == {sources_run["run"]["id"], run2["id"]}
