"""Review 6032108510 (PR #489, second review) m5: route-level tests for review 6028132826 M2, M4 and M6 and the
``/bom`` subject, through the HTTP routes a customer calls, so that a merge resolution that drops a fix (PR #484
rewrites the evidence pack as ``_pack_members``) fails here, not only in a helper test.

* M6  GET /evidence-pack leaves a stored signature out when it does not sign the packed ``bom.cdx.json``, and ships
      one that does.
* /bom GET /bom names the repository (owner/repo from the scan's URL), never the worker's clone directory.
* M2  GET /scan: a match on a version read from a manifest range is listed (marked unverified) and not counted.
* M4  GET /bom serves the licences the worker resolved, with no package-registry call at download time.

Run (repo root): backend/.venv/bin/python -m pytest backend/tests/test_sbom_routes_6032108510.py -q
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import sys
import types
import zipfile
from pathlib import Path

import pytest
from sqlmodel import Session

sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.tests import test_pdf_export_route as EXPORT  # noqa: E402
from backend.tests.test_cbom_consistency import FakeMongo  # noqa: E402

api = EXPORT.api  # the hermetic SQLite + TestClient fixture of the export route tests
AUTH = {"Authorization": "Bearer test"}
CLONE = "/tmp/tmpq8x1_clone/app"
PILLOW = "pkg:pypi/pillow@10.0"
FLASK = "pkg:pypi/flask@0.12.2"
ACME = "pkg:pypi/acme-internal@1.0"


def _sbom() -> dict:
    root = f"urn:dss:subject:{CLONE}"
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "serialNumber": "urn:uuid:3e1b6f0e-2222-4c2a-9a55-0d2c1f6b7a10",
        "metadata": {"timestamp": "2026-11-24T10:00:00Z", "authors": [{"name": "DevSecShield"}],
                     "tools": {"components": [{"type": "application", "name": "syft", "version": "1.57.0"}]},
                     "component": {"type": "application", "name": CLONE, "bom-ref": root},
                     "properties": [{"name": "dss:registry",
                                     "value": "off: no registry lookup (DSS_SBOM_REGISTRY is not 1); licences and "
                                              "hashes from the inventory only"}]},
        "components": [
            {"bom-ref": PILLOW, "type": "library", "name": "pillow", "version": "10.0", "purl": PILLOW,
             "properties": [{"name": "dss:version_source", "value": "range_lower_bound"},
                            {"name": "dss:version_constraint", "value": ">=10.0,<13.0"}]},
            {"bom-ref": FLASK, "type": "library", "name": "flask", "version": "0.12.2", "purl": FLASK,
             "licenses": [{"license": {"id": "BSD-3-Clause"}}]},
            {"bom-ref": ACME, "type": "library", "name": "acme-internal", "version": "1.0", "purl": ACME},
        ],
        "dependencies": [{"ref": root, "dependsOn": [PILLOW, FLASK, ACME]}],
    }


def _rows() -> list[dict]:
    guessed = [{"detected_by": "grype", "vuln_id": vid, "impact": "Critical", "cves": {vid: "x"},
                "title": f"{vid} in pillow ≥ 10.0 (range >=10.0,<13.0) - unverified version",
                "dependency": "pillow (≥ 10.0, range >=10.0,<13.0)", "purl": PILLOW,
                "version_guessed_from": ">=10.0,<13.0", "description": "d", "inventory_only": False,
                "vuln_assessed": True, "owasp_top_10": {}, "compliance_controls": {}, "suggested_fix": "Upgrade"}
               for vid in ("GHSA-3f63-hfp8-52jq", "GHSA-44wm-f244-xhp3", "GHSA-j7hp-h8jx-5ppr")]
    flask = {"detected_by": "grype", "vuln_id": "GHSA-m2qf-hxjv-5gpq", "impact": "High",
             "cves": {"GHSA-m2qf-hxjv-5gpq": "x"}, "title": "GHSA-m2qf-hxjv-5gpq in flask 0.12.2",
             "dependency": "flask==0.12.2", "purl": FLASK, "description": "d", "inventory_only": False,
             "vuln_assessed": True, "license": "BSD-3-Clause", "license_type": "permissive",
             "owasp_top_10": {}, "compliance_controls": {}, "suggested_fix": "Upgrade flask to 2.2.5"}
    acme = {"dependency": "acme-internal==1.0", "purl": ACME, "inventory_only": True, "vuln_assessed": True,
            "cves": {}, "license": "LicenseRef-not-declared", "impact": "Low", "title": "Inventory"}
    return [*guessed, flask, acme]


@pytest.fixture()
def sbom_api(api, monkeypatch):
    """The export fixture's sbom_sca scan, re-stored as an offline worker scan of github.com/acme/app, with its
    findings in a stand-in Mongo, and the certin routes on the same database."""
    from backend.new_models import Scan
    from backend.routers import scans as scans_router
    from backend.utilities.celery.create_findings import create_findings_in_mongo_db
    from backend.utilities.db import findings as findings_mod

    http, ids = api
    engine = scans_router.get_db()
    scan_id = ids["scan_ids"]["sbom_sca"]
    data = {**EXPORT._worker_persist_payload("sbom_sca"), "results": _rows(), "sbom_json": _sbom()}
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        scan.scan_data = data
        scan.scan_metadata = {"repo_url": "https://github.com/acme/app.git", "branch": "main"}
        session.add(scan)
        session.commit()
    mongo = FakeMongo()
    create_findings_in_mongo_db(scan_id=scan_id, scan_results=data, scan_type="sbom_sca", mongo_db=mongo)
    monkeypatch.setattr(findings_mod, "get_mongo_client_db", lambda: mongo)
    monkeypatch.setattr(scans_router, "get_mongo_client_db", lambda: mongo)
    monkeypatch.setattr(scans_router, "get_messages_from_scan", lambda **_k: [])
    monkeypatch.setattr("backend.utilities.dashboard.scan.get_db", lambda: engine)

    async def fake_user(*_a, **_k):
        return types.SimpleNamespace(id=ids["user_id"])

    monkeypatch.setattr("backend.routers.certin.get_db", lambda: engine)
    monkeypatch.setattr("backend.routers.certin.check_if_user_is_in_team", lambda *_a, **_k: None)
    monkeypatch.setattr("backend.routers.certin.get_user_from_header_or_raise_exception", fake_user)
    base = f"/{ids['team_id']}/sbom_sca/scan/{scan_id}"
    return http, base, engine, scan_id


def _store(engine, scan_id: int, **extra) -> None:
    from backend.new_models import Scan

    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        scan.scan_data = {**copy.deepcopy(scan.scan_data), **extra}
        session.add(scan)
        session.commit()


def _digest(bom: dict) -> str:
    canonical = json.dumps(bom, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _pack(http, base) -> zipfile.ZipFile:
    r = http.get(f"{base}/evidence-pack", headers=AUTH)
    assert r.status_code == 200, r.text
    return zipfile.ZipFile(io.BytesIO(r.content))


# ------------------------------------------------------------------------------------------------- M6, route level
def test_m6_evidence_pack_leaves_out_a_stale_stored_signature(sbom_api):
    http, base, engine, scan_id = sbom_api
    stale = {"alg": "HMAC-SHA256", "digest": "0" * 64, "signed_at": "2026-11-01T00:00:00Z", "key_id": "k1"}
    _store(engine, scan_id, bom_signature=stale)
    names = _pack(http, base).namelist()
    assert "bom.cdx.json" in names
    assert "bom_signature.json" not in names


def test_m6_evidence_pack_ships_a_signature_of_the_packed_bom(sbom_api):
    http, base, engine, scan_id = sbom_api
    served = http.get(f"{base}/bom", headers=AUTH).json()
    _store(engine, scan_id, bom_signature={"alg": "HMAC-SHA256", "digest": _digest(served), "key_id": "k1"})
    pack = _pack(http, base)
    packed = json.loads(pack.read("bom.cdx.json"))
    assert packed == served  # the pack's BOM is the /bom document
    assert json.loads(pack.read("bom_signature.json"))["digest"] == _digest(packed)


# ------------------------------------------------------------------------------------------- /bom subject, route level
def test_bom_route_names_the_repository_not_the_clone_directory(sbom_api):
    http, base, _engine, _scan_id = sbom_api
    r = http.get(f"{base}/bom", headers=AUTH)
    assert r.status_code == 200, r.text
    subject = r.json()["metadata"]["component"]
    assert subject["name"] == "acme/app"
    assert CLONE not in json.dumps(r.json())
    pack_bom = json.loads(_pack(http, base).read("bom.cdx.json"))
    assert pack_bom["metadata"]["component"]["name"] == "acme/app"


# ------------------------------------------------------------------------------------------------- M2, route level
def test_m2_scan_route_lists_unverified_matches_without_counting_them(sbom_api):
    http, base, _engine, _scan_id = sbom_api
    r = http.get(base, headers=AUTH)
    assert r.status_code == 200, r.text
    body = r.json()
    cards = body["dashboard"]["card_data"]
    assert cards["total_unverified_version_findings"] == 3
    assert cards["total_vulnerabilities"] == 1 and cards["total_critical_vulnerabilities"] == 0
    pillow = [f for f in body["findings"] if "pillow" in f["dependency"]]
    assert len(pillow) == 3
    assert all(f["version_guessed_from"] == ">=10.0,<13.0" and "unverified" in f["title"] for f in pillow)
    flask = [f for f in body["findings"] if f["dependency"] == "flask==0.12.2"]
    assert flask and flask[0]["version_guessed_from"] is None


# ------------------------------------------------------------------------------------------------- M4, route level
def test_m4_bom_route_serves_the_worker_licences_with_no_registry_call(sbom_api, monkeypatch):
    from backend.utilities.compliance import sbom_registry

    http, base, _engine, _scan_id = sbom_api
    monkeypatch.setenv("DSS_SBOM_REGISTRY", "1")  # even opted in, a worker-resolved scan is served as stored

    def no_egress(*_a, **_k):
        raise AssertionError("package-registry lookup at download time")

    monkeypatch.setattr(sbom_registry, "_fetch_uncached", no_egress)
    bom = http.get(f"{base}/bom", headers=AUTH).json()
    licences = {c["name"]: [x.get("license", {}).get("id") for x in c.get("licenses") or []]
                for c in bom["components"]}
    assert licences["flask"] == ["BSD-3-Clause"]
    assert licences["acme-internal"] == []  # not resolved: stays unknown, it is not made up
