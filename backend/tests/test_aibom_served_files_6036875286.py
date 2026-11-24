"""Review 6036875286 (PR #495): the AI BOM's server files, through the HTTP routes.

* M1  GET /bom of an AI BOM scan carries the scan's compliance verdict (``dss:compliance`` on the metadata and on
      every component), as the file the results page used to build did; the evidence pack's ``bom.cdx.json`` and its
      signature carry it too.
* D5  GET /{team}/ai_bom/scan/{id}/spdx and /sarif serve the stored SPDX 3.0 / SARIF 2.1.0 documents with a detached
      ES256 signature over the exact bytes; the evidence pack holds both with their ``.sig``, its signed manifest lists
      them, and the pack's offline verifier verifies the pack and each file.

Run (repo root): backend/.venv/bin/python -m pytest backend/tests/test_aibom_served_files_6036875286.py -q
"""
from __future__ import annotations

import base64
import copy
import io
import json
import subprocess
import sys
import types
import zipfile
from pathlib import Path

import pytest
from sqlmodel import Session

sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.tests import test_pdf_export_route as EXPORT  # noqa: E402
from backend.utilities.cbom_sources import bom_signing as SIGN  # noqa: E402
from backend.utilities.cbom_sources import bom_verify as V  # noqa: E402
from backend.utilities.compliance import served_artifacts as ARTIFACTS  # noqa: E402

api = EXPORT.api
AUTH = {"Authorization": "Bearer test"}
FAILING = {"disclaimer": "advisory", "cert_in_aibom": {"pass": 5, "fail": 2}, "eu_ai_act": {"pass": 3, "fail": 0}}
SPDX = {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [{"type": "CreationInfo", "@id": "_:creationinfo", "specVersion": "3.0.1",
                    "created": "2026-11-24T00:00:00Z", "createdBy": ["urn:dss:org"]},
                   {"type": "ai_AIPackage", "spdxId": "urn:dss:model:é", "name": "bert-base-uncased",
                    "creationInfo": "_:creationinfo"}]}
SARIF = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
         "runs": [{"tool": {"driver": {"name": "DevSecShield AI BOM", "rules": []}}, "results": []}]}


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    for name in SIGN._ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CERTIN_HMAC_SECRET", "review-6036875286-secret-0123456789abcdef")
    SIGN._CACHE.clear()
    yield
    SIGN._CACHE.clear()


@pytest.fixture()
def ai_api(api, monkeypatch):
    """The export fixture's AI BOM scan with failing compliance and its SPDX / SARIF files; certin routes on it."""
    from backend.new_models import Scan
    from backend.routers import scans as scans_router

    http, ids = api
    engine = scans_router.get_db()
    scan_id = ids["scan_ids"]["ai_bom"]
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        data = copy.deepcopy(scan.scan_data)
        data.update(ai_bom_compliance=FAILING, ai_bom_spdx=SPDX, ai_bom_sarif=SARIF)
        scan.scan_data = data
        session.add(scan)
        session.commit()

    async def fake_user(*_a, **_k):
        return types.SimpleNamespace(id=ids["user_id"])

    monkeypatch.setattr("backend.routers.certin.get_db", lambda: engine)
    monkeypatch.setattr("backend.routers.certin.check_if_user_is_in_team", lambda *_a, **_k: None)
    monkeypatch.setattr("backend.routers.certin.get_user_from_header_or_raise_exception", fake_user)
    return http, f"/{ids['team_id']}/ai_bom/scan/{scan_id}", engine, scan_id


def _verdicts(bom: dict) -> tuple[list[str], list[list[str]]]:
    meta = [p["value"] for p in bom["metadata"]["properties"] if p["name"] == "dss:compliance"]
    comps = [[p["value"] for p in c.get("properties") or [] if p["name"] == "dss:compliance"]
             for c in bom["components"]]
    return meta, comps


# --------------------------------------------------------------------------------------------------------- M1
def test_m1_ai_bom_download_carries_the_failing_compliance_verdict(ai_api):
    http, base, _engine, _scan_id = ai_api
    r = http.get(f"{base}/bom", headers=AUTH)
    assert r.status_code == 200, r.text
    bom = json.loads(r.content)
    meta, comps = _verdicts(bom)
    assert meta == ["fail"]
    assert comps and all(v == ["fail"] for v in comps)  # 13 components, one verdict each
    assert V.verify_document(bom, SIGN.keyring().verifier_keys())["valid"] is True  # the signature covers it
    other = [p["name"] for p in bom["metadata"]["properties"]]
    assert "regulatory:disclaimer" in other  # the document's own properties are kept


def test_m1_a_component_verdict_of_its_own_is_kept_and_the_pack_carries_the_same_document(ai_api):
    from backend.new_models import Scan

    http, base, engine, scan_id = ai_api
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        data = copy.deepcopy(scan.scan_data)
        data["ai_bom_compliance"] = {"cert_in_aibom": {"pass": 4, "fail": 0}}
        data["ai_bom_json"]["components"][0].setdefault("properties", []).append(
            {"name": "dss:compliance", "value": "fail"})
        data["ai_bom_json"]["metadata"]["properties"].append({"name": "dss:compliance.cert_in_aibom", "value": "x"})
        scan.scan_data = data
        session.add(scan)
        session.commit()
    served = json.loads(http.get(f"{base}/bom", headers=AUTH).content)
    meta, comps = _verdicts(served)
    assert meta == ["pass"] and comps[0] == ["fail"] and all(v == ["pass"] for v in comps[1:])
    assert not [p for p in served["metadata"]["properties"] if p["name"].startswith("dss:compliance.")]
    pack = zipfile.ZipFile(io.BytesIO(http.get(f"{base}/evidence-pack", headers=AUTH).content))
    packed = json.loads(pack.read("bom.cdx.json"))
    strip = lambda d: {k: v for k, v in d.items() if k != "signature"}  # noqa: E731
    assert strip(packed) == strip(served)


# ------------------------------------------------------------------------------------------ D5: SPDX and SARIF
@pytest.mark.parametrize("artifact, doc, media", [("spdx", SPDX, "application/ld+json"),
                                                  ("sarif", SARIF, "application/sarif+json")])
def test_spdx_and_sarif_are_served_as_stored_and_signed_detached(ai_api, artifact, doc, media):
    http, base, _engine, scan_id = ai_api
    r = http.get(f"{base}/{artifact}", headers=AUTH)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith(media)
    assert r.content == ARTIFACTS.artifact_bytes(doc)
    assert json.loads(r.content) == doc  # nothing added to the document
    assert r.headers["content-disposition"] == f'attachment; filename="ai_bom-{scan_id}.{ARTIFACTS.ARTIFACTS[artifact][2]}"'
    assert r.headers["x-zs-signature-scope"] == "detached-es256"
    der = base64.b64decode(r.headers["x-zs-signature"])
    assert V.verify_detached(r.content, der, SIGN.keyring().verifier_keys())["valid"] is True
    assert V.verify_detached(r.content + b" ", der, SIGN.keyring().verifier_keys())["valid"] is False
    assert http.get(f"{base}/{artifact}", headers=AUTH).content == r.content  # the same bytes every time


def test_a_scan_without_the_file_is_409(ai_api):
    from backend.new_models import Scan

    http, base, engine, scan_id = ai_api
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        data = {k: v for k, v in scan.scan_data.items() if k != "ai_bom_sarif"}
        scan.scan_data = data
        session.add(scan)
        session.commit()
    r = http.get(f"{base}/sarif", headers=AUTH)
    assert r.status_code == 409 and r.json()["detail"] == "No SARIF 2.1.0 log is stored for this scan"


def test_the_evidence_pack_holds_spdx_and_sarif_and_the_offline_verifier_verifies_them(ai_api, tmp_path):
    http, base, _engine, _scan_id = ai_api
    r = http.get(f"{base}/evidence-pack", headers=AUTH)
    assert r.status_code == 200, r.text
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(zf.namelist())
    assert {"bom.spdx.json", "bom.spdx.json.sig", "bom.sarif", "bom.sarif.sig"} <= names
    assert zf.read("bom.spdx.json") == http.get(f"{base}/spdx", headers=AUTH).content  # the download's bytes
    listed = {e["name"] for e in json.loads(zf.read("manifest.json"))["files"]}
    assert {"bom.spdx.json", "bom.spdx.json.sig", "bom.sarif", "bom.sarif.sig"} <= listed
    pack = tmp_path / "pack.zip"
    pack.write_bytes(r.content)
    zf.extractall(tmp_path / "x")
    keys = tmp_path / "keys.json"  # outside the pack: the key the deployment publishes
    keys.write_text(json.dumps(SIGN.jwks()))
    verifier = tmp_path / "v.py"
    verifier.write_bytes(zf.read("verify/zs_bom_verify.py"))
    done = subprocess.run([sys.executable, "-I", str(verifier), "--keys", str(keys), "pack", str(pack)],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
    checks = {c["check"]: c["valid"] for c in json.loads(done.stdout)["checks"]}
    assert checks["detached bom.spdx.json.sig"] is True and checks["detached bom.sarif.sig"] is True
    for name in ("bom.spdx.json", "bom.sarif"):
        one = subprocess.run([sys.executable, "-I", str(verifier), "--keys", str(keys), "detached",
                              str(tmp_path / "x" / name), str(tmp_path / "x" / f"{name}.sig")],
                             capture_output=True, text=True)
        assert one.returncode == 0, one.stdout + one.stderr
    # an altered SPDX file fails the offline check
    tampered = tmp_path / "x" / "bom.spdx.json"
    tampered.write_bytes(tampered.read_bytes().replace(b"bert", b"BERT"))
    bad = subprocess.run([sys.executable, "-I", str(verifier), "--keys", str(keys), "detached", str(tampered),
                          str(tmp_path / "x" / "bom.spdx.json.sig")], capture_output=True, text=True)
    assert bad.returncode == 1
