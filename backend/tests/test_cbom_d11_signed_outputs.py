"""D11 (audit A-01, A-13, A-14) and D4 / D5 (audit C G-X-3): every BOM output a client can verify offline, with the
CBOM content the CycloneDX 1.6 CBOM guidance expects.

Failing first on dev 214d3ca1e:
* run CBOM: no ``dependencies``, no ``oid`` on the RSA key algorithm, no owner / application of the source;
* run VEX: an ``affects`` ref the BOM does not hold is stated (and a BOM-Link is wrapped twice);
* code-scan VEX: a result row the BOM does not hold is stated as affected;
* code-scan ``/bom``: no signature inside, XML says ``X-ZS-Signature-Scope: json``; the SBOM / AIBOM / CBOM evidence
  packs have no manifest, no public key, no detached signature; there is no scan-level verify route.

Oracles: the published CycloneDX 1.6 JSON schema + XSD (``support/cyclonedx_schema``), the ``openssl`` command line
and the verifier shipped in the pack run in an isolated interpreter.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
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
from test_cbom_posture import ASSETS, _store  # noqa: E402
import test_cbom_sources_api as SOURCES_API  # noqa: E402
import test_cbom_wp9_outputs as WP9  # noqa: E402

from backend.new_models import Scan  # noqa: E402
from backend.tests.support.cyclonedx_schema import json_errors, xml_errors  # noqa: E402
from backend.utilities.cbom_sources import bom_signing as SIGN  # noqa: E402
from backend.utilities.cbom_sources import bom_verify as V  # noqa: E402
from backend.utilities.cbom_sources import run_deliverables as RD  # noqa: E402
from backend.utilities.cbom_sources import vex_semantics as VEX  # noqa: E402

# the shared SQLite + real-router fixtures and the certin route fixture, registered without a module-level name the
# test parameters shadow
globals().update(api=SOURCES_API.api, world=SOURCES_API.world, http=WP9.http)
FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    for name in SIGN._ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CERTIN_HMAC_SECRET", "d11-signed-outputs-secret-0123456789abcdef")
    SIGN._CACHE.clear()
    yield
    SIGN._CACHE.clear()


def _props(comp: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in comp.get("properties") or []:
        out.setdefault(p["name"], []).append(p["value"])
    return out


# ----------------------------------------------------------------------------- run CBOM content (A-14)
def test_run_cbom_has_oids_dependencies_and_owners(api, world):
    engine, _ = world
    src, run = _store(api, engine, ASSETS)
    r = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={
        "config": {**src["config"], "owner": "payments-platform@bank.example", "application": "Payments API",
                   "data_classification": "confidential"}, "expected_version": src["row_version"]})
    assert r.status_code == 200, r.text
    raw = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom").content
    doc = json.loads(raw)
    assert json_errors(doc) == []
    by_ref = {c["bom-ref"]: c for c in doc["components"]}
    assets = [c for c in doc["components"] if c["bom-ref"].startswith("zs-asset-")]
    # owner and application from the source's C5 metadata, on every asset
    for comp in assets:
        p = _props(comp)
        assert p["zs:owner"] == ["payments-platform@bank.example"] and p["zs:application"] == ["Payments API"]
        assert p["zs:data_classification"] == ["confidential"]
    app = next(c for c in doc["components"] if c["type"] == "application")
    assert app["name"] == "Payments API" and _props(app)["zs:owner"] == ["payments-platform@bank.example"]
    assert _props(app)["zs:component_role"] == ["application"]
    deps = {d["ref"]: d["dependsOn"] for d in doc["dependencies"]}
    assert set(deps[app["bom-ref"]]) == {c["bom-ref"] for c in assets}  # the application uses its assets
    # the certificate uses its signature algorithm and public key; the key uses its algorithm
    cert = next(c for c in assets if c["cryptoProperties"]["assetType"] == "certificate")
    cp = cert["cryptoProperties"]["certificateProperties"]
    assert {cp["signatureAlgorithmRef"], cp["subjectPublicKeyRef"]} <= set(deps[cert["bom-ref"]])
    key = by_ref[cp["subjectPublicKeyRef"]]
    alg_ref = key["cryptoProperties"]["relatedCryptoMaterialProperties"]["algorithmRef"]
    assert deps[key["bom-ref"]] == [alg_ref]
    # the RSA key algorithm carries the rsaEncryption OID from algid, and level 0 (Shor)
    rsa = by_ref[alg_ref]["cryptoProperties"]
    assert rsa["oid"] == "1.2.840.113549.1.1.1" and rsa["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    for ref, targets in deps.items():
        assert ref in by_ref and set(targets) <= set(by_ref)
    # the asset count is unchanged: the application is not an asset
    meta = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert meta["zs:asset_count"] == str(len(assets))
    x = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom?format=xml").content
    assert xml_errors(x) == [] and b"<dependencies>" in x and b'provides' not in x


# ----------------------------------------------------------------------------- run VEX: only BOM components (item 4)
def test_run_vex_states_only_components_of_the_bom():
    run = types.SimpleNamespace(id=7, team_id=1, status="done")
    head = {"serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555", "version": 2,
            "metadata": {"properties": [{"name": "zs:kb_version", "value": "k"}]}}
    baseline = "urn:cdx:99999999-2222-3333-4444-555555555555/1#zs-asset-3"
    vulns = [
        {"id": "ZS-CBOM-A", "bom-ref": "zs-vuln-a", "analysis": {"state": "in_triage"},
         "affects": [{"ref": "zs-asset-1"}, {"ref": "zs-asset-404"}]},
        {"id": "ZS-CBOM-GONE", "bom-ref": "zs-vuln-gone", "analysis": {"state": "in_triage"},
         "affects": [{"ref": "zs-asset-405"}]},
        {"id": "ZS-CBOM-RESOLVED", "bom-ref": "zs-vuln-r", "analysis": {"state": "resolved"},
         "affects": [{"ref": baseline}]},
    ]
    data = RD.Summary(head=head, vulnerabilities=vulns, refs={"zs-asset-1", "zs-asset-2"})
    out = RD.run_vex(run, data, {}, dt.datetime(2026, 11, 23, 10))
    ids = [v["id"] for v in out["vulnerabilities"]]
    assert ids == ["ZS-CBOM-A", "ZS-CBOM-RESOLVED"]  # the entry whose only asset is outside the BOM is not stated
    a = out["vulnerabilities"][0]
    assert a["affects"] == [{"ref": "urn:cdx:11111111-2222-3333-4444-555555555555/2#zs-asset-1"}]  # the BOM's version
    assert out["vulnerabilities"][1]["affects"] == [{"ref": baseline}]  # a BOM-Link stays as it is, never re-wrapped
    meta = {p["name"]: p["value"] for p in out["metadata"]["properties"]}
    assert meta["zs:affects_not_in_bom"] == "2"
    assert json_errors(out) == []


def test_code_scan_vex_states_only_components_of_the_bom():
    rows = [{"bom_ref": "crypto-a", "finding_codes": ["WEAK_ALGORITHM"]},
            {"bom_ref": "crypto-missing", "finding_codes": ["WEAK_ALGORITHM", "HARDCODED_KEY"]},
            {"finding_codes": ["WEAK_CIPHER_MODE"]},  # no ref at all: "component-2"
            {"bom_ref": "crypto-b", "finding_codes": []}]
    vex = VEX.code_scan_vex(rows, scan_id=1, components=["crypto-a", "crypto-b"],
                            now=dt.datetime(2026, 11, 23, 10))
    stated = {t["ref"] for v in vex["vulnerabilities"] for t in v["affects"]}
    assert stated == {"crypto-a"}  # crypto-b has no finding: no unjustified not_affected stub (staging QA A-13d)
    assert {v["id"] for v in vex["vulnerabilities"]} == {"ZS-CBOM-WEAK_ALGORITHM"}
    meta = {p["name"]: p["value"] for p in vex["metadata"]["properties"]}
    assert meta["zs:affects_not_in_bom"] == "2"


# ----------------------------------------------------------------------------- code scans: /bom, packs, verify (G-X-3)
def _add_scans(engine) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    ai = json.loads((FIXTURES / "ai_bom_export_scandata.json").read_text())
    with Session(engine) as s:
        s.add(Scan(id=21, team_id=1, owner_user_id=1, scan_type="ai_bom", scan_status="success", created_at=now,
                   scan_data=ai))
        s.add(Scan(id=22, team_id=1, owner_user_id=1, scan_type="sbom_sca", scan_status="success", created_at=now,
                   scan_data={"results": [], "sbom_json": {
                       "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                       "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                       "components": [{"type": "library", "bom-ref": "pkg:pypi/requests@2.31.0", "name": "requests",
                                       "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}]}}))
        s.commit()


def test_code_scan_bom_downloads_are_signed_and_verify(http, tmp_path):
    client, engine, _calls = http
    hdr = {"Authorization": "Bearer t"}
    j = client.get("/1/cbom/scan/2/bom?format=json", headers=hdr)
    assert j.status_code == 200
    doc = json.loads(j.content)
    assert doc["signature"]["algorithm"] == "ES256" and json_errors(doc) == []
    assert SIGN.verify_bom(j.content)["valid"] is True
    assert SIGN.verify_detached(j.content, base64.b64decode(j.headers["x-zs-signature"]))["valid"] is True
    x = client.get("/1/cbom/scan/2/bom?format=xml", headers=hdr)
    assert x.headers["x-zs-signature-scope"] == "detached-es256" and xml_errors(x.content) == []
    assert SIGN.verify_detached(x.content, base64.b64decode(x.headers["x-zs-signature"]))["valid"] is True
    # the disclaimer a bank's CBOM carries never names FDA / HIPAA once the code lane rebuilds the scan (aibom tests)
    verify = "/1/cbom/scan/2/signature/verify"
    ok = client.post(verify, headers=hdr, content=j.content).json()
    assert (ok["valid"], ok["method"]) == (True, "embedded JSF")
    tampered = j.content.replace(b'"MD5"', b'"MD4"', 1)
    assert tampered != j.content and client.post(verify, headers=hdr, content=tampered).json()["valid"] is False
    det = client.post(verify, headers={**hdr, "X-ZS-Signature-B64": x.headers["x-zs-signature"]}, content=x.content)
    assert (det.json()["valid"], det.json()["method"]) == (True, "detached ES256")
    bad = client.post(verify, headers={**hdr, "X-ZS-Signature-B64": x.headers["x-zs-signature"]}, content=x.content + b" ")
    assert bad.json()["valid"] is False
    # a file downloaded before the ES256 key: the stored HMAC still verifies it
    signature = client.post("/1/cbom/scan/2/sign", headers=hdr).json()["bom_signature"]
    assert signature["alg"] == "HMAC-SHA256"
    unsigned = json.dumps({k: v for k, v in doc.items() if k != "signature"}).encode()
    old = client.post(verify, headers=hdr, content=unsigned).json()
    assert (old["valid"], old["method"]) == (True, "stored HMAC-SHA256 (legacy)")
    assert client.post(verify, headers=hdr, content=b"").status_code == 400


@pytest.mark.parametrize("scan_type,scan_id", [("cbom", 2), ("ai_bom", 21), ("sbom_sca", 22)])
def test_every_code_scan_evidence_pack_is_signed_and_verifies_offline(http, tmp_path, scan_type, scan_id):
    client, engine, _calls = http
    _add_scans(engine)
    r = client.get(f"/1/{scan_type}/scan/{scan_id}/evidence-pack", headers={"Authorization": "Bearer t"})
    assert r.status_code == 200, r.text
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(zf.namelist())
    kid = SIGN.keyring().active.kid
    assert {"bom.cdx.json", "bom.cdx.json.sig", "manifest.json", "manifest.json.sig", "SHA256SUMS",
            "SHA256SUMS.sig", "keys/jwks.json", f"keys/{kid}.pem", "verify/zs_bom_verify.py",
            "verify/README.txt"} <= names
    if scan_type == "cbom":
        assert {"bom.cdx.xml", "bom.cdx.xml.sig"} <= names
    manifest = json.loads(zf.read("manifest.json"))
    listed = {e["name"] for e in manifest["files"]}
    assert listed == names - {"manifest.json", "manifest.json.sig", "SHA256SUMS", "SHA256SUMS.sig"}  # every file
    assert manifest["subject"] == {"kind": f"{scan_type}-scan", "scan_id": scan_id, "team_id": 1,
                                   "bom_serial": json.loads(zf.read("bom.cdx.json")).get("serialNumber")}
    assert json_errors(json.loads(zf.read("bom.cdx.json"))) == [] or scan_type != "cbom"
    path = tmp_path / "pack.zip"
    path.write_bytes(r.content)
    (tmp_path / "v.py").write_bytes(zf.read("verify/zs_bom_verify.py"))
    done = subprocess.run([sys.executable, "-I", str(tmp_path / "v.py"), "--keys", "/dev/stdin", "pack", str(path)],
                          input=json.dumps(SIGN.jwks()), capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr  # with the key the deployment publishes
    assert json.loads(done.stdout)["valid"] is True
    assert V.verify_pack(str(path), SIGN.keyring().verifier_keys())["valid"] is True
    hashes = {e["name"]: e["sha256"] for e in manifest["files"]}
    assert all(hashlib.sha256(zf.read(n)).hexdigest() == h for n, h in hashes.items())
