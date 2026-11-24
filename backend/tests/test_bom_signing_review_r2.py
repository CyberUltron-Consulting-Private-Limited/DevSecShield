"""PR #484 review 6029745818 (R2, final): binding on server facts, stable SBOM serials, no placeholder HMAC.

Failing first on 1a5e201d6 (runs recorded in /home/claude/cb38/fa1/failing-first-r2.txt):
* N1 a serialNumber copied into another team's uploaded SBOM (or a CBOM scan) bound that file to the victim's scan,
  and ``zs:scan_id`` / ``zs:run_id`` read from a stored document bound it to another scan or run;
* N2 an SBOM scan without a stored serial got a fresh uuid4 serial on every download, so none of its own files
  verified against it;
* N3 with a placeholder legacy key the run route issued and accepted HMAC-SHA256 under that public key;
* minors: a trailing-slash zip entry that shadows a file passed, a large verify upload took a CBOM export slot and any
  JSON density was parsed, the staging seed check disagreed with ``weak_seed``, an unsigned XML download claimed a
  detached-es256 scope and an unsigned scan pack said nothing; nits: unlisted ``.json`` pack entries read whole, a
  hard link to the pack's key trusted.

Oracles: the reviewer's repros (``/home/claude/cb38/qa/484b``), the shipped verifier in an isolated interpreter,
``bom_signing.weak_seed`` itself (the staging check is compared with it), and child-process peak RSS.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import io
import json
import os
import shutil
import subprocess
import sys
import textwrap
import zipfile
from pathlib import Path

import pytest
from sqlmodel import Session

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as SOURCES_API
import test_cbom_wp9_outputs as WP9
from backend.new_models import Scan, Team
from backend.tests.support.cyclonedx_schema import json_errors, xml_errors
from backend.utilities.cbom_sources import bom_signing as SIGN
from backend.utilities.cbom_sources import bom_verify as V
from test_cbom_d11_signed_outputs import _add_scans
from test_cbom_posture import ASSETS, _store
from test_cbom_sources_api import _collect_job

globals().update(api=SOURCES_API.api, world=SOURCES_API.world, http=WP9.http)
REPO = Path(__file__).resolve().parents[2]
HDR = {"Authorization": "Bearer t"}
_KEY = {"sbom_sca": "sbom_json", "cbom": "cbom_json", "ai_bom": "ai_bom_json"}


@pytest.fixture(autouse=True)
def _key(bom_signing_fixture_key):
    yield bom_signing_fixture_key


def _verifier(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    script = tmp_path / "zs_bom_verify.py"
    script.write_bytes(Path(V.__file__).read_bytes())
    return subprocess.run([sys.executable, "-I", str(script), *args], capture_output=True, text=True, cwd=tmp_path,
                          check=False)


def _uploaded_scan(engine, scan_id: int, team_id: int, bom: dict, scan_type: str = "sbom_sca") -> None:
    """A scan whose stored BOM is a user's uploaded file, kept as uploaded (serial and metadata included)."""
    with Session(engine) as s:
        if s.get(Team, team_id) is None:
            s.add(Team(id=team_id, name=f"other-{team_id}", credit_balance=1.0))
        s.add(Scan(id=scan_id, team_id=team_id, owner_user_id=1, scan_type=scan_type, scan_status="success",
                   created_at=dt.datetime.now(dt.timezone.utc), scan_data={"results": [], _KEY[scan_type]: bom}))
        s.commit()


def _forged_bom(serial: str, **meta) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "serialNumber": serial,
            **({"metadata": meta} if meta else {}),
            "components": [{"type": "library", "bom-ref": "pkg:pypi/forged@6.6.6", "name": "FORGED",
                            "version": "6.6.6", "purl": "pkg:pypi/forged@6.6.6"}]}


def _props(doc: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in (doc.get("metadata") or {}).get("properties") or []:
        out.setdefault(p["name"], []).append(p["value"])
    return out


def _check(client, url: str, body: bytes, sig_b64: str | None = None) -> dict:
    headers = {**HDR, **({"X-ZS-Signature-B64": sig_b64} if sig_b64 else {})}
    r = client.post(url, headers=headers, content=body)
    assert r.status_code == 200, r.text
    return r.json()


# ----------------------------------------------------------------------------------------------- N1
def test_n1_cross_team_serial_copy_does_not_bind(http):
    """The reviewer's repro: team 2 uploads an SBOM with team 1's scan 22 serial; the deployment signs team 2's
    download; team 1's verify route must not call it scan 22's (embedded JSF or detached)."""
    client, engine, _ = http
    _add_scans(engine)
    victim = json.loads(client.get("/1/sbom_sca/scan/22/bom?format=json", headers=HDR).content)["serialNumber"]
    _uploaded_scan(engine, 40, 2, _forged_bom(victim))
    forged = client.get("/2/sbom_sca/scan/40/bom?format=json", headers=HDR)
    assert forged.status_code == 200 and b"FORGED" in forged.content
    verify = "/1/sbom_sca/scan/22/signature/verify"
    for out in (_check(client, verify, forged.content),
                _check(client, verify, forged.content, forged.headers["x-zs-signature"])):
        assert (out["valid"], out["signed_by_deployment"], out["bound"]) == (False, True, False), out
        assert out["file_subject"]["team_id"] == 2 and out["file_subject"]["scan_id"] == 40, out
    # the same file still verifies as what it is: team 2's scan 40
    assert _check(client, "/2/sbom_sca/scan/40/signature/verify", forged.content)["valid"] is True


def test_n1_cross_type_serial_copy_does_not_bind(http):
    """A CBOM scan carrying an SBOM scan's serial (same team): the type is part of the binding."""
    client, engine, _ = http
    _add_scans(engine)
    victim = json.loads(client.get("/1/sbom_sca/scan/22/bom?format=json", headers=HDR).content)["serialNumber"]
    _uploaded_scan(engine, 41, 1, _forged_bom(victim), scan_type="cbom")
    forged = client.get("/1/cbom/scan/41/bom?format=json", headers=HDR)
    assert forged.status_code == 200
    out = _check(client, "/1/sbom_sca/scan/22/signature/verify", forged.content)
    assert (out["valid"], out["bound"]) == (False, False), out
    assert out["file_subject"]["scan_type"] == "cbom", out


def test_n1_stored_zs_properties_are_replaced_by_server_facts(http, api, world):
    """A stored (uploaded) CBOM naming another scan and a Sources run in its zs: metadata: the served file carries the
    server's scan id, type and team only, so it binds to neither the scan nor the run it names."""
    client, engine, _ = http
    _add_scans(engine)
    engine2, _w = world
    _src, run = _store(api, engine2, ASSETS[:1])
    _uploaded_scan(engine, 42, 2, _forged_bom("urn:uuid:99999999-2222-4333-8444-555555555555", properties=[
        {"name": "zs:scan_id", "value": "22"}, {"name": "zs:scan_type", "value": "sbom_sca"},
        {"name": "zs:team_id", "value": "1"}, {"name": "zs:run_id", "value": str(run["id"])},
        {"name": "zs:bom_serial", "value": "urn:uuid:x"}, {"name": "vendor:note", "value": "kept"}]), "cbom")
    forged = client.get("/2/cbom/scan/42/bom?format=json", headers=HDR)
    props = _props(json.loads(forged.content))
    assert props["zs:scan_id"] == ["42"] and props["zs:scan_type"] == ["cbom"] and props["zs:team_id"] == ["2"]
    assert "zs:run_id" not in props and "zs:bom_serial" not in props and props["vendor:note"] == ["kept"]
    assert _check(client, "/1/sbom_sca/scan/22/signature/verify", forged.content)["valid"] is False
    run_res = api("POST", f"/1/cbom/sources/runs/{run['id']}/signature/verify", content=forged.content).json()
    assert run_res["valid"] is False and run_res["signed_by_deployment"] is True, run_res


def test_n1_binding_needs_id_type_and_team():
    """``binding`` accepts a file only on every server-stamped fact of its target, never on a serial alone."""
    scan = {"scan_id": 22, "scan_type": "sbom_sca", "team_id": 1}
    assert SIGN.binding(scan, team_id=1, scan_id=22, scan_type="sbom_sca") is True
    for wrong in ({"scan_id": 23}, {"scan_type": "cbom"}, {"team_id": 2}, {"scan_id": None}, {"team_id": None}):
        subject = {k: v for k, v in {**scan, **wrong}.items() if v is not None}
        assert SIGN.binding(subject, team_id=1, scan_id=22, scan_type="sbom_sca") is False, wrong
    assert SIGN.binding({"serial": "urn:uuid:a"}, team_id=1, scan_id=22, scan_type="sbom_sca") is False
    assert SIGN.binding({**scan, "ambiguous": True}, team_id=1, scan_id=22, scan_type="sbom_sca") is False
    pack = {"pack": True, "kind": "sbom_sca-scan", "scan_id": 22, "team_id": 1}
    assert SIGN.binding(pack, team_id=1, scan_id=22, scan_type="sbom_sca") is True
    assert SIGN.binding({**pack, "team_id": 2}, team_id=1, scan_id=22, scan_type="sbom_sca") is False
    assert SIGN.binding({**pack, "kind": "cbom-scan"}, team_id=1, scan_id=22, scan_type="sbom_sca") is False
    run = {"run_id": 5, "team_id": 1}
    assert SIGN.binding(run, team_id=1, run_id=5) is True
    assert SIGN.binding({"run_id": 5}, team_id=1, run_id=5) is False
    assert SIGN.binding({**run, "team_id": 2}, team_id=1, run_id=5) is False
    assert SIGN.binding({"pack": True, "kind": "cbom-sources-run", **run}, team_id=1, run_id=5) is True
    assert SIGN.binding({"pack": True, "kind": "cbom-scan", **run}, team_id=1, run_id=5) is False


def test_n1_a_repeated_binding_property_is_ambiguous():
    doc = {"metadata": {"properties": [{"name": "zs:scan_id", "value": "1"}, {"name": "zs:scan_id", "value": "2"}]}}
    assert V.subject_of(doc).get("ambiguous") is True


def test_n1_run_file_of_another_team_does_not_bind(api, world):
    """A run CBOM naming this run but another team (signed by the deployment) is not this run's file; the same
    document naming this team is (positive control: the team is what decides)."""
    engine, _ = world
    _src, run = _store(api, engine, ASSETS[:2])
    rid = run["id"]
    raw = api("GET", f"/1/cbom/sources/runs/{rid}/cbom").content
    doc = json.loads(raw)
    assert _props(doc)["zs:team_id"] == ["1"] and _props(doc)["zs:run_id"] == [str(rid)]
    verify = f"/1/cbom/sources/runs/{rid}/signature/verify"
    for team, expected in (("2", False), ("1", True)):
        changed = {**doc, "metadata": {**doc["metadata"], "properties": [
            {**p, "value": team} if p["name"] == "zs:team_id" else p for p in doc["metadata"]["properties"]]}}
        changed["components"] = changed["components"][:1]  # not the run's current bytes: the binding decides
        body = SIGN.bom_bytes(changed)
        embedded = api("POST", verify, content=body).json()
        detached = api("POST", verify, content=body,
                       headers={"X-ZS-Signature-B64": base64.b64encode(SIGN.detached(body)).decode()}).json()
        for out in (embedded, detached):
            assert (out["valid"], out["signed_by_deployment"]) == (expected, True), (team, out)
    vex = json.loads(api("GET", f"/1/cbom/sources/runs/{rid}/vex").content)
    assert _props(vex)["zs:team_id"] == ["1"]


def test_n1_every_own_file_still_verifies(http):
    """Positive control for each scan type: the JSON (embedded and detached), the VEX and the pack's BOM and manifest
    of the scan verify against it."""
    client, engine, _ = http
    _add_scans(engine)
    for kind, sid in (("cbom", 2), ("ai_bom", 21), ("sbom_sca", 22), ("sbom_sca", 3)):
        verify = f"/1/{kind}/scan/{sid}/signature/verify"
        j = client.get(f"/1/{kind}/scan/{sid}/bom?format=json", headers=HDR)
        props = _props(json.loads(j.content))
        assert (props["zs:scan_id"], props["zs:scan_type"], props["zs:team_id"]) == ([str(sid)], [kind], ["1"])
        v = client.get(f"/1/{kind}/scan/{sid}/vex", headers=HDR)
        zf = zipfile.ZipFile(io.BytesIO(client.get(f"/1/{kind}/scan/{sid}/evidence-pack", headers=HDR).content))
        outs = {"json": _check(client, verify, j.content),
                "json_detached": _check(client, verify, j.content, j.headers["x-zs-signature"]),
                "vex": _check(client, verify, v.content),
                "pack_bom": _check(client, verify, zf.read("bom.cdx.json")),
                "pack_manifest": _check(client, verify, zf.read("manifest.json"),
                                        base64.b64encode(zf.read("manifest.json.sig")).decode())}
        if kind == "cbom":
            x = client.get(f"/1/{kind}/scan/{sid}/bom?format=xml", headers=HDR)
            outs["xml"] = _check(client, verify, x.content, x.headers["x-zs-signature"])
        assert all(o["valid"] for o in outs.values()), (kind, sid, {k: o.get("reason") for k, o in outs.items()})


_AD_ASSETS = [
    {"type": "kerberos_account", "target": "dc1.corp.example", "location": "ad:corp.example/domain_controller/DC1$",
     "name": "DC1$", "algorithm": "AES256-CTS-HMAC-SHA1-96", "protocol": "kerberos",
     "facts": {"account": "DC1$", "account_type": "domain_controller", "enc_types_value": 28,
               "enc_types_source": "attribute", "rc4_enabled": True, "aes_enabled": True,
               "enc_types": ["RC4-HMAC", "AES128-CTS-HMAC-SHA1-96", "AES256-CTS-HMAC-SHA1-96"]}},
    {"type": "kerberos_account", "target": "dc1.corp.example", "location": "ad:corp.example/service_account/svc-rc4",
     "name": "svc-rc4", "algorithm": "RC4-HMAC", "protocol": "kerberos",
     "facts": {"account": "svc-rc4", "account_type": "service_account", "rc4_only": True, "rc4_enabled": True,
               "aes_enabled": False, "enc_types": ["RC4-HMAC"], "enc_types_value": 4, "enc_types_source": "attribute"}},
    {"type": "ad_domain", "target": "dc1.corp.example", "location": "ad:corp.example", "name": "corp.example",
     "protocol": "kerberos", "facts": {"domain": "corp.example", "domain_functional_level": 7,
                                       "krbtgt_password_last_set": "2020-01-01T00:00:00Z"}},
]


def test_n1_ad_collector_run_content_is_stamped_and_signed(api, world, tmp_path):
    """#488's Active Directory assets (kerberos_account: related-crypto-material secret-key with its key-type parts)
    reach the run CBOM like every other run asset: the JSON carries zs:run_id + zs:team_id and a valid JSF signature
    (and X-ZS-Signature), the XML its detached signature, the VEX the same stamp, and the evidence pack verifies
    offline; each file is bound to this run of this team (another team's or run's: test_n1_run_file_of_another_team_does_not_bind)."""
    engine, _ = world
    _src, run, claim, hdr = _collect_job(api, engine)
    job = claim["job"]
    r = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr,
            json={"lease_id": job["lease_id"], "batch_id": "ad-d11", "assets": _AD_ASSETS})
    assert r.status_code == 200 and r.json()["accepted"] == 3, r.text
    rid = run["id"]
    j = api("GET", f"/1/cbom/sources/runs/{rid}/cbom")
    doc = json.loads(j.content)
    assert _props(doc)["zs:run_id"] == [str(rid)] and _props(doc)["zs:team_id"] == ["1"]
    kerberos = [c for c in doc["components"] if any(p["name"] == "zs:kerberos_enc_types" for p in c.get("properties") or [])]
    assert {c["name"] for c in kerberos} == {"DC1$", "svc-rc4"}
    for comp in kerberos:
        material = comp["cryptoProperties"]["relatedCryptoMaterialProperties"]
        assert comp["cryptoProperties"]["assetType"] == "related-crypto-material" and material["type"] == "secret-key"
        assert material["algorithmRef"] in {c["bom-ref"] for c in doc["components"]}  # the key-type part is in the BOM
    assert json_errors({k: v for k, v in doc.items() if k != "signature"}) == []
    assert SIGN.verify_bom(j.content)["valid"] is True
    assert SIGN.verify_detached(j.content, base64.b64decode(j.headers["x-zs-signature"]))["valid"] is True
    x = api("GET", f"/1/cbom/sources/runs/{rid}/cbom?format=xml")
    assert b"secret-key" in x.content and xml_errors(x.content) == []
    assert SIGN.verify_detached(x.content, base64.b64decode(x.headers["x-zs-signature"]))["valid"] is True
    vex = api("GET", f"/1/cbom/sources/runs/{rid}/vex")
    assert _props(json.loads(vex.content))["zs:team_id"] == ["1"] and SIGN.verify_bom(vex.content)["valid"] is True
    verify = f"/1/cbom/sources/runs/{rid}/signature/verify"
    for body, sent in ((j.content, None), (x.content, x.headers["x-zs-signature"]),
                       (vex.content, None)):
        out = api("POST", verify, content=body, headers={"X-ZS-Signature-B64": sent} if sent else {}).json()
        assert out["valid"] is True and out["bound"] is True, out
    pack = tmp_path / "pack.zip"
    pack.write_bytes(api("GET", f"/1/cbom/sources/runs/{rid}/evidence-pack").content)
    res = V.verify_pack(str(pack), SIGN.keyring().verifier_keys())
    assert res["valid"] is True, [c for c in res["checks"] if not c.get("valid")]
    assert b"DC1$" in zipfile.ZipFile(pack).read("bom.cdx.json")


# ----------------------------------------------------------------------------------------------- N2
def test_n2_sbom_without_stored_serial_is_stable_and_its_files_verify(http):
    """The reviewer's repro (scan 3 stores no serial): every serve path computes the same serial, twice."""
    client, engine, _ = http
    _add_scans(engine)
    a = client.get("/1/sbom_sca/scan/3/bom?format=json", headers=HDR)
    b = client.get("/1/sbom_sca/scan/3/bom?format=json", headers=HDR)
    assert a.content == b.content
    serial = json.loads(a.content)["serialNumber"]
    assert serial.startswith("urn:uuid:")
    vex = client.get("/1/sbom_sca/scan/3/vex", headers=HDR)
    assert _props(json.loads(vex.content))["zs:bom_serial"] == [serial]
    zf = zipfile.ZipFile(io.BytesIO(client.get("/1/sbom_sca/scan/3/evidence-pack", headers=HDR).content))
    assert json.loads(zf.read("bom.cdx.json"))["serialNumber"] == serial
    assert json.loads(zf.read("manifest.json"))["subject"]["bom_serial"] == serial
    verify = "/1/sbom_sca/scan/3/signature/verify"
    for out in (_check(client, verify, a.content), _check(client, verify, a.content, a.headers["x-zs-signature"]),
                _check(client, verify, vex.content), _check(client, verify, zf.read("bom.cdx.json")),
                _check(client, verify, zf.read("manifest.json"),
                       base64.b64encode(zf.read("manifest.json.sig")).decode())):
        assert out["valid"] is True, out


def test_n2_stub_sbom_from_findings_gets_the_stable_serial(http):
    """No stored sbom_json at all (the stub built from findings): the same uuid5 serial on every download."""
    client, engine, _ = http
    with Session(engine) as s:
        s.add(Scan(id=44, team_id=1, owner_user_id=1, scan_type="sbom_sca", scan_status="success",
                   created_at=dt.datetime.now(dt.timezone.utc),
                   scan_data={"results": [{"package_name": "requests", "installed_version": "2.0.0",
                                           "vulnerability_id": "CVE-2023-32681", "severity": "medium"}]}))
        s.commit()
    first = json.loads(client.get("/1/sbom_sca/scan/44/bom?format=json", headers=HDR).content)["serialNumber"]
    second = json.loads(client.get("/1/sbom_sca/scan/44/bom?format=json", headers=HDR).content)["serialNumber"]
    assert first == second


def test_n2_scan_bom_passes_subject_name_through(monkeypatch):
    """#489 adds ``subject_name`` to ``bom_dict_from_scan_data``: ``_scan_bom`` passes it as given, so the merge is
    mechanical and the download and verify paths compute the same document."""
    from backend.routers import certin

    seen = []
    real = certin.bom_dict_from_scan_data

    def spy(scan_type, data, **kwargs):
        seen.append(kwargs)
        return real(scan_type, data, **kwargs)

    monkeypatch.setattr(certin, "bom_dict_from_scan_data", spy)
    data = {"results": [], "sbom_json": {"bomFormat": "CycloneDX", "specVersion": "1.6"}}
    bom = certin._scan_bom("sbom_sca", 3, data, 1, subject_name="acme/app")
    assert seen[-1].get("subject_name") == "acme/app" and bom["serialNumber"].startswith("urn:uuid:")
    assert data == {"results": [], "sbom_json": {"bomFormat": "CycloneDX", "specVersion": "1.6"}}  # not mutated


# ----------------------------------------------------------------------------------------------- N3
def _weak(monkeypatch, *, es256: bool) -> None:
    keep = os.environ.get("CBOM_SIGNING_KEY_PEM") if es256 else None
    for name in SIGN._ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CERTIN_HMAC_SECRET", "change-me")
    if keep:
        monkeypatch.setenv("CBOM_SIGNING_KEY_PEM", keep)
    SIGN._CACHE.clear()


@pytest.mark.parametrize("es256", [False, True])
def test_n3_placeholder_legacy_key_hmac_is_refused(api, world, monkeypatch, es256):
    """The reviewer's repro: HMAC-SHA256('change-me', forged) sent with a forged run CBOM is refused, with or without
    an ES256 key; so is the HMAC of the genuine bytes (nothing is accepted under a public key)."""
    engine, _ = world
    _src, run = _store(api, engine, ASSETS[:2])
    _weak(monkeypatch, es256=es256)
    rid = run["id"]
    genuine = api("GET", f"/1/cbom/sources/runs/{rid}/cbom").content
    doc = json.loads(genuine)
    doc["components"][0]["name"] = "FORGED"
    forged = json.dumps(doc).encode()
    verify = f"/1/cbom/sources/runs/{rid}/signature/verify"
    for body in (forged, genuine):
        mac = base64.b64encode(hmac.new(b"change-me", body, hashlib.sha256).digest()).decode()
        r = api("POST", verify, content=body, headers={"X-ZS-Signature-B64": mac}).json()
        assert r["valid"] is False and r["signed_by_deployment"] is False, r
        assert "legacy HMAC key is a placeholder" in r["reason"] and "change-me" not in r["reason"], r


def test_n3_placeholder_legacy_key_issues_no_hmac(api, world, monkeypatch):
    """No HMAC under a public key: without an ES256 key GET .../signature answers 503 naming the rule, the pack has no
    bom_signature.json and says why it is unsigned; with an ES256 key the signature document has no legacy_hmac."""
    engine, _ = world
    _src, run = _store(api, engine, ASSETS[:2])
    rid = run["id"]
    _weak(monkeypatch, es256=True)
    sig = api("GET", f"/1/cbom/sources/runs/{rid}/signature")
    assert sig.status_code == 200 and sig.json()["alg"] == "ES256" and "legacy_hmac" not in sig.json()
    _weak(monkeypatch, es256=False)
    sig = api("GET", f"/1/cbom/sources/runs/{rid}/signature")
    assert sig.status_code == 503 and "placeholder" in sig.json()["detail"] and "change-me" not in sig.text, sig.text
    zf = zipfile.ZipFile(io.BytesIO(api("GET", f"/1/cbom/sources/runs/{rid}/evidence-pack").content))
    assert "bom_signature.json" not in zf.namelist() and "UNSIGNED.txt" in zf.namelist()
    assert b"change-me" not in zf.read("UNSIGNED.txt")
    raw = api("GET", f"/1/cbom/sources/runs/{rid}/cbom").content
    out = api("POST", f"/1/cbom/sources/runs/{rid}/signature/verify", content=raw).json()
    assert out["valid"] is False and out["digest_match"] is True and "placeholder" in out["reason"], out


# ----------------------------------------------------------------------------------------------- minors
def _genuine_pack() -> list[tuple[str, bytes]]:
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:11111111-2222-4333-8444-555555555555",
           "version": 1, "components": [{"type": "cryptographic-asset", "bom-ref": "a", "name": "RSA-2048"}]}
    files = [("bom.cdx.json", SIGN.bom_bytes(bom))]
    return files + SIGN.pack_files(files, subject={"kind": "cbom-scan", "scan_id": 1, "team_id": 1},
                                   detached_for=["bom.cdx.json"])


def _zip(path: Path, members) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in members:
            zf.writestr(name, body)
    return path


@pytest.mark.parametrize("extra,ok", [
    ([("bom.cdx.json/", b'{"forged":1}')], False),   # a directory entry with data, named like a file
    ([("bom.cdx.json/", b"")], False),               # empty, but it shadows a file of the pack
    ([("BOM.cdx.json/", b"")], False),               # ... in another case
    ([("other/", b"x")], False),                     # any directory entry with data
    ([("other/", b"")], True),                       # an empty directory entry of its own name is harmless
])
def test_minor1_trailing_slash_entries(tmp_path, extra, ok):
    keys = tmp_path / "k.json"
    keys.write_text(json.dumps(SIGN.jwks()))
    for order in ("first", "after"):
        members = extra + _genuine_pack() if order == "first" else _genuine_pack() + extra
        z = _zip(tmp_path / f"p-{order}.zip", members)
        res = V.verify_pack(str(z), SIGN.keyring().verifier_keys())
        assert res["valid"] is ok, (order, res["checks"][:3])
        assert _verifier(tmp_path, "--keys", str(keys), "pack", str(z)).returncode == (0 if ok else 1)


def _big_signed(min_bytes: int) -> bytes:
    comps = [{"type": "cryptographic-asset", "bom-ref": f"zs-asset-{i}", "name": f"RSA-2048 key {i} " + "x" * 200,
              "description": "a realistic component with a long description " * 4} for i in range(min_bytes // 400)]
    return SIGN.bom_bytes({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                           "serialNumber": "urn:uuid:11111111-2222-4333-8444-555555555555", "components": comps})


def test_minor2_verify_has_its_own_pool(http, monkeypatch, tmp_path):
    """A large verify upload never takes (or waits on) a CBOM export slot; it takes a verify slot, one per team at a
    time, from a pool of its own."""
    from backend.utilities.cbom_sources import export_slots as SLOTS

    monkeypatch.setattr(SLOTS, "LOCK_DIR", str(tmp_path))
    client, _engine, _ = http
    body = _big_signed(SIGN.LARGE_PARSE_BYTES + 1024)
    assert len(body) >= SIGN.LARGE_PARSE_BYTES
    verify = "/1/cbom/scan/2/signature/verify"
    with SLOTS.slot(), SLOTS.slot():  # every CBOM export slot is taken
        r = client.post(verify, headers=HDR, content=body)
    assert r.status_code == 200 and r.json()["signed_by_deployment"] is True, r.text[:300]
    with SLOTS.verify_slot(1):  # this team's verify slot is taken
        busy = client.post(verify, headers=HDR, content=body)
        with SLOTS.verify_slot(2):  # another team still gets one
            pass
    assert busy.status_code == 429 and busy.headers[SLOTS.BUSY_HEADER] == "verify", busy.text
    small = client.post(verify, headers=HDR, content=client.get("/1/cbom/scan/2/bom", headers=HDR).content)
    assert small.status_code == 200


@pytest.mark.parametrize("unit", [b"{},", b"[],", b"0,", b'"a",'])
def test_minor2_dense_json_is_refused_before_parsing(http, api, world, unit):
    """Bodies far denser than any BOM (more nodes than bytes allow) are refused while they arrive (400), on both
    routes, and by ``bom_verify.loads`` (the offline verifier)."""
    client, _engine, _ = http
    body = b"[" + unit * ((9 * 1024 * 1024) // len(unit)) + b"0]"
    r = client.post("/1/cbom/scan/2/signature/verify", headers=HDR, content=body)
    assert r.status_code == 400 and "nodes" in r.json()["detail"], r.text[:300]
    engine, _ = world
    _s, run = _store(api, engine, ASSETS[:1])
    r2 = api("POST", f"/1/cbom/sources/runs/{run['id']}/signature/verify", content=body)
    assert r2.status_code == 400 and "nodes" in r2.json()["detail"], r2.text[:300]
    with pytest.raises(V.InputError, match="nodes"):
        V.loads(body)


def test_minor2_hostile_64mb_does_not_amplify(tmp_path):
    """The reviewer's 64 MB ``[{},...]`` (1,747 MB peak before): refused by the density check before it is decoded or
    parsed, so ``loads`` adds nothing to the peak the body itself made (measured in a fresh process)."""
    script = tmp_path / "m.py"
    script.write_text(textwrap.dedent(f"""
        import resource, sys
        sys.path.insert(0, {str(Path(V.__file__).parent)!r})
        import bom_verify as V
        body = b'[' + b'{{}},' * ((64 * 1024 * 1024 - 16) // 3) + b'{{}}]'
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024
        try:
            V.loads(body)
            verdict = 'parsed'
        except V.InputError:
            verdict = 'refused'
        print(verdict, before, resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024)
    """))
    out = subprocess.run([sys.executable, "-I", str(script)], capture_output=True, text=True, timeout=300,
                         check=False).stdout.split()
    assert out[0] == "refused" and int(out[2]) - int(out[1]) < 16, out  # no copy of the body, no parse


def test_minor2_realistic_bom_is_not_refused():
    """The density caps leave room for compact real BOMs (a CBOM of many small components, no indentation)."""
    comps = [{"type": "cryptographic-asset", "bom-ref": f"a{i}", "name": "RSA",
              "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "pke"}},
              "properties": [{"name": "zs:impact", "value": "High"}]} for i in range(20000)]
    raw = json.dumps({"bomFormat": "CycloneDX", "components": comps}, separators=(",", ":")).encode()
    assert V.loads(raw)["bomFormat"] == "CycloneDX"


SEEDS = {
    "short": "abcVALUEdef",
    "changeme": "change-me",
    "long_placeholder": "change-me-change-me-change-me-change-me",
    "ok": "9f2c4e7a1b3d5f60718293a4b5c6d7e8f9012a3b4c5d6e7f8091a2b3c4d5e6f70",
    "run_of_one": "a" * 48,
    "abab": "ab" * 24,
    "seven_distinct": "abcdefg" * 6,
    "eight_distinct": "abcdefgh" * 6,
    "tests_only": "zeroshield-tests-only-bom-signing-fixture-seed-v1-public",
    "padded_denylist": "  change-me" + " " * 30,
    "upper_placeholder": "PLACEHOLDER-" + "9f2c4e7a1b3d5f60718293a4b5c6d7e8",
    "multibyte": "ééééééééééééééééé",  # 34 bytes, one distinct character twice over in UTF-8
}


def _seed_check(tmp_path: Path, env_text: str | None) -> subprocess.CompletedProcess:
    fn = (REPO / "scripts" / "deploy" / "staging.sh").read_text()
    body = fn[fn.index("check_bom_signing_seed() {"):]
    body = body[:body.index("\n}\n") + 3]
    env_file = tmp_path / "backend.env"
    if env_text is not None:
        env_file.write_bytes(env_text.encode("utf-8"))
    script = tmp_path / "run.sh"
    script.write_text("set -euo pipefail\nlog() { echo \"LOG: $*\"; }\n" + body +
                      f'check_bom_signing_seed "{env_file if env_text is not None else tmp_path / "missing.env"}"\n')
    return subprocess.run(["bash", str(script)], capture_output=True, text=True, env={"PATH": os.environ["PATH"]},
                          check=False)


@pytest.mark.parametrize("name", sorted(SEEDS))
def test_minor3_staging_seed_check_agrees_with_weak_seed(tmp_path, name):
    seed = SEEDS[name]
    done = _seed_check(tmp_path, f"CERTIN_HMAC_SECRET={seed}\n")
    assert done.returncode == 0, done.stderr
    weak = SIGN.weak_seed(seed)
    if weak is None:
        assert "WARNING" not in done.stdout and "rule ok" in done.stdout, done.stdout
    else:
        rule = {"shorter": "rule short", "a": "rule placeholder", "fewer": "rule few-distinct"}[weak.split(" ")[0]]
        assert "WARNING" in done.stdout and rule in done.stdout, (weak, done.stdout)
    assert seed.strip() not in done.stdout and seed.strip() not in done.stderr  # never the value


def test_minor3_staging_seed_check_missing_env_file(tmp_path):
    done = _seed_check(tmp_path, None)
    assert done.returncode == 0 and done.stderr == "" and "WARNING" in done.stdout and "not readable" in done.stdout


def test_minor3_staging_script_is_shellcheck_clean_where_changed():
    tool = shutil.which("shellcheck")
    if tool is None:
        pytest.skip("shellcheck is not installed here (CI's lint job runs it)")
    out = subprocess.run([tool, "-f", "gcc", str(REPO / "scripts" / "deploy" / "staging.sh")], capture_output=True,
                         text=True, check=False).stdout
    fn = (REPO / "scripts" / "deploy" / "staging.sh").read_text().splitlines()
    start = next(i for i, line in enumerate(fn) if line.startswith("check_bom_signing_seed() {")) + 1
    end = next(i for i in range(start, len(fn)) if fn[i] == "}") + 1
    inside = [ln for ln in out.splitlines() if start <= int(ln.split(":")[1]) <= end]
    assert inside == [], inside


def test_minor4_weak_seed_downloads_say_unsigned_consistently(http, monkeypatch):
    client, _engine, _ = http
    _weak(monkeypatch, es256=False)
    x = client.get("/1/cbom/scan/2/bom?format=xml", headers=HDR)
    assert x.headers["x-zs-signature"] == "unsigned" and "x-zs-signature-scope" not in x.headers, dict(x.headers)
    zf = zipfile.ZipFile(io.BytesIO(client.get("/1/cbom/scan/2/evidence-pack", headers=HDR).content))
    note = zf.read("UNSIGNED.txt").decode()
    assert "unsigned" in note.lower() and "CERTIN_HMAC_SECRET" in note and "change-me" not in note
    assert "manifest.json" not in zf.namelist()


def test_minor4_estate_texts_no_longer_say_unsigned():
    page = (REPO / "frontend" / "app" / "[team_id]" / "cbom" / "page.tsx").read_text()
    tip = (REPO / "frontend" / "content" / "infotips" / "text" / "cbom-scans.ts").read_text()
    for text in (page, tip):
        assert "The file is unsigned" not in text and "It is unsigned" not in text


# ----------------------------------------------------------------------------------------------- nits
def test_nit_unlisted_json_entry_is_not_read(tmp_path):
    """A 300 MB (uncompressed) unlisted .json entry fails the pack without being read whole (memory capped at
    ~600 MB for the verifier's process)."""
    z = tmp_path / "bomb.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for name, body in _genuine_pack():
            zf.writestr(name, body)
        with zf.open("evil.json", "w", force_zip64=True) as fh:
            fh.write(b"[")
            for _ in range(300):
                fh.write(b"0," * (1 << 19))
            fh.write(b"0]")
    keys = tmp_path / "k.json"
    keys.write_text(json.dumps(SIGN.jwks()))
    script = tmp_path / "zs_bom_verify.py"
    script.write_bytes(Path(V.__file__).read_bytes())
    p = subprocess.run(["bash", "-c", f"ulimit -v 600000; exec {sys.executable} -I {script} --keys {keys} pack {z}"],
                       capture_output=True, text=True, cwd=tmp_path, timeout=300, check=False)
    assert p.returncode == 1 and "MemoryError" not in p.stderr and "Traceback" not in p.stderr, p.stderr[-500:]
    assert "in the pack but not in the manifest" in p.stdout


def test_nit_hard_link_to_the_packs_key_is_untrusted(tmp_path):
    d = tmp_path / "pk"
    for name, body in _genuine_pack():
        (d / name).parent.mkdir(parents=True, exist_ok=True)
        (d / name).write_bytes(body)
    home = tmp_path / "home"
    home.mkdir()
    os.link(d / "keys" / "jwks.json", home / "hard.json")
    assert _verifier(tmp_path, "--keys", str(home / "hard.json"), "pack", str(d)).returncode == 3
    (home / "copy.json").write_bytes((d / "keys" / "jwks.json").read_bytes())
    assert _verifier(tmp_path, "--keys", str(home / "copy.json"), "pack", str(d)).returncode == 0
