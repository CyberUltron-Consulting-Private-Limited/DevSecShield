"""CB-38 PR-8: a CBOM Sources run's VEX, signature, PDF report and evidence pack (the code page's remaining downloads).

Failing first on dev c84d9e6: none of /runs/{id}/vex, /signature, /report.pdf, /evidence-pack exists (404), and the
run CBOM JSON carried the request time and insertion-ordered keys, so no signature could cover the downloaded file.
Same SQLite + real-router harness as test_cbom_sources_api.py.
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
import zipfile
from pathlib import Path

import pytest
from sqlmodel import Session

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_posture import ASSETS, _store  # noqa: E402
import test_cbom_sources_api as SOURCES_API  # noqa: E402
from test_cbom_sources_api import _collect_job  # noqa: E402

from backend.new_models import CbomCollectionRun  # noqa: E402
from backend.utilities.cbom_sources import inventory as INV  # noqa: E402
from backend.utilities.cbom_sources import run_deliverables as RD  # noqa: E402
from backend.utilities.compliance.cert_in import sign as SIGN  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
FROZEN = dt.datetime(2026, 11, 14, 9, 30, 0)
# the shared SQLite + real-router fixtures, registered without a module-level name the test parameters shadow
globals().update(api=SOURCES_API.api, world=SOURCES_API.world)


def _validator():
    jsonschema = pytest.importorskip("jsonschema")
    from referencing import Registry, Resource

    schemas = ROOT / "aibom/src/aibom/schemas"
    main = json.loads((schemas / "bom-1.6.schema.json").read_text())
    resources = []
    for name in ("spdx.schema.json", "jsf-0.82.schema.json"):
        contents = json.loads((schemas / name).read_text())
        resources += [(contents["$id"], Resource.from_contents(contents)), (name, Resource.from_contents(contents))]
    return jsonschema.Draft7Validator(main, registry=Registry().with_resources(resources))


def _schema_errors(doc: dict) -> list[str]:
    return [f"{list(e.path)}: {e.message}" for e in _validator().iter_errors(doc)][:5]


def _assets(api, run_id: int) -> dict[str, dict]:
    """Remediation items (asset_key, asset_id) by the asset's location."""
    where = {a["id"]: a["location"] for a in api("GET", f"/1/cbom/sources/runs/{run_id}/assets").json()["items"]}
    return {where[i["asset_id"]]: i for i in api("GET", f"/1/cbom/sources/runs/{run_id}/remediation").json()["items"]}


def _assign(api, run_id: int, key: str, status: str) -> None:
    r = api("PUT", "/1/cbom/remediation", json={"run_id": run_id, "items": [{"asset_key": key, "status": status}]})
    assert r.status_code == 200, r.text


def _by_code_and_asset(vex: dict) -> dict[tuple[str, int], dict]:
    out = {}
    for v in vex["vulnerabilities"]:
        for a in v["affects"]:
            out[(v["id"], int(a["ref"].rsplit("zs-asset-", 1)[1]))] = v["analysis"]
    return out


def _finish(engine, run_id: int) -> None:
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, run_id)
        run.status, run.finished_at = "done", dt.datetime.utcnow()
        s.add(run)
        s.commit()


def _freeze(monkeypatch) -> None:
    from backend.routers import cbom_run_deliverables, cbom_sources
    from backend.utilities.integrations import oscal

    for module in (cbom_run_deliverables, cbom_sources, oscal):
        monkeypatch.setattr(module, "utcnow", lambda: FROZEN)


def _pdf_text(raw: bytes, tmp_path: Path) -> str:
    if shutil.which("pdftotext"):
        path = tmp_path / "run.pdf"
        path.write_bytes(raw)
        return subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True,
                              check=True).stdout
    from backend.tests.support.pdf_text import pdf_text

    return pdf_text(raw)


# ----------------------------------------------------------------------------- VEX mapping (pure)
@pytest.mark.parametrize("code,basis", [
    ("WEAK_CIPHER", "observed"), ("PROTO_TLS10", "observed"), ("RSA_LT_2048", "observed"), ("SIG_MD5", "observed"),
    ("KMS_NO_ROTATION", "observed"), ("NO_PQ_KEX", "quantum_only"), ("SSH_NO_PQ_KEX", "quantum_only"),
    ("QUANTUM_VULNERABLE", "quantum_only"), ("IKE_NO_PQ", "quantum_only"), ("DISK_XTS_128", "quantum_only"),
    ("LIB_KNOWN_CVE", "inferred"), ("LIB_EOL", "inferred"), ("DB_EOL_VERSION", "inferred"),
])
def test_code_basis(code, basis):
    assert RD.code_basis(code) == basis


@pytest.mark.parametrize("basis,status,hndl,state,response,detail", [
    ("observed", None, False, "exploitable", None, RD.DETAIL_OBSERVED),
    ("observed", "open", True, "exploitable", None, RD.DETAIL_OBSERVED),
    ("quantum_only", None, True, "in_triage", None, RD.DETAIL_HNDL),
    ("quantum_only", None, False, "in_triage", None, RD.DETAIL_QUANTUM),
    ("inferred", None, False, "in_triage", None, RD.DETAIL_INFERRED),
    ("cve", None, False, "in_triage", None, "Matched on: x"),
    ("observed", "done", False, "resolved", None, RD.DETAIL_DONE),
    ("quantum_only", "done", True, "resolved", None, RD.DETAIL_DONE),
    ("observed", "accepted_risk", False, "exploitable", ["will_not_fix"], RD.DETAIL_ACCEPTED),
    ("quantum_only", "accepted_risk", True, "in_triage", ["will_not_fix"], RD.DETAIL_ACCEPTED),
    ("observed", "in_progress", False, "exploitable", ["update"], RD.DETAIL_IN_PROGRESS),
])
def test_analysis_mapping(basis, status, hndl, state, response, detail):
    out = RD.analysis_for(basis, status=status, hndl=hndl, cve_detail="Matched on: x")
    assert out["state"] == state and out.get("response") == response and out["detail"].startswith(detail)
    assert out["state"] != "not_affected"  # nothing a run observed is ever "not affected"


# ----------------------------------------------------------------------------- VEX endpoint
def test_run_vex_states_follow_evidence_and_remediation_status(api, world):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS)
    rid = run["id"]
    items = _assets(api, rid)
    cert, tls, lib = items["/etc/ssl/pay.pem"], items["10.20.0.1:443"], items["package:openssl"]
    win, kms = items["os"], items["arn:aws:kms:ap-south-1:111122223333:key/abc"]
    _assign(api, rid, cert["asset_key"], "done")
    _assign(api, rid, win["asset_key"], "accepted_risk")
    _assign(api, rid, kms["asset_key"], "in_progress")

    r = api("GET", f"/1/cbom/sources/runs/{rid}/vex")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert r.headers["content-disposition"].endswith(f'cbom-sources-run-{rid}.vex.json"')
    vex = r.json()
    assert _schema_errors(vex) == []
    got = _by_code_and_asset(vex)
    # observed classical weakness on an open asset: exploitable
    assert got[("ZS-CBOM-PROTO_TLS10", tls["asset_id"])] == {"state": "exploitable", "detail": RD.DETAIL_OBSERVED}
    assert got[("ZS-CBOM-WEAK_CIPHER", tls["asset_id"])]["state"] == "exploitable"
    # quantum-only on an endpoint in transit: in triage, harvest now / decrypt later
    assert got[("ZS-CBOM-NO_PQ_KEX", tls["asset_id"])] == {"state": "in_triage", "detail": RD.DETAIL_HNDL}
    # version-inferred: in triage; CVE matches: in triage
    assert got[("ZS-CBOM-LIB_EOL", lib["asset_id"])]["state"] == "in_triage"
    assert got[("ZS-CBOM-LIB_KNOWN_CVE", lib["asset_id"])]["detail"] == RD.DETAIL_INFERRED
    assert got[("CVE-2022-3602", lib["asset_id"])]["state"] == "in_triage"
    # done: resolved, every code on the asset (classical and quantum-only)
    for code in ("SIG_MD5", "CERT_EXPIRED", "RSA_LT_2048", "QUANTUM_VULNERABLE"):
        assert got[(f"ZS-CBOM-{code}", cert["asset_id"])]["state"] == "resolved"
    # accepted risk: still affected, the response says the team will not fix it
    win_tls10 = got[("ZS-CBOM-PROTO_TLS10", win["asset_id"])]
    assert win_tls10["state"] == "exploitable" and win_tls10["response"] == ["will_not_fix"]
    assert got[("ZS-CBOM-KMS_NO_ROTATION", kms["asset_id"])]["response"] == ["update"]
    assert not any(v["analysis"]["state"] == "not_affected" for v in vex["vulnerabilities"])
    # one finding code splits by analysis: PROTO_TLS10 on the open TLS endpoint and the accepted Windows host
    tls10 = [v for v in vex["vulnerabilities"] if v["id"] == "ZS-CBOM-PROTO_TLS10"]
    assert len(tls10) == 2 and len({v["bom-ref"] for v in vex["vulnerabilities"]}) == len(vex["vulnerabilities"])
    # affects are BOM-Links into the run CBOM
    bom = api("GET", f"/1/cbom/sources/runs/{rid}/cbom").json()
    refs = {c["bom-ref"] for c in bom["components"]}
    prefix = f"urn:cdx:{bom['serialNumber'].removeprefix('urn:uuid:')}/1#"
    assert all(a["ref"].startswith(prefix) and a["ref"][len(prefix):] in refs
               for v in vex["vulnerabilities"] for a in v["affects"])
    props = {p["name"]: p["value"] for p in vex["metadata"]["properties"]}
    assert props["zs:vex_rules"] == RD.VEX_RULES and props["zs:bom_serial"] == bom["serialNumber"]
    assert "zs:as_of" in props and "still" in props["zs:as_of"]  # the run is still collecting
    # the run export itself is unchanged (PR #103 owns it): still "exploitable" for every finding code
    assert {v["analysis"]["state"] for v in bom["vulnerabilities"] if v["id"].startswith("ZS-CBOM-")} == {"exploitable"}


def test_vex_of_a_finished_run_has_no_as_of_note(api, world):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS[:2])
    _finish(engine, run["id"])
    vex = api("GET", f"/1/cbom/sources/runs/{run['id']}/vex").json()
    assert "zs:as_of" not in {p["name"] for p in vex["metadata"]["properties"]}


# ----------------------------------------------------------------------------- signature
def test_signature_verifies_the_downloaded_bytes_and_a_one_byte_change_fails(api, world):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS)
    rid = run["id"]
    raw = api("GET", f"/1/cbom/sources/runs/{rid}/cbom").content
    assert api("GET", f"/1/cbom/sources/runs/{rid}/cbom").content == raw  # same run, same bytes
    r = api("GET", f"/1/cbom/sources/runs/{rid}/signature")
    assert r.status_code == 200, r.text
    assert r.headers["content-disposition"].endswith(f'cbom-sources-run-{rid}-signature.json"')
    sig = r.json()
    secret = (os.environ.get("CERTIN_HMAC_SECRET") or os.environ["JWT_SECRET_KEY"]).encode()
    assert sig["alg"] == "HMAC-SHA256" and sig["key_id"] == "certin-hmac-1"  # the code lane's bom_signature scheme
    assert sig["digest"] == hashlib.sha256(raw).hexdigest() and sig["bytes"] == len(raw)
    mac = base64.b64decode(sig["signature_b64"])
    assert hmac.compare_digest(hmac.new(secret, raw, hashlib.sha256).digest(), mac)  # raw file bytes
    assert SIGN.verify_signature(json.loads(raw), sig, secret=secret)  # the code lane's verifier
    tampered = bytearray(raw)
    at = raw.index(b'"zs:run_id"')  # flip one byte inside a value
    tampered[at + 1] = ord("Z")
    assert not hmac.compare_digest(hmac.new(secret, bytes(tampered), hashlib.sha256).digest(), mac)
    last = bytearray(raw)
    last[-1] ^= 1
    assert not hmac.compare_digest(hmac.new(secret, bytes(last), hashlib.sha256).digest(), mac)
    assert sig["serialNumber"] == json.loads(raw)["serialNumber"] and "as_of" in sig
    # the XML is the same document, not covered
    assert api("GET", f"/1/cbom/sources/runs/{rid}/cbom?format=xml").headers["x-zs-signature-scope"] == "json"


# ----------------------------------------------------------------------------- PDF
def test_pdf_report_prints_run_posture_numbers(api, world, tmp_path):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS)
    rid = run["id"]
    posture = api("GET", f"/1/cbom/sources/runs/{rid}/posture").json()["posture"]
    r = api("GET", f"/1/cbom/sources/runs/{rid}/report.pdf")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf" and r.content.startswith(b"%PDF")
    text = _pdf_text(r.content, tmp_path)
    readiness = f"{posture['pqc_readiness_pct']:.1f}%"
    assert readiness == "50.0%" and readiness in text  # Rule P: the posture API's number
    for heading in ("Sources run #", "Post-quantum and risk posture", "Algorithm family by source",
                    "Certificate expiry", "Top risks", "Compliance clauses", "Findings", "Provenance"):
        assert heading in text, heading
    assert "Harvest-now-decrypt-later assets" in text and "CN=pay.bank.local" in text and "linux-dc" in text
    assert "still running" in text  # active run: "as of"
    assert "Findings cap" not in text


def test_pdf_states_the_findings_cap(api, world, tmp_path, monkeypatch):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS)
    monkeypatch.setattr(RD, "PDF_FINDINGS_CAP", 2)
    text = _pdf_text(api("GET", f"/1/cbom/sources/runs/{run['id']}/report.pdf").content, tmp_path)
    assert "Findings cap: this report lists the first 2 of 5 findings" in " ".join(text.split())


# ----------------------------------------------------------------------------- evidence pack
def test_evidence_pack_manifest_hashes_equal_the_endpoint_bodies(api, world, monkeypatch):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS)
    rid = run["id"]
    _finish(engine, rid)
    _freeze(monkeypatch)
    r = api("GET", f"/1/cbom/sources/runs/{rid}/evidence-pack")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/zip"
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    manifest = json.loads(zf.read("manifest.json"))
    names = [f["name"] for f in manifest["files"]]
    assert names == ["bom.cdx.json", "bom.cdx.xml", "oscal-assessment-results.json", "vex.json",
                     "bom_signature.json", "report.pdf"]
    assert sorted(zf.namelist()) == sorted(names + ["manifest.json"]) and manifest["omitted"] == []
    for entry in manifest["files"]:
        body = zf.read(entry["name"])
        assert hashlib.sha256(body).hexdigest() == entry["sha256"] and len(body) == entry["bytes"]
        served = api("GET", entry["endpoint"])
        assert served.status_code == 200, (entry["endpoint"], served.text[:200])
        assert hashlib.sha256(served.content).hexdigest() == entry["sha256"], entry["name"]
    assert manifest["run"]["id"] == rid and manifest["run"]["status"] == "done" and not manifest["run"]["active"]
    assert manifest["run"]["sources"][0]["name"] == "linux-dc"
    assert manifest["inputs"]["bom_serial"] == json.loads(zf.read("bom.cdx.json"))["serialNumber"]
    assert manifest["inputs"]["export_cap"] == INV.EXPORT_CAP and manifest["inputs"]["truncated"] is False
    sig = json.loads(zf.read("bom_signature.json"))
    secret = (os.environ.get("CERTIN_HMAC_SECRET") or os.environ["JWT_SECRET_KEY"]).encode()
    assert SIGN.verify_signature(json.loads(zf.read("bom.cdx.json")), sig, secret=secret)
    assert manifest["signature"]["digest"] == hashlib.sha256(zf.read("bom.cdx.json")).hexdigest()


def test_evidence_pack_of_an_active_run_omits_oscal_and_says_as_of(api, world):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS[:2])
    zf = zipfile.ZipFile(io.BytesIO(api("GET", f"/1/cbom/sources/runs/{run['id']}/evidence-pack").content))
    manifest = json.loads(zf.read("manifest.json"))
    assert "oscal-assessment-results.json" not in zf.namelist()
    assert manifest["omitted"][0]["name"] == "oscal-assessment-results.json" and "running" in manifest["omitted"][0]["reason"]
    assert manifest["run"]["active"] is True and "still running" in manifest["as_of"]


# ----------------------------------------------------------------------------- tenancy, empty run, export cap
@pytest.mark.parametrize("path", ["vex", "signature", "report.pdf", "evidence-pack"])
def test_deliverables_are_team_scoped(api, world, path):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS[:1])
    rid = run["id"]
    assert api("GET", f"/2/cbom/sources/runs/{rid}/{path}", "carol").status_code == 404  # another team's run
    assert api("GET", f"/1/cbom/sources/runs/{rid}/{path}", "carol").status_code == 403  # not a member
    assert api("GET", f"/1/cbom/sources/runs/{rid}/{path}", None).status_code in (401, 403)
    assert api("GET", f"/1/cbom/sources/runs/999999/{path}").status_code == 404
    assert api("GET", f"/1/cbom/sources/runs/{rid}/{path}", "bob").status_code == 200  # any member


def test_empty_run(api, world, tmp_path):
    engine, _ = world
    _src, run, _claim, _hdr = _collect_job(api, engine)
    rid = run["id"]
    vex = api("GET", f"/1/cbom/sources/runs/{rid}/vex").json()
    assert vex["vulnerabilities"] == [] and _schema_errors(vex) == []
    sig = api("GET", f"/1/cbom/sources/runs/{rid}/signature").json()
    assert sig["digest"] == hashlib.sha256(api("GET", f"/1/cbom/sources/runs/{rid}/cbom").content).hexdigest()
    pdf = api("GET", f"/1/cbom/sources/runs/{rid}/report.pdf")
    assert pdf.status_code == 200
    text = _pdf_text(pdf.content, tmp_path)
    assert "n/a" in text and "No assets were collected." in text
    pack = api("GET", f"/1/cbom/sources/runs/{rid}/evidence-pack")
    assert pack.status_code == 200 and "manifest.json" in zipfile.ZipFile(io.BytesIO(pack.content)).namelist()


def test_run_over_the_export_cap_states_the_cap(api, world, tmp_path, monkeypatch):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS)
    monkeypatch.setattr(INV, "EXPORT_CAP", 2)
    rid = run["id"]
    vex = api("GET", f"/1/cbom/sources/runs/{rid}/vex").json()
    props = {p["name"]: p["value"] for p in vex["metadata"]["properties"]}
    assert props["zs:truncated"] == "true" and "first 2 assets" in props["zs:export_cap"]
    text = " ".join(_pdf_text(api("GET", f"/1/cbom/sources/runs/{rid}/report.pdf").content, tmp_path).split())
    assert "Export cap: the CBOM and this report hold the first 2 assets of this run" in text
    manifest = json.loads(zipfile.ZipFile(io.BytesIO(
        api("GET", f"/1/cbom/sources/runs/{rid}/evidence-pack").content)).read("manifest.json"))
    assert manifest["inputs"]["truncated"] is True and "first 2 assets" in manifest["export_cap_note"]
