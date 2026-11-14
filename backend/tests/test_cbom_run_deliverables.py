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
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_posture import ASSETS, _store  # noqa: E402
import test_cbom_sources_api as SOURCES_API  # noqa: E402
from test_cbom_sources_api import _collect_job  # noqa: E402

from backend.new_models import CbomCollectedAsset, CbomCollectionRun  # noqa: E402
from backend.utilities.cbom_sources import inventory as INV  # noqa: E402
from backend.utilities.cbom_sources import run_deliverables as RD  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
FROZEN = dt.datetime(2026, 11, 14, 9, 30, 0)
# the shared SQLite + real-router fixtures, registered without a module-level name the test parameters shadow
globals().update(api=SOURCES_API.api, world=SOURCES_API.world)


def _schema_errors(doc: dict) -> list[str]:
    """Errors against the published CycloneDX 1.6.2 JSON schema (the CB-06 export tests' validator)."""
    from backend.tests.support.cyclonedx_schema import json_errors

    return json_errors(doc, limit=5)


def _assets(api, run_id: int) -> dict[str, dict]:
    """Remediation items (asset_key, asset_id) by the asset's location."""
    where = {a["id"]: a["location"] for a in api("GET", f"/1/cbom/sources/runs/{run_id}/assets").json()["items"]}
    return {where[i["asset_id"]]: i for i in api("GET", f"/1/cbom/sources/runs/{run_id}/remediation").json()["items"]}


def _assign(api, run_id: int, key: str, status: str) -> None:
    r = api("PUT", "/1/cbom/remediation", json={"run_id": run_id, "items": [{"asset_key": key, "status": status}]})
    assert r.status_code == 200, r.text


def _finish(engine, run_id: int) -> None:
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, run_id)
        run.status, run.finished_at = "done", dt.datetime.utcnow()
        s.add(run)
        s.commit()


def _freeze(monkeypatch, when: dt.datetime = FROZEN) -> None:
    from backend.routers import cbom_run_deliverables, cbom_sources
    from backend.utilities.integrations import oscal

    for module in (cbom_run_deliverables, cbom_sources, oscal):
        monkeypatch.setattr(module, "utcnow", lambda: when)


def _pdf_text(raw: bytes, tmp_path: Path) -> str:
    if shutil.which("pdftotext"):
        path = tmp_path / "run.pdf"
        path.write_bytes(raw)
        return subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True,
                              check=True).stdout
    from backend.tests.support.pdf_text import pdf_text

    return pdf_text(raw)


# ----------------------------------------------------------------------------- VEX endpoint (CB-22 semantics + plan)
def _keyed(entries) -> dict[tuple[str, int], dict]:
    """(finding id, asset id) -> analysis, BOM-Links compared by their asset."""
    out = {}
    for v in entries:
        for a in v.get("affects") or []:
            out[(v["id"], int(str(a["ref"]).rsplit("zs-asset-", 1)[1]))] = v["analysis"]
    return out


def test_run_vex_is_the_export_with_the_remediation_plan_overlaid(api, world):
    """CB-22 (#134) owns which analysis a finding gets; the run VEX takes the export's entries as they are and only
    overlays each asset's plan status (vex_semantics.apply_plan_status). Without a plan it equals the export."""
    from backend.utilities.cbom_sources import vex_semantics as VEX

    engine, _ = world
    _src, run = _store(api, engine, ASSETS)
    rid = run["id"]
    plain = api("GET", f"/1/cbom/sources/runs/{rid}/vex").json()
    bom = api("GET", f"/1/cbom/sources/runs/{rid}/cbom").json()
    export = _keyed(bom["vulnerabilities"])
    assert _keyed(plain["vulnerabilities"]) == export  # no plan: the export's analysis for every (finding, asset)
    assert [v["properties"] for v in plain["vulnerabilities"]] == [v["properties"] for v in bom["vulnerabilities"]]

    items = _assets(api, rid)
    cert, tls = items["/etc/ssl/pay.pem"], items["10.20.0.1:443"]
    win, kms = items["os"], items["arn:aws:kms:ap-south-1:111122223333:key/abc"]
    with Session(engine) as s:  # collected an hour before the plan says done (vex_semantics compares the two)
        row = s.get(CbomCollectedAsset, cert["asset_id"])
        row.created_at = dt.datetime.utcnow() - dt.timedelta(hours=1)
        s.add(row)
        s.commit()
    _assign(api, rid, cert["asset_key"], "done")  # marked done after this run collected it
    _assign(api, rid, win["asset_key"], "accepted_risk")
    _assign(api, rid, kms["asset_key"], "in_progress")
    r = api("GET", f"/1/cbom/sources/runs/{rid}/vex")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert r.headers["content-disposition"].endswith(f'cbom-sources-run-{rid}.vex.json"')
    vex = r.json()
    assert _schema_errors(vex) == []
    got = _keyed(vex["vulnerabilities"])
    assert set(got) == set(export)  # the same (finding, asset) pairs
    for (vid, aid), analysis in got.items():
        status = {cert["asset_id"]: "done", win["asset_id"]: "accepted_risk", kms["asset_id"]: "in_progress"}.get(aid)
        if status is None:
            assert analysis == export[(vid, aid)], (vid, aid)  # untouched
        elif status == "done":
            assert analysis["state"] == "resolved" and analysis["detail"].startswith(VEX.DETAIL_DONE)
        else:
            assert analysis["state"] == export[(vid, aid)]["state"]  # the evidence state is kept
            assert analysis["response"] == (["will_not_fix"] if status == "accepted_risk" else ["update"])
    assert got[("ZS-CBOM-PROTO_TLS10", tls["asset_id"])] == export[("ZS-CBOM-PROTO_TLS10", tls["asset_id"])]
    assert not any(v["analysis"]["state"] == "not_affected" for v in vex["vulnerabilities"])
    # an entry whose assets get different analyses is split, one entry per analysis, each with one zs:vex_basis
    tls10 = [v for v in vex["vulnerabilities"] if v["id"] == "ZS-CBOM-PROTO_TLS10"]
    assert len(tls10) == 2 and len({v["bom-ref"] for v in vex["vulnerabilities"]}) == len(vex["vulnerabilities"])
    assert all(len(VEX.props_of(v).get("zs:vex_basis") or []) == 1 for v in vex["vulnerabilities"])
    # affects are BOM-Links into the run CBOM
    refs = {c["bom-ref"] for c in bom["components"]}
    prefix = f"urn:cdx:{bom['serialNumber'].removeprefix('urn:uuid:')}/1#"
    assert all(a["ref"].startswith(prefix) and a["ref"][len(prefix):] in refs
               for v in vex["vulnerabilities"] for a in v["affects"])
    props = {p["name"]: p["value"] for p in vex["metadata"]["properties"]}
    assert props["zs:vex_rules"] == f"{VEX.VEX_RULES}+{RD.PLAN_OVERLAY}" and props["zs:bom_serial"] == bom["serialNumber"]
    assert "zs:as_of" in props and "still" in props["zs:as_of"]  # the run is still collecting
    assert sum(int(v) for k, v in props.items() if k.startswith("zs:pairs_")) == len(got)


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
    assert sig["alg"] == "HMAC-SHA256" and sig["key_id"] == "certin-hmac-1"  # the code lane's bom_signature key and fields
    assert sig["digest"] == hashlib.sha256(raw).hexdigest() and sig["bytes"] == len(raw)
    mac = base64.b64decode(sig["signature_b64"])
    assert hmac.compare_digest(hmac.new(secret, raw, hashlib.sha256).digest(), mac)  # raw file bytes
    assert sig['canonicalization'] == 'none (the raw file bytes)' and json.loads(raw)['bomFormat'] == 'CycloneDX'
    tampered = bytearray(raw)
    at = raw.index(b'"zs:run_id"')  # flip one byte inside a value
    tampered[at + 1] = ord("Z")
    assert not hmac.compare_digest(hmac.new(secret, bytes(tampered), hashlib.sha256).digest(), mac)
    last = bytearray(raw)
    last[-1] ^= 1
    assert not hmac.compare_digest(hmac.new(secret, bytes(last), hashlib.sha256).digest(), mac)
    assert sig["serialNumber"] == json.loads(raw)["serialNumber"] and "as_of" in sig
    assert "XML form is not covered" in sig["scope"] and f"/runs/{rid}/signature/verify" in sig["scope"]
    # the customer's check: the key stays on the server, so the verify route answers for the downloaded file
    verify = f"/1/cbom/sources/runs/{rid}/signature/verify"
    ok = api("POST", verify, content=raw, headers={"X-ZS-Signature-B64": sig["signature_b64"]})
    assert ok.status_code == 200, ok.text
    assert ok.json()["valid"] is True
    assert (ok.json()["signature_match"], ok.json()["digest_match"]) == (True, True)
    assert ok.json()["digest"] == sig["digest"] and ok.json()["bytes"] == len(raw)
    current = api("POST", verify, content=raw).json()  # no signature sent: against the run's current CBOM
    assert (current["valid"], current["digest_match"], current["compared_with"]) == (True, True, "the run's current CBOM JSON")
    for bad in (bytes(tampered), bytes(last)):
        out = api("POST", verify, content=bad, headers={"X-ZS-Signature-B64": sig["signature_b64"]}).json()
        assert (out["valid"], out["signature_match"], out["digest_match"]) == (False, False, False)
        assert api("POST", verify, content=bad).json()["valid"] is False
    wrong = api("POST", verify, content=raw, headers={"X-ZS-Signature-B64": "bm90IGl0"}).json()
    assert (wrong["valid"], wrong["digest_match"]) == (False, True)  # the file is the run's, the signature is not
    assert api("POST", verify, content=b"").status_code == 400
    assert api("POST", f"/2/cbom/sources/runs/{rid}/signature/verify", "carol", content=raw).status_code == 404


def test_run_cbom_bytes_are_inventorys_writer_with_a_stable_timestamp(api, world):
    """The run CBOM is #103's streamed document (inventory.write_cyclonedx) byte for byte except metadata.timestamp,
    which is the run's last data change instead of the request time: two exports at different times are equal."""
    engine, _ = world
    _src, run = _store(api, engine, ASSETS)
    with Session(engine) as s:
        row = s.get(CbomCollectionRun, run["id"])
        later = FROZEN + dt.timedelta(hours=3)
        ours, theirs, again = io.BytesIO(), io.BytesIO(), io.BytesIO()
        RD.write_run_cbom(s, row, FROZEN, "json", ours)
        RD.write_run_cbom(s, row, later, "json", again)
        INV.write_cyclonedx(s, row, FROZEN, "json", theirs)
        stamp = RD.iso_z(RD.stamp(s, row, FROZEN))  # active run: its newest asset's time
    assert ours.getvalue() == again.getvalue()
    assert ours.getvalue() == theirs.getvalue().replace(b'"timestamp":"2026-11-14T09:30:00Z"',
                                                        f'"timestamp":"{stamp}"'.encode(), 1)
    assert json.loads(ours.getvalue())["metadata"]["timestamp"] == stamp


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
    _finish(engine, rid)  # a finished run: every file is the same bytes on every download, whenever it is asked
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
        if entry["name"] == "oscal-assessment-results.json":  # the route stamps last-modified with the request time
            assert entry["endpoint_same_bytes"] is False
            mine, theirs = json.loads(body), json.loads(served.content)
            assert mine["assessment-results"]["metadata"].pop("last-modified") == manifest["generated_at"]
            theirs["assessment-results"]["metadata"].pop("last-modified")
            assert mine == theirs
            continue
        assert entry["endpoint_same_bytes"] is True
        assert hashlib.sha256(served.content).hexdigest() == entry["sha256"], entry["name"]
    assert manifest["run"]["id"] == rid and manifest["run"]["status"] == "done" and not manifest["run"]["active"]
    assert manifest["run"]["sources"][0]["name"] == "linux-dc"
    assert manifest["inputs"]["bom_serial"] == json.loads(zf.read("bom.cdx.json"))["serialNumber"]
    assert manifest["inputs"]["export_cap"] == INV.EXPORT_CAP and manifest["inputs"]["truncated"] is False
    sig = json.loads(zf.read("bom_signature.json"))
    secret = (os.environ.get("CERTIN_HMAC_SECRET") or os.environ["JWT_SECRET_KEY"]).encode()
    mac = hmac.new(secret, zf.read("bom.cdx.json"), hashlib.sha256).digest()
    assert hmac.compare_digest(base64.b64decode(sig["signature_b64"]), mac)  # the pack's signature verifies its JSON
    assert manifest["signature"]["digest"] == hashlib.sha256(zf.read("bom.cdx.json")).hexdigest()
    # every time in it is the run's: the zip entries, the manifest, the signature, the PDF
    with Session(engine) as s:
        finished = RD.iso_z(RD.stamp(s, s.get(CbomCollectionRun, rid), FROZEN))
    assert manifest["generated_at"] == sig["signed_at"] == finished
    y, mo, d, h, mi, sec = (int(x) for x in finished[:19].replace("T", "-").replace(":", "-").split("-"))
    assert {i.date_time for i in zf.infolist()} == {(y, mo, d, h, mi, sec - sec % 2)}  # zip keeps even seconds
    # a later download (three hours on) is the same bytes
    _freeze(monkeypatch, FROZEN + dt.timedelta(hours=3))
    assert api("GET", f"/1/cbom/sources/runs/{rid}/evidence-pack").content == r.content


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


def test_empty_run(api, world, tmp_path, monkeypatch):
    engine, _ = world
    _src, run, _claim, _hdr = _collect_job(api, engine)
    rid = run["id"]
    vex = api("GET", f"/1/cbom/sources/runs/{rid}/vex").json()
    assert vex["vulnerabilities"] == [] and _schema_errors(vex) == []
    # an active run with nothing stored yet is stamped with the run's own time, not the request's (CI run on
    # 715e00f: the signature and the download a second apart differed)
    _freeze(monkeypatch, FROZEN)
    sig = api("GET", f"/1/cbom/sources/runs/{rid}/signature").json()
    _freeze(monkeypatch, FROZEN + dt.timedelta(seconds=7))
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


# ----------------------------------------------------------------------------- realistic sizes (review 5902588239)
def _realistic_assets(n: int) -> list[dict]:
    """``n`` assets cycling through the long-finding kinds: a weak expired certificate (~230-character finding), an
    end-of-life OpenSSL package (~320) and a Windows host (~380)."""
    out = []
    for i in range(n):
        kind = i % 3
        if kind == 0:
            out.append({**ASSETS[0], "location": f"/etc/ssl/pay-{i}.pem", "name": f"pay-{i}"})
        elif kind == 1:
            out.append({**ASSETS[3], "target": f"10.20.{i // 250}.{i % 250 + 1}", "location": f"package:openssl#{i}"})
        else:
            out.append({**ASSETS[4], "target": f"10.30.{i // 250}.{i % 250 + 1}", "location": f"os#{i}"})
    return out


def _finding_rows(n: int) -> list[dict]:
    from backend.utilities.cbom_sources.classify import classify

    texts = []
    for a in _realistic_assets(3):
        v = classify(a["type"], a.get("algorithm"), a.get("key_size"), a.get("protocol"), a["facts"], FROZEN)
        texts.append((v["impact"], v["finding"], a["type"]))
    assert all(len(t[1]) >= 200 for t in texts), [len(t[1]) for t in texts]  # the long sentences that broke it
    return [{"ref": f"zs-asset-{i}", "impact": texts[i % 3][0], "name": f"asset-{i}", "type": texts[i % 3][2],
             "location": f"arn:aws:kms:ap-south-1:111122223333:key/{i:032x}/" + "deep/path/" * 12,
             "source": "linux-dc", "finding": texts[i % 3][1]} for i in range(n)]


@pytest.mark.parametrize("n", [40, 200, 500])
def test_pdf_builds_with_many_long_findings(n):
    """[blocker] 18 rows of 5-6-line findings made one unsplittable catalog panel taller than the page
    (LayoutError, HTTP 500 for report.pdf and the evidence pack once a run had about 12 findings)."""
    from backend.utilities.pdf.cbom_run_pdf import build_run_pdf
    from backend.tests.support.pdf_text import pdf_text

    head = {"serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", "metadata": {"properties": []}}
    posture = {"assets": n, "impacts": {"Critical": n // 3, "High": n - n // 3, "Medium": 0, "Low": 0},
               "pqc_readiness_pct": 12.5, "pqc_classes": {}, "exposure": {}, "mosca": {}, "top_risks": [],
               "compliance": []}
    raw = build_run_pdf(run={"id": 9, "status": "done", "created_at": "2026-11-14T09:00:00Z",
                             "finished_at": "2026-11-14T09:30:00Z", "last_updated": "2026-11-14T09:30:00Z"},
                        sources=[{"name": "linux-dc"}], posture=posture,
                        heatmap={"rows": [], "columns": [], "cells": [], "certificates": []}, head=head,
                        findings=_finding_rows(n), vex_states={}, provenance=[], at=FROZEN, as_of_note=None,
                        findings_cap=RD.PDF_FINDINGS_CAP, export_cap=INV.EXPORT_CAP, cbom_sha256="ab" * 32)
    text = pdf_text(raw)
    assert raw.startswith(b"%PDF") and "12.5%" in text and "\u2026" in text  # cut, with an ellipsis


def test_report_and_pack_of_a_run_with_40_realistic_findings(api, world, tmp_path):
    engine, _ = world
    _src, run = _store(api, engine, _realistic_assets(40))
    rid = run["id"]
    with Session(engine) as s:  # a failed job's reason is shown in the provenance table
        from backend.new_models import CbomCollectionJob

        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == rid)).first()
        job.error = "every target refused the connection (10.20.0.0/29: 6 of 6)"
        s.add(job)
        s.commit()
    pdf = api("GET", f"/1/cbom/sources/runs/{rid}/report.pdf")
    assert pdf.status_code == 200, pdf.text
    text = " ".join(_pdf_text(pdf.content, tmp_path).split())
    assert "40 issues" in text and "refused" in text and "6 of 6)" in text  # the job error, in the provenance table
    pack = api("GET", f"/1/cbom/sources/runs/{rid}/evidence-pack")
    assert pack.status_code == 200, pack.text
    assert zipfile.ZipFile(io.BytesIO(pack.content)).read("report.pdf").startswith(b"%PDF")


def test_a_20k_asset_run_builds_its_pdf_and_states_cut_vex_entries(api, world, monkeypatch):
    """The 20k-run path (R-qa run #6): the PDF builds at the 500-row cap, and a finding on more assets than the
    export lists per entry (5,000) says so in the run VEX with its true total (the export's CB-22 properties)."""
    from backend.routers import cbom_run_deliverables as ROUTE
    from backend.utilities.cbom_sources.classify import classify

    engine, _ = world
    _src, run, claim, _hdr = _collect_job(api, engine)
    job = claim["job"]
    tls = {"type": "tls_endpoint", "facts": {"protocols": ["TLSv1.2", "TLSv1.3"], "group": "x25519"}}
    kinds = [(tls, 6_000), (ASSETS[0], 6_000), (ASSETS[3], 4_000), (ASSETS[4], 4_000)]
    rows, i = [], 0
    for proto, count in kinds:
        v = classify(proto["type"], proto.get("algorithm"), proto.get("key_size"), proto.get("protocol"),
                     proto["facts"], FROZEN)
        for _ in range(count):
            rows.append({"team_id": 1, "run_id": run["id"], "job_id": job["id"], "source_id": job.get("source_id"),
                         "attempt": 1, "asset_key": f"{i:064x}", "asset_type": proto["type"],
                         "cdx_type": v["cdx_type"], "target": f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}",
                         "location": f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}:443#{i}",
                         "name": proto.get("name"), "algorithm": proto.get("algorithm"),
                         "key_size": proto.get("key_size"), "protocol": proto.get("protocol"),
                         "quantum_vulnerable": v["quantum_vulnerable"], "impact": v["impact"],
                         "finding_codes": v["finding_codes"], "finding": v["finding"], "facts": proto["facts"],
                         "created_at": FROZEN})
            i += 1
    assert "NO_PQ_KEX" in rows[0]["finding_codes"]
    with Session(engine) as s:
        for start in range(0, len(rows), 2_000):
            s.execute(CbomCollectedAsset.__table__.insert(), rows[start:start + 2_000])
        s.commit()
    monkeypatch.setattr(ROUTE.EXPORT_SLOTS, "LOCK_DIR", str(Path(os.environ.get("TMPDIR", "/tmp")) / "w7-slots"))
    pdf = ROUTE._report(engine, 1, run["id"])
    assert pdf.startswith(b"%PDF")
    vex = json.loads(ROUTE._vex_doc(engine, 1, run["id"]))
    entry = next(v for v in vex["vulnerabilities"] if v["id"] == "ZS-CBOM-NO_PQ_KEX")
    props = {p["name"]: p["value"] for p in entry["properties"]}
    # the export's cut (CB-22: zs:affected_truncated with the true count) travels into the run VEX unchanged
    assert len(entry["affects"]) == 5_000 and props["zs:affected_truncated"] == "true"
    assert props["zs:affected_total"] == "6000"
