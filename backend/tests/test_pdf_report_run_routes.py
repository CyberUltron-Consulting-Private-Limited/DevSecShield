"""R4 run report.pdf options and R5 run evidence pack logo (see test_pdf_report_routes.py for R1-R3)."""
from __future__ import annotations

import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_posture import ASSETS, _store  # noqa: E402
import test_cbom_sources_api as SOURCES_API  # noqa: E402

from backend.tests.test_cbom_run_deliverables import _finish, _freeze  # noqa: E402
from backend.tests.test_pdf_report_routes import NAVY, _png, clear_logo, set_logo  # noqa: E402

globals().update(api=SOURCES_API.api, world=SOURCES_API.world)


@pytest.fixture()
def run_env(api, world):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS)
    yield api, engine, run["id"]
    clear_logo(engine, 1)


def test_run_report_takes_run_options_and_refuses_code_lane_ones(run_env):
    call, _engine_, rid = run_env
    ok = call("GET", f"/1/cbom/sources/runs/{rid}/report.pdf?preset=executive&prepared_for=Acme&label=internal")
    assert ok.status_code == 200, ok.text
    assert ok.headers["X-Report-Logo"] == "none" and "/" in ok.headers["X-Report-Findings"]
    bad = call("GET", f"/1/cbom/sources/runs/{rid}/report.pdf?statuses=fixed")
    assert bad.status_code == 422 and bad.json()["detail"].startswith("statuses: ")


def test_run_report_post_takes_the_options_as_json(run_env, monkeypatch):
    call, engine, rid = run_env
    _finish(engine, rid)
    _freeze(monkeypatch)
    url = f"/1/cbom/sources/runs/{rid}/report.pdf"
    get = call("GET", url + "?preset=executive&prepared_for=Acme&label=internal")
    post = call("POST", url, json={"preset": "executive", "prepared_for": "Acme", "label": "internal"})
    assert post.status_code == 200, post.text
    assert post.content == get.content  # a finished run's report is byte-stable: the same PDF either way
    for name in ("Content-Disposition", "X-Report-Findings", "X-Report-Logo", "Cache-Control"):
        assert post.headers[name] == get.headers[name], name
    assert call("POST", url, json={}).content == call("GET", url).content  # no option: today's report
    json_type = {"Content-Type": "application/json"}
    assert call("POST", url, content=b"{}").status_code == 415  # no Content-Type
    assert call("POST", url, content=b"{}", headers={"Content-Type": "text/plain"}).status_code == 415
    deep = call("POST", url, content=b'{"title": ' + b"[" * 5000 + b"]" * 5000 + b"}", headers=json_type)
    assert deep.status_code == 422 and deep.json()["detail"].startswith("body: is nested too deeply"), deep.text
    dup = call("POST", url, content=b'{"title": "x", "title": null}', headers=json_type)
    assert dup.status_code == 422 and dup.json()["detail"] == "title: was given more than once"
    bad = call("POST", url, json={"statuses": "fixed"})
    assert bad.status_code == 422 and bad.json()["detail"].startswith("statuses: ")
    assert call("POST", url, json={"hide_evidence": True}).json()["detail"].startswith("hide_evidence: ")
    assert call("POST", url + "?title=x", json={}).json()["detail"].startswith("title: send report options")
    hindi = call("POST", url, json={"title": "प्रबंधन क्षेत्र", "prepared_for": "ПАО Сбербанк"})
    assert hindi.status_code == 200 and b"NotoSansDevanagari-Bold" in hindi.content
    assert call("POST", "/1/cbom/sources/runs/999999/report.pdf", json={}).status_code == 404
    assert call("POST", url, who=None, json={}).status_code == 401


def test_a_large_run_report_uses_the_cbom_pool_not_the_scan_pdf_pool(run_env, monkeypatch, tmp_path):
    """Scan PDFs filling their own slots never make a run report wait; CBOM exports filling theirs do, with the CBOM
    words."""
    call, _engine_, rid = run_env
    from backend.utilities.cbom_sources import export_slots as ES

    monkeypatch.setattr(ES, "LOCK_DIR", str(tmp_path))
    monkeypatch.setattr(ES, "SLOTS", 1)
    monkeypatch.setattr(ES, "PDF_SLOTS", 1)
    monkeypatch.setattr(ES, "LARGE_ASSETS", 1)  # this run counts as large
    url = f"/1/cbom/sources/runs/{rid}/report.pdf"
    with ES.pdf_slot():  # every scan PDF slot taken
        assert call("POST", url, json={"label": "internal"}).status_code == 200
        assert call("GET", f"/1/cbom/sources/runs/{rid}/cbom").status_code == 200
    with ES.slot():  # every CBOM slot taken
        for method, body in (("GET", None), ("POST", {})):
            busy = call(method, url, json=body)
            assert busy.status_code == 429, busy.text
            assert busy.json()["detail"] == ES.CBOM_BUSY and "scan PDF" not in busy.json()["detail"]
            assert busy.headers["Retry-After"] == str(ES.RETRY_AFTER_S)
        assert call("GET", f"/1/cbom/sources/runs/{rid}/cbom").json()["detail"] == ES.CBOM_BUSY


def test_default_run_report_is_unchanged_without_a_logo(run_env, monkeypatch):
    call, engine, rid = run_env
    _finish(engine, rid)
    _freeze(monkeypatch)
    first = call("GET", f"/1/cbom/sources/runs/{rid}/report.pdf").content
    assert call("GET", f"/1/cbom/sources/runs/{rid}/report.pdf?label=confidential").content == first


def test_run_pack_records_the_logo_only_when_set(run_env, monkeypatch):
    call, engine, rid = run_env
    _finish(engine, rid)
    _freeze(monkeypatch)
    url = f"/1/cbom/sources/runs/{rid}/evidence-pack"
    assert call("GET", url + "?label=internal").status_code == 422

    plain = zipfile.ZipFile(io.BytesIO(call("GET", url).content))
    manifest = json.loads(plain.read("manifest.json"))
    assert "logo_sha256" not in manifest["inputs"] and "logo" not in manifest["endpoint_note"]

    sha_a = set_logo(engine, 1, _png(color=NAVY))
    pack = call("GET", url)
    assert pack.headers["X-Report-Logo"] == "applied"
    zf = zipfile.ZipFile(io.BytesIO(pack.content))
    manifest = json.loads(zf.read("manifest.json"))
    assert manifest["inputs"]["logo_sha256"] == sha_a
    assert "same team report logo" in manifest["endpoint_note"]
    entry = next(f for f in manifest["files"] if f["name"] == "report.pdf")
    served = call("GET", entry["endpoint"])
    assert hashlib.sha256(served.content).hexdigest() == entry["sha256"]  # same logo: same bytes
    set_logo(engine, 1, _png(color=(200, 30, 30)))
    served = call("GET", entry["endpoint"])
    assert hashlib.sha256(served.content).hexdigest() != entry["sha256"]  # the note's condition no longer holds


def _run_pdf(ctx, top_risks, cap=None):
    import datetime as dt

    from backend.tests.support.pdf_text import pdf_text
    from backend.utilities.cbom_sources import inventory as INV
    from backend.utilities.cbom_sources import run_deliverables as RD
    from backend.utilities.pdf.cbom_run_pdf import build_run_pdf

    findings = [{"ref": f"zs-asset-{i}", "impact": impact, "name": f"asset-{i}", "type": "certificate",
                 "location": f"/etc/k{i}", "source": "linux-dc", "finding": f"{impact} finding {i}"}
                for i, impact in enumerate(["Critical", "High", "Low"])]
    posture = {"assets": 3, "impacts": {"Critical": 1, "High": 1, "Medium": 0, "Low": 1}, "pqc_readiness_pct": 50.0,
               "pqc_classes": {}, "exposure": {}, "mosca": {}, "top_risks": top_risks, "compliance": []}
    raw = build_run_pdf(run={"id": 9, "status": "done", "created_at": "2026-11-14T09:00:00Z",
                             "finished_at": "2026-11-14T09:30:00Z", "last_updated": "2026-11-14T09:30:00Z"},
                        sources=[{"name": "linux-dc"}], posture=posture,
                        heatmap={"rows": [], "columns": [], "cells": [], "certificates": []},
                        head={"serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                              "metadata": {"properties": []}},
                        findings=findings, vex_states={}, provenance=[], at=dt.datetime(2026, 11, 14, 9, 30),
                        as_of_note=None, findings_cap=cap or RD.PDF_FINDINGS_CAP, export_cap=INV.EXPORT_CAP,
                        cbom_sha256="ab" * 32, ctx=ctx)
    return " ".join(pdf_text(raw).split())


@pytest.mark.parametrize("preset", ["executive", "full"])
def test_a_severity_filtered_run_report_never_names_an_excluded_top_risk(preset):
    """PR #472 review: the Top risks table listed a Critical finding in a Low-only report."""
    from backend.utilities.pdf.report_context import ReportContext
    from backend.utilities.pdf.report_options import parse_report_options

    risks = [{"score": 9.5, "impact": "Critical", "finding": "CRIT-TOP-RISK-CANARY", "location": "/etc/k0",
              "exposure": "internet", "criticality": "high"},
             {"score": 2.0, "impact": "Low", "finding": "LOW-TOP-RISK-KEPT", "location": "/etc/k2",
              "exposure": "internal", "criticality": "low"}]
    options = parse_report_options([("preset", preset), ("severities", "low")], "run")
    text = _run_pdf(ReportContext(options=options), risks)
    assert "CRIT-TOP-RISK-CANARY" not in text and "Critical finding 0" not in text
    assert "LOW-TOP-RISK-KEPT" in text and "1 more top risk(s) are outside the selected severities" in text
    assert "Summary of this run" in text and "Summary of this scan" not in text
    only_critical = parse_report_options([("severities", "medium")], "run")
    text = _run_pdf(ReportContext(options=only_critical), risks)
    assert "No top risk matches the selected severities (2 outside them)" in text and "in the full run" in text
    unfiltered = _run_pdf(None, risks)
    assert "CRIT-TOP-RISK-CANARY" in unfiltered  # unfiltered, the top risk is still there


def test_the_findings_cap_sentence_is_true_for_filtered_and_unfiltered_runs():
    """PR #472 review: a filtered run whose matches fit under the cap said "lists the first N of M findings"."""
    from backend.utilities.pdf.report_context import ReportContext
    from backend.utilities.pdf.report_options import parse_report_options

    ctx = ReportContext(options=parse_report_options([("severities", "critical")], "run"))
    text = _run_pdf(ctx, [], cap=2)
    assert "Findings cap" not in text and "Showing 1 of 3 findings" in text
    assert (ctx.shown, ctx.total) == (1, 3)
    plain = ReportContext()
    text = _run_pdf(plain, [], cap=2)
    assert "lists the first 2 of 3 findings" in text
    assert (plain.shown, plain.total) == (2, 3)  # X-Report-Findings counts what the PDF draws


# ----------------------------------------------------------------------------- staging QA 23 Nov 2026
def _private(r, what):
    assert r.headers.get("Cache-Control") == "no-store", (what, dict(r.headers))
    assert r.headers.get("X-Content-Type-Options") == "nosniff", (what, dict(r.headers))


def _export_lines(out: str) -> list[str]:
    return [line for line in out.splitlines() if "pdf report export" in line]


def test_the_default_run_report_counts_its_findings_and_keeps_its_bytes(run_env, monkeypatch, capsys):
    """QA: the default run report (no option, no logo) answered X-Report-Findings 0/0 and logged shown=0 total=0
    while the PDF held 5 findings: the byte-identity path built with no context, so nothing was counted. The counts
    now come from that build; its bytes are what the old ctx=None build gives."""
    call, engine, rid = run_env
    _finish(engine, rid)
    _freeze(monkeypatch)
    url = f"/1/cbom/sources/runs/{rid}/report.pdf"
    capsys.readouterr()
    default = call("GET", url)
    assert default.status_code == 200, default.text
    shown, total = map(int, default.headers["X-Report-Findings"].split("/"))
    assert shown == total > 0, default.headers["X-Report-Findings"]
    (line,) = _export_lines(capsys.readouterr().out)
    assert f"shown={shown} total={total}" in line and "outcome=ok" in line
    # the options path counts the same rows
    labelled = call("POST", url, json={"label": "internal"})
    assert labelled.headers["X-Report-Findings"] == default.headers["X-Report-Findings"]
    assert call("POST", url, json={}).headers["X-Report-Findings"] == default.headers["X-Report-Findings"]

    # byte identity: rebuild with the old fast path (ctx=None for default options and no logo) and compare
    from backend.routers import cbom_run_deliverables as R

    real = R.build_run_pdf

    def dev_behaviour(**kwargs):
        ctx = kwargs["ctx"]
        if ctx is not None and ctx.options.is_default and not ctx.branding.applied:
            kwargs["ctx"] = None
        return real(**kwargs)

    monkeypatch.setattr(R, "build_run_pdf", dev_behaviour)
    assert call("GET", url).content == default.content
    # the evidence pack's report.pdf is built the same way: same bytes as the download
    monkeypatch.setattr(R, "build_run_pdf", real)
    pack = zipfile.ZipFile(io.BytesIO(call("GET", f"/1/cbom/sources/runs/{rid}/evidence-pack").content))
    assert pack.read("report.pdf") == default.content


def test_run_report_and_pack_are_private_and_a_busy_host_says_so(run_env, monkeypatch, tmp_path):
    call, _engine, rid = run_env
    url = f"/1/cbom/sources/runs/{rid}/report.pdf"
    _private(call("GET", url), "R4 GET")
    _private(call("POST", url, json={"label": "internal"}), "R4 POST")
    pack = call("GET", f"/1/cbom/sources/runs/{rid}/evidence-pack")
    _private(pack, "R5")
    assert pack.headers["Content-Disposition"] == f'attachment; filename="cbom-sources-run-{rid}-evidence-pack.zip"'
    assert pack.headers["Content-Length"] == str(len(pack.content)) and pack.headers["X-Report-Logo"] == "none"
    from backend.utilities.cbom_sources import export_slots as ES

    monkeypatch.setattr(ES, "LOCK_DIR", str(tmp_path))
    monkeypatch.setattr(ES, "SLOTS", 1)
    monkeypatch.setattr(ES, "LARGE_ASSETS", 1)
    with ES.slot():
        for r in (call("GET", url), call("POST", url, json={}), call("GET", f"/1/cbom/sources/runs/{rid}/evidence-pack"),
                  call("GET", f"/1/cbom/sources/runs/{rid}/cbom")):
            assert r.status_code == 429 and r.json()["detail"] == ES.CBOM_BUSY, r.text
            assert r.headers["X-Export-Busy"] == "cbom"
            _private(r, "CBOM slot 429")


def test_run_report_and_pack_log_every_outcome(run_env, monkeypatch, capsys, tmp_path):
    call, _engine, rid = run_env
    url = f"/1/cbom/sources/runs/{rid}/report.pdf"
    capsys.readouterr()
    assert call("GET", f"/1/cbom/sources/runs/{rid}/evidence-pack").status_code == 200
    (line,) = _export_lines(capsys.readouterr().out)
    assert "family=run_pack" in line and "outcome=ok" in line
    assert call("GET", url + "?statuses=fixed").status_code == 422
    (line,) = _export_lines(capsys.readouterr().out)
    assert "family=run" in line and "outcome=refused" in line and "status=422" in line
    assert call("GET", "/1/cbom/sources/runs/999999/report.pdf").status_code == 404
    assert "outcome=refused status=404" in _export_lines(capsys.readouterr().out)[0]
    from backend.utilities.cbom_sources import export_slots as ES

    monkeypatch.setattr(ES, "LOCK_DIR", str(tmp_path))
    monkeypatch.setattr(ES, "SLOTS", 1)
    monkeypatch.setattr(ES, "LARGE_ASSETS", 1)
    with ES.slot():
        assert call("POST", url, json={"label": "internal"}).status_code == 429
        (line,) = _export_lines(capsys.readouterr().out)
        assert "outcome=busy" in line and "status=429" in line and "label=internal" in line
        assert call("GET", f"/1/cbom/sources/runs/{rid}/evidence-pack").status_code == 429
        (line,) = _export_lines(capsys.readouterr().out)
        assert "family=run_pack" in line and "outcome=busy" in line and "status=429" in line
    monkeypatch.setattr(ES, "LARGE_ASSETS", 10**9)
    from backend.routers import cbom_run_deliverables as R

    real = R.build_run_pdf

    def boom(*_a, **_k):
        raise RuntimeError("renderer failed")

    monkeypatch.setattr(R, "build_run_pdf", boom)
    assert call("GET", url).status_code == 500
    (line,) = _export_lines(capsys.readouterr().out)
    assert "outcome=error" in line and "status=500" in line and "renderer failed" not in line
    monkeypatch.setattr(R, "build_run_pdf", real)

    async def gone(_request) -> bool:  # the client disconnected while the report was built
        return True

    monkeypatch.setattr("starlette.requests.Request.is_disconnected", gone)
    assert call("GET", url).status_code == 200
    (line,) = _export_lines(capsys.readouterr().out)
    assert "family=run" in line and "outcome=client_gone" in line
