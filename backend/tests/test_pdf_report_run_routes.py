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
