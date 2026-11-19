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
