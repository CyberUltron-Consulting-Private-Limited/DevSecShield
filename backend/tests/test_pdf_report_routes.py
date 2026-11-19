"""HTTP contract of the PDF report options and the team report logo on every report route.

R1 ``GET /{team}/{type}/scan/{id}/export``      options (scan family), logo, status join, export slot, headers, log
R2 ``GET /{team}/{type}/scan/{id}/evidence-pack`` options refused (422), logo in report.pdf, no temp file left
R3 ``GET /{team}/cbom/deliverables/{slug}``       prepared_for + label only, logo, X-Cbom-Logo-Sha256 when applied
R4 ``GET /{team}/cbom/sources/runs/{id}/report.pdf`` run options, logo
R5 ``GET /{team}/cbom/sources/runs/{id}/evidence-pack`` options refused, manifest ``inputs.logo_sha256`` only when set
and the CORS ``expose_headers`` list the browser needs to read these headers.
"""
from __future__ import annotations

import io
import sys
import tempfile
import zipfile
from pathlib import Path

import pytest
from PIL import Image
from sqlmodel import Session

sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.tests import test_pdf_export_route as EXPORT  # noqa: E402
from backend.utilities.db import finding_rows  # noqa: E402
from backend.utilities.team import logo_image  # noqa: E402
from backend.utilities.team.branding import delete_logo, upsert_logo  # noqa: E402

api = EXPORT.api  # the hermetic SQLite + TestClient fixture of the export route tests

AUTH = {"Authorization": "Bearer test"}
NAVY = (12, 30, 70)


# ----------------------------------------------------------------------------- helpers
def _png(size=(240, 80), color=NAVY, mode="RGB") -> bytes:
    out = io.BytesIO()
    Image.new(mode, size, color).save(out, format="PNG")
    return out.getvalue()


def set_logo(engine, team_id: int, raw: bytes | None = None) -> str:
    logo = logo_image.normalize_logo(raw or _png(), "image/png")
    with Session(engine) as session:
        meta = upsert_logo(session, team_id, logo, user_id=None)
        session.commit()
    return meta["sha256"]


def clear_logo(engine, team_id: int) -> None:
    with Session(engine) as session:
        delete_logo(session, team_id)
        session.commit()


def images(pdf: bytes) -> int:
    return pdf.count(b"/Subtype /Image")


def _engine():
    from backend.routers import scans

    return scans.get_db()  # the fixture's engine (monkeypatched)


def export(http, ids, scan_type="sast", query: str = ""):
    url = f"/{ids['team_id']}/{scan_type}/scan/{ids['scan_ids'][scan_type]}/export"
    return http.get(url + (f"?{query}" if query else ""), headers=AUTH)


def three_findings(ids) -> int:
    """Give the stored SAST scan three findings (Critical, High, Low); returns the row count."""
    import copy

    from backend.new_models import Scan

    payload = EXPORT._worker_persist_payload("sast")
    base = payload["results"][0]["vulnerabilities"][0]
    payload["results"][0]["vulnerabilities"] = [
        {**copy.deepcopy(base), "title": f"Finding {impact}", "impact": impact} for impact in ("Critical", "High", "Low")
    ]
    with Session(_engine()) as session:
        scan = session.get(Scan, ids["scan_ids"]["sast"])
        scan.scan_data = payload
        session.add(scan)
        session.commit()
    return 3


# ----------------------------------------------------------------------------- R1: scan export
def test_default_export_has_report_headers_and_no_logo(api):
    http, ids = api
    total = three_findings(ids)
    r = export(http, ids)
    assert r.status_code == 200, r.text
    assert r.headers["X-Report-Findings"] == f"{total}/{total}"
    assert r.headers["X-Report-Logo"] == "none"
    sast_id = ids["scan_ids"]["sast"]
    assert r.headers["Content-Disposition"] == f'attachment; filename="sast-scan-{sast_id}-report.pdf"'


@pytest.mark.parametrize("query, field", [
    ("preset=board", "preset"),
    ("label=secret", "label"),
    ("severities=urgent", "severities"),
    ("statuses=open", "statuses"),
    ("sections=", "sections"),
    ("hide_evidence=yes", "hide_evidence"),
    ("preset=full&preset=executive", "preset"),
    ("prepared_for=" + "A" * 121, "prepared_for"),
])
def test_bad_options_are_422_naming_the_parameter(api, query, field):
    http, ids = api
    r = export(http, ids, query=query)
    assert r.status_code == 422, r.text
    assert r.json()["detail"].startswith(f"{field}: ")


def test_unrelated_query_parameters_are_ignored(api):
    http, ids = api
    assert export(http, ids, query="utm_source=mail").status_code == 200


def test_a_severity_filter_shows_fewer_rows_and_says_so(api):
    http, ids = api
    three_findings(ids)
    r = export(http, ids, query="severities=critical")
    assert r.status_code == 200, r.text
    assert r.headers["X-Report-Findings"] == "1/3"
    r = export(http, ids, query="severities=critical,high,medium,low,other")
    assert r.headers["X-Report-Findings"] == "3/3"  # every bucket chosen is no filter


def test_the_team_logo_is_drawn_and_reported(api):
    http, ids = api
    engine = _engine()
    plain = export(http, ids)
    set_logo(engine, ids["team_id"])
    branded = export(http, ids)
    assert branded.status_code == 200 and branded.headers["X-Report-Logo"] == "applied"
    assert images(branded.content) > images(plain.content)
    clear_logo(engine, ids["team_id"])
    again = export(http, ids)
    assert again.headers["X-Report-Logo"] == "none" and images(again.content) == images(plain.content)


def test_unreadable_logo_bytes_skip_the_logo_not_the_report(api):
    http, ids = api
    engine = _engine()
    set_logo(engine, ids["team_id"])
    from sqlalchemy import update

    from backend.branding_models import TeamBranding

    with Session(engine) as session:
        session.execute(update(TeamBranding).where(TeamBranding.team_id == ids["team_id"]).values(logo_png=b"junk"))
        session.commit()
    r = export(http, ids)
    assert r.status_code == 200 and r.headers["X-Report-Logo"] == "skipped"


def test_status_filter_reads_statuses_only_when_asked(api, monkeypatch):
    http, ids = api
    total = three_findings(ids)
    calls = []

    def fake(scan_id, scan_type, raw, **_k):
        calls.append(scan_id)
        rows = finding_rows.mongo_rows(scan_type, raw)
        return ["fixed"] + ["not_started"] * (len(rows) - 1)

    monkeypatch.setattr("backend.routers.scans.read_statuses", fake)
    assert export(http, ids).status_code == 200 and calls == []
    r = export(http, ids, query="statuses=not_started,in_progress")
    assert r.status_code == 200, r.text
    assert calls == [ids["scan_ids"]["sast"]]
    assert r.headers["X-Report-Findings"] == f"{total - 1}/{total}"


def test_status_join_failures_answer_409_and_503(api, monkeypatch):
    http, ids = api

    def unavailable(*_a, **_k):
        raise finding_rows.StatusesUnavailable("rows differ")

    def down(*_a, **_k):
        raise finding_rows.StatusStoreDown("ServerSelectionTimeoutError")

    monkeypatch.setattr("backend.routers.scans.read_statuses", unavailable)
    r = export(http, ids, query="statuses=fixed")
    assert r.status_code == 409 and "without the status filter" in r.json()["detail"]
    monkeypatch.setattr("backend.routers.scans.read_statuses", down)
    r = export(http, ids, query="statuses=fixed")
    assert r.status_code == 503 and r.headers["Retry-After"] == "30"


def test_a_large_build_takes_a_slot_and_a_busy_host_answers_429(api, monkeypatch):
    http, ids = api
    from backend.utilities.cbom_sources import export_slots

    taken = []
    real = export_slots.slot

    def counting():
        taken.append(1)
        return real()

    monkeypatch.setattr("backend.routers.scans.LARGE_PDF_ROWS", 1)
    monkeypatch.setattr(export_slots, "LOCK_DIR", tempfile.mkdtemp())
    monkeypatch.setattr(export_slots, "slot", counting)
    assert export(http, ids).status_code == 200 and taken == [1]

    def busy():
        raise export_slots.Busy()

    monkeypatch.setattr(export_slots, "slot", busy)
    r = export(http, ids)
    assert r.status_code == 429 and r.headers["Retry-After"] == str(export_slots.RETRY_AFTER_S)
    monkeypatch.setattr("backend.routers.scans.LARGE_PDF_ROWS", 10**9)
    assert export(http, ids).status_code == 200  # a small build never waits


def test_no_temp_file_is_left_after_success_or_failure(api, monkeypatch, tmp_path):
    http, ids = api
    spool = tmp_path / "spool"
    spool.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(spool))
    assert export(http, ids).status_code == 200
    assert export(http, ids, query="severities=low").status_code == 200

    def boom(*_a, **_k):
        raise RuntimeError("renderer failed")

    monkeypatch.setattr("backend.routers.scans.write_scan_pdf", boom)
    assert export(http, ids).status_code == 500
    assert list(spool.iterdir()) == []


def test_one_log_line_per_export_without_free_text(api, capsys):
    http, ids = api
    r = export(http, ids, query="prepared_for=Acme%20Bank%20Ltd&title=Board%20pack&label=internal&severities=high")
    assert r.status_code == 200, r.text
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if "pdf report export" in line]
    assert len(lines) == 1, out
    line = lines[0]
    for part in ("family=scan", "type=sast", f"team={ids['team_id']}", f"id={ids['scan_ids']['sast']}",
                 "label=internal", "severities=high", "prepared_for_set=1", "title_set=1", "logo=none", "outcome=ok"):
        assert part in line, (part, line)
    assert "Acme" not in out and "Board pack" not in out


def test_every_scan_type_still_exports_with_every_preset(api):
    http, ids = api
    for scan_type in EXPORT._SCAN_TYPES:
        for preset in ("executive", "technical", "full"):
            r = export(http, ids, scan_type, f"preset={preset}")
            assert r.status_code == 200, (scan_type, preset, r.text[:300])
            assert r.content[:5] == b"%PDF-"


# ----------------------------------------------------------------------------- R2: certin evidence pack
@pytest.fixture()
def pack_api(api, monkeypatch):
    http, ids = api
    engine = _engine()
    monkeypatch.setattr("backend.routers.certin.get_db", lambda: engine)
    monkeypatch.setattr("backend.routers.certin.check_if_user_is_in_team", lambda *_a, **_k: None)

    async def fake_user(*_a, **_k):
        import types

        return types.SimpleNamespace(id=ids["user_id"])

    monkeypatch.setattr("backend.routers.certin.get_user_from_header_or_raise_exception", fake_user)
    return http, ids, engine


def _pack(http, ids, scan_type="sbom_sca", query=""):
    url = f"/{ids['team_id']}/{scan_type}/scan/{ids['scan_ids'][scan_type]}/evidence-pack"
    return http.get(url + (f"?{query}" if query else ""), headers=AUTH)


def test_certin_pack_refuses_report_options(pack_api):
    http, ids, _engine_ = pack_api
    r = _pack(http, ids, query="preset=executive")
    assert r.status_code == 422 and r.json()["detail"].startswith("preset: ")


def test_certin_pack_pdf_carries_the_logo(pack_api):
    http, ids, engine = pack_api
    plain = _pack(http, ids)
    assert plain.status_code == 200, plain.text
    assert plain.headers["X-Report-Logo"] == "none"
    set_logo(engine, ids["team_id"])
    branded = _pack(http, ids)
    assert branded.headers["X-Report-Logo"] == "applied"
    pdf_plain = zipfile.ZipFile(io.BytesIO(plain.content)).read("report.pdf")
    pdf_branded = zipfile.ZipFile(io.BytesIO(branded.content)).read("report.pdf")
    assert images(pdf_branded) > images(pdf_plain)


def test_certin_pack_leaves_no_temp_file_when_it_fails(pack_api, monkeypatch, tmp_path):
    http, ids, _engine_ = pack_api
    spool = tmp_path / "spool"
    spool.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(spool))

    def boom(*_a, **_k):
        raise RuntimeError("zip failed")

    monkeypatch.setattr("backend.routers.certin.compliance_key_for", boom)
    r = _pack(http, ids)
    assert r.status_code == 500 and "zip failed" not in r.text
    assert list(spool.iterdir()) == []


# ----------------------------------------------------------------------------- CORS
def test_cors_exposes_the_report_and_cbom_headers():
    from starlette.middleware.cors import CORSMiddleware

    from backend.main import app

    (cors,) = [m for m in app.user_middleware if m.cls is CORSMiddleware]
    exposed = set(cors.kwargs["expose_headers"])
    for name in ("Content-Disposition", "X-Report-Findings", "X-Report-Logo", "Retry-After", "X-ZS-Request-Id",
                 "X-Cbom-Sha256", "X-Cbom-Logo-Sha256", "X-Cbom-Fingerprint", "X-Cbom-Scans-Included"):
        assert name in exposed, name


# ----------------------------------------------------------------------------- R3: regulated deliverables
from backend.routers import cbom_deliverables as DELIVERABLE_ROUTES  # noqa: E402
from backend.tests import test_cbom_deliverables_route as DROUTE  # noqa: E402


@pytest.fixture()
def deliverable_api(tmp_path, monkeypatch):
    from backend.tests.test_cbom_deliverables_no_llm import block_network, plant_tripwires

    world = DROUTE.build_world(tmp_path)
    client = DROUTE.make_api(world, monkeypatch)
    block_network(monkeypatch)  # loading the logo is SQL only (T-NOLLM-3)
    plant_tripwires(monkeypatch)
    yield client, world
    DELIVERABLE_ROUTES.limiter.requests.clear()


def test_deliverable_cover_options_and_logo(deliverable_api):
    client, world = deliverable_api
    url = DROUTE.pdf_url(DROUTE.TEAM_ONE, "board-executive-report")
    plain = client.get(url)
    assert plain.status_code == 200 and plain.headers["X-Report-Logo"] == "none"
    assert "X-Cbom-Logo-Sha256" not in plain.headers
    assert client.get(url + "?severities=high").status_code == 422
    assert client.get(url + "?preset=executive").status_code == 422
    named = client.get(url + "?prepared_for=Acme%20Bank&label=restricted")
    assert named.status_code == 200, named.text
    text = DROUTE.full_text(named.content)
    assert "Acme Bank" in text and "Restricted" in text
    sha = set_logo(world.engine, DROUTE.TEAM_ONE)
    branded = client.get(url)
    assert branded.headers["X-Report-Logo"] == "applied" and branded.headers["X-Cbom-Logo-Sha256"] == sha
    assert images(branded.content) > images(plain.content)
    assert sha[:8] in DROUTE.full_text(branded.content)  # the control table records the presentation


def test_deliverable_default_bytes_do_not_change_without_a_logo(deliverable_api):
    client, _world = deliverable_api
    url = DROUTE.pdf_url(DROUTE.TEAM_ONE, "scope-baseline-register")
    assert client.get(url).content == client.get(url + "?label=confidential").content

