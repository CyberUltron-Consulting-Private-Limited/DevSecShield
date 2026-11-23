"""HTTP contract of the PDF report options and the team report logo on every report route.

R1 ``GET|POST /{team}/{type}/scan/{id}/export``  options (scan family; POST: a JSON body), logo, status join, export
                                                 slot (the scan PDF pool), headers, log
R2 ``GET /{team}/{type}/scan/{id}/evidence-pack`` options refused (422), logo in report.pdf, no temp file left
R3 ``GET|POST /{team}/cbom/deliverables/{slug}``  prepared_for + label only, logo, X-Cbom-Logo-Sha256 when applied
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


def test_an_unsupported_type_is_400_even_with_a_status_filter(api, monkeypatch):
    http, ids = api
    called = []
    monkeypatch.setattr("backend.routers.scans.read_statuses", lambda *a, **k: called.append(1) or [])
    r = http.get(f"/{ids['team_id']}/leakage/scan/{ids['leakage_id']}/export?statuses=fixed", headers=AUTH)
    assert r.status_code == 400 and "not supported" in r.json()["detail"] and called == []


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
    real = export_slots.pdf_slot

    def counting():
        taken.append(1)
        return real()

    monkeypatch.setattr("backend.routers.scans.LARGE_PDF_ROWS", 1)
    monkeypatch.setattr(export_slots, "LOCK_DIR", tempfile.mkdtemp())
    monkeypatch.setattr(export_slots, "pdf_slot", counting)
    assert export(http, ids).status_code == 200 and taken == [1]

    def busy():
        raise export_slots.Busy()

    monkeypatch.setattr(export_slots, "pdf_slot", busy)
    r = export(http, ids)
    assert r.status_code == 429 and r.headers["Retry-After"] == str(export_slots.RETRY_AFTER_S)
    assert "no-store" in r.headers["Cache-Control"]
    assert r.json()["detail"] == export_slots.PDF_BUSY
    assert r.json()["detail"] == "The server is busy building other large scan PDF reports."
    monkeypatch.setattr("backend.routers.scans.LARGE_PDF_ROWS", 10**9)
    assert export(http, ids).status_code == 200  # a small build never waits


def test_scan_pdfs_have_their_own_slots(api, monkeypatch, tmp_path):
    """Every CBOM export slot taken (another worker builds big CBOM exports): a big scan PDF still builds; every scan
    PDF slot taken: the next big scan PDF is 429 with the scan PDF words, never the CBOM ones."""
    http, ids = api
    from backend.utilities.cbom_sources import export_slots as ES

    monkeypatch.setattr(ES, "LOCK_DIR", str(tmp_path))
    monkeypatch.setattr(ES, "SLOTS", 1)
    monkeypatch.setattr(ES, "PDF_SLOTS", 1)
    monkeypatch.setattr("backend.routers.scans.LARGE_PDF_ROWS", 1)
    with ES.slot():  # the CBOM pool is full
        assert export(http, ids).status_code == 200
    with ES.pdf_slot():  # the scan PDF pool is full
        r = export(http, ids)
        assert r.status_code == 429 and r.json()["detail"] == ES.PDF_BUSY and "CBOM" not in r.json()["detail"]
        assert post_export(http, ids, {"label": "internal"}).status_code == 429  # the POST takes the same slot
    assert export(http, ids).status_code == 200  # released


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


JSON = {"Content-Type": "application/json"}
# ~5,000 nested arrays in ~10 KB: under the body limit, past Python's JSON recursion limit (review 6013762056)
DEEP = b'{"title": ' + b"[" * 5000 + b"]" * 5000 + b"}"


def post_export(http, ids, body=None, scan_type="sast", query: str = "", headers=None, **kwargs):
    """POST the export; ``body`` as JSON, or raw ``content`` sent as application/json unless ``headers`` say otherwise."""
    url = f"/{ids['team_id']}/{scan_type}/scan/{ids['scan_ids'][scan_type]}/export"
    if body is not None:
        kwargs["json"] = body
    sent = {**AUTH, **(JSON if "content" in kwargs else {}), **(headers or {})}
    return http.post(url + (f"?{query}" if query else ""), headers=sent, **kwargs)


def test_post_takes_the_options_as_a_json_body_and_answers_like_the_get(api):
    http, ids = api
    total = three_findings(ids)
    get = export(http, ids, query="severities=critical,high&label=internal&prepared_for=Acme%20Bank&title=Q4")
    post = post_export(http, ids, {"severities": "critical,high", "label": "internal", "prepared_for": "Acme Bank",
                                   "title": "Q4"})
    assert get.status_code == post.status_code == 200, post.text
    for name in ("Content-Disposition", "X-Report-Findings", "X-Report-Logo", "Content-Type"):
        assert post.headers[name] == get.headers[name], name
    assert post.headers["X-Report-Findings"] == f"2/{total}"
    from backend.tests.support.pdf_text import pdf_text

    assert pdf_text(post.content).count("Acme Bank") == pdf_text(get.content).count("Acme Bank") == 1
    # JSON's own types: lists for the comma lists, a boolean for the snippet switch, null for "not set"
    typed = post_export(http, ids, {"severities": ["critical", "high"], "hide_evidence": True, "title": None,
                                    "label": "internal", "prepared_for": "Acme Bank"})
    assert typed.status_code == 200 and typed.headers["X-Report-Findings"] == f"2/{total}"
    # an empty JSON body or an empty object: the full report, like a GET without a query
    for kwargs in ({"content": b""}, {"json": {}}):
        r = post_export(http, ids, **kwargs)
        assert r.status_code == 200 and r.headers["X-Report-Findings"] == f"{total}/{total}", kwargs


@pytest.mark.parametrize("content_type, status", [
    (None, 415), ("text/plain", 415), ("application/x-www-form-urlencoded", 415), ("multipart/form-data", 415),
    ("application/jsonx", 415), ("application/json", 200), ("application/json; charset=utf-8", 200),
    ("Application/JSON;charset=UTF-8", 200),
])
def test_post_needs_a_json_content_type(api, content_type, status):
    http, ids = api
    headers = {} if content_type is None else {"Content-Type": content_type}
    url = f"/{ids['team_id']}/sast/scan/{ids['scan_ids']['sast']}/export"
    r = http.post(url, headers={**AUTH, **headers}, content=b'{"label": "internal"}')
    assert r.status_code == status, r.text
    if status == 415:
        assert r.json()["detail"] == "Send the report options as JSON (Content-Type: application/json)"
    assert http.post(url, headers=headers, content=b"{}").status_code == 401  # authentication still comes first


def test_post_keeps_the_client_name_out_of_the_url_and_the_log(api, capsys):
    http, ids = api
    r = post_export(http, ids, {"prepared_for": "Acme Bank Ltd", "title": "Board pack", "label": "internal"})
    assert r.status_code == 200, r.text
    assert "Acme" not in str(r.request.url) and "?" not in str(r.request.url)
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if "pdf report export" in line]
    assert len(lines) == 1 and "prepared_for_set=1" in lines[0] and "title_set=1" in lines[0], out
    assert "Acme" not in out and "Board pack" not in out


@pytest.mark.parametrize("body, field", [
    ({"preset": "board"}, "preset"),
    ({"label": "secret"}, "label"),
    ({"severities": "urgent"}, "severities"),
    ({"severities": []}, "severities"),
    ({"statuses": "open"}, "statuses"),
    ({"sections": ""}, "sections"),
    ({"hide_evidence": "yes"}, "hide_evidence"),
    ({"hide_evidence": 1}, "hide_evidence"),
    ({"prepared_for": "A" * 121}, "prepared_for"),
    ({"prepared_for": "東京銀行"}, "prepared_for"),
    ({"title": 7}, "title"),
    ({"severities": ["high", 3]}, "severities"),
    ({"prepard_for": "Acme"}, "prepard_for"),  # a typo is refused, never a silent full report
    ({"x" * 50: "1"}, "body"),
    ([{"label": "internal"}], "body"),
    ("label=internal", "body"),
])
def test_post_refuses_what_the_get_refuses_with_the_same_words(api, body, field):
    http, ids = api
    r = post_export(http, ids, body)
    assert r.status_code == 422, r.text
    assert r.json()["detail"].startswith(f"{field}: ")


def test_post_words_match_the_get_words(api):
    http, ids = api
    for query, body in (("label=secret", {"label": "secret"}), ("prepared_for=" + "A" * 121, {"prepared_for": "A" * 121}),
                        ("prepared_for=%E6%9D%B1", {"prepared_for": "東"}), ("sections=", {"sections": ""})):
        assert export(http, ids, query=query).json() == post_export(http, ids, body).json(), query


def test_post_refuses_options_in_its_query_string_and_oversized_or_malformed_bodies(api):
    http, ids = api
    r = post_export(http, ids, {}, query="prepared_for=Acme")
    assert r.status_code == 422 and r.json()["detail"].startswith("prepared_for: send report options in the JSON body")
    assert post_export(http, ids, {}, query="utm_source=mail").status_code == 200  # unrelated keys: left alone
    big = post_export(http, ids, content=b'{"title": "' + b"x" * 20_000 + b'"}',
                      headers={**AUTH, "Content-Type": "application/json"})
    assert big.status_code == 413
    bad = post_export(http, ids, content=b"{not json", headers={**AUTH, "Content-Type": "application/json"})
    assert bad.status_code == 422 and bad.json()["detail"] == "body: must be a JSON object of report options"
    for raw in (b'{"label": "internal", "label": "public"}', b'{"label": "internal", "label": null}',
                b'{"label": null, "label": "internal"}', b'{"title": null, "title": null}'):
        twice = post_export(http, ids, content=raw)
        field = raw.split(b'"')[1].decode()
        assert twice.status_code == 422 and twice.json()["detail"] == f"{field}: was given more than once", raw
    five = post_export(http, ids, content=b'{"title": [[[["x"]]]]}')  # 5 levels: past BODY_MAX_DEPTH (4)
    assert five.json()["detail"] == "body: is nested too deeply; send one JSON object of report options"
    brackets = post_export(http, ids, {"title": "[[[[[[{{{{{ \\\" ]]]]"})  # brackets inside a string are text
    assert brackets.status_code == 200, brackets.text
    deep = post_export(http, ids, content=DEEP)
    assert len(DEEP) < 16 * 1024 and deep.status_code == 422, deep.text
    assert deep.json()["detail"] == "body: is nested too deeply; send one JSON object of report options"
    nested = post_export(http, ids, {"title": {"text": "x"}})
    assert nested.status_code == 422 and nested.json()["detail"] == "title: must be a string"
    for raw in (b"null", b"[]", b'"label"', b"3"):  # JSON, but not an object of options
        assert post_export(http, ids, content=raw).json()["detail"] == "body: must be a JSON object of report options"


def test_post_and_get_share_every_route_dependency():
    """Same permission, same rate limiter (one budget for both methods), on R1, R3 and R4."""
    from fastapi.routing import APIRoute

    from backend.main import app

    paths = ("/{team_id}/{type}/scan/{scan_id}/export", "/{team_id}/cbom/deliverables/{slug}",
             "/{team_id}/cbom/sources/runs/{run_id}/report.pdf")
    for path in paths:
        routes = {m: r for r in app.routes if isinstance(r, APIRoute) and r.path == path for m in r.methods}
        assert set(routes) == {"GET", "POST"}, path
        get, post = routes["GET"], routes["POST"]
        assert get.endpoint is post.endpoint, path  # one handler: nothing forked
        def deps(route):  # a policy object per decorator: compared by kind and permission; limiters by identity
            out = []
            for dep in (d.dependency for d in route.dependencies):
                permission = getattr(dep, "permission", None)
                out.append((type(dep), permission.name) if permission is not None else dep)
            return out

        assert deps(get) == deps(post), path
        assert any(isinstance(d, tuple) and d[1] in ("scan.read", "cbom.read") for d in deps(post)), path
        assert type(get) is type(post), path  # route class (CbomRoute on R4)


def test_the_depth_check_ignores_strings_and_holds_on_every_python():
    from backend.utilities.pdf.report_http import BODY_MAX_DEPTH, _too_deep

    assert BODY_MAX_DEPTH == 4
    assert not _too_deep(b'{"sections": ["summary", "catalog"], "title": "a [[[[[ b"}')
    assert not _too_deep(b'{"title": "\\"[[[[[[["}')  # an escaped quote does not end the string
    assert not _too_deep(b'[[[["x"]]]]') and _too_deep(b'[[[[["x"]]]]]')
    assert _too_deep(DEEP)


def test_the_openapi_body_schema_says_what_the_server_accepts():
    from backend.main import app

    spec = app.openapi()["paths"]
    scan = spec["/{team_id}/{type}/scan/{scan_id}/export"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    run = spec["/{team_id}/cbom/sources/runs/{run_id}/report.pdf"]["post"]["requestBody"]["content"]["application/json"]

    def kinds(prop):
        return sorted(option["type"] for option in prop["anyOf"])

    props = scan["properties"]
    for key in ("sections", "severities", "statuses"):
        assert kinds(props[key]) == ["array", "null", "string"], key
    assert kinds(props["hide_evidence"]) == ["boolean", "null", "string"]
    assert kinds(props["prepared_for"]) == ["null", "string"] and props["prepared_for"]["anyOf"][0]["maxLength"] == 120
    assert props["sections"]["anyOf"][1]["items"]["enum"] == ["summary", "catalog", "details", "remediation",
                                                               "mappings", "compliance", "inventory", "notes"]
    assert run["schema"]["properties"]["sections"]["anyOf"][1]["items"]["enum"] == ["summary", "posture", "catalog",
                                                                                    "provenance"]
    assert "statuses" not in run["schema"]["properties"] and scan["additionalProperties"] is False
    for path in ("/{team_id}/{type}/scan/{scan_id}/export", "/{team_id}/cbom/deliverables/{slug}",
                 "/{team_id}/cbom/sources/runs/{run_id}/report.pdf"):
        assert {"413", "415", "422"} <= set(spec[path]["post"]["responses"]), path


def test_cors_lets_a_browser_post_json_with_a_bearer_token():
    from fastapi.testclient import TestClient

    from backend.main import app

    r = TestClient(app).options("/1/sast/scan/1/export", headers={
        "Origin": "http://localhost:3000", "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type"})
    assert r.status_code == 200, r.text
    assert "POST" in r.headers["access-control-allow-methods"]
    allowed = r.headers["access-control-allow-headers"].lower()
    assert "authorization" in allowed and "content-type" in allowed


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


def test_deliverable_post_takes_the_cover_options_as_json(deliverable_api):
    client, _world = deliverable_api
    url = DROUTE.pdf_url(DROUTE.TEAM_ONE, "board-executive-report")
    get = client.get(url + "?prepared_for=Acme%20Bank&label=restricted")
    post = client.post(url, json={"prepared_for": "Acme Bank", "label": "restricted"})
    assert post.status_code == 200, post.text
    assert post.content == get.content  # deliverables are byte-stable: the same document either way
    for name in ("Content-Disposition", "X-Report-Logo", "X-Cbom-Scans-Included", "X-Cbom-Fingerprint",
                 "X-Cbom-Posture", "Cache-Control"):
        assert post.headers[name] == get.headers[name], name
    assert client.post(url, json={}).content == client.get(url).content  # no option: today's document
    raw_post = client.client.post  # the TestClient itself, for bodies and headers the helper does not send
    bearer = {"Authorization": f"Bearer {client.token('alice')}"}
    assert raw_post(url, headers=bearer, content=b"{}").status_code == 415  # no Content-Type
    deep = raw_post(url, headers={**bearer, **JSON}, content=DEEP)
    assert deep.status_code == 422 and deep.json()["detail"].startswith("body: is nested too deeply"), deep.text
    dup = raw_post(url, headers={**bearer, **JSON}, content=b'{"label": "internal", "label": null}')
    assert dup.status_code == 422 and dup.json()["detail"] == "label: was given more than once"
    marathi = client.post(url, json={"prepared_for": "महाराष्ट्र राज्य सहकारी बँक"})
    assert marathi.status_code == 200 and b"NotoSansDevanagari" in marathi.content
    for body, field in (({"severities": "high"}, "severities"), ({"title": "T"}, "title"),
                        ({"prepared_for": "東"}, "prepared_for"), ({"label": 3}, "label")):
        r = client.post(url, json=body)
        assert r.status_code == 422 and r.json()["detail"].startswith(f"{field}: "), (body, r.text)
    assert client.post(DROUTE.pdf_url(DROUTE.TEAM_ONE, "no-such-slug"), json={}).status_code == 404


def test_deliverable_default_bytes_do_not_change_without_a_logo(deliverable_api):
    client, _world = deliverable_api
    url = DROUTE.pdf_url(DROUTE.TEAM_ONE, "scope-baseline-register")
    assert client.get(url).content == client.get(url + "?label=confidential").content



# ----------------------------------------------------------------------------- staging QA 23 Nov 2026
# Every report download and every slot refusal is private (Cache-Control: no-store, X-Content-Type-Options: nosniff):
# R1 used to send neither, R2 and the scan's CycloneDX download neither, R3-R5 both. Each attempt logs one line with
# its outcome; a slot 429 carries X-Export-Busy, the rate limiter's 429 never does.
def assert_private(r, what: str) -> None:
    assert r.headers.get("Cache-Control") == "no-store", (what, dict(r.headers))
    assert r.headers.get("X-Content-Type-Options") == "nosniff", (what, dict(r.headers))


def export_lines(out: str) -> list[str]:
    return [line for line in out.splitlines() if "pdf report export" in line]


def test_every_report_helper_answer_is_private():
    from backend.utilities.cbom_sources.http import PRIVATE as CBOM_PRIVATE
    from backend.utilities.pdf import report_http
    from backend.utilities.pdf.report_context import ReportContext

    assert report_http.PRIVATE == CBOM_PRIVATE == {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
    for findings in (True, False):
        headers = report_http.report_headers(ReportContext(), "r.pdf", findings=findings)
        assert headers["Cache-Control"] == "no-store" and headers["X-Content-Type-Options"] == "nosniff"
        assert ("X-Report-Findings" in headers) is findings
    for pool, words in (("pdf", "scan PDF"), ("cbom", "CBOM")):
        busy = report_http.busy_refusal(pool)
        assert busy.status_code == 429 and words in busy.detail
        assert busy.headers["X-Export-Busy"] == pool and busy.headers["Retry-After"] == "30"
        assert busy.headers["Cache-Control"] == "no-store" and busy.headers["X-Content-Type-Options"] == "nosniff"
        assert report_http.failure_outcome(busy) == ("busy", 429)
    from fastapi import HTTPException

    assert report_http.failure_outcome(HTTPException(429, "Too Many Requests", {"Retry-After": "7"})) == ("refused", 429)
    assert report_http.failure_outcome(HTTPException(422, "label: x")) == ("refused", 422)
    assert report_http.failure_outcome(HTTPException(503, "down")) == ("error", 503)
    assert report_http.failure_outcome(RuntimeError("boom")) == ("error", 500)


def test_scan_export_get_and_post_are_private(api):
    http, ids = api
    assert_private(export(http, ids), "R1 GET")
    assert_private(export(http, ids, query="label=internal"), "R1 GET with options")
    assert_private(post_export(http, ids, {"label": "internal"}), "R1 POST")
    assert_private(post_export(http, ids, json={}), "R1 POST without options")


def test_certin_pack_and_bom_downloads_are_private(pack_api):
    http, ids, _engine = pack_api
    pack = _pack(http, ids)
    assert pack.status_code == 200, pack.text
    assert_private(pack, "R2 certin evidence pack")
    sca = ids["scan_ids"]["sbom_sca"]
    assert pack.headers["Content-Disposition"] == f'attachment; filename="certin-evidence-pack-sbom_sca-{sca}.zip"'
    assert pack.headers["X-Report-Logo"] == "none"
    served = 0
    for scan_type, query in (("sbom_sca", ""), ("cbom", ""), ("cbom", "?format=xml")):
        r = http.get(f"/{ids['team_id']}/{scan_type}/scan/{ids['scan_ids'][scan_type]}/bom{query}", headers=AUTH)
        if r.status_code == 200:
            served += 1
            assert_private(r, f"{scan_type} bom {query}")
            assert r.headers["Content-Disposition"].startswith("attachment; ")
        else:  # a stored scan without a CycloneDX document: refused, nothing to cache
            assert r.status_code == 409, r.text
    assert served, "no CycloneDX download was served"


def test_a_slot_refusal_is_private_and_says_it_is_busy(api, monkeypatch, tmp_path):
    http, ids = api
    from backend.utilities.cbom_sources import export_slots as ES

    monkeypatch.setattr(ES, "LOCK_DIR", str(tmp_path))
    monkeypatch.setattr(ES, "PDF_SLOTS", 1)
    monkeypatch.setattr("backend.routers.scans.LARGE_PDF_ROWS", 1)
    with ES.pdf_slot():
        for r in (export(http, ids), post_export(http, ids, {"label": "internal"})):
            assert r.status_code == 429 and r.json()["detail"] == ES.PDF_BUSY
            assert r.headers["X-Export-Busy"] == "pdf" and r.headers["Retry-After"] == str(ES.RETRY_AFTER_S)
            assert_private(r, "R1 slot 429")


def test_the_rate_limiter_429_has_no_busy_signal(api):
    http, ids = api
    from backend.routers import scans

    scans.write_limiter.reset()
    old = scans.write_limiter.times
    scans.write_limiter.times = 1
    try:
        assert export(http, ids).status_code == 200
        limited = export(http, ids)
    finally:
        scans.write_limiter.times = old
        scans.write_limiter.reset()
    assert limited.status_code == 429 and limited.headers.get("Retry-After"), limited.text
    assert "X-Export-Busy" not in limited.headers  # the client tells "too many requests" by its absence


def test_cors_exposes_the_busy_signal():
    from starlette.middleware.cors import CORSMiddleware

    from backend.main import app

    (cors,) = [m for m in app.user_middleware if m.cls is CORSMiddleware]
    assert "X-Export-Busy" in cors.kwargs["expose_headers"]


def test_every_scan_export_outcome_is_logged(api, monkeypatch, capsys, tmp_path):
    http, ids = api
    from backend.utilities.cbom_sources import export_slots as ES

    def one_line(r, status):
        assert r.status_code == status, r.text
        lines = export_lines(capsys.readouterr().out)
        assert len(lines) == 1, lines
        return lines[0]

    assert "outcome=ok" in one_line(export(http, ids), 200)
    line = one_line(export(http, ids, query="label=secret"), 422)
    assert "outcome=refused" in line and "status=422" in line and "family=scan" in line
    monkeypatch.setattr(ES, "LOCK_DIR", str(tmp_path))
    monkeypatch.setattr(ES, "PDF_SLOTS", 1)
    monkeypatch.setattr("backend.routers.scans.LARGE_PDF_ROWS", 1)
    with ES.pdf_slot():
        line = one_line(post_export(http, ids, {"label": "internal", "prepared_for": "Acme Bank"}), 429)
    assert "outcome=busy" in line and "status=429" in line and "label=internal" in line
    assert "prepared_for_set=1" in line and "Acme" not in line  # the options asked for, never their free text
    monkeypatch.setattr("backend.routers.scans.LARGE_PDF_ROWS", 10**9)

    def boom(*_a, **_k):
        raise RuntimeError("renderer failed")

    monkeypatch.setattr("backend.routers.scans.write_scan_pdf", boom)
    line = one_line(export(http, ids), 500)
    assert "outcome=error" in line and "status=500" in line and "renderer failed" not in line


def _asgi_export(ids, method: str, gone: bool) -> int:
    """Drive the real ASGI app (middleware included) with a client that is still there, or that disconnected while
    the report was built: after its request body, ``receive`` answers ``http.disconnect`` (``gone``) or never
    answers (a connected client; Starlette's non-blocking look then sees nothing)."""
    import anyio

    from backend.main import app

    body = b'{"label": "internal"}' if method == "POST" else b""
    path = f"/{ids['team_id']}/sast/scan/{ids['scan_ids']['sast']}/export"
    headers = [(b"authorization", b"Bearer test"), (b"host", b"testserver")]
    if body:
        headers.append((b"content-type", b"application/json"))
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "scheme": "http",
             "path": path, "raw_path": path.encode(), "query_string": b"", "headers": headers,
             "client": ("127.0.0.1", 5000), "server": ("testserver", 80), "root_path": ""}
    sent: list[dict] = []
    first = [True]

    async def receive():
        if first[0]:
            first[0] = False
            if method == "POST" or not gone:
                return {"type": "http.request", "body": body, "more_body": False}
        if gone:
            return {"type": "http.disconnect"}
        await anyio.sleep_forever()

    async def send(message):
        sent.append(message)

    async def main():
        await app(scope, receive, send)

    anyio.run(main)
    return next(m for m in sent if m["type"] == "http.response.start")["status"]


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_an_abandoned_export_is_logged_client_gone_not_ok(api, capsys, method):
    _http, ids = api
    capsys.readouterr()
    status = _asgi_export(ids, method, gone=True)
    lines = export_lines(capsys.readouterr().out)
    assert len(lines) == 1 and "outcome=client_gone" in lines[0], lines
    assert status == 200  # nothing changes for the response itself
    _asgi_export(ids, method, gone=False)
    lines = export_lines(capsys.readouterr().out)
    assert len(lines) == 1 and "outcome=ok" in lines[0], lines


def test_certin_pack_outcomes_are_logged(pack_api, capsys):
    http, ids, _engine = pack_api
    capsys.readouterr()
    assert _pack(http, ids).status_code == 200
    assert "outcome=ok" in export_lines(capsys.readouterr().out)[0]
    assert _pack(http, ids, query="preset=executive").status_code == 422
    (line,) = export_lines(capsys.readouterr().out)
    assert "family=pack" in line and "outcome=refused" in line and "status=422" in line


def test_deliverable_get_and_post_are_private_and_log_their_outcome(deliverable_api, capsys):
    client, _world = deliverable_api
    url = DROUTE.pdf_url(DROUTE.TEAM_ONE, "scope-baseline-register")
    capsys.readouterr()
    for r in (client.get(url), client.post(url, json={"label": "internal"}), client.post(url, json={})):
        assert r.status_code == 200, r.text
        assert_private(r, "R3")
        assert r.headers["Content-Disposition"].startswith('attachment; filename="cbom-scope-baseline-register-team')
    lines = [line for line in capsys.readouterr().out.splitlines() if line.startswith("cbom deliverable team=")]
    assert len(lines) == 3 and all("outcome=ok" in line for line in lines), lines
    assert client.get(url + "?severities=high").status_code == 422
    assert client.get(DROUTE.pdf_url(DROUTE.TEAM_ONE, "no-such-slug%0Aforged")).status_code == 404
    lines = [line for line in capsys.readouterr().out.splitlines() if line.startswith("cbom deliverable team=")]
    assert len(lines) == 2, lines
    assert "slug=scope-baseline-register outcome=refused status=422" in lines[0]
    assert "slug=unknown outcome=refused status=404" in lines[1] and "forged" not in "".join(lines)
