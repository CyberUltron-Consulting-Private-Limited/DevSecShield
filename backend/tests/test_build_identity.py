"""CB-03 build identity: one commit reported by /health, on every response (X-ZS-Build), in the CBOM exports and
runs, and a request id (X-ZS-Request-Id) on every response and in the log lines of that request.  Run:

    cd backend && PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r AWS_ACCESS_KEY_ID=x \\
      AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 uv run --with pytest python -m pytest \\
      tests/test_build_identity.py -q -p no:cacheprovider
"""
from __future__ import annotations

import datetime as dt
import logging
import re
import xml.etree.ElementTree as ET

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient
from sqlmodel import Session

from test_cbom_sources_api import _collect_job, api, world  # noqa: F401  (fixtures)
from test_cbom_wp9_sources import _post_assets
from backend import main as MAIN
from backend.main import app
from backend.new_models import CbomCollectionRun
from backend.utilities import build_info as B
from backend.utilities.cbom_sources import common as C
from backend.utilities.cbom_sources.cdx_xml import validate_xml
from backend.utilities.integrations import oscal as OSCAL

SHA = "83b570bed86212e3afed395be942df57b8dc3df5"
OTHER = "0123456789abcdef0123456789abcdef01234567"
BUILD = "X-ZS-Build"
RID = "X-ZS-Request-Id"
ISO_Z = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z) ")


@pytest.fixture()
def build(monkeypatch):
    monkeypatch.setenv("DSS_BUILD_SHA", SHA)
    monkeypatch.setenv("DSS_BUILD_VERSION", "1.4.0-rc.2")
    return SHA


# ----------------------------------------------------------------------------- the values
@pytest.mark.parametrize("raw, expected", [
    (SHA, SHA), (SHA.upper(), SHA), (f"  {SHA}\n", SHA), ("", "unknown"), ("not-a-sha", "unknown"),
    (SHA + "0", "unknown"), (SHA[:12], "unknown"), ("g" * 40, "unknown"), (SHA[:39] + "\n", "unknown"),
])
def test_build_sha_accepts_only_a_full_commit(monkeypatch, raw, expected):
    monkeypatch.setenv("DSS_BUILD_SHA", raw)
    assert B.build_sha() == expected


@pytest.mark.parametrize("sha, version, expected", [
    (SHA, "1.4.0-rc.2", "1.4.0-rc.2"),
    (SHA, "", SHA[:12]),                       # no version string: the short commit
    ("", "", "unknown"),
    (SHA, "release 1.4\r\nX-Evil: 1", SHA[:12]),  # not a version string: never echoed
    (SHA, "v" * 65, SHA[:12]),
    (SHA, "k-ed70ff12e203", "k-ed70ff12e203"),
    (SHA, "83b570bed862-dirty", "83b570bed862-dirty"),
])
def test_build_version(monkeypatch, sha, version, expected):
    monkeypatch.setenv("DSS_BUILD_SHA", sha)
    monkeypatch.setenv("DSS_BUILD_VERSION", version)
    assert B.build_version() == expected


def test_engine_version_is_the_short_build(monkeypatch):
    """Runs record the build that judged them; the column is 32 characters, so the 12-character short commit."""
    monkeypatch.setenv("DSS_BUILD_SHA", SHA)
    monkeypatch.setenv("DSS_BUILD_VERSION", "1.4.0")
    assert C.engine_version() == SHA[:12]
    monkeypatch.setenv("DSS_BUILD_SHA", "")
    assert C.engine_version() == "1.4.0"  # an image without a commit still names its version
    monkeypatch.setenv("DSS_BUILD_VERSION", "")
    assert C.engine_version() == "unknown"  # before: "devsecshield-0.1.0" in tests, "unknown" in the image


# ----------------------------------------------------------------------------- /health and headers
def test_health_reports_build(build):
    r = TestClient(app).get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "healthy", "service": "devsecshield-backend", "build": SHA, "version": "1.4.0-rc.2"}
    assert r.headers[BUILD] == SHA


def test_health_without_identity_says_unknown(monkeypatch):
    monkeypatch.delenv("DSS_BUILD_SHA", raising=False)
    monkeypatch.delenv("DSS_BUILD_VERSION", raising=False)
    r = TestClient(app).get("/health")
    assert r.json()["build"] == "unknown" and r.json()["version"] == "unknown" and r.headers[BUILD] == "unknown"


def test_every_response_has_x_zs_build(build, world):  # noqa: F811
    client = TestClient(app, raise_server_exceptions=False)
    responses = {
        "200 health": client.get("/health"),
        "404 unknown path": client.get("/no/such/path"),
        "405 wrong method": client.delete("/health"),
        "401 node api": client.post("/cbom/node/heartbeat", json={}),
        "401 user api": client.get("/1/cbom/sources/nodes"),
        "422 validation": client.get("/1/cbom/sources/runs/not-a-number"),
        "preflight": client.options("/health", headers={"Origin": "http://localhost:3000",
                                                        "Access-Control-Request-Method": "GET"}),
        "head": client.head("/health"),
    }
    seen = {name: (r.status_code, r.headers.get(BUILD), r.headers.get(RID)) for name, r in responses.items()}
    for name, (_status, build_header, rid) in seen.items():
        assert build_header == SHA, (name, seen[name])
        assert rid and re.fullmatch(r"[0-9a-f]{32}", rid), (name, seen[name])
    assert seen["404 unknown path"][0] == 404 and seen["401 node api"][0] == 401
    assert seen["preflight"][0] == 200 and seen["422 validation"][0] in (400, 401, 404, 422)
    assert len({rid for _s, _b, rid in seen.values()}) == len(seen)  # one id per request


def test_an_unhandled_error_still_carries_the_build_and_request_id(build):
    """Starlette's ServerErrorMiddleware answers an unhandled exception outside every user middleware; the identity
    wrapper sits outside it (DssApp.build_middleware_stack)."""
    boom = MAIN.DssApp()
    router = APIRouter()

    @router.get("/boom")
    def _boom():
        raise RuntimeError("unhandled")

    boom.include_router(router)
    r = TestClient(boom, raise_server_exceptions=False).get("/boom", headers={RID: "client-trace-0001"})
    assert r.status_code == 500 and r.headers[BUILD] == SHA and r.headers[RID] == "client-trace-0001"
    assert isinstance(app, MAIN.DssApp)  # the real app is built the same way


@pytest.mark.parametrize("sent, echoed", [
    ("trace-0001-abcd", True), ("0af7651916cd43dd8448eb211c80319c", True), ("a" * 64, True),
    ("short", False), ("a" * 65, False), ("has space here", False), ("semi;colon=1abc", False),
    ("-starts-with-dash", False), ("../../etc/passwd", False), ("", False),
])
def test_request_id_is_echoed_only_when_well_formed(build, sent, echoed):
    r = TestClient(app).get("/health", headers={RID: sent})
    if echoed:
        assert r.headers[RID] == sent
    else:
        assert r.headers[RID] != sent and re.fullmatch(r"[0-9a-f]{32}", r.headers[RID])


def test_existing_headers_are_kept_and_never_duplicated(build):
    r = TestClient(app).post("/cbom/node/heartbeat", json={})  # the node API also stamps X-ZS-Deployment
    raw = [k.lower() for k, _v in r.headers.raw]
    assert raw.count(b"x-zs-build") == 1 and raw.count(b"x-zs-request-id") == 1


# ----------------------------------------------------------------------------- logs
def test_log_line_has_utc_timestamp(capsys):
    C.log("unit test line", job=7)
    line = capsys.readouterr().out.strip().splitlines()[-1]
    m = ISO_Z.match(line)
    assert m, line
    stamp = dt.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc)
    assert abs((dt.datetime.now(dt.timezone.utc) - stamp).total_seconds()) < 5
    assert line[m.end():] == "cbom sources unit test line job=7"  # no request id outside a request


def test_log_lines_and_500_refs_carry_the_request_id(api, world, monkeypatch, capsys, build):  # noqa: F811
    from backend.routers import cbom_sources as R

    def broken(*_a, **_k):
        raise RuntimeError("database went away")

    monkeypatch.setattr(R, "_run_cbom", broken)
    capsys.readouterr()
    r = api("GET", "/1/cbom/sources/runs/1/cbom", headers={RID: "gate-run-trace-42"})
    assert r.status_code == 500 and r.headers[RID] == "gate-run-trace-42"
    ref = re.search(r"\(ref ([0-9a-f]{8})\)", r.json()["detail"]).group(1)
    lines = [ln for ln in capsys.readouterr().out.splitlines() if "FAILED" in ln]
    assert len(lines) == 1, lines
    assert ISO_Z.match(lines[0]) and f"ref={ref}" in lines[0] and "request_id=gate-run-trace-42" in lines[0]
    assert "database went away" not in lines[0]  # the error class only, as before


def test_security_log_lines_use_iso_utc():
    handler = logging.getLogger("backend.auth").handlers[0]
    record = logging.LogRecord("backend.auth", logging.WARNING, __file__, 1, "sign-in refused", None, None)
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z WARNING backend.auth sign-in refused$",
                    handler.format(record))


# ----------------------------------------------------------------------------- exports
CERT = {"type": "certificate", "target": "10.20.0.1", "location": "/etc/ssl/pay.pem", "name": "pay", "algorithm": "RSA",
        "key_size": 1024, "facts": {"subject": "CN=pay.bank.local", "issuer": "CN=pay.bank.local",
                                    "not_after": "2020-01-01T00:00:00Z", "sig_alg": "md5WithRSAEncryption",
                                    "key_alg": "RSA", "key_size": 1024, "self_signed": True,
                                    "fingerprint_sha256": "ab" * 32}}


def _props(doc: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in doc["metadata"]["properties"]}


def test_export_engine_version_is_build(api, world, monkeypatch):  # noqa: F811
    engine, _ = world
    monkeypatch.setenv("DSS_BUILD_SHA", SHA)
    monkeypatch.setenv("DSS_BUILD_VERSION", "1.4.0")
    _src, run, claim, hdr = _collect_job(api, engine)  # the run is created (and judged) by build SHA
    assert _post_assets(api, claim["job"], hdr, [CERT]).status_code == 200
    with Session(engine) as s:
        assert s.get(CbomCollectionRun, run["id"]).engine_version == SHA[:12]

    doc = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom").json()
    props = _props(doc)
    assert props["zs:engine_version"] == SHA[:12] and props["zs:build"] == SHA
    assert doc["metadata"]["tools"]["components"][0]["version"] == "1.4.0"

    # exported later by another build: the run keeps the build that judged it, the file names the one that wrote it
    monkeypatch.setenv("DSS_BUILD_SHA", OTHER)
    monkeypatch.setenv("DSS_BUILD_VERSION", "1.5.0")
    later = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom").json()
    assert _props(later)["zs:engine_version"] == SHA[:12] and _props(later)["zs:build"] == OTHER
    assert later["metadata"]["tools"]["components"][0]["version"] == "1.5.0"

    xml = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom?format=xml")
    assert xml.status_code == 200 and validate_xml(xml.content) == []
    ns = {"c": "http://cyclonedx.org/schema/bom/1.6"}
    xprops = {p.get("name"): p.text for p in ET.fromstring(xml.content).findall("c:metadata/c:properties/c:property", ns)}
    assert xprops["zs:engine_version"] == SHA[:12] and xprops["zs:build"] == OTHER

    job = claim["job"]  # OSCAL is written for finished runs only
    done = api("POST", f"/cbom/node/jobs/{job['id']}/result", None, headers=hdr,
               json={"lease_id": job["lease_id"], "status": "success",
                     "result": {"counts": {"total": 2, "ok": 2, "failed": 0, "skipped": 0}}})
    assert done.status_code == 200, done.text
    oscal = api("GET", f"/1/cbom/sources/runs/{run['id']}/oscal").json()
    assert OSCAL.validate(oscal) == [], OSCAL.validate(oscal)[:3]
    oprops = {p["name"]: p["value"] for p in oscal["assessment-results"]["metadata"]["props"]}
    assert oprops["generator-build"] == OTHER and oprops["engine-version"] == SHA[:12]


def test_export_without_identity_is_still_valid(api, world, monkeypatch):  # noqa: F811
    engine, _ = world
    monkeypatch.delenv("DSS_BUILD_SHA", raising=False)
    monkeypatch.delenv("DSS_BUILD_VERSION", raising=False)
    _src, run, claim, hdr = _collect_job(api, engine)
    assert _post_assets(api, claim["job"], hdr, [CERT]).status_code == 200
    doc = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom").json()
    assert _props(doc)["zs:build"] == "unknown" and _props(doc)["zs:engine_version"] == "unknown"
    xml = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom?format=xml")
    assert validate_xml(xml.content) == []
