"""T-ROUTE: HTTP contract of the team-wide CBOM deliverables routes (WP4, plan 5.3 / 6.3).

``GET /{team_id}/cbom/deliverables`` (manifest) and ``GET /{team_id}/cbom/deliverables/{slug}``
(PDF) are exercised through the REAL application (``backend.main.app``, so the two-line wiring in
``main.py`` is part of what is tested), the real JWT auth, the real team-membership check and the
real ``load_team_cbom_view`` against a file-backed SQLite database seeded from the committed
fixture ``cbom_team_rollup_scans.json``.  Only ``get_db`` (the engine) and the clock are replaced.

ORACLE RULE (plan 8.4): the expected numbers are literals from plan Appendix B (8 scans included
of 9 eligible, 7 sources, mixed fidelity, one failure + two not-completed scans excluded) or are
derived from the fixture JSON with the DOCUMENTED formulas (the data fingerprint), never from the
product aggregator.  Text is read from the PDF bytes with a small pure-Python content-stream
reader, so nothing here needs poppler.

Every test in this module runs under the runtime guard of ``test_cbom_deliverables_no_llm.py``
(autouse fixture below): socket connects, DNS and ``subprocess.Popen`` raise, and the SDK modules
an LLM client would import are tripwires.  This is how "the route tests run offline" is enforced.

Worlds (teams): 1 = the Appendix-B team; 2 = another tenant (holds the other-team canary);
3 = an empty team; 4 = one legacy-format scan only; 5 = only a failed and a running scan.
Users: alice (member of 1, 3, 4, 5), bob (member of 2 only), carol (member of 1, session
inactive).
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
import sys
import warnings
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

# Importing the app chain reads credentials at import time; test values only, never real keys.
os.environ.setdefault("JWT_SECRET_KEY", "cbom-deliverables-route-test-secret")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "cbom-deliverables-route-test-refresh")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "DUMMYDUMMYDUMMY")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "dummydummydummy")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("RABBIT_ADMIN_USERNAME", "u")
os.environ.setdefault("RABBIT_ADMIN_PASSWORD", "p")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from jose import jwt as jose_jwt  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402
from starlette.requests import Request  # noqa: E402
from starlette.routing import Match  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.main import app  # noqa: E402
from backend.new_models import Scan, Team, TeamMembership, User  # noqa: E402
from backend.routers import cbom_deliverables as routes  # noqa: E402
from backend.utilities.auth import auth_utils  # noqa: E402
from backend.utilities.pdf.cbom_deliverables import DELIVERABLES  # noqa: E402
from backend.utilities.pdf.report_branding import REPORT_META  # noqa: E402

UTC = timezone.utc
NOW = datetime(2026, 10, 19, 12, 28, tzinfo=UTC)  # the fixture's frozen "now" (17:58 IST)
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "cbom_team_rollup_scans.json"

MANIFEST_PATH = "/{team_id}/cbom/deliverables"
PDF_PATH = "/{team_id}/cbom/deliverables/{slug}"
SLUGS = [
    "scope-baseline-register",
    "methodology-evidence-plan",
    "infrastructure-cloud-encryption-posture",
    "network-tls-protocol-assessment",
    "certificate-estate-register",
    "data-at-rest-encryption-assessment",
    "third-party-assurance-register",
    "pqc-migration-roadmap",
    "board-executive-report",
]
NUMBERS = dict(zip(SLUGS, [1, 3, 5, 6, 7, 9, 10, 15, 16], strict=True))
GENERIC_500 = {"detail": "Error generating deliverable, please try again later"}

# Strings that exist ONLY in scans a team-1 document must never read (plan Appendix B).
CANARIES = (
    "NOT-A-REAL-TOKEN-CANARY",  # userinfo of scan 8's repo URL
    "x-access-token",
    "FAILED-SCAN-CANARY",
    "QUEUED-SCAN-CANARY",
    "RUNNING-SCAN-CANARY",
    "SBOM-TYPE-CANARY",
    "other-team-canary",
)
FOREIGN_IDENTITY = ("clinithread", "AI BOM", "FDA", "HIPAA", "Traceback")

TEAM_ONE, TEAM_OTHER, TEAM_EMPTY, TEAM_LEGACY, TEAM_FAILED = 1, 2, 3, 4, 5
LEGACY_SCAN_ID, FAILED_ONLY_IDS = 201, (301, 302)
USERS = {  # who -> (email, session_active, team ids)
    "alice": ("alice@e2e.test", True, (TEAM_ONE, TEAM_EMPTY, TEAM_LEGACY, TEAM_FAILED)),
    "bob": ("bob@other.test", True, (TEAM_OTHER,)),
    "carol": ("carol@e2e.test", False, (TEAM_ONE,)),
}


# ---------------------------------------------------------------------------------------------
# PDF inspection (pure Python content-stream reader)
# ---------------------------------------------------------------------------------------------
_LITERAL = rb"\((?:\\.|[^\\()])*\)"
_TEXT_OPS = rb"(?<![A-Za-z0-9/])(?:T\*|Td|TD|Tm|ET|BT)(?![A-Za-z0-9*])"
_TOKEN_RE = re.compile(_LITERAL + rb"|" + _TEXT_OPS, re.S)
_SIMPLE_ESCAPES = {110: b"\n", 114: b"\r", 116: b"\t", 98: b"\b", 102: b"\f"}


def _unescape(literal: bytes) -> str:
    body, out, i = literal[1:-1], bytearray(), 0
    while i < len(body):
        c = body[i]
        if c != 0x5C or i + 1 >= len(body):
            out.append(c)
            i += 1
            continue
        nxt = body[i + 1]
        if 0x30 <= nxt <= 0x37:  # octal escape, up to three digits
            j, digits = i + 1, b""
            while j < len(body) and len(digits) < 3 and 0x30 <= body[j] <= 0x37:
                digits += bytes([body[j]])
                j += 1
            out.append(int(digits, 8) & 0xFF)
            i = j
        elif nxt in (0x0A, 0x0D):
            i += 2
        else:
            out += _SIMPLE_ESCAPES.get(nxt, bytes([nxt]))
            i += 2
    return out.decode("cp1252", errors="replace")


def _streams(raw: bytes) -> list[bytes]:
    chunks: list[bytes] = []
    for match in re.finditer(rb"(?<!end)stream\r?\n(.*?)endstream", raw, re.S):
        data = match.group(1).strip()
        with contextlib.suppress(ValueError, OverflowError):
            data = base64.a85decode(data, adobe=True)
        with contextlib.suppress(zlib.error):
            data = zlib.decompress(data)
        chunks.append(data)
    return chunks


def text_lines(raw: bytes) -> list[str]:
    lines: list[str] = []
    for chunk in _streams(raw):
        if b" Tf" not in chunk or b"BT" not in chunk:
            continue
        current: list[str] = []
        for token in _TOKEN_RE.finditer(chunk):
            value = token.group(0)
            if value.startswith(b"("):
                current.append(_unescape(value))
            elif current:
                lines.append("".join(current))
                current = []
        if current:
            lines.append("".join(current))
    return lines


def full_text(raw: bytes) -> str:
    return "\n".join(text_lines(raw))


def squash(value: str) -> str:
    return re.sub(r"\s+", "", value)


def info_field(raw: bytes, name: str) -> str | None:
    match = re.search(rb"/" + name.encode() + rb"\s*\(((?:\\.|[^\\()])*)\)", raw)
    return _unescape(b"(" + match.group(1) + b")") if match else None


# ---------------------------------------------------------------------------------------------
# The seeded world
# ---------------------------------------------------------------------------------------------
def _ts(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _naive(text: str) -> datetime:
    """Postgres / SQLite hand datetimes back naive UTC; seed them the same way."""
    return _ts(text).replace(tzinfo=None)


def _fixture() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def expected_fingerprint(scans: list[dict[str, Any]], included_ids: list[int]) -> str:
    """The documented formula (plan 4.8 / ``fold_scans``), applied to the fixture JSON."""
    stamped = ",".join(
        f"{s['id']}:{_ts(s['last_updated']).isoformat()}"
        for s in sorted(scans, key=lambda scan: scan["id"])
        if s["id"] in included_ids
    )
    return hashlib.sha256(f"cbom-team-rollup|{stamped}".encode()).hexdigest()[:12]


@dataclass
class World:
    engine: Any
    user_ids: dict[str, int]
    fixture: dict[str, Any]


def build_world(root: Path) -> World:
    data = _fixture()
    engine = create_engine(
        f"sqlite:///{root / 'cbom_deliverables_world.db'}",
        connect_args={"check_same_thread": False},
    )
    SQLModel.metadata.create_all(engine)
    names = {
        TEAM_ONE: data["team"]["name"],
        **{t["id"]: t["name"] for t in data["other_teams"]},
        TEAM_LEGACY: "Legacy Only Team",
        TEAM_FAILED: "Failed Only Team",
    }
    legacy = next(s for s in data["scans"] if s["id"] == 8)
    extra = [
        {**legacy, "id": LEGACY_SCAN_ID, "team_id": TEAM_LEGACY},
        {
            "id": FAILED_ONLY_IDS[0], "team_id": TEAM_FAILED, "scan_type": "cbom",
            "title": "only-failure", "status": "failure", "scan_metadata": {"branch": "main"},
            "created_at": "2026-10-10T09:00:00Z", "last_updated": "2026-10-10T09:05:00Z",
            "scan_data": {"results": [{"title": "FAILED-ONLY-CANARY"}]},
        },
        {
            "id": FAILED_ONLY_IDS[1], "team_id": TEAM_FAILED, "scan_type": "cbom",
            "title": "only-running", "status": "started", "scan_metadata": {"branch": "main"},
            "created_at": "2026-10-11T09:00:00Z", "last_updated": "2026-10-11T09:05:00Z",
            "scan_data": {},
        },
    ]  # fmt: skip
    user_ids: dict[str, int] = {}
    with Session(engine) as session:
        for team_id, name in names.items():
            session.add(Team(id=team_id, name=name, credit_balance=0.0))
        session.commit()
        for who, (email, active, team_ids) in USERS.items():
            user = User(
                email=email, password="x", first_name=who, last_name="tester",
                profile_photo=None, session_active=active, default_team_id=team_ids[0],
            )  # fmt: skip
            session.add(user)
            session.commit()
            session.refresh(user)
            user_ids[who] = user.id
            for team_id in team_ids:
                session.add(TeamMembership(team_id=team_id, user_id=user.id, role="member"))
        session.commit()
        for scan in [*data["scans"], *extra]:
            owner = user_ids["bob"] if scan["team_id"] == TEAM_OTHER else user_ids["alice"]
            session.add(
                Scan(
                    id=scan["id"], team_id=scan["team_id"], owner_user_id=owner,
                    scan_type=scan["scan_type"], title=scan["title"],
                    scan_status=scan["status"], created_at=_naive(scan["created_at"]),
                    last_updated=_naive(scan["last_updated"]),
                    scan_metadata=scan["scan_metadata"], scan_data=scan["scan_data"],
                )
            )  # fmt: skip
        session.commit()
    return World(engine=engine, user_ids=user_ids, fixture=data)


class Api:
    """A TestClient bound to a world; ``get`` authenticates as ``who`` (``None`` = no header)."""

    def __init__(self, world: World) -> None:
        self.world = world
        self.client = TestClient(app)
        self._tokens: dict[str, str] = {}

    def token(self, who: str) -> str:
        """One token per user per test: the rate limiter keys on the token, so a token minted
        again after a second boundary would silently start a new budget."""
        if who not in self._tokens:
            self._tokens[who] = auth_utils.create_access_token(USERS[who][0])
        return self._tokens[who]

    def get(self, url: str, who: str | None = "alice", headers: dict[str, str] | None = None):
        merged = dict(headers or {})
        if who is not None:
            merged.setdefault("Authorization", f"Bearer {self.token(who)}")
        return self.client.get(url, headers=merged)

    def forged(self, **claims: Any) -> str:
        secret = claims.pop("secret", auth_utils.JWT_SECRET_KEY)
        return jose_jwt.encode(claims, secret, auth_utils.ALGORITHM)


def make_api(world: World, monkeypatch) -> Api:
    """Point the router at the world's engine, freeze its clock and clear the rate limiter."""
    monkeypatch.setattr(routes, "get_db", lambda: world.engine)
    monkeypatch.setattr(routes, "_utcnow", lambda: NOW)
    routes.limiter.requests.clear()
    return Api(world)


@pytest.fixture(scope="module")
def world(tmp_path_factory) -> World:
    return build_world(tmp_path_factory.mktemp("cbom_deliverables"))


@pytest.fixture(autouse=True)
def _runtime_guard(monkeypatch):
    """Every route test runs offline: no connect, no DNS, no process, no SDK (T-NOLLM-3)."""
    from backend.tests.test_cbom_deliverables_no_llm import block_network, plant_tripwires

    block_network(monkeypatch)
    plant_tripwires(monkeypatch)


@pytest.fixture()
def api(world, monkeypatch):
    client = make_api(world, monkeypatch)
    yield client
    routes.limiter.requests.clear()


def test_every_route_test_really_runs_under_the_runtime_guard():
    """Control: the autouse fixture is live, so a connection or an SDK import would fail."""
    import socket
    import subprocess

    with pytest.raises(AssertionError, match="network/process access attempted"):
        socket.create_connection(("127.0.0.1", 9))
    with pytest.raises(AssertionError, match="network/process access attempted"):
        subprocess.Popen([sys.executable, "-c", "pass"])
    for name in ("boto3", "openai", "anthropic", "langchain_aws", "requests", "httpx"):
        with pytest.raises(AssertionError, match="forbidden module"):
            sys.modules[name].anything  # noqa: B018 - the attribute access IS the test


def manifest_url(team_id: int) -> str:
    return f"/{team_id}/cbom/deliverables"


def pdf_url(team_id: int, slug: str) -> str:
    return f"/{team_id}/cbom/deliverables/{slug}"


# ---------------------------------------------------------------------------------------------
# 200: the six documents
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("slug", SLUGS)
def test_each_slug_returns_its_own_pdf_with_the_contract_headers(api, world, slug):
    scans = [s for s in world.fixture["scans"] if s["team_id"] == TEAM_ONE]
    fingerprint = expected_fingerprint(scans, [1, 2, 3, 4, 5, 6, 7, 8])

    response = api.get(pdf_url(TEAM_ONE, slug))

    assert response.status_code == 200, response.text[:300]
    body = response.content
    assert response.headers["content-type"] == "application/pdf"
    assert body.startswith(b"%PDF-") and body.rstrip().endswith(b"%%EOF") and len(body) > 3000
    assert response.headers["content-disposition"] == (
        f'attachment; filename="cbom-{slug}-team1-20261019.pdf"'
    )
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-cbom-scans-included"] == "8"
    assert response.headers["x-cbom-sources"] == "7"
    assert response.headers["x-cbom-fidelity"] == "mixed"
    assert response.headers["x-cbom-fingerprint"] == fingerprint
    assert response.headers["x-cbom-posture"] == "not_assessed"
    assert int(response.headers["content-length"]) == len(body)

    text = squash(full_text(body))  # cells wrap differently in portrait and landscape
    for needle in (
        # the right document: its own number, the data fingerprint and its own footer label
        f"CBOM-D{NUMBERS[slug]:02d}-T1-20261019-{fingerprint[:8]}",
        fingerprint,
        REPORT_META[DELIVERABLES[slug].report_key]["footer_label"],
        "2026-10-19 12:28 UTC (17:58 IST)",
        "2026-08-20 to 2026-10-17 (UTC)",  # oldest and newest included scan dates
        "Scans: 8 included of 9 eligible",
        "excluded: 1 failed, 2 not completed, 1 without data",
        "Sources: 7",
        "Fidelity: 7 full / 1 legacy-format",
    ):
        assert squash(needle) in text, needle
    assert (info_field(body, "Title") or "").startswith(DELIVERABLES[slug].title)


def test_the_same_request_twice_gives_byte_identical_pdfs(api):
    first = api.get(pdf_url(TEAM_ONE, "certificate-estate-register")).content
    second = api.get(pdf_url(TEAM_ONE, "certificate-estate-register")).content
    assert first == second


@pytest.mark.parametrize("slug", SLUGS)
def test_no_canary_or_foreign_identity_reaches_any_team_one_pdf(api, slug):
    body = api.get(pdf_url(TEAM_ONE, slug)).content
    text = full_text(body)
    assert len(text) > 500, "the text reader found nothing: this test would pass vacuously"
    for canary in CANARIES:
        assert canary not in text, canary
        assert canary.encode() not in body, canary
    for banned in FOREIGN_IDENTITY:
        assert banned not in text, banned


def test_tenants_are_isolated_in_both_directions(api):
    slug = "certificate-estate-register"
    mine = squash(full_text(api.get(pdf_url(TEAM_ONE, slug)).content))
    theirs = squash(full_text(api.get(pdf_url(TEAM_OTHER, slug), who="bob").content))
    assert "other-team-canary" in theirs, "the canary must be reachable by its owner"
    assert "other-team-canary" not in mine
    assert "synthetic-crypto-app.test" in mine
    assert "synthetic-crypto-app.test" not in theirs
    assert "E2EDemoTeam" in mine and "E2EDemoTeam" not in theirs


# ---------------------------------------------------------------------------------------------
# 200: empty, failed-only and legacy-only teams are data conditions, never 4xx
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("slug", SLUGS)
def test_an_empty_team_gets_a_200_pdf_with_the_banner(api, slug):
    response = api.get(pdf_url(TEAM_EMPTY, slug))
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["x-cbom-scans-included"] == "0"
    assert response.headers["x-cbom-sources"] == "0"
    assert response.headers["x-cbom-fidelity"] == "none"
    assert response.headers["x-cbom-posture"] == "none"
    text = full_text(response.content)
    assert "NO COMPLETED CBOM SCANS" in text
    assert "Empty Team (ID 3)" in text
    if slug == "board-executive-report":
        assert "NOT ASSESSED" in text
        assert "Low risk" not in text


@pytest.mark.parametrize("slug", ["scope-baseline-register", "board-executive-report"])
def test_a_team_with_only_failed_or_running_scans_gets_a_200_pdf_that_counts_them(api, slug):
    response = api.get(pdf_url(TEAM_FAILED, slug))
    assert response.status_code == 200
    assert response.headers["x-cbom-scans-included"] == "0"
    text = full_text(response.content)
    assert "NO COMPLETED CBOM SCANS" in text
    assert "excluded: 1 failed, 1 not completed, 0 without data" in text
    assert "FAILED-ONLY-CANARY" not in text


@pytest.mark.parametrize("slug", SLUGS)
def test_a_legacy_only_team_gets_a_200_pdf_with_the_reduced_fidelity_banner(api, slug):
    response = api.get(pdf_url(TEAM_LEGACY, slug))
    assert response.status_code == 200
    assert response.headers["x-cbom-scans-included"] == "1"
    assert response.headers["x-cbom-sources"] == "1"
    assert response.headers["x-cbom-fidelity"] == "reduced"
    text = full_text(response.content)
    assert "REDUCED-FIDELITY DATA" in text
    assert "NOT-A-REAL-TOKEN-CANARY" not in text and "x-access-token" not in text


def test_the_legacy_scan_url_is_sanitised_and_its_fingerprint_follows_the_documented_formula(
    api, world
):
    response = api.get(pdf_url(TEAM_LEGACY, "scope-baseline-register"))
    legacy = next(s for s in world.fixture["scans"] if s["id"] == 8)
    clone = {**legacy, "id": LEGACY_SCAN_ID}  # the seeded legacy-only team holds a copy of scan 8
    assert response.headers["x-cbom-fingerprint"] == expected_fingerprint(
        [clone], [LEGACY_SCAN_ID]
    )
    text = squash(full_text(response.content))
    assert "github.com/e2e-demo/legacy-billing" in text, "the source must still be listed"
    assert "NOT-A-REAL-TOKEN-CANARY" not in text and "x-access-token" not in text


# ---------------------------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------------------------
def test_manifest_shape_order_and_basis_for_the_appendix_b_team(api):
    response = api.get(manifest_url(TEAM_ONE))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    manifest = response.json()
    assert list(manifest) == ["team_id", "generated_at", "basis", "deliverables"]
    assert manifest["team_id"] == TEAM_ONE
    assert manifest["generated_at"] == "2026-10-19T12:28:00Z"
    # heads only: 9 successful scans (the success-but-empty one is only discovered in pass 2),
    # 8 sources among them, 1 failure and 2 not-completed scans
    assert manifest["basis"] == {
        "eligible": 9,
        "included_hint": 9,
        "sources": 8,
        "excluded": {"failure": 1, "not_completed": 2},
    }
    rows = manifest["deliverables"]
    assert [r["slug"] for r in rows] == SLUGS
    # NUMBERS is the module's own slug -> number table (it grew with D05, D06 and D09; this literal had not)
    assert [r["number"] for r in rows] == [NUMBERS[s] for s in SLUGS]
    for row in rows:
        spec = DELIVERABLES[row["slug"]]
        assert set(row) == {
            "slug", "number", "title", "description", "format", "available", "reason",
        }  # fmt: skip
        assert row["format"] == "pdf"
        assert row["title"] == spec.title and row["description"] == spec.description
        assert row["available"] is True and row["reason"] is None


def test_manifest_marks_only_the_data_dependent_documents_unavailable_for_an_empty_team(api):
    manifest = api.get(manifest_url(TEAM_EMPTY)).json()
    assert manifest["basis"] == {
        "eligible": 0,
        "included_hint": 0,
        "sources": 0,
        "excluded": {"failure": 0, "not_completed": 0},
    }
    flags = {r["slug"]: r for r in manifest["deliverables"]}
    for slug in ("certificate-estate-register", "pqc-migration-roadmap", "board-executive-report"):
        assert flags[slug]["available"] is False
        assert flags[slug]["reason"] and "scan" in flags[slug]["reason"].lower()
    always = (
        "scope-baseline-register",
        "methodology-evidence-plan",
        "third-party-assurance-register",
    )
    for slug in always:
        assert flags[slug]["available"] is True and flags[slug]["reason"] is None


def test_manifest_counts_failed_and_running_scans_without_making_a_team_available(api):
    manifest = api.get(manifest_url(TEAM_FAILED)).json()
    assert manifest["basis"]["eligible"] == 0
    assert manifest["basis"]["excluded"] == {"failure": 1, "not_completed": 1}
    availability = {r["slug"]: r["available"] for r in manifest["deliverables"]}
    assert availability["certificate-estate-register"] is False
    assert availability["pqc-migration-roadmap"] is False
    assert availability["board-executive-report"] is False
    assert availability["scope-baseline-register"] is True


def test_manifest_for_a_legacy_only_team_has_everything_available(api):
    manifest = api.get(manifest_url(TEAM_LEGACY)).json()
    assert manifest["basis"]["eligible"] == 1 and manifest["basis"]["sources"] == 1
    assert all(r["available"] for r in manifest["deliverables"])


def test_manifest_reads_no_scan_data(api, monkeypatch):
    """Heads only: the manifest must work even when the blob loader is unusable."""

    def explode(*_args, **_kwargs):
        raise AssertionError("the manifest must not load scan blobs")

    monkeypatch.setattr(routes, "load_team_cbom_view", explode)
    assert api.get(manifest_url(TEAM_ONE)).status_code == 200


# ---------------------------------------------------------------------------------------------
# 404 / 401 / 403 / 422 / 405
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "slug",
    [
        "not-a-document",
        "CERTIFICATE-ESTATE-REGISTER",
        "certificate-estate-register.pdf",
        "certificate-estate-register%20",
        "%3Cscript%3Ealert(1)%3C",
        "1",
        "x" * 300,
    ],
)
def test_unknown_slug_is_404_and_is_not_echoed(api, slug):
    response = api.get(pdf_url(TEAM_ONE, slug))
    assert response.status_code == 404
    assert response.json() == {"detail": "Unknown deliverable"}
    assert "script" not in response.text and "xxx" not in response.text


@pytest.mark.parametrize("slug", ["..%2F..%2Fetc%2Fpasswd", "a%2Fb", "a/b"])
def test_slugs_that_contain_a_slash_never_reach_the_registry(api, slug):
    response = api.get(pdf_url(TEAM_ONE, slug))
    assert response.status_code == 404
    assert "passwd" not in response.text and not response.content.startswith(b"%PDF")


def test_unknown_slug_for_a_non_member_is_a_403_not_a_404(api):
    assert api.get(pdf_url(TEAM_ONE, "not-a-document"), who="bob").status_code == 403


def _auth_headers(api: Api) -> dict[str, dict[str, str]]:
    """Authorization headers that must all be refused with 401 (one entry per failure mode)."""
    now = datetime.now(UTC)  # token expiry is checked against the real clock by auth_utils
    soon = int((now + timedelta(minutes=5)).timestamp())
    past = int((now - timedelta(minutes=5)).timestamp())
    email = USERS["alice"][0]

    def bearer(**claims: Any) -> dict[str, str]:
        return {"Authorization": "Bearer " + api.forged(**claims)}

    return {
        "empty header": {"Authorization": ""},
        "wrong scheme": {"Authorization": "Token abc"},
        "scheme only": {"Authorization": "Bearer"},
        "too many parts": {"Authorization": "Bearer a b"},
        "garbage token": {"Authorization": "Bearer not.a.jwt"},
        "wrong secret": bearer(sub=email, exp=soon, secret="not-the-server-secret"),
        "expired": bearer(sub=email, exp=past),
        "unknown user": bearer(sub="nobody@nowhere.test", exp=soon),
    }


@pytest.mark.parametrize(
    "case",
    ["no header", "empty header", "wrong scheme", "scheme only", "too many parts",
     "garbage token", "wrong secret", "expired", "unknown user"],
)  # fmt: skip
@pytest.mark.parametrize("url", [manifest_url(TEAM_ONE), pdf_url(TEAM_ONE, SLUGS[2])])
def test_missing_or_invalid_bearer_is_401(api, case, url):
    headers = {} if case == "no header" else _auth_headers(api)[case]
    response = api.get(url, who=None, headers=headers)
    assert response.status_code == 401, (case, response.text[:200])
    assert response.headers["content-type"].startswith("application/json")
    assert "detail" in response.json()
    assert not response.content.startswith(b"%PDF")


@pytest.mark.xfail(
    strict=True,
    reason=(
        "known gap in pre-existing auth_utils (not changed by this feature): a validly signed "
        "token WITHOUT an exp claim raises TypeError, which these routes turn into the generic "
        "500. Only the server's own signing key can mint such a token. Remove this marker "
        "when auth_utils answers 401."
    ),
)
def test_a_signed_token_without_an_exp_claim_should_be_401(api):
    token = api.forged(sub=USERS["alice"][0])
    headers = {"Authorization": f"Bearer {token}"}
    response = api.get(manifest_url(TEAM_ONE), who=None, headers=headers)
    assert response.status_code == 401


@pytest.mark.parametrize("url", [manifest_url(TEAM_ONE), pdf_url(TEAM_ONE, SLUGS[2])])
def test_a_signed_in_non_member_is_403(api, url):
    response = api.get(url, who="bob")
    assert response.status_code == 403
    assert response.json() == {"detail": "User is not in team"}


def test_a_team_that_does_not_exist_is_a_403_too(api):
    response = api.get(manifest_url(999_999))
    assert response.status_code == 403
    assert "not found" not in response.text.lower()


def test_an_inactive_session_is_403(api):
    response = api.get(pdf_url(TEAM_ONE, SLUGS[0]), who="carol")
    assert response.status_code == 403
    assert response.json() == {"detail": "Session not active"}


@pytest.mark.parametrize("team", ["abc", "0", "-1", "99999999999", "1.5"])
def test_a_malformed_team_id_is_a_422_not_a_500(api, team):
    assert api.get(f"/{team}/cbom/deliverables").status_code == 422
    assert api.get(f"/{team}/cbom/deliverables/{SLUGS[0]}").status_code == 422


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_only_get_is_allowed(api, method):
    response = getattr(api.client, method)(
        pdf_url(TEAM_ONE, SLUGS[0]), headers={"Authorization": f"Bearer {api.token('alice')}"}
    )
    assert response.status_code == 405
    assert response.headers["allow"] == "GET"


# ---------------------------------------------------------------------------------------------
# 429: a REAL, per-token, decorator-level limiter
# ---------------------------------------------------------------------------------------------
def test_the_default_limit_is_thirty_requests_per_sixty_seconds(api):
    assert (routes.limiter.times, routes.limiter.seconds) == (30, 60)
    statuses = [api.get(manifest_url(TEAM_ONE)).status_code for _ in range(31)]
    assert statuses == [200] * 30 + [429]


def test_over_the_limit_is_429_with_retry_after_and_no_pdf(api, monkeypatch):
    monkeypatch.setattr(routes.limiter, "times", 2)
    slug = SLUGS[0]
    assert [api.get(pdf_url(TEAM_ONE, slug)).status_code for _ in range(2)] == [200, 200]
    blocked = api.get(pdf_url(TEAM_ONE, slug))
    assert blocked.status_code == 429
    assert blocked.json() == {"detail": "Too Many Requests"}
    assert 0 < int(blocked.headers["retry-after"]) <= 60
    assert not blocked.content.startswith(b"%PDF")
    assert api.get(manifest_url(TEAM_ONE)).status_code == 429, "one budget covers both routes"


def test_the_limit_is_per_token_not_per_address(api, monkeypatch):
    monkeypatch.setattr(routes.limiter, "times", 2)
    assert [api.get(manifest_url(TEAM_ONE)).status_code for _ in range(3)] == [200, 200, 429]
    other_user = api.get(manifest_url(TEAM_OTHER), who="bob")
    assert other_user.status_code == 200, "another token must have its own budget"


def test_invalid_tokens_are_throttled_before_authentication(api, monkeypatch):
    monkeypatch.setattr(routes.limiter, "times", 2)
    bad = {"Authorization": "Bearer not.a.jwt"}
    codes = [api.get(manifest_url(TEAM_ONE), who=None, headers=bad).status_code for _ in range(3)]
    assert codes == [401, 401, 429]


def _request(authorization: str | None) -> Request:
    headers = [] if authorization is None else [(b"authorization", authorization.encode())]
    scope = {"type": "http", "method": "GET", "path": "/", "headers": headers, "query_string": b""}
    return Request(scope)


def test_the_limiter_key_is_a_token_hash_that_never_contains_the_token():
    key_func = routes.limiter.key_func
    assert key_func is not None
    token = "eyJhbGciOi.secret-payload.signature"
    key = key_func(_request(f"Bearer {token}"))
    assert key == hashlib.sha256(token.encode()).hexdigest()[:16]
    assert re.fullmatch(r"[0-9a-f]{16}", key)
    assert "secret" not in key and "eyJ" not in key
    assert key_func(_request(f"Bearer {token}x")) != key
    # the scheme may be written in any letter case: still ONE budget per token
    assert key_func(_request(f"bearer {token}")) == key_func(_request(f"BEARER {token}")) == key
    # anything that is not a well-formed bearer header is hashed as it is (it will get a 401)
    assert key_func(_request("Token abc")) == hashlib.sha256(b"Token abc").hexdigest()[:16]
    assert key_func(_request(None)) == hashlib.sha256(b"").hexdigest()[:16]


def test_changing_the_scheme_case_does_not_buy_a_second_budget(api, monkeypatch):
    monkeypatch.setattr(routes.limiter, "times", 2)
    token = api.token("alice")
    codes = [
        api.get(manifest_url(TEAM_ONE), who=None, headers={"Authorization": f"{scheme} {token}"})
        .status_code
        for scheme in ("Bearer", "bearer", "BEARER", "bEaReR")
    ]
    assert codes == [200, 200, 429, 429]


def test_the_limiter_is_a_decorator_level_dependency_not_a_parameter_default():
    for path in (MANIFEST_PATH, PDF_PATH):
        route = next(r for r in app.routes if getattr(r, "path", None) == path)
        assert [d.dependency for d in route.dependencies] == [routes.limiter]
        assert routes.limiter in [d.call for d in route.dependant.dependencies]
        assert "dependencies" not in {p.name for p in route.dependant.query_params}


def test_openapi_has_both_paths_without_a_dependencies_query_param():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # the pre-existing routers warn about their own defaults
        spec = app.openapi()
    for path in (MANIFEST_PATH, PDF_PATH):
        operation = spec["paths"][path]["get"]
        names = {p["name"].lower() for p in operation.get("parameters", [])}
        assert "dependencies" not in names, path
        assert {"team_id", "authorization"} <= names
        assert {"200", "401", "403", "429", "500"} <= set(operation["responses"])
    assert "slug" in {p["name"] for p in spec["paths"][PDF_PATH]["get"]["parameters"]}
    assert "404" in spec["paths"][PDF_PATH]["get"]["responses"]
    assert "application/pdf" in spec["paths"][PDF_PATH]["get"]["responses"]["200"]["content"]
    assert set(spec["paths"][PDF_PATH]["get"]) >= {"summary", "description"}


def test_the_router_alone_generates_a_warning_free_openapi_schema():
    mini = FastAPI()
    mini.include_router(routes.router)
    with warnings.catch_warnings():
        warnings.simplefilter("error", UserWarning)  # PydanticJsonSchemaWarning is a UserWarning
        spec = mini.openapi()
    assert set(spec["paths"]) == {MANIFEST_PATH, PDF_PATH}
    assert all(set(item) == {"get"} for item in spec["paths"].values())


def test_both_paths_resolve_to_this_router_and_no_earlier_route_shadows_them():
    for concrete, template in (
        ("/1/cbom/deliverables", MANIFEST_PATH),
        ("/1/cbom/deliverables/board-executive-report", PDF_PATH),
        ("/1/cbom/deliverables/anything-else", PDF_PATH),
    ):
        scope = {"type": "http", "method": "GET", "path": concrete, "root_path": "", "headers": []}
        first = next(r for r in app.router.routes if r.matches(scope)[0] == Match.FULL)
        assert first.path == template, (concrete, first.path)


# ---------------------------------------------------------------------------------------------
# 500: generic body, detail only in the server log
# ---------------------------------------------------------------------------------------------
def test_a_failing_builder_gives_a_generic_500_and_logs_the_detail_server_side(
    api, monkeypatch, capsys
):
    slug = "certificate-estate-register"

    def boom(_view):
        raise RuntimeError("boom-secret-detail at /srv/app/secret_module.py")

    monkeypatch.setitem(DELIVERABLES, slug, replace(DELIVERABLES[slug], build=boom))
    response = api.get(pdf_url(TEAM_ONE, slug))
    assert response.status_code == 500
    assert response.json() == GENERIC_500
    for leak in ("boom-secret-detail", "RuntimeError", "Traceback", "/srv/app", ".py"):
        assert leak not in response.text
    logged = capsys.readouterr()
    server_log = logged.out + logged.err
    assert "RuntimeError" in server_log and "team=1" in server_log


def test_a_failing_loader_gives_the_same_generic_500(api, monkeypatch):
    def boom(*_args, **_kwargs):
        raise ValueError("database exploded: password=hunter2")

    monkeypatch.setattr(routes, "load_team_cbom_view", boom)
    response = api.get(pdf_url(TEAM_ONE, SLUGS[0]))
    assert response.status_code == 500 and response.json() == GENERIC_500
    assert "hunter2" not in response.text


def test_a_failing_manifest_query_gives_the_same_generic_500(api, monkeypatch):
    def boom(*_args, **_kwargs):
        raise OSError("disk on fire")

    monkeypatch.setattr(routes, "_load_heads", boom)
    response = api.get(manifest_url(TEAM_ONE))
    assert response.status_code == 500 and response.json() == GENERIC_500
    assert "fire" not in response.text


def test_an_unreachable_database_gives_the_same_generic_500(api, monkeypatch):
    def boom():
        raise RuntimeError("connection to server at 10.0.0.5 failed")

    monkeypatch.setattr(routes, "get_db", boom)
    response = api.get(manifest_url(TEAM_ONE))
    assert response.status_code == 500 and response.json() == GENERIC_500
    assert "10.0.0.5" not in response.text


def test_auth_failures_stay_401_403_even_when_the_builder_would_fail(api, monkeypatch):
    monkeypatch.setitem(
        DELIVERABLES, SLUGS[0], replace(DELIVERABLES[SLUGS[0]], build=lambda _v: 1 / 0)
    )
    assert api.get(pdf_url(TEAM_ONE, SLUGS[0]), who=None).status_code == 401
    assert api.get(pdf_url(TEAM_ONE, SLUGS[0]), who="bob").status_code == 403


# ---------------------------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------------------------
def test_five_concurrent_requests_all_succeed_with_identical_documents(api):
    token = api.token("alice")
    slug = "board-executive-report"

    def fetch(_index: int):
        client = TestClient(app)
        return client.get(pdf_url(TEAM_ONE, slug), headers={"Authorization": f"Bearer {token}"})

    with ThreadPoolExecutor(max_workers=5) as pool:
        responses = list(pool.map(fetch, range(5)))
    assert [r.status_code for r in responses] == [200] * 5
    assert len({r.content for r in responses}) == 1, "concurrent builds must be deterministic"
