"""Live HTTP path for GET /{team}/{type}/scan/{id}/export.

Hermetic SQLite + TestClient — no Postgres/network. Proves the router
allowlists DAST metadata, returns %PDF- for supported types, and maps
unsupported types to HTTP 400.
"""

from __future__ import annotations

import os
import re
import sys
import types
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

os.environ.setdefault("JWT_SECRET_KEY", "pdf-export-route-test-secret-not-for-prod")

from backend.main import app  # noqa: E402
from backend.new_models import Scan, Team, TeamMembership, User  # noqa: E402
from backend.tests.test_pdf_export_smoke import (  # noqa: E402
    _pdf_haystack,
    _worker_persist_payload,
)

_SCAN_TYPES = ("sast", "sbom_sca", "dast", "iac", "mcp", "llm", "cbom", "ai_bom")


@pytest.fixture()
def api(monkeypatch: pytest.MonkeyPatch, tmp_path):
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(eng)
    monkeypatch.setattr("backend.routers.scans.get_db", lambda: eng)
    monkeypatch.setattr("backend.routers.scans.check_if_user_is_in_team", lambda *_a, **_k: None)

    with Session(eng) as session:
        team = Team(name="pdf-export", credit_balance=10.0)
        session.add(team)
        session.commit()
        session.refresh(team)
        user = User(
            email="pdf-export@example.com",
            password="x",
            first_name="pdf",
            last_name="export",
            default_team_id=team.id,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        session.add(TeamMembership(team_id=team.id, user_id=user.id, role="admin"))
        now = datetime.now(timezone.utc)
        scan_ids: dict[str, int] = {}
        for scan_type in _SCAN_TYPES:
            scan = Scan(
                team_id=team.id,
                owner_user_id=user.id,
                scan_type=scan_type,
                title=f"{scan_type} export",
                scan_status="success",
                created_at=now,
                last_updated=now,
                scan_data=_worker_persist_payload(scan_type),
            )
            session.add(scan)
            session.commit()
            session.refresh(scan)
            scan_ids[scan_type] = scan.id

        leak = Scan(
            team_id=team.id,
            owner_user_id=user.id,
            scan_type="leakage",
            title="leakage export",
            scan_status="success",
            created_at=now,
            last_updated=now,
            scan_data={"results": [{"title": "secret found"}], "duration_of_scan": 12},
        )
        session.add(leak)
        pending = Scan(
            team_id=team.id,
            owner_user_id=user.id,
            scan_type="sast",
            title="pending sast",
            scan_status="pending",
            created_at=now,
            last_updated=now,
            scan_data=_worker_persist_payload("sast"),
        )
        session.add(pending)
        session.commit()
        session.refresh(leak)
        session.refresh(pending)
        ids = {
            "team_id": team.id,
            "user_id": user.id,
            "scan_ids": scan_ids,
            "leakage_id": leak.id,
            "pending_id": pending.id,
            "tmp": tmp_path,
        }

    async def fake_user(*_a, **_k):
        return types.SimpleNamespace(id=ids["user_id"], email="pdf-export@example.com")

    monkeypatch.setattr(
        "backend.routers.scans.get_user_from_header_or_raise_exception",
        fake_user,
    )
    yield TestClient(app), ids


def _export(http: TestClient, ids: dict, scan_type: str, scan_id: int):
    return http.get(
        f"/{ids['team_id']}/{scan_type}/scan/{scan_id}/export",
        headers={"Authorization": "Bearer test"},
    )


def test_export_route_returns_pdf_for_all_supported_types(api):
    http, ids = api
    for scan_type in _SCAN_TYPES:
        resp = _export(http, ids, scan_type, ids["scan_ids"][scan_type])
        assert resp.status_code == 200, f"{scan_type}: {resp.status_code} {resp.text[:400]}"
        assert resp.headers.get("content-type", "").startswith("application/pdf")
        assert resp.content[:5] == b"%PDF-"
        assert len(resp.content) > 1000


def test_export_route_dast_keeps_url_counts_and_strips_secrets(api):
    http, ids = api
    resp = _export(http, ids, "dast", ids["scan_ids"]["dast"])
    assert resp.status_code == 200
    out = ids["tmp"] / "dast_route.pdf"
    out.write_bytes(resp.content)
    haystack = _pdf_haystack(str(out))
    assert "URLs included" in haystack
    assert "Reflected XSS" in haystack
    assert "https://example.test/search" in haystack
    assert "AKIA" not in haystack


def test_export_route_sast_does_not_invent_unknown_or_clone_prefix(api):
    http, ids = api
    resp = _export(http, ids, "sast", ids["scan_ids"]["sast"])
    assert resp.status_code == 200
    out = ids["tmp"] / "sast_route.pdf"
    out.write_bytes(resp.content)
    haystack = _pdf_haystack(str(out))
    assert "Exposed Database URL in logs" in haystack
    assert "backup.py:12" in haystack
    assert "/tmp/repo_" not in haystack
    assert not re.search(r"\d+ U\b", haystack)


def test_unsupported_and_incomplete_scans_return_400(api):
    http, ids = api
    leak = _export(http, ids, "leakage", ids["leakage_id"])
    assert leak.status_code == 400, leak.text
    assert "not supported" in leak.json()["detail"].lower() or "leakage" in leak.json()["detail"].lower()
    pending = _export(http, ids, "sast", ids["pending_id"])
    assert pending.status_code == 400
    missing = _export(http, ids, "sast", 999_999)
    assert missing.status_code == 404
