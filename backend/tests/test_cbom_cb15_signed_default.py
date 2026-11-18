"""CB-15: signed scan nodes by default for new teams (DEVILS-ADVOCATE CB-15 failing-first: "an unsigned enrolment by a
new team is refused"), a team that already has unsigned nodes keeps them working, the operator switch, and the
upgrade path (reset, then enrol again with a signing node). The node side is the real scan-node client, as in
``test_cbom_node_auth.py``.

    cd backend && PYTHONPATH=..:../scan_node python -m pytest tests/test_cbom_cb15_signed_default.py -q
"""
from __future__ import annotations

import base64
import datetime as dt
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scan_node"))
from test_cbom_node_auth import _node_client, _registration  # noqa: E402
from test_cbom_sources_api import api, world  # noqa: E402,F401

from backend.new_models import CbomCollectionSettings, CbomScanNode  # noqa: E402
from backend.utilities.cbom_sources import settings as SETTINGS  # noqa: E402

_FIXTURES = (api, world)


@pytest.fixture()
def signed_default(monkeypatch):
    monkeypatch.setenv(SETTINGS.NEW_TEAMS_REQUIRE_SIGNED_ENV, "1")  # the product default (conftest turns it off)


def _settings(api, team=1, who="alice") -> dict:
    r = api("GET", f"/{team}/cbom/sources/settings", who)
    assert r.status_code == 200, r.text
    return r.json()["settings"]


def _unsigned_enroll(api, reg):
    return api("POST", "/cbom/node/enroll", None, json={"registration_token": reg, "hostname": "n1", "version": "1.0",
                                                        "clock": dt.datetime.utcnow().isoformat() + "Z"})


def _signed_enroll(api, reg):
    key = ed25519.Ed25519PrivateKey.generate()
    client = _node_client(api, key)
    return client.enroll({"registration_token": reg, "hostname": "n1", "version": "1.1",
                          "signing_public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode()})


def test_a_new_team_requires_signed_nodes_and_refuses_an_unsigned_enrolment(api, world, signed_default):
    assert _settings(api)["require_signed_nodes"] is True
    _node_id, reg = _registration(api, "dc-new-01")
    r = _unsigned_enroll(api, reg)
    assert r.status_code == 403 and r.headers.get("X-ZS-Refused") == "signed_nodes_required", r.text
    assert "signed scan nodes" in r.text
    data = _signed_enroll(api, reg)  # the refused enrolment did not spend the token: a signing node enrols with it
    assert data["node_token"].startswith("zsn_")
    nodes = api("GET", "/1/cbom/sources/nodes").json()["nodes"]
    assert [(n["name"], n["signing"]) for n in nodes] == [("dc-new-01", "required")]


def test_a_team_with_unsigned_nodes_keeps_them_working(api, world, signed_default):
    engine, _ = world
    with Session(engine) as s:  # an unsigned node enrolled before the team's settings row existed (before CB-15)
        s.add(CbomScanNode(team_id=1, name="old-dc", name_lower="old-dc", segment="DC", owner_user_id=1,
                           enrolled_at=dt.datetime.utcnow(), node_token_hash="x" * 64))
        s.commit()
        assert s.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == 1)).first() is None
    assert _settings(api)["require_signed_nodes"] is False
    _node_id, reg = _registration(api, "dc-legacy-02")
    assert _unsigned_enroll(api, reg).status_code == 200


def test_the_operator_can_turn_the_default_off(api, world, monkeypatch):
    monkeypatch.setenv(SETTINGS.NEW_TEAMS_REQUIRE_SIGNED_ENV, "0")
    assert _settings(api)["require_signed_nodes"] is False


def test_an_existing_team_keeps_its_setting(api, world, signed_default):
    engine, _ = world
    with Session(engine) as s:
        SETTINGS.get_or_create_settings(s, 1)
        row = s.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == 1)).one()
        row.require_signed_nodes = False  # chosen earlier (or made before CB-15)
        s.add(row)
        s.commit()
    assert _settings(api)["require_signed_nodes"] is False


def test_upgrade_path_reset_then_enrol_signed(api, world, monkeypatch):
    monkeypatch.setenv(SETTINGS.NEW_TEAMS_REQUIRE_SIGNED_ENV, "0")  # an older team with a legacy node
    node_id, reg = _registration(api, "dc-legacy-03")
    assert _unsigned_enroll(api, reg).status_code == 200
    node = next(n for n in api("GET", "/1/cbom/sources/nodes").json()["nodes"] if n["id"] == node_id)
    assert node["signing"] == "legacy"
    reset = api("POST", f"/1/cbom/sources/nodes/{node_id}/reset")
    assert reset.status_code == 200, reset.text
    _signed_enroll(api, reset.json()["registration_token"])
    node = next(n for n in api("GET", "/1/cbom/sources/nodes").json()["nodes"] if n["id"] == node_id)
    assert node["signing"] == "required"
    # with every node upgraded, the admin can require signing; a legacy enrolment is then refused
    s = _settings(api)
    r = api("PATCH", "/1/cbom/sources/settings", json={"require_signed_nodes": True, "expected_version": s["row_version"]})
    assert r.status_code == 200 and r.json()["settings"]["require_signed_nodes"] is True, r.text
    _nid, reg2 = _registration(api, "dc-legacy-04")
    assert _unsigned_enroll(api, reg2).status_code == 403
