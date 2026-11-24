"""FIX-A3 (SOW audit A-11): the team's regulated-entity type selects the RBI instrument the regulatory mapping cites.

The client is an NBFC: the Commercial Banks Directions 2026 do not bind it. The type is a team setting (CBOM settings,
``regulated_entity``: nbfc / bank / other; NBFC when not set), stored beside the Mosca inputs without a migration, and
the team deliverables read it through ``load_team_cbom_view``.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.utilities.cbom_sources import regulated_entity  # noqa: E402
from sqlmodel import Session  # noqa: E402
from test_cbom_sources_api import api, world  # noqa: E402,F401  (shared fixtures)

SETTINGS = "/1/cbom/sources/settings"


def test_default_is_nbfc_and_an_admin_can_switch_to_bank_and_back(api, world):  # noqa: F811  (pytest fixtures)
    assert api("GET", SETTINGS).json()["settings"]["regulated_entity"] == "nbfc"
    r = api("PATCH", SETTINGS, json={"regulated_entity": "bank"})
    assert r.status_code == 200, r.text
    assert r.json()["settings"]["regulated_entity"] == "bank"
    assert api("GET", SETTINGS).json()["settings"]["regulated_entity"] == "bank"
    assert api("PATCH", SETTINGS, json={"regulated_entity": "nbfc"}).json()["settings"]["regulated_entity"] == "nbfc"


def test_the_setting_and_the_mosca_inputs_do_not_overwrite_each_other(api, world):  # noqa: F811  (pytest fixtures)
    mosca = {"data_shelf_life_years": 10, "migration_years": 5, "threat_years": 12}
    assert api("PATCH", SETTINGS, json={"risk_model": mosca}).status_code == 200
    got = api("PATCH", SETTINGS, json={"regulated_entity": "other"}).json()["settings"]
    assert got["regulated_entity"] == "other" and got["risk_model"] == mosca
    got = api("PATCH", SETTINGS, json={"risk_model": {"threat_years": 15}}).json()["settings"]
    assert got["regulated_entity"] == "other" and got["risk_model"]["threat_years"] == 15
    got = api("PATCH", SETTINGS, json={"risk_model": None}).json()["settings"]  # clears the three Mosca inputs only
    assert got["regulated_entity"] == "other"
    assert got["risk_model"] == {"data_shelf_life_years": None, "migration_years": None, "threat_years": None}


def test_an_unknown_entity_type_is_refused_and_a_member_cannot_change_it(api, world):  # noqa: F811  (pytest fixtures)
    assert api("PATCH", SETTINGS, json={"regulated_entity": "insurer"}).status_code == 400  # the API's validation code
    assert api("PATCH", SETTINGS, "bob", json={"regulated_entity": "bank"}).status_code == 403
    assert api("GET", SETTINGS).json()["settings"]["regulated_entity"] == "nbfc"


def test_the_team_view_reads_the_setting_without_creating_a_settings_row(api, world):  # noqa: F811  (pytest fixtures)
    engine, _ids = world
    with Session(engine) as session:
        assert regulated_entity.team_entity(session, 2) == "nbfc"  # team 2 has no settings row
    api("PATCH", SETTINGS, json={"regulated_entity": "bank"})
    with Session(engine) as session:
        assert regulated_entity.team_entity(session, 1) == "bank"
