"""#153: an Active Directory source (validation not built yet) showed "not_available" with the summary "None" in
the Last test column.  FIX-B3: the scan node now reads Active Directory over LDAPS / StartTLS, so the source is
created "never" tested, with a connection test like every collectable source."""
from __future__ import annotations

from tests import test_cbom_sources_api as H
from tests.test_cbom_sources_api import PASSWORD, enroll_node

api, world = H.api, H.world  # the harness's fixtures: SQLite + real routers + real JWTs
SUMMARY = None  # FIX-B3: collectable, so nothing to explain (before: "Validation for this source is not available yet")


def _ad(api, node_id: int, name: str = "corp-ad"):
    return api("POST", "/1/cbom/sources/items", json={
        "kind": "active_directory", "name": name, "node_id": node_id,
        "config": {"targets": ["dc01.bank.local"], "credential_type": "password", "login_user": "svc-zscbom"},
        "secrets": {"password": PASSWORD}})


def test_an_active_directory_source_is_collectable_and_testable(api, world):
    node_id, _token, _ = enroll_node(api)
    r = _ad(api, node_id)
    assert r.status_code == 201, r.text
    src = r.json()["source"]
    assert src["last_test_status"] == "never"
    assert src["last_test_summary"] == SUMMARY
    edited = api("PATCH", f"/1/cbom/sources/items/{src['id']}", headers={"If-Match": str(src.get("row_version", 1))},
                 json={
        "config": {"targets": ["dc02.bank.local"], "credential_type": "password",
                                                      "login_user": "svc-zscbom"},
                 "secrets": {"password": PASSWORD}})
    assert edited.status_code == 200, edited.text
    assert edited.json()["source"]["last_test_summary"] == SUMMARY
