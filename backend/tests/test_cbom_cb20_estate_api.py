"""CB-20 PR-1: the estate read API (``GET /{team}/cbom/estate`` keyset pages and filters, ``GET .../{asset_key}``),
team-scoped like the other CBOM routes. Failing-first on dev: the routes do not exist (404)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sqlmodel import Session  # noqa: E402

from test_cbom_cb20_estate import World, endpoint  # noqa: E402
from test_cbom_sources_api import api, world  # noqa: E402,F401

from backend.new_models import CbomCollectionSource  # noqa: E402


def _seed_api(engine) -> tuple[list[str], str]:
    w = World.__new__(World)
    w.engine, w.clock = engine, 0
    net, lin = w.source("network", "lab"), w.source("linux_servers", "linux")
    w.finalise(w.run({net: {"rows": [endpoint(f"10.0.0.{i}") for i in range(1, 6)]},
                      lin: {"rows": [{"type": "crypto_library", "target": "app", "location": "/usr/lib/libssl.so.3",
                                      "facts": {"name": "openssl"}}]}}))
    w.finalise(w.run({net: {"rows": [endpoint(f"10.0.0.{i}") for i in range(1, 5)]}}))
    with Session(engine) as s:
        ref = s.get(CbomCollectionSource, lin).source_uid
    return sorted(w.assets()), ref


def test_estate_api_pages_filters_and_reads_one_asset(world, api):  # noqa: F811
    engine, _ids = world
    keys, linux_ref = _seed_api(engine)
    assert len(keys) == 6
    got, after = [], None
    for _ in range(10):
        r = api("GET", "/1/cbom/estate", params={"limit": 4, **({"after": after} if after else {})})
        assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
        body = r.json()
        got += [i["asset_key"] for i in body["items"]]
        after = body["next"]
        if after is None:
            break
    assert got == keys
    removed = api("GET", "/1/cbom/estate", params={"presence": "removed"}).json()["items"]
    assert [(i["type"], i["presence"]) for i in removed] == [("tls_endpoint", "removed")]
    libs = api("GET", "/1/cbom/estate", params={"type": "crypto_library"}).json()["items"]
    assert len(libs) == 1 and libs[0]["key_kind"] == "source"
    by_source = api("GET", "/1/cbom/estate", params={"source": linux_ref}).json()["items"]
    assert [i["asset_key"] for i in by_source] == [libs[0]["asset_key"]]
    one = api("GET", f"/1/cbom/estate/{removed[0]['asset_key']}").json()
    assert one["presence"] == "removed" and [o["presence"] for o in one["observations"]] == ["removed"]
    assert set(one["observations"][0]) >= {"source_ref", "job_id", "asset_id", "observed_at", "provenance"}
    assert set(one["latest"]) == {"asset_id", "job_id", "run_id", "source_ref", "observed_at"}


def test_estate_api_is_team_scoped_and_validates(world, api):  # noqa: F811
    engine, _ids = world
    keys, _ref = _seed_api(engine)
    assert api("GET", f"/1/cbom/estate/{keys[0]}", who="carol").status_code == 403  # not a member of team 1
    assert api("GET", f"/2/cbom/estate/{keys[0]}", who="carol").status_code == 404  # another team's key
    assert api("GET", "/2/cbom/estate", who="carol").json()["items"] == []
    assert api("GET", "/1/cbom/estate/obs:" + "0" * 40).status_code == 404
    for bad in ("not-a-key", "obs:XYZ", "x" * 70):
        r = api("GET", f"/1/cbom/estate/{bad}")
        assert r.status_code in (400, 404) and bad not in r.text
    assert api("GET", "/1/cbom/estate", params={"limit": 501}).status_code == 400
    assert api("GET", "/1/cbom/estate", params={"presence": "gone"}).status_code == 400
    assert api("GET", "/1/cbom/estate", who=None).status_code in (401, 403)
