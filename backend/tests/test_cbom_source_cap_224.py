"""Issue #224: the per-team source cap is a deployment setting (with per-team overrides), it is shown on the Sources
pages, and the CMDB preview says how many sources will be created, how many are over the cap, and why."""
from __future__ import annotations

import sys
import time
from pathlib import Path

from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import api, enroll_node, linux_body, world  # noqa: E402,F401

from backend.new_models import CbomCollectionSource  # noqa: E402
from backend.utilities.cbom_sources import source_cap as CAP  # noqa: E402


def seed_sources(engine, team_id: int, node_id: int, n: int, prefix: str = "seed") -> None:
    """``n`` Linux server sources inserted directly (the API path is tested separately; this is bulk setup)."""
    with Session(engine) as s:
        for i in range(n):
            s.add(CbomCollectionSource(
                team_id=team_id, owner_user_id=1, kind="linux_servers", name=f"{prefix}-{i}", name_lower=f"{prefix}-{i}",
                node_id=node_id, config={"targets": [f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"],
                                         "credential_type": "node_key", "host_key_policy": "tofu"},
                secret_fields=[], last_test_status="never"))
        s.commit()


def count(engine, team_id: int = 1) -> int:
    with Session(engine) as s:
        return len(s.exec(select(CbomCollectionSource.id).where(CbomCollectionSource.team_id == team_id)).all())


# ----------------------------------------------------------------------------- the setting
def test_cap_default_env_and_per_team_override(monkeypatch):
    monkeypatch.delenv(CAP.ENV, raising=False)
    monkeypatch.delenv(CAP.ENV_TEAMS, raising=False)
    assert CAP.max_sources(1) == CAP.DEFAULT == 10_000  # was 500, hard-coded in two places
    monkeypatch.setenv(CAP.ENV, "25000")
    assert CAP.max_sources(1) == 25_000 and CAP.setting_name(1) == "CBOM_MAX_SOURCES"
    for bad in ("lots", "0", "-5", "2000001"):
        monkeypatch.setenv(CAP.ENV, bad)
        assert CAP.max_sources(1) == CAP.DEFAULT  # ignored (logged once), never a crash
    monkeypatch.setenv(CAP.ENV, "800")
    monkeypatch.setenv(CAP.ENV_TEAMS, " 2:40000 , 7:3, junk, 9:x ")
    assert (CAP.max_sources(1), CAP.max_sources(2), CAP.max_sources(7), CAP.max_sources(9)) == (800, 40_000, 3, 800)
    assert CAP.setting_name(2) == "CBOM_MAX_SOURCES_TEAMS" and CAP.setting_name(1) == "CBOM_MAX_SOURCES"


def test_routers_no_longer_hard_code_500():
    root = Path(__file__).resolve().parents[1]
    for rel in ("routers/cbom_sources.py", "utilities/integrations/cmdb.py"):
        text = (root / rel).read_text()
        assert "MAX_SOURCES = 500" not in text, rel


# ----------------------------------------------------------------------------- the source form
def test_create_source_refused_at_the_configured_cap_with_usage(api, world, monkeypatch):  # noqa: F811 (pytest fixtures)
    monkeypatch.setenv(CAP.ENV, "2")
    node_id, _token, _ = enroll_node(api)
    for i in range(2):
        r = api("POST", "/1/cbom/sources/items", json=linux_body(f"dc-{i}", node_id=node_id, targets=[f"10.0.0.{i + 1}"]))
        assert r.status_code == 201, r.text
    r = api("POST", "/1/cbom/sources/items", json=linux_body("dc-3", node_id=node_id, targets=["10.0.0.9"]))
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert "at most 2 sources and this team has 2" in detail and "CBOM_MAX_SOURCES" in detail, detail
    monkeypatch.setenv(CAP.ENV_TEAMS, "1:3")  # a per-team override raises it for team 1 only
    r = api("POST", "/1/cbom/sources/items", json=linux_body("dc-3", node_id=node_id, targets=["10.0.0.9"]))
    assert r.status_code == 201, r.text


def test_overview_and_source_list_report_usage_against_the_cap(api, world, monkeypatch):  # noqa: F811 (pytest fixtures)
    engine, _ = world
    monkeypatch.setenv(CAP.ENV, "500")
    node_id, _token, _ = enroll_node(api)
    seed_sources(engine, 1, node_id, 145)
    ov = api("GET", "/1/cbom/sources/overview")
    assert ov.status_code == 200, ov.text
    assert ov.json()["limits"]["sources"] == {"used": 145, "max": 500, "remaining": 355, "setting": "CBOM_MAX_SOURCES"}
    items = api("GET", "/1/cbom/sources/items?group=servers").json()
    assert items["limits"]["sources"]["used"] == 145 and items["limits"]["sources"]["max"] == 500
    assert api("GET", "/2/cbom/sources/overview", "carol").json()["limits"]["sources"]["used"] == 0


# ----------------------------------------------------------------------------- the CMDB preview
def _groups_csv(rows: int, groups: int) -> str:
    lines = ["fqdn,ip,os,owner,application,environment"]
    for i in range(rows):
        g = i % groups
        lines.append(f"host-{i}.bank.local,10.{100 + (i >> 16)}.{(i >> 8) & 255}.{i & 255},linux,Owner {g},App {g},prod")
    return "\n".join(lines) + "\n"


def test_cmdb_preview_says_how_many_are_over_the_cap_and_apply_creates_the_rest(api, world, monkeypatch):  # noqa: F811 (pytest fixtures)
    engine, _ = world
    monkeypatch.setenv(CAP.ENV, "4")
    node_id, _token, _ = enroll_node(api)
    seed_sources(engine, 1, node_id, 1)
    csv_text = _groups_csv(6, 6)  # six owner/application groups -> six new Linux sources
    r = api("POST", "/1/cbom/sources/cmdb/preview", json={"csv": csv_text, "node_id": node_id})
    assert r.status_code == 200, r.text
    plan = r.json()["plan"]
    assert plan["counts"]["create"] == 3 and plan["counts"]["over_limit"] == 3, plan["counts"]
    assert plan["limit"] == {"used": 1, "max": 4, "remaining": 3, "setting": "CBOM_MAX_SOURCES"}
    assert len(plan["creates"]) == 3 and len(plan["over_limit"]) == 3
    assert all("4 sources" in o["reason"] and "CBOM_MAX_SOURCES" in o["reason"] for o in plan["over_limit"])
    assert plan["counts"]["new_targets"] == 3  # only what will really be created
    assert plan["warnings"] and "3 of the 6 new sources are over" in plan["warnings"][0], plan["warnings"]
    applied = api("POST", "/1/cbom/sources/cmdb/apply", json={"csv": csv_text, "node_id": node_id,
                                                                "digest": plan["digest"]})
    assert applied.status_code == 200, applied.text
    assert applied.json()["result"]["created"] == 3 and applied.json()["result"]["over_limit"] == 3
    assert count(engine) == 4
    # at the cap: the preview creates nothing and says why (hosts 0-2 are now in sources: metadata, not creates)
    again = api("POST", "/1/cbom/sources/cmdb/preview", json={"csv": _groups_csv(8, 8), "node_id": node_id}).json()["plan"]
    assert again["counts"]["create"] == 0 and again["counts"]["over_limit"] == 5 and again["limit"]["remaining"] == 0
    assert again["unchanged"] == 3


def test_cmdb_apply_rechecks_the_cap_if_sources_were_added_after_the_preview(api, world, monkeypatch):  # noqa: F811 (pytest fixtures)
    engine, _ = world
    monkeypatch.setenv(CAP.ENV, "3")
    node_id, _token, _ = enroll_node(api)
    csv_text = _groups_csv(2, 2)
    plan = api("POST", "/1/cbom/sources/cmdb/preview", json={"csv": csv_text, "node_id": node_id}).json()["plan"]
    assert plan["counts"]["create"] == 2 and plan["counts"]["over_limit"] == 0
    seed_sources(engine, 1, node_id, 2, prefix="late")  # someone else adds two sources meanwhile
    r = api("POST", "/1/cbom/sources/cmdb/apply", json={"csv": csv_text, "node_id": node_id, "digest": plan["digest"]})
    assert r.status_code == 409, r.text  # the plan changed (one is now over the cap): preview again
    assert count(engine) == 2


def test_cmdb_preview_of_5000_rows_with_145_sources_and_a_500_cap(api, world, monkeypatch, capsys):  # noqa: F811 (pytest fixtures)
    """The customer's case from the issue, timed: 5,000 rows in 500 groups, 145 sources, cap 500."""
    engine, _ = world
    monkeypatch.setenv(CAP.ENV, "500")
    node_id, _token, _ = enroll_node(api)
    seed_sources(engine, 1, node_id, 145)
    csv_text = _groups_csv(5000, 500)
    t0 = time.perf_counter()
    r = api("POST", "/1/cbom/sources/cmdb/preview", json={"csv": csv_text, "node_id": node_id})
    preview_s = time.perf_counter() - t0
    assert r.status_code == 200, r.text
    plan = r.json()["plan"]
    assert plan["rows"] == 5000
    assert plan["counts"]["create"] == 355 and plan["counts"]["over_limit"] == 145, plan["counts"]
    t0 = time.perf_counter()
    applied = api("POST", "/1/cbom/sources/cmdb/apply", json={"csv": csv_text, "node_id": node_id,
                                                                "digest": plan["digest"]})
    apply_s = time.perf_counter() - t0
    assert applied.status_code == 200 and applied.json()["result"]["created"] == 355, applied.text
    assert count(engine) == 500
    with capsys.disabled():
        print(f"\n[#224 timing] 5,000-row CMDB preview {preview_s:.2f}s, apply (355 sources) {apply_s:.2f}s")
    assert preview_s < 30 and apply_s < 60


def test_default_cap_is_backed_by_a_timing_at_that_many_sources(api, world, monkeypatch, capsys):  # noqa: F811 (pytest fixtures)
    """The default (10,000) is sized by this check: with 10,000 sources the per-team paths that read every source
    (overview with the run estimate, the full source list, a CMDB preview) still answer in seconds on SQLite."""
    engine, _ = world
    monkeypatch.delenv(CAP.ENV, raising=False)
    node_id, _token, _ = enroll_node(api)
    seed_sources(engine, 1, node_id, CAP.DEFAULT - 1)
    timings = {}
    for name, call in (("overview", lambda: api("GET", "/1/cbom/sources/overview")),
                       ("list", lambda: api("GET", "/1/cbom/sources/items?group=servers")),
                       ("cmdb preview", lambda: api("POST", "/1/cbom/sources/cmdb/preview",
                                                    json={"csv": _groups_csv(50, 5), "node_id": node_id}))):
        t0 = time.perf_counter()
        r = call()
        timings[name] = time.perf_counter() - t0
        assert r.status_code == 200, r.text
    ov = api("GET", "/1/cbom/sources/overview").json()
    assert ov["limits"]["sources"]["used"] == CAP.DEFAULT - 1 and ov["limits"]["sources"]["remaining"] == 1
    plan = api("POST", "/1/cbom/sources/cmdb/preview", json={"csv": _groups_csv(50, 5), "node_id": node_id}).json()["plan"]
    assert plan["counts"]["create"] == 1 and plan["counts"]["over_limit"] == 4
    with capsys.disabled():
        print("\n[#224 timing] at 9,999 sources: " + ", ".join(f"{k} {v:.2f}s" for k, v in timings.items()))
    assert all(v < 30 for v in timings.values()), timings
