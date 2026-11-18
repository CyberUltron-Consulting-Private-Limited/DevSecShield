"""#150: an admin accepts a legitimately changed host key, or forgets the remembered one, under trust on first use.

Staging, build 6a6ef42 (node staging-lab-node, 14 Nov 2026): after the servers' host keys were regenerated every test
failed with "host key changed (pinned SHA256:E4CW..., now SHA256:rYnW...)", and deleting and re-adding the source did
not help: the pins live on the node.  The decision is bound to the result that showed the change, goes to the node
that reported it with its next job for the source, and is marked applied when that node says it applied it.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlmodel import Session, select
from test_cbom_sources_api import api, enroll_node, linux_body, world  # noqa: F401

from backend.new_models import CbomCollectionAuditEvent, CbomHostKeyReset

OLD = "SHA256:" + "E4CW" + "a" * 39
NEW = "SHA256:" + "rYnW" + "b" * 39
HDR = "X-ZS-Node-Token"


def _tofu_source(call, node_id, **cfg):
    body = linux_body(node_id=node_id, targets=["10.232.0.102", "10.232.0.103"], credential_type="node_key",
                      host_key_policy="tofu", known_hosts="", **cfg)
    body["secrets"] = {}
    r = call("POST", "/1/cbom/sources/items", json=body)
    assert r.status_code == 201, r.text
    return r.json()["source"]


def _run_test(call, token, src_id, samples, applied=None):
    """Queue a connection test, claim it as the node, report ``samples``; returns (job id, claimed source config)."""
    job_id = call("POST", f"/1/cbom/sources/items/{src_id}/test").json()["job"]["id"]
    payload = call("POST", "/cbom/node/jobs/claim", None, headers={HDR: token}).json()
    assert payload["job"]["id"] == job_id
    result = {"samples": samples}
    if applied is not None:
        result["host_key_resets_applied"] = applied
    done = call("POST", f"/cbom/node/jobs/{job_id}/result", None, headers={HDR: token},
               json={"lease_id": payload["job"]["lease_id"], "status": "success", "result": result})
    assert done.status_code == 200, done.text
    return job_id, payload["source"]["config"]


CHANGED = [{"target": "10.232.0.102", "status": "host_key_changed", "reachable": True,
            "note": f"host key changed (pinned {OLD}, now {NEW})"},
           {"target": "10.232.0.103", "status": "host_key_changed", "reachable": True,
            "note": "the server no longer offers the pinned host key type"}]


def _decide(call, src_id, who="alice", **body):
    return call("POST", f"/1/cbom/sources/items/{src_id}/host-key-resets", who, json=body)


def test_accept_round_trip_reaches_only_the_reporting_node_and_is_marked_applied(api, world):  # noqa: F811
    node_id, token, _ = enroll_node(api)
    _other_id, other_token, _ = enroll_node(api, name="dc-pune-02")
    src = _tofu_source(api, node_id)
    job_id, config = _run_test(api, token, src["id"], CHANGED)
    assert "host_key_resets" not in config

    r = _decide(api, src["id"], job_id=job_id, target="10.232.0.102", action="accept", fingerprint=NEW)
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["reset"]["status"] == "pending" and out["reset"]["pinned_fingerprint"] == OLD
    assert "intercepting" in out["warning"] and "next job" in out["message"]
    reset_id = out["reset"]["id"]

    # the next job of the source on the reporting node carries the decision; the stored config does not
    job2, config = _run_test(api, token, src["id"], [{"target": "10.232.0.102", "status": "ready"}], applied=[reset_id])
    assert config["host_key_resets"] == [{"id": reset_id, "target": "10.232.0.102", "port": 22, "action": "accept",
                                          "fingerprint": NEW}]
    got = api("GET", f"/1/cbom/sources/items/{src['id']}").json()["source"]
    assert "host_key_resets" not in got["config"]
    listed = api("GET", f"/1/cbom/sources/items/{src['id']}/host-key-resets", "bob").json()["resets"]
    assert listed[0]["status"] == "applied" and listed[0]["applied_job_id"] == job2
    # applied: not sent again
    _job3, config = _run_test(api, token, src["id"], [{"target": "10.232.0.102", "status": "ready"}])
    assert "host_key_resets" not in config
    assert other_token  # the second node never had the source, so it never sees the decision
    with Session(world[0]) as s:
        actions = [a.action for a in s.exec(select(CbomCollectionAuditEvent)).all()]
    assert "source.host_key_accept" in actions and "source.host_key_accept_applied" in actions


def test_a_decision_is_sent_again_until_the_node_applies_it(api, world):  # noqa: F811
    node_id, token, _ = enroll_node(api)
    src = _tofu_source(api, node_id)
    job_id, _ = _run_test(api, token, src["id"], CHANGED)
    reset_id = _decide(api, src["id"], job_id=job_id, target="10.232.0.103", action="forget").json()["reset"]["id"]
    _j, config = _run_test(api, token, src["id"], [{"target": "10.232.0.102", "status": "timeout"}])  # not reached
    assert [r["id"] for r in config["host_key_resets"]] == [reset_id]
    assert "fingerprint" not in config["host_key_resets"][0]
    _j, config = _run_test(api, token, src["id"], [], applied=[reset_id, 99999, "x", True])
    assert [r["id"] for r in config["host_key_resets"]] == [reset_id]
    _j, config = _run_test(api, token, src["id"], [])
    assert "host_key_resets" not in config


def test_accept_must_match_the_key_the_result_shows(api, world):  # noqa: F811
    node_id, token, _ = enroll_node(api)
    src = _tofu_source(api, node_id)
    job_id, _ = _run_test(api, token, src["id"], CHANGED)
    stale = _decide(api, src["id"], job_id=job_id, target="10.232.0.102", action="accept", fingerprint="SHA256:" + "c" * 43)
    assert stale.status_code == 409
    # no new key in the result (the server stopped offering the pinned type): only forget is possible
    nokey = _decide(api, src["id"], job_id=job_id, target="10.232.0.103", action="accept", fingerprint=NEW)
    assert nokey.status_code == 400 and "Forget" in nokey.json()["detail"]
    # a target that did not report a change
    other = _decide(api, src["id"], job_id=job_id, target="10.232.0.104", action="forget")
    assert other.status_code == 400
    with Session(world[0]) as s:
        assert s.exec(select(CbomHostKeyReset)).all() == []


def test_only_a_team_admin_and_only_for_this_teams_source_and_job(api, world):  # noqa: F811
    node_id, token, _ = enroll_node(api)
    src = _tofu_source(api, node_id)
    job_id, _ = _run_test(api, token, src["id"], CHANGED)
    member = _decide(api, src["id"], who="bob", job_id=job_id, target="10.232.0.102", action="forget")
    assert member.status_code == 403 and "team admin" in member.json()["detail"]  # F4 route policy (was 400)
    other_team = api("POST", f"/2/cbom/sources/items/{src['id']}/host-key-resets", "carol",
                     json={"job_id": job_id, "target": "10.232.0.102", "action": "forget"})
    assert other_team.status_code == 404
    bad = _decide(api, src["id"], job_id=job_id, target="10.232.0.102", action="delete-all")
    assert bad.status_code == 422
    missing = _decide(api, src["id"], job_id=job_id + 1000, target="10.232.0.102", action="forget")
    assert missing.status_code == 404
    with Session(world[0]) as s:
        assert s.exec(select(CbomHostKeyReset)).all() == []


def test_a_job_of_another_source_is_not_evidence(api, world):  # noqa: F811
    node_id, token, _ = enroll_node(api)
    a = _tofu_source(api, node_id)
    b = _tofu_source(api, node_id, name="linux-b")
    job_a, _ = _run_test(api, token, a["id"], CHANGED)
    r = _decide(api, b["id"], job_id=job_a, target="10.232.0.102", action="forget")
    assert r.status_code == 404


def test_pinned_known_hosts_sources_have_no_remembered_keys(api, world):  # noqa: F811
    node_id, token, _ = enroll_node(api)
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id)).json()["source"]
    job_id, _ = _run_test(api, token, src["id"], [{"target": "10.20.0.1", "status": "host_key_changed",
                                                   "note": "host key SHA256:x does not match the pinned known_hosts"}])
    r = _decide(api, src["id"], job_id=job_id, target="10.20.0.1", action="forget")
    assert r.status_code == 400 and "known_hosts" in r.json()["detail"]


def test_a_newer_decision_supersedes_the_pending_one(api, world):  # noqa: F811
    node_id, token, _ = enroll_node(api)
    src = _tofu_source(api, node_id)
    job_id, _ = _run_test(api, token, src["id"], CHANGED)
    first = _decide(api, src["id"], job_id=job_id, target="10.232.0.102", action="accept", fingerprint=NEW).json()
    second = _decide(api, src["id"], job_id=job_id, target="10.232.0.102", action="forget").json()
    _j, config = _run_test(api, token, src["id"], [], applied=[first["reset"]["id"]])  # a stale ack changes nothing
    assert [r["id"] for r in config["host_key_resets"]] == [second["reset"]["id"]]
    listed = {r["id"]: r["status"] for r in
              api("GET", f"/1/cbom/sources/items/{src['id']}/host-key-resets").json()["resets"]}
    assert listed == {first["reset"]["id"]: "superseded", second["reset"]["id"]: "pending"}


# ----------------------------------------------------------------------------- migration
PG = os.environ.get("CBOM_TEST_PG_URL")
_VERSIONS = Path(__file__).resolve().parents[2] / "prod_database_migrations" / "migrations" / "versions"


def _up_down_up(engine):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    path = next(_VERSIONS.glob("i150hkreset001_*.py"))
    spec = importlib.util.spec_from_file_location("i150hkreset001", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def run(step):
        with engine.begin() as conn:
            with Operations.context(MigrationContext.configure(conn)):
                getattr(module, step)()
            return {c["name"] for c in sa.inspect(conn).get_columns("cbomhostkeyreset")} \
                if sa.inspect(conn).has_table("cbomhostkeyreset") else None

    with engine.begin() as conn:
        conn.execute(sa.text("DROP TABLE IF EXISTS cbomhostkeyreset"))
        if not sa.inspect(conn).has_table("team"):
            conn.execute(sa.text("CREATE TABLE team (id integer PRIMARY KEY)"))
    try:
        assert module.down_revision == "cb19grade002"
        up = run("upgrade")
        assert up == set(CbomHostKeyReset.__table__.columns.keys())  # the migration builds what the model maps
        assert run("downgrade") is None
        assert run("upgrade") == up
    finally:
        with engine.begin() as conn:
            conn.execute(sa.text("DROP TABLE IF EXISTS cbomhostkeyreset"))
        engine.dispose()


def test_migration_up_down_up_on_sqlite(tmp_path):
    _up_down_up(sa.create_engine(f"sqlite:///{tmp_path / 'm.db'}"))


@pytest.mark.skipif(not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL")
def test_migration_up_down_up_on_postgresql():
    _up_down_up(sa.create_engine(PG))
