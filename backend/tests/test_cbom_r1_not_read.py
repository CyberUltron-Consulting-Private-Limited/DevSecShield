"""Lab UI r1 F2: comparing run #6 with run #4 returned ``not_read: 6`` (the assets of a stopped TLS target), but the
Compare dialog showed only resolved / opened / added / removed / changed and the run's "Changes" had no event for
them, so the stopped target silently dropped out.  Each not-read item now carries the covering coverage row's
detail as ``reason``, and the run's changes list the not-read items apart (they are neither removed nor resolved).
The UI side: frontend components/cbom/sources/notRead.test.ts.

    cd backend && .venv/bin/python -m pytest tests/test_cbom_r1_not_read.py -q
"""
from __future__ import annotations

from test_cbom_network_coverage_drift import _cov, _diff, _tls
from test_cbom_r5_coverage_drift import _send
from test_cbom_sources_api import api, enroll_node, linux_body, world  # noqa: F401  (fixtures)
from test_cbom_wp10_outputs import GONE, OPENSSL, WEAK_TLS, _claim, _run


def test_a_not_read_item_says_why():
    diff = _diff([_tls("10.9.0.5"), _tls("10.9.0.6")],
                 [_tls("10.9.0.6"), _cov("10.9.0.5", "no answer", "unreachable")])
    assert diff["not_read"] and diff["removed"] == [] and diff["resolved"] == []
    assert {d["reason"] for d in diff["not_read"]} == {"node"}  # the coverage row's detail


def test_without_a_detail_the_check_and_status_say_why():
    after = [_tls("10.9.0.6"), _cov("10.9.0.5", "no answer", "unreachable")]
    after[1].facts = {"check": "no answer", "status": "unreachable"}
    diff = _diff([_tls("10.9.0.5"), _tls("10.9.0.6")], after)
    assert {d["reason"] for d in diff["not_read"]} == {"no answer: unreachable"}


def test_the_run_diff_and_the_run_changes_list_what_was_not_read(api, world):
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    api("POST", "/1/cbom/sources/items", json=linux_body("src-a", node_id=node_id, targets=["10.20.0.1"], window="any"))
    _run(api, "r1-f2-run-0001")
    _send(api, hdr, _claim(api, hdr), [WEAK_TLS, GONE, OPENSSL], {"total": 1, "ok": 1, "failed": 0, "skipped": 0})
    run2 = _run(api, "r1-f2-run-0002")
    gap = {"type": "coverage", "target": "10.20.0.1", "location": "10.20.0.1#gap",
           "facts": {"check": "key and certificate files", "status": "denied", "detail": "sudo was refused"}}
    _send(api, hdr, _claim(api, hdr), [WEAK_TLS, OPENSSL, gap],
          {"total": 1, "ok": 0, "partial": 1, "failed": 0, "skipped": 0})
    d = api("GET", f"/1/cbom/sources/runs/{run2['id']}/diff").json()
    assert d["counts"]["not_read"] == 1 and d["removed"] == []
    assert d["not_read"][0]["reason"] == "sudo was refused" and d["not_read"][0]["source_name"] == "src-a"
    changes = api("GET", f"/1/cbom/sources/runs/{run2['id']}/changes").json()
    assert changes["not_read_count"] == 1  # before: no trace of it in the run's changes
    item = changes["not_read"][0]
    assert item["label"].split(" · ")[0] == "DSA host key" and item["reason"] == "sudo was refused"
    assert item["asset_removed"] is True and item["source_name"] == "src-a"
    assert "removed_asset" not in {e["kind"] for e in changes["events"]}
    # the first run has nothing to compare with: nothing not read
    first = api("GET", f"/1/cbom/sources/runs/{run2['id'] - 1}/changes").json()
    assert first["not_read"] == [] and first["not_read_count"] == 0
