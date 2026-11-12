"""CB-12 TLS prober fidelity against real servers (nginx, openssl s_server, socat, PostgreSQL in Docker).

Skipped unless ZS_TLS_LAB points at the work directory of ``scan_node/tests/tls_lab.sh up`` (or run
``scan_node/tests/tls_lab.sh test``). Every expected value comes from that lab's expected.json: the configuration the
script gave each server and, for the full-suite server, the suites nmap ``ssl-enum-ciphers`` (an independent tool)
saw accepted. Nothing expected is taken from the prober. ZS_TLS_LAB_OUT, when set, receives the measured handshakes
per endpoint (the scale numbers of the PR).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from zs_scan_node import netutil
from zs_scan_node.collectors import database as D
from zs_scan_node.collectors import network as N
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

LAB = os.environ.get("ZS_TLS_LAB")
pytestmark = pytest.mark.skipif(not LAB, reason="needs the CB-12 TLS lab (scan_node/tests/tls_lab.sh)")
MEASURED: dict[str, dict] = {}


@pytest.fixture(scope="module")
def expected() -> dict:
    return json.loads((Path(LAB) / "expected.json").read_text())


@pytest.fixture(scope="module", autouse=True)
def _write_measurements():
    yield
    out = os.environ.get("ZS_TLS_LAB_OUT")
    if out:
        Path(out).write_text(json.dumps(MEASURED, indent=1, sort_keys=True))


def _read(target: dict, label: str, sni=(), budget=128, monkeypatch=None):
    names = {target["sni"]: [target["ip"]]} if target.get("sni") else {}
    real = netutil.resolve
    monkeypatch.setattr(netutil, "resolve", lambda n, *a, **k: names[n] if n in names else real(n, *a, **k))
    ctx = JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="network_range",
                     scrubber=Scrubber(), never_scan=NeverScan([]), deadline=time.monotonic() + 300)
    scan = N.NetworkScan(ctx, {"sni_hostnames": list(sni), "rate_limits": {
        "connections_per_second": 20, "parallel_per_server": 2, "handshakes_per_endpoint": budget}})
    t0 = time.monotonic()
    status, err, n = scan.scan_endpoint(N.Endpoint(target["ip"], target["port"], "tls", "https"), "full")
    ctx.flush()
    rows = ctx.collected
    tls = [a for a in rows if a["type"] == "tls_endpoint"]
    MEASURED[label] = {"status": status, "seconds": round(time.monotonic() - t0, 2),
                       "handshakes": tls[0]["facts"].get("handshakes_used") if tls else None,
                       "rows": [(a["type"], a["location"], (a["facts"] or {}).get("status")) for a in rows]}
    return status, err, rows, tls


def _suites(facts: dict, version: str) -> list[str]:
    return sorted(e["name"] for e in facts["cipher_suites"].get(version, []))


def test_sni_only_server_read_with_the_configured_name(expected, monkeypatch):
    t = expected["sni-only"]
    status, err, rows, tls = _read(t, "sni-only+name", sni=[t["sni"]], monkeypatch=monkeypatch)
    assert status == "ok" and len(tls) == 1
    f = tls[0]["facts"]
    assert f["sni"] == t["sni"] and f["tls"] is True
    assert sorted(v for v, ok in f["versions"].items() if ok) == t["versions"]
    for v, suites in t["suites"].items():
        assert _suites(f, v) == sorted(suites), v
    assert f["groups"] == sorted(t["groups"]) and f["enumeration"]["complete"] is True
    certs = [a for a in rows if a["type"] == "certificate"]
    assert certs and f"CN={t['leaf_cn']}" in certs[0]["name"].replace(" ", "")


def test_sni_only_server_without_a_name(expected, monkeypatch):
    status, err, rows, tls = _read(expected["sni-only"], "sni-only", monkeypatch=monkeypatch)
    assert status == "tls_unavailable"
    assert tls[0]["facts"]["negotiation"] == "sni_required" and "negotiated_group" not in tls[0]["facts"]
    assert [a["facts"]["status"] for a in rows if a["type"] == "coverage"] == ["sni_required"]


def test_full_suite_server_every_suite_and_group(expected, monkeypatch):
    t = expected["full-suite"]
    status, err, rows, tls = _read(t, "full-suite", monkeypatch=monkeypatch)
    f = tls[0]["facts"]
    assert status == "ok" and sorted(v for v, ok in f["versions"].items() if ok) == t["versions"]
    nmap = t.get("nmap_suites")
    assert nmap, "the lab's independent nmap self-check is missing (ZS_TLS_LAB_TOOLS image)"
    for version, suites in nmap.items():
        assert _suites(f, version) == sorted(suites), version
    assert _suites(f, "TLSv1.3") == sorted(t["tls13_suites"])
    assert f["groups"] == sorted(t["groups"]) and f["groups_complete"] is True
    assert f["pq_hybrid"] is True and f["classical_tls13_accepted"] is True
    assert f["enumeration"]["complete"] is True and f["handshakes_used"] <= f["handshake_budget"]
    assert len(json.dumps(f)) < 16 * 1024  # inside the node's facts cap, nothing trimmed
    assert "_truncated" not in f


@pytest.mark.parametrize("name", ["closes", "http"])
def test_listeners_that_do_not_speak_tls(expected, name, monkeypatch):
    status, err, rows, tls = _read(expected[name], name, monkeypatch=monkeypatch)
    assert status == "ok" and not tls and not [a for a in rows if a["type"] == "certificate"]
    assert [a["facts"]["status"] for a in rows] == ["not_tls"]


def test_alert_only_tls_server_is_tls(expected, monkeypatch):
    status, err, rows, tls = _read(expected["alert-only"], "alert-only", monkeypatch=monkeypatch)
    assert status == "not_supported" and tls[0]["facts"]["tls"] is True
    assert tls[0]["facts"]["negotiation"] == "no_common_parameters"


def test_postgres_tls_versions(expected):
    t = expected["pg-tls"]
    ctx = JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="database", scrubber=Scrubber(),
                     never_scan=NeverScan([]), deadline=time.monotonic() + 120)
    t0 = time.monotonic()
    facts, _n = D._server_tls(ctx, D.Target("pg.cb12.lab", t["ip"]), t["port"], "postgres")
    MEASURED["pg-tls"] = {"seconds": round(time.monotonic() - t0, 2), "handshakes": facts["handshakes_used"]}
    assert sorted(v for v, ok in facts["versions"].items() if ok) == t["versions"]
    assert facts["negotiated_cipher_code"] and facts["enumeration"]["complete"] is True
