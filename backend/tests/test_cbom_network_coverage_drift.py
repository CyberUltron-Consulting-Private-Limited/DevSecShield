"""Network ranges: what the scan node could not read must never read as fixed (round 5, u3).

The node now sends coverage rows for an address that answered on no port ("no answer", whole target), for an open
endpoint it could not read ("endpoint <ip:port>", scoped) and for TLS checks that could not run ("TLS checks
<ip:port>", scoped, incomplete).  These tests feed rows shaped exactly like the node's into the drift comparison.

    cd backend && .venv/bin/python -m pytest tests/test_cbom_network_coverage_drift.py -q
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.new_models import CbomCollectedAsset  # noqa: E402
from backend.utilities.cbom_sources import drift as D  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402

NOW = dt.datetime(2026, 11, 10, 12, 0, 0)
VERSIONS_WEAK = {"SSLv3": False, "TLSv1.0": True, "TLSv1.1": True, "TLSv1.2": True, "TLSv1.3": False}


def _row(asset_type, target, location, facts, protocol=None, name=None):
    verdict = classify(asset_type, None, None, protocol, facts, NOW)
    return CbomCollectedAsset(
        id=None, team_id=1, run_id=1, job_id=1, source_id=1, attempt=1, asset_key=f"{target}|{location}",
        asset_type=asset_type, cdx_type=verdict["cdx_type"], target=target, location=location, name=name or location,
        algorithm=None, key_size=None, protocol=protocol, quantum_vulnerable=verdict["quantum_vulnerable"],
        impact=verdict["impact"], finding_codes=verdict["finding_codes"], finding=verdict["finding"], facts=facts,
        created_at=NOW)


def _tls(ip, port=443, versions=None, **extra):
    where = f"{ip}:{port}"
    facts = {"tls": True, "service": "tls", "versions": versions or VERSIONS_WEAK, "negotiated_version": "TLSv1.2",
             **extra}
    return _row("tls_endpoint", ip, where, facts, protocol="TLSv1.2", name=f"HTTPS {where}")


def _cov(ip, check, status, scope=None, incomplete=None):
    facts = {"check": check, "status": status, "detail": "node"}
    if scope is not None:
        facts["scope"] = scope
    if incomplete is not None:
        facts["incomplete"] = incomplete
    return _row("coverage", ip, f"{ip}#{check}", facts, name=check)


def _diff(before_rows, after_rows):
    before = D.node_views(before_rows, "src:1", reclassify=False)
    after = D.node_views(after_rows, "src:1", reclassify=False)
    return D.compare(before, after, D.job_gaps(after_rows))


def test_weak_endpoint_has_findings():
    assert _tls("10.9.0.5").finding_codes  # TLS 1.0 / 1.1 accepted: the fixture is a finding


def test_a_host_that_stopped_answering_is_not_read_not_fixed():
    diff = _diff([_tls("10.9.0.5"), _tls("10.9.0.6")],
                 [_tls("10.9.0.6"), _cov("10.9.0.5", "no answer", "unreachable")])
    assert diff["removed"] == [] and diff["resolved"] == []
    assert [d["key"] for d in diff["not_read"]] and all(d["asset_removed"] for d in diff["not_read"])


def test_without_the_coverage_row_the_same_silence_read_as_fixed():
    """What happened before the node sent the row: the vanished endpoint's findings were resolved."""
    diff = _diff([_tls("10.9.0.5")], [])
    assert diff["removed"] and diff["resolved"]


def test_an_endpoint_that_could_not_be_read_is_not_read_while_others_still_drift():
    before = [_tls("10.9.0.5", 443), _tls("10.9.0.5", 8443)]
    after = [_cov("10.9.0.5", "endpoint 10.9.0.5:443", "timeout", scope=["10.9.0.5:443"], incomplete=False)]
    diff = _diff(before, after)
    assert [d["label"] for d in diff["not_read"]] == [D.node_views([before[0]], "src:1", reclassify=False)
                                                      .popitem()[1].label]
    assert len(diff["removed"]) == 1 and diff["removed"][0]["label"].endswith("10.9.0.5:8443")  # really gone: drifts


def test_filtered_ports_on_a_live_host_are_not_read():
    before = [_tls("10.9.0.5", 993)]
    after = [_tls("10.9.0.5", 443),
             _cov("10.9.0.5", "ports not answering", "timeout", scope=["10.9.0.5:993", "10.9.0.5:995"],
                  incomplete=False)]
    diff = _diff(before, after)
    assert diff["removed"] == [] and diff["resolved"] == [] and len(diff["not_read"]) == 1


def test_a_tls_check_that_could_not_run_does_not_resolve_its_finding():
    unknown = {**VERSIONS_WEAK, "TLSv1.0": None, "TLSv1.1": None}
    after = [_tls("10.9.0.5", versions=unknown),
             _cov("10.9.0.5", "TLS checks 10.9.0.5:443", "incomplete", scope=["10.9.0.5:443"], incomplete=True)]
    diff = _diff([_tls("10.9.0.5")], after)
    assert diff["resolved"] == []
    assert diff["not_read"] and diff["not_read"][0]["asset_removed"] is False


def test_a_real_fix_still_resolves():
    fixed = {**VERSIONS_WEAK, "TLSv1.0": False, "TLSv1.1": False, "TLSv1.3": True}
    diff = _diff([_tls("10.9.0.5")], [_tls("10.9.0.5", versions=fixed)])
    assert diff["resolved"] and diff["not_read"] == []
