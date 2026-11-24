"""Output 04: orphaned and unmanaged certificates of the estate (GET /{team}/cbom/certificates/hygiene and .csv).

Two sources: a network probe of the web tier (application "Web") that reads two certificates on endpoint chains (one
of them expired), and a file collector with no owner or application that reads one of those same certificates as a
file (same serial: one estate asset, CB-21), a certificate deployed nowhere, and an ACM certificate (managed).
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as HARNESS  # noqa: E402
from test_cbom_sources_api import enroll_node, linux_body  # noqa: E402
from test_cbom_wp10_outputs import _claim, _collect, _run  # noqa: E402

from backend.utilities.cbom_sources import cert_hygiene as HYG  # noqa: E402
from backend.utilities.cbom_sources import drift as DRIFT  # noqa: E402

api, world = HARNESS.api, HARNESS.world

NOW = dt.datetime.utcnow().replace(microsecond=0)
Z = "%Y-%m-%dT%H:%M:%SZ"


def _cert(location: str, cn: str, serial: str, *, days: int = 200, **extra) -> dict:
    return {"type": "certificate", "target": "10.20.0.1", "location": location, "name": f"CN={cn}",
            "algorithm": "RSA", "key_size": 2048,
            "facts": {"subject": f"CN={cn}", "issuer": "CN=Lab CA", "serial": serial, "key_alg": "RSA", "key_size": 2048,
                      "not_before": (NOW - dt.timedelta(days=400)).strftime(Z),
                      "not_after": (NOW + dt.timedelta(days=days)).strftime(Z), "sig_alg": "sha256WithRSAEncryption",
                      **extra}}


A_CHAIN = _cert("10.20.0.1:443#chain[0]", "a.lab", "0a0a0a0a0a0a0a0a01", source="tls", chain_index=0)
A_FILE = _cert("/etc/ssl/certs/a.pem", "a.lab", "0a0a0a0a0a0a0a0a01", source="file")
EXPIRED = _cert("10.20.0.1:8443#chain[0]", "old.lab", "0b0b0b0b0b0b0b0b02", days=-5, source="tls", chain_index=0)
NOWHERE = _cert("/etc/ssl/certs/=spare.pem", "spare.lab", "0c0c0c0c0c0c0c0c03", source="file")
ACM = _cert("arn:aws:acm:us-east-1:123456789012:certificate/1b2c3d4e", "api.lab", "0d0d0d0d0d0d0d0d04")


@pytest.fixture(autouse=True)
def _fresh():
    HYG.clear_cache()
    yield
    HYG.clear_cache()


def _drift(engine) -> None:
    DRIFT.record_pending_drift(engine, dt.datetime.utcnow())


@pytest.fixture()
def estate(api, world):
    engine, _ = world
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    for name, target, cfg in (("probe-web", "10.20.0.1", {"application": "Web"}), ("files", "10.20.0.2", {})):
        r = api("POST", "/1/cbom/sources/items", json=linux_body(name, node_id=node_id, targets=[target], window="any",
                                                                 **cfg))
        assert r.status_code == 201, r.text
    per = {"probe-web": [A_CHAIN, EXPIRED], "files": [A_FILE, NOWHERE, ACM]}
    _run(api, "hyg-run-0001")
    for _ in range(2):
        claim = _claim(api, hdr)
        _collect(api, hdr, claim, per[claim["source"]["name"]])
    _drift(engine)
    return {"engine": engine, "hdr": hdr, "per": per}


def _list(api, **params) -> dict:
    r = api("GET", "/1/cbom/certificates/hygiene", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def _by_subject(body: dict) -> dict[str, dict]:
    return {i["subject"]: i for i in body["items"]}


def test_each_certificate_carries_its_flags(api, estate):
    body = _list(api, all="true")
    assert body["state"] == "ready" and body["probed"] is True
    items = _by_subject(body)
    assert set(items) == {"CN=a.lab", "CN=old.lab", "CN=spare.lab", "CN=api.lab"}  # a.lab twice = one asset (CB-21)
    a = items["CN=a.lab"]
    assert sorted(a["sources"]) == ["files", "probe-web"] and len(a["observations"]) == 2
    assert a["flags"] == ["unmanaged"] and a["applications"] == ["Web"]
    old = items["CN=old.lab"]
    assert old["flags"] == ["unmanaged", "prober_only", "expired_served"] and old["expired"] is True
    spare = items["CN=spare.lab"]
    assert spare["flags"] == ["unmanaged", "orphaned", "no_owner"]
    acm = items["CN=api.lab"]
    assert acm["flags"] == ["orphaned", "no_owner"] and acm["observations"][0]["managing"] is True
    counts = body["counts"]
    assert counts["certificates"] == 4 and counts["flagged"] == 4
    assert counts["by_flag"] == {"unmanaged": 3, "prober_only": 1, "orphaned": 2, "no_owner": 2,
                                 "expired_served": 1, "stale": 0}


def test_filters_paging_and_validation(api, estate):
    for flag, n in (("unmanaged", 3), ("expired_served", 1), ("orphaned", 2), ("stale", 0)):
        body = _list(api, flag=flag)
        assert body["total"] == n and all(flag in i["flags"] for i in body["items"])
    assert [i["subject"] for i in _list(api, source="files")["items"]] and \
        all("files" in i["sources"] for i in _list(api, source="files")["items"])
    assert [i["subject"] for i in _list(api, q="SPARE")["items"]] == ["CN=spare.lab"]
    seen, after = [], None
    while True:
        body = _list(api, limit=1, **({"after": after} if after else {}))
        seen += [i["key"] for i in body["items"]]
        after = body["next"]
        if not after:
            break
    assert len(seen) == len(set(seen)) == 4
    assert seen[0] == _by_subject(_list(api, all="true"))["CN=old.lab"]["key"]  # expired first
    assert api("GET", "/1/cbom/certificates/hygiene", params={"flag": "lost"}).status_code == 400
    assert api("GET", "/1/cbom/certificates/hygiene", params={"after": "!!"}).status_code == 400
    assert api("GET", "/1/cbom/certificates/hygiene", "carol").status_code in (403, 404)
    assert _list_team2(api)["counts"]["certificates"] == 0


def _list_team2(api) -> dict:
    r = api("GET", "/2/cbom/certificates/hygiene", "carol")
    assert r.status_code == 200, r.text
    return r.json()


def test_csv_has_every_selected_row_and_no_formula_cells(api, estate):
    r = api("GET", "/1/cbom/certificates/hygiene.csv", params={"flag": "unmanaged"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    lines = r.text.strip().splitlines()
    assert lines[0].split(",") == list(HYG.CSV_COLUMNS) and len(lines) == 1 + 3
    spare = next(line for line in lines if "spare.lab" in line)
    assert "/etc/ssl/certs/=spare.pem" in spare
    assert api("GET", "/1/cbom/certificates/hygiene.csv", "carol").status_code in (403, 404)


def test_formula_like_cells_are_neutralised():
    from backend.utilities.cbom_sources.risk_register import _csv_cell

    assert _csv_cell("=HYPERLINK(1)") == "'=HYPERLINK(1)" and _csv_cell("ok") == "ok"


def test_the_list_is_the_d8_list_when_a_source_reads_nothing_later(api, estate):
    """Staging QA Q3-04: the list is ``cert_estate.unique_certificates`` (D8's), not the estate store: a certificate
    only a source's older collection held is in neither (the drift report states it), so nothing listed is stale."""
    from backend.utilities.cbom_sources.cert_estate import unique_certificates
    from backend.utilities.dashboard.cbom_team_rollup import load_core_view
    from sqlmodel import Session

    engine, hdr = estate["engine"], estate["hdr"]
    for n in range(2, 5):  # three more runs: the probe sees its endpoints; the file collector reads nothing
        _run(api, f"hyg-run-{n:04d}")
        for _ in range(2):
            claim = _claim(api, hdr)
            name = claim["source"]["name"]
            if name == "files":
                _collect(api, hdr, claim, [], ok=0, failed=1)
            else:
                _collect(api, hdr, claim, estate["per"][name])
        _drift(engine)
        HYG.clear_cache()
    body = _list(api, all="true")
    with Session(engine) as session:
        d8 = unique_certificates(load_core_view(session, 1))
    assert body["counts"]["certificates"] == len(d8) == 2
    assert set(_by_subject(body)) == {"CN=a.lab", "CN=old.lab"} == {c.subject for c in d8.certificates}
    assert body["counts"]["by_flag"]["stale"] == 0


def test_managing_systems():
    assert HYG._managing("ca_connector", "certificate", "", {})
    assert HYG._managing("key_manager", "certificate", "", {})
    assert HYG._managing("idp", "certificate", "", {})
    assert HYG._managing("kubernetes", "k8s_certificate", "ns/web", {})
    assert HYG._managing("aws_account", "certificate", "arn:aws:acm-pca:eu-west-1:1:certificate-authority/x", {})
    assert not HYG._managing("aws_account", "iam_certificate", "arn:aws:iam::1:server-certificate/x", {})
    assert not HYG._managing("network_range", "certificate", "10.0.0.1:443#chain[0]", {})


def test_no_probe_means_no_orphaned_flag(api, world):
    engine, _ = world
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    api("POST", "/1/cbom/sources/items", json=linux_body("files", node_id=node_id, targets=["10.20.0.2"], window="any"))
    _run(api, "hyg-run-0101")
    _collect(api, hdr, _claim(api, hdr), [A_FILE, NOWHERE])
    _drift(engine)
    body = _list(api, all="true")
    assert body["probed"] is False and body["counts"]["by_flag"]["orphaned"] == 0


def test_empty_team(api, world):
    body = _list(api)
    assert body["items"] == [] and body["counts"]["certificates"] == 0 and body["state"] == "ready"
