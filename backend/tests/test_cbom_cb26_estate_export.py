"""CB-26: the team's estate CBOM (DEVILS-ADVOCATE CB-26 failing-first list; diagram output 01 at estate level).

* the team CBOM route (404 on dev before this change) returns one schema-valid CycloneDX 1.6 document, JSON and XML;
* component count = distinct estate asset keys (a certificate four collectors see is one component, DA-8);
* a source whose latest collection skipped a never-scan entry still contributes what it read (N4);
* filters per application, source and asset type; removed assets are not listed;
* the response says "unsigned" and carries the SHA-256 of the exact bytes; another team is refused.

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_cb26_estate_export.py -q
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from support.cyclonedx_schema import json_errors, xml_errors  # noqa: E402
from test_cbom_cb20_estate import ISSUER, NOT_AFTER, SERIAL, SHA1, SHA256, SUBJECT, World, _sqlite, cert  # noqa: E402
from test_cbom_sources_api import api, world as api_world  # noqa: E402,F401
from test_cbom_wp10_outputs import two_runs  # noqa: E402,F401

from backend.new_models import CbomCollectionSource, CbomEstateAsset  # noqa: E402
from backend.utilities.cbom_sources import drift as DRIFT  # noqa: E402
from backend.utilities.cbom_sources import estate_export as EX  # noqa: E402

world = api_world
_FIXTURES = (api, two_runs)
NOW = dt.datetime(2026, 11, 14, 12, 0)
T0 = dt.datetime(2030, 1, 1, 12, 0, 0)


@pytest.fixture()
def lab(tmp_path):
    w = World(_sqlite(tmp_path / "export.db"))
    yield w
    w.engine.dispose()


def doc(w: World, team_id: int = 1, **filters) -> dict:
    with Session(w.engine) as s:
        return EX.document(s, team_id, EX.Filters(**filters), NOW)


def props(component: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in component.get("properties", []):
        out.setdefault(p["name"], []).append(p["value"])
    return out


def meta(d: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in d["metadata"]["properties"]}


def assets(d: dict) -> list[dict]:
    return [c for c in d["components"] if "zs:estate_key" in props(c)]


def key(name: str, alg: str = "RSA", **facts) -> dict:
    return {"type": "private_key", "target": "app-01", "location": f"/etc/ssl/private/{name}.key", "name": name,
            "algorithm": alg, "qv": alg == "RSA", "facts": {"key_alg": alg, **facts}}


def test_component_count_is_the_number_of_distinct_estate_keys(lab):
    src = [lab.source(k, n) for k, n in (("network", "prober"), ("linux_servers", "linux"),
                                         ("windows_servers", "win"), ("aws_account", "aws"))]
    facts = {"serial": SERIAL, "not_after": NOT_AFTER, "fingerprint_sha256": SHA256, "fingerprint_sha1": SHA1,
             "subject": SUBJECT, "issuer": ISSUER}
    rows = [cert("10.0.0.5", "10.0.0.5:443#chain[0]", **facts), cert("app-01", "/etc/ssl/pay.pem", **facts),
            cert("win-01", "LocalMachine\\My\\" + SHA1, **facts), cert("aws", "arn:aws:acm:eu-west-1:1:certificate/x",
                                                                      **facts)]
    lab.finalise(lab.run({s: {"rows": [r]} for s, r in zip(src, rows)} | {src[1]: {"rows": [rows[1], key("k1")]}}))
    d = doc(lab)
    keys = {k for k, a in lab.assets().items() if a.presence != "removed"}
    listed = assets(d)
    assert len(listed) == len(keys) == 2  # the certificate once (4 observations) + the key
    assert {props(c)["zs:estate_key"][0] for c in listed} == keys
    cert_c = next(c for c in listed if props(c)["zs:estate_key"][0].startswith("cert:"))
    assert props(cert_c)["zs:sources"] == ["4"] and len(props(cert_c)["zs:observed_by"]) == 4
    m = meta(d)
    assert (m["zs:scope"], m["zs:asset_count"], m["zs:truncated"], m["zs:signature"]) == ("estate", "2", "false",
                                                                                            "unsigned")
    assert json_errors(d) == []


def test_a_never_scan_skip_keeps_what_the_source_read_n4(lab):
    s1 = lab.source("network", "dc-range")
    skipped = {"outcome": "partial", "counts": {"ok": 1, "skipped": 1}}  # one address on the never-scan list
    lab.finalise(lab.run({s1: {"rows": [key("a"), key("b")], **skipped}}))
    listed = assets(doc(lab))
    assert len(listed) == 2 and {props(c)["zs:presence"][0] for c in listed} == {"present"}


def test_removed_assets_are_not_listed_and_not_read_ones_are(lab):
    s1 = lab.source("linux_servers", "linux")
    lab.finalise(lab.run({s1: {"rows": [key("a"), key("b")]}}))
    lab.finalise(lab.run({s1: {"rows": [key("a")]}}))  # complete: b removed
    listed = assets(doc(lab))
    assert [props(c)["zs:presence"][0] for c in listed] == ["present"]
    lab.finalise(lab.run({s1: {"rows": [], "status": "failure", "outcome": None}}))  # nothing read: a stays, not_read
    listed = assets(doc(lab))
    with Session(lab.engine) as s:
        presence = {a.presence for a in s.exec(select(CbomEstateAsset).where(CbomEstateAsset.presence != "removed"))}
    assert len(listed) == 1 and {props(listed[0])["zs:presence"][0]} == presence


def test_filters_per_application_source_and_type(lab):
    s1, s2 = lab.source("linux_servers", "payments"), lab.source("linux_servers", "hr")
    with Session(lab.engine) as s:
        for sid, app in ((s1, "Payments"), (s2, "HR")):
            src = s.get(CbomCollectionSource, sid)
            src.config = {**(src.config or {}), "application": app}
            s.add(src)
        s.commit()
        ref1 = s.get(CbomCollectionSource, s1).source_uid
    lab.finalise(lab.run({s1: {"rows": [key("a"), cert("app-01", "/etc/ssl/x.pem", serial="0A0B0C0D0E0F1011",
                                                        not_after=NOT_AFTER, subject="CN=x", issuer="CN=ca")]},
                          s2: {"rows": [{**key("b"), "target": "hr-01"}]}}))
    assert len(assets(doc(lab))) == 3
    assert len(assets(doc(lab, application="payments"))) == 2  # case-insensitive, the source's setting now
    assert len(assets(doc(lab, source=ref1))) == 2
    assert len(assets(doc(lab, type="private_key"))) == 2
    assert len(assets(doc(lab, application="Payments", type="certificate"))) == 1
    assert assets(doc(lab, application="nobody")) == []
    d = doc(lab, application="Payments")
    assert meta(d)["zs:filter:application"] == "Payments" and meta(d)["zs:asset_count"] == "2"
    with Session(lab.engine) as s:
        assert EX.count(s, 1, EX.Filters(application="Payments")) == 2
    assert assets(doc(lab, team_id=2)) == []  # another team's estate is empty


# ----------------------------------------------------------------------------- the route
def _export(api, team=1, who="alice", **params):
    return api("GET", f"/{team}/cbom/estate-export", who, params=params)


def test_the_team_cbom_route_returns_a_valid_signed_or_unsigned_document(api, two_runs):
    assert DRIFT.record_pending_drift(two_runs["engine"], T0) == 2
    r = _export(api)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert r.headers["x-cbom-signature"] == "unsigned"
    assert r.headers["x-cbom-sha256"] == hashlib.sha256(r.content).hexdigest()  # checkable outside ZeroShield
    assert "attachment" in r.headers["content-disposition"] and ".cdx.json" in r.headers["content-disposition"]
    d = json.loads(r.content)
    assert json_errors(d) == []
    with Session(two_runs["engine"]) as s:
        keys = {a.asset_key for a in s.exec(select(CbomEstateAsset).where(CbomEstateAsset.team_id == 1,
                                                                          CbomEstateAsset.presence != "removed"))}
    assert {props(c)["zs:estate_key"][0] for c in assets(d)} == keys
    assert r.headers["x-cbom-assets"] == str(len(keys))
    assert all(props(c)["zs:q_grade"][0] in ("Q0", "Q1", "Q2", "Q3", "Q4", "none") for c in assets(d))
    x = _export(api, format="xml")
    assert x.status_code == 200 and x.headers["content-type"].startswith("application/vnd.cyclonedx+xml")
    assert xml_errors(x.content) == []
    assert x.headers["x-cbom-sha256"] == hashlib.sha256(x.content).hexdigest()
    assert x.content.count(b"zs:estate_key") == len(keys)


def test_route_validation_and_isolation(api, two_runs):
    assert _export(api, format="pdf").status_code in (400, 422)
    assert _export(api, type="Bad Type!").status_code in (400, 422)
    assert _export(api, who="carol").status_code in (403, 404)
    r = _export(api, team=2, who="carol")
    assert r.status_code == 200 and meta(json.loads(r.content))["zs:asset_count"] == "0"


def test_a_large_estate_waits_for_an_export_slot(api, two_runs, monkeypatch):
    from backend.utilities.cbom_sources import export_slots

    assert DRIFT.record_pending_drift(two_runs["engine"], T0) == 2
    monkeypatch.setattr(export_slots, "LARGE_ASSETS", 1)

    def busy():
        raise export_slots.Busy()

    monkeypatch.setattr(export_slots, "slot", busy)
    r = _export(api)
    assert r.status_code == 429 and r.headers.get("retry-after") == str(export_slots.RETRY_AFTER_S)


# ----------------------------------------------------------------------------- certificate hygiene (#263, #126)
def _hygiene_module(monkeypatch, certs, state="ready", fail=False):
    import types

    module = types.ModuleType("backend.utilities.cbom_sources.cert_hygiene")

    def cached(session, team_id, *, now=None, stale_runs=3):
        if fail:
            raise RuntimeError("boom")
        assert now is not None and now.tzinfo is not None
        return types.SimpleNamespace(certs=certs, state=state)

    module.cached = cached
    monkeypatch.setitem(sys.modules, "backend.utilities.cbom_sources.cert_hygiene", module)


def _two_assets(lab):
    s1 = lab.source("linux_servers", "linux")
    lab.finalise(lab.run({s1: {"rows": [key("k"), cert("app-01", "/etc/ssl/x.pem", serial="0A0B0C0D0E0F1011",
                                                      not_after=NOT_AFTER, subject="CN=x", issuer="CN=ca")]}}))
    return next(k for k in lab.assets() if k.startswith("cert:"))


def test_certificate_components_carry_the_hygiene_flags(lab, monkeypatch):
    import types

    cert_key = _two_assets(lab)
    _hygiene_module(monkeypatch, [types.SimpleNamespace(key=cert_key, flags=("unmanaged", "orphaned", "stale"),
                                                        not_seen_runs=4)])
    d = doc(lab)
    assert meta(d)["zs:cert_hygiene"] == "included"
    by_key = {props(c)["zs:estate_key"][0]: props(c) for c in assets(d)}
    assert by_key[cert_key]["zeroshield:cert:flags"] == ["unmanaged orphaned stale"]
    assert by_key[cert_key]["zeroshield:cert:not_seen_runs"] == ["4"]
    other = next(p for k, p in by_key.items() if k != cert_key)
    assert "zeroshield:cert:flags" not in other and "zeroshield:cert:not_seen_runs" not in other
    assert json_errors(d) == []


def test_a_clean_certificate_has_no_flags_property_and_view_states_are_said(lab, monkeypatch):
    import types

    cert_key = _two_assets(lab)
    _hygiene_module(monkeypatch, [types.SimpleNamespace(key=cert_key, flags=(), not_seen_runs=0)], state="pending")
    d = doc(lab)
    p = next(props(c) for c in assets(d) if props(c)["zs:estate_key"][0] == cert_key)
    assert "zeroshield:cert:flags" not in p and p["zeroshield:cert:not_seen_runs"] == ["0"]
    assert meta(d)["zs:cert_hygiene"] == "included:pending"


def test_the_export_says_when_hygiene_is_missing_or_failed(lab, monkeypatch):
    _two_assets(lab)
    monkeypatch.setitem(sys.modules, "backend.utilities.cbom_sources.cert_hygiene", None)  # import fails
    d = doc(lab)
    assert meta(d)["zs:cert_hygiene"] == "not_available"
    assert not any("zeroshield:cert:flags" in props(c) for c in assets(d))
    _hygiene_module(monkeypatch, [], fail=True)
    assert meta(doc(lab))["zs:cert_hygiene"] == "error"
