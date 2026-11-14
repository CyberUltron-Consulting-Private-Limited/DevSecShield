"""CB-25 PR-A: the crypto-agility baseline at system and enterprise level (GET /{team}/cbom/agility and its drill-down).

Over each source's latest successful collection + each repository's latest code scan + the evidence items: one asset
per cross-source identity (asset_keys), class = hardest across its observations, per-system counts that add up to the
enterprise counts, every count also without the post-quantum codes, and a drill-down whose pages equal the counts.
Uses the same harness as test_cbom_sources_api.py / test_cbom_cb24_run_agility.py (SQLite + the real routers).
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest
from sqlmodel import Session

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as HARNESS  # noqa: E402
from test_cbom_sources_api import enroll_node, linux_body  # noqa: E402
from test_cbom_wp10_outputs import _claim, _collect, _run  # noqa: E402

from backend.new_models import CbomEvidenceArea, CbomEvidenceVendor, Scan  # noqa: E402
from backend.utilities.cbom_sources import agility_rollup as ROLLUP  # noqa: E402

api, world = HARNESS.api, HARNESS.world  # the harness's fixtures, used by name below

VALUES = ("configurable", "code-fixed", "vendor-fixed", "hardware-fixed", "unknown", "none")
NOW = dt.datetime.utcnow().replace(microsecond=0)
NOT_BEFORE = (NOW - dt.timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
NOT_AFTER = (NOW + dt.timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
# one certificate (RSA-1024, SHA-1 signed): same serial, fingerprint and DNs wherever it is read
CERT_FACTS = {"subject": "CN=same.lab", "issuer": "CN=Lab CA", "serial": "0a1b2c3d4e5f60718293", "not_before": NOT_BEFORE,
              "not_after": NOT_AFTER, "sig_alg": "sha1WithRSAEncryption", "key_alg": "RSA", "key_size": 1024,
              "fingerprint_sha256": "ab" * 32, "san": ["same.lab"]}
TLS10 = {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:443",
         "facts": {"protocols": ["TLSv1.0", "TLSv1.2", "TLSv1.3"], "pq_group_supported": True}}
TLS_NO_PQ = {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:8443",
             "facts": {"protocols": ["TLSv1.2", "TLSv1.3"], "pq_group_supported": False}}
AES = {"type": "kms_key", "target": "10.20.0.1", "location": "vault:transit/aes", "name": "aes",
       "algorithm": "AES", "key_size": 256, "facts": {"key_spec": "SYMMETRIC_DEFAULT"}}


def _cert(location: str, **extra) -> dict:
    return {"type": "certificate", "target": "10.20.0.1", "location": location, "name": "CN=same.lab",
            "algorithm": "RSA", "key_size": 1024, "facts": {**CERT_FACTS, **extra}}


@pytest.fixture(autouse=True, params=["estate_store", "collections_view"])
def reader(request, monkeypatch):
    """Every test twice: Sources read from the estate store (CB-20, once drift has written it) and from
    collections_view (the fallback until the store has every source's latest collection)."""
    monkeypatch.setattr(ROLLUP, "USE_STORE", request.param == "estate_store")
    ROLLUP.clear_cache()
    yield request.param
    ROLLUP.clear_cache()


def _record_drift(engine) -> None:
    """What the scheduler tick does after a run finishes: drift, and with it the estate store's write."""
    from backend.utilities.cbom_sources import drift as DRIFT

    DRIFT.record_pending_drift(engine, dt.datetime.utcnow())


def _baseline(api, team=1, who="alice", **params) -> dict:
    r = api("GET", f"/{team}/cbom/agility", who, params=params)
    assert r.status_code == 200, r.text
    body = r.json()
    if body["inputs"]["collections"] and team == 1:
        expected = "estate_store" if ROLLUP.USE_STORE else "collections_view"
        assert body["inputs"]["read_from"] == expected, body["inputs"]
    return body


def _all_subjects(api, *, page=2, **params) -> list[dict]:
    """Every item of a drill-down, page by page through the keyset cursor."""
    out, after = [], None
    for _ in range(1000):
        q = {**params, "limit": page, **({"after": after} if after else {})}
        r = api("GET", "/1/cbom/agility/subjects", params=q)
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["items"]) <= page
        out.extend(body["items"])
        after = body["next"]
        if not after:
            assert len(out) == body["total"]
            return out
    raise AssertionError("cursor never ended")


@pytest.fixture()
def estate(api, world):
    """Three sources on one node, one run; each reads the SAME certificate (prober chain[0], the HSM that holds its
    key through PKCS#11, a database chain): A (application "Payments", operated by us), B (no application, ours), C (operated by a vendor).
    A also has a TLS 1.0 endpoint, an endpoint with no post-quantum key exchange and an AES key; C the same TLS 1.0
    weakness on its own (private) address."""
    engine, _ = world
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    made = {}
    for name, target, cfg in (("src-a", "10.20.0.1", {"application": "Payments"}), ("src-b", "10.20.0.2", {}),
                              ("src-c", "10.20.0.3", {"operated_by": "vendor"})):
        r = api("POST", "/1/cbom/sources/items", json=linux_body(name, node_id=node_id, targets=[target], window="any",
                                                                 **cfg))
        assert r.status_code == 201, r.text
        made[r.json()["source"]["id"]] = name
    run = _run(api, "cb25-run-0001")
    per_source = {
        "src-a": [TLS10, TLS_NO_PQ, AES, _cert("10.20.0.1:443#chain[0]", source="tls", chain_index=0)],
        "src-b": [_cert("pkcs11:token=luna;object=same", source="pkcs11", store="pkcs11", token_class="hardware")],
        "src-c": [{**TLS10, "target": "10.20.0.3", "location": "10.20.0.3:443"},
                  _cert("db:5432#chain[0]", source="database", chain_index=0)],
    }
    for _ in range(3):
        claim = _claim(api, hdr)
        name = claim["source"]["name"]
        _collect(api, hdr, claim, per_source[name])
    _record_drift(engine)
    return {"engine": engine, "run": run, "sources": {v: k for k, v in made.items()}}


def _by_location(items: list[dict]) -> dict[str, dict]:
    return {i["location"]: i for i in items}


# ---------------------------------------------------------------------------------------------- the acceptance rows
def test_one_certificate_seen_by_three_sources_counts_once_with_the_hardest_class(api, estate):
    body = _baseline(api)
    items = _all_subjects(api)
    certs = [i for i in items if i["type"] == "certificate"]
    assert len(certs) == 1, certs  # three observations, one asset
    cert = certs[0]
    assert cert["observations"] == 3 and sorted(cert["sources"]) == ["src-a", "src-b", "src-c"]
    # each observation has its own class (the run asset list shows it): the HSM's is hardware-fixed (R-HW), the other
    # two are easier; the asset takes the hardest of the three
    run_items = api("GET", f"/1/cbom/sources/runs/{estate['run']['id']}/assets?page_size=200").json()["items"]
    own = {i["source_name"]: i["fix_class"] for i in run_items if i["type"] == "certificate"}
    assert own["src-b"] == "hardware-fixed" and own["src-a"] != "hardware-fixed" != own["src-c"], own
    assert cert["fix_class"] == "hardware-fixed"
    assert body["dedupe"]["method"] == "asset_keys" and body["dedupe"]["merged"] == 2
    assert body["assets"] == len(items) == sum(body["counts"].values())
    # the two TLS 1.0 endpoints are private addresses of two sources: two assets, not one
    assert sum(1 for i in items if i["type"] == "tls_endpoint" and i["location"].endswith(":443")) == 2


def test_per_system_sums_equal_the_enterprise_totals(api, estate):
    body = _baseline(api, limit=500)
    systems = body["systems"]["items"]
    assert body["systems_total"] == len(systems) == body["systems"]["matched"]
    for view in ("counts", "counts_excl_pq"):
        for v in VALUES:
            assert sum(s[view][v] for s in systems) == body[view][v], (view, v)
    assert sum(s["assets"] for s in systems) == body["assets"]
    kinds = {s["label"]: s["kind"] for s in systems}
    assert kinds["Payments"] == "application"  # system = the source's application (owner default)
    assert kinds.get("src-c") == "source"


def test_post_quantum_codes_are_counted_and_a_second_count_leaves_them_out(api, estate):
    body = _baseline(api)
    items = _by_location(_all_subjects(api))
    no_pq = items["10.20.0.1:8443"]  # its only code is the post-quantum key exchange
    assert no_pq["fix_class"] == "vendor-fixed" and no_pq["fix_class_excl_pq"] == "none"
    assert body["counts_excl_pq"]["none"] > body["counts"]["none"]
    assert sum(body["counts_excl_pq"].values()) == sum(body["counts"].values())
    excl = _all_subjects(api, view="excl_pq", fix_class="none")
    assert len(excl) == body["counts_excl_pq"]["none"] and "10.20.0.1:8443" in {i["location"] for i in excl}


def test_vendor_operated_sources_are_vendor_fixed(api, estate):
    items = _by_location(_all_subjects(api))
    assert items["10.20.0.1:443"]["fix_class"] == "configurable"  # TLS 1.0 on our own server: a setting
    assert items["10.20.0.3:443"]["fix_class"] == "vendor-fixed"  # the same weakness where a vendor operates it
    assert items["10.20.0.3:443"]["system"]["label"] == "src-c"


def test_empty_team(api, world):
    body = _baseline(api)
    assert body["assets"] == 0 and body["counts"] == {v: 0 for v in VALUES}
    assert body["counts_excl_pq"] == {v: 0 for v in VALUES}
    assert body["self_fixable_pct"] is None and body["hardest"] is None
    assert body["systems"] == {"items": [], "next": None, "matched": 0} and body["systems_total"] == 0
    r = api("GET", "/1/cbom/agility/subjects")
    assert r.status_code == 200 and r.json()["items"] == [] and r.json()["total"] == 0


def test_drill_down_equals_the_counts(api, estate):
    body = _baseline(api)
    seen: set[str] = set()
    for view, counts in (("all", body["counts"]), ("excl_pq", body["counts_excl_pq"])):
        for v in VALUES:
            items = _all_subjects(api, page=1, fix_class=v, view=view)
            assert len(items) == counts[v], (view, v)
            assert len({i["key"] for i in items}) == len(items)  # keyset paging: no repeat
            if view == "all":
                assert all(i["fix_class"] == v for i in items)
                seen |= {i["key"] for i in items}
    assert len(seen) == body["assets"]
    for system in body["systems"]["items"]:  # per system, too
        items = _all_subjects(api, system=system["key"])
        assert len(items) == system["assets"] and {i["system"]["key"] for i in items} == {system["key"]}


# ---------------------------------------------------------------------------------------------- code scans, evidence
def _code_scan(engine, scan_id: int, created: dt.datetime, *, branch="main", rows=None) -> None:
    cert_row = {"title": "same.crt", "algorithm_name": "same.crt", "asset_type": "certificate",
                "algorithm_type": "certificate", "location": "deploy/same.crt", "bom_ref": "crypto-cert-same",
                "impact": "High", "finding_codes": ["WEAK_CERTIFICATE_KEY"], "crypto_strength": "weak", "weak": True}
    rsa_row = {"title": "RSA-1024", "algorithm_name": "RSA", "asset_type": "algorithm", "algorithm_type": "pke",
               "location": "src/crypto_utils.py:12", "bom_ref": "crypto-algo-rsa", "impact": "High",
               "finding_codes": ["WEAK_ALGORITHM", "QUANTUM_VULNERABLE"], "crypto_strength": "weak", "weak": True}
    component = {"name": "same.crt", "type": "cryptographic-asset", "bom-ref": "crypto-cert-same",
                 "properties": [{"name": "crypto:subjectName", "value": "same.lab"},
                                {"name": "crypto:issuerName", "value": "Lab CA"},
                                {"name": "crypto:notValidBefore", "value": NOT_BEFORE},
                                {"name": "crypto:notValidAfter", "value": NOT_AFTER}],
                 "cryptoProperties": {"assetType": "certificate"}}
    with Session(engine) as s:
        s.add(Scan(id=scan_id, team_id=1, owner_user_id=1, scan_type="cbom", title="code", scan_status="success",
                   scan_metadata={"repo_url": "https://github.com/acme/pay", "branch": branch}, created_at=created,
                   last_updated=created, scan_data={"results": rows if rows is not None else [cert_row, rsa_row],
                                                    "cbom_json": {"components": [component]}}))
        s.commit()


def test_code_scans_join_the_sources_certificate_and_only_the_latest_scan_counts(api, estate):
    engine = estate["engine"]
    _code_scan(engine, 901, NOW - dt.timedelta(days=3), rows=[{"title": "old", "asset_type": "algorithm",
                                                              "location": "old.py", "finding_codes": ["WEAK_ALGORITHM"]}])
    _code_scan(engine, 902, NOW - dt.timedelta(days=1))
    body = _baseline(api)
    items = _all_subjects(api)
    certs = [i for i in items if i["key"].startswith("cert:")]
    assert len(certs) == 1 and certs[0]["observations"] == 4  # three collectors + the repository
    assert not any(i["name"] == "old" for i in items)  # an older scan of the same repository is history
    rsa = [i for i in items if i["name"] == "RSA-1024"]
    assert len(rsa) == 1 and rsa[0]["system"]["kind"] == "repository" and rsa[0]["fix_class"] == "code-fixed"
    assert body["inputs"]["code_scans"] == 1 and body["assets"] == len(items)
    systems = body["systems"]["items"]
    assert sum(s["assets"] for s in systems) == body["assets"]


def test_evidence_items_count_and_unanswered_areas_are_not_assessed(api, world):
    engine, _ = world
    with Session(engine) as s:
        s.add(CbomEvidenceArea(team_id=1, area_key="hsm_firmware", answers={"model": "Luna 7"}))
        s.add(CbomEvidenceArea(team_id=1, area_key="third_party_vendors", answers={}))
        s.add(CbomEvidenceVendor(team_id=1, name="Card processor"))
        s.commit()
    body = _baseline(api)
    assert body["counts"]["hardware-fixed"] == 1 and body["counts"]["vendor-fixed"] == 1
    assert body["not_assessed"] == 1 and body["inputs"]["evidence_items"] == 2
    labels = {s["label"]: s["kind"] for s in body["systems"]["items"]}
    assert labels == {"Key management (evidence)": "evidence", "Third parties": "evidence"}


# ---------------------------------------------------------------------------------------------- API contract
def test_team_scoped_and_validated(api, estate):
    assert api("GET", "/1/cbom/agility", "carol").status_code in (403, 404)  # carol is in team 2
    assert api("GET", "/1/cbom/agility/subjects", "carol").status_code in (403, 404)
    other = _baseline(api, team=2, who="carol")
    assert other["assets"] == 0  # team 2 sees nothing of team 1
    assert api("GET", "/1/cbom/agility", params={"limit": 501}).status_code == 400  # CbomRoute: validation errors are 400
    assert api("GET", "/1/cbom/agility/subjects", params={"fix_class": "easy"}).status_code == 400  # CbomRoute: validation errors are 400
    assert api("GET", "/1/cbom/agility/subjects", params={"after": "not-a-cursor!"}).status_code == 400
    assert api("GET", "/1/cbom/agility", params={"kind": "galaxy"}).status_code == 400  # CbomRoute: validation errors are 400


def test_systems_keyset_paging_and_filters(api, estate):
    body = _baseline(api, limit=1)
    total, seen, after = body["systems_total"], [s["key"] for s in body["systems"]["items"]], body["systems"]["next"]
    while after:
        page = _baseline(api, limit=1, after=after)
        seen += [s["key"] for s in page["systems"]["items"]]
        after = page["systems"]["next"]
    assert len(seen) == len(set(seen)) == total
    vendor = _baseline(api, fix_class="vendor-fixed")["systems"]["items"]
    assert vendor and all(s["counts"]["vendor-fixed"] for s in vendor)
    apps = _baseline(api, kind="application")["systems"]["items"]
    assert [s["label"] for s in apps] == ["Payments"]


def test_a_new_collection_changes_the_cached_baseline(api, world, estate):
    first = _baseline(api)["assets"]
    _code_scan(estate["engine"], 903, NOW)
    assert _baseline(api)["assets"] == first + 1  # the certificate joins; the RSA row is a new asset


def test_the_store_is_read_only_once_it_has_every_latest_collection_and_both_readers_agree(api, world, reader):
    """Before drift writes the store, the baseline reads collections_view; after, the store; same answer."""
    engine, _ = world
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    api("POST", "/1/cbom/sources/items", json=linux_body("src-a", node_id=node_id, targets=["10.20.0.1"], window="any"))
    _run(api, "cb25-run-0002")
    _collect(api, hdr, _claim(api, hdr), [TLS10, TLS_NO_PQ, AES, _cert("10.20.0.1:443#chain[0]", source="tls")])
    r = api("GET", "/1/cbom/agility")
    before = r.json()
    assert before["inputs"]["read_from"] == "collections_view"  # the store has not written this collection yet
    _record_drift(engine)
    after = api("GET", "/1/cbom/agility").json()
    assert after["inputs"]["read_from"] == reader
    for k in ("assets", "counts", "counts_excl_pq", "self_fixable_pct", "unknown_reasons"):
        assert after[k] == before[k], k


# ---------------------------------------------------------------------------------------------- PR-B: on the store
def _store_only(reader):
    if reader != "estate_store":
        pytest.skip("estate store behaviour")


def test_the_store_carries_the_class_and_the_roll_up_is_its_group_by(api, estate, reader):
    _store_only(reader)
    from sqlmodel import select

    from backend.new_models import CbomEstateAsset, CbomEstateObservation
    from backend.utilities.cbom_sources import agility as AG

    with Session(estate["engine"]) as s:
        assets = s.exec(select(CbomEstateAsset).where(CbomEstateAsset.team_id == 1,
                                                      CbomEstateAsset.presence != "removed")).all()
        observations = s.exec(select(CbomEstateObservation).where(CbomEstateObservation.team_id == 1)).all()
    assert assets and all(a.fix_class in VALUES and a.fix_version == AG.version() and a.system_key for a in assets)
    assert all(o.fix_class in VALUES and o.fix_job_id == o.seen_job_id for o in observations)
    cert = next(a for a in assets if a.asset_type == "certificate")
    assert (cert.fix_class, cert.fix_observations) == ("hardware-fixed", 3)  # MAX over its three observations
    body = _baseline(api)
    stored = {v: sum(1 for a in assets if a.fix_class == v) for v in VALUES}
    assert body["counts"] == stored  # no code scan, no evidence here: the API is the store's GROUP BY
    rollup = ROLLUP.cached(Session(estate["engine"]), 1)
    assert rollup.groups and not rollup.subjects  # every asset counted by the GROUP BY, none loaded one by one


def test_a_baseline_is_written_per_run_and_listed_in_the_history(api, estate, reader):
    _store_only(reader)
    from sqlmodel import select

    from backend.new_models import CbomAgilityBaseline

    with Session(estate["engine"]) as s:
        rows = s.exec(select(CbomAgilityBaseline).where(CbomAgilityBaseline.team_id == 1)).all()
    assert [r.run_id for r in rows] == [estate["run"]["id"]]
    body = _baseline(api, limit=500)
    assert rows[0].counts == body["counts"] and rows[0].counts_excl_pq == body["counts_excl_pq"]
    assert rows[0].assets == body["assets"] and len(rows[0].systems) == body["systems_total"]
    r = api("GET", "/1/cbom/agility/history")
    assert r.status_code == 200 and r.json()["items"][0]["run_id"] == estate["run"]["id"]
    assert r.json()["items"][0]["counts"] == body["counts"]
    assert api("GET", "/1/cbom/agility/history", "carol").status_code in (403, 404)
    from backend.utilities.cbom_sources import agility_store as STORE  # a replay of the run keeps the first row
    with Session(estate["engine"]) as s:
        STORE.write_baseline(s, 1, estate["run"]["id"], dt.datetime.now(dt.timezone.utc))
        s.commit()
        assert len(s.exec(select(CbomAgilityBaseline)).all()) == 1


def test_a_stale_or_missing_stored_class_is_healed_when_read(api, estate, reader):
    _store_only(reader)
    import sqlalchemy as sa
    from sqlmodel import select

    from backend.new_models import CbomEstateAsset, CbomEstateObservation

    good = _baseline(api)
    ROLLUP.clear_cache()
    with Session(estate["engine"]) as s:  # a failed hook, an older model version, a backfill without hooks
        s.execute(sa.update(CbomEstateObservation.__table__).values(fix_class="configurable", fix_version="fx-0+old"))
        s.execute(sa.update(CbomEstateAsset.__table__).values(fix_class=None, fix_version=None))
        s.commit()
    assert _baseline(api)["counts"] == good["counts"]
    with Session(estate["engine"]) as s:
        assert all(a.fix_version and a.fix_class for a in s.exec(select(CbomEstateAsset)).all())


def test_a_failing_hook_never_blocks_the_store_and_the_read_heals(api, world, reader, monkeypatch):
    _store_only(reader)
    from sqlmodel import select

    from backend.new_models import CbomEstateAsset
    from backend.utilities.cbom_sources import agility_store as STORE

    engine, _ = world
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    api("POST", "/1/cbom/sources/items", json=linux_body("src-a", node_id=node_id, targets=["10.20.0.1"], window="any"))
    _run(api, "cb25-run-0003")
    _collect(api, hdr, _claim(api, hdr), [TLS10, AES])

    def boom(*_a, **_k):
        raise RuntimeError("agility hook down")

    original = STORE.judge_observations
    monkeypatch.setattr(STORE, "judge_observations", boom)
    _record_drift(engine)  # drift and the store commit; the plain hook's savepoint is rolled back
    with Session(engine) as s:
        assets = s.exec(select(CbomEstateAsset)).all()
    assert len(assets) == 2 and all(a.fix_class is None for a in assets)
    monkeypatch.setattr(STORE, "judge_observations", original)  # (undo() would also drop the harness's patches)
    body = _baseline(api)
    assert body["assets"] == 2 and body["counts"]["configurable"] == 1 and body["counts"]["none"] == 1


def test_a_certificate_is_rechecked_when_its_expiry_window_opens(api, world, reader):
    _store_only(reader)
    from sqlmodel import select

    from backend.new_models import CbomEstateObservation
    from backend.utilities.cbom_sources import agility_store as STORE

    engine, _ = world
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    api("POST", "/1/cbom/sources/items", json=linux_body("src-a", node_id=node_id, targets=["10.20.0.1"], window="any"))
    _run(api, "cb25-run-0004")
    expires = NOW + dt.timedelta(days=60)
    _collect(api, hdr, _claim(api, hdr), [_cert("10.20.0.1:443#chain[0]", source="tls",
                                                not_after=expires.strftime("%Y-%m-%dT%H:%M:%SZ"))])
    _record_drift(engine)
    with Session(engine) as s:
        obs = s.exec(select(CbomEstateObservation)).one()
        assert obs.fix_recheck_on == (expires - dt.timedelta(days=31)).date()
        first = obs.fix_codes
    later = dt.datetime.combine(obs.fix_recheck_on, dt.time(), tzinfo=dt.timezone.utc) + dt.timedelta(days=2)
    with Session(engine) as s:
        assert STORE.heal(s, 1, later) == 1  # the window opened: judged again
        s.commit()
        obs = s.exec(select(CbomEstateObservation)).one()
    assert obs.fix_recheck_on > later.date() and obs.fix_version
    with Session(engine) as s:
        assert STORE.heal(s, 1, later) == 0  # nothing more to do that day
    assert first is not None or obs.fix_codes is not None


def test_drill_down_pages_cross_the_store_and_the_code_and_evidence_subjects(api, estate, reader):
    engine = estate["engine"]
    _code_scan(engine, 904, NOW - dt.timedelta(hours=1))
    with Session(engine) as s:
        s.add(CbomEvidenceVendor(team_id=1, name="Card processor"))
        s.commit()
    body = _baseline(api)
    for view, counts in (("all", body["counts"]), ("excl_pq", body["counts_excl_pq"])):
        for v in VALUES:
            items = _all_subjects(api, page=1, fix_class=v, view=view)
            assert len(items) == counts[v] and len({i["key"] for i in items}) == len(items), (view, v)
    everything = _all_subjects(api, page=2)
    assert len(everything) == body["assets"] == len({i["key"] for i in everything})
    cert = [i for i in everything if i["type"] == "certificate"]
    assert len(cert) == 1 and cert[0]["fix_class"] == "hardware-fixed" and cert[0]["observations"] == 4
